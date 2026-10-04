import gc
import hashlib
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import FrozenInstanceError, asdict, fields, replace
from datetime import timedelta
from pathlib import Path
from struct import pack
from tempfile import TemporaryDirectory
from unittest.mock import PropertyMock, patch

from analysis import (
    DirectionalIPv6FragmentationStatistics,
    FlowObservationWindowManager,
    FlowStateCoordinator,
    IPV6_FRAGMENT_HEADER_MAX_COUNT,
    IPv6FragmentHeader,
    IPv6Fragmentation,
    IPv6FragmentationStatistics,
    IPv6Packet,
    analyze_packet,
    analyze_packet_outcome,
    extract_flow_feature_snapshot,
    flow_identity_from_packet,
    update_directional_ipv6_fragmentation_statistics,
)
from analysis.flow_observation_window import FlowObservationWindow, FlowObservationWindowUpdate
from analysis.flow_state_coordinator import CoordinatedFlowState
from application import GroundTruth, run_end_to_end_validation, run_flow_observation_session
from capture import PcapPacketSource
from tests.pcap_scenarios import addresses, frame, pcap_bytes, transport
from tests.protocol_scenarios import observation
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ipv6_transport import observation_for
from tests.test_tcp_options import tcp_observation


FIRST = (0, True)
ATOMIC = (0, False)


def raw_packet(protocol=17, headers=(FIRST,), reverse=False, extensions=(), payload=b''):
    segment = transport(protocol, payload, True, reverse)
    prefix, base = b'', protocol
    for specification in reversed(headers):
        offset, more, identification, reserved, bits = tuple(specification) + (1, 0, 0)[len(specification) - 2:]
        prefix = pack('!BBHI', base, reserved, (offset << 3) | (bits << 1) | int(more), identification) + prefix
        base = 44
    for kind in reversed(extensions):
        prefix = bytes((base, 0, 1, 4, 0, 0, 0, 0)) + prefix
        base = kind
    raw = observation_for(protocol, segment, prefix, base).raw_bytes
    source, destination = addresses(True, reverse)
    raw = raw[:22] + source + destination + raw[54:]
    if reverse:
        raw = raw[6:12] + raw[:6] + raw[12:]
    return raw.ljust(60, b'\x00')


def packet(protocol=17, headers=(FIRST,), reverse=False, seconds=0, extensions=(), payload=b''):
    return analyze_packet(observation(raw_packet(protocol, headers, reverse, extensions, payload), seconds))


def manager(timeout=5, capacity=1024):
    return FlowObservationWindowManager('ipv6-fragmentation-statistics', timedelta(seconds=timeout),
                                        max_active_windows=capacity)


def update(current, analysis, identity=None):
    identity = flow_identity_from_packet(analysis) if identity is None else identity
    return update_directional_ipv6_fragmentation_statistics(current, analysis, identity)


def tampered(analysis, **changes):
    copy = replace(analysis)
    for name, value in changes.items():
        object.__setattr__(copy, name, value)
    return copy


def derived(side):
    return (side.fragment_header_count, side.fragment_header_absent_packet_count, side.atomic_fragment_packet_count,
            side.more_fragments_set_header_count, side.more_fragments_clear_header_count)


def summarize(value):
    return asdict(value), tuple(derived(side) for side in (value.forward, value.reverse))


def replay_digest():
    instance = manager(capacity=2)
    events = []
    for index, (protocol, headers, reverse, seconds) in enumerate((
        (17, (FIRST,), False, 0), (17, (ATOMIC,), True, 1), (17, (), False, 2),
        (6, ((0, True, 7, 3, 1), ATOMIC), False, 3), (6, (ATOMIC,), True, 4), (17, (FIRST, FIRST), False, 5),
        (None, (), False, 6), (6, (FIRST,), False, 7), (6, (ATOMIC,), False, 14),
    )):
        if protocol is None:
            source = analyze_packet(observation(frame(6, transport(6)), seconds))
        else:
            source = packet(protocol, headers, reverse, seconds)
        update_value = instance.record(source)
        events.extend((window.key.sequence_number, window.closure_reason.value,
                       summarize(window.ipv6_fragmentation_statistics)) for window in update_value.closed_windows)
        events.append((update_value.active_window.key.sequence_number, index,
                       summarize(update_value.active_window.ipv6_fragmentation_statistics)))
    closed = instance.close(instance.active_windows()[0].identity)
    events.append((closed.key.sequence_number, closed.closure_reason.value, summarize(closed.ipv6_fragmentation_statistics)))
    events.extend((window.key.sequence_number, window.closure_reason.value, summarize(window.ipv6_fragmentation_statistics))
                  for window in instance.end_capture_session())
    return hashlib.sha256(repr(events).encode()).hexdigest()


class IPv6FragmentationStatisticsTests(unittest.TestCase):
    def test_empty_contract_is_immutable_and_directional(self):
        empty = IPv6FragmentationStatistics()
        self.assertEqual(tuple(getattr(empty, member.name) for member in fields(empty)), (0,) * 8)
        self.assertEqual(derived(empty), (0, 0, 0, 0, 0))
        self.assertEqual(DirectionalIPv6FragmentationStatistics(), DirectionalIPv6FragmentationStatistics(empty, empty))
        with self.assertRaises(FrozenInstanceError):
            empty.ipv6_packet_count = 1
        with self.assertRaises(FrozenInstanceError):
            DirectionalIPv6FragmentationStatistics().forward = empty
        for value in (None, (), IPv6FragmentationStatistics):
            with self.assertRaises(TypeError):
                DirectionalIPv6FragmentationStatistics(forward=value)
            with self.assertRaises(TypeError):
                DirectionalIPv6FragmentationStatistics(reverse=value)
        window = manager().record(packet(headers=())).active_window
        self.assertEqual(window.ipv6_fragmentation_statistics.reverse, empty)

    def test_unfragmented_ipv6_packets_count_without_fragment_headers(self):
        for protocol in (6, 17):
            source = packet(protocol, headers=(), extensions=(0, 60))
            self.assertIsNone(source.ipv6_fragmentation)
            value = update(None, source).forward
            self.assertEqual((value.ipv6_packet_count, value.fragment_header_packet_count,
                              value.fragment_header_absent_packet_count), (1, 0, 1))
            self.assertEqual(derived(value)[0], 0)

    def test_first_fragment_records_set_more_fragments_flag(self):
        for protocol in (6, 17):
            with self.subTest(protocol=protocol):
                source = packet(protocol, headers=(FIRST,), extensions=(0,))
                self.assertTrue(source.ipv6_fragmentation.headers[0].is_first_fragment)
                value = update(None, source).forward
                self.assertEqual(asdict(value), dict(
                    ipv6_packet_count=1, fragment_header_packet_count=1, fragmented_packet_count=1,
                    repeated_fragment_header_packet_count=0, first_fragment_header_count=1,
                    atomic_fragment_header_count=0, nonzero_reserved_header_count=0,
                    nonzero_reserved_bits_header_count=0))
                self.assertEqual(derived(value), (1, 0, 0, 1, 0))

    def test_atomic_fragment_records_clear_more_fragments_flag(self):
        for protocol in (6, 17):
            with self.subTest(protocol=protocol):
                source = packet(protocol, headers=(ATOMIC,))
                self.assertTrue(source.ipv6_fragmentation.headers[0].is_whole_datagram)
                value = update(None, source).forward
                self.assertEqual((value.fragment_header_packet_count, value.fragmented_packet_count,
                                  value.first_fragment_header_count, value.atomic_fragment_header_count), (1, 0, 0, 1))
                self.assertEqual(derived(value), (1, 0, 1, 0, 1))

    def test_repeated_headers_reserved_fields_and_extension_header_consistency(self):
        source = packet(6, headers=((0, False, 9, 255, 3), (0, True, 9, 0, 2), (0, False, 10, 1, 0)), extensions=(0,))
        value = update(None, source).forward
        self.assertEqual(asdict(value), dict(
            ipv6_packet_count=1, fragment_header_packet_count=1, fragmented_packet_count=1,
            repeated_fragment_header_packet_count=1, first_fragment_header_count=1,
            atomic_fragment_header_count=2, nonzero_reserved_header_count=2,
            nonzero_reserved_bits_header_count=2))
        window = manager().record(source).active_window
        extension = window.ipv6_extension_header_statistics.forward
        self.assertEqual(dict(extension.extension_header_type_counts)[44],
                         window.ipv6_fragmentation_statistics.forward.fragment_header_count)
        atomic_only = update(None, packet(headers=(ATOMIC, ATOMIC))).forward
        self.assertEqual((atomic_only.fragmented_packet_count, atomic_only.atomic_fragment_packet_count,
                          atomic_only.repeated_fragment_header_packet_count, atomic_only.fragment_header_count), (0, 1, 1, 2))

    def test_non_first_and_maximum_offsets_never_enter_flow_statistics(self):
        baseline = packet()
        identity = flow_identity_from_packet(baseline)
        for offset, more in ((1, True), (1, False), (8191, False), (8191, True)):
            for protocol in (6, 17):
                with self.subTest(offset=offset, more=more, protocol=protocol):
                    source = packet(protocol, headers=((offset, more),))
                    self.assertEqual(source.ipv6_fragmentation.headers[0].fragment_offset, offset)
                    self.assertIsNone(source.ipv6_tcp if protocol == 6 else source.ipv6_udp)
                    with self.assertRaises(ValueError):
                        update(None, source, identity)
        instance = manager()
        first = instance.record(baseline).active_window
        with self.assertRaises(ValueError):
            instance.record(packet(headers=((8191, False),), seconds=1))
        self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
        with patch('analysis.ipv6_fragmentation_statistics.flow_direction_from_packet', return_value=None):
            with self.assertRaisesRegex(ValueError, 'requires initial Fragment Headers'):
                update(None, packet(headers=((8191, False),)), identity)
        header = baseline.ipv6_fragmentation.headers[0]
        forged = replace(header.extension_header, raw_bytes=header.extension_header.raw_bytes[:2] + b'\x00\x08'
                         + header.extension_header.raw_bytes[4:])
        object.__setattr__(header, 'extension_header', forged)
        with self.assertRaises(ValueError):
            update(None, baseline, identity)

    def test_direct_construction_enforces_types_and_cross_field_invariants(self):
        valid = IPv6FragmentationStatistics(5, 3, 2, 1, 3, 2, 1, 1)
        self.assertEqual(derived(valid), (5, 2, 1, 3, 2))
        huge = 10 ** 100
        self.assertEqual(IPv6FragmentationStatistics(huge, huge, huge, 0, huge, 0).fragment_header_count, huge)
        bound = IPv6FragmentationStatistics(1, 1, 0, 1, 0, IPV6_FRAGMENT_HEADER_MAX_COUNT)
        self.assertEqual(bound.fragment_header_count, IPV6_FRAGMENT_HEADER_MAX_COUNT)
        for name in (member.name for member in fields(valid)):
            for value, error in ((True, TypeError), (1.0, TypeError), ('1', TypeError), (None, TypeError), (-1, ValueError)):
                with self.subTest(name=name, value=value), self.assertRaises(error):
                    replace(valid, **{name: value})
        for changes in (
            dict(fragment_header_packet_count=6), dict(fragmented_packet_count=4),
            dict(repeated_fragment_header_packet_count=4), dict(atomic_fragment_header_count=0, first_fragment_header_count=3),
            dict(first_fragment_header_count=1), dict(fragmented_packet_count=0),
            dict(atomic_fragment_header_count=0), dict(nonzero_reserved_header_count=6),
            dict(nonzero_reserved_bits_header_count=6),
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(valid, **changes)
        with self.assertRaises(ValueError):
            replace(bound, atomic_fragment_header_count=IPV6_FRAGMENT_HEADER_MAX_COUNT + 1)
        with self.assertRaises(ValueError):
            IPv6FragmentationStatistics(1, 0, 0, 0, 0, 1)

    def test_malformed_fragmentation_metadata_cannot_publish(self):
        source = packet(6, headers=(FIRST, ATOMIC))
        identity = flow_identity_from_packet(source)
        chain = source.ipv6_extension_headers
        fragmentation = source.ipv6_fragmentation
        entry = fragmentation.headers[0].extension_header
        cases = []
        cases.append((tampered(source, ipv6_fragmentation=None), ValueError))
        cases.append((tampered(source, ipv6_fragmentation=object()), ValueError))
        other = tampered(fragmentation, extension_headers=replace(chain))
        cases.append((tampered(source, ipv6_fragmentation=other), ValueError))
        cases.append((tampered(source, ipv6_fragmentation=tampered(fragmentation, headers=list(fragmentation.headers))), TypeError))
        cases.append((tampered(source, ipv6_fragmentation=tampered(fragmentation, headers=fragmentation.headers[:1])), ValueError))
        cases.append((tampered(source, ipv6_fragmentation=tampered(fragmentation, headers=(object(), fragmentation.headers[1]))),
                      TypeError))
        detached = IPv6FragmentHeader(replace(entry))
        cases.append((tampered(source, ipv6_fragmentation=tampered(fragmentation, headers=(detached, fragmentation.headers[1]))),
                      ValueError))
        cases.append((tampered(source, ipv6_extension_headers=tampered(chain, headers=list(chain.headers))), TypeError))
        cases.append((tampered(source, ipv6_extension_headers=tampered(chain, packet=replace(source.ipv6))), ValueError))
        cases.append((tampered(source, ipv6=object()), TypeError))
        oversized = tampered(chain, headers=chain.headers * (IPV6_FRAGMENT_HEADER_MAX_COUNT // 2 + 1))
        cases.append((tampered(source, ipv6_extension_headers=oversized), ValueError))
        for mutation in (dict(raw_bytes=entry.raw_bytes[:7]), dict(raw_bytes=bytearray(entry.raw_bytes)), dict(declared_length=16)):
            forged = replace(source)
            changed_entry = replace(entry)
            for name, value in mutation.items():
                object.__setattr__(changed_entry, name, value)
            changed_chain = tampered(chain, headers=(changed_entry,) + chain.headers[1:])
            changed_fragmentation = tampered(fragmentation, extension_headers=changed_chain,
                                             headers=(tampered(fragmentation.headers[0], extension_header=changed_entry),)
                                             + fragmentation.headers[1:])
            object.__setattr__(forged, 'ipv6_extension_headers', changed_chain)
            object.__setattr__(forged, 'ipv6_fragmentation', changed_fragmentation)
            cases.append((forged, (TypeError, ValueError)))
        with patch.object(IPv6FragmentHeader, 'more_fragments', new_callable=PropertyMock, return_value=1):
            with self.assertRaises(TypeError):
                update(None, source, identity)
        with patch.object(IPv6FragmentHeader, 'fragment_offset', new_callable=PropertyMock, return_value=8192):
            with self.assertRaises(ValueError):
                update(None, source, identity)
        for index, (analysis, error) in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(error):
                update(None, analysis, identity)
        instance = manager()
        first = instance.record(source).active_window
        for analysis, _ in (cases[0], cases[2], cases[3], cases[4], cases[6]):
            with self.assertRaises((TypeError, ValueError)):
                instance.record(analysis)
            self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
        self.assertEqual(first.ipv6_fragmentation_statistics.forward.ipv6_packet_count, 1)

    def test_public_types_identity_and_coordinator_contract(self):
        source = packet()
        identity = flow_identity_from_packet(source)
        for current, analysis, key in (([], source, identity), (IPv6FragmentationStatistics(), source, identity),
                                       (None, None, identity), (None, source, None), (None, source, tuple(asdict(identity)))):
            with self.assertRaises(TypeError):
                update_directional_ipv6_fragmentation_statistics(current, analysis, key)
        with self.assertRaises(ValueError):
            update(None, source, replace(identity, source_port=1))
        state = FlowStateCoordinator().record(source)
        with self.assertRaises(TypeError):
            replace(state, ipv6_fragmentation_statistics=IPv6FragmentationStatistics())
        legacy = tuple(getattr(state, member.name)
                       for member in fields(CoordinatedFlowState)
                       if member.name not in ('ipv6_fragmentation_statistics', 'icmp_statistics', 'udp_statistics', 'ipv4_header_statistics'))
        self.assertEqual(CoordinatedFlowState(*legacy).ipv6_fragmentation_statistics, DirectionalIPv6FragmentationStatistics())
        names = tuple(member.name for member in fields(CoordinatedFlowState))
        self.assertEqual(names.index('ipv6_fragmentation_statistics'), names.index('ip_hop_limit_statistics') + 1)

    def test_ipv4_traffic_including_fragments_cannot_contaminate(self):
        current = update(None, packet(6, headers=(FIRST,)))
        for fragment in (None, (0, True)):
            ipv4 = analyze_packet(tcp_observation(False, fragment=fragment))
            self.assertIsNone(ipv4.ipv6)
            ipv4_identity = flow_identity_from_packet(ipv4)
            self.assertIs(update(current, ipv4, ipv4_identity), current)
            self.assertEqual(update(None, ipv4, ipv4_identity), DirectionalIPv6FragmentationStatistics())
            window = manager().record(ipv4).active_window
            self.assertEqual(window.ipv6_fragmentation_statistics, DirectionalIPv6FragmentationStatistics())
        smuggled = tampered(ipv4, ipv6_fragmentation=packet().ipv6_fragmentation)
        with self.assertRaises(ValueError):
            update(None, smuggled, ipv4_identity)
        smuggled = tampered(ipv4, ipv6_extension_headers=packet().ipv6_extension_headers)
        with self.assertRaises(ValueError):
            update(None, smuggled, ipv4_identity)

    def test_directional_aggregation_repeats_and_order_independence(self):
        sequence = ((False, (FIRST,)), (True, (ATOMIC,)), (False, ()), (False, (FIRST,)), (True, (FIRST, ATOMIC)),
                    (True, ((0, False, 1, 4, 0),)), (False, (ATOMIC,)))
        results = []
        for ordering in (sequence, sequence[::-1]):
            instance = manager()
            for index, (reverse, headers) in enumerate(ordering):
                window = instance.record(packet(17, headers, reverse, seconds=index)).active_window
            results.append(window.ipv6_fragmentation_statistics)
        self.assertEqual(results[0], results[1])
        forward, reverse = results[0].forward, results[0].reverse
        self.assertEqual(asdict(forward), dict(
            ipv6_packet_count=4, fragment_header_packet_count=3, fragmented_packet_count=2,
            repeated_fragment_header_packet_count=0, first_fragment_header_count=2, atomic_fragment_header_count=1,
            nonzero_reserved_header_count=0, nonzero_reserved_bits_header_count=0))
        self.assertEqual(asdict(reverse), dict(
            ipv6_packet_count=3, fragment_header_packet_count=3, fragmented_packet_count=1,
            repeated_fragment_header_packet_count=1, first_fragment_header_count=1, atomic_fragment_header_count=3,
            nonzero_reserved_header_count=1, nonzero_reserved_bits_header_count=0))
        directional = window.coordinated_state.directional_flow_statistics
        self.assertEqual(directional.forward_packet_count, forward.ipv6_packet_count)
        self.assertEqual(directional.reverse_packet_count, reverse.ipv6_packet_count)
        repeated = packet(17, (FIRST,), seconds=10)
        value = None
        for _ in range(3):
            value = update(value, repeated)
        self.assertEqual((value.forward.ipv6_packet_count, value.forward.first_fragment_header_count), (3, 3))

    def test_identification_cardinality_and_retained_state_are_bounded(self):
        distinct = None
        constant = None
        for index in range(2048):
            identification = (index * 2654435761) & 0xFFFFFFFF
            distinct = update(distinct, packet(headers=((0, bool(index & 1), identification),)))
            constant = update(constant, packet(headers=((0, bool(index & 1), 1),)))
        self.assertEqual(distinct, constant)
        self.assertEqual(distinct.forward.fragment_header_count, 2048)
        for side in (distinct.forward, distinct.reverse):
            self.assertEqual(tuple(vars(side)), tuple(member.name for member in fields(IPv6FragmentationStatistics)))
            self.assertTrue(all(type(value) is int for value in vars(side).values()))
        self.assertEqual(tuple(vars(distinct)), ('forward', 'reverse'))
        maximum = IPV6_FRAGMENT_HEADER_MAX_COUNT - 1
        largest = packet(17, headers=(ATOMIC,) * maximum)
        self.assertEqual(largest.ipv6.payload_length, 65535 - 7)
        self.assertEqual(len(largest.ipv6_fragmentation.headers), maximum)
        value = update(None, largest).forward
        self.assertEqual((value.atomic_fragment_header_count, value.repeated_fragment_header_packet_count,
                          value.fragment_header_packet_count), (maximum, 1, 1))
        self.assertEqual(len(vars(value)), 8)

    def test_statistics_never_read_payload_or_reparse_packet_structure(self):
        source = packet(6, headers=((0, True, 5, 2, 1), ATOMIC), extensions=(0, 60), payload=bytes(range(256)))
        expected = update(None, source)
        identity = flow_identity_from_packet(source)
        with patch.object(IPv6Packet, 'payload', new_callable=PropertyMock, create=True,
                          side_effect=AssertionError('payload access')), \
                patch('analysis.ipv6_extension_headers.validate_ipv6_extension_headers',
                      side_effect=AssertionError('chain reparse')), \
                patch('analysis.ipv6_fragmentation.validate_ipv6_extension_headers',
                      side_effect=AssertionError('chain reparse')), \
                patch.object(IPv6Fragmentation, '__post_init__', side_effect=AssertionError('fragmentation reanalysis')), \
                patch.object(IPv6FragmentHeader, '__post_init__', side_effect=AssertionError('header reconstruction')):
            self.assertEqual(update_directional_ipv6_fragmentation_statistics(None, source, identity), expected)
        sizes = []
        for payload in (b'', bytes(range(256)), bytes(65535 - 16 - 8)):
            sizes.append(update(None, packet(17, headers=(FIRST, ATOMIC), payload=payload)))
        self.assertEqual(sizes, [sizes[0]] * 3)

    def test_failed_candidates_publication_and_retries_count_once(self):
        for target in (CoordinatedFlowState, FlowObservationWindowUpdate):
            with self.subTest(target=target.__name__):
                instance = manager()
                first = instance.record(packet(headers=(ATOMIC,))).active_window
                later = packet(headers=(FIRST,), seconds=1)
                for _ in range(2):
                    with patch.object(target, '__post_init__', side_effect=MemoryError('publication')):
                        with self.assertRaises(MemoryError):
                            instance.record(later)
                    self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
                accepted = instance.record(later).active_window.ipv6_fragmentation_statistics.forward
                self.assertEqual((accepted.ipv6_packet_count, accepted.first_fragment_header_count,
                                  accepted.atomic_fragment_header_count), (2, 1, 1))
                again = instance.record(later).active_window.ipv6_fragmentation_statistics.forward
                self.assertEqual((again.ipv6_packet_count, again.first_fragment_header_count), (3, 2))
                self.assertEqual(first.ipv6_fragmentation_statistics.forward.ipv6_packet_count, 1)
        instance = manager()
        with patch('analysis.ipv6_fragmentation_statistics._reduce', side_effect=MemoryError('allocation')):
            with self.assertRaises(MemoryError):
                instance.record(packet())
        self.assertEqual(instance.active_windows(), ())
        retried = instance.record(packet()).active_window
        self.assertEqual((retried.key.sequence_number, retried.ipv6_fragmentation_statistics.forward.ipv6_packet_count), (0, 1))

    def test_every_closure_reason_preserves_aggregate_and_replacements_start_empty(self):
        for reason in ('explicit_segmentation', 'capture_session_end', 'inactivity', 'capacity'):
            with self.subTest(reason=reason):
                instance = manager(capacity=1)
                first = instance.record(packet(headers=(FIRST,))).active_window
                if reason == 'explicit_segmentation':
                    closed = instance.close(first.identity)
                    replacement = instance.record(packet(headers=(ATOMIC,), seconds=1)).active_window
                elif reason == 'capture_session_end':
                    closed, = instance.end_capture_session()
                    self.assertEqual(instance.end_capture_session(), ())
                    replacement = None
                else:
                    later = packet(6 if reason == 'capacity' else 17, headers=(ATOMIC,), seconds=5)
                    update_value = instance.record(later)
                    closed, = update_value.closed_windows
                    replacement = update_value.active_window
                self.assertEqual(closed.closure_reason.value, reason)
                self.assertIs(closed.ipv6_fragmentation_statistics, first.ipv6_fragmentation_statistics)
                if replacement is not None:
                    self.assertEqual(replacement.ipv6_fragmentation_statistics.forward.first_fragment_header_count, 0)
                    self.assertEqual(replacement.ipv6_fragmentation_statistics.forward.atomic_fragment_header_count, 1)
        instance = manager(capacity=1)
        first = instance.record(packet()).active_window
        with patch.object(FlowObservationWindow, '__post_init__', side_effect=MemoryError('closure')):
            with self.assertRaises(MemoryError):
                instance.end_capture_session()
        closed, = instance.end_capture_session()
        self.assertIs(closed.ipv6_fragmentation_statistics, first.ipv6_fragmentation_statistics)

    def test_snapshots_are_frozen_and_sources_are_released(self):
        source = packet(6, headers=(FIRST, ATOMIC))
        references = tuple(weakref.ref(item) for item in (
            source, source.ipv6, source.ipv6_extension_headers, source.ipv6_fragmentation,
            source.ipv6_fragmentation.headers[0], source.ipv6_fragmentation.headers[0].extension_header,
            source.observation))
        instance = manager()
        first = instance.record(source).active_window
        snapshot = extract_flow_feature_snapshot(first)
        del source
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertIs(snapshot.coordinated_state.ipv6_fragmentation_statistics, first.ipv6_fragmentation_statistics)
        instance.record(packet(6, headers=(FIRST,), seconds=1))
        statistics = snapshot.coordinated_state.ipv6_fragmentation_statistics.forward
        self.assertEqual((statistics.ipv6_packet_count, statistics.fragment_header_count), (1, 2))
        with self.assertRaises(FrozenInstanceError):
            snapshot.coordinated_state.ipv6_fragmentation_statistics.forward.ipv6_packet_count = 0

    def test_protocol_and_detection_contracts_are_unchanged(self):
        from tests.test_dns import header
        from tests.test_dns_packet_analysis import dns_packet
        from tests.test_ldap import message as ldap_message
        from tests.test_ldap_flow_statistics import ldap_observation
        from tests.test_tls_handshake_framing import message
        from tests.test_tls_record_framing import packet as tls_packet, wire
        from tests.test_tls_server_hello import body
        sources = (dns_packet(header()), ldap_observation(ldap_message()), tls_packet(wire(message(body(), 2), 22)),
                   observation(raw_packet(17, (FIRST,)), 1), observation(raw_packet(6, (ATOMIC,), True), 2))
        self.assertTrue(all(analyze_packet_outcome(item).succeeded for item in sources))
        arguments = dict(configuration=settings(), capture_session_id='fragmentation', ground_truth=GroundTruth((), ()))
        actual = run_end_to_end_validation(MemoryPacketSource(sources), **arguments)
        with patch('analysis.flow_state_coordinator.update_directional_ipv6_fragmentation_statistics',
                   return_value=DirectionalIPv6FragmentationStatistics()):
            baseline = run_end_to_end_validation(MemoryPacketSource(sources), **arguments)
        self.assertEqual(actual.report.metrics, baseline.report.metrics)
        self.assertEqual(actual.pipeline_result.packet_findings, baseline.pipeline_result.packet_findings)
        self.assertEqual(len(actual.pipeline_result.flow_findings), len(baseline.pipeline_result.flow_findings))
        observed = []
        for left, right in zip(actual.pipeline_result.flow_findings, baseline.pipeline_result.flow_findings):
            self.assertEqual(left.decision, right.decision)
            if left.detector_id != 'volume':
                continue
            left_state = left.raw_evidence.snapshot.coordinated_state
            right_state = right.raw_evidence.snapshot.coordinated_state
            self.assertEqual(replace(left_state, ipv6_fragmentation_statistics=DirectionalIPv6FragmentationStatistics()),
                             right_state)
            observed.append(left_state.ipv6_fragmentation_statistics)
        self.assertIn(DirectionalIPv6FragmentationStatistics(forward=IPv6FragmentationStatistics(1, 1, 1, 0, 1, 0)),
                      observed)

    def test_capture_sessions_match_across_all_classic_pcap_encodings(self):
        sources = tuple(observation(raw_packet(protocol, headers, reverse), index)
                        for index, (protocol, headers, reverse) in enumerate((
                            (17, (FIRST,), False), (17, (ATOMIC,), True), (17, (), False),
                            (6, ((0, True, 3, 9, 2), ATOMIC), False), (6, (FIRST,), True), (6, (ATOMIC, ATOMIC), True))))
        expected = []
        run_flow_observation_session(MemoryPacketSource(sources), capture_session_id='fragmentation',
                                     inactivity_timeout=timedelta(seconds=60), closed_window_consumer=expected.append)
        self.assertEqual([(window.identity.protocol, asdict(window.ipv6_fragmentation_statistics)) for window in expected], [
            (17, asdict(DirectionalIPv6FragmentationStatistics(IPv6FragmentationStatistics(2, 1, 1, 0, 1, 0),
                                                               IPv6FragmentationStatistics(1, 1, 0, 0, 0, 1)))),
            (6, asdict(DirectionalIPv6FragmentationStatistics(IPv6FragmentationStatistics(1, 1, 1, 1, 1, 1, 1, 1),
                                                              IPv6FragmentationStatistics(2, 2, 1, 1, 1, 2)))),
        ])
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'ipv6-fragmentation.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    with self.subTest(order=order, nano=nano):
                        path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes)
                                                          for index, item in enumerate(sources)), order, nano))
                        source = PcapPacketSource(path)
                        actual = []
                        run_flow_observation_session(source, capture_session_id='fragmentation',
                                                     inactivity_timeout=timedelta(seconds=60),
                                                     closed_window_consumer=actual.append)
                        self.assertEqual(actual, expected)
                        self.assertIsNone(source._file)

    def test_capture_and_consumer_failures_preserve_cleanup(self):
        failure = RuntimeError('capture')
        source = MemoryPacketSource((packet().observation,), iteration_error=failure)
        closed = []
        with self.assertRaises(RuntimeError) as caught:
            run_flow_observation_session(source, capture_session_id='fragmentation',
                                         inactivity_timeout=timedelta(seconds=5), closed_window_consumer=closed.append)
        self.assertIs(caught.exception, failure)
        self.assertTrue(source.stopped)
        self.assertEqual(closed[0].ipv6_fragmentation_statistics.forward.first_fragment_header_count, 1)
        source = MemoryPacketSource((packet().observation, packet(6, (ATOMIC,), seconds=1).observation))
        delivered = []

        def fail(window):
            delivered.append(window)
            raise failure

        with self.assertRaises(RuntimeError):
            run_flow_observation_session(source, capture_session_id='fragmentation', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=fail, max_active_windows=1)
        self.assertTrue(source.stopped)
        self.assertEqual(len(delivered), 1)

    def test_established_seed_timezone_replay_matrix(self):
        expected = replay_digest()
        script = 'from tests.test_ipv6_fragmentation_statistics import replay_digest; print(replay_digest())'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                actual = subprocess.check_output([sys.executable, '-B', '-c', script], cwd=Path(__file__).parents[1],
                                                 env=dict(os.environ, PYTHONHASHSEED=seed, TZ=zone), text=True).strip()
                self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
