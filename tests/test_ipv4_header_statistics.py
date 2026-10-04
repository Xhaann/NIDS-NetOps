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
from tempfile import TemporaryDirectory
from unittest.mock import PropertyMock, patch

from analysis import (
    DirectionalIPv4HeaderStatistics,
    FlowIdentityError,
    FlowStateCoordinator,
    IPV4_DSCP_BINS,
    IPV4_MAX_OPTIONS_LENGTH,
    IPv4HeaderStatistics,
    IPv4Packet,
    analyze_packet,
    analyze_packet_outcome,
    extract_flow_feature_snapshot,
    flow_identity_from_packet,
    update_directional_ipv4_header_statistics,
)
from analysis.flow_direction import FlowDirectionError
from analysis.flow_observation_window import FlowObservationWindow, FlowObservationWindowUpdate
from analysis.flow_state_coordinator import CoordinatedFlowState
from application import GroundTruth, run_end_to_end_validation, run_flow_observation_session
from capture import PcapPacketSource
from tests.pcap_scenarios import checksum, frame, pcap_bytes, transport
from tests.protocol_scenarios import observation
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_icmp_flow_admission import icmp4, icmp6, manager
from tests.test_ipv4_options import with_options
from tests.test_packet_analysis import make_observation


def ipv4(protocol=17, dscp=0, ecn=0, flags=0, options=b'', reverse=False, seconds=0, payload=b'data'):
    if protocol == 1:
        raw = bytearray(icmp4(reverse=reverse).raw_bytes)
    else:
        raw = bytearray(frame(protocol, transport(protocol, payload, False, reverse), False, reverse))
    raw[15] = dscp << 2 | ecn
    raw[20] = raw[20] & 0x1F | flags << 5
    raw[24:26] = bytes(2)
    raw[24:26] = checksum(bytes(raw[14:34])).to_bytes(2, 'big')
    source = observation(bytes(raw), seconds)
    return with_options(source, options) if options else source


def ipv6_udp(reverse=False, seconds=0):
    return observation(frame(17, transport(17, b'data', True, reverse), True, reverse), seconds)


def update(current, analysis, identity=None):
    identity = flow_identity_from_packet(analysis) if identity is None else identity
    return update_directional_ipv4_header_statistics(current, analysis, identity)


def record(sources):
    instance = manager()
    window = None
    for index, source in enumerate(sources):
        source = replace(source, captured_at=source.captured_at + timedelta(milliseconds=index))
        window = instance.record(analyze_packet(source)).active_window
    return window.ipv4_header_statistics


def tampered(value, **changes):
    copy = replace(value)
    for name, item in changes.items():
        object.__setattr__(copy, name, item)
    return copy


def scalars(value):
    return (value.dont_fragment_packet_count, value.more_fragments_packet_count, value.reserved_flag_packet_count,
            value.options_packet_count, value.total_options_length)


def summarize(value):
    return asdict(value), tuple((side.packet_count, side.options_absent_packet_count, side.ecn_capable_packet_count,
                                 side.congestion_experienced_packet_count) for side in (value.forward, value.reverse))


def replay_digest():
    instance = manager(capacity=3)
    events = []
    for source in (ipv4(dscp=46, ecn=2, flags=2, seconds=0), ipv4(dscp=0, ecn=3, reverse=True, seconds=1),
                   ipv6_udp(seconds=2), ipv4(6, dscp=10, flags=1, seconds=3), icmp6(seconds=4),
                   ipv4(1, dscp=63, ecn=1, options=bytes.fromhex('01010100'), seconds=5),
                   ipv4(6, dscp=10, flags=4, reverse=True, seconds=6), ipv4(dscp=8, seconds=7),
                   ipv4(dscp=8, ecn=1, options=b'\x01' * 40, seconds=20)):
        result = instance.record(analyze_packet(source))
        events.extend((window.key.sequence_number, window.closure_reason.value, summarize(window.ipv4_header_statistics))
                      for window in result.closed_windows)
        events.append((result.active_window.key.sequence_number, None, summarize(result.active_window.ipv4_header_statistics)))
    closed = instance.close(instance.active_windows()[0].identity)
    events.append((closed.key.sequence_number, closed.closure_reason.value, summarize(closed.ipv4_header_statistics)))
    events.extend((window.key.sequence_number, window.closure_reason.value, summarize(window.ipv4_header_statistics))
                  for window in instance.end_capture_session())
    return hashlib.sha256(repr(events).encode()).hexdigest()


class IPv4HeaderStatisticsTests(unittest.TestCase):
    def test_empty_aggregate_and_ipv6_flows(self):
        empty = IPv4HeaderStatistics()
        self.assertEqual((empty.dscp_counts, empty.ecn_counts, scalars(empty), empty.packet_count,
                          empty.options_absent_packet_count, empty.ecn_capable_packet_count,
                          empty.congestion_experienced_packet_count), ((), (), (0, 0, 0, 0, 0), 0, 0, 0, 0))
        self.assertEqual(DirectionalIPv4HeaderStatistics(), DirectionalIPv4HeaderStatistics(empty, empty))
        for source in (ipv6_udp(), icmp6()):
            analysis = analyze_packet(source)
            current = update(None, analysis)
            self.assertEqual(current, DirectionalIPv4HeaderStatistics())
            self.assertIs(update(current, analysis), current)
            self.assertEqual(manager().record(analysis).active_window.ipv4_header_statistics, DirectionalIPv4HeaderStatistics())

    def test_single_packet_for_each_admitted_ipv4_protocol(self):
        for protocol in (6, 17, 1):
            with self.subTest(protocol=protocol):
                value = record((ipv4(protocol, dscp=46, ecn=2, flags=2),))
                self.assertEqual((value.forward.dscp_counts, value.forward.ecn_counts), (((46, 1),), ((2, 1),)))
                self.assertEqual(scalars(value.forward), (1, 0, 0, 0, 0))
                self.assertEqual((value.forward.packet_count, value.forward.ecn_capable_packet_count), (1, 1))
                self.assertEqual(value.reverse, IPv4HeaderStatistics())

    def test_dscp_and_ecn_distributions_cover_their_domains(self):
        sources = [ipv4(dscp=dscp, ecn=dscp % 4) for dscp in range(63, -1, -1)] + [ipv4(dscp=0, ecn=3), ipv4(dscp=63, ecn=0)]
        value = record(sources)
        self.assertEqual(value.forward.dscp_counts, tuple((dscp, 2 if dscp in (0, 63) else 1) for dscp in range(64)))
        self.assertEqual(len(value.forward.dscp_counts), IPV4_DSCP_BINS)
        self.assertEqual(value.forward.ecn_counts, ((0, 17), (1, 16), (2, 16), (3, 17)))
        self.assertEqual((value.forward.packet_count, value.forward.ecn_capable_packet_count,
                          value.forward.congestion_experienced_packet_count), (66, 32, 17))
        repeated = record((ipv4(dscp=26, ecn=1), ipv4(dscp=26, ecn=1), ipv4(dscp=26, ecn=1)))
        self.assertEqual((repeated.forward.dscp_counts, repeated.forward.ecn_counts), (((26, 3),), ((1, 3),)))

    def test_flag_bits_are_counted_independently(self):
        value = record([ipv4(flags=flags) for flags in range(8)])
        self.assertEqual(scalars(value.forward), (4, 4, 4, 0, 0))
        clear = record((ipv4(flags=0), ipv4(flags=0)))
        self.assertEqual(scalars(clear.forward), (0, 0, 0, 0, 0))
        first_fragment = analyze_packet(ipv4(flags=1))
        self.assertEqual((first_fragment.ipv4.flags, first_fragment.ipv4.fragment_offset), (1, 0))
        self.assertTrue(analyze_packet_outcome(ipv4(flags=1)).succeeded)
        self.assertEqual(scalars(record((ipv4(6, flags=1), ipv4(6, flags=3))).forward), (1, 2, 0, 0, 0))

    def test_options_presence_and_area_length_come_from_the_header_length(self):
        value = record((ipv4(), ipv4(options=bytes.fromhex('01010100')), ipv4(options=bytes.fromhex('94040000') + b'\x01' * 4),
                        ipv4(options=b'\x01' * IPV4_MAX_OPTIONS_LENGTH)))
        self.assertEqual((value.forward.options_packet_count, value.forward.total_options_length,
                          value.forward.options_absent_packet_count), (3, 52, 1))
        maximum = analyze_packet(ipv4(options=b'\x01' * IPV4_MAX_OPTIONS_LENGTH))
        self.assertEqual(maximum.ipv4.ihl, 15)
        different_content = record((ipv4(options=b'\x01' * 8), ipv4(options=bytes.fromhex('8203ff00') + bytes(4))))
        self.assertEqual(scalars(different_content.forward), (0, 0, 0, 2, 16))

    def test_directions_accumulate_separately_and_repeats_count(self):
        for protocol in (6, 17, 1):
            with self.subTest(protocol=protocol):
                value = record((ipv4(protocol, dscp=10, flags=2), ipv4(protocol, dscp=10, ecn=1, reverse=True),
                                ipv4(protocol, dscp=10, flags=2), ipv4(protocol, dscp=12, ecn=3, reverse=True,
                                                                     options=bytes.fromhex('01010100'))))
                self.assertEqual((value.forward.dscp_counts, value.forward.ecn_counts, scalars(value.forward)),
                                 (((10, 2),), ((0, 2),), (2, 0, 0, 0, 0)))
                self.assertEqual((value.reverse.dscp_counts, value.reverse.ecn_counts, scalars(value.reverse)),
                                 (((10, 1), (12, 1)), ((1, 1), (3, 1)), (0, 0, 0, 1, 4)))

    def test_construction_validates_domains_and_consistency(self):
        valid = IPv4HeaderStatistics(((0, 3), (46, 2)), ((0, 4), (3, 1)), 5, 1, 0, 2, 12)
        self.assertEqual((valid.packet_count, valid.options_absent_packet_count), (5, 3))
        huge = 10 ** 100
        self.assertEqual(IPv4HeaderStatistics(((63, huge),), ((3, huge),), huge, huge, huge, huge, 40 * huge).packet_count, huge)
        for changes, error in (
            (dict(dscp_counts=[]), TypeError), (dict(dscp_counts=((64, 5),)), ValueError),
            (dict(dscp_counts=((46, 2), (0, 3))), ValueError), (dict(dscp_counts=((0, 5), (0, 0))), ValueError),
            (dict(dscp_counts=((True, 5),)), TypeError), (dict(dscp_counts=((0,),)), TypeError),
            (dict(ecn_counts=((4, 5),)), ValueError), (dict(ecn_counts=((0, 4),)), ValueError),
            (dict(ecn_counts=((0, 5.0),)), TypeError), (dict(ecn_counts=(None,) * 5), ValueError),
            (dict(dont_fragment_packet_count=6), ValueError), (dict(more_fragments_packet_count=-1), ValueError),
            (dict(reserved_flag_packet_count=True), TypeError), (dict(options_packet_count=6), ValueError),
            (dict(total_options_length=6), ValueError), (dict(total_options_length=4), ValueError),
            (dict(total_options_length=84), ValueError), (dict(options_packet_count=0), ValueError),
            (dict(total_options_length='12'), TypeError),
        ):
            with self.subTest(changes=changes), self.assertRaises(error):
                replace(valid, **changes)
        with self.assertRaises(ValueError):
            IPv4HeaderStatistics(dscp_counts=(None,) * 65)
        with self.assertRaises(TypeError):
            DirectionalIPv4HeaderStatistics(forward=None)
        with self.assertRaises(TypeError):
            DirectionalIPv4HeaderStatistics(reverse=asdict(valid))

    def test_malformed_sources_family_mixing_and_identities_cannot_publish(self):
        source = analyze_packet(ipv4(dscp=46))
        identity = flow_identity_from_packet(source)
        for current, analysis, key in (([], source, identity), (IPv4HeaderStatistics(), source, identity),
                                       (None, None, identity), (None, source, None), (None, source, asdict(identity))):
            with self.assertRaises(TypeError):
                update_directional_ipv4_header_statistics(current, analysis, key)
        with self.assertRaises(FlowDirectionError):
            update(None, source, replace(identity, source_port=1))
        cases = []
        for name, value, error in (('dscp', 64, ValueError), ('ecn', 4, ValueError), ('flags', 8, ValueError),
                                   ('ihl', 16, ValueError), ('ihl', 4, ValueError), ('version', 6, ValueError),
                                   ('fragment_offset', 8192, ValueError), ('fragment_offset', 1, ValueError),
                                   ('dscp', True, TypeError), ('ecn', None, TypeError), ('flags', '2', TypeError)):
            cases.append((tampered(source, ipv4=tampered(source.ipv4, **{name: value})), error))
        cases.append((tampered(source, ipv4=object()), TypeError))
        cases.append((tampered(source, ipv6=analyze_packet(ipv6_udp()).ipv6), ValueError))
        for index, (analysis, error) in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(error):
                update(None, analysis, identity)
        with self.assertRaisesRegex(ValueError, 'initial fragment'):
            update(None, cases[7][0], identity)
        v6 = analyze_packet(ipv6_udp())
        with self.assertRaisesRegex(ValueError, 'IPv6 flows'):
            update(None, tampered(v6, ipv4=source.ipv4), flow_identity_from_packet(v6))
        instance = manager()
        first = instance.record(source).active_window
        for analysis in (cases[0][0], cases[7][0]):
            with self.assertRaises(ValueError):
                instance.record(analysis)
            self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
        non_initial = analyze_packet_outcome(make_observation(17, transport(17), fragment_field=1))
        self.assertIsNone(non_initial.analysis)
        with self.assertRaises(FlowIdentityError):
            instance.record(analyze_packet(make_observation(253, bytes(8))))
        self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)

    def test_reducer_reads_no_bytes_parsers_or_checksums(self):
        for options in (b'', bytes.fromhex('94040000') + b'\x01' * 36):
            analysis = analyze_packet(ipv4(6, dscp=34, ecn=1, flags=6, options=options, payload=bytes(200)))
            identity = flow_identity_from_packet(analysis)
            expected = update(None, analysis, identity)
            with patch.object(IPv4Packet, 'payload', new_callable=PropertyMock, create=True,
                              side_effect=AssertionError('payload')), \
                    patch.object(IPv4Packet, 'options', new_callable=PropertyMock, create=True,
                                 side_effect=AssertionError('options')), \
                    patch('analysis.ipv4.decode_ipv4', side_effect=AssertionError('decode')), \
                    patch('analysis.ipv4._validate_option_envelope', side_effect=AssertionError('envelope')), \
                    patch('analysis.ipv4_checksum.validate_ipv4_checksum', side_effect=AssertionError('checksum')), \
                    patch.object(IPv4Packet, '__post_init__', side_effect=AssertionError('rebuild')):
                self.assertEqual(update_directional_ipv4_header_statistics(None, analysis, identity), expected)
            changed = replace(analysis, ipv4=replace(analysis.ipv4, header_checksum=0, identification=4321, ttl=1),
                              ipv4_checksum_valid=False)
            self.assertEqual(update(None, changed, identity), expected)

    def test_failed_candidates_and_publication_retry_count_once(self):
        for target in (CoordinatedFlowState, FlowObservationWindowUpdate):
            with self.subTest(target=target.__name__):
                instance = manager()
                first = instance.record(analyze_packet(ipv4(dscp=46))).active_window
                reply = analyze_packet(ipv4(dscp=0, ecn=1, flags=2, reverse=True, seconds=1))
                for _ in range(2):
                    with patch.object(target, '__post_init__', side_effect=MemoryError('publication')):
                        with self.assertRaises(MemoryError):
                            instance.record(reply)
                    self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
                accepted = instance.record(reply).active_window.ipv4_header_statistics
                self.assertEqual((accepted.reverse.dscp_counts, scalars(accepted.reverse)), (((0, 1),), (1, 0, 0, 0, 0)))
                repeated = instance.record(reply).active_window.ipv4_header_statistics
                self.assertEqual((repeated.reverse.dscp_counts, scalars(repeated.reverse)), (((0, 2),), (2, 0, 0, 0, 0)))
                self.assertEqual(first.ipv4_header_statistics.reverse, IPv4HeaderStatistics())
        instance = manager()
        with patch('analysis.ipv4_header_statistics._reduce', side_effect=MemoryError('allocation')):
            with self.assertRaises(MemoryError):
                instance.record(analyze_packet(ipv4()))
        self.assertEqual(instance.active_windows(), ())
        retried = instance.record(analyze_packet(ipv4())).active_window
        self.assertEqual((retried.key.sequence_number, retried.ipv4_header_statistics.forward.packet_count), (0, 1))

    def test_every_closure_reason_preserves_aggregate_and_replacement_starts_empty(self):
        for reason in ('explicit_segmentation', 'capture_session_end', 'inactivity', 'capacity'):
            with self.subTest(reason=reason):
                instance = manager(capacity=1)
                instance.record(analyze_packet(ipv4(dscp=46)))
                published = instance.record(analyze_packet(ipv4(dscp=46, reverse=True, seconds=1))).active_window
                if reason == 'explicit_segmentation':
                    closed = instance.close(published.identity)
                    replacement = instance.record(analyze_packet(ipv4(dscp=8, seconds=2))).active_window
                elif reason == 'capture_session_end':
                    closed, = instance.end_capture_session()
                    replacement = None
                else:
                    later = ipv4(dscp=8, seconds=7) if reason == 'inactivity' else ipv4(6, dscp=8, seconds=2)
                    result = instance.record(analyze_packet(later))
                    closed, = result.closed_windows
                    replacement = result.active_window
                self.assertEqual(closed.closure_reason.value, reason)
                self.assertIs(closed.ipv4_header_statistics, published.ipv4_header_statistics)
                if replacement is not None:
                    self.assertEqual(replacement.ipv4_header_statistics.forward.dscp_counts, ((8, 1),))
                    self.assertEqual(replacement.ipv4_header_statistics.reverse, IPv4HeaderStatistics())
        instance = manager()
        first = instance.record(analyze_packet(ipv4())).active_window
        with patch.object(FlowObservationWindow, '__post_init__', side_effect=MemoryError('closure')):
            with self.assertRaises(MemoryError):
                instance.end_capture_session()
        closed, = instance.end_capture_session()
        self.assertIs(closed.ipv4_header_statistics, first.ipv4_header_statistics)

    def test_immutability_snapshot_stability_and_bounded_state(self):
        instance = manager()
        first = instance.record(analyze_packet(ipv4(dscp=46, ecn=2))).active_window
        snapshot = extract_flow_feature_snapshot(first)
        statistics = snapshot.coordinated_state.ipv4_header_statistics
        with self.assertRaises(FrozenInstanceError):
            statistics.forward = IPv4HeaderStatistics()
        with self.assertRaises(FrozenInstanceError):
            statistics.forward.dscp_counts = ()
        with self.assertRaises(TypeError):
            statistics.forward.dscp_counts[0] = (46, 2)
        for index in range(1, 2049):
            window = instance.record(analyze_packet(ipv4(dscp=index % 64, ecn=index % 4, flags=index % 8,
                                                         options=b'\x01' * (4 * (index % 11)),
                                                         seconds=index / 1000))).active_window
        self.assertEqual((statistics.forward.dscp_counts, statistics.forward.ecn_counts), (((46, 1),), ((2, 1),)))
        current = window.ipv4_header_statistics.forward
        self.assertEqual(current.packet_count, 2049)
        self.assertLessEqual(len(current.dscp_counts), 64)
        self.assertLessEqual(len(current.ecn_counts), 4)
        self.assertEqual(tuple(vars(current)), tuple(member.name for member in fields(IPv4HeaderStatistics)))

    def test_published_statistics_release_packet_and_model_sources(self):
        source = analyze_packet(ipv4(dscp=46, options=bytes.fromhex('01010100')))
        references = tuple(weakref.ref(item) for item in (source, source.ipv4, source.udp, source.observation))
        state = FlowStateCoordinator().record(source)
        del source
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(scalars(state.ipv4_header_statistics.forward), (0, 0, 0, 1, 4))
        values = [value for item in state.ipv4_header_statistics.forward.dscp_counts for value in item]
        self.assertTrue(all(type(value) is int for value in values))

    def test_detection_and_other_flow_results_are_unchanged(self):
        sources = (ipv4(dscp=46, ecn=2, flags=2, seconds=1), ipv4(ecn=3, reverse=True, seconds=2),
                   ipv4(6, dscp=10, flags=1, seconds=3), ipv4(1, options=bytes.fromhex('01010100'), seconds=4),
                   ipv6_udp(seconds=5))
        arguments = dict(configuration=settings(), capture_session_id='ipv4-header', ground_truth=GroundTruth((), ()))
        actual = run_end_to_end_validation(MemoryPacketSource(sources), **arguments)
        with patch('analysis.flow_state_coordinator.update_directional_ipv4_header_statistics',
                   return_value=DirectionalIPv4HeaderStatistics()):
            baseline = run_end_to_end_validation(MemoryPacketSource(sources), **arguments)
        self.assertEqual(actual.report.metrics, baseline.report.metrics)
        self.assertEqual(actual.pipeline_result.packet_findings, baseline.pipeline_result.packet_findings)
        self.assertEqual(len(actual.pipeline_result.flow_findings), len(baseline.pipeline_result.flow_findings))
        observed = []
        for left, right in zip(actual.pipeline_result.flow_findings, baseline.pipeline_result.flow_findings):
            self.assertEqual(left.decision, right.decision)
            if left.detector_id != 'volume':
                continue
            left_state, right_state = left.raw_evidence.snapshot.coordinated_state, right.raw_evidence.snapshot.coordinated_state
            self.assertEqual(replace(left_state, ipv4_header_statistics=DirectionalIPv4HeaderStatistics()), right_state)
            observed.append((left_state.identity.ip_version, left_state.identity.protocol,
                             left_state.ipv4_header_statistics.forward.packet_count))
        self.assertEqual(sorted(observed), [(4, 6, 1), (4, 17, 1), (6, 17, 0)])

    def test_capture_sessions_match_across_all_classic_pcap_encodings(self):
        sources = (ipv4(dscp=46, ecn=2, flags=2, seconds=0), ipv4(dscp=0, ecn=3, reverse=True, seconds=1),
                   ipv4(6, dscp=10, flags=1, options=bytes.fromhex('01010100'), seconds=2),
                   ipv4(1, dscp=63, ecn=1, flags=4, seconds=3), ipv6_udp(seconds=4))
        expected = []
        run_flow_observation_session(MemoryPacketSource(sources), capture_session_id='ipv4-header',
                                     inactivity_timeout=timedelta(seconds=60), closed_window_consumer=expected.append)
        self.assertEqual([(window.identity.protocol, window.ipv4_header_statistics.forward.dscp_counts,
                           window.ipv4_header_statistics.reverse.ecn_counts, scalars(window.ipv4_header_statistics.forward))
                          for window in expected], [
            (17, ((46, 1),), ((3, 1),), (1, 0, 0, 0, 0)), (6, ((10, 1),), (), (0, 1, 0, 1, 4)),
            (1, ((63, 1),), (), (0, 0, 1, 0, 0)), (17, (), (), (0, 0, 0, 0, 0))])
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'ipv4-header.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    with self.subTest(order=order, nano=nano):
                        path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes)
                                                          for index, item in enumerate(sources)), order, nano))
                        source = PcapPacketSource(path)
                        actual = []
                        run_flow_observation_session(source, capture_session_id='ipv4-header',
                                                     inactivity_timeout=timedelta(seconds=60),
                                                     closed_window_consumer=actual.append)
                        self.assertEqual(actual, expected)
                        self.assertIsNone(source._file)

    def test_established_seed_timezone_replay_matrix(self):
        expected = replay_digest()
        script = 'from tests.test_ipv4_header_statistics import replay_digest; print(replay_digest())'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                actual = subprocess.check_output([sys.executable, '-B', '-c', script], cwd=Path(__file__).parents[1],
                                                 env=dict(os.environ, PYTHONHASHSEED=seed, TZ=zone), text=True).strip()
                self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
