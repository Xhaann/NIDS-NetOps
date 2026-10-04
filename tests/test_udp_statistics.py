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
    DirectionalUDPStatistics,
    FlowIdentityError,
    FlowStateCoordinator,
    IPv4Packet,
    IPv6Packet,
    UDP_MAX_PAYLOAD_LENGTH,
    UDPPacket,
    UDPStatistics,
    analyze_packet,
    analyze_packet_outcome,
    extract_flow_feature_snapshot,
    flow_identity_from_packet,
    update_directional_udp_statistics,
)
from analysis.flow_direction import FlowDirectionError
from analysis.flow_observation_window import FlowObservationWindow, FlowObservationWindowUpdate
from analysis.flow_state_coordinator import CoordinatedFlowState
from application import GroundTruth, run_end_to_end_validation, run_flow_observation_session
from capture import PcapPacketSource
from tests.pcap_scenarios import frame, pcap_bytes, transport
from tests.protocol_scenarios import observation
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_icmp_flow_admission import icmp4, icmp6, manager, tcp
from tests.test_ipv4_options import with_options
from tests.test_ipv6_transport import observation_for


def datagram(payload=b'data', ipv6=False, reverse=False, seconds=0, surplus=b'', zero_checksum=False,
             extensions=(), fragment=None):
    segment = transport(17, payload, ipv6, reverse)
    if zero_checksum:
        segment = segment[:6] + b'\x00\x00' + segment[8:]
    return observation(frame(17, segment + surplus, ipv6, reverse, extensions, fragment), seconds)


def update(current, analysis, identity=None):
    identity = flow_identity_from_packet(analysis) if identity is None else identity
    return update_directional_udp_statistics(current, analysis, identity)


def record(sources):
    instance = manager()
    window = None
    for index, source in enumerate(sources):
        source = replace(source, captured_at=source.captured_at + timedelta(milliseconds=index))
        window = instance.record(analyze_packet(source)).active_window
    return window.udp_statistics


def tampered(value, **changes):
    copy = replace(value)
    for name, item in changes.items():
        object.__setattr__(copy, name, item)
    return copy


def side(value):
    return (value.datagram_count, value.empty_payload_datagram_count, value.min_payload_length, value.max_payload_length,
            value.total_payload_length, value.trailing_surplus_datagram_count,
            value.total_trailing_surplus_length)


def summarize(value):
    return asdict(value), tuple(item.nonempty_payload_datagram_count for item in (value.forward, value.reverse))


def replay_digest():
    instance = manager(capacity=3)
    events = []
    for source in (datagram(b'query', seconds=0), datagram(b'response!', reverse=True, seconds=1),
                   datagram(b'', ipv6=True, seconds=2, zero_checksum=True), tcp(seconds=3),
                   datagram(b'x', seconds=4, surplus=bytes(5)), icmp4(seconds=5),
                   datagram(b'tail', ipv6=True, reverse=True, seconds=6, surplus=bytes(9), extensions=(0, 60)),
                   datagram(bytes(300), seconds=7), datagram(b'late', seconds=20)):
        result = instance.record(analyze_packet(source))
        events.extend((window.key.sequence_number, window.closure_reason.value, summarize(window.udp_statistics))
                      for window in result.closed_windows)
        events.append((result.active_window.key.sequence_number, None, summarize(result.active_window.udp_statistics)))
    closed = instance.close(instance.active_windows()[0].identity)
    events.append((closed.key.sequence_number, closed.closure_reason.value, summarize(closed.udp_statistics)))
    events.extend((window.key.sequence_number, window.closure_reason.value, summarize(window.udp_statistics))
                  for window in instance.end_capture_session())
    return hashlib.sha256(repr(events).encode()).hexdigest()


class UDPStatisticsTests(unittest.TestCase):
    def test_empty_aggregate_and_non_udp_flows(self):
        empty = UDPStatistics()
        self.assertEqual(side(empty), (0, 0, None, None, 0, 0, 0))
        self.assertEqual(empty.nonempty_payload_datagram_count, 0)
        self.assertEqual(DirectionalUDPStatistics(), DirectionalUDPStatistics(empty, empty))
        for source in (tcp(), tcp(ipv6=True), icmp4(), icmp6()):
            analysis = analyze_packet(source)
            current = update(None, analysis)
            self.assertEqual(current, DirectionalUDPStatistics())
            self.assertIs(update(current, analysis), current)
            self.assertEqual(manager().record(analysis).active_window.udp_statistics, DirectionalUDPStatistics())

    def test_single_datagram_records_udp_length_structure_for_both_families(self):
        for ipv6, extensions, fragment in ((False, (), None), (True, (), None), (True, (0, 60), None),
                                           (True, (), (0, False)), (True, (43,), (0, True))):
            with self.subTest(ipv6=ipv6, extensions=extensions, fragment=fragment):
                value = record((datagram(b'payload', ipv6, extensions=extensions, fragment=fragment),))
                self.assertEqual(side(value.forward), (1, 0, 7, 7, 7, 0, 0))
                self.assertEqual(value.reverse, UDPStatistics())
        options = with_options(datagram(b'payload'), bytes.fromhex('01010100'))
        self.assertEqual(analyze_packet(options).ipv4.header_length, 24)
        self.assertEqual(side(record((options,)).forward), (1, 0, 7, 7, 7, 0, 0))

    def test_directions_accumulate_separately_and_repeats_count(self):
        for ipv6 in (False, True):
            with self.subTest(ipv6=ipv6):
                value = record((datagram(b'hello', ipv6), datagram(b'', ipv6), datagram(bytes(300), ipv6),
                                datagram(b'reply123', ipv6, reverse=True), datagram(b'hello', ipv6)))
                self.assertEqual(side(value.forward), (4, 1, 0, 300, 310, 0, 0))
                self.assertEqual(value.forward.nonempty_payload_datagram_count, 3)
                self.assertEqual(side(value.reverse), (1, 0, 8, 8, 8, 0, 0))
                identity = flow_identity_from_packet(analyze_packet(datagram(ipv6=ipv6)))
                self.assertEqual(identity, flow_identity_from_packet(analyze_packet(datagram(ipv6=ipv6, reverse=True))))

    def test_payload_length_boundaries(self):
        for ipv6, maximum in ((False, 65507), (True, UDP_MAX_PAYLOAD_LENGTH)):
            with self.subTest(ipv6=ipv6):
                source = datagram(bytes(maximum), ipv6)
                self.assertTrue(analyze_packet_outcome(source).succeeded)
                value = record((datagram(b'', ipv6), source))
                self.assertEqual(side(value.forward), (2, 1, 0, maximum, maximum, 0, 0))
        all_empty = record((datagram(b''), datagram(b'')))
        self.assertEqual((all_empty.forward.min_payload_length, all_empty.forward.max_payload_length), (0, 0))

    def test_statistics_are_independent_of_checksum_fields_results_and_payload_content(self):
        for ipv6 in (False, True):
            with self.subTest(ipv6=ipv6):
                zero = datagram(b'nochecksum', ipv6, zero_checksum=True)
                outcome = analyze_packet_outcome(zero)
                self.assertTrue(outcome.succeeded)
                analysis = outcome.analysis
                field = 'ipv6_udp' if ipv6 else 'udp'
                self.assertEqual(getattr(analysis, field).checksum, 0)
                baseline = update(None, analyze_packet(datagram(b'nochecksum', ipv6)))
                self.assertEqual(update(None, analysis), baseline)
                changed = replace(analysis, **{field: replace(getattr(analysis, field), checksum=1234,
                                                             payload=b'\xff' * 10)})
                if not ipv6:
                    changed = replace(changed, udp_checksum_valid=True, ipv4_checksum_valid=False)
                self.assertEqual(update(None, changed), baseline)
        result = run_end_to_end_validation(MemoryPacketSource((datagram(b'nochecksum', zero_checksum=True),)),
                                           configuration=settings(), capture_session_id='udp', ground_truth=GroundTruth((), ()))
        statistics = result.pipeline_result.flow_findings[0].raw_evidence.snapshot.coordinated_state.udp_statistics
        self.assertEqual(side(statistics.forward), (1, 0, 10, 10, 10, 0, 0))

    def test_trailing_ip_payload_beyond_udp_length_is_measured(self):
        for ipv6, extensions in ((False, ()), (True, ()), (True, (0, 43, 60))):
            with self.subTest(ipv6=ipv6, extensions=extensions):
                source = datagram(b'data', ipv6, surplus=b'hidden', extensions=extensions)
                analysis = analyze_packet(source)
                udp = analysis.ipv6_udp if ipv6 else analysis.udp
                self.assertEqual((udp.length, udp.payload), (12, b'data'))
                value = record((source, datagram(b'data', ipv6, extensions=extensions),
                                datagram(b'', ipv6, surplus=bytes(37), extensions=extensions)))
                self.assertEqual(side(value.forward), (3, 1, 0, 4, 8, 2, 43))
        options = with_options(datagram(b'data', surplus=b'xy'), bytes.fromhex('01010100'))
        self.assertEqual(record((options,)).forward.total_trailing_surplus_length, 2)
        largest = datagram(b'', True, surplus=bytes(UDP_MAX_PAYLOAD_LENGTH))
        self.assertEqual(analyze_packet(largest).ipv6.payload_length, 65535)
        value = record((largest,))
        self.assertEqual(side(value.forward), (1, 1, 0, 0, 0, 1, UDP_MAX_PAYLOAD_LENGTH))

    def test_construction_enforces_types_bounds_and_consistency(self):
        valid = UDPStatistics(4, 1, 0, 300, 310, 1, 5)
        self.assertEqual(valid.nonempty_payload_datagram_count, 3)
        huge = 10 ** 100
        self.assertEqual(UDPStatistics(huge, 0, 1, 1, huge, huge, huge).total_payload_length, huge)
        for name in (member.name for member in fields(valid)):
            for value, error in ((True, TypeError), (1.0, TypeError), ('1', TypeError), (-1, ValueError)):
                with self.subTest(name=name, value=value), self.assertRaises(error):
                    replace(valid, **{name: value})
        for changes, error in (
            (dict(min_payload_length=None), TypeError), (dict(max_payload_length=None), TypeError),
            (dict(max_payload_length=UDP_MAX_PAYLOAD_LENGTH + 1), ValueError), (dict(min_payload_length=301), ValueError),
            (dict(total_payload_length=1201), ValueError), (dict(total_payload_length=-1), ValueError),
            (dict(empty_payload_datagram_count=5), ValueError),
            (dict(trailing_surplus_datagram_count=5), ValueError), (dict(empty_payload_datagram_count=0), ValueError),
            (dict(min_payload_length=1, total_payload_length=310), ValueError),
            (dict(total_trailing_surplus_length=0), ValueError),
            (dict(total_trailing_surplus_length=UDP_MAX_PAYLOAD_LENGTH + 1), ValueError),
            (dict(empty_payload_datagram_count=4), ValueError),
        ):
            with self.subTest(changes=changes), self.assertRaises(error):
                replace(valid, **changes)
        for arguments in ((0, 0, 0, None), (0, 0, None, 0), (1, 0, None, None)):
            with self.subTest(arguments=arguments), self.assertRaises((TypeError, ValueError)):
                UDPStatistics(*arguments)
        with self.assertRaises(TypeError):
            DirectionalUDPStatistics(forward=None)
        with self.assertRaises(TypeError):
            DirectionalUDPStatistics(reverse=asdict(valid))

    def test_malformed_sources_and_identities_cannot_publish(self):
        v4 = analyze_packet(datagram(b'data'))
        v6 = analyze_packet(datagram(b'data', True, extensions=(0,)))
        identity = flow_identity_from_packet(v4)
        for current, analysis, key in (([], v4, identity), (UDPStatistics(), v4, identity), (None, None, identity),
                                       (None, v4, None), (None, v4, asdict(identity))):
            with self.assertRaises(TypeError):
                update_directional_udp_statistics(current, analysis, key)
        with self.assertRaises(FlowDirectionError):
            update(None, v4, replace(identity, source_port=1))
        cases = (
            (tampered(v4, udp=tampered(v4.udp, length=7)), ValueError),
            (tampered(v4, udp=tampered(v4.udp, length=65536)), ValueError),
            (tampered(v4, udp=tampered(v4.udp, length=True)), TypeError),
            (tampered(v4, udp=tampered(v4.udp, length=13)), ValueError),
            (tampered(v4, udp=None), TypeError),
            (tampered(v4, ipv4=object()), TypeError),
            (tampered(v6, ipv6_udp=tampered(v6.ipv6_udp, length=13)), ValueError),
            (tampered(v6, ipv6_extension_headers=replace(v6.ipv6_extension_headers, packet=replace(v6.ipv6))), ValueError),
            (tampered(v6, ipv6_extension_headers=object()), ValueError),
            (tampered(v6, ipv6=object()), TypeError),
        )
        for index, (analysis, error) in enumerate(cases):
            key = flow_identity_from_packet(v6 if analysis.ipv6 is not None else v4)
            with self.subTest(index=index), self.assertRaises(error):
                update(None, analysis, key)
        tcp_analysis = analyze_packet(tcp())
        with self.assertRaisesRegex(ValueError, 'non-UDP'):
            update(None, tampered(tcp_analysis, udp=v4.udp), flow_identity_from_packet(tcp_analysis))
        instance = manager()
        first = instance.record(v4).active_window
        for analysis in (cases[0][0], cases[3][0]):
            with self.assertRaises(ValueError):
                instance.record(analysis)
            self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
        with self.assertRaises(FlowIdentityError):
            instance.record(analyze_packet(observation_for(253, bytes(8))))
        self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)

    def test_reducer_reads_no_payload_raw_bytes_or_decoders(self):
        for source in (datagram(bytes(range(200)), surplus=b'tail'), datagram(bytes(64), True, extensions=(60,))):
            analysis = analyze_packet(source)
            identity = flow_identity_from_packet(analysis)
            expected = update(None, analysis, identity)
            with patch.object(UDPPacket, 'payload', new_callable=PropertyMock, create=True,
                              side_effect=AssertionError('UDP payload')), \
                    patch.object(IPv4Packet, 'payload', new_callable=PropertyMock, create=True,
                                 side_effect=AssertionError('IPv4 payload')), \
                    patch.object(IPv6Packet, 'payload', new_callable=PropertyMock, create=True,
                                 side_effect=AssertionError('IPv6 payload')), \
                    patch('analysis.udp.decode_udp', side_effect=AssertionError('decode')), \
                    patch('analysis.udp_checksum.validate_udp_checksum', side_effect=AssertionError('checksum')), \
                    patch('analysis.ipv6_extension_headers.validate_ipv6_extension_headers',
                          side_effect=AssertionError('chain')), \
                    patch.object(UDPPacket, '__post_init__', side_effect=AssertionError('rebuild')):
                self.assertEqual(update_directional_udp_statistics(None, analysis, identity), expected)
        contents = [record((datagram(payload),)) for payload in (bytes(100), b'\xff' * 100, bytes(range(100)))]
        self.assertEqual(contents, [contents[0]] * 3)

    def test_failed_candidates_and_publication_retry_count_once(self):
        for target in (CoordinatedFlowState, FlowObservationWindowUpdate):
            with self.subTest(target=target.__name__):
                instance = manager()
                first = instance.record(analyze_packet(datagram(b'query'))).active_window
                reply = analyze_packet(datagram(b'answer', reverse=True, seconds=1))
                for _ in range(2):
                    with patch.object(target, '__post_init__', side_effect=MemoryError('publication')):
                        with self.assertRaises(MemoryError):
                            instance.record(reply)
                    self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
                accepted = instance.record(reply).active_window.udp_statistics
                self.assertEqual(side(accepted.reverse), (1, 0, 6, 6, 6, 0, 0))
                repeated = instance.record(reply).active_window.udp_statistics
                self.assertEqual(side(repeated.reverse), (2, 0, 6, 6, 12, 0, 0))
                self.assertEqual(first.udp_statistics.reverse, UDPStatistics())
        instance = manager()
        with patch('analysis.udp_statistics._reduce', side_effect=MemoryError('allocation')):
            with self.assertRaises(MemoryError):
                instance.record(analyze_packet(datagram()))
        self.assertEqual(instance.active_windows(), ())
        retried = instance.record(analyze_packet(datagram())).active_window
        self.assertEqual((retried.key.sequence_number, retried.udp_statistics.forward.datagram_count), (0, 1))

    def test_every_closure_reason_preserves_aggregate_and_replacement_starts_empty(self):
        for reason in ('explicit_segmentation', 'capture_session_end', 'inactivity', 'capacity'):
            with self.subTest(reason=reason):
                instance = manager(capacity=1)
                instance.record(analyze_packet(datagram(b'one')))
                published = instance.record(analyze_packet(datagram(b'two!', reverse=True, seconds=1))).active_window
                if reason == 'explicit_segmentation':
                    closed = instance.close(published.identity)
                    replacement = instance.record(analyze_packet(datagram(b'three', seconds=2))).active_window
                elif reason == 'capture_session_end':
                    closed, = instance.end_capture_session()
                    replacement = None
                else:
                    later = datagram(b'three', seconds=7) if reason == 'inactivity' else datagram(b'three', True, seconds=2)
                    result = instance.record(analyze_packet(later))
                    closed, = result.closed_windows
                    replacement = result.active_window
                self.assertEqual(closed.closure_reason.value, reason)
                self.assertIs(closed.udp_statistics, published.udp_statistics)
                if replacement is not None:
                    self.assertEqual(side(replacement.udp_statistics.forward), (1, 0, 5, 5, 5, 0, 0))
                    self.assertEqual(replacement.udp_statistics.reverse, UDPStatistics())
        instance = manager()
        first = instance.record(analyze_packet(datagram())).active_window
        with patch.object(FlowObservationWindow, '__post_init__', side_effect=MemoryError('closure')):
            with self.assertRaises(MemoryError):
                instance.end_capture_session()
        closed, = instance.end_capture_session()
        self.assertIs(closed.udp_statistics, first.udp_statistics)

    def test_immutability_snapshot_stability_and_bounded_retained_state(self):
        instance = manager()
        first = instance.record(analyze_packet(datagram(b'abc'))).active_window
        snapshot = extract_flow_feature_snapshot(first)
        statistics = snapshot.coordinated_state.udp_statistics
        with self.assertRaises(FrozenInstanceError):
            statistics.forward = UDPStatistics()
        with self.assertRaises(FrozenInstanceError):
            statistics.forward.datagram_count = 9
        for index in range(1, 2049):
            window = instance.record(analyze_packet(datagram(bytes(index % 700), seconds=index / 1000,
                                                             surplus=bytes(index % 3)))).active_window
        self.assertEqual(side(statistics.forward), (1, 0, 3, 3, 3, 0, 0))
        current = window.udp_statistics.forward
        self.assertEqual(current.datagram_count, 2049)
        self.assertEqual(tuple(vars(current)), tuple(member.name for member in fields(UDPStatistics)))
        self.assertTrue(all(value is None or type(value) is int for value in vars(current).values()))
        self.assertEqual(tuple(vars(window.udp_statistics)), ('forward', 'reverse'))

    def test_published_statistics_release_packet_and_model_sources(self):
        for ipv6 in (False, True):
            source = analyze_packet(datagram(b'release', ipv6))
            model = source.ipv6_udp if ipv6 else source.udp
            network = source.ipv6 if ipv6 else source.ipv4
            references = tuple(weakref.ref(item) for item in (source, model, network, source.observation))
            state = FlowStateCoordinator().record(source)
            del source, model, network
            gc.collect()
            self.assertTrue(all(reference() is None for reference in references))
            self.assertEqual(side(state.udp_statistics.forward), (1, 0, 7, 7, 7, 0, 0))

    def test_detection_and_other_flow_results_are_unchanged(self):
        sources = (datagram(b'query', seconds=1), datagram(b'answer', reverse=True, seconds=2, zero_checksum=True),
                   tcp(seconds=3), icmp4(seconds=4), datagram(b'v6', True, seconds=5, surplus=b'pad'),
                   datagram(b'v6!', True, reverse=True, seconds=6))
        arguments = dict(configuration=settings(), capture_session_id='udp', ground_truth=GroundTruth((), ()))
        actual = run_end_to_end_validation(MemoryPacketSource(sources), **arguments)
        with patch('analysis.flow_state_coordinator.update_directional_udp_statistics',
                   return_value=DirectionalUDPStatistics()):
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
            self.assertEqual(replace(left_state, udp_statistics=DirectionalUDPStatistics()), right_state)
            observed.append((left_state.identity.protocol, left_state.udp_statistics))
        self.assertEqual(sorted((protocol, side(value.forward), side(value.reverse)) for protocol, value in observed), [
            (6, side(UDPStatistics()), side(UDPStatistics())),
            (17, (1, 0, 2, 2, 2, 1, 3), (1, 0, 3, 3, 3, 0, 0)),
            (17, (1, 0, 5, 5, 5, 0, 0), (1, 0, 6, 6, 6, 0, 0)),
        ])

    def test_capture_sessions_match_across_all_classic_pcap_encodings(self):
        sources = (datagram(b'query', seconds=0), datagram(b'response', reverse=True, seconds=1),
                   datagram(b'', True, seconds=2, zero_checksum=True), datagram(b'x', True, reverse=True, seconds=3, surplus=bytes(7)),
                   tcp(seconds=4), icmp6(seconds=5))
        expected = []
        run_flow_observation_session(MemoryPacketSource(sources), capture_session_id='udp-statistics',
                                     inactivity_timeout=timedelta(seconds=60), closed_window_consumer=expected.append)
        self.assertEqual([(window.identity.protocol, side(window.udp_statistics.forward), side(window.udp_statistics.reverse))
                          for window in expected], [
            (17, (1, 0, 5, 5, 5, 0, 0), (1, 0, 8, 8, 8, 0, 0)),
            (17, (1, 1, 0, 0, 0, 0, 0), (1, 0, 1, 1, 1, 1, 7)),
            (6, side(UDPStatistics()), side(UDPStatistics())), (58, side(UDPStatistics()), side(UDPStatistics()))])
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'udp-statistics.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    with self.subTest(order=order, nano=nano):
                        path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes)
                                                          for index, item in enumerate(sources)), order, nano))
                        source = PcapPacketSource(path)
                        actual = []
                        run_flow_observation_session(source, capture_session_id='udp-statistics',
                                                     inactivity_timeout=timedelta(seconds=60),
                                                     closed_window_consumer=actual.append)
                        self.assertEqual(actual, expected)
                        self.assertIsNone(source._file)

    def test_established_seed_timezone_replay_matrix(self):
        expected = replay_digest()
        script = 'from tests.test_udp_statistics import replay_digest; print(replay_digest())'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                actual = subprocess.check_output([sys.executable, '-B', '-c', script], cwd=Path(__file__).parents[1],
                                                 env=dict(os.environ, PYTHONHASHSEED=seed, TZ=zone), text=True).strip()
                self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
