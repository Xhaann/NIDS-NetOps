import gc
import hashlib
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import timedelta
from pathlib import Path
from struct import pack
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    DirectionalTCPOptionStatistics,
    FlowObservationWindowManager,
    FlowStateCoordinator,
    TCPOptionStatistics,
    analyze_packet,
    analyze_packet_outcome,
    extract_flow_feature_snapshot,
    flow_identity_from_packet,
    update_directional_tcp_option_statistics,
)
from analysis.flow_observation_window import FlowObservationWindow, FlowObservationWindowUpdate
from analysis.flow_state_coordinator import CoordinatedFlowState
from analysis.tcp import TCPDecodeError
from application import GroundTruth, run_end_to_end_validation, run_flow_observation_session
from capture import PcapPacketSource
from tests.pcap_scenarios import frame, pcap_bytes, transport
from tests.protocol_scenarios import observation
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_tcp_options import tcp_observation


def packet(options=b'', ipv6=False, reverse=False, seconds=0, protocol=6, flags=2):
    options += bytes(-len(options) % 4)
    raw = frame(protocol, transport(protocol, ipv6=ipv6, reverse=reverse, options=options, flags=flags),
                ipv6, reverse, extensions=(0, 60) if ipv6 else ())
    return analyze_packet(observation(raw, seconds))


def manager(timeout=5, capacity=1024):
    return FlowObservationWindowManager('tcp-option-statistics', timedelta(seconds=timeout),
                                        max_active_windows=capacity)


def reduce_packet(value=None, **arguments):
    analysis = packet(**arguments)
    return update_directional_tcp_option_statistics(value, analysis, flow_identity_from_packet(analysis))


def replay_digest():
    instance = manager(capacity=1)
    events = []
    cases = (
        dict(options=bytes.fromhex('020405b40303070402')),
        dict(options=bytes.fromhex('020400000303ff080a') + bytes(8), reverse=True, seconds=1),
        dict(options=bytes.fromhex('020400010202'), seconds=2),
        dict(options=bytes.fromhex('fe02fe02'), ipv6=True, seconds=3),
        dict(options=bytes.fromhex('0522') + bytes(32), ipv6=True, reverse=True, seconds=8),
    )
    for case in cases:
        update = instance.record(packet(**case))
        events.extend((w.key.sequence_number, w.closure_reason.value, asdict(w.tcp_option_statistics))
                      for w in update.closed_windows)
        events.append((update.active_window.key.sequence_number, None, asdict(update.active_window.tcp_option_statistics)))
    events.extend((w.key.sequence_number, w.closure_reason.value, asdict(w.tcp_option_statistics))
                  for w in instance.end_capture_session())
    return hashlib.sha256(repr(events).encode()).hexdigest()


class TCPOptionStatisticsTests(unittest.TestCase):
    def test_empty_and_minimal_tcp_and_udp(self):
        empty = TCPOptionStatistics()
        self.assertEqual(empty.complete_option_packet_count, 0)
        self.assertEqual(empty.timestamp_option_count, 0)
        self.assertEqual(empty.sack_permitted_option_count, 0)
        self.assertEqual(reduce_packet().forward, replace(empty, tcp_packet_count=1))
        value = DirectionalTCPOptionStatistics()
        self.assertIs(reduce_packet(value, protocol=17), value)
        self.assertEqual(manager().end_capture_session(), ())

    def test_representative_options_both_ip_versions_and_directions(self):
        options = bytes.fromhex('020405b40303070402080a') + pack('!II', 0xffffffff, 1)
        for ipv6 in (False, True):
            with self.subTest(ipv6=ipv6):
                value = reduce_packet(options=options, ipv6=ipv6)
                value = reduce_packet(value, options=options, ipv6=ipv6, reverse=True)
                self.assertEqual(value.forward, value.reverse)
                self.assertEqual(value.forward.option_kind_counts, ((0, 1), (2, 1), (3, 1), (4, 1), (8, 1)))
                self.assertEqual(value.forward.mss_value_counts, ((1460, 1),))
                self.assertEqual(value.forward.window_scale_counts, ((7, 1),))
                self.assertEqual(value.forward.timestamp_option_count, 1)
                self.assertEqual(value.forward.sack_permitted_option_count, 1)
                self.assertEqual(value.forward.total_option_bytes, 20)

    def test_wire_extremes_ordering_duplicates_and_non_syn_observations(self):
        options = bytes.fromhex('0204ffff0303ff020400000303000101fe02fe02')
        first = reduce_packet(options=options, flags=16)
        value = reduce_packet(first, options=options, flags=16).forward
        self.assertEqual(value.mss_value_counts, ((0, 2), (65535, 2)))
        self.assertEqual(value.window_scale_counts, ((0, 2), (255, 2)))
        self.assertEqual(value.duplicate_option_count, 6)
        self.assertEqual(value.option_kind_counts, ((1, 4), (2, 4), (3, 4), (254, 4)))
        self.assertEqual(first.forward.tcp_packet_count, 1)
        self.assertEqual(value.tcp_packet_count, 2)

    def test_maximum_area_count_sack_blocks_and_padding(self):
        value = reduce_packet(options=b'\x01' * 40).forward
        self.assertEqual(value.option_kind_counts, ((1, 40),))
        self.assertEqual(value.duplicate_option_count, 0)
        self.assertEqual(value.total_option_bytes, 40)
        self.assertEqual(reduce_packet(options=bytes(40)).forward.option_kind_counts, ((0, 1),))
        for blocks in range(1, 5):
            with self.subTest(blocks=blocks):
                options = bytes((5, 2 + blocks * 8)) + pack('!II', 0xffffffff, 0) * blocks
                value = reduce_packet(options=options).forward
                self.assertEqual(value.sack_block_count, blocks)
        value = reduce_packet(options=(bytes((5, 10)) + bytes(8)) * 4).forward
        self.assertEqual(value.sack_block_count, 4)
        self.assertEqual(value.duplicate_option_count, 3)

    def test_unknown_options_are_counted_without_body_interpretation(self):
        for kind in range(256):
            if kind in (0, 1, 2, 3, 4, 5, 8):
                continue
            with self.subTest(kind=kind):
                value = reduce_packet(options=bytes((kind, 40)) + bytes(range(38))).forward
                self.assertEqual(value.option_kind_counts, ((kind, 1),))
                self.assertEqual(value.malformed_option_packet_count, 0)
                self.assertEqual(value.total_option_bytes, 40)

    def test_known_invalid_lengths_discard_all_partial_measurements(self):
        valid = reduce_packet(options=bytes.fromhex('020405b4'))
        for kind, length in ((2, 2), (2, 5), (3, 2), (3, 4), (4, 3), (5, 2), (5, 9), (5, 11), (8, 2), (8, 11)):
            for ipv6 in (False, True):
                with self.subTest(kind=kind, length=length, ipv6=ipv6):
                    options = bytes.fromhex('02040001') + bytes((kind, length)) + bytes(length - 2)
                    analysis = packet(options, ipv6=ipv6)
                    self.assertTrue(analyze_packet_outcome(analysis.observation).succeeded)
                    result = update_directional_tcp_option_statistics(valid, analysis, flow_identity_from_packet(analysis))
                    self.assertEqual(result.forward, replace(valid.forward, tcp_packet_count=2, malformed_option_packet_count=1))

    def test_malformed_envelopes_and_truncated_headers_preserve_packet_outcomes(self):
        for ipv6 in (False, True):
            for options in (b'\x02\x00\x00\x00', b'\x00\x00\x01\x00', b'\x01\x01\x01\x02', b'\x02\x05\x00\x00'):
                with self.subTest(ipv6=ipv6, options=options):
                    outcome = analyze_packet_outcome(tcp_observation(ipv6, options))
                    self.assertEqual(outcome.failure_classification.value, 'structural_failure')
                    self.assertIsNone(outcome.analysis)
            source = tcp_observation(ipv6, b'\x01' * 40)
            raw = source.raw_bytes[:-8]
            outcome = analyze_packet_outcome(replace(source, raw_bytes=raw, captured_length=len(raw)))
            self.assertEqual(outcome.failure_classification.value, 'incomplete')
            self.assertIsNone(outcome.analysis)

    def test_fragment_and_unsupported_transport_boundaries_are_unchanged(self):
        for ipv6 in (False, True):
            source = tcp_observation(ipv6, bytes.fromhex('020405b4'), fragment=(0, True))
            analysis = analyze_packet(source)
            value = update_directional_tcp_option_statistics(None, analysis, flow_identity_from_packet(analysis))
            self.assertEqual(value.forward.mss_value_counts, ((1460, 1),))
            outcome = analyze_packet_outcome(tcp_observation(ipv6, fragment=(1, True)))
            if ipv6:
                self.assertIsNone(outcome.analysis.ipv6_tcp)
                with self.assertRaises(ValueError):
                    manager().record(outcome.analysis)
            else:
                self.assertEqual(outcome.failure_classification.value, 'unsupported')
        outcome = analyze_packet_outcome(replace(packet().observation, link_type=None))
        self.assertEqual(outcome.failure_classification.value, 'unsupported')

    def test_invalid_input_types_and_metadata_fail_before_publication(self):
        analysis = packet(bytes.fromhex('020405b4'))
        identity = flow_identity_from_packet(analysis)
        for current, source, key in (([], analysis, identity), (None, None, identity), (None, analysis, None)):
            with self.assertRaises(TypeError):
                update_directional_tcp_option_statistics(current, source, key)
        with self.assertRaises(ValueError):
            update_directional_tcp_option_statistics(None, analysis, replace(identity, source_port=1))
        for changes, error in (({'options': bytearray(4)}, TypeError), ({'data_offset': True}, TypeError),
                               ({'options': bytes(41)}, ValueError), ({'options': bytes(44)}, ValueError),
                               ({'options': bytes(8)}, ValueError), ({'data_offset': 16}, ValueError),
                               ({'options': b'\x02\x00\x00\x00'}, TCPDecodeError)):
            with self.subTest(changes=changes):
                bad = replace(analysis.tcp)
                for name, value in changes.items():
                    object.__setattr__(bad, name, value)
                coordinator = FlowStateCoordinator()
                with self.assertRaises(error):
                    coordinator.record(replace(analysis, tcp=bad))
                self.assertIsNone(coordinator.state)

    def test_statistics_construction_rejects_inconsistent_bounded_distributions(self):
        value = reduce_packet(options=bytes.fromhex('020405b4030307')).forward
        for changes in (
            {'tcp_packet_count': True}, {'tcp_packet_count': -1}, {'malformed_option_packet_count': 2},
            {'packets_with_options': 2}, {'total_option_bytes': 44}, {'total_option_bytes': 7},
            {'option_kind_counts': []}, {'option_kind_counts': ((256, 1),)},
            {'option_kind_counts': ((2, 1), (0, 1), (3, 1))},
            {'option_kind_counts': ((0, 1), (2, 1), (2, 1))},
            {'option_kind_counts': ((0, 1), (2, 0), (3, 1))},
            {'option_kind_counts': ((0, 1), (2, True), (3, 1))},
            {'mss_value_counts': ((65536, 1),)}, {'mss_value_counts': ((1, 2),)},
            {'window_scale_counts': ((256, 1),)}, {'sack_block_count': 1},
            {'duplicate_option_count': 1},
        ):
            with self.subTest(changes=changes), self.assertRaises((TypeError, ValueError)):
                replace(value, **changes)
        with self.assertRaises(ValueError):
            TCPOptionStatistics(option_kind_counts=((1, 1),) * 257)
        with self.assertRaises(TypeError):
            DirectionalTCPOptionStatistics(forward=None)

    def test_full_wire_domain_distributions_remain_bounded(self):
        mss = tuple((value, 1) for value in range(65536))
        value = TCPOptionStatistics(tcp_packet_count=65536, packets_with_options=65536,
                                    total_option_bytes=4 * 65536, option_kind_counts=((2, 65536),),
                                    mss_value_counts=mss)
        result = reduce_packet(DirectionalTCPOptionStatistics(forward=value), options=bytes.fromhex('0204ffff')).forward
        self.assertEqual(len(result.mss_value_counts), 65536)
        self.assertEqual(result.mss_value_counts[-1], (65535, 2))
        scales = tuple((value, 1) for value in range(256))
        value = TCPOptionStatistics(tcp_packet_count=256, packets_with_options=256,
                                    total_option_bytes=4 * 256, option_kind_counts=((0, 256), (3, 256)),
                                    window_scale_counts=scales)
        result = reduce_packet(DirectionalTCPOptionStatistics(forward=value), options=bytes.fromhex('0303ff')).forward
        self.assertEqual(len(result.window_scale_counts), 256)
        self.assertEqual(result.window_scale_counts[-1], (255, 2))

    def test_immutability_and_source_release(self):
        analysis = packet(bytes.fromhex('020405b4'))
        references = tuple(weakref.ref(item) for item in (analysis, analysis.tcp, analysis.observation, analysis.observation.source))
        instance = manager()
        window = instance.record(analysis).active_window
        statistics = window.tcp_option_statistics
        with self.assertRaises(FrozenInstanceError):
            statistics.forward.tcp_packet_count = 9
        with self.assertRaises(FrozenInstanceError):
            statistics.forward = TCPOptionStatistics()
        del analysis
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertIs(extract_flow_feature_snapshot(window).coordinated_state.tcp_option_statistics, statistics)

    def test_failed_publication_and_repeated_retry_are_atomic(self):
        for target in (CoordinatedFlowState, FlowObservationWindowUpdate):
            instance = manager()
            source = packet(bytes.fromhex('020405b4'))
            first = instance.record(source).active_window
            later = packet(bytes.fromhex('030307'), seconds=1)
            for _ in range(2):
                with patch.object(target, '__post_init__', side_effect=MemoryError('publication')):
                    with self.assertRaises(MemoryError):
                        instance.record(later)
                self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
            accepted = instance.record(later).active_window
            self.assertEqual(accepted.tcp_option_statistics.forward.tcp_packet_count, 2)
            repeated = instance.record(later).active_window
            self.assertEqual(repeated.tcp_option_statistics.forward.tcp_packet_count, 3)
            self.assertEqual(repeated.tcp_option_statistics.forward.window_scale_counts, ((7, 2),))
            self.assertEqual(first.tcp_option_statistics.forward.window_scale_counts, ())

    def test_initial_reducer_failure_has_no_window_or_sequence_side_effect(self):
        instance = manager()
        with patch('analysis.tcp_option_statistics._merge_bins', side_effect=MemoryError('allocation')):
            with self.assertRaises(MemoryError):
                instance.record(packet(bytes.fromhex('020405b4')))
        self.assertEqual(instance.active_windows(), ())
        window = instance.record(packet()).active_window
        self.assertEqual(window.key.sequence_number, 0)
        self.assertEqual(window.tcp_option_statistics.forward.tcp_packet_count, 1)

    def test_all_closures_preserve_statistics_and_reset_new_windows(self):
        for reason in ('explicit_segmentation', 'inactivity', 'capacity', 'capture_session_end'):
            with self.subTest(reason=reason):
                instance = manager(capacity=1)
                first = instance.record(packet(bytes.fromhex('020405b4'))).active_window
                if reason == 'explicit_segmentation':
                    closed = instance.close(first.identity)
                elif reason == 'inactivity':
                    update = instance.record(packet(bytes.fromhex('030307'), seconds=5))
                    closed, = update.closed_windows
                    self.assertEqual(update.active_window.tcp_option_statistics.forward.mss_value_counts, ())
                elif reason == 'capacity':
                    update = instance.record(packet(ipv6=True, seconds=1))
                    closed, = update.closed_windows
                    self.assertEqual(update.active_window.tcp_option_statistics.forward.mss_value_counts, ())
                else:
                    closed, = instance.end_capture_session()
                    self.assertEqual(instance.end_capture_session(), ())
                    with self.assertRaises(ValueError):
                        instance.record(packet())
                self.assertEqual(closed.closure_reason.value, reason)
                self.assertIs(closed.tcp_option_statistics, first.tcp_option_statistics)

    def test_closure_failure_preserves_active_state_and_retry_is_single(self):
        instance = manager()
        first = instance.record(packet(bytes.fromhex('020405b4'))).active_window
        with patch.object(FlowObservationWindow, '__post_init__', side_effect=MemoryError('closure')):
            with self.assertRaises(MemoryError):
                instance.end_capture_session()
        self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
        closed, = instance.end_capture_session()
        self.assertEqual(closed.tcp_option_statistics.forward.tcp_packet_count, 1)
        self.assertEqual(instance.end_capture_session(), ())

    def test_replacement_publication_failure_preserves_capacity_and_inactivity_windows(self):
        for capacity in (False, True):
            with self.subTest(capacity=capacity):
                instance = manager(capacity=1)
                first = instance.record(packet(bytes.fromhex('020405b4'))).active_window
                incoming = packet(bytes.fromhex('030307'), ipv6=capacity, seconds=5)
                with patch.object(FlowObservationWindowUpdate, '__post_init__', side_effect=MemoryError('replacement')):
                    with self.assertRaises(MemoryError):
                        instance.record(incoming)
                self.assertIs(instance.active_windows()[0].coordinated_state, first.coordinated_state)
                update = instance.record(incoming)
                closed, = update.closed_windows
                self.assertIs(closed.tcp_option_statistics, first.tcp_option_statistics)
                self.assertEqual(update.active_window.key.sequence_number, 1)
                self.assertEqual(update.active_window.tcp_option_statistics.forward.tcp_packet_count, 1)
                self.assertEqual(update.active_window.tcp_option_statistics.forward.mss_value_counts, ())

    def test_capture_and_consumer_failures_keep_normal_finalization(self):
        failure = RuntimeError('capture')
        source = MemoryPacketSource((packet(bytes.fromhex('020405b4')).observation,), iteration_error=failure)
        closed = []
        with self.assertRaises(RuntimeError) as caught:
            run_flow_observation_session(source, capture_session_id='options', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=closed.append)
        self.assertIs(caught.exception, failure)
        self.assertTrue(source.stopped)
        self.assertEqual(len(closed), 1)
        self.assertEqual(closed[0].tcp_option_statistics.forward.mss_value_counts, ((1460, 1),))
        source = MemoryPacketSource((packet().observation, packet(ipv6=True, seconds=1).observation))
        delivered = []

        def fail(window):
            delivered.append(window)
            raise failure

        with self.assertRaises(RuntimeError) as caught:
            run_flow_observation_session(source, capture_session_id='options', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=fail, max_active_windows=1)
        self.assertIs(caught.exception, failure)
        self.assertTrue(source.stopped)
        self.assertEqual(len(delivered), 1)
        self.assertEqual(delivered[0].tcp_option_statistics.forward.tcp_packet_count, 1)

    def test_real_session_and_four_pcap_encodings_match_every_statistic(self):
        sources = tuple(packet(options, ipv6, reverse, seconds=index).observation
                        for index, (options, ipv6, reverse) in enumerate((
                            (bytes.fromhex('020405b4030307'), False, False),
                            (bytes.fromhex('0402080a') + bytes(8), False, True),
                            (bytes.fromhex('02040000fe02fe02'), True, False),
                            (bytes.fromhex('020202040001'), True, True))))
        expected = []
        run_flow_observation_session(MemoryPacketSource(sources), capture_session_id='options',
                                     inactivity_timeout=timedelta(seconds=60), closed_window_consumer=expected.append)
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'tcp-options.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    with self.subTest(order=order, nano=nano):
                        path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes)
                                                         for index, item in enumerate(sources)), order, nano))
                        closed = []
                        source = PcapPacketSource(path)
                        run_flow_observation_session(source, capture_session_id='options',
                                                     inactivity_timeout=timedelta(seconds=60), closed_window_consumer=closed.append)
                        self.assertEqual(closed, expected)
                        self.assertIsNone(source._file)

    def test_packet_failure_does_not_refresh_flows_and_detection_stays_separate(self):
        valid = packet(bytes.fromhex('020405b4')).observation
        invalid = replace(tcp_observation(False, b'\x02\xff\x00\x00'), captured_at=valid.captured_at + timedelta(seconds=4))
        later = packet(bytes.fromhex('030307'), seconds=5).observation
        result = run_end_to_end_validation(MemoryPacketSource((valid, invalid, later)), configuration=settings(),
                                           capture_session_id='options', ground_truth=GroundTruth((), ()))
        self.assertEqual([finding.decision.value for finding in result.pipeline_result.packet_findings],
                         ['no_match', 'match', 'no_match'])
        snapshots = [finding.raw_evidence.snapshot for finding in result.pipeline_result.flow_findings if finding.detector_id == 'volume']
        self.assertEqual(len(snapshots), 2)
        self.assertEqual([s.coordinated_state.tcp_option_statistics.forward.tcp_packet_count for s in snapshots], [1, 1])
        self.assertEqual(snapshots[0].observation_window.closure_reason.value, 'inactivity')

    def test_existing_tls_dns_and_ldap_results_coexist(self):
        from tests.test_dns_packet_analysis import dns_packet
        from tests.test_dns import header
        from tests.test_tls_server_hello import body
        from tests.test_tls_handshake_framing import message
        from tests.test_tls_record_framing import wire
        from tests.test_tls_record_lifecycle import packet as tls_packet
        sources = (dns_packet(header()), tls_packet(wire(message(body(), 2), 22)))
        instance = manager()
        for source in sources:
            window = instance.record(analyze_packet(source)).active_window
            if window.identity.protocol == 17:
                self.assertEqual(window.tcp_option_statistics, DirectionalTCPOptionStatistics())
                self.assertIsNotNone(window.dns_correlation_state)
            else:
                self.assertEqual(window.tcp_option_statistics.forward.tcp_packet_count, 1)
                self.assertEqual(window.tls_server_hello_statistics.forward.total_server_hello_count, 1)
        from tests.test_ldap_flow_statistics import ldap_observation
        from tests.test_ldap import message as ldap_message
        window = instance.record(analyze_packet(ldap_observation(
            ldap_message(), options=bytes.fromhex('020405b4'),
        ))).active_window
        self.assertEqual(window.coordinated_state.ldap_statistics.complete_message_count, 1)
        self.assertEqual(window.tcp_option_statistics.forward.mss_value_counts, ((1460, 1),))

    def test_seed_timezone_replay(self):
        expected = replay_digest()
        script = 'from tests.test_tcp_option_statistics import replay_digest; print(replay_digest())'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                actual = subprocess.check_output([sys.executable, '-B', '-c', script],
                                                 cwd=Path(__file__).parents[1],
                                                 env=dict(os.environ, PYTHONHASHSEED=seed, TZ=zone), text=True).strip()
                self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
