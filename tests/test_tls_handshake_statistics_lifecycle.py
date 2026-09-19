import gc
import hashlib
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import fields, replace
from datetime import timedelta
from fractions import Fraction
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import analysis.flow_state_coordinator as coordinator_module
import analysis.tls_handshake_statistics as statistics_module
from analysis import (
    DirectionalTLSHandshakeStatistics, FeatureContractVersion, FlowObservationWindowClosureReason,
    FlowObservationWindowError, FlowObservationWindowManager, FlowStateCoordinator, TCPStreamStatus,
    analyze_packet, extract_flow_feature_snapshot, update_directional_tls_handshake_statistics,
)
from application import run_flow_observation_session
from capture import CaptureError, PcapPacketSource
from ml import project_flow_features
from tests.pcap_scenarios import pcap_bytes
from tests.test_dns_correlation_lifecycle import manager
from tests.test_dns_stream_lifecycle import raw, framed
from tests.test_dns_transaction_statistics_lifecycle import run_packets
from tests.test_flow_feature_snapshot import snapshot_features
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ldap import message as ldap_message
from tests.test_tls_handshake_framing import message
from tests.test_tls_handshake_lifecycle import traffic as handshake_traffic
from tests.test_tls_handshake_statistics import altered
from tests.test_tls_record_framing import packet, wire


def record(instance, data, **kwargs):
    return instance.record(analyze_packet(packet(data, **kwargs))).active_window


def traffic():
    forward = b''.join(message(bytes((kind,)) * (kind % 5), kind) for kind in range(256))
    reverse = b''.join(message(bytes((kind,)) * (kind % 3), kind) for kind in reversed(range(256)))
    return handshake_traffic() + (packet(wire(forward, 22), client_port=12347, seconds=12),
                                  packet(wire(reverse, 22), client_port=12347, reverse=True, sequence=900, seconds=13))


def observable(window):
    return (window.key.sequence_number, window.identity.ip_version, window.identity.source_port,
            None if window.closure_reason is None else window.closure_reason.value,
            (window.tls_handshake_statistics.forward.mean_message_length,
             window.tls_handshake_statistics.reverse.mean_message_length),
            tuple(None if value is None or value.unavailable_reason is None else value.unavailable_reason.value
                  for value in (window.tls_handshake_state.forward, window.tls_handshake_state.reverse)),
            window.tls_handshake_statistics)


def replay():
    instance = FlowObservationWindowManager('tls-statistics', timedelta(seconds=60), max_active_windows=4)
    events, references = [], []
    sources = traffic() + (packet(b'gap', sequence=5000, seconds=14),
                           packet(wire(b'\x01', 22), client_port=12348, seconds=15))
    for source in sources:
        update = instance.record(analyze_packet(source))
        references.append(weakref.ref(update.active_window.tls_handshake_state))
        events.extend(observable(window) for window in (update.active_window,) + update.closed_windows)
    events.extend(observable(window) for window in instance.end_capture_session())
    del update, instance
    gc.collect()
    return tuple(events), tuple(ref() is None for ref in references)


class TLSHandshakeStatisticsLifecycleTests(unittest.TestCase):
    def test_incremental_partial_later_completion_and_retransmission(self):
        instance = manager()
        data = message(b'abc', 7)
        before = record(instance, wire(message(b'', 1) + message(b'ab', 2) + data[:5], 22))
        stats = before.tls_handshake_statistics.forward
        self.assertEqual((stats.total_message_count, stats.zero_length_message_count, stats.total_message_length_bytes), (2, 1, 2))
        sequence = 100 + len(wire(message(b'', 1) + message(b'ab', 2) + data[:5], 22))
        final_data = wire(data[5:], 22)
        after = record(instance, final_data, sequence=sequence)
        duplicate = record(instance, final_data, sequence=sequence)
        final = after.tls_handshake_statistics.forward
        self.assertEqual((final.total_message_count, final.total_message_length_bytes, final.mean_message_length), (3, 5, Fraction(5, 3)))
        self.assertEqual(duplicate.tls_handshake_statistics, after.tls_handshake_statistics)
        self.assertEqual(stats.total_message_count, 2)

    def test_one_byte_tcp_segmentation_counts_only_complete_handshake(self):
        data = wire(message(b'abc'), 22)
        instance = manager()
        for index, byte in enumerate(data):
            active = record(instance, bytes((byte,)), sequence=100 + index)
            self.assertEqual(active.tls_handshake_statistics.forward.total_message_count, int(index == len(data) - 1))

    def test_real_session_cross_record_coalesced_and_directional_statistics(self):
        windows = run_packets(handshake_traffic())
        self.assertEqual(len(windows), 3)
        self.assertEqual(len({window.identity for window in windows}), 3)
        for window in windows:
            value = window.tls_handshake_statistics
            self.assertEqual((value.forward.total_message_count, value.reverse.total_message_count), (2, 2))
            self.assertEqual((value.forward.total_message_length_bytes, value.reverse.total_message_length_bytes), (13, 7))
            self.assertEqual((value.forward.zero_length_message_count, value.reverse.zero_length_message_count), (0, 1))
            self.assertEqual(value.forward.handshake_type_counts[255], 1)
            self.assertEqual(value.reverse.handshake_type_counts[1], 2)

    def test_all_types_and_both_directions_through_session(self):
        windows = run_packets(traffic())
        window, = [value for value in windows if value.identity.source_port == 12347]
        value = window.tls_handshake_statistics
        for direction, modulus in ((value.forward, 5), (value.reverse, 3)):
            self.assertEqual(direction.handshake_type_counts, (1,) * 256)
            self.assertEqual(direction.total_message_count, 256)
            self.assertEqual(direction.total_message_length_bytes, sum(kind % modulus for kind in range(256)))
            self.assertEqual(direction.zero_length_message_count, sum(kind % modulus == 0 for kind in range(256)))

    def test_ipv6_extensions_and_both_service_orientations(self):
        for extensions in ((), (0,), (60,), (0, 43, 60)):
            for reverse in (False, True):
                window, = run_packets((packet(wire(message(b'abc'), 22), ipv6=True, reverse=reverse, extensions=extensions),))
                value = window.tls_handshake_statistics
                selected, other = (value.reverse, value.forward) if reverse else (value.forward, value.reverse)
                self.assertEqual(selected.total_message_count, 1)
                self.assertEqual(other.total_message_count, 0)
        window, = run_packets((packet(wire(message(b'a'), 22), port=12345, client_port=443),))
        self.assertEqual(window.tls_handshake_statistics.forward.total_message_count, 1)

    def test_ineligible_ports_and_ldap_dns_precedence_have_empty_statistics(self):
        for port in (80, 8443, 853):
            window, = run_packets((packet(wire(message(b'a'), 22), port=port),))
            self.assertEqual(window.tls_handshake_statistics, DirectionalTLSHandshakeStatistics())
        for port, data, name in ((389, ldap_message(), 'ldap_stream_state'), (53, framed(raw()), 'dns_stream_state')):
            for kwargs in ({'client_port': port}, {'port': port, 'client_port': 443}):
                state = FlowStateCoordinator().record(analyze_packet(packet(data, **kwargs)))
                self.assertIsNotNone(getattr(state, name))
                self.assertEqual(state.tls_handshake_statistics, DirectionalTLSHandshakeStatistics())

    def test_partial_and_oversized_frames_contribute_nothing(self):
        for data in (b'\x01', message(b'abc')[:-1], b'\x01\xff\xff\xff'):
            window, = run_packets((packet(wire(data, 22)),))
            self.assertEqual(window.tls_handshake_statistics, DirectionalTLSHandshakeStatistics())
        window, = run_packets((packet(wire(message(b'A') + b'\x01\xff\xff\xff', 22)),))
        self.assertEqual(window.tls_handshake_statistics.forward.total_message_count, 1)

    def test_tcp_failure_and_fin_reset_preserve_completed_counts(self):
        first_data = wire(message(b'A') + b'\x01', 22)
        for flags in (17, 20):
            window, = run_packets((packet(first_data, flags=flags),))
            self.assertEqual(window.tls_handshake_statistics.forward.total_message_count, 1)
        instance = manager()
        first = record(instance, first_data)
        after = record(instance, b'gap', sequence=1000)
        self.assertIs(after.tls_handshake_state.forward.unavailable_reason, TCPStreamStatus.GAP)
        self.assertIs(after.tls_handshake_statistics, first.tls_handshake_statistics)
        closed = instance.close(after.identity)
        self.assertEqual(closed.tls_handshake_statistics.forward.total_message_count, 1)

    def test_explicit_closure_and_repeated_finalization_preserve_exact_aggregate(self):
        instance = manager()
        before = record(instance, wire(message(b'A') + b'\x01', 22))
        closed = instance.close(before.identity)
        self.assertIs(closed.tls_handshake_statistics, before.tls_handshake_statistics)
        self.assertIs(closed.closure_reason, FlowObservationWindowClosureReason.EXPLICIT_SEGMENTATION)
        for _ in range(4):
            self.assertIs(replace(closed).tls_handshake_statistics, closed.tls_handshake_statistics)
        with self.assertRaises(FlowObservationWindowError):
            instance.close(before.identity)
        self.assertEqual(instance.end_capture_session(), ())
        self.assertEqual(instance.end_capture_session(), ())

    def test_empty_finalization_and_empty_observed_flow(self):
        instance = manager()
        self.assertEqual(instance.end_capture_session(), ())
        window, = run_packets((packet(wire(b'', 22)),))
        self.assertEqual(window.tls_handshake_statistics, DirectionalTLSHandshakeStatistics())
        self.assertIsNone(window.tls_handshake_statistics.forward.mean_message_length)

    def test_capacity_inactivity_and_reopened_flow_are_independent(self):
        for capacity, kwargs, reason in ((1, {'ipv6': True}, FlowObservationWindowClosureReason.CAPACITY),
                                         (2, {'seconds': 5}, FlowObservationWindowClosureReason.INACTIVITY)):
            instance = manager(capacity)
            first = record(instance, wire(message(b'A') + b'\x01', 22))
            update = instance.record(analyze_packet(packet(wire(message(b'BB'), 22), sequence=100, **kwargs)))
            closed, = update.closed_windows
            self.assertIs(closed.closure_reason, reason)
            self.assertEqual(closed.tls_handshake_statistics.forward.total_message_length_bytes, 1)
            self.assertEqual(update.active_window.tls_handshake_statistics.forward.total_message_length_bytes, 2)
            instance.close(update.active_window.identity)
            reopened = record(instance, wire(message(b'CCC'), 22), seconds=6)
            self.assertEqual(reopened.tls_handshake_statistics.forward.total_message_count, 1)

    def test_late_aggregation_failure_does_not_publish_partial_counts(self):
        instance = manager()
        before = record(instance, wire(message(b'A'), 22))
        calls = 0
        def reduce(current, source):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise MemoryError('second aggregate')
            return update_directional_tls_handshake_statistics(current, source)
        data = wire(message(b'BB') + message(b'CCC'), 22)
        with patch.object(coordinator_module, 'update_directional_tls_handshake_statistics', side_effect=reduce):
            with self.assertRaises(MemoryError):
                record(instance, data, sequence=110)
        self.assertEqual(calls, 2)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        after = record(instance, data, sequence=110)
        duplicate = record(instance, data, sequence=110)
        self.assertEqual(after.tls_handshake_statistics.forward.total_message_count, 3)
        self.assertEqual(after.tls_handshake_statistics.forward.total_message_length_bytes, 6)
        self.assertEqual(duplicate.tls_handshake_statistics, after.tls_handshake_statistics)

    def test_publication_and_statistic_construction_failure_are_retryable(self):
        for target in ('analysis.tls_handshake_statistics.TLSHandshakeStatistics',
                       'analysis.flow_observation_window.FlowObservationWindowUpdate',
                       'analysis.flow_state_coordinator.CoordinatedFlowState'):
            instance = manager()
            before = record(instance, wire(b'\x01', 22))
            data = wire(message(b'abc')[1:], 22)
            with patch(target, side_effect=MemoryError('construction/publication')):
                with self.assertRaises(MemoryError):
                    record(instance, data, sequence=106)
            self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
            after = record(instance, data, sequence=106)
            self.assertEqual(after.tls_handshake_statistics.forward.total_message_count, 1)

    def test_invalid_complete_observation_aborts_candidate_without_repair(self):
        instance = manager()
        before = record(instance, wire(b'\x01', 22))
        original = coordinator_module.update_tls_handshake_state
        def corrupt(current, records):
            update = original(current, records)
            return altered(update, forward_messages=(altered(update.forward_messages[0], payload=b'wrong'),))
        data = wire(message(b'abc')[1:], 22)
        with patch.object(coordinator_module, 'update_tls_handshake_state', side_effect=corrupt):
            with self.assertRaises(ValueError):
                record(instance, data, sequence=106)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        after = record(instance, data, sequence=106)
        self.assertEqual(after.tls_handshake_statistics.forward.total_message_length_bytes, 3)

    def test_capture_failure_closes_prior_counts_without_counting_partial_suffix(self):
        source = MemoryPacketSource((packet(wire(message(b'A') + b'\x01', 22)),), iteration_error=CaptureError('capture'))
        windows = []
        with self.assertRaises(CaptureError):
            run_flow_observation_session(source, capture_session_id='tls-statistics',
                                         inactivity_timeout=timedelta(seconds=5), closed_window_consumer=windows.append)
        self.assertEqual(windows[0].tls_handshake_statistics.forward.total_message_count, 1)
        self.assertEqual(source.events[-1], 'stop')

    def test_retained_statistics_release_packets_windows_and_completed_messages(self):
        instance, references = manager(), []
        source = packet(wire(message(b'opaque source payload'), 22))
        analyzed = analyze_packet(source)
        def reduce(current, observation):
            references.extend(weakref.ref(value) for value in (observation, observation.header, observation.stream))
            return update_directional_tls_handshake_statistics(current, observation)
        with patch.object(coordinator_module, 'update_directional_tls_handshake_statistics', side_effect=reduce):
            window = instance.record(analyzed).active_window
        statistics = window.tls_handshake_statistics
        references.extend(weakref.ref(value) for value in (source, analyzed, window, window.coordinated_state,
                                                          window.tls_handshake_state, window.tls_record_state))
        instance.close(window.identity)
        del source, analyzed, window
        gc.collect()
        self.assertTrue(all(ref() is None for ref in references))
        self.assertEqual(statistics.forward.total_message_length_bytes, 21)
        reference = weakref.ref(statistics)
        del statistics
        gc.collect()
        self.assertIsNone(reference())

    def test_very_long_real_stream_is_bounded_and_counts_every_message(self):
        instance = manager()
        data = wire(message(b'x' * 1024, 7), 22)
        for index in range(180):
            window = record(instance, data, sequence=100 + index * len(data))
        statistics = window.tls_handshake_statistics.forward
        self.assertEqual((statistics.total_message_count, statistics.total_message_length_bytes), (180, 180 * 1024))
        self.assertEqual(statistics.handshake_type_counts[7], 180)
        self.assertGreater(window.tls_handshake_state.forward.stream.buffer_offset, 65536)
        self.assertEqual(window.tls_handshake_state.forward.payload, b'')
        self.assertEqual(len(statistics.handshake_type_counts), 256)

    def test_generic_snapshot_and_all_49_values_match_without_statistics(self):
        inputs = (packet(wire(message(b'A'), 22)), packet(wire(message(b'BB'), 22), reverse=True, sequence=900, seconds=1))
        window, = run_packets(inputs)
        with patch.object(coordinator_module, 'update_directional_tls_handshake_statistics',
                          side_effect=lambda current, observation: current):
            baseline, = run_packets(inputs)
        left, right = extract_flow_feature_snapshot(window), extract_flow_feature_snapshot(baseline)
        self.assertEqual(left.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
        self.assertEqual(snapshot_features(left), snapshot_features(right))
        self.assertEqual(project_flow_features(left), project_flow_features(right))
        self.assertEqual(len(project_flow_features(left).values), 49)

    def test_no_dns_ldap_or_tls_semantic_parsing_in_statistics_path(self):
        with patch.object(coordinator_module, 'analyze_dns_message', side_effect=AssertionError('DNS')):
            with patch('analysis.ldap_stream_framing._message', side_effect=AssertionError('LDAP')):
                window, = run_packets((packet(wire(message(b'\x00arbitrary', 255), 22)),))
        self.assertEqual(window.tls_handshake_statistics.forward.handshake_type_counts[255], 1)

    def test_coordinator_statistic_type_and_legacy_default(self):
        state = FlowStateCoordinator().record(analyze_packet(packet(wire(message(b'A'), 22))))
        with self.assertRaises(TypeError):
            replace(state, tls_handshake_statistics={})
        legacy = tuple(getattr(state, field.name) for field in fields(state) if field.name not in ('tls_handshake_statistics', 'tls_client_hellos', 'tls_client_hello_statistics', 'tls_server_hellos', 'tls_server_hello_statistics', 'ipv6_extension_header_statistics', 'tcp_option_statistics'))
        self.assertEqual(type(state)(*legacy).tls_handshake_statistics, DirectionalTLSHandshakeStatistics())

    def test_four_classic_pcap_encodings_match_actual_session_statistics(self):
        sources, expected = traffic(), None
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'tls-statistics.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    with self.subTest(order=order, nano=nano):
                        path.write_bytes(pcap_bytes(tuple((index * 1000000, source.raw_bytes) for index, source in enumerate(sources)), order, nano))
                        windows = []
                        run_flow_observation_session(PcapPacketSource(path), capture_session_id='tls-statistics',
                                                     inactivity_timeout=timedelta(seconds=60), closed_window_consumer=windows.append)
                        actual = tuple(map(observable, windows))
                        self.assertEqual(len(actual), 4)
                        all_types, = [window for window in windows if window.identity.source_port == 12347]
                        self.assertEqual(all_types.tls_handshake_statistics.forward.handshake_type_counts, (1,) * 256)
                        if expected is None:
                            expected = actual
                        self.assertEqual(actual, expected)

    def test_replay_includes_all_types_directions_capacity_and_release(self):
        events, released = replay()
        self.assertEqual((events, released), replay())
        self.assertEqual({event[1] for event in events}, {4, 6})
        self.assertTrue(any(event[3] == 'capacity' for event in events))
        self.assertTrue(any('gap' in event[-2] for event in events))
        self.assertTrue(any(event[-1].forward.handshake_type_counts == (1,) * 256 for event in events))
        self.assertTrue(any(event[-1].reverse.handshake_type_counts == (1,) * 256 for event in events))
        self.assertTrue(all(released))

    def test_directional_wire_order_is_reduced_once(self):
        calls = []
        def reduce(current, observation):
            calls.append((observation.header.handshake_type, observation.direction))
            return update_directional_tls_handshake_statistics(current, observation)
        forward = b''.join(message(b'x', kind) for kind in (255, 0, 3))
        reverse = b''.join(message(b'', kind) for kind in (7, 0))
        with patch.object(coordinator_module, 'update_directional_tls_handshake_statistics', side_effect=reduce):
            window, = run_packets((packet(wire(forward, 22)), packet(wire(reverse, 22), reverse=True, sequence=900)))
        self.assertEqual([kind for kind, direction in calls], [255, 0, 3, 7, 0])
        self.assertEqual(len({direction for kind, direction in calls[:3]}), 1)
        self.assertNotEqual(calls[0][1], calls[-1][1])
        self.assertEqual((window.tls_handshake_statistics.forward.total_message_count,
                          window.tls_handshake_statistics.reverse.total_message_count), (3, 2))

    def test_all_nine_seed_timezone_combinations(self):
        script = ('from tests.test_tls_handshake_statistics_lifecycle import replay\n'
                  'import hashlib\nprint(hashlib.sha256(repr(replay()).encode()).hexdigest())\n')
        expected = hashlib.sha256(repr(replay()).encode()).hexdigest().encode() + b'\n'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                with self.subTest(seed=seed, zone=zone):
                    actual = subprocess.check_output([sys.executable, '-B', '-c', script],
                                                    env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
                    self.assertEqual(actual, expected)
