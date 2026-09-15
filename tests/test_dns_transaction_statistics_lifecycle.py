import gc
import hashlib
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import asdict, fields, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    DNSCorrelationStatus, DNSMessageStatus, DNSTransactionStatistics, FeatureContractVersion,
    FlowObservationWindowClosureReason, FlowStateCoordinator, analyze_packet, extract_flow_feature_snapshot,
)
from application import run_flow_observation_session
from capture import CaptureError, PcapPacketSource
from ml import project_flow_features
from tests.pcap_scenarios import pcap_bytes
from tests.test_dns import header, question
from tests.test_dns_correlation_lifecycle import manager, packet, record
from tests.test_dns_packet_analysis import dns_packet
from tests.test_dns_transaction_statistics import aggregate, matched, record_transaction
from tests.test_flow_feature_snapshot import snapshot_features
from tests.test_flow_observation_session import MemoryPacketSource


def run_packets(packets, capacity=1024):
    closed = []
    run_flow_observation_session(MemoryPacketSource(packets), capture_session_id='dns-statistics',
                                 inactivity_timeout=timedelta(seconds=5), max_active_windows=capacity,
                                 closed_window_consumer=closed.append)
    return closed


def replay():
    instance = manager(2)
    events = []
    for index in range(240):
        update = instance.record(analyze_packet(packet(index % 7, bool(index % 3), index // 8,
                                                       bool(index % 2), client_port=12345 + index % 3)))
        events.append((update.active_window.key.sequence_number, asdict(update.active_window.dns_transaction_statistics)))
        events.extend((window.key.sequence_number, asdict(window.dns_transaction_statistics)) for window in update.closed_windows)
    events.extend((window.key.sequence_number, asdict(window.dns_transaction_statistics)) for window in instance.end_capture_session())
    value = aggregate((matched(1), matched(2), record_transaction(opcode=15, response_code=13)))
    events.append((asdict(value), str(value.mean_matched_latency_microseconds)))
    return events


class DNSTransactionStatisticsLifecycleTests(unittest.TestCase):
    def test_non_dns_flow_has_explicit_empty_statistics(self):
        window, = run_packets((packet(port=5353),))
        self.assertIsNone(window.dns_correlation_state)
        self.assertEqual(window.dns_transaction_statistics, DNSTransactionStatistics())

    def test_pending_active_window_is_empty_until_closure(self):
        instance = manager()
        active = record(instance)
        self.assertEqual(active.dns_transaction_statistics, DNSTransactionStatistics())
        closed = instance.close(active.identity)
        self.assertEqual(closed.dns_transaction_statistics.unresolved_count, 1)
        self.assertEqual(active.dns_transaction_statistics.total_transaction_count, 0)

    def test_real_ipv4_udp_request_response(self):
        window, = run_packets((packet(), packet(response=True, seconds=1)))
        self.assertEqual(window.identity.ip_version, 4)
        self.assertEqual(window.identity.protocol, 17)
        self.assertEqual(window.dns_transaction_statistics, aggregate((matched(1000000),)))

    def test_real_ipv6_udp_request_response(self):
        window, = run_packets((packet(ipv6=True), packet(ipv6=True, response=True, seconds=1)))
        self.assertEqual(window.identity.ip_version, 6)
        self.assertEqual(window.dns_transaction_statistics, aggregate((matched(1000000),)))

    def test_ipv6_extension_headers_use_established_udp_path(self):
        request = dns_packet(header(1) + question(), ipv6=True, extensions=(0, 60))
        response = dns_packet(header(1, flags=0x8000) + question(), ipv6=True, reverse=True, extensions=(43, 60))
        window, = run_packets((request, response))
        self.assertEqual(window.dns_transaction_statistics.matched_count, 1)

    def test_ipv4_ipv6_interleaving_remains_isolated_and_equivalent(self):
        windows = run_packets((packet(), packet(ipv6=True), packet(response=True, seconds=1),
                               packet(ipv6=True, response=True, seconds=1)))
        self.assertEqual(len(windows), 2)
        self.assertNotEqual(windows[0].identity, windows[1].identity)
        self.assertEqual(windows[0].dns_transaction_statistics, windows[1].dns_transaction_statistics)
        self.assertEqual([window.dns_transaction_statistics.total_transaction_count for window in windows], [1, 1])

    def test_response_in_other_ip_version_cannot_complete_request(self):
        windows = run_packets((packet(), packet(ipv6=True, response=True)))
        self.assertEqual(windows[0].dns_transaction_statistics.unresolved_count, 1)
        self.assertEqual(windows[1].dns_transaction_statistics.unmatched_response_count, 1)
        self.assertEqual(sum(window.dns_transaction_statistics.matched_count for window in windows), 0)

    def test_identical_ids_in_interleaved_client_flows(self):
        windows = run_packets((packet(), packet(client_port=12346), packet(response=True),
                               packet(response=True, client_port=12346), packet(response=True)))
        first, second = (window.dns_transaction_statistics for window in windows)
        self.assertEqual((first.matched_count, first.unmatched_response_count), (1, 1))
        self.assertEqual((second.matched_count, second.unmatched_response_count), (1, 0))

    def test_sequential_id_reuse_counts_each_match_once(self):
        packets = tuple(packet(response=response, seconds=index) for index in range(30) for response in (False, True))
        value = run_packets(packets)[0].dns_transaction_statistics
        self.assertEqual((value.matched_count, value.total_transaction_count, value.question_count), (30, 30, 60))
        self.assertEqual(value.total_matched_latency_microseconds, 0)

    def test_outstanding_id_reuse_preserves_ambiguous_and_unresolved_events(self):
        value = run_packets((packet(), packet(), packet(response=True)))[0].dns_transaction_statistics
        self.assertEqual((value.ambiguous_count, value.unresolved_count, value.total_transaction_count), (2, 1, 3))
        self.assertEqual((value.question_count, sum(value.opcode_counts), sum(value.response_code_counts)), (3, 3, 1))

    def test_closure_does_not_repeat_last_matched_batch(self):
        instance = manager()
        record(instance)
        before = record(instance, response=True)
        after = instance.close(before.identity)
        self.assertIs(after.dns_transaction_statistics, before.dns_transaction_statistics)
        self.assertEqual(after.dns_transaction_statistics.matched_count, 1)

    def test_closure_skips_retained_unmatched_batch_and_counts_pending_suffix(self):
        value = run_packets((packet(), packet(identifier=2, response=True)))[0].dns_transaction_statistics
        self.assertEqual((value.unmatched_count, value.unresolved_count, value.total_transaction_count), (1, 1, 2))

    def test_closure_skips_retained_ambiguous_batch(self):
        value = run_packets((packet(), packet()))[0].dns_transaction_statistics
        self.assertEqual((value.ambiguous_count, value.unresolved_count, value.total_transaction_count), (1, 1, 2))

    def test_closure_skips_whole_capacity_batch(self):
        value = run_packets(tuple(packet(identifier=index) for index in range(129)))[0].dns_transaction_statistics
        self.assertEqual((value.unresolved_count, value.total_transaction_count), (129, 129))

    def test_sticky_correlation_limit_preserves_later_statuses(self):
        packets = tuple(packet(identifier=index) for index in range(140)) + (packet(response=True),)
        value = run_packets(packets)[0].dns_transaction_statistics
        self.assertEqual((value.unresolved_count, value.unmatched_count, value.total_transaction_count), (140, 1, 141))

    def test_closure_after_invalid_message_keeps_previous_aggregate(self):
        value = run_packets((packet(), packet(response=True), packet(identifier=2), dns_packet(b'')))[0].dns_transaction_statistics
        self.assertEqual((value.matched_count, value.unresolved_count, value.total_transaction_count), (1, 1, 2))

    def test_inactivity_creates_fresh_feature_owner(self):
        windows = run_packets((packet(), packet(response=True, seconds=5)))
        self.assertIs(windows[0].closure_reason, FlowObservationWindowClosureReason.INACTIVITY)
        self.assertEqual(windows[0].dns_transaction_statistics.unresolved_count, 1)
        self.assertEqual(windows[1].dns_transaction_statistics.unmatched_count, 1)

    def test_capacity_eviction_cannot_leak_features_on_readmission(self):
        windows = run_packets((packet(), packet(ipv6=True), packet(response=True)), capacity=1)
        self.assertEqual([window.key.sequence_number for window in windows], [0, 1, 2])
        self.assertEqual([window.dns_transaction_statistics.total_transaction_count for window in windows], [1, 1, 1])
        self.assertEqual(windows[-1].dns_transaction_statistics.unmatched_count, 1)
        self.assertTrue(all(window.closure_reason is FlowObservationWindowClosureReason.CAPACITY for window in windows[:-1]))

    def test_repeated_closed_window_construction_is_idempotent(self):
        instance = manager()
        record(instance)
        closed, = instance.end_capture_session()
        for _ in range(20):
            self.assertIs(replace(closed).dns_transaction_statistics, closed.dns_transaction_statistics)
        self.assertEqual(instance.end_capture_session(), ())
        self.assertEqual(instance.active_windows(), ())

    def test_independent_sessions_have_independent_counts(self):
        first = run_packets((packet(), packet(response=True)))[0].dns_transaction_statistics
        second = run_packets((packet(response=True),))[0].dns_transaction_statistics
        self.assertEqual((first.matched_count, second.matched_count, second.unmatched_count), (1, 0, 1))

    def assert_excluded(self, payload, status):
        for ipv6 in (False, True):
            observation = dns_packet(payload, ipv6=ipv6)
            self.assertIs(analyze_packet(observation).dns.status, status)
            window, = run_packets((observation,))
            self.assertIsNone(window.dns_correlation_state)
            self.assertEqual(window.dns_transaction_statistics, DNSTransactionStatistics())

    def test_malformed_dns_is_excluded(self):
        self.assert_excluded(header(1) + b'\x80', DNSMessageStatus.MALFORMED)

    def test_incomplete_dns_is_excluded(self):
        self.assert_excluded(header(1) + b'\x01', DNSMessageStatus.INCOMPLETE)

    def test_unsupported_dns_is_excluded(self):
        self.assert_excluded(header(1) + b'\x40', DNSMessageStatus.UNSUPPORTED)

    def test_dns_record_limit_input_is_excluded(self):
        self.assert_excluded(header(129) + question() * 129, DNSMessageStatus.UNSUPPORTED)

    def test_tcp_packet_path_does_not_invent_dns_framing(self):
        for ipv6 in (False, True):
            window, = run_packets((dns_packet(header(1) + question(), ipv6=ipv6, protocol=6),))
            self.assertIsNone(window.dns_correlation_state)
            self.assertEqual(window.dns_transaction_statistics, DNSTransactionStatistics())

    def test_failed_statistics_update_does_not_consume_transaction(self):
        instance = manager()
        before = record(instance)
        with patch('analysis.flow_state_coordinator.update_dns_transaction_statistics', side_effect=MemoryError('features')):
            with self.assertRaises(MemoryError):
                record(instance, response=True, seconds=2)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        after = record(instance, response=True, seconds=1)
        self.assertEqual(after.dns_transaction_statistics.total_matched_latency_microseconds, 1000000)

    def test_failed_window_publication_does_not_double_count_retry(self):
        instance = manager()
        record(instance)
        with patch('analysis.flow_observation_window.FlowObservationWindowUpdate', side_effect=RuntimeError('publish')):
            with self.assertRaises(RuntimeError):
                record(instance, response=True)
        self.assertEqual(record(instance, response=True).dns_transaction_statistics.matched_count, 1)

    def test_failed_final_aggregation_leaves_owner_retryable(self):
        instance = manager()
        before = record(instance)
        with patch('analysis.flow_observation_window.update_dns_transaction_statistics', side_effect=MemoryError('close')):
            with self.assertRaises(MemoryError):
                instance.end_capture_session()
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        self.assertEqual(instance.end_capture_session()[0].dns_transaction_statistics.unresolved_count, 1)

    def test_failed_capacity_admission_preserves_old_feature_state(self):
        instance = manager(1)
        record(instance)
        before = record(instance, response=True)
        with patch('analysis.flow_state_coordinator.update_dns_correlation_state', side_effect=RuntimeError('admit')):
            with self.assertRaises(RuntimeError):
                record(instance, ipv6=True)
        self.assertIs(instance.active_windows()[0].dns_transaction_statistics, before.dns_transaction_statistics)
        self.assertEqual(record(instance, response=True).dns_transaction_statistics.unmatched_count, 1)

    def test_decreasing_capture_time_rejection_is_atomic(self):
        instance = manager()
        before = record(instance, seconds=2)
        with self.assertRaises(ValueError):
            record(instance, response=True, seconds=1)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        self.assertEqual(record(instance, response=True, seconds=2).dns_transaction_statistics.total_matched_latency_microseconds, 0)

    def test_capture_failure_still_delivers_final_statistics(self):
        closed = []
        failure = CaptureError('source')
        source = MemoryPacketSource((packet(),), iteration_error=failure)
        with self.assertRaises(CaptureError):
            run_flow_observation_session(source, capture_session_id='dns', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=closed.append)
        self.assertEqual(closed[0].dns_transaction_statistics.unresolved_count, 1)
        self.assertEqual(source.events[-1], 'stop')

    def test_all_classic_pcap_encodings_preserve_exact_feature_statistics(self):
        packets = (packet(), packet(ipv6=True), packet(response=True), packet(ipv6=True, response=True), packet(identifier=2))
        packets = tuple(replace(item, captured_at=packets[0].captured_at + timedelta(microseconds=offset))
                        for item, offset in zip(packets, (0, 1, 3, 6, 7)))
        expected = [window.dns_transaction_statistics for window in run_packets(packets)]
        self.assertEqual([value.total_matched_latency_microseconds for value in expected], [3, 5])
        epoch = packets[0].captured_at.replace(year=1970, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
        entries = []
        for item in packets:
            duration = item.captured_at - epoch
            entries.append(((duration.days * 86400 + duration.seconds) * 1000000 + duration.microseconds, item.raw_bytes))
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'dns-statistics.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    path.write_bytes(pcap_bytes(tuple(entries), order, nano))
                    actual = []
                    run_flow_observation_session(PcapPacketSource(path), capture_session_id='dns-statistics',
                                                 inactivity_timeout=timedelta(seconds=5), closed_window_consumer=actual.append)
                    self.assertEqual([window.dns_transaction_statistics for window in actual], expected)

    def test_feature_retention_does_not_retain_packets_transactions_or_names(self):
        instance = manager()
        analysis = analyze_packet(packet())
        active = instance.record(analysis).active_window
        request = active.dns_correlation_state.requests[0]
        references = [weakref.ref(analysis), weakref.ref(analysis.observation), weakref.ref(request),
                      weakref.ref(request.message), weakref.ref(request.message.questions[0].name)]
        completed = record(instance, response=True)
        transaction = completed.dns_correlation_state.observations[0]
        references.extend((weakref.ref(transaction), weakref.ref(transaction.message)))
        statistics = completed.dns_transaction_statistics
        record(instance, identifier=2)
        del analysis, active, request, completed, transaction
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(statistics.matched_count, 1)

    def test_owner_release_drops_aggregate_reference(self):
        instance = manager()
        record(instance)
        active = record(instance, response=True)
        reference = weakref.ref(active.dns_transaction_statistics)
        instance.close(active.identity)
        del active
        gc.collect()
        self.assertIsNone(reference())
        self.assertEqual(instance.active_windows(), ())

    def test_generic_feature_contract_and_projection_remain_unchanged(self):
        window, = run_packets((packet(), packet(response=True, seconds=1)))
        snapshot = extract_flow_feature_snapshot(window)
        stripped = replace(window, coordinated_state=replace(window.coordinated_state,
                            dns_correlation_state=None, dns_transaction_statistics=DNSTransactionStatistics()))
        baseline = extract_flow_feature_snapshot(stripped)
        self.assertEqual(snapshot.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
        self.assertEqual(snapshot_features(snapshot), snapshot_features(baseline))
        self.assertEqual(project_flow_features(snapshot), project_flow_features(baseline))

    def test_coordinator_default_and_statistic_type_validation(self):
        state = FlowStateCoordinator().record(analyze_packet(packet()))
        legacy = tuple(getattr(state, member.name) for member in fields(state)
                       if member.name not in ('dns_transaction_statistics', 'dns_query_name_statistics'))
        self.assertEqual(type(state)(*legacy).dns_transaction_statistics, DNSTransactionStatistics())
        with self.assertRaises(TypeError):
            replace(state, dns_transaction_statistics={})


class DNSTransactionStatisticsAdversarialTests(unittest.TestCase):
    def test_generated_flow_churn_preserves_global_terminal_accounting(self):
        instance = manager(3)
        emitted = 0
        closed_total = 0
        for index in range(360):
            update = instance.record(analyze_packet(packet(index % 11, bool(index % 3), index // 12,
                                                           bool(index % 2), client_port=12345 + index % 5)))
            current = update.active_window.dns_correlation_state
            emitted += sum(item.status is not DNSCorrelationStatus.PENDING for item in current.observations)
            for window in update.closed_windows:
                final = window.dns_transaction_statistics
                closed_total += final.total_transaction_count
                emitted += sum(item.reason is not None and item.reason.value == 'flow_closed'
                               for item in window.dns_correlation_state.observations)
            active_total = sum(window.dns_transaction_statistics.total_transaction_count for window in instance.active_windows())
            self.assertEqual(emitted, closed_total + active_total)
            self.assertLessEqual(len(instance.active_windows()), 3)
        for window in instance.end_capture_session():
            emitted += sum(item.reason is not None and item.reason.value == 'flow_closed'
                           for item in window.dns_correlation_state.observations)
            closed_total += window.dns_transaction_statistics.total_transaction_count
        self.assertEqual(emitted, closed_total)
        self.assertEqual(instance.active_windows(), ())

    def test_many_matched_transactions_keep_fixed_feature_shape(self):
        instance = manager()
        for index in range(700):
            record(instance, identifier=index % 4)
            value = record(instance, identifier=index % 4, response=True).dns_transaction_statistics
            self.assertEqual((len(value.opcode_counts), len(value.response_code_counts), len(fields(value))), (16, 16, 13))
            self.assertEqual(value.matched_count, index + 1)
        closed, = instance.end_capture_session()
        self.assertEqual(closed.dns_transaction_statistics.total_transaction_count, 700)
        self.assertEqual(closed.dns_correlation_state.requests, ())

    def test_repeated_independent_replay_is_equal(self):
        self.assertEqual(replay(), replay())

    def test_nine_hash_seed_timezone_combinations_are_identical(self):
        script = ('from tests.test_dns_transaction_statistics_lifecycle import replay\n'
                  'import hashlib\nprint(hashlib.sha256(repr(replay()).encode()).hexdigest())\n')
        outputs = []
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                output = subprocess.check_output([sys.executable, '-B', '-c', script],
                                                 env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
                outputs.append(output)
        expected = hashlib.sha256(repr(replay()).encode()).hexdigest().encode() + b'\n'
        self.assertEqual(outputs, [expected] * 9)
