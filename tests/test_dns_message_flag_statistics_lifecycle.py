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
from unittest.mock import PropertyMock, patch

from analysis import (
    DNSHeader, DNSMessageFlagStatistics, DNSMessageStatus, FeatureContractVersion, FlowObservationWindowClosureReason,
    FlowStateCoordinator, analyze_packet, extract_flow_feature_snapshot, update_dns_message_flag_statistics,
)
from application import run_flow_observation_session
from capture import CaptureError, PcapPacketSource
from ml import project_flow_features
from tests.pcap_scenarios import pcap_bytes
from tests.test_dns import header, question, record
from tests.test_dns_correlation_lifecycle import manager
from tests.test_dns_packet_analysis import dns_packet
from tests.test_dns_transaction_statistics_lifecycle import run_packets
from tests.test_flow_feature_snapshot import snapshot_features
from tests.test_flow_observation_session import MemoryPacketSource


def packet(flags=0, identifier=1, questions=(), answers=(), **kwargs):
    raw = header(len(questions), len(answers), flags=flags, identifier=identifier) + b''.join(questions) + b''.join(answers)
    return dns_packet(raw, reverse=bool(flags & 0x8000), **kwargs)


def record_window(instance, **kwargs):
    return instance.record(analyze_packet(packet(**kwargs))).active_window


def replay():
    instance = manager(3)
    events = []
    for index in range(80):
        update = instance.record(analyze_packet(packet(flags=(0, 0x8200, 0x0200, 0x8000)[index % 4],
                                 identifier=index % 7, ipv6=bool(index % 3), client_port=12345 + index % 5,
                                 seconds=index // 8)))
        for window in (update.active_window,) + update.closed_windows:
            events.append((window.key.sequence_number, window.closure_reason.value if window.closure_reason else None,
                           asdict(window.dns_message_flag_statistics), window.dns_message_flag_statistics.query_count))
    events.extend((window.key.sequence_number, window.closure_reason.value, asdict(window.dns_message_flag_statistics),
                   window.dns_message_flag_statistics.query_count) for window in instance.end_capture_session())
    return events


class DNSMessageFlagLifecycleTests(unittest.TestCase):
    def test_non_dns_flow_has_empty_statistics(self):
        window, = run_packets((packet(flags=0x8200, port=5353),))
        self.assertIsNone(window.dns_correlation_state)
        self.assertEqual(window.dns_message_flag_statistics, DNSMessageFlagStatistics())

    def test_pending_message_is_counted_only_when_terminal(self):
        instance = manager()
        active = record_window(instance, flags=0x0200)
        self.assertEqual(active.dns_message_flag_statistics, DNSMessageFlagStatistics())
        closed = instance.close(active.identity)
        self.assertEqual(closed.dns_message_flag_statistics, DNSMessageFlagStatistics(1, 0, 1))
        self.assertEqual(active.dns_message_flag_statistics.message_count, 0)

    def test_real_ipv4_udp_match(self):
        window, = run_packets((packet(flags=0x0200), packet(flags=0x8200)))
        self.assertEqual((window.identity.ip_version, window.identity.protocol), (4, 17))
        self.assertEqual(window.dns_message_flag_statistics, DNSMessageFlagStatistics(2, 1, 2))

    def test_real_ipv6_udp_match(self):
        window, = run_packets((packet(flags=0x0200, ipv6=True), packet(flags=0x8000, ipv6=True)))
        self.assertEqual((window.identity.ip_version, window.identity.protocol), (6, 17))
        self.assertEqual(window.dns_message_flag_statistics, DNSMessageFlagStatistics(2, 1, 1))

    def test_ipv6_extension_headers_use_existing_dns_path(self):
        window, = run_packets((packet(ipv6=True, extensions=(0, 60)), packet(flags=0x8200, ipv6=True, extensions=(43, 60))))
        self.assertEqual(window.dns_message_flag_statistics, DNSMessageFlagStatistics(2, 1, 1))

    def test_equivalent_ip_versions_have_equal_isolated_statistics(self):
        windows = run_packets((packet(), packet(ipv6=True), packet(flags=0x8200), packet(flags=0x8200, ipv6=True)))
        self.assertNotEqual(windows[0].identity, windows[1].identity)
        self.assertEqual([window.dns_message_flag_statistics for window in windows], [DNSMessageFlagStatistics(2, 1, 1)] * 2)

    def test_different_ip_flags_do_not_cross_contaminate(self):
        windows = run_packets((packet(flags=0x0200), packet(ipv6=True), packet(flags=0x8200), packet(flags=0x8000, ipv6=True)))
        self.assertEqual([window.dns_message_flag_statistics.truncated_count for window in windows], [2, 0])

    def test_interleaved_client_ports_with_same_id_are_isolated(self):
        windows = run_packets((packet(), packet(client_port=12346, flags=0x0200), packet(flags=0x8000),
                               packet(flags=0x8200, client_port=12346)))
        self.assertEqual([window.dns_message_flag_statistics for window in windows],
                         [DNSMessageFlagStatistics(2, 1, 0), DNSMessageFlagStatistics(2, 1, 2)])

    def test_sequential_transaction_reuse_remains_multiplicity_sensitive(self):
        window, = run_packets(tuple(item for _ in range(25) for item in (packet(flags=0x0200), packet(flags=0x8000))))
        self.assertEqual(window.dns_message_flag_statistics, DNSMessageFlagStatistics(50, 25, 25))
        self.assertEqual(window.dns_transaction_statistics.matched_count, 25)

    def test_ambiguity_and_unresolved_original_count_each_message_once(self):
        window, = run_packets((packet(flags=0x0200), packet(), packet(flags=0x8200)))
        self.assertEqual(window.dns_message_flag_statistics, DNSMessageFlagStatistics(3, 1, 2))
        self.assertEqual((window.dns_transaction_statistics.ambiguous_count, window.dns_transaction_statistics.unresolved_count), (2, 1))

    def test_inactivity_closure_publishes_before_readmission(self):
        windows = run_packets((packet(flags=0x0200), packet(flags=0x8000, seconds=5)))
        self.assertIs(windows[0].closure_reason, FlowObservationWindowClosureReason.INACTIVITY)
        self.assertEqual([window.dns_message_flag_statistics for window in windows],
                         [DNSMessageFlagStatistics(1, 0, 1), DNSMessageFlagStatistics(1, 1, 0)])

    def test_explicit_closure_readmission_starts_empty(self):
        instance = manager()
        active = record_window(instance, flags=0x8200)
        closed = instance.close(active.identity)
        self.assertIs(closed.closure_reason, FlowObservationWindowClosureReason.EXPLICIT_SEGMENTATION)
        after = record_window(instance)
        self.assertEqual(after.identity, active.identity)
        self.assertNotEqual(after.key, active.key)
        self.assertEqual(after.dns_message_flag_statistics, DNSMessageFlagStatistics())

    def test_capacity_eviction_finalizes_and_releases_old_owner(self):
        instance = manager(1)
        before = record_window(instance, flags=0x0200)
        update = instance.record(analyze_packet(packet(ipv6=True)))
        self.assertIs(update.closed_windows[0].closure_reason, FlowObservationWindowClosureReason.CAPACITY)
        self.assertEqual(update.closed_windows[0].dns_message_flag_statistics, DNSMessageFlagStatistics(1, 0, 1))
        self.assertEqual(update.active_window.dns_message_flag_statistics, DNSMessageFlagStatistics())
        self.assertEqual(len(instance.active_windows()), 1)
        self.assertNotEqual(instance.active_windows()[0].identity, before.identity)

    def test_completed_prefix_is_not_counted_again(self):
        instance = manager()
        record_window(instance)
        before = record_window(instance, flags=0x8200)
        closed = instance.close(before.identity)
        self.assertIs(closed.dns_message_flag_statistics, before.dns_message_flag_statistics)
        self.assertEqual(closed.dns_message_flag_statistics.message_count, 2)

    def test_unresolved_suffix_is_added_after_completed_prefix(self):
        window, = run_packets((packet(flags=0x0200), packet(flags=0x8000, identifier=2)))
        self.assertEqual(window.dns_message_flag_statistics, DNSMessageFlagStatistics(2, 1, 1))

    def test_capture_finalization_is_idempotent(self):
        instance = manager()
        record_window(instance, flags=0x0200)
        window, = instance.end_capture_session()
        self.assertIs(window.closure_reason, FlowObservationWindowClosureReason.CAPTURE_SESSION_END)
        for _ in range(10):
            self.assertIs(replace(window).dns_message_flag_statistics, window.dns_message_flag_statistics)
        self.assertEqual(instance.end_capture_session(), ())
        self.assertEqual(instance.active_windows(), ())

    def test_pending_capacity_and_completed_prefix_accounting(self):
        window, = run_packets(tuple(packet(identifier=index, flags=0x0200) for index in range(140)))
        self.assertEqual(window.dns_message_flag_statistics, DNSMessageFlagStatistics(140, 0, 140))

    def assert_excluded(self, raw, status):
        for ipv6 in (False, True):
            observed = dns_packet(raw, ipv6=ipv6)
            self.assertIs(analyze_packet(observed).dns.status, status)
            window, = run_packets((observed,))
            self.assertIsNone(window.dns_correlation_state)
            self.assertEqual(window.dns_message_flag_statistics, DNSMessageFlagStatistics())

    def test_malformed_message_is_excluded(self):
        self.assert_excluded(header(1, flags=0x8200) + b'\x80', DNSMessageStatus.MALFORMED)

    def test_incomplete_message_is_excluded(self):
        self.assert_excluded(header(1, flags=0x8200) + b'\x01', DNSMessageStatus.INCOMPLETE)

    def test_unsupported_message_is_excluded(self):
        self.assert_excluded(header(1, flags=0x8200) + b'\x40', DNSMessageStatus.UNSUPPORTED)

    def test_invalid_message_header_and_valid_prefix_are_excluded(self):
        self.assert_excluded(header(2, flags=0x8200) + question() + b'\x80', DNSMessageStatus.MALFORMED)

    def test_invalid_dns_cannot_change_previous_flags(self):
        instance = manager()
        before = record_window(instance, flags=0x8200)
        after = instance.record(analyze_packet(dns_packet(header(1) + b'\x80'))).active_window
        self.assertIs(after.dns_message_flag_statistics, before.dns_message_flag_statistics)

    def test_tcp_packet_path_does_not_add_automatic_dns_framing(self):
        for ipv6 in (False, True):
            window, = run_packets((packet(flags=0x8200, protocol=6, ipv6=ipv6),))
            self.assertIsNone(window.dns_correlation_state)
            self.assertEqual(window.dns_message_flag_statistics, DNSMessageFlagStatistics())

    def test_aggregation_failure_preserves_nonempty_prior_state(self):
        instance = manager()
        record_window(instance, flags=0x8200, identifier=2)
        before = record_window(instance)
        with patch('analysis.flow_state_coordinator.update_dns_message_flag_statistics', side_effect=MemoryError('flags')):
            with self.assertRaises(MemoryError):
                record_window(instance, flags=0x8000, seconds=2)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        self.assertEqual(record_window(instance, flags=0x8000, seconds=1).dns_message_flag_statistics, DNSMessageFlagStatistics(3, 2, 1))

    def test_partial_message_batch_failure_preserves_state(self):
        instance = manager()
        record_window(instance, flags=0x8200, identifier=2)
        before = record_window(instance, flags=0x0200)
        with patch.object(DNSHeader, 'truncated', new_callable=PropertyMock, side_effect=(True, MemoryError('second message'))):
            with self.assertRaises(MemoryError):
                record_window(instance, flags=0x8000)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        self.assertEqual(record_window(instance, flags=0x8000).dns_message_flag_statistics, DNSMessageFlagStatistics(3, 2, 2))

    def test_partial_terminal_batch_failure_leaves_closure_retryable(self):
        instance = manager()
        record_window(instance, flags=0x8200, identifier=3)
        record_window(instance, flags=0x0200, identifier=1)
        before = record_window(instance, identifier=2)
        calls = 0
        def fail_second(current, observation):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise MemoryError('second transaction')
            return update_dns_message_flag_statistics(current, observation)
        with patch('analysis.flow_observation_window.update_dns_message_flag_statistics', side_effect=fail_second):
            with self.assertRaises(MemoryError):
                instance.end_capture_session()
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        window, = instance.end_capture_session()
        self.assertEqual(window.dns_message_flag_statistics, DNSMessageFlagStatistics(3, 1, 2))

    def test_failed_publication_does_not_double_count_retry(self):
        instance = manager()
        before = record_window(instance)
        with patch('analysis.flow_observation_window.FlowObservationWindowUpdate', side_effect=RuntimeError('publication')):
            with self.assertRaises(RuntimeError):
                record_window(instance, flags=0x8200)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        self.assertEqual(record_window(instance, flags=0x8200).dns_message_flag_statistics, DNSMessageFlagStatistics(2, 1, 1))

    def test_failed_eviction_keeps_owner_and_pending_message(self):
        instance = manager(1)
        before = record_window(instance, flags=0x0200)
        with patch('analysis.flow_observation_window.update_dns_message_flag_statistics', side_effect=MemoryError('eviction')):
            with self.assertRaises(MemoryError):
                record_window(instance, ipv6=True)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        self.assertEqual(record_window(instance, flags=0x8000).dns_message_flag_statistics, DNSMessageFlagStatistics(2, 1, 1))

    def test_parser_infrastructure_failure_propagates_without_publication(self):
        instance = manager()
        with patch('analysis.packet_analysis.analyze_dns_message', side_effect=MemoryError('parser')):
            with self.assertRaises(MemoryError):
                record_window(instance)
        self.assertEqual(instance.active_windows(), ())

    def test_capture_failure_publishes_existing_terminal_and_pending_messages(self):
        source = MemoryPacketSource((packet(flags=0x8200), packet(flags=0x0200, identifier=2)), iteration_error=CaptureError('capture'))
        closed = []
        with self.assertRaises(CaptureError):
            run_flow_observation_session(source, capture_session_id='flags', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=closed.append)
        self.assertEqual(closed[0].dns_message_flag_statistics, DNSMessageFlagStatistics(2, 1, 2))
        self.assertEqual(source.events[-1], 'stop')

    def test_retained_statistics_release_complete_source_graph(self):
        instance = manager()
        analyzed = analyze_packet(packet(flags=0x0200))
        active = instance.record(analyzed).active_window
        source = active.dns_correlation_state.requests[0]
        references = [weakref.ref(item) for item in (analyzed, analyzed.observation, active, active.coordinated_state,
                      active.identity, active.dns_correlation_state, source, source.message, source.message.header)]
        closed = instance.close(active.identity)
        references.extend(weakref.ref(item) for item in (closed, closed.coordinated_state, closed.dns_correlation_state,
                                                       closed.dns_correlation_state.observations[0]))
        value = closed.dns_message_flag_statistics
        del analyzed, active, source, closed
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(value, DNSMessageFlagStatistics(1, 0, 1))

    def test_completed_sources_are_released_while_flow_stays_active(self):
        instance = manager()
        record_window(instance)
        completed = record_window(instance, flags=0x8200)
        source = completed.dns_correlation_state.observations[0]
        references = [weakref.ref(item) for item in (source, source.request, source.message, source.message.header)]
        value = completed.dns_message_flag_statistics
        record_window(instance, identifier=2)
        del completed, source
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(value, DNSMessageFlagStatistics(2, 1, 1))

    def test_releasing_owner_releases_aggregate(self):
        instance = manager()
        active = record_window(instance, flags=0x8200)
        reference = weakref.ref(active.dns_message_flag_statistics)
        instance.close(active.identity)
        del active
        gc.collect()
        self.assertIsNone(reference())

    def test_features_fourteen_fifteen_sixteen_remain_identical(self):
        packets = (packet(flags=0x0200, questions=(question(),)),
                   packet(flags=0x8200, questions=(question(),), answers=(record(data=b'opaque'),)))
        actual, = run_packets(packets)
        empty = DNSMessageFlagStatistics()
        with patch('analysis.flow_state_coordinator.update_dns_message_flag_statistics', return_value=empty):
            with patch('analysis.flow_observation_window.update_dns_message_flag_statistics', return_value=empty):
                baseline, = run_packets(packets)
        for field in ('dns_transaction_statistics', 'dns_query_name_statistics', 'dns_resource_record_statistics'):
            self.assertEqual(getattr(actual, field), getattr(baseline, field))
        self.assertEqual(actual.dns_transaction_statistics.matched_count, 1)
        self.assertEqual(actual.dns_query_name_statistics.query_name_count, 2)
        self.assertEqual(actual.dns_resource_record_statistics.resource_record_count, 1)

    def test_generic_version_one_and_49_projected_values_remain_identical(self):
        window, = run_packets((packet(flags=0x0200), packet(flags=0x8200, seconds=1)))
        original = extract_flow_feature_snapshot(window)
        stripped = replace(window, coordinated_state=replace(window.coordinated_state, dns_message_flag_statistics=DNSMessageFlagStatistics()))
        baseline = extract_flow_feature_snapshot(stripped)
        self.assertEqual(original.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
        self.assertEqual(snapshot_features(original), snapshot_features(baseline))
        self.assertEqual(project_flow_features(original), project_flow_features(baseline))
        self.assertEqual(len(project_flow_features(original).values), 49)

    def test_legacy_constructor_and_new_field_validation(self):
        state = FlowStateCoordinator().record(analyze_packet(packet()))
        arguments = tuple(getattr(state, field.name) for field in fields(state) if field.name != 'dns_message_flag_statistics')
        self.assertEqual(type(state)(*arguments).dns_message_flag_statistics, DNSMessageFlagStatistics())
        with self.assertRaises(TypeError):
            replace(state, dns_message_flag_statistics={})

    def test_four_classic_pcap_encodings_are_equivalent(self):
        packets = (packet(flags=0x0200), packet(ipv6=True), packet(flags=0x8000), packet(flags=0x8200, ipv6=True))
        expected = [window.dns_message_flag_statistics for window in run_packets(packets)]
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'flags.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes) for index, item in enumerate(packets)), order, nano))
                    windows = []
                    run_flow_observation_session(PcapPacketSource(path), capture_session_id='flags',
                                                 inactivity_timeout=timedelta(seconds=5), closed_window_consumer=windows.append)
                    self.assertEqual([window.dns_message_flag_statistics for window in windows], expected)


class DNSMessageFlagReplayTests(unittest.TestCase):
    def test_bounded_churn_matches_existing_message_accounting(self):
        instance = manager(3)
        for index in range(240):
            update = instance.record(analyze_packet(packet(flags=(0, 0x8200, 0x0200)[index % 3], identifier=index % 7,
                                                           ipv6=bool(index % 2), client_port=12345 + index % 5)))
            self.assertLessEqual(len(instance.active_windows()), 3)
            for window in (update.active_window,) + update.closed_windows:
                value = window.dns_message_flag_statistics
                self.assertEqual(value.message_count, sum(window.dns_transaction_statistics.opcode_counts))
                self.assertEqual(value.response_count, sum(window.dns_transaction_statistics.response_code_counts))
                self.assertEqual(len(vars(value)), 3)
        for window in instance.end_capture_session():
            self.assertEqual(window.dns_message_flag_statistics.message_count, sum(window.dns_transaction_statistics.opcode_counts))

    def test_repeated_independent_replay(self):
        self.assertEqual(replay(), replay())

    def test_all_nine_hash_seed_timezone_combinations(self):
        script = ('from tests.test_dns_message_flag_statistics_lifecycle import replay\n'
                  'import hashlib\nprint(hashlib.sha256(repr(replay()).encode()).hexdigest())\n')
        expected = hashlib.sha256(repr(replay()).encode()).hexdigest().encode() + b'\n'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                actual = subprocess.check_output([sys.executable, '-B', '-c', script],
                                                env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
                self.assertEqual(actual, expected)
