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
    DNSMessageStatus, DNSQueryNameStatistics, FeatureContractVersion, FlowObservationWindowClosureReason,
    FlowStateCoordinator, analyze_packet, extract_flow_feature_snapshot, update_dns_query_name_statistics,
)
from application import run_flow_observation_session
from capture import CaptureError, PcapPacketSource
from ml import project_flow_features
from tests.pcap_scenarios import pcap_bytes
from tests.test_dns import header, name, pointer, question
from tests.test_dns_correlation_lifecycle import manager
from tests.test_dns_packet_analysis import dns_packet
from tests.test_dns_query_name_statistics import statistics, terminal
from tests.test_dns_transaction_statistics_lifecycle import run_packets
from tests.test_flow_feature_snapshot import snapshot_features
from tests.test_flow_observation_session import MemoryPacketSource


def packet(query_names=((b'example',),), response=False, identifier=1, **kwargs):
    payload = header(len(query_names), flags=0x8000 if response else 0, identifier=identifier)
    payload += b''.join(question(name(*labels)) for labels in query_names)
    return dns_packet(payload, reverse=response, **kwargs)


def record(instance, **kwargs):
    return instance.record(analyze_packet(packet(**kwargs))).active_window


def replay():
    instance = manager(2)
    events = []
    for index in range(180):
        labels = ((), (b'Ab9',), (b'_x-', b'\xff'), (b'x' * 63, b'y' * 61))[index % 4]
        update = instance.record(analyze_packet(packet((labels,), response=bool(index % 3), identifier=index % 5,
                                                       ipv6=bool(index % 2), client_port=12345 + index % 3,
                                                       seconds=index // 6)))
        events.append((update.active_window.key.sequence_number, asdict(update.active_window.dns_query_name_statistics)))
        events.extend((window.key.sequence_number, asdict(window.dns_query_name_statistics)) for window in update.closed_windows)
    events.extend((window.key.sequence_number, asdict(window.dns_query_name_statistics)) for window in instance.end_capture_session())
    value = statistics((), (b'a',), (b'ab',))
    events.append((asdict(value), str(value.mean_name_length_bytes), str(value.mean_label_length_bytes)))
    return events


class DNSQueryNameLifecycleTests(unittest.TestCase):
    def test_non_dns_flow_is_empty(self):
        window, = run_packets((packet(port=5353),))
        self.assertIsNone(window.dns_correlation_state)
        self.assertEqual(window.dns_query_name_statistics, DNSQueryNameStatistics())

    def test_pending_questions_wait_until_terminal_observation(self):
        instance = manager()
        active = record(instance)
        self.assertEqual(active.dns_query_name_statistics, DNSQueryNameStatistics())
        closed = instance.close(active.identity)
        self.assertEqual(closed.dns_query_name_statistics, statistics((b'example',)))
        self.assertEqual(active.dns_query_name_statistics.query_name_count, 0)

    def test_real_ipv4_udp_match(self):
        window, = run_packets((packet(), packet(response=True)))
        self.assertEqual((window.identity.ip_version, window.identity.protocol), (4, 17))
        self.assertEqual(window.dns_query_name_statistics, statistics((b'example',), (b'example',)))

    def test_real_ipv6_udp_match(self):
        window, = run_packets((packet(ipv6=True), packet(ipv6=True, response=True)))
        self.assertEqual((window.identity.ip_version, window.identity.protocol), (6, 17))
        self.assertEqual(window.dns_query_name_statistics, statistics((b'example',), (b'example',)))

    def test_ipv6_extension_headers_preserve_structure(self):
        names = ((b'Ab9', b'_tcp'),)
        window, = run_packets((packet(names, ipv6=True, extensions=(0, 60)),
                               packet(names, ipv6=True, response=True, extensions=(43, 60))))
        self.assertEqual(window.dns_query_name_statistics, statistics(*names, *names))

    def test_equivalent_interleaved_ip_flows_are_isolated(self):
        windows = run_packets((packet(), packet(ipv6=True), packet(response=True), packet(ipv6=True, response=True)))
        self.assertNotEqual(windows[0].identity, windows[1].identity)
        self.assertEqual(windows[0].dns_query_name_statistics, windows[1].dns_query_name_statistics)
        self.assertEqual([window.dns_query_name_statistics.query_name_count for window in windows], [2, 2])

    def test_different_names_across_ip_versions_do_not_contaminate(self):
        windows = run_packets((packet(((b'a',),)), packet(((b'long9',),), ipv6=True, response=True)))
        self.assertEqual(windows[0].dns_query_name_statistics, statistics((b'a',)))
        self.assertEqual(windows[1].dns_query_name_statistics, statistics((b'long9',)))

    def test_same_id_and_name_across_interleaved_client_ports(self):
        windows = run_packets((packet(), packet(client_port=12346), packet(response=True),
                               packet(response=True, client_port=12346), packet(response=True)))
        self.assertEqual([window.dns_query_name_statistics.query_name_count for window in windows], [3, 2])

    def test_different_names_across_client_ports_remain_scoped(self):
        windows = run_packets((packet(((b'a',),)), packet(((b'long9',),), client_port=12346),
                               packet(((b'a',),), response=True)))
        self.assertEqual(windows[0].dns_query_name_statistics, statistics((b'a',), (b'a',)))
        self.assertEqual(windows[1].dns_query_name_statistics, statistics((b'long9',)))

    def test_sequential_id_reuse_counts_each_exchange(self):
        packets = tuple(packet(response=response) for _ in range(12) for response in (False, True))
        window, = run_packets(packets)
        self.assertEqual((window.dns_query_name_statistics.query_name_count, window.dns_transaction_statistics.matched_count), (24, 12))

    def test_ambiguous_messages_and_original_closure_count_once_each(self):
        window, = run_packets((packet(((b'original',),)), packet(((b'duplicate9',),)),
                               packet(((b'response',),), response=True)))
        self.assertEqual(window.dns_query_name_statistics, statistics((b'original',), (b'duplicate9',), (b'response',)))
        self.assertEqual((window.dns_transaction_statistics.ambiguous_count, window.dns_transaction_statistics.unresolved_count), (2, 1))

    def test_unmatched_response_and_unresolved_request_use_observed_questions(self):
        window, = run_packets((packet(((b'original',),)), packet(((b'different',),), response=True)))
        self.assertEqual(window.dns_query_name_statistics, statistics((b'original',), (b'different',)))
        self.assertEqual((window.dns_transaction_statistics.unmatched_count, window.dns_transaction_statistics.unresolved_count), (1, 1))

    def test_finalization_skips_retained_completed_prefix(self):
        instance = manager()
        record(instance)
        before = record(instance, response=True)
        closed = instance.close(before.identity)
        self.assertIs(closed.dns_query_name_statistics, before.dns_query_name_statistics)
        self.assertEqual(closed.dns_query_name_statistics.query_name_count, 2)

    def test_repeated_closed_window_construction_is_idempotent(self):
        window, = run_packets((packet(),))
        for _ in range(20):
            self.assertIs(replace(window).dns_query_name_statistics, window.dns_query_name_statistics)

    def test_inactivity_closure_and_readmission(self):
        windows = run_packets((packet(), packet(response=True, seconds=5)))
        self.assertIs(windows[0].closure_reason, FlowObservationWindowClosureReason.INACTIVITY)
        self.assertEqual([window.dns_query_name_statistics.query_name_count for window in windows], [1, 1])
        self.assertNotEqual(windows[0].key, windows[1].key)

    def test_explicit_closure_readmission_starts_empty(self):
        instance = manager()
        first = record(instance)
        closed = instance.close(first.identity)
        new = record(instance)
        self.assertEqual(new.identity, closed.identity)
        self.assertNotEqual(new.key, closed.key)
        self.assertEqual(new.dns_query_name_statistics, DNSQueryNameStatistics())

    def test_capacity_eviction_finalizes_and_new_flow_starts_empty(self):
        instance = manager(1)
        record(instance)
        update = instance.record(analyze_packet(packet(ipv6=True)))
        self.assertIs(update.closed_windows[0].closure_reason, FlowObservationWindowClosureReason.CAPACITY)
        self.assertEqual(update.closed_windows[0].dns_query_name_statistics.query_name_count, 1)
        self.assertEqual(update.active_window.dns_query_name_statistics, DNSQueryNameStatistics())
        self.assertEqual(record(instance, response=True).dns_query_name_statistics.query_name_count, 1)

    def test_correlation_saturation_and_final_prefix_are_counted_once(self):
        packets = tuple(packet(identifier=index) for index in range(140)) + (packet(response=True),)
        window, = run_packets(packets)
        self.assertEqual(window.dns_query_name_statistics.query_name_count, 141)
        self.assertEqual(window.dns_query_name_statistics.query_name_count, window.dns_transaction_statistics.question_count)

    def assert_excluded(self, payload, status):
        for ipv6 in (False, True):
            observed = dns_packet(payload, ipv6=ipv6)
            self.assertIs(analyze_packet(observed).dns.status, status)
            window, = run_packets((observed,))
            self.assertEqual(window.dns_query_name_statistics, DNSQueryNameStatistics())
            self.assertIsNone(window.dns_correlation_state)

    def test_malformed_name_is_excluded(self):
        self.assert_excluded(header(1) + b'\x80', DNSMessageStatus.MALFORMED)

    def test_truncated_name_is_excluded(self):
        self.assert_excluded(header(1) + b'\x04ab', DNSMessageStatus.INCOMPLETE)

    def test_unsupported_name_is_excluded(self):
        self.assert_excluded(header(1) + b'\x40', DNSMessageStatus.UNSUPPORTED)

    def test_pointer_loop_is_excluded(self):
        self.assert_excluded(header(1) + question(pointer(12)), DNSMessageStatus.MALFORMED)

    def test_invalid_pointer_target_is_excluded(self):
        self.assert_excluded(header(1) + question(pointer(0)), DNSMessageStatus.MALFORMED)

    def test_valid_prefix_of_invalid_message_is_not_recovered(self):
        self.assert_excluded(header(2) + question(name(b'valid')) + b'\x04x', DNSMessageStatus.INCOMPLETE)

    def test_invalid_message_does_not_change_existing_aggregate(self):
        instance = manager()
        before = record(instance, response=True)
        update = instance.record(analyze_packet(dns_packet(header(1) + b'\x80')))
        self.assertIs(update.active_window.dns_query_name_statistics, before.dns_query_name_statistics)

    def test_invalid_analysis_type_cannot_publish_feature_state(self):
        coordinator = FlowStateCoordinator()
        with self.assertRaises(TypeError):
            coordinator.record(packet())
        self.assertIsNone(coordinator.state)

    def test_truncated_packet_analysis_propagates_without_feature_publication(self):
        original = packet()
        truncated = replace(original, raw_bytes=original.raw_bytes[:10], captured_length=10)
        source = MemoryPacketSource((truncated,))
        closed = []
        with self.assertRaises(ValueError):
            run_flow_observation_session(source, capture_session_id='names', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=closed.append)
        self.assertEqual(closed, [])
        self.assertEqual(source.events[-1], 'stop')

    def test_tcp_packet_path_preserves_absent_dns_framing(self):
        for ipv6 in (False, True):
            window, = run_packets((packet(ipv6=ipv6, protocol=6),))
            self.assertIsNone(window.dns_correlation_state)
            self.assertEqual(window.dns_query_name_statistics, DNSQueryNameStatistics())

    def test_failed_aggregation_preserves_transaction_and_statistics_for_retry(self):
        instance = manager()
        before = record(instance)
        with patch('analysis.flow_state_coordinator.update_dns_query_name_statistics', side_effect=MemoryError('names')):
            with self.assertRaises(MemoryError):
                record(instance, response=True, seconds=2)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        after = record(instance, response=True, seconds=1)
        self.assertEqual((after.dns_query_name_statistics.query_name_count, after.dns_transaction_statistics.matched_count), (2, 1))

    def test_failed_window_publication_cannot_double_count_retry(self):
        instance = manager()
        record(instance)
        with patch('analysis.flow_observation_window.FlowObservationWindowUpdate', side_effect=RuntimeError('publish')):
            with self.assertRaises(RuntimeError):
                record(instance, response=True)
        self.assertEqual(record(instance, response=True).dns_query_name_statistics.query_name_count, 2)

    def test_failure_partway_through_final_aggregation_is_atomic(self):
        instance = manager()
        record(instance, identifier=1)
        before = record(instance, identifier=2)
        calls = 0
        def fail_second(current, observation):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise MemoryError('second name')
            return update_dns_query_name_statistics(current, observation)
        with patch('analysis.flow_observation_window.update_dns_query_name_statistics', side_effect=fail_second):
            with self.assertRaises(MemoryError):
                instance.end_capture_session()
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        closed, = instance.end_capture_session()
        self.assertEqual((closed.dns_query_name_statistics.query_name_count, closed.dns_transaction_statistics.unresolved_count), (2, 2))

    def test_capacity_aggregation_failure_preserves_owner(self):
        instance = manager(1)
        before = record(instance)
        with patch('analysis.flow_observation_window.update_dns_query_name_statistics', side_effect=MemoryError('evict')):
            with self.assertRaises(MemoryError):
                record(instance, ipv6=True)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        self.assertEqual(record(instance, response=True).dns_query_name_statistics.query_name_count, 2)

    def test_capture_failure_propagates_and_publishes_final_names(self):
        source = MemoryPacketSource((packet(),), iteration_error=CaptureError('capture'))
        closed = []
        with self.assertRaises(CaptureError):
            run_flow_observation_session(source, capture_session_id='names', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=closed.append)
        self.assertEqual(closed[0].dns_query_name_statistics.query_name_count, 1)
        self.assertEqual(source.events[-1], 'stop')

    def test_parser_infrastructure_failure_propagates_without_publication(self):
        instance = manager()
        with patch('analysis.packet_analysis.analyze_dns_message', side_effect=MemoryError('parser')):
            with self.assertRaises(MemoryError):
                record(instance)
        self.assertEqual(instance.active_windows(), ())

    def test_retained_statistics_release_entire_packet_and_flow_graph(self):
        instance = manager()
        analyzed = analyze_packet(packet())
        active = instance.record(analyzed).active_window
        transaction = active.dns_correlation_state.requests[0]
        references = [weakref.ref(item) for item in (analyzed, analyzed.observation, active, active.coordinated_state,
                      active.identity, transaction, transaction.message, transaction.message.questions[0], transaction.message.questions[0].name)]
        closed = instance.close(active.identity)
        references.extend(weakref.ref(item) for item in (closed, closed.coordinated_state, closed.dns_correlation_state.observations[0]))
        result = closed.dns_query_name_statistics
        del analyzed, active, transaction, closed
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(result.query_name_count, 1)

    def test_owner_release_drops_aggregate_when_caller_releases_snapshot(self):
        instance = manager()
        active = record(instance, response=True)
        reference = weakref.ref(active.dns_query_name_statistics)
        instance.close(active.identity)
        del active
        gc.collect()
        self.assertIsNone(reference())

    def test_completed_transaction_graph_is_released_during_active_flow(self):
        instance = manager()
        record(instance)
        completed = record(instance, response=True)
        transaction = completed.dns_correlation_state.observations[0]
        references = [weakref.ref(item) for item in (transaction, transaction.request, transaction.message,
                      transaction.request.questions[0], transaction.message.questions[0].name)]
        result = completed.dns_query_name_statistics
        record(instance, identifier=2)
        del completed, transaction
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(result.query_name_count, 2)

    def test_generic_features_contract_and_ml_projection_are_unchanged(self):
        window, = run_packets((packet(), packet(response=True, seconds=1)))
        original = extract_flow_feature_snapshot(window)
        stripped = replace(window, coordinated_state=replace(window.coordinated_state, dns_query_name_statistics=DNSQueryNameStatistics()))
        baseline = extract_flow_feature_snapshot(stripped)
        self.assertEqual(original.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
        self.assertEqual(snapshot_features(original), snapshot_features(baseline))
        self.assertEqual(project_flow_features(original), project_flow_features(baseline))
        self.assertEqual(len(project_flow_features(original).values), 49)

    def test_legacy_constructor_and_new_field_validation(self):
        state = FlowStateCoordinator().record(analyze_packet(packet()))
        previous = tuple(getattr(state, field.name) for field in fields(state) if field.name not in ('dns_query_name_statistics', 'dns_resource_record_statistics', 'dns_message_flag_statistics', 'dns_edns_statistics', 'dns_stream_state', 'tls_record_state', 'tls_handshake_state', 'tls_handshake_statistics', 'tls_client_hellos'))
        self.assertEqual(type(state)(*previous).dns_query_name_statistics, DNSQueryNameStatistics())
        with self.assertRaises(TypeError):
            replace(state, dns_query_name_statistics={})

    def test_all_classic_pcap_encodings_produce_identical_features(self):
        names = ((), (b'Ab9', b'_srv-'), (b'\xff',))
        packets = (packet(names), packet(names, ipv6=True), packet(names, response=True, seconds=1),
                   packet(names, ipv6=True, response=True, seconds=1))
        expected = [window.dns_query_name_statistics for window in run_packets(packets)]
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'names.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes) for index, item in enumerate(packets)), order, nano))
                    actual = []
                    run_flow_observation_session(PcapPacketSource(path), capture_session_id='names',
                                                 inactivity_timeout=timedelta(seconds=5), closed_window_consumer=actual.append)
                    self.assertEqual([window.dns_query_name_statistics for window in actual], expected)


class DNSQueryNameAdversarialTests(unittest.TestCase):
    def test_many_distinct_and_repeated_names_keep_fifteen_scalar_fields(self):
        current = None
        for index in range(800):
            labels = ((str(index).encode('ascii'),), (b'repeated',))[index % 2]
            current = update_dns_query_name_statistics(current, terminal((labels,)))
            self.assertEqual(len(fields(current)), 15)
            self.assertTrue(all(value is None or type(value) is int for value in vars(current).values()))
        self.assertEqual(current.query_name_count, 800)
        self.assertEqual(current.digit_name_count, 400)

    def test_alternating_root_and_maximum_names_preserve_extrema_and_means(self):
        maximum = (b'a' * 63, b'b' * 63, b'c' * 63, b'd' * 61)
        current = None
        for _ in range(200):
            current = update_dns_query_name_statistics(current, terminal(((), maximum)))
        self.assertEqual((current.query_name_count, current.root_name_count, current.label_count), (400, 200, 800))
        self.assertEqual((current.min_name_length_bytes, current.max_name_length_bytes, current.mean_name_length_bytes), (1, 255, 128))

    def test_flow_churn_keeps_question_accounting_equal_to_feature_fourteen(self):
        instance = manager(3)
        for index in range(300):
            update = instance.record(analyze_packet(packet(((str(index).encode('ascii'),),), response=bool(index % 3),
                                                           ipv6=bool(index % 2), client_port=12345 + index % 5)))
            for window in (update.active_window,) + update.closed_windows:
                self.assertEqual(window.dns_query_name_statistics.query_name_count, window.dns_transaction_statistics.question_count)
            self.assertLessEqual(len(instance.active_windows()), 3)
        for window in instance.end_capture_session():
            self.assertEqual(window.dns_query_name_statistics.query_name_count, window.dns_transaction_statistics.question_count)
        self.assertEqual(instance.active_windows(), ())

    def test_independent_replays_have_no_global_name_state(self):
        self.assertEqual(replay(), replay())

    def test_all_nine_hash_seed_timezone_replays_are_identical(self):
        script = ('from tests.test_dns_query_name_statistics_lifecycle import replay\n'
                  'import hashlib\nprint(hashlib.sha256(repr(replay()).encode()).hexdigest())\n')
        expected = hashlib.sha256(repr(replay()).encode()).hexdigest().encode() + b'\n'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                actual = subprocess.check_output([sys.executable, '-B', '-c', script],
                                                  env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
                self.assertEqual(actual, expected)
