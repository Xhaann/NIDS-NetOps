import gc
import hashlib
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import fields, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    DNSMessageStatus, DNSResourceRecordStatistics, FeatureContractVersion, FlowObservationWindowClosureReason,
    FlowStateCoordinator, analyze_dns_message, analyze_packet, extract_flow_feature_snapshot, update_dns_resource_record_statistics,
)
from application import run_flow_observation_session
from capture import CaptureError, PcapPacketSource
from ml import project_flow_features
from tests.pcap_scenarios import pcap_bytes
from tests.test_dns import header, record
from tests.test_dns_correlation_lifecycle import manager
from tests.test_dns_packet_analysis import dns_packet
from tests.test_dns_resource_record_statistics import advance, payload, statistics, terminal
from tests.test_dns_transaction_statistics_lifecycle import run_packets
from tests.test_flow_feature_snapshot import snapshot_features
from tests.test_flow_observation_session import MemoryPacketSource


def packet(answers=(), authorities=(), additionals=(), response=False, identifier=1, **kwargs):
    return dns_packet(payload(answers, authorities, additionals, response, identifier), reverse=response, **kwargs)


def record_window(instance, **kwargs):
    return instance.record(analyze_packet(packet(**kwargs))).active_window


def replay():
    packets = (packet(additionals=(record(kind=41, cls=4096),)),
               packet(ipv6=True, additionals=(record(kind=65535, cls=65535, data=b'\xff'),)),
               packet(response=True, answers=(record(kind=1, data=b'ab'), record(kind=65000, cls=0))),
               packet(ipv6=True, response=True, authorities=(record(kind=256, cls=257, data=b'abc'),)),
               packet(identifier=2, additionals=(record(),)),
               packet(identifier=2, additionals=(record(data=b'xy'),)),
               packet(identifier=2, response=True, answers=(record(kind=255, data=b'z'),)),
               packet(client_port=12346, response=True, answers=(record(kind=0, cls=65535),)))
    windows = run_packets(packets, capacity=2)
    return tuple((window.key.sequence_number, window.closure_reason.value,
                  tuple(getattr(window.dns_resource_record_statistics, field.name) for field in fields(DNSResourceRecordStatistics)),
                  str(window.dns_resource_record_statistics.mean_rdata_length_bytes)) for window in windows)


class DNSResourceRecordLifecycleTests(unittest.TestCase):
    def test_non_dns_flow_has_empty_statistics(self):
        window, = run_packets((packet(port=5353, answers=(record(),)),))
        self.assertIsNone(window.dns_correlation_state)
        self.assertEqual(window.dns_resource_record_statistics, DNSResourceRecordStatistics())

    def test_pending_request_waits_for_terminal_observation(self):
        instance = manager()
        active = record_window(instance, additionals=(record(),))
        self.assertEqual(active.dns_resource_record_statistics.resource_record_count, 0)
        closed = instance.close(active.identity)
        self.assertEqual(closed.dns_resource_record_statistics.additional_count, 1)
        self.assertEqual(active.dns_resource_record_statistics.resource_record_count, 0)

    def test_real_ipv4_udp_match(self):
        window, = run_packets((packet(), packet(response=True, answers=(record(data=b'ab'),))))
        self.assertEqual((window.identity.ip_version, window.identity.protocol), (4, 17))
        self.assertEqual(window.dns_resource_record_statistics, statistics(answers=(record(data=b'ab'),)))

    def test_real_ipv6_udp_match(self):
        window, = run_packets((packet(ipv6=True), packet(ipv6=True, response=True, answers=(record(data=b'ab'),))))
        self.assertEqual((window.identity.ip_version, window.identity.protocol), (6, 17))
        self.assertEqual(window.dns_resource_record_statistics, statistics(answers=(record(data=b'ab'),)))

    def test_ipv6_extension_headers_delegate_existing_transport(self):
        window, = run_packets((packet(ipv6=True, extensions=(0, 60)),
                               packet(ipv6=True, extensions=(43, 60), response=True, answers=(record(),))))
        self.assertEqual(window.dns_resource_record_statistics.answer_count, 1)

    def test_equivalent_ipv4_ipv6_interleaving_remains_isolated(self):
        windows = run_packets((packet(), packet(ipv6=True), packet(response=True, answers=(record(),)),
                               packet(ipv6=True, response=True, answers=(record(),))))
        self.assertNotEqual(windows[0].identity, windows[1].identity)
        self.assertEqual(windows[0].dns_resource_record_statistics, windows[1].dns_resource_record_statistics)
        self.assertEqual([window.dns_resource_record_statistics.resource_record_count for window in windows], [1, 1])

    def test_different_ip_flows_keep_type_class_and_length_statistics_separate(self):
        windows = run_packets((packet(additionals=(record(kind=41, cls=4096),)),
                               packet(ipv6=True, response=True, answers=(record(kind=65535, cls=0, data=b'abc'),))))
        self.assertEqual(windows[0].dns_resource_record_statistics.type_counts[0][41], 1)
        self.assertEqual(windows[0].dns_resource_record_statistics.type_counts[255][255], 0)
        self.assertEqual(windows[1].dns_resource_record_statistics.class_counts[0][0], 1)
        self.assertEqual(windows[1].dns_resource_record_statistics.total_rdata_length_bytes, 3)

    def test_interleaved_client_ports_do_not_cross_count(self):
        windows = run_packets((packet(), packet(client_port=12346), packet(response=True, answers=(record(),)),
                               packet(response=True, client_port=12346, answers=(record(),) * 2)))
        self.assertEqual([window.dns_resource_record_statistics.answer_count for window in windows], [1, 2])

    def test_sequential_transaction_id_reuse_preserves_multiplicity(self):
        packets = tuple(item for _ in range(20) for item in (packet(), packet(response=True, answers=(record(),))))
        window, = run_packets(packets)
        self.assertEqual(window.dns_resource_record_statistics.answer_count, 20)
        self.assertEqual(window.dns_transaction_statistics.matched_count, 20)

    def test_ambiguous_request_response_and_original_closure_are_counted_once(self):
        window, = run_packets((packet(additionals=(record(),) * 2), packet(additionals=(record(),) * 3),
                               packet(response=True, answers=(record(),))))
        self.assertEqual((window.dns_resource_record_statistics.answer_count,
                          window.dns_resource_record_statistics.additional_count), (1, 5))

    def test_closed_window_does_not_recount_last_completed_prefix(self):
        instance = manager()
        record_window(instance)
        active = record_window(instance, response=True, answers=(record(),))
        closed = instance.close(active.identity)
        self.assertIs(closed.dns_resource_record_statistics, active.dns_resource_record_statistics)
        self.assertEqual(closed.dns_resource_record_statistics.resource_record_count, 1)

    def test_closure_counts_pending_suffix_after_retained_unmatched_response(self):
        window, = run_packets((packet(additionals=(record(),)), packet(identifier=2, response=True, answers=(record(),))))
        self.assertEqual((window.dns_resource_record_statistics.answer_count,
                          window.dns_resource_record_statistics.additional_count), (1, 1))

    def test_inactivity_closure_and_fresh_window(self):
        windows = run_packets((packet(additionals=(record(),)), packet(response=True, seconds=5, answers=(record(),) * 2)))
        self.assertIs(windows[0].closure_reason, FlowObservationWindowClosureReason.INACTIVITY)
        self.assertEqual([window.dns_resource_record_statistics.resource_record_count for window in windows], [1, 2])

    def test_explicit_closure_readmission_starts_empty(self):
        instance = manager()
        before = record_window(instance, response=True, answers=(record(),))
        instance.close(before.identity)
        after = record_window(instance)
        self.assertEqual(after.identity, before.identity)
        self.assertNotEqual(after.key, before.key)
        self.assertEqual(after.dns_resource_record_statistics, DNSResourceRecordStatistics())

    def test_capacity_eviction_preserves_final_statistics_and_fresh_admission(self):
        instance = manager(1)
        record_window(instance, additionals=(record(),))
        update = instance.record(analyze_packet(packet(ipv6=True)))
        self.assertIs(update.closed_windows[0].closure_reason, FlowObservationWindowClosureReason.CAPACITY)
        self.assertEqual(update.closed_windows[0].dns_resource_record_statistics.additional_count, 1)
        self.assertEqual(update.active_window.dns_resource_record_statistics.resource_record_count, 0)
        self.assertEqual(record_window(instance, response=True, answers=(record(),)).dns_resource_record_statistics.resource_record_count, 1)

    def test_repeated_finalization_preserves_identical_result(self):
        instance = manager()
        record_window(instance, additionals=(record(),))
        window, = instance.end_capture_session()
        for _ in range(10):
            self.assertIs(replace(window).dns_resource_record_statistics, window.dns_resource_record_statistics)
        self.assertEqual(instance.end_capture_session(), ())
        self.assertEqual(instance.active_windows(), ())

    def test_correlation_capacity_batch_and_retained_prefix_are_not_duplicated(self):
        packets = tuple(packet(identifier=index, additionals=(record(),)) for index in range(140))
        window, = run_packets(packets)
        self.assertEqual(window.dns_resource_record_statistics.resource_record_count, 140)
        self.assertEqual(window.dns_resource_record_statistics.additional_count, window.dns_transaction_statistics.additional_count)

    def assert_excluded(self, raw, status):
        for ipv6 in (False, True):
            observed = dns_packet(raw, ipv6=ipv6)
            self.assertIs(analyze_packet(observed).dns.status, status)
            window, = run_packets((observed,))
            self.assertIsNone(window.dns_correlation_state)
            self.assertEqual(window.dns_resource_record_statistics, DNSResourceRecordStatistics())

    def test_malformed_dns_is_excluded(self):
        self.assert_excluded(header(0, 1) + b'\x80', DNSMessageStatus.MALFORMED)

    def test_incomplete_dns_is_excluded(self):
        self.assert_excluded(payload(answers=(record(data=b'ab'),))[:-1], DNSMessageStatus.INCOMPLETE)

    def test_unsupported_dns_is_excluded(self):
        self.assert_excluded(header(0, 1) + b'\x40', DNSMessageStatus.UNSUPPORTED)

    def test_invalid_message_does_not_recover_valid_record_prefix(self):
        self.assert_excluded(header(0, 2) + record() + b'\x80', DNSMessageStatus.MALFORMED)

    def test_oversized_message_and_entry_limit_are_excluded(self):
        oversized = (record(data=b'x' * 65513),)
        self.assertIs(analyze_dns_message(payload(answers=oversized)).status, DNSMessageStatus.UNSUPPORTED)
        self.assertIsNone(advance(answers=oversized))
        self.assert_excluded(payload(answers=(record(),) * 129), DNSMessageStatus.UNSUPPORTED)

    def test_invalid_message_leaves_previous_aggregate_intact(self):
        instance = manager()
        before = record_window(instance, response=True, answers=(record(),))
        after = instance.record(analyze_packet(dns_packet(header(0, 1) + b'\x80'))).active_window
        self.assertIs(after.dns_resource_record_statistics, before.dns_resource_record_statistics)

    def test_tcp_packet_path_does_not_add_dns_framing(self):
        for ipv6 in (False, True):
            window, = run_packets((packet(answers=(record(),), protocol=6, ipv6=ipv6),))
            self.assertIsNone(window.dns_correlation_state)
            self.assertEqual(window.dns_resource_record_statistics, DNSResourceRecordStatistics())

    def test_failed_aggregation_preserves_all_previous_protocol_state(self):
        instance = manager()
        before = record_window(instance)
        with patch('analysis.flow_state_coordinator.update_dns_resource_record_statistics', side_effect=MemoryError('RR')):
            with self.assertRaises(MemoryError):
                record_window(instance, response=True, answers=(record(),), seconds=2)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        after = record_window(instance, response=True, answers=(record(),), seconds=1)
        self.assertEqual((after.dns_resource_record_statistics.answer_count, after.dns_transaction_statistics.matched_count), (1, 1))

    def test_failure_partway_through_one_record_batch_is_atomic(self):
        instance = manager()
        before = record_window(instance)
        from analysis.dns_resource_record_statistics import _increment_code
        calls = 0
        def fail_after_one_record(blocks, code):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise MemoryError('second record')
            _increment_code(blocks, code)
        with patch('analysis.dns_resource_record_statistics._increment_code', side_effect=fail_after_one_record):
            with self.assertRaises(MemoryError):
                record_window(instance, response=True, answers=(record(),) * 2)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        self.assertEqual(record_window(instance, response=True, answers=(record(),) * 2).dns_resource_record_statistics.answer_count, 2)

    def test_failure_partway_through_final_transaction_batch_is_atomic(self):
        instance = manager()
        record_window(instance, identifier=1, additionals=(record(),))
        before = record_window(instance, identifier=2, additionals=(record(),))
        calls = 0
        def fail_second(current, observation):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise MemoryError('second transaction')
            return update_dns_resource_record_statistics(current, observation)
        with patch('analysis.flow_observation_window.update_dns_resource_record_statistics', side_effect=fail_second):
            with self.assertRaises(MemoryError):
                instance.end_capture_session()
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        window, = instance.end_capture_session()
        self.assertEqual(window.dns_resource_record_statistics.additional_count, 2)

    def test_publication_failure_cannot_double_count_retry(self):
        instance = manager()
        record_window(instance)
        with patch('analysis.flow_observation_window.FlowObservationWindowUpdate', side_effect=RuntimeError('publication')):
            with self.assertRaises(RuntimeError):
                record_window(instance, response=True, answers=(record(),))
        self.assertEqual(record_window(instance, response=True, answers=(record(),)).dns_resource_record_statistics.answer_count, 1)

    def test_failed_eviction_preserves_active_owner(self):
        instance = manager(1)
        before = record_window(instance, additionals=(record(),))
        with patch('analysis.flow_observation_window.update_dns_resource_record_statistics', side_effect=MemoryError('eviction')):
            with self.assertRaises(MemoryError):
                record_window(instance, ipv6=True)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        self.assertEqual(record_window(instance, response=True).dns_resource_record_statistics.additional_count, 1)

    def test_capture_failure_publishes_terminal_and_newly_closed_records(self):
        source = MemoryPacketSource((packet(response=True, answers=(record(),)), packet(identifier=2, additionals=(record(),))),
                                    iteration_error=CaptureError('capture'))
        closed = []
        with self.assertRaises(CaptureError):
            run_flow_observation_session(source, capture_session_id='rr', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=closed.append)
        self.assertEqual(closed[0].dns_resource_record_statistics.resource_record_count, 2)
        self.assertEqual(source.events[-1], 'stop')

    def test_parser_infrastructure_failure_propagates_without_publication(self):
        instance = manager()
        with patch('analysis.packet_analysis.analyze_dns_message', side_effect=MemoryError('parser')):
            with self.assertRaises(MemoryError):
                record_window(instance)
        self.assertEqual(instance.active_windows(), ())

    def test_retained_statistics_do_not_retain_packet_or_flow_graph(self):
        instance = manager()
        analyzed = analyze_packet(packet(additionals=(record(data=b'opaque'),)))
        active = instance.record(analyzed).active_window
        transaction = active.dns_correlation_state.requests[0]
        references = [weakref.ref(item) for item in (analyzed, analyzed.observation, active, active.coordinated_state,
                      active.identity, transaction, transaction.message, transaction.message.additionals[0],
                      transaction.message.additionals[0].name)]
        closed = instance.close(active.identity)
        references.extend(weakref.ref(item) for item in (closed, closed.coordinated_state, closed.dns_correlation_state.observations[0]))
        value = closed.dns_resource_record_statistics
        del analyzed, active, transaction, closed
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(value.total_rdata_length_bytes, 6)

    def test_completed_source_records_are_released_during_active_flow(self):
        instance = manager()
        record_window(instance)
        completed = record_window(instance, response=True, answers=(record(),))
        source = completed.dns_correlation_state.observations[0]
        references = [weakref.ref(item) for item in (source, source.message, source.message.answers[0])]
        retained = completed.dns_resource_record_statistics
        record_window(instance, identifier=2)
        del completed, source
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(retained.resource_record_count, 1)

    def test_flow_release_does_not_retain_aggregate(self):
        instance = manager()
        active = record_window(instance, response=True, answers=(record(),))
        reference = weakref.ref(active.dns_resource_record_statistics)
        instance.close(active.identity)
        del active
        gc.collect()
        self.assertIsNone(reference())

    def test_generic_snapshot_and_49_value_projection_remain_unchanged(self):
        window, = run_packets((packet(), packet(response=True, seconds=1, answers=(record(),))))
        original = extract_flow_feature_snapshot(window)
        stripped = replace(window, coordinated_state=replace(window.coordinated_state,
                            dns_resource_record_statistics=DNSResourceRecordStatistics()))
        baseline = extract_flow_feature_snapshot(stripped)
        self.assertEqual(original.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
        self.assertEqual(snapshot_features(original), snapshot_features(baseline))
        self.assertEqual(project_flow_features(original), project_flow_features(baseline))
        self.assertEqual(len(project_flow_features(original).values), 49)

    def test_legacy_coordinator_constructor_and_new_field_validation(self):
        state = FlowStateCoordinator().record(analyze_packet(packet()))
        arguments = tuple(getattr(state, field.name) for field in fields(state) if field.name not in ('dns_resource_record_statistics', 'dns_message_flag_statistics'))
        self.assertEqual(type(state)(*arguments).dns_resource_record_statistics, DNSResourceRecordStatistics())
        with self.assertRaises(TypeError):
            replace(state, dns_resource_record_statistics={})

    def test_all_classic_pcap_encodings_produce_equal_statistics(self):
        packets = (packet(additionals=(record(kind=41, cls=4096),)), packet(ipv6=True),
                   packet(response=True, answers=(record(data=b'\x00\xff'),)),
                   packet(ipv6=True, response=True, authorities=(record(kind=65535),)))
        expected = [window.dns_resource_record_statistics for window in run_packets(packets)]
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'rr.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes) for index, item in enumerate(packets)), order, nano))
                    windows = []
                    run_flow_observation_session(PcapPacketSource(path), capture_session_id='rr',
                                                 inactivity_timeout=timedelta(seconds=5), closed_window_consumer=windows.append)
                    self.assertEqual([window.dns_resource_record_statistics for window in windows], expected)


class DNSResourceRecordAdversarialTests(unittest.TestCase):
    def test_many_codes_touch_every_block_without_changing_shape(self):
        current = None
        for index in range(32):
            records = tuple(record(kind=code * 256 + 255, cls=(255 - code) * 256, data=b'x')
                            for code in range(index * 8, index * 8 + 8))
            current = update_dns_resource_record_statistics(current, terminal(answers=records))
            self.assertEqual(len(fields(current)), 8)
            for distribution in (current.type_counts, current.class_counts):
                self.assertEqual(len(distribution), 256)
                self.assertTrue(all(len(block) == 256 for block in distribution))
        self.assertEqual(current.resource_record_count, 256)
        self.assertTrue(all(block[255] == 1 for block in current.type_counts))
        self.assertTrue(all(block[0] == 1 for block in current.class_counts))

    def test_many_repeated_records_have_no_history_growth(self):
        source = terminal(answers=(record(),) * 128)
        current = None
        for _ in range(50):
            current = update_dns_resource_record_statistics(current, source)
        self.assertEqual(current.resource_record_count, 6400)
        self.assertEqual(current.type_counts[0][1], 6400)
        self.assertEqual(len({id(block) for block in current.type_counts}), 2)
        self.assertEqual(len(fields(current)), 8)

    def test_maximum_record_batches_in_both_matched_messages(self):
        packets = (packet(additionals=(record(),) * 128), packet(response=True, answers=(record(),) * 128))
        window, = run_packets(packets)
        self.assertEqual(window.dns_resource_record_statistics.resource_record_count, 256)

    def test_churn_preserves_feature_fourteen_section_accounting(self):
        instance = manager(3)
        for index in range(160):
            update = instance.record(analyze_packet(packet(response=bool(index % 3), identifier=index % 7,
                                   additionals=(record(kind=index * 256, cls=65535),), ipv6=bool(index % 2),
                                   client_port=12345 + index % 5)))
            for window in (update.active_window,) + update.closed_windows:
                for field in ('answer_count', 'authority_count', 'additional_count'):
                    self.assertEqual(getattr(window.dns_resource_record_statistics, field),
                                     getattr(window.dns_transaction_statistics, field))
            self.assertLessEqual(len(instance.active_windows()), 3)
        for window in instance.end_capture_session():
            self.assertEqual(window.dns_resource_record_statistics.additional_count, window.dns_transaction_statistics.additional_count)

    def test_repeated_independent_replay(self):
        self.assertEqual(replay(), replay())

    def test_all_nine_hash_seed_timezone_replays_are_identical(self):
        script = ('from tests.test_dns_resource_record_statistics_lifecycle import replay\n'
                  'import hashlib\nprint(hashlib.sha256(repr(replay()).encode()).hexdigest())\n')
        expected = hashlib.sha256(repr(replay()).encode()).hexdigest().encode() + b'\n'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                actual = subprocess.check_output([sys.executable, '-B', '-c', script],
                                                  env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
                self.assertEqual(actual, expected)
