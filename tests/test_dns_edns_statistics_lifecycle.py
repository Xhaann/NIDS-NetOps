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
from unittest.mock import PropertyMock, patch

from analysis import (
    DNSEDNSOption, DNSEDNSStatistics, DNSMessageStatus, FeatureContractVersion,
    FlowObservationWindowClosureReason, FlowStateCoordinator, analyze_packet,
    extract_flow_feature_snapshot, update_dns_edns_statistics,
)
from application import run_flow_observation_session
from capture import CaptureError, PcapPacketSource
from ml import project_flow_features
from tests.pcap_scenarios import pcap_bytes
from tests.test_dns_correlation import IDENTITY
from tests.test_dns_correlation_lifecycle import manager
from tests.test_dns_edns import message, opt, option
from tests.test_dns_edns_integration import packets
from tests.test_dns_edns_statistics import SCALARS, advance, statistics
from tests.test_dns_packet_analysis import dns_packet
from tests.test_dns_transaction_statistics_lifecycle import run_packets
from tests.test_flow_feature_snapshot import snapshot_features
from tests.test_flow_observation_session import MemoryPacketSource


def packet(identifier=1, response=False, size=1232, extended=0, version=0, flags=0, data=b'', **kwargs):
    raw = message(opt(size, extended, version, flags, data), flags=0x8000 if response else 0)
    return dns_packet(identifier.to_bytes(2, 'big') + raw[2:], reverse=response, **kwargs)


def record(instance, **kwargs):
    return instance.record(analyze_packet(packet(**kwargs))).active_window


def observable(value):
    return (tuple(getattr(value, name) for name in SCALARS), value.extended_rcode_counts,
            value.version_counts, value.option_code_counts, value.mean_option_data_length,
            value.unknown_option_count, value.non_dnssec_ok_count)


def replay():
    instance = manager(3)
    events = []
    for index in range(60):
        update = instance.record(analyze_packet(packet(identifier=index % 7, response=bool(index % 3),
                                 size=index * 1000, version=index % 256, extended=255 - index,
                                 flags=0xffff if index % 2 else 0x7fff,
                                 data=option(index * 1000, b'x' * (index % 4)) + option(65535),
                                 ipv6=bool(index % 3), client_port=12345 + index % 5, seconds=index // 8)))
        events.extend((window.key.sequence_number, window.identity.ip_version,
                       window.closure_reason.value if window.closure_reason else None,
                       observable(window.dns_edns_statistics))
                      for window in (update.active_window,) + update.closed_windows)
    events.extend((window.key.sequence_number, window.identity.ip_version, window.closure_reason.value,
                   observable(window.dns_edns_statistics)) for window in instance.end_capture_session())
    return events


class DNSEDNSStatisticsLifecycleTests(unittest.TestCase):
    def test_pending_contributes_only_on_close_and_old_window_stays_immutable(self):
        instance = manager()
        active = record(instance, data=option(7, b'ab'))
        self.assertEqual(active.dns_edns_statistics, DNSEDNSStatistics())
        closed = instance.close(active.identity)
        self.assertEqual(closed.dns_edns_statistics, statistics(data=option(7, b'ab')))
        self.assertEqual(active.dns_edns_statistics, DNSEDNSStatistics())
        self.assertIs(closed.dns_edns_statistics, closed.coordinated_state.dns_edns_statistics)

    def test_matched_completed_prefix_is_not_counted_on_close(self):
        instance = manager()
        record(instance, data=option(7))
        active = record(instance, response=True, data=option(7, b'ab'))
        closed = instance.close(active.identity)
        self.assertIs(closed.dns_edns_statistics, active.dns_edns_statistics)
        self.assertEqual((closed.dns_edns_statistics.edns_message_count, closed.dns_edns_statistics.option_count), (2, 2))

    def test_unresolved_suffix_is_added_after_completed_prefix(self):
        window, = run_packets((packet(data=option(1)), packet(identifier=2, response=True, data=option(2))))
        self.assertEqual(window.dns_edns_statistics.edns_message_count, 2)
        self.assertEqual(window.dns_edns_statistics.option_count, 2)

    def test_ambiguous_duplicate_and_original_are_each_counted_once(self):
        window, = run_packets((packet(data=option(1)), packet(data=option(2)), packet(response=True, data=option(3))))
        value = window.dns_edns_statistics
        self.assertEqual((value.edns_message_count, value.option_count), (3, 3))
        self.assertEqual(value.option_code_counts[0][1:4], (1, 1, 1))
        self.assertEqual((window.dns_transaction_statistics.ambiguous_count,
                          window.dns_transaction_statistics.unresolved_count), (2, 1))

    def test_sequential_id_reuse_preserves_multiplicity(self):
        window, = run_packets(tuple(item for _ in range(30) for item in
                                    (packet(data=option(7)), packet(response=True, data=option(7, b'ab')))))
        self.assertEqual((window.dns_edns_statistics.edns_message_count, window.dns_edns_statistics.option_count), (60, 60))
        self.assertEqual(window.dns_edns_statistics.option_code_counts[0][7], 60)

    def test_capture_finalization_is_idempotent(self):
        instance = manager()
        record(instance, data=option(7))
        closed, = instance.end_capture_session()
        for _ in range(10):
            self.assertIs(replace(closed).dns_edns_statistics, closed.dns_edns_statistics)
        self.assertEqual(instance.end_capture_session(), ())
        self.assertEqual(closed.dns_edns_statistics.option_count, 1)

    def test_pending_capacity_counts_all_terminal_messages(self):
        window, = run_packets(tuple(packet(identifier=index, data=option(index)) for index in range(140)))
        self.assertEqual((window.dns_edns_statistics.edns_message_count, window.dns_edns_statistics.option_count), (140, 140))
        self.assertEqual(window.dns_edns_statistics.option_code_counts[0][:140], (1,) * 140)

    def test_inactivity_and_explicit_readmission_start_new_aggregates(self):
        windows = run_packets((packet(data=option(1)), packet(response=True, data=option(2), seconds=5)))
        self.assertIs(windows[0].closure_reason, FlowObservationWindowClosureReason.INACTIVITY)
        self.assertEqual([window.dns_edns_statistics.option_count for window in windows], [1, 1])
        instance = manager()
        active = record(instance, response=True, data=option(1))
        instance.close(active.identity)
        self.assertEqual(record(instance).dns_edns_statistics, DNSEDNSStatistics())

    def test_ipv4_ipv6_extensions_and_client_ports_are_isolated(self):
        windows = run_packets(tuple(item for ipv6, port in ((False, 12345), (True, 12345), (True, 12346))
                                    for item in (packet(ipv6=ipv6, client_port=port, data=option(port),
                                                        extensions=(0, 60) if ipv6 else ()),
                                                 packet(ipv6=ipv6, client_port=port, response=True, data=option(port)))))
        self.assertEqual(len({window.identity for window in windows}), 3)
        for window in windows:
            self.assertEqual(window.dns_edns_statistics.option_count, 2)
        self.assertEqual(windows[0].dns_edns_statistics, windows[1].dns_edns_statistics)
        self.assertNotEqual(windows[1].dns_edns_statistics, windows[2].dns_edns_statistics)

    def test_non_dns_and_tcp_packet_paths_have_empty_statistics(self):
        for kwargs in ({'port': 5353}, {'protocol': 6}, {'protocol': 6, 'ipv6': True}):
            window, = run_packets((packet(data=option(1), **kwargs),))
            self.assertEqual(window.dns_edns_statistics, DNSEDNSStatistics())

    def test_already_delimited_tcp_terminal_values_use_same_reducer(self):
        identity = replace(IDENTITY, protocol=6)
        state = advance(raw=message(opt(data=option(1))), identity=identity)
        state = advance(state, message(opt(data=option(2)), flags=0x8000), identity=identity)
        value = update_dns_edns_statistics(None, state.observations[0])
        self.assertEqual((value.edns_message_count, value.option_count), (2, 2))

    def test_invalid_edns_is_excluded_for_both_ip_versions(self):
        cases = ((message(opt(data=b'\xff')), DNSMessageStatus.MALFORMED),
                 (message(opt(data=option()))[:-1], DNSMessageStatus.INCOMPLETE),
                 (message(opt(data=option() * 129)), DNSMessageStatus.UNSUPPORTED),
                 (message(opt(data=option())) + b'\x00', DNSMessageStatus.MALFORMED))
        for raw, status in cases:
            for ipv6 in (False, True):
                observed = dns_packet(raw, ipv6=ipv6)
                self.assertIs(analyze_packet(observed).dns.status, status)
                window, = run_packets((observed,))
                self.assertEqual(window.dns_edns_statistics, DNSEDNSStatistics())

    def test_invalid_message_does_not_recount_previous_terminal_batch(self):
        instance = manager()
        before = record(instance, response=True, data=option(1))
        after = instance.record(analyze_packet(dns_packet(message(opt(data=b'\xff'))))).active_window
        self.assertIs(after.dns_edns_statistics, before.dns_edns_statistics)

    def test_aggregation_failure_is_atomic_and_retryable(self):
        instance = manager()
        record(instance, identifier=2, response=True, data=option(2))
        before = record(instance, data=option(1))
        with patch('analysis.flow_state_coordinator.update_dns_edns_statistics', side_effect=MemoryError('EDNS')):
            with self.assertRaises(MemoryError):
                record(instance, response=True, data=option(3), seconds=2)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        self.assertEqual(record(instance, response=True, data=option(3), seconds=1).dns_edns_statistics.option_count, 3)

    def test_second_message_option_failure_is_atomic(self):
        instance = manager()
        before = record(instance, data=option(1))
        with patch.object(DNSEDNSOption, 'data_length', new_callable=PropertyMock,
                          side_effect=(0, MemoryError('response option'))):
            with self.assertRaises(MemoryError):
                record(instance, response=True, data=option(2))
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        self.assertEqual(record(instance, response=True, data=option(2)).dns_edns_statistics.option_count, 2)

    def test_partial_terminal_batch_failure_leaves_closure_retryable(self):
        instance = manager()
        record(instance, identifier=3, response=True, data=option(3))
        record(instance, identifier=1, data=option(1))
        before = record(instance, identifier=2, data=option(2))
        calls = 0
        def fail_second(current, observation):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise MemoryError('second terminal')
            return update_dns_edns_statistics(current, observation)
        with patch('analysis.flow_observation_window.update_dns_edns_statistics', side_effect=fail_second):
            with self.assertRaises(MemoryError):
                instance.end_capture_session()
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        closed, = instance.end_capture_session()
        self.assertEqual(closed.dns_edns_statistics.option_count, 3)

    def test_failed_publication_does_not_double_count_retry(self):
        instance = manager()
        before = record(instance, data=option(1))
        with patch('analysis.flow_observation_window.FlowObservationWindowUpdate', side_effect=RuntimeError('publication')):
            with self.assertRaises(RuntimeError):
                record(instance, response=True, data=option(2))
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        self.assertEqual(record(instance, response=True, data=option(2)).dns_edns_statistics.option_count, 2)

    def test_failed_capacity_closure_preserves_owner_and_retry(self):
        instance = manager(1)
        before = record(instance, data=option(1))
        with patch('analysis.flow_observation_window.update_dns_edns_statistics', side_effect=MemoryError('eviction')):
            with self.assertRaises(MemoryError):
                record(instance, ipv6=True)
        self.assertIs(instance.active_windows()[0].coordinated_state, before.coordinated_state)
        update = instance.record(analyze_packet(packet(ipv6=True)))
        self.assertIs(update.closed_windows[0].closure_reason, FlowObservationWindowClosureReason.CAPACITY)
        self.assertEqual(update.closed_windows[0].dns_edns_statistics.option_count, 1)

    def test_capture_failure_finalizes_and_releases_source(self):
        source = MemoryPacketSource((packet(response=True, data=option(1)), packet(identifier=2, data=option(2))),
                                    iteration_error=CaptureError('capture'))
        closed = []
        with self.assertRaises(CaptureError):
            run_flow_observation_session(source, capture_session_id='edns-statistics',
                                         inactivity_timeout=timedelta(seconds=5), closed_window_consumer=closed.append)
        self.assertEqual(closed[0].dns_edns_statistics.option_count, 2)
        self.assertEqual(source.events[-1], 'stop')

    def test_retained_statistics_release_entire_source_graph(self):
        instance = manager()
        analyzed = analyze_packet(packets()[0])
        active = instance.record(analyzed).active_window
        source = active.dns_correlation_state.requests[0]
        parsed = source.message
        references = [weakref.ref(item) for item in (analyzed, analyzed.observation, active, active.coordinated_state,
                      active.identity, active.dns_correlation_state, source, parsed, parsed.header,
                      parsed.questions[0], parsed.questions[0].name, parsed.additionals[0], parsed.edns, parsed.edns.options[0])]
        closed = instance.close(active.identity)
        references.extend(weakref.ref(item) for item in (closed, closed.coordinated_state, closed.dns_correlation_state,
                                                       closed.dns_correlation_state.observations[0]))
        value = closed.dns_edns_statistics
        del analyzed, active, source, parsed, closed
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(value.option_count, 1)
        self.assertTrue(all(type(getattr(value, name)) in (int, type(None)) for name in SCALARS))
        self.assertTrue(all(type(count) is int for block in value.option_code_counts for count in block))

    def test_completed_sources_release_while_flow_remains_active(self):
        instance = manager()
        record(instance, data=option(1, b'opaque'))
        completed = record(instance, response=True, data=option(2, b'opaque'))
        source = completed.dns_correlation_state.observations[0]
        references = [weakref.ref(item) for item in (source, source.request, source.message,
                      source.request.edns, source.message.edns, source.request.edns.options[0], source.message.edns.options[0])]
        value = completed.dns_edns_statistics
        record(instance, identifier=2)
        del completed, source
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(value.option_count, 2)

    def test_releasing_owner_releases_nonempty_aggregate(self):
        instance = manager()
        active = record(instance, response=True, data=option(1))
        reference = weakref.ref(active.dns_edns_statistics)
        instance.close(active.identity)
        del active
        gc.collect()
        self.assertIsNone(reference())

    def test_earlier_dns_statistics_and_generic_projection_are_unchanged(self):
        actual = run_packets(packets())
        empty = DNSEDNSStatistics()
        with patch('analysis.flow_state_coordinator.update_dns_edns_statistics', return_value=empty):
            with patch('analysis.flow_observation_window.update_dns_edns_statistics', return_value=empty):
                baseline = run_packets(packets())
        self.assertEqual(len(actual), len(baseline))
        for first, second in zip(actual, baseline):
            for name in ('dns_transaction_statistics', 'dns_query_name_statistics',
                         'dns_resource_record_statistics', 'dns_message_flag_statistics', 'dns_correlation_state'):
                self.assertEqual(getattr(first, name), getattr(second, name))
            left, right = extract_flow_feature_snapshot(first), extract_flow_feature_snapshot(second)
            self.assertEqual(left.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
            self.assertEqual(snapshot_features(left), snapshot_features(right))
            self.assertEqual(project_flow_features(left), project_flow_features(right))
            self.assertEqual(len(project_flow_features(left).values), 49)

    def test_legacy_constructor_and_new_field_validation(self):
        state = FlowStateCoordinator().record(analyze_packet(packet()))
        values = tuple(getattr(state, member.name) for member in fields(state) if member.name not in ('dns_edns_statistics', 'dns_stream_state', 'tls_record_state', 'tls_handshake_state', 'tls_handshake_statistics', 'tls_client_hellos', 'tls_client_hello_statistics', 'tls_server_hellos', 'tls_server_hello_statistics', 'ipv6_extension_header_statistics', 'tcp_option_statistics'))
        self.assertEqual(type(state)(*values).dns_edns_statistics, DNSEDNSStatistics())
        with self.assertRaises(TypeError):
            replace(state, dns_edns_statistics={})

    def test_bounded_flow_churn_conserves_all_message_and_option_counts(self):
        instance = manager(3)
        totals = [0, 0, 0]
        for index in range(180):
            update = instance.record(analyze_packet(packet(identifier=index % 7, response=bool(index % 3),
                                     data=option(index) + option(65535, b'ab'), ipv6=bool(index % 2),
                                     client_port=12345 + index % 5)))
            self.assertLessEqual(len(instance.active_windows()), 3)
            for window in update.closed_windows:
                value = window.dns_edns_statistics
                totals = [totals[0] + value.edns_message_count, totals[1] + value.option_count,
                          totals[2] + value.total_option_data_length_bytes]
            value = update.active_window.dns_edns_statistics
            self.assertEqual(len(vars(value)), 15)
            self.assertEqual(sum(map(sum, value.option_code_counts)), value.option_count)
            self.assertEqual(sum(value.version_counts), value.edns_message_count)
        for window in instance.end_capture_session():
            value = window.dns_edns_statistics
            totals = [totals[0] + value.edns_message_count, totals[1] + value.option_count,
                      totals[2] + value.total_option_data_length_bytes]
        self.assertEqual(totals, [180, 360, 360])

    def test_existing_edns_traffic_has_equal_statistics_in_four_classic_pcap_encodings(self):
        traffic = packets()
        expected = [observable(window.dns_edns_statistics) for window in run_packets(traffic)]
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'edns-statistics.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    with self.subTest(order=order, nano=nano):
                        path.write_bytes(pcap_bytes(tuple((index * 100000, item.raw_bytes)
                                                          for index, item in enumerate(traffic)), order, nano))
                        windows = []
                        run_flow_observation_session(PcapPacketSource(path), capture_session_id='edns-statistics',
                                                     inactivity_timeout=timedelta(seconds=5), closed_window_consumer=windows.append)
                        self.assertEqual([observable(window.dns_edns_statistics) for window in windows], expected)

    def test_independent_replay_is_identical(self):
        self.assertEqual(replay(), replay())

    def test_all_nine_hash_seed_timezone_combinations(self):
        script = ('from tests.test_dns_edns_statistics_lifecycle import replay\n'
                  'import hashlib\nprint(hashlib.sha256(repr(replay()).encode()).hexdigest())\n')
        expected = hashlib.sha256(repr(replay()).encode()).hexdigest().encode() + b'\n'
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                with self.subTest(seed=seed, zone=zone):
                    actual = subprocess.check_output([sys.executable, '-B', '-c', script],
                                                    env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
                    self.assertEqual(actual, expected)
