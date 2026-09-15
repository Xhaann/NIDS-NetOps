import ast
import gc
import os
import subprocess
import sys
import unittest
import weakref
from dataclasses import asdict, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import (
    DNSCorrelationStatus, DNSMessageStatus, FeatureContractVersion, FlowDirection,
    analyze_dns_message, analyze_packet, analyze_packet_outcome, extract_flow_feature_snapshot,
    update_dns_correlation_state,
)
from application import run_flow_observation_session
from capture import CaptureError, PcapPacketSource
from ml import project_flow_features
from tests.pcap_scenarios import pcap_bytes
from tests.test_dns import name, question, record
from tests.test_dns_correlation import EPOCH, IDENTITY
from tests.test_dns_correlation_lifecycle import manager
from tests.test_dns_edns import adversarial_edns_payloads, message, opt, option
from tests.test_dns_header_control_flags import semantic_values
from tests.test_dns_message_flag_statistics import expected_statistics
from tests.test_dns_packet_analysis import dns_packet
from tests.test_dns_resource_record_statistics import altered_observation
from tests.test_dns_transaction_statistics_lifecycle import run_packets
from tests.test_flow_feature_snapshot import snapshot_features
from tests.test_flow_observation_session import MemoryPacketSource


def packet(size=1232, extended=0, version=0, edns_flags=0, data=b'', flags=0, **kwargs):
    raw = message(opt(size, extended, version, edns_flags, data), flags=flags, questions=(question(name(b'Example')),))
    return dns_packet(raw, reverse=bool(flags & 0x8000), **kwargs)


def packets():
    return (packet(size=512, data=option(1, b'a'), flags=0x0130),
            packet(size=4096, version=1, edns_flags=0x8000, ipv6=True),
            packet(size=65535, extended=255, flags=0x87b3, data=option(65535, b'\xff')),
            packet(size=1232, version=2, edns_flags=1, flags=0x8080, ipv6=True),
            packet(size=900, client_port=12346), packet(size=901, flags=0x8000, client_port=12346))


def without_edns(raw):
    value = analyze_dns_message(raw)
    return altered_observation(value, additionals=tuple(altered_observation(item, edns=None) for item in value.additionals))


def replay():
    observations = tuple(asdict(analyze_packet(item).dns) for item in packets())
    windows = run_packets(packets())
    terminal = tuple((window.key.sequence_number, window.identity.ip_version, window.closure_reason.value,
                      tuple((item.status.value, None if item.request is None else asdict(item.request.edns),
                             asdict(item.message.edns)) for item in window.dns_correlation_state.observations))
                     for window in windows)
    invalid = tuple((value.status.value, value.reason, value.failure_offset, value.limit_reached, value.edns)
                    for value in map(analyze_dns_message, adversarial_edns_payloads()))
    return observations, terminal, invalid


class DNSEDNSIntegrationTests(unittest.TestCase):
    def test_ipv4_udp_uses_existing_packet_analysis(self):
        item = packet(edns_flags=0x8000, data=option(1, b'abc'))
        value = analyze_packet(item)
        self.assertEqual(value.dns, analyze_dns_message(value.udp.payload))
        self.assertTrue(value.dns.edns.dnssec_ok)
        self.assertTrue(value.udp_checksum_valid)

    def test_ipv6_udp_has_equivalent_edns(self):
        first = analyze_packet(packet(edns_flags=0x8000)).dns
        second = analyze_packet(packet(edns_flags=0x8000, ipv6=True)).dns
        self.assertEqual(first.edns, second.edns)

    def test_ipv6_extension_headers_delegate_to_same_parser(self):
        value = analyze_packet(packet(version=9, ipv6=True, extensions=(0, 60))).dns
        self.assertEqual(value.edns.version, 9)

    def test_already_delimited_tcp_transactions_preserve_both_edns_values(self):
        identity = replace(IDENTITY, protocol=6)
        raw_request = message(opt(size=512, data=option(1, b'a')))
        raw_response = message(opt(size=4096, flags=0x8000), flags=0x8000)
        request = analyze_dns_message(raw_request)
        response = analyze_dns_message(raw_response)
        state = update_dns_correlation_state(None, request, identity, FlowDirection.FORWARD, EPOCH)
        state = update_dns_correlation_state(state, response, identity, FlowDirection.REVERSE, EPOCH)
        transaction, = state.observations
        self.assertIs(transaction.status, DNSCorrelationStatus.MATCHED)
        self.assertIs(transaction.request.edns, request.edns)
        self.assertIs(transaction.message.edns, response.edns)
        self.assertEqual((request.edns.udp_payload_size, response.edns.udp_payload_size), (512, 4096))
        self.assertIsNone(analyze_packet(dns_packet(raw_request, protocol=6)).dns)

    def test_non_dns_port_does_not_trigger_edns_parsing(self):
        with patch('analysis.dns._edns', side_effect=AssertionError('unexpected EDNS')):
            self.assertIsNone(analyze_packet(packet(port=5353)).dns)

    def test_interleaved_ip_versions_and_client_ports_keep_same_ids_independent(self):
        windows = run_packets(packets())
        self.assertEqual(len(windows), 3)
        self.assertEqual([window.identity.ip_version for window in windows], [4, 6, 4])
        self.assertEqual([(item.request.edns.udp_payload_size, item.message.edns.udp_payload_size)
                          for window in windows for item in window.dns_correlation_state.observations],
                         [(512, 65535), (4096, 1232), (900, 901)])
        self.assertTrue(all(window.dns_transaction_statistics.matched_count == 1 for window in windows))

    def test_sequential_transaction_id_reuse_has_no_edns_history(self):
        instance = manager()
        for size in range(512, 532):
            instance.record(analyze_packet(packet(size=size)))
            window = instance.record(analyze_packet(packet(size=size + 1, flags=0x8000))).active_window
            item, = window.dns_correlation_state.observations
            self.assertEqual((item.request.edns.udp_payload_size, item.message.edns.udp_payload_size), (size, size + 1))
            self.assertEqual(window.dns_correlation_state.requests, ())
        self.assertEqual(window.dns_transaction_statistics.matched_count, 20)

    def test_flow_close_and_readmission_use_existing_ownership(self):
        instance = manager()
        before = instance.record(analyze_packet(packet(size=4096))).active_window
        closed = instance.close(before.identity)
        self.assertEqual(closed.dns_correlation_state.observations[0].message.edns.udp_payload_size, 4096)
        after = instance.record(analyze_packet(packet(size=512))).active_window
        self.assertEqual(after.dns_correlation_state.requests[0].message.edns.udp_payload_size, 512)
        self.assertEqual(after.dns_transaction_statistics.total_transaction_count, 0)

    def test_valid_edns_does_not_change_any_existing_statistics(self):
        actual = run_packets(packets())
        with patch('analysis.packet_analysis.analyze_dns_message', side_effect=without_edns):
            baseline = run_packets(packets())
        for first, second in zip(actual, baseline):
            for field in ('dns_transaction_statistics', 'dns_query_name_statistics', 'dns_resource_record_statistics', 'dns_message_flag_statistics'):
                self.assertEqual(getattr(first, field), getattr(second, field))
        self.assertEqual(len(actual), len(baseline))

    def test_extended_rcode_does_not_change_feature_fourteen_bins(self):
        window, = run_packets((packet(extended=255, flags=0x8003),))
        value = window.dns_transaction_statistics
        self.assertEqual(value.response_code_counts, (0, 0, 0, 1) + (0,) * 12)
        self.assertEqual((value.additional_count, value.question_count), (1, 1))

    def test_opt_owner_is_not_a_query_name(self):
        window, = run_packets((packet(flags=0x8000),))
        value = window.dns_query_name_statistics
        self.assertEqual(value.query_name_count, 1)
        self.assertEqual(value.root_name_count, 0)

    def test_opt_record_and_rdata_are_counted_once_by_feature_sixteen(self):
        data = option(1, b'abc') + option(2)
        window, = run_packets((packet(size=4096, data=data, flags=0x8000),))
        value = window.dns_resource_record_statistics
        self.assertEqual((value.resource_record_count, value.additional_count), (1, 1))
        self.assertEqual(value.type_counts[0][41], 1)
        self.assertEqual(value.class_counts[16][0], 1)
        self.assertEqual(value.total_rdata_length_bytes, 11)

    def test_do_does_not_change_header_flags_or_feature_nineteen(self):
        for flags in (0, 0x8000, 0x7fff, 0xffff):
            window, = run_packets((packet(edns_flags=flags, flags=0x87b0),))
            self.assertEqual(window.dns_message_flag_statistics, expected_statistics(0x87b0))
            self.assertEqual(semantic_values(window.dns_correlation_state.observations[0].message.header), (True,) * 7)

    def test_generic_version_one_and_all_49_projected_values_are_unchanged(self):
        actual = run_packets(packets())
        with patch('analysis.packet_analysis.analyze_dns_message', side_effect=without_edns):
            baseline = run_packets(packets())
        for first, second in zip(actual, baseline):
            left, right = extract_flow_feature_snapshot(first), extract_flow_feature_snapshot(second)
            self.assertEqual(left.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
            self.assertEqual(snapshot_features(left), snapshot_features(right))
            self.assertEqual(project_flow_features(left), project_flow_features(right))
            self.assertEqual(len(project_flow_features(left).values), 49)

    def test_invalid_edns_messages_do_not_enter_correlation_or_statistics(self):
        cases = ((message(opt(data=b'\xff')), DNSMessageStatus.MALFORMED),
                 (message(opt(data=option()))[:-1], DNSMessageStatus.INCOMPLETE),
                 (message(opt(data=option() * 129)), DNSMessageStatus.UNSUPPORTED))
        for raw, status in cases:
            item = dns_packet(raw)
            outcome = analyze_packet_outcome(item)
            self.assertIsNone(outcome.failure_classification)
            self.assertIs(outcome.analysis.dns.status, status)
            window, = run_packets((item,))
            self.assertIsNone(window.dns_correlation_state)
            self.assertEqual(window.dns_transaction_statistics.total_transaction_count, 0)
            self.assertEqual(window.dns_query_name_statistics.query_name_count, 0)
            self.assertEqual(window.dns_resource_record_statistics.resource_record_count, 0)
            self.assertEqual(window.dns_message_flag_statistics.message_count, 0)

    def test_invalid_edns_does_not_release_or_match_pending_request(self):
        instance = manager()
        first = instance.record(analyze_packet(packet())).active_window
        raw = message(opt(data=b'\xff'), flags=0x8000, questions=(question(name(b'Example')),))
        after = instance.record(analyze_packet(dns_packet(raw, reverse=True))).active_window
        self.assertIs(after.dns_correlation_state.requests[0], first.dns_correlation_state.requests[0])
        self.assertEqual(after.dns_correlation_state.observations, ())
        matched = instance.record(analyze_packet(packet(flags=0x8000))).active_window
        self.assertEqual(matched.dns_transaction_statistics.matched_count, 1)

    def test_parser_infrastructure_failure_propagates_without_admission(self):
        instance = manager()
        with patch('analysis.dns._edns', side_effect=MemoryError('EDNS allocation')):
            with self.assertRaises(MemoryError):
                instance.record(analyze_packet(packet()))
        self.assertEqual(instance.active_windows(), ())

    def test_failed_packet_analysis_does_not_parse_edns(self):
        source = replace(packet(), raw_bytes=b'\x00', captured_length=1)
        with patch('analysis.dns._edns', side_effect=AssertionError('EDNS on invalid packet')):
            outcome = analyze_packet_outcome(source)
        self.assertIsNone(outcome.analysis)
        self.assertIsNotNone(outcome.failure_classification)

    def test_capture_failure_preserves_terminal_publication_and_cleanup(self):
        source = MemoryPacketSource((packet(size=4096), packet(size=512, flags=0x8000)), iteration_error=CaptureError('capture'))
        closed = []
        with self.assertRaises(CaptureError):
            run_flow_observation_session(source, capture_session_id='edns', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=closed.append)
        item, = closed[0].dns_correlation_state.observations
        self.assertIs(item.status, DNSCorrelationStatus.MATCHED)
        self.assertEqual((item.request.edns.udp_payload_size, item.message.edns.udp_payload_size), (4096, 512))
        self.assertEqual(source.events[-1], 'stop')

    def test_retained_edns_releases_packet_transaction_and_flow_graph(self):
        instance = manager()
        analyzed = analyze_packet(packet(data=option(1, b'abc')))
        active = instance.record(analyzed).active_window
        request = active.dns_correlation_state.requests[0]
        closed = instance.close(active.identity)
        terminal = closed.dns_correlation_state.observations[0]
        references = [weakref.ref(item) for item in (analyzed, analyzed.observation, active, active.coordinated_state,
                      request, request.message, request.message.header, request.message.additionals[0], terminal, closed)]
        value = request.message.edns
        del analyzed, active, request, terminal, closed
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(value.options[0].data, b'abc')

    def test_four_classic_pcap_encodings_preserve_edns(self):
        traffic = packets()
        expected = tuple(analyze_packet(item).dns.edns for item in traffic)
        expected_windows = run_packets(traffic)
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'edns.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    path.write_bytes(pcap_bytes(tuple((index * 100000, item.raw_bytes) for index, item in enumerate(traffic)), order, nano))
                    source = PcapPacketSource(path)
                    source.start()
                    try:
                        actual = tuple(analyze_packet(item).dns.edns for item in source)
                    finally:
                        source.stop()
                    self.assertEqual(actual, expected)
                    windows = []
                    run_flow_observation_session(PcapPacketSource(path), capture_session_id='edns',
                                                 inactivity_timeout=timedelta(seconds=5), closed_window_consumer=windows.append)
                    for actual_window, expected_window in zip(windows, expected_windows):
                        self.assertEqual([(item.request.edns, item.message.edns) for item in actual_window.dns_correlation_state.observations],
                                         [(item.request.edns, item.message.edns) for item in expected_window.dns_correlation_state.observations])
                    self.assertEqual(len(windows), len(expected_windows))

    def test_repeated_independent_replay(self):
        self.assertEqual(replay(), replay())

    def test_all_nine_hash_seed_timezone_combinations(self):
        script = 'from tests.test_dns_edns_integration import replay; print(repr(replay()))'
        expected = None
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                value = subprocess.check_output([sys.executable, '-B', '-c', script],
                                                env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
                if expected is None:
                    expected = value
                self.assertEqual(value, expected)

    def test_edns_helper_uses_only_existing_record_boundary(self):
        tree = ast.parse(Path('src/analysis/dns.py').read_text())
        function, = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_edns']
        calls = {node.func.id for node in ast.walk(function) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertEqual(calls, {'len', '_DNSParseError', 'unpack_from', '_observation', 'tuple'})
        self.assertFalse(any(isinstance(node, ast.Name) and node.id == 'payload' for node in ast.walk(function)))
        self.assertEqual({node.attr for node in ast.walk(function) if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'record'},
                         {'rdata', 'record_class', 'ttl'})
