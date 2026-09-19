import os
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from pathlib import Path
from struct import pack
from tempfile import TemporaryDirectory
from unittest.mock import PropertyMock, patch

from analysis import (
    FlowCoordinationError, FlowObservationWindowManager, FlowObservationWindowUpdate,
    FlowStateCoordinator, LDAPFlowStatistics, LDAPMessageStatus, PacketAnalysis, analyze_packet,
    analyze_packet_outcome, extract_flow_feature_snapshot, flow_identity_from_packet,
    update_ldap_flow_statistics,
)
from application import GroundTruth, run_end_to_end_validation
from capture import CaptureSource, PcapPacketSource
from research import research_example_from_window
from tests.pcap_scenarios import addresses, checksum, frame, pcap_bytes, transport
from tests.protocol_scenarios import observation
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ldap import RESULT, message
from tests.test_packet_analysis import make_observation


def ldap_observation(payload, seconds=0, ipv6=False, reverse=False, port=389, sequence=100,
                     options=b'', fragment=None):
    segment = transport(6, payload, ipv6, reverse, sequence=sequence, flags=24, options=options)
    ports = (port, 12345) if reverse else (12345, port)
    segment = pack('!HH', *ports) + segment[4:16] + b'\x00\x00' + segment[18:]
    source, destination = addresses(ipv6, reverse)
    pseudo = source + destination + (pack('!I3xB', len(segment), 6) if ipv6 else pack('!BBH', 0, 6, len(segment)))
    segment = segment[:16] + checksum(pseudo + segment).to_bytes(2, 'big') + segment[18:]
    return observation(frame(6, segment, ipv6, reverse, fragment=fragment), seconds)


def observe_payloads(payloads, ipv6=False):
    manager = FlowObservationWindowManager('ldap', timedelta(seconds=5))
    for index, payload in enumerate(payloads):
        manager.record(analyze_packet(ldap_observation(payload, index, ipv6)))
    return manager.end_capture_session()[0]


class LDAPFlowTests(unittest.TestCase):
    def test_ipv4_ipv6_packet_flow_and_feature_observations(self):
        for ipv6 in (False, True):
            manager = FlowObservationWindowManager('ldap', timedelta(seconds=5))
            first = analyze_packet(ldap_observation(message(0x60, b'opaque') + message(0x63), ipv6=ipv6,
                                                  options=b'\x01\x01\x00\x00'))
            before = replace(first)
            self.assertEqual(len(first.ldap.messages), 2)
            manager.record(first)
            manager.record(analyze_packet(ldap_observation(message(0x61, RESULT), 1, ipv6, True)))
            window = manager.end_capture_session()[0]
            statistics = window.coordinated_state.ldap_statistics
            self.assertEqual((statistics.complete_message_count, statistics.request_count, statistics.response_count), (3, 2, 1))
            self.assertEqual(window.coordinated_state.flow_statistics.packet_count, 2)
            self.assertEqual(window.identity.ip_version, 6 if ipv6 else 4)
            controls = window.coordinated_state.tcp_control_statistics
            self.assertEqual((controls.forward_ack_count, controls.reverse_ack_count), (1, 1))
            self.assertEqual(first, before)
            snapshot = extract_flow_feature_snapshot(window)
            self.assertIs(snapshot.ldap_statistics, statistics)
            self.assertEqual(len(research_example_from_window(window).projection.values), 49)

    def test_empty_non_ldap_nonstandard_port_and_encrypted_payloads_remain_tcp(self):
        for ipv6 in (False, True):
            for payload, port in ((b'', 389), (b'GET / HTTP/1.1', 389),
                                  (b'\x16\x03\x03\x00\x05abcde', 389),
                                  (message(), 636), (message(), 1389), (message(), 443)):
                with self.subTest(ipv6=ipv6, payload=payload, port=port):
                    packet = analyze_packet(ldap_observation(payload, ipv6=ipv6, port=port))
                    self.assertIsNone(packet.ldap)
                    state = FlowStateCoordinator().record(packet)
                    self.assertIsNone(state.ldap_statistics)
                    self.assertEqual(state.flow_statistics.packet_count, 1)

    def test_split_segments_are_not_joined_or_reclassified_after_later_packets(self):
        raw = message(0x60, b'abcdefgh')
        for ipv6 in (False, True):
            manager = FlowObservationWindowManager('split', timedelta(seconds=5))
            first = manager.record(analyze_packet(ldap_observation(raw[:8], ipv6=ipv6))).active_window
            second = manager.record(analyze_packet(ldap_observation(raw[8:], 1, ipv6, sequence=108))).active_window
            self.assertEqual(first.coordinated_state.ldap_statistics.incomplete_observation_count, 1)
            self.assertIs(second.coordinated_state.ldap_statistics, first.coordinated_state.ldap_statistics)
            manager.record(analyze_packet(ldap_observation(message(), 2, ipv6, sequence=100 + len(raw))))
            closed = manager.end_capture_session()[0]
            self.assertEqual(closed.coordinated_state.ldap_statistics.complete_message_count, 1)
            self.assertEqual(first.coordinated_state.ldap_statistics.complete_message_count, 0)

    def test_retransmission_and_observation_order_are_not_stream_deduplicated(self):
        window = observe_payloads((message(), message()))
        self.assertEqual(window.coordinated_state.ldap_statistics.complete_message_count, 2)

    def test_malformed_incomplete_unknown_and_valid_traffic_share_normal_flow(self):
        window = observe_payloads((b'\x30\xff', b'\x30', message(0x7A), message()))
        statistics = window.coordinated_state.ldap_statistics
        self.assertEqual((statistics.complete_message_count, statistics.malformed_observation_count,
                          statistics.incomplete_observation_count, statistics.unsupported_observation_count), (1, 1, 1, 1))
        self.assertEqual(window.coordinated_state.flow_statistics.packet_count, 4)
        limited = observe_payloads((message() * 129,)).coordinated_state.ldap_statistics
        self.assertEqual((limited.complete_message_count, limited.limited_payload_count), (128, 1))

    def test_interleaved_unrelated_flows_do_not_affect_ldap_statistics(self):
        manager = FlowObservationWindowManager('mixed', timedelta(seconds=5))
        for second in range(3):
            for ipv6 in (False, True):
                manager.record(analyze_packet(ldap_observation(message(), second, ipv6)))
                manager.record(analyze_packet(ldap_observation(b'HTTP', second, ipv6, port=443)))
                manager.record(analyze_packet(observation(frame(17, transport(17, b'UDP', ipv6), ipv6), second)))
        windows = manager.end_capture_session()
        self.assertEqual(len(windows), 6)
        for window in windows:
            self.assertEqual(window.coordinated_state.flow_statistics.packet_count, 3)
            if window.identity.destination_port == 389:
                expected = observe_payloads((message(),) * 3, window.identity.ip_version == 6)
                self.assertEqual(window.coordinated_state, expected.coordinated_state)
            else:
                self.assertIsNone(window.coordinated_state.ldap_statistics)

    def test_fragmented_and_truncated_capture_observations_keep_existing_admission(self):
        packet = analyze_packet(ldap_observation(message()[:4], ipv6=True, fragment=(0, True)))
        self.assertEqual(packet.ldap.messages[0].status, LDAPMessageStatus.INCOMPLETE)
        self.assertEqual(FlowStateCoordinator().record(packet).ldap_statistics.incomplete_observation_count, 1)
        non_first = analyze_packet(ldap_observation(message()[4:], ipv6=True, fragment=(1, False)))
        self.assertIsNone(non_first.ldap)
        original = ldap_observation(message()[:4])
        first_ipv4 = analyze_packet(make_observation(6, original.raw_bytes[34:58], fragment_field=0x2000))
        self.assertEqual(first_ipv4.ldap.messages[0].status, LDAPMessageStatus.INCOMPLETE)
        self.assertEqual(FlowStateCoordinator().record(first_ipv4).ldap_statistics.incomplete_observation_count, 1)
        captured = replace(original, original_length=original.original_length + 3)
        outcome = analyze_packet_outcome(captured)
        self.assertTrue(outcome.succeeded)
        self.assertEqual(outcome.analysis.ldap.messages[0].status, LDAPMessageStatus.INCOMPLETE)

    def test_closed_windows_and_publication_failure_preserve_immutable_statistics(self):
        manager = FlowObservationWindowManager('atomic', timedelta(seconds=5))
        first = analyze_packet(ldap_observation(message()))
        manager.record(first)
        before = manager.active_windows()
        with patch.object(FlowObservationWindowUpdate, '__post_init__', side_effect=RuntimeError('publication')):
            with self.assertRaises(RuntimeError):
                manager.record(analyze_packet(ldap_observation(message(), 2)))
        self.assertEqual(manager.active_windows(), before)
        accepted = manager.record(analyze_packet(ldap_observation(message(), 1))).active_window
        closed = manager.close(flow_identity_from_packet(first))
        self.assertEqual(closed.coordinated_state.ldap_statistics.complete_message_count, 2)
        restarted = manager.record(analyze_packet(ldap_observation(message(), 2))).active_window
        self.assertEqual(restarted.coordinated_state.ldap_statistics.complete_message_count, 1)
        self.assertEqual(accepted.coordinated_state.ldap_statistics.complete_message_count, 2)
        expired = manager.record(analyze_packet(ldap_observation(message(), 8)))
        self.assertEqual(expired.closed_windows[0].coordinated_state.ldap_statistics.complete_message_count, 1)
        self.assertEqual(expired.active_window.coordinated_state.ldap_statistics.complete_message_count, 1)

    def test_statistics_contract_validation_and_legacy_constructor_compatibility(self):
        packet = analyze_packet(ldap_observation(message()))
        state = FlowStateCoordinator().record(packet)
        statistics = state.ldap_statistics
        for field in fields(statistics):
            with self.assertRaises(FrozenInstanceError):
                setattr(statistics, field.name, None)
            if field.name != 'identity':
                with self.assertRaises(TypeError):
                    replace(statistics, **{field.name: True})
                with self.assertRaises(ValueError):
                    replace(statistics, **{field.name: -1})
        with self.assertRaises(ValueError):
            replace(statistics, request_count=0)
        with self.assertRaises(ValueError):
            replace(statistics, identity=replace(state.identity, protocol=17))
        with self.assertRaises(TypeError):
            replace(state, ldap_statistics=object())
        with self.assertRaises(FlowCoordinationError):
            replace(state, ldap_statistics=replace(statistics, identity=replace(state.identity, source_port=12346)))
        with self.assertRaises(ValueError):
            update_ldap_flow_statistics(statistics, packet, replace(state.identity, source_port=12346))
        with self.assertRaises(ValueError):
            update_ldap_flow_statistics(replace(statistics, identity=replace(state.identity, source_port=12346)), packet, state.identity)
        for args in ((object(), packet, state.identity), (None, object(), state.identity), (None, packet, object())):
            with self.assertRaises(TypeError):
                update_ldap_flow_statistics(*args)
        legacy = type(state)(*(getattr(state, field.name) for field in fields(state)
                               if field.name not in ('ldap_statistics', 'tcp_stream_state', 'ldap_stream_state',
                                                     'ldap_correlation_state', 'dns_transaction_statistics', 'dns_query_name_statistics', 'dns_resource_record_statistics', 'dns_message_flag_statistics', 'dns_edns_statistics', 'dns_stream_state', 'tls_record_state', 'tls_handshake_state', 'tls_handshake_statistics', 'tls_client_hellos', 'tls_client_hello_statistics', 'tls_server_hellos', 'tls_server_hello_statistics', 'ipv6_extension_header_statistics', 'tcp_option_statistics', 'ip_hop_limit_statistics')))
        self.assertIsNone(legacy.ldap_statistics)

    def test_detection_evaluation_and_pcap_do_not_classify_ldap_parse_failures(self):
        config = settings()
        config = replace(config, flow_volume_configuration=replace(config.flow_volume_configuration, threshold=100),
                         tcp_control_configuration=replace(config.tcp_control_configuration, threshold=100))
        packets = tuple(ldap_observation(payload, index, ipv6) for index, (payload, ipv6) in enumerate(
            ((message(0x60), False), (b'\x30\xff', False), (b'\x30', True), (message(0x61, RESULT), True))))
        expected = run_end_to_end_validation(MemoryPacketSource(packets), configuration=config,
                                            capture_session_id='pcap', ground_truth=GroundTruth((), ()))
        with patch.object(PacketAnalysis, 'ldap', new_callable=PropertyMock, return_value=None):
            baseline = run_end_to_end_validation(MemoryPacketSource(packets), configuration=config,
                                                capture_session_id='pcap', ground_truth=GroundTruth((), ()))
        self.assertEqual(expected.pipeline_result.packet_findings, baseline.pipeline_result.packet_findings)
        self.assertEqual(expected.report.metrics, baseline.report.metrics)
        self.assertEqual(len(expected.pipeline_result.flow_findings), len(baseline.pipeline_result.flow_findings))
        for finding, original in zip(expected.pipeline_result.flow_findings, baseline.pipeline_result.flow_findings):
            evidence = finding.raw_evidence
            window = evidence.snapshot.observation_window if hasattr(evidence, 'snapshot') else evidence.observation_window
            stripped = replace(window, coordinated_state=replace(window.coordinated_state, ldap_statistics=None))
            if hasattr(evidence, 'snapshot'):
                evidence = replace(evidence, snapshot=extract_flow_feature_snapshot(stripped))
            else:
                evidence = replace(evidence, observation_window=stripped)
            self.assertEqual(replace(finding, raw_evidence=evidence), original)
        self.assertTrue(all(finding.decision.value != 'match' for finding in expected.pipeline_result.packet_findings))
        self.assertTrue(all(finding.decision.value != 'match' for finding in expected.pipeline_result.flow_findings))
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'ldap.pcap'
            path.write_bytes(pcap_bytes(tuple((index * 1000000, packet.raw_bytes) for index, packet in enumerate(packets))))
            actual = run_end_to_end_validation(PcapPacketSource(path, source=CaptureSource('protocol-combinations')),
                                              configuration=config, capture_session_id='pcap', ground_truth=GroundTruth((), ()))
        self.assertEqual(actual, expected)

    def test_hash_seed_timezone_and_repeated_process_determinism(self):
        script = (
            "from tests.test_ldap_flow_statistics import observe_payloads\n"
            "from tests.test_ldap import message\n"
            "from analysis import analyze_ldap_payload\n"
            "import sys\n"
            "payloads = (message(), b'\\x30', b'\\x30\\xff', message(0x7a))\n"
            "sys.stdout.write(repr((tuple(analyze_ldap_payload(p) for p in payloads), "
            "tuple(observe_payloads(payloads, v) for v in (False, True)))))\n"
        )
        outputs = []
        for seed, zone in (('0', 'UTC'), ('1', 'Asia/Kolkata'), ('7321', 'America/Los_Angeles'), ('0', 'UTC')):
            environment = dict(os.environ, PYTHONHASHSEED=seed, TZ=zone, PYTHONPATH='src', PYTHONDONTWRITEBYTECODE='1')
            outputs.append(subprocess.check_output([sys.executable, '-c', script], env=environment, timeout=15))
        self.assertTrue(all(output == outputs[0] for output in outputs))


if __name__ == '__main__':
    unittest.main()
