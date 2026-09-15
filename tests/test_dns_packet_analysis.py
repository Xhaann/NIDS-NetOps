import os
import subprocess
import sys
import unittest
from dataclasses import fields, replace
from datetime import timedelta
from pathlib import Path
from struct import pack
from tempfile import TemporaryDirectory
from unittest.mock import PropertyMock, patch

from analysis import (
    DNSMessageStatus, DNSQueryNameStatistics, DNSResourceRecordStatistics, DNSTransactionStatistics, FlowObservationWindowManager, PacketAnalysis,
    analyze_dns_message, analyze_packet, analyze_packet_outcome, extract_flow_feature_snapshot,
)
from application import GroundTruth, run_end_to_end_validation, run_streaming_evaluation
from capture import CaptureError, CaptureSource, PcapPacketSource
from detection import DetectionFinding
from tests.pcap_scenarios import addresses, checksum, frame, pcap_bytes, transport
from tests.protocol_scenarios import observation
from tests.test_dns import header, name, question, record
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource


def dns_packet(payload, ipv6=False, reverse=False, protocol=17, port=53, seconds=0, extensions=(), client_port=12345):
    segment = transport(protocol, payload, ipv6, reverse)
    ports = (port, client_port) if reverse else (client_port, port)
    offset = 6 if protocol == 17 else 16
    segment = pack('!HH', *ports) + segment[4:offset] + b'\x00\x00' + segment[offset + 2:]
    source, destination = addresses(ipv6, reverse)
    pseudo = source + destination + (pack('!I3xB', len(segment), protocol) if ipv6 else pack('!BBH', 0, protocol, len(segment)))
    value = checksum(pseudo + segment) or 65535
    segment = segment[:offset] + pack('!H', value) + segment[offset + 2:]
    return observation(frame(protocol, segment, ipv6, reverse, extensions), seconds)


def samples():
    return tuple(dns_packet(payload, ipv6, reverse, seconds=index)
                 for index, (ipv6, reverse, payload) in enumerate(
                     (ipv6, reverse, payload) for ipv6 in (False, True) for reverse in (False, True)
                     for payload in (header(1) + question(name(b'example')), header(flags=0x8003), b'', header(1) + b'\xc0\x0c')))


class DNSPacketTests(unittest.TestCase):
    def test_ipv4_udp_request_and_response_ports(self):
        for reverse in (False, True):
            raw = header(1, flags=0x8000 if reverse else 0) + question(name(b'example'))
            packet = analyze_packet(dns_packet(raw, reverse=reverse))
            self.assertTrue(packet.udp_checksum_valid)
            self.assertEqual(packet.dns, analyze_dns_message(raw))

    def test_ipv6_udp_request_and_response_ports(self):
        for reverse in (False, True):
            raw = header(1, flags=0x8000 if reverse else 0) + question(name(b'example'))
            packet = analyze_packet(dns_packet(raw, ipv6=True, reverse=reverse))
            self.assertTrue(packet.udp_checksum_valid is None)
            self.assertEqual(packet.dns, analyze_dns_message(raw))
            self.assertIsNone(analyze_packet_outcome(packet.observation).failure_classification)

    def test_ipv6_extension_headers_delegate_transport_boundary(self):
        raw = header(1) + question()
        packet = analyze_packet(dns_packet(raw, ipv6=True, extensions=(0, 60)))
        self.assertEqual(packet.dns, analyze_dns_message(raw))

    def test_other_udp_ports_are_not_dispatched(self):
        for ipv6 in (False, True):
            self.assertIsNone(analyze_packet(dns_packet(header(), ipv6, port=5353)).dns)
            self.assertEqual(analyze_dns_message(header()).status, DNSMessageStatus.COMPLETE)

    def test_empty_and_malformed_dns_are_transport_successes(self):
        for ipv6 in (False, True):
            for payload, status in ((b'', DNSMessageStatus.INCOMPLETE), (header(1) + b'\x80', DNSMessageStatus.MALFORMED)):
                outcome = analyze_packet_outcome(dns_packet(payload, ipv6))
                self.assertIsNone(outcome.failure_classification)
                self.assertIs(outcome.analysis.dns.status, status)

    def test_ethernet_padding_is_excluded(self):
        for ipv6 in (False, True):
            packet = analyze_packet(dns_packet(header(), ipv6))
            self.assertEqual(packet.dns.parsed_length, 12)
            self.assertIs(packet.dns.status, DNSMessageStatus.COMPLETE)

    def test_tcp_requires_external_message_delimitation(self):
        raw = header(1) + question()
        for ipv6 in (False, True):
            for reverse in (False, True):
                packet = analyze_packet(dns_packet(pack('!H', len(raw)) + raw, ipv6, reverse, protocol=6))
                self.assertIsNone(packet.dns)
                tcp = packet.ipv6_tcp if ipv6 else packet.tcp
                length = int.from_bytes(tcp.payload[:2], 'big')
                self.assertEqual(len(tcp.payload), length + 2)
                self.assertEqual(analyze_dns_message(tcp.payload[2:]), analyze_dns_message(raw))

    def test_split_and_coalesced_tcp_payloads_are_not_guessed(self):
        raw = header(1) + question()
        for ipv6 in (False, True):
            for payload in (b'\x00', raw[:5], pack('!H', len(raw)) + raw + pack('!H', len(raw)) + raw):
                self.assertIsNone(analyze_packet(dns_packet(payload, ipv6, protocol=6)).dns)

    def test_dns_property_is_lazy_and_delegates_exact_payload(self):
        raw = header()
        with patch('analysis.packet_analysis.analyze_dns_message', return_value=object()) as parser:
            packet = analyze_packet(dns_packet(raw))
            parser.assert_not_called()
            result = packet.dns
            parser.assert_called_once_with(packet.udp.payload)
            self.assertIs(result, parser.return_value)
        self.assertNotIn('dns', [item.name for item in fields(PacketAnalysis)])

    def test_property_infrastructure_failure_propagates(self):
        packet = analyze_packet(dns_packet(header()))
        failure = RuntimeError('parser infrastructure')
        with patch('analysis.packet_analysis.analyze_dns_message', side_effect=failure):
            with self.assertRaises(RuntimeError) as caught:
                _ = packet.dns
        self.assertIs(caught.exception, failure)

    def test_flow_admission_and_finalization_do_not_depend_on_dns_status(self):
        manager = FlowObservationWindowManager('dns', timedelta(seconds=50))
        for item in samples():
            packet = analyze_packet(item)
            _ = packet.dns
            manager.record(packet)
        windows = manager.end_capture_session()
        self.assertEqual(sum(item.coordinated_state.flow_statistics.packet_count for item in windows), len(samples()))
        self.assertEqual(len(windows), 2)
        self.assertEqual(manager.end_capture_session(), ())

    def test_detector_evaluation_and_streaming_semantics_unchanged(self):
        args = dict(configuration=settings(), capture_session_id='dns', ground_truth=GroundTruth((), ()))
        expected = run_end_to_end_validation(MemoryPacketSource(samples()), **args)
        with patch.object(PacketAnalysis, 'dns', new_callable=PropertyMock, return_value=None):
            actual = run_end_to_end_validation(MemoryPacketSource(samples()), **args)
            metrics = run_streaming_evaluation(MemoryPacketSource(samples()), **args)
        self.assertEqual(actual.report.metrics, expected.report.metrics)
        self.assertEqual(actual.pipeline_result.packet_findings, expected.pipeline_result.packet_findings)
        self.assertEqual(len(actual.pipeline_result.flow_findings), len(expected.pipeline_result.flow_findings))
        for finding, baseline in zip(expected.pipeline_result.flow_findings, actual.pipeline_result.flow_findings):
            evidence = finding.raw_evidence
            window = evidence.snapshot.observation_window if hasattr(evidence, 'snapshot') else evidence.observation_window
            stripped = replace(window, coordinated_state=replace(window.coordinated_state, dns_correlation_state=None,
                               dns_transaction_statistics=DNSTransactionStatistics(), dns_query_name_statistics=DNSQueryNameStatistics(),
                               dns_resource_record_statistics=DNSResourceRecordStatistics()))
            evidence = replace(evidence, **({'snapshot': extract_flow_feature_snapshot(stripped)} if hasattr(evidence, 'snapshot')
                                           else {'observation_window': stripped}))
            self.assertEqual(replace(finding, raw_evidence=evidence), baseline)
        self.assertEqual(metrics, expected.report.metrics)
        self.assertEqual([item.name for item in fields(DetectionFinding)],
                         ['detector_id', 'detector_version', 'decision', 'raw_evidence', 'security_interpretation'])

    def test_all_classic_pcap_encodings_produce_identical_dns(self):
        packets = samples()
        expected = tuple(analyze_packet(item).dns for item in packets)
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'dns.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    path.write_bytes(pcap_bytes(tuple((index * 1000000, item.raw_bytes) for index, item in enumerate(packets)), order, nano))
                    source = PcapPacketSource(path, source=CaptureSource('dns'))
                    source.start()
                    try:
                        actual = tuple(analyze_packet(item).dns for item in source)
                    finally:
                        source.stop()
                    self.assertEqual(actual, expected)

    def test_capture_failure_remains_capture_failure(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'truncated.pcap'
            path.write_bytes(pcap_bytes(((0, dns_packet(header()).raw_bytes),))[:-1])
            source = PcapPacketSource(path)
            source.start()
            try:
                with self.assertRaises(CaptureError):
                    tuple(analyze_packet(item).dns for item in source)
            finally:
                source.stop()

    def test_replay_hash_seed_and_timezone_determinism(self):
        script = '\n'.join((
            'from dataclasses import asdict',
            'import hashlib',
            'from analysis import analyze_dns_message, analyze_packet',
            'from tests.test_dns import adversarial_payloads',
            'from tests.test_dns_packet_analysis import samples',
            'values = [asdict(analyze_dns_message(raw)) for raw in adversarial_payloads()]',
            'values += [asdict(analyze_packet(item).dns) for item in samples()]',
            'print(hashlib.sha256(repr(values).encode()).hexdigest())',
        ))
        outputs = []
        for seed in ('1', '29', '503'):
            for zone in ('UTC', 'Asia/Kolkata', 'America/New_York'):
                environment = dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone)
                outputs.append(subprocess.check_output([sys.executable, '-B', '-c', script], env=environment))
        self.assertEqual(outputs, [outputs[0]] * 9)
