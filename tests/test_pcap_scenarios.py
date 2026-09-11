import json
import subprocess
import sys
import unittest
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import FeatureContractVersion, FlowIdentity, FlowIdentityError, FlowObservationWindowKey
from application import (
    DetectionMetrics, FlowDetectionIdentity, GroundTruth, GroundTruthPolarity, GroundTruthRecord,
    PacketDetectionIdentity, run_capture_execution, run_end_to_end_validation,
)
from application import capture_execution, detection_pipeline, detector_orchestration, end_to_end_validation
from capture import CaptureSource, PcapPacketSource
from detection import TCPControlMetric
from tests.pcap_scenarios import addresses, frame, pcap_bytes, tcp_exchange, transport, udp_exchange
from tests.test_end_to_end_validation import settings
from tests.test_ipv6_transport import observation_for


EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
SOURCE = CaptureSource('curated-pcap')


class PcapScenarioTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.configuration = settings()

    def source(self, name, packets, order='<', nano=False):
        path = self.directory / (name + '.pcap')
        path.write_bytes(pcap_bytes(packets, order, nano))
        return path, PcapPacketSource(path, source=SOURCE)

    def packet_truth(self, packets, positive_indices=()):
        return tuple(GroundTruthRecord(PacketDetectionIdentity(
            self.configuration.packet_configuration, index, EPOCH + timedelta(microseconds=time),
            SOURCE.identifier, 1, len(raw), len(raw)),
            GroundTruthPolarity.POSITIVE if index in positive_indices else GroundTruthPolarity.NEGATIVE)
            for index, (time, raw) in enumerate(packets))

    def flow_truth(self, configuration, protocol, ipv6, first, last, positive, sequence=0):
        return GroundTruthRecord(FlowDetectionIdentity(
            configuration, FlowObservationWindowKey('scenario', sequence),
            FlowIdentity(*addresses(ipv6), 12345, 443, protocol),
            EPOCH + timedelta(microseconds=first), EPOCH + timedelta(microseconds=last)),
            GroundTruthPolarity.POSITIVE if positive else GroundTruthPolarity.NEGATIVE)

    def execute(self, source, truth=None, configuration=None):
        with patch.object(source, 'stop', wraps=source.stop) as stop:
            try:
                return run_end_to_end_validation(source, configuration=configuration or self.configuration,
                    capture_session_id='scenario', ground_truth=truth or GroundTruth((), ()))
            finally:
                stop.assert_called_once()
                self.assertEqual(list(source), [])

    def test_tcp_exchange_preserves_handshake_payload_half_close_and_report(self):
        for ipv6 in (False, True):
            with self.subTest(ipv6=ipv6):
                packets = tcp_exchange(ipv6)
                config = replace(self.configuration,
                    flow_volume_configuration=replace(self.configuration.flow_volume_configuration, threshold=7),
                    tcp_control_configuration=replace(self.configuration.tcp_control_configuration,
                                                      metric=TCPControlMetric.REVERSE_SYN_ACK))
                truth = GroundTruth(self.packet_truth(packets), (
                    self.flow_truth(config.flow_volume_configuration, 6, ipv6, 1000000, 1800000, False),
                    self.flow_truth(config.tcp_control_configuration, 6, ipv6, 1000000, 1800000, True)))
                path, source = self.source('ipv6_tcp_exchange' if ipv6 else 'ipv4_tcp_exchange', packets)
                result = self.execute(source, truth, config)
                self.assertEqual(result, self.execute(PcapPacketSource(path, source=SOURCE), truth, config))
                self.assertEqual(result.report.metrics.packet_metrics, DetectionMetrics(0, 0, 0, 7))
                self.assertEqual(result.report.metrics.flow_metrics, DetectionMetrics(1, 0, 0, 1))
                findings = result.pipeline_result.flow_findings
                self.assertEqual([f.detector_id for f in findings], ['volume', 'control'])
                self.assertEqual([f.detector_version for f in findings], ['v1', 'c1'])
                self.assertEqual([f.decision.value for f in findings], ['no_match', 'match'])
                self.assertEqual(tuple(f.name for f in fields(findings[0])),
                    ('detector_id', 'detector_version', 'decision', 'raw_evidence', 'security_interpretation'))
                snapshot = findings[0].raw_evidence.snapshot
                volume = snapshot.flow_volume_features
                self.assertEqual((volume.packet_count, volume.forward_packet_count, volume.reverse_packet_count), (7, 4, 3))
                self.assertEqual(volume.captured_bytes, 521 if ipv6 else 420)
                self.assertEqual(snapshot.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
                self.assertEqual(snapshot.observation_window.closure_reason.value, 'capture_session_end')
                controls = snapshot.coordinated_state.tcp_control_statistics
                self.assertEqual((controls.forward_syn_count, controls.reverse_syn_ack_count, controls.reverse_fin_count), (1, 1, 1))
                analyses = [f.raw_evidence.outcome.analysis for f in result.pipeline_result.packet_findings]
                transports = [a.ipv6_tcp if ipv6 else a.tcp for a in analyses]
                self.assertEqual([p.sequence_number for p in transports], [100, 900, 101, 101, 901, 901, 104])
                self.assertEqual([p.payload for p in transports], [b'', b'', b'', b'abc', b'', b'', b''])
                if not ipv6:
                    self.assertTrue(all(a.ipv4_checksum_valid and a.tcp_checksum_valid for a in analyses))
                self.assertIs(result.report.result.flow_evaluations[0].finding, findings[0])

    def test_udp_exchange_preserves_repeated_request_direction_and_checksum(self):
        for ipv6 in (False, True):
            with self.subTest(ipv6=ipv6):
                packets = udp_exchange(ipv6)
                config = replace(self.configuration, tcp_control_configuration=None)
                truth = GroundTruth(self.packet_truth(packets), (
                    self.flow_truth(config.flow_volume_configuration, 17, ipv6, 1000000, 2000000, True),))
                path, source = self.source('ipv6_udp_exchange' if ipv6 else 'ipv4_udp_exchange', packets)
                result = self.execute(source, truth, config)
                self.assertEqual(result.report.metrics.packet_metrics, DetectionMetrics(0, 0, 0, 3))
                self.assertEqual(result.report.metrics.flow_metrics, DetectionMetrics(1, 0, 0, 0))
                self.assertEqual(len(result.pipeline_result.flow_findings), 1)
                snapshot = result.pipeline_result.flow_findings[0].raw_evidence.snapshot
                volume = snapshot.flow_volume_features
                self.assertEqual((volume.forward_packet_count, volume.reverse_packet_count), (2, 1))
                self.assertEqual((volume.forward_captured_bytes, volume.reverse_captured_bytes), (134, 70) if ipv6 else (120, 60))
                self.assertIsNone(snapshot.coordinated_state.tcp_control_statistics)
                self.assertEqual(snapshot.directional_inter_arrival_features.forward_mean_inter_arrival_seconds, 1.0)
                self.assertIsNone(snapshot.directional_inter_arrival_features.reverse_mean_inter_arrival_seconds)
                analyses = [f.raw_evidence.outcome.analysis for f in result.pipeline_result.packet_findings]
                self.assertEqual([(a.ipv6_udp if ipv6 else a.udp).payload for a in analyses], [b'query', b'response', b'query'])
                if not ipv6:
                    self.assertTrue(all(a.ipv4_checksum_valid and a.udp_checksum_valid for a in analyses))
                self.assertEqual(result, self.execute(PcapPacketSource(path, source=SOURCE), truth, config))

    def test_syn_retransmission_windows_cover_both_detector_threshold_boundaries(self):
        raw = tcp_exchange()[0][1]
        packets = tuple((time * 1000000, raw) for time in (1, 6, 7, 12, 13, 14))
        config = replace(self.configuration,
            flow_volume_configuration=replace(self.configuration.flow_volume_configuration, threshold=2),
            tcp_control_configuration=replace(self.configuration.tcp_control_configuration, threshold=2))
        records = tuple(self.flow_truth(detector, 6, False, first * 1000000, last * 1000000, sequence == 2, sequence)
                        for sequence, (first, last) in enumerate(((1, 1), (6, 7), (12, 14)))
                        for detector in (config.flow_volume_configuration, config.tcp_control_configuration))
        _, source = self.source('syn_retransmission_windows', packets)
        result = self.execute(source, GroundTruth(self.packet_truth(packets), records), config)
        findings = result.pipeline_result.flow_findings
        self.assertEqual([f.decision.value for f in findings], ['no_match'] * 4 + ['match'] * 2)
        self.assertEqual([f.raw_evidence.observed_value for f in findings], [1, 1, 2, 2, 3, 3])
        self.assertEqual([f.raw_evidence.sequence_number for f in findings], [0, 0, 1, 1, 2, 2])
        self.assertEqual([f.raw_evidence.observation_window.closure_reason.value for f in findings],
                         ['inactivity'] * 4 + ['capture_session_end'] * 2)
        self.assertEqual(result.report.metrics.flow_metrics, DetectionMetrics(2, 0, 0, 4))

    def mixed_packets(self):
        tcp, udp = tcp_exchange(True), udp_exchange()
        frames = (udp[0][1], tcp[0][1], tcp[1][1], udp[1][1], tcp[2][1], tcp[3][1],
                  udp[2][1], tcp[4][1], tcp[5][1], tcp[6][1])
        return tuple((1000000 + index * 100000, raw) for index, raw in enumerate(frames))

    def test_interleaved_mixed_exchanges_preserve_order_across_pcap_encodings(self):
        packets = self.mixed_packets()
        results = []
        for order, nano in (('<', False), ('>', True)):
            path, source = self.source('mixed_protocol_exchanges', packets, order, nano)
            before = path.read_bytes()
            with patch.object(capture_execution, 'analyze_packet_outcome', wraps=capture_execution.analyze_packet_outcome) as analyze, \
                 patch.object(detection_pipeline, 'extract_flow_feature_snapshot', wraps=detection_pipeline.extract_flow_feature_snapshot) as extract, \
                 patch.object(detector_orchestration, 'evaluate_packet_integrity', wraps=detector_orchestration.evaluate_packet_integrity) as packet_detector, \
                 patch.object(detector_orchestration, 'evaluate_flow_volume_threshold', wraps=detector_orchestration.evaluate_flow_volume_threshold) as volume_detector, \
                 patch.object(detector_orchestration, 'evaluate_tcp_control_threshold', wraps=detector_orchestration.evaluate_tcp_control_threshold) as control_detector:
                result = self.execute(source)
            self.assertEqual((analyze.call_count, extract.call_count), (10, 2))
            self.assertEqual((packet_detector.call_count, volume_detector.call_count, control_detector.call_count), (10, 2, 1))
            self.assertEqual([f.raw_evidence.outcome.observation.raw_bytes for f in result.pipeline_result.packet_findings],
                             [raw for _, raw in packets])
            self.assertEqual([f.raw_evidence.sequence_number for f in result.pipeline_result.flow_findings], [0, 1, 1])
            self.assertEqual([f.raw_evidence.identity.ip_version for f in result.pipeline_result.flow_findings], [4, 6, 6])
            self.assertEqual(path.read_bytes(), before)
            results.append(result)
        self.assertEqual(results[0], results[1])

    def test_ipv6_extension_and_atomic_fragment_exchange_retains_datagrams(self):
        packets = udp_exchange(True, extensions=(0, 60), fragment=(0, False, 42))
        _, source = self.source('ipv6_extension_atomic_exchange', packets)
        result = self.execute(source)
        self.assertEqual(len(result.pipeline_result.flow_findings), 1)
        self.assertEqual(result.pipeline_result.flow_findings[0].raw_evidence.snapshot.flow_volume_features.packet_count, 3)
        for finding in result.pipeline_result.packet_findings:
            analysis = finding.raw_evidence.outcome.analysis
            self.assertEqual(finding.decision.value, 'no_match')
            self.assertEqual([header.header_type for header in analysis.ipv6_extension_headers.headers], [0, 60, 44])
            self.assertEqual(len(analysis.ipv6_fragmentation.headers), 1)
            self.assertEqual(analysis.ipv6_fragmentation.headers[0].identification, 42)
            self.assertTrue(analysis.ipv6_fragmentation.headers[0].is_whole_datagram)
            self.assertIsNotNone(analysis.ipv6_udp)

    def malformed_packets(self):
        udp = udp_exchange(True)
        segment = transport(6, ipv6=True)
        bad_offset = frame(6, segment[:12] + b'\x40' + segment[13:], True)
        incomplete = frame(6, segment[:8], True)
        extension = observation_for(6, b'', prefix=bytes((6, 1)) + bytes(6), base=60).raw_bytes
        return ((1000000, udp[0][1]), (1100000, extension), (1200000, bad_offset),
                (1300000, incomplete), (1500000, udp[1][1]))

    def test_malformed_headers_between_valid_datagrams_preserve_failure_kinds(self):
        packets = self.malformed_packets()
        _, source = self.source('malformed_header_sequence', packets)
        result = self.execute(source, GroundTruth(self.packet_truth(packets, (1, 2, 3)), ()))
        findings = result.pipeline_result.packet_findings
        self.assertEqual([f.decision.value for f in findings], ['no_match', 'not_evaluable', 'match', 'not_evaluable', 'no_match'])
        self.assertEqual([f.raw_evidence.outcome.failure_classification.value for f in findings[1:4]],
                         ['incomplete', 'structural_failure', 'incomplete'])
        self.assertTrue(all(f.raw_evidence.outcome.analysis is None for f in findings[1:4]))
        self.assertEqual(result.report.metrics.packet_metrics, DetectionMetrics(1, 0, 2, 2))
        self.assertEqual(len(result.pipeline_result.flow_findings), 1)
        self.assertEqual(result.pipeline_result.flow_findings[0].raw_evidence.snapshot.flow_volume_features.packet_count, 2)

    def test_complementary_ipv6_fragments_are_not_reassembled_into_a_udp_flow(self):
        segment = transport(17, b'abcdefghijklmnop', ipv6=True)
        packets = ((1000000, frame(17, segment[:16], True, fragment=(0, True, 73))),
                   (1100000, frame(17, segment[16:], True, fragment=(2, False, 73))),
                   (1200000, udp_exchange(True)[0][1]))
        path, source = self.source('ipv6_complementary_fragments', packets)
        outcomes = []
        run_capture_execution(source, outcomes.append)
        self.assertEqual(list(source), [])
        self.assertEqual(len(outcomes), 3)
        self.assertEqual(outcomes[0].failure_classification.value, 'incomplete')
        self.assertIsNone(outcomes[0].analysis)
        self.assertIsNone(outcomes[1].analysis.ipv6_udp)
        self.assertIsNotNone(outcomes[2].analysis.ipv6_udp)
        with patch.object(capture_execution, 'analyze_packet_outcome', wraps=capture_execution.analyze_packet_outcome) as analyze, \
             patch.object(end_to_end_validation, 'evaluate_detection_result') as evaluate:
            with self.assertRaises(FlowIdentityError):
                self.execute(PcapPacketSource(path, source=SOURCE))
            self.assertEqual(analyze.call_count, 2)
            evaluate.assert_not_called()

    def test_new_exchange_scenarios_have_repeatable_cli_subprocess_results(self):
        root = Path(__file__).resolve().parents[1]
        for name, packets, flow_values, decisions in (
            ('mixed_protocol_exchanges', self.mixed_packets(), [3, 7, 1], ['no_match'] * 10),
            ('malformed_header_sequence', self.malformed_packets(), [2],
             ['no_match', 'not_evaluable', 'match', 'not_evaluable', 'no_match']),
        ):
            with self.subTest(name=name):
                path, _ = self.source(name, packets)
                before = path.read_bytes()
                arguments = [str(path), '--capture-session-id', 'scenario', '--inactivity-timeout-microseconds', '5000000',
                    '--packet-detector-id', 'packet', '--packet-detector-version', 'p1',
                    '--volume-detector-id', 'volume', '--volume-detector-version', 'v1',
                    '--volume-metric', 'packet_count', '--volume-threshold', '0',
                    '--tcp-detector-id', 'control', '--tcp-detector-version', 'c1',
                    '--tcp-metric', 'forward_syn_count', '--tcp-threshold', '0']
                outputs = [subprocess.run([sys.executable, '-B', '-m', 'application'] + arguments,
                           cwd=root, env={'PYTHONPATH': str(root / 'src')}, capture_output=True, text=True, check=False)
                           for _ in range(2)]
                self.assertEqual([(r.returncode, r.stderr) for r in outputs], [(0, ''), (0, '')])
                self.assertEqual(outputs[0].stdout, outputs[1].stdout)
                result = json.loads(outputs[0].stdout)
                self.assertEqual(len(result['packet_findings']), len(packets))
                self.assertEqual([f['decision'] for f in result['packet_findings']], decisions)
                self.assertEqual([f['raw_evidence']['observed_value'] for f in result['flow_findings']], flow_values)
                self.assertEqual(path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
