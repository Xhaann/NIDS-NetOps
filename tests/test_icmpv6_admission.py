import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import FlowIdentityError, FlowObservationWindowManager, analyze_packet_outcome
from application import GroundTruth, run_capture_execution, run_end_to_end_validation
from application import detection_session, end_to_end_validation
from capture import PcapPacketSource
from tests.pcap_scenarios import frame, pcap_bytes, transport
from tests.test_end_to_end_validation import settings
from tests.test_ipv6_extension_transport import extension_chain
from tests.test_ipv6_transport import fragment_header, observation_for


class ICMPv6AdmissionTests(unittest.TestCase):
    def test_fragment_context_controls_analysis_and_failed_admission_is_transactional(self):
        valid = observation_for(17, transport(17, ipv6=True))
        for offset, more in ((0, False), (0, True), (1, False), (1, True), (8191, True)):
            for length in range(6):
                with self.subTest(offset=offset, more=more, length=length):
                    prefix, base = extension_chain(44, ((60, 16), (43, 24), (60, 8)))
                    partial = observation_for(58, bytes.fromhex('80ffff001122')[:length],
                                              prefix + fragment_header(58, offset, more), base)
                    partial = replace(partial, captured_at=valid.captured_at + timedelta(days=1))
                    outcome = analyze_packet_outcome(partial)
                    manager = FlowObservationWindowManager('icmpv6', timedelta(seconds=5))
                    before = manager.record(analyze_packet_outcome(valid).analysis).active_window
                    if offset == 0 and not more and length < 4:
                        self.assertEqual(outcome.failure_classification.value, 'incomplete')
                        self.assertIsNone(outcome.analysis)
                    else:
                        self.assertTrue(outcome.succeeded)
                        self.assertEqual(outcome.analysis.ipv6_icmpv6 is not None, offset == 0 and not more)
                        with self.assertRaises(FlowIdentityError):
                            manager.record(outcome.analysis)
                    self.assertEqual(manager.active_windows(), (before,))
                    later = replace(valid, captured_at=valid.captured_at + timedelta(seconds=1))
                    update = manager.record(analyze_packet_outcome(later).analysis)
                    self.assertEqual(update.closed_windows, ())
                    self.assertEqual(update.active_window.key, before.key)
                    self.assertEqual(update.active_window.coordinated_state.flow_statistics.packet_count, 2)
                    self.assertEqual(len(manager.end_capture_session()), 1)

    def test_uninterpreted_type_code_and_checksum_do_not_invent_structural_failures(self):
        for message in (bytes(4), b'\x80\xff\xff\xff', b'\xff\xff\x00\x00'):
            prefix, base = extension_chain(58, ((60, 16), (43, 24), (60, 8)))
            outcome = analyze_packet_outcome(observation_for(58, message, prefix, base))
            self.assertTrue(outcome.succeeded)
            self.assertEqual(outcome.analysis.ipv6_icmpv6.raw_bytes, message)
            manager = FlowObservationWindowManager('icmpv6', timedelta(seconds=5))
            with self.assertRaises(FlowIdentityError):
                manager.record(outcome.analysis)
            self.assertEqual(manager.end_capture_session(), ())

    def test_truncated_messages_between_valid_datagrams_preserve_packet_findings_and_windows(self):
        prefix, base = extension_chain(58, ((60, 16), (43, 24), (60, 8)))
        short = tuple(observation_for(58, b'\x80\xff\x00'[:size], prefix, base).raw_bytes for size in range(4))
        udp = frame(17, transport(17, ipv6=True), ipv6=True)
        packets = ((1000000, udp),) + tuple((2000000 + i, raw) for i, raw in enumerate(short)) + ((6000000, udp),)
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'icmpv6.pcap'
            path.write_bytes(pcap_bytes(packets))
            results = []
            for _ in range(2):
                source = PcapPacketSource(path)
                result = run_end_to_end_validation(source, configuration=settings(), capture_session_id='icmpv6',
                                                  ground_truth=GroundTruth((), ()))
                results.append(result)
                self.assertEqual(list(source), [])
                self.assertIsNone(source._file)
                self.assertEqual([f.decision.value for f in result.pipeline_result.packet_findings],
                                 ['no_match'] + ['not_evaluable'] * 4 + ['no_match'])
                snapshots = [f.raw_evidence.snapshot for f in result.pipeline_result.flow_findings]
                self.assertEqual([s.flow_volume_features.packet_count for s in snapshots], [1, 1])
                self.assertEqual([s.observation_window.key.sequence_number for s in snapshots], [0, 1])
                self.assertEqual([s.observation_window.closure_reason.value for s in snapshots],
                                 ['inactivity', 'capture_session_end'])
            self.assertEqual(results[0], results[1])
        self.assertFalse(Path(directory).exists())

    def test_partial_fragments_preserve_findings_finalize_prior_flow_and_abort_evaluation(self):
        udp = frame(17, transport(17, ipv6=True), ipv6=True)
        for offset, more in ((0, True), (1, False), (1, True)):
            for payload in (b'', b'\x80', b'\x80\x00\x00\x00'):
                with self.subTest(offset=offset, more=more, payload=payload), TemporaryDirectory() as directory:
                    prefix, base = extension_chain(44, ((60, 16), (43, 24)))
                    partial = observation_for(58, payload, prefix + fragment_header(58, offset, more), base)
                    path = Path(directory) / 'partial.pcap'
                    path.write_bytes(pcap_bytes(((1000000, udp), (2000000, partial.raw_bytes), (3000000, udp))))
                    source = PcapPacketSource(path)
                    packets, snapshots = [], []
                    packet_detector = detection_session.run_packet_detectors
                    flow_detector = detection_session.run_closed_flow_detectors

                    def detect_packet(outcome, configuration):
                        findings = packet_detector(outcome, configuration)
                        packets.extend(findings)
                        return findings

                    def detect_flow(snapshot, **configurations):
                        snapshots.append(snapshot)
                        return flow_detector(snapshot, **configurations)

                    with patch.object(detection_session, 'run_packet_detectors', side_effect=detect_packet), \
                            patch.object(detection_session, 'run_closed_flow_detectors', side_effect=detect_flow), \
                            patch.object(end_to_end_validation, 'evaluate_detection_result') as evaluate:
                        with self.assertRaises(FlowIdentityError):
                            run_end_to_end_validation(source, configuration=settings(), capture_session_id='icmpv6',
                                                      ground_truth=GroundTruth((), ()))
                    evaluate.assert_not_called()
                    self.assertEqual([f.decision.value for f in packets], ['no_match', 'no_match'])
                    self.assertIsNone(packets[-1].raw_evidence.outcome.analysis.ipv6_icmpv6)
                    self.assertEqual(len(snapshots), 1)
                    self.assertEqual(snapshots[0].flow_volume_features.packet_count, 1)
                    self.assertEqual(snapshots[0].observation_window.closure_reason.value, 'capture_session_end')
                    self.assertIsNone(source._file)
                    self.assertEqual(list(source), [])
                self.assertFalse(Path(directory).exists())

    def test_fragment_offset_controls_whether_later_extension_bytes_are_structural(self):
        for offset, expected in ((0, 'incomplete'), (1, None)):
            prefix = fragment_header(60, offset, True)
            observation = observation_for(58, b'\x3a\xff\x80', prefix, 44)
            outcome = analyze_packet_outcome(observation)
            if expected is None:
                self.assertTrue(outcome.succeeded)
                self.assertIsNone(outcome.analysis.ipv6_icmpv6)
            else:
                self.assertEqual(outcome.failure_classification.value, expected)
                self.assertIsNone(outcome.analysis)

    def test_opaque_selectors_and_partial_fragments_are_delivered_in_capture_order(self):
        observations = [observation_for(selector, b'\x80\x00\x00\x00') for selector in (50, 51, 59, 253)]
        observations += [observation_for(58, b'\x80', fragment_header(58, offset, True), 44) for offset in (0, 1)]
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'observations.pcap'
            path.write_bytes(pcap_bytes(tuple((1000000 + i, o.raw_bytes) for i, o in enumerate(observations))))
            outcomes = []
            source = PcapPacketSource(path)
            run_capture_execution(source, outcomes.append)
            self.assertEqual([o.observation.raw_bytes for o in outcomes], [o.raw_bytes for o in observations])
            self.assertTrue(all(o.succeeded for o in outcomes))
            self.assertTrue(all(o.analysis.ipv6_icmpv6 is None for o in outcomes))
            self.assertIsNone(source._file)
        self.assertFalse(Path(directory).exists())
