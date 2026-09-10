import inspect
import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from unittest.mock import PropertyMock, patch

import application
from analysis import (
    FlowIdentityError,
    FlowObservationWindowClosureReason,
    FlowObservationWindowError,
    FlowObservationWindowManager,
    FlowStatisticsError,
    PacketAnalysisOutcome,
    analyze_packet,
    analyze_packet_outcome,
    extract_flow_feature_snapshot,
)
from application import DetectionPipelineResult, DetectionSession, run_detection_pipeline, run_flow_observation_session
from application import detection_pipeline, flow_observation_session
from capture import CaptureError
from detection import DetectionFinding, FlowVolumeMetric, PacketIntegrityConfiguration, PacketIntegrityDecision
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_flow_volume_threshold import configuration as volume_configuration
from tests.test_ipv6_flow import observation_at
from tests.test_ipv6_transport import observation_for
from tests.test_packet_analysis import TCP_BYTES, UDP_BYTES, make_observation
from tests.test_tcp_control_threshold import configuration as control_configuration


class DetectionPipelineTests(unittest.TestCase):
    def setUp(self):
        self.session = DetectionSession(PacketIntegrityConfiguration("packet-integrity", "1"),
                                        volume_configuration(FlowVolumeMetric.PACKET_COUNT), control_configuration())

    def execute(self, observations=(), source=None, **options):
        return run_detection_pipeline(
            MemoryPacketSource(observations) if source is None else source,
            detection_session=options.get("detection_session", self.session),
            capture_session_id=options.get("capture_session_id", "pipeline"),
            inactivity_timeout=options.get("inactivity_timeout", timedelta(seconds=5)),
        )

    def test_public_exports_and_passive_result_construction(self):
        self.assertIs(application.run_detection_pipeline, detection_pipeline.run_detection_pipeline)
        self.assertIs(application.DetectionPipelineResult, detection_pipeline.DetectionPipelineResult)
        self.assertNotIn("_run_flow_observation_session", application.__all__)
        self.assertEqual(tuple(inspect.signature(run_detection_pipeline).parameters),
                         ("source", "detection_session", "capture_session_id", "inactivity_timeout"))
        with patch.object(DetectionSession, "run_packets") as packets, patch.object(DetectionSession, "run_closed_flows") as flows:
            result = DetectionPipelineResult((), ())
            self.assertEqual((result.packet_findings, result.flow_findings), ((), ()))
        packets.assert_not_called()
        flows.assert_not_called()

    def test_empty_packet_source_runs_capture_lifecycle_without_detection(self):
        source = MemoryPacketSource(())
        with patch.object(DetectionSession, "run_packets") as packets, patch.object(DetectionSession, "run_closed_flows") as flows:
            result = self.execute(source=source)
        self.assertEqual(result, DetectionPipelineResult((), ()))
        self.assertEqual(source.events, ["start", "stop"])
        packets.assert_not_called()
        flows.assert_not_called()

    def test_invalid_configuration_fails_before_source_start(self):
        for options, error in (({"detection_session": None}, TypeError),
                               ({"capture_session_id": ""}, FlowObservationWindowError),
                               ({"inactivity_timeout": timedelta(0)}, FlowObservationWindowError)):
            source = MemoryPacketSource(())
            with self.assertRaises(error):
                self.execute(source=source, **options)
            self.assertEqual(source.events, [])

    def test_real_ipv4_ipv6_packet_analysis_flow_admission_features_and_detection_once(self):
        observations = (make_observation(6, TCP_BYTES), make_observation(17, UDP_BYTES),
                        observation_at(6, extensions=(0, 43, 60)), observation_at(17, extensions=(0, 60)))
        source = MemoryPacketSource(observations)
        outcomes, admitted, windows, snapshots, packet_results, flow_results, managers = [], [], [], [], [], [], []
        original_record = FlowObservationWindowManager.record
        original_packets = DetectionSession.run_packets
        original_flows = DetectionSession.run_closed_flows

        def outcome_for(observation):
            outcome = analyze_packet_outcome(observation)
            outcomes.append(outcome)
            return outcome

        def create_manager(*args):
            manager = FlowObservationWindowManager(*args)
            managers.append(manager)
            return manager

        def record(manager, analysis):
            self.assertIs(analysis, outcomes[-1].analysis)
            self.assertEqual(len(packet_results), len(admitted) + 1)
            admitted.append(analysis)
            return original_record(manager, analysis)

        def packet_detection(session, values):
            self.assertIs(session, self.session)
            self.assertEqual(len(values), 1)
            self.assertIs(type(values[0]), PacketAnalysisOutcome)
            self.assertIs(values[0], outcomes[-1])
            findings = original_packets(session, values)
            packet_results.extend(findings)
            return findings

        def features(window):
            self.assertIsNotNone(window.closure_reason)
            self.assertTrue(source.stopped)
            windows.append(window)
            snapshot = extract_flow_feature_snapshot(window)
            snapshots.append(snapshot)
            return snapshot

        def flow_detection(session, values):
            self.assertIs(session, self.session)
            self.assertEqual(len(values), 1)
            self.assertIs(values[0], snapshots[-1])
            self.assertIs(values[0].observation_window, windows[-1])
            findings = original_flows(session, values)
            flow_results.extend(findings)
            return findings

        with patch.object(detection_pipeline, "_run_flow_observation_session", wraps=flow_observation_session._run_flow_observation_session) as lifecycle, \
             patch.object(flow_observation_session, "FlowObservationWindowManager", side_effect=create_manager), \
             patch.object(FlowObservationWindowManager, "record", autospec=True, side_effect=record), \
             patch.object(detection_pipeline, "analyze_packet_outcome", side_effect=outcome_for) as analyze, \
             patch("analysis.packet_analysis_outcome.analyze_packet", wraps=analyze_packet) as parse, \
             patch.object(DetectionSession, "run_packets", autospec=True, side_effect=packet_detection), \
             patch.object(detection_pipeline, "extract_flow_feature_snapshot", side_effect=features) as extract, \
             patch.object(DetectionSession, "run_closed_flows", autospec=True, side_effect=flow_detection):
            result = self.execute(source=source)
        lifecycle.assert_called_once()
        self.assertEqual((analyze.call_count, parse.call_count, len(admitted)), (4, 4, 4))
        self.assertEqual(extract.call_count, 4)
        self.assertEqual(len(managers), 1)
        self.assertEqual(managers[0].active_windows(), ())
        self.assertEqual(source.events, ["start", "produce:0", "produce:1", "produce:2", "produce:3", "stop"])
        for outcome, observation in zip(outcomes, observations):
            self.assertIs(outcome.observation, observation)
        self.assertEqual(tuple(snapshot.identity.ip_version for snapshot in snapshots), (4, 4, 6, 6))
        self.assertEqual(tuple(snapshot.identity.protocol for snapshot in snapshots), (6, 17, 6, 17))
        self.assertEqual(len(result.packet_findings), 4)
        self.assertEqual(len(result.flow_findings), 6)
        for actual, original in zip(result.packet_findings + result.flow_findings, tuple(packet_results + flow_results)):
            self.assertIs(actual, original)
        for finding in result.packet_findings:
            self.assertIs(finding.raw_evidence.configuration, self.session.packet_configuration)
        for finding in result.flow_findings:
            expected = self.session.flow_volume_configuration if finding.detector_id == "flow-volume-threshold" else self.session.tcp_control_configuration
            self.assertIs(finding.raw_evidence.configuration, expected)

    def test_inactivity_and_session_end_preserve_packet_and_closure_order(self):
        source = MemoryPacketSource((observation_at(6), observation_at(17, seconds=1), observation_at(6, seconds=6)))
        deliveries = []

        def extract(window):
            deliveries.append((window, tuple(source.events)))
            return extract_flow_feature_snapshot(window)

        with patch.object(detection_pipeline, "extract_flow_feature_snapshot", side_effect=extract):
            result = self.execute(source=source)
        self.assertEqual(tuple(f.raw_evidence.protocol for f in result.packet_findings), (6, 17, 6))
        self.assertEqual(tuple(f.raw_evidence.protocol for f in result.flow_findings), (6, 6, 17, 6, 6))
        self.assertEqual(tuple(window.key.sequence_number for window, _ in deliveries), (0, 1, 2))
        self.assertEqual(tuple(window.closure_reason for window, _ in deliveries),
                         (FlowObservationWindowClosureReason.INACTIVITY,
                          FlowObservationWindowClosureReason.CAPTURE_SESSION_END,
                          FlowObservationWindowClosureReason.CAPTURE_SESSION_END))
        self.assertNotIn("stop", deliveries[0][1])
        self.assertEqual(deliveries[1][1][-1], "stop")
        self.assertTrue(all(f.raw_evidence.total_packet_count == 1 for f in result.flow_findings))

    def test_bidirectional_ipv6_tcp_and_udp_share_one_flow_with_correct_applicability(self):
        for protocol in (6, 17):
            observations = (observation_at(protocol), observation_at(protocol, seconds=1, reverse=True),
                            observation_at(protocol, seconds=2))
            result = self.execute(observations)
            self.assertEqual(len(result.packet_findings), 3)
            self.assertEqual(len(result.flow_findings), 2 if protocol == 6 else 1)
            evidence = result.flow_findings[0].raw_evidence
            self.assertEqual((evidence.total_packet_count, evidence.forward_packet_count, evidence.reverse_packet_count), (3, 2, 1))
            self.assertEqual(evidence.captured_byte_total, 3 * (74 if protocol == 6 else 62))
            if protocol == 6:
                self.assertEqual(result.flow_findings[1].raw_evidence.observed_value, 2)

    def test_duplicate_observations_are_not_deduplicated_and_flows_are_not_sorted(self):
        first = observation_at(17, source_port=20000)
        second = observation_at(17, source_port=10000)
        result = self.execute((first, second, first))
        self.assertEqual(len(result.packet_findings), 3)
        self.assertEqual(result.packet_findings[0], result.packet_findings[2])
        self.assertEqual(tuple(f.raw_evidence.identity.source_port for f in result.flow_findings), (20000, 10000))
        self.assertEqual(tuple(f.raw_evidence.observed_value for f in result.flow_findings), (2, 1))

    def test_recognized_failed_outcomes_receive_packet_detection_without_flow_admission(self):
        valid = observation_at(17)
        incomplete = replace(valid, raw_bytes=b"", captured_length=0)
        structural = replace(valid, raw_bytes=valid.raw_bytes[:14] + b"\x50" + valid.raw_bytes[15:])
        unsupported = replace(valid, link_type=None)
        integrity = make_observation(17, UDP_BYTES, ipv4_checksum=0)
        result = self.execute((incomplete, structural, unsupported, integrity, valid))
        self.assertEqual(tuple(f.decision for f in result.packet_findings),
                         (PacketIntegrityDecision.NOT_EVALUABLE, PacketIntegrityDecision.MATCH,
                          PacketIntegrityDecision.NOT_EVALUABLE, PacketIntegrityDecision.MATCH, PacketIntegrityDecision.NO_MATCH))
        self.assertTrue(all(f.raw_evidence.analysis is None for f in result.packet_findings[:-1]))
        self.assertEqual(len(result.flow_findings), 1)
        self.assertEqual(result.flow_findings[0].raw_evidence.observed_value, 1)

    def test_unsupported_flow_protocols_and_non_first_fragments_preserve_admission_errors(self):
        observations = [observation_for(protocol, bytes.fromhex("80001234")) for protocol in (58, 59, 50, 51, 132, 253)]
        observations += [observation_at(protocol, fragment=(1, False)) for protocol in (6, 17)]
        for observation in observations:
            source = MemoryPacketSource((observation, observation_at()))
            with patch.object(DetectionSession, "run_packets", autospec=True,
                              return_value=()) as packets, patch.object(DetectionSession, "run_closed_flows") as flows:
                with self.assertRaises(FlowIdentityError):
                    self.execute(source=source)
            packets.assert_called_once()
            flows.assert_not_called()
            self.assertEqual(source.events, ["start", "produce:0", "stop"])

    def test_first_and_whole_fragments_use_existing_transport_analysis(self):
        for protocol in (6, 17):
            for more in (False, True):
                result = self.execute((observation_at(protocol, fragment=(0, more)),))
                self.assertEqual(result.flow_findings[0].raw_evidence.observed_value, 1)
                self.assertEqual(len(result.flow_findings), 2 if protocol == 6 else 1)

    def test_packet_detector_failure_stops_before_admission_and_skips_cleanup_detection(self):
        error = RuntimeError("packet detector sentinel")
        source = MemoryPacketSource((observation_at(), observation_at(seconds=1), observation_at(seconds=2)))
        original = DetectionSession.run_packets
        calls = []

        def execute(session, outcomes):
            calls.append(outcomes[0])
            if len(calls) == 2:
                raise error
            return original(session, outcomes)

        with patch.object(DetectionSession, "run_packets", autospec=True, side_effect=execute), \
             patch.object(DetectionSession, "run_closed_flows") as flows:
            with self.assertRaises(RuntimeError) as raised:
                self.execute(source=source)
        self.assertIs(raised.exception, error)
        self.assertEqual(len(calls), 2)
        flows.assert_not_called()
        self.assertEqual(source.events, ["start", "produce:0", "produce:1", "stop"])

    def test_feature_extraction_failure_stops_without_retry_or_flow_detection(self):
        error = RuntimeError("feature sentinel")
        source = MemoryPacketSource((observation_at(), observation_at(seconds=5), observation_at(seconds=6)))
        with patch.object(detection_pipeline, "extract_flow_feature_snapshot", side_effect=error) as features, \
             patch.object(DetectionSession, "run_closed_flows") as flows:
            with self.assertRaises(RuntimeError) as raised:
                self.execute(source=source)
        self.assertIs(raised.exception, error)
        features.assert_called_once()
        flows.assert_not_called()
        self.assertEqual(source.events, ["start", "produce:0", "produce:1", "stop"])

    def test_closed_flow_detector_failure_is_fail_fast_without_cleanup_retry(self):
        error = RuntimeError("flow detector sentinel")
        source = MemoryPacketSource((observation_at(), observation_at(seconds=5), observation_at(seconds=6)))
        with patch.object(DetectionSession, "run_closed_flows", side_effect=error) as flows:
            with self.assertRaises(RuntimeError) as raised:
                self.execute(source=source)
        self.assertIs(raised.exception, error)
        flows.assert_called_once()
        self.assertEqual(source.events, ["start", "produce:0", "produce:1", "stop"])

    def test_unexpected_analysis_error_propagates_with_existing_session_finalization(self):
        error = RuntimeError("analysis sentinel")
        valid = observation_at()
        outcome = analyze_packet_outcome(valid)
        source = MemoryPacketSource((valid, observation_at(seconds=1), observation_at(seconds=2)))
        with patch.object(detection_pipeline, "analyze_packet_outcome", side_effect=(outcome, error)) as analysis, \
             patch.object(detection_pipeline, "extract_flow_feature_snapshot", wraps=extract_flow_feature_snapshot) as features:
            with self.assertRaises(RuntimeError) as raised:
                self.execute(source=source)
        self.assertIs(raised.exception, error)
        self.assertEqual(analysis.call_count, 2)
        features.assert_called_once()
        self.assertEqual(features.call_args.args[0].coordinated_state.flow_statistics.packet_count, 1)
        self.assertTrue(source.stopped)

    def test_flow_admission_and_timestamp_errors_propagate_without_reordering(self):
        for second, error in ((replace(observation_at(seconds=1), original_length=None), FlowStatisticsError),
                              (observation_at(seconds=-1), FlowObservationWindowError)):
            source = MemoryPacketSource((observation_at(), second, observation_at(seconds=2)))
            with self.assertRaises(error):
                self.execute(source=source)
            self.assertEqual(source.events, ["start", "produce:0", "produce:1", "stop"])

    def test_capture_start_iteration_and_stop_errors_preserve_cleanup(self):
        for phase in ("start", "iteration", "stop"):
            error = CaptureError(phase)
            source = MemoryPacketSource((observation_at(),), **{phase + "_error": error})
            with self.assertRaises(CaptureError) as raised:
                self.execute(source=source)
            self.assertIs(raised.exception, error)
            self.assertTrue(source.stopped)
            self.assertEqual(source.events.count("start"), 1)
            self.assertEqual(source.events.count("stop"), 1)

    def test_stop_failure_preserves_existing_precedence_over_packet_detection_error(self):
        detector_error, stop_error = RuntimeError("packet sentinel"), CaptureError("stop sentinel")
        source = MemoryPacketSource((observation_at(),), stop_error=stop_error)
        with patch.object(DetectionSession, "run_packets", side_effect=detector_error):
            with self.assertRaises(CaptureError) as raised:
                self.execute(source=source)
        self.assertIs(raised.exception, stop_error)
        self.assertIs(raised.exception.__context__, detector_error)

    def test_final_detection_failure_preserves_existing_cleanup_exception_precedence(self):
        capture_error, detector_error = CaptureError("iteration sentinel"), RuntimeError("final detector sentinel")
        source = MemoryPacketSource((observation_at(),), iteration_error=capture_error)
        with patch.object(DetectionSession, "run_closed_flows", side_effect=detector_error) as flows:
            with self.assertRaises(RuntimeError) as raised:
                self.execute(source=source)
        self.assertIs(raised.exception, detector_error)
        self.assertIs(raised.exception.__context__, capture_error)
        flows.assert_called_once()
        self.assertTrue(source.stopped)

    def test_pipeline_consumes_semantics_without_raw_access_or_reanalysis(self):
        observation = observation_at(6, extensions=(0, 43, 60))
        outcome = analyze_packet_outcome(observation)
        with ExitStack() as stack:
            analyze = stack.enter_context(patch.object(detection_pipeline, "analyze_packet_outcome", return_value=outcome))
            for target in ("analysis.packet_analysis.analyze_packet", "analysis.packet_analysis_outcome.analyze_packet",
                           "analysis.packet_analysis.decode_ipv6", "analysis.packet_analysis.decode_tcp", "analysis.packet_analysis.decode_udp",
                           "analysis.packet_analysis.validate_ipv6_extension_headers", "analysis.packet_analysis.analyze_ipv6_fragmentation",
                           "analysis.ipv6_extension_headers.validate_ipv6_extension_headers", "analysis.ipv6_fragmentation.validate_ipv6_extension_headers",
                           "analysis.flow_tracker.FlowTracker.__init__"):
                stack.enter_context(patch(target, side_effect=AssertionError(target)))
            for target in ("capture.packet_observation.PacketObservation.raw_bytes", "analysis.ipv6.IPv6Packet.payload",
                           "analysis.ethernet.EthernetFrame.payload", "analysis.ipv6_extension_headers.IPv6ExtensionHeader.raw_bytes"):
                stack.enter_context(patch(target, new_callable=PropertyMock, create=True, side_effect=AssertionError(target)))
            result = self.execute((observation,))
        analyze.assert_called_once_with(observation)
        self.assertIs(result.packet_findings[0].raw_evidence.outcome, outcome)
        self.assertEqual(result.flow_findings[0].raw_evidence.observed_value, 1)

    def test_direct_capture_and_flow_observation_remain_detector_free(self):
        source = MemoryPacketSource((observation_at(),))
        windows = []
        with patch.object(DetectionSession, "run_packets", side_effect=AssertionError("automatic packet detection")), \
             patch.object(DetectionSession, "run_closed_flows", side_effect=AssertionError("automatic flow detection")), \
             patch.object(detection_pipeline, "analyze_packet_outcome", side_effect=AssertionError("pipeline not invoked")):
            run_flow_observation_session(source, capture_session_id="existing", inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=windows.append)
        self.assertEqual(len(windows), 1)
        self.assertTrue(source.stopped)

    def test_repeated_execution_and_independent_sources_are_deterministic_without_mutation(self):
        observations = (observation_at(6), observation_at(17, seconds=1), observation_at(6, seconds=2, reverse=True))
        before = tuple(replace(observation) for observation in observations)
        session_state = vars(self.session).copy()
        first = self.execute(observations)
        other = DetectionSession(self.session.packet_configuration, self.session.flow_volume_configuration,
                                 self.session.tcp_control_configuration)
        second = self.execute(observations, detection_session=other)
        self.assertEqual(first, second)
        self.assertEqual(first, self.execute(observations))
        self.assertEqual(observations, before)
        self.assertEqual(vars(self.session), session_state)
        self.assertEqual(vars(other), session_state)

    def test_result_is_minimal_immutable_and_preserves_findings(self):
        result = self.execute((observation_at(),))
        self.assertEqual(tuple(field.name for field in fields(result)), ("packet_findings", "flow_findings"))
        copy = DetectionPipelineResult(result.packet_findings, result.flow_findings)
        self.assertIs(copy.packet_findings, result.packet_findings)
        self.assertIs(copy.flow_findings, result.flow_findings)
        models = (result,) + result.packet_findings + result.flow_findings
        models += (result.packet_findings[0].raw_evidence.outcome,
                   result.flow_findings[0].raw_evidence.observation_window,
                   result.flow_findings[0].raw_evidence.snapshot)
        for model in models:
            for field in fields(model):
                with self.assertRaises(FrozenInstanceError):
                    setattr(model, field.name, None)
        self.assertEqual(tuple(field.name for field in fields(DetectionFinding)),
                         ("detector_id", "detector_version", "decision", "raw_evidence", "security_interpretation"))
        for invalid in ([], (None,), (object(),)):
            with self.assertRaises(TypeError):
                DetectionPipelineResult(invalid, ())
            with self.assertRaises(TypeError):
                DetectionPipelineResult((), invalid)


if __name__ == "__main__":
    unittest.main()
