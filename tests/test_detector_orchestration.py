import ast
import inspect
import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, replace
from unittest.mock import PropertyMock, patch

import application
from analysis import (
    FlowFeatureSnapshot,
    FlowIdentity,
    FlowObservationWindowClosureReason,
    PacketAnalysisOutcome,
    analyze_packet_outcome,
    extract_flow_feature_snapshot,
)
from application import run_closed_flow_detectors, run_packet_detectors
from application import detector_orchestration
from capture import PacketObservation
from detection import (
    DetectionFinding,
    DetectionFindingError,
    FlowVolumeMetric,
    FlowVolumeThresholdConfiguration,
    FlowVolumeThresholdDecision,
    FlowVolumeThresholdError,
    PacketIntegrityConfiguration,
    PacketIntegrityDecision,
    PacketIntegrityError,
    TCPControlMetric,
    TCPControlThresholdConfiguration,
    TCPControlThresholdDecision,
    TCPControlThresholdError,
    detection_finding_from_evaluation,
    evaluate_flow_volume_threshold,
    evaluate_packet_integrity,
    evaluate_tcp_control_threshold,
)
from tests.test_packet_integrity import (
    ICMP_BYTES,
    TCP_BYTES,
    UDP_BYTES,
    incomplete_outcome,
    integrity_outcome,
    make_observation,
    structural_outcome,
    unsupported_outcome,
)
from tests.test_tcp_control_threshold import closed_window, tcp_packet, udp_packet


class DetectorOrchestrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.packet_configuration = PacketIntegrityConfiguration("packet-integrity", "1")
        self.volume_configuration = FlowVolumeThresholdConfiguration(
            "flow-volume", "1", FlowVolumeMetric.PACKET_COUNT, 0
        )
        self.control_configuration = TCPControlThresholdConfiguration(
            "tcp-control", "1", TCPControlMetric.FORWARD_SYN, 0
        )
        self.outcome = analyze_packet_outcome(make_observation(6, TCP_BYTES))
        self.window = closed_window(tcp_packet(0, syn=True), tcp_packet(1))
        self.snapshot = extract_flow_feature_snapshot(self.window)
        self.udp_snapshot = extract_flow_feature_snapshot(closed_window(udp_packet(0)))

    def run_flow(self, snapshot=None, **configurations):
        return run_closed_flow_detectors(
            self.snapshot if snapshot is None else snapshot,
            flow_volume_configuration=configurations.get(
                "volume", self.volume_configuration
            ),
            tcp_control_configuration=configurations.get(
                "control", self.control_configuration
            ),
        )

    def assert_preserved(self, finding, evaluation) -> None:
        self.assertIs(type(finding), DetectionFinding)
        self.assertIs(finding.decision, evaluation.decision)
        self.assertIs(finding.raw_evidence, evaluation.raw_evidence)
        self.assertIs(finding.security_interpretation, evaluation.security_interpretation)
        self.assertEqual(finding.detector_id, evaluation.raw_evidence.detector_id)
        self.assertEqual(finding.detector_version, evaluation.raw_evidence.detector_version)

    def test_public_exports(self) -> None:
        self.assertIs(application.run_packet_detectors, detector_orchestration.run_packet_detectors)
        self.assertIs(application.run_closed_flow_detectors, detector_orchestration.run_closed_flow_detectors)
        self.assertEqual(
            application.__all__,
            ["DetectionSession", "run_closed_flow_detectors", "run_flow_observation_session", "run_packet_detectors"],
        )

    def test_packet_evaluates_and_normalizes_exact_objects_once(self) -> None:
        evaluations = []
        findings = []

        def evaluate(outcome, configuration):
            result = evaluate_packet_integrity(outcome, configuration)
            evaluations.append(result)
            return result

        def normalize_evaluation(evaluation):
            finding = detection_finding_from_evaluation(evaluation)
            findings.append(finding)
            return finding

        with patch.object(detector_orchestration, "evaluate_packet_integrity", side_effect=evaluate) as detector:
            with patch.object(detector_orchestration, "detection_finding_from_evaluation", side_effect=normalize_evaluation) as normalize:
                result = run_packet_detectors(self.outcome, self.packet_configuration)
        detector.assert_called_once()
        self.assertIs(detector.call_args.args[0], self.outcome)
        self.assertIs(detector.call_args.args[1], self.packet_configuration)
        normalize.assert_called_once()
        self.assertIs(normalize.call_args.args[0], evaluations[0])
        self.assertEqual(len(result), 1)
        self.assertIs(result[0], findings[0])
        self.assert_preserved(result[0], evaluations[0])
        self.assertIs(result[0].raw_evidence.outcome, self.outcome)
        self.assertIs(result[0].raw_evidence.configuration, self.packet_configuration)

    def test_successful_packet_protocols_retain_no_match(self) -> None:
        for protocol, payload in ((6, TCP_BYTES), (17, UDP_BYTES), (1, ICMP_BYTES), (99, b"")):
            with self.subTest(protocol=protocol):
                outcome = analyze_packet_outcome(make_observation(protocol, payload))
                result = run_packet_detectors(outcome, self.packet_configuration)
                self.assertIs(result[0].decision, PacketIntegrityDecision.NO_MATCH)
                self.assertIs(result[0].raw_evidence.outcome, outcome)

    def check_packet_failure(self, outcome, decision) -> None:
        with patch.object(detector_orchestration, "evaluate_packet_integrity", wraps=evaluate_packet_integrity) as detector:
            result = run_packet_detectors(outcome, self.packet_configuration)
        detector.assert_called_once()
        self.assertIs(detector.call_args.args[0], outcome)
        self.assertIs(result[0].decision, decision)
        self.assertIs(result[0].raw_evidence.outcome, outcome)
        self.assertIs(result[0].raw_evidence.failure_classification, outcome.failure_classification)
        self.assertIs(result[0].raw_evidence.failure_description, outcome.failure_description)

    def test_structural_failure_retains_match(self) -> None:
        self.check_packet_failure(structural_outcome(), PacketIntegrityDecision.MATCH)

    def test_integrity_failure_retains_match(self) -> None:
        self.check_packet_failure(integrity_outcome(), PacketIntegrityDecision.MATCH)

    def test_incomplete_outcome_retains_not_evaluable(self) -> None:
        self.check_packet_failure(incomplete_outcome(), PacketIntegrityDecision.NOT_EVALUABLE)

    def test_unsupported_outcome_retains_not_evaluable(self) -> None:
        self.check_packet_failure(unsupported_outcome(), PacketIntegrityDecision.NOT_EVALUABLE)

    def test_tcp_evaluates_exact_inputs_and_configurations_once_in_order(self) -> None:
        calls = []
        evaluations = []
        findings = []

        def volume(snapshot, configuration):
            calls.append("volume")
            self.assertIs(snapshot, self.snapshot)
            self.assertIs(configuration, self.volume_configuration)
            evaluation = evaluate_flow_volume_threshold(snapshot, configuration)
            evaluations.append(evaluation)
            return evaluation

        def control(window, configuration):
            calls.append("control")
            self.assertIs(window, self.window)
            self.assertIs(configuration, self.control_configuration)
            evaluation = evaluate_tcp_control_threshold(window, configuration)
            evaluations.append(evaluation)
            return evaluation

        def normalize(evaluation):
            calls.append("normalize")
            self.assertIs(evaluation, evaluations[-1])
            finding = detection_finding_from_evaluation(evaluation)
            findings.append(finding)
            return finding

        with patch.object(detector_orchestration, "evaluate_flow_volume_threshold", side_effect=volume) as volume_detector:
            with patch.object(detector_orchestration, "evaluate_tcp_control_threshold", side_effect=control) as control_detector:
                with patch.object(detector_orchestration, "detection_finding_from_evaluation", side_effect=normalize):
                    result = self.run_flow()
        volume_detector.assert_called_once()
        control_detector.assert_called_once()
        self.assertEqual(calls, ["volume", "normalize", "control", "normalize"])
        self.assertEqual(len(result), 2)
        for actual, expected in zip(result, findings):
            self.assertIs(actual, expected)
        for finding, evaluation in zip(result, evaluations):
            self.assert_preserved(finding, evaluation)
        self.assertIs(result[0].raw_evidence.snapshot, self.snapshot)
        self.assertIs(result[0].raw_evidence.configuration, self.volume_configuration)
        self.assertIs(result[1].raw_evidence.observation_window, self.window)
        self.assertIs(result[1].raw_evidence.configuration, self.control_configuration)
        self.assertIs(result[1].raw_evidence.tcp_control_statistics, self.window.coordinated_state.tcp_control_statistics)

    def test_udp_runs_only_volume_with_or_without_tcp_configuration(self) -> None:
        with patch.object(detector_orchestration, "evaluate_tcp_control_threshold", side_effect=AssertionError("TCP invoked for UDP")) as control:
            with patch.object(detector_orchestration, "evaluate_flow_volume_threshold", wraps=evaluate_flow_volume_threshold) as volume:
                first = run_closed_flow_detectors(self.udp_snapshot, flow_volume_configuration=self.volume_configuration)
                second = self.run_flow(self.udp_snapshot)
        control.assert_not_called()
        self.assertEqual(volume.call_count, 2)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)
        self.assertIs(first[0].raw_evidence.snapshot, self.udp_snapshot)

    def test_flow_match_and_no_match_are_retained_without_filtering(self) -> None:
        for volume_threshold, volume_decision in ((0, FlowVolumeThresholdDecision.MATCH), (2, FlowVolumeThresholdDecision.NO_MATCH)):
            for control_threshold, control_decision in ((0, TCPControlThresholdDecision.MATCH), (1, TCPControlThresholdDecision.NO_MATCH)):
                with self.subTest(volume=volume_decision, control=control_decision):
                    result = self.run_flow(
                        volume=replace(self.volume_configuration, threshold=volume_threshold),
                        control=replace(self.control_configuration, threshold=control_threshold),
                    )
                    self.assertEqual(len(result), 2)
                    self.assertIs(result[0].decision, volume_decision)
                    self.assertIs(result[1].decision, control_decision)

    def test_not_evaluable_volume_does_not_skip_tcp(self) -> None:
        snapshot = extract_flow_feature_snapshot(closed_window(tcp_packet(0, syn=True)))
        result = self.run_flow(snapshot, volume=replace(self.volume_configuration, metric=FlowVolumeMetric.PACKETS_PER_SECOND, threshold=0.0))
        self.assertEqual(len(result), 2)
        self.assertIs(result[0].decision, FlowVolumeThresholdDecision.NOT_EVALUABLE)
        self.assertIsNone(result[0].raw_evidence.observed_value)
        self.assertIs(result[1].decision, TCPControlThresholdDecision.MATCH)

    def test_udp_not_evaluable_is_retained(self) -> None:
        result = self.run_flow(self.udp_snapshot, volume=replace(self.volume_configuration, metric=FlowVolumeMetric.PACKETS_PER_SECOND, threshold=0.0))
        self.assertEqual(len(result), 1)
        self.assertIs(result[0].decision, FlowVolumeThresholdDecision.NOT_EVALUABLE)

    def test_every_existing_closure_reason_is_supported(self) -> None:
        for reason in FlowObservationWindowClosureReason:
            with self.subTest(reason=reason):
                window = closed_window(tcp_packet(0), closure_reason=reason)
                result = self.run_flow(extract_flow_feature_snapshot(window))
                self.assertEqual(len(result), 2)
                self.assertIs(result[0].raw_evidence.observation_window, window)
                self.assertIs(result[1].raw_evidence.observation_window, window)

    def test_repeated_inputs_produce_equal_immutable_tuples(self) -> None:
        for invoke in (lambda: run_packet_detectors(self.outcome, self.packet_configuration), self.run_flow):
            first = invoke()
            self.run_flow(self.udp_snapshot)
            self.assertEqual(first, invoke())
            self.assertIs(type(first), tuple)
            with self.assertRaises(TypeError):
                first[0] = first[0]
            with self.assertRaises(FrozenInstanceError):
                first[0].detector_id = "changed"

    def test_packet_detector_errors_propagate_unchanged_without_normalization(self) -> None:
        for error in (RuntimeError("unexpected packet failure"), PacketIntegrityError("packet failure")):
            with self.subTest(error=type(error)):
                with patch.object(detector_orchestration, "evaluate_packet_integrity", side_effect=error) as detector:
                    with patch.object(detector_orchestration, "detection_finding_from_evaluation") as normalize:
                        with self.assertRaises(type(error)) as raised:
                            run_packet_detectors(self.outcome, self.packet_configuration)
                self.assertIs(raised.exception, error)
                detector.assert_called_once()
                normalize.assert_not_called()

    def test_volume_errors_stop_before_normalization_and_tcp(self) -> None:
        for error in (RuntimeError("unexpected volume failure"), FlowVolumeThresholdError("volume failure")):
            with self.subTest(error=type(error)):
                with patch.object(detector_orchestration, "evaluate_flow_volume_threshold", side_effect=error) as volume:
                    with patch.object(detector_orchestration, "evaluate_tcp_control_threshold") as control:
                        with patch.object(detector_orchestration, "detection_finding_from_evaluation") as normalize:
                            with self.assertRaises(type(error)) as raised:
                                self.run_flow()
                self.assertIs(raised.exception, error)
                volume.assert_called_once()
                control.assert_not_called()
                normalize.assert_not_called()

    def test_tcp_errors_publish_no_partial_tuple_and_do_not_retry(self) -> None:
        for error in (RuntimeError("unexpected TCP failure"), TCPControlThresholdError("TCP failure")):
            with self.subTest(error=type(error)):
                published = []
                with patch.object(detector_orchestration, "evaluate_tcp_control_threshold", side_effect=error) as control:
                    with patch.object(detector_orchestration, "evaluate_flow_volume_threshold", wraps=evaluate_flow_volume_threshold) as volume:
                        with patch.object(detector_orchestration, "detection_finding_from_evaluation", wraps=detection_finding_from_evaluation) as normalize:
                            for _ in range(2):
                                with self.assertRaises(type(error)) as raised:
                                    published.append(self.run_flow())
                                self.assertIs(raised.exception, error)
                self.assertEqual(published, [])
                self.assertEqual(volume.call_count, 2)
                self.assertEqual(control.call_count, 2)
                self.assertEqual(normalize.call_count, 2)

    def test_packet_normalization_error_propagates_without_retry(self) -> None:
        error = DetectionFindingError("normalization failed")
        with patch.object(detector_orchestration, "evaluate_packet_integrity", wraps=evaluate_packet_integrity) as detector:
            with patch.object(detector_orchestration, "detection_finding_from_evaluation", side_effect=error) as normalize:
                with self.assertRaises(DetectionFindingError) as raised:
                    run_packet_detectors(self.outcome, self.packet_configuration)
        self.assertIs(raised.exception, error)
        detector.assert_called_once()
        normalize.assert_called_once()

    def test_flow_normalization_errors_stop_and_publish_nothing(self) -> None:
        for failure_position in (1, 2):
            for error in (DetectionFindingError("invalid finding"), RuntimeError("unexpected normalization failure")):
                with self.subTest(position=failure_position, error=type(error)):
                    calls = []
                    published = []

                    def normalize(evaluation):
                        calls.append(evaluation)
                        if len(calls) == failure_position:
                            raise error
                        return detection_finding_from_evaluation(evaluation)

                    with patch.object(detector_orchestration, "evaluate_tcp_control_threshold", wraps=evaluate_tcp_control_threshold) as control:
                        with patch.object(detector_orchestration, "detection_finding_from_evaluation", side_effect=normalize):
                            with self.assertRaises(type(error)) as raised:
                                published.append(self.run_flow())
                    self.assertIs(raised.exception, error)
                    self.assertEqual(published, [])
                    self.assertEqual(len(calls), failure_position)
                    self.assertEqual(control.call_count, failure_position - 1)

    def test_packet_rejects_wrong_inputs_and_subclasses(self) -> None:
        class OutcomeSubclass(PacketAnalysisOutcome):
            pass

        subclass = OutcomeSubclass(self.outcome.observation, self.outcome.analysis, None, None)
        for value in (None, b"", self.outcome.observation, self.outcome.analysis, self.window, self.snapshot, subclass):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    run_packet_detectors(value, self.packet_configuration)

    def test_flow_rejects_wrong_inputs_and_subclasses(self) -> None:
        class SnapshotSubclass(FlowFeatureSnapshot):
            pass

        for value in (None, b"", self.outcome, self.outcome.analysis, self.window, object.__new__(SnapshotSubclass)):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    run_closed_flow_detectors(value, flow_volume_configuration=self.volume_configuration, tcp_control_configuration=self.control_configuration)

    def test_wrong_configuration_types_and_subclasses_are_rejected(self) -> None:
        for invoke, configuration in (
            (lambda value: run_packet_detectors(self.outcome, value), self.packet_configuration),
            (lambda value: self.run_flow(volume=value), self.volume_configuration),
            (lambda value: self.run_flow(control=value), self.control_configuration),
            (lambda value: self.run_flow(self.udp_snapshot, control=value), self.control_configuration),
        ):
            subclass = type("ConfigurationSubclass", (type(configuration),), {})
            for value in (object(), "configuration", object.__new__(subclass)):
                with self.subTest(configuration=type(configuration), value=type(value)):
                    with self.assertRaises(TypeError):
                        invoke(value)

    def test_tcp_configuration_is_required_for_tcp(self) -> None:
        with self.assertRaisesRegex(TypeError, "TCP windows require"):
            run_closed_flow_detectors(self.snapshot, flow_volume_configuration=self.volume_configuration)

    def test_active_snapshot_is_rejected_before_tcp_or_normalization(self) -> None:
        active = extract_flow_feature_snapshot(replace(self.window, closure_reason=None))
        with patch.object(detector_orchestration, "evaluate_tcp_control_threshold") as control:
            with patch.object(detector_orchestration, "detection_finding_from_evaluation") as normalize:
                with self.assertRaises(FlowVolumeThresholdError):
                    self.run_flow(active)
        control.assert_not_called()
        normalize.assert_not_called()
        self.assertIsNone(active.observation_window.closure_reason)

    def test_unsupported_flow_protocol_is_rejected_at_identity_construction(self) -> None:
        identity = self.window.identity
        for protocol in (1, 99):
            with self.subTest(protocol=protocol):
                with self.assertRaisesRegex(ValueError, "protocol must be 6 or 17"):
                    FlowIdentity(
                        source_address=identity.source_address,
                        destination_address=identity.destination_address,
                        source_port=identity.source_port,
                        destination_port=identity.destination_port,
                        protocol=protocol,
                    )

    def test_no_packet_inspection_extraction_io_or_clock_access(self) -> None:
        with ExitStack() as stack:
            for target in (
                "builtins.open", "io.open", "os.open", "os.listdir", "os.scandir",
                "socket.socket", "socket.create_connection", "time.time", "time.monotonic",
                "analysis.packet_analysis.analyze_packet",
                "analysis.packet_analysis_outcome.analyze_packet_outcome",
                "analysis.flow_feature_snapshot.extract_flow_feature_snapshot",
            ):
                stack.enter_context(patch(target, side_effect=AssertionError(target)))
            stack.enter_context(patch.object(PacketObservation, "raw_bytes", new_callable=PropertyMock, side_effect=AssertionError("packet bytes read"), create=True))
            self.assertEqual(len(run_packet_detectors(self.outcome, self.packet_configuration)), 1)
            self.assertEqual(len(self.run_flow()), 2)
            self.assertEqual(len(self.run_flow(self.udp_snapshot)), 1)

    def test_module_has_only_explicit_dependencies_and_stateless_functions(self) -> None:
        tree = ast.parse(inspect.getsource(detector_orchestration))
        imports = []
        for node in tree.body:
            self.assertIsInstance(node, (ast.ImportFrom, ast.FunctionDef))
            if isinstance(node, ast.ImportFrom):
                imports.append(node.module)
        self.assertEqual(imports, [
            "typing",
            "analysis.flow_feature_snapshot",
            "analysis.packet_analysis_outcome",
            "detection.detection_finding",
            "detection.flow_volume_threshold",
            "detection.packet_integrity",
            "detection.tcp_control_threshold",
        ])
        for node in ast.walk(tree):
            self.assertNotIsInstance(node, (ast.Global, ast.Nonlocal, ast.Yield, ast.YieldFrom, ast.AsyncFunctionDef))


if __name__ == "__main__":
    unittest.main()
