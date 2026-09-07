import unittest
from dataclasses import FrozenInstanceError, fields, replace
from enum import Enum
from unittest.mock import PropertyMock, patch

from analysis import analyze_packet_outcome
from detection import (
    DetectionFinding,
    DetectionFindingError,
    FlowVolumeMetric,
    FlowVolumeThresholdConfiguration,
    FlowVolumeThresholdDecision,
    FlowVolumeThresholdEvidence,
    FlowVolumeThresholdInterpretation,
    PacketIntegrityConfiguration,
    PacketIntegrityDecision,
    PacketIntegrityEvidence,
    PacketIntegrityInterpretation,
    TCPControlMetric,
    TCPControlThresholdConfiguration,
    TCPControlThresholdDecision,
    TCPControlThresholdEvidence,
    TCPControlThresholdInterpretation,
    detection_finding_from_evaluation,
    evaluate_flow_volume_threshold,
    evaluate_packet_integrity,
    evaluate_tcp_control_threshold,
)
from detection import detection_finding
from tests.test_flow_volume_threshold import packet, snapshot
from tests.test_packet_integrity import TCP_BYTES, incomplete_outcome, make_observation
from tests.test_tcp_control_threshold import closed_window, tcp_packet


def packet_integrity_evaluation(decision: PacketIntegrityDecision):
    if decision is PacketIntegrityDecision.NO_MATCH:
        outcome = analyze_packet_outcome(make_observation(6, TCP_BYTES))
    elif decision is PacketIntegrityDecision.MATCH:
        outcome = analyze_packet_outcome(
            make_observation(6, TCP_BYTES, ipv4_checksum=0)
        )
    else:
        outcome = incomplete_outcome()
    return evaluate_packet_integrity(
        outcome,
        PacketIntegrityConfiguration("packet-integrity", "1.0.0"),
    )


def flow_volume_evaluation(decision: FlowVolumeThresholdDecision):
    if decision is FlowVolumeThresholdDecision.NOT_EVALUABLE:
        flow_snapshot = snapshot(
            packets=(packet(17, 0),),
        )
        configuration = FlowVolumeThresholdConfiguration(
            "flow-volume-threshold",
            "1.0.0",
            FlowVolumeMetric.PACKETS_PER_SECOND,
            0.0,
        )
    else:
        flow_snapshot = snapshot()
        threshold = 0 if decision is FlowVolumeThresholdDecision.MATCH else 3
        configuration = FlowVolumeThresholdConfiguration(
            "flow-volume-threshold",
            "1.0.0",
            FlowVolumeMetric.PACKET_COUNT,
            threshold,
        )
    return evaluate_flow_volume_threshold(flow_snapshot, configuration)


def tcp_control_evaluation(decision: TCPControlThresholdDecision):
    window = closed_window(tcp_packet(0, syn=True))
    threshold = 0 if decision is TCPControlThresholdDecision.MATCH else 1
    return evaluate_tcp_control_threshold(
        window,
        TCPControlThresholdConfiguration(
            "tcp-control-threshold",
            "1.0.0",
            TCPControlMetric.FORWARD_SYN,
            threshold,
        ),
    )


def current_evaluations():
    return (
        packet_integrity_evaluation(PacketIntegrityDecision.MATCH),
        flow_volume_evaluation(FlowVolumeThresholdDecision.MATCH),
        tcp_control_evaluation(TCPControlThresholdDecision.MATCH),
    )


class FlowVolumeThresholdEvidenceSubclass(FlowVolumeThresholdEvidence):
    pass


class DetectionFindingTests(unittest.TestCase):
    def test_finding_has_exact_frozen_field_contract(self) -> None:
        self.assertEqual(
            tuple(field.name for field in fields(DetectionFinding)),
            (
                "detector_id",
                "detector_version",
                "decision",
                "raw_evidence",
                "security_interpretation",
            ),
        )
        finding = detection_finding_from_evaluation(current_evaluations()[0])
        with self.assertRaises(FrozenInstanceError):
            finding.detector_id = "changed"

    def test_all_current_evaluations_convert_with_exact_objects(self) -> None:
        for evaluation in current_evaluations():
            with self.subTest(evaluation=type(evaluation).__name__):
                finding = detection_finding_from_evaluation(evaluation)
                self.assertEqual(
                    finding.detector_id,
                    evaluation.raw_evidence.detector_id,
                )
                self.assertEqual(
                    finding.detector_version,
                    evaluation.raw_evidence.detector_version,
                )
                self.assertIs(finding.decision, evaluation.decision)
                self.assertIs(finding.raw_evidence, evaluation.raw_evidence)
                self.assertIs(
                    finding.security_interpretation,
                    evaluation.security_interpretation,
                )
                self.assertIs(type(finding.raw_evidence), type(evaluation.raw_evidence))
                self.assertIs(
                    type(finding.security_interpretation),
                    type(evaluation.security_interpretation),
                )

    def test_match_no_match_and_not_evaluable_are_preserved_exactly(self) -> None:
        evaluations = (
            packet_integrity_evaluation(PacketIntegrityDecision.MATCH),
            packet_integrity_evaluation(PacketIntegrityDecision.NO_MATCH),
            packet_integrity_evaluation(PacketIntegrityDecision.NOT_EVALUABLE),
            flow_volume_evaluation(FlowVolumeThresholdDecision.MATCH),
            flow_volume_evaluation(FlowVolumeThresholdDecision.NO_MATCH),
            flow_volume_evaluation(FlowVolumeThresholdDecision.NOT_EVALUABLE),
            tcp_control_evaluation(TCPControlThresholdDecision.MATCH),
            tcp_control_evaluation(TCPControlThresholdDecision.NO_MATCH),
        )
        for evaluation in evaluations:
            with self.subTest(decision=evaluation.decision):
                finding = detection_finding_from_evaluation(evaluation)
                self.assertIs(finding.decision, evaluation.decision)

    def test_detector_metadata_disagreement_is_rejected_for_every_family(self) -> None:
        for evaluation in current_evaluations():
            with self.subTest(evaluation=type(evaluation).__name__, field="detector_id"):
                with self.assertRaises(DetectionFindingError):
                    DetectionFinding(
                        "different-detector",
                        evaluation.raw_evidence.detector_version,
                        evaluation.decision,
                        evaluation.raw_evidence,
                        evaluation.security_interpretation,
                    )
            with self.subTest(evaluation=type(evaluation).__name__, field="detector_version"):
                with self.assertRaises(DetectionFindingError):
                    DetectionFinding(
                        evaluation.raw_evidence.detector_id,
                        "different-version",
                        evaluation.decision,
                        evaluation.raw_evidence,
                        evaluation.security_interpretation,
                    )

    def test_decision_disagreement_is_rejected_for_every_family(self) -> None:
        alternatives = (
            (
                packet_integrity_evaluation(PacketIntegrityDecision.MATCH),
                PacketIntegrityDecision.NO_MATCH,
            ),
            (
                flow_volume_evaluation(FlowVolumeThresholdDecision.MATCH),
                FlowVolumeThresholdDecision.NO_MATCH,
            ),
            (
                tcp_control_evaluation(TCPControlThresholdDecision.MATCH),
                TCPControlThresholdDecision.NO_MATCH,
            ),
        )
        for evaluation, decision in alternatives:
            with self.subTest(evaluation=type(evaluation).__name__):
                with self.assertRaises(DetectionFindingError):
                    DetectionFinding(
                        evaluation.raw_evidence.detector_id,
                        evaluation.raw_evidence.detector_version,
                        decision,
                        evaluation.raw_evidence,
                        evaluation.security_interpretation,
                    )

    def test_direct_construction_accepts_each_consistent_family(self) -> None:
        for evaluation in current_evaluations():
            finding = DetectionFinding(
                evaluation.raw_evidence.detector_id,
                evaluation.raw_evidence.detector_version,
                evaluation.decision,
                evaluation.raw_evidence,
                evaluation.security_interpretation,
            )
            self.assertIs(finding.raw_evidence, evaluation.raw_evidence)
            self.assertIs(
                finding.security_interpretation,
                evaluation.security_interpretation,
            )

    def test_blank_and_wrong_metadata_types_are_rejected(self) -> None:
        class StringSubclass(str):
            pass

        evaluation = current_evaluations()[0]
        values = {
            "detector_id": evaluation.raw_evidence.detector_id,
            "detector_version": evaluation.raw_evidence.detector_version,
            "decision": evaluation.decision,
            "raw_evidence": evaluation.raw_evidence,
            "security_interpretation": evaluation.security_interpretation,
        }
        for name in ("detector_id", "detector_version"):
            for value in (None, True, 1, b"value", StringSubclass("value")):
                with self.subTest(name=name, value=value):
                    with self.assertRaises(TypeError):
                        DetectionFinding(**dict(values, **{name: value}))
            for value in ("", " ", "\t\n"):
                with self.subTest(name=name, blank=repr(value)):
                    with self.assertRaises(DetectionFindingError):
                        DetectionFinding(**dict(values, **{name: value}))

    def test_arbitrary_decisions_evidence_and_interpretations_are_rejected(self) -> None:
        class OtherDecision(Enum):
            MATCH = "match"

        evaluation = current_evaluations()[0]
        arguments = (
            evaluation.raw_evidence.detector_id,
            evaluation.raw_evidence.detector_version,
            evaluation.decision,
            evaluation.raw_evidence,
            evaluation.security_interpretation,
        )
        for decision in (None, "match", OtherDecision.MATCH, object()):
            with self.subTest(decision=decision):
                with self.assertRaises(TypeError):
                    DetectionFinding(*arguments[:2], decision, *arguments[3:])
        with self.assertRaises(TypeError):
            DetectionFinding(*arguments[:3], None, arguments[4])
        with self.assertRaises(TypeError):
            DetectionFinding(*arguments[:4], None)

    def test_detector_families_cannot_be_mixed(self) -> None:
        packet_evaluation, flow_evaluation, tcp_evaluation = current_evaluations()
        for decision, evidence, interpretation in (
            (
                packet_evaluation.decision,
                flow_evaluation.raw_evidence,
                packet_evaluation.security_interpretation,
            ),
            (
                flow_evaluation.decision,
                tcp_evaluation.raw_evidence,
                flow_evaluation.security_interpretation,
            ),
            (
                tcp_evaluation.decision,
                packet_evaluation.raw_evidence,
                tcp_evaluation.security_interpretation,
            ),
        ):
            with self.subTest(decision=type(decision).__name__):
                with self.assertRaises(DetectionFindingError):
                    DetectionFinding(
                        evidence.detector_id,
                        evidence.detector_version,
                        decision,
                        evidence,
                        interpretation,
                    )

    def test_security_interpretation_must_match_decision(self) -> None:
        evaluations = (
            packet_integrity_evaluation(PacketIntegrityDecision.MATCH),
            flow_volume_evaluation(FlowVolumeThresholdDecision.MATCH),
            tcp_control_evaluation(TCPControlThresholdDecision.MATCH),
        )
        alternatives = (
            PacketIntegrityInterpretation.NO_INTEGRITY_OR_STRUCTURAL_VIOLATION,
            FlowVolumeThresholdInterpretation.THRESHOLD_NOT_EXCEEDED,
            TCPControlThresholdInterpretation.THRESHOLD_NOT_EXCEEDED,
        )
        for evaluation, interpretation in zip(evaluations, alternatives):
            with self.subTest(evaluation=type(evaluation).__name__):
                with self.assertRaises(DetectionFindingError):
                    DetectionFinding(
                        evaluation.raw_evidence.detector_id,
                        evaluation.raw_evidence.detector_version,
                        evaluation.decision,
                        evaluation.raw_evidence,
                        interpretation,
                    )

    def test_nonexact_evidence_is_rejected(self) -> None:
        evaluation = flow_volume_evaluation(FlowVolumeThresholdDecision.MATCH)
        evidence = evaluation.raw_evidence
        derived = FlowVolumeThresholdEvidenceSubclass(
            evidence.snapshot,
            evidence.configuration,
            evidence.observed_value,
            evidence.comparison_operator,
        )
        with self.assertRaises(TypeError):
            DetectionFinding(
                evidence.detector_id,
                evidence.detector_version,
                evaluation.decision,
                derived,
                evaluation.security_interpretation,
            )

    def test_wrong_and_nonexact_evaluation_types_are_rejected(self) -> None:
        evaluation = packet_integrity_evaluation(PacketIntegrityDecision.MATCH)

        class DerivedEvaluation(type(evaluation)):
            pass

        derived = DerivedEvaluation(
            evaluation.decision,
            evaluation.raw_evidence,
            evaluation.security_interpretation,
        )
        for value in (None, object(), evaluation.raw_evidence, derived):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    detection_finding_from_evaluation(value)

    def test_conversion_does_not_mutate_the_evaluation(self) -> None:
        evaluation = flow_volume_evaluation(FlowVolumeThresholdDecision.MATCH)
        before = replace(evaluation)
        finding = detection_finding_from_evaluation(evaluation)
        self.assertEqual(evaluation, before)
        self.assertIs(evaluation.raw_evidence, before.raw_evidence)
        self.assertIs(finding.raw_evidence, evaluation.raw_evidence)

    def test_repeated_conversion_is_deterministic(self) -> None:
        for evaluation in current_evaluations():
            first = detection_finding_from_evaluation(evaluation)
            second = detection_finding_from_evaluation(evaluation)
            self.assertEqual(first, second)
            self.assertIs(first.decision, evaluation.decision)
            self.assertIs(second.raw_evidence, evaluation.raw_evidence)

    def test_conversion_does_not_execute_any_detector(self) -> None:
        evaluations = current_evaluations()
        operations = (
            "detection.packet_integrity.evaluate_packet_integrity",
            "detection.flow_volume_threshold.evaluate_flow_volume_threshold",
            "detection.tcp_control_threshold.evaluate_tcp_control_threshold",
        )
        patches = [patch(name, side_effect=AssertionError(name)) for name in operations]
        try:
            for operation in patches:
                operation.start()
            findings = tuple(
                detection_finding_from_evaluation(evaluation)
                for evaluation in evaluations
            )
        finally:
            for operation in reversed(patches):
                operation.stop()
        self.assertEqual(len(findings), 3)

    def test_conversion_does_not_inspect_packets_or_flow_state(self) -> None:
        packet_evaluation, flow_evaluation, tcp_evaluation = current_evaluations()
        with patch.object(
            PacketIntegrityEvidence,
            "observation",
            new_callable=PropertyMock,
            side_effect=AssertionError("packet inspection"),
        ):
            with patch.object(
                FlowVolumeThresholdEvidence,
                "observation_window",
                new_callable=PropertyMock,
                side_effect=AssertionError("flow inspection"),
            ):
                with patch.object(
                    TCPControlThresholdEvidence,
                    "tcp_control_statistics",
                    new_callable=PropertyMock,
                    side_effect=AssertionError("state inspection"),
                ):
                    findings = tuple(
                        detection_finding_from_evaluation(evaluation)
                        for evaluation in (
                            packet_evaluation,
                            flow_evaluation,
                            tcp_evaluation,
                        )
                    )
        self.assertEqual(len(findings), 3)

    def test_conversion_performs_no_filesystem_or_network_access(self) -> None:
        evaluations = current_evaluations()
        with patch("builtins.open", side_effect=AssertionError("filesystem access")):
            with patch("socket.socket", side_effect=AssertionError("network access")):
                findings = tuple(
                    detection_finding_from_evaluation(evaluation)
                    for evaluation in evaluations
                )
        self.assertEqual(len(findings), 3)

    def test_module_has_no_mutable_global_state(self) -> None:
        public_values = (
            value
            for name, value in vars(detection_finding).items()
            if not name.startswith("_")
        )
        for value in public_values:
            self.assertNotIsInstance(value, (dict, list, set))


if __name__ == "__main__":
    unittest.main()
