import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
from struct import pack
from unittest.mock import patch

from analysis import (
    PacketAnalysisFailureClassification,
    PacketAnalysisOutcome,
    analyze_packet_outcome,
)
from capture.packet_observation import CaptureSource, LinkType, PacketObservation
from detection import (
    PacketIntegrityConfiguration,
    PacketIntegrityDecision,
    PacketIntegrityError,
    PacketIntegrityEvaluation,
    PacketIntegrityEvidence,
    PacketIntegrityInterpretation,
    evaluate_packet_integrity,
)


ETHERNET_HEADER = bytes.fromhex("00112233445566778899aabb0800")
TCP_BYTES = bytes.fromhex("1234abcd0123456789abcdef5b55fedc38ec2468")
UDP_BYTES = bytes.fromhex("1234abcd000855a5")
ICMP_BYTES = bytes.fromhex("fdab80d500ff807f")


def make_observation(
    protocol: int,
    payload: bytes,
    *,
    ipv4_checksum: int = -1,
) -> PacketObservation:
    header = pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        0,
        0,
        64,
        protocol,
        0,
        b"\xc0\x00\x02\x01",
        b"\xc6\x33\x64\x02",
    )
    if ipv4_checksum == -1:
        words = [
            int.from_bytes(header[index:index + 2], "big")
            for index in range(0, 20, 2)
        ]
        ipv4_checksum = 65535 - sum(words) % 65535
    raw_bytes = ETHERNET_HEADER + header[:10] + ipv4_checksum.to_bytes(2, "big")
    raw_bytes += header[12:] + payload
    return PacketObservation(
        captured_at=datetime(2026, 9, 8, tzinfo=timezone.utc),
        link_type=LinkType(1),
        captured_length=len(raw_bytes),
        original_length=len(raw_bytes),
        raw_bytes=raw_bytes,
        source=CaptureSource("test-packet-integrity"),
    )


def incomplete_outcome() -> PacketAnalysisOutcome:
    observation = make_observation(6, TCP_BYTES)
    observation = replace(
        observation,
        raw_bytes=b"",
        captured_length=0,
        original_length=0,
    )
    return analyze_packet_outcome(observation)


def unsupported_outcome() -> PacketAnalysisOutcome:
    return analyze_packet_outcome(replace(make_observation(6, TCP_BYTES), link_type=None))


def structural_outcome() -> PacketAnalysisOutcome:
    payload = UDP_BYTES[:4] + (7).to_bytes(2, "big") + UDP_BYTES[6:]
    return analyze_packet_outcome(make_observation(17, payload))


def integrity_outcome() -> PacketAnalysisOutcome:
    return analyze_packet_outcome(make_observation(6, TCP_BYTES, ipv4_checksum=0))


def configuration() -> PacketIntegrityConfiguration:
    return PacketIntegrityConfiguration("packet-integrity", "1")


class PacketAnalysisOutcomeSubclass(PacketAnalysisOutcome):
    pass


class PacketIntegrityConfigurationSubclass(PacketIntegrityConfiguration):
    pass


class PacketIntegrityTests(unittest.TestCase):
    def test_public_models_have_exact_fields_and_enum_members(self) -> None:
        self.assertEqual(
            tuple(field.name for field in fields(PacketIntegrityConfiguration)),
            ("detector_id", "detector_version"),
        )
        self.assertEqual(
            tuple(field.name for field in fields(PacketIntegrityEvidence)),
            ("outcome", "configuration"),
        )
        self.assertEqual(
            tuple(field.name for field in fields(PacketIntegrityEvaluation)),
            ("decision", "raw_evidence", "security_interpretation"),
        )
        self.assertEqual(
            tuple(PacketIntegrityDecision),
            (
                PacketIntegrityDecision.MATCH,
                PacketIntegrityDecision.NO_MATCH,
                PacketIntegrityDecision.NOT_EVALUABLE,
            ),
        )
        self.assertEqual(
            tuple(PacketIntegrityInterpretation),
            (
                PacketIntegrityInterpretation.NO_INTEGRITY_OR_STRUCTURAL_VIOLATION,
                PacketIntegrityInterpretation.STRUCTURAL_OR_INTEGRITY_VIOLATION_OBSERVED,
                PacketIntegrityInterpretation.ANALYSIS_NOT_EVALUABLE,
            ),
        )

    def test_successful_tcp_udp_and_icmp_are_no_match(self) -> None:
        for protocol, payload in ((6, TCP_BYTES), (17, UDP_BYTES), (1, ICMP_BYTES)):
            with self.subTest(protocol=protocol):
                outcome = analyze_packet_outcome(make_observation(protocol, payload))
                result = evaluate_packet_integrity(outcome, configuration())
                self.assertIs(result.decision, PacketIntegrityDecision.NO_MATCH)
                self.assertIs(
                    result.security_interpretation,
                    PacketIntegrityInterpretation.NO_INTEGRITY_OR_STRUCTURAL_VIOLATION,
                )
                self.assertEqual(result.raw_evidence.protocol, protocol)

    def test_structural_and_integrity_failures_are_match(self) -> None:
        for classification, outcome in (
            (PacketAnalysisFailureClassification.STRUCTURAL_FAILURE, structural_outcome()),
            (PacketAnalysisFailureClassification.INTEGRITY_FAILURE, integrity_outcome()),
        ):
            with self.subTest(classification=classification):
                result = evaluate_packet_integrity(outcome, configuration())
                self.assertIs(outcome.failure_classification, classification)
                self.assertIs(result.decision, PacketIntegrityDecision.MATCH)
                self.assertIs(
                    result.security_interpretation,
                    PacketIntegrityInterpretation.STRUCTURAL_OR_INTEGRITY_VIOLATION_OBSERVED,
                )
                self.assertIsNone(result.raw_evidence.protocol)

    def test_incomplete_and_unsupported_are_not_evaluable(self) -> None:
        for classification, outcome in (
            (PacketAnalysisFailureClassification.INCOMPLETE, incomplete_outcome()),
            (PacketAnalysisFailureClassification.UNSUPPORTED, unsupported_outcome()),
        ):
            with self.subTest(classification=classification):
                result = evaluate_packet_integrity(outcome, configuration())
                self.assertIs(outcome.failure_classification, classification)
                self.assertIs(result.decision, PacketIntegrityDecision.NOT_EVALUABLE)
                self.assertIs(
                    result.security_interpretation,
                    PacketIntegrityInterpretation.ANALYSIS_NOT_EVALUABLE,
                )
                self.assertIsNone(result.raw_evidence.protocol)

    def test_udp_checksum_omission_remains_no_match(self) -> None:
        observation = make_observation(17, UDP_BYTES[:6] + b"\x00\x00")
        outcome = analyze_packet_outcome(observation)
        result = evaluate_packet_integrity(outcome, configuration())
        self.assertIsNotNone(outcome.analysis)
        self.assertIs(outcome.analysis.udp_checksum_valid, False)
        self.assertIs(result.decision, PacketIntegrityDecision.NO_MATCH)
        self.assertIs(
            result.security_interpretation,
            PacketIntegrityInterpretation.NO_INTEGRITY_OR_STRUCTURAL_VIOLATION,
        )

    def test_evidence_preserves_exact_success_provenance(self) -> None:
        observation = make_observation(6, TCP_BYTES)
        outcome = analyze_packet_outcome(observation)
        detector_configuration = configuration()
        result = evaluate_packet_integrity(outcome, detector_configuration)
        evidence = result.raw_evidence
        self.assertIs(evidence.outcome, outcome)
        self.assertIs(evidence.configuration, detector_configuration)
        self.assertIs(evidence.observation, observation)
        self.assertIs(evidence.analysis, outcome.analysis)
        self.assertIs(evidence.captured_at, observation.captured_at)
        self.assertIs(evidence.capture_source, observation.source)
        self.assertIs(evidence.link_type, observation.link_type)
        self.assertEqual(evidence.captured_length, observation.captured_length)
        self.assertEqual(evidence.original_length, observation.original_length)
        self.assertEqual(evidence.detector_id, detector_configuration.detector_id)
        self.assertEqual(
            evidence.detector_version,
            detector_configuration.detector_version,
        )
        self.assertIs(evidence.decision, result.decision)
        self.assertIsNone(evidence.failure_classification)
        self.assertIsNone(evidence.failure_description)

    def test_failure_description_and_provenance_are_preserved_exactly(self) -> None:
        for outcome in (
            structural_outcome(),
            integrity_outcome(),
            incomplete_outcome(),
            unsupported_outcome(),
        ):
            with self.subTest(classification=outcome.failure_classification):
                result = evaluate_packet_integrity(outcome, configuration())
                evidence = result.raw_evidence
                self.assertIs(evidence.outcome, outcome)
                self.assertIs(evidence.observation, outcome.observation)
                self.assertIs(
                    evidence.failure_classification,
                    outcome.failure_classification,
                )
                self.assertIs(evidence.failure_description, outcome.failure_description)
                self.assertIsNone(evidence.analysis)

    def test_configuration_requires_exact_nonblank_strings(self) -> None:
        class StringSubclass(str):
            pass

        for name in ("detector_id", "detector_version"):
            for value in (None, True, 1, b"value", StringSubclass("value")):
                with self.subTest(name=name, value=value):
                    values = {"detector_id": "detector", "detector_version": "1"}
                    values[name] = value
                    with self.assertRaises(TypeError):
                        PacketIntegrityConfiguration(**values)
            for value in ("", " ", "\t\n"):
                with self.subTest(name=name, blank=repr(value)):
                    values = {"detector_id": "detector", "detector_version": "1"}
                    values[name] = value
                    with self.assertRaises(PacketIntegrityError):
                        PacketIntegrityConfiguration(**values)

    def test_evaluation_requires_exact_input_types(self) -> None:
        outcome = analyze_packet_outcome(make_observation(6, TCP_BYTES))
        derived_outcome = PacketAnalysisOutcomeSubclass(
            outcome.observation,
            outcome.analysis,
            outcome.failure_classification,
            outcome.failure_description,
        )
        derived_configuration = PacketIntegrityConfigurationSubclass("detector", "1")
        for value in (None, outcome.observation, outcome.analysis, object(), derived_outcome):
            with self.subTest(outcome_type=type(value)):
                with self.assertRaises(TypeError):
                    evaluate_packet_integrity(value, configuration())
        for value in (None, {}, object(), derived_configuration):
            with self.subTest(configuration_type=type(value)):
                with self.assertRaises(TypeError):
                    evaluate_packet_integrity(outcome, value)

    def test_evidence_rejects_nonexact_inputs(self) -> None:
        outcome = analyze_packet_outcome(make_observation(6, TCP_BYTES))
        with self.assertRaises(TypeError):
            PacketIntegrityEvidence(object(), configuration())
        with self.assertRaises(TypeError):
            PacketIntegrityEvidence(outcome, object())

    def test_inconsistent_evaluation_construction_is_rejected(self) -> None:
        cases = (
            (
                analyze_packet_outcome(make_observation(6, TCP_BYTES)),
                PacketIntegrityDecision.NO_MATCH,
                PacketIntegrityInterpretation.NO_INTEGRITY_OR_STRUCTURAL_VIOLATION,
            ),
            (
                structural_outcome(),
                PacketIntegrityDecision.MATCH,
                PacketIntegrityInterpretation.STRUCTURAL_OR_INTEGRITY_VIOLATION_OBSERVED,
            ),
            (
                incomplete_outcome(),
                PacketIntegrityDecision.NOT_EVALUABLE,
                PacketIntegrityInterpretation.ANALYSIS_NOT_EVALUABLE,
            ),
        )
        decisions = tuple(PacketIntegrityDecision)
        interpretations = tuple(PacketIntegrityInterpretation)
        for outcome, expected_decision, expected_interpretation in cases:
            evidence = PacketIntegrityEvidence(outcome, configuration())
            for decision in decisions:
                for interpretation in interpretations:
                    if decision is expected_decision and interpretation is expected_interpretation:
                        PacketIntegrityEvaluation(decision, evidence, interpretation)
                    else:
                        with self.assertRaises(PacketIntegrityError):
                            PacketIntegrityEvaluation(decision, evidence, interpretation)

    def test_evaluation_model_rejects_nonexact_field_types(self) -> None:
        outcome = analyze_packet_outcome(make_observation(6, TCP_BYTES))
        result = evaluate_packet_integrity(outcome, configuration())
        with self.assertRaises(TypeError):
            PacketIntegrityEvaluation("no_match", result.raw_evidence, result.security_interpretation)
        with self.assertRaises(TypeError):
            PacketIntegrityEvaluation(result.decision, object(), result.security_interpretation)
        with self.assertRaises(TypeError):
            PacketIntegrityEvaluation(result.decision, result.raw_evidence, "no violation")

    def test_all_public_models_are_frozen(self) -> None:
        detector_configuration = configuration()
        result = evaluate_packet_integrity(
            analyze_packet_outcome(make_observation(6, TCP_BYTES)),
            detector_configuration,
        )
        for value, name, replacement in (
            (detector_configuration, "detector_id", "changed"),
            (result.raw_evidence, "outcome", None),
            (result, "decision", PacketIntegrityDecision.MATCH),
        ):
            with self.subTest(model=type(value).__name__):
                with self.assertRaises(FrozenInstanceError):
                    setattr(value, name, replacement)

    def test_repeated_evaluation_is_deterministic_and_does_not_mutate_inputs(self) -> None:
        outcome = integrity_outcome()
        detector_configuration = configuration()
        first = evaluate_packet_integrity(outcome, detector_configuration)
        second = evaluate_packet_integrity(outcome, detector_configuration)
        self.assertEqual(first, second)
        self.assertIs(first.raw_evidence.outcome, outcome)
        self.assertIs(second.raw_evidence.outcome, outcome)
        self.assertIs(first.raw_evidence.configuration, detector_configuration)
        self.assertIs(second.raw_evidence.configuration, detector_configuration)

    def test_detector_performs_no_decoding_or_checksum_validation(self) -> None:
        outcome = analyze_packet_outcome(make_observation(6, TCP_BYTES))
        operations = (
            "analysis.packet_analysis.decode_ethernet",
            "analysis.packet_analysis.decode_ipv4",
            "analysis.packet_analysis.decode_tcp",
            "analysis.packet_analysis.validate_ipv4_checksum",
            "analysis.packet_analysis.validate_tcp_checksum",
        )
        patches = [patch(operation, side_effect=AssertionError(operation)) for operation in operations]
        entered = []
        try:
            for operation in patches:
                entered.append(operation.start())
            result = evaluate_packet_integrity(outcome, configuration())
        finally:
            for operation in reversed(patches):
                operation.stop()
        self.assertIs(result.decision, PacketIntegrityDecision.NO_MATCH)

    def test_detector_performs_no_filesystem_or_network_access(self) -> None:
        outcome = analyze_packet_outcome(make_observation(6, TCP_BYTES))
        with patch("builtins.open", side_effect=AssertionError("filesystem access")):
            with patch("socket.socket", side_effect=AssertionError("network access")):
                result = evaluate_packet_integrity(outcome, configuration())
        self.assertIs(result.decision, PacketIntegrityDecision.NO_MATCH)

    def test_security_interpretations_exclude_forbidden_conclusions(self) -> None:
        forbidden = (
            "malicious",
            "attack",
            "exploit",
            "fuzzing",
            "scanner",
            "scan",
            "dos",
            "ddos",
            "flood",
            "attacker",
            "victim",
            "client",
            "server",
            "initiator",
            "responder",
            "compromise",
            "intent",
        )
        for interpretation in PacketIntegrityInterpretation:
            text = (interpretation.name + " " + interpretation.value).lower()
            for term in forbidden:
                with self.subTest(interpretation=interpretation, term=term):
                    self.assertNotIn(term, text)

    def test_result_retains_only_current_outcome_and_configuration(self) -> None:
        outcome = structural_outcome()
        detector_configuration = configuration()
        result = evaluate_packet_integrity(outcome, detector_configuration)
        self.assertEqual(
            tuple(field.name for field in fields(result.raw_evidence)),
            ("outcome", "configuration"),
        )
        self.assertIs(result.raw_evidence.outcome, outcome)
        self.assertIs(result.raw_evidence.configuration, detector_configuration)


if __name__ == "__main__":
    unittest.main()
