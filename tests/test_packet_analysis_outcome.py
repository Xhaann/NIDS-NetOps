import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
from struct import pack
from unittest.mock import patch

from analysis import (
    PacketAnalysis,
    PacketAnalysisError,
    PacketAnalysisFailureClassification,
    PacketAnalysisOutcome,
    PacketAnalysisOutcomeError,
    analyze_packet,
    analyze_packet_outcome,
)
from analysis import packet_analysis_outcome
from capture.packet_observation import CaptureSource, LinkType, PacketObservation


ETHERNET_HEADER = bytes.fromhex("00112233445566778899aabb0800")
TCP_BYTES = bytes.fromhex("1234abcd0123456789abcdef5b55fedc38ec2468")
UDP_BYTES = bytes.fromhex("1234abcd000855a5")
ICMP_BYTES = bytes.fromhex("fdab80d500ff807f")


def make_observation(
    protocol: int,
    payload: bytes,
    *,
    fragment_field: int = 0,
    ipv4_checksum: int = -1,
) -> PacketObservation:
    header = pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        0,
        fragment_field,
        64,
        protocol,
        0,
        b"\xc0\x00\x02\x01",
        b"\xc6\x33\x64\x02",
    )
    if ipv4_checksum == -1:
        words = [int.from_bytes(header[index:index + 2], "big") for index in range(0, 20, 2)]
        ipv4_checksum = 65535 - sum(words) % 65535
    raw_bytes = ETHERNET_HEADER + header[:10] + ipv4_checksum.to_bytes(2, "big")
    raw_bytes += header[12:] + payload
    return PacketObservation(
        captured_at=datetime(2026, 9, 7, tzinfo=timezone.utc),
        link_type=LinkType(1),
        captured_length=len(raw_bytes),
        original_length=len(raw_bytes),
        raw_bytes=raw_bytes,
        source=CaptureSource("test-analysis-outcome"),
    )


def with_raw_bytes(observation: PacketObservation, raw_bytes: bytes) -> PacketObservation:
    return replace(
        observation,
        raw_bytes=raw_bytes,
        captured_length=len(raw_bytes),
        original_length=len(raw_bytes),
    )


class PacketObservationSubclass(PacketObservation):
    pass


class PacketAnalysisOutcomeTests(unittest.TestCase):
    def test_failure_classification_is_exactly_bounded(self) -> None:
        self.assertEqual(
            list(PacketAnalysisFailureClassification),
            [
                PacketAnalysisFailureClassification.STRUCTURAL_FAILURE,
                PacketAnalysisFailureClassification.UNSUPPORTED,
                PacketAnalysisFailureClassification.INCOMPLETE,
                PacketAnalysisFailureClassification.INTEGRITY_FAILURE,
            ],
        )

    def test_model_has_exact_fields_and_success_preserves_exact_objects(self) -> None:
        observation = make_observation(6, TCP_BYTES)
        analysis = analyze_packet(observation)
        with patch.object(packet_analysis_outcome, "analyze_packet", return_value=analysis) as operation:
            outcome = analyze_packet_outcome(observation)
        operation.assert_called_once_with(observation)
        self.assertEqual(
            [field.name for field in fields(PacketAnalysisOutcome)],
            ["observation", "analysis", "failure_classification", "failure_description"],
        )
        self.assertIs(outcome.observation, observation)
        self.assertIs(outcome.analysis, analysis)
        self.assertIsNone(outcome.failure_classification)
        self.assertIsNone(outcome.failure_description)
        self.assertIs(outcome.succeeded, True)

    def test_exact_observation_input_is_required(self) -> None:
        observation = make_observation(6, TCP_BYTES)
        subclass = PacketObservationSubclass(
            observation.captured_at,
            observation.link_type,
            observation.captured_length,
            observation.original_length,
            observation.raw_bytes,
            observation.source,
        )
        for value in (None, object(), subclass):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    analyze_packet_outcome(value)

    def test_unsupported_link_and_network_scope_are_outcomes(self) -> None:
        observation = make_observation(6, TCP_BYTES)
        unsupported = (
            replace(observation, link_type=None),
            with_raw_bytes(
                observation,
                observation.raw_bytes[:12] + b"\x08\x06" + observation.raw_bytes[14:],
            ),
        )
        for value in unsupported:
            with self.subTest(link_type=value.link_type, ether_type=value.raw_bytes[12:14]):
                outcome = analyze_packet_outcome(value)
                self.assertIs(outcome.observation, value)
                self.assertIsNone(outcome.analysis)
                self.assertIs(
                    outcome.failure_classification,
                    PacketAnalysisFailureClassification.UNSUPPORTED,
                )
                self.assertTrue(outcome.failure_description)
                self.assertIs(outcome.succeeded, False)

    def test_non_initial_transport_fragments_are_unsupported(self) -> None:
        for protocol, payload in ((6, TCP_BYTES), (17, UDP_BYTES), (1, ICMP_BYTES)):
            with self.subTest(protocol=protocol):
                observation = make_observation(protocol, payload, fragment_field=1)
                outcome = analyze_packet_outcome(observation)
                self.assertIs(outcome.observation, observation)
                self.assertIsNone(outcome.analysis)
                self.assertIs(
                    outcome.failure_classification,
                    PacketAnalysisFailureClassification.UNSUPPORTED,
                )

    def test_incomplete_headers_preserve_observation(self) -> None:
        tcp = make_observation(6, TCP_BYTES)
        cases = (
            with_raw_bytes(tcp, b""),
            with_raw_bytes(tcp, ETHERNET_HEADER + b"\x45"),
            make_observation(6, b""),
            make_observation(17, b""),
            make_observation(1, b""),
        )
        for observation in cases:
            with self.subTest(length=observation.captured_length, protocol=observation.raw_bytes[23:24]):
                outcome = analyze_packet_outcome(observation)
                self.assertIs(outcome.observation, observation)
                self.assertIsNone(outcome.analysis)
                self.assertIs(
                    outcome.failure_classification,
                    PacketAnalysisFailureClassification.INCOMPLETE,
                )
                self.assertIs(type(outcome.failure_description), str)
                self.assertTrue(outcome.failure_description.strip())

    def test_declared_lengths_exceeding_available_bytes_are_incomplete(self) -> None:
        ipv4 = bytearray(make_observation(17, UDP_BYTES).raw_bytes)
        ipv4[16:18] = (200).to_bytes(2, "big")
        udp = bytearray(UDP_BYTES)
        udp[4:6] = (24).to_bytes(2, "big")
        for observation in (
            with_raw_bytes(make_observation(17, UDP_BYTES), bytes(ipv4)),
            make_observation(17, bytes(udp)),
        ):
            with self.subTest(raw_bytes=observation.raw_bytes):
                outcome = analyze_packet_outcome(observation)
                self.assertIs(
                    outcome.failure_classification,
                    PacketAnalysisFailureClassification.INCOMPLETE,
                )

    def test_structural_header_rules_are_classified_separately(self) -> None:
        ipv4 = bytearray(make_observation(6, TCP_BYTES).raw_bytes)
        ipv4[14] = 0x55
        tcp = bytearray(TCP_BYTES)
        tcp[12] = 0x45
        udp = bytearray(UDP_BYTES)
        udp[4:6] = (7).to_bytes(2, "big")
        cases = (
            with_raw_bytes(make_observation(6, TCP_BYTES), bytes(ipv4)),
            make_observation(6, bytes(tcp)),
            make_observation(17, bytes(udp)),
        )
        for observation in cases:
            with self.subTest(raw_bytes=observation.raw_bytes):
                outcome = analyze_packet_outcome(observation)
                self.assertIs(outcome.observation, observation)
                self.assertIsNone(outcome.analysis)
                self.assertIs(
                    outcome.failure_classification,
                    PacketAnalysisFailureClassification.STRUCTURAL_FAILURE,
                )

    def test_ipv4_and_transport_checksum_failures_are_integrity_outcomes(self) -> None:
        cases = [
            make_observation(6, TCP_BYTES, ipv4_checksum=0),
        ]
        for protocol, payload, checksum_offset in (
            (6, TCP_BYTES, 16),
            (17, UDP_BYTES, 6),
            (1, ICMP_BYTES, 2),
        ):
            altered = payload[:checksum_offset] + b"\x00\x01" + payload[checksum_offset + 2:]
            cases.append(make_observation(protocol, altered))
        for observation in cases:
            with self.subTest(protocol=observation.raw_bytes[23]):
                outcome = analyze_packet_outcome(observation)
                self.assertIs(outcome.observation, observation)
                self.assertIsNone(outcome.analysis)
                self.assertIs(
                    outcome.failure_classification,
                    PacketAnalysisFailureClassification.INTEGRITY_FAILURE,
                )
                self.assertIn("checksum validation failed", outcome.failure_description.lower())

    def test_multiple_checksum_failures_have_deterministic_layer_order(self) -> None:
        altered = TCP_BYTES[:16] + b"\x00\x01" + TCP_BYTES[18:]
        observation = make_observation(6, altered, ipv4_checksum=0)
        outcome = analyze_packet_outcome(observation)
        self.assertEqual(outcome.failure_description, "Checksum validation failed for IPv4, TCP")

    def test_omitted_udp_checksum_remains_a_successful_analysis(self) -> None:
        observation = make_observation(17, UDP_BYTES[:6] + b"\x00\x00")
        outcome = analyze_packet_outcome(observation)
        self.assertIs(outcome.observation, observation)
        self.assertIsInstance(outcome.analysis, PacketAnalysis)
        self.assertIs(outcome.analysis.udp_checksum_valid, False)
        self.assertIsNone(outcome.failure_classification)
        self.assertIsNone(outcome.failure_description)

    def test_unknown_ipv4_protocol_remains_successful_network_analysis(self) -> None:
        observation = make_observation(253, b"\x00\xff\x80")
        outcome = analyze_packet_outcome(observation)
        self.assertIs(outcome.observation, observation)
        self.assertIsInstance(outcome.analysis, PacketAnalysis)
        self.assertIsNone(outcome.failure_classification)

    def test_inconsistent_direct_construction_is_rejected(self) -> None:
        observation = make_observation(6, TCP_BYTES)
        analysis = analyze_packet(observation)
        other = make_observation(6, TCP_BYTES)
        invalid = (
            (observation, None, None, None),
            (
                observation,
                analysis,
                PacketAnalysisFailureClassification.STRUCTURAL_FAILURE,
                None,
            ),
            (observation, analysis, None, "failure"),
            (observation, analyze_packet(other), None, None),
            (
                observation,
                None,
                PacketAnalysisFailureClassification.STRUCTURAL_FAILURE,
                "",
            ),
            (
                observation,
                None,
                PacketAnalysisFailureClassification.STRUCTURAL_FAILURE,
                "   ",
            ),
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments[1:]):
                with self.assertRaises(PacketAnalysisOutcomeError):
                    PacketAnalysisOutcome(*arguments)

    def test_direct_construction_rejects_nonexact_field_types(self) -> None:
        observation = make_observation(6, TCP_BYTES)
        with self.assertRaises(TypeError):
            PacketAnalysisOutcome(object(), None, PacketAnalysisFailureClassification.INCOMPLETE, "x")
        with self.assertRaises(TypeError):
            PacketAnalysisOutcome(observation, object(), None, None)
        with self.assertRaises(TypeError):
            PacketAnalysisOutcome(observation, None, "incomplete", "x")
        with self.assertRaises(TypeError):
            PacketAnalysisOutcome(
                observation,
                None,
                PacketAnalysisFailureClassification.INCOMPLETE,
                1,
            )

    def test_outcome_and_failure_classification_are_immutable(self) -> None:
        outcome = analyze_packet_outcome(make_observation(6, TCP_BYTES))
        with self.assertRaises(FrozenInstanceError):
            outcome.analysis = None
        with self.assertRaises(AttributeError):
            PacketAnalysisFailureClassification.INCOMPLETE.value = "changed"

    def test_repeated_analysis_is_deterministic_and_stateless(self) -> None:
        for observation in (
            make_observation(6, TCP_BYTES),
            make_observation(6, b""),
            make_observation(6, TCP_BYTES, ipv4_checksum=0),
        ):
            with self.subTest(raw_bytes=observation.raw_bytes):
                first = analyze_packet_outcome(observation)
                second = analyze_packet_outcome(observation)
                self.assertEqual(first, second)
                self.assertIs(first.observation, observation)
                self.assertIs(second.observation, observation)

    def test_unrecognized_decoder_failures_are_not_converted(self) -> None:
        observation = make_observation(6, TCP_BYTES)
        error = PacketAnalysisError("unexpected internal failure")
        with patch.object(packet_analysis_outcome, "analyze_packet", side_effect=error):
            with self.assertRaises(PacketAnalysisError) as raised:
                analyze_packet_outcome(observation)
        self.assertIs(raised.exception, error)

    def test_unexpected_programming_exceptions_propagate(self) -> None:
        observation = make_observation(6, TCP_BYTES)
        error = RuntimeError("programming failure")
        with patch.object(packet_analysis_outcome, "analyze_packet", side_effect=error):
            with self.assertRaises(RuntimeError) as raised:
                analyze_packet_outcome(observation)
        self.assertIs(raised.exception, error)

    def test_analysis_performs_no_filesystem_or_network_access(self) -> None:
        observation = make_observation(6, TCP_BYTES)
        with patch("builtins.open", side_effect=AssertionError("filesystem access")):
            with patch("socket.socket", side_effect=AssertionError("network access")):
                outcome = analyze_packet_outcome(observation)
        self.assertIs(outcome.succeeded, True)


if __name__ == "__main__":
    unittest.main()
