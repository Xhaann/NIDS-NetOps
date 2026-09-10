import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from analysis import (
    FlowIdentity,
    FlowIdentityError,
    FlowObservationWindowManager,
    IPv6DecodeError,
    IPv6Packet,
    PacketAnalysis,
    PacketAnalysisError,
    PacketAnalysisFailureClassification,
    analyze_packet,
    analyze_packet_outcome,
    decode_ethernet,
    decode_ipv6,
    extract_flow_feature_snapshot,
    flow_identity_from_packet,
)
from analysis import packet_analysis, packet_analysis_outcome
from application import run_closed_flow_detectors
from capture import CaptureSource, LinkType, PacketObservation
from detection import (
    FlowVolumeMetric,
    FlowVolumeThresholdConfiguration,
    FlowVolumeThresholdError,
    TCPControlMetric,
    TCPControlThresholdConfiguration,
    TCPControlThresholdError,
    evaluate_tcp_control_threshold,
)
from tests.test_ipv6 import IPV6_HEADER, ipv6_header
from tests.test_network_identity import synthetic_window
from tests.test_packet_analysis import TCP_BYTES, make_observation


def ipv6_observation(raw_bytes):
    frame_bytes = bytes.fromhex("00112233445566778899aabb86dd") + raw_bytes
    return PacketObservation(
        captured_at=datetime(2026, 9, 11, tzinfo=timezone.utc),
        link_type=LinkType(1), captured_length=len(frame_bytes),
        original_length=len(frame_bytes), raw_bytes=frame_bytes,
        source=CaptureSource("test-ipv6-analysis"),
    )


class IPv6PacketAnalysisTests(unittest.TestCase):
    def test_ethernet_dispatch_retains_exact_decoder_outputs_and_observation(self) -> None:
        observation = ipv6_observation(IPV6_HEADER + b"abcd")
        ethernet = decode_ethernet(observation)
        ipv6 = decode_ipv6(ethernet)
        with patch.object(packet_analysis, "decode_ethernet", return_value=ethernet) as ethernet_decoder:
            with patch.object(packet_analysis, "decode_ipv6", return_value=ipv6) as ipv6_decoder:
                result = analyze_packet(observation)
        ethernet_decoder.assert_called_once()
        ipv6_decoder.assert_called_once()
        self.assertIs(ethernet_decoder.call_args.args[0], observation)
        self.assertIs(ipv6_decoder.call_args.args[0], ethernet)
        self.assertIs(result.observation, observation)
        self.assertIs(result.ethernet, ethernet)
        self.assertIs(result.ipv6, ipv6)
        for name in ("ipv4", "tcp", "udp", "icmp", "ipv4_checksum_valid", "tcp_checksum_valid", "udp_checksum_valid", "icmp_checksum_valid"):
            self.assertIsNone(getattr(result, name))

    def test_raw_next_header_never_dispatches_transport_or_ipv4_decoding(self) -> None:
        for next_header in (0, 6, 17, 43, 44, 50, 51, 58, 59, 60, 135, 253, 254, 255):
            with self.subTest(next_header=next_header):
                observation = ipv6_observation(ipv6_header(next_header=next_header, payload_length=1) + b"\xff")
                with ExitStack() as stack:
                    for name in ("decode_ipv4", "decode_tcp", "decode_udp", "decode_icmp", "validate_ipv4_checksum", "validate_tcp_checksum", "validate_udp_checksum", "validate_icmp_checksum"):
                        stack.enter_context(patch.object(packet_analysis, name, side_effect=AssertionError(name)))
                    result = analyze_packet(observation)
                    outcome = analyze_packet_outcome(observation)
                self.assertEqual(result.ipv6.next_header, next_header)
                self.assertEqual(result.ipv6.payload, b"\xff")
                self.assertTrue(outcome.succeeded)
                self.assertEqual(outcome.analysis, result)

    def test_ipv6_decoding_and_outcome_do_not_invoke_detectors_or_orchestration(self) -> None:
        with ExitStack() as stack:
            for target in (
                "application.detector_orchestration.run_packet_detectors",
                "application.detector_orchestration.run_closed_flow_detectors",
                "detection.packet_integrity.evaluate_packet_integrity",
                "detection.flow_volume_threshold.evaluate_flow_volume_threshold",
                "detection.tcp_control_threshold.evaluate_tcp_control_threshold",
            ):
                stack.enter_context(patch(target, side_effect=AssertionError(target)))
            for raw_bytes in (ipv6_header(), ipv6_header(version=4), ipv6_header()[:39]):
                outcome = analyze_packet_outcome(ipv6_observation(raw_bytes))
                if raw_bytes == ipv6_header():
                    self.assertIsInstance(outcome.analysis.ipv6, IPv6Packet)
                else:
                    self.assertIsNone(outcome.analysis)

    def test_successful_outcome_retains_exact_analysis_and_observation(self) -> None:
        observation = ipv6_observation(ipv6_header())
        result = analyze_packet(observation)
        with patch.object(packet_analysis_outcome, "analyze_packet", return_value=result) as analyze:
            outcome = analyze_packet_outcome(observation)
        analyze.assert_called_once()
        self.assertIs(analyze.call_args.args[0], observation)
        self.assertIs(outcome.analysis, result)
        self.assertIs(outcome.observation, observation)
        self.assertIsNone(outcome.failure_classification)
        self.assertIsNone(outcome.failure_description)

    def test_short_header_outcome_is_incomplete_without_partial_analysis(self) -> None:
        for length in range(40):
            with self.subTest(length=length):
                observation = ipv6_observation(ipv6_header()[:length])
                outcome = analyze_packet_outcome(observation)
                self.assertFalse(outcome.succeeded)
                self.assertIsNone(outcome.analysis)
                self.assertIs(outcome.observation, observation)
                self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)
                self.assertEqual(outcome.failure_description, "IPv6 header is too short: expected at least 40 bytes")

    def test_ethernet_bytes_and_original_length_cannot_supply_missing_header_bytes(self) -> None:
        observation = ipv6_observation(ipv6_header()[:39])
        self.assertGreater(len(observation.raw_bytes), 40)
        observation = replace(observation, original_length=1000)
        outcome = analyze_packet_outcome(observation)
        self.assertIsNone(outcome.analysis)
        self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)

    def test_declared_payload_truncation_is_incomplete(self) -> None:
        for declared, actual in ((1, 0), (20, 19), (65535, 65534)):
            with self.subTest(declared=declared):
                observation = ipv6_observation(ipv6_header(payload_length=declared) + bytes(actual))
                outcome = analyze_packet_outcome(observation)
                self.assertIsNone(outcome.analysis)
                self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)
                self.assertEqual(outcome.failure_description, "IPv6 payload length exceeds available bytes")

    def test_wrong_version_is_structural_despite_extra_captured_bytes(self) -> None:
        for version in (0, 4, 5, 7, 15):
            with self.subTest(version=version):
                observation = ipv6_observation(ipv6_header(version=version) + bytes(100))
                outcome = analyze_packet_outcome(observation)
                self.assertIsNone(outcome.analysis)
                self.assertIs(outcome.observation, observation)
                self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.STRUCTURAL_FAILURE)
                self.assertEqual(outcome.failure_description, "IPv6 version must be 6")

    def test_ipv4_payload_labeled_as_ipv6_is_a_structural_failure(self) -> None:
        ipv4_observation = make_observation(6, TCP_BYTES)
        observation = replace(
            ipv4_observation,
            raw_bytes=ipv4_observation.raw_bytes[:12] + b"\x86\xdd" + ipv4_observation.raw_bytes[14:],
        )
        outcome = analyze_packet_outcome(observation)
        self.assertIs(outcome.observation, observation)
        self.assertIsNone(outcome.analysis)
        self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.STRUCTURAL_FAILURE)
        self.assertEqual(outcome.failure_description, "IPv6 version must be 6")

    def test_decoder_exception_propagates_exactly_without_publishing_partial_result(self) -> None:
        observation = ipv6_observation(ipv6_header())
        error = IPv6DecodeError("IPv6 version must be 6")
        published = []
        with patch.object(packet_analysis, "decode_ipv6", side_effect=error) as decoder:
            with self.assertRaises(IPv6DecodeError) as raised:
                published.append(analyze_packet(observation))
        decoder.assert_called_once()
        self.assertIs(raised.exception, error)
        self.assertEqual(published, [])

    def test_unrecognized_ipv6_and_programming_errors_are_not_classified(self) -> None:
        observation = ipv6_observation(ipv6_header())
        for error in (IPv6DecodeError("unrecognized decoder failure"), RuntimeError("programming failure")):
            with self.subTest(error=type(error)):
                with patch.object(packet_analysis, "decode_ipv6", side_effect=error) as decoder:
                    with self.assertRaises(type(error)) as raised:
                        analyze_packet_outcome(observation)
                decoder.assert_called_once()
                self.assertIs(raised.exception, error)

    def test_ipv6_model_is_optional_and_preserves_existing_positional_arguments(self) -> None:
        original = analyze_packet(make_observation(6, TCP_BYTES))
        self.assertIsNone(original.ipv6)
        positional = PacketAnalysis(
            original.observation, original.ethernet, original.ipv4, original.tcp,
            original.udp, original.icmp, original.ipv4_checksum_valid,
            original.tcp_checksum_valid, original.udp_checksum_valid, original.icmp_checksum_valid,
        )
        self.assertEqual(positional, original)
        self.assertIs(positional.ipv4, original.ipv4)
        self.assertIs(positional.tcp, original.tcp)

    def test_ipv6_cannot_coexist_with_ipv4_transport_or_checksum_models(self) -> None:
        result = analyze_packet(ipv6_observation(ipv6_header()))
        ipv4_result = analyze_packet(make_observation(6, TCP_BYTES))
        for name, value in (
            ("ipv4", ipv4_result.ipv4), ("tcp", ipv4_result.tcp),
            ("ipv4_checksum_valid", True), ("tcp_checksum_valid", False),
            ("udp_checksum_valid", True), ("icmp_checksum_valid", False),
        ):
            with self.subTest(name=name):
                with self.assertRaises(PacketAnalysisError):
                    replace(result, **{name: value})
        for invalid in (object(), b"", ipv4_result.ipv4):
            with self.subTest(invalid=type(invalid)):
                with self.assertRaises(TypeError):
                    replace(result, ipv6=invalid)

    def test_ipv6_packet_analysis_and_outcome_are_frozen_and_deterministic(self) -> None:
        observation = ipv6_observation(IPV6_HEADER + b"abcd")
        before = replace(observation)
        result = analyze_packet(observation)
        outcome = analyze_packet_outcome(observation)
        self.assertEqual(analyze_packet(observation), result)
        self.assertEqual(analyze_packet_outcome(observation), outcome)
        self.assertEqual(observation, before)
        self.assertIs(observation.raw_bytes, before.raw_bytes)
        for model in (result, outcome):
            for field in fields(model):
                with self.assertRaises(FrozenInstanceError):
                    setattr(model, field.name, None)
                with self.assertRaises(FrozenInstanceError):
                    delattr(model, field.name)

    def test_ipv6_packet_does_not_enter_existing_ipv4_flow_lifecycle(self) -> None:
        result = analyze_packet(ipv6_observation(ipv6_header(next_header=6)))
        manager = FlowObservationWindowManager("ipv6-base", timedelta(seconds=5))
        with self.assertRaises(FlowIdentityError):
            flow_identity_from_packet(result)
        with self.assertRaises(FlowIdentityError):
            manager.record(result)
        self.assertEqual(manager.active_windows(), ())
        self.assertEqual(manager.end_capture_session(), ())

    def test_decoded_ipv6_addresses_do_not_expand_existing_detector_scope(self) -> None:
        result = analyze_packet(ipv6_observation(ipv6_header(next_header=6)))
        identity = FlowIdentity(result.ipv6.source_address, result.ipv6.destination_address, 1, 2, 6)
        window = synthetic_window(identity)
        snapshot = extract_flow_feature_snapshot(window)
        volume = FlowVolumeThresholdConfiguration("volume", "1", FlowVolumeMetric.PACKET_COUNT, 0)
        control = TCPControlThresholdConfiguration("control", "1", TCPControlMetric.FORWARD_SYN, 0)
        with self.assertRaisesRegex(FlowVolumeThresholdError, "IPv4"):
            run_closed_flow_detectors(snapshot, flow_volume_configuration=volume, tcp_control_configuration=control)
        with self.assertRaisesRegex(TCPControlThresholdError, "IPv4"):
            evaluate_tcp_control_threshold(window, control)
        self.assertIs(snapshot.observation_window, window)
        self.assertIs(window.identity, identity)


if __name__ == "__main__":
    unittest.main()
