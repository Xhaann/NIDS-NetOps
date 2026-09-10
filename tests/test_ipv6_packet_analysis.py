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
    IPv6ExtensionHeader,
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
from tests.test_ipv6 import ipv6_header
from tests.test_network_identity import synthetic_window
from tests.test_packet_analysis import TCP_BYTES, UDP_BYTES, make_observation


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
        observation = ipv6_observation(ipv6_header(next_header=6, payload_length=len(TCP_BYTES)) + TCP_BYTES)
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
        self.assertIs(result.ipv6_extension_headers.packet, ipv6)
        self.assertEqual(result.ipv6_extension_headers.headers, ())
        self.assertEqual(result.ipv6_extension_headers.terminating_next_header, 6)
        for name in ("ipv4", "tcp", "udp", "icmp", "ipv4_checksum_valid", "tcp_checksum_valid", "udp_checksum_valid", "icmp_checksum_valid"):
            self.assertIsNone(getattr(result, name))

    def test_terminal_next_header_selects_transport_without_ipv4_decoding(self) -> None:
        for next_header in (0, 6, 17, 43, 44, 50, 51, 58, 59, 60, 135, 253, 254, 255):
            with self.subTest(next_header=next_header):
                payload = b"\xff\x00" + bytes(6) if next_header in (0, 43, 44, 60) else b"\xff"
                if next_header in (6, 17):
                    payload = TCP_BYTES if next_header == 6 else UDP_BYTES
                if next_header == 58:
                    payload = bytes.fromhex("ff000000")
                observation = ipv6_observation(ipv6_header(next_header=next_header, payload_length=len(payload)) + payload)
                with ExitStack() as stack:
                    for name in ("decode_ipv4", "decode_icmp", "validate_ipv4_checksum", "validate_tcp_checksum", "validate_udp_checksum", "validate_icmp_checksum"):
                        stack.enter_context(patch.object(packet_analysis, name, side_effect=AssertionError(name)))
                    result = analyze_packet(observation)
                    outcome = analyze_packet_outcome(observation)
                self.assertEqual(result.ipv6.next_header, next_header)
                self.assertEqual(result.ipv6.payload, payload)
                expected_types = (next_header,) if next_header in (0, 43, 44, 60) else ()
                self.assertEqual(tuple(header.header_type for header in result.ipv6_extension_headers.headers), expected_types)
                self.assertEqual(result.ipv6_extension_headers.terminating_next_header, 255 if expected_types else next_header)
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
        self.assertIsNone(original.ipv6_extension_headers)
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
        observation = ipv6_observation(ipv6_header(next_header=6, payload_length=len(TCP_BYTES)) + TCP_BYTES)
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
        result = analyze_packet(ipv6_observation(ipv6_header(next_header=6, payload_length=len(TCP_BYTES)) + TCP_BYTES))
        manager = FlowObservationWindowManager("ipv6-base", timedelta(seconds=5))
        with self.assertRaises(FlowIdentityError):
            flow_identity_from_packet(result)
        with self.assertRaises(FlowIdentityError):
            manager.record(result)
        self.assertEqual(manager.active_windows(), ())
        self.assertEqual(manager.end_capture_session(), ())

    def test_decoded_ipv6_addresses_do_not_expand_existing_detector_scope(self) -> None:
        result = analyze_packet(ipv6_observation(ipv6_header(next_header=6, payload_length=len(TCP_BYTES)) + TCP_BYTES))
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


class IPv6ExtensionHeaderPacketAnalysisTests(unittest.TestCase):
    def test_packet_analysis_and_outcome_retain_complete_chain_and_exact_context(self) -> None:
        hop_by_hop = bytes.fromhex("2b01000102030405060708090a0b0c0d")
        routing = bytes.fromhex("2c000708090a0b0c")
        fragment = bytes.fromhex("3cffeeddccbbaa99")
        destination = bytes.fromhex("0600010203040506")
        payload = hop_by_hop + routing + fragment + destination + b"\x00\xff"
        observation = ipv6_observation(ipv6_header(
            next_header=0, payload_length=42, traffic_class=171, flow_label=74565, hop_limit=0,
        ) + payload + b"excess Ethernet bytes")
        before = replace(observation)
        result = analyze_packet(observation)
        outcome = analyze_packet_outcome(observation)
        self.assertTrue(outcome.succeeded)
        self.assertIsNone(outcome.failure_classification)
        self.assertEqual(outcome.analysis, result)
        self.assertEqual(analyze_packet(observation), result)
        self.assertEqual(analyze_packet_outcome(observation), outcome)
        self.assertEqual(observation, before)
        self.assertIs(observation.raw_bytes, before.raw_bytes)
        for value in (result, outcome.analysis):
            chain = value.ipv6_extension_headers
            self.assertIs(value.observation, observation)
            self.assertIs(chain.packet, value.ipv6)
            self.assertEqual(value.ipv6, decode_ipv6(decode_ethernet(observation)))
            self.assertEqual(value.ipv6.payload, payload)
            self.assertEqual(value.ethernet.payload[82:], b"excess Ethernet bytes")
            self.assertEqual(chain.headers, (
                IPv6ExtensionHeader(0, 40, 16, hop_by_hop, 43),
                IPv6ExtensionHeader(43, 56, 8, routing, 44),
                IPv6ExtensionHeader(44, 64, 8, fragment, 60),
                IPv6ExtensionHeader(60, 72, 8, destination, 6),
            ))
            self.assertEqual(chain.terminating_next_header, 6)
            for name in ("ipv4", "tcp", "udp", "icmp", "ipv4_checksum_valid", "tcp_checksum_valid", "udp_checksum_valid", "icmp_checksum_valid"):
                self.assertIsNone(getattr(value, name))

    def test_no_next_header_preserves_trailing_payload_without_reparsing(self) -> None:
        for base_next_header, prefix in ((59, b""), (0, bytes.fromhex("3b00010203040506"))):
            for trailing in (b"", b"\x00\xff", bytes.fromhex("0000010203040506")):
                with self.subTest(base_next_header=base_next_header, trailing=trailing):
                    payload = prefix + trailing
                    observation = ipv6_observation(ipv6_header(
                        next_header=base_next_header, payload_length=len(payload),
                    ) + payload)
                    outcome = analyze_packet_outcome(observation)
                    self.assertTrue(outcome.succeeded)
                    self.assertEqual(outcome.analysis.ipv6.payload, payload)
                    chain = outcome.analysis.ipv6_extension_headers
                    self.assertEqual(chain.terminating_next_header, 59)
                    expected = (IPv6ExtensionHeader(0, 40, 8, prefix, 59),) if prefix else ()
                    self.assertEqual(chain.headers, expected)

    def test_all_unsupported_extension_next_headers_are_successful_termination(self) -> None:
        for next_header in range(256):
            if next_header in (0, 43, 44, 60):
                continue
            with self.subTest(next_header=next_header):
                raw_header = bytes((next_header, 0)) + bytes(6)
                transport = {6: TCP_BYTES, 17: UDP_BYTES, 58: bytes.fromhex("00ff0000")}
                payload = raw_header + transport.get(next_header, b"\x00\xff")
                observation = ipv6_observation(ipv6_header(next_header=43, payload_length=len(payload)) + payload)
                outcome = analyze_packet_outcome(observation)
                self.assertTrue(outcome.succeeded)
                self.assertEqual(outcome.analysis.ipv6_extension_headers.headers, (
                    IPv6ExtensionHeader(43, 40, 8, raw_header, next_header),
                ))
                self.assertEqual(outcome.analysis.ipv6_extension_headers.terminating_next_header, next_header)

    def test_chain_requires_the_exact_analysis_packet(self) -> None:
        result = analyze_packet(ipv6_observation(ipv6_header()))
        self.assertEqual(replace(result, ipv6_extension_headers=None).ipv6, result.ipv6)
        for packet in (None, replace(result.ipv6), replace(result.ipv6, next_header=6)):
            with self.subTest(packet=packet):
                with self.assertRaisesRegex(PacketAnalysisError, "exact IPv6 packet"):
                    replace(result, ipv6=packet)
        for chain in ((), object(), result.ipv6):
            with self.subTest(chain=type(chain)):
                with self.assertRaises(TypeError):
                    replace(result, ipv6_extension_headers=chain)


class IPv6ExtensionHeaderOutcomeTests(unittest.TestCase):
    def test_truncated_headers_are_incomplete_without_partial_analysis(self) -> None:
        for header_type in (0, 43, 44, 60):
            for available in range(8):
                for prefix in (b"", bytes((header_type, 0)) + bytes(6)):
                    with self.subTest(header_type=header_type, available=available, prefix=prefix):
                        payload = prefix + bytes.fromhex("3b00010203040506")[:available]
                        base_next_header = 0 if prefix else header_type
                        observation = ipv6_observation(ipv6_header(
                            next_header=base_next_header, payload_length=len(payload),
                        ) + payload)
                        with self.assertRaises(IPv6DecodeError) as raised:
                            analyze_packet(observation)
                        outcome = analyze_packet_outcome(observation)
                        self.assertFalse(outcome.succeeded)
                        self.assertIsNone(outcome.analysis)
                        self.assertIs(outcome.observation, observation)
                        self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)
                        self.assertEqual(outcome.failure_description, str(raised.exception))
                        self.assertEqual(analyze_packet_outcome(observation), outcome)

    def test_declared_extension_length_cannot_use_excess_ethernet_or_original_length(self) -> None:
        for header_type in (0, 43, 44, 60):
            raw_header = bytes.fromhex("3b00010203040506") if header_type == 44 else b"\x3b\xff" + bytes(2046)
            for declared in (0, 1, len(raw_header) - 1):
                with self.subTest(header_type=header_type, declared=declared):
                    observation = ipv6_observation(ipv6_header(
                        next_header=header_type, payload_length=8 + declared,
                    ) + bytes((header_type, 0)) + bytes(6) + raw_header)
                    observation = replace(observation, original_length=10000)
                    outcome = analyze_packet_outcome(observation)
                    self.assertFalse(outcome.succeeded)
                    self.assertIsNone(outcome.analysis)
                    self.assertIs(outcome.observation, observation)
                    self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)

    def test_invalid_base_structure_remains_structural_before_extension_validation(self) -> None:
        raw_bytes = ipv6_header(version=4, next_header=0, payload_length=8) + bytes.fromhex("3b00010203040506")
        observation = ipv6_observation(raw_bytes)
        with patch.object(packet_analysis, "validate_ipv6_extension_headers") as validate:
            outcome = analyze_packet_outcome(observation)
        validate.assert_not_called()
        self.assertIsNone(outcome.analysis)
        self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.STRUCTURAL_FAILURE)
        self.assertEqual(outcome.failure_description, "IPv6 version must be 6")

    def test_unrecognized_validator_errors_propagate_without_conversion(self) -> None:
        observation = ipv6_observation(ipv6_header())
        for error in (
            IPv6DecodeError("unrecognized extension failure"),
            ValueError("invalid internal value"), TypeError("invalid internal type"),
            IndexError("invalid internal offset"), RuntimeError("programming failure"),
        ):
            with self.subTest(error=type(error)):
                with patch.object(packet_analysis, "validate_ipv6_extension_headers", side_effect=error) as validate:
                    with self.assertRaises(type(error)) as raised:
                        analyze_packet_outcome(observation)
                validate.assert_called_once()
                self.assertIs(raised.exception, error)


if __name__ == "__main__":
    unittest.main()
