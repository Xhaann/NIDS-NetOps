import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
from struct import pack
from types import SimpleNamespace
from typing import Optional, cast
from unittest.mock import Mock, call, patch

from analysis import (
    EthernetDecodeError,
    EthernetFrame,
    ICMPDecodeError,
    ICMPMessage,
    IPv4DecodeError,
    IPv4Packet,
    PacketAnalysis,
    PacketAnalysisError,
    TCPDecodeError,
    TCPPacket,
    UDPDecodeError,
    UDPPacket,
    analyze_packet,
    packet_analysis,
)
from capture.packet_observation import CaptureSource, LinkType, PacketObservation


ETHERNET_HEADER = bytes.fromhex("00112233445566778899aabb0800")
TCP_BYTES = bytes.fromhex("1234abcd0123456789abcdef5b55fedc38ec2468")
UDP_BYTES = bytes.fromhex("1234abcd000855a5")
ICMP_BYTES = bytes.fromhex("fdab80d500ff807f")
PROTOCOLS = ((6, "tcp", TCP_BYTES), (17, "udp", UDP_BYTES), (1, "icmp", ICMP_BYTES))


def make_observation(
    protocol: int,
    payload: bytes,
    *,
    fragment_field: int = 0,
    ipv4_checksum: Optional[int] = None,
) -> PacketObservation:
    header = pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, fragment_field, 64, protocol,
        0, b"\xc0\x00\x02\x01", b"\xc6\x33\x64\x02",
    )
    if ipv4_checksum is None:
        words = [int.from_bytes(header[i:i + 2], "big") for i in range(0, 20, 2)]
        ipv4_checksum = 65535 - sum(words) % 65535
    raw_bytes = ETHERNET_HEADER + header[:10] + ipv4_checksum.to_bytes(2, "big")
    raw_bytes += header[12:] + payload
    return PacketObservation(
        captured_at=datetime(2026, 9, 6, tzinfo=timezone.utc),
        link_type=LinkType(1),
        captured_length=len(raw_bytes),
        original_length=len(raw_bytes),
        raw_bytes=raw_bytes,
        source=CaptureSource("test-analysis"),
    )


class PacketAnalysisTests(unittest.TestCase):
    def test_real_supported_paths_preserve_observation_and_checksum_results(self) -> None:
        for protocol, name, payload in PROTOCOLS:
            with self.subTest(protocol=protocol):
                observation = make_observation(protocol, payload)
                before = replace(observation)
                result = analyze_packet(observation)
                self.assertIs(result.observation, observation)
                self.assertEqual(observation, before)
                self.assertIs(observation.raw_bytes, before.raw_bytes)
                self.assertIsInstance(result.ethernet, EthernetFrame)
                self.assertIsInstance(result.ipv4, IPv4Packet)
                self.assertIs(result.ipv4_checksum_valid, True)
                for layer, model in (("tcp", TCPPacket), ("udp", UDPPacket), ("icmp", ICMPMessage)):
                    if layer == name:
                        self.assertIsInstance(getattr(result, layer), model)
                        self.assertIs(getattr(result, f"{layer}_checksum_valid"), True)
                    else:
                        self.assertIsNone(getattr(result, layer))
                        self.assertIsNone(getattr(result, f"{layer}_checksum_valid"))

    def test_unknown_ipv4_protocol_keeps_only_decoded_network_layers(self) -> None:
        result = analyze_packet(make_observation(253, b"\x00\xff\x80"))
        self.assertIsInstance(result.ethernet, EthernetFrame)
        self.assertIsInstance(result.ipv4, IPv4Packet)
        self.assertIs(result.ipv4_checksum_valid, True)
        for name in ("tcp", "udp", "icmp"):
            self.assertIsNone(getattr(result, name))
            self.assertIsNone(getattr(result, f"{name}_checksum_valid"))

    def test_wrong_input_and_unsupported_link_types_are_rejected_before_decoding(self) -> None:
        observation = make_observation(6, TCP_BYTES)
        with patch.object(packet_analysis, "decode_ethernet") as decoder:
            for value in (None, observation.raw_bytes, SimpleNamespace(**vars(observation))):
                with self.subTest(value=value):
                    with self.assertRaises(TypeError):
                        analyze_packet(cast(PacketObservation, value))
            for link_type in (None, LinkType(0), LinkType(101)):
                with self.subTest(link_type=link_type):
                    with self.assertRaisesRegex(PacketAnalysisError, "LinkType"):
                        analyze_packet(replace(observation, link_type=link_type))
            decoder.assert_not_called()

    def test_unsupported_ether_types_are_rejected_before_ip_decoding(self) -> None:
        observation = make_observation(6, TCP_BYTES)
        with patch.object(packet_analysis, "decode_ipv4") as decoder:
            for ether_type in (0, 0x0806, 0xFFFF):
                with self.subTest(ether_type=ether_type):
                    raw_bytes = observation.raw_bytes[:12] + ether_type.to_bytes(2, "big")
                    raw_bytes += observation.raw_bytes[14:]
                    with self.assertRaisesRegex(PacketAnalysisError, "EtherType"):
                        analyze_packet(replace(observation, raw_bytes=raw_bytes))
            decoder.assert_not_called()

    def test_real_malformed_layers_raise_existing_decode_errors(self) -> None:
        observation = make_observation(6, TCP_BYTES)
        for raw_bytes, error in (
            (b"", EthernetDecodeError),
            (ETHERNET_HEADER + b"\x45", IPv4DecodeError),
            (make_observation(6, b"").raw_bytes, TCPDecodeError),
            (make_observation(17, b"").raw_bytes, UDPDecodeError),
            (make_observation(1, b"").raw_bytes, ICMPDecodeError),
        ):
            with self.subTest(error=error):
                malformed = replace(
                    observation, raw_bytes=raw_bytes,
                    captured_length=len(raw_bytes), original_length=len(raw_bytes),
                )
                with self.assertRaises(error):
                    analyze_packet(malformed)

    def test_decoder_exceptions_propagate_with_original_identity(self) -> None:
        for name, protocol, payload, error in (
            ("ethernet", 6, TCP_BYTES, EthernetDecodeError("short frame")),
            ("ipv4", 6, TCP_BYTES, IPv4DecodeError("short header")),
            ("tcp", 6, TCP_BYTES, TCPDecodeError("short header")),
            ("udp", 17, UDP_BYTES, UDPDecodeError("short header")),
            ("icmp", 1, ICMP_BYTES, ICMPDecodeError("short header")),
        ):
            with self.subTest(layer=name):
                with patch.object(packet_analysis, f"decode_{name}", side_effect=error):
                    with self.assertRaises(type(error)) as failure:
                        analyze_packet(make_observation(protocol, payload))
                self.assertIs(failure.exception, error)

    def test_checksum_failures_are_results_and_do_not_stop_decoding(self) -> None:
        for protocol, name, payload in PROTOCOLS:
            with self.subTest(protocol=protocol):
                result = analyze_packet(make_observation(protocol, payload, ipv4_checksum=0))
                self.assertIs(result.ipv4_checksum_valid, False)
                self.assertIs(getattr(result, f"{name}_checksum_valid"), True)
                offset = {6: 16, 17: 6, 1: 2}[protocol]
                altered = payload[:offset] + b"\x00\x01" + payload[offset + 2:]
                result = analyze_packet(make_observation(protocol, altered))
                self.assertIs(result.ipv4_checksum_valid, True)
                self.assertIs(getattr(result, f"{name}_checksum_valid"), False)

    def test_udp_and_icmp_zero_checksums_retain_distinct_semantics(self) -> None:
        udp = analyze_packet(make_observation(17, UDP_BYTES[:6] + b"\x00\x00"))
        self.assertEqual(cast(UDPPacket, udp.udp).checksum, 0)
        self.assertIs(udp.udp_checksum_valid, False)
        icmp = analyze_packet(make_observation(1, bytes.fromhex("fdab000000000254")))
        self.assertEqual(cast(ICMPMessage, icmp.icmp).checksum, 0)
        self.assertIs(icmp.icmp_checksum_valid, True)

    def test_delegation_order_and_exact_decoder_output_references(self) -> None:
        for protocol, name, payload in PROTOCOLS + ((253, "none", b""),):
            with self.subTest(protocol=protocol):
                observation = make_observation(protocol, payload)
                ethernet = packet_analysis.decode_ethernet(observation)
                ipv4 = packet_analysis.decode_ipv4(ethernet)
                transport = (
                    getattr(packet_analysis, f"decode_{name}")(ipv4) if name != "none" else None
                )
                operations = {
                    "decode_ethernet": ethernet,
                    "decode_ipv4": ipv4,
                    "validate_ipv4_checksum": False,
                }
                for layer in ("tcp", "udp", "icmp"):
                    operations[f"decode_{layer}"] = transport if layer == name else None
                    operations[f"validate_{layer}_checksum"] = True
                calls = Mock()
                with ExitStack() as stack:
                    for operation, result in operations.items():
                        mocked = stack.enter_context(
                            patch.object(packet_analysis, operation, return_value=result)
                        )
                        calls.attach_mock(mocked, operation)
                    analysis = analyze_packet(observation)
                expected = [
                    call.decode_ethernet(observation), call.decode_ipv4(ethernet),
                    call.validate_ipv4_checksum(ipv4),
                ]
                if name != "none":
                    expected.extend([
                        getattr(call, f"decode_{name}")(ipv4),
                        getattr(call, f"validate_{name}_checksum")(ipv4, transport),
                    ])
                    self.assertIs(getattr(analysis, name), transport)
                self.assertEqual(calls.mock_calls, expected)
                self.assertIs(analysis.observation, observation)
                self.assertIs(analysis.ethernet, ethernet)
                self.assertIs(analysis.ipv4, ipv4)
                self.assertIs(analysis.ipv4_checksum_valid, False)

    def test_non_initial_fragments_preserve_current_decoder_rejections(self) -> None:
        for protocol, name, payload in PROTOCOLS:
            with self.subTest(protocol=protocol):
                error = {6: TCPDecodeError, 17: UDPDecodeError, 1: ICMPDecodeError}[protocol]
                with patch.object(packet_analysis, f"validate_{name}_checksum") as validator:
                    with self.assertRaises(error):
                        analyze_packet(make_observation(protocol, payload, fragment_field=1))
                    validator.assert_not_called()

    def test_returned_non_initial_fragment_models_skip_checksum_validation(self) -> None:
        for protocol, name, payload in PROTOCOLS:
            with self.subTest(protocol=protocol):
                original = analyze_packet(make_observation(protocol, payload))
                transport = getattr(original, name)
                observation = make_observation(protocol, payload, fragment_field=1)
                with patch.object(packet_analysis, f"decode_{name}", return_value=transport) as decoder:
                    with patch.object(packet_analysis, f"validate_{name}_checksum") as validator:
                        result = analyze_packet(observation)
                decoder.assert_called_once_with(result.ipv4)
                validator.assert_not_called()
                self.assertIs(getattr(result, name), transport)
                self.assertIsNone(getattr(result, f"{name}_checksum_valid"))
                self.assertIs(result.ipv4_checksum_valid, True)

    def test_initial_fragments_with_more_fragments_are_checked(self) -> None:
        for protocol, name, payload in PROTOCOLS:
            with self.subTest(protocol=protocol):
                result = analyze_packet(make_observation(protocol, payload, fragment_field=0x2000))
                self.assertIs(result.ipv4_checksum_valid, True)
                self.assertIs(getattr(result, f"{name}_checksum_valid"), True)

    def test_result_is_immutable_and_model_fields_are_typed(self) -> None:
        result = analyze_packet(make_observation(6, TCP_BYTES))
        for field in fields(result):
            with self.subTest(field=field.name):
                with self.assertRaises(FrozenInstanceError):
                    setattr(result, field.name, None)
                with self.assertRaises(FrozenInstanceError):
                    delattr(result, field.name)
                with self.assertRaises(TypeError):
                    replace(result, **{field.name: []})
        for name in ("ipv4_checksum_valid", "tcp_checksum_valid", "udp_checksum_valid", "icmp_checksum_valid"):
            with self.subTest(field=name):
                with self.assertRaises(TypeError):
                    replace(result, **{name: 1})
