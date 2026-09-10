import unittest
from dataclasses import FrozenInstanceError, fields, replace
from ipaddress import IPv6Address
from struct import pack

import analysis
from analysis import (
    EthernetFrame,
    FlowIdentity,
    IPv6DecodeError,
    IPv6Packet,
    decode_ipv6,
    flow_identity_from_addresses,
)
from analysis import ipv6


SOURCE_ADDRESS = bytes.fromhex("20010db8000000000000000000000001")
DESTINATION_ADDRESS = bytes.fromhex("20010db8000000000000000000000002")
IPV6_HEADER = bytes.fromhex(
    "6ab1234500040600"
    "20010db8000000000000000000000001"
    "20010db8000000000000000000000002"
)


def ipv6_header(
    *,
    version=6,
    traffic_class=0,
    flow_label=0,
    payload_length=0,
    next_header=59,
    hop_limit=64,
):
    return pack(
        "!IHBB16s16s",
        (version << 28) | (traffic_class << 20) | flow_label,
        payload_length, next_header, hop_limit, SOURCE_ADDRESS, DESTINATION_ADDRESS,
    )


def ipv6_frame(raw_bytes):
    return EthernetFrame(bytes(6), bytes(6), 0x86DD, raw_bytes)


class IPv6DecoderTests(unittest.TestCase):
    def test_literal_header_decodes_every_field_in_network_order(self) -> None:
        packet = decode_ipv6(ipv6_frame(IPV6_HEADER + b"\x00\xff\x80\x01"))
        self.assertEqual(packet, IPv6Packet(
            version=6, traffic_class=0xAB, flow_label=0x12345,
            payload_length=4, next_header=6, hop_limit=0,
            source_address=SOURCE_ADDRESS, destination_address=DESTINATION_ADDRESS,
            payload=b"\x00\xff\x80\x01",
        ))
        self.assertEqual(packet.header_length, 40)

    def test_exactly_forty_bytes_accepts_zero_declared_payload(self) -> None:
        raw_bytes = ipv6_header(flow_label=0, hop_limit=0)
        self.assertEqual(len(raw_bytes), 40)
        packet = decode_ipv6(ipv6_frame(raw_bytes))
        self.assertEqual(packet.version, 6)
        self.assertEqual(packet.flow_label, 0)
        self.assertEqual(packet.hop_limit, 0)
        self.assertEqual(packet.payload_length, 0)
        self.assertEqual(packet.payload, b"")

    def test_every_short_header_is_rejected(self) -> None:
        for length in range(40):
            with self.subTest(length=length):
                with self.assertRaisesRegex(IPv6DecodeError, "header is too short"):
                    decode_ipv6(ipv6_frame(IPV6_HEADER[:length]))

    def test_every_non_ipv6_version_is_rejected_despite_sufficient_bytes(self) -> None:
        for version in range(16):
            if version != 6:
                with self.subTest(version=version):
                    with self.assertRaisesRegex(IPv6DecodeError, "version must be 6"):
                        decode_ipv6(ipv6_frame(ipv6_header(version=version) + bytes(100)))

    def test_declared_payload_must_be_available(self) -> None:
        for declared, available in ((1, 0), (4, 3), (65535, 65534)):
            with self.subTest(declared=declared, available=available):
                with self.assertRaisesRegex(IPv6DecodeError, "payload length exceeds"):
                    decode_ipv6(ipv6_frame(ipv6_header(payload_length=declared) + bytes(available)))

    def test_payload_is_bounded_by_declared_length_without_changing_fields(self) -> None:
        for payload in (b"abcd", b"\xff\x00\x80\x01"):
            for excess in (b"", b"extra captured bytes"):
                with self.subTest(payload=payload, excess=excess):
                    frame = ipv6_frame(IPV6_HEADER + payload + excess)
                    before = replace(frame)
                    packet = decode_ipv6(frame)
                    self.assertEqual(packet.payload_length, 4)
                    self.assertEqual(packet.payload, payload)
                    self.assertEqual((packet.traffic_class, packet.flow_label, packet.next_header, packet.hop_limit), (0xAB, 0x12345, 6, 0))
                    self.assertEqual(frame.payload[40 + packet.payload_length:], excess)
                    self.assertEqual(frame, before)
                    self.assertIs(frame.payload, before.payload)

    def test_zero_payload_length_is_preserved_without_inferred_length(self) -> None:
        for next_header in (0, 59, 255):
            with self.subTest(next_header=next_header):
                frame = ipv6_frame(ipv6_header(next_header=next_header) + b"opaque trailing bytes")
                packet = decode_ipv6(frame)
                self.assertEqual(packet.payload_length, 0)
                self.assertEqual(packet.payload, b"")
                self.assertEqual(frame.payload[40:], b"opaque trailing bytes")

    def test_maximum_field_values_and_payload_are_preserved(self) -> None:
        payload = bytes(range(256)) * 255 + bytes(range(255))
        packet = decode_ipv6(ipv6_frame(ipv6_header(
            traffic_class=255, flow_label=1048575, payload_length=65535,
            next_header=255, hop_limit=255,
        ) + payload))
        self.assertEqual(packet.traffic_class, 255)
        self.assertEqual(packet.flow_label, 1048575)
        self.assertEqual(packet.payload_length, 65535)
        self.assertEqual(packet.next_header, 255)
        self.assertEqual(packet.hop_limit, 255)
        self.assertEqual(packet.payload, payload)
        self.assertEqual(packet.header_length + len(packet.payload), 65575)

    def test_traffic_class_and_flow_label_bits_do_not_overlap(self) -> None:
        for traffic_class in (0, 1, 15, 16, 127, 128, 255):
            for flow_label in (0, 1, 65535, 65536, 524288, 1048575):
                with self.subTest(traffic_class=traffic_class, flow_label=flow_label):
                    packet = decode_ipv6(ipv6_frame(ipv6_header(
                        traffic_class=traffic_class, flow_label=flow_label,
                    )))
                    self.assertEqual(packet.version, 6)
                    self.assertEqual(packet.traffic_class, traffic_class)
                    self.assertEqual(packet.flow_label, flow_label)

    def test_next_header_values_leave_payload_opaque(self) -> None:
        for next_header in (0, 6, 17, 43, 44, 50, 51, 58, 59, 60, 135, 253, 254, 255):
            with self.subTest(next_header=next_header):
                packet = decode_ipv6(ipv6_frame(ipv6_header(
                    next_header=next_header, payload_length=1,
                ) + b"\xff"))
                self.assertEqual(packet.next_header, next_header)
                self.assertEqual(packet.payload, b"\xff")

    def test_addresses_preserve_order_family_and_canonical_identity(self) -> None:
        packet = decode_ipv6(ipv6_frame(ipv6_header()))
        self.assertEqual(packet.source_address, SOURCE_ADDRESS)
        self.assertEqual(packet.destination_address, DESTINATION_ADDRESS)
        self.assertEqual(IPv6Address(packet.source_address), IPv6Address("2001:db8::1"))
        self.assertEqual(IPv6Address(packet.destination_address), IPv6Address("2001:0db8:0:0:0:0:0:2"))
        identity = FlowIdentity(packet.source_address, packet.destination_address, 1, 2, 6)
        self.assertEqual(identity.ip_version, 6)
        self.assertIs(identity.source_address, packet.source_address)
        self.assertIs(identity.destination_address, packet.destination_address)
        self.assertEqual(identity, flow_identity_from_addresses("2001:db8::1", "2001:db8::2", 1, 2, 6))
        reversed_header = ipv6_header()[:8] + DESTINATION_ADDRESS + SOURCE_ADDRESS
        reversed_packet = decode_ipv6(ipv6_frame(reversed_header))
        self.assertEqual(reversed_packet.source_address, DESTINATION_ADDRESS)
        self.assertEqual(reversed_packet.destination_address, SOURCE_ADDRESS)

    def test_wrong_frame_type_and_ethertype_are_rejected(self) -> None:
        for value in (None, IPV6_HEADER, bytearray(IPV6_HEADER), object()):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    decode_ipv6(value)
        for ether_type in (0, 0x0800, 0x0806, 65535):
            with self.subTest(ether_type=ether_type):
                with self.assertRaisesRegex(IPv6DecodeError, "EtherType 0x86DD"):
                    decode_ipv6(replace(ipv6_frame(ipv6_header()), ether_type=ether_type))

    def test_repeated_decoding_is_deterministic_and_keeps_input_unchanged(self) -> None:
        frame = ipv6_frame(IPV6_HEADER + b"abcd")
        raw_bytes = frame.payload
        first = decode_ipv6(frame)
        decode_ipv6(ipv6_frame(ipv6_header()))
        second = decode_ipv6(frame)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertIs(frame.payload, raw_bytes)


class IPv6PacketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.packet = decode_ipv6(ipv6_frame(ipv6_header()))

    def test_integer_fields_enforce_types_and_ranges(self) -> None:
        for name, minimum, maximum in (
            ("version", 6, 6), ("traffic_class", 0, 255),
            ("flow_label", 0, 1048575), ("payload_length", 0, 65535),
            ("next_header", 0, 255), ("hop_limit", 0, 255),
        ):
            for value in (True, False, 6.0, "6", None):
                with self.subTest(name=name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.packet, **{name: value})
            for value in (minimum - 1, maximum + 1):
                with self.subTest(name=name, value=value):
                    with self.assertRaises(ValueError):
                        replace(self.packet, **{name: value})

    def test_addresses_require_sixteen_immutable_bytes(self) -> None:
        for name in ("source_address", "destination_address"):
            for value in (bytes(0), bytes(4), bytes(15), bytes(17)):
                with self.subTest(name=name, length=len(value)):
                    with self.assertRaises(ValueError):
                        replace(self.packet, **{name: value})
            for value in (bytearray(16), memoryview(bytes(16)), "::1", None):
                with self.subTest(name=name, value=type(value)):
                    with self.assertRaises(TypeError):
                        replace(self.packet, **{name: value})

    def test_direct_model_retains_exact_address_and_payload_objects(self) -> None:
        payload = b"opaque bytes"
        for source, destination in ((bytes(16), b"\xff" * 16), (DESTINATION_ADDRESS, SOURCE_ADDRESS)):
            with self.subTest(source=source):
                packet = replace(self.packet, source_address=source, destination_address=destination, payload=payload, payload_length=len(payload))
                self.assertIs(packet.source_address, source)
                self.assertIs(packet.destination_address, destination)
                self.assertIs(packet.payload, payload)

    def test_payload_must_be_immutable_and_match_declared_length(self) -> None:
        for value in (bytearray(), memoryview(b""), "", None):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    replace(self.packet, payload=value)
        for length, payload in ((0, b"a"), (1, b""), (2, b"a")):
            with self.subTest(length=length, payload=payload):
                with self.assertRaisesRegex(ValueError, "payload_length"):
                    replace(self.packet, payload_length=length, payload=payload)

    def test_model_is_frozen_and_contains_only_observed_fields(self) -> None:
        self.assertEqual(tuple(field.name for field in fields(self.packet)), (
            "version", "traffic_class", "flow_label", "payload_length", "next_header",
            "hop_limit", "source_address", "destination_address", "payload",
        ))
        for name in tuple(field.name for field in fields(self.packet)) + ("header_length",):
            with self.assertRaises(FrozenInstanceError):
                setattr(self.packet, name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(self.packet, name)

    def test_public_exports_match_ipv4_convention(self) -> None:
        for name in ("IPv6DecodeError", "IPv6Packet", "decode_ipv6"):
            self.assertIn(name, analysis.__all__)
            self.assertIs(getattr(analysis, name), getattr(ipv6, name))


if __name__ == "__main__":
    unittest.main()
