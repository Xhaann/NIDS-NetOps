import unittest
from dataclasses import FrozenInstanceError, replace
from typing import cast

from analysis import IPv4Packet, UDPDecodeError, UDPPacket, decode_udp
from capture.packet_source import CaptureError


UDP_HEADER = bytes.fromhex("1234abcd00081357")
IPV4_PACKET = IPv4Packet(
    version=4,
    ihl=5,
    dscp=0,
    ecn=0,
    total_length=28,
    identification=0,
    flags=0,
    fragment_offset=0,
    ttl=64,
    protocol=17,
    header_checksum=0,
    source_address=b"\xc0\x00\x02\x01",
    destination_address=b"\xc6\x33\x64\x02",
    options=b"",
    payload=UDP_HEADER,
)


class UDPDecoderTests(unittest.TestCase):
    def test_minimal_datagram_decodes_in_network_order(self) -> None:
        packet = decode_udp(IPV4_PACKET)
        self.assertEqual(
            packet,
            UDPPacket(
                source_port=0x1234,
                destination_port=0xABCD,
                length=8,
                checksum=0x1357,
                payload=b"",
            ),
        )

    def test_payload_ends_at_declared_length_without_mutating_ipv4(self) -> None:
        for payload in (b"", b"\x00\xff\x80\n\r\x00"):
            for excess in (b"", b"\xff\x00extra"):
                with self.subTest(payload=payload, excess=excess):
                    length = 8 + len(payload)
                    header = (
                        UDP_HEADER[:4]
                        + length.to_bytes(2, byteorder="big")
                        + UDP_HEADER[6:]
                    )
                    raw_bytes = header + payload + excess
                    ipv4 = replace(
                        IPV4_PACKET, payload=raw_bytes, total_length=20 + len(raw_bytes)
                    )
                    before = replace(ipv4)
                    packet = decode_udp(ipv4)
                    self.assertEqual(packet.length, length)
                    self.assertEqual(packet.payload, payload)
                    self.assertIsInstance(packet.payload, bytes)
                    self.assertEqual(ipv4.payload[packet.length:], excess)
                    self.assertEqual(ipv4, before)
                    self.assertIs(ipv4.payload, raw_bytes)
                    self.assertEqual(raw_bytes, header + payload + excess)

    def test_malformed_datagrams_raise_udp_errors(self) -> None:
        malformed = (
            (b"", "too short"),
            (b"\x00", "too short"),
            (UDP_HEADER[:7], "too short"),
            (UDP_HEADER[:4] + b"\x00\x00" + UDP_HEADER[6:], "at least 8"),
            (UDP_HEADER[:4] + b"\x00\x07" + UDP_HEADER[6:], "at least 8"),
            (UDP_HEADER[:4] + b"\x00\x09" + UDP_HEADER[6:], "exceeds"),
            (UDP_HEADER[:4] + b"\xff\xff" + UDP_HEADER[6:], "exceeds"),
        )
        for raw_bytes, message in malformed:
            with self.subTest(raw_bytes=raw_bytes):
                ipv4 = replace(
                    IPV4_PACKET, payload=raw_bytes, total_length=20 + len(raw_bytes)
                )
                with self.assertRaisesRegex(UDPDecodeError, message) as failure:
                    decode_udp(ipv4)
                self.assertNotIsInstance(failure.exception, CaptureError)

    def test_other_ipv4_protocols_are_rejected(self) -> None:
        for protocol in (0, 1, 6, 255):
            with self.subTest(protocol=protocol):
                with self.assertRaisesRegex(UDPDecodeError, "protocol 17"):
                    decode_udp(replace(IPV4_PACKET, protocol=protocol))

    def test_non_initial_fragments_are_rejected(self) -> None:
        for fragment_offset in (1, 8191):
            with self.subTest(fragment_offset=fragment_offset):
                with self.assertRaisesRegex(UDPDecodeError, "initial IPv4 fragment"):
                    decode_udp(replace(IPV4_PACKET, fragment_offset=fragment_offset))

    def test_initial_fragment_still_requires_complete_declared_datagram(self) -> None:
        initial = replace(IPV4_PACKET, flags=1)
        self.assertEqual(decode_udp(initial), decode_udp(IPV4_PACKET))
        incomplete = UDP_HEADER[:4] + b"\x00\x10" + UDP_HEADER[6:]
        with self.assertRaisesRegex(UDPDecodeError, "length exceeds"):
            decode_udp(replace(initial, payload=incomplete))

    def test_decoder_requires_ipv4_packet(self) -> None:
        for value in (None, UDP_HEADER):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    decode_udp(cast(IPv4Packet, value))

    def test_datagrams_decode_independently_with_extreme_ports_and_checksums(self) -> None:
        first = decode_udp(replace(IPV4_PACKET, payload=bytes.fromhex("0000ffff00080000")))
        second = decode_udp(replace(IPV4_PACKET, payload=bytes.fromhex("ffff00000008ffff")))
        self.assertEqual(first, UDPPacket(0, 65535, 8, 0, b""))
        self.assertEqual(second, UDPPacket(65535, 0, 8, 65535, b""))
        self.assertIsNot(first, second)

    def test_largest_datagram_that_fits_minimal_ipv4_header(self) -> None:
        payload = bytes(65507)
        raw_bytes = UDP_HEADER[:4] + b"\xff\xeb" + UDP_HEADER[6:] + payload
        ipv4 = replace(IPV4_PACKET, payload=raw_bytes, total_length=65535)
        packet = decode_udp(ipv4)
        self.assertEqual(packet.length, 65515)
        self.assertEqual(packet.payload, payload)


class UDPPacketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.packet = UDPPacket(0x1234, 0xABCD, 8, 0x1357, b"")

    def test_numeric_fields_reject_invalid_ranges_and_types(self) -> None:
        ranges = (
            ("source_port", 0, 65535),
            ("destination_port", 0, 65535),
            ("length", 8, 65535),
            ("checksum", 0, 65535),
        )
        for name, minimum, maximum in ranges:
            for value in (minimum - 1, maximum + 1):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(ValueError):
                        replace(self.packet, **{name: value})
            for value in (True, False, 8.0, "8", None):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.packet, **{name: value})

    def test_payload_requires_immutable_bytes(self) -> None:
        for value in (bytearray(), memoryview(b""), "", None):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    replace(self.packet, payload=value)

    def test_length_must_equal_header_plus_payload_length(self) -> None:
        for changes in ({"length": 9}, {"payload": b"extra"}):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ValueError, "8 plus payload length"):
                    replace(self.packet, **changes)

    def test_model_preserves_maximum_unsigned_datagram_length(self) -> None:
        payload = bytes(65527)
        packet = UDPPacket(0, 65535, 65535, 65535, payload)
        self.assertEqual(packet.length, 65535)
        self.assertIs(packet.payload, payload)

    def test_packet_is_immutable(self) -> None:
        for name, value in (
            ("source_port", 0),
            ("destination_port", 0),
            ("length", 9),
            ("checksum", 0),
            ("payload", b"changed"),
        ):
            with self.subTest(field=name):
                with self.assertRaises(FrozenInstanceError):
                    setattr(self.packet, name, value)
                with self.assertRaises(FrozenInstanceError):
                    delattr(self.packet, name)
