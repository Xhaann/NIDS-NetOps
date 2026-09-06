import unittest
from dataclasses import FrozenInstanceError, replace
from typing import cast

from analysis import ICMPDecodeError, ICMPMessage, IPv4Packet, decode_icmp
from capture.packet_source import CaptureError


ICMP_HEADER = bytes.fromhex("fdab135700ff807f")
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
    protocol=1,
    header_checksum=0,
    source_address=b"\xc0\x00\x02\x01",
    destination_address=b"\xc6\x33\x64\x02",
    options=b"",
    payload=ICMP_HEADER,
)


class ICMPDecoderTests(unittest.TestCase):
    def test_minimal_message_decodes_in_network_order(self) -> None:
        message = decode_icmp(IPV4_PACKET)
        self.assertEqual(
            message,
            ICMPMessage(
                icmp_type=0xFD,
                code=0xAB,
                checksum=0x1357,
                rest_of_header=b"\x00\xff\x80\x7f",
                payload=b"",
            ),
        )

    def test_byte_boundaries_are_preserved_without_mutating_ipv4(self) -> None:
        for payload in (b"", b"\x00\xff\x80\n\r\x00"):
            with self.subTest(payload=payload):
                raw_bytes = ICMP_HEADER + payload
                ipv4 = replace(
                    IPV4_PACKET, payload=raw_bytes, total_length=20 + len(raw_bytes)
                )
                before = replace(ipv4)
                message = decode_icmp(ipv4)
                self.assertEqual(message.rest_of_header, b"\x00\xff\x80\x7f")
                self.assertIsInstance(message.rest_of_header, bytes)
                self.assertEqual(message.payload, payload)
                self.assertIsInstance(message.payload, bytes)
                self.assertEqual(ipv4, before)
                self.assertIs(ipv4.payload, raw_bytes)
                self.assertEqual(raw_bytes, ICMP_HEADER + payload)

    def test_short_headers_raise_icmp_errors(self) -> None:
        for length in range(8):
            with self.subTest(length=length):
                ipv4 = replace(
                    IPV4_PACKET, payload=ICMP_HEADER[:length], total_length=20 + length
                )
                with self.assertRaisesRegex(ICMPDecodeError, "too short") as failure:
                    decode_icmp(ipv4)
                self.assertIsInstance(failure.exception, ValueError)
                self.assertNotIsInstance(failure.exception, CaptureError)

    def test_other_ipv4_protocols_are_rejected(self) -> None:
        for protocol in (0, 6, 17, 255):
            with self.subTest(protocol=protocol):
                with self.assertRaisesRegex(ICMPDecodeError, "protocol 1"):
                    decode_icmp(replace(IPV4_PACKET, protocol=protocol))

    def test_non_initial_fragments_are_rejected(self) -> None:
        for fragment_offset in (1, 8191):
            with self.subTest(fragment_offset=fragment_offset):
                with self.assertRaisesRegex(ICMPDecodeError, "initial IPv4 fragment"):
                    decode_icmp(replace(IPV4_PACKET, fragment_offset=fragment_offset))

    def test_initial_fragment_requires_header_and_preserves_available_payload(self) -> None:
        for payload in (b"", b"\x00\xff\x80"):
            with self.subTest(payload=payload):
                raw_bytes = ICMP_HEADER + payload
                initial = replace(
                    IPV4_PACKET,
                    flags=1,
                    payload=raw_bytes,
                    total_length=20 + len(raw_bytes),
                )
                self.assertEqual(
                    decode_icmp(initial),
                    ICMPMessage(0xFD, 0xAB, 0x1357, b"\x00\xff\x80\x7f", payload),
                )
        with self.assertRaisesRegex(ICMPDecodeError, "too short"):
            decode_icmp(
                replace(IPV4_PACKET, flags=1, payload=ICMP_HEADER[:7], total_length=27)
            )

    def test_decoder_requires_ipv4_packet(self) -> None:
        for value in (None, ICMP_HEADER):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    decode_icmp(cast(IPv4Packet, value))

    def test_messages_decode_independently_with_extreme_numeric_values(self) -> None:
        first = decode_icmp(
            replace(IPV4_PACKET, payload=bytes.fromhex("00ff000000010203"))
        )
        second = decode_icmp(
            replace(IPV4_PACKET, payload=bytes.fromhex("ff00fffffffefdfc"))
        )
        self.assertEqual(first, ICMPMessage(0, 255, 0, b"\x00\x01\x02\x03", b""))
        self.assertEqual(second, ICMPMessage(255, 0, 65535, b"\xff\xfe\xfd\xfc", b""))
        self.assertIsNot(first, second)


class ICMPMessageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.message = ICMPMessage(0xFD, 0xAB, 0x1357, b"\x00\xff\x80\x7f", b"")

    def test_numeric_fields_reject_invalid_ranges_and_types(self) -> None:
        for name, maximum in (("icmp_type", 255), ("code", 255), ("checksum", 65535)):
            for value in (-1, maximum + 1):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(ValueError):
                        replace(self.message, **{name: value})
            for value in (True, False, 1.0, "1", None):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.message, **{name: value})

    def test_byte_fields_require_immutable_bytes(self) -> None:
        for name in ("rest_of_header", "payload"):
            for value in (bytearray(4), memoryview(bytes(4)), "0000", None):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.message, **{name: value})

    def test_rest_of_header_requires_exactly_four_bytes(self) -> None:
        for length in (0, 1, 3, 5):
            with self.subTest(length=length):
                with self.assertRaisesRegex(ValueError, "exactly 4 bytes"):
                    replace(self.message, rest_of_header=bytes(length))

    def test_message_is_immutable(self) -> None:
        for name, value in (
            ("icmp_type", 0),
            ("code", 0),
            ("checksum", 0),
            ("rest_of_header", b"abcd"),
            ("payload", b"changed"),
        ):
            with self.subTest(field=name):
                with self.assertRaises(FrozenInstanceError):
                    setattr(self.message, name, value)
                with self.assertRaises(FrozenInstanceError):
                    delattr(self.message, name)
