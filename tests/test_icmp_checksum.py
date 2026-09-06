import unittest
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace
from typing import cast

from analysis import (
    ICMPChecksumValidationError,
    ICMPMessage,
    IPv4Packet,
    decode_icmp,
    validate_icmp_checksum,
)
from capture.packet_source import CaptureError


ICMP_HEADER = bytes.fromhex("fdab80d500ff807f")
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
ICMP_MESSAGE = ICMPMessage(0xFD, 0xAB, 0x80D5, b"\x00\xff\x80\x7f", b"")


class ICMPChecksumTests(unittest.TestCase):
    def test_known_minimum_message_checksum_in_network_order(self) -> None:
        words = (0xFDAB, 0, 0x00FF, 0x807F)
        self.assertEqual(65535 - sum(words) % 65535, 0x80D5)
        self.assertIs(validate_icmp_checksum(IPV4_PACKET, ICMP_MESSAGE), True)
        for checksum in (0, 0xD580, 0x80D4, 65535):
            with self.subTest(checksum=checksum):
                message = replace(ICMP_MESSAGE, checksum=checksum)
                self.assertIs(validate_icmp_checksum(IPV4_PACKET, message), False)

    def test_known_binary_payload_checksums_with_even_and_odd_lengths(self) -> None:
        for payload, wire, expected in (
            (b"\x00\xff\x80\n\r\x00", "fdab000000ff807f00ff800a0d00", 0xF2CB),
            (b"\x00\xff\x80", "fdab000000ff807f00ff80", 0xFFD5),
        ):
            with self.subTest(payload=payload):
                padded = wire + ("00" if len(wire) % 4 else "")
                words = [
                    int(padded[index:index + 4], 16)
                    for index in range(0, len(padded), 4)
                ]
                self.assertEqual(65535 - sum(words) % 65535, expected)
                message = replace(ICMP_MESSAGE, payload=payload, checksum=expected)
                before = replace(message)
                self.assertIs(validate_icmp_checksum(IPV4_PACKET, message), True)
                changed = replace(message, payload=payload[:-1] + b"\x01")
                self.assertIs(validate_icmp_checksum(IPV4_PACKET, changed), False)
                self.assertEqual(message, before)
                self.assertIs(message.payload, payload)
                self.assertIs(message.rest_of_header, before.rest_of_header)
        self.assertIs(validate_icmp_checksum(IPV4_PACKET, ICMP_MESSAGE), True)

    def test_type_code_and_rest_of_header_participate(self) -> None:
        for changes in (
            {"icmp_type": 0xFC},
            {"code": 0xAA},
            {"rest_of_header": b"\x01\xff\x80\x7f"},
            {"rest_of_header": b"\x00\xff\x80\x7e"},
        ):
            with self.subTest(changes=changes):
                message = replace(ICMP_MESSAGE, **changes)
                self.assertIs(validate_icmp_checksum(IPV4_PACKET, message), False)

    def test_ipv4_addresses_headers_and_enclosing_bytes_are_excluded(self) -> None:
        for changes in (
            {"source_address": b"\xc0\x00\x02\x02"},
            {"destination_address": b"\xc6\x33\x64\x03"},
            {"dscp": 63, "ecn": 3, "ttl": 0, "identification": 65535},
            {"header_checksum": 65535, "flags": 2},
            {"ihl": 6, "options": b"\xff\x00\x80\x7f", "total_length": 32},
            {"payload": ICMP_HEADER + b"\xff\x80extra", "total_length": 35},
            {"payload": bytes(8)},
        ):
            with self.subTest(changes=changes):
                packet = replace(IPV4_PACKET, **changes)
                self.assertIs(validate_icmp_checksum(packet, ICMP_MESSAGE), True)

    def test_zero_checksum_is_compared_directly_and_carries_are_folded(self) -> None:
        self.assertEqual(0xFDAB + 0x0254, 0xFFFF)
        zero = replace(ICMP_MESSAGE, rest_of_header=b"\x00\x00\x02\x54", checksum=0)
        self.assertIs(validate_icmp_checksum(IPV4_PACKET, zero), True)
        self.assertIs(validate_icmp_checksum(IPV4_PACKET, replace(zero, checksum=65535)), False)
        self.assertEqual(0xFDAB + 0xFFFF + 0x0255, 0x1FFFF)
        carry = replace(ICMP_MESSAGE, rest_of_header=b"\xff\xff\x02\x55", checksum=0xFFFE)
        self.assertIs(validate_icmp_checksum(IPV4_PACKET, carry), True)
        all_zero = ICMPMessage(0, 0, 65535, bytes(4), b"")
        self.assertIs(validate_icmp_checksum(IPV4_PACKET, all_zero), True)

    def test_protocol_and_fragment_boundaries(self) -> None:
        for changes, message in (
            ({"protocol": 0}, "protocol 1"),
            ({"protocol": 6}, "protocol 1"),
            ({"protocol": 17}, "protocol 1"),
            ({"protocol": 255}, "protocol 1"),
            ({"fragment_offset": 1}, "initial IPv4 fragment"),
            ({"fragment_offset": 8191}, "initial IPv4 fragment"),
        ):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(ICMPChecksumValidationError, message) as failure:
                    validate_icmp_checksum(replace(IPV4_PACKET, **changes), ICMP_MESSAGE)
                self.assertIsInstance(failure.exception, ValueError)
                self.assertNotIsInstance(failure.exception, CaptureError)
        self.assertIs(validate_icmp_checksum(replace(IPV4_PACKET, flags=1), ICMP_MESSAGE), True)

    def test_wrong_object_types_are_rejected(self) -> None:
        for value in (None, ICMP_HEADER, SimpleNamespace(**vars(IPV4_PACKET))):
            with self.subTest(packet=value):
                with self.assertRaises(TypeError):
                    validate_icmp_checksum(cast(IPv4Packet, value), ICMP_MESSAGE)
        for value in (None, ICMP_HEADER, SimpleNamespace(**vars(ICMP_MESSAGE))):
            with self.subTest(message=value):
                with self.assertRaises(TypeError):
                    validate_icmp_checksum(IPV4_PACKET, cast(ICMPMessage, value))

    def test_inputs_remain_unchanged_and_immutable(self) -> None:
        before_packet = replace(IPV4_PACKET)
        before_message = replace(ICMP_MESSAGE)
        self.assertIs(validate_icmp_checksum(IPV4_PACKET, ICMP_MESSAGE), True)
        self.assertEqual(IPV4_PACKET, before_packet)
        self.assertEqual(ICMP_MESSAGE, before_message)
        self.assertIs(IPV4_PACKET.payload, before_packet.payload)
        self.assertIs(ICMP_MESSAGE.rest_of_header, before_message.rest_of_header)
        for model, field in ((IPV4_PACKET, "header_checksum"), (ICMP_MESSAGE, "checksum")):
            with self.subTest(model=type(model).__name__):
                with self.assertRaises(FrozenInstanceError):
                    setattr(model, field, 0)

    def test_structural_decoder_does_not_validate_checksum(self) -> None:
        raw_bytes = ICMP_HEADER[:2] + b"\x00\x00" + ICMP_HEADER[4:]
        packet = replace(IPV4_PACKET, payload=raw_bytes)
        message = decode_icmp(packet)
        self.assertEqual(message, replace(ICMP_MESSAGE, checksum=0))
        self.assertIs(validate_icmp_checksum(packet, message), False)
