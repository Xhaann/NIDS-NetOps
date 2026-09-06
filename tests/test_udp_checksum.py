import unittest
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace
from typing import cast

from analysis import (
    IPv4Packet,
    UDPChecksumValidationError,
    UDPPacket,
    decode_udp,
    validate_udp_checksum,
)
from capture.packet_source import CaptureError


UDP_HEADER = bytes.fromhex("1234abcd000855a5")
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
UDP_DATAGRAM = UDPPacket(0x1234, 0xABCD, 8, 0x55A5, b"")


class UDPChecksumTests(unittest.TestCase):
    def test_known_minimum_datagram_checksum_in_network_order(self) -> None:
        words = (
            0xC000, 0x0201, 0xC633, 0x6402, 0x0011, 0x0008,
            0x1234, 0xABCD, 0x0008, 0,
        )
        self.assertEqual(65535 - sum(words) % 65535, 0x55A5)
        self.assertIs(validate_udp_checksum(IPV4_PACKET, UDP_DATAGRAM), True)
        for checksum in (0xA555, 0x55A4, 65535):
            with self.subTest(checksum=checksum):
                datagram = replace(UDP_DATAGRAM, checksum=checksum)
                self.assertIs(validate_udp_checksum(IPV4_PACKET, datagram), False)

    def test_known_binary_payload_checksums_with_even_and_odd_lengths(self) -> None:
        for payload, wire, expected in (
            (
                b"\x00\xff\x80\n\r\x00",
                "c0000201c63364020011000e1234abcd000e000000ff800a0d00",
                0xC78F,
            ),
            (
                b"\x00\xff\x80",
                "c0000201c63364020011000b1234abcd000b000000ff80",
                0xD49F,
            ),
        ):
            with self.subTest(payload=payload):
                padded = wire + ("00" if len(wire) % 4 else "")
                words = [
                    int(padded[index:index + 4], 16)
                    for index in range(0, len(padded), 4)
                ]
                self.assertEqual(65535 - sum(words) % 65535, expected)
                datagram = UDPPacket(0x1234, 0xABCD, 8 + len(payload), expected, payload)
                before = replace(datagram)
                self.assertIs(validate_udp_checksum(IPV4_PACKET, datagram), True)
                changed = replace(datagram, payload=payload[:-1] + b"\x01")
                self.assertIs(validate_udp_checksum(IPV4_PACKET, changed), False)
                self.assertEqual(datagram, before)
                self.assertIs(datagram.payload, payload)
        self.assertIs(validate_udp_checksum(IPV4_PACKET, UDP_DATAGRAM), True)

    def test_zero_checksum_means_integrity_was_not_validated(self) -> None:
        for payload in (b"", b"\x00\xff\x80"):
            with self.subTest(payload=payload):
                datagram = UDPPacket(0x1234, 0xABCD, 8 + len(payload), 0, payload)
                self.assertIs(validate_udp_checksum(IPV4_PACKET, datagram), False)

    def test_ports_and_datagram_length_participate(self) -> None:
        for changes in (
            {"source_port": 0x1235},
            {"destination_port": 0xABCC},
            {"length": 9, "payload": b"\x00"},
            {"length": 10, "payload": b"\x00\x00"},
        ):
            with self.subTest(changes=changes):
                self.assertIs(
                    validate_udp_checksum(IPV4_PACKET, replace(UDP_DATAGRAM, **changes)),
                    False,
                )

    def test_pseudo_header_addresses_participate(self) -> None:
        for changes in (
            {"source_address": b"\xc0\x00\x02\x02"},
            {"destination_address": b"\xc6\x33\x64\x03"},
        ):
            with self.subTest(changes=changes):
                packet = replace(IPV4_PACKET, **changes)
                self.assertIs(validate_udp_checksum(packet, UDP_DATAGRAM), False)

    def test_unrelated_ipv4_fields_and_enclosing_bytes_are_excluded(self) -> None:
        for changes in (
            {"dscp": 63, "ecn": 3, "ttl": 0, "identification": 65535},
            {"header_checksum": 65535, "flags": 2},
            {"ihl": 6, "options": b"\xff\x00\x80\x7f", "total_length": 32},
            {"payload": UDP_HEADER + b"\xff\x80extra", "total_length": 35},
            {"payload": bytes(8)},
        ):
            with self.subTest(changes=changes):
                packet = replace(IPV4_PACKET, **changes)
                self.assertIs(validate_udp_checksum(packet, UDP_DATAGRAM), True)

    def test_protocol_and_fragment_boundaries_precede_checksum_omission(self) -> None:
        for checksum in (0, UDP_DATAGRAM.checksum):
            datagram = replace(UDP_DATAGRAM, checksum=checksum)
            for changes, message in (
                ({"protocol": 0}, "protocol 17"),
                ({"protocol": 1}, "protocol 17"),
                ({"protocol": 6}, "protocol 17"),
                ({"protocol": 255}, "protocol 17"),
                ({"fragment_offset": 1}, "initial IPv4 fragment"),
                ({"fragment_offset": 8191}, "initial IPv4 fragment"),
            ):
                with self.subTest(checksum=checksum, changes=changes):
                    with self.assertRaisesRegex(UDPChecksumValidationError, message) as failure:
                        validate_udp_checksum(replace(IPV4_PACKET, **changes), datagram)
                    self.assertIsInstance(failure.exception, ValueError)
                    self.assertNotIsInstance(failure.exception, CaptureError)
        self.assertIs(validate_udp_checksum(replace(IPV4_PACKET, flags=1), UDP_DATAGRAM), True)

    def test_inconsistent_model_length_is_rejected_before_checksum_omission(self) -> None:
        for checksum in (0, UDP_DATAGRAM.checksum):
            with self.subTest(checksum=checksum):
                datagram = replace(UDP_DATAGRAM, checksum=checksum)
                object.__setattr__(datagram, "length", 9)
                with self.assertRaisesRegex(UDPChecksumValidationError, "8 plus payload length"):
                    validate_udp_checksum(IPV4_PACKET, datagram)

    def test_wrong_object_types_are_rejected(self) -> None:
        for value in (None, UDP_HEADER, SimpleNamespace(**vars(IPV4_PACKET))):
            with self.subTest(packet=value):
                with self.assertRaises(TypeError):
                    validate_udp_checksum(cast(IPv4Packet, value), UDP_DATAGRAM)
        for value in (None, UDP_HEADER, SimpleNamespace(**vars(UDP_DATAGRAM))):
            with self.subTest(datagram=value):
                with self.assertRaises(TypeError):
                    validate_udp_checksum(IPV4_PACKET, cast(UDPPacket, value))

    def test_inputs_remain_unchanged_and_immutable(self) -> None:
        before_packet = replace(IPV4_PACKET)
        before_datagram = replace(UDP_DATAGRAM)
        self.assertIs(validate_udp_checksum(IPV4_PACKET, UDP_DATAGRAM), True)
        self.assertEqual(IPV4_PACKET, before_packet)
        self.assertEqual(UDP_DATAGRAM, before_datagram)
        self.assertIs(IPV4_PACKET.source_address, before_packet.source_address)
        self.assertIs(IPV4_PACKET.destination_address, before_packet.destination_address)
        for model, field in ((IPV4_PACKET, "header_checksum"), (UDP_DATAGRAM, "checksum")):
            with self.subTest(model=type(model).__name__):
                with self.assertRaises(FrozenInstanceError):
                    setattr(model, field, 0)

    def test_structural_decoding_remains_separate_and_excludes_excess_bytes(self) -> None:
        for checksum in (0, 0x55A4, 0x55A5):
            with self.subTest(checksum=checksum):
                raw_bytes = UDP_HEADER[:6] + checksum.to_bytes(2, byteorder="big") + b"extra"
                packet = replace(IPV4_PACKET, payload=raw_bytes, total_length=33)
                datagram = decode_udp(packet)
                self.assertEqual(datagram, replace(UDP_DATAGRAM, checksum=checksum))
                self.assertIs(validate_udp_checksum(packet, datagram), checksum == 0x55A5)

    def test_computed_zero_encoding_and_repeated_carry_folding(self) -> None:
        self.assertEqual(0x2AA58 - 0x1234 + 0x67D9, 3 * 65535)
        zero = replace(UDP_DATAGRAM, source_port=0x67D9, checksum=65535)
        self.assertIs(validate_udp_checksum(IPV4_PACKET, zero), True)
        self.assertIs(validate_udp_checksum(IPV4_PACKET, replace(zero, checksum=0)), False)
        self.assertEqual(0x2AA58 - 0x1234 + 0x67DB, 0x2FFFF)
        carry = replace(UDP_DATAGRAM, source_port=0x67DB, checksum=0xFFFD)
        self.assertIs(validate_udp_checksum(IPV4_PACKET, carry), True)
