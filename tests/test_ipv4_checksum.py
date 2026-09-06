import unittest
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace
from typing import cast

from analysis import EthernetFrame, IPv4Packet, decode_ipv4, validate_ipv4_checksum


IPV4_PACKET = IPv4Packet(
    version=4,
    ihl=5,
    dscp=42,
    ecn=3,
    total_length=20,
    identification=0x1234,
    flags=5,
    fragment_offset=0x1234,
    ttl=0,
    protocol=253,
    header_checksum=0x08A3,
    source_address=b"\xc0\x00\x02\x01",
    destination_address=b"\xc6\x33\x64\x02",
    options=b"",
    payload=b"",
)


class IPv4ChecksumTests(unittest.TestCase):
    def test_known_headers_validate_in_network_order(self) -> None:
        other = replace(
            IPV4_PACKET,
            dscp=0,
            ecn=0,
            total_length=115,
            identification=0,
            flags=2,
            fragment_offset=0,
            ttl=64,
            protocol=17,
            header_checksum=0xB861,
            source_address=b"\xc0\xa8\x00\x01",
            destination_address=b"\xc0\xa8\x00\xc7",
            payload=bytes(95),
        )
        for packet, header in (
            (IPV4_PACKET, "45ab00141234b23400fd0000c0000201c6336402"),
            (other, "450000730000400040110000c0a80001c0a800c7"),
        ):
            with self.subTest(header=header):
                words = [int(header[index:index + 4], 16) for index in range(0, 40, 4)]
                self.assertEqual(65535 - sum(words) % 65535, packet.header_checksum)
                self.assertIs(validate_ipv4_checksum(packet), True)

    def test_checksum_mismatch_returns_false(self) -> None:
        for checksum in (0, 0xA308, 0x08A2, 65535):
            with self.subTest(checksum=checksum):
                self.assertIs(
                    validate_ipv4_checksum(replace(IPV4_PACKET, header_checksum=checksum)),
                    False,
                )

    def test_each_header_field_participates(self) -> None:
        for changes in (
            {"source_address": b"\xc0\x00\x02\x02"},
            {"destination_address": b"\xc6\x33\x64\x03"},
            {"protocol": 252},
            {"ttl": 1},
            {"identification": 0x1235},
            {"flags": 4},
            {"fragment_offset": 0x1235},
            {"total_length": 21, "payload": b"\x00"},
            {"dscp": 43},
            {"ecn": 2},
            {"ihl": 6, "total_length": 24, "options": bytes(4)},
        ):
            with self.subTest(changes=changes):
                self.assertIs(validate_ipv4_checksum(replace(IPV4_PACKET, **changes)), False)

    def test_options_are_included_without_interpretation(self) -> None:
        packet = replace(
            IPV4_PACKET,
            ihl=6,
            total_length=24,
            options=b"\x01\xff\x80\x7f",
            header_checksum=0x8520,
        )
        words = (
            0x46AB, 0x0018, 0x1234, 0xB234, 0x00FD, 0,
            0xC000, 0x0201, 0xC633, 0x6402, 0x01FF, 0x807F,
        )
        self.assertEqual(65535 - sum(words) % 65535, 0x8520)
        self.assertIs(validate_ipv4_checksum(packet), True)
        for options in (b"\x00\xff\x80\x7f", b"\x01\xff\x80\x7e", bytes(4)):
            with self.subTest(options=options):
                self.assertIs(validate_ipv4_checksum(replace(packet, options=options)), False)

    def test_payload_is_excluded_and_packet_remains_immutable(self) -> None:
        for payload in (bytes(4), b"\x00\xff\x80\x7f", b"abcd"):
            with self.subTest(payload=payload):
                packet = replace(
                    IPV4_PACKET, total_length=24, header_checksum=0x089F, payload=payload
                )
                before = replace(packet)
                self.assertIs(validate_ipv4_checksum(packet), True)
                self.assertEqual(packet, before)
                self.assertIs(packet.payload, payload)
                self.assertIs(packet.options, before.options)
                with self.assertRaises(FrozenInstanceError):
                    setattr(packet, "header_checksum", 0)

    def test_extreme_header_values_and_maximum_options_length(self) -> None:
        packet = IPv4Packet(
            version=4,
            ihl=15,
            dscp=63,
            ecn=3,
            total_length=65535,
            identification=65535,
            flags=7,
            fragment_offset=8191,
            ttl=255,
            protocol=255,
            header_checksum=0xB000,
            source_address=b"\xff" * 4,
            destination_address=b"\xff" * 4,
            options=b"\xff" * 40,
            payload=bytes(65475),
        )
        self.assertEqual(65535 - (0x4FFF + 28 * 65535) % 65535, 0xB000)
        self.assertIs(validate_ipv4_checksum(packet), True)
        self.assertIs(
            validate_ipv4_checksum(replace(packet, options=b"\xff" * 39 + b"\xfe")),
            False,
        )

    def test_repeated_carry_folding_and_zero_checksum(self) -> None:
        packet = replace(
            IPV4_PACKET,
            dscp=0,
            ecn=0,
            identification=0,
            flags=0,
            fragment_offset=0,
            protocol=0,
            source_address=bytes(4),
            destination_address=bytes(4),
        )
        self.assertEqual(0x4500 + 20 + 0xFFFF + 0xBAEC, 0x1FFFF)
        self.assertIs(
            validate_ipv4_checksum(
                replace(packet, source_address=b"\xff\xff\xba\xec", header_checksum=0xFFFE)
            ),
            True,
        )
        self.assertEqual(0x4500 + 20 + 0xBAEB, 0xFFFF)
        zero = replace(packet, source_address=b"\x00\x00\xba\xeb", header_checksum=0)
        self.assertIs(validate_ipv4_checksum(zero), True)
        self.assertIs(validate_ipv4_checksum(replace(zero, header_checksum=65535)), False)

    def test_validator_requires_ipv4_packet(self) -> None:
        for value in (None, b"", SimpleNamespace(**vars(IPV4_PACKET))):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    validate_ipv4_checksum(cast(IPv4Packet, value))

    def test_structural_decoding_does_not_validate_checksum(self) -> None:
        header = bytes.fromhex("45ab00141234b23400fd0000c0000201c6336402")
        packet = decode_ipv4(EthernetFrame(bytes(6), bytes(6), 0x0800, header))
        self.assertEqual(packet, replace(IPV4_PACKET, header_checksum=0))
        self.assertIs(validate_ipv4_checksum(packet), False)
