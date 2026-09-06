import unittest
from dataclasses import FrozenInstanceError, replace
from typing import cast

from analysis import EthernetFrame, IPv4DecodeError, IPv4Packet, decode_ipv4
from capture.packet_source import CaptureError


IPV4_HEADER = bytes.fromhex("45ab00141234b23400fd9abcc0000201c6336402")


class IPv4DecoderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.frame = EthernetFrame(bytes(6), bytes(6), 0x0800, IPV4_HEADER)

    def test_minimal_header_decodes_all_fields_in_network_order(self) -> None:
        packet = decode_ipv4(self.frame)
        self.assertEqual(
            packet,
            IPv4Packet(
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
                header_checksum=0x9ABC,
                source_address=b"\xc0\x00\x02\x01",
                destination_address=b"\xc6\x33\x64\x02",
                options=b"",
                payload=b"",
            ),
        )
        self.assertEqual(packet.header_length, 20)

    def test_payload_ends_at_total_length_without_modifying_ethernet(self) -> None:
        payload = b"\x00\xff\x80\n\r\x00"
        header = IPV4_HEADER[:2] + b"\x00\x1a" + IPV4_HEADER[4:]
        for excess in (b"", b"\xff\x00extra"):
            with self.subTest(excess=excess):
                raw_bytes = header + payload + excess
                frame = replace(self.frame, payload=raw_bytes)
                before = replace(frame)
                packet = decode_ipv4(frame)
                self.assertEqual(packet.payload, payload)
                self.assertIsInstance(packet.payload, bytes)
                self.assertEqual(packet.total_length, 26)
                self.assertEqual(frame.payload[packet.total_length:], excess)
                self.assertEqual(frame, before)
                self.assertIs(frame.payload, raw_bytes)
                self.assertEqual(raw_bytes, header + payload + excess)

    def test_options_are_preserved_and_excluded_from_payload(self) -> None:
        for ihl in (6, 15):
            for payload in (b"", b"\x00\x81\xff"):
                with self.subTest(ihl=ihl, payload=payload):
                    options = bytes(range(ihl * 4 - 20))
                    total_length = ihl * 4 + len(payload)
                    header = (
                        bytes([0x40 | ihl, 0xAB])
                        + total_length.to_bytes(2, byteorder="big")
                        + IPV4_HEADER[4:]
                    )
                    packet = decode_ipv4(
                        replace(self.frame, payload=header + options + payload)
                    )
                    self.assertEqual(packet.ihl, ihl)
                    self.assertEqual(packet.header_length, ihl * 4)
                    self.assertEqual(packet.options, options)
                    self.assertIsInstance(packet.options, bytes)
                    self.assertEqual(packet.payload, payload)
                    self.assertEqual(packet.total_length, total_length)

    def test_malformed_headers_raise_analysis_errors(self) -> None:
        malformed = (
            (b"", "too short"),
            (b"\x45", "too short"),
            (IPV4_HEADER[:19], "too short"),
            (b"\x65" + IPV4_HEADER[1:], "version"),
            (b"\x05" + IPV4_HEADER[1:], "version"),
            (b"\x40" + IPV4_HEADER[1:], "IHL"),
            (b"\x44" + IPV4_HEADER[1:], "IHL"),
            (b"\x46" + IPV4_HEADER[1:], "header length exceeds"),
            (IPV4_HEADER[:2] + b"\x00\x13" + IPV4_HEADER[4:], "smaller than"),
            (b"\x46" + IPV4_HEADER[1:] + bytes(4), "smaller than"),
            (IPV4_HEADER[:2] + b"\x00\x15" + IPV4_HEADER[4:], "total length exceeds"),
            (IPV4_HEADER[:2] + b"\xff\xff" + IPV4_HEADER[4:], "total length exceeds"),
        )
        for raw_bytes, message in malformed:
            with self.subTest(raw_bytes=raw_bytes):
                with self.assertRaisesRegex(IPv4DecodeError, message) as failure:
                    decode_ipv4(replace(self.frame, payload=raw_bytes))
                self.assertNotIsInstance(failure.exception, CaptureError)

    def test_non_ipv4_ether_types_are_rejected(self) -> None:
        for ether_type in (0, 0x0806, 0x86DD, 65535):
            with self.subTest(ether_type=ether_type):
                with self.assertRaisesRegex(IPv4DecodeError, "EtherType 0x0800"):
                    decode_ipv4(replace(self.frame, ether_type=ether_type))

    def test_decoder_requires_ethernet_frame(self) -> None:
        with self.assertRaises(TypeError):
            decode_ipv4(cast(EthernetFrame, IPV4_HEADER))

    def test_packets_decode_independently(self) -> None:
        first = decode_ipv4(self.frame)
        other_header = bytes.fromhex("45000014ffffffffffff00000102030405060708")
        second = decode_ipv4(replace(self.frame, payload=other_header))
        self.assertEqual(first.identification, 0x1234)
        self.assertEqual(first.source_address, b"\xc0\x00\x02\x01")
        self.assertEqual(second.identification, 65535)
        self.assertEqual(second.flags, 7)
        self.assertEqual(second.fragment_offset, 8191)
        self.assertEqual(second.ttl, 255)
        self.assertEqual(second.protocol, 255)
        self.assertEqual(second.dscp, 0)
        self.assertEqual(second.ecn, 0)
        self.assertEqual(second.header_checksum, 0)
        self.assertEqual(second.source_address, b"\x01\x02\x03\x04")
        self.assertEqual(second.destination_address, b"\x05\x06\x07\x08")
        self.assertIsNot(first, second)


class IPv4PacketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.packet = decode_ipv4(EthernetFrame(bytes(6), bytes(6), 0x0800, IPV4_HEADER))

    def test_numeric_fields_reject_invalid_ranges_and_types(self) -> None:
        ranges = (
            ("version", 4, 4), ("ihl", 5, 15), ("dscp", 0, 63), ("ecn", 0, 3),
            ("total_length", 0, 65535), ("identification", 0, 65535),
            ("flags", 0, 7), ("fragment_offset", 0, 8191), ("ttl", 0, 255),
            ("protocol", 0, 255), ("header_checksum", 0, 65535),
        )
        for name, minimum, maximum in ranges:
            for value in (minimum - 1, maximum + 1):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(ValueError):
                        replace(self.packet, **{name: value})
            for value in (True, False, 4.0, "4", None):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.packet, **{name: value})

    def test_addresses_require_exactly_four_immutable_bytes(self) -> None:
        for name in ("source_address", "destination_address"):
            for value in (b"", b"123", b"12345"):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(ValueError):
                        replace(self.packet, **{name: value})
            for value in (bytearray(4), memoryview(bytes(4)), "192.0.2.1", None):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.packet, **{name: value})

    def test_options_and_payload_require_immutable_bytes(self) -> None:
        for name in ("options", "payload"):
            for value in (bytearray(), memoryview(b""), "", None):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.packet, **{name: value})

    def test_header_and_payload_lengths_must_be_consistent(self) -> None:
        for changes in (
            {"options": bytes(4)},
            {"ihl": 6},
            {"total_length": 19},
            {"total_length": 21},
            {"payload": b"extra"},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    replace(self.packet, **changes)

    def test_packet_and_derived_header_length_are_immutable(self) -> None:
        for name, value in (
            ("ihl", 6), ("header_length", 24), ("source_address", bytes(4)),
            ("flags", 0), ("options", bytes(4)), ("payload", b"changed"),
        ):
            with self.subTest(field=name):
                with self.assertRaises(FrozenInstanceError):
                    setattr(self.packet, name, value)
                with self.assertRaises(FrozenInstanceError):
                    delattr(self.packet, name)
