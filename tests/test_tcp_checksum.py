import unittest
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace
from typing import cast

from analysis import (
    IPv4Packet,
    TCPChecksumValidationError,
    TCPPacket,
    decode_tcp,
    validate_tcp_checksum,
)
from capture.packet_source import CaptureError


TCP_HEADER = bytes.fromhex("1234abcd0123456789abcdef5b55fedc38ec2468")
IPV4_PACKET = IPv4Packet(
    version=4,
    ihl=5,
    dscp=0,
    ecn=0,
    total_length=40,
    identification=0,
    flags=0,
    fragment_offset=0,
    ttl=64,
    protocol=6,
    header_checksum=0,
    source_address=b"\xc0\x00\x02\x01",
    destination_address=b"\xc6\x33\x64\x02",
    options=b"",
    payload=TCP_HEADER,
)
TCP_SEGMENT = TCPPacket(
    source_port=0x1234,
    destination_port=0xABCD,
    sequence_number=0x01234567,
    acknowledgment_number=0x89ABCDEF,
    data_offset=5,
    reserved_bits=5,
    ns=True,
    cwr=False,
    ece=True,
    urg=False,
    ack=True,
    psh=False,
    rst=True,
    syn=False,
    fin=True,
    window_size=0xFEDC,
    checksum=0x38EC,
    urgent_pointer=0x2468,
    options=b"",
    payload=b"",
)


class TCPChecksumTests(unittest.TestCase):
    def test_known_minimum_header_checksum_in_network_order(self) -> None:
        words = (
            0xC000, 0x0201, 0xC633, 0x6402, 0x0006, 0x0014,
            0x1234, 0xABCD, 0x0123, 0x4567, 0x89AB, 0xCDEF,
            0x5B55, 0xFEDC, 0, 0x2468,
        )
        self.assertEqual(65535 - sum(words) % 65535, 0x38EC)
        self.assertIs(validate_tcp_checksum(IPV4_PACKET, TCP_SEGMENT), True)
        for checksum in (0, 0xEC38, 0x38ED, 65535):
            with self.subTest(checksum=checksum):
                segment = replace(TCP_SEGMENT, checksum=checksum)
                self.assertIs(validate_tcp_checksum(IPV4_PACKET, segment), False)

    def test_known_even_binary_payload_checksum(self) -> None:
        wire = (
            "c0000201c63364020006001a"
            "1234abcd0123456789abcdef5b55fedc00002468"
            "00ff800a0d00"
        )
        words = [int(wire[index:index + 4], 16) for index in range(0, len(wire), 4)]
        self.assertEqual(65535 - sum(words) % 65535, 0xAADC)
        segment = replace(TCP_SEGMENT, payload=b"\x00\xff\x80\n\r\x00", checksum=0xAADC)
        self.assertIs(validate_tcp_checksum(IPV4_PACKET, segment), True)
        altered = replace(segment, payload=b"\x00\xff\x80\n\r\x01")
        self.assertIs(validate_tcp_checksum(IPV4_PACKET, altered), False)
        self.assertIs(validate_tcp_checksum(IPV4_PACKET, TCP_SEGMENT), True)

    def test_known_options_and_odd_payload_checksum(self) -> None:
        wire = (
            "c0000201c63364020006001b"
            "1234abcd0123456789abcdef6b55fedc00002468"
            "00ff807f00ff80"
        )
        padded = wire + "00"
        words = [int(padded[index:index + 4], 16) for index in range(0, len(padded), 4)]
        self.assertEqual(65535 - sum(words) % 65535, 0x2667)
        segment = replace(
            TCP_SEGMENT,
            data_offset=6,
            options=b"\x00\xff\x80\x7f",
            payload=b"\x00\xff\x80",
            checksum=0x2667,
        )
        before = replace(segment)
        self.assertIs(validate_tcp_checksum(IPV4_PACKET, segment), True)
        for changes in (
            {"options": b"\x01\xff\x80\x7f"},
            {"options": b"\x00\xff\x80\x7e"},
            {"payload": b"\x00\xff\x81"},
            {"payload": b"\x00\xff\x80\x00"},
        ):
            with self.subTest(changes=changes):
                self.assertIs(
                    validate_tcp_checksum(IPV4_PACKET, replace(segment, **changes)), False
                )
        self.assertEqual(segment, before)
        self.assertIs(segment.options, before.options)
        self.assertIs(segment.payload, before.payload)

    def test_numeric_tcp_header_fields_participate(self) -> None:
        for changes in (
            {"source_port": 0x1235},
            {"destination_port": 0xABCC},
            {"sequence_number": 0x01234568},
            {"acknowledgment_number": 0x89ABCDEE},
            {"reserved_bits": 4},
            {"window_size": 0xFEDD},
            {"urgent_pointer": 0x2469},
            {"data_offset": 6, "options": bytes(4)},
        ):
            with self.subTest(changes=changes):
                segment = replace(TCP_SEGMENT, **changes)
                self.assertIs(validate_tcp_checksum(IPV4_PACKET, segment), False)

    def test_each_control_bit_uses_its_wire_position(self) -> None:
        flags = ("ns", "cwr", "ece", "urg", "ack", "psh", "rst", "syn", "fin")
        segment = replace(TCP_SEGMENT, **{name: False for name in flags})
        for name, checksum in (
            ("none", 0x3A41), ("ns", 0x3941), ("cwr", 0x39C1),
            ("ece", 0x3A01), ("urg", 0x3A21), ("ack", 0x3A31),
            ("psh", 0x3A39), ("rst", 0x3A3D), ("syn", 0x3A3F), ("fin", 0x3A40),
        ):
            with self.subTest(flag=name):
                changes = {name: True} if name != "none" else {}
                active = replace(segment, checksum=checksum, **changes)
                self.assertIs(validate_tcp_checksum(IPV4_PACKET, active), True)

    def test_pseudo_header_addresses_and_segment_length_participate(self) -> None:
        for changes in (
            {"source_address": b"\xc0\x00\x02\x02"},
            {"destination_address": b"\xc6\x33\x64\x03"},
        ):
            with self.subTest(changes=changes):
                packet = replace(IPV4_PACKET, **changes)
                self.assertIs(validate_tcp_checksum(packet, TCP_SEGMENT), False)
        for payload in (b"\x00", b"\x00\x00"):
            with self.subTest(payload=payload):
                segment = replace(TCP_SEGMENT, payload=payload)
                self.assertIs(validate_tcp_checksum(IPV4_PACKET, segment), False)

    def test_other_ipv4_fields_and_payload_bytes_are_excluded(self) -> None:
        for changes in (
            {"dscp": 63, "ecn": 3, "ttl": 0, "identification": 65535},
            {"header_checksum": 65535, "flags": 2},
            {"ihl": 6, "options": b"\xff\x00\x80\x7f", "total_length": 44},
            {"payload": TCP_HEADER + b"\xff\x80extra", "total_length": 47},
            {"payload": bytes(20)},
        ):
            with self.subTest(changes=changes):
                packet = replace(IPV4_PACKET, **changes)
                self.assertIs(validate_tcp_checksum(packet, TCP_SEGMENT), True)

    def test_protocol_and_fragment_boundaries(self) -> None:
        for changes, message in (
            ({"protocol": 0}, "protocol 6"),
            ({"protocol": 1}, "protocol 6"),
            ({"protocol": 17}, "protocol 6"),
            ({"protocol": 255}, "protocol 6"),
            ({"fragment_offset": 1}, "initial IPv4 fragment"),
            ({"fragment_offset": 8191}, "initial IPv4 fragment"),
        ):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(TCPChecksumValidationError, message) as failure:
                    validate_tcp_checksum(replace(IPV4_PACKET, **changes), TCP_SEGMENT)
                self.assertIsInstance(failure.exception, ValueError)
                self.assertNotIsInstance(failure.exception, CaptureError)
        self.assertIs(validate_tcp_checksum(replace(IPV4_PACKET, flags=1), TCP_SEGMENT), True)

    def test_wrong_object_types_are_rejected(self) -> None:
        for value in (None, TCP_HEADER, SimpleNamespace(**vars(IPV4_PACKET))):
            with self.subTest(packet=value):
                with self.assertRaises(TypeError):
                    validate_tcp_checksum(cast(IPv4Packet, value), TCP_SEGMENT)
        for value in (None, TCP_HEADER, SimpleNamespace(**vars(TCP_SEGMENT))):
            with self.subTest(segment=value):
                with self.assertRaises(TypeError):
                    validate_tcp_checksum(IPV4_PACKET, cast(TCPPacket, value))

    def test_inputs_remain_unchanged_and_immutable(self) -> None:
        before_packet = replace(IPV4_PACKET)
        before_segment = replace(TCP_SEGMENT)
        self.assertIs(validate_tcp_checksum(IPV4_PACKET, TCP_SEGMENT), True)
        self.assertEqual(IPV4_PACKET, before_packet)
        self.assertEqual(TCP_SEGMENT, before_segment)
        self.assertIs(IPV4_PACKET.source_address, before_packet.source_address)
        self.assertIs(IPV4_PACKET.destination_address, before_packet.destination_address)
        for model, field in ((IPV4_PACKET, "header_checksum"), (TCP_SEGMENT, "checksum")):
            with self.subTest(model=type(model).__name__):
                with self.assertRaises(FrozenInstanceError):
                    setattr(model, field, 0)

    def test_structural_decoder_does_not_validate_checksum(self) -> None:
        raw_bytes = TCP_HEADER[:16] + b"\x00\x00" + TCP_HEADER[18:]
        packet = replace(IPV4_PACKET, payload=raw_bytes)
        segment = decode_tcp(packet)
        self.assertEqual(segment, replace(TCP_SEGMENT, checksum=0))
        self.assertIs(validate_tcp_checksum(packet, segment), False)

    def test_segment_length_must_fit_pseudo_header(self) -> None:
        segment = replace(TCP_SEGMENT, payload=bytes(65515), checksum=0x3900)
        self.assertEqual(65535 - (0x5C70E - 20 + 65535) % 65535, 0x3900)
        self.assertIs(validate_tcp_checksum(IPV4_PACKET, segment), True)
        oversized = replace(segment, payload=bytes(65516))
        with self.assertRaisesRegex(TCPChecksumValidationError, "length exceeds 65535"):
            validate_tcp_checksum(IPV4_PACKET, oversized)

    def test_repeated_carry_folding_and_zero_checksum(self) -> None:
        self.assertEqual(0x5C70E - 0x2468 + 0x5D59, 0x5FFFF)
        for urgent_pointer, checksum in ((0x5D59, 0xFFFA), (0x5D54, 0)):
            with self.subTest(checksum=checksum):
                segment = replace(TCP_SEGMENT, urgent_pointer=urgent_pointer, checksum=checksum)
                self.assertIs(validate_tcp_checksum(IPV4_PACKET, segment), True)
