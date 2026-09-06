import unittest
from dataclasses import FrozenInstanceError, replace
from typing import cast

from analysis import IPv4Packet, TCPDecodeError, TCPPacket, decode_tcp
from capture.packet_source import CaptureError


TCP_HEADER = bytes.fromhex("1234abcd0123456789abcdef5b55fedc13572468")
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


class TCPDecoderTests(unittest.TestCase):
    def test_minimal_header_decodes_all_fields_in_network_order(self) -> None:
        packet = decode_tcp(IPV4_PACKET)
        self.assertEqual(
            packet,
            TCPPacket(
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
                checksum=0x1357,
                urgent_pointer=0x2468,
                options=b"",
                payload=b"",
            ),
        )
        self.assertEqual(packet.header_length, 20)

    def test_each_control_flag_is_decoded_independently(self) -> None:
        flags = (
            ("ns", 0x0100),
            ("cwr", 0x0080),
            ("ece", 0x0040),
            ("urg", 0x0020),
            ("ack", 0x0010),
            ("psh", 0x0008),
            ("rst", 0x0004),
            ("syn", 0x0002),
            ("fin", 0x0001),
        )
        for active_name, mask in (("none", 0),) + flags:
            with self.subTest(flag=active_name):
                header = (
                    TCP_HEADER[:12]
                    + (0x5000 | mask).to_bytes(2, byteorder="big")
                    + TCP_HEADER[14:]
                )
                packet = decode_tcp(replace(IPV4_PACKET, payload=header))
                for name, _ in flags:
                    self.assertIs(getattr(packet, name), name == active_name)
                self.assertEqual(packet.reserved_bits, 0)
                self.assertEqual(packet.data_offset, 5)

    def test_binary_payload_and_ipv4_packet_are_preserved(self) -> None:
        payload = b"\x00\xff\x80\n\r\x00"
        raw_bytes = TCP_HEADER + payload
        ipv4 = replace(IPV4_PACKET, payload=raw_bytes, total_length=20 + len(raw_bytes))
        before = replace(ipv4)
        packet = decode_tcp(ipv4)
        self.assertEqual(packet.payload, payload)
        self.assertIsInstance(packet.payload, bytes)
        self.assertEqual(ipv4, before)
        self.assertIs(ipv4.payload, raw_bytes)
        self.assertEqual(raw_bytes, TCP_HEADER + payload)

    def test_options_are_preserved_and_excluded_from_payload(self) -> None:
        for data_offset in (6, 15):
            for payload in (b"", b"\x00\x81\xff"):
                with self.subTest(data_offset=data_offset, payload=payload):
                    options = bytes(range(data_offset * 4 - 20))
                    header = (
                        TCP_HEADER[:12]
                        + bytes([(data_offset << 4) | 0x0B])
                        + TCP_HEADER[13:]
                    )
                    raw_bytes = header + options + payload
                    ipv4 = replace(
                        IPV4_PACKET, payload=raw_bytes, total_length=20 + len(raw_bytes)
                    )
                    packet = decode_tcp(ipv4)
                    self.assertEqual(packet.data_offset, data_offset)
                    self.assertEqual(packet.header_length, data_offset * 4)
                    self.assertEqual(packet.options, options)
                    self.assertIsInstance(packet.options, bytes)
                    self.assertEqual(packet.payload, payload)
                    self.assertEqual(packet.reserved_bits, 5)
                    self.assertTrue(packet.ns)

    def test_malformed_headers_raise_tcp_errors(self) -> None:
        malformed = (
            (b"", "too short"),
            (b"\x00", "too short"),
            (TCP_HEADER[:19], "too short"),
            (TCP_HEADER[:12] + b"\x0b" + TCP_HEADER[13:], "data offset"),
            (TCP_HEADER[:12] + b"\x4b" + TCP_HEADER[13:], "data offset"),
            (TCP_HEADER[:12] + b"\x6b" + TCP_HEADER[13:], "header length exceeds"),
            (
                TCP_HEADER[:12] + b"\xfb" + TCP_HEADER[13:] + bytes(39),
                "header length exceeds",
            ),
        )
        for raw_bytes, message in malformed:
            with self.subTest(raw_bytes=raw_bytes):
                ipv4 = replace(
                    IPV4_PACKET, payload=raw_bytes, total_length=20 + len(raw_bytes)
                )
                with self.assertRaisesRegex(TCPDecodeError, message) as failure:
                    decode_tcp(ipv4)
                self.assertNotIsInstance(failure.exception, CaptureError)

    def test_other_ipv4_protocols_are_rejected(self) -> None:
        for protocol in (0, 1, 17, 255):
            with self.subTest(protocol=protocol):
                with self.assertRaisesRegex(TCPDecodeError, "protocol 6"):
                    decode_tcp(replace(IPV4_PACKET, protocol=protocol))

    def test_non_initial_fragments_are_rejected(self) -> None:
        for fragment_offset in (1, 8191):
            with self.subTest(fragment_offset=fragment_offset):
                with self.assertRaisesRegex(TCPDecodeError, "initial IPv4 fragment"):
                    decode_tcp(replace(IPV4_PACKET, fragment_offset=fragment_offset))

    def test_initial_fragment_with_more_fragments_can_be_decoded(self) -> None:
        packet = decode_tcp(replace(IPV4_PACKET, flags=1))
        self.assertEqual(packet, decode_tcp(IPV4_PACKET))

    def test_decoder_requires_ipv4_packet(self) -> None:
        for value in (None, TCP_HEADER):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    decode_tcp(cast(IPv4Packet, value))

    def test_packets_decode_independently_and_preserve_extreme_values(self) -> None:
        first = decode_tcp(IPV4_PACKET)
        header = bytes.fromhex("0000ffff00000000ffffffff5fffffff0000ffff")
        second = decode_tcp(replace(IPV4_PACKET, payload=header))
        self.assertEqual(first.sequence_number, 0x01234567)
        self.assertEqual(first.reserved_bits, 5)
        self.assertEqual(second.source_port, 0)
        self.assertEqual(second.destination_port, 65535)
        self.assertEqual(second.sequence_number, 0)
        self.assertEqual(second.acknowledgment_number, 0xFFFFFFFF)
        self.assertEqual(second.reserved_bits, 7)
        self.assertEqual(second.window_size, 65535)
        self.assertEqual(second.checksum, 0)
        self.assertEqual(second.urgent_pointer, 65535)
        for name in ("ns", "cwr", "ece", "urg", "ack", "psh", "rst", "syn", "fin"):
            self.assertIs(getattr(second, name), True)
        self.assertIsNot(first, second)


class TCPPacketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.packet = decode_tcp(IPV4_PACKET)

    def test_numeric_fields_reject_invalid_ranges_and_types(self) -> None:
        ranges = (
            ("source_port", 0, 65535),
            ("destination_port", 0, 65535),
            ("sequence_number", 0, 0xFFFFFFFF),
            ("acknowledgment_number", 0, 0xFFFFFFFF),
            ("data_offset", 5, 15),
            ("reserved_bits", 0, 7),
            ("window_size", 0, 65535),
            ("checksum", 0, 65535),
            ("urgent_pointer", 0, 65535),
        )
        for name, minimum, maximum in ranges:
            for value in (minimum - 1, maximum + 1):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(ValueError):
                        replace(self.packet, **{name: value})
            for value in (True, False, 5.0, "5", None):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.packet, **{name: value})

    def test_control_flags_require_booleans(self) -> None:
        for name in ("ns", "cwr", "ece", "urg", "ack", "psh", "rst", "syn", "fin"):
            for value in (0, 1, 1.0, "true", None):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.packet, **{name: value})

    def test_options_and_payload_require_immutable_bytes(self) -> None:
        for name in ("options", "payload"):
            for value in (bytearray(), memoryview(b""), "", None):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.packet, **{name: value})

    def test_options_length_must_match_data_offset(self) -> None:
        for changes in ({"options": bytes(4)}, {"data_offset": 6}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    replace(self.packet, **changes)

    def test_packet_and_derived_header_length_are_immutable(self) -> None:
        for name, value in (
            ("source_port", 0),
            ("sequence_number", 0),
            ("data_offset", 6),
            ("header_length", 24),
            ("reserved_bits", 0),
            ("syn", True),
            ("options", bytes(4)),
            ("payload", b"changed"),
        ):
            with self.subTest(field=name):
                with self.assertRaises(FrozenInstanceError):
                    setattr(self.packet, name, value)
                with self.assertRaises(FrozenInstanceError):
                    delattr(self.packet, name)
