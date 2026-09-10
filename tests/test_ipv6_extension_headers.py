import unittest
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import patch

import analysis
from analysis import (
    IPv6DecodeError,
    IPv6ExtensionHeader,
    IPv6ExtensionHeaderChain,
    IPv6Packet,
    decode_ipv6,
    validate_ipv6_extension_headers,
)
from analysis import ipv6_extension_headers
from tests.test_ipv6 import ipv6_frame, ipv6_header


def represented_packet():
    return decode_ipv6(ipv6_frame(ipv6_header(next_header=0, payload_length=16) + bytes(16)))


class IPv6ExtensionHeaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw_bytes = b"\x3c\x00\xff\x01\x02\x03\x04\x05"
        self.header = IPv6ExtensionHeader(0, 40, 8, self.raw_bytes, 60)

    def test_supplied_metadata_and_exact_raw_bytes_are_preserved(self) -> None:
        self.assertEqual(self.header.header_type, 0)
        self.assertEqual(self.header.offset, 40)
        self.assertEqual(self.header.declared_length, 8)
        self.assertIs(self.header.raw_bytes, self.raw_bytes)
        self.assertEqual(self.header.next_header, 60)

    def test_raw_protocol_identifiers_do_not_require_a_known_extension_type(self) -> None:
        for identifier in (0, 6, 17, 43, 44, 50, 51, 59, 60, 253, 254, 255):
            with self.subTest(identifier=identifier):
                header = replace(self.header, header_type=identifier, next_header=identifier)
                self.assertEqual(header.header_type, identifier)
                self.assertEqual(header.next_header, identifier)

    def test_unknown_length_and_next_header_are_explicitly_absent(self) -> None:
        header = IPv6ExtensionHeader(50, 40, None, b"\xff", None)
        self.assertIsNone(header.declared_length)
        self.assertIsNone(header.next_header)
        self.assertEqual(header.raw_bytes, b"\xff")

    def test_zero_and_large_offsets_and_lengths_are_preserved_as_supplied(self) -> None:
        for value in (0, 1, 39, 40, 65535, 65576):
            with self.subTest(value=value):
                header = replace(self.header, offset=value, declared_length=value)
                self.assertEqual(header.offset, value)
                self.assertEqual(header.declared_length, value)

    def test_declared_length_is_not_compared_with_observed_bytes(self) -> None:
        for length, raw_bytes in ((0, b"\xff"), (100, b""), (1, bytes(20))):
            with self.subTest(length=length, raw_bytes=raw_bytes):
                header = replace(self.header, declared_length=length, raw_bytes=raw_bytes)
                self.assertEqual(header.declared_length, length)
                self.assertIs(header.raw_bytes, raw_bytes)

    def test_raw_contents_do_not_derive_or_override_metadata(self) -> None:
        raw_bytes = b"\xff\xffopaque"
        header = IPv6ExtensionHeader(0, 40, 3, raw_bytes, 6)
        self.assertEqual(header.header_type, 0)
        self.assertEqual(header.declared_length, 3)
        self.assertEqual(header.next_header, 6)
        self.assertIs(header.raw_bytes, raw_bytes)

    def test_invalid_integer_types_are_rejected(self) -> None:
        for name in ("header_type", "offset", "declared_length", "next_header"):
            for value in (True, False, 1.0, "1", object()):
                with self.subTest(name=name, value=type(value)):
                    with self.assertRaises(TypeError):
                        replace(self.header, **{name: value})
        for name in ("header_type", "offset"):
            with self.subTest(name=name):
                with self.assertRaises(TypeError):
                    replace(self.header, **{name: None})

    def test_invalid_protocol_identifier_ranges_are_rejected(self) -> None:
        for name in ("header_type", "next_header"):
            for value in (-1, 256):
                with self.subTest(name=name, value=value):
                    with self.assertRaises(ValueError):
                        replace(self.header, **{name: value})

    def test_negative_offsets_and_lengths_are_rejected(self) -> None:
        for name in ("offset", "declared_length"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    replace(self.header, **{name: -1})

    def test_mutable_and_nonbyte_raw_data_are_rejected(self) -> None:
        for value in (bytearray(self.raw_bytes), memoryview(self.raw_bytes), list(self.raw_bytes), "bytes", None):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    replace(self.header, raw_bytes=value)

    def test_header_is_frozen_and_has_only_representation_fields(self) -> None:
        self.assertEqual(tuple(field.name for field in fields(self.header)), (
            "header_type", "offset", "declared_length", "raw_bytes", "next_header",
        ))
        for field in fields(self.header):
            with self.assertRaises(FrozenInstanceError):
                setattr(self.header, field.name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(self.header, field.name)
        with self.assertRaises(TypeError):
            self.header.raw_bytes[0] = 0

    def test_repeated_construction_has_deterministic_equality_and_hashing(self) -> None:
        equal = IPv6ExtensionHeader(0, 40, 8, bytes(bytearray(self.raw_bytes)), 60)
        self.assertEqual(self.header, equal)
        self.assertEqual(hash(self.header), hash(equal))
        self.assertEqual({self.header: "entry"}[equal], "entry")
        for changes in (
            {"header_type": 60}, {"offset": 48}, {"declared_length": None},
            {"raw_bytes": b"different"}, {"next_header": None},
        ):
            with self.subTest(changes=changes):
                self.assertNotEqual(self.header, replace(self.header, **changes))


class IPv6ExtensionHeaderChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.packet = represented_packet()
        self.first = IPv6ExtensionHeader(0, 40, 8, bytes(8), 60)
        self.second = IPv6ExtensionHeader(60, 48, 8, bytes(8), 6)
        self.headers = (self.first, self.second)

    def test_empty_chain_preserves_packet_without_claiming_no_extensions(self) -> None:
        chain = IPv6ExtensionHeaderChain(self.packet, ())
        self.assertIs(chain.packet, self.packet)
        self.assertEqual(chain.headers, ())
        self.assertEqual(chain.packet.next_header, 0)

    def test_order_entry_identity_and_next_header_relationship_are_preserved(self) -> None:
        chain = IPv6ExtensionHeaderChain(self.packet, self.headers)
        self.assertIs(chain.packet, self.packet)
        self.assertIs(chain.headers, self.headers)
        self.assertIs(chain.headers[0], self.first)
        self.assertIs(chain.headers[1], self.second)
        self.assertEqual(chain.headers[0].header_type, chain.packet.next_header)
        self.assertEqual(chain.headers[0].next_header, chain.headers[1].header_type)
        self.assertEqual(chain.headers[1].next_header, 6)
        self.assertEqual(tuple(header.offset for header in chain.headers), (40, 48))

    def test_chain_does_not_reorder_deduplicate_or_certify_supplied_links(self) -> None:
        headers = (self.second, self.first, self.first)
        chain = IPv6ExtensionHeaderChain(self.packet, headers)
        self.assertIs(chain.headers, headers)
        self.assertEqual(chain.packet.next_header, 0)
        self.assertEqual(chain.headers[0].header_type, 60)
        self.assertEqual(tuple(header.offset for header in chain.headers), (48, 40, 40))
        self.assertIs(chain.headers[1], chain.headers[2])

    def test_offsets_and_raw_bytes_are_not_validated_against_packet_payload(self) -> None:
        header = IPv6ExtensionHeader(253, 1000, 99, b"uninterpreted bytes", None)
        chain = IPv6ExtensionHeaderChain(self.packet, (header,))
        self.assertIs(chain.headers[0], header)
        self.assertIs(chain.packet.payload, self.packet.payload)

    def test_collection_must_be_an_exact_tuple(self) -> None:
        class TupleSubclass(tuple):
            pass

        for value in ([], list(self.headers), iter(self.headers), {self.first}, None, TupleSubclass(self.headers)):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    IPv6ExtensionHeaderChain(self.packet, value)

    def test_invalid_elements_and_subclasses_are_rejected(self) -> None:
        class HeaderSubclass(IPv6ExtensionHeader):
            pass

        subclass = HeaderSubclass(0, 40, 8, bytes(8), 60)
        for value in (None, 0, b"", {}, self.packet, subclass):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    IPv6ExtensionHeaderChain(self.packet, (self.first, value))

    def test_packet_must_be_the_exact_ipv6_model(self) -> None:
        class PacketSubclass(IPv6Packet):
            pass

        subclass = PacketSubclass(**vars(self.packet))
        for value in (None, b"", {}, self.first, subclass):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    IPv6ExtensionHeaderChain(value, self.headers)

    def test_caller_list_mutation_cannot_change_a_constructed_chain(self) -> None:
        caller_headers = list(self.headers)
        with self.assertRaises(TypeError):
            IPv6ExtensionHeaderChain(self.packet, caller_headers)
        chain = IPv6ExtensionHeaderChain(self.packet, tuple(caller_headers))
        caller_headers.reverse()
        caller_headers.clear()
        self.assertEqual(chain.headers, self.headers)
        self.assertIs(chain.headers[0], self.first)
        self.assertIs(chain.headers[1], self.second)

    def test_chain_and_retained_inputs_are_immutable(self) -> None:
        packet_before = replace(self.packet)
        chain = IPv6ExtensionHeaderChain(self.packet, self.headers)
        self.assertEqual(tuple(field.name for field in fields(chain)), ("packet", "headers"))
        for field in fields(chain):
            with self.assertRaises(FrozenInstanceError):
                setattr(chain, field.name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(chain, field.name)
        with self.assertRaises(TypeError):
            chain.headers[0] = self.second
        with self.assertRaises(FrozenInstanceError):
            chain.headers[0].offset = 48
        with self.assertRaises(FrozenInstanceError):
            chain.packet.next_header = 6
        self.assertEqual(self.packet, packet_before)
        self.assertIs(self.packet.payload, packet_before.payload)
        self.assertIs(chain.headers, self.headers)

    def test_equality_and_hashing_preserve_order_and_packet_context(self) -> None:
        first = IPv6ExtensionHeaderChain(self.packet, self.headers)
        equal = IPv6ExtensionHeaderChain(replace(self.packet), (replace(self.first), replace(self.second)))
        self.assertEqual(first, equal)
        self.assertEqual(hash(first), hash(equal))
        self.assertEqual(len({first, equal}), 1)
        reversed_chain = IPv6ExtensionHeaderChain(self.packet, tuple(reversed(self.headers)))
        self.assertNotEqual(first, reversed_chain)
        self.assertNotEqual(first, IPv6ExtensionHeaderChain(replace(self.packet, next_header=60), self.headers))

    def test_base_header_decoder_does_not_construct_representation(self) -> None:
        raw_bytes = ipv6_header(next_header=0, payload_length=1) + b"\xff"
        with patch.object(ipv6_extension_headers, "IPv6ExtensionHeader", side_effect=AssertionError("entry constructed")):
            with patch.object(ipv6_extension_headers, "IPv6ExtensionHeaderChain", side_effect=AssertionError("chain constructed")):
                packet = decode_ipv6(ipv6_frame(raw_bytes))
        self.assertEqual(packet.next_header, 0)
        self.assertEqual(packet.payload, b"\xff")
        self.assertEqual(tuple(field.name for field in fields(packet)), (
            "version", "traffic_class", "flow_label", "payload_length", "next_header",
            "hop_limit", "source_address", "destination_address", "payload",
        ))

    def test_public_exports_resolve(self) -> None:
        for name in ("IPv6ExtensionHeader", "IPv6ExtensionHeaderChain", "validate_ipv6_extension_headers"):
            self.assertIn(name, analysis.__all__)
            self.assertIs(getattr(analysis, name), getattr(ipv6_extension_headers, name))


class IPv6ExtensionHeaderValidationTests(unittest.TestCase):
    def test_all_unsupported_base_next_headers_terminate_without_reading_payload(self) -> None:
        for next_header in range(256):
            if next_header in (0, 43, 44, 60):
                continue
            for payload in (b"", b"\x00\xff", bytes.fromhex("3b00010203040506")):
                with self.subTest(next_header=next_header, payload=payload):
                    packet = decode_ipv6(ipv6_frame(ipv6_header(
                        next_header=next_header, payload_length=len(payload),
                    ) + payload))
                    chain = validate_ipv6_extension_headers(packet)
                    self.assertIs(chain.packet, packet)
                    self.assertEqual(chain.headers, ())
                    self.assertEqual(chain.terminating_next_header, next_header)

    def test_variable_headers_preserve_independently_declared_lengths_and_bytes(self) -> None:
        for header_type in (0, 43, 60):
            for encoded_length, expected_length in ((0, 8), (1, 16), (2, 24), (127, 1024), (255, 2048)):
                with self.subTest(header_type=header_type, encoded_length=encoded_length):
                    raw_header = bytes((6, encoded_length)) + b"\xa5" * (expected_length - 2)
                    packet = decode_ipv6(ipv6_frame(ipv6_header(
                        next_header=header_type, payload_length=expected_length,
                    ) + raw_header))
                    chain = validate_ipv6_extension_headers(packet)
                    self.assertIs(chain.packet, packet)
                    self.assertEqual(chain.headers, (
                        IPv6ExtensionHeader(header_type, 40, expected_length, raw_header, 6),
                    ))
                    self.assertEqual(chain.terminating_next_header, 6)
                    self.assertEqual(chain.headers[0].offset + chain.headers[0].declared_length, 40 + expected_length)

    def test_fragment_preserves_exactly_eight_bytes_with_opaque_remainder(self) -> None:
        for opaque_bytes in (bytes(7), b"\xff" * 7, bytes.fromhex("80010203040506")):
            with self.subTest(opaque_bytes=opaque_bytes):
                raw_header = b"\x06" + opaque_bytes
                payload = raw_header + b"\x00\xff"
                packet = decode_ipv6(ipv6_frame(ipv6_header(
                    next_header=44, payload_length=10,
                ) + payload))
                chain = validate_ipv6_extension_headers(packet)
                self.assertEqual(chain.headers, (IPv6ExtensionHeader(44, 40, 8, raw_header, 6),))
                self.assertEqual(chain.terminating_next_header, 6)
                self.assertEqual(packet.payload, payload)

    def test_mixed_lengths_and_next_header_links_define_exact_packet_offsets(self) -> None:
        hop_by_hop = bytes.fromhex("2b01000102030405060708090a0b0c0d")
        routing = bytes.fromhex("2c02000102030405060708090a0b0c0d0e0f101112131415")
        fragment = bytes.fromhex("3cffeeddccbbaa99")
        destination = bytes.fromhex("0600010203040506")
        payload = hop_by_hop + routing + fragment + destination + b"\x00\xff"
        packet = decode_ipv6(ipv6_frame(ipv6_header(next_header=0, payload_length=58) + payload))
        chain = validate_ipv6_extension_headers(packet)
        self.assertEqual(chain.headers, (
            IPv6ExtensionHeader(0, 40, 16, hop_by_hop, 43),
            IPv6ExtensionHeader(43, 56, 24, routing, 44),
            IPv6ExtensionHeader(44, 80, 8, fragment, 60),
            IPv6ExtensionHeader(60, 88, 8, destination, 6),
        ))
        self.assertIs(chain.packet, packet)
        self.assertEqual(chain.terminating_next_header, 6)
        self.assertEqual(packet.next_header, 0)

    def test_every_short_prefix_and_fragment_is_rejected(self) -> None:
        for header_type in (0, 43, 44, 60):
            for available in range(8):
                with self.subTest(header_type=header_type, available=available):
                    payload = bytes.fromhex("3b00010203040506")[:available]
                    packet = decode_ipv6(ipv6_frame(ipv6_header(
                        next_header=header_type, payload_length=available,
                    ) + payload))
                    with self.assertRaises(IPv6DecodeError):
                        validate_ipv6_extension_headers(packet)

    def test_variable_declared_extent_must_be_available_in_full(self) -> None:
        for header_type in (0, 43, 60):
            for encoded_length, expected_length in ((1, 16), (2, 24), (255, 2048)):
                for available in (2, 8, expected_length - 1):
                    with self.subTest(header_type=header_type, encoded_length=encoded_length, available=available):
                        payload = bytes((59, encoded_length)) + bytes(available - 2)
                        packet = decode_ipv6(ipv6_frame(ipv6_header(
                            next_header=header_type, payload_length=available,
                        ) + payload))
                        with self.assertRaisesRegex(IPv6DecodeError, "length exceeds available IPv6 payload"):
                            validate_ipv6_extension_headers(packet)

    def test_ethernet_trailing_bytes_cannot_supply_prefix_or_declared_extent(self) -> None:
        for header_type in (0, 43, 44, 60):
            raw_header = bytes.fromhex("3b00010203040506") if header_type == 44 else b"\x3b\x01" + bytes(14)
            for declared_payload_length in (0, 1, 7, len(raw_header) - 1):
                with self.subTest(header_type=header_type, declared_payload_length=declared_payload_length):
                    frame = ipv6_frame(ipv6_header(
                        next_header=header_type, payload_length=declared_payload_length,
                    ) + raw_header)
                    packet = decode_ipv6(frame)
                    self.assertEqual(len(packet.payload), declared_payload_length)
                    self.assertEqual(packet.payload, raw_header[:declared_payload_length])
                    with self.assertRaises(IPv6DecodeError):
                        validate_ipv6_extension_headers(packet)
                    self.assertEqual(frame.payload[40:], raw_header)

    def test_each_header_can_end_exactly_at_payload_boundary(self) -> None:
        raw_header = bytes.fromhex("3b00010203040506")
        for header_type in (0, 43, 44, 60):
            with self.subTest(header_type=header_type):
                packet = decode_ipv6(ipv6_frame(ipv6_header(
                    next_header=header_type, payload_length=8,
                ) + raw_header + b"\x00\xff"))
                chain = validate_ipv6_extension_headers(packet)
                self.assertEqual(chain.headers, (IPv6ExtensionHeader(header_type, 40, 8, raw_header, 59),))
                self.assertEqual(chain.terminating_next_header, 59)

    def test_every_unsupported_extension_next_header_terminates_before_trailing_bytes(self) -> None:
        for next_header in range(256):
            if next_header in (0, 43, 44, 60):
                continue
            with self.subTest(next_header=next_header):
                raw_header = bytes((next_header, 0)) + bytes(6)
                payload = raw_header + bytes.fromhex("0000010203040506") + b"\x00\xff"
                packet = decode_ipv6(ipv6_frame(ipv6_header(next_header=60, payload_length=18) + payload))
                chain = validate_ipv6_extension_headers(packet)
                self.assertEqual(chain.headers, (IPv6ExtensionHeader(60, 40, 8, raw_header, next_header),))
                self.assertEqual(chain.terminating_next_header, next_header)
                self.assertEqual(packet.payload, payload)

    def test_header_contents_are_not_scanned_for_embedded_headers(self) -> None:
        payload = bytes.fromhex("3c0100000000000000ff0000000000003b00010203040506")
        packet = decode_ipv6(ipv6_frame(ipv6_header(next_header=0, payload_length=24) + payload))
        chain = validate_ipv6_extension_headers(packet)
        self.assertEqual(chain.headers, (
            IPv6ExtensionHeader(0, 40, 16, payload[:16], 60),
            IPv6ExtensionHeader(60, 56, 8, payload[16:], 59),
        ))

    def test_truncated_first_header_is_not_skipped_for_later_header_bytes(self) -> None:
        payload = bytes.fromhex("3cff0000000000003b00010203040506")
        packet = decode_ipv6(ipv6_frame(ipv6_header(next_header=0, payload_length=16) + payload))
        with self.assertRaises(IPv6DecodeError):
            validate_ipv6_extension_headers(packet)

    def test_repeated_headers_keep_observed_order_without_restriction_or_deduplication(self) -> None:
        header_types = (60, 0, 43, 43, 44, 44, 60, 0)
        next_headers = (0, 43, 43, 44, 44, 60, 0, 59)
        raw_headers = tuple(bytes((next_header, 0)) + bytes((index,)) * 6 for index, next_header in enumerate(next_headers))
        packet = decode_ipv6(ipv6_frame(ipv6_header(next_header=60, payload_length=64) + b"".join(raw_headers)))
        chain = validate_ipv6_extension_headers(packet)
        self.assertEqual(tuple(header.header_type for header in chain.headers), header_types)
        self.assertEqual(tuple(header.next_header for header in chain.headers), next_headers)
        self.assertEqual(tuple(header.offset for header in chain.headers), (40, 48, 56, 64, 72, 80, 88, 96))
        self.assertEqual(tuple(header.raw_bytes for header in chain.headers), raw_headers)
        self.assertEqual(chain.terminating_next_header, 59)

    def test_maximum_payload_bounds_traversal_even_when_header_type_repeats(self) -> None:
        repeated = bytes.fromhex("0000010203040506")
        last = bytes.fromhex("3b00010203040506")
        payload = repeated * 8190 + last + bytes(7)
        packet = decode_ipv6(ipv6_frame(ipv6_header(next_header=0, payload_length=65535) + payload))
        chain = validate_ipv6_extension_headers(packet)
        self.assertEqual(len(chain.headers), 8191)
        self.assertEqual(tuple(header.offset for header in chain.headers), tuple(range(40, 65568, 8)))
        self.assertEqual(chain.headers[-1], IPv6ExtensionHeader(0, 65560, 8, last, 59))
        self.assertEqual(chain.terminating_next_header, 59)
        unterminated = replace(packet, payload=repeated * 8191 + bytes(7))
        with self.assertRaises(IPv6DecodeError):
            validate_ipv6_extension_headers(unterminated)

    def test_failed_later_header_never_constructs_or_returns_a_partial_chain(self) -> None:
        for header_type in (0, 43, 44, 60):
            for suffix in (b"", b"\x3b", b"\x3b\x00" + bytes(5)):
                with self.subTest(header_type=header_type, suffix=suffix):
                    payload = bytes((header_type, 0)) + bytes(6) + suffix
                    packet = decode_ipv6(ipv6_frame(ipv6_header(next_header=0, payload_length=len(payload)) + payload))
                    before = replace(packet)
                    with patch.object(ipv6_extension_headers, "IPv6ExtensionHeaderChain") as constructor:
                        with self.assertRaises(IPv6DecodeError):
                            validate_ipv6_extension_headers(packet)
                    constructor.assert_not_called()
                    self.assertEqual(packet, before)
                    self.assertIs(packet.payload, before.payload)

    def test_validation_is_deterministic_and_preserves_exact_packet_context(self) -> None:
        payload = bytes.fromhex("2b000102030405063b000708090a0b0c")
        packet = decode_ipv6(ipv6_frame(ipv6_header(
            next_header=0, payload_length=16, traffic_class=171, flow_label=74565, hop_limit=0,
        ) + payload))
        before = replace(packet)
        first = validate_ipv6_extension_headers(packet)
        validate_ipv6_extension_headers(decode_ipv6(ipv6_frame(ipv6_header())))
        second = validate_ipv6_extension_headers(packet)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertIs(first.packet, packet)
        self.assertIs(second.packet, packet)
        self.assertEqual(packet, before)
        self.assertIs(packet.payload, before.payload)
        self.assertIs(first.packet.source_address, before.source_address)
        self.assertIs(first.packet.destination_address, before.destination_address)

    def test_validator_requires_exact_ipv6_packet(self) -> None:
        class PacketSubclass(IPv6Packet):
            pass

        packet = represented_packet()
        for value in (None, b"", object(), ipv6_frame(ipv6_header()), PacketSubclass(**vars(packet))):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    validate_ipv6_extension_headers(value)

    def test_derived_termination_does_not_certify_manually_supplied_metadata(self) -> None:
        packet = represented_packet()
        self.assertEqual(IPv6ExtensionHeaderChain(packet, ()).terminating_next_header, 0)
        header = IPv6ExtensionHeader(50, 40, None, b"\xff", None)
        self.assertIsNone(IPv6ExtensionHeaderChain(packet, (header,)).terminating_next_header)


if __name__ == "__main__":
    unittest.main()
