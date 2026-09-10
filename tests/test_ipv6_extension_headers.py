import unittest
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import patch

import analysis
from analysis import (
    IPv6ExtensionHeader,
    IPv6ExtensionHeaderChain,
    IPv6Packet,
    analyze_packet,
    decode_ipv6,
)
from analysis import ipv6_extension_headers
from tests.test_ipv6 import ipv6_frame, ipv6_header
from tests.test_ipv6_packet_analysis import ipv6_observation


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

    def test_decoder_and_packet_analysis_do_not_construct_representation(self) -> None:
        raw_bytes = ipv6_header(next_header=0, payload_length=1) + b"\xff"
        with patch.object(ipv6_extension_headers, "IPv6ExtensionHeader", side_effect=AssertionError("entry constructed")):
            with patch.object(ipv6_extension_headers, "IPv6ExtensionHeaderChain", side_effect=AssertionError("chain constructed")):
                packet = decode_ipv6(ipv6_frame(raw_bytes))
                result = analyze_packet(ipv6_observation(raw_bytes))
        self.assertEqual(result.ipv6, packet)
        self.assertEqual(packet.next_header, 0)
        self.assertEqual(packet.payload, b"\xff")
        self.assertEqual(tuple(field.name for field in fields(packet)), (
            "version", "traffic_class", "flow_label", "payload_length", "next_header",
            "hop_limit", "source_address", "destination_address", "payload",
        ))

    def test_public_exports_resolve(self) -> None:
        for name in ("IPv6ExtensionHeader", "IPv6ExtensionHeaderChain"):
            self.assertIn(name, analysis.__all__)
            self.assertIs(getattr(analysis, name), getattr(ipv6_extension_headers, name))


if __name__ == "__main__":
    unittest.main()
