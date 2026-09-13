import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import patch

import analysis
from analysis import (
    IPv6DecodeError,
    IPv6ExtensionHeader,
    IPv6ExtensionHeaderChain,
    IPv6FragmentHeader,
    IPv6Fragmentation,
    PacketAnalysis,
    PacketAnalysisError,
    PacketAnalysisFailureClassification,
    analyze_ipv6_fragmentation,
    analyze_packet,
    analyze_packet_outcome,
    decode_ethernet,
    decode_ipv6,
    validate_ipv6_extension_headers,
)
from analysis import ipv6_fragmentation, packet_analysis
from tests.test_ipv6 import ipv6_frame, ipv6_header
from tests.test_ipv6_packet_analysis import ipv6_observation
from tests.test_packet_analysis_outcome import TCP_BYTES, UDP_BYTES, ICMP_BYTES, make_observation


def fragment_chain(raw_bytes, next_header=44):
    packet = decode_ipv6(ipv6_frame(ipv6_header(
        next_header=next_header, payload_length=len(raw_bytes),
    ) + raw_bytes))
    return validate_ipv6_extension_headers(packet)


class IPv6FragmentHeaderTests(unittest.TestCase):
    def test_literal_vectors_extract_every_wire_field(self) -> None:
        vectors = (
            ("0600000000000000", (6, 0, 0, 0, False, 0)),
            ("1100000100000001", (17, 0, 0, 0, True, 1)),
            ("3a00000800000001", (58, 0, 1, 0, False, 1)),
            ("3b000009ffffffff", (59, 0, 1, 0, True, 4294967295)),
            ("fdffffff12345678", (253, 255, 8191, 3, True, 305419896)),
            ("ffa5fffeffffffff", (255, 165, 8191, 3, False, 4294967295)),
            ("065a000200000000", (6, 90, 0, 1, False, 0)),
            ("06c3000400000001", (6, 195, 0, 2, False, 1)),
            ("0600800501020304", (6, 0, 4096, 2, True, 16909060)),
            ("0600000080000000", (6, 0, 0, 0, False, 2147483648)),
        )
        for literal, expected in vectors:
            with self.subTest(literal=literal):
                raw_bytes = bytes.fromhex(literal)
                chain = fragment_chain(raw_bytes)
                result = analyze_ipv6_fragmentation(chain)
                self.assertEqual(len(result.headers), 1)
                header = result.headers[0]
                self.assertEqual((
                    header.next_header, header.reserved, header.fragment_offset,
                    header.reserved_bits, header.more_fragments, header.identification,
                ), expected)
                self.assertIs(type(header.more_fragments), bool)
                self.assertIs(header.extension_header, chain.headers[0])
                self.assertEqual(header.extension_header.raw_bytes, raw_bytes)
                self.assertIs(header.extension_header.raw_bytes, chain.headers[0].raw_bytes)
                self.assertIs(result.extension_headers, chain)
                self.assertIs(result.packet, chain.packet)

    def test_each_offset_and_flag_bit_is_independent(self) -> None:
        vectors = (
            ("0001", 0, 0, True), ("0002", 0, 1, False), ("0004", 0, 2, False),
            ("0008", 1, 0, False), ("0010", 2, 0, False), ("0020", 4, 0, False),
            ("0040", 8, 0, False), ("0080", 16, 0, False), ("0100", 32, 0, False),
            ("0200", 64, 0, False), ("0400", 128, 0, False), ("0800", 256, 0, False),
            ("1000", 512, 0, False), ("2000", 1024, 0, False),
            ("4000", 2048, 0, False), ("8000", 4096, 0, False),
        )
        for literal, offset, reserved_bits, more_fragments in vectors:
            with self.subTest(literal=literal):
                raw_bytes = bytes.fromhex("06a5" + literal + "01020304")
                header = analyze_ipv6_fragmentation(fragment_chain(raw_bytes)).headers[0]
                self.assertEqual(header.fragment_offset, offset)
                self.assertEqual(header.reserved_bits, reserved_bits)
                self.assertIs(header.more_fragments, more_fragments)
                self.assertEqual(header.reserved, 165)
                self.assertEqual(header.identification, 16909060)

    def test_position_predicates_describe_only_local_offset_and_m_flag(self) -> None:
        vectors = (
            ("0600000000000001", (True, False, False, True, False)),
            ("0600000100000001", (False, True, False, False, False)),
            ("0600000800000001", (False, False, True, True, False)),
            ("0600000900000001", (False, False, True, False, True)),
        )
        for literal, expected in vectors:
            with self.subTest(literal=literal):
                header = analyze_ipv6_fragmentation(fragment_chain(bytes.fromhex(literal))).headers[0]
                self.assertEqual((
                    header.is_whole_datagram, header.is_first_fragment, header.is_non_first_fragment,
                    header.is_last_fragment, header.is_intermediate_fragment,
                ), expected)

    def test_all_reserved_byte_values_are_preserved(self) -> None:
        for reserved in range(256):
            with self.subTest(reserved=reserved):
                raw_bytes = b"\x3b" + bytes((reserved,)) + bytes.fromhex("ffff01020304")
                header = analyze_ipv6_fragmentation(fragment_chain(raw_bytes)).headers[0]
                self.assertEqual(header.reserved, reserved)
                self.assertEqual(header.reserved_bits, 3)
                self.assertEqual(header.fragment_offset, 8191)
                self.assertTrue(header.more_fragments)

    def test_direct_view_requires_exact_type_and_eight_byte_extent(self) -> None:
        extension = fragment_chain(bytes.fromhex("0600000000000000")).headers[0]

        class ExtensionSubclass(IPv6ExtensionHeader):
            pass

        for value in (None, bytes(8), bytearray(8), memoryview(bytes(8)), object(), ExtensionSubclass(**vars(extension))):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    IPv6FragmentHeader(value)
        for length in tuple(range(8)) + (9, 16, 2048):
            with self.subTest(length=length):
                with self.assertRaisesRegex(ValueError, "exactly 8 bytes"):
                    IPv6FragmentHeader(replace(extension, raw_bytes=bytes(length)))

    def test_direct_view_rejects_wrong_type_length_and_next_header_metadata(self) -> None:
        extension = fragment_chain(bytes.fromhex("0600000000000000")).headers[0]
        for changes in (
            {"header_type": 0}, {"header_type": 43}, {"header_type": 60},
            {"declared_length": None}, {"declared_length": 0}, {"declared_length": 16},
            {"next_header": None}, {"next_header": 59},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    IPv6FragmentHeader(replace(extension, **changes))

    def test_models_and_semantic_properties_are_immutable(self) -> None:
        result = analyze_ipv6_fragmentation(fragment_chain(bytes.fromhex("06ffffff01020304")))
        header = result.headers[0]
        for model in (result, header):
            names = [entry.name for entry in fields(model)]
            names += [name for name, member in vars(type(model)).items() if isinstance(member, property)]
            for name in names:
                with self.subTest(model=type(model), name=name):
                    with self.assertRaises(FrozenInstanceError):
                        setattr(model, name, None)
                    with self.assertRaises(FrozenInstanceError):
                        delattr(model, name)
        with self.assertRaises(TypeError):
            result.headers[0] = header
        with self.assertRaises(TypeError):
            header.extension_header.raw_bytes[0] = 59
        with self.assertRaises(TypeError):
            IPv6Fragmentation(result.extension_headers, [])

    def test_equality_and_hashing_retain_bytes_position_and_packet_context(self) -> None:
        raw_bytes = bytes.fromhex("06ffffff01020304")
        first = analyze_ipv6_fragmentation(fragment_chain(raw_bytes))
        second = analyze_ipv6_fragmentation(fragment_chain(raw_bytes))
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(len({first.headers[0], second.headers[0]}), 1)
        for index in range(8):
            changed = bytearray(raw_bytes)
            changed[index] ^= 1
            different = analyze_ipv6_fragmentation(fragment_chain(bytes(changed)))
            self.assertNotEqual(first.headers[0], different.headers[0])
        changed_chain = replace(first.extension_headers, packet=replace(first.packet, hop_limit=1))
        self.assertNotEqual(first, analyze_ipv6_fragmentation(changed_chain))


class IPv6FragmentationTests(unittest.TestCase):
    def test_fragment_after_each_supported_variable_header_retains_its_offset(self) -> None:
        fragment = bytes.fromhex("0600000901020304")
        for header_type in (0, 43, 60):
            with self.subTest(header_type=header_type):
                prefix = bytes.fromhex("2c01000102030405060708090a0b0c0d")
                chain = fragment_chain(prefix + fragment, header_type)
                result = analyze_ipv6_fragmentation(chain)
                self.assertEqual(len(result.headers), 1)
                self.assertIs(result.headers[0].extension_header, chain.headers[1])
                self.assertEqual(result.headers[0].extension_header.offset, 56)
                self.assertEqual(result.headers[0].fragment_offset, 1)
                self.assertEqual(result.headers[0].identification, 16909060)

    def test_non_initial_fragment_stops_before_supported_extension_selector(self) -> None:
        for following_type in (0, 43, 60):
            with self.subTest(following_type=following_type):
                fragment = bytes((following_type,)) + bytes.fromhex("a5000901020304")
                following = bytes.fromhex("3b00000000000000")
                chain = fragment_chain(fragment + following)
                result = analyze_ipv6_fragmentation(chain)
                self.assertIs(result.extension_headers, chain)
                self.assertEqual(tuple(header.header_type for header in chain.headers), (44,))
                self.assertEqual(result.headers[0].next_header, following_type)
                self.assertEqual(chain.terminating_next_header, following_type)

    def test_repeated_fragment_headers_remain_separate_in_observed_order(self) -> None:
        raw_bytes = bytes.fromhex("2c000001000000013c000008000000013b00000000000000")
        chain = fragment_chain(raw_bytes)
        result = analyze_ipv6_fragmentation(chain)
        self.assertEqual(len(result.headers), 2)
        self.assertEqual(tuple(header.extension_header.offset for header in result.headers), (40, 48))
        self.assertEqual(tuple(header.fragment_offset for header in result.headers), (0, 1))
        self.assertEqual(tuple(header.identification for header in result.headers), (1, 1))
        self.assertIs(result.headers[0].extension_header, chain.headers[0])
        self.assertIs(result.headers[1].extension_header, chain.headers[1])
        self.assertEqual(len(chain.headers), 2)
        self.assertEqual(chain.terminating_next_header, 60)

    def test_empty_fragment_collection_preserves_non_fragmented_packet(self) -> None:
        for base_next_header, payload in ((6, b""), (59, bytes(8)), (253, bytes(8)), (0, bytes.fromhex("3b00000000000000"))):
            with self.subTest(base_next_header=base_next_header):
                chain = fragment_chain(payload, base_next_header)
                result = analyze_ipv6_fragmentation(chain)
                self.assertEqual(result.headers, ())
                self.assertIs(result.extension_headers, chain)
                self.assertIs(result.packet, chain.packet)

    def test_manual_chains_cannot_bypass_the_existing_validator(self) -> None:
        chain = fragment_chain(bytes.fromhex("0600000901020304"))
        extension = chain.headers[0]
        invalid_chains = [replace(chain, headers=()), replace(chain, headers=(extension, extension))]
        for changes in (
            {"offset": 0}, {"offset": 48}, {"header_type": 43}, {"declared_length": 16},
            {"raw_bytes": bytes.fromhex("0600000901020305")}, {"next_header": 59},
        ):
            invalid_chains.append(replace(chain, headers=(replace(extension, **changes),)))
        for invalid in invalid_chains:
            with self.subTest(invalid=invalid):
                with patch.object(ipv6_fragmentation, "IPv6FragmentHeader") as construct:
                    with self.assertRaisesRegex(ValueError, "validated IPv6 packet chain"):
                        analyze_ipv6_fragmentation(invalid)
                construct.assert_not_called()

    def test_truncated_packet_is_rejected_before_semantic_model_construction(self) -> None:
        for length in range(8):
            with self.subTest(length=length):
                packet = decode_ipv6(ipv6_frame(ipv6_header(next_header=44, payload_length=length) + bytes(length)))
                unvalidated = IPv6ExtensionHeaderChain(packet, ())
                with patch.object(ipv6_fragmentation, "IPv6FragmentHeader") as construct:
                    with self.assertRaises(IPv6DecodeError):
                        analyze_ipv6_fragmentation(unvalidated)
                construct.assert_not_called()

    def test_wrong_chain_types_and_subclasses_are_rejected(self) -> None:
        chain = fragment_chain(bytes.fromhex("0600000000000000"))

        class ChainSubclass(IPv6ExtensionHeaderChain):
            pass

        for value in (None, bytes(8), [], (), chain.packet, chain.headers[0], ChainSubclass(chain.packet, chain.headers)):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    analyze_ipv6_fragmentation(value)

    def test_analysis_is_deterministic_without_mutating_retained_inputs(self) -> None:
        chain = fragment_chain(bytes.fromhex("06ffffff01020304"))
        packet_before = replace(chain.packet)
        chain_before = replace(chain)
        first = analyze_ipv6_fragmentation(chain)
        analyze_ipv6_fragmentation(fragment_chain(bytes.fromhex("3b00000000000000")))
        second = analyze_ipv6_fragmentation(chain)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(chain, chain_before)
        self.assertEqual(chain.packet, packet_before)
        self.assertIs(first.packet, chain.packet)
        self.assertIs(chain.packet.payload, packet_before.payload)
        self.assertIs(chain.headers, chain_before.headers)

    def test_maximum_repeated_chain_is_validated_once_for_semantic_analysis(self) -> None:
        chain = fragment_chain(bytes.fromhex("2c00000101020304") * 8190 + bytes.fromhex("3b00000801020304"))
        with patch.object(ipv6_fragmentation, "validate_ipv6_extension_headers", wraps=validate_ipv6_extension_headers) as validate:
            result = analyze_ipv6_fragmentation(chain)
        validate.assert_called_once_with(chain.packet)
        self.assertEqual(len(result.headers), 8191)
        self.assertIs(result.headers[-1].extension_header, chain.headers[-1])
        self.assertEqual(result.headers[-1].extension_header.offset, 65560)

    def test_public_exports_resolve(self) -> None:
        for name in ("IPv6FragmentHeader", "IPv6Fragmentation", "analyze_ipv6_fragmentation"):
            self.assertIn(name, analysis.__all__)
            self.assertIs(getattr(analysis, name), getattr(ipv6_fragmentation, name))


class IPv6FragmentationPacketAnalysisTests(unittest.TestCase):
    def test_integration_preserves_exact_models_and_observation(self) -> None:
        raw_bytes = ipv6_header(next_header=44, payload_length=8) + bytes.fromhex("06ffffff01020304")
        observation = ipv6_observation(raw_bytes)
        ethernet = decode_ethernet(observation)
        packet = decode_ipv6(ethernet)
        chain = validate_ipv6_extension_headers(packet)
        fragmentation = analyze_ipv6_fragmentation(chain)
        with ExitStack() as stack:
            stack.enter_context(patch.object(packet_analysis, "decode_ethernet", return_value=ethernet))
            stack.enter_context(patch.object(packet_analysis, "decode_ipv6", return_value=packet))
            stack.enter_context(patch.object(packet_analysis, "validate_ipv6_extension_headers", return_value=chain))
            analyze = stack.enter_context(patch.object(packet_analysis, "analyze_ipv6_fragmentation", return_value=fragmentation))
            outcome = analyze_packet_outcome(observation)
        analyze.assert_called_once_with(chain)
        self.assertTrue(outcome.succeeded)
        self.assertIsNone(outcome.failure_classification)
        self.assertIsNone(outcome.failure_description)
        self.assertIs(outcome.observation, observation)
        result = outcome.analysis
        self.assertIs(result.observation, observation)
        self.assertIs(result.ethernet, ethernet)
        self.assertIs(result.ipv6, packet)
        self.assertIs(result.ipv6_extension_headers, chain)
        self.assertIs(result.ipv6_fragmentation, fragmentation)
        self.assertIs(fragmentation.packet, packet)

    def test_every_terminating_next_header_preserves_semantics_without_protocol_decoding(self) -> None:
        for next_header in range(256):
            if next_header in (0, 43, 44, 60):
                continue
            with self.subTest(next_header=next_header):
                raw_fragment = bytes((next_header,)) + bytes.fromhex("ff000901020304")
                observation = ipv6_observation(ipv6_header(next_header=44, payload_length=10) + raw_fragment + b"\x2c\xff")
                with ExitStack() as stack:
                    for name in ("decode_ipv4", "decode_tcp", "decode_udp", "decode_icmp", "validate_ipv4_checksum", "validate_tcp_checksum", "validate_udp_checksum", "validate_icmp_checksum"):
                        stack.enter_context(patch.object(packet_analysis, name, side_effect=AssertionError(name)))
                    outcome = analyze_packet_outcome(observation)
                self.assertTrue(outcome.succeeded)
                result = outcome.analysis
                self.assertEqual(result.ipv6_fragmentation.headers[0].next_header, next_header)
                self.assertEqual(result.ipv6_extension_headers.terminating_next_header, next_header)
                self.assertEqual(result.ipv6.payload, raw_fragment + b"\x2c\xff")
                self.assertEqual(len(result.ipv6_fragmentation.headers), 1)
                for name in ("ipv4", "tcp", "udp", "icmp", "ipv4_checksum_valid", "tcp_checksum_valid", "udp_checksum_valid", "icmp_checksum_valid"):
                    self.assertIsNone(getattr(result, name))

    def test_whole_datagram_header_is_preserved_without_synthesizing_packet(self) -> None:
        raw_bytes = ipv6_header(next_header=44, payload_length=8 + len(TCP_BYTES)) + bytes.fromhex("0600000000000001") + TCP_BYTES
        observation = ipv6_observation(raw_bytes)
        result = analyze_packet(observation)
        self.assertTrue(result.ipv6_fragmentation.headers[0].is_whole_datagram)
        self.assertEqual(result.ipv6.next_header, 44)
        self.assertEqual(result.ipv6.payload, raw_bytes[40:])
        self.assertEqual(result.ipv6_extension_headers.headers[0].next_header, 6)
        self.assertEqual(result.observation.raw_bytes[14:], raw_bytes)
        self.assertEqual(analyze_packet(observation), result)
        self.assertEqual(analyze_packet_outcome(observation).analysis, result)

    def test_truncation_and_later_failure_publish_no_partial_analysis(self) -> None:
        fragment = bytes.fromhex("3b00000000000001")
        for length in range(8):
            for prefix in (b"", bytes.fromhex("2c00000100000001")):
                with self.subTest(length=length, prefix=prefix):
                    payload = prefix + fragment[:length]
                    observation = ipv6_observation(ipv6_header(next_header=44, payload_length=len(payload)) + payload)
                    with patch.object(packet_analysis, "analyze_ipv6_fragmentation") as analyze:
                        outcome = analyze_packet_outcome(observation)
                    analyze.assert_not_called()
                    self.assertIsNone(outcome.analysis)
                    self.assertIs(outcome.observation, observation)
                    self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)
        payload = bytes.fromhex("3c00000100000001") + b"\x3b"
        outcome = analyze_packet_outcome(ipv6_observation(ipv6_header(next_header=44, payload_length=9) + payload))
        self.assertIsNone(outcome.analysis)
        self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)

    def test_ethernet_trailing_bytes_cannot_supply_or_change_fragment_semantics(self) -> None:
        fragment = bytes.fromhex("06ffffff01020304")
        for declared in range(9):
            with self.subTest(declared=declared):
                observation = ipv6_observation(ipv6_header(next_header=44, payload_length=declared) + fragment + bytes(20))
                outcome = analyze_packet_outcome(observation)
                if declared < 8:
                    self.assertIsNone(outcome.analysis)
                    self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)
                else:
                    self.assertTrue(outcome.succeeded)
                    header = outcome.analysis.ipv6_fragmentation.headers[0]
                    self.assertEqual(header.extension_header.raw_bytes, fragment)
                    self.assertEqual(header.identification, 16909060)
                    self.assertEqual(outcome.analysis.ipv6.payload, fragment)

    def test_non_fragmented_ipv6_keeps_fragmentation_absent_and_payload_unchanged(self) -> None:
        for next_header, payload in ((6, TCP_BYTES), (59, bytes.fromhex("2c00000000000000")), (253, b"\x2c\xff"), (0, bytes.fromhex("3b00000000000000"))):
            with self.subTest(next_header=next_header):
                observation = ipv6_observation(ipv6_header(next_header=next_header, payload_length=len(payload)) + payload)
                outcome = analyze_packet_outcome(observation)
                self.assertTrue(outcome.succeeded)
                self.assertIsNone(outcome.analysis.ipv6_fragmentation)
                self.assertEqual(outcome.analysis.ipv6.payload, payload)

    def test_ipv4_and_existing_positional_construction_are_unchanged(self) -> None:
        for protocol, payload in ((6, TCP_BYTES), (17, UDP_BYTES), (1, ICMP_BYTES), (253, b"")):
            with self.subTest(protocol=protocol):
                observation = make_observation(protocol, payload)
                with patch.object(packet_analysis, "analyze_ipv6_fragmentation", side_effect=AssertionError("IPv4 fragmentation dispatch")):
                    outcome = analyze_packet_outcome(observation)
                self.assertTrue(outcome.succeeded)
                result = outcome.analysis
                self.assertIsNone(result.ipv6_fragmentation)
                prior_arguments = tuple(getattr(result, entry.name) for entry in fields(result) if entry.name not in ("ipv6_fragmentation", "ipv6_icmpv6", "ipv6_tcp", "ipv6_udp"))
                self.assertEqual(PacketAnalysis(*prior_arguments), result)
        self.assertEqual(fields(PacketAnalysis)[12].name, "ipv6_fragmentation")

    def test_direct_packet_analysis_requires_exact_retained_chain(self) -> None:
        observation = ipv6_observation(ipv6_header(next_header=44, payload_length=8) + bytes.fromhex("3b00000100000001"))
        result = analyze_packet(observation)
        for chain in (None, replace(result.ipv6_extension_headers)):
            with self.subTest(chain=chain):
                with self.assertRaisesRegex(PacketAnalysisError, "exact extension-header chain"):
                    replace(result, ipv6_extension_headers=chain)
        for value in ((), [], result.ipv6, result.ipv6_extension_headers):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    replace(result, ipv6_fragmentation=value)
        with self.assertRaises(PacketAnalysisError):
            replace(result, ipv6=replace(result.ipv6))
        prior = replace(result, ipv6_fragmentation=None)
        self.assertIs(prior.ipv6_extension_headers, result.ipv6_extension_headers)

    def test_unexpected_internal_errors_propagate_without_packet_classification(self) -> None:
        observation = ipv6_observation(ipv6_header(next_header=44, payload_length=8) + bytes.fromhex("0600000000000001"))
        for error in (ValueError("chain mismatch"), TypeError("wrong model"), IndexError("internal offset"), RuntimeError("unexpected"), IPv6DecodeError("unrecognized semantic failure")):
            with self.subTest(error=type(error)):
                with patch.object(packet_analysis, "analyze_ipv6_fragmentation", side_effect=error):
                    with self.assertRaises(type(error)) as raised:
                        analyze_packet_outcome(observation)
                self.assertIs(raised.exception, error)


if __name__ == "__main__":
    unittest.main()
