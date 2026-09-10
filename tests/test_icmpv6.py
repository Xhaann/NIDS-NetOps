import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import patch

import analysis
from analysis import (
    ICMPv6Packet,
    IPv6DecodeError,
    IPv6ExtensionHeader,
    IPv6ExtensionHeaderChain,
    PacketAnalysis,
    PacketAnalysisError,
    PacketAnalysisFailureClassification,
    analyze_packet,
    analyze_packet_outcome,
    decode_ethernet,
    decode_icmpv6,
    decode_ipv6,
    validate_ipv6_extension_headers,
)
from analysis import icmpv6, packet_analysis
from tests.test_ipv6 import ipv6_frame, ipv6_header
from tests.test_ipv6_packet_analysis import ipv6_observation
from tests.test_packet_analysis_outcome import TCP_BYTES, UDP_BYTES, ICMP_BYTES, make_observation


def message_chain(payload, next_header=58):
    packet = decode_ipv6(ipv6_frame(ipv6_header(
        next_header=next_header, payload_length=len(payload),
    ) + payload))
    return validate_ipv6_extension_headers(packet)


class ICMPv6DecoderTests(unittest.TestCase):
    def test_literal_header_and_opaque_body_preserve_exact_context(self) -> None:
        raw_bytes = bytes.fromhex("81ab123400ff803a002c")
        chain = message_chain(raw_bytes)
        result = decode_icmpv6(chain)
        self.assertIs(result.extension_headers, chain)
        self.assertIs(result.packet, chain.packet)
        self.assertEqual(result.offset, 40)
        self.assertEqual(result.raw_bytes, raw_bytes)
        self.assertEqual((result.icmp_type, result.code, result.checksum), (129, 171, 4660))
        self.assertEqual(result.body, bytes.fromhex("00ff803a002c"))
        self.assertIs(type(result.raw_bytes), bytes)
        self.assertIs(type(result.body), bytes)

    def test_exactly_four_bytes_support_zero_length_body(self) -> None:
        result = decode_icmpv6(message_chain(bytes.fromhex("00ff0000")))
        self.assertEqual((result.icmp_type, result.code, result.checksum), (0, 255, 0))
        self.assertEqual(result.body, b"")
        self.assertEqual(result.raw_bytes, bytes.fromhex("00ff0000"))

    def test_one_byte_body_is_preserved(self) -> None:
        result = decode_icmpv6(message_chain(bytes.fromhex("ff00ffff80")))
        self.assertEqual(result.body, b"\x80")
        self.assertEqual((result.icmp_type, result.code, result.checksum), (255, 0, 65535))

    def test_all_type_values_and_protocol_local_classification(self) -> None:
        for icmp_type in range(256):
            with self.subTest(icmp_type=icmp_type):
                raw_bytes = bytes((icmp_type, 171, 18, 52))
                result = decode_icmpv6(message_chain(raw_bytes))
                self.assertEqual(result.icmp_type, icmp_type)
                self.assertEqual((result.code, result.checksum), (171, 4660))
                self.assertIs(result.is_error_message, icmp_type <= 127)
                self.assertIs(result.is_informational_message, icmp_type >= 128)
                self.assertEqual(result.raw_bytes, raw_bytes)

    def test_all_code_values_are_preserved_without_subtype_rules(self) -> None:
        for code in range(256):
            with self.subTest(code=code):
                result = decode_icmpv6(message_chain(bytes((128, code, 171, 205))))
                self.assertEqual((result.icmp_type, result.code, result.checksum), (128, code, 43981))
                self.assertEqual(result.body, b"")

    def test_checksum_is_observed_without_validation_or_normalization(self) -> None:
        for encoded, expected in (("0000", 0), ("0001", 1), ("0100", 256), ("1234", 4660), ("ffff", 65535)):
            with self.subTest(encoded=encoded):
                raw_bytes = bytes.fromhex("80ff" + encoded + "00ff")
                result = decode_icmpv6(message_chain(raw_bytes))
                self.assertEqual(result.checksum, expected)
                self.assertEqual(result.raw_bytes, raw_bytes)
                self.assertFalse(hasattr(result, "checksum_valid"))

    def test_maximum_declared_payload_preserves_large_arbitrary_body(self) -> None:
        body = (bytes(range(256)) * 256)[:65531]
        result = decode_icmpv6(message_chain(bytes.fromhex("ff001234") + body))
        self.assertEqual(result.packet.payload_length, 65535)
        self.assertEqual(result.raw_bytes, bytes.fromhex("ff001234") + body)
        self.assertEqual(result.body, body)
        self.assertEqual(result.offset, 40)

    def test_variable_extensions_locate_header_after_validated_extent(self) -> None:
        prefix = bytes.fromhex("3a01000102030405060708090a0b0c0d")
        message = bytes.fromhex("00ffabcd80")
        for next_header in (0, 43, 60):
            with self.subTest(next_header=next_header):
                chain = message_chain(prefix + message, next_header)
                result = decode_icmpv6(chain)
                self.assertEqual(result.offset, 56)
                self.assertEqual(result.offset, chain.headers[-1].offset + chain.headers[-1].declared_length)
                self.assertEqual(result.raw_bytes, message)
                self.assertEqual((result.icmp_type, result.code, result.checksum), (0, 255, 43981))
                self.assertIs(result.packet, chain.packet)

    def test_mixed_extension_lengths_and_whole_datagram_fragment(self) -> None:
        prefix = bytes.fromhex(
            "2b01000102030405060708090a0b0c0d"
            "3c00000000000000"
            "2c01000102030405060708090a0b0c0d"
            "3aff000612345678"
        )
        message = bytes.fromhex("81ff0102030405")
        chain = message_chain(prefix + message, 0)
        result = decode_icmpv6(chain)
        self.assertEqual(tuple(header.header_type for header in chain.headers), (0, 43, 60, 44))
        self.assertEqual(result.offset, 88)
        self.assertEqual(result.raw_bytes, message)
        self.assertEqual(result.body, bytes.fromhex("030405"))

    def test_whole_datagram_fragment_as_first_extension(self) -> None:
        fragment = bytes.fromhex("3aff000600000001")
        result = decode_icmpv6(message_chain(fragment + bytes.fromhex("80001234"), 44))
        self.assertEqual(result.offset, 48)
        self.assertEqual(result.raw_bytes, bytes.fromhex("80001234"))
        self.assertEqual(result.packet.next_header, 44)
        self.assertEqual(result.packet.payload[:8], fragment)

    def test_repeated_whole_datagram_headers_preserve_observed_chain(self) -> None:
        chain = message_chain(bytes.fromhex("2c000000000000013a0000000000000280001234"), 44)
        result = decode_icmpv6(chain)
        self.assertIs(result.extension_headers, chain)
        self.assertEqual(result.offset, 56)
        self.assertEqual(result.raw_bytes, bytes.fromhex("80001234"))

    def test_first_intermediate_and_final_fragments_are_not_decoded(self) -> None:
        for encoded in ("0001", "0008", "0009", "fff8", "ffff"):
            for message in (b"", bytes.fromhex("80001234")):
                with self.subTest(encoded=encoded, message=message):
                    fragment = bytes.fromhex("3a00" + encoded + "00000001")
                    with self.assertRaisesRegex(IPv6DecodeError, "whole-datagram"):
                        decode_icmpv6(message_chain(fragment + message, 44))

    def test_any_partial_fragment_in_repeated_chain_blocks_decoding(self) -> None:
        for prefix in (
            "2c000001000000013a00000000000002",
            "2c000000000000013a00000800000002",
        ):
            with self.subTest(prefix=prefix):
                with self.assertRaisesRegex(IPv6DecodeError, "whole-datagram"):
                    decode_icmpv6(message_chain(bytes.fromhex(prefix + "80001234"), 44))

    def test_zero_through_three_byte_headers_are_incomplete(self) -> None:
        for length in range(4):
            for prefix, next_header in ((b"", 58), (bytes.fromhex("3a00000000000000"), 60)):
                with self.subTest(length=length, next_header=next_header):
                    with self.assertRaisesRegex(IPv6DecodeError, "at least 4 bytes"):
                        decode_icmpv6(message_chain(prefix + bytes.fromhex("80ff1234")[:length], next_header))

    def test_wrong_terminal_protocol_and_no_next_header_are_rejected(self) -> None:
        for next_header in range(256):
            if next_header in (0, 43, 44, 58, 60):
                continue
            with self.subTest(next_header=next_header):
                with self.assertRaisesRegex(IPv6DecodeError, "terminal Next Header 58"):
                    decode_icmpv6(message_chain(bytes.fromhex("3a001234"), next_header))

    def test_no_scan_ahead_inside_extension_or_message_body(self) -> None:
        prefix = bytes.fromhex("3a013a00000000003a00000000000000")
        raw_bytes = bytes.fromhex("3b0012343aff000000000001")
        result = decode_icmpv6(message_chain(prefix + raw_bytes, 0))
        self.assertEqual(result.offset, 56)
        self.assertEqual(result.icmp_type, 59)
        self.assertEqual(result.body, raw_bytes[4:])

    def test_wrong_types_and_ipv4_context_are_rejected(self) -> None:
        chain = message_chain(bytes.fromhex("80000000"))
        ipv4 = analyze_packet(make_observation(6, TCP_BYTES)).ipv4

        class ChainSubclass(IPv6ExtensionHeaderChain):
            pass

        for value in (None, b"", bytearray(4), memoryview(bytes(4)), chain.packet, ipv4, (), [], ChainSubclass(chain.packet, chain.headers)):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    decode_icmpv6(value)

    def test_manually_constructed_invalid_chain_metadata_is_rejected(self) -> None:
        chain = message_chain(bytes.fromhex("3a0000000000000080001234"), 0)
        header = chain.headers[0]
        invalid = [replace(chain, headers=()), replace(chain, headers=(header, header))]
        for changes in (
            {"offset": 0}, {"offset": 48}, {"declared_length": None}, {"declared_length": 16},
            {"header_type": 60}, {"next_header": 6}, {"raw_bytes": bytes.fromhex("3a00000000000001")},
        ):
            invalid.append(replace(chain, headers=(replace(header, **changes),)))
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "validated IPv6 packet chain"):
                    decode_icmpv6(value)

    def test_manually_constructed_truncated_chain_uses_existing_validator(self) -> None:
        packet = decode_ipv6(ipv6_frame(ipv6_header(next_header=0, payload_length=1) + b"\x3a"))
        chain = IPv6ExtensionHeaderChain(packet, (IPv6ExtensionHeader(0, 40, 8, b"\x3a", 58),))
        with self.assertRaisesRegex(IPv6DecodeError, "extension header prefix"):
            decode_icmpv6(chain)

    def test_immutable_fields_properties_and_derived_construction(self) -> None:
        result = decode_icmpv6(message_chain(bytes.fromhex("80001234ff")))
        for name in tuple(entry.name for entry in fields(result)) + ("packet", "is_error_message", "is_informational_message"):
            with self.subTest(name=name):
                with self.assertRaises(FrozenInstanceError):
                    setattr(result, name, None)
                with self.assertRaises(FrozenInstanceError):
                    delattr(result, name)
        with self.assertRaises(TypeError):
            result.body[0] = 0
        with self.assertRaises(TypeError):
            ICMPv6Packet(result.extension_headers, raw_bytes=bytes(4))

    def test_determinism_equality_hashing_and_input_preservation(self) -> None:
        chain = message_chain(bytes.fromhex("80ab1234ff"))
        before = replace(chain.packet)
        first = decode_icmpv6(chain)
        decode_icmpv6(message_chain(bytes.fromhex("00ff0000")))
        second = decode_icmpv6(chain)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(len({first, second}), 1)
        self.assertIs(first.packet, chain.packet)
        self.assertEqual(chain.packet, before)
        self.assertIs(chain.packet.payload, before.payload)
        self.assertNotEqual(first, decode_icmpv6(message_chain(bytes.fromhex("80ab1234fe"))))
        self.assertNotEqual(first, decode_icmpv6(replace(chain, packet=replace(chain.packet, hop_limit=1))))

    def test_public_exports_resolve(self) -> None:
        for name in ("ICMPv6Packet", "decode_icmpv6"):
            self.assertIn(name, analysis.__all__)
            self.assertIs(getattr(analysis, name), getattr(icmpv6, name))


class ICMPv6PacketAnalysisTests(unittest.TestCase):
    def test_integration_retains_exact_decoder_models(self) -> None:
        observation = ipv6_observation(ipv6_header(next_header=58, payload_length=4) + bytes.fromhex("00ff0000"))
        ethernet = decode_ethernet(observation)
        packet = decode_ipv6(ethernet)
        chain = validate_ipv6_extension_headers(packet)
        message = decode_icmpv6(chain)
        with ExitStack() as stack:
            stack.enter_context(patch.object(packet_analysis, "decode_ethernet", return_value=ethernet))
            stack.enter_context(patch.object(packet_analysis, "decode_ipv6", return_value=packet))
            stack.enter_context(patch.object(packet_analysis, "validate_ipv6_extension_headers", return_value=chain))
            decoder = stack.enter_context(patch.object(packet_analysis, "decode_icmpv6", return_value=message))
            outcome = analyze_packet_outcome(observation)
        decoder.assert_called_once_with(chain)
        self.assertTrue(outcome.succeeded)
        self.assertIs(outcome.observation, observation)
        result = outcome.analysis
        self.assertIs(result.observation, observation)
        self.assertIs(result.ethernet, ethernet)
        self.assertIs(result.ipv6, packet)
        self.assertIs(result.ipv6_extension_headers, chain)
        self.assertIs(result.ipv6_icmpv6, message)
        self.assertIsNone(result.icmp_checksum_valid)
        self.assertIsNone(result.icmp)

    def test_supported_extension_paths_decode_at_exact_offsets(self) -> None:
        for next_header, prefix, expected_offset in (
            (58, b"", 40),
            (0, bytes.fromhex("3a00000000000000"), 48),
            (43, bytes.fromhex("3a010000000000000000000000000000"), 56),
            (60, bytes.fromhex("3a00000000000000"), 48),
            (44, bytes.fromhex("3aff000600000001"), 48),
            (44, bytes.fromhex("3c000000000000013a00000000000000"), 56),
        ):
            with self.subTest(next_header=next_header, prefix=prefix):
                raw_bytes = bytes.fromhex("80ffabcdff")
                payload = prefix + raw_bytes
                observation = ipv6_observation(ipv6_header(next_header=next_header, payload_length=len(payload)) + payload)
                outcome = analyze_packet_outcome(observation)
                self.assertTrue(outcome.succeeded)
                result = outcome.analysis
                self.assertEqual(result.ipv6_icmpv6.raw_bytes, raw_bytes)
                self.assertEqual(result.ipv6_icmpv6.offset, expected_offset)
                self.assertIs(result.ipv6_icmpv6.packet, result.ipv6)
                self.assertEqual(result, analyze_packet(observation))

    def test_partial_fragments_retain_ipv6_analysis_without_icmpv6_dispatch(self) -> None:
        for encoded in ("0001", "0008", "0009", "ffff"):
            for suffix in (b"", b"\x80", bytes.fromhex("80ff1234")):
                with self.subTest(encoded=encoded, suffix=suffix):
                    payload = bytes.fromhex("3a00" + encoded + "00000001") + suffix
                    observation = ipv6_observation(ipv6_header(next_header=44, payload_length=len(payload)) + payload)
                    with patch.object(packet_analysis, "decode_icmpv6", side_effect=AssertionError("partial fragment decoded")):
                        outcome = analyze_packet_outcome(observation)
                    self.assertTrue(outcome.succeeded)
                    self.assertIsNone(outcome.analysis.ipv6_icmpv6)
                    self.assertEqual(outcome.analysis.ipv6_extension_headers.terminating_next_header, 58)
                    self.assertEqual(outcome.analysis.ipv6.payload, payload)
                    self.assertIsNotNone(outcome.analysis.ipv6_fragmentation)

    def test_later_whole_header_cannot_override_earlier_partial_fragment(self) -> None:
        payload = bytes.fromhex("2c000008000000013a0000000000000280001234")
        result = analyze_packet(ipv6_observation(ipv6_header(next_header=44, payload_length=20) + payload))
        self.assertIsNone(result.ipv6_icmpv6)
        self.assertEqual(len(result.ipv6_fragmentation.headers), 2)

    def test_no_next_header_and_other_selectors_do_not_scan_payload(self) -> None:
        for next_header in (6, 17, 50, 51, 59, 253, 255):
            for prefix, base in ((b"", next_header), (bytes((next_header, 0)) + bytes(6), 0)):
                with self.subTest(next_header=next_header, base=base):
                    payload = prefix + bytes.fromhex("3a0080001234")
                    observation = ipv6_observation(ipv6_header(next_header=base, payload_length=len(payload)) + payload)
                    with patch.object(packet_analysis, "decode_icmpv6", side_effect=AssertionError("incorrect dispatch")):
                        outcome = analyze_packet_outcome(observation)
                    self.assertTrue(outcome.succeeded)
                    self.assertIsNone(outcome.analysis.ipv6_icmpv6)

    def test_short_icmpv6_headers_are_incomplete_without_partial_analysis(self) -> None:
        for length in range(4):
            for prefix, next_header in ((b"", 58), (bytes.fromhex("3a00000000000000"), 0), (bytes.fromhex("3a00000000000001"), 44)):
                with self.subTest(length=length, next_header=next_header):
                    payload = prefix + bytes.fromhex("80001234")[:length]
                    observation = ipv6_observation(ipv6_header(next_header=next_header, payload_length=len(payload)) + payload)
                    with self.assertRaisesRegex(IPv6DecodeError, "at least 4 bytes"):
                        analyze_packet(observation)
                    outcome = analyze_packet_outcome(observation)
                    self.assertFalse(outcome.succeeded)
                    self.assertIsNone(outcome.analysis)
                    self.assertIs(outcome.observation, observation)
                    self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)
                    self.assertEqual(outcome.failure_description, "ICMPv6 header is too short: expected at least 4 bytes")

    def test_ipv6_and_extension_truncation_remain_incomplete(self) -> None:
        for raw_bytes in (
            ipv6_header(next_header=58, payload_length=5) + bytes(4),
            ipv6_header(next_header=58)[:39],
            ipv6_header(next_header=0, payload_length=1) + b"\x3a",
            ipv6_header(next_header=0, payload_length=8) + bytes.fromhex("3a01000000000000"),
        ):
            with self.subTest(raw_bytes=raw_bytes):
                with patch.object(packet_analysis, "decode_icmpv6", side_effect=AssertionError("premature dispatch")):
                    outcome = analyze_packet_outcome(ipv6_observation(raw_bytes))
                self.assertIsNone(outcome.analysis)
                self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)

    def test_ethernet_trailing_bytes_cannot_supply_header_or_body(self) -> None:
        raw_bytes = bytes.fromhex("80ff1234abcd")
        for declared in range(7):
            with self.subTest(declared=declared):
                observation = ipv6_observation(ipv6_header(next_header=58, payload_length=declared) + raw_bytes + bytes(20))
                outcome = analyze_packet_outcome(observation)
                if declared < 4:
                    self.assertIsNone(outcome.analysis)
                    self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)
                else:
                    self.assertTrue(outcome.succeeded)
                    self.assertEqual(outcome.analysis.ipv6_icmpv6.raw_bytes, raw_bytes[:declared])
                    self.assertEqual(outcome.analysis.ipv6_icmpv6.body, raw_bytes[4:declared])

    def test_checksum_values_never_dispatch_existing_checksum_validators(self) -> None:
        for raw_bytes in (bytes.fromhex("80000000"), bytes.fromhex("8000ffff")):
            with ExitStack() as stack:
                for name in ("validate_icmp_checksum", "validate_tcp_checksum", "validate_udp_checksum", "validate_ipv4_checksum"):
                    stack.enter_context(patch.object(packet_analysis, name, side_effect=AssertionError(name)))
                outcome = analyze_packet_outcome(ipv6_observation(ipv6_header(next_header=58, payload_length=4) + raw_bytes))
            self.assertTrue(outcome.succeeded)
            self.assertEqual(outcome.analysis.ipv6_icmpv6.raw_bytes, raw_bytes)
            self.assertIsNone(outcome.analysis.icmp_checksum_valid)

    def test_ipv4_and_existing_positional_fields_remain_unchanged(self) -> None:
        expected = (
            "observation", "ethernet", "ipv4", "tcp", "udp", "icmp", "ipv4_checksum_valid",
            "tcp_checksum_valid", "udp_checksum_valid", "icmp_checksum_valid", "ipv6",
            "ipv6_extension_headers", "ipv6_fragmentation", "ipv6_icmpv6",
        )
        self.assertEqual(tuple(entry.name for entry in fields(PacketAnalysis)), expected)
        for protocol, payload in ((6, TCP_BYTES), (17, UDP_BYTES), (1, ICMP_BYTES), (253, b"")):
            with self.subTest(protocol=protocol):
                with patch.object(packet_analysis, "decode_icmpv6", side_effect=AssertionError("IPv4 dispatch")):
                    outcome = analyze_packet_outcome(make_observation(protocol, payload))
                self.assertTrue(outcome.succeeded)
                result = outcome.analysis
                self.assertIsNone(result.ipv6_icmpv6)
                self.assertEqual(PacketAnalysis(*(getattr(result, name) for name in expected[:-1])), result)

    def test_direct_analysis_requires_exact_icmpv6_chain_and_packet(self) -> None:
        result = analyze_packet(ipv6_observation(ipv6_header(next_header=58, payload_length=4) + bytes.fromhex("80000000")))
        for chain in (None, replace(result.ipv6_extension_headers)):
            with self.subTest(chain=chain):
                with self.assertRaisesRegex(PacketAnalysisError, "exact extension-header chain"):
                    replace(result, ipv6_extension_headers=chain)
        with self.assertRaises(PacketAnalysisError):
            replace(result, ipv6=replace(result.ipv6))
        for value in (bytes(4), (), result.ipv6, result.ipv6_extension_headers):
            with self.subTest(value=type(value)):
                with self.assertRaises(TypeError):
                    replace(result, ipv6_icmpv6=value)

    def test_internal_exceptions_propagate_without_failure_conversion(self) -> None:
        observation = ipv6_observation(ipv6_header(next_header=58, payload_length=4) + bytes.fromhex("80000000"))
        for error in (ValueError("bad chain"), RuntimeError("internal"), IndexError("internal offset"), TypeError("wrong type"), IPv6DecodeError("unknown internal failure")):
            with self.subTest(error=type(error)):
                with patch.object(packet_analysis, "decode_icmpv6", side_effect=error):
                    with self.assertRaises(type(error)) as raised:
                        analyze_packet_outcome(observation)
                self.assertIs(raised.exception, error)


if __name__ == "__main__":
    unittest.main()
