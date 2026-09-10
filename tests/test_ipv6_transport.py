import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from struct import pack
from unittest.mock import patch

from analysis import (
    FlowIdentityError,
    FlowObservationWindowManager,
    FlowTracker,
    IPv6Fragmentation,
    PacketAnalysis,
    PacketAnalysisError,
    PacketAnalysisFailureClassification,
    TCPDecodeError,
    TCPPacket,
    UDPDecodeError,
    UDPPacket,
    analyze_ipv6_fragmentation,
    analyze_packet,
    analyze_packet_outcome,
    decode_ipv6,
    decode_tcp,
    decode_udp,
    flow_identity_from_packet,
    validate_ipv6_extension_headers,
)
from analysis import ipv6_fragmentation, packet_analysis
from tests.test_ipv6 import ipv6_frame, ipv6_header
from tests.test_ipv6_packet_analysis import ipv6_observation
from tests.test_packet_analysis import TCP_BYTES, UDP_BYTES, make_observation
from tests.test_tcp import TCP_HEADER
from tests.test_udp import UDP_HEADER


PROTOCOLS = ((6, "ipv6_tcp", TCP_HEADER, decode_tcp, TCPDecodeError),
             (17, "ipv6_udp", UDP_HEADER, decode_udp, UDPDecodeError))


def observation_for(protocol, payload, prefix=b"", base=None, declared=None, trailing=b""):
    payload = prefix + payload
    return ipv6_observation(ipv6_header(
        next_header=protocol if base is None else base,
        payload_length=len(payload) if declared is None else declared,
    ) + payload + trailing)


def context_for(protocol, payload, prefix=b"", base=None):
    observation = observation_for(protocol, payload, prefix, base)
    packet = decode_ipv6(ipv6_frame(observation.raw_bytes[14:]))
    return analyze_ipv6_fragmentation(validate_ipv6_extension_headers(packet))


def fragment_header(protocol, offset=0, more=False, identification=1):
    return pack("!BBHI", protocol, 0, (offset << 3) | int(more), identification)


class IPv6TCPTests(unittest.TestCase):
    def test_literal_header_preserves_every_tcp_field(self):
        context = context_for(6, TCP_HEADER)
        result = decode_tcp(packet=context)
        self.assertEqual(result, TCPPacket(
            source_port=0x1234, destination_port=0xABCD,
            sequence_number=0x01234567, acknowledgment_number=0x89ABCDEF,
            data_offset=5, reserved_bits=5, ns=True, cwr=False, ece=True,
            urg=False, ack=True, psh=False, rst=True, syn=False, fin=True,
            window_size=0xFEDC, checksum=0x1357, urgent_pointer=0x2468,
            options=b"", payload=b"",
        ))
        self.assertEqual(context.packet.payload, TCP_HEADER)
        self.assertEqual(result.header_length, 20)

    def test_options_payload_and_exact_header_bytes_after_extensions(self):
        for data_offset in (6, 15):
            with self.subTest(data_offset=data_offset):
                options = bytes(range(data_offset * 4 - 20))
                payload = b"\x00\xff\x80\r\n"
                header = TCP_HEADER[:12] + bytes(((data_offset << 4) | 11,)) + TCP_HEADER[13:]
                raw = header + options + payload
                context = context_for(6, raw, bytes.fromhex("060006113a0000ff"), 43)
                result = decode_tcp(context)
                self.assertEqual(result.options, options)
                self.assertEqual(result.payload, payload)
                self.assertEqual(result.data_offset, data_offset)
                self.assertEqual(context.packet.payload[8:8 + result.header_length], header + options)
                reconstructed = pack(
                    "!HHIIHHHH", result.source_port, result.destination_port,
                    result.sequence_number, result.acknowledgment_number,
                    (data_offset << 12) | 0xB55, result.window_size,
                    result.checksum, result.urgent_pointer,
                ) + result.options
                self.assertEqual(reconstructed, raw[:result.header_length])

    def test_each_tcp_flag_is_preserved(self):
        flags = ("fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr", "ns")
        for bit, name in enumerate(flags):
            with self.subTest(flag=name):
                raw = TCP_HEADER[:12] + (0x5000 | (1 << bit)).to_bytes(2, "big") + TCP_HEADER[14:]
                result = decode_tcp(context_for(6, raw))
                self.assertEqual(result.reserved_bits, 0)
                for field in flags:
                    self.assertIs(getattr(result, field), field == name)

    def test_incomplete_options_are_not_a_complete_tcp_header(self):
        raw = TCP_HEADER[:12] + b"\x6b" + TCP_HEADER[13:] + bytes(3)
        with self.assertRaisesRegex(TCPDecodeError, "TCP header length exceeds available IPv6 payload"):
            decode_tcp(context_for(6, raw))
        outcome = analyze_packet_outcome(observation_for(6, raw))
        self.assertIsNone(outcome.analysis)
        self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)

    def test_invalid_data_offset_is_structural_failure(self):
        for data_offset in range(5):
            with self.subTest(data_offset=data_offset):
                raw = TCP_HEADER[:12] + bytes((data_offset << 4,)) + TCP_HEADER[13:]
                outcome = analyze_packet_outcome(observation_for(6, raw))
                self.assertIsNone(outcome.analysis)
                self.assertEqual(outcome.failure_description, "TCP data offset must be at least 5")
                self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.STRUCTURAL_FAILURE)


class IPv6UDPTests(unittest.TestCase):
    def test_literal_header_preserves_all_udp_fields(self):
        context = context_for(17, UDP_HEADER)
        result = decode_udp(packet=context)
        self.assertEqual(result, UDPPacket(0x1234, 0xABCD, 8, 0x1357, b""))
        self.assertEqual(pack("!HHHH", result.source_port, result.destination_port,
                              result.length, result.checksum), UDP_HEADER)
        self.assertEqual(context.packet.payload, UDP_HEADER)

    def test_udp_declared_length_bounds_payload_and_preserves_excess(self):
        payload = b"\x00\xff\x80\r\n"
        header = UDP_HEADER[:4] + (8 + len(payload)).to_bytes(2, "big") + UDP_HEADER[6:]
        context = context_for(17, header + payload + b"excess", bytes.fromhex("110006113a0000ff"), 60)
        result = decode_udp(context)
        self.assertEqual(result, UDPPacket(0x1234, 0xABCD, 13, 0x1357, payload))
        self.assertEqual(context.packet.payload[8:16], header)
        self.assertEqual(context.packet.payload[8 + result.length:], b"excess")

    def test_maximum_ipv6_udp_length_is_preserved(self):
        payload = bytes(65527)
        result = decode_udp(context_for(17, UDP_HEADER[:4] + b"\xff\xff" + UDP_HEADER[6:] + payload))
        self.assertEqual(result.length, 65535)
        self.assertEqual(result.payload, payload)

    def test_udp_length_below_eight_is_structural_failure(self):
        for length in range(8):
            with self.subTest(length=length):
                raw = UDP_HEADER[:4] + length.to_bytes(2, "big") + UDP_HEADER[6:]
                outcome = analyze_packet_outcome(observation_for(17, raw))
                self.assertIsNone(outcome.analysis)
                self.assertEqual(outcome.failure_description, "UDP length must be at least 8 bytes")
                self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.STRUCTURAL_FAILURE)

    def test_udp_length_exceeding_upper_layer_bytes_is_incomplete(self):
        raw = UDP_HEADER[:4] + b"\x00\x09" + UDP_HEADER[6:]
        with self.assertRaisesRegex(UDPDecodeError, "UDP length exceeds available IPv6 payload"):
            decode_udp(context_for(17, raw))
        outcome = analyze_packet_outcome(observation_for(17, raw, trailing=b"\xff"))
        self.assertIsNone(outcome.analysis)
        self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)
        self.assertEqual(outcome.failure_description, "UDP length exceeds available IPv6 payload")


class IPv6TransportIntegrationTests(unittest.TestCase):
    def test_supported_extension_combinations_and_exact_offsets(self):
        for protocol, name, raw, decoder, _ in PROTOCOLS:
            for header_types in ((), (0,), (43,), (60,), (0, 43, 60), (0, 60, 43, 60)):
                with self.subTest(protocol=protocol, header_types=header_types):
                    prefix = b""
                    next_headers = header_types[1:] + (protocol,)
                    for index, next_header in enumerate(next_headers if header_types else ()):
                        prefix += bytes((next_header, 1)) + bytes((index + 32,)) * 14
                    base = header_types[0] if header_types else protocol
                    observation = observation_for(protocol, raw, prefix, base)
                    result = analyze_packet(observation)
                    transport = getattr(result, name)
                    self.assertEqual(transport.source_port, 0x1234)
                    self.assertEqual(transport.destination_port, 0xABCD)
                    self.assertEqual(transport.payload, b"")
                    chain = result.ipv6_extension_headers
                    self.assertEqual(chain.terminating_next_header, protocol)
                    self.assertEqual(tuple(header.offset for header in chain.headers),
                                     tuple(40 + 16 * i for i in range(len(header_types))))
                    offset = 40 if not chain.headers else chain.headers[-1].offset + chain.headers[-1].declared_length
                    self.assertEqual(offset, 40 + len(prefix))
                    self.assertEqual(observation.raw_bytes[14 + offset:], raw)
                    self.assertEqual(result.ipv6.payload[offset - 40:], raw)
                    self.assertEqual(transport, decoder(analyze_ipv6_fragmentation(chain)))
                    self.assertIs(result.observation, observation)
                    self.assertIs(chain.packet, result.ipv6)
                    self.assertIsNone(result.ipv6_fragmentation)
                    self.assertIsNone(result.tcp)
                    self.assertIsNone(result.udp)

    def test_transport_decoders_do_not_repeat_extension_traversal(self):
        for protocol, _, raw, decoder, _ in PROTOCOLS:
            context = context_for(protocol, raw, bytes((protocol, 0)) + bytes(6), 43)
            with patch.object(ipv6_fragmentation, "validate_ipv6_extension_headers", side_effect=AssertionError("repeated traversal")):
                self.assertEqual(decoder(context).source_port, 0x1234)

    def test_packet_dispatch_reuses_exact_fragmentation_context_and_decoder_result(self):
        for protocol, name, raw, decoder, _ in PROTOCOLS:
            for prefix, base in ((b"", protocol), (fragment_header(protocol), 44)):
                with self.subTest(protocol=protocol, base=base):
                    observation = observation_for(protocol, raw, prefix, base)
                    contexts = []
                    decoded = []

                    def decode(context):
                        contexts.append(context)
                        decoded.append(decoder(context))
                        return decoded[-1]

                    with patch.object(packet_analysis, decoder.__name__, side_effect=decode) as decode_call:
                        result = analyze_packet(observation)
                    decode_call.assert_called_once()
                    self.assertIs(contexts[0].extension_headers, result.ipv6_extension_headers)
                    self.assertIs(getattr(result, name), decoded[0])
                    if prefix:
                        self.assertIs(contexts[0], result.ipv6_fragmentation)
                    else:
                        self.assertEqual(contexts[0].headers, ())

    def test_every_short_transport_header_is_incomplete_without_partial_analysis(self):
        for protocol, _, raw, _, error in PROTOCOLS:
            for length in range(len(raw)):
                with self.subTest(protocol=protocol, length=length):
                    observation = observation_for(protocol, raw[:length], bytes((protocol, 0)) + bytes(6), 0)
                    with self.assertRaises(error):
                        analyze_packet(observation)
                    outcome = analyze_packet_outcome(observation)
                    self.assertIsNone(outcome.analysis)
                    self.assertIs(outcome.observation, observation)
                    self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)

    def test_declared_ipv6_payload_excludes_ethernet_trailing_header_bytes(self):
        for protocol, _, raw, _, _ in PROTOCOLS:
            for prefix, base in ((b"", protocol), (bytes((protocol, 0)) + bytes(6), 60)):
                for available in range(len(raw)):
                    with self.subTest(protocol=protocol, base=base, available=available):
                        observation = observation_for(protocol, raw, prefix, base, len(prefix) + available, bytes(100))
                        outcome = analyze_packet_outcome(replace(observation, original_length=10000))
                        self.assertIsNone(outcome.analysis)
                        self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)

    def test_ethernet_trailing_bytes_never_become_transport_payload(self):
        for protocol, name, raw, _, _ in PROTOCOLS:
            result = analyze_packet(observation_for(protocol, raw, trailing=b"\x00\xffextra"))
            self.assertEqual(getattr(result, name).payload, b"")
            self.assertEqual(result.ipv6.payload, raw)
            self.assertEqual(result.ethernet.payload[40 + len(raw):], b"\x00\xffextra")

    def test_truncated_ipv6_payload_and_extension_never_dispatch_transport(self):
        for protocol, _, raw, _, _ in PROTOCOLS:
            observations = (
                observation_for(protocol, raw, declared=len(raw) + 1),
                observation_for(protocol, b"\x06", base=0),
                observation_for(protocol, bytes((protocol, 255)) + raw, base=43),
            )
            for observation in observations:
                with ExitStack() as stack:
                    for name in ("decode_tcp", "decode_udp"):
                        stack.enter_context(patch.object(packet_analysis, name, side_effect=AssertionError("premature dispatch")))
                    outcome = analyze_packet_outcome(observation)
                self.assertIsNone(outcome.analysis)
                self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)

    def test_invalid_leading_transport_bytes_do_not_scan_ahead(self):
        for protocol, _, raw, _, _ in PROTOCOLS:
            outcome = analyze_packet_outcome(observation_for(protocol, bytes(20) + raw))
            self.assertIsNone(outcome.analysis)
            self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.STRUCTURAL_FAILURE)

    def test_no_next_header_and_unsupported_protocols_do_not_scan_payload(self):
        for protocol in (1, 50, 51, 59, 253, 255):
            for prefix, base in ((b"", protocol), (bytes((protocol, 0)) + bytes(6), 43)):
                with self.subTest(protocol=protocol, base=base):
                    with ExitStack() as stack:
                        for name in ("decode_tcp", "decode_udp", "decode_icmpv6"):
                            stack.enter_context(patch.object(packet_analysis, name, side_effect=AssertionError("scan ahead")))
                        result = analyze_packet(observation_for(protocol, TCP_HEADER + UDP_HEADER, prefix, base))
                    self.assertEqual(result.ipv6_extension_headers.terminating_next_header, protocol)
                    self.assertIsNone(result.ipv6_tcp)
                    self.assertIsNone(result.ipv6_udp)

    def test_checksum_fields_are_preserved_without_validation(self):
        for protocol, name, raw, _, _ in PROTOCOLS:
            checksum_offset = 16 if protocol == 6 else 6
            for checksum in (0, 65535):
                with self.subTest(protocol=protocol, checksum=checksum):
                    raw = raw[:checksum_offset] + checksum.to_bytes(2, "big") + raw[checksum_offset + 2:]
                    with ExitStack() as stack:
                        for validator in ("validate_tcp_checksum", "validate_udp_checksum", "validate_ipv4_checksum", "validate_icmp_checksum"):
                            stack.enter_context(patch.object(packet_analysis, validator, side_effect=AssertionError(validator)))
                        outcome = analyze_packet_outcome(observation_for(protocol, raw))
                    self.assertTrue(outcome.succeeded)
                    self.assertEqual(getattr(outcome.analysis, name).checksum, checksum)
                    self.assertIsNone(outcome.analysis.tcp_checksum_valid)
                    self.assertIsNone(outcome.analysis.udp_checksum_valid)

    def test_direct_decoders_reject_wrong_protocol_and_unvalidated_context(self):
        for protocol, _, raw, decoder, error in PROTOCOLS:
            for wrong in (6, 17, 58, 59, 253):
                if wrong != protocol:
                    with self.assertRaisesRegex(error, "terminal IPv6 Next Header"):
                        decoder(context_for(wrong, raw))
            context = context_for(protocol, raw)
            for value in (None, raw, context.packet, context.extension_headers):
                with self.assertRaises(TypeError):
                    decoder(value)
            chain = context_for(protocol, raw, bytes((protocol, 0)) + bytes(6), 0).extension_headers
            with self.assertRaisesRegex(ValueError, "validated IPv6 packet chain"):
                IPv6Fragmentation(replace(chain, headers=()))

    def test_determinism_immutability_and_exact_observation_timestamp(self):
        for protocol, name, raw, decoder, _ in PROTOCOLS:
            observation = observation_for(protocol, raw)
            before = replace(observation)
            first = analyze_packet(observation)
            self.assertEqual(first, analyze_packet(observation))
            self.assertEqual(analyze_packet_outcome(observation), analyze_packet_outcome(observation))
            context = context_for(protocol, raw)
            self.assertEqual(decoder(context), decoder(context))
            self.assertEqual(observation, before)
            self.assertIs(first.observation.captured_at, observation.captured_at)
            transport = getattr(first, name)
            self.assertIs(type(transport.payload), bytes)
            for field in fields(transport):
                with self.assertRaises(FrozenInstanceError):
                    setattr(transport, field.name, None)


class IPv6TransportFragmentTests(unittest.TestCase):
    def test_first_and_whole_fragments_decode_complete_transport(self):
        for protocol, name, raw, decoder, _ in PROTOCOLS:
            for more in (False, True):
                with self.subTest(protocol=protocol, more=more):
                    prefix = fragment_header(protocol, more=more)
                    result = analyze_packet(observation_for(protocol, raw, prefix, 44))
                    fragment = result.ipv6_fragmentation.headers[0]
                    self.assertEqual(fragment.fragment_offset, 0)
                    self.assertIs(fragment.more_fragments, more)
                    self.assertEqual(getattr(result, name), decoder(context_for(protocol, raw)))
                    self.assertEqual(result.ipv6.payload[:8], prefix)

    def test_fragment_then_destination_options_uses_terminal_offset(self):
        for protocol, name, raw, _, _ in PROTOCOLS:
            prefix = fragment_header(60, more=True) + bytes((protocol, 0)) + bytes(6)
            result = analyze_packet(observation_for(protocol, raw, prefix, 44))
            self.assertEqual(result.ipv6_extension_headers.headers[-1].offset, 48)
            self.assertEqual(result.observation.raw_bytes[14 + 56:], raw)
            self.assertEqual(getattr(result, name).source_port, 0x1234)

    def test_non_first_fragments_never_decode_even_with_complete_looking_headers(self):
        for protocol, name, raw, decoder, error in PROTOCOLS:
            for offset in (1, 8191):
                for more in (False, True):
                    for payload in (b"", raw):
                        with self.subTest(protocol=protocol, offset=offset, more=more, payload=payload):
                            prefix = fragment_header(protocol, offset, more)
                            observation = observation_for(protocol, payload, prefix, 44)
                            with ExitStack() as stack:
                                for target in ("decode_tcp", "decode_udp"):
                                    stack.enter_context(patch.object(packet_analysis, target, side_effect=AssertionError("non-first fragment")))
                                outcome = analyze_packet_outcome(observation)
                            self.assertTrue(outcome.succeeded)
                            self.assertIsNone(outcome.analysis.ipv6_tcp)
                            self.assertIsNone(outcome.analysis.ipv6_udp)
                            self.assertEqual(outcome.analysis.ipv6.payload, prefix + payload)
                            self.assertEqual(outcome.analysis.ipv6_fragmentation.headers[0].fragment_offset, offset)
                            with self.assertRaisesRegex(error, "initial IPv6 fragment"):
                                decoder(outcome.analysis.ipv6_fragmentation)

    def test_later_initial_fragment_header_cannot_override_non_first_fragment(self):
        for protocol, name, raw, _, _ in PROTOCOLS:
            prefix = fragment_header(44, 1) + fragment_header(protocol)
            result = analyze_packet(observation_for(protocol, raw, prefix, 44))
            self.assertIsNone(getattr(result, name))
            self.assertEqual(len(result.ipv6_fragmentation.headers), 2)

    def test_incomplete_first_fragments_are_not_reassembled_or_correlated(self):
        for protocol, name, raw, _, _ in PROTOCOLS:
            first = observation_for(protocol, raw[:4], fragment_header(protocol, more=True), 44)
            last = observation_for(protocol, raw[4:], fragment_header(protocol, 1), 44)
            before = analyze_packet_outcome(first)
            self.assertIsNone(before.analysis)
            self.assertIs(before.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)
            later = analyze_packet(last)
            self.assertIsNone(getattr(later, name))
            self.assertEqual(analyze_packet_outcome(first), before)
            self.assertEqual(analyze_packet(last), later)

    def test_first_udp_fragment_still_requires_complete_declared_datagram(self):
        raw = UDP_HEADER[:4] + b"\x00\x10" + UDP_HEADER[6:]
        outcome = analyze_packet_outcome(observation_for(17, raw, fragment_header(17, more=True), 44))
        self.assertIsNone(outcome.analysis)
        self.assertEqual(outcome.failure_description, "UDP length exceeds available IPv6 payload")
        self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)

    def test_first_tcp_fragment_requires_options_and_retains_only_local_payload(self):
        header = TCP_HEADER[:12] + b"\x6b" + TCP_HEADER[13:]
        prefix = fragment_header(6, more=True)
        for options in (b"", bytes(3)):
            outcome = analyze_packet_outcome(observation_for(6, header + options, prefix, 44))
            self.assertIsNone(outcome.analysis)
            self.assertEqual(outcome.failure_description, "TCP header length exceeds available IPv6 payload")
            self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)
        result = analyze_packet(observation_for(6, header + b"\x00\xff\x01\x80local", prefix, 44))
        self.assertEqual(result.ipv6_tcp.options, b"\x00\xff\x01\x80")
        self.assertEqual(result.ipv6_tcp.payload, b"local")
        self.assertTrue(result.ipv6_fragmentation.headers[0].more_fragments)


class IPv6TransportContractTests(unittest.TestCase):
    def test_old_positional_fields_are_unchanged_and_new_fields_are_appended(self):
        old_names = (
            "observation", "ethernet", "ipv4", "tcp", "udp", "icmp",
            "ipv4_checksum_valid", "tcp_checksum_valid", "udp_checksum_valid", "icmp_checksum_valid",
            "ipv6", "ipv6_extension_headers", "ipv6_fragmentation", "ipv6_icmpv6",
        )
        self.assertEqual(tuple(field.name for field in fields(PacketAnalysis)), old_names + ("ipv6_tcp", "ipv6_udp"))
        for protocol, payload in ((6, TCP_BYTES), (17, UDP_BYTES)):
            result = analyze_packet(make_observation(protocol, payload))
            self.assertEqual(PacketAnalysis(*(getattr(result, name) for name in old_names)), result)
            self.assertIsNone(result.ipv6_tcp)
            self.assertIsNone(result.ipv6_udp)
            self.assertIs(result.tcp_checksum_valid if protocol == 6 else result.udp_checksum_valid, True)
        for protocol, _, raw, _, _ in PROTOCOLS:
            result = analyze_packet(observation_for(protocol, raw))
            self.assertEqual(PacketAnalysis(*(getattr(result, field.name) for field in fields(result))), result)

    def test_ipv6_transport_rejects_missing_family_chain_and_wrong_models(self):
        for protocol, name, raw, _, _ in PROTOCOLS:
            result = analyze_packet(observation_for(protocol, raw))
            for changes in ({"ipv6": None}, {"ipv6_extension_headers": None},
                            {"ipv6": None, "ipv6_extension_headers": None}):
                with self.assertRaises(PacketAnalysisError):
                    replace(result, **changes)
            for value in (raw, object(), bytearray(raw)):
                with self.assertRaises(TypeError):
                    replace(result, **{name: value})
            ipv4 = analyze_packet(make_observation(6, TCP_BYTES))
            with self.assertRaises(PacketAnalysisError):
                replace(ipv4, **{name: getattr(result, name)})
            for field in ("ipv4", "tcp", "ipv4_checksum_valid", "tcp_checksum_valid"):
                with self.assertRaises(PacketAnalysisError):
                    replace(result, **{field: getattr(ipv4, field)})

    def test_ipv6_transport_requires_matching_protocol_and_fragment_safety(self):
        tcp = decode_tcp(context_for(6, TCP_HEADER))
        udp = decode_udp(context_for(17, UDP_HEADER))
        result = analyze_packet(observation_for(6, TCP_HEADER))
        with self.assertRaises(PacketAnalysisError):
            replace(result, ipv6_udp=udp)
        with self.assertRaises(PacketAnalysisError):
            replace(result, ipv6_tcp=None, ipv6_udp=udp)
        result = analyze_packet(observation_for(6, TCP_HEADER, fragment_header(6, 1), 44))
        with self.assertRaises(PacketAnalysisError):
            replace(result, ipv6_tcp=tcp)
        result = analyze_packet(observation_for(6, TCP_HEADER, fragment_header(6), 44))
        with self.assertRaises(PacketAnalysisError):
            replace(result, ipv6_fragmentation=None)

    def test_icmpv6_path_and_fragment_gate_are_unchanged(self):
        for more, expected in ((False, bytes.fromhex("80001234")), (True, None)):
            with ExitStack() as stack:
                for name in ("decode_tcp", "decode_udp"):
                    stack.enter_context(patch.object(packet_analysis, name, side_effect=AssertionError("ICMPv6 transport dispatch")))
                result = analyze_packet(observation_for(58, bytes.fromhex("80001234"), fragment_header(58, more=more), 44))
            self.assertIsNone(result.ipv6_tcp)
            self.assertIsNone(result.ipv6_udp)
            self.assertEqual(None if result.ipv6_icmpv6 is None else result.ipv6_icmpv6.raw_bytes, expected)
            if not more:
                self.assertEqual(result.ipv6_icmpv6.offset, 48)

    def test_flow_admission_without_transport_remains_unsupported(self):
        for protocol, _, raw, _, _ in PROTOCOLS:
            result = analyze_packet(observation_for(protocol, raw))
            result = replace(result, ipv6_tcp=None, ipv6_udp=None)
            tracker = FlowTracker()
            manager = FlowObservationWindowManager("ipv6-transport", timedelta(seconds=5))
            for action in (flow_identity_from_packet, tracker.record, manager.record):
                with self.assertRaises(FlowIdentityError):
                    action(result)
            self.assertEqual(tracker.flow_count(), 0)
            self.assertEqual(manager.active_windows(), ())

    def test_unknown_internal_decoder_errors_propagate_exactly(self):
        for protocol, _, raw, decoder, error_type in PROTOCOLS:
            for error in (error_type("unrecognized failure"), ValueError("internal"),
                          TypeError("internal"), IndexError("internal"), RuntimeError("internal")):
                with self.subTest(protocol=protocol, error=error):
                    with patch.object(packet_analysis, decoder.__name__, side_effect=error):
                        with self.assertRaises(type(error)) as raised:
                            analyze_packet_outcome(observation_for(protocol, raw))
                    self.assertIs(raised.exception, error)

    def test_known_ipv6_decoder_boundary_errors_keep_existing_unsupported_classification(self):
        for protocol, _, raw, decoder, error_type in PROTOCOLS:
            prefix = "TCP" if protocol == 6 else "UDP"
            for message in (f"{prefix} decoding requires terminal IPv6 Next Header {protocol}",
                            f"{prefix} decoding requires an initial IPv6 fragment"):
                with patch.object(packet_analysis, decoder.__name__, side_effect=error_type(message)):
                    outcome = analyze_packet_outcome(observation_for(protocol, raw))
                self.assertIsNone(outcome.analysis)
                self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.UNSUPPORTED)
                self.assertEqual(outcome.failure_description, message)


if __name__ == "__main__":
    unittest.main()
