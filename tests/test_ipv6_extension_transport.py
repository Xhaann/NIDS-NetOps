import unittest
from datetime import timedelta
from unittest.mock import patch

from analysis import FlowIdentityError, FlowObservationWindowManager, analyze_packet_outcome, extract_flow_feature_snapshot
from analysis import packet_analysis
from tests.pcap_scenarios import transport
from tests.test_ipv6_transport import fragment_header, observation_for


def extension_chain(protocol, specifications):
    prefix = b''
    selector = protocol
    for kind, length in reversed(specifications):
        prefix = bytes((selector, length // 8 - 1)) + bytes(length - 2) + prefix
        selector = kind
    return prefix, selector


class IPv6ExtensionTransportTests(unittest.TestCase):
    def test_repeated_destination_headers_preserve_transport_offsets_and_features(self):
        for protocol in (6, 17):
            for lengths in ((8, 8, 8), (16, 24, 2048), (2048, 8, 16)):
                with self.subTest(protocol=protocol, lengths=lengths):
                    specifications = tuple(zip((60, 43, 60), lengths))
                    prefix, base = extension_chain(protocol, specifications)
                    segment = transport(protocol, b'opaque payload', ipv6=True)
                    observation = observation_for(protocol, segment, prefix, base)
                    outcome = analyze_packet_outcome(observation)
                    self.assertTrue(outcome.succeeded)
                    self.assertEqual(outcome, analyze_packet_outcome(observation))
                    analysis = outcome.analysis
                    headers = analysis.ipv6_extension_headers.headers
                    self.assertEqual([h.offset for h in headers], [40, 40 + lengths[0], 40 + sum(lengths[:2])])
                    self.assertEqual(tuple(h.declared_length for h in headers), lengths)
                    self.assertEqual(b''.join(h.raw_bytes for h in headers), prefix)
                    decoded = analysis.ipv6_tcp if protocol == 6 else analysis.ipv6_udp
                    self.assertEqual(decoded.payload, b'opaque payload')
                    manager = FlowObservationWindowManager('extensions', timedelta(seconds=5))
                    manager.record(analysis)
                    snapshot = extract_flow_feature_snapshot(manager.end_capture_session()[0])
                    self.assertEqual(snapshot.identity.protocol, protocol)
                    self.assertEqual(snapshot.flow_volume_features.packet_count, 1)
                    self.assertEqual(snapshot.flow_volume_features.captured_bytes, len(observation.raw_bytes))

    def test_later_variable_header_cannot_borrow_padding_or_transport_bytes(self):
        for protocol in (6, 17):
            prefix, base = extension_chain(60, ((0, 16), (43, 24)))
            for suffix in (b'', b'\x06', bytes((protocol, 255)) + bytes(7)):
                with self.subTest(protocol=protocol, suffix=suffix):
                    observation = observation_for(protocol, suffix, prefix, base, trailing=bytes(4096))
                    outcome = analyze_packet_outcome(observation)
                    self.assertEqual(outcome.failure_classification.value, 'incomplete')
                    self.assertIsNone(outcome.analysis)

    def test_complete_chain_cannot_supply_a_missing_transport_header(self):
        for protocol, minimum in ((6, 20), (17, 8)):
            prefix, base = extension_chain(protocol, ((60, 16), (43, 24), (60, 8)))
            segment = transport(protocol, ipv6=True)
            for available in range(minimum):
                with self.subTest(protocol=protocol, available=available):
                    result = analyze_packet_outcome(observation_for(
                        protocol, segment[:available], prefix, base, trailing=segment))
                    self.assertEqual(result.failure_classification.value, 'incomplete')
                    self.assertIsNone(result.analysis)

    def test_non_initial_payload_never_becomes_a_repeated_extension(self):
        for selector in (0, 43, 44, 60, 6, 17, 50, 51, 59, 253):
            for offset in (1, 8191):
                for suffix in (b'', b'\x06\xff', fragment_header(17) + transport(17, ipv6=True)):
                    with self.subTest(selector=selector, offset=offset, suffix=suffix):
                        prefix, base = extension_chain(44, ((60, 16), (43, 24), (60, 8)))
                        fragment = fragment_header(selector, offset, True)
                        observation = observation_for(selector, suffix, prefix + fragment, base)
                        with patch.object(packet_analysis, 'decode_tcp') as tcp, patch.object(packet_analysis, 'decode_udp') as udp:
                            outcome = analyze_packet_outcome(observation)
                        tcp.assert_not_called()
                        udp.assert_not_called()
                        self.assertTrue(outcome.succeeded)
                        analysis = outcome.analysis
                        self.assertEqual([h.header_type for h in analysis.ipv6_extension_headers.headers], [60, 43, 60, 44])
                        self.assertEqual(analysis.ipv6_extension_headers.terminating_next_header, selector)
                        self.assertEqual(analysis.ipv6.payload, prefix + fragment + suffix)
                        self.assertEqual(analysis.ipv6_fragmentation.headers[0].fragment_offset, offset)
                        manager = FlowObservationWindowManager('fragments', timedelta(seconds=5))
                        with self.assertRaises(FlowIdentityError):
                            manager.record(analysis)
                        self.assertEqual(manager.end_capture_session(), ())

    def test_initial_and_atomic_fragments_continue_through_variable_extensions(self):
        for protocol in (6, 17):
            for more in (False, True):
                prefix, base = extension_chain(protocol, ((60, 16), (43, 24), (60, 8)))
                observation = observation_for(protocol, transport(protocol, ipv6=True),
                                              fragment_header(base, more=more) + prefix, 44)
                result = analyze_packet_outcome(observation)
                self.assertTrue(result.succeeded)
                self.assertEqual(len(result.analysis.ipv6_extension_headers.headers), 4)
                self.assertIsNotNone(result.analysis.ipv6_tcp if protocol == 6 else result.analysis.ipv6_udp)

    def test_opaque_terminal_selectors_do_not_scan_repeated_header_like_payload(self):
        for selector in (50, 51, 59, 253):
            prefix, base = extension_chain(selector, ((60, 16), (43, 8), (60, 24)))
            result = analyze_packet_outcome(observation_for(selector, b'\x06\xff' + bytes(32), prefix, base))
            self.assertTrue(result.succeeded)
            self.assertEqual(result.analysis.ipv6_extension_headers.terminating_next_header, selector)
            self.assertEqual(len(result.analysis.ipv6_extension_headers.headers), 3)
            self.assertIsNone(result.analysis.ipv6_tcp)
            self.assertIsNone(result.analysis.ipv6_udp)
