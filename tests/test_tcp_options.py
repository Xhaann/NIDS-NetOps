import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import analyze_packet_outcome, decode_tcp, packet_analysis
from application import GroundTruth, run_end_to_end_validation
from capture import PcapPacketSource
from tests.pcap_scenarios import frame, pcap_bytes, transport
from tests.test_end_to_end_validation import settings
from tests.test_ipv4_options import with_options
from tests.test_ipv6_extension_transport import extension_chain
from tests.test_ipv6_transport import context_for, fragment_header, observation_for
from tests.test_packet_analysis import make_observation


def tcp_observation(ipv6, options=b'', payload=b'data', fragment=None):
    segment = transport(6, payload, ipv6=ipv6, options=options)
    if ipv6:
        prefix, base = extension_chain(6 if fragment is None else 44, ((60, 16), (43, 8), (60, 24)))
        if fragment is not None:
            prefix += fragment_header(6, fragment[0], fragment[1])
        return observation_for(6, segment, prefix, base)
    field = 0 if fragment is None else fragment[0] | (int(fragment[1]) << 13)
    return with_options(make_observation(6, segment, fragment_field=field), b'\x01' * 4)


class TCPOptionsTests(unittest.TestCase):
    def test_every_legal_data_offset_preserves_payload_ports_and_control_bits(self):
        for ipv6 in (False, True):
            for size in range(0, 41, 4):
                with self.subTest(ipv6=ipv6, size=size):
                    observation = tcp_observation(ipv6, b'\x01' * size)
                    outcome = analyze_packet_outcome(observation)
                    self.assertTrue(outcome.succeeded)
                    self.assertEqual(outcome, analyze_packet_outcome(observation))
                    tcp = outcome.analysis.ipv6_tcp if ipv6 else outcome.analysis.tcp
                    self.assertEqual(tcp.options, b'\x01' * size)
                    self.assertEqual(tcp.payload, b'data')
                    self.assertEqual(tcp.header_length, 20 + size)
                    self.assertEqual((tcp.source_port, tcp.destination_port, tcp.sequence_number, tcp.syn), (12345, 443, 100, True))

    def test_multiple_options_and_opaque_unknown_bodies_are_preserved(self):
        for options in (bytes.fromhex('020405b404020000'), bytes.fromhex('019e03ff9f020000'),
                        b'\x9e\x28' + bytes(range(38)), bytes(40)):
            for ipv6 in (False, True):
                with self.subTest(ipv6=ipv6, options=options):
                    outcome = analyze_packet_outcome(tcp_observation(ipv6, options))
                    self.assertTrue(outcome.succeeded)
                    tcp = outcome.analysis.ipv6_tcp if ipv6 else outcome.analysis.tcp
                    self.assertEqual(tcp.options, options)
                    self.assertEqual(tcp.payload, b'data')

    def test_malformed_envelopes_are_structural_without_partial_analysis(self):
        for ipv6 in (False, True):
            for options in (b'\x02\x00\x00\x00', b'\x02\x01\x00\x00', b'\x02\x05\x00\x00',
                            b'\x01\x01\x01\x02', b'\x00\x00\x01\x00', b'\x9e\x04\x00\xff\x9f\xff\x00\x00'):
                with self.subTest(ipv6=ipv6, options=options):
                    observation = tcp_observation(ipv6, options, payload=bytes(255))
                    with patch.object(packet_analysis, 'validate_tcp_checksum') as checksum:
                        outcome = analyze_packet_outcome(observation)
                    checksum.assert_not_called()
                    self.assertEqual(outcome.failure_classification.value, 'structural_failure')
                    self.assertIsNone(outcome.analysis)
                    self.assertIs(outcome.observation, observation)

    def test_base_decoder_retains_opaque_representation_contract(self):
        options = b'\x02\x00\x00\x00'
        for ipv6 in (False, True):
            segment = transport(6, ipv6=ipv6, options=options)
            if ipv6:
                context = context_for(6, segment)
            else:
                observation = make_observation(6, segment)
                context = packet_analysis.decode_ipv4(packet_analysis.decode_ethernet(observation))
            self.assertEqual(decode_tcp(context).options, options)

    def test_missing_option_bytes_cannot_be_supplied_by_ethernet_padding(self):
        for ipv6 in (False, True):
            segment = transport(6, ipv6=ipv6, options=b'\x01' * 40)
            for available in range(20, 60):
                with self.subTest(ipv6=ipv6, available=available):
                    if ipv6:
                        observation = observation_for(6, segment[:available], trailing=segment)
                    else:
                        observation = make_observation(6, segment[:available])
                        raw = observation.raw_bytes + segment
                        observation = replace(observation, raw_bytes=raw, captured_length=len(raw), original_length=len(raw))
                    outcome = analyze_packet_outcome(observation)
                    self.assertEqual(outcome.failure_classification.value, 'incomplete')
                    self.assertIsNone(outcome.analysis)

    def test_fragments_validate_only_available_initial_tcp_headers(self):
        for ipv6 in (False, True):
            for options in (b'\x01\x01\x00\x00', b'\x02\xff\x00\x00'):
                initial = analyze_packet_outcome(tcp_observation(ipv6, options, fragment=(0, True)))
                self.assertEqual(initial.succeeded, options[0] == 1)
                non_initial = analyze_packet_outcome(tcp_observation(ipv6, options, fragment=(1, True)))
                if ipv6:
                    self.assertTrue(non_initial.succeeded)
                    self.assertIsNone(non_initial.analysis.ipv6_tcp)
                else:
                    self.assertEqual(non_initial.failure_classification.value, 'unsupported')

    def test_unrecognized_option_validation_failures_propagate_exactly(self):
        error = RuntimeError('validator failure')
        for ipv6 in (False, True):
            with patch.object(packet_analysis, '_validate_tcp_options', side_effect=error):
                with self.assertRaises(RuntimeError) as failure:
                    analyze_packet_outcome(tcp_observation(ipv6))
            self.assertIs(failure.exception, error)

    def test_malformed_tcp_options_cannot_refresh_flow_or_advance_control_statistics(self):
        for ipv6 in (False, True):
            with self.subTest(ipv6=ipv6), TemporaryDirectory() as directory:
                valid = tcp_observation(ipv6, b'\x01\x01\x00\x00').raw_bytes
                invalid = tcp_observation(ipv6, b'\x02\xff\x00\x00').raw_bytes
                udp = frame(17, transport(17, ipv6=ipv6), ipv6)
                packets = ((1000000, valid), (2000000, udp), (5000000, invalid), (6000000, valid))
                path = Path(directory) / 'tcp-options.pcap'
                path.write_bytes(pcap_bytes(packets))
                results = []
                for _ in range(2):
                    source = PcapPacketSource(path)
                    result = run_end_to_end_validation(source, configuration=settings(), capture_session_id='tcp-options',
                                                      ground_truth=GroundTruth((), ()))
                    results.append(result)
                    self.assertEqual([f.decision.value for f in result.pipeline_result.packet_findings],
                                     ['no_match', 'no_match', 'match', 'no_match'])
                    snapshots = [f.raw_evidence.snapshot for f in result.pipeline_result.flow_findings if f.detector_id == 'volume']
                    self.assertEqual([s.flow_volume_features.packet_count for s in snapshots], [1, 1, 1])
                    self.assertEqual([s.observation_window.key.sequence_number for s in snapshots], [0, 1, 2])
                    self.assertEqual(snapshots[0].observation_window.closure_reason.value, 'inactivity')
                    self.assertEqual([s.coordinated_state.tcp_control_statistics.forward_syn_count
                                      for s in snapshots if s.identity.protocol == 6], [1, 1])
                    self.assertIsNone(source._file)
                self.assertEqual(results[0], results[1])
            self.assertFalse(Path(directory).exists())
