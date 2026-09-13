import unittest
from dataclasses import replace
from datetime import timedelta
from unittest.mock import patch

from analysis import (
    FlowObservationWindowManager, IPv4DecodeError, analyze_packet,
    analyze_packet_outcome, decode_ethernet, decode_ipv4,
    extract_flow_feature_snapshot, flow_identity_from_packet,
)
from analysis import packet_analysis
from application import GroundTruth, run_end_to_end_validation
from tests.pcap_scenarios import checksum, transport
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_packet_analysis import ICMP_BYTES, make_observation


def with_options(observation, options):
    raw = observation.raw_bytes
    header = bytearray(raw[14:34])
    header[0] = 0x45 + len(options) // 4
    header[2:4] = (int.from_bytes(header[2:4], 'big') + len(options)).to_bytes(2, 'big')
    header[10:12] = bytes(2)
    header = header + options
    header[10:12] = checksum(header).to_bytes(2, 'big')
    raw = raw[:14] + bytes(header) + raw[34:]
    return replace(observation, raw_bytes=raw, captured_length=len(raw), original_length=len(raw))


class IPv4OptionsTests(unittest.TestCase):
    def test_legal_ihl_boundaries_preserve_transport_and_identity(self):
        for protocol in (6, 17):
            original = make_observation(protocol, transport(protocol, b'payload'))
            baseline = analyze_packet(original)
            for size in range(0, 41, 4):
                with self.subTest(protocol=protocol, size=size):
                    options = bytes((1,)) * size
                    outcome = analyze_packet_outcome(with_options(original, options))
                    self.assertTrue(outcome.succeeded)
                    result = outcome.analysis
                    self.assertEqual(result.ipv4.options, options)
                    self.assertEqual(result.ipv4.header_length, 20 + size)
                    self.assertEqual(result.ipv4.payload, baseline.ipv4.payload)
                    self.assertEqual((result.tcp, result.udp), (baseline.tcp, baseline.udp))
                    self.assertEqual(flow_identity_from_packet(result), flow_identity_from_packet(baseline))

    def test_multiple_unknown_options_and_zero_padding_preserve_opaque_data(self):
        for options in (bytes.fromhex('9e0400ff9f02a002'), bytes.fromhex('019e03ff00000000'),
                        bytes.fromhex('9e280001') + bytes(range(36)), bytes(40)):
            with self.subTest(options=options):
                observation = with_options(make_observation(253, b'opaque'), options)
                result = analyze_packet_outcome(observation)
                self.assertTrue(result.succeeded)
                self.assertEqual(result.analysis.ipv4.options, options)
                self.assertEqual(result.analysis.ipv4.payload, b'opaque')
                self.assertIsNone(result.analysis.tcp)
                self.assertIsNone(result.analysis.udp)

    def test_malformed_envelopes_fail_before_transport_without_partial_analysis(self):
        for options in (b'\x9e\x00\x00\x00', b'\x9e\x01\x00\x00', b'\x9e\x05\x00\x00',
                        b'\x01\x01\x01\x9e', b'\x00\x00\x01\x00',
                        b'\x9e\x04\x00\xff\x9f\xff\x00\x00'):
            with self.subTest(options=options):
                observation = with_options(make_observation(17, transport(17, bytes(255))), options)
                self.assertEqual(decode_ipv4(decode_ethernet(observation)).options, options)
                with patch.object(packet_analysis, 'decode_udp') as decoder:
                    with self.assertRaises(IPv4DecodeError):
                        analyze_packet(observation)
                    outcome = analyze_packet_outcome(observation)
                decoder.assert_not_called()
                self.assertEqual(outcome.failure_classification.value, 'structural_failure')
                self.assertIsNone(outcome.analysis)
                self.assertIs(outcome.observation, observation)

    def test_captured_option_truncation_remains_incomplete(self):
        original = with_options(make_observation(17, transport(17)), bytes((1,)) * 40)
        for length in range(34, 74):
            with self.subTest(length=length):
                observation = replace(original, raw_bytes=original.raw_bytes[:length], captured_length=length)
                result = analyze_packet_outcome(observation)
                self.assertEqual(result.failure_classification.value, 'incomplete')
                self.assertIsNone(result.analysis)

    def test_checksum_mismatch_and_udp_omission_keep_existing_semantics(self):
        original = with_options(make_observation(17, transport(17)), b'\x01' * 4)
        raw = original.raw_bytes
        corrupted = replace(original, raw_bytes=raw[:36] + bytes(2) + raw[38:])
        self.assertEqual(analyze_packet_outcome(corrupted).failure_classification.value, 'integrity_failure')
        omitted = with_options(make_observation(17, bytes.fromhex('303901bb00080000')), b'\x01' * 4)
        self.assertTrue(analyze_packet_outcome(omitted).succeeded)

    def test_fragment_behavior_and_icmp_checksums_remain_unchanged(self):
        for protocol, segment in ((6, transport(6)), (17, transport(17)), (1, ICMP_BYTES)):
            for fragment in (0, 0x2000, 1, 0x2001):
                with self.subTest(protocol=protocol, fragment=fragment):
                    original = make_observation(protocol, segment, fragment_field=fragment)
                    baseline = analyze_packet_outcome(original)
                    result = analyze_packet_outcome(with_options(original, b'\x9e\x02\x00\x00'))
                    self.assertEqual(result.failure_classification, baseline.failure_classification)
                    self.assertEqual(result.failure_description, baseline.failure_description)
                    if result.succeeded:
                        self.assertEqual((result.analysis.tcp, result.analysis.udp, result.analysis.icmp),
                                         (baseline.analysis.tcp, baseline.analysis.udp, baseline.analysis.icmp))

    def test_valid_options_accumulate_actual_capture_sizes(self):
        manager = FlowObservationWindowManager('options', timedelta(seconds=5))
        original = make_observation(17, transport(17, b'data'))
        observations = (original, with_options(replace(original, captured_at=original.captured_at + timedelta(seconds=1)),
                                              b'\x01' * 40))
        for observation in observations:
            manager.record(analyze_packet_outcome(observation).analysis)
        window, = manager.end_capture_session()
        snapshot = extract_flow_feature_snapshot(window)
        self.assertEqual(snapshot.flow_volume_features.packet_count, 2)
        self.assertEqual(snapshot.flow_volume_features.captured_bytes, sum(o.captured_length for o in observations))
        self.assertEqual(snapshot.packet_size_features.max_captured_length, observations[1].captured_length)
        self.assertEqual(snapshot.flow_duration_features.duration_seconds, 1)

    def test_malformed_options_do_not_refresh_flow_or_suppress_packet_findings(self):
        original = make_observation(17, transport(17))
        bad = with_options(replace(original, captured_at=original.captured_at + timedelta(seconds=4)), b'\x9e\xff\x00\x00')
        later = with_options(replace(original, captured_at=original.captured_at + timedelta(seconds=5)), bytes(4))
        results = []
        for _ in range(2):
            source = MemoryPacketSource((original, bad, later))
            result = run_end_to_end_validation(source, configuration=settings(), capture_session_id='options',
                                              ground_truth=GroundTruth((), ()))
            results.append(result)
            self.assertEqual([f.decision.value for f in result.pipeline_result.packet_findings],
                             ['no_match', 'match', 'no_match'])
            snapshots = [f.raw_evidence.snapshot for f in result.pipeline_result.flow_findings]
            self.assertEqual([s.flow_volume_features.packet_count for s in snapshots], [1, 1])
            self.assertEqual([s.observation_window.key.sequence_number for s in snapshots], [0, 1])
            self.assertEqual([s.observation_window.closure_reason.value for s in snapshots],
                             ['inactivity', 'capture_session_end'])
        self.assertEqual(results[0], results[1])
