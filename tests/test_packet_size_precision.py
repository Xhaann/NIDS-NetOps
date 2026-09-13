import unittest
from dataclasses import replace
from fractions import Fraction
from math import sqrt
from pathlib import Path
from tempfile import TemporaryDirectory

from analysis import PacketSizeFeaturesError, extract_packet_size_features, flow_identity_from_packet, update_flow_packet_size_statistics
from application import GroundTruth, run_end_to_end_validation
from capture import PcapPacketSource
from ml import project_flow_features
from research import research_example_from_window
from tests.pcap_scenarios import frame, transport
from tests.test_end_to_end_validation import settings
from tests.test_packet_size_features import TCP_ANALYSIS
from tests.test_pcap_packet_source import global_header, record


def size_statistics(forward, reverse=()):
    statistics = update_flow_packet_size_statistics(None, TCP_ANALYSIS, flow_identity_from_packet(TCP_ANALYSIS))
    values = {}
    for prefix, lengths in (('', forward + reverse), ('forward_', forward), ('reverse_', reverse)):
        values[prefix + 'packet_count'] = len(lengths)
        for kind in ('captured', 'original'):
            values[prefix + kind + '_bytes'] = sum(lengths)
            values[prefix + 'min_' + kind + '_length'] = min(lengths, default=0)
            values[prefix + 'max_' + kind + '_length'] = max(lengths, default=0)
            values[prefix + 'sum_' + kind + '_length_squares'] = sum(x * x for x in lengths)
    return replace(statistics, **values)


def exact_variance(lengths):
    mean = Fraction(sum(lengths), len(lengths))
    return float(sum((Fraction(x) - mean) ** 2 for x in lengths) / len(lengths))


class PacketSizePrecisionTests(unittest.TestCase):
    def test_large_nearby_lengths_recover_positive_variance_in_all_channels(self):
        for base in (2 ** 27, 2 ** 32 - 4, 2 ** 53, 10 ** 100):
            with self.subTest(base=base):
                forward = (base, base + 1)
                reverse = (base + 2, base + 4, base + 3)
                statistics = size_statistics(forward, reverse)
                before = replace(statistics)
                result = extract_packet_size_features(statistics)
                self.assertEqual(result.variance_captured_length, exact_variance(forward + reverse))
                self.assertEqual(result.variance_original_length, exact_variance(forward + reverse))
                self.assertEqual(result.forward_variance_captured_length, exact_variance(forward))
                self.assertEqual(result.reverse_variance_captured_length, exact_variance(reverse))
                self.assertEqual(result.standard_deviation_captured_length, sqrt(exact_variance(forward + reverse)))
                self.assertEqual(result, extract_packet_size_features(statistics))
                self.assertEqual(statistics, before)

    def test_constant_lengths_do_not_acquire_positive_roundoff_variance(self):
        for length in (2 ** 53 + 1, 2 ** 53 + 3, 10 ** 100):
            result = extract_packet_size_features(size_statistics((length,) * 3))
            for name in ('variance_captured_length', 'variance_original_length', 'standard_deviation_captured_length',
                         'standard_deviation_original_length', 'forward_variance_captured_length', 'reverse_variance_captured_length'):
                self.assertEqual(getattr(result, name), 0.0)
            self.assertEqual(result.reverse_mean_captured_length, 0.0)

    def test_exactly_negative_integer_moments_are_rejected_even_when_float_variance_is_zero(self):
        statistics = size_statistics((2 ** 32,) * 2, (2 ** 32,) * 2)
        for name in ('sum_captured_length_squares', 'sum_original_length_squares',
                     'forward_sum_captured_length_squares', 'reverse_sum_captured_length_squares'):
            with self.subTest(name=name):
                invalid = replace(statistics, **{name: getattr(statistics, name) - 1})
                with self.assertRaises(PacketSizeFeaturesError):
                    extract_packet_size_features(invalid)

    def test_ordinary_non_cancelling_arithmetic_remains_bit_for_bit_unchanged(self):
        for lengths in ((1, 2, 4), (0, 100, 10000), (7, 31, 73, 1000)):
            result = extract_packet_size_features(size_statistics(lengths))
            mean = sum(lengths) / len(lengths)
            variance = sum(x * x for x in lengths) / len(lengths) - mean * mean
            self.assertEqual(result.mean_captured_length, mean)
            self.assertEqual(result.variance_captured_length, variance)
            self.assertEqual(result.variance_original_length, variance)
            self.assertEqual(result.forward_variance_captured_length, variance)
            self.assertEqual(result.standard_deviation_captured_length, sqrt(variance))

    def test_finite_moment_requirements_remain_in_force(self):
        statistics = size_statistics((10 ** 200,) * 2)
        with self.assertRaises(PacketSizeFeaturesError):
            extract_packet_size_features(statistics)

    def test_pcap_original_length_precision_reaches_snapshots_and_projection_without_changing_detection(self):
        for ipv6 in (False, True):
            for protocol in (6, 17):
                with self.subTest(ipv6=ipv6, protocol=protocol), TemporaryDirectory() as directory:
                    raw = frame(protocol, transport(protocol, ipv6=ipv6), ipv6)
                    path = Path(directory) / 'large-lengths.pcap'
                    data = global_header() + record(raw, seconds=1, original=2 ** 32 - 2) + record(raw, seconds=2, original=2 ** 32 - 1)
                    path.write_bytes(data)
                    results = []
                    for _ in range(2):
                        source = PcapPacketSource(path)
                        result = run_end_to_end_validation(source, configuration=settings(), capture_session_id='precision',
                                                          ground_truth=GroundTruth((), ()))
                        results.append(result)
                        self.assertEqual([f.decision.value for f in result.pipeline_result.packet_findings], ['no_match', 'no_match'])
                        self.assertTrue(all(f.decision.value == 'match' for f in result.pipeline_result.flow_findings))
                        snapshot = result.pipeline_result.flow_findings[0].raw_evidence.snapshot
                        self.assertEqual(snapshot.packet_size_features.variance_original_length, 0.25)
                        self.assertEqual(snapshot.packet_size_features.standard_deviation_original_length, 0.5)
                        self.assertEqual(snapshot.packet_size_features.variance_captured_length, 0.0)
                        self.assertEqual(snapshot.flow_volume_features.original_bytes, 2 ** 33 - 3)
                        projection = project_flow_features(snapshot)
                        self.assertEqual(len(projection.values), 49)
                        values = dict(zip(projection.feature_names, projection.values))
                        self.assertEqual(values['packet_size_features.variance_original_length'], 0.25)
                        example = research_example_from_window(snapshot.observation_window)
                        self.assertEqual(example.projection, projection)
                        self.assertIsNone(example.ground_truth)
                        self.assertIsNone(source._file)
                    self.assertEqual(results[0], results[1])
                    self.assertEqual(path.read_bytes(), data)
                self.assertFalse(Path(directory).exists())
