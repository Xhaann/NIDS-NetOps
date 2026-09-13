import unittest
from dataclasses import replace
from datetime import timedelta
from fractions import Fraction
from sys import float_info

from analysis import (
    FlowRateFeatures, FlowRateFeaturesError, analyze_packet, extract_flow_rate_features,
    flow_identity_from_packet, update_flow_statistics,
)
from tests.test_flow_rate_features import STATISTICS
from tests.test_packet_analysis import UDP_BYTES, make_observation


class FlowRateExtremeTests(unittest.TestCase):
    def test_large_integer_numerators_with_finite_quotients_are_accepted(self):
        count = 10 ** 310
        statistics = replace(STATISTICS, packet_count=count, captured_bytes=count, original_bytes=count,
                             last_captured_at=STATISTICS.first_captured_at + timedelta(seconds=10 ** 10))
        self.assertEqual(extract_flow_rate_features(statistics), FlowRateFeatures(1e300, 1e300, 1e300))

    def test_each_rate_uses_its_own_numerator_without_converting_other_counts(self):
        for counts in ((10 ** 310, 0, 0), (1, 10 ** 310, 10 ** 311), (1, 1, 10 ** 310)):
            with self.subTest(counts=counts):
                statistics = replace(STATISTICS, packet_count=counts[0], captured_bytes=counts[1],
                                     original_bytes=counts[2], last_captured_at=STATISTICS.first_captured_at
                                     + timedelta(seconds=10 ** 10))
                expected = FlowRateFeatures(*(float(Fraction(count, 10 ** 10)) for count in counts))
                self.assertEqual(extract_flow_rate_features(statistics), expected)

    def test_fractional_duration_fallback_uses_the_existing_duration_float(self):
        for seconds in (9.5, 10.000001, 999.999999):
            with self.subTest(seconds=seconds):
                statistics = replace(STATISTICS, original_bytes=10 ** 309,
                                     last_captured_at=STATISTICS.first_captured_at + timedelta(seconds=seconds))
                duration = (statistics.last_captured_at - statistics.first_captured_at).total_seconds()
                expected = float(Fraction(statistics.original_bytes) / Fraction.from_float(duration))
                self.assertEqual(extract_flow_rate_features(statistics).original_bytes_per_second, expected)

    def test_maximum_finite_quotient_and_unrepresentable_neighbor(self):
        largest = int(float_info.max)
        for count in (2 * largest - 2, 2 * largest, 2 * largest + 2):
            statistics = replace(STATISTICS, original_bytes=count,
                                 last_captured_at=STATISTICS.first_captured_at + timedelta(seconds=2))
            self.assertEqual(extract_flow_rate_features(statistics).original_bytes_per_second,
                             float(Fraction(count, 2)))
        for count in (2 ** 1025, 10 ** 400):
            statistics = replace(STATISTICS, original_bytes=count,
                                 last_captured_at=STATISTICS.first_captured_at + timedelta(seconds=2))
            with self.assertRaises(OverflowError):
                float(Fraction(count, 2))
            with self.assertRaises(FlowRateFeaturesError) as failure:
                extract_flow_rate_features(statistics)
            self.assertIsInstance(failure.exception.__cause__, OverflowError)

    def test_ordinary_divisions_remain_exactly_equal_to_historical_results(self):
        for count in (1, 2 ** 53 + 1, 10 ** 100, 10 ** 300):
            for interval in (timedelta(microseconds=1), timedelta(seconds=1.5), timedelta(days=10000)):
                statistics = replace(STATISTICS, packet_count=count, captured_bytes=count,
                                     original_bytes=count + 1, last_captured_at=STATISTICS.first_captured_at + interval)
                duration = interval.total_seconds()
                expected = FlowRateFeatures(count / duration, count / duration, (count + 1) / duration)
                self.assertEqual(extract_flow_rate_features(statistics), expected)

    def test_admitted_observation_lengths_accumulate_without_losing_finite_rates(self):
        observation = replace(make_observation(17, UDP_BYTES), original_length=10 ** 309)
        first = analyze_packet(observation)
        second = analyze_packet(replace(observation, captured_at=observation.captured_at + timedelta(seconds=20.25)))
        identity = flow_identity_from_packet(first)
        initial = update_flow_statistics(None, first, identity)
        statistics = update_flow_statistics(initial, second, identity)
        before = replace(statistics)
        expected = float(Fraction(2 * 10 ** 309) / Fraction('20.25'))
        for _ in range(3):
            result = extract_flow_rate_features(statistics)
            self.assertEqual(result.original_bytes_per_second, expected)
            self.assertEqual(statistics, before)
            self.assertEqual(initial.packet_count, 1)
            self.assertEqual(initial.original_bytes, 10 ** 309)


if __name__ == '__main__':
    unittest.main()
