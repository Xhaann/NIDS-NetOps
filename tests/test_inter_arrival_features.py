import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from math import isfinite, nextafter, sqrt, ulp
from types import SimpleNamespace
from unittest.mock import Mock, patch

from analysis import (
    FlowFeatureInput,
    FlowIdentity,
    FlowInterArrivalStatistics,
    FlowPacketSizeStatistics,
    FlowStatistics,
    InterArrivalFeatures,
    InterArrivalFeaturesError,
    PacketAnalysis,
    extract_inter_arrival_features,
)
from capture.packet_observation import CaptureSource, PacketObservation


IDENTITY = FlowIdentity(b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", 12345, 443, 6)
TIMESTAMP = datetime(2026, 9, 6, 12, tzinfo=timezone.utc)
STATISTICS = FlowInterArrivalStatistics(
    IDENTITY, 3, TIMESTAMP, TIMESTAMP + timedelta(seconds=4), 2, 4.0, 8.5, 1.5, 2.5,
)


def statistics_for(intervals: tuple[float, ...]) -> FlowInterArrivalStatistics:
    return FlowInterArrivalStatistics(
        identity=IDENTITY,
        packet_count=len(intervals) + 1,
        first_captured_at=TIMESTAMP,
        last_captured_at=TIMESTAMP,
        inter_arrival_count=len(intervals),
        inter_arrival_sum_seconds=sum(intervals, 0.0),
        inter_arrival_sum_seconds_squared=sum((value * value for value in intervals), 0.0),
        min_inter_arrival_seconds=min(intervals, default=0.0),
        max_inter_arrival_seconds=max(intervals, default=0.0),
    )


class InterArrivalFeaturesTests(unittest.TestCase):
    def assert_unchanged_failure(self, statistics: FlowInterArrivalStatistics) -> None:
        before = vars(statistics).copy()
        with self.assertRaises(InterArrivalFeaturesError):
            extract_inter_arrival_features(statistics)
        self.assertEqual(vars(statistics), before)

    def test_known_population_vectors_and_zero_policies(self) -> None:
        for statistics, expected in (
            (STATISTICS, InterArrivalFeatures(2.0, 0.25, 0.5, 1.5, 2.5)),
            (statistics_for((2.0, 2.0, 2.0)), InterArrivalFeatures(2.0, 0.0, 0.0, 2.0, 2.0)),
            (statistics_for(()), InterArrivalFeatures(0.0, 0.0, 0.0, 0.0, 0.0)),
            (statistics_for((0.0,)), InterArrivalFeatures(0.0, 0.0, 0.0, 0.0, 0.0)),
            (statistics_for((0.0, 0.0, 0.0)), InterArrivalFeatures(0.0, 0.0, 0.0, 0.0, 0.0)),
            (statistics_for((0.0, 0.0, 3.0)), InterArrivalFeatures(1.0, 2.0, sqrt(2.0), 0.0, 3.0)),
        ):
            with self.subTest(statistics=statistics):
                result = extract_inter_arrival_features(statistics)
                self.assertEqual(result, expected)
                for value in vars(result).values():
                    self.assertIs(type(value), float)
                    self.assertTrue(isfinite(value))
                    self.assertGreaterEqual(value, 0.0)
        self.assertNotEqual(extract_inter_arrival_features(STATISTICS).variance_inter_arrival_seconds, 0.5)

    def test_fractional_microsecond_and_large_values_use_unrounded_formulas(self) -> None:
        for intervals in ((1.0, 2.0, 4.0), (0.125, 0.375), (0.000001, 0.000003), (1e150, 2e150)):
            statistics = statistics_for(intervals)
            result = extract_inter_arrival_features(statistics)
            mean = statistics.inter_arrival_sum_seconds / len(intervals)
            variance = statistics.inter_arrival_sum_seconds_squared / len(intervals) - mean * mean
            self.assertEqual(result, InterArrivalFeatures(
                mean, variance, sqrt(variance), min(intervals), max(intervals)))
            self.assertEqual(result.standard_deviation_inter_arrival_seconds,
                             sqrt(result.variance_inter_arrival_seconds))
        self.assertNotEqual(extract_inter_arrival_features(statistics_for((1.0, 2.0, 4.0)))
                            .mean_inter_arrival_seconds, 2.333333)

    def test_source_extrema_and_aggregates_are_authoritative_without_timestamp_access(self) -> None:
        statistics = replace(STATISTICS, min_inter_arrival_seconds=0.25, max_inter_arrival_seconds=9.0,
                             identity=replace(IDENTITY, protocol=17), last_captured_at=TIMESTAMP)
        result = extract_inter_arrival_features(statistics)
        self.assertEqual(result, InterArrivalFeatures(2.0, 0.25, 0.5, 0.25, 9.0))
        self.assertIs(result.min_inter_arrival_seconds, statistics.min_inter_arrival_seconds)
        self.assertIs(result.max_inter_arrival_seconds, statistics.max_inter_arrival_seconds)

    def test_roundoff_boundary_is_ulp_based_and_material_negative_variance_is_rejected(self) -> None:
        statistics = statistics_for((0.1, 0.1, 0.1))
        mean = statistics.inter_arrival_sum_seconds / statistics.inter_arrival_count
        second_moment = statistics.inter_arrival_sum_seconds_squared / statistics.inter_arrival_count
        variance = second_moment - mean * mean
        error = ulp(mean)
        bound = ulp(second_moment) + ulp(mean * mean) + error * (2 * abs(mean) + error)
        self.assertLess(variance, 0.0)
        self.assertLessEqual(-variance, bound)
        result = extract_inter_arrival_features(statistics)
        self.assertEqual(result.mean_inter_arrival_seconds, mean)
        self.assertEqual(result.variance_inter_arrival_seconds, 0.0)
        self.assertEqual(result.standard_deviation_inter_arrival_seconds, 0.0)
        unit = statistics_for((1.0,))
        for squares, accepted in ((1.0 - 2 * ulp(1.0), True), (1.0 - 8 * ulp(1.0), False)):
            statistics = replace(unit, inter_arrival_sum_seconds_squared=squares)
            bound = ulp(squares) + ulp(1.0) + ulp(1.0) * (2.0 + ulp(1.0))
            if accepted:
                self.assertLessEqual(1.0 - squares, bound)
                self.assertEqual(extract_inter_arrival_features(statistics).variance_inter_arrival_seconds, 0.0)
            else:
                self.assertGreater(1.0 - squares, bound)
                self.assert_unchanged_failure(statistics)
        self.assert_unchanged_failure(replace(STATISTICS, inter_arrival_sum_seconds_squared=1.0))

    def test_small_positive_variance_is_not_clamped(self) -> None:
        statistics = replace(statistics_for((1.0,)), inter_arrival_sum_seconds_squared=nextafter(1.0, 2.0))
        result = extract_inter_arrival_features(statistics)
        self.assertEqual(result.variance_inter_arrival_seconds, ulp(1.0))
        self.assertEqual(result.standard_deviation_inter_arrival_seconds, sqrt(ulp(1.0)))

    def test_accumulated_roundoff_does_not_reject_constant_intervals(self) -> None:
        for interval in (0.1, 0.3, 0.000001):
            with self.subTest(interval=interval):
                statistics = statistics_for((interval,) * 500)
                result = extract_inter_arrival_features(statistics)
                self.assertAlmostEqual(result.mean_inter_arrival_seconds / interval, 1.0)
                self.assertAlmostEqual(result.variance_inter_arrival_seconds / interval ** 2, 0.0)
                self.assertGreaterEqual(result.variance_inter_arrival_seconds, 0.0)
                self.assertEqual(result.min_inter_arrival_seconds, interval)
                self.assertEqual(result.max_inter_arrival_seconds, interval)
                self.assert_unchanged_failure(replace(statistics,
                    inter_arrival_sum_seconds_squared=statistics.inter_arrival_sum_seconds_squared * 0.9))

    def test_overflow_and_nonfinite_derived_values_fail_without_mutation(self) -> None:
        self.assert_unchanged_failure(replace(STATISTICS, inter_arrival_sum_seconds=1e308))
        self.assert_unchanged_failure(replace(STATISTICS, packet_count=10 ** 400 + 1,
                                             inter_arrival_count=10 ** 400))
        for field in ("inter_arrival_sum_seconds", "inter_arrival_sum_seconds_squared"):
            for value in (float("inf"), float("nan")):
                with patch.object(FlowInterArrivalStatistics, "__post_init__", return_value=None):
                    invalid = replace(STATISTICS, **{field: value})
                self.assert_unchanged_failure(invalid)
        for value in (float("inf"), float("nan")):
            with patch("analysis.inter_arrival_features.sqrt", return_value=value) as square_root:
                self.assert_unchanged_failure(STATISTICS)
                square_root.assert_called_once_with(0.25)

    def test_wrong_input_models_duck_types_mocks_and_subclasses_are_rejected(self) -> None:
        class DerivedStatistics(FlowInterArrivalStatistics):
            pass

        observation = PacketObservation(TIMESTAMP, None, 0, None, b"", CaptureSource("test-inter-arrival-features"))
        packet_size_values = {field.name: 0 for field in fields(FlowPacketSizeStatistics) if field.name != "identity"}
        packet_size_values["packet_count"] = 1
        for value in (
            None, True, False, 1, 1.0, "statistics", b"", {}, [], SimpleNamespace(**vars(STATISTICS)),
            Mock(spec=FlowInterArrivalStatistics), DerivedStatistics(**vars(STATISTICS)),
            observation, PacketAnalysis(observation),
            FlowStatistics(IDENTITY, 1, 0, 0, TIMESTAMP, TIMESTAMP),
            FlowPacketSizeStatistics(identity=IDENTITY, **packet_size_values),
            FlowFeatureInput(IDENTITY, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        ):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    extract_inter_arrival_features(value)

    def test_direct_model_requires_finite_nonnegative_exact_floats(self) -> None:
        self.assertTrue(issubclass(InterArrivalFeaturesError, ValueError))
        valid = InterArrivalFeatures(2.0, 0.25, 0.5, 1.5, 2.5)
        for field in fields(valid):
            for value in (True, False, 0, 1, None, "1.0", Decimal("1.0"), complex(1), SimpleNamespace()):
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(TypeError):
                        replace(valid, **{field.name: value})
            for value in (-1.0, float("inf"), float("-inf"), float("nan")):
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(InterArrivalFeaturesError):
                        replace(valid, **{field.name: value})
        with self.assertRaises(InterArrivalFeaturesError):
            replace(valid, min_inter_arrival_seconds=3.0)
        self.assertEqual(InterArrivalFeatures(0.0, 0.0, 0.0, 0.0, 0.0).mean_inter_arrival_seconds, 0.0)

    def test_exact_five_frozen_float_fields_with_no_hidden_state_or_source_retention(self) -> None:
        result = extract_inter_arrival_features(STATISTICS)
        names = (
            "mean_inter_arrival_seconds", "variance_inter_arrival_seconds",
            "standard_deviation_inter_arrival_seconds", "min_inter_arrival_seconds", "max_inter_arrival_seconds",
        )
        self.assertEqual(tuple(field.name for field in fields(result)), names)
        self.assertEqual(tuple(vars(result)), names)
        for name in names:
            self.assertIs(type(getattr(result, name)), float)
            self.assertIsNot(getattr(result, name), STATISTICS)
            with self.assertRaises(FrozenInstanceError):
                setattr(result, name, 0.0)
            with self.assertRaises(FrozenInstanceError):
                delattr(result, name)

    def test_repeated_extraction_is_deterministic_and_preserves_complete_input(self) -> None:
        before = vars(STATISTICS).copy()
        expected = InterArrivalFeatures(2.0, 0.25, 0.5, 1.5, 2.5)
        for source in (STATISTICS, STATISTICS, replace(STATISTICS)):
            self.assertEqual(extract_inter_arrival_features(source), expected)
        self.assertEqual(vars(STATISTICS), before)
        for name, value in before.items():
            self.assertIs(getattr(STATISTICS, name), value)
