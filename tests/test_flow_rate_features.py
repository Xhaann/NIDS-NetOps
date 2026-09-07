import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, patch

from analysis import (
    FlowDurationFeatures,
    FlowFeatureInput,
    FlowIdentity,
    FlowPacketSizeStatistics,
    FlowRateFeatures,
    FlowRateFeaturesError,
    FlowStatistics,
    PacketAnalysis,
    PacketSizeFeatures,
    extract_flow_rate_features,
)
from capture.packet_observation import CaptureSource, PacketObservation


IDENTITY = FlowIdentity(b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", 12345, 443, 6)
CAPTURED_AT = datetime(2026, 9, 6, 12, tzinfo=timezone.utc)
STATISTICS = FlowStatistics(IDENTITY, 10, 1000, 2000, CAPTURED_AT, CAPTURED_AT + timedelta(seconds=5))


class FlowRateFeaturesTests(unittest.TestCase):
    def test_positive_intervals_use_explicit_unrounded_formulas(self) -> None:
        for interval, counts, expected in (
            (timedelta(seconds=1), (10, 1000, 2000), (10.0, 1000.0, 2000.0)),
            (timedelta(seconds=5), (10, 1000, 2000), (2.0, 200.0, 400.0)),
            (timedelta(seconds=1.5), (7, 100, 140), (7 / 1.5, 100 / 1.5, 140 / 1.5)),
            (timedelta(microseconds=1), (10, 1000, 2000), (10000000.0, 1000000000.0, 2000000000.0)),
            (timedelta(seconds=3), (1, 1, 2), (1 / 3, 1 / 3, 2 / 3)),
        ):
            with self.subTest(interval=interval):
                statistics = FlowStatistics(IDENTITY, *counts, CAPTURED_AT, CAPTURED_AT + interval)
                result = extract_flow_rate_features(statistics)
                self.assertEqual(result, FlowRateFeatures(*expected))
                duration = (statistics.last_captured_at - statistics.first_captured_at).total_seconds()
                for field, numerator in zip(fields(result), counts):
                    value = getattr(result, field.name)
                    self.assertIs(type(value), float)
                    self.assertEqual(value, numerator / duration)
        fractional = replace(STATISTICS, packet_count=1, last_captured_at=CAPTURED_AT + timedelta(seconds=3))
        self.assertNotEqual(extract_flow_rate_features(fractional).packets_per_second, 0.333333)

    def test_positive_duration_allows_zero_byte_numerators(self) -> None:
        for captured, original, expected in ((0, 100, (2.0, 0.0, 20.0)), (0, 0, (2.0, 0.0, 0.0))):
            statistics = replace(STATISTICS, captured_bytes=captured, original_bytes=original)
            self.assertEqual(extract_flow_rate_features(statistics), FlowRateFeatures(*expected))

    def test_numerators_and_duration_control_only_the_declared_rates(self) -> None:
        for changes, expected in (
            ({"packet_count": 20}, FlowRateFeatures(4.0, 200.0, 400.0)),
            ({"captured_bytes": 1500}, FlowRateFeatures(2.0, 300.0, 400.0)),
            ({"original_bytes": 3000}, FlowRateFeatures(2.0, 200.0, 600.0)),
            ({"last_captured_at": CAPTURED_AT + timedelta(seconds=10)}, FlowRateFeatures(1.0, 100.0, 200.0)),
            ({"identity": replace(IDENTITY, protocol=17)}, FlowRateFeatures(2.0, 200.0, 400.0)),
            ({"last_captured_at": STATISTICS.last_captured_at.astimezone(timezone(timedelta(0), "UTC alias"))},
             FlowRateFeatures(2.0, 200.0, 400.0)),
        ):
            with self.subTest(changes=changes):
                self.assertEqual(extract_flow_rate_features(replace(STATISTICS, **changes)), expected)

    def test_valid_zero_duration_inputs_fail_atomically(self) -> None:
        for captured, original in ((0, 0), (0, 100), (60, 100)):
            statistics = replace(STATISTICS, captured_bytes=captured, original_bytes=original,
                                 last_captured_at=CAPTURED_AT)
            before = vars(statistics).copy()
            with self.assertRaises(FlowRateFeaturesError):
                extract_flow_rate_features(statistics)
            self.assertEqual(vars(statistics), before)

    def test_zero_duration_policy_with_constructor_validation_bypassed(self) -> None:
        for counts, expected in (
            ((0, 0, 0), FlowRateFeatures(0.0, 0.0, 0.0)),
            ((1, 0, 0), None),
            ((0, 1, 0), None),
            ((0, 0, 1), None),
            ((1, 60, 100), None),
        ):
            with self.subTest(counts=counts):
                with patch.object(FlowStatistics, "__post_init__", return_value=None):
                    statistics = FlowStatistics(IDENTITY, *counts, CAPTURED_AT, CAPTURED_AT)
                self.assertIs(type(statistics), FlowStatistics)
                before = vars(statistics).copy()
                if expected is None:
                    with self.assertRaises(FlowRateFeaturesError):
                        extract_flow_rate_features(statistics)
                else:
                    self.assertEqual(extract_flow_rate_features(statistics), expected)
                self.assertEqual(vars(statistics), before)

    def test_negative_and_nonfinite_duration_are_rejected(self) -> None:
        with patch.object(FlowStatistics, "__post_init__", return_value=None):
            backwards = FlowStatistics(IDENTITY, 1, 0, 0, CAPTURED_AT, CAPTURED_AT - timedelta(seconds=1))
        with self.assertRaises(FlowRateFeaturesError):
            extract_flow_rate_features(backwards)
        for duration in (float("nan"), float("inf"), float("-inf")):
            end = MagicMock()
            end.__sub__.return_value.total_seconds.return_value = duration
            with patch.object(FlowStatistics, "__post_init__", return_value=None):
                statistics = FlowStatistics(IDENTITY, 1, 0, 0, CAPTURED_AT, end)
            with self.assertRaises(FlowRateFeaturesError):
                extract_flow_rate_features(statistics)

    def test_overflow_and_nonfinite_calculated_rates_are_rejected(self) -> None:
        for changes in (
            {"packet_count": 10 ** 400},
            {"captured_bytes": 10 ** 400, "original_bytes": 10 ** 400},
            {"original_bytes": 10 ** 400},
            {"packet_count": 10 ** 308, "last_captured_at": CAPTURED_AT + timedelta(microseconds=1)},
        ):
            statistics = replace(STATISTICS, **changes)
            before = vars(statistics).copy()
            with self.assertRaises(FlowRateFeaturesError):
                extract_flow_rate_features(statistics)
            self.assertEqual(vars(statistics), before)

    def test_wrong_input_types_and_subclasses_are_rejected(self) -> None:
        class DerivedStatistics(FlowStatistics):
            pass

        observation = PacketObservation(CAPTURED_AT, None, 0, 0, b"", CaptureSource("test-rates"))
        feature_input = FlowFeatureInput(IDENTITY, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        size_values = {field.name: 0 for field in fields(FlowPacketSizeStatistics) if field.name != "identity"}
        size_values["packet_count"] = 1
        size_statistics = FlowPacketSizeStatistics(identity=IDENTITY, **size_values)
        size_features = PacketSizeFeatures(0, 0, 0.0, 0.0, 0.0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        for value in (
            None, True, False, 1, 1.0, {}, [], b"", SimpleNamespace(**vars(STATISTICS)),
            observation, PacketAnalysis(observation), feature_input, size_statistics, size_features,
            FlowDurationFeatures(0.0), DerivedStatistics(**vars(STATISTICS)),
        ):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    extract_flow_rate_features(cast(FlowStatistics, value))

    def test_direct_model_validates_every_field(self) -> None:
        self.assertTrue(issubclass(FlowRateFeaturesError, ValueError))
        valid = FlowRateFeatures(2.0, 100.0, 150.0)
        for field in fields(valid):
            for value in (1, True, False, None, "1.0", Decimal("1.0"), complex(1), SimpleNamespace()):
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(TypeError):
                        replace(valid, **{field.name: value})
            for value in (float("nan"), float("inf"), float("-inf"), -1.0, -0.000001):
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(FlowRateFeaturesError):
                        replace(valid, **{field.name: value})
            self.assertEqual(getattr(replace(valid, **{field.name: 0.0}), field.name), 0.0)
            self.assertEqual(getattr(replace(valid, **{field.name: 1.5}), field.name), 1.5)

    def test_exact_three_fields_are_frozen_floats_with_no_input_retention(self) -> None:
        result = extract_flow_rate_features(STATISTICS)
        names = ("packets_per_second", "captured_bytes_per_second", "original_bytes_per_second")
        self.assertEqual(tuple(field.name for field in fields(result)), names)
        self.assertEqual(set(vars(result)), set(names))
        self.assertIs(type(result), FlowRateFeatures)
        for name in names:
            value = getattr(result, name)
            self.assertIs(type(value), float)
            self.assertIsNot(value, STATISTICS)
            with self.assertRaises(FrozenInstanceError):
                setattr(result, name, 0.0)
            with self.assertRaises(FrozenInstanceError):
                delattr(result, name)

    def test_repeated_extraction_is_deterministic_and_preserves_all_input_fields(self) -> None:
        before = vars(STATISTICS).copy()
        identity_before = vars(IDENTITY).copy()
        for statistics in (STATISTICS, STATISTICS, replace(STATISTICS)):
            self.assertEqual(extract_flow_rate_features(statistics), FlowRateFeatures(2.0, 200.0, 400.0))
        self.assertEqual(vars(STATISTICS), before)
        self.assertEqual(vars(IDENTITY), identity_before)
        for name, value in before.items():
            self.assertIs(getattr(STATISTICS, name), value)
