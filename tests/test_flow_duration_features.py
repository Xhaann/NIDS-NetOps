import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
from typing import cast

from analysis import (
    FlowDurationFeatures,
    FlowDurationFeaturesError,
    FlowFeatureInput,
    FlowIdentity,
    FlowStatistics,
    PacketAnalysis,
    extract_flow_duration_features,
)
from capture.packet_observation import CaptureSource, PacketObservation


IDENTITY = FlowIdentity(b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", 12345, 443, 6)
CAPTURED_AT = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
STATISTICS = FlowStatistics(IDENTITY, 1, 60, 100, CAPTURED_AT, CAPTURED_AT)


class FlowDurationFeaturesTests(unittest.TestCase):
    def test_zero_and_fractional_intervals_use_direct_datetime_subtraction(self) -> None:
        for interval, expected in (
            (timedelta(0), 0.0),
            (timedelta(microseconds=1), 0.000001),
            (timedelta(seconds=1, microseconds=500000), 1.5),
            (timedelta(seconds=13, microseconds=123457), 13.123457),
            (timedelta(minutes=5), 300.0),
            (timedelta(hours=1, microseconds=123457), 3600.123457),
            (timedelta(hours=7, minutes=2, microseconds=1), 25320.000001),
        ):
            with self.subTest(interval=interval):
                statistics = replace(STATISTICS, last_captured_at=CAPTURED_AT + interval)
                result = extract_flow_duration_features(statistics)
                self.assertIs(type(result), FlowDurationFeatures)
                self.assertIs(type(result.duration_seconds), float)
                self.assertEqual(result.duration_seconds, expected)
                self.assertEqual(result.duration_seconds,
                                 (statistics.last_captured_at - statistics.first_captured_at).total_seconds())

    def test_explicit_caller_conversion_to_utc_preserves_elapsed_time(self) -> None:
        local = (CAPTURED_AT + timedelta(seconds=1.5)).astimezone(timezone(timedelta(hours=5, minutes=30)))
        end = local.astimezone(timezone.utc)
        statistics = replace(STATISTICS, last_captured_at=end)
        self.assertEqual(extract_flow_duration_features(statistics).duration_seconds, 1.5)

    def test_wrong_inputs_and_flow_statistics_subclasses_are_rejected(self) -> None:
        class DerivedStatistics(FlowStatistics):
            pass

        observation = PacketObservation(CAPTURED_AT, None, 0, 0, b"", CaptureSource("test-duration"))
        feature_input = FlowFeatureInput(IDENTITY, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        for value in (
            None, False, True, 1, 1.0, b"", {}, [], observation, PacketAnalysis(observation),
            feature_input, SimpleNamespace(**vars(STATISTICS)), DerivedStatistics(**vars(STATISTICS)),
        ):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    extract_flow_duration_features(cast(FlowStatistics, value))

    def test_direct_model_rejects_wrong_types_and_invalid_numbers(self) -> None:
        self.assertTrue(issubclass(FlowDurationFeaturesError, ValueError))
        valid = FlowDurationFeatures(1.5)
        for value in (1, True, False, None, "1.0", Decimal("1.5"), [], SimpleNamespace()):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    replace(valid, duration_seconds=value)
        for value in (float("nan"), float("inf"), float("-inf"), -1.0, -0.000001):
            with self.subTest(value=value):
                with self.assertRaises(FlowDurationFeaturesError):
                    replace(valid, duration_seconds=value)
        self.assertEqual(FlowDurationFeatures(0.0).duration_seconds, 0.0)
        self.assertEqual(valid.duration_seconds, 1.5)

    def test_exact_one_field_is_frozen_and_retains_only_a_float(self) -> None:
        result = extract_flow_duration_features(STATISTICS)
        self.assertEqual(tuple(field.name for field in fields(result)), ("duration_seconds",))
        self.assertEqual(vars(result), {"duration_seconds": 0.0})
        self.assertIs(type(result.duration_seconds), float)
        self.assertIsNot(result.duration_seconds, STATISTICS)
        with self.assertRaises(FrozenInstanceError):
            result.duration_seconds = 2.0
        with self.assertRaises(FrozenInstanceError):
            del result.duration_seconds

    def test_extraction_is_deterministic_preserves_input_and_ignores_counts(self) -> None:
        statistics = replace(STATISTICS, last_captured_at=CAPTURED_AT + timedelta(seconds=1.5))
        before = vars(statistics).copy()
        identity_before = vars(statistics.identity).copy()
        for source in (
            statistics, statistics, replace(statistics),
            replace(statistics, packet_count=100, captured_bytes=1000, original_bytes=2000,
                    identity=replace(IDENTITY, protocol=17)),
        ):
            self.assertEqual(extract_flow_duration_features(source), FlowDurationFeatures(1.5))
        self.assertEqual(vars(statistics), before)
        self.assertEqual(vars(statistics.identity), identity_before)
        for name, value in before.items():
            self.assertIs(getattr(statistics, name), value)
