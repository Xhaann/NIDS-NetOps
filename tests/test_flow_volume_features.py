import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import cast

from analysis import (
    DirectionalFlowStatistics,
    FlowDirection,
    FlowFeatureInput,
    FlowIdentity,
    FlowStatistics,
    FlowTracker,
    FlowVolumeFeatures,
    FlowVolumeFeaturesError,
    PacketAnalysis,
    extract_flow_volume_features,
)
from capture.packet_observation import CaptureSource, PacketObservation


IDENTITY = FlowIdentity(b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", 12345, 443, 6)
INPUT = FlowFeatureInput(IDENTITY, 10, 100, 200, 2, 3, 25, 50, 50, 125)


class FlowVolumeFeaturesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.features = FlowVolumeFeatures(10, 100, 200, 2, 3, 25, 50, 50, 125,
                                           0.2, 0.3, 0.25, 0.5, 0.25, 0.625, 0.5)

    def test_copied_values_and_all_ratios_use_explicit_unreconciled_totals(self) -> None:
        result = extract_flow_volume_features(INPUT)
        self.assertEqual(result, self.features)
        for field in fields(FlowFeatureInput):
            if field.name != "identity":
                self.assertEqual(getattr(result, field.name), getattr(INPUT, field.name))
        for name in ("packet_count", "captured_bytes", "original_bytes"):
            self.assertNotEqual(getattr(result, name),
                                getattr(result, f"forward_{name}") + getattr(result, f"reverse_{name}"))
        overlapping = replace(INPUT, forward_packet_count=8, reverse_packet_count=8,
                              forward_captured_bytes=80, reverse_captured_bytes=80,
                              forward_original_bytes=180, reverse_original_bytes=180)
        self.assertEqual(extract_flow_volume_features(overlapping),
                         FlowVolumeFeatures(10, 100, 200, 8, 8, 80, 80, 180, 180,
                                            0.8, 0.8, 0.8, 0.8, 0.9, 0.9, 0.5))

    def test_all_zero_input_and_independent_zero_denominators(self) -> None:
        zero = FlowFeatureInput(IDENTITY, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        self.assertEqual(extract_flow_volume_features(zero),
                         FlowVolumeFeatures(0, 0, 0, 0, 0, 0, 0, 0, 0,
                                            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0))
        cases = (
            (replace(INPUT, packet_count=0),
             replace(self.features, packet_count=0, forward_packet_ratio=0.0, reverse_packet_ratio=0.0)),
            (replace(INPUT, captured_bytes=0),
             replace(self.features, captured_bytes=0, forward_captured_byte_ratio=0.0,
                     reverse_captured_byte_ratio=0.0, capture_ratio=0.0)),
            (replace(INPUT, captured_bytes=0, original_bytes=0),
             replace(self.features, captured_bytes=0, original_bytes=0, forward_captured_byte_ratio=0.0,
                     reverse_captured_byte_ratio=0.0, forward_original_byte_ratio=0.0,
                     reverse_original_byte_ratio=0.0, capture_ratio=0.0)),
        )
        for input_data, expected in cases:
            with self.subTest(input_data=input_data):
                self.assertEqual(extract_flow_volume_features(input_data), expected)

    def test_forward_only_reverse_only_and_equal_capture_boundaries(self) -> None:
        for input_data, expected in (
            (FlowFeatureInput(IDENTITY, 1, 1, 1, 1, 0, 1, 0, 1, 0),
             FlowVolumeFeatures(1, 1, 1, 1, 0, 1, 0, 1, 0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0)),
            (FlowFeatureInput(IDENTITY, 1, 1, 1, 0, 1, 0, 1, 0, 1),
             FlowVolumeFeatures(1, 1, 1, 0, 1, 0, 1, 0, 1, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 1.0)),
        ):
            with self.subTest(input_data=input_data):
                self.assertEqual(extract_flow_volume_features(input_data), expected)

    def test_fractional_ratios_are_not_rounded(self) -> None:
        input_data = FlowFeatureInput(IDENTITY, 3, 3, 9, 1, 2, 1, 2, 3, 6)
        result = extract_flow_volume_features(input_data)
        for name in ("forward_packet_ratio", "forward_captured_byte_ratio",
                     "forward_original_byte_ratio", "capture_ratio"):
            self.assertAlmostEqual(getattr(result, name), 1 / 3)
            self.assertEqual(getattr(result, name), 1 / 3)
            self.assertNotEqual(getattr(result, name), 0.333333)
        for name in ("reverse_packet_ratio", "reverse_captured_byte_ratio", "reverse_original_byte_ratio"):
            self.assertAlmostEqual(getattr(result, name), 2 / 3)
            self.assertEqual(getattr(result, name), 2 / 3)

    def test_ratios_above_one_raise_without_clamping_or_changing_input(self) -> None:
        for changes in (
            {"forward_packet_count": 11}, {"reverse_packet_count": 11},
            {"forward_captured_bytes": 101, "forward_original_bytes": 101},
            {"reverse_captured_bytes": 101},
            {"forward_original_bytes": 201}, {"reverse_original_bytes": 201},
        ):
            with self.subTest(changes=changes):
                input_data = replace(INPUT, **changes)
                before = vars(input_data).copy()
                with self.assertRaises(FlowVolumeFeaturesError):
                    extract_flow_volume_features(input_data)
                self.assertEqual(vars(input_data), before)

    def test_only_flow_feature_input_is_accepted(self) -> None:
        timestamp = datetime(2026, 9, 6, tzinfo=timezone.utc)
        observation = PacketObservation(timestamp, None, 0, 0, b"", CaptureSource("test-volume-features"))
        statistics = FlowStatistics(IDENTITY, 1, 0, 0, timestamp, timestamp)
        directional = DirectionalFlowStatistics(IDENTITY, 0, 0, 0, 0, 0, 0)
        for value in (None, False, True, 1, 1.0, b"", {}, [], IDENTITY, statistics, directional,
                      observation, PacketAnalysis(observation), FlowTracker(), FlowDirection.FORWARD,
                      SimpleNamespace(**vars(INPUT))):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    extract_flow_volume_features(cast(FlowFeatureInput, value))

    def test_exact_sixteen_fields_are_numeric_only_and_frozen(self) -> None:
        names = (
            "packet_count", "captured_bytes", "original_bytes", "forward_packet_count",
            "reverse_packet_count", "forward_captured_bytes", "reverse_captured_bytes",
            "forward_original_bytes", "reverse_original_bytes", "forward_packet_ratio",
            "reverse_packet_ratio", "forward_captured_byte_ratio", "reverse_captured_byte_ratio",
            "forward_original_byte_ratio", "reverse_original_byte_ratio", "capture_ratio",
        )
        self.assertEqual(tuple(field.name for field in fields(self.features)), names)
        self.assertEqual(set(vars(self.features)), set(names))
        result = extract_flow_volume_features(INPUT)
        for index, name in enumerate(names):
            self.assertIs(type(getattr(result, name)), int if index < 9 else float)
            with self.assertRaises(FrozenInstanceError):
                setattr(result, name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(result, name)

    def test_direct_construction_rejects_wrong_integer_and_float_types(self) -> None:
        for field in fields(self.features):
            values = (True, False, None, "1", [], SimpleNamespace())
            values += (1,) if field.name.endswith("ratio") else (1.0,)
            for value in values:
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.features, **{field.name: value})

    def test_direct_construction_rejects_negative_nonfinite_and_out_of_range_values(self) -> None:
        self.assertTrue(issubclass(FlowVolumeFeaturesError, ValueError))
        for field in fields(self.features):
            values = (-0.1, 1.0001, float("nan"), float("inf"), float("-inf")) if field.name.endswith("ratio") else (-1,)
            for value in values:
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(FlowVolumeFeaturesError):
                        replace(self.features, **{field.name: value})

    def test_extraction_is_deterministic_and_preserves_input(self) -> None:
        before = vars(INPUT).copy()
        identity_before = vars(IDENTITY).copy()
        for input_data in (INPUT, INPUT, replace(INPUT), replace(INPUT, identity=replace(IDENTITY, protocol=17))):
            self.assertEqual(extract_flow_volume_features(input_data), self.features)
        self.assertEqual(vars(INPUT), before)
        self.assertEqual(vars(IDENTITY), identity_before)
        for name, value in before.items():
            self.assertIs(getattr(INPUT, name), value)
