import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import cast

from analysis import (
    DirectionalFlowStatistics,
    FlowFeatureInput,
    FlowFeatureInputError,
    FlowIdentity,
    FlowStatistics,
    flow_feature_input_from_statistics,
)


IDENTITY = FlowIdentity(b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", 12345, 443, 6)
CAPTURED_AT = datetime(2026, 9, 6, tzinfo=timezone.utc)
STATISTICS = FlowStatistics(IDENTITY, 100, 1000, 1500, CAPTURED_AT, CAPTURED_AT)
DIRECTIONAL = DirectionalFlowStatistics(replace(IDENTITY), 2, 3, 20, 40, 30, 50)


class FlowFeatureInputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = FlowFeatureInput(IDENTITY, 100, 1000, 1500, 2, 3, 20, 40, 30, 50)

    def test_projection_preserves_authoritative_values_and_total_identity(self) -> None:
        for protocol in (6, 17):
            with self.subTest(protocol=protocol):
                identity_a = replace(IDENTITY, protocol=protocol)
                identity_b = replace(identity_a)
                statistics = replace(STATISTICS, identity=identity_a)
                directional = replace(DIRECTIONAL, identity=identity_b)
                result = flow_feature_input_from_statistics(statistics, directional)
                self.assertEqual(identity_a, identity_b)
                self.assertIsNot(identity_a, identity_b)
                self.assertIs(result.identity, identity_a)
                self.assertIsNot(result.identity, identity_b)
                self.assertEqual(vars(result), {
                    "identity": identity_a,
                    "packet_count": 100,
                    "captured_bytes": 1000,
                    "original_bytes": 1500,
                    "forward_packet_count": 2,
                    "reverse_packet_count": 3,
                    "forward_captured_bytes": 20,
                    "reverse_captured_bytes": 40,
                    "forward_original_bytes": 30,
                    "reverse_original_bytes": 50,
                })
                for name in ("packet_count", "captured_bytes", "original_bytes"):
                    self.assertEqual(getattr(result, name), getattr(statistics, name))
                    self.assertNotEqual(getattr(result, name),
                                        getattr(directional, f"forward_{name}") +
                                        getattr(directional, f"reverse_{name}"))
                same_identity = flow_feature_input_from_statistics(
                    statistics, replace(directional, identity=identity_a))
                self.assertEqual(result, same_identity)
                self.assertIs(same_identity.identity, identity_a)

    def test_projection_and_identity_failure_do_not_mutate_sources(self) -> None:
        different = replace(DIRECTIONAL, identity=replace(IDENTITY, destination_port=444))
        for directional in (DIRECTIONAL, different):
            objects = (STATISTICS, directional, STATISTICS.identity, directional.identity)
            before = [vars(value).copy() for value in objects]
            if directional is DIRECTIONAL:
                flow_feature_input_from_statistics(STATISTICS, directional)
            else:
                with self.assertRaises(FlowFeatureInputError):
                    flow_feature_input_from_statistics(STATISTICS, directional)
            for value, original in zip(objects, before):
                self.assertEqual(vars(value), original)
                for name, reference in original.items():
                    self.assertIs(getattr(value, name), reference)

    def test_projection_rejects_wrong_source_types(self) -> None:
        for value in (None, False, 1, b"", CAPTURED_AT, {}, DIRECTIONAL, SimpleNamespace(**vars(STATISTICS))):
            with self.subTest(argument="statistics", value=value):
                with self.assertRaises(TypeError):
                    flow_feature_input_from_statistics(cast(FlowStatistics, value), DIRECTIONAL)
        for value in (None, False, 1, b"", CAPTURED_AT, {}, STATISTICS, SimpleNamespace(**vars(DIRECTIONAL))):
            with self.subTest(argument="directional", value=value):
                with self.assertRaises(TypeError):
                    flow_feature_input_from_statistics(STATISTICS, cast(DirectionalFlowStatistics, value))

    def test_source_timestamps_have_no_effect_and_no_source_objects_are_retained(self) -> None:
        shifted = replace(STATISTICS, first_captured_at=CAPTURED_AT - timedelta(days=1),
                          last_captured_at=CAPTURED_AT + timedelta(days=1))
        result = flow_feature_input_from_statistics(shifted, DIRECTIONAL)
        self.assertEqual(result, flow_feature_input_from_statistics(STATISTICS, DIRECTIONAL))
        self.assertEqual(tuple(field.name for field in fields(result)), (
            "identity", "packet_count", "captured_bytes", "original_bytes",
            "forward_packet_count", "reverse_packet_count", "forward_captured_bytes",
            "reverse_captured_bytes", "forward_original_bytes", "reverse_original_bytes",
        ))
        self.assertEqual(set(vars(result)), {field.name for field in fields(result)})
        for field in fields(result):
            value = getattr(result, field.name)
            self.assertIs(type(value), FlowIdentity if field.name == "identity" else int)
            self.assertIsNot(value, shifted)
            self.assertIsNot(value, DIRECTIONAL)

    def test_model_is_frozen(self) -> None:
        for field in fields(self.model):
            with self.subTest(field=field.name):
                with self.assertRaises(FrozenInstanceError):
                    setattr(self.model, field.name, None)
                with self.assertRaises(FrozenInstanceError):
                    delattr(self.model, field.name)

    def test_model_rejects_wrong_identity_and_numeric_types(self) -> None:
        for value in (None, False, {}, b"", STATISTICS, SimpleNamespace(**vars(IDENTITY))):
            with self.assertRaises(TypeError):
                replace(self.model, identity=value)
        for field in fields(self.model):
            if field.name == "identity":
                continue
            for value in (True, False, None, 1.0, "1", [], {}, SimpleNamespace()):
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.model, **{field.name: value})

    def test_model_rejects_negative_values_and_each_original_byte_violation(self) -> None:
        self.assertTrue(issubclass(FlowFeatureInputError, ValueError))
        for field in fields(self.model):
            if field.name != "identity":
                with self.subTest(field=field.name):
                    with self.assertRaises(FlowFeatureInputError):
                        replace(self.model, **{field.name: -1})
        for name, value in (("original_bytes", 999), ("forward_original_bytes", 19),
                            ("reverse_original_bytes", 39)):
            with self.subTest(field=name):
                with self.assertRaises(FlowFeatureInputError):
                    replace(self.model, **{name: value})

    def test_zero_values_and_unreconciled_directional_totals_are_valid(self) -> None:
        zero = FlowFeatureInput(IDENTITY, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        self.assertTrue(all(getattr(zero, field.name) == 0 for field in fields(zero)
                            if field.name != "identity"))
        unequal = replace(zero, forward_packet_count=2, reverse_packet_count=3,
                          forward_captured_bytes=20, reverse_captured_bytes=40,
                          forward_original_bytes=20, reverse_original_bytes=40)
        self.assertEqual(unequal.packet_count, 0)
        self.assertEqual(unequal.captured_bytes, 0)
        self.assertEqual(unequal.original_bytes, 0)
        no_directional_packets = DirectionalFlowStatistics(IDENTITY, 0, 0, 0, 0, 0, 0)
        result = flow_feature_input_from_statistics(STATISTICS, no_directional_packets)
        self.assertEqual(result, FlowFeatureInput(IDENTITY, 100, 1000, 1500, 0, 0, 0, 0, 0, 0))
