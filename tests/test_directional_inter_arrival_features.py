import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from math import isfinite, nextafter, sqrt, ulp
from types import SimpleNamespace
from unittest.mock import Mock, patch

from analysis import (
    DirectionalInterArrivalFeatures,
    DirectionalInterArrivalFeaturesError,
    DirectionalInterArrivalStatistics,
    FlowIdentity,
    IPv4Packet,
    PacketAnalysis,
    TCPPacket,
    extract_directional_inter_arrival_features,
    update_directional_inter_arrival_statistics,
)
from capture import CaptureSource, PacketObservation


IDENTITY = FlowIdentity(b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", 12345, 443, 6)
TIMESTAMP = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
OBSERVATION = PacketObservation(
    TIMESTAMP, None, 3, 3, b"abc", CaptureSource("test-directional-inter-arrival-features")
)
IPV4 = IPv4Packet(
    version=4, ihl=5, dscp=0, ecn=0, total_length=40, identification=0, flags=0,
    fragment_offset=0, ttl=64, protocol=6, header_checksum=0,
    source_address=IDENTITY.source_address, destination_address=IDENTITY.destination_address,
    options=b"", payload=bytes(20),
)
TCP = TCPPacket(
    source_port=IDENTITY.source_port, destination_port=IDENTITY.destination_port,
    sequence_number=0, acknowledgment_number=0, data_offset=5, reserved_bits=0,
    ns=False, cwr=False, ece=False, urg=False, ack=False, psh=False, rst=False,
    syn=False, fin=False, window_size=0, checksum=0, urgent_pointer=0,
    options=b"", payload=b"",
)
ANALYSIS = PacketAnalysis(OBSERVATION, ipv4=IPV4, tcp=TCP)


def packet_at(seconds: float, reverse: bool = False) -> PacketAnalysis:
    packet = replace(
        ANALYSIS,
        observation=replace(OBSERVATION, captured_at=TIMESTAMP + timedelta(seconds=seconds)),
    )
    if not reverse:
        return packet
    return replace(
        packet,
        ipv4=replace(
            IPV4,
            source_address=IPV4.destination_address,
            destination_address=IPV4.source_address,
        ),
        tcp=replace(
            TCP,
            source_port=TCP.destination_port,
            destination_port=TCP.source_port,
        ),
    )


def statistics_for(
    forward: tuple[float, ...],
    reverse: tuple[float, ...],
    forward_observed: bool = True,
    reverse_observed: bool = True,
) -> DirectionalInterArrivalStatistics:
    return DirectionalInterArrivalStatistics(
        identity=IDENTITY,
        packet_count=len(forward) + len(reverse) + int(forward_observed) + int(reverse_observed),
        first_captured_at=TIMESTAMP,
        last_captured_at=TIMESTAMP,
        last_forward_captured_at=TIMESTAMP if forward_observed else None,
        last_reverse_captured_at=TIMESTAMP if reverse_observed else None,
        forward_inter_arrival_count=len(forward),
        reverse_inter_arrival_count=len(reverse),
        forward_inter_arrival_sum_seconds=sum(forward, 0.0),
        reverse_inter_arrival_sum_seconds=sum(reverse, 0.0),
        forward_inter_arrival_sum_seconds_squared=sum((value * value for value in forward), 0.0),
        reverse_inter_arrival_sum_seconds_squared=sum((value * value for value in reverse), 0.0),
        forward_min_inter_arrival_seconds=min(forward, default=0.0),
        forward_max_inter_arrival_seconds=max(forward, default=0.0),
        reverse_min_inter_arrival_seconds=min(reverse, default=0.0),
        reverse_max_inter_arrival_seconds=max(reverse, default=0.0),
    )


class DirectionalInterArrivalFeaturesTests(unittest.TestCase):
    def assert_unchanged_failure(self, statistics: DirectionalInterArrivalStatistics) -> None:
        before = vars(statistics).copy()
        with self.assertRaises(DirectionalInterArrivalFeaturesError):
            extract_directional_inter_arrival_features(statistics)
        self.assertEqual(vars(statistics), before)

    def test_directional_lifecycle_and_unavailable_values(self) -> None:
        scenarios = (
            (((0, False),), (None,) * 10),
            (((0, False), (1, False)), (1.0, 0.0, 0.0, 1.0, 1.0) + (None,) * 5),
            (((0, True), (1, True)), (None,) * 5 + (1.0, 0.0, 0.0, 1.0, 1.0)),
            (((0, False), (1, True)), (None,) * 10),
            (((0, False), (1, True), (3, False)), (3.0, 0.0, 0.0, 3.0, 3.0) + (None,) * 5),
            (((0, False), (1, True), (3, True)), (None,) * 5 + (2.0, 0.0, 0.0, 2.0, 2.0)),
            (((0, False), (1, True), (3, False), (5, True)),
             (3.0, 0.0, 0.0, 3.0, 3.0, 4.0, 0.0, 0.0, 4.0, 4.0)),
        )
        for sequence, expected in scenarios:
            with self.subTest(sequence=sequence):
                current = None
                for seconds, reverse in sequence:
                    current = update_directional_inter_arrival_statistics(
                        current, packet_at(seconds, reverse), IDENTITY
                    )
                result = extract_directional_inter_arrival_features(current)
                self.assertEqual(tuple(vars(result).values()), expected)

    def test_known_population_features_remain_independent_by_direction(self) -> None:
        statistics = statistics_for((1.0, 2.0, 4.0), (0.0, 3.0))
        result = extract_directional_inter_arrival_features(statistics)
        forward_mean = 7.0 / 3.0
        forward_variance = 21.0 / 3.0 - forward_mean * forward_mean
        self.assertEqual(result, DirectionalInterArrivalFeatures(
            forward_mean, forward_variance, sqrt(forward_variance), 1.0, 4.0,
            1.5, 2.25, 1.5, 0.0, 3.0,
        ))
        self.assertNotEqual(
            result.forward_mean_inter_arrival_seconds,
            result.reverse_mean_inter_arrival_seconds,
        )

    def test_zero_second_intervals_are_observed_values_not_unavailable_values(self) -> None:
        statistics = statistics_for((0.0, 0.0), (), reverse_observed=False)
        result = extract_directional_inter_arrival_features(statistics)
        self.assertEqual(tuple(vars(result).values()), (0.0,) * 5 + (None,) * 5)
        for value in tuple(vars(result).values())[:5]:
            self.assertIs(type(value), float)

    def test_fractional_intervals_use_unrounded_population_formulas(self) -> None:
        statistics = statistics_for((0.125, 0.375), (0.000001, 0.000003))
        result = extract_directional_inter_arrival_features(statistics)
        reverse_mean = (
            statistics.reverse_inter_arrival_sum_seconds
            / statistics.reverse_inter_arrival_count
        )
        reverse_variance = (
            statistics.reverse_inter_arrival_sum_seconds_squared
            / statistics.reverse_inter_arrival_count
            - reverse_mean * reverse_mean
        )
        self.assertEqual(result, DirectionalInterArrivalFeatures(
            0.25, 0.015625, 0.125, 0.125, 0.375,
            reverse_mean, reverse_variance, sqrt(reverse_variance), 0.000001, 0.000003,
        ))

    def test_ulp_cancellation_policy_matches_global_inter_arrival_features(self) -> None:
        statistics = statistics_for((0.1, 0.1, 0.1), (), reverse_observed=False)
        mean = statistics.forward_inter_arrival_sum_seconds / statistics.forward_inter_arrival_count
        second_moment = (
            statistics.forward_inter_arrival_sum_seconds_squared
            / statistics.forward_inter_arrival_count
        )
        variance = second_moment - mean * mean
        mean_error = ulp(mean)
        bound = (
            ulp(second_moment)
            + ulp(mean * mean)
            + mean_error * (2 * abs(mean) + mean_error)
        )
        self.assertLess(variance, 0.0)
        self.assertLessEqual(-variance, bound)
        result = extract_directional_inter_arrival_features(statistics)
        self.assertEqual(result.forward_variance_inter_arrival_seconds, 0.0)
        self.assertEqual(result.forward_standard_deviation_inter_arrival_seconds, 0.0)
        unit = statistics_for((1.0,), (), reverse_observed=False)
        positive = replace(
            unit,
            forward_inter_arrival_sum_seconds_squared=nextafter(1.0, 2.0),
        )
        self.assertEqual(
            extract_directional_inter_arrival_features(positive)
            .forward_variance_inter_arrival_seconds,
            ulp(1.0),
        )
        self.assert_unchanged_failure(replace(
            unit,
            forward_inter_arrival_sum_seconds_squared=1.0 - 8 * ulp(1.0),
        ))

    def test_exact_input_type_is_required(self) -> None:
        class DerivedStatistics(DirectionalInterArrivalStatistics):
            pass

        statistics = statistics_for((1.0,), (), reverse_observed=False)
        for value in (
            None, True, 1, 1.0, "statistics", {}, [],
            SimpleNamespace(**vars(statistics)), Mock(spec=DirectionalInterArrivalStatistics),
            DerivedStatistics(**vars(statistics)),
        ):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    extract_directional_inter_arrival_features(value)

    def test_accumulated_roundoff_is_bounded_independently_by_direction(self) -> None:
        for forward, reverse in ((0.1, 0.3), (0.3, 0.000001)):
            with self.subTest(forward=forward, reverse=reverse):
                statistics = statistics_for((forward,) * 500, (reverse,) * 500)
                result = extract_directional_inter_arrival_features(statistics)
                for direction, interval in (("forward", forward), ("reverse", reverse)):
                    self.assertAlmostEqual(getattr(result, direction + "_mean_inter_arrival_seconds") / interval, 1.0)
                    variance = getattr(result, direction + "_variance_inter_arrival_seconds")
                    self.assertAlmostEqual(variance / interval ** 2, 0.0)
                    self.assertGreaterEqual(variance, 0.0)
                    name = direction + "_inter_arrival_sum_seconds_squared"
                    self.assert_unchanged_failure(replace(statistics, **{name: getattr(statistics, name) * 0.9}))

    def test_malformed_raw_counts_aggregates_and_outputs_are_rejected(self) -> None:
        valid = statistics_for((1.0, 2.0), (3.0,))
        malformed_cases = (
            ({"packet_count": valid.packet_count + 1}, DirectionalInterArrivalFeaturesError),
            ({"forward_inter_arrival_count": -1}, DirectionalInterArrivalFeaturesError),
            ({"reverse_inter_arrival_count": True}, TypeError),
            ({"forward_inter_arrival_sum_seconds": -1.0}, DirectionalInterArrivalFeaturesError),
            ({"forward_inter_arrival_sum_seconds_squared": float("inf")},
             DirectionalInterArrivalFeaturesError),
            ({"reverse_min_inter_arrival_seconds": float("nan")},
             DirectionalInterArrivalFeaturesError),
            ({"reverse_min_inter_arrival_seconds": 4.0,
              "reverse_max_inter_arrival_seconds": 3.0}, DirectionalInterArrivalFeaturesError),
        )
        for changes, error in malformed_cases:
            with self.subTest(changes=changes):
                with patch.object(DirectionalInterArrivalStatistics, "__post_init__", return_value=None):
                    malformed = replace(valid, **changes)
                before = vars(malformed).copy()
                with self.assertRaises(error):
                    extract_directional_inter_arrival_features(malformed)
                self.assertEqual(vars(malformed), before)
        empty_reverse = statistics_for((1.0,), (), reverse_observed=False)
        with patch.object(DirectionalInterArrivalStatistics, "__post_init__", return_value=None):
            nonzero_empty = replace(empty_reverse, reverse_inter_arrival_sum_seconds=1.0)
        self.assert_unchanged_failure(nonzero_empty)
        self.assert_unchanged_failure(replace(
            statistics_for((1.0,), (), reverse_observed=False),
            forward_inter_arrival_sum_seconds_squared=0.5,
        ))
        for value in (float("inf"), float("nan")):
            with patch("analysis.directional_inter_arrival_features.sqrt", return_value=value):
                self.assert_unchanged_failure(valid)

    def test_direct_model_requires_complete_finite_nonnegative_optional_float_groups(self) -> None:
        self.assertTrue(issubclass(DirectionalInterArrivalFeaturesError, ValueError))
        unavailable_reverse = DirectionalInterArrivalFeatures(
            2.0, 0.25, 0.5, 1.5, 2.5,
            None, None, None, None, None,
        )
        with self.assertRaises(DirectionalInterArrivalFeaturesError):
            replace(unavailable_reverse, reverse_mean_inter_arrival_seconds=1.0)
        valid = DirectionalInterArrivalFeatures(
            2.0, 0.25, 0.5, 1.5, 2.5,
            3.0, 1.0, 1.0, 2.0, 4.0,
        )
        for field in fields(valid):
            for value in (True, False, 0, 1, Decimal("1.0"), "1.0", complex(1)):
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(TypeError):
                        replace(valid, **{field.name: value})
            for value in (-1.0, float("inf"), float("-inf"), float("nan")):
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(DirectionalInterArrivalFeaturesError):
                        replace(valid, **{field.name: value})
        with self.assertRaises(DirectionalInterArrivalFeaturesError):
            replace(valid, forward_min_inter_arrival_seconds=3.0)

    def test_exact_frozen_field_order_has_no_identity_source_or_hidden_state(self) -> None:
        result = extract_directional_inter_arrival_features(statistics_for((1.0,), (2.0,)))
        names = (
            "forward_mean_inter_arrival_seconds",
            "forward_variance_inter_arrival_seconds",
            "forward_standard_deviation_inter_arrival_seconds",
            "forward_min_inter_arrival_seconds",
            "forward_max_inter_arrival_seconds",
            "reverse_mean_inter_arrival_seconds",
            "reverse_variance_inter_arrival_seconds",
            "reverse_standard_deviation_inter_arrival_seconds",
            "reverse_min_inter_arrival_seconds",
            "reverse_max_inter_arrival_seconds",
        )
        self.assertEqual(tuple(field.name for field in fields(result)), names)
        self.assertEqual(tuple(vars(result)), names)
        self.assertFalse(hasattr(result, "identity"))
        for name in names:
            value = getattr(result, name)
            self.assertIn(type(value), (float, type(None)))
            if value is not None:
                self.assertTrue(isfinite(value))
            with self.assertRaises(FrozenInstanceError):
                setattr(result, name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(result, name)

    def test_repeated_extraction_is_deterministic_and_preserves_source_statistics(self) -> None:
        statistics = statistics_for((1.0, 2.0, 4.0), (0.0, 3.0))
        before = vars(statistics).copy()
        first = extract_directional_inter_arrival_features(statistics)
        second = extract_directional_inter_arrival_features(statistics)
        third = extract_directional_inter_arrival_features(replace(statistics))
        self.assertEqual(first, second)
        self.assertEqual(second, third)
        self.assertIsNot(first, second)
        self.assertEqual(vars(statistics), before)
        for name, value in before.items():
            self.assertIs(getattr(statistics, name), value)
