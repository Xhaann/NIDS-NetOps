import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
from decimal import Decimal
from math import sqrt, ulp
from types import SimpleNamespace
from typing import cast

from analysis import (
    FlowIdentity,
    FlowPacketSizeStatistics,
    IPv4Packet,
    PacketAnalysis,
    PacketSizeFeatures,
    PacketSizeFeaturesError,
    TCPPacket,
    UDPPacket,
    extract_packet_size_features,
    flow_identity_from_packet,
    update_flow_packet_size_statistics,
)
from capture.packet_observation import CaptureSource, PacketObservation


OBSERVATION = PacketObservation(
    captured_at=datetime(2026, 9, 6, tzinfo=timezone.utc),
    link_type=None,
    captured_length=60,
    original_length=100,
    raw_bytes=bytes(60),
    source=CaptureSource("test-packet-size-features"),
)
IPV4_PACKET = IPv4Packet(
    version=4,
    ihl=5,
    dscp=0,
    ecn=0,
    total_length=40,
    identification=0,
    flags=0,
    fragment_offset=0,
    ttl=64,
    protocol=6,
    header_checksum=0,
    source_address=b"\x0a\x00\x00\x01",
    destination_address=b"\x0a\x00\x00\x02",
    options=b"",
    payload=bytes(20),
)
TCP_PACKET = TCPPacket(
    source_port=12345,
    destination_port=443,
    sequence_number=0,
    acknowledgment_number=0,
    data_offset=5,
    reserved_bits=0,
    ns=False,
    cwr=False,
    ece=False,
    urg=False,
    ack=False,
    psh=False,
    rst=False,
    syn=False,
    fin=False,
    window_size=0,
    checksum=0,
    urgent_pointer=0,
    options=b"",
    payload=b"",
)
UDP_PACKET = UDPPacket(12345, 443, 8, 0, b"")
TCP_ANALYSIS = PacketAnalysis(OBSERVATION, ipv4=IPV4_PACKET, tcp=TCP_PACKET)
UDP_ANALYSIS = PacketAnalysis(
    OBSERVATION,
    ipv4=replace(IPV4_PACKET, protocol=17, total_length=28, payload=bytes(8)),
    udp=UDP_PACKET,
)
ANALYSES = ((TCP_ANALYSIS, "tcp"), (UDP_ANALYSIS, "udp"))


def analysis_with_lengths(base: PacketAnalysis, captured: int, original: int, reverse: bool = False) -> PacketAnalysis:
    packet = replace(base, observation=replace(OBSERVATION, captured_length=captured,
                                              original_length=original, raw_bytes=bytes(captured)))
    if reverse:
        ipv4 = cast(IPv4Packet, base.ipv4)
        layer = "tcp" if base.tcp is not None else "udp"
        transport = getattr(base, layer)
        packet = replace(packet, ipv4=replace(ipv4, source_address=ipv4.destination_address,
                                             destination_address=ipv4.source_address),
                         **{layer: replace(transport, source_port=transport.destination_port,
                                           destination_port=transport.source_port)})
    return packet


class PacketSizeFeaturesTests(unittest.TestCase):
    def setUp(self) -> None:
        identity = flow_identity_from_packet(TCP_ANALYSIS)
        current = None
        for captured, original, reverse in ((10, 20, False), (20, 40, False), (30, 60, True)):
            current = update_flow_packet_size_statistics(
                current, analysis_with_lengths(TCP_ANALYSIS, captured, original, reverse), identity)
        self.statistics = cast(FlowPacketSizeStatistics, current)
        self.features = extract_packet_size_features(self.statistics)

    def test_accumulated_examples_use_population_statistics(self) -> None:
        result = self.features
        self.assertEqual((result.min_captured_length, result.max_captured_length), (10, 30))
        self.assertEqual((result.min_original_length, result.max_original_length), (20, 60))
        self.assertEqual(result.mean_captured_length, 20.0)
        self.assertEqual(result.mean_original_length, 40.0)
        self.assertAlmostEqual(result.variance_captured_length, 200 / 3)
        self.assertAlmostEqual(result.variance_original_length, 800 / 3)
        self.assertAlmostEqual(result.standard_deviation_captured_length, sqrt(200 / 3))
        self.assertAlmostEqual(result.standard_deviation_original_length, sqrt(800 / 3))
        self.assertEqual(result.standard_deviation_captured_length, sqrt(result.variance_captured_length))
        self.assertEqual(result.standard_deviation_original_length, sqrt(result.variance_original_length))
        self.assertNotEqual(result.variance_captured_length, 100.0)
        self.assertEqual(result.forward_mean_captured_length, 15.0)
        self.assertEqual(result.reverse_mean_captured_length, 30.0)
        self.assertEqual(result.forward_variance_captured_length, 25.0)
        self.assertEqual(result.reverse_variance_captured_length, 0.0)

    def test_repeated_lengths_and_unused_directions_have_exact_zero_variance(self) -> None:
        identity = self.statistics.identity
        for reverse in (False, True):
            current = None
            for count in range(3):
                current = update_flow_packet_size_statistics(
                    current, analysis_with_lengths(TCP_ANALYSIS, 10, 10, reverse), identity)
            result = extract_packet_size_features(cast(FlowPacketSizeStatistics, current))
            self.assertEqual(result.mean_captured_length, 10.0)
            self.assertEqual(result.mean_original_length, 10.0)
            self.assertEqual(result.variance_captured_length, 0.0)
            self.assertEqual(result.variance_original_length, 0.0)
            self.assertEqual(result.standard_deviation_captured_length, 0.0)
            self.assertEqual(result.standard_deviation_original_length, 0.0)
            used, unused = ("reverse", "forward") if reverse else ("forward", "reverse")
            self.assertEqual(getattr(result, f"{used}_mean_captured_length"), 10.0)
            self.assertEqual(getattr(result, f"{used}_variance_captured_length"), 0.0)
            self.assertEqual(getattr(result, f"{unused}_mean_captured_length"), 0.0)
            self.assertEqual(getattr(result, f"{unused}_variance_captured_length"), 0.0)
        zero = update_flow_packet_size_statistics(
            None, analysis_with_lengths(TCP_ANALYSIS, 0, 0), identity)
        self.assertTrue(all(value == 0 for value in vars(extract_packet_size_features(zero)).values()))

    def test_nonterminating_mean_and_variance_use_unrounded_python_arithmetic(self) -> None:
        current = None
        for length in (1, 2, 4):
            current = update_flow_packet_size_statistics(
                current, analysis_with_lengths(TCP_ANALYSIS, length, length), self.statistics.identity)
        result = extract_packet_size_features(cast(FlowPacketSizeStatistics, current))
        expected_mean = (1 + 2 + 4) / 3
        expected_variance = (1 * 1 + 2 * 2 + 4 * 4) / 3 - expected_mean * expected_mean
        self.assertAlmostEqual(result.mean_captured_length, expected_mean)
        self.assertEqual(result.mean_captured_length, expected_mean)
        self.assertEqual(result.mean_original_length, expected_mean)
        self.assertEqual(result.forward_mean_captured_length, expected_mean)
        self.assertAlmostEqual(result.variance_captured_length, expected_variance)
        self.assertEqual(result.variance_captured_length, expected_variance)
        self.assertEqual(result.variance_original_length, expected_variance)
        self.assertEqual(result.forward_variance_captured_length, expected_variance)
        self.assertEqual(result.standard_deviation_captured_length, sqrt(expected_variance))
        self.assertNotEqual(result.mean_captured_length, 2.333333)

    def test_global_and_directional_values_remain_independent(self) -> None:
        independent = replace(self.statistics, packet_count=4, captured_bytes=100, original_bytes=200,
                              sum_captured_length_squares=3000, sum_original_length_squares=12000,
                              min_captured_length=7, max_captured_length=91,
                              min_original_length=9, max_original_length=99)
        result = extract_packet_size_features(independent)
        self.assertEqual((result.min_captured_length, result.max_captured_length,
                          result.min_original_length, result.max_original_length), (7, 91, 9, 99))
        self.assertEqual(result.mean_captured_length, 25.0)
        self.assertEqual(result.mean_original_length, 50.0)
        self.assertEqual(result.variance_captured_length, 125.0)
        self.assertEqual(result.variance_original_length, 500.0)
        self.assertEqual(result.forward_mean_captured_length, 15.0)
        self.assertEqual(result.forward_variance_captured_length, 25.0)
        self.assertEqual(result.reverse_mean_captured_length, 30.0)
        self.assertEqual(result.reverse_variance_captured_length, 0.0)
        directional_change = replace(independent, forward_packet_count=1, forward_captured_bytes=15,
                                     forward_sum_captured_length_squares=225)
        changed = extract_packet_size_features(directional_change)
        self.assertEqual(changed.forward_variance_captured_length, 0.0)
        for field in fields(result):
            if not field.name.startswith("forward_"):
                self.assertEqual(getattr(changed, field.name), getattr(result, field.name))

    def test_mathematically_zero_variance_roundoff_is_corrected_within_ulp_bound(self) -> None:
        length = 2 ** 53 + 3
        count = 3
        total = count * length
        squares = count * length * length
        mean = total / count
        second_moment = squares / count
        raw_variance = second_moment - mean * mean
        bound = ulp(second_moment) + ulp(mean * mean) + ulp(mean) * (2 * abs(mean) + ulp(mean))
        self.assertEqual(count * squares - total * total, 0)
        self.assertLess(raw_variance, 0.0)
        self.assertLessEqual(-raw_variance, bound)
        changes = {}
        for prefix in ("", "forward_", "reverse_"):
            changes[prefix + "packet_count"] = count
            for kind in ("captured", "original"):
                changes[f"{prefix}{kind}_bytes"] = total
                changes[f"{prefix}min_{kind}_length"] = length
                changes[f"{prefix}max_{kind}_length"] = length
                changes[f"{prefix}sum_{kind}_length_squares"] = squares
        statistics = replace(self.statistics, **changes)
        result = extract_packet_size_features(statistics)
        for name in ("variance_captured_length", "variance_original_length",
                     "forward_variance_captured_length", "reverse_variance_captured_length",
                     "standard_deviation_captured_length", "standard_deviation_original_length"):
            self.assertEqual(getattr(result, name), 0.0)
        invalid = replace(statistics, sum_captured_length_squares=squares - count * 2 ** 58)
        with self.assertRaises(PacketSizeFeaturesError):
            extract_packet_size_features(invalid)

    def test_materially_negative_or_unrepresentable_moments_are_rejected(self) -> None:
        for name in ("sum_captured_length_squares", "sum_original_length_squares",
                     "forward_sum_captured_length_squares", "reverse_sum_captured_length_squares"):
            with self.subTest(field=name):
                invalid = replace(self.statistics, **{name: 0})
                before = vars(invalid).copy()
                with self.assertRaises(PacketSizeFeaturesError):
                    extract_packet_size_features(invalid)
                self.assertEqual(vars(invalid), before)
        for changes in (
            {"captured_bytes": 10 ** 400, "original_bytes": 10 ** 400},
            {"captured_bytes": 10 ** 200, "original_bytes": 10 ** 200},
            {"sum_captured_length_squares": 10 ** 400},
        ):
            with self.assertRaises(PacketSizeFeaturesError):
                extract_packet_size_features(replace(self.statistics, **changes))

    def test_exact_fourteen_numeric_fields_are_frozen_and_retain_no_input(self) -> None:
        names = (
            "min_captured_length", "max_captured_length", "mean_captured_length",
            "variance_captured_length", "standard_deviation_captured_length", "min_original_length",
            "max_original_length", "mean_original_length", "variance_original_length",
            "standard_deviation_original_length", "forward_mean_captured_length", "reverse_mean_captured_length",
            "forward_variance_captured_length", "reverse_variance_captured_length",
        )
        self.assertEqual(tuple(field.name for field in fields(self.features)), names)
        self.assertEqual(set(vars(self.features)), set(names))
        for name in names:
            value = getattr(self.features, name)
            expected_type = int if name.startswith(("min_", "max_")) else float
            self.assertIs(type(value), expected_type)
            self.assertIsNot(value, self.statistics)
            with self.assertRaises(FrozenInstanceError):
                setattr(self.features, name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(self.features, name)

    def test_wrong_input_types_are_rejected(self) -> None:
        for value in (None, True, False, 1, 1.0, b"", {}, [], TCP_ANALYSIS, OBSERVATION,
                      self.statistics.identity, SimpleNamespace(**vars(self.statistics))):
            with self.assertRaises(TypeError):
                extract_packet_size_features(cast(FlowPacketSizeStatistics, value))

    def test_direct_model_types_values_and_ordering_are_validated(self) -> None:
        valid = PacketSizeFeatures(10, 30, 20.0, 4.0, 2.0, 20, 60, 40.0, 9.0, 3.0,
                                   15.0, 30.0, 25.0, 0.0)
        self.assertTrue(issubclass(PacketSizeFeaturesError, ValueError))
        for field in fields(valid):
            integer = field.name.startswith(("min_", "max_"))
            wrong = (True, False, None, "1", Decimal("1"), SimpleNamespace(), 1.0 if integer else 1)
            for value in wrong:
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(TypeError):
                        replace(valid, **{field.name: value})
            invalid_values = (-1,) if integer else (-1.0, float("nan"), float("inf"), float("-inf"))
            for value in invalid_values:
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(PacketSizeFeaturesError):
                        replace(valid, **{field.name: value})
        for changes in ({"min_captured_length": 31}, {"min_original_length": 61}):
            with self.assertRaises(PacketSizeFeaturesError):
                replace(valid, **changes)

    def test_repeated_extraction_is_deterministic_and_preserves_complete_input(self) -> None:
        before = vars(self.statistics).copy()
        identity_before = vars(self.statistics.identity).copy()
        for statistics in (self.statistics, self.statistics, replace(self.statistics)):
            self.assertEqual(extract_packet_size_features(statistics), self.features)
        self.assertEqual(vars(self.statistics), before)
        self.assertEqual(vars(self.statistics.identity), identity_before)
        for name, value in before.items():
            self.assertIs(getattr(self.statistics, name), value)
