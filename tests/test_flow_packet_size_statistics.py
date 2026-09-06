import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from analysis import (
    FlowDirection,
    FlowDirectionError,
    FlowIdentity,
    FlowIdentityError,
    FlowPacketSizeStatistics,
    FlowPacketSizeStatisticsError,
    IPv4Packet,
    PacketAnalysis,
    TCPPacket,
    UDPPacket,
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
    source=CaptureSource("test-packet-size-statistics"),
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


class FlowPacketSizeStatisticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = flow_identity_from_packet(TCP_ANALYSIS)
        self.current = update_flow_packet_size_statistics(None, TCP_ANALYSIS, self.identity)

    def assert_aggregates(self, model: FlowPacketSizeStatistics, prefix: str, expected: tuple[int, ...]) -> None:
        names = ("packet_count", "captured_bytes", "original_bytes", "min_captured_length",
                 "max_captured_length", "sum_captured_length_squares", "min_original_length",
                 "max_original_length", "sum_original_length_squares")
        self.assertEqual(tuple(getattr(model, prefix + name) for name in names), expected)

    def test_first_packet_in_either_direction_uses_capture_metadata(self) -> None:
        for base, layer in ANALYSES:
            for reverse in (False, True):
                with self.subTest(protocol=layer, reverse=reverse):
                    identity = flow_identity_from_packet(base)
                    analysis = analysis_with_lengths(base, 60, 100, reverse)
                    result = update_flow_packet_size_statistics(None, analysis, identity)
                    expected = (1, 60, 100, 60, 60, 3600, 100, 100, 10000)
                    self.assert_aggregates(result, "", expected)
                    self.assert_aggregates(result, "reverse_" if reverse else "forward_", expected)
                    self.assert_aggregates(result, "forward_" if reverse else "reverse_", (0,) * 9)
                    self.assertIs(result.identity, identity)
                    self.assertNotEqual(result.captured_bytes, len(cast(IPv4Packet, base.ipv4).payload))
                    self.assertNotEqual(result.captured_bytes, len(getattr(base, layer).payload))
                    self.assertNotEqual(result.original_bytes, len(analysis.observation.raw_bytes))

    def test_mixed_sequence_accumulates_exact_global_and_directional_integers(self) -> None:
        sequence = (
            (60, 100, False, (1, 60, 100, 60, 60, 3600, 100, 100, 10000),
             (1, 60, 100, 60, 60, 3600, 100, 100, 10000)),
            (100, 140, False, (2, 160, 240, 60, 100, 13600, 100, 140, 29600),
             (2, 160, 240, 60, 100, 13600, 100, 140, 29600)),
            (80, 120, True, (3, 240, 360, 60, 100, 20000, 100, 140, 44000),
             (1, 80, 120, 80, 80, 6400, 120, 120, 14400)),
            (40, 160, True, (4, 280, 520, 40, 100, 21600, 100, 160, 69600),
             (2, 120, 280, 40, 80, 8000, 120, 160, 40000)),
            (0, 20, False, (5, 280, 540, 0, 100, 21600, 20, 160, 70000),
             (3, 160, 260, 0, 100, 13600, 20, 140, 30000)),
            (120, 200, True, (6, 400, 740, 0, 120, 36000, 20, 200, 110000),
             (3, 240, 480, 40, 120, 22400, 120, 200, 80000)),
        )
        for base, layer in ANALYSES:
            current = None
            initial = None
            for captured, original, reverse, global_expected, directional_expected in sequence:
                with self.subTest(protocol=layer, count=global_expected[0]):
                    analysis = analysis_with_lengths(base, captured, original, reverse)
                    identity = flow_identity_from_packet(base)
                    old = current
                    before = None if old is None else vars(old).copy()
                    sources = (analysis, analysis.observation, identity)
                    source_values = [vars(value).copy() for value in sources]
                    current = update_flow_packet_size_statistics(old, analysis, identity)
                    self.assert_aggregates(current, "", global_expected)
                    self.assert_aggregates(current, "reverse_" if reverse else "forward_", directional_expected)
                    self.assertIs(current.identity, identity)
                    if old is not None:
                        self.assertIsNot(current, old)
                        self.assertIsNot(current.identity, old.identity)
                        self.assertEqual(vars(old), before)
                        opposite = "forward_" if reverse else "reverse_"
                        for name, value in before.items():
                            if name.startswith(opposite):
                                self.assertEqual(getattr(current, name), value)
                    else:
                        initial = current
                    for value, original_values in zip(sources, source_values):
                        self.assertEqual(vars(value), original_values)
                    self.assertEqual(current, update_flow_packet_size_statistics(old, analysis, identity))
            self.assert_aggregates(cast(FlowPacketSizeStatistics, initial), "",
                                   (1, 60, 100, 60, 60, 3600, 100, 100, 10000))

    def test_zero_length_first_packet_is_not_confused_with_unused_direction(self) -> None:
        for reverse in (False, True):
            zero = analysis_with_lengths(TCP_ANALYSIS, 0, 0, reverse)
            first = update_flow_packet_size_statistics(None, zero, self.identity)
            later = analysis_with_lengths(TCP_ANALYSIS, 60, 100, reverse)
            result = update_flow_packet_size_statistics(first, later, self.identity)
            self.assert_aggregates(result, "", (2, 60, 100, 0, 60, 3600, 0, 100, 10000))
            self.assert_aggregates(result, "reverse_" if reverse else "forward_",
                                   (2, 60, 100, 0, 60, 3600, 0, 100, 10000))
            self.assert_aggregates(result, "forward_" if reverse else "reverse_", (0,) * 9)

    def test_large_lengths_and_existing_square_totals_preserve_integer_precision(self) -> None:
        original = 2 ** 60 + 1
        packet = analysis_with_lengths(TCP_ANALYSIS, 65535, original)
        first = update_flow_packet_size_statistics(None, packet, self.identity)
        self.assertEqual(first.sum_captured_length_squares, 4294836225)
        self.assertEqual(first.sum_original_length_squares, original * original)
        supplied = replace(first, sum_captured_length_squares=2 ** 80 + 1,
                           forward_sum_captured_length_squares=2 ** 80 + 3)
        result = update_flow_packet_size_statistics(supplied, packet, self.identity)
        self.assertEqual(result.sum_captured_length_squares, 2 ** 80 + 1 + 4294836225)
        self.assertEqual(result.forward_sum_captured_length_squares, 2 ** 80 + 3 + 4294836225)
        self.assertEqual(result.sum_original_length_squares, 2 * original * original)
        self.assertEqual(result.forward_sum_original_length_squares, 2 * original * original)
        self.assertEqual(result.original_bytes, 2 * original)
        for field in fields(result):
            if field.name != "identity":
                self.assertIs(type(getattr(result, field.name)), int)

    def test_direction_calculation_is_delegated_once_per_update(self) -> None:
        for direction, prefix in ((FlowDirection.FORWARD, "forward_"), (FlowDirection.REVERSE, "reverse_")):
            for current in (None, self.current):
                with self.subTest(direction=direction, current=current):
                    identity = replace(self.identity)
                    with patch("analysis.flow_packet_size_statistics.flow_direction_from_packet",
                               return_value=direction) as direction_function:
                        result = update_flow_packet_size_statistics(current, TCP_ANALYSIS, identity)
                        direction_function.assert_called_once_with(TCP_ANALYSIS, identity)
                    self.assertIs(result.identity, identity)
                    old_count = 0 if current is None else getattr(current, prefix + "packet_count")
                    self.assertEqual(getattr(result, prefix + "packet_count"), old_count + 1)
                    other = "reverse_" if prefix == "forward_" else "forward_"
                    for field in fields(result):
                        if field.name.startswith(other):
                            self.assertEqual(getattr(result, field.name),
                                             0 if current is None else getattr(current, field.name))

    def test_failed_updates_leave_all_sources_unchanged(self) -> None:
        other = replace(self.identity, source_port=12346)
        unknown = replace(TCP_ANALYSIS, observation=replace(OBSERVATION, original_length=None))
        for current, analysis, identity, error in (
            (None, unknown, self.identity, FlowPacketSizeStatisticsError),
            (self.current, unknown, self.identity, FlowPacketSizeStatisticsError),
            (replace(self.current, identity=other), TCP_ANALYSIS, self.identity, FlowPacketSizeStatisticsError),
            (self.current, TCP_ANALYSIS, other, FlowDirectionError),
            (self.current, replace(TCP_ANALYSIS, tcp=None), self.identity, FlowIdentityError),
        ):
            objects = (analysis, analysis.observation, identity) if current is None else (
                current, analysis, analysis.observation, identity)
            before = [vars(value).copy() for value in objects]
            with self.assertRaises(error):
                update_flow_packet_size_statistics(current, analysis, identity)
            for value, original in zip(objects, before):
                self.assertEqual(vars(value), original)
        failure = FlowDirectionError("direction unavailable")
        before = vars(self.current).copy()
        with patch("analysis.flow_packet_size_statistics.flow_direction_from_packet", side_effect=failure):
            with self.assertRaises(FlowDirectionError) as raised:
                update_flow_packet_size_statistics(self.current, TCP_ANALYSIS, self.identity)
        self.assertIs(raised.exception, failure)
        self.assertEqual(vars(self.current), before)

    def test_wrong_update_argument_types_are_rejected(self) -> None:
        arguments = [self.current, TCP_ANALYSIS, self.identity]
        before = vars(self.current).copy()
        for position in range(3):
            for value in (False, 1, [], SimpleNamespace()):
                invalid = arguments.copy()
                invalid[position] = value
                with self.assertRaises(TypeError):
                    update_flow_packet_size_statistics(*invalid)
        for position in (1, 2):
            invalid = arguments.copy()
            invalid[position] = None
            with self.assertRaises(TypeError):
                update_flow_packet_size_statistics(*invalid)
        self.assertEqual(vars(self.current), before)

    def test_exact_28_fields_are_immutable_values_only(self) -> None:
        names = (
            "identity", "packet_count", "captured_bytes", "original_bytes", "min_captured_length",
            "max_captured_length", "sum_captured_length_squares", "min_original_length",
            "max_original_length", "sum_original_length_squares", "forward_packet_count",
            "reverse_packet_count", "forward_captured_bytes", "reverse_captured_bytes",
            "forward_min_captured_length", "forward_max_captured_length", "forward_sum_captured_length_squares",
            "reverse_min_captured_length", "reverse_max_captured_length", "reverse_sum_captured_length_squares",
            "forward_original_bytes", "reverse_original_bytes", "forward_min_original_length",
            "forward_max_original_length", "forward_sum_original_length_squares", "reverse_min_original_length",
            "reverse_max_original_length", "reverse_sum_original_length_squares",
        )
        result = update_flow_packet_size_statistics(self.current, TCP_ANALYSIS, self.identity)
        self.assertEqual(tuple(field.name for field in fields(result)), names)
        self.assertEqual(set(vars(result)), set(names))
        for name in names:
            value = getattr(result, name)
            self.assertIs(type(value), FlowIdentity if name == "identity" else int)
            self.assertIsNot(value, self.current)
            with self.assertRaises(FrozenInstanceError):
                setattr(result, name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(result, name)

    def test_model_rejects_wrong_types_and_negative_numbers(self) -> None:
        self.assertTrue(issubclass(FlowPacketSizeStatisticsError, ValueError))
        for value in (None, False, [], SimpleNamespace(**vars(self.identity))):
            with self.assertRaises(TypeError):
                replace(self.current, identity=value)
        for field in fields(self.current):
            if field.name == "identity":
                continue
            for value in (True, False, None, 1.0, "1", []):
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.current, **{field.name: value})
            with self.assertRaises(FlowPacketSizeStatisticsError):
                replace(self.current, **{field.name: -1})
        with self.assertRaises(FlowPacketSizeStatisticsError):
            replace(self.current, packet_count=0)

    def test_model_byte_relationships_and_all_minimum_maximum_pairs(self) -> None:
        both = update_flow_packet_size_statistics(self.current,
                                                  analysis_with_lengths(TCP_ANALYSIS, 80, 120, True), self.identity)
        for prefix in ("", "forward_", "reverse_"):
            with self.assertRaises(FlowPacketSizeStatisticsError):
                replace(both, **{prefix + "original_bytes": getattr(both, prefix + "captured_bytes") - 1})
            for kind in ("captured", "original"):
                with self.assertRaises(FlowPacketSizeStatisticsError):
                    replace(both, **{f"{prefix}min_{kind}_length": getattr(both, f"{prefix}max_{kind}_length") + 1})

    def test_unused_directions_require_zero_aggregates(self) -> None:
        reverse_first = update_flow_packet_size_statistics(None,
                        analysis_with_lengths(TCP_ANALYSIS, 60, 100, True), self.identity)
        for model, unused in ((self.current, "reverse_"), (reverse_first, "forward_")):
            for field in fields(model):
                if field.name.startswith(unused) and field.name != unused + "packet_count":
                    with self.subTest(field=field.name):
                        with self.assertRaises(FlowPacketSizeStatisticsError):
                            replace(model, **{field.name: 1})
