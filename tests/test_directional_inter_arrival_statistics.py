import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone, tzinfo
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import patch

from analysis import (
    DirectionalInterArrivalStatistics,
    DirectionalInterArrivalStatisticsError,
    FlowDirection,
    FlowIdentity,
    FlowIdentityError,
    IPv4Packet,
    PacketAnalysis,
    TCPPacket,
    UDPPacket,
    flow_identity_from_packet,
    update_directional_inter_arrival_statistics,
)
from capture.packet_observation import CaptureSource, PacketObservation


TIMESTAMP = datetime(2026, 9, 6, 12, tzinfo=timezone.utc)
OBSERVATION = PacketObservation(TIMESTAMP, None, 3, None, b"abc", CaptureSource("test-directional-inter-arrival"))
IPV4 = IPv4Packet(
    version=4, ihl=5, dscp=0, ecn=0, total_length=40, identification=0, flags=0,
    fragment_offset=0, ttl=64, protocol=6, header_checksum=0,
    source_address=b"\x0a\x00\x00\x01", destination_address=b"\x0a\x00\x00\x02",
    options=b"", payload=bytes(20),
)
TCP = TCPPacket(
    source_port=12345, destination_port=443, sequence_number=0, acknowledgment_number=0,
    data_offset=5, reserved_bits=0, ns=False, cwr=False, ece=False, urg=False, ack=False,
    psh=False, rst=False, syn=False, fin=False, window_size=0, checksum=0,
    urgent_pointer=0, options=b"", payload=b"",
)
TCP_ANALYSIS = PacketAnalysis(OBSERVATION, ipv4=IPV4, tcp=TCP)
UDP_ANALYSIS = PacketAnalysis(
    OBSERVATION, ipv4=replace(IPV4, protocol=17, total_length=28, payload=bytes(8)),
    udp=UDPPacket(12345, 443, 8, 0, b""),
)
AGGREGATE_SUFFIXES = (
    "inter_arrival_sum_seconds", "inter_arrival_sum_seconds_squared",
    "min_inter_arrival_seconds", "max_inter_arrival_seconds",
)


def packet_at(offset: float, reverse: bool = False, base: PacketAnalysis = TCP_ANALYSIS) -> PacketAnalysis:
    packet = replace(base, observation=replace(OBSERVATION, captured_at=TIMESTAMP + timedelta(seconds=offset)))
    if reverse:
        layer = "tcp" if base.tcp is not None else "udp"
        transport = getattr(base, layer)
        packet = replace(
            packet,
            ipv4=replace(base.ipv4, source_address=base.ipv4.destination_address,
                         destination_address=base.ipv4.source_address),
            **{layer: replace(transport, source_port=transport.destination_port,
                              destination_port=transport.source_port)},
        )
    return packet


class NoOffset(tzinfo):
    def utcoffset(self, value: object) -> None:
        return None


class DirectionalInterArrivalStatisticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = flow_identity_from_packet(TCP_ANALYSIS)
        self.current = update_directional_inter_arrival_statistics(None, TCP_ANALYSIS, self.identity)

    def assert_atomic_failure(self, error, current, analysis, identity) -> None:
        objects = [value for value in (current, analysis, identity) if hasattr(value, "__dict__")]
        if isinstance(analysis, PacketAnalysis):
            objects.append(analysis.observation)
        before = [vars(value).copy() for value in objects]
        with self.assertRaises(error):
            update_directional_inter_arrival_statistics(current, analysis, identity)
        for value, original in zip(objects, before):
            self.assertEqual(vars(value), original)

    def test_first_packets_and_first_opposite_packets_create_no_intervals(self) -> None:
        for base in (TCP_ANALYSIS, UDP_ANALYSIS):
            for reverse in (False, True):
                packet = packet_at(0, reverse, base)
                identity = flow_identity_from_packet(packet)
                current = update_directional_inter_arrival_statistics(None, packet, identity)
                used, unused = ("reverse", "forward") if reverse else ("forward", "reverse")
                self.assertIs(current.identity, identity)
                self.assertIs(current.first_captured_at, packet.observation.captured_at)
                self.assertIs(current.last_captured_at, packet.observation.captured_at)
                self.assertIs(getattr(current, f"last_{used}_captured_at"), packet.observation.captured_at)
                self.assertIsNone(getattr(current, f"last_{unused}_captured_at"))
                self.assertEqual(current.packet_count, 1)
                opposite = packet_at(1, not reverse, base)
                result = update_directional_inter_arrival_statistics(current, opposite, identity)
                self.assertEqual(result.packet_count, 2)
                self.assertIs(getattr(result, f"last_{used}_captured_at"), packet.observation.captured_at)
                self.assertIs(getattr(result, f"last_{unused}_captured_at"), opposite.observation.captured_at)
                for value in (current, result):
                    self.assertEqual(value.forward_inter_arrival_count, 0)
                    self.assertEqual(value.reverse_inter_arrival_count, 0)
                    for direction in ("forward", "reverse"):
                        for suffix in AGGREGATE_SUFFIXES:
                            self.assertEqual(getattr(value, f"{direction}_{suffix}"), 0.0)

    def test_alternating_sequence_uses_independent_timestamps_and_correct_count_invariant(self) -> None:
        for base in (TCP_ANALYSIS, UDP_ANALYSIS):
            identity = flow_identity_from_packet(base)
            current = None
            for offset, reverse, forward_time, reverse_time, forward_values, reverse_values in (
                (0, False, 0, None, (0, 0.0, 0.0, 0.0, 0.0), (0, 0.0, 0.0, 0.0, 0.0)),
                (1, True, 0, 1, (0, 0.0, 0.0, 0.0, 0.0), (0, 0.0, 0.0, 0.0, 0.0)),
                (3, False, 3, 1, (1, 3.0, 9.0, 3.0, 3.0), (0, 0.0, 0.0, 0.0, 0.0)),
                (4, True, 3, 4, (1, 3.0, 9.0, 3.0, 3.0), (1, 3.0, 9.0, 3.0, 3.0)),
                (7, False, 7, 4, (2, 7.0, 25.0, 3.0, 4.0), (1, 3.0, 9.0, 3.0, 3.0)),
                (9, True, 7, 9, (2, 7.0, 25.0, 3.0, 4.0), (2, 8.0, 34.0, 3.0, 5.0)),
            ):
                packet = packet_at(offset, reverse, base)
                before = [vars(value).copy() for value in (packet, packet.observation, identity)]
                previous = current
                previous_before = None if previous is None else vars(previous).copy()
                supplied = identity if current is None else replace(identity)
                current = update_directional_inter_arrival_statistics(current, packet, supplied)
                self.assertIs(current.identity, identity)
                if previous is not None:
                    self.assertIsNot(supplied, identity)
                    self.assertIsNot(current, previous)
                    self.assertEqual(vars(previous), previous_before)
                    self.assertEqual(current.packet_count, previous.packet_count + 1)
                    self.assertIs(current.first_captured_at, previous.first_captured_at)
                self.assertIs(current.last_captured_at, packet.observation.captured_at)
                for direction, time, expected in (("forward", forward_time, forward_values),
                                                   ("reverse", reverse_time, reverse_values)):
                    self.assertEqual(getattr(current, f"last_{direction}_captured_at"),
                                     None if time is None else TIMESTAMP + timedelta(seconds=time))
                    values = (getattr(current, f"{direction}_inter_arrival_count"),) + tuple(
                        getattr(current, f"{direction}_{suffix}") for suffix in AGGREGATE_SUFFIXES)
                    self.assertEqual(values, expected)
                observed = int(current.last_forward_captured_at is not None) + int(current.last_reverse_captured_at is not None)
                self.assertEqual(current.forward_inter_arrival_count + current.reverse_inter_arrival_count,
                                 current.packet_count - observed)
                if offset == 7:
                    self.assertEqual(current.packet_count, 5)
                    self.assertEqual(current.forward_inter_arrival_count + current.reverse_inter_arrival_count, 3)
                for value, original in zip((packet, packet.observation, identity), before):
                    self.assertEqual(vars(value), original)

    def test_unidirectional_sequences_and_zero_intervals_preserve_actual_extrema(self) -> None:
        for reverse in (False, True):
            current = None
            direction = "reverse" if reverse else "forward"
            for offset, expected in (
                (0, (0, 0.0, 0.0, 0.0, 0.0)),
                (1, (1, 1.0, 1.0, 1.0, 1.0)),
                (3, (2, 3.0, 5.0, 1.0, 2.0)),
                (3, (3, 3.0, 5.0, 0.0, 2.0)),
                (3, (4, 3.0, 5.0, 0.0, 2.0)),
            ):
                current = update_directional_inter_arrival_statistics(current, packet_at(offset, reverse), self.identity)
                values = (getattr(current, f"{direction}_inter_arrival_count"),) + tuple(
                    getattr(current, f"{direction}_{suffix}") for suffix in AGGREGATE_SUFFIXES)
                self.assertEqual(values, expected)
                self.assertEqual(current.packet_count - 1, expected[0])
            initial = update_directional_inter_arrival_statistics(None, packet_at(0, reverse), self.identity)
            zero = update_directional_inter_arrival_statistics(initial, packet_at(0, reverse), self.identity)
            self.assertEqual(getattr(zero, f"{direction}_inter_arrival_count"), 1)
            for suffix in AGGREGATE_SUFFIXES:
                self.assertEqual(getattr(zero, f"{direction}_{suffix}"), 0.0)

    def test_fractional_microsecond_and_offset_timestamps_use_direct_subtraction(self) -> None:
        for reverse in (False, True):
            current = update_directional_inter_arrival_statistics(None, packet_at(0, reverse), self.identity)
            for seconds in (0.000001, 1.5, 2.345678):
                packet = packet_at(seconds, reverse)
                timestamp = packet.observation.captured_at.astimezone(timezone(timedelta(hours=5, minutes=30)))
                packet = replace(packet, observation=replace(packet.observation, captured_at=timestamp))
                result = update_directional_inter_arrival_statistics(current, packet, self.identity)
                direction = "reverse" if reverse else "forward"
                interval = (timestamp - TIMESTAMP).total_seconds()
                self.assertEqual(getattr(result, f"{direction}_inter_arrival_sum_seconds"), interval)
                self.assertEqual(getattr(result, f"{direction}_inter_arrival_sum_seconds_squared"), interval * interval)
                self.assertIs(getattr(result, f"last_{direction}_captured_at"), timestamp)
                self.assertIs(result.last_captured_at, timestamp)

    def test_identity_and_direction_delegate_once_and_returned_direction_controls_updates(self) -> None:
        for direction, prefix in ((FlowDirection.FORWARD, "forward"), (FlowDirection.REVERSE, "reverse")):
            current = None
            for offset in (0, 2):
                packet = packet_at(offset)
                with patch("analysis.directional_inter_arrival_statistics.flow_identity_from_packet",
                           return_value=replace(self.identity)) as identity_factory:
                    with patch("analysis.directional_inter_arrival_statistics.flow_direction_from_packet",
                               return_value=direction) as direction_factory:
                        current = update_directional_inter_arrival_statistics(current, packet, self.identity)
                        identity_factory.assert_called_once_with(packet)
                        direction_factory.assert_called_once_with(packet, self.identity)
                self.assertIs(current.identity, self.identity)
            self.assertEqual(getattr(current, f"{prefix}_inter_arrival_count"), 1)
            self.assertEqual(getattr(current, f"{prefix}_inter_arrival_sum_seconds"), 2.0)
            opposite = "reverse" if prefix == "forward" else "forward"
            self.assertIsNone(getattr(current, f"last_{opposite}_captured_at"))

    def test_identity_mismatch_and_unsupported_analysis_fail_atomically(self) -> None:
        other = replace(self.identity, source_port=12346)
        different = replace(TCP_ANALYSIS, tcp=replace(TCP, source_port=12346))
        for current, analysis, identity in (
            (None, TCP_ANALYSIS, other), (self.current, TCP_ANALYSIS, other),
            (self.current, different, self.identity), (self.current, different, other),
            (replace(self.current, identity=other), TCP_ANALYSIS, self.identity),
        ):
            self.assert_atomic_failure(DirectionalInterArrivalStatisticsError, current, analysis, identity)
        for analysis in (
            replace(TCP_ANALYSIS, ipv4=None), replace(TCP_ANALYSIS, tcp=None),
            replace(TCP_ANALYSIS, ipv4=replace(IPV4, protocol=1), tcp=None),
            replace(TCP_ANALYSIS, ipv4=replace(IPV4, protocol=253), tcp=None),
        ):
            self.assert_atomic_failure(FlowIdentityError, self.current, analysis, self.identity)

    def test_global_and_same_direction_out_of_order_packets_fail_atomically(self) -> None:
        for reverse in (False, True):
            current = update_directional_inter_arrival_statistics(None, packet_at(0, reverse), self.identity)
            current = update_directional_inter_arrival_statistics(current, packet_at(3, not reverse), self.identity)
            self.assert_atomic_failure(DirectionalInterArrivalStatisticsError, current, packet_at(2, reverse), self.identity)
            current = update_directional_inter_arrival_statistics(current, packet_at(4, reverse), self.identity)
            self.assert_atomic_failure(DirectionalInterArrivalStatisticsError, current, packet_at(3, reverse), self.identity)
            self.assert_atomic_failure(DirectionalInterArrivalStatisticsError, current, packet_at(-1, reverse), self.identity)

    def test_nonfinite_negative_intervals_and_aggregate_overflow_are_rejected_atomically(self) -> None:
        for reverse in (False, True):
            current = update_directional_inter_arrival_statistics(None, packet_at(0, reverse), self.identity)
            prefix = "reverse" if reverse else "forward"
            for interval in (float("nan"), float("inf"), float("-inf"), -1.0, 1e154, 1e308):
                class SyntheticDelta(timedelta):
                    def total_seconds(self) -> float:
                        return interval

                class SyntheticTimestamp(datetime):
                    def __sub__(self, other):
                        return SyntheticDelta()

                timestamp = SyntheticTimestamp(2026, 9, 6, 12, 0, 1, tzinfo=timezone.utc)
                packet = replace(packet_at(1, reverse), observation=replace(OBSERVATION, captured_at=timestamp))
                source = current
                if interval in (1e154, 1e308):
                    source = replace(current, packet_count=2, **{
                        f"{prefix}_inter_arrival_count": 1,
                        f"{prefix}_inter_arrival_sum_seconds": 1.7e308,
                        f"{prefix}_inter_arrival_sum_seconds_squared": 1.7e308,
                    })
                self.assert_atomic_failure(DirectionalInterArrivalStatisticsError, source, packet, self.identity)

    def test_wrong_update_types_and_identity_subclasses_are_rejected(self) -> None:
        class DerivedIdentity(FlowIdentity):
            pass

        for position in range(3):
            for value in (True, False, 1, 1.0, [], {}, SimpleNamespace()):
                arguments = [self.current, TCP_ANALYSIS, self.identity]
                arguments[position] = value
                self.assert_atomic_failure(TypeError, *arguments)
        for position in (1, 2):
            arguments = [self.current, TCP_ANALYSIS, self.identity]
            arguments[position] = None
            self.assert_atomic_failure(TypeError, *arguments)
        derived = DerivedIdentity(**vars(self.identity))
        self.assert_atomic_failure(TypeError, self.current, TCP_ANALYSIS, derived)
        with self.assertRaises(TypeError):
            replace(self.current, identity=derived)

    def test_direct_numeric_types_and_values(self) -> None:
        self.assertTrue(issubclass(DirectionalInterArrivalStatisticsError, ValueError))
        populated = replace(self.current, packet_count=3, last_reverse_captured_at=TIMESTAMP,
                            forward_inter_arrival_count=1)
        for name in ("packet_count", "forward_inter_arrival_count", "reverse_inter_arrival_count"):
            for value in (True, False, 1.0, "1", Decimal("1"), None):
                with self.assertRaises(TypeError):
                    replace(populated, **{name: value})
            with self.assertRaises(DirectionalInterArrivalStatisticsError):
                replace(populated, **{name: -1})
        for direction in ("forward", "reverse"):
            for suffix in AGGREGATE_SUFFIXES:
                name = f"{direction}_{suffix}"
                for value in (True, False, 0, None, "0.0", Decimal("0.0"), complex(0)):
                    with self.assertRaises(TypeError):
                        replace(populated, **{name: value})
                for value in (-1.0, float("nan"), float("inf"), float("-inf")):
                    with self.assertRaises(DirectionalInterArrivalStatisticsError):
                        replace(populated, **{name: value})
            observed = replace(self.current, packet_count=2, last_reverse_captured_at=TIMESTAMP)
            for suffix in AGGREGATE_SUFFIXES:
                with self.assertRaises(DirectionalInterArrivalStatisticsError):
                    replace(observed, **{f"{direction}_{suffix}": 1.0})
            with self.assertRaises(DirectionalInterArrivalStatisticsError):
                replace(observed, packet_count=3, **{f"{direction}_inter_arrival_count": 1,
                                                    f"{direction}_min_inter_arrival_seconds": 2.0,
                                                    f"{direction}_max_inter_arrival_seconds": 1.0})

    def test_direct_timestamp_states_and_count_invariants(self) -> None:
        for name in ("first_captured_at", "last_captured_at", "last_forward_captured_at", "last_reverse_captured_at"):
            for value in (1, True, "timestamp", SimpleNamespace()):
                with self.assertRaises(TypeError):
                    replace(self.current, **{name: value})
            for value in (datetime(2026, 9, 6), datetime(2026, 9, 6, tzinfo=NoOffset())):
                with self.assertRaises(DirectionalInterArrivalStatisticsError):
                    replace(self.current, **{name: value})
        for name in ("first_captured_at", "last_captured_at"):
            with self.assertRaises(TypeError):
                replace(self.current, **{name: None})
        for changes in (
            {"packet_count": 0}, {"packet_count": 2}, {"forward_inter_arrival_count": 1},
            {"last_forward_captured_at": None},
            {"last_reverse_captured_at": TIMESTAMP},
            {"packet_count": 2, "reverse_inter_arrival_count": 1},
            {"last_captured_at": TIMESTAMP - timedelta(seconds=1)},
        ):
            with self.assertRaises(DirectionalInterArrivalStatisticsError):
                replace(self.current, **changes)
        for direction in ("forward", "reverse"):
            observed = replace(self.current, packet_count=2, last_reverse_captured_at=TIMESTAMP)
            for offset in (-1, 1):
                with self.assertRaises(DirectionalInterArrivalStatisticsError):
                    replace(observed, **{f"last_{direction}_captured_at": TIMESTAMP + timedelta(seconds=offset)})
            unseen = replace(self.current, last_forward_captured_at=None if direction == "forward" else TIMESTAMP,
                             last_reverse_captured_at=TIMESTAMP if direction == "forward" else None)
            for suffix in AGGREGATE_SUFFIXES:
                with self.assertRaises(DirectionalInterArrivalStatisticsError):
                    replace(unseen, **{f"{direction}_{suffix}": 1.0})

    def test_exact_sixteen_frozen_fields_without_history_or_hidden_state(self) -> None:
        names = (
            "identity", "packet_count", "first_captured_at", "last_captured_at",
            "last_forward_captured_at", "last_reverse_captured_at",
            "forward_inter_arrival_count", "reverse_inter_arrival_count",
            "forward_inter_arrival_sum_seconds", "reverse_inter_arrival_sum_seconds",
            "forward_inter_arrival_sum_seconds_squared", "reverse_inter_arrival_sum_seconds_squared",
            "forward_min_inter_arrival_seconds", "forward_max_inter_arrival_seconds",
            "reverse_min_inter_arrival_seconds", "reverse_max_inter_arrival_seconds",
        )
        self.assertEqual(tuple(field.name for field in fields(self.current)), names)
        self.assertEqual(tuple(vars(self.current)), names)
        for name in names:
            value = getattr(self.current, name)
            self.assertIn(type(value), (FlowIdentity, int, datetime, float, type(None)))
            if name.endswith("seconds") or name.endswith("squared"):
                self.assertIs(type(value), float)
            with self.assertRaises(FrozenInstanceError):
                setattr(self.current, name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(self.current, name)

    def test_large_counts_remain_exact(self) -> None:
        count = 10 ** 100
        current = replace(self.current, packet_count=count, forward_inter_arrival_count=count - 1)
        result = update_directional_inter_arrival_statistics(current, TCP_ANALYSIS, self.identity)
        self.assertEqual(result.packet_count, count + 1)
        self.assertEqual(result.forward_inter_arrival_count, count)
        self.assertIs(type(result.packet_count), int)
        self.assertIs(type(result.forward_inter_arrival_count), int)

    def test_determinism_and_independence_from_payload_lengths_flags_and_checksums(self) -> None:
        for reverse in (False, True):
            first = packet_at(0, reverse)
            current = update_directional_inter_arrival_statistics(None, first, self.identity)
            packet = packet_at(2, reverse)
            expected = update_directional_inter_arrival_statistics(current, packet, self.identity)
            for checksum in (True, False, None):
                changed = replace(
                    packet,
                    observation=replace(packet.observation, captured_length=5, original_length=50, raw_bytes=b"other"),
                    tcp=replace(packet.tcp, syn=True, payload=b"unrelated"),
                    ipv4_checksum_valid=checksum, tcp_checksum_valid=checksum,
                    udp_checksum_valid=checksum, icmp_checksum_valid=checksum,
                )
                self.assertEqual(update_directional_inter_arrival_statistics(current, changed, self.identity), expected)
            self.assertEqual(update_directional_inter_arrival_statistics(current, packet, self.identity), expected)
            self.assertEqual(update_directional_inter_arrival_statistics(replace(current), packet, self.identity), expected)
