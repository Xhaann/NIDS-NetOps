import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone, tzinfo
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from analysis import (
    FlowIdentity,
    FlowIdentityError,
    FlowInterArrivalStatistics,
    FlowInterArrivalStatisticsError,
    IPv4Packet,
    PacketAnalysis,
    TCPPacket,
    UDPPacket,
    flow_identity_from_packet,
    update_flow_inter_arrival_statistics,
)
from capture.packet_observation import CaptureSource, PacketObservation


TIMESTAMP = datetime(2026, 9, 6, 12, tzinfo=timezone.utc)
OBSERVATION = PacketObservation(TIMESTAMP, None, 3, None, b"abc", CaptureSource("test-inter-arrival"))
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
AGGREGATES = (
    "inter_arrival_sum_seconds", "inter_arrival_sum_seconds_squared",
    "min_inter_arrival_seconds", "max_inter_arrival_seconds",
)


class NoOffset(tzinfo):
    def utcoffset(self, value: object) -> None:
        return None


class FlowInterArrivalStatisticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = flow_identity_from_packet(TCP_ANALYSIS)
        self.current = update_flow_inter_arrival_statistics(None, TCP_ANALYSIS, self.identity)

    def assert_atomic_failure(self, error, current, analysis, identity) -> None:
        objects = [value for value in (current, analysis, identity) if hasattr(value, "__dict__")]
        if isinstance(analysis, PacketAnalysis):
            objects.append(analysis.observation)
        before = [vars(value).copy() for value in objects]
        with self.assertRaises(error):
            update_flow_inter_arrival_statistics(current, analysis, identity)
        for value, original in zip(objects, before):
            self.assertEqual(vars(value), original)

    def test_first_packet_has_no_intervals_for_tcp_and_udp(self) -> None:
        for analysis in (TCP_ANALYSIS, UDP_ANALYSIS):
            identity = flow_identity_from_packet(analysis)
            result = update_flow_inter_arrival_statistics(None, analysis, identity)
            self.assertEqual(result, FlowInterArrivalStatistics(
                identity, 1, TIMESTAMP, TIMESTAMP, 0, 0.0, 0.0, 0.0, 0.0))
            self.assertIs(result.identity, identity)
            self.assertIs(result.first_captured_at, analysis.observation.captured_at)
            self.assertIs(result.last_captured_at, analysis.observation.captured_at)
            for name in AGGREGATES:
                self.assertIs(type(getattr(result, name)), float)

    def test_adjacent_intervals_and_reverse_packets_preserve_existing_identity(self) -> None:
        for analysis, transport_name in ((TCP_ANALYSIS, "tcp"), (UDP_ANALYSIS, "udp")):
            identity = flow_identity_from_packet(analysis)
            current = update_flow_inter_arrival_statistics(None, analysis, identity)
            reverse = replace(
                analysis,
                ipv4=replace(analysis.ipv4, source_address=analysis.ipv4.destination_address,
                             destination_address=analysis.ipv4.source_address),
                **{transport_name: replace(getattr(analysis, transport_name),
                                           source_port=443, destination_port=12345)},
            )
            for offset, packet, count, total, squares, minimum, maximum in (
                (1.5, reverse, 2, 1.5, 2.25, 1.5, 1.5),
                (4.0, analysis, 3, 4.0, 8.5, 1.5, 2.5),
                (4.5, reverse, 4, 4.5, 8.75, 0.5, 2.5),
            ):
                timestamp = TIMESTAMP + timedelta(seconds=offset)
                packet = replace(packet, observation=replace(OBSERVATION, captured_at=timestamp))
                before = [vars(value).copy() for value in (current, packet, packet.observation, identity)]
                equal_identity = replace(identity)
                self.assertEqual(equal_identity, identity)
                self.assertIsNot(equal_identity, identity)
                result = update_flow_inter_arrival_statistics(current, packet, equal_identity)
                self.assertEqual(result, FlowInterArrivalStatistics(
                    identity, count, TIMESTAMP, timestamp, count - 1, total, squares, minimum, maximum))
                self.assertIs(result.identity, identity)
                self.assertIsNot(result.identity, equal_identity)
                self.assertIs(result.first_captured_at, current.first_captured_at)
                self.assertIs(result.last_captured_at, timestamp)
                self.assertIsNot(result, current)
                for value, original in zip((current, packet, packet.observation, identity), before):
                    self.assertEqual(vars(value), original)
                current = result

    def test_zero_intervals_are_preserved_including_after_positive_intervals(self) -> None:
        current = self.current
        for offset, count, total, squares, minimum, maximum in (
            (0, 2, 0.0, 0.0, 0.0, 0.0),
            (1, 3, 1.0, 1.0, 0.0, 1.0),
            (3, 4, 3.0, 5.0, 0.0, 2.0),
            (3, 5, 3.0, 5.0, 0.0, 2.0),
        ):
            timestamp = TIMESTAMP + timedelta(seconds=offset)
            packet = replace(TCP_ANALYSIS, observation=replace(OBSERVATION, captured_at=timestamp))
            current = update_flow_inter_arrival_statistics(current, packet, self.identity)
            self.assertEqual(current, FlowInterArrivalStatistics(
                self.identity, count, TIMESTAMP, timestamp, count - 1, total, squares, minimum, maximum))

    def test_microsecond_large_intervals_and_named_utc_use_datetime_subtraction(self) -> None:
        for delta in (timedelta(microseconds=1), timedelta(seconds=1.234567), timedelta(days=1000000)):
            timestamp = (TIMESTAMP + delta).astimezone(timezone(timedelta(0), "UTC alias"))
            packet = replace(TCP_ANALYSIS, observation=replace(OBSERVATION, captured_at=timestamp))
            result = update_flow_inter_arrival_statistics(self.current, packet, self.identity)
            interval = (timestamp - TIMESTAMP).total_seconds()
            self.assertEqual(result.inter_arrival_sum_seconds, interval)
            self.assertEqual(result.inter_arrival_sum_seconds_squared, interval * interval)
            self.assertEqual(result.min_inter_arrival_seconds, interval)
            self.assertEqual(result.max_inter_arrival_seconds, interval)
            self.assertIs(result.last_captured_at, timestamp)
            for name in AGGREGATES:
                self.assertIs(type(getattr(result, name)), float)

    def test_identity_mismatches_and_unsupported_packets_fail_atomically(self) -> None:
        other = replace(self.identity, source_port=12346)
        different_packet = replace(TCP_ANALYSIS, tcp=replace(TCP, source_port=12346))
        for current, analysis, identity in (
            (None, TCP_ANALYSIS, other),
            (self.current, TCP_ANALYSIS, other),
            (self.current, different_packet, self.identity),
            (self.current, different_packet, other),
            (replace(self.current, identity=other), TCP_ANALYSIS, self.identity),
        ):
            self.assert_atomic_failure(FlowInterArrivalStatisticsError, current, analysis, identity)
        for analysis in (
            replace(TCP_ANALYSIS, ipv4=None), replace(TCP_ANALYSIS, tcp=None),
            replace(TCP_ANALYSIS, ipv4=replace(IPV4, protocol=1), tcp=None),
            replace(TCP_ANALYSIS, ipv4=replace(IPV4, protocol=253), tcp=None),
        ):
            self.assert_atomic_failure(FlowIdentityError, self.current, analysis, self.identity)

    def test_identity_validation_delegates_once_without_replacing_stored_identity(self) -> None:
        derived = replace(self.identity)
        for current in (None, self.current):
            with patch("analysis.flow_inter_arrival_statistics.flow_identity_from_packet",
                       return_value=derived) as factory:
                result = update_flow_inter_arrival_statistics(current, TCP_ANALYSIS, self.identity)
                factory.assert_called_once_with(TCP_ANALYSIS)
                self.assertIs(result.identity, self.identity)
                self.assertIsNot(result.identity, derived)
        with patch("analysis.flow_inter_arrival_statistics.flow_identity_from_packet",
                   return_value=replace(derived, source_port=12346)) as factory:
            self.assert_atomic_failure(FlowInterArrivalStatisticsError, self.current, TCP_ANALYSIS, self.identity)
            factory.assert_called_once_with(TCP_ANALYSIS)

    def test_out_of_order_and_nonfinite_intervals_fail_atomically(self) -> None:
        current = replace(self.current, packet_count=2, inter_arrival_count=1,
                          last_captured_at=TIMESTAMP + timedelta(seconds=2),
                          inter_arrival_sum_seconds=2.0, inter_arrival_sum_seconds_squared=4.0,
                          min_inter_arrival_seconds=2.0, max_inter_arrival_seconds=2.0)
        for offset in (-1, 1):
            packet = replace(TCP_ANALYSIS, observation=replace(
                OBSERVATION, captured_at=TIMESTAMP + timedelta(seconds=offset)))
            self.assert_atomic_failure(FlowInterArrivalStatisticsError, current, packet, self.identity)
        for interval in (float("nan"), float("inf"), float("-inf")):
            timestamp = MagicMock()
            timestamp.__sub__.return_value.total_seconds.return_value = interval
            with patch.object(PacketObservation, "__post_init__", return_value=None):
                observation = replace(OBSERVATION, captured_at=timestamp)
            packet = replace(TCP_ANALYSIS, observation=observation)
            self.assert_atomic_failure(FlowInterArrivalStatisticsError, current, packet, self.identity)

    def test_wrong_update_types_and_identity_subclasses_are_rejected_atomically(self) -> None:
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

    def test_direct_field_types_reject_booleans_and_non_exact_numbers(self) -> None:
        for field in fields(self.current):
            for value in (None, [], SimpleNamespace()):
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.current, **{field.name: value})
        for name in ("packet_count", "inter_arrival_count"):
            for value in (True, False, 1.0, "1", Decimal("1")):
                with self.assertRaises(TypeError):
                    replace(self.current, **{name: value})
        for name in AGGREGATES:
            for value in (True, False, 0, 1, "0.0", Decimal("0.0"), complex(0)):
                with self.assertRaises(TypeError):
                    replace(self.current, **{name: value})

    def test_direct_numeric_and_zero_interval_invariants(self) -> None:
        self.assertTrue(issubclass(FlowInterArrivalStatisticsError, ValueError))
        for changes in (
            {"packet_count": 0}, {"packet_count": -1}, {"inter_arrival_count": -1},
            {"inter_arrival_count": 1}, {"packet_count": 2},
        ):
            with self.assertRaises(FlowInterArrivalStatisticsError):
                replace(self.current, **changes)
        populated = replace(self.current, packet_count=2, inter_arrival_count=1)
        for name in AGGREGATES:
            for value in (-1.0, float("nan"), float("inf"), float("-inf")):
                with self.assertRaises(FlowInterArrivalStatisticsError):
                    replace(populated, **{name: value})
            with self.assertRaises(FlowInterArrivalStatisticsError):
                replace(self.current, **{name: 1.0})
        with self.assertRaises(FlowInterArrivalStatisticsError):
            replace(populated, min_inter_arrival_seconds=2.0, max_inter_arrival_seconds=1.0)
        self.assertEqual(populated.inter_arrival_count, 1)

    def test_direct_timestamps_must_be_aware_and_ordered(self) -> None:
        for name in ("first_captured_at", "last_captured_at"):
            for timestamp in (datetime(2026, 9, 6), datetime(2026, 9, 6, tzinfo=NoOffset())):
                with self.assertRaises(FlowInterArrivalStatisticsError):
                    replace(self.current, **{name: timestamp})
        with self.assertRaises(FlowInterArrivalStatisticsError):
            replace(self.current, last_captured_at=TIMESTAMP - timedelta(microseconds=1))

    def test_exact_nine_frozen_fields_retain_no_packets_or_history(self) -> None:
        expected = (
            "identity", "packet_count", "first_captured_at", "last_captured_at", "inter_arrival_count",
            "inter_arrival_sum_seconds", "inter_arrival_sum_seconds_squared",
            "min_inter_arrival_seconds", "max_inter_arrival_seconds",
        )
        self.assertEqual(tuple(field.name for field in fields(self.current)), expected)
        self.assertEqual(tuple(vars(self.current)), expected)
        for name in expected:
            value = getattr(self.current, name)
            self.assertIn(type(value), (FlowIdentity, int, datetime, float))
            with self.assertRaises(FrozenInstanceError):
                setattr(self.current, name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(self.current, name)

    def test_large_packet_and_interval_counts_remain_exact_integers(self) -> None:
        count = 10 ** 100
        current = replace(self.current, packet_count=count, inter_arrival_count=count - 1)
        result = update_flow_inter_arrival_statistics(current, TCP_ANALYSIS, self.identity)
        self.assertIs(type(result.packet_count), int)
        self.assertEqual(result.packet_count, count + 1)
        self.assertEqual(result.inter_arrival_count, count)

    def test_determinism_and_independence_from_payload_lengths_and_checksums(self) -> None:
        packet = replace(TCP_ANALYSIS, observation=replace(OBSERVATION, captured_at=TIMESTAMP + timedelta(seconds=2)))
        expected = update_flow_inter_arrival_statistics(self.current, packet, self.identity)
        for checksum in (True, False, None):
            changed = replace(
                packet, observation=replace(packet.observation, captured_length=5, original_length=50,
                                            raw_bytes=b"other"),
                tcp=replace(TCP, syn=True, payload=b"unrelated"),
                ipv4_checksum_valid=checksum, tcp_checksum_valid=checksum,
                udp_checksum_valid=checksum, icmp_checksum_valid=checksum,
            )
            self.assertEqual(update_flow_inter_arrival_statistics(self.current, changed, self.identity), expected)
        self.assertEqual(update_flow_inter_arrival_statistics(self.current, packet, self.identity), expected)
        self.assertEqual(update_flow_inter_arrival_statistics(replace(self.current), packet, self.identity), expected)
