import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone, tzinfo
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from analysis import (
    FlowIdentity,
    FlowIdentityError,
    FlowStatistics,
    FlowStatisticsError,
    IPv4Packet,
    PacketAnalysis,
    TCPPacket,
    UDPPacket,
    flow_identity_from_packet,
    update_flow_statistics,
)
from capture.packet_observation import CaptureSource, PacketObservation


OBSERVATION = PacketObservation(
    captured_at=datetime(2026, 9, 6, tzinfo=timezone.utc),
    link_type=None,
    captured_length=3,
    original_length=30,
    raw_bytes=b"\x00\x80\xff",
    source=CaptureSource("test-flow-statistics"),
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


class NoOffset(tzinfo):
    def utcoffset(self, value: object) -> None:
        return None


class FlowStatisticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = flow_identity_from_packet(TCP_ANALYSIS)
        self.current = FlowStatistics(self.identity, 1, 3, 30,
                                      OBSERVATION.captured_at, OBSERVATION.captured_at)

    def test_first_update_uses_capture_metadata_for_both_protocols(self) -> None:
        for analysis, layer in ANALYSES:
            with self.subTest(protocol=layer):
                identity = flow_identity_from_packet(analysis)
                result = update_flow_statistics(None, analysis, identity)
                self.assertEqual(result.packet_count, 1)
                self.assertEqual(result.captured_bytes, 3)
                self.assertEqual(result.original_bytes, 30)
                self.assertIs(result.first_captured_at, analysis.observation.captured_at)
                self.assertIs(result.last_captured_at, analysis.observation.captured_at)
                self.assertIs(result.identity, identity)
                self.assertNotEqual(result.original_bytes, len(analysis.observation.raw_bytes))
                self.assertNotEqual(result.captured_bytes, len(cast(IPv4Packet, analysis.ipv4).payload))
                self.assertNotEqual(result.captured_bytes, len(getattr(analysis, layer).payload))

    def test_sequential_and_reverse_updates_preserve_prior_values_and_supplied_identity(self) -> None:
        for analysis, layer in ANALYSES:
            with self.subTest(protocol=layer):
                current = update_flow_statistics(None, analysis, flow_identity_from_packet(analysis))
                initial = current
                ipv4 = cast(IPv4Packet, analysis.ipv4)
                transport = getattr(analysis, layer)
                reverse = replace(
                    analysis,
                    ipv4=replace(ipv4, source_address=ipv4.destination_address,
                                 destination_address=ipv4.source_address),
                    **{layer: replace(transport, source_port=transport.destination_port,
                                      destination_port=transport.source_port)},
                )
                for count, packet, size, original, captured, total_original in (
                    (2, reverse, 5, 50, 8, 80),
                    (3, analysis, 0, 0, 8, 80),
                ):
                    timestamp = OBSERVATION.captured_at + timedelta(seconds=count)
                    packet = replace(packet, observation=replace(
                        OBSERVATION, captured_at=timestamp, raw_bytes=bytes(size),
                        captured_length=size, original_length=original))
                    identity = replace(current.identity)
                    previous = current
                    before = vars(previous).copy()
                    packet_before = vars(packet).copy()
                    current = update_flow_statistics(previous, packet, identity)
                    self.assertEqual(current.packet_count, count)
                    self.assertEqual(current.captured_bytes, captured)
                    self.assertEqual(current.original_bytes, total_original)
                    self.assertIs(current.first_captured_at, initial.first_captured_at)
                    self.assertIs(current.last_captured_at, timestamp)
                    self.assertIs(current.identity, identity)
                    self.assertIsNot(identity, previous.identity)
                    self.assertIsNot(current, previous)
                    self.assertEqual(vars(previous), before)
                    self.assertEqual(vars(packet), packet_before)
                self.assertEqual(initial.packet_count, 1)
                self.assertEqual(initial.captured_bytes, 3)
                self.assertEqual(initial.original_bytes, 30)

    def test_capture_order_is_not_sorted_and_offsets_are_preserved(self) -> None:
        first = OBSERVATION.captured_at
        current = replace(self.current, last_captured_at=first + timedelta(seconds=10))
        for timestamp in (
            (first + timedelta(seconds=5)).astimezone(timezone(timedelta(hours=5, minutes=30))),
            first,
        ):
            analysis = replace(TCP_ANALYSIS, observation=replace(OBSERVATION, captured_at=timestamp))
            result = update_flow_statistics(current, analysis, self.identity)
            self.assertIs(result.first_captured_at, first)
            self.assertIs(result.last_captured_at, timestamp)
        earlier = replace(TCP_ANALYSIS, observation=replace(
            OBSERVATION, captured_at=first - timedelta(microseconds=1)))
        before = vars(current).copy()
        with self.assertRaises(FlowStatisticsError):
            update_flow_statistics(current, earlier, self.identity)
        self.assertEqual(vars(current), before)

    def test_checksum_results_do_not_affect_statistics(self) -> None:
        for analysis, layer in ANALYSES:
            identity = flow_identity_from_packet(analysis)
            for checksum in (True, False, None):
                with self.subTest(protocol=layer, checksum=checksum):
                    packet = replace(analysis, ipv4_checksum_valid=checksum,
                                     **{f"{layer}_checksum_valid": checksum})
                    result = update_flow_statistics(None, packet, identity)
                    self.assertEqual(result, FlowStatistics(identity, 1, 3, 30,
                                                           OBSERVATION.captured_at, OBSERVATION.captured_at))

    def test_wrong_function_input_types_are_rejected(self) -> None:
        arguments = [self.current, TCP_ANALYSIS, self.identity]
        for position in range(3):
            for value in (False, 1, [], SimpleNamespace()):
                with self.subTest(position=position, value=value):
                    invalid = arguments.copy()
                    invalid[position] = value
                    with self.assertRaises(TypeError):
                        update_flow_statistics(*invalid)
        for position in (1, 2):
            invalid = arguments.copy()
            invalid[position] = None
            with self.assertRaises(TypeError):
                update_flow_statistics(*invalid)

    def test_mismatched_identities_and_unknown_original_length_leave_inputs_unchanged(self) -> None:
        other = replace(self.identity, source_port=12346)
        unknown = replace(TCP_ANALYSIS, observation=replace(OBSERVATION, original_length=None))
        for current, analysis, identity in (
            (None, TCP_ANALYSIS, other),
            (self.current, TCP_ANALYSIS, other),
            (replace(self.current, identity=other), TCP_ANALYSIS, self.identity),
            (None, unknown, self.identity),
            (self.current, unknown, self.identity),
        ):
            before = None if current is None else vars(current).copy()
            analysis_before = vars(analysis).copy()
            observation_before = vars(analysis.observation).copy()
            identity_before = vars(identity).copy()
            with self.assertRaises(FlowStatisticsError):
                update_flow_statistics(current, analysis, identity)
            self.assertEqual(None if current is None else vars(current), before)
            self.assertEqual(vars(analysis), analysis_before)
            self.assertEqual(vars(analysis.observation), observation_before)
            self.assertEqual(vars(identity), identity_before)

    def test_identity_verification_delegates_once_and_compares_values(self) -> None:
        derived = replace(self.identity)
        self.assertIsNot(derived, self.identity)
        for current in (None, self.current):
            with patch("analysis.flow_statistics.flow_identity_from_packet", return_value=derived) as factory:
                result = update_flow_statistics(current, TCP_ANALYSIS, self.identity)
                factory.assert_called_once_with(TCP_ANALYSIS)
            self.assertIs(result.identity, self.identity)
            self.assertIsNot(result.identity, derived)
        with patch("analysis.flow_statistics.flow_identity_from_packet",
                   return_value=replace(derived, destination_port=444)) as factory:
            with self.assertRaises(FlowStatisticsError):
                update_flow_statistics(self.current, TCP_ANALYSIS, self.identity)
            factory.assert_called_once_with(TCP_ANALYSIS)
        error = FlowIdentityError("unavailable identity")
        before = vars(self.current).copy()
        with patch("analysis.flow_statistics.flow_identity_from_packet", side_effect=error):
            with self.assertRaises(FlowIdentityError) as failure:
                update_flow_statistics(self.current, TCP_ANALYSIS, self.identity)
        self.assertIs(failure.exception, error)
        self.assertEqual(vars(self.current), before)

    def test_missing_transport_and_unsupported_protocols_preserve_identity_errors(self) -> None:
        for analysis in (
            replace(TCP_ANALYSIS, ipv4=None),
            replace(TCP_ANALYSIS, tcp=None),
            replace(TCP_ANALYSIS, ipv4=replace(IPV4_PACKET, protocol=1), tcp=None),
            replace(TCP_ANALYSIS, ipv4=replace(IPV4_PACKET, protocol=253), tcp=None),
        ):
            with self.assertRaises(FlowIdentityError):
                update_flow_statistics(self.current, analysis, self.identity)

    def test_model_contains_only_value_fields_and_is_frozen(self) -> None:
        result = update_flow_statistics(None, TCP_ANALYSIS, self.identity)
        self.assertEqual(tuple(field.name for field in fields(result)), (
            "identity", "packet_count", "captured_bytes", "original_bytes",
            "first_captured_at", "last_captured_at",
        ))
        self.assertEqual(set(vars(result)), {field.name for field in fields(result)})
        for field in fields(result):
            value = getattr(result, field.name)
            self.assertNotIsInstance(value, (PacketAnalysis, PacketObservation, bytes, list, dict, set, bytearray))
            with self.assertRaises(FrozenInstanceError):
                setattr(result, field.name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(result, field.name)

    def test_model_rejects_wrong_field_types_including_boolean_counters(self) -> None:
        for field in fields(self.current):
            for value in (None, [], SimpleNamespace()):
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.current, **{field.name: value})
        for name in ("packet_count", "captured_bytes", "original_bytes"):
            for value in (True, False, 1.0, "1"):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.current, **{name: value})

    def test_model_numeric_invariants(self) -> None:
        for invalid in (
            {"packet_count": 0}, {"packet_count": -1}, {"captured_bytes": -1},
            {"original_bytes": -1}, {"original_bytes": 2},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(FlowStatisticsError):
                    replace(self.current, **invalid)
        empty = replace(self.current, captured_bytes=0, original_bytes=0)
        self.assertEqual(empty.captured_bytes, empty.original_bytes)

    def test_model_requires_aware_and_consistent_timestamps(self) -> None:
        for name in ("first_captured_at", "last_captured_at"):
            for timestamp in (datetime(2026, 9, 6), datetime(2026, 9, 6, tzinfo=NoOffset())):
                with self.subTest(field=name, timestamp=timestamp):
                    with self.assertRaises(FlowStatisticsError):
                        replace(self.current, **{name: timestamp})
        with self.assertRaises(FlowStatisticsError):
            replace(self.current, last_captured_at=OBSERVATION.captured_at - timedelta(microseconds=1))
