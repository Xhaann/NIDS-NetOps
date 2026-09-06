import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from analysis import (
    DirectionalFlowStatistics,
    DirectionalFlowStatisticsError,
    FlowDirection,
    FlowDirectionError,
    FlowIdentity,
    FlowIdentityError,
    IPv4Packet,
    PacketAnalysis,
    TCPPacket,
    UDPPacket,
    flow_identity_from_packet,
    update_directional_flow_statistics,
)
from capture.packet_observation import CaptureSource, PacketObservation


OBSERVATION = PacketObservation(
    captured_at=datetime(2026, 9, 6, tzinfo=timezone.utc),
    link_type=None,
    captured_length=3,
    original_length=30,
    raw_bytes=b"\x00\x80\xff",
    source=CaptureSource("test-directional-statistics"),
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


class DirectionalFlowStatisticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = flow_identity_from_packet(TCP_ANALYSIS)
        self.current = DirectionalFlowStatistics(self.identity, 2, 3, 6, 9, 60, 90)

    def test_initial_forward_and_reverse_updates_use_capture_lengths(self) -> None:
        for analysis, layer in ANALYSES:
            identity = flow_identity_from_packet(analysis)
            ipv4 = cast(IPv4Packet, analysis.ipv4)
            transport = getattr(analysis, layer)
            reverse = replace(
                analysis,
                ipv4=replace(ipv4, source_address=ipv4.destination_address,
                             destination_address=ipv4.source_address),
                **{layer: replace(transport, source_port=transport.destination_port,
                                  destination_port=transport.source_port)},
            )
            for packet, counters in ((analysis, (1, 0, 3, 0, 30, 0)), (reverse, (0, 1, 0, 3, 0, 30))):
                with self.subTest(protocol=layer, counters=counters):
                    result = update_directional_flow_statistics(None, packet, identity)
                    self.assertEqual(result, DirectionalFlowStatistics(identity, *counters))
                    self.assertIs(result.identity, identity)
                    self.assertNotEqual(packet.observation.original_length, len(packet.observation.raw_bytes))
                    self.assertNotEqual(packet.observation.captured_length, len(ipv4.payload))
                    self.assertNotEqual(packet.observation.captured_length, len(transport.payload))

    def test_sequential_updates_change_only_selected_direction_and_preserve_inputs(self) -> None:
        for analysis, layer in ANALYSES:
            with self.subTest(protocol=layer):
                identity = flow_identity_from_packet(analysis)
                current = update_directional_flow_statistics(None, analysis, identity)
                initial = current
                ipv4 = cast(IPv4Packet, analysis.ipv4)
                transport = getattr(analysis, layer)
                reverse = replace(
                    analysis,
                    ipv4=replace(ipv4, source_address=ipv4.destination_address,
                                 destination_address=ipv4.source_address),
                    **{layer: replace(transport, source_port=transport.destination_port,
                                      destination_port=transport.source_port)},
                    observation=replace(OBSERVATION, raw_bytes=bytes(5), captured_length=5, original_length=50),
                )
                for packet, counters in (
                    (analysis, (2, 0, 6, 0, 60, 0)),
                    (reverse, (2, 1, 6, 5, 60, 50)),
                    (replace(reverse), (2, 2, 6, 10, 60, 100)),
                    (analysis, (3, 2, 9, 10, 90, 100)),
                ):
                    supplied = replace(identity)
                    previous = current
                    objects = (previous, packet, packet.observation, supplied)
                    before = [vars(value).copy() for value in objects]
                    current = update_directional_flow_statistics(previous, packet, supplied)
                    self.assertEqual(current, DirectionalFlowStatistics(supplied, *counters))
                    self.assertIs(current.identity, supplied)
                    self.assertIsNot(current.identity, previous.identity)
                    self.assertIsNot(current, previous)
                    for value, original in zip(objects, before):
                        self.assertEqual(vars(value), original)
                        for name, reference in original.items():
                            self.assertIs(getattr(value, name), reference)
                self.assertEqual(initial, DirectionalFlowStatistics(identity, 1, 0, 3, 0, 30, 0))

    def test_direction_delegates_once_and_controls_selected_counters(self) -> None:
        for direction, first, later in (
            (FlowDirection.FORWARD, (1, 0, 3, 0, 30, 0), (3, 3, 9, 9, 90, 90)),
            (FlowDirection.REVERSE, (0, 1, 0, 3, 0, 30), (2, 4, 6, 12, 60, 120)),
        ):
            for current, expected in ((None, first), (self.current, later)):
                with self.subTest(direction=direction, current=current):
                    supplied = replace(self.identity)
                    with patch("analysis.directional_flow_statistics.flow_direction_from_packet",
                               return_value=direction) as direction_function:
                        result = update_directional_flow_statistics(current, TCP_ANALYSIS, supplied)
                        direction_function.assert_called_once_with(TCP_ANALYSIS, supplied)
                    self.assertEqual(result, DirectionalFlowStatistics(supplied, *expected))
                    self.assertIs(result.identity, supplied)

    def test_wrong_update_argument_types_raise_type_error(self) -> None:
        arguments = [self.current, TCP_ANALYSIS, self.identity]
        for position in range(3):
            for value in (False, 1, [], SimpleNamespace()):
                with self.subTest(position=position, value=value):
                    invalid = arguments.copy()
                    invalid[position] = value
                    with self.assertRaises(TypeError):
                        update_directional_flow_statistics(*invalid)
        for position in (1, 2):
            invalid = arguments.copy()
            invalid[position] = None
            with self.assertRaises(TypeError):
                update_directional_flow_statistics(*invalid)

    def test_identity_and_unknown_length_failures_preserve_all_inputs(self) -> None:
        other = replace(self.identity, destination_port=444)
        unknown = replace(TCP_ANALYSIS, observation=replace(OBSERVATION, original_length=None))
        for current, packet, identity, error_type in (
            (None, TCP_ANALYSIS, other, FlowDirectionError),
            (self.current, TCP_ANALYSIS, other, FlowDirectionError),
            (replace(self.current, identity=other), TCP_ANALYSIS, self.identity, DirectionalFlowStatisticsError),
            (None, unknown, self.identity, DirectionalFlowStatisticsError),
            (self.current, unknown, self.identity, DirectionalFlowStatisticsError),
            (self.current, replace(TCP_ANALYSIS, tcp=None), self.identity, FlowIdentityError),
            (self.current, replace(TCP_ANALYSIS, ipv4=replace(IPV4_PACKET, protocol=1), tcp=None),
             self.identity, FlowIdentityError),
        ):
            with self.subTest(error=error_type, current=current):
                objects = (packet, packet.observation, identity) if current is None else (
                    current, packet, packet.observation, identity)
                before = [vars(value).copy() for value in objects]
                with self.assertRaises(error_type):
                    update_directional_flow_statistics(current, packet, identity)
                for value, original in zip(objects, before):
                    self.assertEqual(vars(value), original)
        error = FlowDirectionError("packet does not belong to identity")
        with patch("analysis.directional_flow_statistics.flow_direction_from_packet", side_effect=error):
            with self.assertRaises(FlowDirectionError) as failure:
                update_directional_flow_statistics(self.current, TCP_ANALYSIS, self.identity)
        self.assertIs(failure.exception, error)

    def test_checksums_timestamps_and_payloads_do_not_affect_accumulation(self) -> None:
        for analysis, layer in ANALYSES:
            identity = flow_identity_from_packet(analysis)
            ipv4 = cast(IPv4Packet, analysis.ipv4)
            transport = getattr(analysis, layer)
            packets = [replace(analysis, **{name: checksum}) for name in (
                "ipv4_checksum_valid", "tcp_checksum_valid", "udp_checksum_valid", "icmp_checksum_valid",
            ) for checksum in (True, False, None)]
            packets.extend((
                replace(analysis, observation=replace(OBSERVATION,
                        captured_at=OBSERVATION.captured_at - timedelta(days=10))),
                replace(analysis, observation=replace(OBSERVATION, raw_bytes=b"\x7f\x01\x00")),
                replace(analysis, ipv4=replace(ipv4, payload=bytes(12), total_length=32)),
                replace(analysis, **{layer: replace(transport, payload=b"\x00\xff\x80",
                        **({"length": 11} if layer == "udp" else {}))}),
            ))
            current = DirectionalFlowStatistics(identity, 2, 3, 6, 9, 60, 90)
            expected = DirectionalFlowStatistics(identity, 3, 3, 9, 9, 90, 90)
            for packet in packets:
                with self.subTest(protocol=layer, packet=packet):
                    self.assertEqual(update_directional_flow_statistics(current, packet, identity), expected)

    def test_model_has_exactly_seven_value_fields_and_is_frozen(self) -> None:
        result = update_directional_flow_statistics(None, TCP_ANALYSIS, self.identity)
        self.assertEqual(tuple(field.name for field in fields(result)), (
            "identity", "forward_packet_count", "reverse_packet_count", "forward_captured_bytes",
            "reverse_captured_bytes", "forward_original_bytes", "reverse_original_bytes",
        ))
        self.assertEqual(set(vars(result)), {field.name for field in fields(result)})
        for field in fields(result):
            value = getattr(result, field.name)
            self.assertIsInstance(value, FlowIdentity if field.name == "identity" else int)
            self.assertNotIsInstance(value, (PacketAnalysis, PacketObservation, bytes, datetime, FlowDirection,
                                           list, dict, set, bytearray))
            with self.assertRaises(FrozenInstanceError):
                setattr(result, field.name, None)
            with self.assertRaises(FrozenInstanceError):
                delattr(result, field.name)

    def test_model_counter_types_and_negative_values_are_rejected(self) -> None:
        self.assertTrue(issubclass(DirectionalFlowStatisticsError, ValueError))
        for value in (None, False, 1, [], SimpleNamespace(**vars(self.identity))):
            with self.assertRaises(TypeError):
                replace(self.current, identity=value)
        for field in fields(self.current):
            if field.name == "identity":
                continue
            for value in (True, False, None, 1.0, "1", [], SimpleNamespace()):
                with self.subTest(field=field.name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.current, **{field.name: value})
            with self.subTest(field=field.name):
                with self.assertRaises(DirectionalFlowStatisticsError):
                    replace(self.current, **{field.name: -1})

    def test_zero_models_and_independent_directional_original_byte_invariants(self) -> None:
        zero = DirectionalFlowStatistics(self.identity, 0, 0, 0, 0, 0, 0)
        self.assertEqual(update_directional_flow_statistics(zero, TCP_ANALYSIS, self.identity),
                         DirectionalFlowStatistics(self.identity, 1, 0, 3, 0, 30, 0))
        for name, value in (("forward_original_bytes", 5), ("reverse_original_bytes", 8)):
            with self.subTest(field=name):
                with self.assertRaises(DirectionalFlowStatisticsError):
                    replace(self.current, **{name: value})
        equal = replace(self.current, forward_original_bytes=6, reverse_original_bytes=9)
        self.assertEqual(equal.forward_original_bytes, equal.forward_captured_bytes)
        self.assertEqual(equal.reverse_original_bytes, equal.reverse_captured_bytes)
