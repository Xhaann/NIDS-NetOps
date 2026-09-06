import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from types import SimpleNamespace
from typing import cast

from analysis import (
    FlowDirection,
    FlowDirectionError,
    FlowIdentity,
    FlowIdentityError,
    ICMPMessage,
    IPv4Packet,
    PacketAnalysis,
    TCPPacket,
    UDPPacket,
    flow_direction_from_packet,
    flow_identity_from_packet,
)
from capture.packet_observation import CaptureSource, PacketObservation


OBSERVATION = PacketObservation(
    captured_at=datetime(2026, 9, 6, tzinfo=timezone.utc),
    link_type=None,
    captured_length=3,
    original_length=30,
    raw_bytes=b"\x00\x80\xff",
    source=CaptureSource("test-flow-direction"),
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


class FlowDirectionTests(unittest.TestCase):
    def test_forward_reverse_and_repeated_calls_for_tcp_and_udp(self) -> None:
        for analysis, layer in ANALYSES:
            with self.subTest(protocol=layer):
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
                self.assertEqual(flow_identity_from_packet(reverse), identity)
                for packet, expected in (
                    (reverse, FlowDirection.REVERSE),
                    (analysis, FlowDirection.FORWARD),
                    (replace(analysis), FlowDirection.FORWARD),
                    (reverse, FlowDirection.REVERSE),
                ):
                    self.assertIs(flow_direction_from_packet(packet, identity), expected)
                    self.assertIs(flow_direction_from_packet(packet, replace(identity)), expected)

    def test_equal_addresses_use_ports_for_canonical_direction(self) -> None:
        for analysis, layer in ANALYSES:
            with self.subTest(protocol=layer):
                ipv4 = cast(IPv4Packet, analysis.ipv4)
                packet = replace(analysis, ipv4=replace(ipv4, destination_address=ipv4.source_address))
                identity = flow_identity_from_packet(packet)
                self.assertEqual(identity.source_address, identity.destination_address)
                self.assertEqual(identity.source_port, 443)
                self.assertEqual(identity.destination_port, 12345)
                self.assertIs(flow_direction_from_packet(packet, identity), FlowDirection.REVERSE)
                transport = getattr(packet, layer)
                reverse = replace(packet, **{layer: replace(
                    transport, source_port=443, destination_port=12345)})
                self.assertIs(flow_direction_from_packet(reverse, identity), FlowDirection.FORWARD)

    def test_identical_endpoints_choose_forward(self) -> None:
        for analysis, layer in ANALYSES:
            with self.subTest(protocol=layer):
                ipv4 = cast(IPv4Packet, analysis.ipv4)
                transport = getattr(analysis, layer)
                packet = replace(
                    analysis,
                    ipv4=replace(ipv4, destination_address=ipv4.source_address),
                    **{layer: replace(transport, destination_port=transport.source_port)},
                )
                identity = flow_identity_from_packet(packet)
                self.assertIs(flow_direction_from_packet(packet, identity), FlowDirection.FORWARD)

    def test_each_address_and_port_must_match_both_endpoints(self) -> None:
        for analysis, layer in ANALYSES:
            ipv4 = cast(IPv4Packet, analysis.ipv4)
            transport = getattr(analysis, layer)
            identity = flow_identity_from_packet(analysis)
            invalid_packets = (
                replace(analysis, ipv4=replace(ipv4, source_address=b"\x0a\x00\x00\x03")),
                replace(analysis, ipv4=replace(ipv4, destination_address=b"\x0a\x00\x00\x03")),
                replace(analysis, **{layer: replace(transport, source_port=12346)}),
                replace(analysis, **{layer: replace(transport, destination_port=444)}),
                replace(analysis, ipv4=replace(
                    ipv4, source_address=ipv4.destination_address, destination_address=ipv4.source_address)),
                replace(analysis, **{layer: replace(
                    transport, source_port=transport.destination_port, destination_port=transport.source_port)}),
            )
            for packet in invalid_packets:
                with self.subTest(protocol=layer, packet=packet):
                    with self.assertRaises(FlowDirectionError):
                        flow_direction_from_packet(packet, identity)
            with self.assertRaises(FlowDirectionError):
                flow_direction_from_packet(analysis, replace(identity, destination_port=444))

    def test_tcp_and_udp_protocol_mismatch_raises_direction_error(self) -> None:
        for analysis, layer in ANALYSES:
            with self.subTest(protocol=layer):
                identity = flow_identity_from_packet(analysis)
                other = replace(identity, protocol=17 if identity.protocol == 6 else 6)
                self.assertNotEqual(identity, other)
                with self.assertRaises(FlowDirectionError):
                    flow_direction_from_packet(analysis, other)

    def test_invalid_packet_layers_preserve_flow_identity_error_semantics(self) -> None:
        invalid_packets = (
            replace(TCP_ANALYSIS, ipv4=None),
            replace(TCP_ANALYSIS, tcp=None),
            replace(UDP_ANALYSIS, udp=None),
            replace(TCP_ANALYSIS, udp=UDP_PACKET),
            replace(UDP_ANALYSIS, tcp=TCP_PACKET),
            replace(TCP_ANALYSIS, icmp=ICMPMessage(0, 0, 0, bytes(4), b"")),
            replace(UDP_ANALYSIS, icmp=ICMPMessage(0, 0, 0, bytes(4), b"")),
            replace(TCP_ANALYSIS, ipv4=replace(IPV4_PACKET, protocol=1), tcp=None,
                    icmp=ICMPMessage(0, 0, 0, bytes(4), b"")),
            replace(TCP_ANALYSIS, ipv4=replace(IPV4_PACKET, protocol=253), tcp=None),
        )
        identity = flow_identity_from_packet(TCP_ANALYSIS)
        for packet in invalid_packets:
            with self.subTest(packet=packet):
                with self.assertRaises(FlowIdentityError) as existing:
                    flow_identity_from_packet(packet)
                with self.assertRaises(FlowIdentityError) as direction:
                    flow_direction_from_packet(packet, identity)
                self.assertIs(type(direction.exception), type(existing.exception))
                self.assertEqual(str(direction.exception), str(existing.exception))

    def test_wrong_argument_types_raise_type_error(self) -> None:
        identity = flow_identity_from_packet(TCP_ANALYSIS)
        for value in (None, False, OBSERVATION, SimpleNamespace(**vars(TCP_ANALYSIS))):
            with self.subTest(argument="analysis", value=value):
                with self.assertRaises(TypeError):
                    flow_direction_from_packet(cast(PacketAnalysis, value), identity)
        for value in (None, False, TCP_ANALYSIS, SimpleNamespace(**vars(identity))):
            with self.subTest(argument="identity", value=value):
                with self.assertRaises(TypeError):
                    flow_direction_from_packet(TCP_ANALYSIS, cast(FlowIdentity, value))

    def test_non_endpoint_data_does_not_affect_direction_or_change_inputs(self) -> None:
        for analysis, layer in ANALYSES:
            identity = flow_identity_from_packet(analysis)
            ipv4 = cast(IPv4Packet, analysis.ipv4)
            transport = getattr(analysis, layer)
            for checksum in (True, False, None):
                with self.subTest(protocol=layer, checksum=checksum):
                    changes = {"payload": b"\x00\xff\x80"}
                    if layer == "tcp":
                        changes.update(syn=True, ack=True, fin=True, rst=True, sequence_number=123)
                    else:
                        changes.update(length=11)
                    packet = replace(
                        analysis,
                        observation=replace(OBSERVATION, captured_at=OBSERVATION.captured_at - timedelta(days=1),
                                            raw_bytes=b"\xff" * 5, captured_length=5, original_length=50),
                        ipv4=replace(ipv4, ttl=0, payload=bytes(10), total_length=30),
                        ipv4_checksum_valid=checksum,
                        **{layer: replace(transport, **changes), f"{layer}_checksum_valid": checksum},
                    )
                    objects = (analysis, analysis.observation, ipv4, transport, identity,
                               packet, packet.observation, packet.ipv4, getattr(packet, layer))
                    before = [vars(value).copy() for value in objects]
                    self.assertIs(flow_direction_from_packet(packet, identity), FlowDirection.FORWARD)
                    self.assertIs(flow_direction_from_packet(analysis, identity), FlowDirection.FORWARD)
                    with self.assertRaises(FlowDirectionError):
                        flow_direction_from_packet(packet, replace(identity, source_port=12346))
                    for value, original in zip(objects, before):
                        self.assertEqual(vars(value), original)
                        for name, reference in original.items():
                            self.assertIs(getattr(value, name), reference)

    def test_enum_has_only_forward_and_reverse_with_read_only_names_and_values(self) -> None:
        self.assertTrue(issubclass(FlowDirection, Enum))
        self.assertEqual(tuple(FlowDirection), (FlowDirection.FORWARD, FlowDirection.REVERSE))
        self.assertEqual(set(FlowDirection.__members__), {"FORWARD", "REVERSE"})
        for member, value in ((FlowDirection.FORWARD, "forward"), (FlowDirection.REVERSE, "reverse")):
            self.assertEqual(member.value, value)
            self.assertIs(FlowDirection(value), member)
            self.assertNotIsInstance(member, str)
            for name in ("name", "value"):
                with self.assertRaises(AttributeError):
                    setattr(member, name, "changed")
                with self.assertRaises(AttributeError):
                    delattr(member, name)
