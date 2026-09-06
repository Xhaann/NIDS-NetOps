import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import cast

from analysis import (
    EthernetFrame,
    FlowIdentity,
    FlowIdentityError,
    ICMPMessage,
    IPv4Packet,
    PacketAnalysis,
    TCPPacket,
    UDPPacket,
    flow_identity_from_packet,
)
from capture.packet_observation import CaptureSource, PacketObservation


SOURCE_ADDRESS = b"\x0a\x00\x00\x01"
DESTINATION_ADDRESS = b"\x0a\x00\x00\x02"
OBSERVATION = PacketObservation(
    captured_at=datetime(2026, 9, 6, tzinfo=timezone.utc),
    link_type=None,
    captured_length=0,
    original_length=0,
    raw_bytes=b"",
    source=CaptureSource("test-flow-identity"),
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
    source_address=SOURCE_ADDRESS,
    destination_address=DESTINATION_ADDRESS,
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


class FlowIdentityFromPacketTests(unittest.TestCase):
    def test_forward_and_reverse_packets_have_expected_identity(self) -> None:
        for analysis, layer in ANALYSES:
            with self.subTest(protocol=layer):
                ipv4 = cast(IPv4Packet, analysis.ipv4)
                transport = getattr(analysis, layer)
                reverse = replace(
                    analysis,
                    ipv4=replace(
                        ipv4, source_address=DESTINATION_ADDRESS,
                        destination_address=SOURCE_ADDRESS,
                    ),
                    **{layer: replace(transport, source_port=443, destination_port=12345)},
                )
                expected = FlowIdentity(SOURCE_ADDRESS, DESTINATION_ADDRESS, 12345, 443, ipv4.protocol)
                self.assertEqual(flow_identity_from_packet(analysis), expected)
                self.assertEqual(flow_identity_from_packet(reverse), expected)
                self.assertEqual(flow_identity_from_packet(replace(analysis)), expected)

    def test_protocol_and_each_endpoint_field_distinguish_identities(self) -> None:
        self.assertNotEqual(flow_identity_from_packet(TCP_ANALYSIS), flow_identity_from_packet(UDP_ANALYSIS))
        for analysis, layer in ANALYSES:
            ipv4 = cast(IPv4Packet, analysis.ipv4)
            transport = getattr(analysis, layer)
            for changes in (
                {"ipv4": replace(ipv4, source_address=b"\x0a\x00\x00\x03")},
                {"ipv4": replace(ipv4, destination_address=b"\x0a\x00\x00\x04")},
                {layer: replace(transport, source_port=12346)},
                {layer: replace(transport, destination_port=444)},
            ):
                with self.subTest(protocol=layer, changes=changes):
                    self.assertNotEqual(
                        flow_identity_from_packet(analysis),
                        flow_identity_from_packet(replace(analysis, **changes)),
                    )

    def test_same_address_endpoints_are_ordered_by_port(self) -> None:
        for analysis, layer in ANALYSES:
            for source_port, destination_port in ((65535, 0), (0, 65535), (443, 443)):
                with self.subTest(protocol=layer, ports=(source_port, destination_port)):
                    ipv4 = replace(cast(IPv4Packet, analysis.ipv4), destination_address=SOURCE_ADDRESS)
                    transport = replace(
                        getattr(analysis, layer), source_port=source_port,
                        destination_port=destination_port,
                    )
                    result = flow_identity_from_packet(replace(analysis, ipv4=ipv4, **{layer: transport}))
                    self.assertEqual(
                        result,
                        FlowIdentity(SOURCE_ADDRESS, SOURCE_ADDRESS, min(source_port, destination_port),
                                     max(source_port, destination_port), ipv4.protocol),
                    )

    def test_missing_unsupported_and_conflicting_models_are_rejected(self) -> None:
        icmp = ICMPMessage(0, 0, 0, bytes(4), b"")
        invalid = (
            replace(TCP_ANALYSIS, ipv4=None),
            replace(TCP_ANALYSIS, tcp=None),
            replace(UDP_ANALYSIS, udp=None),
            replace(TCP_ANALYSIS, tcp=None, udp=UDP_PACKET),
            replace(UDP_ANALYSIS, udp=None, tcp=TCP_PACKET),
            replace(TCP_ANALYSIS, udp=UDP_PACKET),
            replace(UDP_ANALYSIS, tcp=TCP_PACKET),
            replace(TCP_ANALYSIS, icmp=icmp),
            replace(UDP_ANALYSIS, icmp=icmp),
        )
        for analysis in invalid:
            with self.subTest(analysis=analysis):
                with self.assertRaises(FlowIdentityError):
                    flow_identity_from_packet(analysis)
        for protocol in (0, 1, 7, 16, 255):
            with self.subTest(protocol=protocol):
                analysis = replace(TCP_ANALYSIS, ipv4=replace(IPV4_PACKET, protocol=protocol))
                with self.assertRaises(FlowIdentityError):
                    flow_identity_from_packet(analysis)

    def test_wrong_top_level_type_is_rejected(self) -> None:
        for value in (None, IPV4_PACKET, SimpleNamespace(**vars(TCP_ANALYSIS))):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    flow_identity_from_packet(cast(PacketAnalysis, value))

    def test_checksum_results_do_not_affect_identity(self) -> None:
        for analysis, layer in ANALYSES:
            for ipv4_valid in (True, False, None):
                for transport_valid in (True, False, None):
                    with self.subTest(protocol=layer, ipv4=ipv4_valid, transport=transport_valid):
                        changed = replace(
                            analysis, ipv4_checksum_valid=ipv4_valid,
                            **{f"{layer}_checksum_valid": transport_valid},
                        )
                        self.assertEqual(flow_identity_from_packet(changed), flow_identity_from_packet(analysis))

    def test_only_decoded_endpoint_fields_are_used_without_mutating_analysis(self) -> None:
        observation = replace(
            OBSERVATION,
            captured_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source=CaptureSource("different-source"),
            raw_bytes=b"\xff\x00\x80", captured_length=3, original_length=100,
        )
        for analysis, layer in ANALYSES:
            with self.subTest(protocol=layer):
                ipv4 = cast(IPv4Packet, analysis.ipv4)
                transport = getattr(analysis, layer)
                changes = {"checksum": 65535, "payload": b"\x00\xff"}
                if layer == "tcp":
                    changes.update(sequence_number=123, acknowledgment_number=456, syn=True)
                else:
                    changes.update(length=10)
                changed = replace(
                    analysis, observation=observation,
                    ethernet=EthernetFrame(bytes(6), bytes(6), 0, b"unrelated"),
                    ipv4=replace(ipv4, ttl=0, header_checksum=65535, ihl=6,
                                 options=b"\x00\xff\x80\x7f", total_length=ipv4.total_length + 4),
                    **{layer: replace(transport, **changes)},
                )
                before = replace(changed)
                self.assertEqual(flow_identity_from_packet(changed), flow_identity_from_packet(analysis))
                self.assertEqual(changed, before)
                self.assertIs(changed.observation, observation)
                self.assertIs(getattr(changed, layer), getattr(before, layer))


class FlowIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = FlowIdentity(SOURCE_ADDRESS, DESTINATION_ADDRESS, 12345, 443, 6)

    def test_direct_construction_canonicalizes_complete_binary_endpoints(self) -> None:
        first = b"\x01\xff\x80\x00"
        second = b"\x80\x00\x00\x01"
        for protocol in (6, 17):
            with self.subTest(protocol=protocol):
                forward = FlowIdentity(first, second, 65535, 0, protocol)
                reverse = FlowIdentity(second, first, 0, 65535, protocol)
                self.assertEqual(forward, reverse)
                self.assertIs(reverse.source_address, first)
                self.assertIs(reverse.destination_address, second)
                self.assertEqual((reverse.source_port, reverse.destination_port), (65535, 0))
                self.assertEqual(
                    FlowIdentity(first, first, 65535, 0, protocol),
                    FlowIdentity(first, first, 0, 65535, protocol),
                )

    def test_addresses_require_exactly_four_immutable_bytes(self) -> None:
        for name in ("source_address", "destination_address"):
            for value in (b"", bytes(3), bytes(5)):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(ValueError):
                        replace(self.identity, **{name: value})
            for value in (bytearray(4), memoryview(bytes(4)), "10.0.0.1", None):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.identity, **{name: value})

    def test_ports_and_protocol_reject_invalid_types_and_values(self) -> None:
        for name in ("source_port", "destination_port", "protocol"):
            for value in (True, False, 6.0, "6", None):
                with self.subTest(field=name, value=value):
                    with self.assertRaises(TypeError):
                        replace(self.identity, **{name: value})
            invalid = (-1, 65536) if name != "protocol" else (-1, 0, 1, 7, 16, 18, 255)
            for value in invalid:
                with self.subTest(field=name, value=value):
                    with self.assertRaises(ValueError):
                        replace(self.identity, **{name: value})

    def test_identity_is_immutable(self) -> None:
        for field in fields(self.identity):
            with self.subTest(field=field.name):
                with self.assertRaises(FrozenInstanceError):
                    setattr(self.identity, field.name, None)
                with self.assertRaises(FrozenInstanceError):
                    delattr(self.identity, field.name)
