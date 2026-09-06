import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

from analysis import (
    FlowIdentity,
    FlowIdentityError,
    FlowPacket,
    FlowSnapshot,
    FlowTracker,
    FlowTrackingError,
    ICMPMessage,
    IPv4Packet,
    PacketAnalysis,
    TCPPacket,
    UDPPacket,
    flow_identity_from_packet,
)
from capture.packet_observation import CaptureSource, PacketObservation


OBSERVATION = PacketObservation(
    captured_at=datetime(2026, 9, 6, tzinfo=timezone.utc),
    link_type=None,
    captured_length=0,
    original_length=0,
    raw_bytes=b"",
    source=CaptureSource("test-flow-tracker"),
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


class FlowTrackerTests(unittest.TestCase):
    def test_empty_tracker_and_lookup_do_not_create_state(self) -> None:
        tracker = FlowTracker()
        self.assertEqual(tracker.flow_count(), 0)
        self.assertEqual(tracker.identities(), ())
        self.assertEqual(tracker.snapshots(), ())
        self.assertIsNone(tracker.get(flow_identity_from_packet(TCP_ANALYSIS)))
        for value in (None, TCP_ANALYSIS, SimpleNamespace()):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    tracker.get(cast(FlowIdentity, value))
        self.assertEqual(tracker.flow_count(), 0)

    def test_bidirectional_stateful_sequence_retains_exact_analyses(self) -> None:
        for first, layer in ANALYSES:
            with self.subTest(protocol=layer):
                tracker = FlowTracker()
                ipv4 = cast(IPv4Packet, first.ipv4)
                transport = getattr(first, layer)
                reverse = replace(
                    first,
                    ipv4=replace(ipv4, source_address=ipv4.destination_address,
                                 destination_address=ipv4.source_address),
                    **{layer: replace(transport, source_port=transport.destination_port,
                                      destination_port=transport.source_port)},
                )
                third = replace(first)
                different = replace(first, **{layer: replace(transport, source_port=12346)})
                initial = tracker.record(first)
                identities = tracker.identities()
                snapshots = tracker.snapshots()
                self.assertIsInstance(identities, tuple)
                self.assertIsInstance(snapshots, tuple)
                self.assertEqual(initial.packet_count, 1)
                self.assertEqual(tracker.flow_count(), 1)
                self.assertIs(initial.first_analysis, first)
                self.assertIs(initial.last_analysis, first)
                for count, analysis in ((2, reverse), (3, third)):
                    current = tracker.record(analysis)
                    self.assertEqual(tracker.flow_count(), 1)
                    self.assertEqual(current.packet_count, count)
                    self.assertIs(current.first_analysis, first)
                    self.assertIs(current.last_analysis, analysis)
                    self.assertIs(tracker.get(initial.identity), current)
                    self.assertIsNot(current, initial)
                other = tracker.record(different)
                self.assertEqual(tracker.flow_count(), 2)
                self.assertEqual(other.packet_count, 1)
                self.assertIs(other.first_analysis, different)
                self.assertIs(other.last_analysis, different)
                self.assertEqual(tracker.identities(), (initial.identity, other.identity))
                self.assertEqual(tracker.snapshots(), (current, other))
                self.assertEqual(identities, (initial.identity,))
                self.assertEqual(snapshots, (initial,))
                self.assertEqual(initial.packet_count, 1)
                self.assertIs(initial.last_analysis, first)

    def test_repeated_and_equivalent_packets_are_counted_each_time(self) -> None:
        tracker = FlowTracker()
        other_tracker = FlowTracker()
        for count, analysis in enumerate((TCP_ANALYSIS, TCP_ANALYSIS, replace(TCP_ANALYSIS)), 1):
            snapshot = tracker.record(analysis)
            self.assertEqual(snapshot.packet_count, count)
            self.assertIs(snapshot.first_analysis, TCP_ANALYSIS)
            self.assertIs(snapshot.last_analysis, analysis)
        self.assertEqual(tracker.flow_count(), 1)
        self.assertEqual(other_tracker.flow_count(), 0)

    def test_protocol_addresses_and_ports_create_distinct_entries(self) -> None:
        tracker = FlowTracker()
        analyses = (
            TCP_ANALYSIS,
            UDP_ANALYSIS,
            replace(TCP_ANALYSIS, tcp=replace(TCP_PACKET, source_port=12346)),
            replace(UDP_ANALYSIS, udp=replace(UDP_PACKET, destination_port=444)),
            replace(TCP_ANALYSIS, ipv4=replace(IPV4_PACKET, source_address=b"\x0a\x00\x00\x03")),
            replace(TCP_ANALYSIS, ipv4=replace(IPV4_PACKET, destination_address=b"\x0a\x00\x00\x04")),
        )
        for count, analysis in enumerate(analyses, 1):
            snapshot = tracker.record(analysis)
            self.assertEqual(snapshot.packet_count, 1)
            self.assertEqual(tracker.flow_count(), count)
            self.assertIs(tracker.get(snapshot.identity), snapshot)
        before = tracker.snapshots()
        unknown = FlowIdentity(bytes(4), bytes(4), 0, 0, 6)
        self.assertIsNone(tracker.get(unknown))
        self.assertEqual(tracker.snapshots(), before)
        self.assertEqual(tracker.flow_count(), len(analyses))

    def test_checksum_false_and_none_do_not_prevent_recording(self) -> None:
        for original, layer in ANALYSES:
            with self.subTest(protocol=layer):
                tracker = FlowTracker()
                for count, checksum in enumerate((False, None), 1):
                    analysis = replace(original, ipv4_checksum_valid=checksum,
                                       **{f"{layer}_checksum_valid": checksum})
                    snapshot = tracker.record(analysis)
                    self.assertEqual(snapshot.packet_count, count)
                    self.assertIs(snapshot.last_analysis, analysis)
                self.assertEqual(tracker.flow_count(), 1)

    def test_invalid_records_leave_existing_or_empty_state_unchanged(self) -> None:
        for populated in (False, True):
            with self.subTest(populated=populated):
                tracker = FlowTracker()
                if populated:
                    tracker.record(TCP_ANALYSIS)
                before = tracker.snapshots()
                identities = tracker.identities()
                for invalid in (
                    replace(TCP_ANALYSIS, ipv4=None),
                    replace(TCP_ANALYSIS, tcp=None),
                    replace(TCP_ANALYSIS, ipv4=replace(IPV4_PACKET, protocol=253)),
                    replace(TCP_ANALYSIS, ipv4=replace(IPV4_PACKET, protocol=1),
                            tcp=None, icmp=ICMPMessage(0, 0, 0, bytes(4), b"")),
                ):
                    with self.assertRaises(FlowIdentityError):
                        tracker.record(invalid)
                for value in (None, OBSERVATION, SimpleNamespace(**vars(TCP_ANALYSIS))):
                    with self.assertRaises(TypeError):
                        tracker.record(cast(PacketAnalysis, value))
                self.assertEqual(tracker.flow_count(), len(before))
                self.assertEqual(tracker.identities(), identities)
                self.assertEqual(tracker.snapshots(), before)
                for snapshot in before:
                    self.assertIs(tracker.get(snapshot.identity), snapshot)

    def test_record_delegates_once_and_retains_returned_identity_objects(self) -> None:
        tracker = FlowTracker()
        first_identity = FlowIdentity(bytes(4), b"\xff" * 4, 0, 65535, 17)
        second_identity = replace(first_identity)
        for identity in (first_identity, second_identity):
            with patch("analysis.flow_tracker.flow_identity_from_packet", return_value=identity) as factory:
                snapshot = tracker.record(TCP_ANALYSIS)
                factory.assert_called_once_with(TCP_ANALYSIS)
            self.assertIs(snapshot.identity, identity)
            self.assertIs(tracker.get(identity), snapshot)
            self.assertEqual(tracker.flow_count(), 1)
            self.assertIs(tracker.identities()[0], first_identity)
        self.assertEqual(snapshot.packet_count, 2)

    def test_identity_and_snapshot_failures_are_atomic_and_propagate_unchanged(self) -> None:
        for populated in (False, True):
            for target, error in (
                ("flow_identity_from_packet", FlowIdentityError("identity unavailable")),
                ("FlowSnapshot", FlowTrackingError("snapshot invalid")),
            ):
                with self.subTest(populated=populated, stage=target):
                    tracker = FlowTracker()
                    if populated:
                        tracker.record(TCP_ANALYSIS)
                    before = tracker.snapshots()
                    identities = tracker.identities()
                    with patch(f"analysis.flow_tracker.{target}", side_effect=error):
                        with self.assertRaises(type(error)) as failure:
                            tracker.record(TCP_ANALYSIS)
                    self.assertIs(failure.exception, error)
                    self.assertEqual(tracker.snapshots(), before)
                    self.assertEqual(tracker.identities(), identities)
                    self.assertEqual(tracker.flow_count(), len(before))
                    for snapshot in before:
                        self.assertIs(tracker.get(snapshot.identity), snapshot)


class FlowModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = flow_identity_from_packet(TCP_ANALYSIS)
        self.packet = FlowPacket(self.identity, TCP_ANALYSIS)
        self.latest = replace(TCP_ANALYSIS)
        self.snapshot = FlowSnapshot(self.identity, 2, TCP_ANALYSIS, self.latest)

    def test_models_retain_exact_references_and_are_immutable(self) -> None:
        self.assertIs(self.packet.identity, self.identity)
        self.assertIs(self.packet.analysis, TCP_ANALYSIS)
        self.assertIs(self.snapshot.identity, self.identity)
        self.assertIs(self.snapshot.first_analysis, TCP_ANALYSIS)
        self.assertIs(self.snapshot.last_analysis, self.latest)
        for model in (self.packet, self.snapshot):
            for field in fields(model):
                with self.subTest(model=type(model).__name__, field=field.name):
                    with self.assertRaises(FrozenInstanceError):
                        setattr(model, field.name, None)
                    with self.assertRaises(FrozenInstanceError):
                        delattr(model, field.name)

    def test_model_field_types_are_validated(self) -> None:
        for model in (self.packet, self.snapshot):
            for field in fields(model):
                for value in (None, [], SimpleNamespace()):
                    with self.subTest(model=type(model).__name__, field=field.name, value=value):
                        with self.assertRaises(TypeError):
                            replace(model, **{field.name: value})

    def test_packet_count_requires_positive_exact_integer(self) -> None:
        for value in (True, False, 1.0, "1"):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    replace(self.snapshot, packet_count=value)
        for value in (0, -1):
            with self.subTest(value=value):
                with self.assertRaises(FlowTrackingError) as failure:
                    replace(self.snapshot, packet_count=value)
                self.assertIsInstance(failure.exception, ValueError)
