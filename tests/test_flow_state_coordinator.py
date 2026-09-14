import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

from analysis import (
    CoordinatedFlowState,
    FlowCoordinationError,
    FlowIdentityError,
    FlowInterArrivalStatisticsError,
    FlowRateFeaturesError,
    FlowStateCoordinator,
    FlowStatisticsError,
    IPv4Packet,
    PacketAnalysis,
    TCPControlStatistics,
    TCPControlStatisticsError,
    TCPPacket,
    UDPPacket,
    extract_flow_duration_features,
    extract_flow_rate_features,
    extract_inter_arrival_features,
    flow_identity_from_packet,
    update_directional_flow_statistics,
    update_directional_inter_arrival_statistics,
    update_flow_inter_arrival_statistics,
    update_flow_packet_size_statistics,
    update_flow_statistics,
    update_tcp_control_statistics,
)
from capture.packet_observation import CaptureSource, PacketObservation


TIMESTAMP = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
OBSERVATION = PacketObservation(
    TIMESTAMP, None, 60, 100, bytes(60), CaptureSource("test-flow-coordination"),
)
IPV4 = IPv4Packet(
    version=4, ihl=5, dscp=0, ecn=0, total_length=28, identification=0, flags=0,
    fragment_offset=0, ttl=64, protocol=17, header_checksum=0,
    source_address=b"\x0a\x00\x00\x01", destination_address=b"\x0a\x00\x00\x02",
    options=b"", payload=bytes(8),
)
UDP_ANALYSIS = PacketAnalysis(OBSERVATION, ipv4=IPV4, udp=UDPPacket(12345, 443, 8, 0, b""))
TCP_ANALYSIS = PacketAnalysis(
    OBSERVATION, ipv4=replace(IPV4, protocol=6, total_length=40, payload=bytes(20)),
    tcp=TCPPacket(
        source_port=12345, destination_port=443, sequence_number=0, acknowledgment_number=0,
        data_offset=5, reserved_bits=0, ns=False, cwr=False, ece=False, urg=False, ack=False,
        psh=False, rst=False, syn=False, fin=False, window_size=0, checksum=0,
        urgent_pointer=0, options=b"", payload=b"",
    ),
)


def packet_at(seconds: float, reverse: bool = False, captured: int = 60) -> PacketAnalysis:
    packet = replace(UDP_ANALYSIS, observation=replace(
        OBSERVATION, captured_at=TIMESTAMP + timedelta(seconds=seconds),
        captured_length=captured, original_length=captured + 40, raw_bytes=bytes(captured),
    ))
    if reverse:
        packet = replace(
            packet,
            ipv4=replace(IPV4, source_address=IPV4.destination_address,
                         destination_address=IPV4.source_address),
            udp=replace(packet.udp, source_port=443, destination_port=12345),
        )
    return packet


def tcp_packet_at(
    seconds: float,
    reverse: bool = False,
    captured: int = 60,
    **flags,
) -> PacketAnalysis:
    packet = replace(
        TCP_ANALYSIS,
        observation=replace(
            OBSERVATION,
            captured_at=TIMESTAMP + timedelta(seconds=seconds),
            captured_length=captured,
            original_length=captured + 40,
            raw_bytes=bytes(captured),
        ),
        tcp=replace(TCP_ANALYSIS.tcp, **flags),
    )
    if reverse:
        packet = replace(
            packet,
            ipv4=replace(
                TCP_ANALYSIS.ipv4,
                source_address=TCP_ANALYSIS.ipv4.destination_address,
                destination_address=TCP_ANALYSIS.ipv4.source_address,
            ),
            tcp=replace(packet.tcp, source_port=443, destination_port=12345),
        )
    return packet


def state_components(state: CoordinatedFlowState) -> tuple:
    return tuple(value for value in vars(state).values() if value is not None)


class FlowStateCoordinatorTests(unittest.TestCase):
    def assert_atomic_failure(self, coordinator, packet, error) -> None:
        current = coordinator.state
        objects = [coordinator, packet, packet.observation]
        objects.extend(value for value in (packet.ipv4, packet.tcp, packet.udp) if value is not None)
        if current is not None:
            objects.extend([current, current.identity])
            objects.extend(state_components(current))
        before = [vars(value).copy() for value in objects]
        with self.assertRaises(error):
            coordinator.record(packet)
        self.assertIs(coordinator.state, current)
        for value, original in zip(objects, before):
            self.assertEqual(vars(value), original)

    def test_empty_and_first_packet_publish_protocol_correct_state(self) -> None:
        for packet in (UDP_ANALYSIS, TCP_ANALYSIS, packet_at(0, True)):
            coordinator = FlowStateCoordinator()
            self.assertIsNone(coordinator.state)
            state = coordinator.record(packet)
            self.assertIs(type(state), CoordinatedFlowState)
            self.assertIs(coordinator.state, state)
            self.assertEqual(state.identity, flow_identity_from_packet(packet))
            self.assertIs(state.identity, state.flow_statistics.identity)
            for accumulator in state_components(state):
                self.assertIs(accumulator.identity, state.identity)
            if state.identity.protocol == 6:
                self.assertIs(type(state.tcp_control_statistics), TCPControlStatistics)
                self.assertIs(state.tcp_control_statistics.identity, state.identity)
            else:
                self.assertIsNone(state.tcp_control_statistics)
            self.assertEqual(state.flow_statistics.packet_count, 1)
            self.assertEqual(state.flow_statistics.captured_bytes, 60)
            self.assertEqual(state.flow_statistics.original_bytes, 100)
            self.assertEqual(state.flow_packet_size_statistics.packet_count, 1)
            self.assertEqual(state.flow_packet_size_statistics.sum_captured_length_squares, 3600)
            self.assertEqual(state.flow_inter_arrival_statistics.inter_arrival_count, 0)
            directional = state.directional_inter_arrival_statistics
            self.assertEqual(directional.forward_inter_arrival_count, 0)
            self.assertEqual(directional.reverse_inter_arrival_count, 0)
            self.assertIs(state.flow_statistics.first_captured_at, packet.observation.captured_at)

    def test_mixed_sequence_keeps_global_and_directional_state_coherent(self) -> None:
        coordinator = FlowStateCoordinator()
        first = None
        for count, (seconds, reverse) in enumerate(((0, False), (1, True), (3, False), (4, True), (7, False)), 1):
            packet = packet_at(seconds, reverse, 50 + count * 10)
            previous = coordinator.state
            state = coordinator.record(packet)
            if first is None:
                first = state
            self.assertIsNot(state, previous)
            self.assertIs(state.identity, first.identity)
            self.assertEqual(state.flow_statistics.packet_count, count)
            self.assertEqual(state.flow_packet_size_statistics.packet_count, count)
            self.assertEqual(state.flow_inter_arrival_statistics.packet_count, count)
            self.assertEqual(state.directional_inter_arrival_statistics.packet_count, count)
            self.assertIsNone(state.tcp_control_statistics)
            directional = state.directional_flow_statistics
            self.assertEqual(directional.forward_packet_count + directional.reverse_packet_count, count)
            if count == 2:
                timing = state.directional_inter_arrival_statistics
                self.assertEqual(timing.forward_inter_arrival_count, 0)
                self.assertEqual(timing.reverse_inter_arrival_count, 0)
            if count == 3:
                self.assertEqual(state.directional_inter_arrival_statistics.last_reverse_captured_at,
                                 TIMESTAMP + timedelta(seconds=1))
        self.assertEqual(first.flow_statistics.packet_count, 1)
        self.assertEqual(state.flow_statistics.captured_bytes, 400)
        self.assertEqual(state.flow_statistics.original_bytes, 600)
        sizes = state.flow_packet_size_statistics
        self.assertEqual((sizes.min_captured_length, sizes.max_captured_length), (60, 100))
        self.assertEqual(sizes.sum_captured_length_squares, 33000)
        self.assertEqual(sizes.sum_original_length_squares, 73000)
        self.assertEqual((directional.forward_packet_count, directional.reverse_packet_count), (3, 2))
        self.assertEqual((directional.forward_captured_bytes, directional.reverse_captured_bytes), (240, 160))
        self.assertEqual((directional.forward_original_bytes, directional.reverse_original_bytes), (360, 240))
        timing = state.flow_inter_arrival_statistics
        self.assertEqual((timing.inter_arrival_count, timing.inter_arrival_sum_seconds,
                          timing.inter_arrival_sum_seconds_squared), (4, 7.0, 15.0))
        timing = state.directional_inter_arrival_statistics
        self.assertEqual((timing.forward_inter_arrival_count, timing.reverse_inter_arrival_count), (2, 1))
        self.assertEqual((timing.forward_inter_arrival_sum_seconds, timing.reverse_inter_arrival_sum_seconds), (7.0, 3.0))
        self.assertEqual((timing.forward_inter_arrival_sum_seconds_squared,
                          timing.reverse_inter_arrival_sum_seconds_squared), (25.0, 9.0))
        self.assertEqual((timing.forward_min_inter_arrival_seconds, timing.forward_max_inter_arrival_seconds), (3.0, 4.0))
        self.assertEqual(timing.last_forward_captured_at, TIMESTAMP + timedelta(seconds=7))
        self.assertEqual(timing.last_reverse_captured_at, TIMESTAMP + timedelta(seconds=4))

    def test_tcp_control_state_tracks_flags_directions_and_identity_atomically(self) -> None:
        packets = (
            tcp_packet_at(0, syn=True),
            tcp_packet_at(1, True, syn=True, ack=True, cwr=True, ece=True),
            tcp_packet_at(2, ns=True, urg=True, ack=True, psh=True, rst=True, fin=True),
            tcp_packet_at(3, True, **{
                "ns": True, "cwr": True, "ece": True, "urg": True, "ack": True,
                "psh": True, "rst": True, "syn": True, "fin": True,
            }),
        )
        coordinator = FlowStateCoordinator()
        first_identity = None
        for count, packet in enumerate(packets, 1):
            previous = coordinator.state
            previous_components = () if previous is None else state_components(previous)
            previous_values = [vars(value).copy() for value in previous_components]
            state = coordinator.record(packet)
            tcp_control = state.tcp_control_statistics
            self.assertIs(type(tcp_control), TCPControlStatistics)
            self.assertEqual(tcp_control.packet_count, count)
            self.assertEqual(tcp_control.packet_count, state.flow_statistics.packet_count)
            self.assertEqual(
                (tcp_control.forward_packet_count, tcp_control.reverse_packet_count),
                (state.directional_flow_statistics.forward_packet_count,
                 state.directional_flow_statistics.reverse_packet_count),
            )
            self.assertIs(tcp_control.identity, state.identity)
            if first_identity is None:
                first_identity = state.identity
            self.assertIs(state.identity, first_identity)
            if previous is not None:
                self.assertIsNot(state, previous)
                self.assertIsNot(tcp_control, previous.tcp_control_statistics)
                for value, original in zip(previous_components, previous_values):
                    self.assertEqual(vars(value), original)
        self.assertEqual((tcp_control.forward_packet_count, tcp_control.reverse_packet_count), (2, 2))
        self.assertEqual(
            (tcp_control.forward_ns_count, tcp_control.forward_urg_count,
             tcp_control.forward_ack_count, tcp_control.forward_psh_count,
             tcp_control.forward_rst_count, tcp_control.forward_syn_count,
             tcp_control.forward_fin_count, tcp_control.forward_syn_ack_count),
            (1, 1, 1, 1, 1, 1, 1, 0),
        )
        self.assertEqual(
            (tcp_control.reverse_ns_count, tcp_control.reverse_cwr_count,
             tcp_control.reverse_ece_count, tcp_control.reverse_urg_count,
             tcp_control.reverse_ack_count, tcp_control.reverse_psh_count,
             tcp_control.reverse_rst_count, tcp_control.reverse_syn_count,
             tcp_control.reverse_fin_count, tcp_control.reverse_syn_ack_count),
            (1, 2, 2, 1, 2, 1, 1, 2, 1, 2),
        )

    def test_tcp_updater_result_is_published_only_with_complete_candidate(self) -> None:
        coordinator = FlowStateCoordinator()
        for packet in (tcp_packet_at(0, syn=True), tcp_packet_at(1, True, syn=True, ack=True)):
            previous = coordinator.state
            results = []

            def observe(current, analysis, identity):
                self.assertIs(coordinator.state, previous)
                self.assertIs(current, None if previous is None else previous.tcp_control_statistics)
                self.assertIs(analysis, packet)
                if previous is None:
                    self.assertEqual(identity, flow_identity_from_packet(packet))
                else:
                    self.assertIs(identity, previous.identity)
                result = update_tcp_control_statistics(current, analysis, identity)
                self.assertIs(coordinator.state, previous)
                results.append(result)
                return result

            with patch(
                "analysis.flow_state_coordinator.update_tcp_control_statistics",
                side_effect=observe,
            ) as updater:
                state = coordinator.record(packet)
            updater.assert_called_once()
            self.assertIs(state.tcp_control_statistics, results[0])
            self.assertIs(state.identity, results[0].identity)
            self.assertIs(coordinator.state, state)

    def test_tcp_control_update_failure_preserves_empty_or_published_state(self) -> None:
        for populated in (False, True):
            coordinator = FlowStateCoordinator()
            if populated:
                coordinator.record(tcp_packet_at(0, syn=True))
            packet = tcp_packet_at(1 if populated else 0, ack=True)
            with patch(
                "analysis.flow_state_coordinator.update_tcp_control_statistics",
                side_effect=TCPControlStatisticsError("rejected TCP control observation"),
            ):
                self.assert_atomic_failure(coordinator, packet, TCPControlStatisticsError)

    def test_repeated_tcp_publication_is_deterministic(self) -> None:
        packets = (
            tcp_packet_at(0, syn=True),
            tcp_packet_at(1, True, syn=True, ack=True),
            tcp_packet_at(3, ack=True, psh=True),
        )
        left = FlowStateCoordinator()
        right = FlowStateCoordinator()
        for packet in packets:
            left_state = left.record(packet)
            right_state = right.record(packet)
            self.assertEqual(left_state, right_state)
            self.assertIsNot(left_state, right_state)
            self.assertIsNot(left_state.tcp_control_statistics, right_state.tcp_control_statistics)

    def test_unidirectional_repeated_zero_fractional_and_microsecond_intervals(self) -> None:
        for reverse in (False, True):
            coordinator = FlowStateCoordinator()
            for seconds in (0, 0, 1.5, 1.500001):
                state = coordinator.record(packet_at(seconds, reverse))
            prefix = "reverse" if reverse else "forward"
            opposite = "forward" if reverse else "reverse"
            timing = state.directional_inter_arrival_statistics
            self.assertEqual(getattr(timing, prefix + "_inter_arrival_count"), 3)
            self.assertEqual(getattr(timing, prefix + "_inter_arrival_sum_seconds"), 1.5 + 0.000001)
            self.assertEqual(getattr(timing, prefix + "_inter_arrival_sum_seconds_squared"), 1.5 * 1.5 + 0.000001 * 0.000001)
            self.assertEqual(getattr(timing, prefix + "_min_inter_arrival_seconds"), 0.0)
            self.assertIsNone(getattr(timing, "last_" + opposite + "_captured_at"))
            self.assertEqual(getattr(timing, opposite + "_inter_arrival_count"), 0)

    def test_publication_occurs_only_after_real_updates_and_preserves_exact_results(self) -> None:
        coordinator = FlowStateCoordinator()
        updates = (
            ("flow_statistics", update_flow_statistics),
            ("directional_flow_statistics", update_directional_flow_statistics),
            ("flow_packet_size_statistics", update_flow_packet_size_statistics),
            ("flow_inter_arrival_statistics", update_flow_inter_arrival_statistics),
            ("directional_inter_arrival_statistics", update_directional_inter_arrival_statistics),
        )
        for packet in (packet_at(0), packet_at(2, True)):
            previous = coordinator.state
            calls = []
            candidates = {}
            identities = []

            def observe(name, operation):
                def update(current, analysis, identity):
                    self.assertIs(coordinator.state, previous)
                    self.assertIs(current, None if previous is None else getattr(previous, name))
                    self.assertIs(analysis, packet)
                    identities.append(identity)
                    result = operation(current, analysis, identity)
                    self.assertIs(coordinator.state, previous)
                    calls.append(name)
                    candidates[name] = result
                    return result
                return update

            with ExitStack() as stack:
                for name, operation in updates:
                    stack.enter_context(patch(
                        "analysis.flow_state_coordinator." + operation.__name__,
                        side_effect=observe(name, operation),
                    ))
                state = coordinator.record(packet)
            self.assertEqual(calls, [name for name, operation in updates])
            for name, result in candidates.items():
                self.assertIs(getattr(state, name), result)
            for identity in identities:
                self.assertIs(identity, state.identity)
            if previous is not None:
                self.assertIs(state.identity, previous.identity)

    def test_unknown_original_length_failure_leaves_empty_or_populated_state_unchanged(self) -> None:
        invalid = replace(packet_at(2), observation=replace(OBSERVATION, original_length=None))
        for populated in (False, True):
            coordinator = FlowStateCoordinator()
            if populated:
                coordinator.record(packet_at(0))
            self.assert_atomic_failure(coordinator, invalid, FlowStatisticsError)
            state = coordinator.record(packet_at(3))
            self.assertEqual(state.flow_statistics.packet_count, 2 if populated else 1)

    def test_later_temporal_failure_discards_successful_volume_and_size_candidates(self) -> None:
        coordinator = FlowStateCoordinator()
        coordinator.record(packet_at(0))
        current = coordinator.record(packet_at(3, True))
        packet = packet_at(2)
        identity = current.identity
        self.assertEqual(update_flow_statistics(current.flow_statistics, packet, identity).packet_count, 3)
        self.assertEqual(update_directional_flow_statistics(
            current.directional_flow_statistics, packet, identity).forward_packet_count, 2)
        self.assertEqual(update_flow_packet_size_statistics(
            current.flow_packet_size_statistics, packet, identity).packet_count, 3)
        self.assert_atomic_failure(coordinator, packet, FlowInterArrivalStatisticsError)
        self.assertIs(coordinator.state, current)
        result = coordinator.record(packet_at(4))
        self.assertEqual(result.flow_statistics.packet_count, 3)
        self.assertEqual(result.flow_inter_arrival_statistics.inter_arrival_sum_seconds, 4.0)
        self.assertEqual(result.directional_inter_arrival_statistics.forward_inter_arrival_sum_seconds, 4.0)
        self.assert_atomic_failure(coordinator, packet_at(-1), FlowStatisticsError)

    def test_identity_failures_preserve_existing_state_and_do_not_bind_empty_owner(self) -> None:
        coordinator = FlowStateCoordinator()
        unsupported = replace(UDP_ANALYSIS, udp=None)
        self.assert_atomic_failure(coordinator, unsupported, FlowIdentityError)
        state = coordinator.record(TCP_ANALYSIS)
        self.assert_atomic_failure(coordinator, UDP_ANALYSIS, FlowCoordinationError)
        self.assert_atomic_failure(coordinator, unsupported, FlowIdentityError)
        different = replace(TCP_ANALYSIS, tcp=replace(TCP_ANALYSIS.tcp, source_port=12346))
        self.assert_atomic_failure(coordinator, different, FlowCoordinationError)
        self.assertIs(coordinator.state, state)

    def test_wrong_inputs_and_external_state_injection_are_rejected(self) -> None:
        class DerivedAnalysis(PacketAnalysis):
            pass

        coordinator = FlowStateCoordinator()
        state = coordinator.record(UDP_ANALYSIS)
        for value in (None, True, 1, 1.0, {}, [], OBSERVATION, state,
                      SimpleNamespace(**vars(UDP_ANALYSIS)), DerivedAnalysis(**vars(UDP_ANALYSIS))):
            with self.assertRaises(TypeError):
                coordinator.record(value)
            self.assertIs(coordinator.state, state)
        with self.assertRaises(TypeError):
            FlowStateCoordinator(state)
        with self.assertRaises(AttributeError):
            coordinator.state = state
        with self.assertRaises(AttributeError):
            del coordinator.state

    def test_frozen_state_retains_sources_and_validates_types_and_identities(self) -> None:
        state = FlowStateCoordinator().record(TCP_ANALYSIS)
        names = ("flow_statistics", "directional_flow_statistics", "flow_packet_size_statistics",
                 "flow_inter_arrival_statistics", "directional_inter_arrival_statistics",
                 "tcp_control_statistics")
        self.assertEqual(tuple(field.name for field in fields(state)), names + ("ldap_statistics", "tcp_stream_state"))
        self.assertEqual(tuple(vars(state)), names + ("ldap_statistics", "tcp_stream_state"))
        self.assertIsNone(state.ldap_statistics)
        other = replace(state.identity, source_port=12346)
        for name in names:
            value = getattr(state, name)
            with self.assertRaises(FrozenInstanceError):
                setattr(state, name, value)
            with self.assertRaises(FrozenInstanceError):
                delattr(state, name)
            for invalid in (True, 1, {}, SimpleNamespace(**vars(value))):
                with self.assertRaises(TypeError):
                    replace(state, **{name: invalid})
            if name == "tcp_control_statistics":
                with self.assertRaises(FlowCoordinationError):
                    replace(state, **{name: None})
            else:
                with self.assertRaises(TypeError):
                    replace(state, **{name: None})
            with self.assertRaises(FlowCoordinationError):
                replace(state, **{name: replace(value, identity=other)})
        copy = CoordinatedFlowState(**vars(state))
        for name in names:
            self.assertIs(getattr(copy, name), getattr(state, name))
        self.assertIs(copy.identity, state.identity)

    def test_public_state_constructor_rejects_cross_family_disagreement(self) -> None:
        coordinator = FlowStateCoordinator()
        for seconds, reverse, captured in ((0, False, 60), (1, True, 80),
                                            (3, False, 100), (4, True, 120)):
            state = coordinator.record(packet_at(seconds, reverse, captured))
        flow = state.flow_statistics
        directional = state.directional_flow_statistics
        packet_sizes = state.flow_packet_size_statistics
        intervals = state.flow_inter_arrival_statistics
        directional_intervals = state.directional_inter_arrival_statistics
        disagreements = (
            ("flow packet count", "flow_statistics", replace(flow, packet_count=5)),
            ("packet-size packet count", "flow_packet_size_statistics",
             replace(packet_sizes, packet_count=5)),
            ("global-IAT packet count", "flow_inter_arrival_statistics",
             replace(intervals, packet_count=5, inter_arrival_count=4)),
            ("directional-IAT packet count", "directional_inter_arrival_statistics", replace(
                directional_intervals, packet_count=5, forward_inter_arrival_count=2,
            )),
            ("directional packet count", "directional_flow_statistics",
             replace(directional, forward_packet_count=3)),
            ("packet-size directional count", "flow_packet_size_statistics",
             replace(packet_sizes, forward_packet_count=3)),
            ("directional interval allocation", "directional_inter_arrival_statistics", replace(
                directional_intervals,
                forward_inter_arrival_count=2,
                reverse_inter_arrival_count=0,
                reverse_inter_arrival_sum_seconds=0.0,
                reverse_inter_arrival_sum_seconds_squared=0.0,
                reverse_min_inter_arrival_seconds=0.0,
                reverse_max_inter_arrival_seconds=0.0,
            )),
            ("global captured bytes", "flow_statistics", replace(flow, captured_bytes=361)),
            ("packet-size global captured bytes", "flow_packet_size_statistics",
             replace(packet_sizes, captured_bytes=361)),
            ("directional captured bytes", "directional_flow_statistics", replace(
                directional, forward_captured_bytes=161, reverse_captured_bytes=199,
            )),
            ("packet-size directional captured bytes", "flow_packet_size_statistics", replace(
                packet_sizes, forward_captured_bytes=161, reverse_captured_bytes=199,
            )),
            ("global original bytes", "flow_statistics", replace(flow, original_bytes=521)),
            ("packet-size global original bytes", "flow_packet_size_statistics",
             replace(packet_sizes, original_bytes=521)),
            ("directional original bytes", "directional_flow_statistics", replace(
                directional, forward_original_bytes=241, reverse_original_bytes=279,
            )),
            ("packet-size directional original bytes", "flow_packet_size_statistics", replace(
                packet_sizes, forward_original_bytes=241, reverse_original_bytes=279,
            )),
            ("flow first timestamp", "flow_statistics", replace(
                flow, first_captured_at=TIMESTAMP + timedelta(microseconds=1),
            )),
            ("global-IAT first timestamp", "flow_inter_arrival_statistics", replace(
                intervals, first_captured_at=TIMESTAMP + timedelta(microseconds=1),
            )),
            ("directional-IAT first timestamp", "directional_inter_arrival_statistics", replace(
                directional_intervals, first_captured_at=TIMESTAMP + timedelta(microseconds=1),
            )),
            ("flow last timestamp", "flow_statistics", replace(
                flow, last_captured_at=TIMESTAMP + timedelta(seconds=5),
            )),
            ("global-IAT last timestamp", "flow_inter_arrival_statistics", replace(
                intervals, last_captured_at=TIMESTAMP + timedelta(seconds=5),
            )),
            ("directional-IAT last timestamp", "directional_inter_arrival_statistics", replace(
                directional_intervals, last_captured_at=TIMESTAMP + timedelta(seconds=5),
            )),
        )
        before = [vars(value).copy() for value in state_components(state)]
        for label, name, value in disagreements:
            with self.subTest(label=label):
                with self.assertRaises(FlowCoordinationError):
                    replace(state, **{name: value})
        for value, original in zip(state_components(state), before):
            self.assertEqual(vars(value), original)

    def test_public_state_constructor_enforces_tcp_presence_and_cross_family_counts(self) -> None:
        tcp_coordinator = FlowStateCoordinator()
        tcp_coordinator.record(tcp_packet_at(0))
        tcp_state = tcp_coordinator.record(tcp_packet_at(1, True))
        udp_state = FlowStateCoordinator().record(UDP_ANALYSIS)
        tcp_control = tcp_state.tcp_control_statistics
        different_identity = replace(tcp_state.identity, source_port=12346)
        mismatched_identity = replace(tcp_control, identity=different_identity)
        mismatched_packet_count = replace(
            tcp_control,
            packet_count=tcp_control.packet_count + 1,
            forward_packet_count=tcp_control.forward_packet_count + 1,
        )
        mismatched_direction = replace(
            tcp_control,
            forward_packet_count=2,
            reverse_packet_count=0,
        )
        for label, state, changes in (
            ("TCP absence", tcp_state, {"tcp_control_statistics": None}),
            ("UDP presence", udp_state, {"tcp_control_statistics": tcp_control}),
            ("identity", tcp_state, {"tcp_control_statistics": mismatched_identity}),
            ("packet count", tcp_state, {"tcp_control_statistics": mismatched_packet_count}),
            ("directional counts", tcp_state, {"tcp_control_statistics": mismatched_direction}),
        ):
            with self.subTest(label=label):
                with self.assertRaises(FlowCoordinationError):
                    replace(state, **changes)
        with self.assertRaises(TypeError):
            replace(tcp_state, tcp_control_statistics=SimpleNamespace(**vars(tcp_control)))
        with patch.object(TCPControlStatistics, "__post_init__", return_value=None):
            non_tcp_control = replace(tcp_control, identity=udp_state.identity)
        with self.assertRaises(FlowCoordinationError):
            replace(tcp_state, tcp_control_statistics=non_tcp_control)
        self.assertEqual(replace(udp_state), udp_state)

    def test_coordinator_publications_satisfy_cross_family_invariants_for_edge_cases(self) -> None:
        sequences = (
            ((0, False, 0),),
            ((0, False, 60), (0, False, 80)),
            ((0, False, 60), (1, True, 80)),
            ((0, True, 60), (0, True, 80), (1.5, True, 100)),
            ((0, False, 60), (1, True, 80), (3, False, 100), (3, True, 120)),
        )
        for sequence in sequences:
            for packet_factory in (packet_at, tcp_packet_at):
                with self.subTest(sequence=sequence, protocol=packet_factory.__name__):
                    coordinator = FlowStateCoordinator()
                    for seconds, reverse, captured in sequence:
                        state = coordinator.record(packet_factory(seconds, reverse, captured))
                flow = state.flow_statistics
                directional = state.directional_flow_statistics
                packet_sizes = state.flow_packet_size_statistics
                intervals = state.flow_inter_arrival_statistics
                directional_intervals = state.directional_inter_arrival_statistics
                self.assertEqual(
                    (flow.packet_count, packet_sizes.packet_count, intervals.packet_count,
                     directional_intervals.packet_count),
                    (len(sequence),) * 4,
                )
                self.assertEqual(
                    directional.forward_packet_count + directional.reverse_packet_count,
                    flow.packet_count,
                )
                for direction in ("forward", "reverse"):
                    packet_count = getattr(directional, direction + "_packet_count")
                    self.assertEqual(getattr(packet_sizes, direction + "_packet_count"), packet_count)
                    observed = int(getattr(
                        directional_intervals, "last_" + direction + "_captured_at",
                    ) is not None)
                    self.assertEqual(
                        getattr(directional_intervals, direction + "_inter_arrival_count") + observed,
                        packet_count,
                    )
                for length in ("captured", "original"):
                    total = getattr(flow, length + "_bytes")
                    self.assertEqual(getattr(packet_sizes, length + "_bytes"), total)
                    self.assertEqual(
                        getattr(directional, "forward_" + length + "_bytes")
                        + getattr(directional, "reverse_" + length + "_bytes"),
                        total,
                    )
                    for direction in ("forward", "reverse"):
                        self.assertEqual(
                            getattr(packet_sizes, direction + "_" + length + "_bytes"),
                            getattr(directional, direction + "_" + length + "_bytes"),
                        )
                self.assertEqual(intervals.inter_arrival_count, flow.packet_count - 1)
                self.assertEqual(
                    directional_intervals.forward_inter_arrival_count
                    + directional_intervals.reverse_inter_arrival_count,
                    flow.packet_count
                    - int(directional_intervals.last_forward_captured_at is not None)
                    - int(directional_intervals.last_reverse_captured_at is not None),
                )
                self.assertEqual(
                    (flow.first_captured_at, intervals.first_captured_at,
                     directional_intervals.first_captured_at),
                    (flow.first_captured_at,) * 3,
                )
                self.assertEqual(
                    (flow.last_captured_at, intervals.last_captured_at,
                     directional_intervals.last_captured_at),
                    (flow.last_captured_at,) * 3,
                )
                if flow.identity.protocol == 6:
                    tcp_control = state.tcp_control_statistics
                    self.assertEqual(tcp_control.packet_count, flow.packet_count)
                    self.assertEqual(
                        (tcp_control.forward_packet_count, tcp_control.reverse_packet_count),
                        (directional.forward_packet_count, directional.reverse_packet_count),
                    )
                else:
                    self.assertIsNone(state.tcp_control_statistics)

    def test_zero_duration_admission_does_not_change_feature_error_or_zero_interval_semantics(self) -> None:
        coordinator = FlowStateCoordinator()
        for count in (1, 2):
            state = coordinator.record(UDP_ANALYSIS)
            before = vars(state).copy()
            self.assertEqual(extract_flow_duration_features(state.flow_statistics).duration_seconds, 0.0)
            with self.assertRaises(FlowRateFeaturesError):
                extract_flow_rate_features(state.flow_statistics)
            features = extract_inter_arrival_features(state.flow_inter_arrival_statistics)
            self.assertEqual(tuple(vars(features).values()), (0.0,) * 5)
            self.assertEqual(state.flow_inter_arrival_statistics.inter_arrival_count, count - 1)
            self.assertIs(coordinator.state, state)
            self.assertEqual(vars(state), before)
        positive = coordinator.record(packet_at(1))
        self.assertEqual(extract_flow_rate_features(positive.flow_statistics).packets_per_second, 3.0)

    def test_determinism_input_immutability_and_independence_from_payload_and_checksums(self) -> None:
        left = FlowStateCoordinator()
        right = FlowStateCoordinator()
        for seconds, reverse in ((0, False), (1, True), (3, False)):
            packet = packet_at(seconds, reverse)
            objects = (packet, packet.observation, packet.ipv4, packet.udp)
            before = [vars(value).copy() for value in objects]
            changed = replace(packet, observation=replace(packet.observation, raw_bytes=b"x" * 60),
                              udp=replace(packet.udp, checksum=1234),
                              ipv4_checksum_valid=False, udp_checksum_valid=True)
            previous = left.state
            sources_before = None if previous is None else [
                vars(value).copy() for value in state_components(previous)
            ]
            actual = left.record(packet)
            equivalent = right.record(changed)
            self.assertEqual(actual, equivalent)
            self.assertIsNot(actual, equivalent)
            self.assertIsNot(actual.identity, equivalent.identity)
            for value, original in zip(objects, before):
                self.assertEqual(vars(value), original)
            if previous is not None:
                for value, original in zip(state_components(previous), sources_before):
                    self.assertEqual(vars(value), original)
            self.assertEqual(tuple(vars(left)), ("_state",))
            for value in vars(actual).values():
                self.assertIsNot(value, packet)
                self.assertIsNot(value, packet.observation)
