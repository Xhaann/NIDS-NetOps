import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from analysis import (
    CoordinatedFlowState,
    FlowIdentity,
    FlowIdentityError,
    FlowObservationWindow,
    FlowObservationWindowClosureReason,
    FlowObservationWindowError,
    FlowObservationWindowKey,
    FlowObservationWindowManager,
    FlowObservationWindowUpdate,
    FlowStateCoordinator,
    FlowStatisticsError,
    IPv4Packet,
    PacketAnalysis,
    TCPPacket,
    UDPPacket,
    flow_identity_from_packet,
)
from capture.packet_observation import CaptureSource, PacketObservation


TIMESTAMP = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
SOURCE = CaptureSource("test-flow-observation-window")
IPV4 = IPv4Packet(
    version=4, ihl=5, dscp=0, ecn=0, total_length=40, identification=0,
    flags=0, fragment_offset=0, ttl=64, protocol=6, header_checksum=0,
    source_address=b"\x0a\x00\x00\x01", destination_address=b"\x0a\x00\x00\x02",
    options=b"", payload=bytes(20),
)
TCP = TCPPacket(
    source_port=12345, destination_port=443, sequence_number=0,
    acknowledgment_number=0, data_offset=5, reserved_bits=0, ns=False,
    cwr=False, ece=False, urg=False, ack=False, psh=False, rst=False,
    syn=False, fin=False, window_size=0, checksum=0, urgent_pointer=0,
    options=b"", payload=b"",
)
UDP = UDPPacket(12345, 443, 8, 0, b"")


def packet_at(
    seconds: float,
    *,
    reverse: bool = False,
    protocol: int = 6,
    source_port: int = 12345,
    captured_length: int = 60,
    original_length=100,
    **flags,
) -> PacketAnalysis:
    observation = PacketObservation(
        TIMESTAMP + timedelta(seconds=seconds), None, captured_length,
        original_length, bytes(captured_length), SOURCE,
    )
    ipv4 = replace(IPV4, protocol=protocol)
    if protocol == 6:
        transport = replace(TCP, source_port=source_port, **flags)
        if reverse:
            ipv4 = replace(
                ipv4,
                source_address=IPV4.destination_address,
                destination_address=IPV4.source_address,
            )
            transport = replace(
                transport,
                source_port=transport.destination_port,
                destination_port=source_port,
            )
        return PacketAnalysis(observation, ipv4=ipv4, tcp=transport)
    transport = replace(UDP, source_port=source_port)
    if reverse:
        ipv4 = replace(
            ipv4,
            source_address=IPV4.destination_address,
            destination_address=IPV4.source_address,
        )
        transport = replace(
            transport,
            source_port=transport.destination_port,
            destination_port=source_port,
        )
    return PacketAnalysis(observation, ipv4=ipv4, udp=transport)


def assert_cross_family(test: unittest.TestCase, window: FlowObservationWindow) -> None:
    state = window.coordinated_state
    packet_count = state.flow_statistics.packet_count
    directional = state.directional_flow_statistics
    test.assertEqual(state.flow_packet_size_statistics.packet_count, packet_count)
    test.assertEqual(state.flow_inter_arrival_statistics.packet_count, packet_count)
    test.assertEqual(state.directional_inter_arrival_statistics.packet_count, packet_count)
    test.assertEqual(
        directional.forward_packet_count + directional.reverse_packet_count,
        packet_count,
    )
    if state.tcp_control_statistics is not None:
        test.assertEqual(state.tcp_control_statistics.packet_count, packet_count)
        test.assertEqual(
            state.tcp_control_statistics.forward_packet_count,
            directional.forward_packet_count,
        )
        test.assertEqual(
            state.tcp_control_statistics.reverse_packet_count,
            directional.reverse_packet_count,
        )


class FlowObservationWindowModelTests(unittest.TestCase):
    def setUp(self) -> None:
        coordinator = FlowStateCoordinator()
        self.state = coordinator.record(packet_at(0))
        self.key = FlowObservationWindowKey("capture-a", 0)
        self.active = FlowObservationWindow(self.key, self.state, None)
        self.closed = FlowObservationWindow(
            self.key,
            self.state,
            FlowObservationWindowClosureReason.INACTIVITY,
        )

    def test_exact_field_order_properties_and_frozen_models(self) -> None:
        update = FlowObservationWindowUpdate(self.active, ())
        self.assertEqual(
            tuple(field.name for field in fields(self.key)),
            ("capture_session_id", "sequence_number"),
        )
        self.assertEqual(
            tuple(field.name for field in fields(self.active)),
            ("key", "coordinated_state", "closure_reason"),
        )
        self.assertEqual(
            tuple(field.name for field in fields(update)),
            ("active_window", "closed_windows"),
        )
        self.assertIs(self.active.identity, self.state.identity)
        self.assertIs(
            self.active.first_captured_at,
            self.state.flow_statistics.first_captured_at,
        )
        self.assertIs(
            self.active.last_captured_at,
            self.state.flow_statistics.last_captured_at,
        )
        self.assertNotIn("identity", vars(self.active))
        self.assertNotIn("first_captured_at", vars(self.active))
        self.assertNotIn("last_captured_at", vars(self.active))
        for model in (self.key, self.active, update):
            for field in fields(model):
                with self.assertRaises(FrozenInstanceError):
                    setattr(model, field.name, getattr(model, field.name))
                with self.assertRaises(FrozenInstanceError):
                    delattr(model, field.name)

    def test_key_and_manager_constructor_validate_exact_types_and_values(self) -> None:
        class StringSubclass(str):
            pass

        self.assertTrue(issubclass(FlowObservationWindowError, ValueError))
        for value in (None, 1, b"capture", StringSubclass("capture")):
            with self.assertRaises(TypeError):
                FlowObservationWindowKey(value, 0)
            with self.assertRaises(TypeError):
                FlowObservationWindowManager(value, timedelta(seconds=1))
        for value in ("", " ", "\t\n"):
            with self.assertRaises(FlowObservationWindowError):
                FlowObservationWindowKey(value, 0)
            with self.assertRaises(FlowObservationWindowError):
                FlowObservationWindowManager(value, timedelta(seconds=1))
        for value in (True, False, 0.0, "0", None):
            with self.assertRaises(TypeError):
                FlowObservationWindowKey("capture", value)
        with self.assertRaises(FlowObservationWindowError):
            FlowObservationWindowKey("capture", -1)
        for value in (None, 1, 1.0, "1"):
            with self.assertRaises(TypeError):
                FlowObservationWindowManager("capture", value)
        for value in (timedelta(0), timedelta(microseconds=-1)):
            with self.assertRaises(FlowObservationWindowError):
                FlowObservationWindowManager("capture", value)

    def test_window_and_update_validate_exact_types_activity_and_uniqueness(self) -> None:
        class DerivedKey(FlowObservationWindowKey):
            pass

        class DerivedWindow(FlowObservationWindow):
            pass

        for key in (None, SimpleNamespace(), DerivedKey("capture", 0)):
            with self.assertRaises(TypeError):
                FlowObservationWindow(key, self.state, None)
        for state in (None, SimpleNamespace(), replace(self.state)):
            if type(state) is CoordinatedFlowState:
                continue
            with self.assertRaises(TypeError):
                FlowObservationWindow(self.key, state, None)
        for reason in (True, "inactivity", SimpleNamespace()):
            with self.assertRaises(TypeError):
                FlowObservationWindow(self.key, self.state, reason)
        bad_flow = object.__new__(type(self.state.flow_statistics))
        object.__setattr__(bad_flow, "packet_count", 0)
        bad_state = object.__new__(CoordinatedFlowState)
        object.__setattr__(bad_state, "flow_statistics", bad_flow)
        with self.assertRaises(FlowObservationWindowError):
            FlowObservationWindow(self.key, bad_state, None)
        with self.assertRaises(FlowObservationWindowError):
            FlowObservationWindowUpdate(self.closed, ())
        with self.assertRaises(TypeError):
            FlowObservationWindowUpdate(self.active, [])
        with self.assertRaises(TypeError):
            FlowObservationWindowUpdate(self.active, (SimpleNamespace(),))
        with self.assertRaises(TypeError):
            FlowObservationWindowUpdate(DerivedWindow(**vars(self.active)), ())
        with self.assertRaises(FlowObservationWindowError):
            FlowObservationWindowUpdate(self.active, (self.active,))
        with self.assertRaises(FlowObservationWindowError):
            FlowObservationWindowUpdate(self.active, (self.closed, self.closed))

    def test_closure_reason_has_exact_protocol_neutral_values(self) -> None:
        self.assertEqual(
            tuple(FlowObservationWindowClosureReason),
            (
                FlowObservationWindowClosureReason.INACTIVITY,
                FlowObservationWindowClosureReason.CAPTURE_SESSION_END,
                FlowObservationWindowClosureReason.EXPLICIT_SEGMENTATION,
            ),
        )
        self.assertEqual(
            tuple(reason.value for reason in FlowObservationWindowClosureReason),
            ("inactivity", "capture_session_end", "explicit_segmentation"),
        )


class FlowObservationWindowManagerTests(unittest.TestCase):
    def test_first_continuation_equal_time_and_canonical_direction(self) -> None:
        manager = FlowObservationWindowManager("capture-a", timedelta(seconds=10))
        first = manager.record(packet_at(0, syn=True))
        equal = manager.record(packet_at(0, reverse=True, fin=True))
        continued = manager.record(packet_at(9, ack=True))
        self.assertEqual(first.active_window.key, FlowObservationWindowKey("capture-a", 0))
        self.assertEqual(first.closed_windows, ())
        self.assertEqual(equal.closed_windows, ())
        self.assertEqual(continued.closed_windows, ())
        self.assertEqual(continued.active_window.coordinated_state.flow_statistics.packet_count, 3)
        directional = continued.active_window.coordinated_state.directional_flow_statistics
        self.assertEqual((directional.forward_packet_count, directional.reverse_packet_count), (2, 1))
        tcp = continued.active_window.coordinated_state.tcp_control_statistics
        self.assertEqual((tcp.forward_syn_count, tcp.reverse_fin_count, tcp.forward_ack_count), (1, 1, 1))
        assert_cross_family(self, continued.active_window)

    def test_exact_and_greater_timeout_segment_without_counting_boundary_gap(self) -> None:
        for boundary in (14, 15):
            with self.subTest(boundary=boundary):
                manager = FlowObservationWindowManager("capture", timedelta(seconds=10))
                manager.record(packet_at(0, captured_length=60, original_length=100))
                manager.record(packet_at(4, captured_length=80, original_length=120))
                update = manager.record(
                    packet_at(boundary, reverse=True, captured_length=70, original_length=110)
                )
                self.assertEqual(update.active_window.key.sequence_number, 1)
                self.assertEqual(len(update.closed_windows), 1)
                closed = update.closed_windows[0]
                self.assertEqual(
                    closed.closure_reason,
                    FlowObservationWindowClosureReason.INACTIVITY,
                )
                self.assertEqual((closed.first_captured_at, closed.last_captured_at),
                                 (TIMESTAMP, TIMESTAMP + timedelta(seconds=4)))
                old_state = closed.coordinated_state
                self.assertEqual(old_state.flow_statistics.packet_count, 2)
                self.assertEqual(old_state.flow_statistics.captured_bytes, 140)
                self.assertEqual(old_state.flow_inter_arrival_statistics.inter_arrival_sum_seconds, 4.0)
                self.assertEqual(
                    old_state.directional_inter_arrival_statistics.forward_inter_arrival_sum_seconds,
                    4.0,
                )
                new_state = update.active_window.coordinated_state
                self.assertEqual(new_state.flow_statistics.packet_count, 1)
                self.assertEqual(new_state.flow_statistics.captured_bytes, 70)
                self.assertEqual(new_state.flow_inter_arrival_statistics.inter_arrival_count, 0)
                self.assertEqual(new_state.directional_inter_arrival_statistics.reverse_inter_arrival_count, 0)
                assert_cross_family(self, closed)
                assert_cross_family(self, update.active_window)

    def test_tcp_flags_do_not_control_lifecycle_and_tcp_state_resets(self) -> None:
        manager = FlowObservationWindowManager("capture", timedelta(seconds=10))
        for analysis in (
            packet_at(0, syn=True),
            packet_at(1, fin=True),
            packet_at(2, rst=True),
        ):
            update = manager.record(analysis)
            self.assertEqual(update.active_window.key.sequence_number, 0)
            self.assertEqual(update.closed_windows, ())
        old_tcp = update.active_window.coordinated_state.tcp_control_statistics
        self.assertEqual((old_tcp.forward_syn_count, old_tcp.forward_fin_count,
                          old_tcp.forward_rst_count), (1, 1, 1))
        segmented = manager.record(packet_at(12, ack=True))
        new_tcp = segmented.active_window.coordinated_state.tcp_control_statistics
        self.assertEqual(new_tcp.packet_count, 1)
        self.assertEqual((new_tcp.forward_syn_count, new_tcp.forward_fin_count,
                          new_tcp.forward_rst_count, new_tcp.forward_ack_count), (0, 0, 0, 1))

    def test_udp_uses_same_lifecycle_and_never_creates_tcp_state(self) -> None:
        manager = FlowObservationWindowManager("capture", timedelta(seconds=5))
        first = manager.record(packet_at(0, protocol=17))
        second = manager.record(packet_at(1, protocol=17, reverse=True))
        third = manager.record(packet_at(6, protocol=17))
        self.assertEqual((first.active_window.key.sequence_number,
                          second.active_window.key.sequence_number,
                          third.active_window.key.sequence_number), (0, 0, 1))
        self.assertEqual(len(third.closed_windows), 1)
        for window in (first.active_window, second.active_window,
                       third.closed_windows[0], third.active_window):
            self.assertIsNone(window.coordinated_state.tcp_control_statistics)
            assert_cross_family(self, window)

    def test_multiple_identities_and_active_order_are_independent_and_deterministic(self) -> None:
        manager = FlowObservationWindowManager("capture", timedelta(days=1))
        first = manager.record(packet_at(0, source_port=20000))
        second = manager.record(packet_at(1, source_port=10000))
        updated = manager.record(packet_at(2, source_port=20000, reverse=True))
        active = manager.active_windows()
        self.assertIs(type(active), tuple)
        self.assertEqual(tuple(window.key.sequence_number for window in active), (0, 1))
        self.assertEqual(active[0].coordinated_state.flow_statistics.packet_count, 2)
        self.assertEqual(active[1].coordinated_state.flow_statistics.packet_count, 1)
        self.assertEqual(updated.active_window.key, first.active_window.key)
        self.assertNotEqual(first.active_window.identity, second.active_window.identity)
        with self.assertRaises(TypeError):
            active[0] = active[1]

    def test_global_timestamp_regression_rejects_without_state_or_sequence_change(self) -> None:
        manager = FlowObservationWindowManager("capture", timedelta(seconds=10))
        original = manager.record(packet_at(10))
        before = manager.active_windows()
        with self.assertRaises(FlowObservationWindowError):
            manager.record(packet_at(9, source_port=20000))
        self.assertEqual(manager.active_windows(), before)
        accepted = manager.record(packet_at(10, source_port=20000))
        self.assertEqual(accepted.active_window.key.sequence_number, 1)
        self.assertEqual(original.active_window.coordinated_state,
                         manager.active_windows()[0].coordinated_state)

    def test_explicit_close_is_immutable_removed_and_identity_reuse_gets_new_key(self) -> None:
        manager = FlowObservationWindowManager("capture", timedelta(seconds=10))
        first = manager.record(packet_at(0))
        identity = first.active_window.identity
        closed = manager.close(identity)
        self.assertEqual(
            closed.closure_reason,
            FlowObservationWindowClosureReason.EXPLICIT_SEGMENTATION,
        )
        self.assertEqual(manager.active_windows(), ())
        with self.assertRaises(FrozenInstanceError):
            closed.closure_reason = None
        with self.assertRaises(FlowObservationWindowError):
            manager.close(identity)
        later = manager.record(packet_at(0, ack=True))
        self.assertEqual(later.active_window.key.sequence_number, 1)
        self.assertEqual(later.closed_windows, ())
        self.assertEqual(later.active_window.identity, identity)
        self.assertEqual(later.active_window.coordinated_state.flow_statistics.packet_count, 1)
        self.assertEqual(closed.coordinated_state.flow_statistics.packet_count, 1)

    def test_capture_session_end_closes_once_in_sequence_order_and_rejects_reuse(self) -> None:
        manager = FlowObservationWindowManager("capture", timedelta(seconds=10))
        manager.record(packet_at(0, source_port=20000))
        manager.record(packet_at(1, source_port=10000))
        closed = manager.end_capture_session()
        self.assertEqual(tuple(window.key.sequence_number for window in closed), (0, 1))
        self.assertTrue(all(
            window.closure_reason is FlowObservationWindowClosureReason.CAPTURE_SESSION_END
            for window in closed
        ))
        self.assertEqual(manager.active_windows(), ())
        self.assertEqual(manager.end_capture_session(), ())
        with self.assertRaises(FlowObservationWindowError):
            manager.record(packet_at(2))
        with self.assertRaises(FlowObservationWindowError):
            manager.close(closed[0].identity)
        empty = FlowObservationWindowManager("empty", timedelta(seconds=1))
        self.assertEqual(empty.end_capture_session(), ())
        self.assertEqual(empty.end_capture_session(), ())

    def test_closed_window_graph_is_unchanged_by_later_identity_reuse(self) -> None:
        manager = FlowObservationWindowManager("capture", timedelta(seconds=5))
        manager.record(packet_at(0, syn=True))
        transition = manager.record(packet_at(5, ack=True))
        closed = transition.closed_windows[0]
        sources = (closed, closed.coordinated_state) + tuple(
            value for value in vars(closed.coordinated_state).values() if value is not None
        )
        before = [vars(value).copy() for value in sources]
        manager.record(packet_at(6, fin=True))
        for value, expected in zip(sources, before):
            self.assertEqual(vars(value), expected)
        self.assertEqual(closed.coordinated_state.flow_statistics.packet_count, 1)
        self.assertEqual(manager.active_windows()[0].coordinated_state.flow_statistics.packet_count, 2)

    def test_failed_first_creation_changes_nothing_and_consumes_no_key_or_frontier(self) -> None:
        manager = FlowObservationWindowManager("capture", timedelta(seconds=10))
        invalid = packet_at(10, original_length=None)
        with self.assertRaises(FlowStatisticsError) as failure:
            manager.record(invalid)
        self.assertIs(type(failure.exception), FlowStatisticsError)
        self.assertEqual(manager.active_windows(), ())
        accepted = manager.record(packet_at(5))
        self.assertEqual(accepted.active_window.key.sequence_number, 0)

    def test_failed_continuation_preserves_window_frontier_and_next_sequence(self) -> None:
        manager = FlowObservationWindowManager("capture", timedelta(seconds=10))
        first = manager.record(packet_at(0))
        before = manager.active_windows()
        with self.assertRaises(FlowStatisticsError) as failure:
            manager.record(packet_at(5, original_length=None))
        self.assertIs(type(failure.exception), FlowStatisticsError)
        self.assertEqual(manager.active_windows(), before)
        other = manager.record(packet_at(4, source_port=20000))
        self.assertEqual(other.active_window.key.sequence_number, 1)
        retained = next(
            window for window in manager.active_windows()
            if window.identity == first.active_window.identity
        )
        self.assertEqual(retained.coordinated_state.flow_statistics.packet_count, 1)

    def test_failed_inactivity_candidate_does_not_close_or_consume_sequence(self) -> None:
        manager = FlowObservationWindowManager("capture", timedelta(seconds=10))
        first = manager.record(packet_at(0))
        before = manager.active_windows()
        with self.assertRaises(FlowStatisticsError) as failure:
            manager.record(packet_at(100, original_length=None))
        self.assertIs(type(failure.exception), FlowStatisticsError)
        self.assertEqual(manager.active_windows(), before)
        continuation = manager.record(packet_at(1))
        self.assertEqual(continuation.active_window.key, first.active_window.key)
        self.assertEqual(continuation.active_window.coordinated_state.flow_statistics.packet_count, 2)
        closed = manager.close(continuation.active_window.identity)
        next_window = manager.record(packet_at(1))
        self.assertEqual(closed.key.sequence_number, 0)
        self.assertEqual(next_window.active_window.key.sequence_number, 1)

    def test_wrong_inputs_and_unsupported_icmp_preserve_lower_level_errors(self) -> None:
        class DerivedAnalysis(PacketAnalysis):
            pass

        class DerivedIdentity(FlowIdentity):
            pass

        manager = FlowObservationWindowManager("capture", timedelta(seconds=10))
        analysis = packet_at(0)
        for value in (None, True, 1, SimpleNamespace(), DerivedAnalysis(**vars(analysis))):
            with self.assertRaises(TypeError):
                manager.record(value)
        identity = flow_identity_from_packet(analysis)
        for value in (None, True, 1, SimpleNamespace(), DerivedIdentity(**vars(identity))):
            with self.assertRaises(TypeError):
                manager.close(value)
        icmp = replace(analysis, ipv4=replace(analysis.ipv4, protocol=1), tcp=None)
        with self.assertRaises(FlowIdentityError):
            manager.record(icmp)
        self.assertEqual(manager.active_windows(), ())

    def test_determinism_one_packet_zero_duration_and_large_timeout(self) -> None:
        timeout = timedelta.max
        left = FlowObservationWindowManager("capture", timeout)
        right = FlowObservationWindowManager("capture", timeout)
        observations = (
            packet_at(0, syn=True),
            packet_at(0, reverse=True, ack=True),
            packet_at(1, fin=True),
        )
        for observation in observations:
            left_update = left.record(observation)
            right_update = right.record(observation)
            self.assertEqual(left_update, right_update)
            self.assertIsNot(left_update, right_update)
        window = left.active_windows()[0]
        self.assertEqual(window.first_captured_at, TIMESTAMP)
        self.assertEqual(window.last_captured_at, TIMESTAMP + timedelta(seconds=1))
        one = FlowObservationWindowManager("one", timeout).record(packet_at(0)).active_window
        self.assertEqual(one.first_captured_at, one.last_captured_at)
        self.assertEqual(one.coordinated_state.flow_inter_arrival_statistics.inter_arrival_count, 0)
        assert_cross_family(self, one)


if __name__ == "__main__":
    unittest.main()
