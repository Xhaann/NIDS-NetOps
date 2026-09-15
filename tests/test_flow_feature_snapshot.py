import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Optional
from unittest.mock import Mock, PropertyMock, patch

from analysis import (
    CoordinatedFlowState,
    DirectionalInterArrivalFeatures,
    DirectionalInterArrivalFeaturesError,
    FlowDurationFeatures,
    FlowFeatureInput,
    FlowFeatureSnapshot,
    FlowFeatureSnapshotError,
    FlowObservationWindow,
    FlowObservationWindowClosureReason,
    FlowObservationWindowManager,
    FlowRateFeatures,
    FlowRateFeaturesError,
    FlowStateCoordinator,
    FlowVolumeFeatures,
    InterArrivalFeatures,
    IPv4Packet,
    PacketAnalysis,
    PacketSizeFeatures,
    PacketSizeFeaturesError,
    TCPPacket,
    UDPPacket,
    extract_directional_inter_arrival_features,
    extract_flow_duration_features,
    extract_flow_feature_snapshot,
    extract_flow_rate_features,
    extract_flow_volume_features,
    extract_inter_arrival_features,
    extract_packet_size_features,
    flow_feature_input_from_statistics,
)
from capture.packet_observation import CaptureSource, PacketObservation


TIMESTAMP = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
OBSERVATION = PacketObservation(
    TIMESTAMP, None, 60, 100, bytes(60), CaptureSource("test-feature-snapshot"),
)
IPV4 = IPv4Packet(
    version=4, ihl=5, dscp=0, ecn=0, total_length=28, identification=0, flags=0,
    fragment_offset=0, ttl=64, protocol=17, header_checksum=0,
    source_address=b"\x0a\x00\x00\x01", destination_address=b"\x0a\x00\x00\x02",
    options=b"", payload=bytes(8),
)
UDP_ANALYSIS = PacketAnalysis(
    OBSERVATION,
    ipv4=IPV4,
    udp=UDPPacket(12345, 443, 8, 0, b""),
)
TCP_ANALYSIS = PacketAnalysis(
    OBSERVATION,
    ipv4=replace(IPV4, protocol=6, total_length=40, payload=bytes(20)),
    tcp=TCPPacket(
        source_port=12345, destination_port=443, sequence_number=0,
        acknowledgment_number=0, data_offset=5, reserved_bits=0, ns=False,
        cwr=False, ece=False, urg=False, ack=False, psh=False, rst=False,
        syn=False, fin=False, window_size=0, checksum=0, urgent_pointer=0,
        options=b"", payload=b"",
    ),
)


def packet_at(
    seconds: float,
    reverse: bool = False,
    captured: int = 60,
    original: int = 100,
) -> PacketAnalysis:
    packet = replace(
        UDP_ANALYSIS,
        observation=replace(
            OBSERVATION,
            captured_at=TIMESTAMP + timedelta(seconds=seconds),
            captured_length=captured,
            original_length=original,
            raw_bytes=bytes(captured),
        ),
    )
    if reverse:
        packet = replace(
            packet,
            ipv4=replace(
                IPV4,
                source_address=IPV4.destination_address,
                destination_address=IPV4.source_address,
            ),
            udp=replace(packet.udp, source_port=443, destination_port=12345),
        )
    return packet


def tcp_packet_at(seconds: float, reverse: bool = False, **flags) -> PacketAnalysis:
    packet = replace(
        TCP_ANALYSIS,
        observation=replace(
            OBSERVATION,
            captured_at=TIMESTAMP + timedelta(seconds=seconds),
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


def active_window_from_packets(
    *packets: PacketAnalysis,
    capture_session_id: str = "snapshot",
) -> tuple[FlowObservationWindowManager, FlowObservationWindow]:
    manager = FlowObservationWindowManager(capture_session_id, timedelta.max)
    update = None
    for packet in packets:
        update = manager.record(packet)
    if update is None:
        raise ValueError("at least one packet is required")
    return manager, update.active_window


def snapshot_features(snapshot: FlowFeatureSnapshot) -> tuple:
    return (
        snapshot.flow_volume_features,
        snapshot.packet_size_features,
        snapshot.flow_duration_features,
        snapshot.flow_rate_features,
        snapshot.inter_arrival_features,
        snapshot.directional_inter_arrival_features,
    )


def state_components(state: CoordinatedFlowState) -> tuple:
    return tuple(component for value in vars(state).values() if value is not None
                 for component in (value if type(value) is tuple else (value,)))


class FlowFeatureSnapshotTests(unittest.TestCase):
    def test_bidirectional_active_window_uses_all_established_feature_families(self) -> None:
        manager, window = active_window_from_packets(
            packet_at(0, False, 60, 100),
            packet_at(1.5, True, 80, 120),
            packet_at(4, False, 100, 140),
        )
        snapshot = extract_flow_feature_snapshot(window)
        state = window.coordinated_state
        self.assertIs(type(snapshot), FlowFeatureSnapshot)
        self.assertIs(snapshot.observation_window, window)
        self.assertIs(snapshot.coordinated_state, state)
        self.assertIs(snapshot.identity, window.identity)
        self.assertIs(snapshot.observation_window.key, window.key)
        self.assertEqual(snapshot.observation_window.key.capture_session_id, "snapshot")
        self.assertEqual(snapshot.observation_window.key.sequence_number, 0)
        self.assertIsNone(snapshot.observation_window.closure_reason)
        self.assertEqual(snapshot.flow_volume_features.packet_count, 3)
        self.assertEqual(snapshot.flow_volume_features.captured_bytes, 240)
        self.assertEqual(snapshot.flow_volume_features.original_bytes, 360)
        self.assertEqual(snapshot.flow_volume_features.forward_packet_ratio, 2 / 3)
        self.assertEqual(snapshot.packet_size_features.mean_captured_length, 80.0)
        self.assertAlmostEqual(snapshot.packet_size_features.variance_captured_length, 800 / 3)
        self.assertEqual(snapshot.packet_size_features.forward_mean_captured_length, 80.0)
        self.assertEqual(snapshot.packet_size_features.forward_variance_captured_length, 400.0)
        self.assertEqual(snapshot.packet_size_features.reverse_variance_captured_length, 0.0)
        self.assertEqual(snapshot.flow_duration_features, FlowDurationFeatures(4.0))
        self.assertEqual(snapshot.flow_rate_features, FlowRateFeatures(0.75, 60.0, 90.0))
        self.assertEqual(
            snapshot.inter_arrival_features,
            InterArrivalFeatures(2.0, 0.25, 0.5, 1.5, 2.5),
        )
        self.assertEqual(
            snapshot.directional_inter_arrival_features,
            DirectionalInterArrivalFeatures(
                4.0, 0.0, 0.0, 4.0, 4.0,
                None, None, None, None, None,
            ),
        )
        self.assertEqual(manager.active_windows(), (window,))

    def test_all_closure_reasons_preserve_identical_numerical_formulas(self) -> None:
        inactivity_manager = FlowObservationWindowManager("same", timedelta(seconds=5))
        inactivity_manager.record(packet_at(0))
        inactivity = inactivity_manager.record(packet_at(5)).closed_windows[0]

        session_manager = FlowObservationWindowManager("same", timedelta(seconds=5))
        session_manager.record(packet_at(0))
        session_end = session_manager.end_capture_session()[0]

        explicit_manager = FlowObservationWindowManager("same", timedelta(seconds=5))
        active = explicit_manager.record(packet_at(0)).active_window
        explicit = explicit_manager.close(active.identity)

        snapshots = tuple(
            extract_flow_feature_snapshot(window)
            for window in (inactivity, session_end, explicit)
        )
        self.assertEqual(
            tuple(snapshot.observation_window.closure_reason for snapshot in snapshots),
            (
                FlowObservationWindowClosureReason.INACTIVITY,
                FlowObservationWindowClosureReason.CAPTURE_SESSION_END,
                FlowObservationWindowClosureReason.EXPLICIT_SEGMENTATION,
            ),
        )
        self.assertEqual(snapshot_features(snapshots[0]), snapshot_features(snapshots[1]))
        self.assertEqual(snapshot_features(snapshots[1]), snapshot_features(snapshots[2]))
        self.assertNotEqual(snapshots[0], snapshots[1])
        self.assertNotEqual(snapshots[1], snapshots[2])

    def test_distinct_window_keys_make_numerically_equal_snapshots_unequal(self) -> None:
        windows = []
        for session_id in ("capture-a", "capture-b"):
            manager = FlowObservationWindowManager(session_id, timedelta.max)
            manager.record(packet_at(0))
            windows.append(manager.end_capture_session()[0])
        first = extract_flow_feature_snapshot(windows[0])
        second = extract_flow_feature_snapshot(windows[1])
        self.assertNotEqual(first.observation_window.key, second.observation_window.key)
        self.assertEqual(first.coordinated_state, second.coordinated_state)
        self.assertEqual(snapshot_features(first), snapshot_features(second))
        self.assertNotEqual(first, second)

    def test_first_packet_and_populated_zero_duration_have_absent_rates(self) -> None:
        manager = FlowObservationWindowManager("zero", timedelta.max)
        for packet in (packet_at(0), packet_at(0, True), packet_at(0)):
            window = manager.record(packet).active_window
            state = window.coordinated_state
            with self.assertRaises(FlowRateFeaturesError):
                extract_flow_rate_features(state.flow_statistics)
            with patch(
                "analysis.flow_feature_snapshot.extract_flow_rate_features",
                wraps=extract_flow_rate_features,
            ) as rate_extractor:
                snapshot = extract_flow_feature_snapshot(window)
                rate_extractor.assert_not_called()
            self.assertEqual(snapshot.flow_duration_features.duration_seconds, 0.0)
            self.assertIsNone(snapshot.flow_rate_features)
            self.assertEqual(
                snapshot.inter_arrival_features,
                InterArrivalFeatures(0.0, 0.0, 0.0, 0.0, 0.0),
            )
            directional = snapshot.directional_inter_arrival_features
            if state.directional_inter_arrival_statistics.forward_inter_arrival_count == 0:
                self.assertEqual(tuple(vars(directional).values()), (None,) * 10)
            else:
                self.assertEqual(
                    tuple(vars(directional).values()),
                    (0.0,) * 5 + (None,) * 5,
                )
            self.assertIsNone(window.closure_reason)

    def test_unidirectional_fractional_and_positive_duration_semantics_are_preserved(self) -> None:
        for reverse in (False, True):
            for seconds in (0.000001, 1.5):
                manager, window = active_window_from_packets(
                    packet_at(0, reverse),
                    packet_at(seconds, reverse),
                    capture_session_id=f"{reverse}-{seconds}",
                )
                snapshot = extract_flow_feature_snapshot(window)
                unused = "forward" if reverse else "reverse"
                used = "reverse" if reverse else "forward"
                self.assertEqual(
                    getattr(snapshot.packet_size_features, unused + "_mean_captured_length"),
                    0.0,
                )
                self.assertEqual(
                    getattr(snapshot.packet_size_features, unused + "_variance_captured_length"),
                    0.0,
                )
                self.assertEqual(snapshot.flow_duration_features.duration_seconds, seconds)
                self.assertEqual(snapshot.flow_rate_features.packets_per_second, 2 / seconds)
                self.assertEqual(snapshot.inter_arrival_features.mean_inter_arrival_seconds, seconds)
                directional = snapshot.directional_inter_arrival_features
                self.assertEqual(
                    getattr(directional, used + "_mean_inter_arrival_seconds"),
                    seconds,
                )
                self.assertIsNone(
                    getattr(directional, unused + "_mean_inter_arrival_seconds")
                )
                self.assertEqual(manager.active_windows(), (window,))

    def test_positive_duration_zero_byte_rates_are_present_numerical_zeros(self) -> None:
        manager, window = active_window_from_packets(
            packet_at(0, captured=0, original=0),
            packet_at(1, captured=0, original=0),
        )
        snapshot = extract_flow_feature_snapshot(window)
        self.assertEqual(
            snapshot.flow_rate_features,
            FlowRateFeatures(2.0, 0.0, 0.0),
        )
        self.assertEqual(manager.active_windows(), (window,))

    def test_exact_source_arguments_and_extractor_result_references_are_preserved(self) -> None:
        manager, window = active_window_from_packets(packet_at(0), packet_at(3, True))
        state = window.coordinated_state
        operations = (
            ("volume_input", flow_feature_input_from_statistics),
            ("flow_volume_features", extract_flow_volume_features),
            ("packet_size_features", extract_packet_size_features),
            ("flow_duration_features", extract_flow_duration_features),
            ("flow_rate_features", extract_flow_rate_features),
            ("inter_arrival_features", extract_inter_arrival_features),
            ("directional_inter_arrival_features", extract_directional_inter_arrival_features),
        )
        results = {}
        arguments = {}

        def observe(name, operation):
            def extract(*args):
                result = operation(*args)
                results[name] = result
                arguments[name] = args
                return result
            return extract

        with ExitStack() as stack:
            calls = []
            for name, operation in operations:
                calls.append(stack.enter_context(patch(
                    "analysis.flow_feature_snapshot." + operation.__name__,
                    side_effect=observe(name, operation),
                )))
            snapshot = extract_flow_feature_snapshot(window)
            for operation_call in calls:
                self.assertEqual(operation_call.call_count, 1)
        self.assertIs(snapshot.observation_window, window)
        self.assertIs(arguments["volume_input"][0], state.flow_statistics)
        self.assertIs(arguments["volume_input"][1], state.directional_flow_statistics)
        self.assertIs(arguments["flow_volume_features"][0], results["volume_input"])
        self.assertIs(arguments["packet_size_features"][0], state.flow_packet_size_statistics)
        self.assertIs(arguments["flow_duration_features"][0], state.flow_statistics)
        self.assertIs(arguments["flow_rate_features"][0], state.flow_statistics)
        self.assertIs(arguments["inter_arrival_features"][0], state.flow_inter_arrival_statistics)
        self.assertIs(
            arguments["directional_inter_arrival_features"][0],
            state.directional_inter_arrival_statistics,
        )
        for name, operation in operations[1:]:
            self.assertIs(getattr(snapshot, name), results[name])
        self.assertEqual(manager.active_windows(), (window,))

    def test_frozen_seven_typed_fields_delegate_state_and_identity(self) -> None:
        manager, window = active_window_from_packets(packet_at(0), packet_at(1))
        snapshot = extract_flow_feature_snapshot(window)
        expected = (
            ("observation_window", FlowObservationWindow),
            ("flow_volume_features", FlowVolumeFeatures),
            ("packet_size_features", PacketSizeFeatures),
            ("flow_duration_features", FlowDurationFeatures),
            ("flow_rate_features", FlowRateFeatures),
            ("inter_arrival_features", InterArrivalFeatures),
            ("directional_inter_arrival_features", DirectionalInterArrivalFeatures),
        )
        self.assertEqual(
            tuple(field.name for field in fields(snapshot)),
            tuple(name for name, kind in expected),
        )
        self.assertEqual(
            tuple(field.type for field in fields(snapshot)),
            (
                FlowObservationWindow,
                FlowVolumeFeatures,
                PacketSizeFeatures,
                FlowDurationFeatures,
                Optional[FlowRateFeatures],
                InterArrivalFeatures,
                DirectionalInterArrivalFeatures,
            ),
        )
        self.assertEqual(tuple(vars(snapshot)), tuple(name for name, kind in expected))
        for name, kind in expected:
            self.assertIs(type(getattr(snapshot, name)), kind)
            with self.assertRaises(FrozenInstanceError):
                setattr(snapshot, name, getattr(snapshot, name))
            with self.assertRaises(FrozenInstanceError):
                delattr(snapshot, name)
        with self.assertRaises(FrozenInstanceError):
            snapshot.coordinated_state = snapshot.coordinated_state
        with self.assertRaises(FrozenInstanceError):
            snapshot.identity = snapshot.identity
        with self.assertRaises(FrozenInstanceError):
            snapshot.extra = 1
        self.assertNotIn("coordinated_state", vars(snapshot))
        self.assertNotIn("identity", vars(snapshot))
        self.assertNotIn("coordinator", vars(snapshot))
        self.assertIs(snapshot.observation_window, window)
        self.assertIs(snapshot.coordinated_state, window.coordinated_state)
        self.assertIs(snapshot.identity, window.identity)
        self.assertEqual(manager.active_windows(), (window,))

    def test_canonical_utc_temporal_families_remain_semantically_distinct(self) -> None:
        manager, window = active_window_from_packets(
            *(packet_at(seconds, reverse) for seconds, reverse in (
                (0, False), (1, True), (3, False), (5, True),
            ))
        )
        state = window.coordinated_state
        snapshot = extract_flow_feature_snapshot(window)
        self.assertIs(type(state.flow_statistics.first_captured_at.tzinfo), timezone)
        self.assertIs(type(state.flow_statistics.last_captured_at.tzinfo), timezone)
        self.assertEqual(
            snapshot.flow_duration_features.duration_seconds,
            (state.flow_statistics.last_captured_at - state.flow_statistics.first_captured_at).total_seconds(),
        )
        self.assertEqual(state.flow_inter_arrival_statistics.inter_arrival_sum_seconds, 5.0)
        self.assertEqual(snapshot.inter_arrival_features.mean_inter_arrival_seconds, 5.0 / 3.0)
        self.assertEqual(
            snapshot.directional_inter_arrival_features,
            DirectionalInterArrivalFeatures(
                3.0, 0.0, 0.0, 3.0, 3.0,
                4.0, 0.0, 0.0, 4.0, 4.0,
            ),
        )
        self.assertEqual(manager.active_windows(), (window,))

    def test_extraction_errors_propagate_without_mutating_window_or_state(self) -> None:
        manager, window = active_window_from_packets(packet_at(0))
        state = window.coordinated_state
        sources = (window, state, *state_components(state))
        before = [vars(value).copy() for value in sources]
        error = DirectionalInterArrivalFeaturesError("invalid directional moments")
        with patch(
            "analysis.flow_feature_snapshot.extract_directional_inter_arrival_features",
            side_effect=error,
        ) as directional_extractor:
            with self.assertRaises(DirectionalInterArrivalFeaturesError) as failure:
                extract_flow_feature_snapshot(window)
        self.assertIs(failure.exception, error)
        directional_extractor.assert_called_once_with(
            state.directional_inter_arrival_statistics
        )
        for value, original in zip(sources, before):
            self.assertEqual(vars(value), original)
        self.assertEqual(manager.active_windows(), (window,))

    def test_direct_construction_replacement_and_feature_injection_are_rejected(self) -> None:
        manager, window = active_window_from_packets(packet_at(0))
        snapshot = extract_flow_feature_snapshot(window)
        self.assertTrue(issubclass(FlowFeatureSnapshotError, ValueError))
        with self.assertRaises(TypeError):
            FlowFeatureSnapshot()
        with self.assertRaises(TypeError):
            FlowFeatureSnapshot(window)
        with self.assertRaises(TypeError):
            FlowFeatureSnapshot(**vars(snapshot))
        with self.assertRaises(TypeError):
            replace(snapshot, observation_window=window)
        with self.assertRaises(TypeError):
            extract_flow_feature_snapshot(
                window,
                flow_volume_features=snapshot.flow_volume_features,
            )
        self.assertEqual(manager.active_windows(), (window,))

    def test_wrong_inputs_reject_coordinators_states_analyses_feature_inputs_and_subclasses(self) -> None:
        manager, window = active_window_from_packets(packet_at(0))
        state = window.coordinated_state
        snapshot = extract_flow_feature_snapshot(window)
        volume_input = flow_feature_input_from_statistics(
            state.flow_statistics,
            state.directional_flow_statistics,
        )

        class DerivedWindow(FlowObservationWindow):
            pass

        derived = DerivedWindow(window.key, state, window.closure_reason)
        coordinator = FlowStateCoordinator()
        coordinator.record(packet_at(0))
        for value in (
            None, True, 1, 1.0, {}, [], coordinator, state, replace(state),
            UDP_ANALYSIS, OBSERVATION, volume_input,
            FlowFeatureInput(**vars(volume_input)), snapshot,
            SimpleNamespace(
                key=window.key,
                coordinated_state=state,
                closure_reason=None,
            ),
            Mock(spec=FlowObservationWindow), derived,
        ):
            with self.subTest(kind=type(value)):
                with self.assertRaises(TypeError):
                    extract_flow_feature_snapshot(value)
        self.assertEqual(manager.active_windows(), (window,))

    def test_repeated_active_extraction_and_later_admission_preserve_snapshot(self) -> None:
        manager, window = active_window_from_packets(packet_at(0), packet_at(1, True))
        state = window.coordinated_state
        sources = (window, state, state.identity, *state_components(state))
        before = [vars(value).copy() for value in sources]
        first = extract_flow_feature_snapshot(window)
        second = extract_flow_feature_snapshot(window)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIs(first.observation_window, second.observation_window)
        self.assertIs(first.coordinated_state, second.coordinated_state)
        frozen_values = [vars(value).copy() for value in vars(first).values()]
        later_window = manager.record(packet_at(4)).active_window
        later = extract_flow_feature_snapshot(later_window)
        self.assertIs(first.observation_window, window)
        self.assertIsNone(first.observation_window.closure_reason)
        self.assertEqual(first.flow_volume_features.packet_count, 2)
        self.assertEqual(later.flow_volume_features.packet_count, 3)
        self.assertIsNot(later.observation_window, window)
        for value, original in zip(sources, before):
            self.assertEqual(vars(value), original)
        for value, original in zip(vars(first).values(), frozen_values):
            self.assertEqual(vars(value), original)

    def test_window_coordinated_state_is_read_exactly_once(self) -> None:
        manager = FlowObservationWindowManager("single-read", timedelta.max)
        first_window = manager.record(packet_at(0)).active_window
        first_state = first_window.coordinated_state
        second_state = manager.record(packet_at(1)).active_window.coordinated_state
        with patch.object(
            FlowObservationWindow,
            "coordinated_state",
            new_callable=PropertyMock,
            side_effect=(first_state, second_state),
            create=True,
        ) as publication:
            snapshot = extract_flow_feature_snapshot(first_window)
            publication.assert_called_once_with()
        self.assertIs(snapshot.observation_window, first_window)
        self.assertEqual(snapshot.flow_volume_features.packet_count, 1)
        self.assertEqual(snapshot.flow_duration_features.duration_seconds, 0.0)

    def test_tcp_and_udp_raw_control_provenance_is_preserved(self) -> None:
        tcp_manager, tcp_window = active_window_from_packets(
            tcp_packet_at(0, syn=True),
            tcp_packet_at(1, reverse=True, ack=True),
            capture_session_id="tcp",
        )
        udp_manager, udp_window = active_window_from_packets(
            packet_at(0), packet_at(1, True), capture_session_id="udp",
        )
        tcp_snapshot = extract_flow_feature_snapshot(tcp_window)
        udp_snapshot = extract_flow_feature_snapshot(udp_window)
        tcp_control = tcp_window.coordinated_state.tcp_control_statistics
        self.assertIs(tcp_snapshot.coordinated_state.tcp_control_statistics, tcp_control)
        self.assertEqual(tcp_control.forward_syn_count, 1)
        self.assertEqual(tcp_control.reverse_ack_count, 1)
        self.assertIsNone(udp_snapshot.coordinated_state.tcp_control_statistics)
        self.assertEqual(tcp_manager.active_windows(), (tcp_window,))
        self.assertEqual(udp_manager.active_windows(), (udp_window,))

    def test_real_feature_overflow_propagates_without_changing_window(self) -> None:
        manager, window = active_window_from_packets(packet_at(0, original=10 ** 400))
        state = window.coordinated_state
        sources = (window, state, state.identity, *state_components(state))
        before = [vars(value).copy() for value in sources]
        with self.assertRaises(PacketSizeFeaturesError):
            extract_flow_feature_snapshot(window)
        for value, original in zip(sources, before):
            self.assertEqual(vars(value), original)
        self.assertEqual(manager.active_windows(), (window,))


if __name__ == "__main__":
    unittest.main()
