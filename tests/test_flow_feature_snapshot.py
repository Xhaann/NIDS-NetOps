import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock, PropertyMock, patch

from analysis import (
    CoordinatedFlowState,
    DirectionalInterArrivalFeatures,
    DirectionalInterArrivalFeaturesError,
    FlowDurationFeatures,
    FlowFeatureSnapshot,
    FlowFeatureSnapshotError,
    FlowRateFeatures,
    FlowRateFeaturesError,
    FlowStateCoordinator,
    FlowVolumeFeatures,
    InterArrivalFeatures,
    IPv4Packet,
    PacketAnalysis,
    PacketSizeFeatures,
    PacketSizeFeaturesError,
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
ANALYSIS = PacketAnalysis(OBSERVATION, ipv4=IPV4, udp=UDPPacket(12345, 443, 8, 0, b""))


def packet_at(seconds: float, reverse: bool = False, captured: int = 60, original: int = 100) -> PacketAnalysis:
    packet = replace(ANALYSIS, observation=replace(
        OBSERVATION, captured_at=TIMESTAMP + timedelta(seconds=seconds),
        captured_length=captured, original_length=original, raw_bytes=bytes(captured),
    ))
    if reverse:
        packet = replace(
            packet,
            ipv4=replace(IPV4, source_address=IPV4.destination_address,
                         destination_address=IPV4.source_address),
            udp=replace(packet.udp, source_port=443, destination_port=12345),
        )
    return packet


class FlowFeatureSnapshotTests(unittest.TestCase):
    def test_bidirectional_snapshot_uses_all_established_feature_families(self) -> None:
        coordinator = FlowStateCoordinator()
        coordinator.record(packet_at(0, False, 60, 100))
        coordinator.record(packet_at(1.5, True, 80, 120))
        state = coordinator.record(packet_at(4, False, 100, 140))
        snapshot = extract_flow_feature_snapshot(coordinator)
        self.assertIs(type(snapshot), FlowFeatureSnapshot)
        self.assertIs(snapshot.coordinated_state, state)
        self.assertIs(snapshot.identity, state.identity)
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
        self.assertEqual(snapshot.inter_arrival_features, InterArrivalFeatures(2.0, 0.25, 0.5, 1.5, 2.5))
        self.assertIs(type(snapshot.directional_inter_arrival_features), DirectionalInterArrivalFeatures)
        self.assertEqual(snapshot.directional_inter_arrival_features, DirectionalInterArrivalFeatures(
            4.0, 0.0, 0.0, 4.0, 4.0,
            None, None, None, None, None,
        ))
        directional = state.directional_inter_arrival_statistics
        self.assertIs(snapshot.coordinated_state.directional_inter_arrival_statistics, directional)
        self.assertEqual(directional.forward_inter_arrival_sum_seconds, 4.0)
        self.assertEqual(directional.reverse_inter_arrival_count, 0)

    def test_first_packet_and_populated_zero_duration_have_absent_rates(self) -> None:
        coordinator = FlowStateCoordinator()
        for packet in (packet_at(0), packet_at(0, True), packet_at(0)):
            state = coordinator.record(packet)
            with self.assertRaises(FlowRateFeaturesError):
                extract_flow_rate_features(state.flow_statistics)
            with patch("analysis.flow_feature_snapshot.extract_flow_rate_features",
                       wraps=extract_flow_rate_features) as rate_extractor:
                snapshot = extract_flow_feature_snapshot(coordinator)
                rate_extractor.assert_not_called()
            self.assertEqual(snapshot.flow_duration_features.duration_seconds, 0.0)
            self.assertIsNone(snapshot.flow_rate_features)
            self.assertEqual(snapshot.inter_arrival_features, InterArrivalFeatures(0.0, 0.0, 0.0, 0.0, 0.0))
            directional = snapshot.directional_inter_arrival_features
            if state.directional_inter_arrival_statistics.forward_inter_arrival_count == 0:
                self.assertEqual(tuple(vars(directional).values()), (None,) * 10)
            else:
                self.assertEqual(tuple(vars(directional).values()), (0.0,) * 5 + (None,) * 5)
            self.assertIs(coordinator.state, state)

    def test_unidirectional_unused_size_direction_and_fractional_time_are_preserved(self) -> None:
        for reverse in (False, True):
            for seconds in (0.000001, 1.5):
                coordinator = FlowStateCoordinator()
                coordinator.record(packet_at(0, reverse))
                coordinator.record(packet_at(seconds, reverse))
                snapshot = extract_flow_feature_snapshot(coordinator)
                unused = "forward" if reverse else "reverse"
                self.assertEqual(getattr(snapshot.packet_size_features, unused + "_mean_captured_length"), 0.0)
                self.assertEqual(getattr(snapshot.packet_size_features, unused + "_variance_captured_length"), 0.0)
                self.assertEqual(snapshot.flow_duration_features.duration_seconds, seconds)
                self.assertEqual(snapshot.flow_rate_features.packets_per_second, 2 / seconds)
                self.assertEqual(snapshot.inter_arrival_features.mean_inter_arrival_seconds, seconds)
                self.assertEqual(snapshot.inter_arrival_features.variance_inter_arrival_seconds, 0.0)
                used = "reverse" if reverse else "forward"
                directional = snapshot.directional_inter_arrival_features
                self.assertEqual(getattr(directional, used + "_mean_inter_arrival_seconds"), seconds)
                self.assertEqual(getattr(directional, used + "_variance_inter_arrival_seconds"), 0.0)
                self.assertIsNone(getattr(directional, unused + "_mean_inter_arrival_seconds"))

    def test_positive_duration_zero_byte_rates_are_present_numerical_zeros(self) -> None:
        coordinator = FlowStateCoordinator()
        coordinator.record(packet_at(0, captured=0, original=0))
        coordinator.record(packet_at(1, captured=0, original=0))
        snapshot = extract_flow_feature_snapshot(coordinator)
        self.assertIs(type(snapshot.flow_rate_features), FlowRateFeatures)
        self.assertEqual(snapshot.flow_rate_features, FlowRateFeatures(2.0, 0.0, 0.0))

    def test_exact_source_arguments_and_extractor_result_references_are_preserved(self) -> None:
        coordinator = FlowStateCoordinator()
        coordinator.record(packet_at(0))
        state = coordinator.record(packet_at(3, True))
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
            snapshot = extract_flow_feature_snapshot(coordinator)
            for call in calls:
                self.assertEqual(call.call_count, 1)
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
        self.assertTrue(all(value is not results["volume_input"] for value in vars(snapshot).values()))

    def test_frozen_seven_typed_fields_have_no_duplicate_sources_or_flattening(self) -> None:
        coordinator = FlowStateCoordinator()
        coordinator.record(packet_at(0))
        coordinator.record(packet_at(1))
        snapshot = extract_flow_feature_snapshot(coordinator)
        expected = (
            ("coordinated_state", CoordinatedFlowState),
            ("flow_volume_features", FlowVolumeFeatures),
            ("packet_size_features", PacketSizeFeatures),
            ("flow_duration_features", FlowDurationFeatures),
            ("flow_rate_features", FlowRateFeatures),
            ("inter_arrival_features", InterArrivalFeatures),
            ("directional_inter_arrival_features", DirectionalInterArrivalFeatures),
        )
        self.assertEqual(tuple(field.name for field in fields(snapshot)), tuple(name for name, kind in expected))
        self.assertEqual(tuple(vars(snapshot)), tuple(name for name, kind in expected))
        for name, kind in expected:
            self.assertIs(type(getattr(snapshot, name)), kind)
            with self.assertRaises(FrozenInstanceError):
                setattr(snapshot, name, getattr(snapshot, name))
            with self.assertRaises(FrozenInstanceError):
                delattr(snapshot, name)
        with self.assertRaises(FrozenInstanceError):
            snapshot.identity = snapshot.identity
        with self.assertRaises(FrozenInstanceError):
            snapshot.extra = 1
        with self.assertRaises(TypeError):
            iter(snapshot)
        self.assertNotIn("identity", vars(snapshot))
        self.assertNotIn("coordinator", vars(snapshot))
        self.assertNotIn("directional_inter_arrival_statistics", vars(snapshot))

    def test_canonical_utc_temporal_families_remain_semantically_distinct(self) -> None:
        coordinator = FlowStateCoordinator()
        for seconds, reverse in ((0, False), (1, True), (3, False), (5, True)):
            state = coordinator.record(packet_at(seconds, reverse))
        snapshot = extract_flow_feature_snapshot(coordinator)
        self.assertIs(type(state.flow_statistics.first_captured_at.tzinfo), timezone)
        self.assertIs(type(state.flow_statistics.last_captured_at.tzinfo), timezone)
        self.assertEqual(
            snapshot.flow_duration_features.duration_seconds,
            (state.flow_statistics.last_captured_at - state.flow_statistics.first_captured_at).total_seconds(),
        )
        self.assertEqual(state.flow_inter_arrival_statistics.inter_arrival_sum_seconds, 5.0)
        self.assertEqual(snapshot.inter_arrival_features.mean_inter_arrival_seconds, 5.0 / 3.0)
        self.assertEqual(state.directional_inter_arrival_statistics.forward_inter_arrival_sum_seconds, 3.0)
        self.assertEqual(state.directional_inter_arrival_statistics.reverse_inter_arrival_sum_seconds, 4.0)
        self.assertEqual(snapshot.directional_inter_arrival_features, DirectionalInterArrivalFeatures(
            3.0, 0.0, 0.0, 3.0, 3.0,
            4.0, 0.0, 0.0, 4.0, 4.0,
        ))

    def test_directional_extraction_errors_propagate_without_mutating_state(self) -> None:
        coordinator = FlowStateCoordinator()
        state = coordinator.record(packet_at(0))
        before = [vars(value).copy() for value in (coordinator, state, *vars(state).values())]
        with patch(
            "analysis.flow_feature_snapshot.extract_directional_inter_arrival_features",
            side_effect=DirectionalInterArrivalFeaturesError("invalid directional moments"),
        ) as directional_extractor:
            with self.assertRaises(DirectionalInterArrivalFeaturesError):
                extract_flow_feature_snapshot(coordinator)
        directional_extractor.assert_called_once_with(state.directional_inter_arrival_statistics)
        for value, original in zip((coordinator, state, *vars(state).values()), before):
            self.assertEqual(vars(value), original)

    def test_no_direct_construction_replacement_or_arbitrary_feature_injection(self) -> None:
        coordinator = FlowStateCoordinator()
        state = coordinator.record(packet_at(0))
        snapshot = extract_flow_feature_snapshot(coordinator)
        with self.assertRaises(TypeError):
            FlowFeatureSnapshot()
        with self.assertRaises(TypeError):
            FlowFeatureSnapshot(coordinator)
        with self.assertRaises(TypeError):
            FlowFeatureSnapshot(**vars(snapshot))
        with self.assertRaises(TypeError):
            replace(snapshot, coordinated_state=replace(state))
        with self.assertRaises(TypeError):
            extract_flow_feature_snapshot(coordinator, flow_volume_features=snapshot.flow_volume_features)

    def test_wrong_inputs_include_manual_states_and_coordinator_subclasses(self) -> None:
        coordinator = FlowStateCoordinator()
        state = coordinator.record(packet_at(0))
        snapshot = extract_flow_feature_snapshot(coordinator)

        class DerivedCoordinator(FlowStateCoordinator):
            pass

        derived = DerivedCoordinator()
        derived.record(packet_at(0))
        for value in (
            None, True, 1, 1.0, {}, [], state, replace(state), state.identity,
            state.flow_statistics, state.flow_packet_size_statistics, ANALYSIS, OBSERVATION,
            snapshot, snapshot.flow_volume_features, SimpleNamespace(state=state),
            Mock(spec=FlowStateCoordinator), derived,
        ):
            with self.subTest(kind=type(value)):
                with self.assertRaises(TypeError):
                    extract_flow_feature_snapshot(value)

    def test_empty_coordinator_has_no_snapshot_and_is_not_mutated(self) -> None:
        coordinator = FlowStateCoordinator()
        before = vars(coordinator).copy()
        self.assertTrue(issubclass(FlowFeatureSnapshotError, ValueError))
        with self.assertRaises(FlowFeatureSnapshotError):
            extract_flow_feature_snapshot(coordinator)
        self.assertEqual(vars(coordinator), before)
        self.assertIsNone(coordinator.state)

    def test_repeated_extraction_and_later_admission_preserve_original_state_and_features(self) -> None:
        coordinator = FlowStateCoordinator()
        coordinator.record(packet_at(0))
        state = coordinator.record(packet_at(1, True))
        sources = (coordinator, state, state.identity) + tuple(vars(state).values())
        before = [vars(value).copy() for value in sources]
        first = extract_flow_feature_snapshot(coordinator)
        second = extract_flow_feature_snapshot(coordinator)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIs(first.coordinated_state, second.coordinated_state)
        for value, original in zip(sources, before):
            self.assertEqual(vars(value), original)
            for name, field_value in original.items():
                self.assertIs(getattr(value, name), field_value)
        frozen_values = [vars(value).copy() for value in vars(first).values()]
        coordinator.record(packet_at(4))
        later = extract_flow_feature_snapshot(coordinator)
        self.assertIs(first.coordinated_state, state)
        self.assertEqual(first.flow_volume_features.packet_count, 2)
        self.assertEqual(later.flow_volume_features.packet_count, 3)
        self.assertIsNot(later.coordinated_state, state)
        for value, original in zip(vars(first).values(), frozen_values):
            self.assertEqual(vars(value), original)

    def test_published_state_is_read_exactly_once(self) -> None:
        coordinator = FlowStateCoordinator()
        first = coordinator.record(packet_at(0))
        second = coordinator.record(packet_at(1))
        with patch.object(FlowStateCoordinator, "state", new_callable=PropertyMock,
                          side_effect=(first, second)) as publication:
            snapshot = extract_flow_feature_snapshot(coordinator)
            publication.assert_called_once_with()
        self.assertIs(snapshot.coordinated_state, first)
        self.assertIsNone(snapshot.flow_rate_features)

    def test_real_feature_overflow_propagates_without_changing_published_state(self) -> None:
        coordinator = FlowStateCoordinator()
        state = coordinator.record(packet_at(0, original=10 ** 400))
        sources = (coordinator, state, state.identity) + tuple(vars(state).values())
        before = [vars(value).copy() for value in sources]
        with self.assertRaises(PacketSizeFeaturesError):
            extract_flow_feature_snapshot(coordinator)
        self.assertIs(coordinator.state, state)
        for value, original in zip(sources, before):
            self.assertEqual(vars(value), original)
