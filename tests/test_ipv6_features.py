import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta, timezone
from math import sqrt
from unittest.mock import PropertyMock, patch

from analysis import (
    FlowIdentityError,
    FlowInterArrivalStatisticsError,
    FlowObservationWindowClosureReason,
    FlowObservationWindowError,
    FlowObservationWindowManager,
    FlowStateCoordinator,
    FlowStatisticsError,
    InterArrivalFeatures,
    PacketAnalysisFailureClassification,
    analyze_packet,
    analyze_packet_outcome,
    extract_flow_feature_snapshot,
    update_tcp_control_statistics,
)
from application import run_flow_observation_session
from tests.test_flow_feature_snapshot import active_window_from_packets, snapshot_features
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_flow_observation_window import packet_at as ipv4_packet_at
from tests.test_ipv6_flow import observation_at, packet_at
from tests.test_ipv6_transport import fragment_header, observation_for


FLAGS = ("ns", "cwr", "ece", "urg", "ack", "psh", "rst", "syn", "fin")
SEQUENCE = ((0, False), (1, True), (3, False), (6, True))


def snapshot_from_packets(*packets):
    return extract_flow_feature_snapshot(active_window_from_packets(*packets)[1])


def feature_sequence(protocol):
    return tuple(
        packet_at(protocol, seconds=seconds, reverse=reverse, extensions=extensions)
        for (seconds, reverse), extensions in zip(
            SEQUENCE, ((), (0,), (43, 60), (0, 43, 60))
        )
    )


def scalar_values(value):
    return tuple(getattr(value, field.name) for field in fields(value) if field.name != "identity")


class IPv6FeatureParityTests(unittest.TestCase):
    def assert_volume_and_sizes(self, protocol):
        packets = feature_sequence(protocol)
        packets = tuple(replace(packet, observation=replace(
            packet.observation, original_length=packet.observation.captured_length + 10,
        )) for packet in packets)
        snapshot = snapshot_from_packets(*packets)
        base = 74 if protocol == 6 else 62
        volume = snapshot.flow_volume_features
        self.assertEqual(volume.packet_count, 4)
        self.assertEqual(volume.captured_bytes, 4 * base + 48)
        self.assertEqual(volume.original_bytes, 4 * base + 88)
        self.assertEqual((volume.forward_packet_count, volume.reverse_packet_count), (2, 2))
        self.assertEqual((volume.forward_captured_bytes, volume.reverse_captured_bytes),
                         (2 * base + 16, 2 * base + 32))
        self.assertEqual((volume.forward_original_bytes, volume.reverse_original_bytes),
                         (2 * base + 36, 2 * base + 52))
        self.assertEqual((volume.forward_packet_ratio, volume.reverse_packet_ratio), (0.5, 0.5))
        self.assertEqual(volume.forward_captured_byte_ratio, (2 * base + 16) / (4 * base + 48))
        self.assertEqual(volume.reverse_captured_byte_ratio, (2 * base + 32) / (4 * base + 48))
        self.assertEqual(volume.forward_original_byte_ratio, (2 * base + 36) / (4 * base + 88))
        self.assertEqual(volume.reverse_original_byte_ratio, (2 * base + 52) / (4 * base + 88))
        self.assertEqual(volume.capture_ratio, (4 * base + 48) / (4 * base + 88))
        sizes = snapshot.packet_size_features
        self.assertEqual((sizes.min_captured_length, sizes.max_captured_length), (base, base + 24))
        self.assertEqual((sizes.min_original_length, sizes.max_original_length), (base + 10, base + 34))
        self.assertEqual((sizes.mean_captured_length, sizes.mean_original_length), (base + 12.0, base + 22.0))
        self.assertEqual((sizes.variance_captured_length, sizes.variance_original_length), (80.0, 80.0))
        self.assertEqual((sizes.standard_deviation_captured_length, sizes.standard_deviation_original_length),
                         (sqrt(80), sqrt(80)))
        self.assertEqual((sizes.forward_mean_captured_length, sizes.reverse_mean_captured_length),
                         (base + 8.0, base + 16.0))
        self.assertEqual((sizes.forward_variance_captured_length, sizes.reverse_variance_captured_length),
                         (64.0, 64.0))
        self.assertEqual(snapshot.flow_duration_features.duration_seconds, 6.0)
        self.assertEqual(scalar_values(snapshot.flow_rate_features),
                         (4 / 6, (4 * base + 48) / 6, (4 * base + 88) / 6))

    def test_tcp_volume_direction_size_and_rate_features(self):
        self.assert_volume_and_sizes(6)

    def test_udp_volume_direction_size_and_rate_features(self):
        self.assert_volume_and_sizes(17)

    def assert_intervals(self, protocol):
        packets = feature_sequence(protocol)
        snapshot = snapshot_from_packets(*packets)
        intervals = snapshot.inter_arrival_features
        self.assertEqual(intervals.mean_inter_arrival_seconds, 2.0)
        self.assertAlmostEqual(intervals.variance_inter_arrival_seconds, 2 / 3)
        self.assertAlmostEqual(intervals.standard_deviation_inter_arrival_seconds, sqrt(2 / 3))
        self.assertEqual((intervals.min_inter_arrival_seconds, intervals.max_inter_arrival_seconds), (1.0, 3.0))
        self.assertEqual(scalar_values(snapshot.directional_inter_arrival_features),
                         (3.0, 0.0, 0.0, 3.0, 3.0, 5.0, 0.0, 0.0, 5.0, 5.0))
        state = snapshot.coordinated_state
        self.assertEqual(state.flow_inter_arrival_statistics.inter_arrival_count, 3)
        self.assertEqual(state.flow_inter_arrival_statistics.inter_arrival_sum_seconds, 6.0)
        self.assertEqual(state.flow_inter_arrival_statistics.inter_arrival_sum_seconds_squared, 14.0)
        self.assertIs(state.flow_statistics.first_captured_at, packets[0].observation.captured_at)
        self.assertIs(state.flow_statistics.last_captured_at, packets[-1].observation.captured_at)
        self.assertIs(state.flow_statistics.first_captured_at.tzinfo, timezone.utc)

    def test_tcp_global_and_directional_intervals(self):
        self.assert_intervals(6)

    def test_udp_global_and_directional_intervals(self):
        self.assert_intervals(17)

    def test_each_tcp_control_bit_and_syn_ack_are_counted_in_both_directions(self):
        for reverse in (False, True):
            for index, flag in enumerate(FLAGS):
                with self.subTest(reverse=reverse, flag=flag):
                    snapshot = snapshot_from_packets(packet_at(flags=1 << (8 - index), reverse=reverse))
                    control = snapshot.coordinated_state.tcp_control_statistics
                    selected = "reverse" if reverse else "forward"
                    self.assertEqual(control.packet_count, 1)
                    for direction in ("forward", "reverse"):
                        self.assertEqual(getattr(control, direction + "_packet_count"), int(direction == selected))
                        for other in FLAGS:
                            self.assertEqual(getattr(control, f"{direction}_{other}_count"),
                                             int(direction == selected and flag == other))
                        self.assertEqual(getattr(control, direction + "_syn_ack_count"), 0)
        control = snapshot_from_packets(
            packet_at(flags=0x1ff), packet_at(seconds=1, reverse=True, flags=0x1ff),
            packet_at(seconds=2, flags=0),
        ).coordinated_state.tcp_control_statistics
        self.assertEqual((control.packet_count, control.forward_packet_count, control.reverse_packet_count), (3, 2, 1))
        for direction in ("forward", "reverse"):
            for flag in FLAGS + ("syn_ack",):
                self.assertEqual(getattr(control, f"{direction}_{flag}_count"), 1)

    def test_udp_generic_features_have_no_tcp_control_state(self):
        snapshot = snapshot_from_packets(*feature_sequence(17))
        self.assertIsNone(snapshot.coordinated_state.tcp_control_statistics)
        self.assertEqual(snapshot.identity.protocol, 17)
        self.assertEqual(snapshot.flow_volume_features.packet_count, 4)

    def assert_family_equivalence(self, protocol):
        ipv6 = tuple(packet_at(protocol, seconds=t, reverse=r, flags=mask)
                     for (t, r), mask in zip(SEQUENCE, (0x1ff, 0x12, 0x10, 0)))
        ipv4 = []
        for v6, (t, r) in zip(ipv6, SEQUENCE):
            flags = {} if protocol == 17 else {name: getattr(v6.ipv6_tcp, name) for name in FLAGS}
            v4 = ipv4_packet_at(t, reverse=r, protocol=protocol, **flags)
            ipv4.append(replace(v4, observation=replace(
                v4.observation, captured_at=v6.observation.captured_at,
                captured_length=v6.observation.captured_length,
                original_length=v6.observation.original_length,
                raw_bytes=bytes(v6.observation.captured_length),
            )))
        v4_snapshot, v6_snapshot = (snapshot_from_packets(*packets) for packets in (ipv4, ipv6))
        self.assertNotEqual(v4_snapshot.identity, v6_snapshot.identity)
        self.assertEqual(snapshot_features(v4_snapshot), snapshot_features(v6_snapshot))
        for field in fields(v4_snapshot.coordinated_state):
            if field.name in ("tcp_stream_state", "tls_record_state"):
                continue
            left = getattr(v4_snapshot.coordinated_state, field.name)
            right = getattr(v6_snapshot.coordinated_state, field.name)
            if left is None:
                self.assertIsNone(right)
            else:
                self.assertEqual(scalar_values(left), scalar_values(right))

    def test_equivalent_ipv4_ipv6_tcp_semantics_produce_equal_features(self):
        self.assert_family_equivalence(6)

    def test_equivalent_ipv4_ipv6_udp_semantics_produce_equal_features(self):
        self.assert_family_equivalence(17)

    def test_single_packet_has_zero_global_intervals_absent_rates_and_directional_intervals(self):
        for protocol in (6, 17):
            for reverse in (False, True):
                snapshot = snapshot_from_packets(packet_at(protocol, reverse=reverse))
                self.assertIsNone(snapshot.flow_rate_features)
                self.assertEqual(snapshot.flow_duration_features.duration_seconds, 0.0)
                self.assertEqual(snapshot.inter_arrival_features, InterArrivalFeatures(0.0, 0.0, 0.0, 0.0, 0.0))
                self.assertEqual(scalar_values(snapshot.directional_inter_arrival_features), (None,) * 10)
                self.assertEqual(snapshot.flow_volume_features.forward_packet_count, int(not reverse))
                self.assertEqual(snapshot.flow_volume_features.reverse_packet_count, int(reverse))

    def test_repeated_timestamps_produce_real_zero_directional_intervals(self):
        for protocol in (6, 17):
            snapshot = snapshot_from_packets(*(packet_at(protocol, reverse=r) for r in (False, True, False, True)))
            self.assertEqual(scalar_values(snapshot.directional_inter_arrival_features), (0.0,) * 10)
            self.assertEqual(scalar_values(snapshot.inter_arrival_features), (0.0,) * 5)
            self.assertIsNone(snapshot.flow_rate_features)

    def test_same_direction_and_reverse_first_use_canonical_direction(self):
        for protocol in (6, 17):
            for reverse in (False, True):
                snapshot = snapshot_from_packets(*(packet_at(protocol, seconds=t, reverse=reverse) for t in (0, 2, 6)))
                values = (3.0, 1.0, 1.0, 2.0, 4.0)
                expected = (None,) * 5 + values if reverse else values + (None,) * 5
                self.assertEqual(scalar_values(snapshot.directional_inter_arrival_features), expected)
                self.assertEqual(snapshot.flow_volume_features.packet_count, 3)

    def test_named_utc_and_microsecond_timestamps_are_preserved(self):
        for protocol in (6, 17):
            first = packet_at(protocol)
            timestamp = first.observation.captured_at.replace(tzinfo=timezone(timedelta(0), "capture UTC"))
            first = replace(first, observation=replace(first.observation, captured_at=timestamp))
            last = replace(first, observation=replace(first.observation, captured_at=timestamp + timedelta(microseconds=3)))
            snapshot = snapshot_from_packets(first, last)
            self.assertIs(snapshot.observation_window.first_captured_at, timestamp)
            self.assertIs(snapshot.observation_window.last_captured_at, last.observation.captured_at)
            self.assertEqual(snapshot.inter_arrival_features.mean_inter_arrival_seconds, 0.000003)
            self.assertEqual(snapshot.flow_duration_features.duration_seconds, 0.000003)

    def test_out_of_order_admission_preserves_prior_features(self):
        for protocol in (6, 17):
            manager, window = active_window_from_packets(packet_at(protocol), packet_at(protocol, seconds=3))
            before = extract_flow_feature_snapshot(window)
            with self.assertRaises(FlowObservationWindowError):
                manager.record(packet_at(protocol, seconds=2, reverse=True))
            self.assertEqual(extract_flow_feature_snapshot(manager.active_windows()[0]), before)
            coordinator = FlowStateCoordinator()
            coordinator.record(packet_at(protocol))
            state = coordinator.record(packet_at(protocol, seconds=3))
            with self.assertRaises(FlowInterArrivalStatisticsError):
                coordinator.record(packet_at(protocol, seconds=2))
            self.assertIs(coordinator.state, state)

    def test_unknown_original_length_does_not_publish_features(self):
        for protocol in (6, 17):
            packet = packet_at(protocol)
            manager, window = active_window_from_packets(packet)
            invalid = replace(packet, observation=replace(packet.observation, original_length=None))
            with self.assertRaises(FlowStatisticsError):
                manager.record(invalid)
            self.assertEqual(manager.active_windows(), (window,))

    def test_independent_flow_windows_keep_feature_state_separate(self):
        manager = FlowObservationWindowManager("independent", timedelta(seconds=10))
        for protocol in (6, 17):
            for port in (12345, 12346):
                manager.record(packet_at(protocol, source_port=port))
        updated = manager.record(packet_at(6, seconds=2, reverse=True)).active_window
        snapshots = tuple(extract_flow_feature_snapshot(window) for window in manager.active_windows())
        self.assertEqual(tuple(s.flow_volume_features.packet_count for s in snapshots), (2, 1, 1, 1))
        self.assertEqual(tuple(s.flow_duration_features.duration_seconds for s in snapshots), (2.0, 0.0, 0.0, 0.0))
        self.assertEqual(len({s.identity for s in snapshots}), 4)
        self.assertEqual(snapshots[0].identity, updated.identity)

    def test_inactivity_boundary_excludes_gap_from_new_feature_window(self):
        for protocol in (6, 17):
            manager = FlowObservationWindowManager("boundary", timedelta(seconds=5))
            first = manager.record(packet_at(protocol)).active_window
            old_snapshot = extract_flow_feature_snapshot(first)
            manager.record(packet_at(protocol, seconds=1, reverse=True))
            update = manager.record(packet_at(protocol, seconds=6))
            closed = extract_flow_feature_snapshot(update.closed_windows[0])
            active = extract_flow_feature_snapshot(update.active_window)
            self.assertIs(closed.observation_window.closure_reason, FlowObservationWindowClosureReason.INACTIVITY)
            self.assertEqual(closed.flow_volume_features.packet_count, 2)
            self.assertEqual(closed.flow_duration_features.duration_seconds, 1.0)
            self.assertEqual(active.flow_volume_features.packet_count, 1)
            self.assertIsNone(active.flow_rate_features)
            self.assertEqual(active.observation_window.key.sequence_number, 1)
            self.assertEqual(old_snapshot.flow_volume_features.packet_count, 1)
            final = extract_flow_feature_snapshot(manager.end_capture_session()[0])
            self.assertEqual(snapshot_features(final), snapshot_features(active))

    def test_first_and_whole_fragment_features_use_admitted_transport(self):
        for protocol in (6, 17):
            for more in (False, True):
                packets = tuple(packet_at(protocol, seconds=t, reverse=r, fragment=(0, more)) for t, r in SEQUENCE)
                snapshot = snapshot_from_packets(*packets)
                self.assertEqual(snapshot.flow_volume_features.captured_bytes, 4 * (82 if protocol == 6 else 70))
                self.assertEqual(snapshot.flow_volume_features.packet_count, 4)
                self.assertEqual(snapshot.inter_arrival_features.mean_inter_arrival_seconds, 2.0)
                self.assertEqual(snapshot.coordinated_state.tcp_control_statistics is None, protocol == 17)

    def test_non_first_fragments_never_contribute_or_correlate(self):
        for protocol in (6, 17):
            manager = FlowObservationWindowManager("fragments", timedelta(seconds=10))
            non_first = packet_at(protocol, fragment=(1, False))
            with self.assertRaises(FlowIdentityError):
                manager.record(non_first)
            self.assertEqual(manager.active_windows(), ())
            first = manager.record(packet_at(protocol, fragment=(0, True))).active_window
            for packet in (non_first, packet_at(protocol, fragment=(1, True))):
                with self.assertRaises(FlowIdentityError):
                    manager.record(packet)
                self.assertEqual(manager.active_windows(), (first,))
            last = manager.record(packet_at(protocol, seconds=1, fragment=(0, True))).active_window
            snapshot = extract_flow_feature_snapshot(last)
            self.assertEqual(snapshot.flow_volume_features.packet_count, 2)
            self.assertEqual(snapshot.flow_volume_features.captured_bytes, 2 * (82 if protocol == 6 else 70))

    def test_missing_transport_icmpv6_and_unsupported_protocols_do_not_publish_features(self):
        packets = [replace(packet_at(protocol, fragment=(0, False)), ipv6_tcp=None, ipv6_udp=None)
                   for protocol in (6, 17)]
        packets.extend(analyze_packet(observation_for(protocol, bytes.fromhex("80001234")))
                       for protocol in (58, 59, 50, 51, 132, 33, 47, 253))
        manager, window = active_window_from_packets(packet_at(6))
        before = extract_flow_feature_snapshot(window)
        for packet in packets:
            with self.assertRaises(FlowIdentityError):
                manager.record(packet)
            self.assertEqual(extract_flow_feature_snapshot(manager.active_windows()[0]), before)

    def test_incomplete_fragment_and_extension_analysis_cannot_supply_feature_input(self):
        for protocol in (6, 17):
            observations = (
                observation_for(protocol, b"\x00\x01", fragment_header(protocol, 0, True), 44),
                observation_for(protocol, b"\x00", base=0),
            )
            for observation in observations:
                outcome = analyze_packet_outcome(observation)
                self.assertIsNone(outcome.analysis)
                self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)

    def test_decoded_tcp_flags_are_authoritative_without_raw_packet_access(self):
        packet = packet_at(6, extensions=(0, 43, 60), flags=2)
        packet = replace(packet, ipv6_tcp=replace(packet.ipv6_tcp, syn=False, ack=True, rst=True))
        _, window = active_window_from_packets(packet)
        with ExitStack() as stack:
            for target in ("analysis.ipv6.IPv6Packet.payload", "capture.packet_observation.PacketObservation.raw_bytes",
                           "analysis.tcp.TCPPacket.payload", "analysis.ethernet.EthernetFrame.payload"):
                stack.enter_context(patch(target, new_callable=PropertyMock, create=True,
                                          side_effect=AssertionError("raw packet access")))
            snapshot = extract_flow_feature_snapshot(window)
            direct_control = update_tcp_control_statistics(None, packet, window.identity)
        control = snapshot.coordinated_state.tcp_control_statistics
        self.assertEqual(control, direct_control)
        self.assertEqual((control.forward_syn_count, control.forward_ack_count, control.forward_rst_count), (0, 1, 1))
        self.assertEqual(snapshot.flow_volume_features.captured_bytes, 98)

    def test_extension_transport_features_do_not_repeat_packet_analysis(self):
        for protocol in (6, 17):
            for extensions in ((), (0,), (43,), (60,), (0, 43, 60)):
                packets = (packet_at(protocol, extensions=extensions),
                           packet_at(protocol, seconds=2, reverse=True, extensions=extensions))
                with ExitStack() as stack:
                    for target in ("analysis.packet_analysis.analyze_packet", "analysis.packet_analysis.decode_ipv6",
                                   "analysis.packet_analysis.decode_tcp", "analysis.packet_analysis.decode_udp",
                                   "analysis.packet_analysis.validate_ipv6_extension_headers",
                                   "analysis.packet_analysis.analyze_ipv6_fragmentation",
                                   "analysis.ipv6_fragmentation.validate_ipv6_extension_headers",
                                   "analysis.ipv6_extension_headers.validate_ipv6_extension_headers"):
                        stack.enter_context(patch(target, side_effect=AssertionError("repeated packet analysis")))
                    snapshot = snapshot_from_packets(*packets)
                self.assertEqual(snapshot.flow_volume_features.captured_bytes,
                                 2 * ((74 if protocol == 6 else 62) + 8 * len(extensions)))
                self.assertEqual(snapshot.inter_arrival_features.mean_inter_arrival_seconds, 2.0)

    def test_extraction_reads_only_coordinated_state_and_invokes_no_detectors(self):
        for protocol in (6, 17):
            window = active_window_from_packets(*feature_sequence(protocol))[1]
            with ExitStack() as stack:
                for target in ("analysis.packet_analysis.PacketAnalysis.observation",
                               "analysis.packet_analysis.PacketAnalysis.ipv6",
                               "analysis.packet_analysis.PacketAnalysis.ipv6_tcp",
                               "analysis.packet_analysis.PacketAnalysis.ipv6_udp"):
                    stack.enter_context(patch(target, new_callable=PropertyMock, create=True,
                                              side_effect=AssertionError("feature accessed packets")))
                for target in ("application.detector_orchestration.run_packet_detectors",
                               "application.detector_orchestration.run_closed_flow_detectors",
                               "detection.packet_integrity.evaluate_packet_integrity",
                               "detection.flow_volume_threshold.evaluate_flow_volume_threshold",
                               "detection.tcp_control_threshold.evaluate_tcp_control_threshold",
                               "detection.detection_finding.detection_finding_from_evaluation"):
                    stack.enter_context(patch(target, side_effect=AssertionError("detector invoked")))
                snapshot = extract_flow_feature_snapshot(window)
                self.assertEqual(snapshot.flow_volume_features.packet_count, 4)
                self.assertIs(snapshot.coordinated_state, window.coordinated_state)

    def test_all_feature_and_state_models_remain_immutable(self):
        for protocol in (6, 17):
            snapshot = snapshot_from_packets(*feature_sequence(protocol))
            state = snapshot.coordinated_state
            models = (snapshot, snapshot.observation_window, state) + snapshot_features(snapshot)
            models += tuple(getattr(state, field.name) for field in fields(state))
            for model in models:
                if model is not None:
                    for field in fields(model):
                        with self.assertRaises(FrozenInstanceError):
                            setattr(model, field.name, None)

    def test_repeated_identical_sequences_and_extractions_are_equal(self):
        for protocol in (6, 17):
            first = snapshot_from_packets(*feature_sequence(protocol))
            second = snapshot_from_packets(*feature_sequence(protocol))
            self.assertEqual(first, second)
            self.assertEqual(first, extract_flow_feature_snapshot(first.observation_window))

    def test_application_closed_window_consumer_extracts_deterministic_features(self):
        for protocol in (6, 17):
            runs = []
            for _ in range(2):
                source = MemoryPacketSource(observation_at(protocol, seconds=t, reverse=r) for t, r in SEQUENCE)
                snapshots = []
                run_flow_observation_session(
                    source, capture_session_id="ipv6-features", inactivity_timeout=timedelta(seconds=10),
                    closed_window_consumer=lambda window: snapshots.append(extract_flow_feature_snapshot(window)),
                )
                self.assertTrue(source.stopped)
                self.assertEqual(len(snapshots), 1)
                self.assertIs(snapshots[0].observation_window.closure_reason,
                              FlowObservationWindowClosureReason.CAPTURE_SESSION_END)
                self.assertEqual(snapshots[0].flow_volume_features.packet_count, 4)
                self.assertEqual(snapshots[0].flow_duration_features.duration_seconds, 6.0)
                runs.append(snapshots)
            self.assertEqual(runs[0], runs[1])


if __name__ == "__main__":
    unittest.main()
