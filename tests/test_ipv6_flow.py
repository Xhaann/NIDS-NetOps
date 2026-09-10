import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from unittest.mock import patch

from analysis import (
    FlowCoordinationError,
    FlowDirection,
    FlowDirectionError,
    FlowIdentity,
    FlowIdentityError,
    FlowObservationWindowClosureReason,
    FlowObservationWindowError,
    FlowObservationWindowManager,
    FlowStateCoordinator,
    FlowTracker,
    PacketAnalysis,
    PacketAnalysisError,
    PacketAnalysisFailureClassification,
    analyze_packet,
    analyze_packet_outcome,
    flow_direction_from_packet,
    flow_identity_from_addresses,
    flow_identity_from_packet,
)
from analysis import flow_feature_snapshot
from application import run_flow_observation_session
from tests.test_flow_identity import TCP_ANALYSIS, UDP_ANALYSIS
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ipv6 import SOURCE_ADDRESS, DESTINATION_ADDRESS
from tests.test_ipv6_transport import observation_for, fragment_header
from tests.test_tcp import TCP_HEADER
from tests.test_udp import UDP_HEADER


def observation_at(protocol=6, seconds=0, reverse=False, source=SOURCE_ADDRESS,
                   destination=DESTINATION_ADDRESS, source_port=12345,
                   destination_port=443, extensions=(), fragment=None, flags=2):
    raw = TCP_HEADER if protocol == 6 else UDP_HEADER
    if protocol == 6:
        raw = raw[:12] + (0x5000 | flags).to_bytes(2, "big") + raw[14:]
    if reverse:
        source, destination = destination, source
        source_port, destination_port = destination_port, source_port
    raw = source_port.to_bytes(2, "big") + destination_port.to_bytes(2, "big") + raw[4:]
    base = protocol
    prefix = b""
    if fragment is not None:
        prefix = fragment_header(protocol, *fragment)
        base = 44
    for header_type in reversed(extensions):
        prefix = bytes((base, 0)) + bytes(6) + prefix
        base = header_type
    observation = observation_for(protocol, raw, prefix, base)
    wire = observation.raw_bytes[:22] + source + destination + observation.raw_bytes[54:]
    return replace(observation, raw_bytes=wire,
                   captured_at=observation.captured_at + timedelta(seconds=seconds))


def packet_at(*args, **kwargs):
    return analyze_packet(observation_at(*args, **kwargs))


class IPv6FlowIdentityTests(unittest.TestCase):
    def assert_identity(self, protocol):
        packet = packet_at(protocol)
        identity = flow_identity_from_packet(packet)
        self.assertEqual(identity, FlowIdentity(SOURCE_ADDRESS, DESTINATION_ADDRESS, 12345, 443, protocol))
        self.assertIs(identity.source_address, packet.ipv6.source_address)
        self.assertIs(identity.destination_address, packet.ipv6.destination_address)
        self.assertEqual((identity.source_port, identity.destination_port), (12345, 443))
        self.assertEqual(identity.protocol, protocol)
        self.assertEqual(identity.ip_version, 6)
        self.assertEqual(len(identity.source_address), 16)
        self.assertIs(type(identity.source_address), bytes)

    def test_tcp_uses_exact_packed_addresses_and_decoded_ports(self):
        self.assert_identity(6)

    def test_udp_uses_exact_packed_addresses_and_decoded_ports(self):
        self.assert_identity(17)

    def test_identity_is_immutable_deterministic_and_hashable(self):
        for protocol in (6, 17):
            observation = observation_at(protocol)
            first = flow_identity_from_packet(analyze_packet(observation))
            second = flow_identity_from_packet(analyze_packet(observation))
            self.assertEqual(first, second)
            self.assertEqual(hash(first), hash(second))
            self.assertEqual(len({first, second}), 1)
            for field in fields(first):
                with self.assertRaises(FrozenInstanceError):
                    setattr(first, field.name, None)

    def test_each_endpoint_component_distinguishes_flows(self):
        for protocol in (6, 17):
            packets = [packet_at(protocol)]
            for changes in ({"source": bytes.fromhex("20010db8000000000000000000000003")},
                            {"destination": bytes.fromhex("20010db8000000000000000000000004")},
                            {"source_port": 12346}, {"destination_port": 444}):
                packets.append(packet_at(protocol, **changes))
            identities = [flow_identity_from_packet(packet) for packet in packets]
            self.assertEqual(len(set(identities)), 5)
            tracker = FlowTracker()
            for packet in packets:
                self.assertEqual(tracker.record(packet).packet_count, 1)
            self.assertEqual(tracker.flow_count(), 5)

    def test_protocol_and_family_remain_distinct(self):
        packets = (TCP_ANALYSIS, UDP_ANALYSIS, packet_at(6), packet_at(17))
        identities = tuple(flow_identity_from_packet(packet) for packet in packets)
        self.assertEqual(tuple(identity.ip_version for identity in identities), (4, 4, 6, 6))
        self.assertEqual(tuple(identity.protocol for identity in identities), (6, 17, 6, 17))
        self.assertEqual(len(set(identities)), 4)
        mapped = FlowIdentity(bytes(10) + b"\xff\xff" + TCP_ANALYSIS.ipv4.source_address,
                              bytes(10) + b"\xff\xff" + TCP_ANALYSIS.ipv4.destination_address,
                              12345, 443, 6)
        self.assertNotEqual(mapped, identities[0])
        tracker = FlowTracker()
        for packet in packets:
            tracker.record(packet)
        self.assertEqual(tracker.flow_count(), 4)

    def test_mixed_family_and_scoped_construction_remain_rejected(self):
        with self.assertRaises(ValueError):
            FlowIdentity(SOURCE_ADDRESS, bytes(4), 1, 2, 6)
        with self.assertRaises(ValueError):
            flow_identity_from_addresses("192.0.2.1", "2001:db8::1", 1, 2, 17)
        with self.assertRaises(ValueError):
            flow_identity_from_addresses("fe80::1%eth0", "fe80::2", 1, 2, 6)

    def test_forward_reverse_share_identity_regardless_of_first_observation(self):
        for protocol in (6, 17):
            forward = packet_at(protocol)
            reverse = packet_at(protocol, reverse=True)
            identity = flow_identity_from_packet(reverse)
            self.assertEqual(identity, flow_identity_from_packet(forward))
            self.assertIs(flow_direction_from_packet(forward, identity), FlowDirection.FORWARD)
            self.assertIs(flow_direction_from_packet(reverse, identity), FlowDirection.REVERSE)
            for sequence in ((forward, reverse), (reverse, forward)):
                tracker = FlowTracker()
                tracker.record(sequence[0])
                snapshot = tracker.record(sequence[1])
                self.assertEqual(snapshot.packet_count, 2)
                self.assertEqual(snapshot.identity, identity)
                self.assertEqual(tracker.flow_count(), 1)
                self.assertIs(snapshot.first_analysis, sequence[0])
                self.assertIs(snapshot.last_analysis, sequence[1])

    def test_same_address_and_identical_endpoints_preserve_direction_rules(self):
        for protocol in (6, 17):
            packet = packet_at(protocol, destination=SOURCE_ADDRESS)
            identity = flow_identity_from_packet(packet)
            self.assertEqual((identity.source_port, identity.destination_port), (443, 12345))
            self.assertIs(flow_direction_from_packet(packet, identity), FlowDirection.REVERSE)
            reverse = packet_at(protocol, destination=SOURCE_ADDRESS, reverse=True)
            self.assertIs(flow_direction_from_packet(reverse, identity), FlowDirection.FORWARD)
            identical = packet_at(protocol, destination=SOURCE_ADDRESS, destination_port=12345)
            self.assertIs(flow_direction_from_packet(identical, flow_identity_from_packet(identical)), FlowDirection.FORWARD)

    def test_direction_rejects_wrong_protocol_family_and_endpoints(self):
        for protocol in (6, 17):
            packet = packet_at(protocol)
            identity = flow_identity_from_packet(packet)
            for other in (replace(identity, protocol=17 if protocol == 6 else 6),
                          replace(identity, destination_port=444),
                          FlowIdentity(bytes(4), bytes(4), 12345, 443, protocol)):
                with self.assertRaises(FlowDirectionError):
                    flow_direction_from_packet(packet, other)

    def test_extension_boundaries_use_semantics_without_parsing_again(self):
        for protocol in (6, 17):
            for extensions in ((), (0,), (43,), (60,), (0, 43, 60)):
                with self.subTest(protocol=protocol, extensions=extensions):
                    packet = packet_at(protocol, extensions=extensions)
                    name = "ipv6_tcp" if protocol == 6 else "ipv6_udp"
                    packet = replace(packet, **{name: replace(getattr(packet, name), source_port=43210)})
                    packet = replace(packet, observation=replace(packet.observation, raw_bytes=b"", captured_length=0))
                    with ExitStack() as stack:
                        for target in ("analysis.packet_analysis.analyze_packet",
                                       "analysis.packet_analysis.decode_tcp", "analysis.packet_analysis.decode_udp",
                                       "analysis.ipv6_fragmentation.analyze_ipv6_fragmentation",
                                       "analysis.ipv6_fragmentation.validate_ipv6_extension_headers",
                                       "analysis.ipv6_extension_headers.validate_ipv6_extension_headers",
                                       "analysis.flow_identity._packed_ip_address"):
                            stack.enter_context(patch(target, side_effect=AssertionError("flow parsed bytes")))
                        identity = flow_identity_from_packet(packet)
                        self.assertEqual(identity.source_port, 43210)
                        self.assertIs(identity.source_address, packet.ipv6.source_address)
                        self.assertIs(flow_direction_from_packet(packet, identity), FlowDirection.FORWARD)
                        self.assertEqual(FlowStateCoordinator().record(packet).identity, identity)

    def test_flow_label_does_not_change_identity(self):
        packet = packet_at()
        network = replace(packet.ipv6, flow_label=1048575)
        changed = replace(packet, ipv6=network,
                          ipv6_extension_headers=replace(packet.ipv6_extension_headers, packet=network))
        self.assertEqual(flow_identity_from_packet(packet), flow_identity_from_packet(changed))


class IPv6FlowLifecycleTests(unittest.TestCase):
    def test_same_direction_tracker_packets_reuse_one_flow(self):
        for protocol in (6, 17):
            tracker = FlowTracker()
            for count in range(1, 4):
                snapshot = tracker.record(packet_at(protocol, seconds=count))
                self.assertEqual(snapshot.packet_count, count)
            self.assertEqual(tracker.flow_count(), 1)
            self.assertIs(tracker.get(snapshot.identity), snapshot)

    def test_coordinator_admits_both_protocols_and_preserves_raw_directional_state(self):
        for protocol in (6, 17):
            coordinator = FlowStateCoordinator()
            self.assertIsNone(coordinator.state)
            first = coordinator.record(packet_at(protocol))
            coordinator.record(packet_at(protocol, seconds=1, reverse=True, flags=0x12))
            final = coordinator.record(packet_at(protocol, seconds=3, flags=0x10))
            self.assertIs(coordinator.state, final)
            self.assertIs(final.identity, first.identity)
            self.assertEqual(first.flow_statistics.packet_count, 1)
            self.assertEqual(final.flow_statistics.packet_count, 3)
            self.assertEqual(final.flow_statistics.captured_bytes, 3 * (74 if protocol == 6 else 62))
            direction = final.directional_flow_statistics
            self.assertEqual((direction.forward_packet_count, direction.reverse_packet_count), (2, 1))
            timing = final.directional_inter_arrival_statistics
            self.assertEqual(timing.forward_inter_arrival_count, 1)
            self.assertEqual(timing.forward_inter_arrival_sum_seconds, 3.0)
            self.assertEqual(timing.reverse_inter_arrival_count, 0)
            if protocol == 6:
                control = final.tcp_control_statistics
                self.assertEqual(control.packet_count, 3)
                self.assertEqual((control.forward_syn_count, control.forward_ack_count,
                                  control.reverse_syn_ack_count), (1, 1, 1))
            else:
                self.assertIsNone(final.tcp_control_statistics)

    def test_coordinators_keep_distinct_flows_independent(self):
        for protocol in (6, 17):
            first, second = FlowStateCoordinator(), FlowStateCoordinator()
            state = first.record(packet_at(protocol))
            other = second.record(packet_at(protocol, source_port=12346))
            self.assertNotEqual(state.identity, other.identity)
            with self.assertRaises(FlowCoordinationError):
                first.record(packet_at(protocol, source_port=12346))
            self.assertIs(first.state, state)
            self.assertIs(second.state, other)

    def test_windows_reuse_identity_and_preserve_utc_timestamps(self):
        for protocol in (6, 17):
            manager = FlowObservationWindowManager("ipv6-flow", timedelta(seconds=5))
            first_packet = packet_at(protocol)
            first = manager.record(first_packet).active_window
            second = manager.record(packet_at(protocol, seconds=1)).active_window
            last_packet = packet_at(protocol, seconds=2, reverse=True)
            update = manager.record(last_packet)
            self.assertEqual(update.active_window.key, first.key)
            self.assertEqual(second.key, first.key)
            self.assertEqual(update.closed_windows, ())
            self.assertEqual(update.active_window.coordinated_state.flow_statistics.packet_count, 3)
            self.assertIs(update.active_window.first_captured_at, first_packet.observation.captured_at)
            self.assertIs(update.active_window.last_captured_at, last_packet.observation.captured_at)
            self.assertEqual(len(manager.active_windows()), 1)

    def test_timeout_boundary_closes_and_starts_without_accumulating_gap(self):
        for protocol in (6, 17):
            manager = FlowObservationWindowManager("timeout", timedelta(seconds=5))
            manager.record(packet_at(protocol))
            manager.record(packet_at(protocol, seconds=1, reverse=True))
            update = manager.record(packet_at(protocol, seconds=6))
            self.assertEqual(update.active_window.key.sequence_number, 1)
            self.assertEqual(update.active_window.coordinated_state.flow_statistics.packet_count, 1)
            self.assertEqual(len(update.closed_windows), 1)
            closed = update.closed_windows[0]
            self.assertIs(closed.closure_reason, FlowObservationWindowClosureReason.INACTIVITY)
            self.assertEqual(closed.coordinated_state.flow_statistics.packet_count, 2)
            self.assertEqual(closed.coordinated_state.flow_inter_arrival_statistics.inter_arrival_sum_seconds, 1.0)
            self.assertEqual(update.active_window.coordinated_state.flow_inter_arrival_statistics.inter_arrival_count, 0)

    def test_distinct_families_protocols_and_endpoints_keep_separate_windows(self):
        manager = FlowObservationWindowManager("separate", timedelta(seconds=5))
        packets = (TCP_ANALYSIS, UDP_ANALYSIS, packet_at(6), packet_at(17), packet_at(6, source_port=12346))
        for index, packet in enumerate(packets):
            window = manager.record(packet).active_window
            self.assertEqual(window.key.sequence_number, index)
            self.assertEqual(window.coordinated_state.flow_statistics.packet_count, 1)
        self.assertEqual(len(manager.active_windows()), 5)
        closed = manager.end_capture_session()
        self.assertEqual(tuple(window.key.sequence_number for window in closed), (0, 1, 2, 3, 4))
        self.assertTrue(all(window.closure_reason is FlowObservationWindowClosureReason.CAPTURE_SESSION_END for window in closed))

    def test_timestamp_regression_preserves_state_and_next_sequence(self):
        manager = FlowObservationWindowManager("time", timedelta(seconds=5))
        manager.record(packet_at(seconds=2))
        before = manager.active_windows()
        with self.assertRaises(FlowObservationWindowError):
            manager.record(packet_at(seconds=1, reverse=True))
        self.assertEqual(manager.active_windows(), before)
        later = manager.record(packet_at(seconds=3, source_port=12346))
        self.assertEqual(later.active_window.key.sequence_number, 1)

    def test_repeated_sequences_produce_equal_flow_and_window_states(self):
        for protocol in (6, 17):
            observations = [observation_at(protocol, seconds=second, reverse=reverse)
                            for second, reverse in ((0, False), (0, False), (1, True), (3, False), (8, True))]
            results = []
            for _ in range(2):
                tracker = FlowTracker()
                manager = FlowObservationWindowManager("repeat", timedelta(seconds=5))
                updates = []
                for observation in observations:
                    packet = analyze_packet(observation)
                    tracker.record(packet)
                    updates.append(manager.record(packet))
                results.append((tracker.snapshots(), updates, manager.end_capture_session()))
            self.assertEqual(results[0], results[1])

    def test_application_session_uses_existing_lifecycle_without_features_or_detectors(self):
        for protocol in (6, 17):
            source = MemoryPacketSource([observation_at(protocol, seconds=seconds, reverse=reverse)
                                         for seconds, reverse in ((0, False), (1, True), (6, False))])
            closed = []
            with ExitStack() as stack:
                for name in vars(flow_feature_snapshot):
                    if name.startswith("extract_"):
                        stack.enter_context(patch.object(flow_feature_snapshot, name, side_effect=AssertionError("feature calculation")))
                for target in ("detection.flow_volume_threshold.evaluate_flow_volume_threshold",
                               "detection.tcp_control_threshold.evaluate_tcp_control_threshold",
                               "detection.packet_integrity.evaluate_packet_integrity",
                               "application.detector_orchestration.run_packet_detectors",
                               "application.detector_orchestration.run_closed_flow_detectors"):
                    stack.enter_context(patch(target, side_effect=AssertionError("detector invoked")))
                run_flow_observation_session(source, capture_session_id="session", inactivity_timeout=timedelta(seconds=5),
                                             closed_window_consumer=closed.append)
            self.assertTrue(source.stopped)
            self.assertEqual(tuple(window.key.sequence_number for window in closed), (0, 1))
            self.assertEqual(tuple(window.coordinated_state.flow_statistics.packet_count for window in closed), (2, 1))
            self.assertEqual(tuple(window.identity.ip_version for window in closed), (6, 6))


class IPv6FlowAdmissionBoundaryTests(unittest.TestCase):
    def assert_rejected(self, packet):
        identity = FlowIdentity(SOURCE_ADDRESS, DESTINATION_ADDRESS, 12345, 443, 6)
        tracker = FlowTracker()
        coordinator = FlowStateCoordinator()
        manager = FlowObservationWindowManager("rejected", timedelta(seconds=5))
        for action in (flow_identity_from_packet, tracker.record, coordinator.record, manager.record):
            with self.assertRaises(FlowIdentityError):
                action(packet)
        with self.assertRaises(FlowIdentityError):
            flow_direction_from_packet(packet, identity)
        self.assertEqual(tracker.flow_count(), 0)
        self.assertIsNone(coordinator.state)
        self.assertEqual(manager.active_windows(), ())

    def test_missing_transport_models_are_rejected(self):
        for protocol in (6, 17):
            self.assert_rejected(replace(packet_at(protocol), ipv6_tcp=None, ipv6_udp=None))

    def test_missing_ipv6_context_is_rejected(self):
        packet = replace(packet_at(), ipv6_tcp=None)
        self.assert_rejected(replace(packet, ipv6_extension_headers=None))
        self.assert_rejected(PacketAnalysis(packet.observation))

    def test_icmpv6_no_next_header_and_unsupported_protocols_are_rejected(self):
        for protocol in (58, 59, 50, 51, 132, 33, 47, 253, 255):
            with self.subTest(protocol=protocol):
                observation = observation_for(protocol, bytes.fromhex("80001234"), bytes((protocol, 0)) + bytes(6), 43)
                self.assert_rejected(analyze_packet(observation))

    def test_non_first_fragments_never_enter_state_or_correlate(self):
        for protocol in (6, 17):
            manager = FlowObservationWindowManager("fragments", timedelta(seconds=5))
            initial = manager.record(packet_at(protocol, fragment=(0, True))).active_window
            for offset, more in ((1, True), (1, False), (8191, False)):
                non_first = packet_at(protocol, fragment=(offset, more))
                self.assert_rejected(non_first)
                with self.assertRaises(FlowIdentityError):
                    manager.record(non_first)
                self.assertEqual(manager.active_windows(), (initial,))
            next_packet = manager.record(packet_at(protocol, seconds=1, fragment=(0, True))).active_window
            self.assertEqual(next_packet.coordinated_state.flow_statistics.packet_count, 2)

    def test_fragment_header_without_transport_is_rejected(self):
        for protocol in (6, 17):
            whole = packet_at(protocol, fragment=(0, False))
            self.assert_rejected(replace(whole, ipv6_tcp=None, ipv6_udp=None))
            non_first = analyze_packet(observation_for(protocol, b"", fragment_header(protocol, 1), 44))
            self.assert_rejected(non_first)

    def test_first_and_whole_fragments_with_decoded_transport_are_admitted(self):
        for protocol in (6, 17):
            for more in (False, True):
                packet = packet_at(protocol, extensions=(0, 43), fragment=(0, more))
                state = FlowStateCoordinator().record(packet)
                self.assertEqual(state.identity, flow_identity_from_packet(packet_at(protocol)))
                self.assertEqual(state.flow_statistics.packet_count, 1)

    def test_truncated_analysis_is_incomplete_without_fragment_reassembly(self):
        for protocol in (6, 17):
            first = observation_for(protocol, b"\x00\x01", fragment_header(protocol, 0, True), 44)
            before = analyze_packet_outcome(first)
            self.assertIsNone(before.analysis)
            self.assertIs(before.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)
            self.assert_rejected(packet_at(protocol, fragment=(1, False)))
            self.assertEqual(analyze_packet_outcome(first), before)

    def test_conflicting_family_transport_and_context_models_are_rejected_at_construction(self):
        tcp = packet_at(6)
        udp = packet_at(17)
        for changes in ({"ipv4": TCP_ANALYSIS.ipv4}, {"tcp": TCP_ANALYSIS.tcp},
                        {"udp": UDP_ANALYSIS.udp}, {"ipv6_udp": udp.ipv6_udp},
                        {"ipv6_tcp": None, "ipv6_udp": udp.ipv6_udp},
                        {"ipv6_extension_headers": None}, {"ipv6": None}):
            with self.assertRaises(PacketAnalysisError):
                replace(tcp, **changes)
        for value in (b"", object(), tcp.ipv6):
            with self.assertRaises(TypeError):
                replace(tcp, ipv6_tcp=value)
        with self.assertRaises(PacketAnalysisError):
            replace(TCP_ANALYSIS, ipv6_tcp=tcp.ipv6_tcp)
        with self.assertRaises(PacketAnalysisError):
            replace(packet_at(fragment=(1, False)), ipv6_tcp=tcp.ipv6_tcp)

    def test_rejected_packets_do_not_update_published_lifecycle_state(self):
        for protocol in (6, 17):
            packet = packet_at(protocol)
            invalid = replace(packet, ipv6_tcp=None, ipv6_udp=None)
            tracker, coordinator = FlowTracker(), FlowStateCoordinator()
            manager = FlowObservationWindowManager("atomic", timedelta(seconds=5))
            snapshot = tracker.record(packet)
            state = coordinator.record(packet)
            window = manager.record(packet).active_window
            for action in (tracker.record, coordinator.record, manager.record):
                with self.assertRaises(FlowIdentityError):
                    action(invalid)
            self.assertIs(tracker.get(snapshot.identity), snapshot)
            self.assertIs(coordinator.state, state)
            self.assertEqual(manager.active_windows(), (window,))

    def test_wrong_top_level_types_and_internal_errors_propagate(self):
        for value in (None, b"", object()):
            with self.assertRaises(TypeError):
                flow_identity_from_packet(value)
        error = RuntimeError("internal endpoint failure")
        with patch("analysis.flow_identity._flow_packet_endpoints", side_effect=error):
            with self.assertRaises(RuntimeError) as raised:
                FlowTracker().record(packet_at())
        self.assertIs(raised.exception, error)


if __name__ == "__main__":
    unittest.main()
