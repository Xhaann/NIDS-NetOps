import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from unittest.mock import PropertyMock, patch

from analysis import (
    FlowIdentityError,
    FlowObservationWindowClosureReason,
    FlowObservationWindowManager,
    PacketAnalysisOutcome,
    PacketAnalysisFailureClassification,
    analyze_packet,
    analyze_packet_outcome,
    extract_flow_feature_snapshot,
)
from application import run_closed_flow_detectors, run_flow_observation_session, run_packet_detectors
from application import detector_orchestration
from detection import (
    DetectionFinding,
    FlowVolumeMetric,
    FlowVolumeThresholdComparison,
    FlowVolumeThresholdDecision,
    FlowVolumeThresholdError,
    FlowVolumeThresholdInterpretation,
    PacketIntegrityConfiguration,
    PacketIntegrityDecision,
    PacketIntegrityInterpretation,
    TCPControlMetric,
    TCPControlThresholdComparison,
    TCPControlThresholdDecision,
    TCPControlThresholdError,
    TCPControlThresholdInterpretation,
    detection_finding_from_evaluation,
    evaluate_flow_volume_threshold,
    evaluate_packet_integrity,
    evaluate_tcp_control_threshold,
)
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_flow_observation_window import packet_at as ipv4_packet_at
from tests.test_flow_volume_threshold import configuration as volume_configuration
from tests.test_ipv6_features import FLAGS, SEQUENCE, feature_sequence
from tests.test_ipv6_flow import observation_at, packet_at
from tests.test_ipv6_transport import fragment_header, observation_for
from tests.test_tcp import TCP_HEADER
from tests.test_tcp_control_threshold import configuration as control_configuration


def closed_snapshot(*packets):
    manager = FlowObservationWindowManager("ipv6-detection", timedelta(seconds=10))
    for packet in packets:
        manager.record(packet)
    return extract_flow_feature_snapshot(manager.end_capture_session()[0])


def detect(snapshot, volume=None, control=None):
    return run_closed_flow_detectors(
        snapshot,
        flow_volume_configuration=volume if volume is not None else volume_configuration(FlowVolumeMetric.PACKET_COUNT),
        tcp_control_configuration=control if control is not None else control_configuration(),
    )


class IPv6FlowDetectionTests(unittest.TestCase):
    def assert_volume_metrics(self, protocol):
        packets = tuple(replace(packet, observation=replace(
            packet.observation, original_length=packet.observation.captured_length + 10,
        )) for packet in feature_sequence(protocol))
        snapshot = closed_snapshot(*packets)
        base = 74 if protocol == 6 else 62
        expected = (4, 4 * base + 48, 4 * base + 88, 2, 2,
                    2 * base + 16, 2 * base + 32, 2 * base + 36, 2 * base + 52,
                    4 / 6, (4 * base + 48) / 6, (4 * base + 88) / 6)
        self.assertEqual(len(tuple(FlowVolumeMetric)), len(expected))
        for metric, value in zip(FlowVolumeMetric, expected):
            step = 0.25 if type(value) is float else 1
            for threshold, decision, interpretation in (
                (value - step, FlowVolumeThresholdDecision.MATCH, FlowVolumeThresholdInterpretation.THRESHOLD_EXCEEDED),
                (value, FlowVolumeThresholdDecision.NO_MATCH, FlowVolumeThresholdInterpretation.THRESHOLD_NOT_EXCEEDED),
                (value + step, FlowVolumeThresholdDecision.NO_MATCH, FlowVolumeThresholdInterpretation.THRESHOLD_NOT_EXCEEDED),
            ):
                with self.subTest(protocol=protocol, metric=metric, threshold=threshold):
                    configuration = volume_configuration(metric, threshold)
                    result = evaluate_flow_volume_threshold(snapshot, configuration)
                    self.assertIs(result.decision, decision)
                    self.assertIs(result.security_interpretation, interpretation)
                    evidence = result.raw_evidence
                    self.assertEqual(evidence.observed_value, value)
                    self.assertIs(type(evidence.observed_value), type(value))
                    self.assertIs(evidence.configuration, configuration)
                    self.assertIs(evidence.snapshot, snapshot)
                    self.assertIs(evidence.comparison_operator, FlowVolumeThresholdComparison.GREATER_THAN)
                    self.assertEqual((evidence.detector_id, evidence.detector_version), ("flow-volume-threshold", "1.0.0"))
                    self.assertEqual(evidence.threshold, threshold)
                    self.assertIs(evidence.selected_metric, metric)

    def test_tcp_all_volume_metrics_below_at_and_above_threshold(self):
        self.assert_volume_metrics(6)

    def test_udp_all_volume_metrics_below_at_and_above_threshold(self):
        self.assert_volume_metrics(17)

    def test_tcp_all_control_metrics_below_at_and_above_threshold(self):
        snapshot = closed_snapshot(*(packet_at(6, seconds=t, reverse=r, flags=0x1ff) for t, r in SEQUENCE))
        window = snapshot.observation_window
        for metric in TCPControlMetric:
            for threshold, decision, interpretation in (
                (1, TCPControlThresholdDecision.MATCH, TCPControlThresholdInterpretation.THRESHOLD_EXCEEDED),
                (2, TCPControlThresholdDecision.NO_MATCH, TCPControlThresholdInterpretation.THRESHOLD_NOT_EXCEEDED),
                (3, TCPControlThresholdDecision.NO_MATCH, TCPControlThresholdInterpretation.THRESHOLD_NOT_EXCEEDED),
            ):
                with self.subTest(metric=metric, threshold=threshold):
                    configuration = control_configuration(metric, threshold)
                    result = evaluate_tcp_control_threshold(window, configuration)
                    self.assertIs(result.decision, decision)
                    self.assertIs(result.security_interpretation, interpretation)
                    evidence = result.raw_evidence
                    self.assertEqual(evidence.observed_value, 2)
                    self.assertIs(evidence.configuration, configuration)
                    self.assertIs(evidence.tcp_control_statistics, window.coordinated_state.tcp_control_statistics)
                    self.assertIs(evidence.comparison_operator, TCPControlThresholdComparison.GREATER_THAN)
                    self.assertEqual((evidence.detector_id, evidence.detector_version), ("tcp-control-threshold", "1.0.0"))

    def test_tcp_control_directions_and_syn_ack_joint_count_remain_distinct(self):
        window = closed_snapshot(
            packet_at(flags=2), packet_at(seconds=1, flags=0x10),
            packet_at(seconds=2, reverse=True, flags=0x12),
        ).observation_window
        for metric, count in ((TCPControlMetric.FORWARD_SYN, 1), (TCPControlMetric.FORWARD_ACK, 1),
                              (TCPControlMetric.FORWARD_SYN_ACK, 0), (TCPControlMetric.REVERSE_SYN_ACK, 1),
                              (TCPControlMetric.REVERSE_RST, 0)):
            result = evaluate_tcp_control_threshold(window, control_configuration(metric))
            self.assertEqual(result.raw_evidence.observed_value, count)
            self.assertIs(result.decision, TCPControlThresholdDecision.MATCH if count else TCPControlThresholdDecision.NO_MATCH)

    def test_udp_rejects_direct_tcp_control_and_orchestration_never_calls_it(self):
        snapshot = closed_snapshot(packet_at(17))
        with self.assertRaises(TCPControlThresholdError):
            evaluate_tcp_control_threshold(snapshot.observation_window, control_configuration())
        for configuration in (None, control_configuration()):
            with patch.object(detector_orchestration, "evaluate_tcp_control_threshold", side_effect=AssertionError("UDP control")):
                findings = run_closed_flow_detectors(snapshot, flow_volume_configuration=volume_configuration(FlowVolumeMetric.PACKET_COUNT),
                                                     tcp_control_configuration=configuration)
            self.assertEqual(len(findings), 1)
            self.assertIs(findings[0].decision, FlowVolumeThresholdDecision.MATCH)
        self.assertIsNone(snapshot.coordinated_state.tcp_control_statistics)

    def test_zero_duration_rate_is_not_evaluable_without_suppressing_tcp(self):
        for protocol in (6, 17):
            snapshot = closed_snapshot(packet_at(protocol))
            for metric in (FlowVolumeMetric.PACKETS_PER_SECOND, FlowVolumeMetric.CAPTURED_BYTES_PER_SECOND,
                           FlowVolumeMetric.ORIGINAL_BYTES_PER_SECOND):
                findings = detect(snapshot, volume_configuration(metric))
                self.assertIs(findings[0].decision, FlowVolumeThresholdDecision.NOT_EVALUABLE)
                self.assertIsNone(findings[0].raw_evidence.observed_value)
                self.assertIs(findings[0].security_interpretation, FlowVolumeThresholdInterpretation.METRIC_NOT_EVALUABLE)
                self.assertEqual(len(findings), 2 if protocol == 6 else 1)
                if protocol == 6:
                    self.assertIs(findings[1].decision, TCPControlThresholdDecision.MATCH)

    def assert_family_equivalence(self, protocol):
        ipv6 = tuple(packet_at(protocol, seconds=t, reverse=r, flags=mask)
                     for (t, r), mask in zip(SEQUENCE, (0x1ff, 0x12, 0x10, 0)))
        ipv4 = []
        for v6, (t, r) in zip(ipv6, SEQUENCE):
            flags = {} if protocol == 17 else {name: getattr(v6.ipv6_tcp, name) for name in FLAGS}
            v4 = ipv4_packet_at(t, reverse=r, protocol=protocol, **flags)
            ipv4.append(replace(v4, observation=replace(
                v4.observation, captured_at=v6.observation.captured_at,
                captured_length=v6.observation.captured_length, original_length=v6.observation.original_length,
                raw_bytes=bytes(v6.observation.captured_length),
            )))
        left, right = closed_snapshot(*ipv4), closed_snapshot(*ipv6)
        pairs = [(evaluate_flow_volume_threshold(left, configuration), evaluate_flow_volume_threshold(right, configuration))
                 for configuration in (volume_configuration(metric) for metric in FlowVolumeMetric)]
        if protocol == 6:
            pairs += [(evaluate_tcp_control_threshold(left.observation_window, configuration),
                       evaluate_tcp_control_threshold(right.observation_window, configuration))
                      for configuration in (control_configuration(metric) for metric in TCPControlMetric)]
        for v4, v6 in pairs:
            self.assertIs(v4.decision, v6.decision)
            self.assertIs(v4.security_interpretation, v6.security_interpretation)
            self.assertEqual(type(v4.raw_evidence), type(v6.raw_evidence))
            self.assertIs(v4.raw_evidence.configuration, v6.raw_evidence.configuration)
            for name in ("observed_value", "comparison_operator", "detector_id", "detector_version", "protocol",
                         "threshold", "selected_metric", "total_packet_count", "forward_packet_count",
                         "reverse_packet_count", "first_captured_at", "last_captured_at", "capture_session_id",
                         "sequence_number", "closure_reason"):
                self.assertEqual(getattr(v4.raw_evidence, name), getattr(v6.raw_evidence, name))
            self.assertEqual(v6.raw_evidence.identity.ip_version, 6)
            self.assertEqual(v4.raw_evidence.identity.ip_version, 4)

    def test_tcp_ipv4_ipv6_equivalent_decisions_evidence_and_interpretations(self):
        self.assert_family_equivalence(6)

    def test_udp_ipv4_ipv6_equivalent_decisions_evidence_and_interpretations(self):
        self.assert_family_equivalence(17)

    def test_independent_flows_and_same_direction_counts(self):
        manager = FlowObservationWindowManager("independent", timedelta(seconds=10))
        for protocol in (6, 17):
            for port in (12345, 12346):
                manager.record(packet_at(protocol, source_port=port))
        manager.record(packet_at(6, seconds=1))
        snapshots = tuple(extract_flow_feature_snapshot(window) for window in manager.end_capture_session())
        results = tuple(detect(snapshot, volume_configuration(FlowVolumeMetric.PACKET_COUNT, 1))[0] for snapshot in snapshots)
        self.assertEqual(tuple(result.raw_evidence.observed_value for result in results), (2, 1, 1, 1))
        self.assertEqual(tuple(result.decision for result in results), (FlowVolumeThresholdDecision.MATCH,) + (FlowVolumeThresholdDecision.NO_MATCH,) * 3)
        self.assertEqual(len({result.raw_evidence.identity for result in results}), 4)

    def test_exact_evidence_and_finding_schemas_and_provenance(self):
        snapshot = closed_snapshot(packet_at(), packet_at(seconds=1, reverse=True))
        findings = detect(snapshot)
        self.assertEqual(tuple(field.name for field in fields(DetectionFinding)),
                         ("detector_id", "detector_version", "decision", "raw_evidence", "security_interpretation"))
        for finding, first_field in zip(findings, ("snapshot", "observation_window")):
            evidence = finding.raw_evidence
            self.assertEqual(tuple(field.name for field in fields(evidence)),
                             (first_field, "configuration", "observed_value", "comparison_operator"))
            self.assertIs(evidence.observation_window, snapshot.observation_window)
            self.assertIs(evidence.identity, snapshot.identity)
            self.assertIs(evidence.first_captured_at, snapshot.observation_window.first_captured_at)
            self.assertIs(evidence.last_captured_at, snapshot.observation_window.last_captured_at)
            self.assertEqual((evidence.capture_session_id, evidence.sequence_number), ("ipv6-detection", 0))
            self.assertIs(evidence.closure_reason, FlowObservationWindowClosureReason.CAPTURE_SESSION_END)
            self.assertEqual((evidence.total_packet_count, evidence.forward_packet_count, evidence.reverse_packet_count), (2, 1, 1))
            self.assertEqual(finding.detector_id, evidence.configuration.detector_id)
            self.assertEqual(finding.detector_version, evidence.configuration.detector_version)
        self.assertEqual(findings[0].raw_evidence.captured_byte_total, 148)
        self.assertEqual(findings[0].raw_evidence.original_byte_total, 148)

    def test_extension_headers_use_semantic_detection_without_reanalysis_or_state_creation(self):
        for protocol in (6, 17):
            for extensions in ((), (0,), (43,), (60,), (0, 43, 60)):
                snapshot = closed_snapshot(packet_at(protocol, extensions=extensions))
                with ExitStack() as stack:
                    for target in (
                        "analysis.packet_analysis.analyze_packet", "analysis.packet_analysis.decode_ipv6",
                        "analysis.packet_analysis.decode_tcp", "analysis.packet_analysis.decode_udp",
                        "analysis.packet_analysis.validate_ipv6_extension_headers", "analysis.packet_analysis.analyze_ipv6_fragmentation",
                        "analysis.ipv6_extension_headers.validate_ipv6_extension_headers", "analysis.ipv6_fragmentation.validate_ipv6_extension_headers",
                        "analysis.flow_feature_snapshot.extract_flow_feature_snapshot", "analysis.flow_tracker.FlowTracker.record",
                        "analysis.flow_state_coordinator.FlowStateCoordinator.record", "analysis.flow_observation_window.FlowObservationWindowManager.__init__",
                        "detection.packet_integrity.evaluate_packet_integrity",
                    ):
                        stack.enter_context(patch(target, side_effect=AssertionError(target)))
                    for target in (
                        "capture.packet_observation.PacketObservation.raw_bytes", "analysis.ipv6.IPv6Packet.payload",
                        "analysis.ethernet.EthernetFrame.payload", "analysis.packet_analysis.PacketAnalysis.ipv6",
                        "analysis.packet_analysis.PacketAnalysis.ipv6_extension_headers", "analysis.packet_analysis.PacketAnalysis.ipv6_fragmentation",
                        "analysis.packet_analysis.PacketAnalysis.ipv6_tcp", "analysis.packet_analysis.PacketAnalysis.ipv6_udp",
                    ):
                        stack.enter_context(patch(target, new_callable=PropertyMock, create=True, side_effect=AssertionError(target)))
                    findings = detect(snapshot)
                self.assertEqual(findings[0].raw_evidence.observed_value, 1)
                self.assertEqual(findings[0].raw_evidence.captured_byte_total, (74 if protocol == 6 else 62) + 8 * len(extensions))

    def test_first_and_whole_fragments_follow_existing_applicability(self):
        for protocol in (6, 17):
            for more in (False, True):
                snapshot = closed_snapshot(packet_at(protocol, fragment=(0, more)))
                findings = detect(snapshot)
                self.assertEqual(findings[0].raw_evidence.captured_byte_total, 82 if protocol == 6 else 70)
                self.assertIs(findings[0].decision, FlowVolumeThresholdDecision.MATCH)
                self.assertEqual(len(findings), 2 if protocol == 6 else 1)
                if protocol == 6:
                    self.assertEqual(findings[1].raw_evidence.observed_value, 1)

    def test_non_first_fragments_do_not_enter_detection_or_correlate(self):
        for protocol in (6, 17):
            manager = FlowObservationWindowManager("fragments", timedelta(seconds=10))
            non_first = packet_at(protocol, fragment=(1, False))
            with self.assertRaises(FlowIdentityError):
                manager.record(non_first)
            self.assertEqual(manager.active_windows(), ())
            initial = manager.record(packet_at(protocol, fragment=(0, True))).active_window
            for packet in (non_first, packet_at(protocol, fragment=(1, True))):
                with self.assertRaises(FlowIdentityError):
                    manager.record(packet)
                self.assertEqual(manager.active_windows(), (initial,))
            snapshot = extract_flow_feature_snapshot(manager.end_capture_session()[0])
            self.assertEqual(detect(snapshot)[0].raw_evidence.observed_value, 1)

    def test_missing_transport_icmpv6_and_unsupported_protocols_cannot_supply_flow_detection(self):
        packets = [replace(packet_at(protocol), ipv6_tcp=None, ipv6_udp=None) for protocol in (6, 17)]
        packets += [analyze_packet(observation_for(protocol, bytes.fromhex("80001234")))
                    for protocol in (58, 59, 50, 51, 132, 33, 47, 253)]
        manager = FlowObservationWindowManager("unsupported", timedelta(seconds=10))
        for packet in packets:
            with self.assertRaises(FlowIdentityError):
                manager.record(packet)
            self.assertEqual(manager.active_windows(), ())
        self.assertEqual(manager.end_capture_session(), ())

    def test_missing_tcp_control_and_volume_features_propagate_errors(self):
        snapshot = closed_snapshot(packet_at())
        state = replace(snapshot.coordinated_state)
        object.__setattr__(state, "tcp_control_statistics", None)
        window = replace(snapshot.observation_window, coordinated_state=state)
        with self.assertRaises(TCPControlThresholdError):
            evaluate_tcp_control_threshold(window, control_configuration())
        invalid = object.__new__(type(snapshot))
        for field in fields(snapshot):
            object.__setattr__(invalid, field.name, getattr(snapshot, field.name))
        object.__setattr__(invalid, "flow_volume_features", None)
        with self.assertRaises(AttributeError):
            detect(invalid)

    def test_active_windows_are_rejected_without_lifecycle_changes(self):
        for protocol in (6, 17):
            manager = FlowObservationWindowManager("active", timedelta(seconds=10))
            window = manager.record(packet_at(protocol)).active_window
            snapshot = extract_flow_feature_snapshot(window)
            with patch.object(detector_orchestration, "evaluate_tcp_control_threshold") as control:
                with self.assertRaises(FlowVolumeThresholdError):
                    detect(snapshot)
            control.assert_not_called()
            with self.assertRaises(TCPControlThresholdError):
                evaluate_tcp_control_threshold(window, control_configuration())
            self.assertEqual(manager.active_windows(), (window,))

    def test_inactivity_and_explicit_closures_preserve_detection_boundaries(self):
        for protocol in (6, 17):
            manager = FlowObservationWindowManager("closures", timedelta(seconds=5))
            manager.record(packet_at(protocol))
            manager.record(packet_at(protocol, seconds=1, reverse=True))
            update = manager.record(packet_at(protocol, seconds=6))
            old = detect(extract_flow_feature_snapshot(update.closed_windows[0]))[0]
            self.assertEqual(old.raw_evidence.observed_value, 2)
            self.assertIs(old.raw_evidence.closure_reason, FlowObservationWindowClosureReason.INACTIVITY)
            explicit = manager.close(update.active_window.identity)
            new = detect(extract_flow_feature_snapshot(explicit))[0]
            self.assertEqual(new.raw_evidence.observed_value, 1)
            self.assertIs(new.raw_evidence.closure_reason, FlowObservationWindowClosureReason.EXPLICIT_SEGMENTATION)
            self.assertEqual(new.raw_evidence.sequence_number, 1)

    def test_orchestration_preserves_exact_order_configurations_and_evaluations(self):
        snapshot = closed_snapshot(packet_at())
        volume, control = volume_configuration(FlowVolumeMetric.PACKET_COUNT), control_configuration()
        calls, evaluations = [], []

        def evaluate_volume(actual, configuration):
            self.assertIs(actual, snapshot)
            self.assertIs(configuration, volume)
            calls.append("volume")
            result = evaluate_flow_volume_threshold(actual, configuration)
            evaluations.append(result)
            return result

        def evaluate_control(actual, configuration):
            self.assertIs(actual, snapshot.observation_window)
            self.assertIs(configuration, control)
            calls.append("control")
            result = evaluate_tcp_control_threshold(actual, configuration)
            evaluations.append(result)
            return result

        def normalize(evaluation):
            calls.append("finding")
            self.assertIs(evaluation, evaluations[-1])
            return detection_finding_from_evaluation(evaluation)

        with patch.object(detector_orchestration, "evaluate_flow_volume_threshold", side_effect=evaluate_volume), \
             patch.object(detector_orchestration, "evaluate_tcp_control_threshold", side_effect=evaluate_control), \
             patch.object(detector_orchestration, "detection_finding_from_evaluation", side_effect=normalize):
            findings = detect(snapshot, volume, control)
        self.assertEqual(calls, ["volume", "finding", "control", "finding"])
        for finding, evaluation in zip(findings, evaluations):
            self.assertIs(finding.raw_evidence, evaluation.raw_evidence)
            self.assertIs(finding.decision, evaluation.decision)
            self.assertIs(finding.security_interpretation, evaluation.security_interpretation)

    def test_orchestration_fail_fast_propagates_each_error_without_retry(self):
        snapshot = closed_snapshot(packet_at())
        for failure_at in range(4):
            error = RuntimeError("detector sentinel")
            calls = []

            def step(name, function, *args):
                calls.append(name)
                if len(calls) - 1 == failure_at:
                    raise error
                return function(*args)

            with patch.object(detector_orchestration, "evaluate_flow_volume_threshold", side_effect=lambda *args: step("volume", evaluate_flow_volume_threshold, *args)), \
                 patch.object(detector_orchestration, "evaluate_tcp_control_threshold", side_effect=lambda *args: step("control", evaluate_tcp_control_threshold, *args)), \
                 patch.object(detector_orchestration, "detection_finding_from_evaluation", side_effect=lambda *args: step("finding", detection_finding_from_evaluation, *args)):
                with self.assertRaises(RuntimeError) as raised:
                    detect(snapshot)
            self.assertIs(raised.exception, error)
            self.assertEqual(calls, ["volume", "finding", "control", "finding"][:failure_at + 1])

    def test_tcp_configuration_remains_required(self):
        snapshot = closed_snapshot(packet_at())
        with self.assertRaisesRegex(TypeError, "TCP windows require"):
            run_closed_flow_detectors(snapshot, flow_volume_configuration=volume_configuration(FlowVolumeMetric.PACKET_COUNT))

    def test_deterministic_immutable_evaluations_findings_and_inputs(self):
        for protocol in (6, 17):
            snapshot = closed_snapshot(*feature_sequence(protocol))
            findings = detect(snapshot)
            self.assertEqual(findings, detect(snapshot))
            self.assertEqual(findings, detect(closed_snapshot(*feature_sequence(protocol))))
            evaluations = [evaluate_flow_volume_threshold(snapshot, volume_configuration(FlowVolumeMetric.PACKET_COUNT))]
            if protocol == 6:
                evaluations.append(evaluate_tcp_control_threshold(snapshot.observation_window, control_configuration()))
            for evaluation in evaluations:
                self.assertEqual(detection_finding_from_evaluation(evaluation), detection_finding_from_evaluation(evaluation))
            models = (snapshot, snapshot.observation_window, snapshot.coordinated_state) + findings + tuple(evaluations)
            models += tuple(finding.raw_evidence for finding in findings)
            models += tuple(finding.raw_evidence.configuration for finding in findings)
            for model in models:
                for field in fields(model):
                    with self.assertRaises(FrozenInstanceError):
                        setattr(model, field.name, None)

    def test_application_sessions_do_not_automatically_execute_detectors(self):
        for protocol in (6, 17):
            windows = []
            source = MemoryPacketSource((observation_at(protocol), observation_at(protocol, seconds=1)))
            with ExitStack() as stack:
                for target in ("application.detector_orchestration.run_packet_detectors",
                               "application.detector_orchestration.run_closed_flow_detectors",
                               "application.detector_orchestration.evaluate_flow_volume_threshold",
                               "application.detector_orchestration.evaluate_tcp_control_threshold",
                               "application.detector_orchestration.evaluate_packet_integrity"):
                    stack.enter_context(patch(target, side_effect=AssertionError("automatic detection")))
                run_flow_observation_session(source, capture_session_id="explicit", inactivity_timeout=timedelta(seconds=10),
                                             closed_window_consumer=windows.append)
            self.assertTrue(source.stopped)
            self.assertEqual(len(windows), 1)
            self.assertEqual(detect(extract_flow_feature_snapshot(windows[0]))[0].raw_evidence.observed_value, 2)


class IPv6PacketDetectionTests(unittest.TestCase):
    def setUp(self):
        self.configuration = PacketIntegrityConfiguration("packet-integrity", "1.0.0")

    def test_valid_tcp_udp_terminal_protocol_evidence_uses_validated_extensions(self):
        for protocol in (6, 17):
            for extensions in ((), (0,), (43,), (60,), (0, 43, 60)):
                outcome = analyze_packet_outcome(observation_at(protocol, extensions=extensions))
                result = evaluate_packet_integrity(outcome, self.configuration)
                self.assertEqual(result.raw_evidence.protocol, protocol)
                self.assertIs(result.decision, PacketIntegrityDecision.NO_MATCH)
                self.assertIs(result.security_interpretation, PacketIntegrityInterpretation.NO_INTEGRITY_OR_STRUCTURAL_VIOLATION)
                self.assertIs(result.raw_evidence.outcome, outcome)
                self.assertIs(result.raw_evidence.analysis, outcome.analysis)
                self.assertIs(result.raw_evidence.configuration, self.configuration)

    def test_icmpv6_no_next_header_and_unknown_protocols_are_not_violations(self):
        for protocol in (58, 59, 50, 51, 132, 33, 47, 253):
            outcome = analyze_packet_outcome(observation_for(protocol, bytes.fromhex("80001234")))
            finding, = run_packet_detectors(outcome, self.configuration)
            self.assertIs(finding.decision, PacketIntegrityDecision.NO_MATCH)
            self.assertEqual(finding.raw_evidence.protocol, protocol)
            self.assertEqual(tuple(field.name for field in fields(finding.raw_evidence)), ("outcome", "configuration"))
            self.assertIs(finding.raw_evidence.observation, outcome.observation)

    def test_fragment_metadata_is_not_a_packet_integrity_violation(self):
        for protocol in (6, 17):
            for fragment in ((0, False), (0, True), (1, False), (1, True)):
                outcome = analyze_packet_outcome(observation_at(protocol, fragment=fragment))
                finding, = run_packet_detectors(outcome, self.configuration)
                self.assertIs(finding.decision, PacketIntegrityDecision.NO_MATCH)
                self.assertEqual(finding.raw_evidence.protocol, protocol)

    def test_missing_terminal_context_does_not_infer_base_protocol(self):
        packet = packet_at()
        packet = replace(packet, ipv6_tcp=None, ipv6_extension_headers=None)
        outcome = PacketAnalysisOutcome(packet.observation, packet, None, None)
        evidence = evaluate_packet_integrity(outcome, self.configuration).raw_evidence
        self.assertIsNone(evidence.protocol)
        self.assertIs(evidence.decision, PacketIntegrityDecision.NO_MATCH)

    def test_structural_and_incomplete_failures_retain_existing_decisions(self):
        invalid_tcp = TCP_HEADER[:12] + bytes(2) + TCP_HEADER[14:]
        version = observation_for(59, b"")
        version = replace(version, raw_bytes=version.raw_bytes[:14] + b"\x50" + version.raw_bytes[15:])
        cases = (
            (version, PacketAnalysisFailureClassification.STRUCTURAL_FAILURE, PacketIntegrityDecision.MATCH),
            (observation_for(6, invalid_tcp), PacketAnalysisFailureClassification.STRUCTURAL_FAILURE, PacketIntegrityDecision.MATCH),
            (observation_for(17, bytes.fromhex("0001000200070000")), PacketAnalysisFailureClassification.STRUCTURAL_FAILURE, PacketIntegrityDecision.MATCH),
            (observation_for(6, b"\x00"), PacketAnalysisFailureClassification.INCOMPLETE, PacketIntegrityDecision.NOT_EVALUABLE),
            (observation_for(17, b"\x00"), PacketAnalysisFailureClassification.INCOMPLETE, PacketIntegrityDecision.NOT_EVALUABLE),
            (observation_for(6, b"\x06", base=0), PacketAnalysisFailureClassification.INCOMPLETE, PacketIntegrityDecision.NOT_EVALUABLE),
            (observation_for(58, b"\x80"), PacketAnalysisFailureClassification.INCOMPLETE, PacketIntegrityDecision.NOT_EVALUABLE),
            (observation_for(6, b"", declared=1), PacketAnalysisFailureClassification.INCOMPLETE, PacketIntegrityDecision.NOT_EVALUABLE),
            (observation_for(6, b"\x00", fragment_header(6, 0, True), 44), PacketAnalysisFailureClassification.INCOMPLETE, PacketIntegrityDecision.NOT_EVALUABLE),
            (replace(observation_at(), link_type=None), PacketAnalysisFailureClassification.UNSUPPORTED, PacketIntegrityDecision.NOT_EVALUABLE),
        )
        for observation, classification, decision in cases:
            outcome = analyze_packet_outcome(observation)
            self.assertIsNone(outcome.analysis)
            self.assertIs(outcome.failure_classification, classification)
            finding, = run_packet_detectors(outcome, self.configuration)
            self.assertIs(finding.decision, decision)
            self.assertIsNone(finding.raw_evidence.protocol)
            self.assertIs(finding.raw_evidence.failure_description, outcome.failure_description)
            self.assertIs(finding.security_interpretation,
                          PacketIntegrityInterpretation.STRUCTURAL_OR_INTEGRITY_VIOLATION_OBSERVED if decision is PacketIntegrityDecision.MATCH
                          else PacketIntegrityInterpretation.ANALYSIS_NOT_EVALUABLE)
            with self.assertRaises(TypeError):
                FlowObservationWindowManager("failed", timedelta(seconds=10)).record(outcome.analysis)

    def test_packet_detection_consumes_outcomes_without_raw_bytes_or_revalidation(self):
        outcome = analyze_packet_outcome(observation_at(6, extensions=(0, 43, 60)))
        with ExitStack() as stack:
            for target in ("analysis.packet_analysis.analyze_packet", "analysis.packet_analysis_outcome.analyze_packet",
                           "analysis.packet_analysis.decode_ipv6", "analysis.packet_analysis.decode_tcp", "analysis.packet_analysis.decode_udp",
                           "analysis.packet_analysis.validate_ipv6_extension_headers", "analysis.packet_analysis.analyze_ipv6_fragmentation",
                           "analysis.ipv6_extension_headers.validate_ipv6_extension_headers", "analysis.ipv6_fragmentation.validate_ipv6_extension_headers",
                           "application.detector_orchestration.evaluate_flow_volume_threshold", "application.detector_orchestration.evaluate_tcp_control_threshold"):
                stack.enter_context(patch(target, side_effect=AssertionError(target)))
            for target in ("capture.packet_observation.PacketObservation.raw_bytes", "analysis.ipv6.IPv6Packet.payload",
                           "analysis.ethernet.EthernetFrame.payload", "analysis.ipv6_extension_headers.IPv6ExtensionHeader.raw_bytes"):
                stack.enter_context(patch(target, new_callable=PropertyMock, create=True, side_effect=AssertionError(target)))
            first, = run_packet_detectors(outcome, self.configuration)
            second, = run_packet_detectors(outcome, self.configuration)
            self.assertEqual(first, second)
            self.assertEqual(first.raw_evidence.protocol, 6)
            self.assertIs(first.raw_evidence.outcome, outcome)
            self.assertEqual((first.detector_id, first.detector_version), ("packet-integrity", "1.0.0"))


if __name__ == "__main__":
    unittest.main()
