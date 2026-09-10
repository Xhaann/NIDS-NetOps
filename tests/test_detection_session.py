import inspect
import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from unittest.mock import PropertyMock, patch

import application
from analysis import (
    FlowIdentityError,
    FlowObservationWindowManager,
    analyze_packet_outcome,
    extract_flow_feature_snapshot,
)
from application import DetectionSession, run_closed_flow_detectors, run_flow_observation_session, run_packet_detectors
from application import detection_session, detector_orchestration
from detection import (
    DetectionFinding,
    FlowVolumeMetric,
    FlowVolumeThresholdDecision,
    FlowVolumeThresholdError,
    PacketIntegrityConfiguration,
    PacketIntegrityDecision,
    TCPControlThresholdDecision,
    TCPControlThresholdError,
)
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_flow_observation_window import packet_at as ipv4_packet_at
from tests.test_flow_volume_threshold import configuration as volume_configuration
from tests.test_ipv6_detection import closed_snapshot
from tests.test_ipv6_flow import observation_at, packet_at
from tests.test_packet_integrity import TCP_BYTES, incomplete_outcome, make_observation, structural_outcome, unsupported_outcome
from tests.test_tcp_control_threshold import configuration as control_configuration


class DetectionSessionTests(unittest.TestCase):
    def setUp(self):
        self.packet_configuration = PacketIntegrityConfiguration("packet-integrity", "1")
        self.volume_configuration = volume_configuration(FlowVolumeMetric.PACKET_COUNT)
        self.control_configuration = control_configuration()
        self.session = DetectionSession(self.packet_configuration, self.volume_configuration, self.control_configuration)
        self.ipv4 = analyze_packet_outcome(make_observation(6, TCP_BYTES))
        self.ipv6 = analyze_packet_outcome(observation_at(6, extensions=(0, 43, 60)))
        self.snapshots = tuple(closed_snapshot(packet) for packet in (
            ipv4_packet_at(0, protocol=6, syn=True), ipv4_packet_at(0, protocol=17),
            packet_at(6, extensions=(0, 43, 60)), packet_at(17, extensions=(0, 60)),
        ))

    def test_public_export_signature_and_exact_configuration_references(self):
        self.assertIs(application.DetectionSession, detection_session.DetectionSession)
        self.assertIn("DetectionSession", application.__all__)
        self.assertEqual(tuple(field.name for field in fields(DetectionSession)),
                         ("packet_configuration", "flow_volume_configuration", "tcp_control_configuration"))
        self.assertEqual(tuple(inspect.signature(DetectionSession).parameters),
                         ("packet_configuration", "flow_volume_configuration", "tcp_control_configuration"))
        self.assertIs(self.session.packet_configuration, self.packet_configuration)
        self.assertIs(self.session.flow_volume_configuration, self.volume_configuration)
        self.assertIs(self.session.tcp_control_configuration, self.control_configuration)
        self.assertIs(detection_session.run_packet_detectors, detector_orchestration.run_packet_detectors)
        self.assertIs(detection_session.run_closed_flow_detectors, detector_orchestration.run_closed_flow_detectors)

    def test_construction_and_empty_inputs_execute_nothing(self):
        with patch.object(detection_session, "run_packet_detectors") as packets, \
             patch.object(detection_session, "run_closed_flow_detectors") as flows:
            session = DetectionSession(self.packet_configuration, self.volume_configuration)
            self.assertIsNone(session.tcp_control_configuration)
            for empty in ((), [], iter(())):
                self.assertEqual(session.run_packets(empty), ())
                self.assertEqual(session.run_closed_flows(empty), ())
        packets.assert_not_called()
        flows.assert_not_called()

    def test_constructor_rejects_wrong_configuration_types_without_execution(self):
        originals = (self.packet_configuration, self.volume_configuration, self.control_configuration)
        for index, original in enumerate(originals):
            derived = type("DerivedConfiguration", (type(original),), {})
            subclass = derived(*(getattr(original, field.name) for field in fields(original)))
            for invalid in (object(), False, "configuration", subclass):
                values = list(originals)
                values[index] = invalid
                with self.assertRaises(TypeError):
                    DetectionSession(*values)
        for index in (0, 1):
            values = list(originals)
            values[index] = None
            with self.assertRaises(TypeError):
                DetectionSession(*values)

    def test_ipv4_and_ipv6_packet_delegation_retains_exact_findings_and_configuration(self):
        for outcome in (self.ipv4, self.ipv6):
            expected = run_packet_detectors(outcome, self.packet_configuration)
            with patch.object(detection_session, "run_packet_detectors", return_value=expected) as delegate:
                result = self.session.run_packets((outcome,))
            delegate.assert_called_once_with(outcome, self.packet_configuration)
            self.assertIs(type(result), tuple)
            self.assertEqual(len(result), 1)
            self.assertIs(result[0], expected[0])
            self.assertIs(result[0].raw_evidence.configuration, self.packet_configuration)
            self.assertIs(result[0].raw_evidence.outcome, outcome)
            self.assertIs(result[0].decision, PacketIntegrityDecision.NO_MATCH)

    def test_packet_input_order_decisions_and_duplicates_are_preserved(self):
        outcomes = (self.ipv6, structural_outcome(), self.ipv4, incomplete_outcome(), unsupported_outcome(), self.ipv6)
        calls = []

        def execute(outcome, configuration):
            calls.append(outcome)
            return run_packet_detectors(outcome, configuration)

        with patch.object(detection_session, "run_packet_detectors", side_effect=execute):
            findings = self.session.run_packets(outcome for outcome in outcomes)
        self.assertEqual(tuple(calls), outcomes)
        self.assertEqual(tuple(finding.decision for finding in findings), (
            PacketIntegrityDecision.NO_MATCH, PacketIntegrityDecision.MATCH, PacketIntegrityDecision.NO_MATCH,
            PacketIntegrityDecision.NOT_EVALUABLE, PacketIntegrityDecision.NOT_EVALUABLE, PacketIntegrityDecision.NO_MATCH,
        ))
        for finding, outcome in zip(findings, outcomes):
            self.assertIs(finding.raw_evidence.outcome, outcome)
        self.assertEqual(findings[0], findings[-1])
        self.assertEqual(len(findings), len(outcomes))

    def test_all_ipv4_ipv6_closed_flow_inputs_delegate_with_exact_configurations(self):
        for snapshot in self.snapshots:
            expected = run_closed_flow_detectors(snapshot, flow_volume_configuration=self.volume_configuration,
                                                 tcp_control_configuration=self.control_configuration)
            with patch.object(detection_session, "run_closed_flow_detectors", return_value=expected) as delegate:
                findings = self.session.run_closed_flows((snapshot,))
            delegate.assert_called_once_with(snapshot, flow_volume_configuration=self.volume_configuration,
                                             tcp_control_configuration=self.control_configuration)
            self.assertEqual(len(findings), 2 if snapshot.identity.protocol == 6 else 1)
            for finding, original in zip(findings, expected):
                self.assertIs(finding, original)
            self.assertIs(findings[0].raw_evidence.snapshot, snapshot)
            self.assertIs(findings[0].raw_evidence.configuration, self.volume_configuration)
            self.assertIs(findings[0].decision, FlowVolumeThresholdDecision.MATCH)
            if snapshot.identity.protocol == 6:
                self.assertIs(findings[1].raw_evidence.configuration, self.control_configuration)
                self.assertIs(findings[1].decision, TCPControlThresholdDecision.MATCH)

    def test_mixed_flow_order_and_per_flow_detector_order_are_preserved(self):
        snapshots = (self.snapshots[3], self.snapshots[0], self.snapshots[2], self.snapshots[1], self.snapshots[3])
        calls, expected = [], []

        def execute(snapshot, **configurations):
            calls.append(snapshot)
            findings = run_closed_flow_detectors(snapshot, **configurations)
            expected.extend(findings)
            return findings

        with patch.object(detection_session, "run_closed_flow_detectors", side_effect=execute):
            result = self.session.run_closed_flows(iter(snapshots))
        self.assertEqual(tuple(calls), snapshots)
        self.assertEqual(len(result), 7)
        self.assertEqual(tuple(finding.detector_id for finding in result),
                         ("flow-volume-threshold", "flow-volume-threshold", "tcp-control-threshold",
                          "flow-volume-threshold", "tcp-control-threshold", "flow-volume-threshold", "flow-volume-threshold"))
        for finding, original in zip(result, expected):
            self.assertIs(finding, original)

    def test_tcp_configuration_requirement_and_udp_applicability_are_delegated(self):
        session = DetectionSession(self.packet_configuration, self.volume_configuration)
        for snapshot in self.snapshots:
            if snapshot.identity.protocol == 6:
                with self.assertRaisesRegex(TypeError, "TCP windows require"):
                    session.run_closed_flows((snapshot,))
            else:
                with patch.object(detector_orchestration, "evaluate_tcp_control_threshold", side_effect=AssertionError("UDP control")):
                    findings = session.run_closed_flows((snapshot,))
                self.assertEqual(len(findings), 1)
                self.assertIs(findings[0].decision, FlowVolumeThresholdDecision.MATCH)

    def test_not_evaluable_rate_preserves_tcp_execution_and_packet_decisions(self):
        session = DetectionSession(self.packet_configuration, volume_configuration(FlowVolumeMetric.PACKETS_PER_SECOND),
                                   self.control_configuration)
        for snapshot in self.snapshots:
            findings = session.run_closed_flows((snapshot,))
            self.assertIs(findings[0].decision, FlowVolumeThresholdDecision.NOT_EVALUABLE)
            self.assertIsNone(findings[0].raw_evidence.observed_value)
            if snapshot.identity.protocol == 6:
                self.assertIs(findings[1].decision, TCPControlThresholdDecision.MATCH)
        self.assertIs(session.run_packets((incomplete_outcome(),))[0].decision, PacketIntegrityDecision.NOT_EVALUABLE)

    def test_packet_failure_is_fail_fast_not_retried_and_returns_no_partial_tuple(self):
        self.assert_fail_fast("run_packets", "run_packet_detectors", self.ipv6)

    def test_flow_failure_is_fail_fast_not_retried_and_returns_no_partial_tuple(self):
        self.assert_fail_fast("run_closed_flows", "run_closed_flow_detectors", self.snapshots[2])

    def assert_fail_fast(self, method, delegate, value):
        error = RuntimeError("execution sentinel")
        produced, executions = [], []
        original = getattr(detection_session, delegate)

        def inputs():
            for index in range(3):
                produced.append(index)
                yield value

        def execute(*args, **kwargs):
            executions.append(args[0])
            if len(executions) == 2:
                raise error
            return original(*args, **kwargs)

        returned = []
        with patch.object(detection_session, delegate, side_effect=execute):
            with self.assertRaises(RuntimeError) as raised:
                returned.append(getattr(self.session, method)(inputs()))
        self.assertIs(raised.exception, error)
        self.assertEqual(produced, [0, 1])
        self.assertEqual(len(executions), 2)
        self.assertEqual(returned, [])
        self.assertEqual(getattr(self.session, method)((value,)), getattr(self.session, method)((value,)))

    def test_actual_detector_failure_propagates_without_later_flow_execution(self):
        error = RuntimeError("TCP evaluator sentinel")
        with patch.object(detector_orchestration, "evaluate_tcp_control_threshold", side_effect=error) as control, \
             patch.object(detection_session, "run_closed_flow_detectors", wraps=run_closed_flow_detectors) as flows:
            with self.assertRaises(RuntimeError) as raised:
                self.session.run_closed_flows((self.snapshots[2], self.snapshots[3]))
        self.assertIs(raised.exception, error)
        control.assert_called_once()
        flows.assert_called_once()

    def test_input_iteration_failures_propagate_without_restarting(self):
        for method, value in ((self.session.run_packets, self.ipv6), (self.session.run_closed_flows, self.snapshots[2])):
            error = RuntimeError("iterator sentinel")
            produced = []

            def inputs():
                produced.append(0)
                yield value
                produced.append(1)
                raise error

            with self.assertRaises(RuntimeError) as raised:
                method(inputs())
            self.assertIs(raised.exception, error)
            self.assertEqual(produced, [0, 1])

    def test_raw_packets_bare_windows_and_wrong_inputs_retain_type_errors(self):
        for invalid in (None, b"packet", self.ipv6.observation, self.ipv6.analysis, self.snapshots[2]):
            with self.assertRaises(TypeError):
                self.session.run_packets((invalid,))
        for invalid in (None, b"packet", self.ipv6, self.ipv6.analysis, self.snapshots[2].observation_window):
            with self.assertRaises(TypeError):
                self.session.run_closed_flows((invalid,))
        for method in (self.session.run_packets, self.session.run_closed_flows):
            with self.assertRaises(TypeError):
                method(None)

    def test_active_snapshots_remain_rejected_and_windows_are_not_closed(self):
        for protocol in (6, 17):
            manager = FlowObservationWindowManager("active", timedelta(seconds=10))
            window = manager.record(packet_at(protocol)).active_window
            snapshot = extract_flow_feature_snapshot(window)
            with self.assertRaises(FlowVolumeThresholdError):
                self.session.run_closed_flows((snapshot,))
            self.assertEqual(manager.active_windows(), (window,))
            self.assertIsNone(window.closure_reason)

    def test_missing_feature_and_tcp_state_keep_existing_failures(self):
        snapshot = self.snapshots[2]
        invalid = object.__new__(type(snapshot))
        for field in fields(snapshot):
            object.__setattr__(invalid, field.name, getattr(snapshot, field.name))
        object.__setattr__(invalid, "flow_volume_features", None)
        with self.assertRaises(AttributeError):
            self.session.run_closed_flows((invalid,))
        state = replace(snapshot.coordinated_state)
        object.__setattr__(state, "tcp_control_statistics", None)
        window = replace(snapshot.observation_window, coordinated_state=state)
        object.__setattr__(invalid, "flow_volume_features", snapshot.flow_volume_features)
        object.__setattr__(invalid, "observation_window", window)
        with self.assertRaises(TCPControlThresholdError):
            self.session.run_closed_flows((invalid,))

    def test_non_first_fragments_remain_packet_outcomes_not_flow_inputs(self):
        for protocol in (6, 17):
            outcome = analyze_packet_outcome(observation_at(protocol, fragment=(1, False)))
            self.assertIsNone(outcome.analysis.ipv6_tcp)
            self.assertIsNone(outcome.analysis.ipv6_udp)
            self.assertIs(self.session.run_packets((outcome,))[0].decision, PacketIntegrityDecision.NO_MATCH)
            with self.assertRaises(TypeError):
                self.session.run_closed_flows((outcome,))
            manager = FlowObservationWindowManager("fragments", timedelta(seconds=10))
            with self.assertRaises(FlowIdentityError):
                manager.record(outcome.analysis)
            self.assertEqual(manager.end_capture_session(), ())

    def test_packet_and_flow_execution_never_parse_revalidate_or_build_state(self):
        with ExitStack() as stack:
            for target in (
                "analysis.packet_analysis.analyze_packet", "analysis.packet_analysis_outcome.analyze_packet",
                "analysis.packet_analysis.decode_ipv6", "analysis.packet_analysis.decode_tcp", "analysis.packet_analysis.decode_udp",
                "analysis.packet_analysis.validate_ipv6_extension_headers", "analysis.packet_analysis.analyze_ipv6_fragmentation",
                "analysis.ipv6_extension_headers.validate_ipv6_extension_headers", "analysis.ipv6_fragmentation.validate_ipv6_extension_headers",
                "analysis.flow_feature_snapshot.extract_flow_feature_snapshot", "analysis.flow_tracker.FlowTracker.__init__",
                "analysis.flow_state_coordinator.FlowStateCoordinator.__init__", "analysis.flow_observation_window.FlowObservationWindowManager.__init__",
                "capture.packet_ingestion.consume", "application.flow_observation_session.run_flow_observation_session",
                "time.time", "time.monotonic",
            ):
                stack.enter_context(patch(target, side_effect=AssertionError(target)))
            for target in ("capture.packet_observation.PacketObservation.raw_bytes", "analysis.ipv6.IPv6Packet.payload",
                           "analysis.ethernet.EthernetFrame.payload", "analysis.ipv6_extension_headers.IPv6ExtensionHeader.raw_bytes"):
                stack.enter_context(patch(target, new_callable=PropertyMock, create=True, side_effect=AssertionError(target)))
            packet_findings = self.session.run_packets((self.ipv4, self.ipv6))
            flow_findings = self.session.run_closed_flows(self.snapshots)
            self.assertEqual(len(packet_findings), 2)
            self.assertEqual(packet_findings[1].raw_evidence.protocol, 6)
            self.assertEqual(len(flow_findings), 6)

    def test_sessions_and_inputs_are_immutable_and_execution_leaves_no_instance_state(self):
        before = vars(self.session).copy()
        outcomes_before = (replace(self.ipv4), replace(self.ipv6))
        snapshots_before = tuple(extract_flow_feature_snapshot(snapshot.observation_window) for snapshot in self.snapshots)
        findings = self.session.run_packets((self.ipv4, self.ipv6)) + self.session.run_closed_flows(self.snapshots)
        self.assertEqual(vars(self.session), before)
        self.assertEqual((self.ipv4, self.ipv6), outcomes_before)
        self.assertEqual(self.snapshots, snapshots_before)
        models = (self.session, self.packet_configuration, self.volume_configuration, self.control_configuration,
                  self.ipv4, self.ipv6, self.ipv6.analysis) + self.snapshots + findings
        models += tuple(snapshot.observation_window for snapshot in self.snapshots)
        models += tuple(snapshot.coordinated_state for snapshot in self.snapshots)
        for model in models:
            for field in fields(model):
                with self.assertRaises(FrozenInstanceError):
                    setattr(model, field.name, None)
        self.assertEqual(tuple(field.name for field in fields(DetectionFinding)),
                         ("detector_id", "detector_version", "decision", "raw_evidence", "security_interpretation"))

    def test_repeated_execution_and_independent_sessions_preserve_order_without_deduplication(self):
        other = DetectionSession(self.packet_configuration, self.volume_configuration, self.control_configuration)
        strict = DetectionSession(self.packet_configuration, replace(self.volume_configuration, threshold=100), self.control_configuration)
        outcomes = (self.ipv6, self.ipv4, self.ipv6)
        snapshots = self.snapshots + self.snapshots
        packets = self.session.run_packets(outcomes)
        flows = self.session.run_closed_flows(snapshots)
        self.assertEqual(len(packets), 3)
        self.assertEqual(len(flows), 12)
        self.assertEqual(packets, other.run_packets(outcomes))
        self.assertEqual(flows, other.run_closed_flows(snapshots))
        self.assertIs(strict.run_closed_flows((self.snapshots[2],))[0].decision, FlowVolumeThresholdDecision.NO_MATCH)
        self.assertEqual(flows, self.session.run_closed_flows(snapshots))
        self.assertEqual(packets, self.session.run_packets(outcomes))
        self.assertEqual(vars(self.session), vars(other))

    def test_capture_observation_remains_independent_until_explicit_detection(self):
        for protocol in (6, 17):
            source = MemoryPacketSource((observation_at(protocol), observation_at(protocol, seconds=1)))
            windows = []
            with patch.object(detection_session, "run_packet_detectors", side_effect=AssertionError("automatic packet detection")), \
                 patch.object(detection_session, "run_closed_flow_detectors", side_effect=AssertionError("automatic flow detection")), \
                 patch.object(detector_orchestration, "run_packet_detectors", side_effect=AssertionError("automatic packet detection")), \
                 patch.object(detector_orchestration, "run_closed_flow_detectors", side_effect=AssertionError("automatic flow detection")):
                run_flow_observation_session(source, capture_session_id="explicit", inactivity_timeout=timedelta(seconds=10),
                                             closed_window_consumer=windows.append)
            self.assertTrue(source.stopped)
            self.assertEqual(len(windows), 1)
            snapshot = extract_flow_feature_snapshot(windows[0])
            findings = self.session.run_closed_flows((snapshot,))
            self.assertEqual(findings[0].raw_evidence.observed_value, 2)
            self.assertEqual(len(findings), 2 if protocol == 6 else 1)


if __name__ == "__main__":
    unittest.main()
