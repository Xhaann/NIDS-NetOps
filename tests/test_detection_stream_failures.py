import unittest
from unittest.mock import patch

from analysis import (
    FlowObservationWindow, FlowObservationWindowClosureReason, FlowObservationWindowError,
    FlowObservationWindowManager, FlowObservationWindowUpdate,
)
from application import DetectionSession
from application import capture_execution, detection_pipeline, detector_orchestration, flow_observation_session
from capture import CaptureError
from detection import DetectionFinding
from tests.test_detection_stream import collected, execute
from tests.test_flow_capacity import capacity_packet
from tests.test_flow_capacity_pipeline import session
from tests.test_flow_observation_session import MemoryPacketSource


class DetectionStreamFailureTests(unittest.TestCase):
    def test_packet_consumer_failure_stops_before_admission_and_suppresses_final_detection(self):
        for error in (RuntimeError('consumer'), MemoryError('consumer'), KeyboardInterrupt()):
            packets = tuple(capacity_packet(i, i) for i in range(3))
            source = MemoryPacketSource(packets)
            delivered = []
            managers = []

            def manager(*args, **kwargs):
                owner = FlowObservationWindowManager(*args, **kwargs)
                managers.append(owner)
                return owner

            def receive(finding):
                delivered.append(finding)
                if len(delivered) == 2:
                    raise error

            with patch.object(flow_observation_session, 'FlowObservationWindowManager', manager), \
                 patch.object(detection_pipeline, 'extract_flow_feature_snapshot') as features:
                with self.assertRaises(type(error)) as raised:
                    execute(source, receive, self.fail)
            self.assertIs(raised.exception, error)
            self.assertEqual(len(delivered), 2)
            features.assert_not_called()
            self.assertEqual(source.events, ['start', 'produce:0', 'produce:1', 'stop'])
            self.assertEqual(managers[0].active_windows(), ())
            self.assertEqual(managers[0].end_capture_session(), ())

    def test_flow_consumer_failure_in_each_closure_phase_is_not_retried(self):
        for phase in ('capacity', 'inactivity', 'capture_session_end'):
            for fail_at in (1, 2):
                for ipv6 in (False, True):
                    first = capacity_packet(0, ipv6=ipv6, protocol=6)
                    second = capacity_packet(0 if phase == 'inactivity' else 1,
                                             5 if phase == 'inactivity' else 1, ipv6, 6)
                    source = MemoryPacketSource((first, second, capacity_packet(2, 6, ipv6, 6)))
                    delivered, packets = [], []
                    error = RuntimeError('flow output')

                    def receive(finding):
                        delivered.append(finding)
                        if len(delivered) == fail_at:
                            raise error

                    with self.subTest(phase=phase, fail_at=fail_at, ipv6=ipv6):
                        with self.assertRaises(RuntimeError) as raised:
                            execute(source, packets.append, receive,
                                    max_active_windows=3 if phase == 'capture_session_end' else 1)
                        self.assertIs(raised.exception, error)
                        self.assertEqual(len(delivered), fail_at)
                        self.assertEqual(delivered[0].raw_evidence.closure_reason.value, phase)
                        self.assertEqual([f.detector_id for f in delivered], ['volume', 'control'][:fail_at])
                        self.assertEqual(len(packets), 3 if phase == 'capture_session_end' else 2)
                        self.assertEqual(source.events[-1], 'stop')

    def test_capture_start_iteration_and_stop_failures_preserve_cleanup_and_final_delivery(self):
        for phase in ('start', 'iteration', 'stop'):
            error = CaptureError('capture unavailable')
            source = MemoryPacketSource((capacity_packet(0), capacity_packet(1, 1)), **{phase + '_error': error})
            packets, flows = [], []
            with self.assertRaises(CaptureError) as raised:
                execute(source, packets.append, flows.append, max_active_windows=1)
            self.assertIs(raised.exception, error)
            self.assertEqual(len(packets), 0 if phase == 'start' else 2)
            self.assertEqual([f.raw_evidence.closure_reason.value for f in flows],
                             [] if phase == 'start' else ['capacity', 'capture_session_end'])
            self.assertEqual(source.events.count('stop'), 1)

    def test_packet_detector_failure_does_not_publish_failing_packet_or_finalize_detection(self):
        original = DetectionSession.run_packets
        calls = []
        error = RuntimeError('packet detector')
        source = MemoryPacketSource(tuple(capacity_packet(i, i) for i in range(3)))
        delivered = []

        def detect(owner, outcomes):
            calls.append(outcomes[0])
            if len(calls) == 2:
                raise error
            return original(owner, outcomes)

        with patch.object(DetectionSession, 'run_packets', detect), \
             patch.object(detection_pipeline, 'extract_flow_feature_snapshot') as features:
            with self.assertRaises(RuntimeError) as raised:
                execute(source, delivered.append, self.fail)
        self.assertIs(raised.exception, error)
        self.assertEqual(len(delivered), 1)
        features.assert_not_called()
        self.assertEqual(source.events, ['start', 'produce:0', 'produce:1', 'stop'])

    def test_second_tcp_detector_failure_publishes_none_of_that_window_batch(self):
        error = RuntimeError('TCP detector')
        source = MemoryPacketSource((capacity_packet(0, protocol=6), capacity_packet(1, 1), capacity_packet(2, 2)))
        packets, flows = [], []
        with patch.object(detector_orchestration, 'evaluate_tcp_control_threshold', side_effect=error) as control, \
             patch.object(detector_orchestration, 'evaluate_flow_volume_threshold',
                          wraps=detector_orchestration.evaluate_flow_volume_threshold) as volume:
            with self.assertRaises(RuntimeError) as raised:
                execute(source, packets.append, flows.append, max_active_windows=1)
        self.assertIs(raised.exception, error)
        self.assertEqual(flows, [])
        self.assertEqual(len(packets), 2)
        self.assertEqual((volume.call_count, control.call_count), (1, 1))
        self.assertEqual(source.events[-1], 'stop')

    def test_missing_tcp_configuration_is_not_silently_treated_as_volume_only(self):
        configured = session()
        no_tcp = DetectionSession(configured.packet_configuration, configured.flow_volume_configuration)
        packets, flows = [], []
        with self.assertRaisesRegex(TypeError, 'TCP windows require'):
            execute(MemoryPacketSource((capacity_packet(0, protocol=6),)), packets.append, flows.append,
                    detection_session=no_tcp)
        self.assertEqual(len(packets), 1)
        self.assertEqual(flows, [])

    def test_finding_construction_failure_obeys_packet_and_flow_batch_publication_boundaries(self):
        original = DetectionFinding.__post_init__
        for failing_detector in ('packet', 'control'):
            error = MemoryError('finding construction')
            packets, flows = [], []
            source = MemoryPacketSource((capacity_packet(0, protocol=6), capacity_packet(1, 1)))

            def validate(finding):
                original(finding)
                if finding.detector_id == failing_detector:
                    raise error

            with patch.object(DetectionFinding, '__post_init__', validate):
                with self.assertRaises(MemoryError) as raised:
                    execute(source, packets.append, flows.append, max_active_windows=1)
            self.assertIs(raised.exception, error)
            self.assertEqual(len(packets), 0 if failing_detector == 'packet' else 2)
            self.assertEqual(flows, [])
            self.assertEqual(source.events[-1], 'stop')

    def test_feature_extraction_failure_does_not_publish_or_retry_flow_findings(self):
        error = RuntimeError('feature extraction')
        packets, flows = [], []
        source = MemoryPacketSource((capacity_packet(0), capacity_packet(1, 1)))
        with patch.object(detection_pipeline, 'extract_flow_feature_snapshot', side_effect=error) as extract:
            with self.assertRaises(RuntimeError) as raised:
                execute(source, packets.append, flows.append, max_active_windows=1)
        self.assertIs(raised.exception, error)
        self.assertEqual(len(packets), 2)
        self.assertEqual(flows, [])
        self.assertEqual(extract.call_count, 1)

    def test_window_publication_failure_preserves_prior_admission_but_not_rollback_of_packet_delivery(self):
        packets, flows, previous = [], [], []
        error = MemoryError('window publication')
        original = FlowObservationWindowUpdate.__post_init__

        def validate(update):
            original(update)
            if update.closed_windows:
                previous.append(update.closed_windows[0].coordinated_state)
                raise error

        source = MemoryPacketSource((capacity_packet(0), capacity_packet(1, 1), capacity_packet(2, 2)))
        with patch.object(FlowObservationWindowUpdate, '__post_init__', validate):
            with self.assertRaises(MemoryError) as raised:
                execute(source, packets.append, flows.append, max_active_windows=1)
        self.assertIs(raised.exception, error)
        self.assertEqual(len(packets), 2)
        self.assertEqual(len(flows), 1)
        window = flows[0].raw_evidence.snapshot.observation_window
        self.assertIs(window.coordinated_state, previous[0])
        self.assertEqual(window.key.sequence_number, 0)
        self.assertIs(window.closure_reason, FlowObservationWindowClosureReason.CAPTURE_SESSION_END)
        self.assertEqual(window.coordinated_state.flow_statistics.packet_count, 1)

    def test_unexpected_analysis_failure_still_delivers_previously_admitted_windows(self):
        original = capture_execution.analyze_packet_outcome
        calls = []
        error = RuntimeError('analysis')

        def analyze(observation):
            calls.append(observation)
            if len(calls) == 2:
                raise error
            return original(observation)

        packets, flows = [], []
        with patch.object(capture_execution, 'analyze_packet_outcome', analyze):
            with self.assertRaises(RuntimeError) as raised:
                execute(MemoryPacketSource((capacity_packet(0), capacity_packet(1, 1))), packets.append, flows.append)
        self.assertIs(raised.exception, error)
        self.assertEqual((len(packets), len(flows)), (1, 1))
        self.assertEqual(flows[0].raw_evidence.total_packet_count, 1)

    def test_stop_failure_supersedes_consumer_failure_with_original_context(self):
        consumer_error, stop_error = RuntimeError('consumer'), CaptureError('stop')
        source = MemoryPacketSource((capacity_packet(0),), stop_error=stop_error)

        def fail(finding):
            raise consumer_error

        with self.assertRaises(CaptureError) as raised:
            execute(source, fail, self.fail)
        self.assertIs(raised.exception, stop_error)
        self.assertIs(raised.exception.__context__, consumer_error)

    def test_final_consumer_failure_supersedes_capture_failure_with_original_context(self):
        capture_error, consumer_error = CaptureError('capture'), RuntimeError('consumer')
        source = MemoryPacketSource((capacity_packet(0),), iteration_error=capture_error)
        delivered = []

        def fail(finding):
            delivered.append(finding)
            raise consumer_error

        with self.assertRaises(RuntimeError) as raised:
            execute(source, lambda f: None, fail)
        self.assertIs(raised.exception, consumer_error)
        self.assertIs(raised.exception.__context__, capture_error)
        self.assertEqual(len(delivered), 1)
        self.assertTrue(source.stopped)

    def test_finalization_failure_preserves_manager_retry_without_stream_redelivery(self):
        managers, packets, flows = [], [], []
        original = FlowObservationWindow.__post_init__
        error = MemoryError('finalization')

        def manager(*args, **kwargs):
            owner = FlowObservationWindowManager(*args, **kwargs)
            managers.append(owner)
            return owner

        def validate(window):
            original(window)
            if window.closure_reason is FlowObservationWindowClosureReason.CAPTURE_SESSION_END:
                raise error

        source = MemoryPacketSource((capacity_packet(0), capacity_packet(1, 1)))
        with patch.object(flow_observation_session, 'FlowObservationWindowManager', manager), \
             patch.object(FlowObservationWindow, '__post_init__', validate):
            with self.assertRaises(MemoryError) as raised:
                execute(source, packets.append, flows.append)
        self.assertIs(raised.exception, error)
        self.assertEqual(len(managers[0].active_windows()), 2)
        self.assertEqual(len(managers[0].end_capture_session()), 2)
        self.assertEqual(managers[0].end_capture_session(), ())
        self.assertEqual(flows, [])
        self.assertTrue(source.stopped)

    def test_successful_finalization_occurs_once_and_repeated_manager_end_delivers_nothing(self):
        managers, packets, flows = [], [], []

        def manager(*args, **kwargs):
            owner = FlowObservationWindowManager(*args, **kwargs)
            managers.append(owner)
            return owner

        with patch.object(flow_observation_session, 'FlowObservationWindowManager', manager):
            execute(MemoryPacketSource((capacity_packet(0),)), packets.append, flows.append)
        self.assertEqual(managers[0].end_capture_session(), ())
        self.assertEqual(managers[0].end_capture_session(), ())
        self.assertEqual((len(packets), len(flows)), (1, 1))
        with self.assertRaises(FlowObservationWindowError):
            managers[0].record(packets[0].raw_evidence.analysis)

    def test_partial_delivery_remains_caller_owned_and_fresh_replay_can_repeat_prefix(self):
        observations = (capacity_packet(0, protocol=6), capacity_packet(1, 1), capacity_packet(2, 2))
        partial_packets, partial_flows = [], []
        error = RuntimeError('caller output')

        def receive(finding):
            partial_flows.append(finding)
            raise error

        with self.assertRaises(RuntimeError):
            execute(MemoryPacketSource(observations), partial_packets.append, receive, max_active_windows=1)
        repeated_packets, repeated_flows = [], []
        execute(MemoryPacketSource(observations), repeated_packets.append, repeated_flows.append, max_active_windows=1)
        self.assertEqual(partial_packets, repeated_packets[:2])
        self.assertEqual(partial_flows, repeated_flows[:1])
        self.assertEqual(tuple(repeated_flows), collected(observations, max_active_windows=1).flow_findings)
        self.assertEqual(len(partial_flows), 1)

    def test_collecting_adapter_propagates_failure_without_constructing_partial_result(self):
        original = DetectionSession.run_packets
        error = RuntimeError('detector')
        calls = []

        def detect(owner, outcomes):
            calls.append(outcomes)
            if len(calls) == 2:
                raise error
            return original(owner, outcomes)

        with patch.object(DetectionSession, 'run_packets', detect), \
             patch.object(detection_pipeline, 'DetectionPipelineResult') as result:
            with self.assertRaises(RuntimeError) as raised:
                collected((capacity_packet(0), capacity_packet(1, 1)))
        self.assertIs(raised.exception, error)
        result.assert_not_called()
