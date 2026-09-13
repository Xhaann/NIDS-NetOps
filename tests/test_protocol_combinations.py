import unittest
from dataclasses import replace
from datetime import timedelta

from analysis import (
    FlowIdentityError, FlowObservationWindowKey, FlowObservationWindowManager,
    analyze_packet_outcome, extract_flow_feature_snapshot,
)
from application import (
    DetectionPipelineResult, DetectionSession, ExpectedDetection, ExpectedDetectionResult,
    FlowDetectionIdentity, GroundTruth, calculate_detection_metrics, evaluate_detection_result,
    run_capture_execution, run_end_to_end_validation,
)
from research import ResearchDataset, research_example_from_window
from tests.protocol_scenarios import failed_observations, interleaved_observations, protocol_flows
from tests.test_end_to_end_validation import settings
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ipv6_transport import fragment_header, observation_for


def observe(observations):
    manager = FlowObservationWindowManager('combinations', timedelta(seconds=5))
    outcomes, windows = [], []

    def receive(outcome):
        outcomes.append(outcome)
        if outcome.analysis is not None:
            windows.extend(manager.record(outcome.analysis).closed_windows)

    source = MemoryPacketSource(observations)
    run_capture_execution(source, receive)
    windows.extend(manager.end_capture_session())
    return tuple(outcomes), tuple(windows), tuple(source.events)


def normalize_windows(windows, identity):
    return tuple(replace(window, key=FlowObservationWindowKey('isolated', index))
                 for index, window in enumerate(w for w in windows if w.identity == identity))


class ProtocolCombinationTests(unittest.TestCase):
    def test_interleaving_matches_every_isolated_flow_state_feature_and_research_example(self):
        combined = interleaved_observations()
        outcomes, windows, events = observe(combined)
        self.assertEqual(observe(combined), (outcomes, windows, events))
        self.assertEqual([o.observation for o in outcomes], list(combined))
        self.assertEqual(events, ('start',) + tuple('produce:' + str(i) for i in range(len(combined))) + ('stop',))
        self.assertEqual([w.key.sequence_number for w in windows], [2, 1, 0, 3, 4, 5, 6, 7])
        self.assertEqual([w.closure_reason.value for w in windows], ['inactivity'] * 4 + ['capture_session_end'] * 4)
        identities = tuple(w.identity for w in windows[:4])
        self.assertEqual(len(set(identities)), 4)
        self.assertEqual({(i.ip_version, i.protocol) for i in identities}, {(4, 6), (4, 17), (6, 6), (6, 17)})
        for version in (4, 6):
            pair = [i for i in identities if i.ip_version == version]
            self.assertEqual((pair[0].source_address, pair[0].destination_address, pair[0].source_port, pair[0].destination_port),
                             (pair[1].source_address, pair[1].destination_address, pair[1].source_port, pair[1].destination_port))
        for group in protocol_flows():
            isolated_outcomes, isolated_windows, _ = observe(group)
            identity = isolated_windows[0].identity
            with self.subTest(identity=identity):
                expected = normalize_windows(isolated_windows, identity)
                actual = normalize_windows(windows, identity)
                self.assertEqual(actual, expected)
                self.assertEqual([w.coordinated_state.flow_statistics.packet_count for w in actual], [3, 2])
                self.assertEqual(tuple(extract_flow_feature_snapshot(w) for w in actual),
                                 tuple(extract_flow_feature_snapshot(w) for w in expected))
                dataset = ResearchDataset(tuple(research_example_from_window(w) for w in actual))
                self.assertEqual(dataset, ResearchDataset(tuple(research_example_from_window(w) for w in expected)))
                self.assertTrue(all(e.ground_truth is None and len(e.projection.values) == 49 for e in dataset.examples))
                self.assertEqual(tuple(o for o in outcomes if o.observation in group), isolated_outcomes)

    def test_failure_insertion_and_equal_timestamp_order_do_not_change_per_flow_results(self):
        _, baseline, _ = observe(interleaved_observations(include_failures=False))
        for reverse_ties in (False, True):
            observations = interleaved_observations(reverse_ties=reverse_ties)
            outcomes, windows, _ = observe(observations)
            self.assertEqual([o.failure_classification.value for o in outcomes if not o.succeeded],
                             ['structural_failure', 'unsupported', 'incomplete', 'incomplete',
                              'structural_failure', 'incomplete', 'incomplete'])
            for identity in dict.fromkeys(w.identity for w in baseline):
                self.assertEqual(normalize_windows(windows, identity), normalize_windows(baseline, identity))
        self.assertEqual(observe(failed_observations())[1], ())

    def test_isolated_and_interleaved_windows_have_equal_detection_and_explicit_evaluation(self):
        _, windows, _ = observe(interleaved_observations())
        configuration = settings()
        session = DetectionSession(configuration.packet_configuration,
                                   replace(configuration.flow_volume_configuration, threshold=2),
                                   configuration.tcp_control_configuration)
        for group in protocol_flows():
            _, isolated, _ = observe(group)
            identity = isolated[0].identity
            actual = normalize_windows(windows, identity)
            expected = normalize_windows(isolated, identity)
            findings = tuple(f for w in actual for f in session.run_closed_flows((extract_flow_feature_snapshot(w),)))
            baseline = tuple(f for w in expected for f in session.run_closed_flows((extract_flow_feature_snapshot(w),)))
            self.assertEqual(findings, baseline)
            expectations = []
            for index, window in enumerate(expected):
                expectations.append(ExpectedDetection(FlowDetectionIdentity(session.flow_volume_configuration,
                    window.key, identity, window.first_captured_at, window.last_captured_at), index == 0))
                if identity.protocol == 6:
                    expectations.append(ExpectedDetection(FlowDetectionIdentity(session.tcp_control_configuration,
                        window.key, identity, window.first_captured_at, window.last_captured_at), index == 0))
            truth = ExpectedDetectionResult((), tuple(expectations))
            result = evaluate_detection_result(DetectionPipelineResult((), findings), truth)
            self.assertEqual(result, evaluate_detection_result(DetectionPipelineResult((), baseline), truth))
            classifications = [e.classification.value for e in result.flow_evaluations]
            self.assertEqual(classifications, ['true_positive', 'true_negative'] if identity.protocol == 17 else
                             ['true_positive', 'true_positive', 'true_negative', 'true_negative'])
            self.assertEqual(calculate_detection_metrics(result).flow_metrics.unclassified_count, 0)

    def test_complete_pipeline_matches_observation_windows_and_repeats_exactly(self):
        observations = interleaved_observations()
        _, windows, _ = observe(observations)
        results = []
        for _ in range(2):
            result = run_end_to_end_validation(MemoryPacketSource(observations), configuration=settings(),
                                              capture_session_id='combinations', ground_truth=GroundTruth((), ()))
            results.append(result)
            snapshots = [f.raw_evidence.snapshot for f in result.pipeline_result.flow_findings if f.detector_id == 'volume']
            self.assertEqual(tuple(s.observation_window for s in snapshots), windows)
            self.assertEqual(tuple(f.raw_evidence.outcome for f in result.pipeline_result.packet_findings), observe(observations)[0])
        self.assertEqual(results[0], results[1])

    def test_admission_errors_do_not_mutate_any_interleaved_active_flow(self):
        manager = FlowObservationWindowManager('combinations', timedelta(seconds=5))
        for group in protocol_flows():
            manager.record(analyze_packet_outcome(group[0]).analysis)
        before = manager.active_windows()
        for observation in (observation_for(58, bytes(4)), observation_for(253, bytes(32)),
                            observation_for(6, bytes(32), fragment_header(6, offset=1), 44)):
            analysis = analyze_packet_outcome(observation).analysis
            self.assertIsNotNone(analysis)
            with self.assertRaises(FlowIdentityError):
                manager.record(analysis)
            self.assertEqual(manager.active_windows(), before)
        for group in protocol_flows():
            manager.record(analyze_packet_outcome(group[1]).analysis)
        windows = manager.end_capture_session()
        self.assertEqual([w.key.sequence_number for w in windows], [0, 1, 2, 3])
        self.assertEqual([w.coordinated_state.flow_statistics.packet_count for w in windows], [2] * 4)
