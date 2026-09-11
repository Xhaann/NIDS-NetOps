import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from analysis import FeatureContractVersion, FlowIdentityError
from application import (
    DetectionBenchmarkCaseResult, DetectionDataset, DetectionDatasetCase, DetectionExperiment,
    DetectionMetrics, EvaluationReport, GroundTruth, GroundTruthPolarity, OperationalErrorCategory,
    PerformanceBenchmarkConfiguration, diagnose_error, run_capture_execution, run_detection_benchmark,
    run_end_to_end_validation, run_performance_benchmark,
)
from application import capture_execution, end_to_end_validation
from capture import CaptureError, PcapPacketSource
from detection import FlowVolumeMetric
from tests.test_end_to_end_validation import SOURCE, packet_truth, settings, timestamp, truth_for, wire
from tests.test_ipv6_flow import observation_at
from tests.test_ipv6_transport import observation_for
from tests.test_pcap_packet_source import global_header, record


class SystemRegressionTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'regression.pcap'
        self.configuration = settings()

    def source(self, observations, times=None, order='<', nano=False, suffix=b''):
        if times is None:
            times = tuple((i + 1, 123456) for i in range(len(observations)))
        self.assertEqual(len(observations), len(times))
        data = global_header(order=order, nano=nano) + b''.join(
            record(o.raw_bytes, order=order, seconds=seconds, fraction=fraction,
                   original=o.original_length)
            for o, (seconds, fraction) in zip(observations, times)
        ) + suffix
        self.path.write_bytes(data)
        return PcapPacketSource(self.path, source=SOURCE)

    def execute(self, source, truth=None, configuration=None):
        return run_end_to_end_validation(
            source, configuration=self.configuration if configuration is None else configuration,
            capture_session_id='validation', ground_truth=GroundTruth((), ()) if truth is None else truth,
        )

    def test_all_pcap_encodings_produce_equal_mixed_protocol_reports(self):
        observations = (wire(False, 6), wire(False, 17),
                        observation_at(6, extensions=(0, 43, 60)),
                        observation_at(17, fragment=(0, False, 1)))
        truth = GroundTruth(tuple(packet_truth(o, i, i + 1) for i, o in enumerate(observations)), ())
        results = []
        for order, nano in (('<', False), ('>', False), ('<', True), ('>', True)):
            with self.subTest(order=order, nano=nano):
                times = tuple((i + 1, 123456000 if nano else 123456) for i in range(4))
                source = self.source(observations, times, order, nano)
                before = self.path.read_bytes()
                result = self.execute(source, truth)
                self.assertEqual(result.report.metrics.packet_metrics, DetectionMetrics(0, 0, 0, 4))
                self.assertEqual([(f.raw_evidence.identity.ip_version, f.raw_evidence.identity.protocol)
                                  for f in result.pipeline_result.flow_findings],
                                 [(4, 6), (4, 6), (4, 17), (6, 6), (6, 6), (6, 17)])
                self.assertEqual(self.path.read_bytes(), before)
                self.assertEqual(list(source), [])
                results.append(result)
        self.assertTrue(all(result == results[0] for result in results[1:]))

    def test_submicrosecond_capture_differences_do_not_invent_flow_duration(self):
        observation = wire(True, 17)
        configuration = replace(self.configuration, flow_volume_configuration=replace(
            self.configuration.flow_volume_configuration, metric=FlowVolumeMetric.PACKETS_PER_SECOND,
            threshold=0.0))
        micro = self.execute(self.source((observation, observation), ((1, 123456), (1, 123456))),
                             configuration=configuration)
        nano = self.execute(self.source((observation, observation),
                                       ((1, 123456999), (1, 123456000)), nano=True),
                            configuration=configuration)
        self.assertEqual(nano, micro)
        finding = nano.pipeline_result.flow_findings[0]
        snapshot = finding.raw_evidence.snapshot
        self.assertEqual(snapshot.flow_duration_features.duration_seconds, 0.0)
        self.assertEqual(snapshot.directional_inter_arrival_features.forward_mean_inter_arrival_seconds, 0.0)
        self.assertIsNone(snapshot.directional_inter_arrival_features.reverse_mean_inter_arrival_seconds)
        self.assertIsNone(snapshot.flow_rate_features)
        self.assertEqual(finding.decision.value, 'not_evaluable')
        self.assertEqual(nano.report.metrics.flow_metrics, DetectionMetrics(0, 0, 0, 0, 1))

    def test_nanosecond_truncation_precedes_inactivity_boundary_comparison(self):
        configuration = replace(self.configuration, inactivity_timeout=timedelta(microseconds=10))
        observation = wire(True, 17)
        for fraction, counts, reasons in (
            (18999, [2], ['capture_session_end']),
            (19000, [1, 1], ['inactivity', 'capture_session_end']),
            (20000, [1, 1], ['inactivity', 'capture_session_end']),
        ):
            with self.subTest(fraction=fraction):
                result = self.execute(self.source((observation, observation),
                                                 ((1, 9999), (1, fraction)), nano=True),
                                      configuration=configuration)
                findings = result.pipeline_result.flow_findings
                self.assertEqual([f.raw_evidence.snapshot.flow_volume_features.packet_count for f in findings], counts)
                self.assertEqual([f.raw_evidence.observation_window.closure_reason.value for f in findings], reasons)
                self.assertEqual([f.raw_evidence.sequence_number for f in findings], list(range(len(counts))))

    def test_failed_analysis_timestamp_does_not_advance_admitted_flow_time(self):
        valid = wire(True, 17)
        malformed = replace(valid, raw_bytes=b'', captured_length=0, original_length=0)
        observations = (valid, malformed, valid)
        truth = GroundTruth((packet_truth(valid, 0, 1),
                             packet_truth(malformed, 1, 100, GroundTruthPolarity.POSITIVE),
                             packet_truth(valid, 2, 2)), ())
        result = self.execute(self.source(observations, ((1, 123456), (100, 123456), (2, 123456))), truth)
        outcomes = tuple(f.raw_evidence.outcome for f in result.pipeline_result.packet_findings)
        self.assertEqual([o.observation.captured_at for o in outcomes], [timestamp(1), timestamp(100), timestamp(2)])
        self.assertIsNone(outcomes[1].analysis)
        self.assertEqual(outcomes[1].failure_classification.value, 'incomplete')
        self.assertEqual(result.pipeline_result.packet_findings[1].decision.value, 'not_evaluable')
        self.assertEqual(result.report.metrics.packet_metrics, DetectionMetrics(0, 0, 1, 2))
        snapshot = result.pipeline_result.flow_findings[0].raw_evidence.snapshot
        self.assertEqual(snapshot.flow_volume_features.packet_count, 2)
        self.assertEqual(snapshot.flow_duration_features.duration_seconds, 1.0)
        self.assertEqual(len(result.pipeline_result.flow_findings), 1)

    def test_failed_analysis_does_not_refresh_an_active_flow_timeout(self):
        valid = wire(True, 6)
        malformed = replace(valid, raw_bytes=b'', captured_length=0, original_length=0)
        result = self.execute(self.source((valid, malformed, valid), ((1, 0), (5, 0), (6, 0))))
        findings = result.pipeline_result.flow_findings
        self.assertEqual([f.detector_id for f in findings], ['volume', 'control', 'volume', 'control'])
        self.assertEqual([f.raw_evidence.sequence_number for f in findings], [0, 0, 1, 1])
        self.assertEqual([f.raw_evidence.observation_window.closure_reason.value for f in findings],
                         ['inactivity', 'inactivity', 'capture_session_end', 'capture_session_end'])
        for finding in findings:
            self.assertEqual(finding.raw_evidence.observation_window.coordinated_state.flow_statistics.packet_count, 1)

    def test_inactivity_delivery_order_is_not_sorted_by_creation_sequence(self):
        first, second = wire(False, 17), wire(True, 6)
        result = self.execute(self.source((first, second, second, first), ((1, 0), (2, 0), (7, 0), (8, 0))))
        findings = result.pipeline_result.flow_findings
        self.assertEqual([f.raw_evidence.sequence_number for f in findings], [1, 1, 0, 2, 2, 3])
        self.assertEqual([f.detector_id for f in findings], ['volume', 'control', 'volume', 'volume', 'control', 'volume'])
        self.assertEqual([f.raw_evidence.observation_window.closure_reason.value for f in findings],
                         ['inactivity'] * 3 + ['capture_session_end'] * 3)
        for index, (entry, finding) in enumerate(zip(result.report.result.flow_evaluations, findings)):
            self.assertEqual(entry.actual_index, index)
            self.assertIs(entry.finding, finding)

    def test_icmpv6_analysis_success_remains_distinct_from_flow_admission_failure(self):
        observation = observation_for(58, bytes.fromhex('80000000'))
        outcomes = []
        run_capture_execution(self.source((observation,)), outcomes.append)
        self.assertEqual(len(outcomes), 1)
        self.assertIsNone(outcomes[0].failure_classification)
        self.assertEqual(outcomes[0].analysis.ipv6_icmpv6.icmp_type, 128)
        source = self.source((observation, wire(True, 17)))
        with patch.object(capture_execution, 'analyze_packet_outcome', wraps=capture_execution.analyze_packet_outcome) as analyze, \
             patch.object(end_to_end_validation, 'evaluate_detection_result') as evaluation, \
             patch.object(source, 'stop', wraps=source.stop) as stop:
            with self.assertRaises(FlowIdentityError) as raised:
                self.execute(source)
            analyze.assert_called_once()
            evaluation.assert_not_called()
            stop.assert_called_once()
        diagnostic = diagnose_error(raised.exception, operation_id='validation', message='flow admission failed')
        self.assertIs(diagnostic.category, OperationalErrorCategory.FLOW_PROCESSING_FAILURE)
        self.assertEqual(list(source), [])

    def test_threshold_changes_reach_evaluation_without_changing_feature_values(self):
        observations = (wire(True, 6), wire(True, 6))
        snapshots = []
        for threshold, decision, metrics in (
            (1, 'match', DetectionMetrics(2, 0, 0, 0)),
            (2, 'no_match', DetectionMetrics(0, 0, 2, 0)),
            (3, 'no_match', DetectionMetrics(0, 0, 2, 0)),
        ):
            with self.subTest(threshold=threshold):
                configuration = replace(self.configuration,
                    flow_volume_configuration=replace(self.configuration.flow_volume_configuration, threshold=threshold),
                    tcp_control_configuration=replace(self.configuration.tcp_control_configuration, threshold=threshold))
                truth = truth_for(observations, (1, 2), True, 6)
                truth = replace(truth, flow_records=tuple(
                    replace(record, target=replace(record.target, configuration=config))
                    for record, config in zip(truth.flow_records,
                        (configuration.flow_volume_configuration, configuration.tcp_control_configuration))))
                result = self.execute(self.source(observations), truth, configuration)
                self.assertEqual([f.decision.value for f in result.pipeline_result.flow_findings], [decision, decision])
                self.assertEqual(result.report.metrics.flow_metrics, metrics)
                self.assertEqual(result.report.metrics.packet_metrics, DetectionMetrics(0, 0, 0, 2))
                self.assertIs(result.report.configuration, configuration)
                snapshot = result.pipeline_result.flow_findings[0].raw_evidence.snapshot
                self.assertEqual(snapshot.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
                snapshots.append(snapshot)
        self.assertEqual(snapshots[0], snapshots[1])
        self.assertEqual(snapshots[1], snapshots[2])

    def test_partial_capture_failure_cannot_complete_a_measured_dataset_report(self):
        observation = wire()
        truth = packet_truth(observation, 0, 1)
        dataset = DetectionDataset('capture-cases', tuple(
            DetectionDatasetCase(name, truth.target, truth) for name in ('valid', 'corrupt', 'unreached')))
        experiment = DetectionExperiment('capture-study', dataset, 'dataset-validation', '1')
        configuration = PerformanceBenchmarkConfiguration('dataset-validation', '1', 2, experiment=experiment,
                                                         detection_configuration=self.configuration)
        calls, completed, sources = [], [], []
        clock = Mock(side_effect=(0.0, 1.0, 2.0, 3.0))

        def operation(case):
            calls.append(case)
            source = self.source((observation,), suffix=b'bad' if case.case_id == 'corrupt' else b'')
            sources.append(source)
            result = self.execute(source, GroundTruth((truth,), ()))
            completed.append(result)
            return DetectionBenchmarkCaseResult(case, result.report.result, result.report.metrics)

        def measured():
            benchmark = run_detection_benchmark(dataset, operation)
            return EvaluationReport(benchmark, experiment=experiment, configuration=self.configuration)

        with patch.object(end_to_end_validation, 'evaluate_detection_result',
                          wraps=end_to_end_validation.evaluate_detection_result) as evaluation, \
             patch.object(end_to_end_validation, 'calculate_detection_metrics',
                          wraps=end_to_end_validation.calculate_detection_metrics) as metrics, \
             patch.object(EvaluationReport, '__post_init__', autospec=True,
                          side_effect=EvaluationReport.__post_init__) as report:
            with self.assertRaisesRegex(CaptureError, 'truncated PCAP record header'):
                run_performance_benchmark(measured, configuration=configuration, clock=clock)
            evaluation.assert_called_once()
            metrics.assert_called_once()
            report.assert_called_once()
        self.assertEqual(calls, list(dataset.cases[:2]))
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].report.metrics.packet_metrics, DetectionMetrics(0, 0, 0, 1))
        clock.assert_called_once()
        self.assertTrue(all(list(source) == [] for source in sources))
        self.assertIs(configuration.experiment, experiment)


if __name__ == '__main__':
    unittest.main()
