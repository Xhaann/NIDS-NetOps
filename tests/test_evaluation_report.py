import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import PropertyMock, patch

import application
from application import (
    DetectionBenchmarkCaseResult, DetectionBenchmarkResult, DetectionDataset, DetectionDatasetCase,
    DetectionEvaluationMetrics, DetectionEvaluationResult, DetectionExperiment, DetectionMetrics, EvaluationReport,
    detection_identity,
)
from detection import PacketIntegrityDecision
from tests.test_detection_benchmark import mixed_dataset, supplied_metrics
from tests.test_detection_configuration import configuration
from tests.test_detection_evaluation import C, evaluate, expected, packet_finding
from tests.test_ground_truth import flow_target, negative, packet_target, positive
from tests.test_ipv6_detection import closed_snapshot, detect
from tests.test_ipv6_features import feature_sequence


def benchmark(data=None):
    data = mixed_dataset() if data is None else data
    return DetectionBenchmarkResult(data, tuple(DetectionBenchmarkCaseResult(case, DetectionEvaluationResult((), ()), supplied_metrics())
                                               for case in data.cases))


def experiment(data):
    return DetectionExperiment('study-a', data, 'external-evaluation', 'revision-a')


class EvaluationReportTests(unittest.TestCase):
    def test_standalone_result_and_metrics_are_retained_exactly(self):
        result, metrics = DetectionEvaluationResult((), ()), supplied_metrics()
        report = EvaluationReport(result, metrics)
        self.assertIs(report.result, result)
        self.assertIs(report.metrics, metrics)

    def test_result_is_required(self):
        with self.assertRaises(TypeError):
            EvaluationReport()

    def test_invalid_result_references_are_rejected(self):
        for value in (None, (), [], {}, 'result', True, supplied_metrics(), configuration()):
            with self.subTest(value=value), self.assertRaisesRegex(TypeError, 'result must be exactly'):
                EvaluationReport(value)

    def test_result_subclasses_are_rejected(self):
        class EvaluationSubclass(DetectionEvaluationResult):
            pass
        class BenchmarkSubclass(DetectionBenchmarkResult):
            pass
        for value in (EvaluationSubclass((), ()), BenchmarkSubclass(DetectionDataset('empty', ()), ())):
            with self.assertRaises(TypeError):
                EvaluationReport(value)

    def test_absent_metrics_are_not_computed_or_replaced(self):
        report = EvaluationReport(DetectionEvaluationResult((), ()))
        self.assertIsNone(report.metrics)
        self.assertNotEqual(report, replace(report, metrics=DetectionEvaluationMetrics(DetectionMetrics(0, 0, 0, 0), DetectionMetrics(0, 0, 0, 0))))

    def test_invalid_metrics_references_are_rejected(self):
        for value in ((), [], {}, 'metrics', True, DetectionMetrics(0, 0, 0, 0)):
            with self.subTest(value=value), self.assertRaisesRegex(TypeError, 'metrics must be exactly'):
                EvaluationReport(DetectionEvaluationResult((), ()), value)

    def test_metrics_subclasses_are_rejected(self):
        class OtherMetrics(DetectionEvaluationMetrics):
            pass
        with self.assertRaises(TypeError):
            EvaluationReport(DetectionEvaluationResult((), ()), OtherMetrics(DetectionMetrics(0, 0, 0, 0), DetectionMetrics(0, 0, 0, 0)))

    def test_benchmark_report_rejects_ambiguous_top_level_metrics(self):
        with self.assertRaisesRegex(ValueError, 'benchmark reports retain metrics only in their case results'):
            EvaluationReport(benchmark(), supplied_metrics())

    def test_packet_and_flow_metrics_retain_exact_separate_references(self):
        metrics = supplied_metrics()
        report = EvaluationReport(DetectionEvaluationResult((), ()), metrics)
        self.assertIs(report.metrics.packet_metrics, metrics.packet_metrics)
        self.assertIs(report.metrics.flow_metrics, metrics.flow_metrics)
        self.assertNotEqual(report.metrics.packet_metrics, report.metrics.flow_metrics)

    def test_classification_counts_are_authoritative_not_recounted(self):
        result, metrics = DetectionEvaluationResult((), ()), supplied_metrics()
        report = EvaluationReport(result, metrics)
        packet = report.metrics.packet_metrics
        self.assertEqual((packet.true_positives, packet.false_positives, packet.false_negatives, packet.true_negatives), (8, 2, 4, 86))
        self.assertEqual(report.result.packet_evaluations, ())

    def test_derived_values_remain_owned_by_supplied_metrics(self):
        report = EvaluationReport(DetectionEvaluationResult((), ()), supplied_metrics())
        packet = report.metrics.packet_metrics
        self.assertEqual(packet.precision, 8 / 10)
        self.assertEqual(packet.recall, 8 / 12)
        self.assertEqual(packet.f1, 2 * (8 / 10) * (8 / 12) / ((8 / 10) + (8 / 12)))
        self.assertEqual(packet.accuracy, 94 / 100)

    def test_undefined_values_remain_none(self):
        report = EvaluationReport(DetectionEvaluationResult((), ()), supplied_metrics())
        flow = report.metrics.flow_metrics
        self.assertEqual((flow.precision, flow.recall, flow.f1, flow.accuracy), (None, None, None, None))
        self.assertEqual(flow.unclassified_count, 2)

    def test_defined_zero_metrics_remain_distinct_from_undefined(self):
        metrics = DetectionEvaluationMetrics(DetectionMetrics(0, 1, 1, 0), DetectionMetrics(0, 0, 0, 0))
        report = EvaluationReport(DetectionEvaluationResult((), ()), metrics)
        self.assertEqual((report.metrics.packet_metrics.precision, report.metrics.packet_metrics.recall, report.metrics.packet_metrics.accuracy), (0.0, 0.0, 0.0))
        self.assertIsNone(report.metrics.packet_metrics.f1)
        self.assertIsNone(report.metrics.flow_metrics.accuracy)

    def test_existing_not_evaluable_false_negative_is_preserved(self):
        finding = packet_finding(PacketIntegrityDecision.NOT_EVALUABLE)
        result = evaluate(packets=(finding,), packet_expectations=(expected(finding, index=0),))
        report = EvaluationReport(result)
        entry = report.result.packet_evaluations[0]
        self.assertIs(entry.classification, C.FALSE_NEGATIVE)
        self.assertIs(entry.finding.decision, PacketIntegrityDecision.NOT_EVALUABLE)
        self.assertIs(entry, result.packet_evaluations[0])

    def test_unclassified_evaluation_is_not_inferred_negative(self):
        finding = packet_finding(PacketIntegrityDecision.NOT_EVALUABLE)
        result = evaluate(packets=(finding,))
        report = EvaluationReport(result)
        self.assertIsNone(report.result.packet_evaluations[0].classification)
        self.assertIsNone(report.result.packet_evaluations[0].expectation)

    def test_no_dataset_context_remains_absent_not_empty(self):
        report = EvaluationReport(DetectionEvaluationResult((), ()))
        self.assertIsNone(report.dataset)
        self.assertIsNone(report.dataset_case_count)
        self.assertIsNone(report.experiment)
        self.assertIsNone(report.configuration)

    def test_empty_benchmark_dataset_retains_name_and_zero_count(self):
        data = DetectionDataset(' Empty Study ', ())
        result = benchmark(data)
        report = EvaluationReport(result)
        self.assertIs(report.dataset, data)
        self.assertEqual(report.dataset.name, ' Empty Study ')
        self.assertEqual(report.dataset_case_count, 0)
        self.assertEqual(report.result.case_results, ())

    def test_single_case_preserves_source_association(self):
        case = DetectionDatasetCase('case-a', packet_target())
        report = EvaluationReport(benchmark(DetectionDataset('data', (case,))))
        self.assertEqual(report.dataset_case_count, 1)
        self.assertIs(report.result.case_results[0].case, case)

    def test_multiple_mixed_cases_retain_order(self):
        data = mixed_dataset()
        result = benchmark(data)
        report = EvaluationReport(result)
        self.assertEqual(report.dataset_case_count, 3)
        self.assertEqual([r.case.case_id for r in report.result.case_results], ['z', 'a', 'm'])
        self.assertIs(report.result.case_results, result.case_results)
        self.assertIs(report.dataset.cases, data.cases)

    def test_ipv4_ipv6_tcp_udp_targets_are_retained(self):
        cases = tuple(DetectionDatasetCase(str((ipv6, protocol)), flow_target(protocol, ipv6))
                      for ipv6 in (False, True) for protocol in (6, 17))
        report = EvaluationReport(benchmark(DetectionDataset('transports', cases)))
        self.assertEqual([(r.case.target.flow_identity.ip_version, r.case.target.flow_identity.protocol)
                          for r in report.result.case_results], [(4, 6), (4, 17), (6, 6), (6, 17)])
        for actual, case in zip(report.result.case_results, cases):
            self.assertIs(actual.case.target, case.target)

    def test_positive_negative_and_missing_truth_remain_distinct(self):
        target = packet_target()
        cases = (DetectionDatasetCase('positive', target, positive(target)),
                 DetectionDatasetCase('negative', target, negative(target)), DetectionDatasetCase('unlabeled', target))
        report = EvaluationReport(benchmark(DetectionDataset('truth', cases)))
        for actual, case in zip(report.result.case_results, cases):
            self.assertIs(actual.case.ground_truth, case.ground_truth)
        self.assertIsNone(report.result.case_results[2].case.ground_truth)

    def test_benchmark_per_case_evaluation_and_metrics_are_not_reconstructed(self):
        result = benchmark()
        report = EvaluationReport(result)
        self.assertIs(report.result, result)
        for actual, original in zip(report.result.case_results, result.case_results):
            self.assertIs(actual, original)
            self.assertIs(actual.evaluation, original.evaluation)
            self.assertIs(actual.metrics, original.metrics)
        self.assertIsNone(report.metrics)

    def test_missing_benchmark_case_outputs_remain_missing(self):
        data = DetectionDataset('data', (DetectionDatasetCase('case', packet_target()),))
        result = DetectionBenchmarkResult(data, (DetectionBenchmarkCaseResult(data.cases[0]),))
        report = EvaluationReport(result)
        self.assertIsNone(report.result.case_results[0].evaluation)
        self.assertIsNone(report.result.case_results[0].metrics)

    def test_experiment_identity_and_operation_reference_are_preserved(self):
        result = benchmark()
        definition = experiment(result.dataset)
        report = EvaluationReport(result, experiment=definition)
        self.assertIs(report.experiment, definition)
        self.assertEqual((report.experiment.experiment_id, report.experiment.benchmark_operation_id,
                          report.experiment.benchmark_operation_version), ('study-a', 'external-evaluation', 'revision-a'))

    def test_standalone_report_uses_explicit_experiment_dataset_context(self):
        definition = experiment(mixed_dataset())
        report = EvaluationReport(DetectionEvaluationResult((), ()), experiment=definition)
        self.assertIs(report.dataset, definition.dataset)
        self.assertEqual(report.dataset_case_count, 3)

    def test_invalid_experiment_references_are_rejected(self):
        for value in ('study', {}, (), mixed_dataset()):
            with self.assertRaisesRegex(TypeError, 'experiment must be exactly'):
                EvaluationReport(DetectionEvaluationResult((), ()), experiment=value)

    def test_experiment_subclasses_are_rejected(self):
        class OtherExperiment(DetectionExperiment):
            pass
        with self.assertRaises(TypeError):
            EvaluationReport(DetectionEvaluationResult((), ()), experiment=OtherExperiment('id', mixed_dataset(), 'op', '1'))

    def test_benchmark_and_experiment_dataset_name_mismatch_is_rejected(self):
        result = benchmark()
        with self.assertRaisesRegex(ValueError, 'experiment dataset must equal benchmark dataset'):
            EvaluationReport(result, experiment=experiment(replace(result.dataset, name='different')))

    def test_same_dataset_name_different_case_order_is_rejected(self):
        result = benchmark()
        other = replace(result.dataset, cases=tuple(reversed(result.dataset.cases)))
        with self.assertRaises(ValueError):
            EvaluationReport(result, experiment=experiment(other))

    def test_same_dataset_name_different_truth_is_rejected(self):
        result = benchmark()
        first = result.dataset.cases[0]
        other = replace(result.dataset, cases=(replace(first, ground_truth=positive(first.target)),) + result.dataset.cases[1:])
        with self.assertRaises(ValueError):
            EvaluationReport(result, experiment=experiment(other))

    def test_equivalent_independent_dataset_references_are_valid(self):
        result = benchmark()
        definition = experiment(mixed_dataset())
        self.assertIsNot(definition.dataset, result.dataset)
        report = EvaluationReport(result, experiment=definition)
        self.assertIs(report.dataset, result.dataset)
        self.assertIs(report.experiment.dataset, definition.dataset)

    def test_configuration_is_exact_optional_declared_context(self):
        config = configuration()
        report = EvaluationReport(DetectionEvaluationResult((), ()), configuration=config)
        self.assertIs(report.configuration, config)
        self.assertIs(report.configuration.packet_configuration, config.packet_configuration)
        self.assertEqual(report.configuration.packet_configuration.version_reference, config.packet_configuration.version_reference)
        self.assertIsNone(replace(report, configuration=None).configuration)

    def test_invalid_configuration_references_and_subclasses_are_rejected(self):
        class OtherConfiguration(application.DetectionConfiguration):
            pass
        config = configuration()
        other = OtherConfiguration(config.packet_configuration, config.flow_volume_configuration, config.inactivity_timeout)
        for value in ('config', {}, (), config.packet_configuration, other):
            with self.assertRaisesRegex(TypeError, 'configuration must be exactly'):
                EvaluationReport(DetectionEvaluationResult((), ()), configuration=value)

    def test_finding_versions_and_feature_provenance_remain_in_original_evidence(self):
        snapshot = closed_snapshot(*feature_sequence(6))
        finding = detect(snapshot)[0]
        result = evaluate(flows=(finding,), flow_expectations=(expected(finding),))
        report = EvaluationReport(result)
        retained = report.result.flow_evaluations[0].finding
        self.assertIs(retained, finding)
        self.assertEqual(retained.version_reference, finding.version_reference)
        self.assertIs(retained.raw_evidence.snapshot, snapshot)
        self.assertEqual(retained.raw_evidence.snapshot.feature_contract, snapshot.feature_contract)
        self.assertEqual(detection_identity(retained), detection_identity(finding))

    def test_finding_duplicates_and_channel_order_are_preserved(self):
        packet = packet_finding()
        flows = detect(closed_snapshot(*feature_sequence(6)))
        result = evaluate(packets=(packet, packet), flows=flows)
        report = EvaluationReport(result)
        self.assertIs(report.result.packet_evaluations, result.packet_evaluations)
        self.assertIs(report.result.flow_evaluations, result.flow_evaluations)
        self.assertEqual([e.actual_index for e in report.result.packet_evaluations], [0, 1])
        self.assertEqual([e.finding for e in report.result.flow_evaluations], list(flows))

    def test_report_and_nested_collections_are_immutable(self):
        report = EvaluationReport(benchmark(), configuration=configuration())
        for field in fields(report):
            with self.assertRaises(FrozenInstanceError):
                setattr(report, field.name, None)
        with self.assertRaises(TypeError):
            report.result.case_results[0] = report.result.case_results[1]
        with self.assertRaises(FrozenInstanceError):
            report.result.case_results[0].metrics.packet_metrics.true_positives = 0

    def test_caller_owned_references_and_collections_remain_unchanged(self):
        result = benchmark()
        values = dict(result=result, experiment=experiment(result.dataset), configuration=configuration())
        before = values.copy()
        report = EvaluationReport(**values)
        self.assertEqual(values, before)
        values.clear()
        for name, value in before.items():
            self.assertIs(getattr(report, name), value)

    def test_repeated_independent_reports_compare_equal_without_hidden_state(self):
        first = EvaluationReport(benchmark(), configuration=configuration())
        for _ in range(3):
            EvaluationReport(DetectionEvaluationResult((), ()))
            with self.assertRaises(TypeError):
                EvaluationReport(None)
            second = EvaluationReport(benchmark(), configuration=configuration())
            self.assertEqual(first, second)
            self.assertEqual(first.dataset_case_count, second.dataset_case_count)

    def test_meaningful_context_and_metric_differences_affect_equality(self):
        report = EvaluationReport(DetectionEvaluationResult((), ()), supplied_metrics(), experiment(mixed_dataset()), configuration())
        self.assertNotEqual(report, replace(report, metrics=None))
        self.assertNotEqual(report, replace(report, experiment=replace(report.experiment, experiment_id='other')))
        self.assertNotEqual(report, replace(report, configuration=None))
        self.assertNotEqual(report, replace(report, result=evaluate(packets=(packet_finding(),))))

    def test_construction_and_inspection_do_not_execute_compute_or_render(self):
        result, metrics, config = benchmark(), supplied_metrics(), configuration()
        definition = experiment(result.dataset)
        evaluation = DetectionEvaluationResult((), ())
        targets = (
            'application.detection_evaluation.evaluate_detection_result', 'application.detection_metrics.calculate_detection_metrics',
            'application.detection_benchmark.run_detection_benchmark', 'application.detection_experiment.DetectionExperiment.__post_init__',
            'application.detection_session.DetectionSession.__post_init__', 'application.detection_session.DetectionSession.run_packets',
            'application.detection_session.DetectionSession.run_closed_flows', 'application.detection_pipeline.run_detection_pipeline',
            'application.capture_execution.run_capture_execution', 'analysis.packet_analysis.analyze_packet',
            'analysis.packet_analysis_outcome.analyze_packet_outcome', 'analysis.flow_feature_snapshot.extract_flow_feature_snapshot',
            'analysis.ipv6.decode_ipv6', 'detection.packet_integrity.evaluate_packet_integrity',
            'detection.flow_volume_threshold.evaluate_flow_volume_threshold', 'detection.tcp_control_threshold.evaluate_tcp_control_threshold',
            'capture.packet_ingestion.consume', 'capture.pcap_packet_source.PcapPacketSource.start',
            'builtins.open', 'pathlib.Path.open', 'pathlib.Path.stat', 'socket.socket', 'socket.gethostname', 'os.getpid', 'os.getenv',
            'time.time', 'time.monotonic', 'time.perf_counter', 'random.random', 'uuid.uuid4', 'sqlite3.connect',
            'threading.Thread.start', 'multiprocessing.Process.start', 'subprocess.run', 'subprocess.check_output',
            'importlib.metadata.version', 'json.dumps', 'json.dump', 'csv.writer', 'pickle.dumps', 'builtins.print',
        )
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(target, side_effect=AssertionError(target))) for target in targets]
            for name in ('precision', 'recall', 'f1', 'accuracy'):
                guards.append(stack.enter_context(patch.object(DetectionMetrics, name, new_callable=PropertyMock,
                              side_effect=AssertionError('metric calculation'))))
            guards.append(stack.enter_context(patch('importlib.import_module', side_effect=AssertionError('dynamic import'))))
            report = EvaluationReport(result, experiment=definition, configuration=config)
            standalone = EvaluationReport(evaluation, metrics)
            self.assertIs(report.result, result)
            self.assertIs(report.dataset, result.dataset)
            self.assertEqual(report.dataset_case_count, 3)
            self.assertIs(standalone.metrics.packet_metrics, metrics.packet_metrics)
            for guard in guards:
                guard.assert_not_called()

    def test_minimal_public_contract_and_export(self):
        self.assertIs(application.EvaluationReport, EvaluationReport)
        self.assertIn('EvaluationReport', application.__all__)
        self.assertEqual(tuple(f.name for f in fields(EvaluationReport)), ('result', 'metrics', 'experiment', 'configuration'))


if __name__ == '__main__':
    unittest.main()
