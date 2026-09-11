import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import Mock, PropertyMock, patch

import application
from application import (
    DetectionBenchmarkCaseResult,
    DetectionBenchmarkResult,
    DetectionDataset,
    DetectionDatasetCase,
    DetectionEvaluationMetrics,
    DetectionEvaluationResult,
    DetectionMetrics,
    GroundTruthPolarity,
    run_detection_benchmark,
)
from detection import PacketIntegrityDecision
from tests.test_detection_evaluation import evaluate, expected, packet_finding
from tests.test_ground_truth import flow_target, negative, packet_target, positive


def packet_case(name='packet'):
    return DetectionDatasetCase(name, packet_target())


def mixed_dataset():
    return DetectionDataset(' Mixed Study ', (DetectionDatasetCase('z', flow_target(6, True)), packet_case('a'),
                                             DetectionDatasetCase('m', flow_target(17))))


def supplied_metrics():
    return DetectionEvaluationMetrics(DetectionMetrics(8, 2, 4, 86), DetectionMetrics(0, 0, 0, 0, 2))


class DetectionBenchmarkTests(unittest.TestCase):
    def test_result_construction_is_inert_and_retains_dataset(self):
        dataset = DetectionDataset('study', (packet_case(),))
        case_result = DetectionBenchmarkCaseResult(dataset.cases[0])
        with patch('application.detection_benchmark.run_detection_benchmark', side_effect=AssertionError('execution')) as guard:
            result = DetectionBenchmarkResult(dataset, (case_result,))
            guard.assert_not_called()
        self.assertIs(result.dataset, dataset)
        self.assertIs(result.case_results[0], case_result)

    def test_empty_dataset_calls_no_operation_and_has_zero_count(self):
        dataset = DetectionDataset('empty', ())
        operation = Mock()
        result = run_detection_benchmark(dataset, operation)
        self.assertEqual((result.dataset_name, result.case_results, result.total_case_count), ('empty', (), 0))
        operation.assert_not_called()

    def test_single_case_executes_once_and_preserves_exact_return(self):
        case = packet_case()
        output = DetectionBenchmarkCaseResult(case)
        operation = Mock(return_value=output)
        result = run_detection_benchmark(DetectionDataset('one', (case,)), operation)
        operation.assert_called_once_with(case)
        self.assertIs(operation.call_args.args[0], case)
        self.assertIs(result.case_results[0], output)
        self.assertEqual(result.total_case_count, 1)

    def test_mixed_cases_execute_once_in_exact_dataset_order(self):
        dataset = mixed_dataset()
        received = []
        outputs = []
        def operation(case):
            received.append(case)
            output = DetectionBenchmarkCaseResult(case)
            outputs.append(output)
            return output
        result = run_detection_benchmark(dataset, operation)
        self.assertEqual(tuple(received), dataset.cases)
        self.assertEqual(tuple(item.case.case_id for item in result.case_results), ('z', 'a', 'm'))
        self.assertEqual(result.total_case_count, 3)
        for supplied, received_case, output, retained in zip(dataset.cases, received, outputs, result.case_results):
            self.assertIs(received_case, supplied)
            self.assertIs(retained, output)

    def test_dataset_name_is_preserved_without_normalization(self):
        dataset = mixed_dataset()
        result = run_detection_benchmark(dataset, DetectionBenchmarkCaseResult)
        self.assertIs(result.dataset, dataset)
        self.assertEqual(result.dataset_name, ' Mixed Study ')

    def test_plain_function_operation_is_supported(self):
        def operation(case):
            return DetectionBenchmarkCaseResult(case, DetectionEvaluationResult((), ()))
        result = run_detection_benchmark(DetectionDataset('study', (packet_case(),)), operation)
        self.assertEqual(result.case_results[0].evaluation, DetectionEvaluationResult((), ()))

    def test_callable_instance_is_supported_without_registration(self):
        class Operation:
            def __call__(self, case):
                return DetectionBenchmarkCaseResult(case)
        dataset = DetectionDataset('study', (packet_case(),))
        self.assertEqual(run_detection_benchmark(dataset, Operation()).case_results,
                         (DetectionBenchmarkCaseResult(dataset.cases[0]),))

    def test_invalid_dataset_rejected_before_operation(self):
        operation = Mock()
        for value in (None, (), [], {}, 'study', packet_case()):
            with self.assertRaisesRegex(TypeError, 'dataset must be exactly a DetectionDataset'):
                run_detection_benchmark(value, operation)
        operation.assert_not_called()

    def test_invalid_operation_rejected_even_for_empty_dataset(self):
        for value in (None, 'operation', 1, (), {}, DetectionBenchmarkCaseResult(packet_case())):
            with self.assertRaisesRegex(TypeError, 'operation must be callable'):
                run_detection_benchmark(DetectionDataset('empty', ()), value)

    def test_callable_signature_errors_propagate(self):
        def operation():
            raise AssertionError('body should not execute')
        with self.assertRaises(TypeError):
            run_detection_benchmark(DetectionDataset('study', (packet_case(),)), operation)

    def test_missing_payloads_remain_explicitly_absent(self):
        result = run_detection_benchmark(DetectionDataset('study', (packet_case(),)), DetectionBenchmarkCaseResult)
        self.assertIsNone(result.case_results[0].evaluation)
        self.assertIsNone(result.case_results[0].metrics)
        self.assertEqual(result.total_case_count, 1)

    def test_evaluation_result_is_preserved_without_reconstruction(self):
        case = packet_case()
        evaluation = DetectionEvaluationResult((), ())
        output = DetectionBenchmarkCaseResult(case, evaluation)
        result = run_detection_benchmark(DetectionDataset('study', (case,)), lambda supplied: output)
        self.assertIs(result.case_results[0].evaluation, evaluation)
        self.assertIsNone(result.case_results[0].metrics)

    def test_metrics_can_be_supplied_without_evaluation_and_are_retained(self):
        case = packet_case()
        metrics = supplied_metrics()
        result = run_detection_benchmark(DetectionDataset('study', (case,)),
                                         lambda supplied: DetectionBenchmarkCaseResult(supplied, metrics=metrics))
        self.assertIs(result.case_results[0].metrics, metrics)
        self.assertIs(result.case_results[0].metrics.packet_metrics, metrics.packet_metrics)
        self.assertIsNone(result.case_results[0].evaluation)

    def test_evaluation_and_metrics_payloads_are_not_reconciled_or_recomputed(self):
        case = packet_case()
        evaluation = DetectionEvaluationResult((), ())
        metrics = supplied_metrics()
        output = DetectionBenchmarkCaseResult(case, evaluation, metrics)
        result = run_detection_benchmark(DetectionDataset('study', (case,)), lambda supplied: output)
        self.assertIs(result.case_results[0].evaluation, evaluation)
        self.assertIs(result.case_results[0].metrics, metrics)
        self.assertEqual(result.case_results[0].metrics.packet_metrics.true_positives, 8)

    def test_not_evaluable_associated_false_negative_is_not_reinterpreted(self):
        finding = packet_finding(PacketIntegrityDecision.NOT_EVALUABLE)
        expectation = expected(finding, True, 0)
        case = DetectionDatasetCase('case', expectation.identity, positive(expectation.identity))
        evaluation = evaluate(packets=(finding,), packet_expectations=(expectation,))
        output = DetectionBenchmarkCaseResult(case, evaluation)
        result = run_detection_benchmark(DetectionDataset('study', (case,)), lambda supplied: output)
        self.assertIs(result.case_results[0].evaluation, evaluation)
        self.assertEqual(evaluation.packet_evaluations[0].classification.value, 'false_negative')
        self.assertIs(evaluation.packet_evaluations[0].finding, finding)

    def test_packet_target_and_identity_are_preserved(self):
        case = packet_case()
        result = run_detection_benchmark(DetectionDataset('study', (case,)), DetectionBenchmarkCaseResult)
        self.assertIs(result.case_results[0].case.target, case.target)
        self.assertEqual(result.case_results[0].case.case_id, 'packet')

    def test_ipv4_ipv6_tcp_udp_flow_targets_are_preserved(self):
        cases = tuple(DetectionDatasetCase(f'{family}-{protocol}', flow_target(protocol, family == 6))
                      for family in (4, 6) for protocol in (6, 17))
        result = run_detection_benchmark(DetectionDataset('flows', cases), DetectionBenchmarkCaseResult)
        self.assertEqual(tuple((item.case.target.flow_identity.ip_version, item.case.target.flow_identity.protocol)
                               for item in result.case_results), ((4, 6), (4, 17), (6, 6), (6, 17)))
        for case, item in zip(cases, result.case_results):
            self.assertIs(item.case.target, case.target)

    def test_positive_and_negative_truth_are_passed_through_unchanged(self):
        packet, flow = packet_target(), flow_target()
        cases = (DetectionDatasetCase('positive', packet, positive(packet)), DetectionDatasetCase('negative', flow, negative(flow)))
        result = run_detection_benchmark(DetectionDataset('truth', cases), DetectionBenchmarkCaseResult)
        self.assertEqual(tuple(item.case.ground_truth.polarity for item in result.case_results),
                         (GroundTruthPolarity.POSITIVE, GroundTruthPolarity.NEGATIVE))
        for case, item in zip(cases, result.case_results):
            self.assertIs(item.case.ground_truth, case.ground_truth)

    def test_unlabeled_case_does_not_acquire_truth(self):
        case = packet_case()
        result = run_detection_benchmark(DetectionDataset('study', (case,)), DetectionBenchmarkCaseResult)
        self.assertIsNone(result.case_results[0].case.ground_truth)

    def test_duplicate_case_ids_remain_rejected_by_dataset(self):
        case = packet_case()
        with self.assertRaisesRegex(ValueError, 'duplicate case_id'):
            DetectionDataset('study', (case, case))

    def test_equal_targets_with_distinct_case_ids_are_not_deduplicated(self):
        first = packet_case('first')
        second = replace(first, case_id='second')
        operation = Mock(side_effect=DetectionBenchmarkCaseResult)
        result = run_detection_benchmark(DetectionDataset('study', (first, second)), operation)
        self.assertEqual(operation.call_count, 2)
        self.assertEqual(tuple(item.case.case_id for item in result.case_results), ('first', 'second'))

    def test_repeated_calls_are_deterministic_without_retained_results(self):
        dataset = mixed_dataset()
        first = run_detection_benchmark(dataset, DetectionBenchmarkCaseResult)
        for _ in range(3):
            run_detection_benchmark(DetectionDataset('empty', ()), DetectionBenchmarkCaseResult)
            other = run_detection_benchmark(mixed_dataset(), DetectionBenchmarkCaseResult)
            self.assertEqual(first, other)
            self.assertIsNot(first, other)
            self.assertIsNot(first.case_results, other.case_results)

    def test_operation_exception_propagates_same_instance_without_retry_or_later_cases(self):
        dataset = mixed_dataset()
        failure = RuntimeError('operation failed')
        operation = Mock(side_effect=(DetectionBenchmarkCaseResult(dataset.cases[0]), failure,
                                      AssertionError('later case must not execute')))
        with self.assertRaises(RuntimeError) as raised:
            run_detection_benchmark(dataset, operation)
        self.assertIs(raised.exception, failure)
        self.assertEqual(operation.call_count, 2)
        self.assertEqual(tuple(call.args[0] for call in operation.call_args_list), dataset.cases[:2])

    def test_prior_operation_side_effects_are_not_rolled_back_on_failure(self):
        dataset = mixed_dataset()
        calls = []
        failure = ValueError('stop')
        def operation(case):
            calls.append(case.case_id)
            if case == dataset.cases[1]:
                raise failure
            return DetectionBenchmarkCaseResult(case)
        with self.assertRaises(ValueError) as raised:
            run_detection_benchmark(dataset, operation)
        self.assertIs(raised.exception, failure)
        self.assertEqual(calls, ['z', 'a'])

    def test_first_case_failure_stops_immediately(self):
        operation = Mock(side_effect=LookupError('missing supplied result'))
        with self.assertRaises(LookupError):
            run_detection_benchmark(mixed_dataset(), operation)
        self.assertEqual(operation.call_count, 1)

    def test_malformed_operation_return_stops_before_next_case(self):
        for value in (None, (), {}, DetectionEvaluationResult((), ()), supplied_metrics()):
            operation = Mock(return_value=value)
            with self.assertRaisesRegex(TypeError, 'case result must be exactly a DetectionBenchmarkCaseResult'):
                run_detection_benchmark(mixed_dataset(), operation)
            self.assertEqual(operation.call_count, 1)

    def test_wrong_case_id_return_is_rejected_immediately(self):
        case = packet_case()
        operation = Mock(return_value=DetectionBenchmarkCaseResult(replace(case, case_id='other')))
        with self.assertRaisesRegex(ValueError, 'source dataset case'):
            run_detection_benchmark(DetectionDataset('study', (case,)), operation)
        operation.assert_called_once_with(case)

    def test_cross_domain_case_substitution_is_rejected(self):
        case = packet_case()
        other = DetectionDatasetCase(case.case_id, flow_target())
        with self.assertRaisesRegex(ValueError, 'source dataset case'):
            run_detection_benchmark(DetectionDataset('study', (case,)), lambda supplied: DetectionBenchmarkCaseResult(other))

    def test_truth_substitution_on_return_is_rejected(self):
        case = packet_case()
        other = replace(case, ground_truth=negative(case.target))
        with self.assertRaisesRegex(ValueError, 'source dataset case'):
            run_detection_benchmark(DetectionDataset('study', (case,)), lambda supplied: DetectionBenchmarkCaseResult(other))

    def test_equal_independent_case_return_matches_by_value(self):
        case = packet_case()
        output = DetectionBenchmarkCaseResult(packet_case())
        result = run_detection_benchmark(DetectionDataset('study', (case,)), lambda supplied: output)
        self.assertIsNot(output.case, case)
        self.assertIs(result.case_results[0], output)
        self.assertEqual(output.case, case)

    def test_case_result_validates_case_type(self):
        for value in (None, 'case', packet_target(), DetectionDataset('empty', ())):
            with self.assertRaisesRegex(TypeError, 'case must be exactly a DetectionDatasetCase'):
                DetectionBenchmarkCaseResult(value)

    def test_case_result_rejects_invalid_evaluation_payload(self):
        for value in ((), [], {}, False, supplied_metrics()):
            with self.assertRaisesRegex(TypeError, 'evaluation must be exactly a DetectionEvaluationResult or None'):
                DetectionBenchmarkCaseResult(packet_case(), evaluation=value)

    def test_case_result_rejects_invalid_metrics_payload(self):
        for value in ((), [], {}, False, DetectionMetrics(0, 0, 0, 0), DetectionEvaluationResult((), ())):
            with self.assertRaisesRegex(TypeError, 'metrics must be exactly a DetectionEvaluationMetrics or None'):
                DetectionBenchmarkCaseResult(packet_case(), metrics=value)

    def test_result_rejects_invalid_dataset(self):
        with self.assertRaisesRegex(TypeError, 'dataset must be exactly a DetectionDataset'):
            DetectionBenchmarkResult('study', ())

    def test_result_rejects_mutable_collection_without_mutating_it(self):
        case = packet_case()
        outputs = [DetectionBenchmarkCaseResult(case)]
        before = outputs[:]
        with self.assertRaisesRegex(TypeError, 'case_results must be exactly a tuple'):
            DetectionBenchmarkResult(DetectionDataset('study', (case,)), outputs)
        self.assertEqual(outputs, before)

    def test_result_rejects_missing_or_extra_case_results(self):
        case = packet_case()
        output = DetectionBenchmarkCaseResult(case)
        for outputs in ((), (output, output)):
            with self.assertRaisesRegex(ValueError, 'one result per dataset case'):
                DetectionBenchmarkResult(DetectionDataset('study', (case,)), outputs)

    def test_result_rejects_reordered_results(self):
        dataset = mixed_dataset()
        outputs = tuple(DetectionBenchmarkCaseResult(case) for case in reversed(dataset.cases))
        with self.assertRaisesRegex(ValueError, 'source dataset case'):
            DetectionBenchmarkResult(dataset, outputs)

    def test_result_rejects_malformed_element(self):
        with self.assertRaisesRegex(TypeError, 'case result must be exactly a DetectionBenchmarkCaseResult'):
            DetectionBenchmarkResult(DetectionDataset('study', (packet_case(),)), (None,))

    def test_result_and_nested_case_result_are_frozen(self):
        result = run_detection_benchmark(DetectionDataset('study', (packet_case(),)), DetectionBenchmarkCaseResult)
        for obj, name, value in ((result, 'dataset', None), (result, 'case_results', ()),
                                  (result, 'total_case_count', 99), (result, 'dataset_name', 'other'),
                                  (result.case_results[0], 'case', None), (result.case_results[0], 'evaluation', None),
                                  (result.case_results[0], 'metrics', None)):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, name, value)
        with self.assertRaises(TypeError):
            result.case_results[0] = result.case_results[0]

    def test_source_dataset_cases_and_truth_remain_immutable_and_unchanged(self):
        target = packet_target()
        truth = positive(target)
        case = DetectionDatasetCase('case', target, truth)
        dataset = DetectionDataset('study', (case,))
        result = run_detection_benchmark(dataset, DetectionBenchmarkCaseResult)
        self.assertIs(result.dataset, dataset)
        self.assertIs(result.case_results[0].case, case)
        self.assertEqual(dataset, DetectionDataset('study', (DetectionDatasetCase('case', packet_target(), positive(packet_target())),)))
        for obj, name in ((dataset, 'name'), (case, 'target'), (truth, 'polarity')):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, name, None)

    def test_framework_has_no_performance_or_experiment_metadata(self):
        self.assertEqual(tuple(field.name for field in fields(DetectionBenchmarkResult)), ('dataset', 'case_results'))
        self.assertEqual(tuple(field.name for field in fields(DetectionBenchmarkCaseResult)), ('case', 'evaluation', 'metrics'))

    def test_explicit_operation_can_delegate_evaluation_and_metrics_once(self):
        from application import calculate_detection_metrics, evaluate_detection_result, ExpectedDetectionResult, DetectionPipelineResult
        finding = packet_finding()
        expectation = expected(finding, True, 0)
        case = DetectionDatasetCase('case', expectation.identity)
        actual = DetectionPipelineResult((finding,), ())
        expectations = ExpectedDetectionResult((expectation,), ())
        evaluator = Mock(wraps=evaluate_detection_result)
        calculator = Mock(wraps=calculate_detection_metrics)
        def operation(supplied):
            evaluation = evaluator(actual, expectations)
            return DetectionBenchmarkCaseResult(supplied, evaluation, calculator(evaluation))
        result = run_detection_benchmark(DetectionDataset('study', (case,)), operation)
        evaluator.assert_called_once_with(actual, expectations)
        calculator.assert_called_once_with(result.case_results[0].evaluation)
        self.assertEqual(result.case_results[0].metrics.packet_metrics, DetectionMetrics(1, 0, 0, 0))

    def test_framework_invokes_only_supplied_operation_without_upstream_or_external_execution(self):
        dataset = mixed_dataset()
        evaluation = DetectionEvaluationResult((), ())
        metrics = supplied_metrics()
        operation = Mock(side_effect=lambda case: DetectionBenchmarkCaseResult(case, evaluation, metrics))
        targets = (
            'application.detection_evaluation.evaluate_detection_result', 'application.detection_metrics.calculate_detection_metrics',
            'application.detection_pipeline.run_detection_pipeline', 'application.detection_session.DetectionSession.__post_init__',
            'application.capture_execution.run_capture_execution', 'application.flow_observation_session.run_flow_observation_session',
            'application.ground_truth.GroundTruthRecord.__post_init__', 'application.ground_truth.GroundTruth.__post_init__',
            'application.detector_orchestration.run_packet_detectors', 'application.detector_orchestration.run_closed_flow_detectors',
            'analysis.packet_analysis.analyze_packet', 'analysis.packet_analysis_outcome.analyze_packet_outcome',
            'analysis.flow_feature_snapshot.extract_flow_feature_snapshot', 'detection.packet_integrity.evaluate_packet_integrity',
            'detection.flow_volume_threshold.evaluate_flow_volume_threshold', 'detection.tcp_control_threshold.evaluate_tcp_control_threshold',
            'capture.packet_ingestion.consume', 'capture.pcap_packet_source.PcapPacketSource.start',
            'builtins.open', 'pathlib.Path.open', 'pathlib.Path.stat', 'pathlib.Path.iterdir', 'socket.socket',
            'time.time', 'time.monotonic', 'time.perf_counter', 'random.random', 'uuid.uuid4',
            'threading.Thread.start', 'multiprocessing.Process.start',
        )
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(target, side_effect=AssertionError(target))) for target in targets]
            for target in ('capture.packet_observation.PacketObservation.raw_bytes', 'detection.detection_finding.DetectionFinding.decision',
                           'detection.detection_finding.DetectionFinding.raw_evidence',
                           'application.detection_evaluation.DetectionEvaluationResult.packet_evaluations',
                           'application.detection_evaluation.DetectionEvaluationResult.flow_evaluations',
                           'application.detection_metrics.DetectionMetrics.precision'):
                guards.append(stack.enter_context(patch(target, new_callable=PropertyMock, create=True, side_effect=AssertionError(target))))
            result = run_detection_benchmark(dataset, operation)
            for guard in guards:
                guard.assert_not_called()
        self.assertEqual(operation.call_count, 3)
        for item in result.case_results:
            self.assertIs(item.evaluation, evaluation)
            self.assertIs(item.metrics, metrics)

    def test_public_exports_resolve(self):
        for value in (DetectionBenchmarkCaseResult, DetectionBenchmarkResult, run_detection_benchmark):
            self.assertIn(value.__name__, application.__all__)
            self.assertIs(getattr(application, value.__name__), value)


if __name__ == '__main__':
    unittest.main()
