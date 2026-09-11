import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from math import fsum
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

import application
from analysis import FeatureContractVersion, analyze_packet_outcome
from application import (
    DetectionBenchmarkCaseResult, DetectionDataset, DetectionDatasetCase, DetectionExperiment, DetectionSession,
    GroundTruth, PerformanceBenchmarkConfiguration, PerformanceBenchmarkResult, run_detection_benchmark,
    run_detection_pipeline, run_end_to_end_validation, run_performance_benchmark,
)
from application import capture_execution, detection_pipeline, detector_orchestration, end_to_end_validation
from application import performance_benchmark as performance
from capture import PcapPacketSource
from tests.test_end_to_end_validation import SOURCE, settings, wire
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ground_truth import flow_target, negative, packet_target, positive
from tests.test_ipv6_detection import closed_snapshot
from tests.test_ipv6_flow import packet_at
from tests.test_pcap_packet_source import global_header, record


def methodology(measured=3, warmup=0, **context):
    return PerformanceBenchmarkConfiguration('explicit-operation', 'revision-a', measured, warmup, **context)


def dataset():
    packet, flow = packet_target(), flow_target(6, True)
    return DetectionDataset(' Study ', (DetectionDatasetCase('z', flow, positive(flow)),
                                       DetectionDatasetCase('a', packet, negative(packet))))


def clock_for(count):
    return Mock(side_effect=tuple(float(i) for i in range(count * 2)))


class PerformanceBenchmarkTests(unittest.TestCase):
    def test_valid_configuration_retains_explicit_methodology(self):
        value = methodology(4, 2)
        self.assertEqual((value.operation_id, value.operation_version), ('explicit-operation', 'revision-a'))
        self.assertEqual((value.measured_executions, value.warmup_executions, value.total_executions), (4, 2, 6))

    def test_identity_and_version_preserve_exact_strings(self):
        value = PerformanceBenchmarkConfiguration(' Étude ', ' Revision 01 ', 1)
        self.assertEqual((value.operation_id, value.operation_version), (' Étude ', ' Revision 01 '))
        self.assertNotEqual(value, replace(value, operation_version='Revision 01'))

    def test_blank_identity_and_version_are_rejected(self):
        for name in ('operation_id', 'operation_version'):
            for value in ('', ' ', '\t\n'):
                with self.assertRaises(ValueError):
                    replace(methodology(), **{name: value})

    def test_identity_types_are_exact_without_coercion(self):
        class String(str):
            pass
        for name in ('operation_id', 'operation_version'):
            for value in (None, 1, True, b'op', String('op')):
                with self.assertRaises(TypeError):
                    replace(methodology(), **{name: value})

    def test_measured_execution_count_must_be_positive(self):
        for value in (0, -1):
            with self.assertRaises(ValueError):
                methodology(value)

    def test_warmup_count_must_be_nonnegative(self):
        with self.assertRaises(ValueError):
            methodology(warmup=-1)
        self.assertEqual(methodology().warmup_executions, 0)

    def test_counts_require_exact_integers(self):
        class Integer(int):
            pass
        for name in ('measured_executions', 'warmup_executions'):
            for value in (True, False, 1.0, '1', None, Integer(1)):
                with self.assertRaises(TypeError):
                    replace(methodology(), **{name: value})

    def test_context_requires_existing_exact_value_objects(self):
        for name in ('dataset', 'experiment', 'detection_configuration'):
            with self.assertRaises(TypeError):
                methodology(**{name: 'context'})
        class Dataset(DetectionDataset):
            pass
        with self.assertRaises(TypeError):
            methodology(dataset=Dataset('study', ()))

    def test_experiment_operation_mismatch_is_rejected(self):
        for identity, version in (('other', 'revision-a'), ('explicit-operation', 'other')):
            experiment = DetectionExperiment('experiment', dataset(), identity, version)
            with self.assertRaisesRegex(ValueError, 'operation identity and version must match'):
                methodology(experiment=experiment)

    def test_same_dataset_name_with_different_cases_is_rejected(self):
        data = dataset()
        experiment = DetectionExperiment('experiment', replace(data, cases=()), 'explicit-operation', 'revision-a')
        with self.assertRaisesRegex(ValueError, 'dataset must equal experiment dataset'):
            methodology(dataset=data, experiment=experiment)

    def test_equivalent_dataset_references_remain_exact(self):
        data = dataset()
        other = dataset()
        experiment = DetectionExperiment('experiment', other, 'explicit-operation', 'revision-a')
        config = methodology(1, dataset=data, experiment=experiment)
        result = run_performance_benchmark(lambda: None, configuration=config, clock=clock_for(1))
        self.assertIs(result.configuration, config)
        self.assertIs(result.dataset, data)
        self.assertIs(result.configuration.experiment.dataset, other)
        self.assertEqual(result.dataset_case_count, 2)

    def test_experiment_alone_supplies_dataset_context(self):
        experiment = DetectionExperiment('experiment', dataset(), 'explicit-operation', 'revision-a')
        result = PerformanceBenchmarkResult(methodology(1, experiment=experiment), (1.0,))
        self.assertIs(result.dataset, experiment.dataset)
        self.assertIs(result.configuration.experiment, experiment)
        self.assertEqual(result.dataset.name, ' Study ')

    def test_absent_dataset_context_is_not_an_empty_dataset(self):
        result = PerformanceBenchmarkResult(methodology(1), (0.0,))
        self.assertIsNone(result.dataset)
        self.assertIsNone(result.dataset_case_count)

    def test_configuration_and_result_are_frozen(self):
        config = methodology()
        result = PerformanceBenchmarkResult(config, (3.0, 1.0, 2.0))
        for value in (config, result):
            for field in fields(value):
                with self.assertRaises(FrozenInstanceError):
                    setattr(value, field.name, None)
        with self.assertRaises(TypeError):
            result.elapsed_seconds[0] = 0.0

    def test_observations_reject_mutable_and_non_tuple_inputs(self):
        for observations in ([1.0], iter((1.0,)), {1.0}, '1.0'):
            with self.assertRaises(TypeError):
                PerformanceBenchmarkResult(methodology(1), observations)

    def test_observation_count_must_match_configuration(self):
        for observations in ((), (1.0,), (1.0, 2.0, 3.0, 4.0)):
            with self.assertRaises(ValueError):
                PerformanceBenchmarkResult(methodology(3), observations)
        with self.assertRaises(TypeError):
            PerformanceBenchmarkResult(None, (1.0,))

    def test_observations_require_finite_nonnegative_floats(self):
        for value in (1, True, None, '1', [1.0]):
            with self.assertRaises(TypeError):
                PerformanceBenchmarkResult(methodology(1), (value,))
        for value in (-1.0, float('nan'), float('inf'), -float('inf')):
            with self.assertRaises(ValueError):
                PerformanceBenchmarkResult(methodology(1), (value,))

    def test_unrepresentable_total_raises_instead_of_infinite_summary(self):
        with self.assertRaises(OverflowError):
            PerformanceBenchmarkResult(methodology(2), (1e308, 1e308))

    def test_hand_computable_statistics_preserve_observation_order(self):
        observations = (4.0, 1.0, 3.0, 2.0)
        result = PerformanceBenchmarkResult(methodology(4), observations)
        self.assertIs(result.elapsed_seconds, observations)
        self.assertEqual((result.minimum_elapsed_seconds, result.maximum_elapsed_seconds), (1.0, 4.0))
        self.assertEqual((result.total_elapsed_seconds, result.mean_elapsed_seconds, result.median_elapsed_seconds),
                         (10.0, 2.5, 2.5))
        self.assertEqual(result.elapsed_seconds, (4.0, 1.0, 3.0, 2.0))

    def test_odd_median_uses_middle_observation_without_reordering(self):
        result = PerformanceBenchmarkResult(methodology(), (100.0, 1.0, 2.0))
        self.assertEqual(result.median_elapsed_seconds, 2.0)
        self.assertEqual(result.mean_elapsed_seconds, 103.0 / 3)
        self.assertEqual(result.elapsed_seconds, (100.0, 1.0, 2.0))

    def test_zero_duration_is_valid_for_all_statistics(self):
        result = PerformanceBenchmarkResult(methodology(1), (0.0,))
        self.assertEqual((result.minimum_elapsed_seconds, result.maximum_elapsed_seconds, result.total_elapsed_seconds,
                          result.mean_elapsed_seconds, result.median_elapsed_seconds), (0.0,) * 5)

    def test_precision_is_not_rounded_and_total_uses_accurate_summation(self):
        observations = (1e16, 1.0, 1.0)
        result = PerformanceBenchmarkResult(methodology(), observations)
        self.assertEqual(result.total_elapsed_seconds, fsum(observations))
        self.assertNotEqual(result.total_elapsed_seconds, sum(observations))
        tiny = PerformanceBenchmarkResult(methodology(1), (0.000000000123456789,))
        self.assertEqual(tiny.mean_elapsed_seconds, 0.000000000123456789)

    def test_controlled_clock_produces_raw_execution_order(self):
        operation = Mock()
        clock = Mock(side_effect=(10.0, 13.0, 20.0, 21.0, 30.0, 32.0))
        result = run_performance_benchmark(operation, configuration=methodology(), clock=clock)
        self.assertEqual(result.elapsed_seconds, (3.0, 1.0, 2.0))
        self.assertEqual((operation.call_count, clock.call_count), (3, 6))

    def test_warmups_precede_measurements_and_never_read_clock(self):
        events = []
        readings = iter((0.0, 2.0, 3.0, 4.0))
        def clock():
            events.append('clock')
            return next(readings)
        def operation():
            events.append('operation')
        result = run_performance_benchmark(operation, configuration=methodology(2, 2), clock=clock)
        self.assertEqual(events, ['operation', 'operation', 'clock', 'operation', 'clock', 'clock', 'operation', 'clock'])
        self.assertEqual(result.elapsed_seconds, (2.0, 1.0))
        self.assertEqual(result.total_elapsed_seconds, 3.0)

    def test_default_warmup_is_zero_with_no_hidden_repetitions(self):
        operation, clock = Mock(), clock_for(1)
        run_performance_benchmark(operation, configuration=methodology(1), clock=clock)
        operation.assert_called_once_with()
        self.assertEqual(clock.call_count, 2)

    def test_repeated_controlled_runs_have_equal_value_results(self):
        first = run_performance_benchmark(lambda: None, configuration=methodology(), clock=clock_for(3))
        second = run_performance_benchmark(lambda: None, configuration=methodology(), clock=clock_for(3))
        self.assertEqual(first, second)
        self.assertNotEqual(first, replace(first, elapsed_seconds=(1.0, 1.0, 2.0)))
        self.assertNotEqual(first, replace(first, configuration=replace(first.configuration, operation_version='b')))

    def test_invalid_operation_configuration_or_clock_fails_before_execution(self):
        operation, clock = Mock(), Mock()
        with self.assertRaises(TypeError):
            run_performance_benchmark(operation, configuration=None, clock=clock)
        with self.assertRaises(TypeError):
            run_performance_benchmark('operation', configuration=methodology(), clock=clock)
        with self.assertRaises(TypeError):
            run_performance_benchmark(operation, configuration=methodology(1, 2), clock='clock')
        operation.assert_not_called()
        clock.assert_not_called()

    def test_warmup_failure_propagates_without_measurement_or_retry(self):
        error = RuntimeError('warmup')
        operation, clock = Mock(side_effect=error), Mock()
        with self.assertRaises(RuntimeError) as raised:
            run_performance_benchmark(operation, configuration=methodology(3, 2), clock=clock)
        self.assertIs(raised.exception, error)
        operation.assert_called_once()
        clock.assert_not_called()

    def test_measured_failure_propagates_without_end_read_retry_or_summary(self):
        error = RuntimeError('measured')
        operation, clock = Mock(side_effect=(None, error, None)), clock_for(3)
        with self.assertRaises(RuntimeError) as raised:
            run_performance_benchmark(operation, configuration=methodology(), clock=clock)
        self.assertIs(raised.exception, error)
        self.assertEqual((operation.call_count, clock.call_count), (2, 3))

    def test_base_exception_is_not_swallowed(self):
        error = KeyboardInterrupt()
        operation, clock = Mock(side_effect=error), clock_for(2)
        with self.assertRaises(KeyboardInterrupt) as raised:
            run_performance_benchmark(operation, configuration=methodology(2), clock=clock)
        self.assertIs(raised.exception, error)
        self.assertEqual((operation.call_count, clock.call_count), (1, 1))

    def test_clock_start_failure_prevents_operation(self):
        error = RuntimeError('clock')
        operation, clock = Mock(), Mock(side_effect=error)
        with self.assertRaises(RuntimeError) as raised:
            run_performance_benchmark(operation, configuration=methodology(), clock=clock)
        self.assertIs(raised.exception, error)
        operation.assert_not_called()
        clock.assert_called_once()

    def test_clock_end_failure_prevents_later_executions(self):
        operation, clock = Mock(), Mock(side_effect=(0.0, RuntimeError('clock')))
        with self.assertRaises(RuntimeError):
            run_performance_benchmark(operation, configuration=methodology(), clock=clock)
        self.assertEqual((operation.call_count, clock.call_count), (1, 2))

    def test_clock_readings_require_finite_exact_floats(self):
        for value, error in ((True, TypeError), (1, TypeError), (None, TypeError), ('1', TypeError),
                             (float('nan'), ValueError), (float('inf'), ValueError)):
            operation = Mock()
            with self.assertRaises(error):
                run_performance_benchmark(operation, configuration=methodology(1), clock=Mock(return_value=value))
            operation.assert_not_called()

    def test_clock_cannot_reverse_within_measurement(self):
        operation = Mock()
        with self.assertRaisesRegex(ValueError, 'nondecreasing'):
            run_performance_benchmark(operation, configuration=methodology(2), clock=Mock(side_effect=(2.0, 1.0)))
        operation.assert_called_once()

    def test_clock_cannot_reverse_between_measurements(self):
        operation = Mock()
        with self.assertRaisesRegex(ValueError, 'nondecreasing'):
            run_performance_benchmark(operation, configuration=methodology(2), clock=Mock(side_effect=(1.0, 2.0, 1.0)))
        operation.assert_called_once()

    def test_clock_origin_can_be_negative_or_repeated(self):
        result = run_performance_benchmark(lambda: None, configuration=methodology(2),
                                           clock=Mock(side_effect=(-10.0, -10.0, -9.0, -8.0)))
        self.assertEqual(result.elapsed_seconds, (0.0, 1.0))

    def test_elapsed_overflow_fails_without_later_execution(self):
        operation = Mock()
        with self.assertRaisesRegex(ValueError, 'elapsed observation must be finite'):
            run_performance_benchmark(operation, configuration=methodology(2), clock=Mock(side_effect=(-1e308, 1e308)))
        operation.assert_called_once()

    def test_result_disposal_occurs_after_end_clock(self):
        events = []
        class Output:
            def __del__(self):
                events.append('dispose')
        def operation():
            events.append('operation')
            return Output()
        def clock():
            events.append('clock')
            return 1.0
        run_performance_benchmark(operation, configuration=methodology(1), clock=clock)
        self.assertEqual(events, ['clock', 'operation', 'clock', 'dispose'])

    def test_production_default_resolves_perf_counter(self):
        with patch.object(performance, 'perf_counter', side_effect=(10.0, 10.5)) as timer:
            result = run_performance_benchmark(lambda: None, configuration=methodology(1))
        self.assertEqual(result.elapsed_seconds, (0.5,))
        self.assertEqual(timer.call_count, 2)

    def test_real_production_clock_has_no_speed_threshold(self):
        result = run_performance_benchmark(lambda: None, configuration=methodology(2))
        self.assertEqual(len(result.elapsed_seconds), 2)
        self.assertTrue(all(value >= 0.0 for value in result.elapsed_seconds))

    def test_empty_dataset_still_measures_explicit_dataset_invocation(self):
        data = DetectionDataset('empty', ())
        case_operation = Mock()
        result = run_performance_benchmark(lambda: run_detection_benchmark(data, case_operation),
                                           configuration=methodology(2, dataset=data), clock=clock_for(2))
        case_operation.assert_not_called()
        self.assertIs(result.dataset, data)
        self.assertEqual(result.dataset_case_count, 0)
        self.assertEqual(len(result.elapsed_seconds), 2)

    def test_single_case_execution_is_measured_through_existing_framework(self):
        data = DetectionDataset('one', (dataset().cases[0],))
        operation = Mock(side_effect=DetectionBenchmarkCaseResult)
        result = run_performance_benchmark(lambda: run_detection_benchmark(data, operation),
                                           configuration=methodology(2, 1, dataset=data), clock=clock_for(2))
        self.assertEqual(result.dataset_case_count, 1)
        self.assertEqual(operation.call_count, 3)
        self.assertTrue(all(call.args[0] is data.cases[0] for call in operation.call_args_list))

    def test_dataset_case_order_truth_and_domains_survive_each_repetition(self):
        data = dataset()
        before = replace(data)
        cases, outputs = [], []
        def case_operation(case):
            cases.append(case)
            return DetectionBenchmarkCaseResult(case)
        def operation():
            value = run_detection_benchmark(data, case_operation)
            outputs.append(value)
            return value
        result = run_performance_benchmark(operation, configuration=methodology(2, 1, dataset=data), clock=clock_for(2))
        self.assertEqual([case.case_id for case in cases], ['z', 'a'] * 3)
        self.assertEqual(data, before)
        self.assertIs(result.dataset, data)
        for output in outputs:
            for supplied, retained in zip(data.cases, output.case_results):
                self.assertIs(retained.case, supplied)
                self.assertIs(retained.case.target, supplied.target)
                self.assertIs(retained.case.ground_truth, supplied.ground_truth)

    def test_dataset_case_failure_preserves_framework_fail_fast(self):
        data = dataset()
        operation, clock = Mock(side_effect=ValueError('case')), clock_for(2)
        with self.assertRaisesRegex(ValueError, 'case'):
            run_performance_benchmark(lambda: run_detection_benchmark(data, operation),
                                      configuration=methodology(2, dataset=data), clock=clock)
        operation.assert_called_once_with(data.cases[0])
        self.assertEqual(clock.call_count, 1)

    def test_complete_detection_pipeline_can_be_measured_directly(self):
        config = settings()
        session = DetectionSession(config.packet_configuration, config.flow_volume_configuration, config.tcp_control_configuration)
        outputs = []
        def operation():
            value = run_detection_pipeline(MemoryPacketSource((wire(), wire(True, 6))), detection_session=session,
                                           capture_session_id='performance', inactivity_timeout=config.inactivity_timeout)
            outputs.append(value)
            return value
        result = run_performance_benchmark(operation, configuration=methodology(2, detection_configuration=config), clock=clock_for(2))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual((len(outputs[0].packet_findings), len(outputs[0].flow_findings)), (2, 3))
        self.assertIs(result.configuration.detection_configuration, config)
        self.assertEqual(outputs[0].flow_findings[0].version_reference, config.flow_volume_configuration.version_reference)

    def test_packet_session_boundary_does_not_reanalyze_prepared_outcomes(self):
        config = settings()
        session = DetectionSession(config.packet_configuration, config.flow_volume_configuration)
        outcomes = tuple(analyze_packet_outcome(wire(ipv6)) for ipv6 in (False, True))
        outputs = []
        with patch.object(capture_execution, 'analyze_packet_outcome', side_effect=AssertionError('analysis')):
            run_performance_benchmark(lambda: outputs.append(session.run_packets(outcomes)),
                                      configuration=methodology(2), clock=clock_for(2))
        self.assertEqual(outputs[0], outputs[1])
        self.assertIs(outputs[0][0].raw_evidence.outcome, outcomes[0])

    def test_closed_flow_session_boundary_preserves_feature_and_detector_versions(self):
        config = settings()
        session = DetectionSession(config.packet_configuration, config.flow_volume_configuration, config.tcp_control_configuration)
        snapshots = (closed_snapshot(packet_at(6)), closed_snapshot(packet_at(17)))
        outputs = []
        with patch.object(detection_pipeline, 'extract_flow_feature_snapshot', side_effect=AssertionError('extraction')):
            run_performance_benchmark(lambda: outputs.append(session.run_closed_flows(snapshots)),
                                      configuration=methodology(2, detection_configuration=config), clock=clock_for(2))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual([finding.detector_id for finding in outputs[0]], ['volume', 'control', 'volume'])
        self.assertIs(outputs[0][0].raw_evidence.snapshot, snapshots[0])
        self.assertEqual(snapshots[0].feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
        self.assertEqual(outputs[0][1].version_reference, config.tcp_control_configuration.version_reference)

    def test_real_pcap_to_report_repetitions_use_authoritative_stages_once(self):
        observations = (wire(), wire(True, 6))
        outputs = []
        config = settings()
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'input.pcap'
            path.write_bytes(global_header() + b''.join(record(o.raw_bytes, seconds=i + 1, fraction=123456,
                                                              original=o.original_length) for i, o in enumerate(observations)))
            def operation():
                value = run_end_to_end_validation(PcapPacketSource(path, source=SOURCE), configuration=config,
                                                 capture_session_id='performance', ground_truth=GroundTruth((), ()))
                outputs.append(value)
                return value
            with ExitStack() as stack:
                spies = []
                for module, name in ((capture_execution, 'analyze_packet_outcome'),
                                     (detection_pipeline, 'extract_flow_feature_snapshot'),
                                     (detector_orchestration, 'evaluate_packet_integrity'),
                                     (detector_orchestration, 'evaluate_flow_volume_threshold'),
                                     (detector_orchestration, 'evaluate_tcp_control_threshold'),
                                     (end_to_end_validation, 'run_detection_pipeline'),
                                     (end_to_end_validation, 'evaluate_detection_result'),
                                     (end_to_end_validation, 'calculate_detection_metrics')):
                    spies.append(stack.enter_context(patch.object(module, name, wraps=getattr(module, name))))
                result = run_performance_benchmark(operation, configuration=methodology(2, 1, detection_configuration=config), clock=clock_for(2))
            self.assertEqual([spy.call_count for spy in spies], [6, 6, 6, 6, 3, 3, 3, 3])
        self.assertEqual(outputs, [outputs[0]] * 3)
        self.assertIs(outputs[0].report.configuration, result.configuration.detection_configuration)
        self.assertEqual(result.elapsed_seconds, (1.0, 1.0))

    def test_framework_has_no_external_discovery_storage_randomness_or_concurrency(self):
        config = methodology(2, 1)
        with ExitStack() as stack:
            for name in ('builtins.open', 'pathlib.Path.open', 'socket.socket', 'socket.gethostname', 'os.getenv',
                         'subprocess.run', 'subprocess.Popen', 'importlib.metadata.version', 'random.random', 'uuid.uuid4',
                         'time.time', 'time.monotonic', 'threading.Thread.start', 'multiprocessing.Process.start'):
                stack.enter_context(patch(name, side_effect=AssertionError(name)))
            result = run_performance_benchmark(lambda: None, configuration=config, clock=clock_for(2))
            self.assertEqual(result.total_elapsed_seconds, 2.0)

    def test_public_exports_resolve(self):
        for name in ('PerformanceBenchmarkConfiguration', 'PerformanceBenchmarkResult', 'run_performance_benchmark'):
            self.assertIn(name, application.__all__)
            self.assertIs(getattr(application, name), getattr(performance, name))
        self.assertNotIn('_read_clock', application.__all__)


if __name__ == '__main__':
    unittest.main()
