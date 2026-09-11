import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock, PropertyMock, patch

import application
from application import (
    DetectionBenchmarkCaseResult,
    DetectionBenchmarkResult,
    DetectionDataset,
    DetectionDatasetCase,
    DetectionEvaluationResult,
    DetectionExperiment,
    DetectionMetrics,
    DetectionPipelineResult,
    FlowDetectionIdentity,
    GroundTruthPolarity,
    PacketDetectionIdentity,
)
from detection import FlowVolumeMetric, TCPControlMetric, TCPControlThresholdConfiguration
from tests.test_ground_truth import flow_target, negative, packet_target, positive


def dataset():
    packet, flow = packet_target(), flow_target(6, True)
    return DetectionDataset('study', (DetectionDatasetCase('packet', packet, positive(packet)),
                                      DetectionDatasetCase('flow', flow, negative(flow))))


def experiment(data=None):
    return DetectionExperiment('experiment-a', dataset() if data is None else data, 'explicit-evaluation', 'revision-a')


class DetectionExperimentTests(unittest.TestCase):
    def test_valid_definition_retains_explicit_inputs(self):
        data = dataset()
        value = DetectionExperiment('experiment-a', data, 'explicit-evaluation', 'revision-a')
        self.assertEqual((value.experiment_id, value.benchmark_operation_id, value.benchmark_operation_version),
                         ('experiment-a', 'explicit-evaluation', 'revision-a'))
        self.assertIs(value.dataset, data)

    def test_experiment_identity_is_required(self):
        with self.assertRaises(TypeError):
            DetectionExperiment(dataset=dataset(), benchmark_operation_id='operation', benchmark_operation_version='1')

    def test_empty_and_blank_experiment_ids_are_rejected(self):
        for identity in ('', ' ', '\t\n'):
            with self.assertRaisesRegex(ValueError, 'experiment_id must not be blank'):
                replace(experiment(), experiment_id=identity)

    def test_non_string_experiment_identity_is_rejected_without_coercion(self):
        for identity in (None, True, 1, b'id', Path('id')):
            with self.assertRaisesRegex(TypeError, 'experiment_id must be exactly a string'):
                replace(experiment(), experiment_id=identity)

    def test_valid_identity_preserves_unicode_case_and_whitespace(self):
        value = replace(experiment(), experiment_id=' Étude A ')
        self.assertEqual(value.experiment_id, ' Étude A ')
        self.assertNotEqual(value, replace(value, experiment_id='étude a'))

    def test_dataset_reference_is_required(self):
        with self.assertRaises(TypeError):
            DetectionExperiment('experiment-a', benchmark_operation_id='operation', benchmark_operation_version='1')

    def test_invalid_dataset_reference_is_rejected(self):
        for data in (None, 'study', (), [], {}, packet_target()):
            with self.assertRaisesRegex(TypeError, 'dataset must be exactly a DetectionDataset'):
                experiment(data) if data is not None else replace(experiment(), dataset=None)

    def test_dataset_subclass_is_not_silently_accepted(self):
        class OtherDataset(DetectionDataset):
            pass
        with self.assertRaisesRegex(TypeError, 'dataset must be exactly a DetectionDataset'):
            experiment(OtherDataset('study', ()))

    def test_empty_dataset_is_a_valid_explicit_reference(self):
        data = DetectionDataset('empty', ())
        value = experiment(data)
        self.assertIs(value.dataset, data)
        self.assertEqual((value.dataset.name, value.dataset.cases), ('empty', ()))

    def test_same_name_different_dataset_cases_remain_distinct(self):
        first = experiment()
        second = replace(first, dataset=DetectionDataset(first.dataset.name, first.dataset.cases[:1]))
        self.assertNotEqual(first, second)

    def test_dataset_name_participates_in_experiment_equality(self):
        first = experiment()
        self.assertNotEqual(first, replace(first, dataset=replace(first.dataset, name='other-study')))

    def test_operation_identity_and_revision_are_both_required(self):
        with self.assertRaises(TypeError):
            DetectionExperiment('id', dataset(), benchmark_operation_version='1')
        with self.assertRaises(TypeError):
            DetectionExperiment('id', dataset(), 'operation')

    def test_operation_id_rejects_blank_values(self):
        for value in ('', ' ', '\t\n'):
            with self.assertRaisesRegex(ValueError, 'benchmark_operation_id must not be blank'):
                replace(experiment(), benchmark_operation_id=value)

    def test_operation_version_rejects_blank_values(self):
        for value in ('', ' ', '\t\n'):
            with self.assertRaisesRegex(ValueError, 'benchmark_operation_version must not be blank'):
                replace(experiment(), benchmark_operation_version=value)

    def test_operation_reference_types_are_exact_strings(self):
        for name in ('benchmark_operation_id', 'benchmark_operation_version'):
            for value in (None, True, 1, b'operation', Path('operation')):
                with self.assertRaisesRegex(TypeError, name + ' must be exactly a string'):
                    replace(experiment(), **{name: value})

    def test_callable_operation_is_rejected_without_invocation(self):
        operation = Mock(side_effect=AssertionError('must not execute'))
        with self.assertRaisesRegex(TypeError, 'benchmark_operation_id must be exactly a string'):
            replace(experiment(), benchmark_operation_id=operation)
        operation.assert_not_called()

    def test_operation_reference_is_opaque_without_lookup_or_normalization(self):
        value = DetectionExperiment('id', dataset(), ' External Operation ', ' release candidate α ')
        self.assertEqual((value.benchmark_operation_id, value.benchmark_operation_version),
                         (' External Operation ', ' release candidate α '))

    def test_experiment_id_difference_changes_value(self):
        first = experiment()
        self.assertNotEqual(first, replace(first, experiment_id='experiment-b'))

    def test_operation_id_difference_changes_value(self):
        first = experiment()
        self.assertNotEqual(first, replace(first, benchmark_operation_id='another-operation'))

    def test_operation_version_difference_changes_value(self):
        first = experiment()
        self.assertNotEqual(first, replace(first, benchmark_operation_version='revision-b'))

    def test_independently_constructed_equivalent_definitions_compare_equal(self):
        first, second = experiment(), experiment()
        self.assertIsNot(first.dataset, second.dataset)
        self.assertIsNot(first.dataset.cases[0].target, second.dataset.cases[0].target)
        self.assertEqual(first, second)

    def test_case_order_is_preserved_and_semantically_significant(self):
        value = experiment()
        self.assertEqual(tuple(case.case_id for case in value.dataset.cases), ('packet', 'flow'))
        reversed_data = replace(value.dataset, cases=tuple(reversed(value.dataset.cases)))
        self.assertNotEqual(value, replace(value, dataset=reversed_data))

    def test_case_id_changes_distinguish_definitions(self):
        first = experiment()
        cases = (replace(first.dataset.cases[0], case_id='another-case'), first.dataset.cases[1])
        self.assertNotEqual(first, replace(first, dataset=replace(first.dataset, cases=cases)))

    def test_packet_and_flow_targets_are_preserved_by_reference(self):
        data = dataset()
        value = experiment(data)
        self.assertEqual(tuple(type(case.target) for case in value.dataset.cases), (PacketDetectionIdentity, FlowDetectionIdentity))
        for original, retained in zip(data.cases, value.dataset.cases):
            self.assertIs(retained, original)
            self.assertIs(retained.target, original.target)

    def test_ipv4_ipv6_tcp_udp_dataset_semantics_are_retained(self):
        cases = tuple(DetectionDatasetCase(f'{family}-{protocol}', flow_target(protocol, family == 6))
                      for family in (4, 6) for protocol in (6, 17))
        value = experiment(DetectionDataset('flows', cases))
        self.assertEqual(tuple((case.target.flow_identity.ip_version, case.target.flow_identity.protocol)
                               for case in value.dataset.cases), ((4, 6), (4, 17), (6, 6), (6, 17)))
        self.assertIs(value.dataset.cases, cases)

    def test_positive_and_negative_truth_remain_unchanged(self):
        data = dataset()
        value = experiment(data)
        self.assertEqual(tuple(case.ground_truth.polarity for case in value.dataset.cases),
                         (GroundTruthPolarity.POSITIVE, GroundTruthPolarity.NEGATIVE))
        for supplied, retained in zip(data.cases, value.dataset.cases):
            self.assertIs(retained.ground_truth, supplied.ground_truth)

    def test_missing_truth_remains_unlabeled_and_distinct_from_negative(self):
        target = packet_target()
        unlabeled = DetectionDatasetCase('case', target)
        first = experiment(DetectionDataset('study', (unlabeled,)))
        second = experiment(DetectionDataset('study', (replace(unlabeled, ground_truth=negative(target)),)))
        self.assertIsNone(first.dataset.cases[0].ground_truth)
        self.assertNotEqual(first, second)

    def test_changed_truth_changes_definition(self):
        first = experiment()
        case = first.dataset.cases[0]
        cases = (replace(case, ground_truth=negative(case.target)), first.dataset.cases[1])
        self.assertNotEqual(first, replace(first, dataset=replace(first.dataset, cases=cases)))

    def test_detector_id_difference_is_preserved_through_dataset(self):
        target = packet_target()
        other = replace(target, configuration=replace(target.configuration, detector_id='other'))
        first = experiment(DetectionDataset('study', (DetectionDatasetCase('case', target),)))
        second = experiment(DetectionDataset('study', (DetectionDatasetCase('case', other),)))
        self.assertNotEqual(first, second)
        self.assertEqual(second.dataset.cases[0].target.configuration.detector_id, 'other')

    def test_existing_detector_version_distinguishes_definitions(self):
        target = flow_target()
        other = replace(target, configuration=replace(target.configuration, detector_version='2'))
        first = experiment(DetectionDataset('study', (DetectionDatasetCase('case', target),)))
        second = experiment(DetectionDataset('study', (DetectionDatasetCase('case', other),)))
        self.assertNotEqual(first, second)
        self.assertEqual(second.dataset.cases[0].target.configuration.detector_version, '2')

    def test_flow_threshold_and_metric_changes_distinguish_definitions(self):
        target = flow_target()
        first = experiment(DetectionDataset('study', (DetectionDatasetCase('case', target),)))
        for config in (replace(target.configuration, threshold=20),
                       replace(target.configuration, metric=FlowVolumeMetric.CAPTURED_BYTES)):
            other = replace(target, configuration=config)
            second = experiment(DetectionDataset('study', (DetectionDatasetCase('case', other),)))
            self.assertNotEqual(first, second)
            self.assertIs(second.dataset.cases[0].target.configuration, config)

    def test_tcp_control_configuration_is_reused_without_new_configuration_model(self):
        config = TCPControlThresholdConfiguration('control', '1', TCPControlMetric.FORWARD_SYN, 2)
        target = flow_target(6, True, configuration=config)
        value = experiment(DetectionDataset('control-study', (DetectionDatasetCase('tcp', target),)))
        self.assertIs(value.dataset.cases[0].target.configuration, config)
        self.assertEqual(config.threshold, 2)

    def test_packet_provenance_changes_distinguish_definitions(self):
        target = packet_target()
        first = experiment(DetectionDataset('study', (DetectionDatasetCase('case', target),)))
        for other in (replace(target, packet_index=1), replace(target, capture_source='another-source'),
                      replace(target, captured_at=target.captured_at + timedelta(microseconds=1))):
            second = experiment(DetectionDataset('study', (DetectionDatasetCase('case', other),)))
            self.assertNotEqual(first, second)

    def test_flow_window_and_endpoint_changes_distinguish_definitions(self):
        target = flow_target()
        first = experiment(DetectionDataset('study', (DetectionDatasetCase('case', target),)))
        for other in (replace(target, window_key=replace(target.window_key, sequence_number=2)),
                      replace(target, flow_identity=replace(target.flow_identity, destination_port=444))):
            second = experiment(DetectionDataset('study', (DetectionDatasetCase('case', other),)))
            self.assertNotEqual(first, second)

    def test_definition_fields_are_frozen(self):
        value = experiment()
        for name, replacement in (('experiment_id', 'other'), ('dataset', None),
                                  ('benchmark_operation_id', 'other'), ('benchmark_operation_version', 'other')):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, name, replacement)

    def test_nested_collection_and_values_remain_immutable(self):
        value = experiment()
        with self.assertRaises(TypeError):
            value.dataset.cases[0] = value.dataset.cases[1]
        for obj, name in ((value.dataset, 'cases'), (value.dataset.cases[0], 'target'),
                          (value.dataset.cases[0].ground_truth, 'polarity'),
                          (value.dataset.cases[0].target.configuration, 'detector_version')):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, name, None)

    def test_caller_collection_snapshot_is_not_changed_or_retained_mutably(self):
        cases = list(dataset().cases)
        before = cases[:]
        data = DetectionDataset('study', tuple(cases))
        value = experiment(data)
        self.assertEqual(cases, before)
        cases.clear()
        self.assertEqual(value.dataset.cases, tuple(before))
        self.assertIs(value.dataset, data)

    def test_repeated_construction_and_inspection_has_no_cross_call_state(self):
        first = experiment()
        before = (first.experiment_id, first.dataset, first.benchmark_operation_id, first.benchmark_operation_version)
        for _ in range(3):
            experiment(DetectionDataset('empty', ()))
            with self.assertRaises(ValueError):
                replace(first, experiment_id='')
            other = experiment()
            self.assertEqual(other, first)
            self.assertEqual((other.experiment_id, other.dataset, other.benchmark_operation_id, other.benchmark_operation_version), before)

    def test_result_objects_cannot_replace_dataset_reference(self):
        data = dataset()
        benchmark = DetectionBenchmarkResult(data, tuple(DetectionBenchmarkCaseResult(case) for case in data.cases))
        for result in (benchmark, DetectionEvaluationResult((), ()), DetectionMetrics(0, 0, 0, 0), DetectionPipelineResult((), ())):
            with self.assertRaisesRegex(TypeError, 'dataset must be exactly a DetectionDataset'):
                experiment(result)

    def test_definition_contains_only_explicit_reproducibility_inputs(self):
        value = experiment()
        self.assertEqual(tuple(field.name for field in fields(value)),
                         ('experiment_id', 'dataset', 'benchmark_operation_id', 'benchmark_operation_version'))
        self.assertFalse(callable(value))

    def test_construction_and_inspection_do_not_execute_or_access_external_state(self):
        data = dataset()
        targets = (
            'application.detection_benchmark.run_detection_benchmark',
            'application.detection_evaluation.evaluate_detection_result', 'application.detection_metrics.calculate_detection_metrics',
            'application.detection_pipeline.run_detection_pipeline', 'application.detection_session.DetectionSession.__post_init__',
            'application.capture_execution.run_capture_execution', 'application.flow_observation_session.run_flow_observation_session',
            'application.ground_truth.GroundTruthRecord.__post_init__', 'application.ground_truth.GroundTruth.__post_init__',
            'application.detection_dataset.DetectionDataset.__post_init__',
            'application.detector_orchestration.run_packet_detectors', 'application.detector_orchestration.run_closed_flow_detectors',
            'analysis.packet_analysis.analyze_packet', 'analysis.packet_analysis_outcome.analyze_packet_outcome',
            'analysis.flow_feature_snapshot.extract_flow_feature_snapshot', 'analysis.ipv6.decode_ipv6',
            'detection.packet_integrity.evaluate_packet_integrity', 'detection.flow_volume_threshold.evaluate_flow_volume_threshold',
            'detection.tcp_control_threshold.evaluate_tcp_control_threshold', 'capture.packet_ingestion.consume',
            'capture.pcap_packet_source.PcapPacketSource.start', 'builtins.open', 'pathlib.Path.open', 'pathlib.Path.stat',
            'pathlib.Path.iterdir', 'pathlib.Path.write_text', 'socket.socket', 'socket.gethostname', 'os.getpid',
            'time.time', 'time.monotonic', 'time.perf_counter', 'random.random', 'uuid.uuid4', 'sqlite3.connect',
            'threading.Thread.start', 'multiprocessing.Process.start',
        )
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(target, side_effect=AssertionError(target))) for target in targets]
            guards.append(stack.enter_context(patch('capture.packet_observation.PacketObservation.raw_bytes',
                          new_callable=PropertyMock, create=True, side_effect=AssertionError('raw bytes'))))
            first = DetectionExperiment('id', data, 'operation', '1')
            second = DetectionExperiment('id', data, 'operation', '1')
            self.assertEqual(first, second)
            self.assertEqual(first.dataset.name, 'study')
            self.assertEqual(first.benchmark_operation_id, 'operation')
            self.assertEqual(first.benchmark_operation_version, '1')
            for guard in guards:
                guard.assert_not_called()
        self.assertIs(first.dataset, data)

    def test_public_export_resolves(self):
        self.assertIn('DetectionExperiment', application.__all__)
        self.assertIs(application.DetectionExperiment, DetectionExperiment)


if __name__ == '__main__':
    unittest.main()
