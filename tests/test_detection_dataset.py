import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from unittest.mock import PropertyMock, patch

import application
from application import (
    DetectionDataset,
    DetectionDatasetCase,
    DetectionPipelineResult,
    ExpectedDetection,
    FlowDetectionIdentity,
    GroundTruth,
    GroundTruthPolarity,
    GroundTruthRecord,
    PacketDetectionIdentity,
)
from tests.test_ground_truth import flow_target, negative, packet_target, positive


class DetectionDatasetTests(unittest.TestCase):
    def test_named_dataset_retains_supplied_cases(self):
        case = DetectionDatasetCase('packet-a', packet_target())
        cases = (case,)
        dataset = DetectionDataset('integrity-study', cases)
        self.assertEqual(dataset.name, 'integrity-study')
        self.assertIs(dataset.cases, cases)
        self.assertIs(dataset.cases[0], case)

    def test_empty_dataset_is_valid_and_preserves_name(self):
        dataset = DetectionDataset('empty-study', ())
        self.assertEqual((dataset.name, dataset.cases), ('empty-study', ()))
        self.assertEqual(len(dataset.cases), 0)

    def test_dataset_name_must_be_explicit(self):
        with self.assertRaises(TypeError):
            DetectionDataset(cases=())

    def test_dataset_name_rejects_empty_and_whitespace(self):
        for name in ('', ' ', '\t\n'):
            with self.assertRaisesRegex(ValueError, 'name must not be blank'):
                DetectionDataset(name, ())

    def test_dataset_name_rejects_non_strings_without_coercion(self):
        for name in (None, 1, True, b'study', Path('study')):
            with self.assertRaisesRegex(TypeError, 'name must be exactly a string'):
                DetectionDataset(name, ())

    def test_dataset_name_is_preserved_without_normalization(self):
        name = ' Étude Alpha '
        self.assertEqual(DetectionDataset(name, ()).name, name)
        self.assertNotEqual(DetectionDataset(name, ()), DetectionDataset(name.strip(), ()))

    def test_dataset_identity_participates_in_equality(self):
        cases = (DetectionDatasetCase('case', packet_target()),)
        self.assertNotEqual(DetectionDataset('first', cases), DetectionDataset('second', cases))

    def test_case_identity_is_explicit_and_retained(self):
        target = flow_target()
        case = DetectionDatasetCase('flow-a', target)
        self.assertEqual(case.case_id, 'flow-a')
        self.assertIs(case.target, target)
        with self.assertRaises(TypeError):
            DetectionDatasetCase(target=target)

    def test_case_identity_rejects_empty_and_whitespace(self):
        for name in ('', ' ', '\t\n'):
            with self.assertRaisesRegex(ValueError, 'case_id must not be blank'):
                DetectionDatasetCase(name, packet_target())

    def test_case_identity_rejects_non_strings_without_coercion(self):
        for name in (None, 1, True, b'case', Path('case')):
            with self.assertRaisesRegex(TypeError, 'case_id must be exactly a string'):
                DetectionDatasetCase(name, packet_target())

    def test_case_identity_preserves_case_and_whitespace(self):
        target = packet_target()
        cases = tuple(DetectionDatasetCase(name, target) for name in ('A', 'a', ' a '))
        self.assertEqual(tuple(case.case_id for case in DetectionDataset('study', cases).cases), ('A', 'a', ' a '))

    def test_case_identity_participates_in_equality(self):
        target = packet_target()
        self.assertNotEqual(DetectionDatasetCase('first', target), DetectionDatasetCase('second', target))

    def test_dataset_keeps_caller_order_instead_of_sorting_ids_or_targets(self):
        cases = tuple(DetectionDatasetCase(name, packet_target(packet_index=index)) for name, index in
                      (('z', 4), ('a', 0), ('m', 2)))
        dataset = DetectionDataset('ordered', cases)
        self.assertEqual(tuple(case.case_id for case in dataset.cases), ('z', 'a', 'm'))
        self.assertEqual(tuple(case.target.packet_index for case in dataset.cases), (4, 0, 2))

    def test_reversing_case_order_changes_dataset_value(self):
        cases = (DetectionDatasetCase('a', packet_target()), DetectionDatasetCase('b', flow_target()))
        self.assertNotEqual(DetectionDataset('study', cases), DetectionDataset('study', tuple(reversed(cases))))

    def test_duplicate_same_case_is_rejected_without_deduplication(self):
        case = DetectionDatasetCase('same', packet_target())
        cases = (case, case)
        with self.assertRaisesRegex(ValueError, 'duplicate case_id'):
            DetectionDataset('study', cases)
        self.assertEqual(cases, (case, case))

    def test_equal_independent_case_ids_are_duplicates(self):
        cases = (DetectionDatasetCase('same', packet_target()), DetectionDatasetCase(''.join(('sa', 'me')), packet_target()))
        with self.assertRaisesRegex(ValueError, 'duplicate case_id'):
            DetectionDataset('study', cases)

    def test_duplicate_id_with_different_truth_cannot_overwrite(self):
        target = packet_target()
        first = DetectionDatasetCase('same', target, positive(target))
        second = DetectionDatasetCase('same', target, negative(target))
        for cases in ((first, second), (second, first)):
            with self.assertRaisesRegex(ValueError, 'duplicate case_id'):
                DetectionDataset('study', cases)
        self.assertIs(first.ground_truth.polarity, GroundTruthPolarity.POSITIVE)
        self.assertIs(second.ground_truth.polarity, GroundTruthPolarity.NEGATIVE)

    def test_duplicate_ids_are_rejected_across_packet_flow_domains(self):
        cases = (DetectionDatasetCase('same', packet_target()), DetectionDatasetCase('same', flow_target()))
        with self.assertRaisesRegex(ValueError, 'duplicate case_id'):
            DetectionDataset('study', cases)

    def test_distinct_case_ids_can_retain_equal_targets_without_merging(self):
        target = flow_target()
        truth = positive(target)
        cases = (DetectionDatasetCase('first', target, truth), DetectionDatasetCase('second', target, truth))
        self.assertEqual(DetectionDataset('study', cases).cases, cases)
        self.assertEqual(len(cases), 2)

    def test_case_identity_uniqueness_is_local_to_each_dataset(self):
        case = DetectionDatasetCase('case', packet_target())
        first = DetectionDataset('one', (case,))
        second = DetectionDataset('two', (case,))
        self.assertIs(first.cases[0], second.cases[0])

    def test_mutable_case_collections_are_rejected_without_mutation(self):
        case = DetectionDatasetCase('case', packet_target())
        cases = [case]
        with self.assertRaisesRegex(TypeError, 'cases must be exactly a tuple'):
            DetectionDataset('study', cases)
        self.assertEqual(cases, [case])
        dataset = DetectionDataset('study', tuple(cases))
        cases.clear()
        self.assertEqual(dataset.cases, (case,))

    def test_unordered_and_non_collection_inputs_are_rejected(self):
        case = DetectionDatasetCase('case', packet_target())
        for cases in ({case}, {'case': case}, 'case', None, iter((case,))):
            with self.assertRaisesRegex(TypeError, 'cases must be exactly a tuple'):
                DetectionDataset('study', cases)

    def test_malformed_case_elements_are_rejected(self):
        for case in (None, 'case', packet_target(), positive(packet_target()), {'case_id': 'case'}):
            with self.assertRaisesRegex(TypeError, 'cases must contain exactly DetectionDatasetCase'):
                DetectionDataset('study', (case,))

    def test_dataset_is_frozen(self):
        dataset = DetectionDataset('study', ())
        for name, value in (('name', 'other'), ('cases', ())):
            with self.assertRaises(FrozenInstanceError):
                setattr(dataset, name, value)

    def test_case_is_frozen(self):
        target = packet_target()
        case = DetectionDatasetCase('case', target, positive(target))
        for name, value in (('case_id', 'other'), ('target', flow_target()), ('ground_truth', None)):
            with self.assertRaises(FrozenInstanceError):
                setattr(case, name, value)

    def test_internal_tuple_cannot_be_modified(self):
        case = DetectionDatasetCase('case', packet_target())
        dataset = DetectionDataset('study', (case,))
        with self.assertRaises(TypeError):
            dataset.cases[0] = case
        with self.assertRaises(AttributeError):
            dataset.cases.append(case)

    def test_packet_case_preserves_existing_metadata_identity(self):
        target = packet_target(packet_index=7, link_type=None, original_length=None)
        case = DetectionDatasetCase('packet', target)
        self.assertIs(type(case.target), PacketDetectionIdentity)
        self.assertEqual((case.target.packet_index, case.target.link_type, case.target.original_length), (7, None, None))
        self.assertIs(case.target.captured_at, target.captured_at)

    def test_flow_case_preserves_existing_window_identity(self):
        target = flow_target()
        case = DetectionDatasetCase('flow', target, positive(target))
        self.assertIs(type(case.target), FlowDetectionIdentity)
        self.assertIs(case.target.window_key, target.window_key)
        self.assertIs(case.target.flow_identity, target.flow_identity)

    def test_ipv4_ipv6_tcp_udp_targets_remain_typed_and_exact(self):
        cases = tuple(DetectionDatasetCase(f'{family}-{protocol}', flow_target(protocol, ipv6=family == 6))
                      for family in (4, 6) for protocol in (6, 17))
        dataset = DetectionDataset('flows', cases)
        self.assertEqual(tuple((case.target.flow_identity.ip_version, case.target.flow_identity.protocol)
                               for case in dataset.cases), ((4, 6), (4, 17), (6, 6), (6, 17)))
        self.assertEqual(tuple(len(case.target.flow_identity.source_address) for case in dataset.cases), (4, 4, 16, 16))

    def test_mixed_domain_dataset_retains_domain_at_each_position(self):
        cases = (DetectionDatasetCase('flow', flow_target()), DetectionDatasetCase('packet', packet_target()))
        dataset = DetectionDataset('mixed', cases)
        self.assertEqual(tuple(type(case.target) for case in dataset.cases), (FlowDetectionIdentity, PacketDetectionIdentity))
        self.assertNotEqual(cases[0].target, cases[1].target)

    def test_supplied_positive_truth_is_preserved_by_reference(self):
        target = packet_target()
        truth = GroundTruth((positive(target),), ())
        case = DetectionDatasetCase('packet', target, truth.packet_records[0])
        self.assertIs(case.ground_truth, truth.packet_records[0])
        self.assertIs(case.ground_truth.polarity, GroundTruthPolarity.POSITIVE)

    def test_supplied_negative_truth_is_preserved_by_reference(self):
        target = flow_target()
        truth = GroundTruth((), (negative(target),))
        case = DetectionDatasetCase('flow', target, truth.flow_records[0])
        self.assertIs(case.ground_truth, truth.flow_records[0])
        self.assertIs(case.ground_truth.polarity, GroundTruthPolarity.NEGATIVE)

    def test_missing_truth_is_unlabeled_not_negative(self):
        target = packet_target()
        missing = DetectionDatasetCase('case', target)
        explicit = DetectionDatasetCase('case', target, negative(target))
        self.assertIsNone(missing.ground_truth)
        self.assertNotEqual(missing, explicit)
        self.assertEqual(missing, DetectionDatasetCase('case', target, None))

    def test_partial_truth_does_not_label_other_cases(self):
        target = packet_target()
        cases = (DetectionDatasetCase('labeled', target, positive(target)), DetectionDatasetCase('unlabeled', flow_target()))
        dataset = DetectionDataset('partial', cases)
        self.assertIs(dataset.cases[0].ground_truth.polarity, GroundTruthPolarity.POSITIVE)
        self.assertIsNone(dataset.cases[1].ground_truth)

    def test_equivalent_independent_truth_target_is_accepted(self):
        target = packet_target()
        truth = positive(packet_target())
        case = DetectionDatasetCase('case', target, truth)
        self.assertIsNot(case.target, truth.target)
        self.assertIs(case.ground_truth, truth)
        self.assertEqual(case.target, truth.target)

    def test_packet_truth_cannot_describe_flow_case_or_reverse(self):
        packet, flow = packet_target(), flow_target()
        for target, truth in ((packet, positive(flow)), (flow, positive(packet))):
            with self.assertRaisesRegex(ValueError, 'ground_truth target must equal case target'):
                DetectionDatasetCase('case', target, truth)

    def test_unrelated_packet_truth_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'ground_truth target must equal case target'):
            DetectionDatasetCase('case', packet_target(), positive(packet_target(packet_index=1)))

    def test_unrelated_flow_window_truth_is_rejected(self):
        target = flow_target()
        other = replace(target, window_key=replace(target.window_key, sequence_number=1))
        with self.assertRaisesRegex(ValueError, 'ground_truth target must equal case target'):
            DetectionDatasetCase('case', target, positive(other))

    def test_detector_configuration_remains_part_of_target_alignment(self):
        target = packet_target()
        for config in (replace(target.configuration, detector_id='other'), replace(target.configuration, detector_version='2')):
            with self.assertRaisesRegex(ValueError, 'ground_truth target must equal case target'):
                DetectionDatasetCase('case', target, positive(replace(target, configuration=config)))

    def test_invalid_truth_objects_are_not_coerced(self):
        target = packet_target()
        for truth in (True, False, 'positive', GroundTruth((), ()), ExpectedDetection(target, True), (positive(target),)):
            with self.assertRaisesRegex(TypeError, 'ground_truth must be exactly a GroundTruthRecord or None'):
                DetectionDatasetCase('case', target, truth)

    def test_missing_and_invalid_target_rejected(self):
        with self.assertRaises(TypeError):
            DetectionDatasetCase('case')
        for target in (None, {}, 'packet', positive(packet_target()), DetectionPipelineResult((), ())):
            with self.assertRaisesRegex(TypeError, 'target must be exactly a packet or flow detection identity'):
                DetectionDatasetCase('case', target)

    def test_repeated_independent_construction_has_no_shared_state(self):
        def construct():
            target = packet_target()
            return DetectionDataset('study', (DetectionDatasetCase('case', target, positive(target)),))
        first = construct()
        for _ in range(3):
            DetectionDataset('unrelated', ())
            other = construct()
            self.assertEqual(first, other)
            self.assertIsNot(first.cases[0], other.cases[0])
            self.assertEqual(tuple(case.case_id for case in other.cases), ('case',))

    def test_nested_immutable_inputs_are_retained_unchanged(self):
        target = flow_target(6, ipv6=True)
        truth = positive(target)
        before = positive(flow_target(6, ipv6=True))
        dataset = DetectionDataset('study', (DetectionDatasetCase('case', target, truth),))
        self.assertEqual(truth, before)
        self.assertIs(dataset.cases[0].target.configuration, target.configuration)
        for obj, name, value in ((truth, 'polarity', GroundTruthPolarity.NEGATIVE),
                                  (target, 'window_key', None), (target.configuration, 'threshold', 99)):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, name, value)

    def test_contract_has_no_generated_identity_or_execution_metadata(self):
        self.assertEqual(tuple(field.name for field in fields(DetectionDataset)), ('name', 'cases'))
        self.assertEqual(tuple(field.name for field in fields(DetectionDatasetCase)), ('case_id', 'target', 'ground_truth'))

    def test_construction_executes_no_loading_analysis_evaluation_or_metrics(self):
        target = packet_target()
        truth = positive(target)
        targets = (
            'application.detection_evaluation.evaluate_detection_result',
            'application.detection_metrics.calculate_detection_metrics',
            'application.ground_truth.GroundTruth.__post_init__',
            'application.ground_truth.GroundTruthRecord.__post_init__',
            'application.detection_pipeline.run_detection_pipeline',
            'application.detection_session.DetectionSession.__post_init__',
            'application.capture_execution.run_capture_execution',
            'application.detector_orchestration.run_packet_detectors',
            'application.detector_orchestration.run_closed_flow_detectors',
            'analysis.packet_analysis.analyze_packet',
            'analysis.packet_analysis_outcome.analyze_packet_outcome',
            'analysis.flow_feature_snapshot.extract_flow_feature_snapshot',
            'detection.packet_integrity.evaluate_packet_integrity',
            'detection.flow_volume_threshold.evaluate_flow_volume_threshold',
            'detection.tcp_control_threshold.evaluate_tcp_control_threshold',
            'capture.packet_ingestion.consume', 'capture.pcap_packet_source.PcapPacketSource.start',
            'builtins.open', 'pathlib.Path.open', 'pathlib.Path.stat', 'pathlib.Path.iterdir',
            'socket.socket', 'time.time', 'time.monotonic', 'random.random', 'uuid.uuid4',
        )
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(name, side_effect=AssertionError(name))) for name in targets]
            guards.append(stack.enter_context(patch('capture.packet_observation.PacketObservation.raw_bytes',
                          new_callable=PropertyMock, create=True, side_effect=AssertionError('raw bytes'))))
            dataset = DetectionDataset('study', (DetectionDatasetCase('case', target, truth),))
            for guard in guards:
                guard.assert_not_called()
        self.assertIs(dataset.cases[0].ground_truth, truth)

    def test_public_exports_resolve(self):
        for value in (DetectionDataset, DetectionDatasetCase):
            self.assertIn(value.__name__, application.__all__)
            self.assertIs(getattr(application, value.__name__), value)


if __name__ == '__main__':
    unittest.main()
