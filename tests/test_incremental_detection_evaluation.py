import gc
import inspect
from itertools import product
import unittest
import weakref
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import patch

import application
from analysis import extract_flow_feature_snapshot
from application import (
    DetectionClassification as C, DetectionEvaluationEntry, DetectionEvaluationResult,
    DetectionPipelineResult, ExpectedDetection, ExpectedDetectionResult, FlowDetectionIdentity, GroundTruth,
    GroundTruthPolarity, GroundTruthRecord, IncrementalDetectionEvaluator,
    calculate_detection_metrics, detection_identity, evaluate_detection_result,
)
from application import incremental_detection_evaluation as incremental
from detection import DetectionFinding, FlowVolumeThresholdDecision, FlowVolumeThresholdInterpretation, PacketIntegrityDecision
from tests.test_detection_evaluation import (
    AlternateHashAddress, UnhashableAddress, UnindexableAddress, expected, flow_finding,
    flow_finding_with_address_type, packet_finding,
)


def flow_variants():
    yes, no = flow_finding(), flow_finding(positive=False)
    unavailable = replace(yes, decision=FlowVolumeThresholdDecision.NOT_EVALUABLE,
                          security_interpretation=FlowVolumeThresholdInterpretation.METRIC_NOT_EVALUABLE)
    return yes, no, unavailable


def evaluator(expectations=None, packets=None, flows=None):
    return IncrementalDetectionEvaluator(
        ExpectedDetectionResult((), ()) if expectations is None else expectations,
        packet_evaluation_consumer=(lambda entry: None) if packets is None else packets.append,
        flow_evaluation_consumer=(lambda entry: None) if flows is None else flows.append,
    )


def incrementally(packets=(), flows=(), expectations=None):
    expected_result = ExpectedDetectionResult((), ()) if expectations is None else expectations
    packet_entries, flow_entries = [], []
    owner = evaluator(expected_result, packet_entries, flow_entries)
    for finding in packets:
        owner.record_packet(finding)
    for finding in flows:
        owner.record_flow(finding)
    owner.finish()
    return DetectionEvaluationResult(tuple(packet_entries), tuple(flow_entries))


class IncrementalDetectionEvaluationTests(unittest.TestCase):
    def assert_equivalent(self, packets=(), flows=(), expectations=None):
        expected_result = ExpectedDetectionResult((), ()) if expectations is None else expectations
        baseline = evaluate_detection_result(DetectionPipelineResult(tuple(packets), tuple(flows)), expected_result)
        result = incrementally(packets, flows, expected_result)
        self.assertEqual(result, baseline)
        self.assertEqual(calculate_detection_metrics(result), calculate_detection_metrics(baseline))
        for entries, originals in ((result.packet_evaluations, packets), (result.flow_evaluations, flows)):
            for entry, original in zip(entries, originals):
                self.assertIs(entry.finding, original)
        return result

    def test_public_signatures_existing_types_and_required_consumers(self):
        self.assertIs(application.IncrementalDetectionEvaluator, incremental.IncrementalDetectionEvaluator)
        self.assertIn('IncrementalDetectionEvaluator', application.__all__)
        self.assertEqual(tuple(inspect.signature(IncrementalDetectionEvaluator).parameters),
                         ('expected', 'packet_evaluation_consumer', 'flow_evaluation_consumer'))
        for method in ('record_packet', 'record_flow', 'finish', 'abort'):
            self.assertIsNone(inspect.signature(getattr(IncrementalDetectionEvaluator, method)).return_annotation)
        self.assertEqual(tuple(inspect.signature(evaluate_detection_result).parameters), ('actual', 'expected'))
        self.assertIs(inspect.signature(evaluate_detection_result).return_annotation, DetectionEvaluationResult)
        self.assertEqual(tuple(f.name for f in fields(DetectionFinding)),
                         ('detector_id', 'detector_version', 'decision', 'raw_evidence', 'security_interpretation'))
        self.assertEqual(tuple(f.name for f in fields(DetectionEvaluationEntry)),
                         ('classification', 'expectation_index', 'expectation', 'actual_index', 'finding'))
        with self.assertRaises(TypeError):
            IncrementalDetectionEvaluator(ExpectedDetectionResult((), ()))

    def test_empty_stream_and_repeated_successful_finalization(self):
        packets, flows = [], []
        owner = evaluator(packets=packets, flows=flows)
        self.assertFalse(owner.finished)
        self.assertEqual(owner.pending_flow_count, 0)
        self.assertIsNone(owner.finish())
        self.assertTrue(owner.finished)
        self.assertIsNone(owner.finish())
        self.assertEqual((packets, flows), ([], []))
        self.assert_equivalent()
        with self.assertRaises(ValueError):
            owner.record_packet(packet_finding())
        with self.assertRaises(ValueError):
            owner.abort()

    def test_all_packet_decisions_and_polarities_deliver_immediately(self):
        for decision, positive in product(PacketIntegrityDecision, (True, False)):
            finding = packet_finding(decision)
            expectation = expected(finding, positive, 0)
            expectations = ExpectedDetectionResult((expectation,), ())
            entries = []
            owner = evaluator(expectations, entries)
            owner.record_packet(finding)
            self.assertEqual(len(entries), 1)
            self.assertIs(entries[0].finding, finding)
            self.assertIs(entries[0].expectation, expectation)
            self.assertFalse(owner.finished)
            owner.finish()
            self.assertEqual(tuple(entries), self.assert_equivalent((finding,), expectations=expectations).packet_evaluations)
            if decision is PacketIntegrityDecision.NOT_EVALUABLE:
                self.assertIs(entries[0].classification, C.FALSE_NEGATIVE if positive else None)

    def test_no_expectations_preserves_all_findings_and_unclassified_entries(self):
        packets = tuple(packet_finding(decision) for decision in PacketIntegrityDecision)
        flows = flow_variants()
        result = self.assert_equivalent(packets, flows)
        self.assertEqual([entry.classification for entry in result.flow_evaluations], [C.FALSE_POSITIVE, None, None])

    def test_missing_expectations_are_emitted_only_at_finish_in_original_order(self):
        packet = packet_finding()
        yes, no, _ = flow_variants()
        expectations = ExpectedDetectionResult((expected(packet, False, 4), expected(packet, True, 0)),
                                              (expected(yes),))
        packets, flows = [], []
        owner = evaluator(expectations, packets, flows)
        self.assertEqual((packets, flows), ([], []))
        owner.finish()
        result = self.assert_equivalent(expectations=expectations)
        self.assertEqual(tuple(packets), result.packet_evaluations)
        self.assertEqual(tuple(flows), result.flow_evaluations)
        self.assertEqual([entry.expectation_index for entry in packets], [0, 1])
        self.assertEqual([entry.classification for entry in packets], [None, C.FALSE_NEGATIVE])

    def test_duplicate_packet_findings_have_distinct_positions_and_expectation_multiplicity(self):
        finding = packet_finding(PacketIntegrityDecision.NOT_EVALUABLE)
        expectation = expected(finding, True, 0)
        expectations = ExpectedDetectionResult((expectation, expectation, expected(finding, False, 1)), ())
        result = self.assert_equivalent((finding, finding), expectations=expectations)
        self.assertEqual([entry.actual_index for entry in result.packet_evaluations], [0, 1, None])
        self.assertEqual([entry.expectation_index for entry in result.packet_evaluations], [0, 2, 1])

    def test_later_required_flow_decision_displaces_earlier_opposite_without_reordering(self):
        yes, no, _ = flow_variants()
        for findings, positive in (((no, yes), True), ((yes, no), False)):
            entries = []
            expectations = ExpectedDetectionResult((), (expected(yes, positive),))
            owner = evaluator(expectations, flows=entries)
            owner.record_flow(findings[0])
            self.assertEqual(owner.pending_flow_count, 1)
            self.assertEqual(entries, [])
            owner.record_flow(findings[1])
            self.assertEqual(owner.pending_flow_count, 2)
            self.assertEqual(entries, [])
            owner.finish()
            self.assertEqual(owner.pending_flow_count, 0)
            self.assertIsNone(entries[0].expectation)
            self.assertEqual(entries[1].expectation_index, 0)
            self.assertEqual(tuple(entries), self.assert_equivalent(flows=findings, expectations=expectations).flow_evaluations)

    def test_required_prefix_is_delivered_and_deferred_suffix_preserves_global_indices(self):
        yes, no, unavailable = flow_variants()
        expectation = expected(yes)
        expectations = ExpectedDetectionResult((), (expectation, expectation, expectation))
        flows = []
        owner = evaluator(expectations, flows=flows)
        owner.record_flow(yes)
        self.assertEqual([(entry.actual_index, entry.expectation_index) for entry in flows], [(0, 0)])
        for finding in (unavailable, no, yes):
            owner.record_flow(finding)
        self.assertEqual(len(flows), 1)
        owner.finish()
        result = self.assert_equivalent(flows=(yes, unavailable, no, yes), expectations=expectations)
        self.assertEqual(tuple(flows), result.flow_evaluations)
        self.assertEqual([entry.expectation_index for entry in flows], [0, None, 2, 1])

    def test_exhaustive_short_flow_sequences_match_historical_priority_and_multiplicity(self):
        variants = flow_variants()
        for length in range(5):
            for sequence in product(range(3), repeat=length):
                findings = tuple(variants[index] for index in sequence)
                for positive, count in product((True, False), (0, 1, 2, 4, 5)):
                    expectation = expected(variants[0], positive)
                    expectations = ExpectedDetectionResult((), (expectation,) * count)
                    with self.subTest(sequence=sequence, positive=positive, count=count):
                        result = self.assert_equivalent(flows=findings, expectations=expectations)
                        priority = ('match', 'no_match', 'not_evaluable') if positive else ('no_match', 'match', 'not_evaluable')
                        order = [index for decision in priority for index, finding in enumerate(findings)
                                 if finding.decision.value == decision]
                        assignments = {actual: index for index, actual in enumerate(order[:count])}
                        self.assertEqual([entry.expectation_index for entry in result.flow_evaluations[:length]],
                                         [assignments.get(index) for index in range(length)])

    def test_address_subclass_equality_fallback_and_late_unindexable_inputs(self):
        variants = flow_variants()
        for address_type in (UnhashableAddress, UnindexableAddress, AlternateHashAddress):
            for name in ('source_address', 'destination_address'):
                for positive in (True, False):
                    first = variants[0 if positive else 1]
                    custom = flow_finding_with_address_type(variants[2], address_type, name)
                    findings = (first, custom, variants[1], variants[0])
                    expectations = ExpectedDetectionResult((), (expected(first, positive),) * 3)
                    self.assert_equivalent(flows=findings, expectations=expectations)
        custom = flow_finding_with_address_type(variants[0], AlternateHashAddress)
        expectations = ExpectedDetectionResult((), (expected(custom), expected(variants[0]), expected(custom)))
        self.assert_equivalent(flows=(variants[0], variants[1], variants[0]), expectations=expectations)
        for positive in (True, False):
            targets = (expected(custom, positive), expected(variants[0], not positive))
            self.assertEqual(targets[0].identity, targets[1].identity)
            for ordered in (targets, tuple(reversed(targets))):
                expectations = ExpectedDetectionResult((), ordered)
                for findings in product(variants, repeat=3):
                    self.assert_equivalent(flows=findings, expectations=expectations)

    def test_distinct_detector_ids_versions_and_window_targets_never_share_assignments(self):
        variants = []
        for detector_id, version in (('one', '1'), ('two', '1'), ('one', '2')):
            base = flow_finding()
            configuration = replace(base.raw_evidence.configuration, detector_id=detector_id, detector_version=version)
            variants.append(flow_finding(configuration=configuration))
        targets = tuple(expected(finding) for finding in reversed(variants))
        result = self.assert_equivalent(flows=tuple(variants), expectations=ExpectedDetectionResult((), targets))
        self.assertEqual([entry.expectation_index for entry in result.flow_evaluations], [2, 1, 0])

    def test_channel_interleaving_preserves_independent_indices_and_all_classifications(self):
        packets = (packet_finding(), packet_finding(PacketIntegrityDecision.NO_MATCH))
        yes, no, _ = flow_variants()
        expectations = ExpectedDetectionResult((expected(packets[0], index=0), expected(packets[1], False, 1)),
                                              (expected(yes), expected(yes)))
        results = []
        for order in (('p', 'f', 'p', 'f', 'f'), ('f', 'f', 'p', 'f', 'p')):
            packet_entries, flow_entries = [], []
            owner = evaluator(expectations, packet_entries, flow_entries)
            channels = {'p': iter(packets), 'f': iter((yes, no, yes))}
            for channel in order:
                (owner.record_packet if channel == 'p' else owner.record_flow)(next(channels[channel]))
            owner.finish()
            results.append(DetectionEvaluationResult(tuple(packet_entries), tuple(flow_entries)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], self.assert_equivalent(packets, (yes, no, yes), expectations))

    def test_settled_findings_and_evidence_are_released_without_consumer_retention(self):
        refs = []
        seed = flow_finding()
        expectations = ExpectedDetectionResult((), (expected(seed),))
        owner = evaluator(expectations)
        for _ in range(64):
            finding = flow_finding()
            refs.extend((weakref.ref(finding), weakref.ref(finding.raw_evidence.observation_window)))
            owner.record_flow(finding)
            self.assertEqual(owner.pending_flow_count, 0)
            del finding
        gc.collect()
        self.assertTrue(all(reference() is None for reference in refs))
        owner.finish()

    def test_ordinary_expectation_lookup_work_is_linear_for_reversed_and_disjoint_targets(self):
        base = flow_finding()
        for count in (64, 128):
            findings = []
            for index in range(count):
                window = base.raw_evidence.observation_window
                window = replace(window, key=replace(window.key, sequence_number=index))
                findings.append(replace(base, raw_evidence=replace(
                    base.raw_evidence, snapshot=extract_flow_feature_snapshot(window))))
            for disjoint in (False, True):
                expectations = tuple(expected(finding) for finding in reversed(findings))
                if disjoint:
                    expectations = tuple(replace(item, identity=replace(item.identity, configuration=replace(
                        item.identity.configuration, detector_version='absent'))) for item in expectations)
                targets = ExpectedDetectionResult((), expectations)
                original = FlowDetectionIdentity.__hash__
                calls = []

                def hashed(identity):
                    calls.append(None)
                    return original(identity)

                with patch.object(FlowDetectionIdentity, '__hash__', hashed):
                    owner = evaluator(targets)
                    for finding in findings:
                        owner.record_flow(finding)
                    owner.finish()
                self.assertLessEqual(len(calls), 12 * count)

    def test_deferred_suffix_retention_is_explicit_and_released_on_finish_or_abort(self):
        yes, no, _ = flow_variants()
        expectations = ExpectedDetectionResult((), (expected(yes),))
        for complete in (True, False):
            owner = evaluator(expectations)
            owner.record_flow(no)
            refs = []
            for index in range(32):
                finding = flow_finding()
                window = finding.raw_evidence.observation_window
                window = replace(window, key=replace(window.key, sequence_number=index + 1))
                finding = replace(finding, raw_evidence=replace(finding.raw_evidence, snapshot=extract_flow_feature_snapshot(window)))
                refs.append(weakref.ref(finding))
                owner.record_flow(finding)
            del finding, window
            gc.collect()
            self.assertEqual(owner.pending_flow_count, 33)
            self.assertTrue(all(reference() is not None for reference in refs))
            (owner.finish if complete else owner.abort)()
            gc.collect()
            self.assertEqual(owner.pending_flow_count, 0)
            self.assertTrue(all(reference() is None for reference in refs))

    def test_caller_retention_preserves_exact_immutable_entries_and_expectations(self):
        finding = flow_finding()
        expectation = expected(finding)
        entries = []
        owner = evaluator(ExpectedDetectionResult((), (expectation,)), flows=entries)
        owner.record_flow(finding)
        owner.finish()
        self.assertIs(entries[0].finding, finding)
        self.assertIs(entries[0].expectation, expectation)
        with self.assertRaises(FrozenInstanceError):
            entries[0].actual_index = 9

    def test_invalid_expectations_consumers_and_truth_keep_existing_validation(self):
        for invalid in (None, (), [], GroundTruth((), ())):
            with self.assertRaises(TypeError):
                evaluator(invalid if invalid is not None else [])
        for channel in ('packet_evaluation_consumer', 'flow_evaluation_consumer'):
            with self.assertRaises(TypeError):
                IncrementalDetectionEvaluator(ExpectedDetectionResult((), ()), **dict(
                    {'packet_evaluation_consumer': lambda e: None, 'flow_evaluation_consumer': lambda e: None},
                    **{channel: None},
                ))
        expectation = expected(flow_finding())
        with self.assertRaises(ValueError):
            ExpectedDetectionResult((), (expectation, replace(expectation, positive=False)))
        record = GroundTruthRecord(expectation.identity, GroundTruthPolarity.POSITIVE)
        with self.assertRaises(ValueError):
            GroundTruth((), (record, record))
        with self.assertRaises(TypeError):
            GroundTruthRecord(expectation.identity, True)

    def test_invalid_finding_and_wrong_channel_make_evaluator_terminal(self):
        for finding, packet, error in ((None, True, TypeError), (object(), False, TypeError),
                                       (flow_finding(), True, ValueError), (packet_finding(), False, ValueError)):
            owner = evaluator()
            with self.assertRaises(error):
                (owner.record_packet if packet else owner.record_flow)(finding)
            self.assertFalse(owner.finished)
            with self.assertRaises(ValueError):
                owner.finish()
            with self.assertRaises(ValueError):
                owner.record_flow(flow_finding())
            owner.abort()
            owner.abort()

    def test_consumer_failure_is_terminal_preserves_exception_and_has_no_retry(self):
        for error in (RuntimeError('consumer'), MemoryError('consumer'), KeyboardInterrupt()):
            attempted = []

            def fail(entry):
                attempted.append(entry)
                raise error

            owner = IncrementalDetectionEvaluator(ExpectedDetectionResult((), ()),
                                                  packet_evaluation_consumer=fail, flow_evaluation_consumer=fail)
            with self.assertRaises(type(error)) as caught:
                owner.record_packet(packet_finding())
            self.assertIs(caught.exception, error)
            with self.assertRaises(ValueError):
                owner.finish()
            self.assertEqual(len(attempted), 1)

    def test_entry_construction_and_matching_failures_release_pending_state(self):
        for target in ('DetectionEvaluationEntry', '_match_findings'):
            yes, no, _ = flow_variants()
            owner = evaluator(ExpectedDetectionResult((), (expected(yes),)))
            owner.record_flow(no)
            error = MemoryError('finalization')
            with patch.object(incremental, target, side_effect=error):
                with self.assertRaises(MemoryError) as caught:
                    owner.finish()
            self.assertIs(caught.exception, error)
            self.assertEqual(owner.pending_flow_count, 0)
            self.assertFalse(owner.finished)
            with self.assertRaises(ValueError):
                owner.finish()

    def test_finish_consumer_failure_preserves_partial_output_without_false_completion(self):
        yes, no, _ = flow_variants()
        attempted = []

        def fail(entry):
            attempted.append(entry)
            self.assertEqual(owner.pending_flow_count, 1)
            raise RuntimeError('final output')

        owner = IncrementalDetectionEvaluator(ExpectedDetectionResult((), (expected(yes),)),
                                              packet_evaluation_consumer=self.fail, flow_evaluation_consumer=fail)
        owner.record_flow(no)
        owner.record_flow(yes)
        with self.assertRaises(RuntimeError):
            owner.finish()
        self.assertFalse(owner.finished)
        self.assertEqual(owner.pending_flow_count, 0)
        self.assertEqual(len(attempted), 1)
        with self.assertRaises(ValueError):
            owner.finish()

    def test_abort_emits_no_missing_expectations_and_prevents_later_completion(self):
        entries = []
        owner = evaluator(ExpectedDetectionResult((expected(packet_finding(), index=0),), ()), entries)
        owner.abort()
        owner.abort()
        self.assertEqual(entries, [])
        self.assertFalse(owner.finished)
        with self.assertRaises(ValueError):
            owner.finish()

    def test_reentrant_consumption_finalization_and_abort_are_rejected(self):
        for operation in ('finish', 'abort', 'record_packet'):
            finding = packet_finding()

            def receive(entry):
                if operation == 'record_packet':
                    owner.record_packet(finding)
                else:
                    getattr(owner, operation)()

            owner = IncrementalDetectionEvaluator(ExpectedDetectionResult((), ()),
                                                  packet_evaluation_consumer=receive, flow_evaluation_consumer=self.fail)
            with self.assertRaises(ValueError):
                owner.record_packet(finding)
            with self.assertRaises(ValueError):
                owner.finish()
