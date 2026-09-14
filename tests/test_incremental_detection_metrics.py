from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from fractions import Fraction
import gc
import inspect
from itertools import product
import unittest
from unittest.mock import PropertyMock, patch
import weakref

import application
from application import (
    DetectionClassification as C, DetectionEvaluationEntry, DetectionEvaluationMetrics, DetectionEvaluationResult,
    DetectionMetrics, IncrementalDetectionMetrics, calculate_detection_metrics,
)
from application import detection_metrics, incremental_detection_metrics
from capture import PacketObservation
from detection import DetectionFinding, PacketIntegrityDecision
from tests.test_detection_evaluation import evaluate, expected, flow_finding, packet_finding
from tests.test_incremental_detection_evaluation import flow_variants


def classified_entries(packet):
    yes = packet_finding() if packet else flow_finding()
    no = packet_finding(PacketIntegrityDecision.NO_MATCH) if packet else flow_finding(positive=False)
    entries = []
    for finding, polarity in ((yes, True), (yes, None), (no, True), (no, False), (no, None)):
        expectations = () if polarity is None else (expected(finding, polarity, 0 if packet else None),)
        result = (evaluate(packets=(finding,), packet_expectations=expectations) if packet
                  else evaluate(flows=(finding,), flow_expectations=expectations))
        entries.append((result.packet_evaluations if packet else result.flow_evaluations)[0])
    return tuple(entries)


def accumulated(packets=(), flows=()):
    metrics = IncrementalDetectionMetrics()
    for entry in packets:
        metrics.record_packet(entry)
    for entry in flows:
        metrics.record_flow(entry)
    return metrics.finish()


def ratios(metrics):
    return metrics.precision, metrics.recall, metrics.f1, metrics.accuracy


def seed_counts(owner, counts, packet=True):
    channel = owner._packets if packet else owner._flows
    channel.counts.update(zip((C.TRUE_POSITIVE, C.FALSE_POSITIVE, C.FALSE_NEGATIVE, C.TRUE_NEGATIVE), counts[:4]))
    channel.unclassified = counts[4]


class IncrementalDetectionMetricsTests(unittest.TestCase):
    def test_public_api_existing_result_types_and_field_contracts(self):
        self.assertIs(application.IncrementalDetectionMetrics, incremental_detection_metrics.IncrementalDetectionMetrics)
        self.assertEqual(application.__all__.count('IncrementalDetectionMetrics'), 1)
        self.assertEqual(tuple(inspect.signature(IncrementalDetectionMetrics).parameters), ())
        for name in ('record_packet', 'record_flow', 'abort'):
            self.assertIsNone(inspect.signature(getattr(IncrementalDetectionMetrics, name)).return_annotation)
        self.assertIs(inspect.signature(IncrementalDetectionMetrics.finish).return_annotation, DetectionEvaluationMetrics)
        self.assertEqual(tuple(inspect.signature(calculate_detection_metrics).parameters), ('result',))
        self.assertEqual(tuple(field.name for field in fields(DetectionFinding)),
                         ('detector_id', 'detector_version', 'decision', 'raw_evidence', 'security_interpretation'))
        self.assertEqual(tuple(field.name for field in fields(DetectionEvaluationEntry)),
                         ('classification', 'expectation_index', 'expectation', 'actual_index', 'finding'))
        self.assertEqual(tuple(field.name for field in fields(DetectionMetrics)),
                         ('true_positives', 'false_positives', 'false_negatives', 'true_negatives', 'unclassified_count'))
        owner = IncrementalDetectionMetrics()
        with self.assertRaises(AttributeError):
            owner.finished = True
        with self.assertRaises(TypeError):
            IncrementalDetectionMetrics(initial_counts=(1, 2, 3, 4))

    def test_empty_complete_evaluation_has_undefined_ratios(self):
        owner = IncrementalDetectionMetrics()
        self.assertFalse(owner.finished)
        result = owner.finish()
        self.assertTrue(owner.finished)
        self.assertEqual(result, calculate_detection_metrics(evaluate()))
        self.assertEqual(ratios(result.packet_metrics), (None,) * 4)
        self.assertEqual(ratios(result.flow_metrics), (None,) * 4)
        self.assertIsNot(result.packet_metrics, result.flow_metrics)

    def test_empty_packet_and_empty_flow_channels_are_independent(self):
        packet, flow = classified_entries(True)[0], classified_entries(False)[0]
        self.assertEqual(accumulated((packet,)).flow_metrics, DetectionMetrics(0, 0, 0, 0))
        self.assertEqual(accumulated(flows=(flow,)).packet_metrics, DetectionMetrics(0, 0, 0, 0))

    def test_each_classification_in_each_channel_counts_once(self):
        for packet in (True, False):
            for index, entry in enumerate(classified_entries(packet)):
                result = accumulated((entry,)) if packet else accumulated(flows=(entry,))
                counts = tuple(int(index == position) for position in range(5))
                self.assertEqual(result.packet_metrics if packet else result.flow_metrics, DetectionMetrics(*counts))

    def test_not_evaluable_keeps_positive_false_negative_and_other_unclassified_outcomes(self):
        for packet in (True, False):
            finding = packet_finding(PacketIntegrityDecision.NOT_EVALUABLE) if packet else flow_variants()[2]
            for polarity in (True, False, None):
                targets = () if polarity is None else (expected(finding, polarity, 0 if packet else None),)
                evaluation = (evaluate(packets=(finding,), packet_expectations=targets) if packet
                              else evaluate(flows=(finding,), flow_expectations=targets))
                result = accumulated(evaluation.packet_evaluations, evaluation.flow_evaluations)
                metrics = result.packet_metrics if packet else result.flow_metrics
                self.assertEqual(metrics, DetectionMetrics(0, 0, int(polarity is True), 0, int(polarity is not True)))
                self.assertEqual(result, calculate_detection_metrics(evaluation))

    def test_missing_expectations_count_without_finding_objects(self):
        for packet in (True, False):
            finding = packet_finding() if packet else flow_finding()
            for positive in (True, False):
                target = expected(finding, positive, 7 if packet else None)
                evaluation = evaluate(packet_expectations=(target,)) if packet else evaluate(flow_expectations=(target,))
                result = accumulated(evaluation.packet_evaluations, evaluation.flow_evaluations)
                metrics = result.packet_metrics if packet else result.flow_metrics
                self.assertEqual(metrics, DetectionMetrics(0, 0, int(positive), 0, int(not positive)))

    def test_mixed_counts_and_interleaving_do_not_cross_channels(self):
        owner = IncrementalDetectionMetrics()
        packets, flows = classified_entries(True), classified_entries(False)
        for index in range(5):
            for _ in range(index + 1):
                owner.record_packet(packets[index])
            for _ in range(5 - index):
                owner.record_flow(flows[index])
        self.assertEqual(owner.finish(), DetectionEvaluationMetrics(DetectionMetrics(1, 2, 3, 4, 5),
                                                                    DetectionMetrics(5, 4, 3, 2, 1)))

    def test_duplicate_entries_are_not_deduplicated(self):
        for packet in (True, False):
            entry = classified_entries(packet)[0]
            result = accumulated((entry,) * 7) if packet else accumulated(flows=(entry,) * 7)
            self.assertEqual(result.packet_metrics if packet else result.flow_metrics, DetectionMetrics(7, 0, 0, 0))

    def test_indices_and_input_order_are_neither_rewritten_nor_validated_as_a_sequence(self):
        for packet in (True, False):
            entry = classified_entries(packet)[1]
            entries = tuple(replace(entry, actual_index=index) for index in (9, 2, 2, 0))
            before = tuple(tuple(getattr(item, field.name) for field in fields(item)) for item in entries)
            first = accumulated(entries) if packet else accumulated(flows=entries)
            second = accumulated(tuple(reversed(entries))) if packet else accumulated(flows=tuple(reversed(entries)))
            self.assertEqual(first, second)
            self.assertEqual(before, tuple(tuple(getattr(item, field.name) for field in fields(item)) for item in entries))

    def test_unclassified_counts_are_excluded_from_all_ratios(self):
        entries = classified_entries(True)
        binary = accumulated(entries[:4]).packet_metrics
        result = accumulated(entries[:4] + (entries[4],) * 31).packet_metrics
        self.assertEqual(ratios(result), ratios(binary))
        self.assertEqual(result.unclassified_count, 31)

    def test_zero_denominators_and_zero_sum_f1_remain_distinct_from_zero(self):
        entries = classified_entries(True)
        for sequence, values in (((), (None, None, None, None)), ((1,), (0.0, None, None, 0.0)),
                                 ((2,), (None, 0.0, None, 0.0)), ((3,), (None, None, None, 1.0)),
                                 ((1, 2), (0.0, 0.0, None, 0.0)), ((4,), (None, None, None, None))):
            self.assertEqual(ratios(accumulated(tuple(entries[index] for index in sequence)).packet_metrics), values)

    def test_ordinary_ratios_preserve_float_operations_without_rounding(self):
        entries = classified_entries(True)
        result = accumulated((entries[0],) + (entries[1],) * 2 + (entries[2],) * 7).packet_metrics
        self.assertEqual(ratios(result), (1 / 3, 1 / 8, 2 * (1 / 3) * (1 / 8) / (1 / 3 + 1 / 8), 1 / 10))
        self.assertNotEqual(result.f1, round(result.f1, 3))

    def test_finish_returns_same_immutable_result_without_reaggregation(self):
        owner = IncrementalDetectionMetrics()
        owner.record_packet(classified_entries(True)[0])
        result = owner.finish()
        with patch.object(detection_metrics._MetricCounts, 'finish', side_effect=AssertionError('recomputation')):
            self.assertIs(owner.finish(), result)
            self.assertIs(owner.finish(), result)
        with self.assertRaises(FrozenInstanceError):
            result.packet_metrics.true_positives = 99
        with self.assertRaises(FrozenInstanceError):
            result.flow_metrics = result.packet_metrics

    def test_recording_after_finish_is_rejected_without_changing_result(self):
        owner = IncrementalDetectionMetrics()
        result = owner.finish()
        for method, packet in ((owner.record_packet, True), (owner.record_flow, False)):
            with self.assertRaises(ValueError):
                method(classified_entries(packet)[0])
            self.assertIs(owner.finish(), result)

    def test_invalid_entry_types_and_subclasses_are_terminal(self):
        class EntrySubclass(DetectionEvaluationEntry):
            pass

        entry = classified_entries(True)[0]
        subclass = EntrySubclass(*(getattr(entry, field.name) for field in fields(entry)))
        for invalid in (None, (), [], {}, entry.finding, evaluate(), subclass):
            for packet in (True, False):
                owner = IncrementalDetectionMetrics()
                with self.assertRaises(TypeError):
                    (owner.record_packet if packet else owner.record_flow)(invalid)
                self.assertFalse(owner.finished)
                with self.assertRaises(ValueError):
                    owner.finish()

    def test_wrong_channels_reject_findings_and_expectation_only_entries(self):
        for packet in (True, False):
            finding = packet_finding() if packet else flow_finding()
            target = expected(finding, True, 0 if packet else None)
            missing = evaluate(packet_expectations=(target,)) if packet else evaluate(flow_expectations=(target,))
            absent = (missing.packet_evaluations if packet else missing.flow_evaluations)[0]
            for entry in (*classified_entries(packet), absent):
                owner = IncrementalDetectionMetrics()
                with self.assertRaises(ValueError):
                    (owner.record_flow if packet else owner.record_packet)(entry)
                with self.assertRaises(ValueError):
                    owner.finish()

    def test_abort_after_partial_input_is_idempotent_and_prevents_completion(self):
        owner = IncrementalDetectionMetrics()
        owner.record_packet(classified_entries(True)[0])
        self.assertIsNone(owner.abort())
        self.assertIsNone(owner.abort())
        self.assertFalse(owner.finished)
        with self.assertRaises(ValueError):
            owner.finish()
        with self.assertRaises(ValueError):
            owner.record_flow(classified_entries(False)[0])

    def test_abort_cannot_invalidate_a_completed_result(self):
        owner = IncrementalDetectionMetrics()
        result = owner.finish()
        with self.assertRaises(ValueError):
            owner.abort()
        self.assertTrue(owner.finished)
        self.assertIs(owner.finish(), result)

    def test_counting_failure_propagates_original_exception_and_never_retries(self):
        entry = classified_entries(True)[0]
        for error in (RuntimeError('count'), MemoryError('count'), KeyboardInterrupt()):
            owner = IncrementalDetectionMetrics()
            with patch.object(detection_metrics._MetricCounts, 'record', side_effect=error) as record:
                with self.assertRaises(type(error)) as caught:
                    owner.record_packet(entry)
                self.assertIs(caught.exception, error)
                with self.assertRaises(ValueError):
                    owner.record_packet(entry)
                self.assertEqual(record.call_count, 1)
            with self.assertRaises(ValueError):
                owner.finish()
            owner.abort()

    def test_finalization_failure_does_not_publish_partial_metrics_or_retry(self):
        for target in ('application.detection_metrics.DetectionMetrics',
                       'application.incremental_detection_metrics.DetectionEvaluationMetrics'):
            for fail_at in ((1, 2) if target.endswith('.DetectionMetrics') else (1,)):
                owner = IncrementalDetectionMetrics()
                owner.record_packet(classified_entries(True)[0])
                error = MemoryError('result publication')
                attempts = []
                original = DetectionMetrics if target.endswith('.DetectionMetrics') else DetectionEvaluationMetrics

                def construct(*args):
                    attempts.append(args)
                    if len(attempts) == fail_at:
                        raise error
                    return original(*args)

                with patch(target, construct):
                    with self.assertRaises(MemoryError) as caught:
                        owner.finish()
                    self.assertIs(caught.exception, error)
                    with self.assertRaises(ValueError):
                        owner.finish()
                self.assertEqual(len(attempts), fail_at)
                self.assertFalse(owner.finished)
                self.assertIsNone(owner._result)

    def test_reentrant_record_finish_and_abort_are_rejected(self):
        entry = classified_entries(True)[0]
        for action in ('record_packet', 'finish', 'abort'):
            owner = IncrementalDetectionMetrics()

            def nested(channel, item):
                method = getattr(owner, action)
                method(item) if action == 'record_packet' else method()

            with patch.object(detection_metrics._MetricCounts, 'record', nested):
                with self.assertRaises(ValueError):
                    owner.record_packet(entry)
            with self.assertRaises(ValueError):
                owner.finish()

    def test_record_does_not_retain_entries_findings_expectations_or_evidence(self):
        owner = IncrementalDetectionMetrics()
        references = []
        for packet in (True, False):
            for _ in range(24):
                entry = classified_entries(packet)[0]
                references.extend(weakref.ref(item) for item in (entry, entry.finding, entry.expectation, entry.finding.raw_evidence))
                self.assertIsNone((owner.record_packet if packet else owner.record_flow)(entry))
                del entry
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(owner.finish(), DetectionEvaluationMetrics(DetectionMetrics(24, 0, 0, 0), DetectionMetrics(24, 0, 0, 0)))

    def test_caller_retention_remains_independent_of_metrics_lifecycle(self):
        entry = classified_entries(True)[0]
        owner = IncrementalDetectionMetrics()
        owner.record_packet(entry)
        owner.abort()
        self.assertIs(entry.classification, C.TRUE_POSITIVE)
        with self.assertRaises(FrozenInstanceError):
            entry.classification = C.FALSE_POSITIVE

    def test_many_entries_retain_only_fixed_counter_state(self):
        owner = IncrementalDetectionMetrics()
        entries = classified_entries(True)
        for index in range(10003):
            owner.record_packet(entries[index % 5])
        self.assertEqual(owner.finish().packet_metrics, DetectionMetrics(2001, 2001, 2001, 2000, 2000))
        self.assertEqual(set(vars(owner._packets)), {'counts', 'unclassified'})
        self.assertEqual(set(vars(owner._flows)), {'counts', 'unclassified'})
        self.assertEqual(set(owner._packets.counts), set(C))
        self.assertTrue(all(type(value) is int for value in owner._packets.counts.values()))

    def test_exhaustive_short_classification_sequences_match_collecting_and_count_oracle(self):
        for packet in (True, False):
            entries = classified_entries(packet)
            for length in range(5):
                for sequence in product(range(5), repeat=length):
                    selected = tuple(entries[index] for index in sequence)
                    evaluation = DetectionEvaluationResult(selected, ()) if packet else DetectionEvaluationResult((), selected)
                    result = accumulated(evaluation.packet_evaluations, evaluation.flow_evaluations)
                    self.assertEqual(result, calculate_detection_metrics(evaluation))
                    actual = result.packet_metrics if packet else result.flow_metrics
                    self.assertEqual(actual, DetectionMetrics(*(sequence.count(index) for index in range(5))))

    def test_channel_validation_reads_no_decisions_indices_or_payload_content(self):
        packet, flow = classified_entries(True)[0], classified_entries(False)[0]
        with ExitStack() as stack:
            for owner, name in ((DetectionFinding, 'decision'), (DetectionFinding, 'security_interpretation'),
                                (DetectionEvaluationEntry, 'actual_index'), (DetectionEvaluationEntry, 'expectation_index'),
                                (PacketObservation, 'raw_bytes')):
                stack.enter_context(patch.object(owner, name, new_callable=PropertyMock, create=True,
                                                 side_effect=AssertionError('semantic detail read')))
            result = accumulated((packet,), (flow,))
        self.assertEqual(result, DetectionEvaluationMetrics(DetectionMetrics(1, 0, 0, 0), DetectionMetrics(1, 0, 0, 0)))

    def test_exact_increment_above_float_range_and_arbitrarily_large_counts(self):
        entries = classified_entries(True)
        for size in (2 ** 53 + 1, 10 ** 400):
            owner = IncrementalDetectionMetrics()
            counts = tuple(size + index for index in range(5))
            seed_counts(owner, counts)
            for entry in entries:
                owner.record_packet(entry)
            result = owner.finish().packet_metrics
            self.assertEqual(result, DetectionMetrics(*(value + 1 for value in counts)))
            self.assertTrue(all(type(getattr(result, field.name)) is int for field in fields(result)))
            self.assertEqual(ratios(result), ratios(DetectionMetrics(*(value + 1 for value in counts))))

    def test_f1_underflow_and_normal_product_boundary_preserve_existing_formulas(self):
        for exponent in (152, 153, 154, 155, 160, 200, 308, 320, 323):
            size = 10 ** exponent
            owner = IncrementalDetectionMetrics()
            seed_counts(owner, (1, size - 1, size - 1, 0, 0))
            result = owner.finish().packet_metrics
            reference = DetectionMetrics(1, size - 1, size - 1, 0)
            self.assertEqual(ratios(result), ratios(reference))
            if exponent >= 155:
                self.assertEqual(result.f1, float(Fraction(1, size)))
                self.assertGreater(result.f1, 0.0)

    def test_asymmetric_precision_recall_and_f1_use_large_integer_counts(self):
        for tp, fp, fn in ((3, 10 ** 160, 10 ** 170), (10 ** 400, 10 ** 560, 10 ** 570),
                          (1, 10 ** 324, 0), (1, 10 ** 325, 0)):
            for left, right in ((fp, fn), (fn, fp)):
                owner = IncrementalDetectionMetrics()
                seed_counts(owner, (tp, left, right, 17, 91), packet=False)
                result = owner.finish().flow_metrics
                self.assertEqual(result.precision, tp / (tp + left))
                self.assertEqual(result.recall, tp / (tp + right))
                self.assertEqual(result.f1, float(Fraction(2 * tp, 2 * tp + left + right)))
                self.assertEqual(result.accuracy, (tp + 17) / (tp + left + right + 17))

    def test_both_ratios_underflowing_to_zero_keep_historical_undefined_f1(self):
        owner = IncrementalDetectionMetrics()
        seed_counts(owner, (1, 10 ** 400, 10 ** 400, 0, 0))
        result = owner.finish().packet_metrics
        self.assertEqual((result.precision, result.recall), (0.0, 0.0))
        self.assertIsNone(result.f1)

    def test_recording_and_finalization_do_not_evaluate_float_properties(self):
        entry = classified_entries(True)[0]
        with ExitStack() as stack:
            for name in ('precision', 'recall', 'f1', 'accuracy'):
                stack.enter_context(patch.object(DetectionMetrics, name, new_callable=PropertyMock,
                                                 side_effect=AssertionError('premature ratio calculation')))
            result = accumulated((entry,))
        self.assertEqual(ratios(result.packet_metrics), (1.0,) * 4)

    def test_independent_instances_share_no_accumulation_or_failure_state(self):
        first, second = IncrementalDetectionMetrics(), IncrementalDetectionMetrics()
        entry = classified_entries(True)[0]
        first.record_packet(entry)
        first.abort()
        self.assertFalse(second.finished)
        self.assertEqual(second.finish(), calculate_detection_metrics(evaluate()))
