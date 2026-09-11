import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields
from unittest.mock import PropertyMock, patch

import application
from application import DetectionEvaluationEntry, DetectionEvaluationResult, DetectionPipelineResult, GroundTruth
from application.detection_metrics import DetectionEvaluationMetrics, DetectionMetrics, calculate_detection_metrics
from capture import PacketObservation
from detection import DetectionFinding, FlowVolumeThresholdDecision, PacketIntegrityDecision, detection_finding_from_evaluation
from tests.test_detection_evaluation import evaluate, expected, flow_finding, packet_finding
from tests.test_detection_finding import flow_volume_evaluation


class DetectionMetricsValueTests(unittest.TestCase):
    def assert_values(self, counts, precision, recall, f1, accuracy):
        metrics = DetectionMetrics(*counts)
        self.assertEqual((metrics.true_positives, metrics.false_positives, metrics.false_negatives, metrics.true_negatives), counts)
        self.assertEqual((metrics.precision, metrics.recall, metrics.f1, metrics.accuracy), (precision, recall, f1, accuracy))
        for value in (metrics.precision, metrics.recall, metrics.f1, metrics.accuracy):
            if value is not None:
                self.assertIs(type(value), float)
        return metrics

    def test_all_zero_counts_have_undefined_ratios(self):
        self.assert_values((0, 0, 0, 0), None, None, None, None)

    def test_true_positive_only_is_perfect(self):
        self.assert_values((3, 0, 0, 0), 1.0, 1.0, 1.0, 1.0)

    def test_false_positive_only_has_zero_precision_and_undefined_recall(self):
        self.assert_values((0, 4, 0, 0), 0.0, None, None, 0.0)

    def test_false_negative_only_has_undefined_precision_and_zero_recall(self):
        self.assert_values((0, 0, 5, 0), None, 0.0, None, 0.0)

    def test_true_negative_only_has_perfect_accuracy_without_positive_metrics(self):
        self.assert_values((0, 0, 0, 6), None, None, None, 1.0)

    def test_true_and_false_positives_have_perfect_recall(self):
        self.assert_values((3, 1, 0, 0), 3 / 4, 1.0, 2 * (3 / 4) / (3 / 4 + 1), 3 / 4)

    def test_true_positives_and_false_negatives_have_perfect_precision(self):
        self.assert_values((2, 0, 3, 0), 1.0, 2 / 5, 2 * (2 / 5) / (1 + 2 / 5), 2 / 5)

    def test_correct_positive_and_negative_predictions_are_perfect(self):
        self.assert_values((2, 0, 0, 7), 1.0, 1.0, 1.0, 1.0)

    def test_false_positives_and_negatives_have_undefined_zero_sum_f1(self):
        self.assert_values((0, 2, 3, 0), 0.0, 0.0, None, 0.0)

    def test_false_positives_and_true_negatives_have_no_positive_truth(self):
        self.assert_values((0, 2, 0, 6), 0.0, None, None, 6 / 8)

    def test_false_negatives_and_true_negatives_have_no_positive_predictions(self):
        self.assert_values((0, 0, 3, 7), None, 0.0, None, 7 / 10)

    def test_hand_computable_all_four_classifications(self):
        precision, recall = 8 / 10, 8 / 12
        self.assert_values((8, 2, 4, 86), precision, recall, 2 * precision * recall / (precision + recall), 94 / 100)

    def test_precision_excludes_false_negatives_and_true_negatives(self):
        self.assertEqual(DetectionMetrics(3, 7, 0, 0).precision, 3 / 10)
        self.assertEqual(DetectionMetrics(3, 7, 100, 200).precision, 3 / 10)

    def test_recall_excludes_false_positives_and_true_negatives(self):
        self.assertEqual(DetectionMetrics(3, 0, 7, 0).recall, 3 / 10)
        self.assertEqual(DetectionMetrics(3, 100, 7, 200).recall, 3 / 10)

    def test_f1_uses_precision_and_recall_without_rounding(self):
        metrics = DetectionMetrics(1, 2, 7, 0)
        self.assertEqual(metrics.precision, 1 / 3)
        self.assertEqual(metrics.recall, 1 / 8)
        self.assertEqual(metrics.f1, 2 * (1 / 3) * (1 / 8) / (1 / 3 + 1 / 8))
        self.assertNotEqual(metrics.precision, round(metrics.precision, 3))
        self.assertNotEqual(metrics.f1, round(metrics.f1, 3))

    def test_accuracy_includes_every_binary_classification(self):
        self.assertEqual(DetectionMetrics(2, 3, 4, 5).accuracy, 7 / 14)
        self.assertEqual(DetectionMetrics(2, 3, 4, 6).accuracy, 8 / 15)

    def test_zero_metrics_remain_distinct_from_undefined(self):
        zero = DetectionMetrics(0, 1, 1, 0)
        undefined = DetectionMetrics(0, 0, 0, 0)
        for name in ('precision', 'recall', 'accuracy'):
            self.assertEqual(getattr(zero, name), 0.0)
            self.assertIsNone(getattr(undefined, name))
        self.assertIsNone(zero.f1)

    def test_excluded_counts_do_not_change_any_ratio(self):
        metrics = DetectionMetrics(8, 2, 4, 86, 2000)
        reference = DetectionMetrics(8, 2, 4, 86)
        self.assertEqual((metrics.precision, metrics.recall, metrics.f1, metrics.accuracy),
                         (reference.precision, reference.recall, reference.f1, reference.accuracy))
        self.assertEqual(metrics.unclassified_count, 2000)

    def test_only_excluded_counts_leave_all_metrics_undefined(self):
        metrics = DetectionMetrics(0, 0, 0, 0, 4)
        self.assertEqual((metrics.precision, metrics.recall, metrics.f1, metrics.accuracy), (None, None, None, None))

    def test_integer_counts_larger_than_float_exact_range_are_preserved(self):
        count = 2 ** 53 + 1
        metrics = DetectionMetrics(count, count + 1, count + 2, count + 3)
        self.assertEqual(metrics.true_positives, count)
        self.assertEqual(metrics.false_positives, count + 1)
        self.assertEqual(metrics.false_negatives, count + 2)
        self.assertEqual(metrics.true_negatives, count + 3)
        self.assertIs(type(metrics.true_positives), int)
        self.assertEqual(metrics.accuracy, (2 * count + 3) / (4 * count + 6))

    def test_large_integer_ratios_do_not_require_float_count_conversion(self):
        count = 10 ** 400
        metrics = DetectionMetrics(count, count, count, count)
        self.assertEqual((metrics.precision, metrics.recall, metrics.f1, metrics.accuracy), (0.5, 0.5, 0.5, 0.5))

    def test_negative_counts_are_rejected_for_all_count_fields(self):
        for index in range(5):
            counts = [0] * 5
            counts[index] = -1
            with self.assertRaisesRegex(ValueError, 'nonnegative'):
                DetectionMetrics(*counts)

    def test_counts_are_exact_integers_without_coercion(self):
        for value in (True, False, 1.0, '1', None, float('nan'), float('inf')):
            for index in range(5):
                counts = [0] * 5
                counts[index] = value
                with self.assertRaisesRegex(TypeError, 'exactly integers'):
                    DetectionMetrics(*counts)

    def test_counts_and_derived_metrics_are_immutable(self):
        metrics = DetectionMetrics(1, 2, 3, 4)
        for name in ('true_positives', 'false_positives', 'false_negatives', 'true_negatives',
                     'unclassified_count', 'precision', 'recall', 'f1', 'accuracy'):
            with self.assertRaises(FrozenInstanceError):
                setattr(metrics, name, 0)

    def test_packet_and_flow_metric_values_are_separate_immutable_objects(self):
        packet = DetectionMetrics(1, 2, 3, 4)
        flow = DetectionMetrics(4, 3, 2, 1)
        result = DetectionEvaluationMetrics(packet, flow)
        self.assertIs(result.packet_metrics, packet)
        self.assertIs(result.flow_metrics, flow)
        self.assertEqual(result.packet_metrics.precision, 1 / 3)
        self.assertEqual(result.flow_metrics.precision, 4 / 7)
        with self.assertRaises(FrozenInstanceError):
            result.packet_metrics = flow

    def test_domain_metric_contract_rejects_untyped_values(self):
        metrics = DetectionMetrics(0, 0, 0, 0)
        for value in (None, (), {}, (0, 0, 0, 0)):
            with self.assertRaises(TypeError):
                DetectionEvaluationMetrics(value, metrics)
            with self.assertRaises(TypeError):
                DetectionEvaluationMetrics(metrics, value)

    def test_equivalent_count_inputs_produce_equal_repeated_values(self):
        first = DetectionMetrics(8, 2, 4, 86, 6)
        for _ in range(3):
            other = DetectionMetrics(8, 2, 4, 86, 6)
            self.assertEqual(first, other)
            self.assertEqual((first.precision, first.recall, first.f1, first.accuracy),
                             (other.precision, other.recall, other.f1, other.accuracy))


class DetectionMetricsAggregationTests(unittest.TestCase):
    def test_empty_evaluation_produces_separate_empty_metrics(self):
        self.assertEqual(calculate_detection_metrics(DetectionEvaluationResult((), ())),
                         DetectionEvaluationMetrics(DetectionMetrics(0, 0, 0, 0), DetectionMetrics(0, 0, 0, 0)))

    def test_packet_classifications_are_counted_exactly(self):
        positive = packet_finding()
        negative = packet_finding(PacketIntegrityDecision.NO_MATCH)
        result = evaluate(packets=(positive, positive, negative, negative), packet_expectations=(
            expected(positive, True, 0), expected(negative, True, 2), expected(negative, False, 3)))
        metrics = calculate_detection_metrics(result)
        self.assertEqual(metrics.packet_metrics, DetectionMetrics(1, 1, 1, 1))
        self.assertEqual(metrics.flow_metrics, DetectionMetrics(0, 0, 0, 0))

    def test_flow_classifications_are_counted_exactly(self):
        positive = flow_finding()
        negative = flow_finding(positive=False)
        matched = evaluate(flows=(positive,), flow_expectations=(expected(positive),))
        unexpected = evaluate(flows=(positive,))
        missed = evaluate(flows=(negative,), flow_expectations=(expected(negative),))
        correct_negative = evaluate(flows=(negative,), flow_expectations=(expected(negative, False),))
        result = DetectionEvaluationResult((), tuple(entry for part in (matched, unexpected, missed, correct_negative)
                                                    for entry in part.flow_evaluations))
        metrics = calculate_detection_metrics(result)
        self.assertEqual(metrics.flow_metrics, DetectionMetrics(1, 1, 1, 1))
        self.assertEqual(metrics.packet_metrics, DetectionMetrics(0, 0, 0, 0))

    def test_packet_and_flow_counts_do_not_cross_domains(self):
        packet = packet_finding()
        flow = flow_finding()
        result = evaluate(packets=(packet, packet), flows=(flow,), flow_expectations=(expected(flow),))
        metrics = calculate_detection_metrics(result)
        self.assertEqual(metrics.packet_metrics, DetectionMetrics(0, 2, 0, 0))
        self.assertEqual(metrics.flow_metrics, DetectionMetrics(1, 0, 0, 0))
        self.assertEqual((metrics.packet_metrics.precision, metrics.flow_metrics.precision), (0.0, 1.0))

    def test_absent_positive_is_counted_as_existing_false_negative(self):
        result = evaluate(packet_expectations=(expected(packet_finding(), True, 0),))
        self.assertEqual(calculate_detection_metrics(result).packet_metrics, DetectionMetrics(0, 0, 1, 0))

    def test_absent_negative_is_unclassified_not_true_negative(self):
        result = evaluate(packet_expectations=(expected(packet_finding(), False, 0),))
        self.assertEqual(calculate_detection_metrics(result).packet_metrics, DetectionMetrics(0, 0, 0, 0, 1))

    def test_unexpected_no_match_remains_unclassified(self):
        result = evaluate(packets=(packet_finding(PacketIntegrityDecision.NO_MATCH),))
        self.assertEqual(calculate_detection_metrics(result).packet_metrics, DetectionMetrics(0, 0, 0, 0, 1))

    def test_unexpected_not_evaluable_adds_no_binary_classification(self):
        result = evaluate(packets=(packet_finding(PacketIntegrityDecision.NOT_EVALUABLE),))
        metrics = calculate_detection_metrics(result).packet_metrics
        self.assertEqual(metrics, DetectionMetrics(0, 0, 0, 0, 1))
        self.assertIsNone(metrics.accuracy)

    def test_negative_not_evaluable_remains_unclassified(self):
        finding = packet_finding(PacketIntegrityDecision.NOT_EVALUABLE)
        result = evaluate(packets=(finding,), packet_expectations=(expected(finding, False, 0),))
        self.assertEqual(calculate_detection_metrics(result).packet_metrics, DetectionMetrics(0, 0, 0, 0, 1))

    def test_positive_not_evaluable_preserves_authoritative_packet_false_negative(self):
        finding = packet_finding(PacketIntegrityDecision.NOT_EVALUABLE)
        result = evaluate(packets=(finding,), packet_expectations=(expected(finding, True, 0),))
        self.assertEqual(calculate_detection_metrics(result).packet_metrics, DetectionMetrics(0, 0, 1, 0))
        self.assertIs(result.packet_evaluations[0].finding, finding)

    def test_positive_not_evaluable_preserves_authoritative_flow_false_negative(self):
        finding = detection_finding_from_evaluation(flow_volume_evaluation(FlowVolumeThresholdDecision.NOT_EVALUABLE))
        result = evaluate(flows=(finding,), flow_expectations=(expected(finding),))
        metrics = calculate_detection_metrics(result).flow_metrics
        self.assertEqual(metrics, DetectionMetrics(0, 0, 1, 0))
        self.assertEqual((metrics.recall, metrics.accuracy), (0.0, 0.0))

    def test_unclassified_entries_are_excluded_from_binary_denominators(self):
        positive = packet_finding()
        negative = packet_finding(PacketIntegrityDecision.NO_MATCH)
        unevaluable = packet_finding(PacketIntegrityDecision.NOT_EVALUABLE)
        result = evaluate(packets=(positive, negative, unevaluable), packet_expectations=(expected(positive, True, 0),))
        metrics = calculate_detection_metrics(result).packet_metrics
        self.assertEqual(metrics, DetectionMetrics(1, 0, 0, 0, 2))
        self.assertEqual((metrics.precision, metrics.recall, metrics.f1, metrics.accuracy), (1.0, 1.0, 1.0, 1.0))

    def test_duplicate_evaluation_entries_preserve_multiplicity(self):
        entry = evaluate(flows=(flow_finding(),)).flow_evaluations[0]
        result = DetectionEvaluationResult((), (entry, entry, entry))
        self.assertEqual(calculate_detection_metrics(result).flow_metrics, DetectionMetrics(0, 3, 0, 0))

    def test_ipv4_ipv6_tcp_udp_classifications_share_aggregation(self):
        findings = tuple(flow_finding(protocol=protocol, ipv6=ipv6) for ipv6 in (False, True) for protocol in (6, 17))
        result = evaluate(flows=findings, flow_expectations=tuple(expected(finding) for finding in findings))
        self.assertEqual(calculate_detection_metrics(result).flow_metrics, DetectionMetrics(4, 0, 0, 0))

    def test_equivalent_independent_evaluations_produce_equal_metrics(self):
        first = calculate_detection_metrics(evaluate(packets=(packet_finding(),)))
        for _ in range(3):
            self.assertEqual(calculate_detection_metrics(evaluate()), DetectionEvaluationMetrics(
                DetectionMetrics(0, 0, 0, 0), DetectionMetrics(0, 0, 0, 0)))
            self.assertEqual(calculate_detection_metrics(evaluate(packets=(packet_finding(),))), first)

    def test_input_order_and_exact_records_are_preserved(self):
        findings = (packet_finding(), packet_finding(PacketIntegrityDecision.NO_MATCH))
        result = evaluate(packets=findings)
        records = result.packet_evaluations
        before = tuple(tuple(getattr(entry, field.name) for field in fields(entry)) for entry in records)
        reverse = DetectionEvaluationResult(tuple(reversed(records)), ())
        self.assertEqual(calculate_detection_metrics(result), calculate_detection_metrics(reverse))
        self.assertIs(result.packet_evaluations, records)
        self.assertEqual(tuple(tuple(getattr(entry, field.name) for field in fields(entry)) for entry in records), before)
        for entry, finding in zip(records, findings):
            self.assertIs(entry.finding, finding)

    def test_metrics_read_classifications_without_accessing_findings_or_expectations(self):
        finding = packet_finding(PacketIntegrityDecision.NOT_EVALUABLE)
        result = evaluate(packets=(finding,), packet_expectations=(expected(finding, True, 0),))
        with ExitStack() as stack:
            guards = [stack.enter_context(patch.object(owner, name, new_callable=PropertyMock, create=True,
                       side_effect=AssertionError('semantic detail accessed'))) for owner, name in (
                           (DetectionEvaluationEntry, 'finding'), (DetectionEvaluationEntry, 'expectation'),
                           (DetectionFinding, 'decision'), (DetectionFinding, 'raw_evidence'),
                           (PacketObservation, 'raw_bytes'))]
            self.assertEqual(calculate_detection_metrics(result).packet_metrics, DetectionMetrics(0, 0, 1, 0))
            for guard in guards:
                guard.assert_not_called()

    def test_metrics_execute_no_upstream_or_external_behavior(self):
        result = evaluate(packets=(packet_finding(),), flows=(flow_finding(),))
        targets = (
            'application.detection_evaluation.evaluate_detection_result',
            'application.ground_truth.GroundTruth',
            'application.detection_pipeline.run_detection_pipeline',
            'application.detection_session.DetectionSession',
            'application.capture_execution.run_capture_execution',
            'application.flow_observation_session.run_flow_observation_session',
            'application.detector_orchestration.run_packet_detectors',
            'application.detector_orchestration.run_closed_flow_detectors',
            'application.cli.main',
            'analysis.packet_analysis.analyze_packet',
            'analysis.packet_analysis_outcome.analyze_packet_outcome',
            'analysis.flow_feature_snapshot.extract_flow_feature_snapshot',
            'analysis.ipv6_extension_headers.validate_ipv6_extension_headers',
            'detection.packet_integrity.evaluate_packet_integrity',
            'detection.flow_volume_threshold.evaluate_flow_volume_threshold',
            'detection.tcp_control_threshold.evaluate_tcp_control_threshold',
            'capture.packet_ingestion.consume',
            'capture.pcap_packet_source.PcapPacketSource',
            'builtins.open', 'socket.socket',
        )
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(target, side_effect=AssertionError('execution attempted'))) for target in targets]
            self.assertEqual(calculate_detection_metrics(result), DetectionEvaluationMetrics(
                DetectionMetrics(0, 1, 0, 0), DetectionMetrics(0, 1, 0, 0)))
            for guard in guards:
                guard.assert_not_called()

    def test_only_existing_evaluation_result_is_accepted(self):
        for value in (None, (), [], {}, DetectionPipelineResult((), ()), GroundTruth((), ()), DetectionMetrics(0, 0, 0, 0)):
            with self.assertRaisesRegex(TypeError, 'exactly a DetectionEvaluationResult'):
                calculate_detection_metrics(value)

    def test_public_exports_resolve_to_metric_contracts(self):
        for name, value in (('DetectionMetrics', DetectionMetrics), ('DetectionEvaluationMetrics', DetectionEvaluationMetrics),
                            ('calculate_detection_metrics', calculate_detection_metrics)):
            self.assertIn(name, application.__all__)
            self.assertIs(getattr(application, name), value)


if __name__ == '__main__':
    unittest.main()
