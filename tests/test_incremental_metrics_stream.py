from contextlib import ExitStack
from dataclasses import asdict, replace
from itertools import product
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from analysis import FlowObservationWindowUpdate
from application import (
    DetectionEvaluationResult, DetectionPipelineResult, ExpectedDetectionResult, IncrementalDetectionEvaluator,
    IncrementalDetectionMetrics, calculate_detection_metrics, evaluate_detection_result,
)
from application import capture_execution, detection_metrics, detection_pipeline, detector_orchestration
from capture import PcapPacketSource
from tests.pcap_scenarios import pcap_bytes
from tests.test_detection_evaluation import AlternateHashAddress, expected, flow_finding_with_address_type
from tests.test_detection_stream import collected, execute
from tests.test_flow_capacity import capacity_packet
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_incremental_detection_evaluation import flow_variants
from tests.test_incremental_detection_metrics import accumulated, classified_entries, ratios
from tests.test_incremental_evaluation_stream import expectations_from_truth, external_truth
from tests.test_ldap_correlation import correlation_message, correlation_packets


def consumers(expectations):
    metrics = IncrementalDetectionMetrics()
    evaluation = IncrementalDetectionEvaluator(expectations, packet_evaluation_consumer=metrics.record_packet,
                                               flow_evaluation_consumer=metrics.record_flow)
    return evaluation, metrics


def complete_stream(source, evaluation, metrics):
    try:
        execute(source, evaluation.record_packet, evaluation.record_flow)
        evaluation.finish()
        return metrics.finish()
    except BaseException:
        metrics.abort()
        if not evaluation.finished:
            evaluation.abort()
        raise


def streamed_metrics(source, expectations):
    return complete_stream(source, *consumers(expectations))


def evaluated_metrics(findings, expectations):
    evaluation, metrics = consumers(expectations)
    for finding in findings:
        evaluation.record_flow(finding)
    evaluation.finish()
    return metrics.finish()


def replay_metrics():
    results = []
    for ipv6, protocol in product((False, True), (6, 17)):
        packets = tuple(capacity_packet(0, second, ipv6, protocol) for second in (0, 1))
        expectations = expectations_from_truth(external_truth(packets, ipv6, protocol))
        results.append(streamed_metrics(MemoryPacketSource(packets), expectations))
    yes, no, unavailable = flow_variants()
    for positive in (False, True):
        results.append(evaluated_metrics((yes, unavailable, no, yes),
                                        ExpectedDetectionResult((), (expected(yes, positive),) * 3)))
    rows = [(asdict(result), ratios(result.packet_metrics), ratios(result.flow_metrics)) for result in results]
    return json.dumps(rows, ensure_ascii=True, allow_nan=False, separators=(',', ':'))


class IncrementalMetricsStreamTests(unittest.TestCase):
    def test_end_to_end_ipv4_ipv6_tcp_udp_matches_collecting_without_result_accumulation(self):
        for ipv6, protocol in product((False, True), (6, 17)):
            packets = tuple(capacity_packet(0, second, ipv6, protocol) for second in (0, 1))
            expectations = expectations_from_truth(external_truth(packets, ipv6, protocol))
            baseline = calculate_detection_metrics(evaluate_detection_result(collected(packets), expectations))
            source = MemoryPacketSource(packets)
            with patch.object(DetectionPipelineResult, '__post_init__', side_effect=AssertionError('pipeline result')), \
                 patch.object(DetectionEvaluationResult, '__post_init__', side_effect=AssertionError('evaluation result')), \
                 patch.object(detection_pipeline, 'run_detection_pipeline', side_effect=AssertionError('collecting path')), \
                 patch.object(detection_metrics, 'calculate_detection_metrics', side_effect=AssertionError('collecting metrics')), \
                 patch.object(capture_execution, 'analyze_packet_outcome', wraps=capture_execution.analyze_packet_outcome) as analyze, \
                 patch.object(detection_pipeline, 'run_capture_execution', wraps=detection_pipeline.run_capture_execution) as capture, \
                 patch.object(detector_orchestration, 'evaluate_flow_volume_threshold',
                              wraps=detector_orchestration.evaluate_flow_volume_threshold) as volume, \
                 patch.object(detector_orchestration, 'evaluate_tcp_control_threshold',
                              wraps=detector_orchestration.evaluate_tcp_control_threshold) as control:
                result = streamed_metrics(source, expectations)
            self.assertEqual(result, baseline)
            self.assertEqual((capture.call_count, analyze.call_count, volume.call_count, control.call_count),
                             (1, 2, 1, int(protocol == 6)))
            self.assertEqual(source.events, ['start', 'produce:0', 'produce:1', 'stop'])
            self.assertEqual(result.packet_metrics.true_negatives, 2)
            self.assertEqual(result.flow_metrics.true_positives, 1)
            self.assertEqual(result.flow_metrics.true_negatives, int(protocol == 6))

    def test_mixed_capacity_inactivity_malformed_and_unavailable_inputs_match_collecting(self):
        packets = tuple(capacity_packet(index, second, ipv6=bool(index % 2), protocol=6 if index % 3 else 17)
                        for index, second in ((0, 0), (1, 0), (2, 1), (3, 2), (3, 7)))
        invalid = capacity_packet(9, 7)
        invalid = replace(invalid, raw_bytes=invalid.raw_bytes[:14] + b'\x05' + invalid.raw_bytes[15:])
        packets += (replace(packets[-1], captured_length=0, raw_bytes=b''), replace(packets[-1], link_type=None), invalid)
        expectations = ExpectedDetectionResult((), ())
        result = streamed_metrics(MemoryPacketSource(packets), expectations)
        baseline = calculate_detection_metrics(evaluate_detection_result(collected(packets), expectations))
        self.assertEqual(result, baseline)
        self.assertEqual(result.packet_metrics.false_positives, 1)
        self.assertEqual(result.packet_metrics.unclassified_count, 7)

    def test_short_finding_sequences_through_incremental_evaluation_match_collecting(self):
        variants = flow_variants()
        for length in range(5):
            for findings in product(variants, repeat=length):
                for positive, count in product((False, True), (0, 1, 2, 4, 5)):
                    expectations = ExpectedDetectionResult((), (expected(variants[0], positive),) * count)
                    baseline = calculate_detection_metrics(evaluate_detection_result(DetectionPipelineResult((), findings), expectations))
                    self.assertEqual(evaluated_metrics(findings, expectations), baseline)

    def test_deferred_flow_suffix_and_equality_fallback_complete_before_metrics(self):
        yes, no, unavailable = flow_variants()
        custom = flow_finding_with_address_type(yes, AlternateHashAddress)
        expectations = ExpectedDetectionResult((), (expected(custom), expected(yes), expected(custom)))
        evaluation, metrics = consumers(expectations)
        findings = (no, unavailable, yes, custom)
        for finding in findings:
            evaluation.record_flow(finding)
        self.assertEqual(evaluation.pending_flow_count, 4)
        self.assertFalse(metrics.finished)
        evaluation.finish()
        self.assertEqual(metrics.finish(), calculate_detection_metrics(evaluate_detection_result(
            DetectionPipelineResult((), findings), expectations)))
        self.assertEqual(evaluation.pending_flow_count, 0)

    def test_empty_source_and_unresolved_expectations_finalize_in_order(self):
        packets = (capacity_packet(0, protocol=6),)
        expectations = expectations_from_truth(external_truth(packets, False, 6))
        evaluation, metrics = consumers(expectations)
        source = MemoryPacketSource(())
        result = complete_stream(source, evaluation, metrics)
        self.assertTrue(evaluation.finished)
        self.assertTrue(metrics.finished)
        self.assertEqual(source.events, ['start', 'stop'])
        baseline = calculate_detection_metrics(evaluate_detection_result(DetectionPipelineResult((), ()), expectations))
        self.assertEqual(result, baseline)
        self.assertEqual(result.packet_metrics.unclassified_count, 1)
        self.assertEqual(result.flow_metrics.false_negatives, 1)
        self.assertEqual(result.flow_metrics.unclassified_count, 1)

    def test_ldap_pending_and_completed_flows_need_no_special_metric_logic(self):
        for ipv6, completed in product((False, True), (False, True)):
            events = ((False, correlation_message(0x60)),)
            if completed:
                events += ((True, correlation_message(0x61)),)
            packets = correlation_packets(events, ipv6)
            expectations = ExpectedDetectionResult((), ())
            baseline = calculate_detection_metrics(evaluate_detection_result(collected(packets), expectations))
            with patch('integrations.iter_ldap_summary_jsonl', side_effect=AssertionError('LDAP export')):
                self.assertEqual(streamed_metrics(MemoryPacketSource(packets), expectations), baseline)

    def test_all_classic_pcap_encodings_produce_equivalent_final_metrics(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'metrics.pcap'
            for ipv6, protocol in product((False, True), (6, 17)):
                packets = tuple(capacity_packet(0, second, ipv6, protocol) for second in (0, 1))
                expectations = expectations_from_truth(external_truth(packets, ipv6, protocol))
                baseline = calculate_detection_metrics(evaluate_detection_result(collected(packets), expectations))
                for order, nano in product(('<', '>'), (False, True)):
                    path.write_bytes(pcap_bytes(tuple((index * 1000000, packet.raw_bytes)
                                                      for index, packet in enumerate(packets)), order, nano))
                    source = PcapPacketSource(path, source=packets[0].source)
                    self.assertEqual(streamed_metrics(source, expectations), baseline)

    def test_metrics_execute_no_upstream_research_ml_or_external_operations(self):
        packets, flows = classified_entries(True), classified_entries(False)
        baseline = calculate_detection_metrics(DetectionEvaluationResult(packets, flows))
        with ExitStack() as stack:
            for target in ('application.detection_pipeline.run_detection_stream',
                           'application.detection_pipeline.run_detection_pipeline',
                           'application.capture_execution.run_capture_execution',
                           'application.flow_observation_session.run_flow_observation_session',
                           'application.flow_observation_session._run_flow_observation_session',
                           'application.detection_session.DetectionSession.run_packets',
                           'application.detection_session.DetectionSession.run_closed_flows',
                           'application.detection_evaluation.evaluate_detection_result',
                           'application.incremental_detection_evaluation.IncrementalDetectionEvaluator',
                           'analysis.packet_analysis.analyze_packet',
                           'analysis.packet_analysis_outcome.analyze_packet_outcome',
                           'analysis.flow_feature_snapshot.extract_flow_feature_snapshot',
                           'analysis.ldap.analyze_ldap_payload',
                           'ml.feature_projection.project_flow_features',
                           'research.research_example.research_example_from_window',
                           'integrations.iter_ldap_summary_jsonl', 'socket.socket', 'builtins.open'):
                stack.enter_context(patch(target, side_effect=AssertionError(target)))
            self.assertEqual(accumulated(packets, flows), baseline)

    def test_capture_detector_and_publication_failures_abort_partial_metrics(self):
        packets = (capacity_packet(0, protocol=6), capacity_packet(1, 1, protocol=6), capacity_packet(2, 2, protocol=6))
        expectations = ExpectedDetectionResult((), ())
        for phase in ('capture', 'detector', 'publication'):
            error = RuntimeError(phase)
            source = MemoryPacketSource(packets[:1], iteration_error=error) if phase == 'capture' else MemoryPacketSource(packets)
            evaluation, metrics = consumers(expectations)
            with ExitStack() as stack:
                if phase == 'detector':
                    stack.enter_context(patch.object(detector_orchestration, 'evaluate_tcp_control_threshold', side_effect=error))
                if phase == 'publication':
                    original = FlowObservationWindowUpdate.__post_init__

                    def validate(update):
                        original(update)
                        if update.closed_windows:
                            raise error

                    stack.enter_context(patch.object(FlowObservationWindowUpdate, '__post_init__', validate))
                with self.assertRaises(RuntimeError) as caught:
                    complete_stream(source, evaluation, metrics)
            self.assertIs(caught.exception, error)
            self.assertFalse(metrics.finished)
            self.assertFalse(evaluation.finished)
            with self.assertRaises(ValueError):
                metrics.finish()
            self.assertTrue(source.stopped)

    def test_metric_consumer_failure_stops_capture_and_makes_evaluator_terminal(self):
        error = MemoryError('metric accumulation')
        evaluation, metrics = consumers(ExpectedDetectionResult((), ()))
        source = MemoryPacketSource((capacity_packet(0), capacity_packet(1, 1)))
        with patch.object(detection_metrics._MetricCounts, 'record', side_effect=error):
            with self.assertRaises(MemoryError) as caught:
                complete_stream(source, evaluation, metrics)
        self.assertIs(caught.exception, error)
        self.assertEqual(source.events, ['start', 'produce:0', 'stop'])
        for owner in (evaluation, metrics):
            self.assertFalse(owner.finished)
            with self.assertRaises(ValueError):
                owner.finish()

    def test_evaluation_finalization_failure_cannot_certify_partial_metrics(self):
        packets = (capacity_packet(0),)
        expectations = expectations_from_truth(external_truth(packets, False, 17))
        evaluation, metrics = consumers(expectations)
        error = RuntimeError('evaluation finalization')
        with patch.object(evaluation._flows, 'finish', side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                complete_stream(MemoryPacketSource(packets), evaluation, metrics)
        self.assertIs(caught.exception, error)
        self.assertFalse(metrics.finished)
        with self.assertRaises(ValueError):
            metrics.finish()

    def test_metrics_finalization_failure_does_not_undo_successful_evaluation(self):
        evaluation, metrics = consumers(ExpectedDetectionResult((), ()))
        error = MemoryError('metrics finalization')
        with patch('application.incremental_detection_metrics.DetectionEvaluationMetrics', side_effect=error):
            with self.assertRaises(MemoryError) as caught:
                complete_stream(MemoryPacketSource((capacity_packet(0),)), evaluation, metrics)
        self.assertIs(caught.exception, error)
        self.assertTrue(evaluation.finished)
        self.assertFalse(metrics.finished)
        with self.assertRaises(ValueError):
            metrics.finish()

    def test_repeated_serialization_is_identical_across_hash_seeds_and_timezones(self):
        baseline = replay_metrics().encode()
        self.assertEqual(replay_metrics().encode(), baseline)
        command = [sys.executable, '-B', '-c',
                   'from tests.test_incremental_metrics_stream import replay_metrics; print(replay_metrics(), end="")']
        for seed, zone in product(('1', '29', '503'), ('UTC', 'Asia/Kolkata', 'America/New_York')):
            result = subprocess.run(command, capture_output=True, check=True,
                                    env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
            self.assertEqual(result.stdout, baseline)
            self.assertEqual(result.stderr, b'')
