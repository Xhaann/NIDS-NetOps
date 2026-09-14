from contextlib import ExitStack
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from analysis import FlowIdentity, FlowObservationWindowKey
from application import (
    DetectionEvaluationResult, ExpectedDetection, ExpectedDetectionResult, FlowDetectionIdentity,
    GroundTruth, GroundTruthPolarity, GroundTruthRecord, IncrementalDetectionEvaluator,
    PacketDetectionIdentity, calculate_detection_metrics, evaluate_detection_result,
)
from application import capture_execution, detection_pipeline
from application.cli import _finding_json
from capture import CaptureError, PcapPacketSource
from tests.pcap_scenarios import addresses, pcap_bytes
from tests.test_detection_evaluation import expected
from tests.test_detection_stream import collected, execute
from tests.test_end_to_end_validation import settings
from tests.test_flow_capacity import capacity_packet
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_incremental_detection_evaluation import flow_variants, incrementally
from tests.test_ldap_correlation import correlation_message, correlation_packets


def expectations_from_truth(truth):
    return ExpectedDetectionResult(
        tuple(ExpectedDetection(record.target, record.polarity is GroundTruthPolarity.POSITIVE)
              for record in truth.packet_records),
        tuple(ExpectedDetection(record.target, record.polarity is GroundTruthPolarity.POSITIVE)
              for record in truth.flow_records),
    )


def external_truth(packets, ipv6, protocol):
    configuration = settings()
    packet_records = tuple(GroundTruthRecord(PacketDetectionIdentity(
        configuration.packet_configuration, index, packet.captured_at, packet.source.identifier,
        packet.link_type.value, packet.captured_length, packet.original_length,
    ), GroundTruthPolarity.NEGATIVE) for index, packet in enumerate(packets))
    identity = FlowIdentity(*addresses(ipv6), 12000, 443, protocol)
    target = FlowDetectionIdentity(configuration.flow_volume_configuration, FlowObservationWindowKey('stream', 0),
                                   identity, packets[0].captured_at, packets[-1].captured_at)
    flow_records = (GroundTruthRecord(target, GroundTruthPolarity.POSITIVE),)
    if protocol == 6:
        flow_records += (GroundTruthRecord(replace(target, configuration=configuration.tcp_control_configuration),
                                          GroundTruthPolarity.NEGATIVE),)
    return GroundTruth(packet_records, flow_records)


def stream_evaluation(source, expectations):
    packets, flows = [], []
    owner = IncrementalDetectionEvaluator(expectations, packet_evaluation_consumer=packets.append,
                                          flow_evaluation_consumer=flows.append)
    try:
        execute(source, owner.record_packet, owner.record_flow)
    except BaseException:
        owner.abort()
        raise
    else:
        owner.finish()
    return DetectionEvaluationResult(tuple(packets), tuple(flows))


def replay_values():
    rows = []
    for ipv6 in (False, True):
        for protocol in (6, 17):
            packets = tuple(capacity_packet(0, second, ipv6, protocol) for second in (0, 1))
            expectations = expectations_from_truth(external_truth(packets, ipv6, protocol))
            result = stream_evaluation(MemoryPacketSource(packets), expectations)
            rows.append([
                [(None if entry.classification is None else entry.classification.value,
                  entry.actual_index, entry.expectation_index,
                  None if entry.finding is None else _finding_json(entry.finding)) for entry in entries]
                for entries in (result.packet_evaluations, result.flow_evaluations)
            ])
    return json.dumps(rows, ensure_ascii=True, allow_nan=False, separators=(',', ':'))


class IncrementalEvaluationStreamTests(unittest.TestCase):
    def test_external_truth_ipv4_ipv6_tcp_udp_matches_collecting_evaluation_and_metrics(self):
        for ipv6 in (False, True):
            for protocol in (6, 17):
                packets = tuple(capacity_packet(0, second, ipv6, protocol) for second in (0, 1))
                truth = external_truth(packets, ipv6, protocol)
                expectations = expectations_from_truth(truth)
                actual = stream_evaluation(MemoryPacketSource(packets), expectations)
                baseline = evaluate_detection_result(collected(packets), expectations)
                self.assertEqual(actual, baseline)
                self.assertEqual(calculate_detection_metrics(actual), calculate_detection_metrics(baseline))
                metrics = calculate_detection_metrics(actual)
                self.assertEqual(metrics.packet_metrics.true_negatives, 2)
                self.assertEqual(metrics.flow_metrics.true_positives, 1)
                self.assertEqual(metrics.flow_metrics.true_negatives, int(protocol == 6))

    def test_mixed_protocol_capacity_inactivity_and_malformed_findings_preserve_channel_order(self):
        packets = tuple(capacity_packet(index, second, ipv6=bool(index % 2), protocol=6 if index % 3 else 17)
                        for index, second in ((0, 0), (1, 0), (2, 1), (3, 2), (3, 7)))
        malformed = replace(packets[-1], captured_length=0, raw_bytes=b'')
        packets += (malformed, replace(packets[-1], link_type=None))
        expectations = ExpectedDetectionResult((), ())
        actual = stream_evaluation(MemoryPacketSource(packets), expectations)
        self.assertEqual(actual, evaluate_detection_result(collected(packets), expectations))
        self.assertEqual([entry.actual_index for entry in actual.packet_evaluations], list(range(7)))
        self.assertEqual([entry.finding.raw_evidence.closure_reason.value for entry in actual.flow_evaluations],
                         ['capacity', 'capacity', 'capacity', 'inactivity', 'capture_session_end',
                          'capture_session_end', 'capture_session_end'])

    def test_single_stream_execution_owns_capture_parsing_and_detection_once(self):
        packets = (capacity_packet(0, protocol=6), capacity_packet(0, 1, protocol=6))
        expected_result = expectations_from_truth(external_truth(packets, False, 6))
        source = MemoryPacketSource(packets)
        with patch.object(capture_execution, 'analyze_packet_outcome', wraps=capture_execution.analyze_packet_outcome) as analyze, \
             patch.object(detection_pipeline, 'run_capture_execution', wraps=detection_pipeline.run_capture_execution) as capture, \
             patch.object(detection_pipeline, 'extract_flow_feature_snapshot',
                          wraps=detection_pipeline.extract_flow_feature_snapshot) as extract, \
             patch.object(detection_pipeline, 'run_detection_pipeline', side_effect=AssertionError('collecting pipeline')):
            result = stream_evaluation(source, expected_result)
        self.assertEqual((capture.call_count, analyze.call_count, extract.call_count), (1, 2, 1))
        self.assertEqual(source.events, ['start', 'produce:0', 'produce:1', 'stop'])
        self.assertEqual(len(result.flow_evaluations), 2)

    def test_evaluator_reads_existing_findings_without_upstream_or_research_execution(self):
        packets = tuple(capacity_packet(0, second, protocol=6) for second in (0, 1))
        findings = collected(packets)
        with ExitStack() as stack:
            for target in ('application.detection_pipeline.run_detection_stream',
                           'application.detection_session.DetectionSession.run_packets',
                           'application.detection_session.DetectionSession.run_closed_flows',
                           'application.capture_execution.run_capture_execution',
                           'analysis.packet_analysis.analyze_packet',
                           'analysis.ldap.analyze_ldap_payload',
                           'ml.feature_projection.project_flow_features',
                           'research.research_example.research_example_from_window'):
                stack.enter_context(patch(target, side_effect=AssertionError(target)))
            result = incrementally(findings.packet_findings, findings.flow_findings)
        self.assertEqual(len(result.packet_evaluations), 2)
        self.assertEqual(len(result.flow_evaluations), 2)

    def test_ldap_pending_and_completed_flows_use_generic_evaluation_without_export(self):
        for ipv6 in (False, True):
            for completed in (False, True):
                events = ((False, correlation_message(0x60)),)
                if completed:
                    events += ((True, correlation_message(0x61)),)
                packets = correlation_packets(events, ipv6)
                expectations = ExpectedDetectionResult((), ())
                with patch('integrations.iter_ldap_summary_jsonl', side_effect=AssertionError('export')):
                    result = stream_evaluation(MemoryPacketSource(packets), expectations)
                self.assertEqual(result, evaluate_detection_result(collected(packets), expectations))
                self.assertEqual(len(result.flow_evaluations), 2)

    def test_all_four_pcap_encodings_match_incremental_and_collecting_paths(self):
        packets = (capacity_packet(0, ipv6=True), capacity_packet(0, 1, ipv6=True))
        expectations = expectations_from_truth(external_truth(packets, True, 17))
        baseline = evaluate_detection_result(collected(packets), expectations)
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'evaluation.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    path.write_bytes(pcap_bytes(tuple((index * 1000000, packet.raw_bytes)
                                                      for index, packet in enumerate(packets)), order, nano))
                    source = PcapPacketSource(path, source=packets[0].source)
                    self.assertEqual(stream_evaluation(source, expectations), baseline)

    def test_capture_failure_is_aborted_without_final_missing_expectations(self):
        packets = (capacity_packet(0), capacity_packet(0, 1))
        expectations = expectations_from_truth(external_truth(packets, False, 17))
        packet_entries, flow_entries = [], []
        owner = IncrementalDetectionEvaluator(expectations, packet_evaluation_consumer=packet_entries.append,
                                              flow_evaluation_consumer=flow_entries.append)
        error = CaptureError('capture truncated')
        source = MemoryPacketSource(packets[:1], iteration_error=error)
        with self.assertRaises(CaptureError) as caught:
            try:
                execute(source, owner.record_packet, owner.record_flow)
            except BaseException:
                owner.abort()
                raise
        self.assertIs(caught.exception, error)
        self.assertFalse(owner.finished)
        self.assertEqual(len(packet_entries), 1)
        self.assertTrue(all(entry.finding is not None for entry in packet_entries + flow_entries))
        with self.assertRaises(ValueError):
            owner.finish()

    def test_evaluation_consumer_failure_stops_detection_stream_and_suppresses_further_delivery(self):
        error = RuntimeError('evaluation output')
        attempted = []

        def fail(entry):
            attempted.append(entry)
            raise error

        owner = IncrementalDetectionEvaluator(ExpectedDetectionResult((), ()),
                                              packet_evaluation_consumer=fail, flow_evaluation_consumer=self.fail)
        source = MemoryPacketSource((capacity_packet(0), capacity_packet(1, 1)))
        with self.assertRaises(RuntimeError) as caught:
            execute(source, owner.record_packet, owner.record_flow)
        self.assertIs(caught.exception, error)
        self.assertEqual(source.events, ['start', 'produce:0', 'stop'])
        self.assertEqual(len(attempted), 1)
        with self.assertRaises(ValueError):
            owner.finish()

    def test_packet_evaluation_progresses_while_flow_suffix_is_deferred(self):
        yes, no, _ = flow_variants()
        packet_entries, flow_entries = [], []
        owner = IncrementalDetectionEvaluator(ExpectedDetectionResult((), (expected(yes),)),
                                              packet_evaluation_consumer=packet_entries.append,
                                              flow_evaluation_consumer=flow_entries.append)
        owner.record_flow(no)
        packet_findings = collected((capacity_packet(0),)).packet_findings
        owner.record_packet(packet_findings[0])
        self.assertEqual(len(packet_entries), 1)
        self.assertEqual(flow_entries, [])
        owner.finish()
        self.assertEqual(len(flow_entries), 1)

    def test_deterministic_evaluation_across_hash_seeds_timezones_and_repeated_runs(self):
        expected_bytes = replay_values().encode()
        self.assertEqual(replay_values().encode(), expected_bytes)
        command = [sys.executable, '-B', '-c',
                   'from tests.test_incremental_evaluation_stream import replay_values; print(replay_values(), end="")']
        for seed, zone in (('1', 'UTC'), ('29', 'Asia/Kolkata'), ('503', 'America/New_York')):
            process = subprocess.run(command, capture_output=True, check=True,
                                     env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
            self.assertEqual(process.stdout, expected_bytes)
            self.assertEqual(process.stderr, b'')
