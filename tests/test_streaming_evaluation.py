from contextlib import ExitStack
from dataclasses import asdict, FrozenInstanceError, replace
import gc
import inspect
from itertools import product
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import weakref

import application
from application import (
    DetectionEvaluationEntry, DetectionEvaluationMetrics, DetectionMetrics, GroundTruth, GroundTruthPolarity, GroundTruthRecord,
    IncrementalDetectionEvaluator, IncrementalDetectionMetrics, run_end_to_end_validation, run_streaming_evaluation,
)
from application import capture_execution, detector_orchestration, streaming_evaluation
from capture import PacketSource, PcapPacketSource
from detection import DetectionFinding
from tests.pcap_scenarios import pcap_bytes
from tests.test_end_to_end_validation import settings
from tests.test_flow_capacity import capacity_packet
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_incremental_detection_metrics import ratios
from tests.test_incremental_evaluation_stream import external_truth
from tests.test_ldap_correlation import correlation_message, correlation_packets


def configuration():
    return replace(settings(), max_active_windows=2)


def execute(source, truth=None, config=None):
    return run_streaming_evaluation(source, configuration=configuration() if config is None else config,
                                    capture_session_id='stream', ground_truth=GroundTruth((), ()) if truth is None else truth)


def collecting(packets, truth=None, config=None):
    return run_end_to_end_validation(MemoryPacketSource(packets),
                                     configuration=configuration() if config is None else config,
                                     capture_session_id='stream', ground_truth=GroundTruth((), ()) if truth is None else truth).report.metrics


def replay():
    results = []
    for ipv6, protocol in product((False, True), (6, 17)):
        packets = tuple(capacity_packet(0, second, ipv6, protocol) for second in (0, 1))
        results.append(execute(MemoryPacketSource(packets), external_truth(packets, ipv6, protocol)))
    return json.dumps([(asdict(result), ratios(result.packet_metrics), ratios(result.flow_metrics)) for result in results],
                      ensure_ascii=True, allow_nan=False, separators=(',', ':'))


class StreamingEvaluationTests(unittest.TestCase):
    def test_public_api_is_additive_and_returns_existing_immutable_metrics(self):
        self.assertIs(application.run_streaming_evaluation, streaming_evaluation.run_streaming_evaluation)
        self.assertEqual(application.__all__.count('run_streaming_evaluation'), 1)
        signature = inspect.signature(run_streaming_evaluation)
        self.assertEqual(tuple(signature.parameters), ('source', 'configuration', 'capture_session_id', 'ground_truth'))
        self.assertIs(signature.return_annotation, DetectionEvaluationMetrics)
        for name in ('configuration', 'capture_session_id', 'ground_truth'):
            self.assertIs(signature.parameters[name].kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertIs(signature.parameters[name].default, inspect.Parameter.empty)
        result = execute(MemoryPacketSource(()))
        self.assertIs(type(result), DetectionEvaluationMetrics)
        with self.assertRaises(FrozenInstanceError):
            result.packet_metrics = result.flow_metrics
        with self.assertRaises(TypeError):
            run_streaming_evaluation(MemoryPacketSource(()), configuration=configuration(), capture_session_id='stream',
                                     ground_truth=GroundTruth((), ()), packet_finding_consumer=lambda value: None)

    def test_empty_stream_starts_stops_and_returns_empty_metrics(self):
        source = MemoryPacketSource(())
        result = execute(source)
        self.assertEqual(result, collecting(()))
        self.assertEqual(source.events, ['start', 'stop'])
        self.assertEqual(ratios(result.packet_metrics), (None,) * 4)
        self.assertEqual(ratios(result.flow_metrics), (None,) * 4)

    def test_real_ipv4_ipv6_tcp_udp_execution_matches_collecting_for_explicit_truth_modes(self):
        for ipv6, protocol in product((False, True), (6, 17)):
            packets = tuple(capacity_packet(0, second, ipv6, protocol) for second in (0, 1))
            truth = external_truth(packets, ipv6, protocol)
            modes = (GroundTruth((), ()), truth,
                     GroundTruth(tuple(reversed(truth.packet_records)), tuple(reversed(truth.flow_records))))
            modes += tuple(GroundTruth(tuple(replace(record, polarity=polarity) for record in truth.packet_records),
                                       tuple(replace(record, polarity=polarity) for record in truth.flow_records))
                           for polarity in GroundTruthPolarity)
            for mode in modes:
                result = execute(MemoryPacketSource(packets), mode)
                baseline = collecting(packets, mode)
                self.assertEqual(result, baseline)
                self.assertEqual(ratios(result.packet_metrics), ratios(baseline.packet_metrics))
                self.assertEqual(ratios(result.flow_metrics), ratios(baseline.flow_metrics))

    def test_packet_only_failures_preserve_positive_negative_and_unlabeled_semantics(self):
        base = capacity_packet(0)
        malformed = replace(base, raw_bytes=base.raw_bytes[:14] + b'\x05' + base.raw_bytes[15:])
        for packet in (malformed, replace(base, captured_length=0, raw_bytes=b''), replace(base, link_type=None)):
            target = external_truth((base,), False, 17).packet_records[0].target
            target = replace(target, captured_length=packet.captured_length,
                             link_type=None if packet.link_type is None else packet.link_type.value)
            for polarity in (None, *GroundTruthPolarity):
                truth = GroundTruth(() if polarity is None else (GroundTruthRecord(target, polarity),), ())
                result = execute(MemoryPacketSource((packet,)), truth)
                self.assertEqual(result, collecting((packet,), truth))
                self.assertEqual(result.flow_metrics, DetectionMetrics(0, 0, 0, 0))
                if packet is not malformed and polarity is GroundTruthPolarity.POSITIVE:
                    self.assertEqual(result.packet_metrics.false_negatives, 1)

    def test_flow_only_truth_does_not_disable_mandatory_packet_detection(self):
        packets = (capacity_packet(0, protocol=6),)
        truth = external_truth(packets, False, 6)
        result = execute(MemoryPacketSource(packets), GroundTruth((), truth.flow_records))
        self.assertEqual(result.packet_metrics.unclassified_count, 1)
        self.assertEqual(result.flow_metrics.true_positives, 1)
        self.assertEqual(result.flow_metrics.true_negatives, 1)
        with self.assertRaises(TypeError):
            replace(configuration(), packet_configuration=None)

    def test_missing_truth_targets_finalize_after_empty_input_without_invented_negatives(self):
        packets = (capacity_packet(0, protocol=6),)
        truth = external_truth(packets, False, 6)
        result = execute(MemoryPacketSource(()), truth)
        self.assertEqual(result, collecting((), truth))
        self.assertEqual(result.packet_metrics.unclassified_count, 1)
        self.assertEqual(result.flow_metrics, DetectionMetrics(0, 0, 1, 0, 1))

    def test_capacity_inactivity_and_capture_end_follow_configuration(self):
        packets = tuple(capacity_packet(index, second, ipv6=bool(index % 2), protocol=6 if index % 3 else 17)
                        for index, second in ((0, 0), (1, 0), (2, 1), (3, 2), (3, 7)))
        for limit in (1, 2, 4):
            config = replace(configuration(), max_active_windows=limit)
            self.assertEqual(execute(MemoryPacketSource(packets), config=config), collecting(packets, config=config))

    def test_udp_without_tcp_configuration_and_tcp_missing_configuration_keep_existing_behavior(self):
        config = replace(configuration(), tcp_control_configuration=None)
        packets = (capacity_packet(0),)
        self.assertEqual(execute(MemoryPacketSource(packets), config=config), collecting(packets, config=config))
        source = MemoryPacketSource((capacity_packet(0, protocol=6),))
        with self.assertRaisesRegex(TypeError, 'TCP windows require'):
            execute(source, config=config)
        self.assertTrue(source.stopped)

    def test_truth_conversion_preserves_order_targets_and_external_polarity(self):
        packets = (capacity_packet(0, protocol=6),)
        truth = external_truth(packets, False, 6)
        truth = replace(truth, flow_records=tuple(reversed(truth.flow_records)))
        before = replace(truth)
        with patch.object(streaming_evaluation, 'IncrementalDetectionEvaluator', wraps=IncrementalDetectionEvaluator) as evaluator:
            execute(MemoryPacketSource(packets), truth)
        expected = evaluator.call_args.args[0]
        for records, expectations in ((truth.packet_records, expected.packet_expectations),
                                      (truth.flow_records, expected.flow_expectations)):
            for record, item in zip(records, expectations):
                self.assertIs(item.identity, record.target)
                self.assertIs(item.positive, record.polarity is GroundTruthPolarity.POSITIVE)
        self.assertEqual(truth, before)

    def test_detection_and_evaluation_order_reaches_metrics_once_before_finalization(self):
        packets = (capacity_packet(0, protocol=6), capacity_packet(1, 1), capacity_packet(2, 2, protocol=6))
        trace, findings, entries = [], {'packet': [], 'flow': []}, {'packet': [], 'flow': []}
        original_stream = streaming_evaluation.run_detection_stream

        def stream(*args, **kwargs):
            trace.append('stream')
            original_stream(*args, **kwargs)
            trace.append('stream_done')

        def record(owner_type, name, channel, sink):
            original = getattr(owner_type, name)

            def receive(owner, value):
                sink[channel].append(value)
                trace.append(name)
                return original(owner, value)

            return receive

        def finalize(owner_type, label):
            original = owner_type.finish

            def finish(owner):
                trace.append(label)
                result = original(owner)
                trace.append(label + '_done')
                return result

            return finish

        with ExitStack() as stack:
            stack.enter_context(patch.object(streaming_evaluation, 'run_detection_stream', stream))
            for channel in ('packet', 'flow'):
                name = 'record_' + channel
                stack.enter_context(patch.object(IncrementalDetectionEvaluator, name,
                                                 record(IncrementalDetectionEvaluator, name, channel, findings)))
                stack.enter_context(patch.object(IncrementalDetectionMetrics, name,
                                                 record(IncrementalDetectionMetrics, name, channel, entries)))
            stack.enter_context(patch.object(IncrementalDetectionEvaluator, 'finish', finalize(IncrementalDetectionEvaluator, 'evaluation')))
            stack.enter_context(patch.object(IncrementalDetectionMetrics, 'finish', finalize(IncrementalDetectionMetrics, 'metrics')))
            result = execute(MemoryPacketSource(packets))
        self.assertEqual([entry.actual_index for entry in entries['packet']], [0, 1, 2])
        self.assertEqual([finding.detector_id for finding in findings['flow']], ['volume', 'control', 'volume', 'volume', 'control'])
        for channel in ('packet', 'flow'):
            self.assertEqual(len(entries[channel]), len(findings[channel]))
            for entry, finding in zip(entries[channel], findings[channel]):
                self.assertIs(entry.finding, finding)
        self.assertEqual(trace[-5:], ['stream_done', 'evaluation', 'evaluation_done', 'metrics', 'metrics_done'])
        self.assertEqual(result, collecting(packets))

    def test_single_delegated_execution_never_constructs_collecting_results_or_reports(self):
        packets = (capacity_packet(0, protocol=6), capacity_packet(0, 1, protocol=6))
        baseline = collecting(packets)
        with ExitStack() as stack:
            for target in ('application.detection_pipeline.DetectionPipelineResult.__post_init__',
                           'application.detection_evaluation.DetectionEvaluationResult.__post_init__',
                           'application.evaluation_report.EvaluationReport.__post_init__',
                           'application.detection_pipeline.run_detection_pipeline',
                           'application.detection_evaluation.evaluate_detection_result',
                           'application.detection_metrics.calculate_detection_metrics',
                           'ml.feature_projection.project_flow_features',
                           'research.research_example.research_example_from_window',
                           'integrations.iter_ldap_summary_jsonl'):
                stack.enter_context(patch(target, side_effect=AssertionError(target)))
            stream = stack.enter_context(patch.object(streaming_evaluation, 'run_detection_stream', wraps=streaming_evaluation.run_detection_stream))
            evaluator = stack.enter_context(patch.object(streaming_evaluation, 'IncrementalDetectionEvaluator', wraps=IncrementalDetectionEvaluator))
            metrics = stack.enter_context(patch.object(streaming_evaluation, 'IncrementalDetectionMetrics', wraps=IncrementalDetectionMetrics))
            analyze = stack.enter_context(patch.object(capture_execution, 'analyze_packet_outcome', wraps=capture_execution.analyze_packet_outcome))
            volume = stack.enter_context(patch.object(detector_orchestration, 'evaluate_flow_volume_threshold', wraps=detector_orchestration.evaluate_flow_volume_threshold))
            control = stack.enter_context(patch.object(detector_orchestration, 'evaluate_tcp_control_threshold', wraps=detector_orchestration.evaluate_tcp_control_threshold))
            self.assertEqual(execute(MemoryPacketSource(packets)), baseline)
        self.assertEqual((stream.call_count, evaluator.call_count, metrics.call_count, analyze.call_count, volume.call_count, control.call_count),
                         (1, 1, 1, 2, 1, 1))

    def test_lazy_source_releases_historical_observations_findings_and_entries(self):
        references, output_references = [], []

        def observe(original):
            def initialize(value):
                original(value)
                output_references.append(weakref.ref(value))
            return initialize

        class LazySource(PacketSource):
            def start(self):
                pass

            def stop(self):
                pass

            def __iter__(self):
                for index in range(64):
                    if index > 4:
                        gc.collect()
                        self_test.assertTrue(all(reference() is None for reference in references[:-4]))
                        self_test.assertTrue(all(reference() is None for reference in output_references[:-8]))
                    packet = capacity_packet(index, index)
                    references.append(weakref.ref(packet))
                    yield packet

        self_test = self
        with patch.object(DetectionFinding, '__post_init__', observe(DetectionFinding.__post_init__)), \
             patch.object(DetectionEvaluationEntry, '__post_init__', observe(DetectionEvaluationEntry.__post_init__)):
            result = execute(LazySource(), config=replace(configuration(), max_active_windows=1))
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertTrue(all(reference() is None for reference in output_references))
        self.assertEqual(result.packet_metrics.unclassified_count, 64)
        self.assertEqual(result.flow_metrics.false_positives, 64)

    def test_completed_metrics_do_not_keep_input_truth_or_configuration_reachable(self):
        config = configuration()
        packets = (capacity_packet(0),)
        truth = external_truth(packets, False, 17)
        source = MemoryPacketSource(packets)
        references = [weakref.ref(value) for value in (config, truth, source, packets[0])]
        result = execute(source, truth, config)
        del config, truth, source, packets
        gc.collect()
        self.assertTrue(all(reference() is None for reference in references))
        self.assertEqual(result.flow_metrics.true_positives, 1)

    def test_ldap_pending_and_completed_flows_remain_generic(self):
        for ipv6, complete in product((False, True), (False, True)):
            events = ((False, correlation_message(0x60)),)
            if complete:
                events += ((True, correlation_message(0x61)),)
            packets = correlation_packets(events, ipv6)
            self.assertEqual(execute(MemoryPacketSource(packets)), collecting(packets))

    def test_all_pcap_encodings_match_collecting_for_both_ip_and_transport_families(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'streaming.pcap'
            for ipv6, protocol in product((False, True), (6, 17)):
                packets = tuple(capacity_packet(0, second, ipv6, protocol) for second in (0, 1))
                truth = external_truth(packets, ipv6, protocol)
                baseline = collecting(packets, truth)
                for order, nano in product(('<', '>'), (False, True)):
                    path.write_bytes(pcap_bytes(tuple((index * 1000000, packet.raw_bytes)
                                                      for index, packet in enumerate(packets)), order, nano))
                    self.assertEqual(execute(PcapPacketSource(path, source=packets[0].source), truth), baseline)

    def test_repeated_independent_executions_are_identical_across_hash_seeds_and_timezones(self):
        baseline = replay().encode()
        self.assertEqual(replay().encode(), baseline)
        command = [sys.executable, '-B', '-c', 'from tests.test_streaming_evaluation import replay; print(replay(), end="")']
        for seed, zone in product(('1', '29', '503'), ('UTC', 'Asia/Kolkata', 'America/New_York')):
            result = subprocess.run(command, capture_output=True, check=True,
                                    env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
            self.assertEqual(result.stdout, baseline)
            self.assertEqual(result.stderr, b'')
