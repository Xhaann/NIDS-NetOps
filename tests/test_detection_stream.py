import gc
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
import weakref
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from unittest.mock import patch

import application
from analysis import FlowObservationWindowError, LDAPRequestSummaryStatus
from application import DetectionPipelineResult, DetectionSession, run_detection_pipeline, run_detection_stream
from application import detection_pipeline
from application.cli import _finding_json
from capture import PcapPacketSource
from detection import DetectionFinding, PacketIntegrityDecision
from integrations import iter_ldap_summary_jsonl
from tests.pcap_scenarios import pcap_bytes
from tests.test_flow_capacity import capacity_packet
from tests.test_flow_capacity_pipeline import session
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ldap_correlation import correlation_message, correlation_packets


def execute(source, packet_consumer, flow_consumer, **options):
    arguments = dict(detection_session=session(), capture_session_id='stream',
                     inactivity_timeout=timedelta(seconds=5), max_active_windows=2,
                     packet_finding_consumer=packet_consumer, flow_finding_consumer=flow_consumer)
    arguments.update(options)
    return run_detection_stream(source, **arguments)


def collected(packets, **options):
    return run_detection_pipeline(MemoryPacketSource(packets), detection_session=session(),
                                  capture_session_id='stream', inactivity_timeout=timedelta(seconds=5),
                                  max_active_windows=options.get('max_active_windows', 2))


def ordered_replay():
    packets = tuple(capacity_packet(index, second, ipv6=bool(index % 2), protocol=6 if index % 3 else 17)
                    for index, second in ((0, 0), (1, 0), (0, 1), (2, 2), (3, 2), (3, 7)))
    deliveries = []
    execute(MemoryPacketSource(packets), lambda f: deliveries.append(('packet', _finding_json(f))),
            lambda f: deliveries.append(('flow', _finding_json(f))))
    return json.dumps(deliveries, ensure_ascii=True, allow_nan=False, separators=(',', ':'))


class DetectionStreamTests(unittest.TestCase):
    def test_public_signature_requires_consumers_without_new_finding_fields(self):
        self.assertIs(application.run_detection_stream, detection_pipeline.run_detection_stream)
        self.assertIn('run_detection_stream', application.__all__)
        signature = inspect.signature(run_detection_stream)
        self.assertEqual(tuple(signature.parameters),
                         ('source', 'detection_session', 'capture_session_id', 'inactivity_timeout',
                          'packet_finding_consumer', 'flow_finding_consumer', 'max_active_windows'))
        self.assertIsNone(signature.return_annotation)
        self.assertEqual(signature.parameters['max_active_windows'].default, 1024)
        for name in tuple(signature.parameters)[1:]:
            self.assertIs(signature.parameters[name].kind, inspect.Parameter.KEYWORD_ONLY)
        for name in ('packet_finding_consumer', 'flow_finding_consumer'):
            self.assertIs(signature.parameters[name].default, inspect.Parameter.empty)
        self.assertEqual(tuple(f.name for f in fields(DetectionFinding)),
                         ('detector_id', 'detector_version', 'decision', 'raw_evidence', 'security_interpretation'))
        self.assertEqual(tuple(f.name for f in fields(DetectionPipelineResult)), ('packet_findings', 'flow_findings'))

    def test_invalid_consumers_and_configuration_fail_before_capture_even_when_empty(self):
        invalid_options = [({name: value}, TypeError)
                           for name in ('packet_finding_consumer', 'flow_finding_consumer')
                           for value in (None, False, 0, 'consumer', [], object())]
        invalid_options += [({'detection_session': None}, TypeError),
                            ({'capture_session_id': ''}, FlowObservationWindowError),
                            ({'inactivity_timeout': timedelta(0)}, FlowObservationWindowError),
                            ({'max_active_windows': 0}, FlowObservationWindowError),
                            ({'max_active_windows': True}, TypeError)]
        for options, error in invalid_options:
            source = MemoryPacketSource(())
            with self.subTest(options=options), self.assertRaises(error):
                execute(source, lambda f: None, lambda f: None, **options)
            self.assertEqual(source.events, [])
        with self.assertRaises(TypeError):
            run_detection_stream(MemoryPacketSource(()), detection_session=session(), capture_session_id='stream',
                                 inactivity_timeout=timedelta(seconds=5))

    def test_empty_input_runs_cleanup_without_callbacks_or_result_allocation(self):
        source = MemoryPacketSource(())
        with patch.object(detection_pipeline, 'DetectionPipelineResult', side_effect=AssertionError('collection')), \
             patch.object(DetectionSession, 'run_packets') as packets, \
             patch.object(DetectionSession, 'run_closed_flows') as flows:
            result = execute(source, self.fail, self.fail)
        self.assertIsNone(result)
        packets.assert_not_called()
        flows.assert_not_called()
        self.assertEqual(source.events, ['start', 'stop'])

    def test_ipv4_ipv6_tcp_udp_deliver_exact_existing_findings_and_original_observations(self):
        for ipv6 in (False, True):
            for protocol in (6, 17):
                packets = tuple(capacity_packet(0, second, ipv6, protocol, reverse=bool(second % 2))
                                for second in (0, 1, 6))
                packet_findings, flow_findings = [], []
                self.assertIsNone(execute(MemoryPacketSource(packets), packet_findings.append, flow_findings.append))
                expected = collected(packets)
                self.assertEqual(DetectionPipelineResult(tuple(packet_findings), tuple(flow_findings)), expected)
                for finding, observation in zip(packet_findings, packets):
                    self.assertIs(finding.raw_evidence.observation, observation)
                self.assertEqual(len(flow_findings), 4 if protocol == 6 else 2)

    def test_delivery_precedes_next_acquisition_and_packet_precedes_capacity_or_inactivity_closure(self):
        packets = (capacity_packet(0), capacity_packet(1, 1, protocol=6),
                   capacity_packet(2, 2), capacity_packet(2, 7))
        source = MemoryPacketSource(packets)
        events = []

        def packet(finding):
            events.append(('packet', int(finding.raw_evidence.captured_at.timestamp()), source.events[-1]))

        def flow(finding):
            evidence = finding.raw_evidence
            events.append(('flow', evidence.sequence_number, finding.detector_id,
                           evidence.closure_reason.value, source.events[-1]))

        execute(source, packet, flow)
        self.assertEqual(events, [
            ('packet', 0, 'produce:0'), ('packet', 1, 'produce:1'), ('packet', 2, 'produce:2'),
            ('flow', 0, 'volume', 'capacity', 'produce:2'), ('packet', 7, 'produce:3'),
            ('flow', 2, 'volume', 'inactivity', 'produce:3'),
            ('flow', 1, 'volume', 'capture_session_end', 'stop'),
            ('flow', 1, 'control', 'capture_session_end', 'stop'),
            ('flow', 3, 'volume', 'capture_session_end', 'stop'),
        ])

    def test_duplicate_observations_and_identical_consumer_are_not_deduplicated(self):
        observation = capacity_packet(0)
        deliveries = []
        execute(MemoryPacketSource((observation, observation)), deliveries.append, deliveries.append)
        self.assertEqual(len(deliveries), 3)
        self.assertEqual(deliveries[0], deliveries[1])
        self.assertIsNot(deliveries[0], deliveries[1])
        self.assertEqual(deliveries[2].raw_evidence.total_packet_count, 2)

    def test_return_values_do_not_request_cancellation_or_automatic_retry(self):
        deliveries = []

        def receive(finding):
            deliveries.append(finding)
            return False

        execute(MemoryPacketSource((capacity_packet(0), capacity_packet(1))), receive, receive)
        self.assertEqual(len(deliveries), 4)

    def test_recognized_malformed_incomplete_unavailable_and_integrity_failures_are_delivered(self):
        valid = capacity_packet(0)
        packets = (replace(valid, raw_bytes=b'', captured_length=0),
                   replace(valid, raw_bytes=valid.raw_bytes[:14] + b'\x50' + valid.raw_bytes[15:]),
                   replace(valid, link_type=None),
                   replace(valid, raw_bytes=valid.raw_bytes[:24] + b'\x00\x00' + valid.raw_bytes[26:]), valid)
        findings, flows = [], []
        execute(MemoryPacketSource(packets), findings.append, flows.append)
        self.assertEqual(tuple(findings), collected(packets).packet_findings)
        self.assertEqual([finding.decision for finding in findings],
                         [PacketIntegrityDecision.NOT_EVALUABLE, PacketIntegrityDecision.MATCH,
                          PacketIntegrityDecision.NOT_EVALUABLE, PacketIntegrityDecision.MATCH, PacketIntegrityDecision.NO_MATCH])
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].raw_evidence.total_packet_count, 1)

    def test_collecting_adapter_preserves_exact_objects_without_reexecuting_detection(self):
        sample = collected((capacity_packet(0),))
        calls = []

        def deliver(source, **options):
            calls.append((source, options))
            options['packet_finding_consumer'](sample.packet_findings[0])
            options['flow_finding_consumer'](sample.flow_findings[0])

        source = MemoryPacketSource(())
        with patch.object(detection_pipeline, 'run_detection_stream', deliver):
            result = run_detection_pipeline(source, detection_session=session(), capture_session_id='stream',
                                             inactivity_timeout=timedelta(seconds=5), max_active_windows=3)
        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0][0], source)
        self.assertEqual(calls[0][1]['max_active_windows'], 3)
        self.assertIs(result.packet_findings[0], sample.packet_findings[0])
        self.assertIs(result.flow_findings[0], sample.flow_findings[0])
        self.assertEqual(source.events, [])

    def test_caller_can_retain_immutable_objects_after_stream_completion(self):
        packets = (capacity_packet(0, protocol=6, payload=b'synthetic-body'), capacity_packet(1, 1))
        findings, flows = [], []
        execute(MemoryPacketSource(packets), findings.append, flows.append, max_active_windows=1)
        first = flows[0]
        window = first.raw_evidence.snapshot.observation_window
        self.assertEqual(window.coordinated_state.tcp_stream_state.forward.contiguous_payload, b'synthetic-body')
        self.assertEqual(tuple(findings), collected(packets, max_active_windows=1).packet_findings)
        with self.assertRaises(FrozenInstanceError):
            first.detector_id = 'changed'
        self.assertEqual(window.coordinated_state.flow_statistics.packet_count, 1)

    def test_no_historical_findings_windows_or_packet_objects_retained_with_lazy_input(self):
        class LazySource:
            def __init__(self, count):
                self.count = count
                self.starts = 0
                self.stops = 0

            def start(self):
                self.starts += 1

            def __iter__(self):
                for index in range(self.count):
                    yield capacity_packet(index, index, ipv6=bool(index % 2), protocol=6, payload=b'x' * 256)

            def stop(self):
                self.stops += 1

        for count in (32, 256):
            references = []
            seen = [0, 0]

            def packet(finding):
                gc.collect()
                self.assertTrue(all(reference() is None for reference in references))
                references.append(weakref.ref(finding))
                references.append(weakref.ref(finding.raw_evidence.observation))
                seen[0] += 1

            def flow(finding):
                references.append(weakref.ref(finding))
                window = (finding.raw_evidence.snapshot.observation_window if hasattr(finding.raw_evidence, 'snapshot')
                          else finding.raw_evidence.observation_window)
                references.append(weakref.ref(window))
                seen[1] += 1

            source = LazySource(count)
            execute(source, packet, flow, max_active_windows=4)
            gc.collect()
            self.assertEqual(seen, [count, count * 2])
            self.assertEqual((source.starts, source.stops), (1, 1))
            self.assertTrue(all(reference() is None for reference in references))

    def test_pcap_stream_matches_collecting_pipeline_for_each_encoding(self):
        packets = tuple(capacity_packet(i, i, ipv6=bool(i % 2), protocol=6 if i % 3 else 17) for i in range(5))
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'stream.pcap'
            for order in ('<', '>'):
                for nano in (False, True):
                    path.write_bytes(pcap_bytes(tuple((i * 1000000, p.raw_bytes) for i, p in enumerate(packets)), order, nano))
                    actual_packets, actual_flows = [], []
                    execute(PcapPacketSource(path, source=packets[0].source), actual_packets.append, actual_flows.append)
                    self.assertEqual(DetectionPipelineResult(tuple(actual_packets), tuple(actual_flows)), collected(packets))

    def test_ldap_findings_reuse_finalized_summaries_and_existing_export_without_reparsing(self):
        for ipv6 in (False, True):
            packets = correlation_packets(((False, correlation_message(0x63)),), ipv6)
            flows = []
            execute(MemoryPacketSource(packets), lambda f: None, flows.append)
            self.assertEqual(tuple(flows), collected(packets).flow_findings)
            window = flows[0].raw_evidence.snapshot.observation_window
            summary = window.ldap_correlation_state.requests[0].request_summary
            self.assertIs(summary.status, LDAPRequestSummaryStatus.UNRESOLVED)
            with patch('analysis.packet_analysis.analyze_packet', side_effect=AssertionError('reparse')):
                encoded, = iter_ldap_summary_jsonl((summary,))
            self.assertEqual(json.loads(encoded)['status'], 'unresolved')
            self.assertNotIn('payload', encoded.decode())

    def test_stream_does_not_invoke_collecting_result_serialization_research_or_export(self):
        with patch.object(detection_pipeline, 'run_detection_pipeline', side_effect=AssertionError('collect')), \
             patch.object(detection_pipeline, 'DetectionPipelineResult', side_effect=AssertionError('result')), \
             patch('application.cli._result_json', side_effect=AssertionError('serialize')), \
             patch('research.research_example_from_window', side_effect=AssertionError('research')), \
             patch('ml.project_flow_features', side_effect=AssertionError('ML')), \
             patch('integrations.iter_ldap_summary_jsonl', side_effect=AssertionError('export')):
            execute(MemoryPacketSource((capacity_packet(0, protocol=6),)), lambda f: None, lambda f: None)

    def test_repeated_replay_is_byte_identical_across_hash_seeds_and_timezones(self):
        expected = ordered_replay().encode()
        self.assertEqual(ordered_replay().encode(), expected)
        command = [sys.executable, '-B', '-c',
                   'from tests.test_detection_stream import ordered_replay; print(ordered_replay(), end="")']
        for seed, zone in (('1', 'UTC'), ('53', 'Asia/Kolkata'), ('821', 'America/New_York')):
            process = subprocess.run(command, capture_output=True, check=True,
                                     env=dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone))
            self.assertEqual(process.stdout, expected)
            self.assertEqual(process.stderr, b'')
