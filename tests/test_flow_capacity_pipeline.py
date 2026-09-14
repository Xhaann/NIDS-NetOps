import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from dataclasses import fields, replace
from datetime import timedelta
from unittest.mock import patch

from analysis import (
    DEFAULT_MAX_ACTIVE_WINDOWS, FeatureContractVersion, FlowObservationWindowClosureReason,
    FlowObservationWindowManager, analyze_packet, extract_flow_feature_snapshot,
)
from application import (
    DetectionSession, GroundTruth, run_detection_pipeline, run_end_to_end_validation,
    run_flow_observation_session,
)
from application import detector_orchestration
from application.cli import _result_json
from capture import CaptureError, PcapPacketSource
from detection import DetectionFinding
from research import research_example_from_window
from tests.pcap_scenarios import pcap_bytes
from tests.test_end_to_end_validation import settings
from tests.test_flow_capacity import capacity_packet
from tests.test_flow_observation_session import MemoryPacketSource


def session():
    configuration = settings()
    return DetectionSession(configuration.packet_configuration, configuration.flow_volume_configuration,
                            configuration.tcp_control_configuration)


def pipeline(packets, limit=2):
    return run_detection_pipeline(MemoryPacketSource(packets), detection_session=session(),
                                  capture_session_id='capacity', inactivity_timeout=timedelta(seconds=5),
                                  max_active_windows=limit)


def capacity_replay():
    packets = tuple(capacity_packet(index, seconds, ipv6=bool(index % 2), protocol=6 if index % 3 else 17)
                    for index, seconds in ((0, 0), (1, 0), (2, 0), (0, 1), (3, 2), (1, 3), (4, 4)))
    return _result_json(pipeline(packets))


class FlowCapacityPipelineTests(unittest.TestCase):
    def test_configuration_retains_bound_and_rejects_invalid_limits_before_capture(self):
        configuration = settings()
        self.assertEqual(configuration.max_active_windows, DEFAULT_MAX_ACTIVE_WINDOWS)
        for invalid in (True, None, 1.5, '2', 0, -1):
            error = ValueError if type(invalid) is int else TypeError
            with self.assertRaises(error):
                replace(configuration, max_active_windows=invalid)
            for operation in ('flow', 'pipeline'):
                source = MemoryPacketSource(())
                with self.assertRaises(error):
                    if operation == 'flow':
                        run_flow_observation_session(source, capture_session_id='capacity',
                                                     inactivity_timeout=timedelta(seconds=5),
                                                     closed_window_consumer=lambda window: None,
                                                     max_active_windows=invalid)
                    else:
                        run_detection_pipeline(source, detection_session=session(), capture_session_id='capacity',
                                               inactivity_timeout=timedelta(seconds=5), max_active_windows=invalid)
                self.assertEqual(source.events, [])
        self.assertNotEqual(replace(configuration, max_active_windows=1), configuration)

    def test_closed_windows_are_delivered_once_in_capacity_then_final_creation_order(self):
        packets = (capacity_packet(0), capacity_packet(1, 1, ipv6=True, protocol=6),
                   capacity_packet(0, 2), capacity_packet(2, 3, protocol=6))
        source = MemoryPacketSource(packets)
        delivered = []

        def receive(window):
            delivered.append((window, tuple(source.events)))

        run_flow_observation_session(source, capture_session_id='capacity', inactivity_timeout=timedelta(seconds=5),
                                     closed_window_consumer=receive, max_active_windows=2)
        self.assertEqual([w.key.sequence_number for w, _ in delivered], [1, 0, 2])
        self.assertEqual([w.closure_reason.value for w, _ in delivered],
                         ['capacity', 'capture_session_end', 'capture_session_end'])
        self.assertNotIn('stop', delivered[0][1])
        self.assertEqual(delivered[1][1][-1], 'stop')
        self.assertEqual(source.events.count('stop'), 1)

    def test_capacity_consumer_failure_stops_capture_without_retry_or_final_delivery(self):
        source = MemoryPacketSource(tuple(capacity_packet(i) for i in range(4)))
        delivered = []
        error = RuntimeError('consumer failed')

        def fail(window):
            delivered.append(window)
            raise error

        with self.assertRaises(RuntimeError) as raised:
            run_flow_observation_session(source, capture_session_id='capacity', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=fail, max_active_windows=1)
        self.assertIs(raised.exception, error)
        self.assertEqual([w.key.sequence_number for w in delivered], [0])
        self.assertEqual(source.events, ['start', 'produce:0', 'produce:1', 'stop'])

    def test_capture_failure_finalizes_only_remaining_active_windows(self):
        error = CaptureError('capture unavailable')
        source = MemoryPacketSource((capacity_packet(0), capacity_packet(1, 1)), iteration_error=error)
        delivered = []
        with self.assertRaises(CaptureError) as raised:
            run_flow_observation_session(source, capture_session_id='capacity', inactivity_timeout=timedelta(seconds=5),
                                         closed_window_consumer=delivered.append, max_active_windows=1)
        self.assertIs(raised.exception, error)
        self.assertEqual([w.key.sequence_number for w in delivered], [0, 1])
        self.assertEqual([w.closure_reason.value for w in delivered], ['capacity', 'capture_session_end'])
        self.assertEqual(source.events[-1], 'stop')

    def test_failed_packet_analysis_never_consumes_capacity(self):
        valid = capacity_packet(0)
        malformed = replace(capacity_packet(1, 1), raw_bytes=b'', captured_length=0)
        result = pipeline((valid, malformed), 1)
        self.assertEqual(len(result.packet_findings), 2)
        self.assertEqual(len(result.flow_findings), 1)
        self.assertIs(result.flow_findings[0].raw_evidence.closure_reason,
                      FlowObservationWindowClosureReason.CAPTURE_SESSION_END)
        self.assertEqual(result.flow_findings[0].raw_evidence.total_packet_count, 1)

    def test_detectors_match_explicit_window_reference_for_both_families_and_transports(self):
        for ipv6 in (False, True):
            for protocol in (6, 17):
                packets = tuple(capacity_packet(i, i, ipv6, protocol) for i in range(3))
                result = pipeline(packets, 1)
                reference = FlowObservationWindowManager('capacity', timedelta(seconds=5))
                expected = []
                for index, packet in enumerate(packets):
                    active = reference.record(analyze_packet(packet)).active_window
                    closed = reference.close(active.identity)
                    reason = (FlowObservationWindowClosureReason.CAPACITY if index < 2
                              else FlowObservationWindowClosureReason.CAPTURE_SESSION_END)
                    snapshot = extract_flow_feature_snapshot(replace(closed, closure_reason=reason))
                    self.assertEqual(snapshot.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
                    expected.extend(session().run_closed_flows((snapshot,)))
                    example = research_example_from_window(snapshot.observation_window)
                    self.assertEqual(len(example.projection.values), 49)
                self.assertEqual(result.flow_findings, tuple(expected))
                unlimited = pipeline(packets, 10)
                self.assertEqual(result.packet_findings, unlimited.packet_findings)
                self.assertEqual([f.decision for f in result.flow_findings], [f.decision for f in unlimited.flow_findings])
        self.assertEqual(tuple(f.name for f in fields(DetectionFinding)),
                         ('detector_id', 'detector_version', 'decision', 'raw_evidence', 'security_interpretation'))

    def test_below_capacity_matches_default_pipeline_exactly_and_empty_input_is_valid(self):
        packets = tuple(capacity_packet(i % 2, i, ipv6=bool(i % 2)) for i in range(4))
        expected = run_detection_pipeline(MemoryPacketSource(packets), detection_session=session(),
                                          capture_session_id='capacity', inactivity_timeout=timedelta(seconds=5))
        self.assertEqual(pipeline(packets, 2), expected)
        self.assertEqual(pipeline((), 1).packet_findings, ())
        self.assertEqual(pipeline((), 1).flow_findings, ())

    def test_capacity_detector_failure_preserves_existing_stop_and_no_retry_behavior(self):
        source = MemoryPacketSource(tuple(capacity_packet(i) for i in range(3)))
        error = RuntimeError('flow detector failed')
        with patch.object(detector_orchestration, 'evaluate_flow_volume_threshold', side_effect=error) as detect:
            with self.assertRaises(RuntimeError) as raised:
                run_detection_pipeline(source, detection_session=session(), capture_session_id='capacity',
                                       inactivity_timeout=timedelta(seconds=5), max_active_windows=1)
        self.assertIs(raised.exception, error)
        self.assertEqual(detect.call_count, 1)
        self.assertEqual(source.events, ['start', 'produce:0', 'produce:1', 'stop'])

    def test_pcap_evaluation_retains_capacity_configuration_and_matches_direct_pipeline(self):
        packets = tuple(capacity_packet(i, i, ipv6=bool(i % 2), protocol=6 if i % 3 else 17) for i in range(5))
        configuration = replace(settings(), max_active_windows=2)
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'capacity.pcap'
            path.write_bytes(pcap_bytes(tuple((i * 1000000, p.raw_bytes) for i, p in enumerate(packets))))
            result = run_end_to_end_validation(PcapPacketSource(path, source=packets[0].source),
                                               configuration=configuration, capture_session_id='capacity',
                                               ground_truth=GroundTruth((), ()))
        self.assertEqual(result.pipeline_result, pipeline(packets))
        self.assertIs(result.report.configuration, configuration)
        self.assertEqual(result.report.configuration.max_active_windows, 2)
        self.assertIsNotNone(result.report.metrics)

    def test_capacity_finding_json_contains_no_payload_or_additional_finding_fields(self):
        secret = b'synthetic-private-body'
        result = pipeline((capacity_packet(0, protocol=6, payload=secret), capacity_packet(1, 1)), 1)
        encoded = _result_json(result)
        self.assertIn('"closure_reason":"capacity"', encoded)
        for value in (secret.decode(), secret.hex(), 'raw_bytes', 'contiguous_payload', 'password', 'severity', 'confidence'):
            self.assertNotIn(value, encoded)

    def test_repeated_process_hash_seed_timezone_results_are_byte_identical(self):
        expected = capacity_replay().encode()
        self.assertEqual(capacity_replay().encode(), expected)
        command = [sys.executable, '-B', '-c',
                   'from tests.test_flow_capacity_pipeline import capacity_replay; print(capacity_replay(), end="")']
        for seed, zone in (('1', 'UTC'), ('17', 'Asia/Kolkata'), ('123', 'America/New_York')):
            environment = dict(os.environ, PYTHONPATH='src', PYTHONHASHSEED=seed, TZ=zone)
            process = subprocess.run(command, env=environment, capture_output=True, check=True)
            self.assertEqual(process.stderr, b'')
            self.assertEqual(process.stdout, expected)
