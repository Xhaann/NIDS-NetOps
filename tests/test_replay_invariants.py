import json
import os
import subprocess
import sys
import unittest
from dataclasses import asdict, replace
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analysis import FlowIdentity, FlowObservationWindowKey, FlowObservationWindowManager, extract_flow_feature_snapshot
from application import (
    DetectionMetrics, FlowDetectionIdentity, GroundTruth, GroundTruthPolarity, GroundTruthRecord,
    PacketDetectionIdentity, run_capture_execution, run_end_to_end_validation,
)
from application import end_to_end_validation
from capture import CaptureError, CaptureSource, PcapPacketSource
from ml import project_flow_features
from research import ResearchDataset, research_example_from_window
from tests.pcap_scenarios import addresses
from tests.protocol_scenarios import EPOCH, interleaved_observations
from tests.test_end_to_end_validation import settings
from tests.test_pcap_packet_source import global_header, record


SOURCE = CaptureSource('protocol-combinations')
ROOT = Path(__file__).resolve().parents[1]


def replay_configuration():
    configuration = settings()
    return replace(configuration, flow_volume_configuration=replace(configuration.flow_volume_configuration, threshold=2))


def replay_truth():
    configuration = replay_configuration()
    observations = interleaved_observations()
    packets = tuple(GroundTruthRecord(PacketDetectionIdentity(configuration.packet_configuration, index,
        o.captured_at, SOURCE.identifier, 1, o.captured_length, o.original_length),
        GroundTruthPolarity.POSITIVE if index in (8, 12) else GroundTruthPolarity.NEGATIVE)
        for index, o in enumerate(observations))
    flows = []
    for index, (ipv6, protocol, restart, next_sequence) in enumerate((
            (False, 6, 10, 6), (False, 17, 9, 5), (True, 6, 8, 4), (True, 17, 11, 7))):
        source, destination = addresses(ipv6)
        identity = FlowIdentity(source, destination, 12345, 443, protocol)
        for sequence, first, last, positive in ((index, 1, 3, True), (next_sequence, restart, restart + 1, False)):
            configurations = (configuration.flow_volume_configuration,)
            if protocol == 6:
                configurations += (configuration.tcp_control_configuration,)
            for detector_configuration in configurations:
                target = FlowDetectionIdentity(detector_configuration, FlowObservationWindowKey('replay', sequence),
                    identity, EPOCH + timedelta(seconds=first), EPOCH + timedelta(seconds=last))
                flows.append(GroundTruthRecord(target, GroundTruthPolarity.POSITIVE if positive else GroundTruthPolarity.NEGATIVE))
    return GroundTruth(packets, tuple(flows))


def capture_bytes():
    return global_header() + b''.join(record(o.raw_bytes,
        seconds=(o.captured_at - EPOCH).seconds, fraction=o.captured_at.microsecond, original=o.original_length)
        for o in interleaved_observations())


def replay(path):
    source = PcapPacketSource(path, source=SOURCE)
    result = run_end_to_end_validation(source, configuration=replay_configuration(),
                                      capture_session_id='replay', ground_truth=replay_truth())
    assert source._file is None and list(source) == []
    manager = FlowObservationWindowManager('replay', timedelta(seconds=5))
    outcomes, windows = [], []

    def receive(outcome):
        outcomes.append(outcome)
        if outcome.analysis is not None:
            windows.extend(manager.record(outcome.analysis).closed_windows)

    source = PcapPacketSource(path, source=SOURCE)
    run_capture_execution(source, receive)
    windows.extend(manager.end_capture_session())
    assert source._file is None and list(source) == []
    snapshots = tuple(extract_flow_feature_snapshot(window) for window in windows)
    dataset = ResearchDataset(tuple(research_example_from_window(window) for window in windows))
    return result, tuple(outcomes), tuple(windows), snapshots, dataset


def encode(result):
    validation, outcomes, windows, snapshots, dataset = result

    def scalar(value):
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, timedelta):
            return (value.days, value.seconds, value.microseconds)
        if isinstance(value, Enum):
            return value.value
        raise TypeError(type(value).__name__)

    data = (asdict(validation), tuple(asdict(o) for o in outcomes), tuple(asdict(w) for w in windows),
            tuple(asdict(s) for s in snapshots), asdict(dataset),
            tuple(example.projection.feature_names for example in dataset.examples))
    return json.dumps(data, default=scalar, sort_keys=True, separators=(',', ':'), allow_nan=False)


def failed_replay(path):
    source = PcapPacketSource(path, source=SOURCE)
    with patch.object(end_to_end_validation, 'evaluate_detection_result') as evaluate:
        try:
            run_end_to_end_validation(source, configuration=replay_configuration(),
                                      capture_session_id='replay', ground_truth=replay_truth())
        except CaptureError as error:
            failure = (type(error).__name__, str(error))
        else:
            raise AssertionError('truncated capture returned a validation result')
    evaluate.assert_not_called()
    assert source._file is None and list(source) == []
    return failure


class ReplayInvariantTests(unittest.TestCase):
    def test_complete_replays_preserve_exact_observations_windows_features_and_evaluation(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'mixed.pcap'
            data = capture_bytes()
            path.write_bytes(data)
            first = replay(path)
            self.assertEqual(first, replay(path))
            validation, outcomes, windows, snapshots, dataset = first
            self.assertEqual(tuple(o.observation for o in outcomes), interleaved_observations())
            self.assertEqual(tuple(f.raw_evidence.outcome for f in validation.pipeline_result.packet_findings), outcomes)
            self.assertEqual(tuple(f.raw_evidence.snapshot for f in validation.pipeline_result.flow_findings
                                   if f.detector_id == 'volume'), snapshots)
            self.assertEqual([w.key.sequence_number for w in windows], [2, 1, 0, 3, 4, 5, 6, 7])
            self.assertEqual(validation.report.metrics.packet_metrics, DetectionMetrics(2, 0, 0, 20, 5))
            self.assertEqual(validation.report.metrics.flow_metrics, DetectionMetrics(6, 0, 0, 6))
            for window, snapshot, example in zip(windows, snapshots, dataset.examples):
                self.assertIs(snapshot.observation_window, window)
                self.assertIs(example.observation_window, window)
                self.assertEqual(example.projection, project_flow_features(snapshot))
                self.assertEqual(len(example.projection.values), 49)
                self.assertIsNone(example.ground_truth)
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(tuple(Path(directory).iterdir()), (path,))
        self.assertFalse(Path(directory).exists())

    def test_complete_output_is_identical_across_hash_seeds_and_timezones(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'mixed.pcap'
            data = capture_bytes()
            path.write_bytes(data)
            expected = (encode(replay(path)) + '\n').encode()
            script = ('from pathlib import Path\n'
                      'import sys\n'
                      'from tests.test_replay_invariants import replay, encode\n'
                      'print(encode(replay(Path(sys.argv[1]))))\n')
            for seed, zone in (('1', 'UTC'), ('8675309', 'Asia/Kolkata'), ('42', 'America/Los_Angeles')):
                with self.subTest(seed=seed, zone=zone):
                    result = subprocess.run([sys.executable, '-B', '-c', script, str(path)], cwd=ROOT,
                        env=dict(os.environ, PYTHONPATH=str(ROOT / 'src'), PYTHONHASHSEED=seed, TZ=zone),
                        capture_output=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, b'')
                    self.assertEqual(result.stdout, expected)
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(tuple(Path(directory).iterdir()), (path,))
        self.assertFalse(Path(directory).exists())

    def test_truncated_replay_preserves_failure_and_cleanup_across_environments(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'truncated.pcap'
            data = capture_bytes()[:-1]
            path.write_bytes(data)
            expected = ('CaptureError', 'truncated PCAP packet payload')
            self.assertEqual(failed_replay(path), expected)
            self.assertEqual(failed_replay(path), expected)
            script = ('from pathlib import Path\n'
                      'import sys\n'
                      'from tests.test_replay_invariants import failed_replay\n'
                      'print(repr(failed_replay(Path(sys.argv[1]))))\n')
            for seed, zone in (('1', 'UTC'), ('8675309', 'Asia/Kolkata')):
                result = subprocess.run([sys.executable, '-B', '-c', script, str(path)], cwd=ROOT,
                    env=dict(os.environ, PYTHONPATH=str(ROOT / 'src'), PYTHONHASHSEED=seed, TZ=zone),
                    capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b'')
                self.assertEqual(result.stdout, (repr(expected) + '\n').encode())
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(tuple(Path(directory).iterdir()), (path,))
        self.assertFalse(Path(directory).exists())
