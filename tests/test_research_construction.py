import os
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent
from unittest.mock import patch

from analysis import FlowObservationWindow, FlowObservationWindowManager, extract_flow_feature_snapshot
from ml import project_flow_features
from research import ResearchDataset, ResearchExample, research_example_from_window
from tests.test_flow_feature_snapshot import packet_at
from tests.test_research_observation_timestamps import closed_window, replace_timestamp, MutableOffset, TIMESTAMP_FIELDS


class ResearchConstructionTests(unittest.TestCase):
    def test_snapshot_projection_and_example_share_one_origin(self):
        window = closed_window()
        snapshots, projections = [], []

        def extract(origin):
            snapshot = extract_flow_feature_snapshot(origin)
            snapshots.append(snapshot)
            return snapshot

        def project(snapshot):
            projection = project_flow_features(snapshot)
            projections.append(projection)
            return projection

        truth = ' Observed condition É '
        before = repr(window)
        with patch('research.research_example.extract_flow_feature_snapshot', side_effect=extract) as extraction, \
             patch('research.research_example.project_flow_features', side_effect=project) as projection:
            example = research_example_from_window(window, truth)
        extraction.assert_called_once_with(window)
        projection.assert_called_once_with(snapshots[0])
        self.assertIs(snapshots[0].observation_window, window)
        self.assertIs(example.observation_window, window)
        self.assertIs(example.projection, projections[0])
        self.assertIs(example.ground_truth, truth)
        expected = project_flow_features(extract_flow_feature_snapshot(window))
        self.assertEqual(example.projection, expected)
        self.assertEqual(example.projection.feature_names, expected.feature_names)
        self.assertEqual(example.projection.feature_contract, expected.feature_contract)
        self.assertEqual(len(example.projection.values), 49)
        self.assertIn(None, example.projection.values)
        self.assertIn(0.0, example.projection.values)
        self.assertEqual(repr(window), before)
        self.assertEqual(example, ResearchExample(expected, truth, window))
        self.assertEqual(ResearchExample(expected), ResearchExample(expected, None))
        self.assertEqual(ResearchExample(expected, truth), ResearchExample(expected, truth, None))
        self.assertIsNone(research_example_from_window(window).ground_truth)

    def test_invalid_inputs_fail_before_extraction_with_stable_precedence(self):
        window = closed_window()
        active = replace(window, closure_reason=None)

        class OtherWindow(FlowObservationWindow):
            pass

        class OtherTruth(str):
            pass

        other = OtherWindow(window.key, window.coordinated_state, window.closure_reason)
        cases = [(value, '', TypeError, 'window must be exactly a FlowObservationWindow')
                 for value in (None, True, {}, window.key, other)]
        cases += [(window, truth, TypeError, 'ground_truth must be exactly a string or None')
                  for truth in (True, 1, [], OtherTruth('label'))]
        cases += [(window, truth, ValueError, 'ground_truth must not be blank') for truth in ('', ' \t')]
        cases += [(active, '', ValueError, 'ground_truth must not be blank'),
                  (active, None, ValueError, 'observation_window must be closed')]
        for aggregate, field in TIMESTAMP_FIELDS:
            timestamp = getattr(getattr(window.coordinated_state, aggregate), field)
            unsafe = replace_timestamp(window, aggregate, field, timestamp.replace(tzinfo=MutableOffset()))
            cases.append((unsafe, None, ValueError,
                          f'observation_window.coordinated_state.{aggregate}.{field} must use a fixed UTC datetime.timezone'))
        with patch('research.research_example.extract_flow_feature_snapshot') as extraction, \
             patch('research.research_example.project_flow_features') as projection:
            for origin, truth, error_type, message in cases:
                with self.subTest(message=message):
                    with self.assertRaises(error_type) as error:
                        research_example_from_window(origin, truth)
                    self.assertEqual(str(error.exception), message)
            extraction.assert_not_called()
            projection.assert_not_called()
        self.assertIsNone(active.closure_reason)

    def test_extraction_and_projection_failures_propagate_without_retry(self):
        window = closed_window()
        for target in ('extract_flow_feature_snapshot', 'project_flow_features'):
            error = RuntimeError(target)
            with self.subTest(target=target), patch('research.research_example.' + target, side_effect=error) as operation:
                with self.assertRaises(RuntimeError) as caught:
                    research_example_from_window(window)
                self.assertIs(caught.exception, error)
                operation.assert_called_once()

    def test_multiple_windows_and_repeated_members_keep_their_context(self):
        manager = FlowObservationWindowManager('construction', timedelta(seconds=5))
        windows = []
        for seconds in (0, 1, 6, 7):
            windows.extend(manager.record(packet_at(seconds)).closed_windows)
        windows.append(manager.close(manager.active_windows()[0].identity))
        manager.record(packet_at(8))
        windows.extend(manager.end_capture_session())
        examples = tuple(research_example_from_window(window) for window in windows)
        self.assertEqual(examples[0].projection, examples[1].projection)
        self.assertNotEqual(examples[0], examples[1])
        self.assertEqual([window.closure_reason.value for window in windows],
                         ['inactivity', 'explicit_segmentation', 'capture_session_end'])
        for example, window in zip(examples, windows):
            self.assertIs(example.observation_window, window)
        caller = [examples[1], examples[0], examples[1], examples[2]]
        dataset = ResearchDataset(caller)
        before = repr(dataset)
        caller.clear()
        self.assertEqual(manager.end_capture_session(), ())
        self.assertEqual(dataset.examples, (examples[1], examples[0], examples[1], examples[2]))
        self.assertIs(dataset.examples[0], dataset.examples[2])
        self.assertGreater(dataset.examples[0].observation_window.first_captured_at,
                           dataset.examples[1].observation_window.first_captured_at)
        self.assertEqual(repr(dataset), before)
        with self.assertRaises(FrozenInstanceError):
            examples[0].observation_window = None

    def test_pcap_outcomes_produce_exact_context_for_ipv4_ipv6_tcp_udp(self):
        from application import GroundTruth, run_capture_execution, run_end_to_end_validation
        from capture import PcapPacketSource
        from tests.test_end_to_end_validation import settings, wire
        from tests.test_packet_analysis import make_observation, UDP_BYTES
        from tests.test_pcap_packet_source import global_header, record

        for ipv6, protocol in ((False, 6), (False, 17), (True, 6), (True, 17)):
            with self.subTest(ipv6=ipv6, protocol=protocol), TemporaryDirectory() as directory:
                frame = wire(ipv6, protocol)
                bad = make_observation(17, UDP_BYTES, ipv4_checksum=0)
                data = global_header() + record(bad.raw_bytes, seconds=0)
                data += b''.join(record(frame.raw_bytes, seconds=t) for t in (1, 2, 7, 8))
                path = Path(directory) / 'observations.pcap'
                path.write_bytes(data)

                def replay():
                    return run_end_to_end_validation(PcapPacketSource(path), configuration=settings(),
                                                    capture_session_id='construction', ground_truth=GroundTruth((), ()))

                before = replay()
                manager = FlowObservationWindowManager('construction', timedelta(seconds=5))
                outcomes, windows, examples = [], [], []

                def publish(window):
                    windows.append(window)
                    examples.append(research_example_from_window(window))

                def receive(outcome):
                    outcomes.append(outcome)
                    if outcome.analysis is not None:
                        for window in manager.record(outcome.analysis).closed_windows:
                            publish(window)

                run_capture_execution(PcapPacketSource(path), receive)
                for window in manager.end_capture_session():
                    publish(window)
                self.assertIsNone(outcomes[0].analysis)
                self.assertEqual(len(windows), 2)
                self.assertEqual(windows[0].identity, windows[1].identity)
                self.assertEqual(examples[0].projection, examples[1].projection)
                self.assertNotEqual(examples[0], examples[1])
                for example, window in zip(examples, windows):
                    self.assertIs(example.observation_window, window)
                    self.assertEqual(example.projection, project_flow_features(extract_flow_feature_snapshot(window)))
                self.assertEqual(replay(), before)
                self.assertEqual(path.read_bytes(), data)
            self.assertFalse(Path(directory).exists())

    def test_complete_representations_are_deterministic_without_detector_imports(self):
        root = Path(__file__).resolve().parents[1]
        script = dedent('''
            import sys
            class RejectDetectionImports:
                def find_spec(self, fullname, path=None, target=None):
                    if fullname.split('.')[0] in ('application', 'detection'):
                        raise AssertionError(fullname)
            sys.meta_path.insert(0, RejectDetectionImports())
            from analysis import extract_flow_feature_snapshot
            from research import ResearchDataset, research_example_from_window
            from research.research_example import research_example_from_window as direct
            from tests.test_research_observation_timestamps import closed_window
            assert direct is research_example_from_window
            window = closed_window()
            snapshot = extract_flow_feature_snapshot(window)
            examples = tuple(research_example_from_window(window, truth) for truth in (None, 'label'))
            dataset = ResearchDataset(examples + (examples[0],))
            assert examples[0] == research_example_from_window(closed_window())
            assert not any(name.split('.')[0] in ('application', 'detection') for name in sys.modules)
            print(repr((window, snapshot, examples[0].projection, examples[0].projection.feature_names, examples, dataset)))
        ''')
        outputs = []
        for seed, zone in (('1', 'UTC'), ('8675309', 'Asia/Kolkata')):
            result = subprocess.run([sys.executable, '-B', '-c', script], cwd=root,
                                    env=dict(os.environ, PYTHONPATH=str(root / 'src'), PYTHONHASHSEED=seed, TZ=zone),
                                    capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b'')
            self.assertNotEqual(result.stdout, b'')
            outputs.append(result.stdout)
        self.assertEqual(outputs[0], outputs[1])
