import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent
from types import SimpleNamespace
from unittest.mock import patch

from analysis import FlowObservationWindow, FlowObservationWindowManager, extract_flow_feature_snapshot
from ml import MLFeatureProjection, project_flow_features
from research import ResearchDataset, ResearchExample
from tests.test_flow_feature_snapshot import active_window_from_packets, packet_at


def closed_snapshot(source_port=12345, session='research'):
    manager = FlowObservationWindowManager(session, timedelta(seconds=5))
    for seconds in (0, 2):
        packet = packet_at(seconds)
        manager.record(replace(packet, udp=replace(packet.udp, source_port=source_port)))
    return extract_flow_feature_snapshot(manager.end_capture_session()[0])


class ResearchObservationTests(unittest.TestCase):
    def test_context_and_projection_are_retained_without_recomputation(self):
        snapshot = closed_snapshot()
        projection = project_flow_features(snapshot)
        before = repr((snapshot, projection, projection.feature_names))
        with patch('ml.feature_projection.project_flow_features', side_effect=AssertionError('projection repeated')), \
             patch('analysis.flow_feature_snapshot.extract_flow_feature_snapshot', side_effect=AssertionError('extraction repeated')):
            example = ResearchExample(projection, 'condition alpha', observation_window=snapshot.observation_window)
        self.assertIs(example.projection, projection)
        self.assertIs(example.observation_window, snapshot.observation_window)
        self.assertIs(example.observation_window.coordinated_state, snapshot.coordinated_state)
        self.assertIs(example.observation_window.identity, snapshot.identity)
        self.assertIs(example.projection.values, projection.values)
        self.assertIs(example.projection.feature_names, projection.feature_names)
        self.assertIs(example.projection.feature_contract, projection.feature_contract)
        self.assertEqual(len(projection.values), 49)
        self.assertIn(None, projection.values)
        self.assertIn(0.0, projection.values)
        self.assertEqual(tuple(field.name for field in fields(MLFeatureProjection)), ('feature_contract', 'values'))
        self.assertTrue(all(value is None or type(value) in (int, float) for value in projection.values))
        self.assertEqual(repr((snapshot, projection, projection.feature_names)), before)

    def test_published_context_and_truth_remain_independent_and_immutable(self):
        manager, active = active_window_from_packets(packet_at(0), packet_at(2))
        window = manager.close(active.identity)
        projection = project_flow_features(extract_flow_feature_snapshot(window))
        supplied = dict(projection=projection, ground_truth=' État expérimental ', observation_window=window)
        example = ResearchExample(**supplied)
        before = repr(example)
        supplied.clear()
        for target, name, value in ((example, 'observation_window', None), (window, 'closure_reason', None),
                                    (window.key, 'sequence_number', 99), (window.identity, 'protocol', 6),
                                    (window.coordinated_state.flow_statistics, 'packet_count', 99)):
            with self.assertRaises(FrozenInstanceError):
                setattr(target, name, value)
        for truth in (None, 'condition beta', ' État expérimental '):
            changed = replace(example, ground_truth=truth)
            self.assertIs(changed.observation_window, window)
            self.assertIs(changed.projection, projection)
            self.assertEqual(changed.ground_truth, truth)
        manager.record(packet_at(3))
        manager.end_capture_session()
        self.assertEqual(repr(example), before)
        self.assertEqual(window.coordinated_state.flow_statistics.packet_count, 2)

    def test_equal_features_do_not_determine_observation_context(self):
        first = closed_snapshot()
        different_flow = closed_snapshot(source_port=12346)
        different_session = closed_snapshot(session='another replay')
        projection = project_flow_features(first)
        example = ResearchExample(projection, observation_window=first.observation_window)
        for other in (different_flow, different_session):
            other_projection = project_flow_features(other)
            self.assertEqual(projection, other_projection)
            associated = ResearchExample(other_projection, observation_window=other.observation_window)
            self.assertNotEqual(example, associated)
            self.assertNotEqual(ResearchDataset((example,)), ResearchDataset((associated,)))
        independent = closed_snapshot()
        self.assertIsNot(first.observation_window, independent.observation_window)
        self.assertEqual(example, ResearchExample(project_flow_features(independent),
                                                 observation_window=independent.observation_window))
        unassociated = ResearchExample(projection)
        self.assertIsNone(unassociated.observation_window)
        self.assertNotEqual(example, unassociated)
        self.assertEqual(unassociated, ResearchExample(projection, None, None))

    def test_dataset_retains_order_equal_values_and_repeated_observations(self):
        first, second = closed_snapshot(), closed_snapshot(source_port=12346)
        a = ResearchExample(project_flow_features(first), 'alpha', first.observation_window)
        b = ResearchExample(project_flow_features(second), None, second.observation_window)
        equal_a = replace(a)
        supplied = [b, a, equal_a, a]
        dataset = ResearchDataset(supplied)
        supplied.reverse()
        supplied.clear()
        self.assertEqual(dataset.examples, (b, a, equal_a, a))
        for actual, expected in zip(dataset.examples, (b, a, equal_a, a)):
            self.assertIs(actual, expected)
        self.assertIsNot(a, equal_a)
        self.assertEqual(a, equal_a)
        self.assertIs(dataset.examples[1], dataset.examples[3])
        self.assertEqual(dataset, ResearchDataset((b, a, equal_a, a)))
        self.assertNotEqual(dataset, ResearchDataset((a, b, equal_a, a)))
        self.assertEqual(ResearchDataset([]), ResearchDataset(()))
        with self.assertRaises(FrozenInstanceError):
            dataset.examples = ()

    def test_closed_context_accepts_lifecycle_reasons_but_never_closes_active_windows(self):
        manager = FlowObservationWindowManager('research', timedelta(seconds=5))
        active = manager.record(packet_at(0)).active_window
        projection = project_flow_features(extract_flow_feature_snapshot(active))
        before = manager.active_windows()
        with self.assertRaisesRegex(ValueError, '^observation_window must be closed$'):
            ResearchExample(projection, observation_window=active)
        self.assertEqual(manager.active_windows(), before)
        self.assertIsNone(ResearchExample(projection).observation_window)
        inactivity = manager.record(packet_at(5)).closed_windows[0]
        explicit = manager.close(inactivity.identity)
        manager.record(packet_at(6))
        session_end = manager.end_capture_session()[0]
        for window in (inactivity, explicit, session_end):
            snapshot = extract_flow_feature_snapshot(window)
            example = ResearchExample(project_flow_features(snapshot), observation_window=window)
            self.assertIs(example.observation_window, window)
        self.assertEqual([w.key.sequence_number for w in (inactivity, explicit, session_end)], [0, 1, 2])

    def test_invalid_context_and_existing_validation_precedence(self):
        snapshot = closed_snapshot()
        window = snapshot.observation_window
        projection = project_flow_features(snapshot)

        class OtherWindow(FlowObservationWindow):
            pass

        other = OtherWindow(window.key, window.coordinated_state, window.closure_reason)
        invalid = (True, 'window', {}, [], snapshot, window.key, window.identity, projection,
                   projection.values, SimpleNamespace(closure_reason=window.closure_reason), other)
        before = repr((snapshot, projection))
        for context in invalid:
            with self.subTest(type=type(context).__name__):
                with self.assertRaisesRegex(TypeError, '^observation_window must be exactly a FlowObservationWindow or None$'):
                    ResearchExample(projection, observation_window=context)
                with self.assertRaisesRegex(TypeError, '^projection must be exactly an MLFeatureProjection$'):
                    ResearchExample(None, '', context)
                with self.assertRaisesRegex(ValueError, '^ground_truth must not be blank$'):
                    ResearchExample(projection, '', context)
        for truth in (True, 0, b'label', [], {}):
            with self.assertRaisesRegex(TypeError, '^ground_truth must be exactly a string or None$'):
                ResearchExample(projection, truth, window)
        for truth in ('', ' ', '\t\n'):
            with self.assertRaisesRegex(ValueError, '^ground_truth must not be blank$'):
                ResearchExample(projection, truth, window)
        self.assertEqual(repr((snapshot, projection)), before)

    def test_complete_context_representation_is_deterministic_and_detector_independent(self):
        root = Path(__file__).resolve().parents[1]
        script = dedent('''
            import sys
            class RejectDetectionImports:
                def find_spec(self, fullname, path=None, target=None):
                    if fullname.split('.')[0] in ('application', 'detection'):
                        raise AssertionError(fullname)
            sys.meta_path.insert(0, RejectDetectionImports())
            from research import ResearchDataset, ResearchExample
            from ml import project_flow_features
            from tests.test_research_observation import closed_snapshot
            def dataset():
                snapshots = (closed_snapshot(), closed_snapshot(source_port=12346))
                examples = [ResearchExample(project_flow_features(s), truth, s.observation_window)
                            for s, truth in zip(snapshots, (None, 'condition alpha'))]
                return ResearchDataset(examples + [examples[0]])
            first, second = dataset(), dataset()
            assert first == second
            assert first.examples[0] is first.examples[2]
            assert not any(name.split('.')[0] in ('application', 'detection') for name in sys.modules)
            print(repr((first, tuple(e.projection.feature_names for e in first.examples))))
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

    def test_pcap_outcome_admission_context_and_detection_outputs_remain_separate(self):
        from application import GroundTruth, run_capture_execution, run_end_to_end_validation
        from application.cli import main
        from capture import PcapPacketSource
        from detection import FlowVolumeThresholdEvidence
        from tests.test_end_to_end_validation import settings, wire
        from tests.test_packet_analysis import make_observation, UDP_BYTES
        from tests.test_pcap_packet_source import global_header, record

        frames = tuple(wire(ipv6, protocol) for ipv6, protocol in ((False, 6), (False, 17), (True, 6), (True, 17)))
        bad = make_observation(17, UDP_BYTES, ipv4_checksum=0)
        data = global_header() + record(bad.raw_bytes, seconds=0)
        data += b''.join(record(frame.raw_bytes, seconds=t) for t in (1, 2) for frame in frames)
        data += record(frames[1].raw_bytes, seconds=7)
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'observations.pcap'
            path.write_bytes(data)
            configuration = settings()

            def replay():
                return run_end_to_end_validation(PcapPacketSource(path), configuration=configuration,
                                                capture_session_id='research', ground_truth=GroundTruth((), ()))

            def cli_output():
                output, errors = StringIO(), StringIO()
                arguments = [str(path), '--capture-session-id', 'research', '--inactivity-timeout-microseconds', '5000000',
                             '--packet-detector-id', 'packet', '--packet-detector-version', 'p1',
                             '--volume-detector-id', 'volume', '--volume-detector-version', 'v1',
                             '--volume-metric', configuration.flow_volume_configuration.metric.value, '--volume-threshold', '0',
                             '--tcp-detector-id', 'control', '--tcp-detector-version', 'c1',
                             '--tcp-metric', configuration.tcp_control_configuration.metric.value, '--tcp-threshold', '0']
                with redirect_stdout(output), redirect_stderr(errors):
                    status = main(arguments)
                return status, output.getvalue(), errors.getvalue()

            before = replay()
            cli_before = cli_output()
            self.assertEqual((cli_before[0], cli_before[2]), (0, ''))
            manager = FlowObservationWindowManager('research', configuration.inactivity_timeout)
            outcomes, windows = [], []

            def receive(outcome):
                outcomes.append(outcome)
                if outcome.analysis is not None:
                    windows.extend(manager.record(outcome.analysis).closed_windows)

            run_capture_execution(PcapPacketSource(path), receive)
            windows.extend(manager.end_capture_session())
            self.assertEqual(len(outcomes), 10)
            self.assertIsNone(outcomes[0].analysis)
            self.assertEqual([w.key.sequence_number for w in windows], [1, 0, 2, 3, 4])
            self.assertEqual([w.closure_reason.value for w in windows], ['inactivity'] + ['capture_session_end'] * 4)
            snapshots = tuple(extract_flow_feature_snapshot(w) for w in windows)
            retained = tuple(f.raw_evidence.snapshot for f in before.pipeline_result.flow_findings
                             if type(f.raw_evidence) is FlowVolumeThresholdEvidence)
            self.assertEqual(snapshots, retained)
            dataset = ResearchDataset(tuple(ResearchExample(project_flow_features(s), observation_window=s.observation_window)
                                            for s in snapshots))
            for example, snapshot, window in zip(dataset.examples, snapshots, windows):
                self.assertIs(example.observation_window, window)
                self.assertIs(snapshot.observation_window, window)
                self.assertEqual(example.projection, project_flow_features(snapshot))
                self.assertIsNone(example.ground_truth)
            self.assertEqual(replay(), before)
            self.assertEqual(cli_output(), cli_before)
            self.assertEqual(path.read_bytes(), data)
