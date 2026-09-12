import os
import subprocess
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from textwrap import dedent

from analysis import FlowObservationWindowManager, extract_flow_feature_snapshot
from ml import project_flow_features
from research import ResearchDataset, ResearchExample
from tests.test_flow_feature_snapshot import OBSERVATION, packet_at


TIMESTAMP_FIELDS = (
    ('flow_statistics', 'first_captured_at'),
    ('flow_statistics', 'last_captured_at'),
    ('flow_inter_arrival_statistics', 'first_captured_at'),
    ('flow_inter_arrival_statistics', 'last_captured_at'),
    ('directional_inter_arrival_statistics', 'first_captured_at'),
    ('directional_inter_arrival_statistics', 'last_captured_at'),
    ('directional_inter_arrival_statistics', 'last_forward_captured_at'),
    ('directional_inter_arrival_statistics', 'last_reverse_captured_at'),
)


class MutableOffset(tzinfo):
    def __init__(self):
        self.hours = 0

    def utcoffset(self, value):
        return timedelta(hours=self.hours)

    def dst(self, value):
        return timedelta(0)


class CustomDatetime(datetime):
    pass


def closed_window():
    manager = FlowObservationWindowManager('timestamp ownership', timedelta(seconds=5))
    manager.record(packet_at(0))
    manager.record(packet_at(1, reverse=True))
    return manager.end_capture_session()[0]


def replace_timestamp(window, aggregate_name, timestamp_name, timestamp):
    state = window.coordinated_state
    aggregate = replace(getattr(state, aggregate_name), **{timestamp_name: timestamp})
    return replace(window, coordinated_state=replace(state, **{aggregate_name: aggregate}))


class ResearchObservationTimestampTests(unittest.TestCase):
    def test_mutable_timezones_and_datetime_subclasses_are_rejected_in_every_retained_field(self):
        window = closed_window()
        projection = project_flow_features(extract_flow_feature_snapshot(window))
        reference = ResearchExample(projection, 'truth', window)
        before = repr(reference)
        for aggregate_name, timestamp_name in TIMESTAMP_FIELDS:
            original = getattr(getattr(window.coordinated_state, aggregate_name), timestamp_name)
            zone = MutableOffset()
            subclass = CustomDatetime(original.year, original.month, original.day, original.hour,
                                      original.minute, original.second, original.microsecond, tzinfo=timezone.utc)
            for timestamp, error, suffix in (
                (original.replace(tzinfo=zone), ValueError, 'must use a fixed UTC datetime.timezone'),
                (subclass, TypeError, 'must be a datetime of the exact built-in type'),
            ):
                with self.subTest(aggregate=aggregate_name, field=timestamp_name, kind=type(timestamp).__name__):
                    unsafe = replace_timestamp(window, aggregate_name, timestamp_name, timestamp)
                    with self.assertRaises(error) as capture_error:
                        replace(OBSERVATION, captured_at=timestamp)
                    self.assertEqual(str(capture_error.exception), 'captured_at ' + suffix)
                    with self.assertRaises(error) as research_error:
                        ResearchExample(projection, 'truth', unsafe)
                    self.assertEqual(str(research_error.exception),
                                     f'observation_window.coordinated_state.{aggregate_name}.{timestamp_name} {suffix}')
            zone.hours = 1
            self.assertEqual(repr(reference), before)
            self.assertEqual(ResearchDataset([reference]), ResearchDataset([ResearchExample(projection, 'truth', window)]))

    def test_fixed_nonzero_offsets_follow_packet_observation_rejection_in_every_retained_field(self):
        window = closed_window()
        projection = project_flow_features(extract_flow_feature_snapshot(window))
        for aggregate_name, timestamp_name in TIMESTAMP_FIELDS:
            original = getattr(getattr(window.coordinated_state, aggregate_name), timestamp_name)
            timestamp = original.astimezone(timezone(timedelta(hours=1)))
            unsafe = replace_timestamp(window, aggregate_name, timestamp_name, timestamp)
            with self.subTest(aggregate=aggregate_name, field=timestamp_name):
                with self.assertRaisesRegex(ValueError, '^captured_at must have a zero UTC offset$'):
                    replace(OBSERVATION, captured_at=timestamp)
                with self.assertRaises(ValueError) as error:
                    ResearchExample(projection, observation_window=unsafe)
                self.assertEqual(str(error.exception),
                                 f'observation_window.coordinated_state.{aggregate_name}.{timestamp_name} must have a zero UTC offset')

    def test_valid_manager_windows_retain_exact_utc_timestamps_through_cleanup(self):
        for zone in (timezone.utc, timezone(timedelta(0), 'UTC alias')):
            manager = FlowObservationWindowManager('timestamp ownership', timedelta(seconds=5))
            windows = []
            for seconds in (0, 1, 6, 7):
                packet = packet_at(seconds, reverse=seconds in (1, 7))
                packet = replace(packet, observation=replace(packet.observation,
                                 captured_at=packet.observation.captured_at.replace(tzinfo=zone)))
                windows.extend(manager.record(packet).closed_windows)
            windows.append(manager.close(manager.active_windows()[0].identity))
            manager.record(packet_at(8))
            windows.extend(manager.end_capture_session())
            projections = tuple(project_flow_features(extract_flow_feature_snapshot(w)) for w in windows)
            examples = tuple(ResearchExample(p, truth, w) for p, truth, w in zip(projections, (None, ' label ', 'other'), windows))
            self.assertEqual(projections[0], projections[1])
            self.assertNotEqual(examples[0], replace(examples[1], ground_truth=None))
            self.assertEqual([w.closure_reason.value for w in windows],
                             ['inactivity', 'explicit_segmentation', 'capture_session_end'])
            for example, projection, window in zip(examples, projections, windows):
                self.assertIs(example.observation_window, window)
                self.assertIs(example.projection, projection)
                self.assertEqual(ResearchExample(projection), ResearchExample(projection, None, None))
                self.assertEqual(ResearchExample(projection, ' label '), ResearchExample(projection, ' label ', None))
                for aggregate_name, timestamp_name in TIMESTAMP_FIELDS:
                    actual = getattr(getattr(example.observation_window.coordinated_state, aggregate_name), timestamp_name)
                    expected = getattr(getattr(window.coordinated_state, aggregate_name), timestamp_name)
                    self.assertIs(actual, expected)
                    if actual is not None:
                        self.assertIs(actual.tzinfo, zone if window is not windows[2] else timezone.utc)
            caller = [examples[1], examples[0], examples[1], examples[2]]
            dataset = ResearchDataset(caller)
            before = repr(dataset)
            caller.clear()
            self.assertEqual(manager.end_capture_session(), ())
            self.assertEqual(manager.active_windows(), ())
            del manager
            self.assertEqual(repr(dataset), before)
            self.assertEqual(dataset, ResearchDataset((examples[1], examples[0], examples[1], examples[2])))
            self.assertIs(dataset.examples[0], dataset.examples[2])

    def test_unsafe_timestamps_do_not_precede_existing_validation_errors(self):
        window = closed_window()
        projection = project_flow_features(extract_flow_feature_snapshot(window))
        unsafe = replace_timestamp(window, 'flow_statistics', 'first_captured_at',
                                   window.first_captured_at.replace(tzinfo=MutableOffset()))
        cases = (
            ((None, '', unsafe), TypeError, 'projection must be exactly an MLFeatureProjection'),
            ((projection, True, unsafe), TypeError, 'ground_truth must be exactly a string or None'),
            ((projection, ' ', unsafe), ValueError, 'ground_truth must not be blank'),
            ((projection, None, object()), TypeError, 'observation_window must be exactly a FlowObservationWindow or None'),
            ((projection, None, replace(unsafe, closure_reason=None)), ValueError, 'observation_window must be closed'),
        )
        for arguments, error_type, message in cases:
            with self.subTest(message=message):
                with self.assertRaises(error_type) as error:
                    ResearchExample(*arguments)
                self.assertEqual(str(error.exception), message)

    def test_valid_representations_and_unsafe_failures_match_across_environments(self):
        root = Path(__file__).resolve().parents[1]
        script = dedent('''
            import sys
            class RejectDetectionImports:
                def find_spec(self, fullname, path=None, target=None):
                    if fullname.split('.')[0] in ('application', 'detection'):
                        raise AssertionError(fullname)
            sys.meta_path.insert(0, RejectDetectionImports())
            from tests.test_research_observation_timestamps import closed_window, replace_timestamp, MutableOffset, TIMESTAMP_FIELDS
            from analysis import extract_flow_feature_snapshot
            from ml import project_flow_features
            from research import ResearchExample, ResearchDataset
            window = closed_window()
            projection = project_flow_features(extract_flow_feature_snapshot(window))
            example = ResearchExample(projection, 'label', window)
            dataset = ResearchDataset([example, example])
            failures = []
            for aggregate, field in TIMESTAMP_FIELDS:
                timestamp = getattr(getattr(window.coordinated_state, aggregate), field)
                unsafe = replace_timestamp(window, aggregate, field, timestamp.replace(tzinfo=MutableOffset()))
                try:
                    ResearchExample(projection, 'label', unsafe)
                except ValueError as error:
                    failures.append((type(error).__name__, str(error)))
                else:
                    raise AssertionError('unsafe context accepted')
            assert len(failures) == 8
            assert not any(name.split('.')[0] in ('application', 'detection') for name in sys.modules)
            print(repr((window, projection, projection.feature_names, example, dataset, tuple(failures))))
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
