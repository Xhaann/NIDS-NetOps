import os
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from textwrap import dedent
from types import SimpleNamespace
from unittest.mock import PropertyMock, patch

from ml import project_flow_features
from research import ResearchDataset, ResearchExample
from tests.test_ml_feature_projection import representative_snapshot


def examples():
    projection = project_flow_features(representative_snapshot())
    return tuple(ResearchExample(projection, truth) for truth in ('gamma', None, 'alpha', 'gamma'))


class ResearchDatasetTests(unittest.TestCase):
    def test_order_repeats_and_exact_members_are_retained_without_feature_or_truth_inspection(self):
        supplied = examples()
        supplied = supplied + (supplied[0],)
        before = repr(supplied)
        with patch.object(ResearchExample, 'projection', create=True, new_callable=PropertyMock,
                          side_effect=AssertionError('projection inspected')), \
             patch.object(ResearchExample, 'ground_truth', new_callable=PropertyMock,
                          side_effect=AssertionError('truth inspected')):
            dataset = ResearchDataset(supplied)
        self.assertIs(type(dataset.examples), tuple)
        self.assertEqual(len(dataset.examples), 5)
        self.assertEqual(tuple(item.ground_truth for item in dataset.examples), ('gamma', None, 'alpha', 'gamma', 'gamma'))
        for original, retained in zip(supplied, dataset.examples):
            self.assertIs(retained, original)
            self.assertIs(retained.projection, original.projection)
            self.assertIs(retained.projection.feature_contract, original.projection.feature_contract)
            self.assertIs(retained.projection.values, original.projection.values)
            self.assertIs(retained.projection.feature_names, original.projection.feature_names)
            self.assertIs(retained.ground_truth, original.ground_truth)
            self.assertIn(None, retained.projection.values)
            self.assertIn(0.0, retained.projection.values)
        self.assertEqual(dataset.examples[0], dataset.examples[3])
        self.assertIsNot(dataset.examples[0], dataset.examples[3])
        self.assertIs(dataset.examples[0], dataset.examples[4])
        self.assertEqual(repr(supplied), before)

    def test_empty_datasets_and_equality_depend_only_on_ordered_example_values(self):
        self.assertEqual(ResearchDataset([]), ResearchDataset(()))
        self.assertEqual(ResearchDataset([]).examples, ())
        self.assertEqual(tuple(field.name for field in fields(ResearchDataset)), ('examples',))
        supplied = examples()
        dataset = ResearchDataset(supplied)
        independent = examples()
        self.assertIsNot(supplied[0], independent[0])
        self.assertEqual(dataset, ResearchDataset(list(independent)))
        self.assertEqual(repr(dataset), repr(ResearchDataset(independent)))
        self.assertNotEqual(dataset, ResearchDataset(tuple(reversed(supplied))))
        self.assertNotEqual(dataset, ResearchDataset(supplied[:-1]))
        self.assertNotEqual(dataset, ResearchDataset((replace(supplied[0], ground_truth='other'),) + supplied[1:]))

    def test_caller_list_mutation_and_published_mutation_cannot_change_membership(self):
        supplied = list(examples())
        original = tuple(supplied)
        dataset = ResearchDataset(supplied)
        before = repr(dataset)
        supplied.reverse()
        supplied[0] = original[1]
        supplied.append(original[0])
        supplied.clear()
        self.assertEqual(dataset.examples, original)
        for actual, expected in zip(dataset.examples, original):
            self.assertIs(actual, expected)
        with self.assertRaises(FrozenInstanceError):
            dataset.examples = ()
        with self.assertRaises(TypeError):
            dataset.examples[0] = original[1]
        with self.assertRaises(FrozenInstanceError):
            dataset.examples[0].ground_truth = 'changed'
        for method in ('append', 'extend', 'insert', 'remove', 'pop', 'clear', 'sort', 'reverse'):
            self.assertFalse(hasattr(dataset, method))
        changed = replace(dataset, examples=[])
        self.assertEqual(changed, ResearchDataset(()))
        self.assertEqual(repr(dataset), before)

    def test_only_explicit_builtin_ordered_collections_are_accepted(self):
        supplied = examples()

        class OtherList(list):
            pass

        class OtherTuple(tuple):
            pass

        iterator = iter(supplied)
        for value in (None, True, 1, 'examples', b'examples', {}, set(supplied), frozenset(supplied),
                      iterator, supplied[0], supplied[0].projection, OtherList(supplied), OtherTuple(supplied)):
            with self.subTest(type=type(value).__name__):
                with self.assertRaisesRegex(TypeError, '^examples must be exactly a list or tuple$'):
                    ResearchDataset(value)
        self.assertIs(next(iterator), supplied[0])
        with self.assertRaises(TypeError):
            ResearchDataset()

    def test_invalid_members_are_rejected_without_conversion_or_input_mutation(self):
        example = examples()[0]

        class OtherExample(ResearchExample):
            pass

        for invalid in (None, True, 'example', {}, [], example.projection, representative_snapshot(),
                        SimpleNamespace(projection=example.projection, ground_truth=example.ground_truth),
                        OtherExample(example.projection)):
            for position in range(3):
                with self.subTest(type=type(invalid).__name__, position=position):
                    supplied = [example, example]
                    supplied.insert(position, invalid)
                    before = tuple(supplied)
                    for collection in (supplied, tuple(supplied)):
                        with self.assertRaisesRegex(TypeError, '^examples must contain exactly ResearchExample values$'):
                            ResearchDataset(collection)
                    for actual, expected in zip(supplied, before):
                        self.assertIs(actual, expected)

    def test_detector_and_evaluation_objects_are_not_research_members(self):
        from application import DetectionPipelineResult, ExpectedDetectionResult, calculate_detection_metrics, evaluate_detection_result
        from tests.test_detection_evaluation import packet_finding
        from tests.test_detection_experiment import dataset, experiment
        from tests.test_ground_truth import flow_target, packet_target, positive

        evaluation = evaluate_detection_result(DetectionPipelineResult((), ()), ExpectedDetectionResult((), ()))
        target = flow_target()
        for value in (packet_finding(), target, packet_target(), target.configuration, positive(target),
                      evaluation, calculate_detection_metrics(evaluation), dataset(), experiment()):
            with self.subTest(type=type(value).__name__):
                with self.assertRaisesRegex(TypeError, '^examples must contain exactly ResearchExample values$'):
                    ResearchDataset((value,))

    def test_independent_import_and_complete_dataset_output_across_hash_seeds_and_timezones(self):
        root = Path(__file__).resolve().parents[1]
        script = dedent('''
            import sys
            class RejectDetectionImports:
                def find_spec(self, fullname, path=None, target=None):
                    if fullname.split('.')[0] in ('application', 'detection'):
                        raise AssertionError(fullname)
            sys.meta_path.insert(0, RejectDetectionImports())
            from research import ResearchDataset, ResearchExample
            from research.research_dataset import ResearchDataset as DirectDataset
            from analysis import extract_flow_feature_snapshot
            from ml import project_flow_features
            from tests.test_flow_feature_snapshot import active_window_from_packets, packet_at
            assert ResearchDataset is DirectDataset
            def dataset():
                manager, window = active_window_from_packets(packet_at(0))
                projection = project_flow_features(extract_flow_feature_snapshot(window))
                members = [ResearchExample(projection, truth) for truth in ('gamma', None, 'alpha', 'gamma')]
                result = ResearchDataset(members)
                members.clear()
                return result
            first, second = dataset(), dataset()
            assert first == second
            assert tuple(item.ground_truth for item in first.examples) == ('gamma', None, 'alpha', 'gamma')
            assert ResearchDataset([]) == ResearchDataset(())
            assert not any(name.split('.')[0] in ('application', 'detection') for name in sys.modules)
            print(repr((ResearchDataset(()), first, tuple(item.projection.feature_names for item in first.examples))))
        ''')
        outputs = []
        for seed, zone in (('1', 'UTC'), ('8675309', 'Asia/Kolkata')):
            environment = dict(os.environ, PYTHONPATH=str(root / 'src'), PYTHONHASHSEED=seed, TZ=zone)
            result = subprocess.run([sys.executable, '-B', '-c', script], cwd=root, env=environment,
                                    capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b'')
            self.assertNotEqual(result.stdout, b'')
            outputs.append(result.stdout)
        self.assertEqual(outputs[0], outputs[1])
