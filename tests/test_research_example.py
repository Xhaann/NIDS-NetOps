import os
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from textwrap import dedent
from types import SimpleNamespace
from unittest.mock import patch

from analysis import extract_flow_feature_snapshot
from ml import MLFeatureProjection, project_flow_features
from research import ResearchExample
from tests.test_flow_feature_snapshot import active_window_from_packets, packet_at
from tests.test_ml_feature_projection import representative_snapshot


class ResearchExampleTests(unittest.TestCase):
    def test_retains_exact_projection_contract_names_and_values_without_recomputation(self):
        manager, window = active_window_from_packets(packet_at(0))
        for snapshot in (extract_flow_feature_snapshot(window), representative_snapshot()):
            projection = project_flow_features(snapshot)
            contract = projection.feature_contract
            before = repr(projection)
            with patch('ml.feature_projection.project_flow_features', side_effect=AssertionError('projection repeated')), \
                 patch('analysis.flow_feature_snapshot.extract_flow_feature_snapshot', side_effect=AssertionError('extraction repeated')):
                example = ResearchExample(projection, 'observed condition')
            self.assertIs(example.projection, projection)
            self.assertIs(example.projection.feature_contract, contract)
            self.assertEqual(contract, snapshot.feature_contract)
            self.assertIs(example.projection.feature_names, projection.feature_names)
            self.assertIs(example.projection.values, projection.values)
            self.assertIn(None, example.projection.values)
            self.assertIn(0.0, example.projection.values)
            self.assertEqual(repr(projection), before)
            self.assertEqual(tuple(field.name for field in fields(example)), ('projection', 'ground_truth'))
        manager.end_capture_session()

    def test_truth_is_optional_explicit_and_preserved_without_a_fixed_vocabulary(self):
        projection = project_flow_features(representative_snapshot())
        unlabeled = ResearchExample(projection)
        self.assertIsNone(unlabeled.ground_truth)
        self.assertEqual(unlabeled, ResearchExample(projection, None))
        for truth in ('condition alpha', 'condition beta', 'condition gamma', ' État expérimental '):
            example = ResearchExample(projection, truth)
            self.assertIs(example.ground_truth, truth)
            self.assertIs(example.projection, unlabeled.projection)
            self.assertNotEqual(example, unlabeled)
            self.assertEqual(example, ResearchExample(project_flow_features(representative_snapshot()), truth))
        self.assertNotEqual(ResearchExample(projection, 'Label'), ResearchExample(projection, 'label'))
        self.assertNotEqual(ResearchExample(projection, ' label '), ResearchExample(projection, 'label'))

    def test_invalid_projections_are_rejected_without_coercion(self):
        projection = project_flow_features(representative_snapshot())

        class OtherProjection(MLFeatureProjection):
            pass

        for value in (None, True, 'features', projection.values, list(projection.values),
                      representative_snapshot(), SimpleNamespace(feature_contract=projection.feature_contract,
                      values=projection.values), object.__new__(OtherProjection)):
            with self.subTest(type=type(value).__name__):
                with self.assertRaisesRegex(TypeError, '^projection must be exactly an MLFeatureProjection$'):
                    ResearchExample(value)
        with self.assertRaises(TypeError):
            ResearchExample()

    def test_invalid_truth_is_rejected_without_coercion_or_normalization(self):
        projection = project_flow_features(representative_snapshot())

        class OtherText(str):
            pass

        for value in (True, False, 0, 1.0, b'label', [], {}, ('label',), OtherText('label')):
            with self.subTest(type=type(value).__name__):
                with self.assertRaisesRegex(TypeError, '^ground_truth must be exactly a string or None$'):
                    ResearchExample(projection, value)
        for value in ('', ' ', '\t\n'):
            with self.assertRaisesRegex(ValueError, '^ground_truth must not be blank$'):
                ResearchExample(projection, value)

    def test_published_state_is_immutable_and_not_owned_by_caller_containers(self):
        projection = project_flow_features(representative_snapshot())
        inputs = {'projection': projection, 'ground_truth': 'condition alpha'}
        example = ResearchExample(**inputs)
        before = repr(example)
        inputs['projection'] = None
        inputs['ground_truth'] = 'condition beta'
        for obj, field, value in ((example, 'projection', None), (example, 'ground_truth', 'changed'),
                                  (projection, 'values', ()), (projection, 'feature_contract', None),
                                  (projection.feature_contract, 'contract_version', 'other')):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, field, value)
        with self.assertRaises(TypeError):
            projection.values[0] = 10
        with self.assertRaises(TypeError):
            projection.feature_names[0] = 'other'
        changed = replace(example, ground_truth='condition beta')
        self.assertIs(changed.projection, projection)
        self.assertEqual(repr(example), before)
        self.assertNotEqual(changed, example)

    def test_detector_and_evaluation_objects_cannot_be_features_or_research_truth(self):
        from application import DetectionPipelineResult, ExpectedDetectionResult, calculate_detection_metrics, evaluate_detection_result
        from tests.test_detection_evaluation import packet_finding
        from tests.test_ground_truth import flow_target, packet_target, positive

        projection = project_flow_features(representative_snapshot())
        evaluation = evaluate_detection_result(DetectionPipelineResult((), ()), ExpectedDetectionResult((), ()))
        target = flow_target()
        values = (packet_finding(), target, packet_target(), target.configuration,
                  positive(target), positive(target).polarity, evaluation, calculate_detection_metrics(evaluation))
        for value in values:
            with self.subTest(type=type(value).__name__):
                with self.assertRaisesRegex(TypeError, '^projection must be exactly an MLFeatureProjection$'):
                    ResearchExample(value)
                with self.assertRaisesRegex(TypeError, '^ground_truth must be exactly a string or None$'):
                    ResearchExample(projection, value)

    def test_import_and_complete_construction_are_detector_independent_and_deterministic(self):
        root = Path(__file__).resolve().parents[1]
        script = dedent('''
            import sys
            class RejectDetectionImports:
                def find_spec(self, fullname, path=None, target=None):
                    if fullname.split('.')[0] in ('application', 'detection'):
                        raise AssertionError(fullname)
            sys.meta_path.insert(0, RejectDetectionImports())
            from research import ResearchExample
            from research.research_example import ResearchExample as DirectExample
            from analysis import extract_flow_feature_snapshot
            from ml import project_flow_features
            from tests.test_flow_feature_snapshot import active_window_from_packets, packet_at
            assert ResearchExample is DirectExample
            def examples():
                manager, window = active_window_from_packets(packet_at(0))
                projection = project_flow_features(extract_flow_feature_snapshot(window))
                return tuple(ResearchExample(projection, truth) for truth in ('gamma', None, 'alpha', 'gamma'))
            first, second = examples(), examples()
            assert first == second
            assert first[0] == first[3]
            assert tuple(example.ground_truth for example in first) == ('gamma', None, 'alpha', 'gamma')
            assert not any(name.split('.')[0] in ('application', 'detection') for name in sys.modules)
            print(repr(tuple((example, example.projection.feature_names) for example in first)))
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
