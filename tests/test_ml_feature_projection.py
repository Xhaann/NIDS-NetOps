import os
import subprocess
import sys
import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from math import sqrt
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, PropertyMock, patch

from analysis import FeatureContractVersion, FlowFeatureSnapshot, extract_flow_feature_snapshot
from analysis import flow_feature_snapshot
from application import (
    DetectionDataset, DetectionDatasetCase, DetectionMetrics, GroundTruth,
    GroundTruthPolarity, GroundTruthRecord, detection_identity, run_end_to_end_validation,
)
from detection import detection_finding_from_evaluation, evaluate_flow_volume_threshold
from ml import MLFeatureProjection, project_flow_features
from tests.test_end_to_end_validation import settings, wire
from tests.test_flow_feature_snapshot import active_window_from_packets, packet_at, tcp_packet_at
from tests.test_flow_observation_session import MemoryPacketSource


EXPECTED_NAMES = (
    'flow_volume_features.packet_count',
    'flow_volume_features.captured_bytes',
    'flow_volume_features.original_bytes',
    'flow_volume_features.forward_packet_count',
    'flow_volume_features.reverse_packet_count',
    'flow_volume_features.forward_captured_bytes',
    'flow_volume_features.reverse_captured_bytes',
    'flow_volume_features.forward_original_bytes',
    'flow_volume_features.reverse_original_bytes',
    'flow_volume_features.forward_packet_ratio',
    'flow_volume_features.reverse_packet_ratio',
    'flow_volume_features.forward_captured_byte_ratio',
    'flow_volume_features.reverse_captured_byte_ratio',
    'flow_volume_features.forward_original_byte_ratio',
    'flow_volume_features.reverse_original_byte_ratio',
    'flow_volume_features.capture_ratio',
    'packet_size_features.min_captured_length',
    'packet_size_features.max_captured_length',
    'packet_size_features.mean_captured_length',
    'packet_size_features.variance_captured_length',
    'packet_size_features.standard_deviation_captured_length',
    'packet_size_features.min_original_length',
    'packet_size_features.max_original_length',
    'packet_size_features.mean_original_length',
    'packet_size_features.variance_original_length',
    'packet_size_features.standard_deviation_original_length',
    'packet_size_features.forward_mean_captured_length',
    'packet_size_features.reverse_mean_captured_length',
    'packet_size_features.forward_variance_captured_length',
    'packet_size_features.reverse_variance_captured_length',
    'flow_duration_features.duration_seconds',
    'flow_rate_features.packets_per_second',
    'flow_rate_features.captured_bytes_per_second',
    'flow_rate_features.original_bytes_per_second',
    'inter_arrival_features.mean_inter_arrival_seconds',
    'inter_arrival_features.variance_inter_arrival_seconds',
    'inter_arrival_features.standard_deviation_inter_arrival_seconds',
    'inter_arrival_features.min_inter_arrival_seconds',
    'inter_arrival_features.max_inter_arrival_seconds',
    'directional_inter_arrival_features.forward_mean_inter_arrival_seconds',
    'directional_inter_arrival_features.forward_variance_inter_arrival_seconds',
    'directional_inter_arrival_features.forward_standard_deviation_inter_arrival_seconds',
    'directional_inter_arrival_features.forward_min_inter_arrival_seconds',
    'directional_inter_arrival_features.forward_max_inter_arrival_seconds',
    'directional_inter_arrival_features.reverse_mean_inter_arrival_seconds',
    'directional_inter_arrival_features.reverse_variance_inter_arrival_seconds',
    'directional_inter_arrival_features.reverse_standard_deviation_inter_arrival_seconds',
    'directional_inter_arrival_features.reverse_min_inter_arrival_seconds',
    'directional_inter_arrival_features.reverse_max_inter_arrival_seconds',
)


def representative_snapshot():
    manager, _ = active_window_from_packets(
        packet_at(0, False, 60, 100), packet_at(2, True, 80, 120), packet_at(5, False, 100, 140),
    )
    return extract_flow_feature_snapshot(manager.end_capture_session()[0])


class MLFeatureProjectionTests(unittest.TestCase):
    def test_canonical_values_and_explicit_order_cover_every_numerical_feature(self):
        snapshot = representative_snapshot()
        projection = project_flow_features(snapshot)
        captured_variance = 20000 / 3 - 6400
        original_variance = 44000 / 3 - 14400
        expected = (
            3, 240, 360, 2, 1, 160, 80, 240, 120,
            2 / 3, 1 / 3, 2 / 3, 1 / 3, 2 / 3, 1 / 3, 2 / 3,
            60, 100, 80.0, captured_variance, sqrt(captured_variance),
            100, 140, 120.0, original_variance, sqrt(original_variance), 80.0, 80.0, 400.0, 0.0,
            5.0, 0.6, 48.0, 72.0, 2.5, 0.25, 0.5, 2.0, 3.0,
            5.0, 0.0, 0.0, 5.0, 5.0, None, None, None, None, None,
        )
        self.assertEqual(projection.feature_names, EXPECTED_NAMES)
        self.assertEqual(projection.values, expected)
        self.assertEqual(tuple(map(type, projection.values)), tuple(map(type, expected)))
        canonical_names = tuple(
            family.name + '.' + field.name
            for family in fields(snapshot) if family.name != 'observation_window'
            for field in fields(getattr(snapshot, family.name))
        )
        self.assertEqual(projection.feature_names, canonical_names)
        self.assertEqual(len(projection.values), len(set(projection.feature_names)))

    def test_projection_reads_scalars_without_extraction_or_provenance_access(self):
        snapshot = representative_snapshot()
        source_values = tuple(getattr(getattr(snapshot, family), name)
                              for family, name in (value.split('.') for value in EXPECTED_NAMES))
        contract = snapshot.feature_contract
        with ExitStack() as stack:
            for name in ('extract_flow_feature_snapshot', 'flow_feature_input_from_statistics',
                         'extract_flow_volume_features', 'extract_packet_size_features',
                         'extract_flow_duration_features', 'extract_flow_rate_features',
                         'extract_inter_arrival_features', 'extract_directional_inter_arrival_features'):
                stack.enter_context(patch.object(flow_feature_snapshot, name,
                    side_effect=AssertionError('duplicate feature extraction')))
            for name in ('observation_window', 'coordinated_state', 'identity'):
                stack.enter_context(patch.object(FlowFeatureSnapshot, name, create=True,
                    new_callable=PropertyMock, side_effect=AssertionError('provenance access')))
            version = stack.enter_context(patch.object(FlowFeatureSnapshot, 'feature_contract',
                new_callable=PropertyMock, return_value=contract))
            projection = project_flow_features(snapshot)
            version.assert_called_once_with()
        self.assertIs(projection.feature_contract, contract)
        for actual, original in zip(projection.values, source_values):
            self.assertIs(actual, original)

    def test_unavailable_slots_remain_none_and_observed_zero_remains_zero(self):
        for packets, rates, intervals, directional in (
            ((packet_at(0),), (None,) * 3, (0.0,) * 5, (None,) * 10),
            ((packet_at(0), packet_at(0)), (None,) * 3, (0.0,) * 5, (0.0,) * 5 + (None,) * 5),
            ((packet_at(0), packet_at(2)), (1.0, 60.0, 100.0),
             (2.0, 0.0, 0.0, 2.0, 2.0), (2.0, 0.0, 0.0, 2.0, 2.0) + (None,) * 5),
            ((packet_at(0), packet_at(2, True)), (1.0, 60.0, 100.0),
             (2.0, 0.0, 0.0, 2.0, 2.0), (None,) * 10),
        ):
            with self.subTest(packets=len(packets), directional=directional):
                _, window = active_window_from_packets(*packets)
                projection = project_flow_features(extract_flow_feature_snapshot(window))
                self.assertEqual(projection.feature_names, EXPECTED_NAMES)
                self.assertEqual(len(projection.values), 49)
                self.assertEqual(projection.values[31:34], rates)
                self.assertEqual(projection.values[34:39], intervals)
                self.assertEqual(projection.values[39:], directional)

    def test_canonical_version_is_required_before_reading_features(self):
        snapshot = representative_snapshot()
        self.assertEqual(project_flow_features(snapshot).feature_contract,
                         FeatureContractVersion('flow-feature-snapshot', '1'))
        for contract, error in (
            (FeatureContractVersion('flow-feature-snapshot', '2'), ValueError),
            (FeatureContractVersion('other', '1'), ValueError),
            ('flow-feature-snapshot:1', TypeError), (None, TypeError),
        ):
            with self.subTest(contract=contract):
                with patch.object(FlowFeatureSnapshot, 'feature_contract', new_callable=PropertyMock,
                                  return_value=contract), \
                     patch.object(FlowFeatureSnapshot, 'flow_volume_features', create=True,
                                  new_callable=PropertyMock, side_effect=AssertionError('feature read')):
                    with self.assertRaises(error):
                        project_flow_features(snapshot)

    def test_factory_only_immutable_contract_rejects_other_inputs(self):
        snapshot = representative_snapshot()
        projection = project_flow_features(snapshot)
        self.assertEqual(tuple(field.name for field in fields(projection)), ('feature_contract', 'values'))
        self.assertEqual(tuple(vars(projection)), ('feature_contract', 'values'))
        self.assertIs(type(projection.values), tuple)
        self.assertTrue(all(type(value) in (int, float, type(None)) for value in projection.values))
        for name in ('feature_contract', 'values', 'feature_names', 'label', 'decision'):
            with self.assertRaises(FrozenInstanceError):
                setattr(projection, name, None)
        with self.assertRaises(TypeError):
            MLFeatureProjection()
        with self.assertRaises(TypeError):
            MLFeatureProjection(snapshot.feature_contract, projection.values)
        for invalid in (None, snapshot.observation_window, snapshot.coordinated_state,
                        projection, projection.values, {}, SimpleNamespace(**vars(snapshot)),
                        Mock(spec=FlowFeatureSnapshot), GroundTruth((), ())):
            with self.subTest(input_type=type(invalid)):
                with self.assertRaises(TypeError):
                    project_flow_features(invalid)
        self.assertEqual(projection, project_flow_features(snapshot))
        self.assertEqual(projection, project_flow_features(representative_snapshot()))
        self.assertEqual(hash(projection), hash(project_flow_features(snapshot)))

    def test_changing_ground_truth_and_dataset_labels_does_not_change_values(self):
        observation = wire()
        baseline = run_end_to_end_validation(MemoryPacketSource((observation,)), configuration=settings(),
            capture_session_id='label-independence', ground_truth=GroundTruth((), ()))
        finding = baseline.pipeline_result.flow_findings[0]
        target = detection_identity(finding)
        datasets, projections, metrics = [], [], []
        for polarity in (GroundTruthPolarity.POSITIVE, GroundTruthPolarity.NEGATIVE):
            record = GroundTruthRecord(target, polarity)
            truth = GroundTruth((), (record,))
            dataset = DetectionDataset('external-labels', (DetectionDatasetCase('case', target, record),))
            datasets.append(dataset)
            result = run_end_to_end_validation(MemoryPacketSource((observation,)), configuration=settings(),
                capture_session_id='label-independence', ground_truth=truth)
            self.assertEqual(result.pipeline_result, baseline.pipeline_result)
            projections.append(project_flow_features(result.pipeline_result.flow_findings[0].raw_evidence.snapshot))
            metrics.append(result.report.metrics.flow_metrics)
            for invalid in (truth, record, dataset, dataset.cases[0]):
                with self.assertRaises(TypeError):
                    project_flow_features(invalid)
        self.assertNotEqual(datasets[0], datasets[1])
        self.assertEqual(metrics, [DetectionMetrics(1, 0, 0, 0), DetectionMetrics(0, 1, 0, 0)])
        self.assertEqual(projections[0], projections[1])
        self.assertEqual(projections[0].values, projections[1].values)

    def test_changing_detector_outcomes_does_not_change_values(self):
        snapshot = representative_snapshot()
        findings, projections = [], []
        for threshold in (0, 3):
            configuration = replace(settings().flow_volume_configuration, threshold=threshold)
            finding = detection_finding_from_evaluation(evaluate_flow_volume_threshold(snapshot, configuration))
            findings.append(finding)
            projections.append(project_flow_features(snapshot))
            for invalid in (finding, finding.decision, finding.raw_evidence):
                with self.assertRaises(TypeError):
                    project_flow_features(invalid)
        self.assertEqual([finding.decision.value for finding in findings], ['match', 'no_match'])
        self.assertEqual(projections[0], projections[1])

    def test_active_snapshot_is_isolated_from_future_observations_and_closure(self):
        manager, window = active_window_from_packets(packet_at(0), packet_at(2))
        snapshot = extract_flow_feature_snapshot(window)
        projection = project_flow_features(snapshot)
        later = manager.record(packet_at(9, True)).active_window
        self.assertEqual(project_flow_features(snapshot), projection)
        self.assertNotEqual(project_flow_features(extract_flow_feature_snapshot(later)), projection)
        closed = manager.end_capture_session()[0]
        self.assertEqual(project_flow_features(extract_flow_feature_snapshot(later)),
                         project_flow_features(extract_flow_feature_snapshot(closed)))
        self.assertEqual(project_flow_features(snapshot), projection)
        _, renamed = active_window_from_packets(packet_at(0), packet_at(2), capture_session_id='unrelated')
        self.assertEqual(project_flow_features(extract_flow_feature_snapshot(renamed)), projection)
        tcp_projections = []
        for syn in (False, True):
            _, tcp_window = active_window_from_packets(tcp_packet_at(0, syn=syn), tcp_packet_at(2, syn=syn))
            tcp_projections.append(project_flow_features(extract_flow_feature_snapshot(tcp_window)))
        self.assertEqual(tcp_projections[0], tcp_projections[1])

    def test_pipeline_is_independent_and_projection_has_ipv4_ipv6_tcp_udp_parity(self):
        for ipv6 in (False, True):
            for protocol in (6, 17):
                with self.subTest(ipv6=ipv6, protocol=protocol):
                    observation = wire(ipv6, protocol)
                    source = MemoryPacketSource((observation,))
                    with patch('ml.feature_projection.project_flow_features', side_effect=AssertionError('ML invoked')):
                        before = run_end_to_end_validation(source, configuration=settings(),
                            capture_session_id='projection-regression', ground_truth=GroundTruth((), ()))
                    finding = before.pipeline_result.flow_findings[0]
                    snapshot = finding.raw_evidence.snapshot
                    projection = project_flow_features(snapshot)
                    self.assertEqual(projection.feature_names, EXPECTED_NAMES)
                    for name, value in zip(projection.feature_names, projection.values):
                        family, field = name.split('.')
                        features = getattr(snapshot, family)
                        self.assertEqual(value, None if features is None else getattr(features, field))
                    self.assertEqual(projection.values[0], 1)
                    self.assertEqual(projection.values[31:34], (None,) * 3)
                    self.assertEqual(before.report.metrics.packet_metrics, DetectionMetrics(0, 0, 0, 0, 1))
                    after = run_end_to_end_validation(MemoryPacketSource((observation,)), configuration=settings(),
                        capture_session_id='projection-regression', ground_truth=GroundTruth((), ()))
                    self.assertEqual(before, after)
                    self.assertEqual(source.events, ['start', 'produce:0', 'stop'])

    def test_projection_is_identical_across_hash_seeds_and_timezones(self):
        root = Path(__file__).resolve().parents[1]
        script = (
            'from ml import project_flow_features; '
            'from tests.test_ml_feature_projection import representative_snapshot; '
            'p = project_flow_features(representative_snapshot()); '
            'print(repr((p.feature_contract, p.feature_names, p.values)))'
        )
        results = []
        for seed, zone in (('1', 'UTC'), ('8675309', 'Asia/Kolkata')):
            environment = dict(os.environ, PYTHONPATH=str(root / 'src'), PYTHONHASHSEED=seed, TZ=zone)
            result = subprocess.run([sys.executable, '-B', '-c', script], cwd=root, env=environment,
                                    capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b'')
            self.assertNotEqual(result.stdout, b'')
            results.append(result.stdout)
        self.assertEqual(results[0], results[1])
