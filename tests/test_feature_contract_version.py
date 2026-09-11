import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import PropertyMock, patch

import analysis
from analysis import FeatureContractVersion, FlowFeatureSnapshot, FlowObservationWindowClosureReason, extract_flow_feature_snapshot
from application import DetectionBenchmarkCaseResult, DetectionBenchmarkResult, DetectionDataset, DetectionDatasetCase, DetectionExperiment, detection_identity
from detection import DetectorVersion, FlowVolumeThresholdError
from tests.test_detection_configuration import configuration
from tests.test_detection_evaluation import C, evaluate, expected, packet_finding
from tests.test_flow_feature_snapshot import active_window_from_packets, packet_at, snapshot_features, tcp_packet_at
from tests.test_flow_volume_threshold import snapshot
from tests.test_ground_truth import positive
from tests.test_ipv6_detection import closed_snapshot, detect
from tests.test_ipv6_features import feature_sequence


class FeatureContractVersionTests(unittest.TestCase):
    def test_explicit_pair_construction(self):
        value = FeatureContractVersion('flow-features', 'revision-a')
        self.assertEqual((value.contract_id, value.contract_version), ('flow-features', 'revision-a'))

    def test_both_identity_components_are_required(self):
        with self.assertRaises(TypeError):
            FeatureContractVersion(contract_id='features')
        with self.assertRaises(TypeError):
            FeatureContractVersion(contract_version='1')

    def test_blank_contract_ids_are_rejected(self):
        for value in ('', ' ', '\t\n'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'contract_id must not be blank'):
                FeatureContractVersion(value, '1')

    def test_blank_versions_are_rejected(self):
        for value in ('', ' ', '\t\n'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'contract_version must not be blank'):
                FeatureContractVersion('features', value)

    def test_invalid_contract_id_types_are_not_coerced(self):
        for value in (None, 1, True, b'id', (), [], {}, object()):
            with self.subTest(value=value), self.assertRaisesRegex(TypeError, 'contract_id must be exactly a string'):
                FeatureContractVersion(value, '1')

    def test_invalid_version_types_are_not_coerced(self):
        for value in (None, 1, 1.0, True, b'1', (1, 0, 0), [], {}, object()):
            with self.subTest(value=value), self.assertRaisesRegex(TypeError, 'contract_version must be exactly a string'):
                FeatureContractVersion('features', value)

    def test_string_subclasses_are_rejected(self):
        class OtherString(str):
            pass
        for values in ((OtherString('id'), '1'), ('id', OtherString('1'))):
            with self.assertRaises(TypeError):
                FeatureContractVersion(*values)

    def test_explicit_non_semver_versions_are_accepted(self):
        for version in ('revision-a', '1', 'vNext', 'study-contract', '1.0.0+local'):
            self.assertEqual(FeatureContractVersion('id', version).contract_version, version)

    def test_exact_whitespace_case_and_unicode_are_preserved(self):
        identity, version = ' Caractéristiques A ', '\tRévision B\n'
        value = FeatureContractVersion(identity, version)
        self.assertIs(value.contract_id, identity)
        self.assertIs(value.contract_version, version)

    def test_independent_equivalent_pairs_compare_equal(self):
        first, second = FeatureContractVersion('id', '1'), FeatureContractVersion('id', '1')
        self.assertIsNot(first, second)
        self.assertEqual(first, second)

    def test_different_contract_ids_are_distinct(self):
        self.assertNotEqual(FeatureContractVersion('first', '1'), FeatureContractVersion('second', '1'))

    def test_different_contract_versions_are_distinct(self):
        self.assertNotEqual(FeatureContractVersion('id', '1'), FeatureContractVersion('id', '2'))

    def test_no_normalization_affects_equality(self):
        first = FeatureContractVersion('id', 'v1')
        for version in ('V1', ' v1', 'v1 ', '1', '1.0.0'):
            self.assertNotEqual(first, FeatureContractVersion('id', version))

    def test_contract_fields_are_frozen(self):
        value = FeatureContractVersion('id', '1')
        self.assertEqual(tuple(f.name for f in fields(value)), ('contract_id', 'contract_version'))
        for name in ('contract_id', 'contract_version'):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, name, 'other')

    def test_versions_have_no_semantic_ordering(self):
        with self.assertRaises(TypeError):
            FeatureContractVersion('id', '2') < FeatureContractVersion('id', '10')

    def test_detector_and_feature_versions_are_distinct_contracts(self):
        value = FeatureContractVersion('id', '1')
        self.assertNotEqual(value, DetectorVersion('id', '1'))
        self.assertNotEqual(value, ('id', '1'))

    def test_snapshot_declares_static_current_contract(self):
        self.assertEqual(snapshot().feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))

    def test_snapshot_field_names_and_order_remain_unchanged(self):
        self.assertEqual(tuple(f.name for f in fields(FlowFeatureSnapshot)),
                         ('observation_window', 'flow_volume_features', 'packet_size_features', 'flow_duration_features',
                          'flow_rate_features', 'inter_arrival_features', 'directional_inter_arrival_features'))

    def test_snapshot_cannot_be_relabelled_with_an_external_contract(self):
        value = snapshot()
        other = FeatureContractVersion('flow-feature-snapshot', '2')
        with self.assertRaises(TypeError):
            FlowFeatureSnapshot(feature_contract=other)
        with self.assertRaises(TypeError):
            replace(value, feature_contract=other)
        with self.assertRaises(FrozenInstanceError):
            value.feature_contract = other
        self.assertEqual(value.feature_contract.contract_version, '1')

    def test_snapshot_and_nested_features_remain_frozen(self):
        value = snapshot()
        with self.assertRaises(FrozenInstanceError):
            value.flow_rate_features = None
        with self.assertRaises(FrozenInstanceError):
            value.flow_volume_features.packet_count = 99
        with self.assertRaises(FrozenInstanceError):
            value.feature_contract.contract_version = '2'

    def test_inspection_preserves_exact_window_state_and_feature_references(self):
        value = snapshot()
        before = (value.observation_window, value.coordinated_state, value.identity) + snapshot_features(value)
        for _ in range(3):
            self.assertEqual(value.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
            after = (value.observation_window, value.coordinated_state, value.identity) + snapshot_features(value)
            for first, second in zip(before, after):
                self.assertIs(first, second)

    def test_equivalent_snapshots_keep_existing_value_equality(self):
        first, second = snapshot(), snapshot()
        self.assertIsNot(first, second)
        self.assertEqual(first.feature_contract, second.feature_contract)
        self.assertEqual(first, second)

    def test_same_contract_does_not_hide_different_feature_values(self):
        first = snapshot()
        second = snapshot(packets=(packet_at(0),))
        self.assertEqual(first.feature_contract, second.feature_contract)
        self.assertNotEqual(first.flow_volume_features, second.flow_volume_features)
        self.assertNotEqual(first, second)

    def test_active_provenance_does_not_bypass_closed_detector_boundary(self):
        manager, window = active_window_from_packets(packet_at(0), packet_at(1))
        active = extract_flow_feature_snapshot(window)
        with self.assertRaises(FlowVolumeThresholdError):
            detect(active)
        closed = extract_flow_feature_snapshot(manager.end_capture_session()[0])
        self.assertEqual(active.feature_contract, closed.feature_contract)
        self.assertEqual(snapshot_features(active), snapshot_features(closed))
        self.assertIsNone(active.observation_window.closure_reason)
        self.assertIsNotNone(closed.observation_window.closure_reason)

    def test_all_closure_reasons_share_the_contract_without_formula_changes(self):
        values = [snapshot(close_reason=reason) for reason in FlowObservationWindowClosureReason]
        self.assertEqual([v.observation_window.closure_reason for v in values], list(FlowObservationWindowClosureReason))
        for value in values:
            self.assertEqual(value.feature_contract, values[0].feature_contract)
            self.assertEqual(snapshot_features(value), snapshot_features(values[0]))

    def test_single_packet_optional_and_zero_features_are_preserved(self):
        value = snapshot(packets=(packet_at(0),))
        self.assertEqual(value.feature_contract.contract_version, '1')
        self.assertEqual(value.flow_duration_features.duration_seconds, 0.0)
        self.assertIsNone(value.flow_rate_features)
        self.assertEqual(tuple(vars(value.inter_arrival_features).values()), (0.0,) * 5)
        self.assertEqual(tuple(vars(value.directional_inter_arrival_features).values()), (None,) * 10)

    def test_equal_timestamps_distinguish_zero_intervals_from_absence(self):
        value = snapshot(packets=(packet_at(0), packet_at(0)))
        self.assertEqual(value.feature_contract.contract_version, '1')
        self.assertIsNone(value.flow_rate_features)
        directional = value.directional_inter_arrival_features
        self.assertEqual(directional.forward_mean_inter_arrival_seconds, 0.0)
        self.assertIsNone(directional.reverse_mean_inter_arrival_seconds)

    def test_global_and_directional_intervals_remain_distinct(self):
        value = snapshot(packets=(packet_at(0), packet_at(1, True), packet_at(3), packet_at(6, True)))
        reference = value.feature_contract
        self.assertEqual(value.inter_arrival_features.mean_inter_arrival_seconds, 2.0)
        self.assertAlmostEqual(value.inter_arrival_features.variance_inter_arrival_seconds, 2 / 3)
        self.assertEqual(value.directional_inter_arrival_features.forward_mean_inter_arrival_seconds, 3.0)
        self.assertEqual(value.directional_inter_arrival_features.reverse_mean_inter_arrival_seconds, 5.0)
        self.assertEqual(value.feature_contract, reference)

    def test_volume_size_and_rate_values_remain_exact(self):
        value = snapshot()
        reference = value.feature_contract
        self.assertEqual((value.flow_volume_features.packet_count, value.flow_volume_features.captured_bytes,
                          value.flow_volume_features.original_bytes), (3, 240, 360))
        self.assertEqual(value.packet_size_features.mean_captured_length, 80.0)
        self.assertAlmostEqual(value.packet_size_features.variance_captured_length, 800 / 3)
        self.assertEqual(value.flow_rate_features.packets_per_second, 0.75)
        self.assertEqual(value.flow_rate_features.captured_bytes_per_second, 60.0)
        self.assertEqual(value.feature_contract, reference)

    def test_microsecond_duration_precision_remains_unchanged(self):
        value = snapshot(packets=(packet_at(0), packet_at(0.000001)))
        self.assertEqual(value.feature_contract.contract_version, '1')
        self.assertEqual(value.flow_duration_features.duration_seconds, 0.000001)
        self.assertEqual(value.flow_rate_features.packets_per_second, 2000000.0)

    def test_ipv4_ipv6_tcp_udp_share_one_feature_contract(self):
        values = (snapshot(6), snapshot(17), closed_snapshot(*feature_sequence(6)), closed_snapshot(*feature_sequence(17)))
        self.assertEqual([(v.identity.ip_version, v.identity.protocol) for v in values], [(4, 6), (4, 17), (6, 6), (6, 17)])
        for value in values:
            self.assertEqual(value.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))

    def test_tcp_control_state_remains_raw_and_directional(self):
        value = snapshot(packets=(tcp_packet_at(0, syn=True), tcp_packet_at(1, True, syn=True, ack=True)))
        control = value.coordinated_state.tcp_control_statistics
        reference = value.feature_contract
        self.assertEqual(control.forward_syn_count, 1)
        self.assertEqual(control.reverse_syn_ack_count, 1)
        self.assertIs(value.coordinated_state.tcp_control_statistics, control)
        self.assertEqual(value.feature_contract, reference)

    def test_udp_does_not_acquire_tcp_control_state(self):
        for value in (snapshot(17), closed_snapshot(*feature_sequence(17))):
            self.assertEqual(value.feature_contract.contract_version, '1')
            self.assertIsNone(value.coordinated_state.tcp_control_statistics)
            self.assertEqual(len(detect(value)), 1)

    def test_detector_version_changes_do_not_change_feature_contract(self):
        value = snapshot()
        config = configuration().flow_volume_configuration
        first = detect(value, volume=config)[0]
        second = detect(value, volume=replace(config, detector_version='next'))[0]
        self.assertNotEqual(first.version_reference, second.version_reference)
        self.assertEqual(first.raw_evidence.snapshot.feature_contract, second.raw_evidence.snapshot.feature_contract)

    def test_system_configuration_and_detector_settings_are_not_mutated(self):
        config = configuration()
        before = replace(config)
        value = snapshot()
        value.feature_contract
        self.assertEqual(config, before)
        self.assertEqual(tuple(f.name for f in fields(config)),
                         ('packet_configuration', 'flow_volume_configuration', 'inactivity_timeout', 'tcp_control_configuration'))

    def test_volume_finding_retains_snapshot_provenance_without_new_fields(self):
        value = snapshot()
        finding = detect(value)[0]
        self.assertIs(finding.raw_evidence.snapshot, value)
        self.assertEqual(finding.raw_evidence.snapshot.feature_contract, value.feature_contract)
        self.assertEqual(tuple(f.name for f in fields(finding)),
                         ('detector_id', 'detector_version', 'decision', 'raw_evidence', 'security_interpretation'))

    def test_flow_evaluation_keeps_existing_full_target_identity(self):
        value = snapshot()
        finding = detect(value)[0]
        identity = detection_identity(finding)
        reference = value.feature_contract
        result = evaluate(flows=(finding,), flow_expectations=(expected(finding),))
        self.assertIs(result.flow_evaluations[0].classification, C.TRUE_POSITIVE)
        self.assertIs(identity.configuration, finding.raw_evidence.configuration)
        self.assertEqual(detection_identity(finding), identity)
        self.assertEqual(value.feature_contract, reference)

    def test_packet_evaluation_has_no_invented_flow_feature_provenance(self):
        finding = packet_finding()
        identity = detection_identity(finding, packet_index=0)
        self.assertEqual(evaluate(packets=(finding,), packet_expectations=(expected(finding, index=0),)).packet_evaluations[0].classification, C.TRUE_POSITIVE)
        self.assertEqual(tuple(f.name for f in fields(identity)),
                         ('configuration', 'packet_index', 'captured_at', 'capture_source', 'link_type', 'captured_length', 'original_length'))

    def test_truth_dataset_benchmark_and_experiment_associations_are_preserved(self):
        value = snapshot()
        finding = detect(value)[0]
        target = detection_identity(finding)
        truth = positive(target)
        case = DetectionDatasetCase('case', target, truth)
        data = DetectionDataset('data', (case,))
        evaluation = evaluate(flows=(finding,), flow_expectations=(expected(finding),))
        benchmark = DetectionBenchmarkResult(data, (DetectionBenchmarkCaseResult(case, evaluation),))
        experiment = DetectionExperiment('experiment', data, 'evaluate', '1')
        self.assertIs(experiment.dataset, data)
        self.assertIs(benchmark.case_results[0].case.ground_truth, truth)
        retained = benchmark.case_results[0].evaluation.flow_evaluations[0].finding.raw_evidence.snapshot
        self.assertIs(retained, value)
        self.assertEqual(retained.feature_contract, value.feature_contract)

    def test_construction_and_inspection_do_not_execute_or_discover_state(self):
        value = snapshot()
        targets = (
            'analysis.flow_feature_snapshot.extract_flow_feature_snapshot',
            'analysis.flow_feature_snapshot.extract_flow_volume_features', 'analysis.flow_feature_snapshot.extract_packet_size_features',
            'analysis.flow_feature_snapshot.extract_flow_duration_features', 'analysis.flow_feature_snapshot.extract_flow_rate_features',
            'analysis.flow_feature_snapshot.extract_inter_arrival_features', 'analysis.flow_feature_snapshot.extract_directional_inter_arrival_features',
            'application.detection_session.DetectionSession.__post_init__', 'application.detection_session.DetectionSession.run_closed_flows',
            'application.detection_pipeline.run_detection_pipeline', 'application.capture_execution.run_capture_execution',
            'application.detection_evaluation.evaluate_detection_result', 'application.detection_metrics.calculate_detection_metrics',
            'application.detection_benchmark.run_detection_benchmark', 'application.detection_experiment.DetectionExperiment.__post_init__',
            'analysis.packet_analysis.analyze_packet', 'analysis.packet_analysis_outcome.analyze_packet_outcome', 'analysis.ipv6.decode_ipv6',
            'detection.packet_integrity.evaluate_packet_integrity', 'detection.flow_volume_threshold.evaluate_flow_volume_threshold',
            'detection.tcp_control_threshold.evaluate_tcp_control_threshold', 'capture.packet_ingestion.consume',
            'capture.pcap_packet_source.PcapPacketSource.start', 'builtins.open', 'pathlib.Path.open', 'pathlib.Path.stat',
            'socket.socket', 'socket.gethostname', 'os.getpid', 'os.getenv', 'time.time', 'time.monotonic', 'time.perf_counter',
            'random.random', 'uuid.uuid4', 'sqlite3.connect', 'threading.Thread.start', 'multiprocessing.Process.start',
            'subprocess.run', 'subprocess.check_output', 'importlib.metadata.version', 'importlib.metadata.distribution',
        )
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(target, side_effect=AssertionError(target))) for target in targets]
            guards.append(stack.enter_context(patch.object(FlowFeatureSnapshot, 'observation_window', new_callable=PropertyMock,
                          create=True, side_effect=AssertionError('window access'))))
            guards.append(stack.enter_context(patch('importlib.import_module', side_effect=AssertionError('dynamic import'))))
            for _ in range(3):
                self.assertEqual(value.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
                with self.assertRaises(ValueError):
                    FeatureContractVersion('other', '')
            for guard in guards:
                guard.assert_not_called()

    def test_public_export_resolves(self):
        self.assertIn('FeatureContractVersion', analysis.__all__)
        self.assertIs(analysis.FeatureContractVersion, FeatureContractVersion)


if __name__ == '__main__':
    unittest.main()
