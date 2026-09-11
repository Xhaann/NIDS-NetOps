import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import PropertyMock, patch

import detection
from application import (
    DetectionBenchmarkCaseResult, DetectionBenchmarkResult, DetectionDataset, DetectionDatasetCase,
    DetectionExperiment, GroundTruth, detection_identity,
)
from detection import (
    DetectionFinding, DetectorVersion, FlowVolumeMetric, FlowVolumeThresholdConfiguration,
    FlowVolumeThresholdDecision, PacketIntegrityConfiguration, PacketIntegrityDecision,
    TCPControlMetric, TCPControlThresholdConfiguration, TCPControlThresholdDecision,
    detection_finding_from_evaluation,
)
from tests.test_detection_configuration import configuration
from tests.test_detection_evaluation import C, evaluate, expected, flow_finding, packet_finding
from tests.test_detection_finding import flow_volume_evaluation, tcp_control_evaluation
from tests.test_ground_truth import flow_target, negative, packet_target, positive


class DetectorVersionTests(unittest.TestCase):
    def test_explicit_pair_construction(self):
        value = DetectorVersion('integrity', 'revision-a')
        self.assertEqual((value.detector_id, value.detector_version), ('integrity', 'revision-a'))

    def test_both_identity_components_are_required(self):
        with self.assertRaises(TypeError):
            DetectorVersion(detector_id='integrity')
        with self.assertRaises(TypeError):
            DetectorVersion(detector_version='revision-a')

    def test_blank_detector_ids_are_rejected(self):
        for value in ('', ' ', '\t\n'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'detector_id must not be blank'):
                DetectorVersion(value, '1')

    def test_blank_versions_are_rejected(self):
        for value in ('', ' ', '\t\n'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'detector_version must not be blank'):
                DetectorVersion('integrity', value)

    def test_invalid_detector_id_types_are_not_coerced(self):
        for value in (None, 1, True, b'id', (), [], {}, object()):
            with self.subTest(value=value), self.assertRaisesRegex(TypeError, 'detector_id must be exactly a string'):
                DetectorVersion(value, '1')

    def test_invalid_version_types_are_not_coerced(self):
        for value in (None, 1, 1.0, True, b'1', (1, 0, 0), [], {}, object()):
            with self.subTest(value=value), self.assertRaisesRegex(TypeError, 'detector_version must be exactly a string'):
                DetectorVersion('integrity', value)

    def test_string_subclasses_are_rejected_for_both_components(self):
        class OtherString(str):
            pass
        for values in ((OtherString('id'), '1'), ('id', OtherString('1'))):
            with self.assertRaises(TypeError):
                DetectorVersion(*values)

    def test_explicit_non_semantic_versions_are_accepted(self):
        for version in ('revision-a', '1', 'vNext', '2026-study', '1.0.0+local'):
            self.assertEqual(DetectorVersion('id', version).detector_version, version)

    def test_exact_whitespace_case_and_unicode_are_preserved(self):
        detector_id, version = ' Détecteur A ', '\tRévision B\n'
        value = DetectorVersion(detector_id, version)
        self.assertIs(value.detector_id, detector_id)
        self.assertIs(value.detector_version, version)

    def test_independently_constructed_equal_pairs_compare_equal(self):
        first, second = DetectorVersion('id', '1'), DetectorVersion('id', '1')
        self.assertIsNot(first, second)
        self.assertEqual(first, second)

    def test_different_detector_ids_are_distinct(self):
        self.assertNotEqual(DetectorVersion('packet', '1'), DetectorVersion('volume', '1'))

    def test_different_versions_are_distinct(self):
        self.assertNotEqual(DetectorVersion('id', '1'), DetectorVersion('id', '2'))

    def test_no_version_normalization_affects_equality(self):
        first = DetectorVersion('id', 'v1')
        for version in ('V1', ' v1', 'v1 ', '1', '1.0.0'):
            self.assertNotEqual(first, DetectorVersion('id', version))

    def test_both_fields_are_immutable(self):
        value = DetectorVersion('id', '1')
        for name in ('detector_id', 'detector_version'):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, name, 'other')

    def test_pair_has_no_semantic_version_ordering(self):
        with self.assertRaises(TypeError):
            DetectorVersion('id', '2') < DetectorVersion('id', '10')

    def test_reference_is_not_a_configuration_or_untyped_tuple(self):
        reference = DetectorVersion('id', '1')
        self.assertNotEqual(reference, ('id', '1'))
        self.assertNotEqual(reference, PacketIntegrityConfiguration('id', '1'))

    def test_packet_configuration_projection_preserves_pair(self):
        config = PacketIntegrityConfiguration('packet', 'p-rev')
        self.assertEqual(config.version_reference, DetectorVersion('packet', 'p-rev'))
        self.assertEqual(tuple(f.name for f in fields(config)), ('detector_id', 'detector_version'))

    def test_volume_configuration_projection_preserves_pair(self):
        config = FlowVolumeThresholdConfiguration('volume', 'v-rev', FlowVolumeMetric.PACKET_COUNT, 10)
        self.assertEqual(config.version_reference, DetectorVersion('volume', 'v-rev'))
        self.assertEqual(tuple(f.name for f in fields(config)), ('detector_id', 'detector_version', 'metric', 'threshold'))

    def test_tcp_configuration_projection_preserves_pair(self):
        config = TCPControlThresholdConfiguration('control', 'c-rev', TCPControlMetric.FORWARD_SYN, 5)
        self.assertEqual(config.version_reference, DetectorVersion('control', 'c-rev'))
        self.assertEqual(tuple(f.name for f in fields(config)), ('detector_id', 'detector_version', 'metric', 'threshold'))

    def test_threshold_changes_do_not_change_version_reference(self):
        config = configuration()
        for value in (config.flow_volume_configuration, config.tcp_control_configuration):
            other = replace(value, threshold=value.threshold + 1)
            self.assertNotEqual(value, other)
            self.assertEqual(value.version_reference, other.version_reference)

    def test_metric_changes_do_not_change_version_reference(self):
        config = configuration()
        for value, metric in ((config.flow_volume_configuration, FlowVolumeMetric.ORIGINAL_BYTES),
                              (config.tcp_control_configuration, TCPControlMetric.REVERSE_SYN)):
            other = replace(value, metric=metric)
            self.assertNotEqual(value, other)
            self.assertEqual(value.version_reference, other.version_reference)

    def test_configuration_replacement_has_no_stale_version_reference(self):
        config = configuration()
        for value in (config.packet_configuration, config.flow_volume_configuration, config.tcp_control_configuration):
            original = value.version_reference
            changed = replace(value, detector_version='next')
            self.assertEqual(changed.version_reference, DetectorVersion(value.detector_id, 'next'))
            self.assertNotEqual(original, changed.version_reference)
            self.assertEqual(value.version_reference, original)

    def test_aggregate_configuration_preserves_nested_versions(self):
        config = configuration()
        before = replace(config)
        self.assertEqual(tuple(c.version_reference for c in (config.packet_configuration, config.flow_volume_configuration, config.tcp_control_configuration)),
                         (DetectorVersion('integrity', 'packet-v1'), DetectorVersion('volume', 'volume-v2'), DetectorVersion('control', 'tcp-v3')))
        self.assertEqual(config, before)
        self.assertIsNone(replace(config, tcp_control_configuration=None).tcp_control_configuration)

    def test_packet_finding_projection_retains_all_decisions_and_evidence(self):
        for decision in PacketIntegrityDecision:
            finding = packet_finding(decision)
            evidence = finding.raw_evidence
            self.assertEqual(finding.version_reference, evidence.configuration.version_reference)
            self.assertIs(finding.raw_evidence, evidence)
            self.assertIs(finding.decision, decision)

    def test_volume_finding_projection_retains_all_decisions_and_evidence(self):
        for decision in FlowVolumeThresholdDecision:
            finding = detection_finding_from_evaluation(flow_volume_evaluation(decision))
            evidence = finding.raw_evidence
            self.assertEqual(finding.version_reference, evidence.configuration.version_reference)
            self.assertIs(finding.raw_evidence, evidence)
            self.assertIs(finding.decision, decision)

    def test_tcp_finding_projection_retains_supported_decisions_and_evidence(self):
        for decision in (TCPControlThresholdDecision.MATCH, TCPControlThresholdDecision.NO_MATCH):
            finding = detection_finding_from_evaluation(tcp_control_evaluation(decision))
            evidence = finding.raw_evidence
            self.assertEqual(finding.version_reference, evidence.configuration.version_reference)
            self.assertIs(finding.raw_evidence, evidence)
            self.assertIs(finding.decision, decision)

    def test_finding_schema_remains_the_existing_five_fields(self):
        self.assertEqual(tuple(f.name for f in fields(DetectionFinding)),
                         ('detector_id', 'detector_version', 'decision', 'raw_evidence', 'security_interpretation'))

    def test_packet_detection_identity_keeps_version_and_position(self):
        finding = packet_finding()
        first, second = detection_identity(finding, packet_index=0), detection_identity(finding, packet_index=1)
        self.assertEqual(first.configuration.version_reference, finding.version_reference)
        self.assertEqual(first.configuration.version_reference, second.configuration.version_reference)
        self.assertNotEqual(first, second)

    def test_flow_detection_identity_preserves_ipv4_ipv6_tcp_udp_domains(self):
        for ipv6 in (False, True):
            for protocol in (6, 17):
                with self.subTest(ipv6=ipv6, protocol=protocol):
                    finding = flow_finding(protocol=protocol, ipv6=ipv6)
                    identity = detection_identity(finding)
                    self.assertEqual(identity.configuration.version_reference, finding.version_reference)
                    self.assertEqual(identity.flow_identity.ip_version, 6 if ipv6 else 4)
                    self.assertEqual(identity.flow_identity.protocol, protocol)

    def test_equal_version_pair_does_not_merge_packet_and_flow_targets(self):
        packet = packet_target()
        flow = flow_target(configuration=FlowVolumeThresholdConfiguration('integrity', '1', FlowVolumeMetric.PACKET_COUNT, 10))
        self.assertEqual(packet.configuration.version_reference, flow.configuration.version_reference)
        self.assertNotEqual(packet, flow)

    def test_truth_preserves_versions_and_polarities(self):
        first = packet_target()
        second = replace(first, configuration=replace(first.configuration, detector_version='2'))
        truth = GroundTruth((positive(first), negative(second)), ())
        self.assertEqual(tuple(r.target.configuration.version_reference for r in truth.packet_records),
                         (DetectorVersion('integrity', '1'), DetectorVersion('integrity', '2')))
        self.assertEqual(truth.packet_records, (positive(first), negative(second)))

    def test_dataset_preserves_order_truth_and_target_references(self):
        packet, flow = packet_target(), flow_target()
        cases = (DetectionDatasetCase('flow', flow, negative(flow)), DetectionDatasetCase('packet', packet, positive(packet)))
        data = DetectionDataset('study', cases)
        references = tuple(case.target.configuration.version_reference for case in data.cases)
        self.assertEqual(references, (DetectorVersion('volume', '1'), DetectorVersion('integrity', '1')))
        self.assertIs(data.cases, cases)
        self.assertIs(data.cases[0].target, flow)

    def test_benchmark_artifact_preserves_case_version_without_execution(self):
        case = DetectionDatasetCase('packet', packet_target())
        data = DetectionDataset('study', (case,))
        result = DetectionBenchmarkResult(data, (DetectionBenchmarkCaseResult(case),))
        self.assertIs(result.case_results[0].case, case)
        self.assertEqual(result.case_results[0].case.target.configuration.version_reference, DetectorVersion('integrity', '1'))
        self.assertIsNone(result.case_results[0].evaluation)
        self.assertIsNone(result.case_results[0].metrics)

    def test_experiment_dataset_version_changes_remain_meaningful(self):
        target = packet_target()
        first = DetectionExperiment('study', DetectionDataset('data', (DetectionDatasetCase('case', target),)), 'evaluate', '1')
        changed = replace(target, configuration=replace(target.configuration, detector_version='2'))
        second = replace(first, dataset=DetectionDataset('data', (DetectionDatasetCase('case', changed),)))
        self.assertNotEqual(first, second)
        self.assertEqual(first.dataset.cases[0].target.configuration.version_reference, DetectorVersion('integrity', '1'))
        self.assertEqual(second.dataset.cases[0].target.configuration.version_reference, DetectorVersion('integrity', '2'))

    def test_packet_evaluation_still_distinguishes_versions(self):
        finding = packet_finding()
        expectation = expected(finding, index=0)
        identity = expectation.identity
        other = replace(expectation, identity=replace(identity, configuration=replace(identity.configuration, detector_version='2')))
        self.assertEqual(evaluate(packets=(finding,), packet_expectations=(expectation,)).packet_evaluations[0].classification, C.TRUE_POSITIVE)
        result = evaluate(packets=(finding,), packet_expectations=(other,))
        self.assertCountEqual([e.classification for e in result.packet_evaluations], [C.FALSE_POSITIVE, C.FALSE_NEGATIVE])

    def test_flow_evaluation_still_uses_full_configuration(self):
        finding = flow_finding()
        expectation = expected(finding)
        identity = expectation.identity
        for changes in ({'detector_version': '2'}, {'threshold': 2}):
            other = replace(expectation, identity=replace(identity, configuration=replace(identity.configuration, **changes)))
            result = evaluate(flows=(finding,), flow_expectations=(other,))
            self.assertCountEqual([e.classification for e in result.flow_evaluations], [C.FALSE_POSITIVE, C.FALSE_NEGATIVE])
        self.assertEqual(evaluate(flows=(finding,), flow_expectations=(expectation,)).flow_evaluations[0].classification, C.TRUE_POSITIVE)

    def test_repeated_inspection_is_deterministic_and_does_not_mutate_inputs(self):
        config, finding = configuration(), packet_finding()
        before = replace(config), replace(finding)
        for _ in range(3):
            with self.assertRaises(ValueError):
                DetectorVersion('other', '')
            self.assertEqual(config.packet_configuration.version_reference, configuration().packet_configuration.version_reference)
            self.assertEqual(finding.version_reference, packet_finding().version_reference)
        self.assertEqual((config, finding), before)

    def test_reference_contains_only_explicit_identity_and_version(self):
        value = DetectorVersion('id', 'revision')
        self.assertEqual(tuple(f.name for f in fields(value)), ('detector_id', 'detector_version'))
        self.assertFalse(callable(value))

    def test_projection_does_not_read_raw_evidence_or_packets(self):
        finding = packet_finding()
        with patch.object(DetectionFinding, 'raw_evidence', new_callable=PropertyMock, create=True,
                          side_effect=AssertionError('evidence access')) as guard:
            self.assertEqual(finding.version_reference, DetectorVersion('packet-integrity', '1'))
            guard.assert_not_called()

    def test_construction_and_projection_do_not_execute_or_discover_state(self):
        config, finding = configuration(), packet_finding()
        targets = (
            'application.detection_session.DetectionSession.__post_init__',
            'application.detection_session.DetectionSession.run_packets', 'application.detection_session.DetectionSession.run_closed_flows',
            'application.detection_pipeline.run_detection_pipeline', 'application.capture_execution.run_capture_execution',
            'application.detection_evaluation.evaluate_detection_result', 'application.detection_metrics.calculate_detection_metrics',
            'application.detection_benchmark.run_detection_benchmark', 'application.detection_experiment.DetectionExperiment.__post_init__',
            'analysis.packet_analysis.analyze_packet', 'analysis.packet_analysis_outcome.analyze_packet_outcome',
            'analysis.flow_feature_snapshot.extract_flow_feature_snapshot', 'detection.packet_integrity.evaluate_packet_integrity',
            'detection.flow_volume_threshold.evaluate_flow_volume_threshold', 'detection.tcp_control_threshold.evaluate_tcp_control_threshold',
            'capture.packet_ingestion.consume', 'capture.pcap_packet_source.PcapPacketSource.start',
            'builtins.open', 'pathlib.Path.open', 'pathlib.Path.stat', 'socket.socket', 'socket.gethostname',
            'os.getpid', 'os.getenv', 'time.time', 'time.monotonic', 'time.perf_counter', 'random.random', 'uuid.uuid4',
            'sqlite3.connect', 'threading.Thread.start', 'multiprocessing.Process.start', 'subprocess.run', 'subprocess.check_output',
            'importlib.metadata.version', 'importlib.metadata.distribution',
        )
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(target, side_effect=AssertionError(target))) for target in targets]
            guards.append(stack.enter_context(patch('importlib.import_module', side_effect=AssertionError('dynamic import'))))
            reference = DetectorVersion('packet-integrity', '1')
            self.assertEqual(finding.version_reference, reference)
            self.assertEqual(config.packet_configuration.version_reference, DetectorVersion('integrity', 'packet-v1'))
            self.assertEqual(config.flow_volume_configuration.version_reference, DetectorVersion('volume', 'volume-v2'))
            self.assertEqual(config.tcp_control_configuration.version_reference, DetectorVersion('control', 'tcp-v3'))
            for guard in guards:
                guard.assert_not_called()

    def test_public_export_resolves(self):
        self.assertIn('DetectorVersion', detection.__all__)
        self.assertIs(detection.DetectorVersion, DetectorVersion)


if __name__ == '__main__':
    unittest.main()
