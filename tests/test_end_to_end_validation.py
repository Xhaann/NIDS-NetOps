import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import application
from analysis import FeatureContractVersion, FlowIdentity, FlowIdentityError, FlowObservationWindowError, FlowObservationWindowKey
from application import (
    DetectionConfiguration, DetectionDataset, DetectionDatasetCase, DetectionEvaluationResult, DetectionExperiment,
    DetectionMetrics, DetectionPipelineResult, EndToEndValidationResult, EvaluationReport, FlowDetectionIdentity,
    GroundTruth, GroundTruthPolarity, GroundTruthRecord, PacketDetectionIdentity, run_end_to_end_validation,
)
from application import capture_execution, detection_pipeline, detector_orchestration, end_to_end_validation as validation
from capture import CaptureError, CaptureSource, PcapPacketSource
from detection import FlowVolumeMetric, FlowVolumeThresholdConfiguration, PacketIntegrityConfiguration, TCPControlMetric, TCPControlThresholdConfiguration
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ipv6 import SOURCE_ADDRESS, DESTINATION_ADDRESS
from tests.test_ipv6_flow import observation_at
from tests.test_ipv6_transport import fragment_header, observation_for
from tests.test_packet_analysis import TCP_BYTES, UDP_BYTES, make_observation
from tests.test_pcap_packet_source import global_header, record


EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
SOURCE = CaptureSource('validation-input')


def settings():
    return DetectionConfiguration(PacketIntegrityConfiguration('packet', 'p1'),
                                  FlowVolumeThresholdConfiguration('volume', 'v1', FlowVolumeMetric.PACKET_COUNT, 0),
                                  timedelta(seconds=5),
                                  TCPControlThresholdConfiguration('control', 'c1', TCPControlMetric.FORWARD_SYN, 0))


def wire(ipv6=False, protocol=17):
    return observation_at(protocol) if ipv6 else make_observation(protocol, TCP_BYTES if protocol == 6 else UDP_BYTES)


def timestamp(seconds):
    return EPOCH + timedelta(seconds=seconds, microseconds=123456)


def packet_truth(observation, index, seconds, polarity=GroundTruthPolarity.NEGATIVE, network=1):
    target = PacketDetectionIdentity(settings().packet_configuration, index, timestamp(seconds), SOURCE.identifier,
                                     network, len(observation.raw_bytes), observation.original_length)
    return GroundTruthRecord(target, polarity)


def truth_for(observations, seconds, ipv6=False, protocol=17):
    config = settings()
    identity = FlowIdentity(SOURCE_ADDRESS if ipv6 else bytes.fromhex('c0000201'),
                            DESTINATION_ADDRESS if ipv6 else bytes.fromhex('c6336402'),
                            12345 if ipv6 else 0x1234, 443 if ipv6 else 0xabcd, protocol)
    target = FlowDetectionIdentity(config.flow_volume_configuration, FlowObservationWindowKey('validation', 0),
                                   identity, timestamp(seconds[0]), timestamp(seconds[-1]))
    flows = (GroundTruthRecord(target, GroundTruthPolarity.POSITIVE),)
    if protocol == 6:
        control = replace(target, configuration=config.tcp_control_configuration)
        flows += (GroundTruthRecord(control, GroundTruthPolarity.POSITIVE if ipv6 else GroundTruthPolarity.NEGATIVE),)
    return GroundTruth(tuple(packet_truth(o, i, t) for i, (o, t) in enumerate(zip(observations, seconds))), flows)


class EndToEndValidationTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'validation.pcap'

    def source(self, observations=(), seconds=None, network=1, suffix=b''):
        times = tuple(range(1, len(observations) + 1)) if seconds is None else seconds
        data = global_header(network=network) + b''.join(record(o.raw_bytes, seconds=t, fraction=123456, original=o.original_length)
                                                        for o, t in zip(observations, times)) + suffix
        self.path.write_bytes(data)
        return PcapPacketSource(self.path, source=SOURCE)

    def execute(self, source, truth=None, config=None, **kwargs):
        return run_end_to_end_validation(source, configuration=settings() if config is None else config,
                                        capture_session_id='validation', ground_truth=GroundTruth((), ()) if truth is None else truth,
                                        **kwargs)

    def complete_path(self, ipv6, protocol):
        observations = (wire(ipv6, protocol), wire(ipv6, protocol))
        truth = truth_for(observations, (1, 2), ipv6, protocol)
        result = self.execute(self.source(observations), truth)
        self.assertIs(result.ground_truth, truth)
        self.assertEqual(result.report.metrics.packet_metrics, DetectionMetrics(0, 0, 0, 2))
        expected = DetectionMetrics(2, 0, 0, 0) if ipv6 and protocol == 6 else DetectionMetrics(1, 0, 0, int(protocol == 6))
        self.assertEqual(result.report.metrics.flow_metrics, expected)
        self.assertEqual(len(result.pipeline_result.packet_findings), 2)
        self.assertEqual(len(result.pipeline_result.flow_findings), 2 if protocol == 6 else 1)
        self.assertEqual(result.pipeline_result.flow_findings[0].raw_evidence.identity.ip_version, 6 if ipv6 else 4)
        return result

    def test_ipv4_tcp_packet_to_report(self):
        self.complete_path(False, 6)

    def test_ipv4_udp_packet_to_report(self):
        self.complete_path(False, 17)

    def test_ipv6_tcp_packet_to_report(self):
        self.complete_path(True, 6)

    def test_ipv6_udp_packet_to_report(self):
        self.complete_path(True, 17)

    def test_empty_pcap_produces_empty_results_and_undefined_metrics(self):
        result = self.execute(self.source())
        self.assertEqual(result.pipeline_result, DetectionPipelineResult((), ()))
        self.assertEqual(result.report.result, DetectionEvaluationResult((), ()))
        for metrics in (result.report.metrics.packet_metrics, result.report.metrics.flow_metrics):
            self.assertEqual(metrics, DetectionMetrics(0, 0, 0, 0))
            self.assertEqual((metrics.precision, metrics.recall, metrics.f1, metrics.accuracy), (None,) * 4)

    def test_single_packet_preserves_zero_and_unavailable_features(self):
        result = self.execute(self.source((wire(),)))
        snapshot = result.pipeline_result.flow_findings[0].raw_evidence.snapshot
        self.assertEqual(snapshot.flow_duration_features.duration_seconds, 0.0)
        self.assertIsNone(snapshot.flow_rate_features)
        self.assertIsNone(snapshot.directional_inter_arrival_features.reverse_mean_inter_arrival_seconds)
        self.assertEqual(snapshot.flow_volume_features.packet_count, 1)

    def test_duplicate_packets_and_equal_timestamps_keep_source_order(self):
        observations = (wire(), wire(), wire(True))
        result = self.execute(self.source(observations, (1, 1, 2)))
        outcomes = tuple(f.raw_evidence.outcome for f in result.pipeline_result.packet_findings)
        self.assertEqual([o.observation.raw_bytes for o in outcomes], [o.raw_bytes for o in observations])
        self.assertEqual([o.observation.captured_at for o in outcomes], [timestamp(1), timestamp(1), timestamp(2)])
        self.assertIsNot(outcomes[0], outcomes[1])

    def test_capture_lengths_bytes_and_source_are_preserved(self):
        observation = wire()
        observation = replace(observation, original_length=len(observation.raw_bytes) + 50)
        source = self.source((observation,))
        before = self.path.read_bytes()
        result = self.execute(source)
        retained = result.pipeline_result.packet_findings[0].raw_evidence.outcome.observation
        self.assertEqual((retained.raw_bytes, retained.captured_length, retained.original_length),
                         (observation.raw_bytes, len(observation.raw_bytes), observation.original_length))
        self.assertIs(retained.source, SOURCE)
        self.assertEqual(self.path.read_bytes(), before)

    def test_multiple_flow_closure_order_and_detector_order(self):
        result = self.execute(self.source((wire(True, 6), wire(False, 17), wire(True, 17))))
        findings = result.pipeline_result.flow_findings
        self.assertEqual([f.detector_id for f in findings], ['volume', 'control', 'volume', 'volume'])
        self.assertEqual([f.raw_evidence.sequence_number for f in findings], [0, 0, 1, 2])
        self.assertTrue(all(f.raw_evidence.observation_window.closure_reason.value == 'capture_session_end' for f in findings))

    def test_inactivity_boundary_closes_before_new_window(self):
        result = self.execute(self.source((wire(), wire(), wire()), (1, 6, 7)))
        windows = [f.raw_evidence.observation_window for f in result.pipeline_result.flow_findings]
        self.assertEqual([w.closure_reason.value for w in windows], ['inactivity', 'capture_session_end'])
        self.assertEqual([w.key.sequence_number for w in windows], [0, 1])
        self.assertEqual([f.raw_evidence.snapshot.flow_volume_features.packet_count for f in result.pipeline_result.flow_findings], [1, 2])

    def test_directional_features_and_tcp_control_are_retained(self):
        observations = tuple(observation_at(6, reverse=r) for r in (False, True, False, True))
        result = self.execute(self.source(observations, (1, 2, 4, 7)), config=replace(settings(), inactivity_timeout=timedelta(seconds=10)))
        snapshot = result.pipeline_result.flow_findings[0].raw_evidence.snapshot
        self.assertEqual(snapshot.directional_inter_arrival_features.forward_mean_inter_arrival_seconds, 3.0)
        self.assertEqual(snapshot.directional_inter_arrival_features.reverse_mean_inter_arrival_seconds, 5.0)
        self.assertEqual(snapshot.coordinated_state.tcp_control_statistics.forward_syn_count, 2)
        self.assertEqual(snapshot.coordinated_state.tcp_control_statistics.reverse_syn_count, 2)

    def test_feature_contract_and_detector_versions_remain_separate(self):
        result = self.complete_path(True, 6)
        finding = result.pipeline_result.flow_findings[0]
        self.assertEqual(finding.raw_evidence.snapshot.feature_contract, FeatureContractVersion('flow-feature-snapshot', '1'))
        self.assertEqual((finding.version_reference.detector_id, finding.version_reference.detector_version), ('volume', 'v1'))
        self.assertIs(result.report.result.flow_evaluations[0].finding, finding)

    def test_udp_requires_no_tcp_configuration(self):
        result = self.execute(self.source((wire(True, 17),)), config=replace(settings(), tcp_control_configuration=None))
        self.assertEqual([f.detector_id for f in result.pipeline_result.flow_findings], ['volume'])
        self.assertIsNone(result.pipeline_result.flow_findings[0].raw_evidence.snapshot.coordinated_state.tcp_control_statistics)

    def test_tcp_missing_configuration_preserves_existing_error(self):
        source = self.source((wire(True, 6),))
        with self.assertRaisesRegex(TypeError, 'TCP windows require tcp_control_configuration'):
            self.execute(source, config=replace(settings(), tcp_control_configuration=None))
        self.assertEqual(list(source), [])

    def test_structural_analysis_failure_remains_packet_finding(self):
        observation = replace(wire(), raw_bytes=b'', captured_length=0, original_length=0)
        result = self.execute(self.source((observation,)))
        outcome = result.pipeline_result.packet_findings[0].raw_evidence.outcome
        self.assertIsNone(outcome.analysis)
        self.assertIsNotNone(outcome.failure_classification)
        self.assertEqual(result.pipeline_result.flow_findings, ())

    def test_integrity_failure_obeys_explicit_positive_truth(self):
        observation = make_observation(6, TCP_BYTES, ipv4_checksum=0)
        truth = GroundTruth((packet_truth(observation, 0, 1, GroundTruthPolarity.POSITIVE),), ())
        result = self.execute(self.source((observation,)), truth)
        self.assertEqual(result.pipeline_result.packet_findings[0].decision.value, 'match')
        self.assertEqual(result.report.metrics.packet_metrics, DetectionMetrics(1, 0, 0, 0))
        self.assertEqual(result.pipeline_result.flow_findings, ())

    def test_unsupported_link_not_evaluable_is_not_reinterpreted(self):
        observation = wire()
        truth = GroundTruth((packet_truth(observation, 0, 1, GroundTruthPolarity.POSITIVE, 101),), ())
        result = self.execute(self.source((observation,), network=101), truth)
        self.assertEqual(result.pipeline_result.packet_findings[0].decision.value, 'not_evaluable')
        self.assertEqual(result.report.metrics.packet_metrics.false_negatives, 1)
        self.assertEqual(result.pipeline_result.flow_findings, ())

    def test_unsupported_transport_remains_outside_flow_admission(self):
        source = self.source((make_observation(99, b''),))
        with self.assertRaisesRegex(FlowIdentityError, 'supports only IPv4 TCP'):
            self.execute(source)
        self.assertEqual(list(source), [])

    def test_ipv6_extensions_follow_existing_transport_path(self):
        result = self.execute(self.source((observation_at(6, extensions=(0, 43, 60)),)))
        self.assertEqual(len(result.pipeline_result.flow_findings), 2)
        self.assertIsNotNone(result.pipeline_result.packet_findings[0].raw_evidence.outcome.analysis.ipv6_tcp)

    def test_non_first_ipv6_fragment_is_not_reassembled_or_admitted(self):
        observation = observation_for(6, b'fragment', fragment_header(6, offset=1, more=True), 44)
        source = self.source((observation, observation))
        with patch.object(validation, 'evaluate_detection_result') as evaluation:
            with self.assertRaisesRegex(FlowIdentityError, 'requires an initial fragment'):
                self.execute(source)
            evaluation.assert_not_called()
        self.assertEqual(list(source), [])

    def test_ipv6_atomic_fragment_preserves_transport_admission(self):
        result = self.execute(self.source((observation_at(17, fragment=(0, False, 1)),)))
        self.assertEqual(len(result.pipeline_result.flow_findings), 1)
        self.assertEqual(result.pipeline_result.flow_findings[0].raw_evidence.identity.protocol, 17)

    def test_explicit_truth_order_and_exact_targets_are_preserved(self):
        observations = (wire(), wire())
        truth = truth_for(observations, (1, 2))
        truth = replace(truth, packet_records=tuple(reversed(truth.packet_records)))
        result = self.execute(self.source(observations), truth)
        entries = result.report.result.packet_evaluations
        self.assertEqual([e.expectation_index for e in entries], [1, 0])
        self.assertIs(entries[0].expectation.identity, truth.packet_records[1].target)
        self.assertIs(entries[1].expectation.identity, truth.packet_records[0].target)

    def test_unlabeled_truth_does_not_become_negative(self):
        result = self.execute(self.source((wire(),)))
        self.assertEqual(result.report.metrics.packet_metrics, DetectionMetrics(0, 0, 0, 0, 1))
        self.assertEqual(result.report.metrics.flow_metrics, DetectionMetrics(0, 1, 0, 0))

    def test_missing_positive_truth_and_negative_absence_keep_existing_semantics(self):
        observation = wire()
        truth = GroundTruth((packet_truth(observation, 0, 1, GroundTruthPolarity.POSITIVE),
                             packet_truth(observation, 1, 2, GroundTruthPolarity.NEGATIVE)), ())
        result = self.execute(self.source(), truth)
        self.assertEqual(result.report.metrics.packet_metrics, DetectionMetrics(0, 0, 1, 0, 1))

    def test_dataset_and_experiment_context_reaches_report_without_execution(self):
        observation = wire()
        truth = truth_for((observation,), (1,))
        records = truth.packet_records + truth.flow_records
        dataset = DetectionDataset('validation-data', tuple(DetectionDatasetCase(str(i), r.target, r) for i, r in enumerate(records)))
        experiment = DetectionExperiment('validation-study', dataset, 'explicit-validation', '1')
        with patch('application.detection_benchmark.run_detection_benchmark', side_effect=AssertionError('benchmark')):
            result = self.execute(self.source((observation,)), truth, experiment=experiment)
        self.assertIs(result.report.experiment, experiment)
        self.assertIs(result.report.dataset, dataset)
        self.assertEqual(result.report.dataset_case_count, 2)

    def test_configuration_and_inputs_are_retained_without_mutation(self):
        config = settings()
        observation = wire()
        truth = truth_for((observation,), (1,))
        before = replace(config), replace(truth)
        result = self.execute(self.source((observation,)), truth, config)
        self.assertIs(result.report.configuration, config)
        self.assertIs(result.pipeline_result.packet_findings[0].raw_evidence.configuration, config.packet_configuration)
        self.assertEqual((config, truth), before)

    def test_equivalent_fresh_sources_produce_equal_validation_results(self):
        observations = (wire(), wire(True))
        first = self.execute(self.source(observations))
        second = self.execute(PcapPacketSource(self.path, source=SOURCE))
        self.assertEqual(first, second)

    def test_explicit_observation_source_uses_same_validation_boundary(self):
        observation = wire()
        observation = replace(observation, captured_at=timestamp(1), source=SOURCE)
        result = self.execute(MemoryPacketSource((observation,)))
        self.assertIs(result.pipeline_result.packet_findings[0].raw_evidence.outcome.observation, observation)

    def test_no_duplicate_pipeline_analysis_features_detectors_evaluation_metrics_or_report(self):
        source = self.source((wire(True, 6), wire(True, 6)))
        outcomes, snapshots, calculated_metrics = [], [], []
        original_analysis = capture_execution.analyze_packet_outcome
        original_features = detection_pipeline.extract_flow_feature_snapshot
        original_report_init = EvaluationReport.__post_init__
        original_metrics = validation.calculate_detection_metrics
        def analyze(observation):
            value = original_analysis(observation)
            outcomes.append(value)
            return value
        def extract(window):
            value = original_features(window)
            snapshots.append(value)
            return value
        def calculate(evaluation):
            value = original_metrics(evaluation)
            calculated_metrics.append(value)
            return value
        with ExitStack() as stack:
            analysis = stack.enter_context(patch.object(capture_execution, 'analyze_packet_outcome', side_effect=analyze))
            features = stack.enter_context(patch.object(detection_pipeline, 'extract_flow_feature_snapshot', side_effect=extract))
            pipeline = stack.enter_context(patch.object(validation, 'run_detection_pipeline', wraps=validation.run_detection_pipeline))
            evaluation = stack.enter_context(patch.object(validation, 'evaluate_detection_result', wraps=validation.evaluate_detection_result))
            metrics = stack.enter_context(patch.object(validation, 'calculate_detection_metrics', side_effect=calculate))
            report = stack.enter_context(patch.object(EvaluationReport, '__post_init__', autospec=True, side_effect=original_report_init))
            packet = stack.enter_context(patch.object(detector_orchestration, 'evaluate_packet_integrity', wraps=detector_orchestration.evaluate_packet_integrity))
            volume = stack.enter_context(patch.object(detector_orchestration, 'evaluate_flow_volume_threshold', wraps=detector_orchestration.evaluate_flow_volume_threshold))
            control = stack.enter_context(patch.object(detector_orchestration, 'evaluate_tcp_control_threshold', wraps=detector_orchestration.evaluate_tcp_control_threshold))
            result = self.execute(source)
        self.assertEqual((analysis.call_count, features.call_count, packet.call_count, volume.call_count, control.call_count), (2, 1, 2, 1, 1))
        for spy in (pipeline, evaluation, metrics, report):
            spy.assert_called_once()
        self.assertIs(evaluation.call_args.args[0], result.pipeline_result)
        self.assertIs(metrics.call_args.args[0], result.report.result)
        self.assertIs(result.report.metrics, calculated_metrics[0])
        self.assertIs(report.call_args.args[0], result.report)
        self.assertIs(result.pipeline_result.flow_findings[0].raw_evidence.snapshot, snapshots[0])
        for finding, outcome in zip(result.pipeline_result.packet_findings, outcomes):
            self.assertIs(finding.raw_evidence.outcome, outcome)

    def test_source_lifecycle_runs_once_and_cannot_replay(self):
        source = self.source((wire(),))
        with patch.object(source, 'start', wraps=source.start) as start, patch.object(source, 'stop', wraps=source.stop) as stop:
            self.execute(source)
            start.assert_called_once()
            stop.assert_called_once()
        self.assertEqual(list(source), [])
        with self.assertRaisesRegex(RuntimeError, 'source cannot be restarted'):
            self.execute(source)

    def test_corrupt_pcap_after_valid_record_raises_without_evaluation(self):
        source = self.source((wire(),), suffix=b'bad')
        with patch.object(validation, 'evaluate_detection_result') as evaluation, patch.object(source, 'stop', wraps=source.stop) as stop:
            with self.assertRaises(CaptureError):
                self.execute(source)
            evaluation.assert_not_called()
            stop.assert_called_once()
        self.assertEqual(list(source), [])

    def test_missing_pcap_preserves_capture_error(self):
        with self.assertRaises(CaptureError):
            self.execute(PcapPacketSource(self.path))

    def test_decreasing_admitted_timestamps_preserve_flow_error(self):
        source = self.source((wire(), wire()), (2, 1))
        with self.assertRaises(FlowObservationWindowError):
            self.execute(source)
        self.assertEqual(list(source), [])

    def test_analysis_exception_propagates_once_and_stops_source(self):
        source = self.source((wire(), wire()))
        error = RuntimeError('analysis failed')
        with patch.object(capture_execution, 'analyze_packet_outcome', side_effect=error) as analyze:
            with self.assertRaises(RuntimeError) as raised:
                self.execute(source)
            self.assertIs(raised.exception, error)
            analyze.assert_called_once()
        self.assertEqual(list(source), [])

    def test_feature_failure_propagates_without_retry_or_evaluation(self):
        error = RuntimeError('features failed')
        with patch.object(detection_pipeline, 'extract_flow_feature_snapshot', side_effect=error) as features, patch.object(validation, 'evaluate_detection_result') as evaluation:
            with self.assertRaises(RuntimeError) as raised:
                self.execute(self.source((wire(),)))
            self.assertIs(raised.exception, error)
            features.assert_called_once()
            evaluation.assert_not_called()

    def test_packet_detector_failure_prevents_closed_flow_detection(self):
        error = RuntimeError('detector failed')
        source = self.source((wire(), wire()))
        with patch.object(detector_orchestration, 'evaluate_packet_integrity', side_effect=error) as packet, patch.object(detector_orchestration, 'evaluate_flow_volume_threshold') as volume:
            with self.assertRaises(RuntimeError) as raised:
                self.execute(source)
            self.assertIs(raised.exception, error)
            packet.assert_called_once()
            volume.assert_not_called()
        self.assertEqual(list(source), [])

    def test_evaluation_metrics_and_reporting_failures_propagate_once(self):
        for name in ('evaluate_detection_result', 'calculate_detection_metrics', 'EvaluationReport'):
            source = self.source((wire(),))
            error = RuntimeError(name)
            with self.subTest(stage=name), patch.object(validation, name, side_effect=error) as stage:
                with self.assertRaises(RuntimeError) as raised:
                    self.execute(source)
                self.assertIs(raised.exception, error)
                stage.assert_called_once()
            self.assertEqual(list(source), [])

    def test_invalid_configuration_truth_and_experiment_fail_before_capture(self):
        source = self.source()
        with patch.object(source, 'start') as start:
            for changes in ({'configuration': None}, {'ground_truth': None}, {'experiment': 'experiment'}):
                args = dict(configuration=settings(), ground_truth=GroundTruth((), ()), capture_session_id='validation')
                args.update(changes)
                with self.assertRaises(TypeError):
                    run_end_to_end_validation(source, **args)
            start.assert_not_called()

    def test_validation_result_and_nested_artifacts_are_immutable(self):
        result = self.complete_path(False, 17)
        for field in fields(result):
            with self.assertRaises(FrozenInstanceError):
                setattr(result, field.name, None)
        with self.assertRaises(FrozenInstanceError):
            result.report.metrics.packet_metrics.true_positives = 99
        with self.assertRaises(TypeError):
            result.pipeline_result.packet_findings[0] = None

    def test_result_validation_rejects_wrong_or_incomplete_artifacts(self):
        result = self.execute(self.source())
        for name in ('pipeline_result', 'ground_truth', 'report'):
            with self.assertRaises(TypeError):
                replace(result, **{name: None})
        with self.assertRaises(ValueError):
            replace(result, report=replace(result.report, metrics=None))
        with self.assertRaises(ValueError):
            replace(result, report=replace(result.report, configuration=None))

    def test_invalid_session_identity_is_rejected_before_capture(self):
        source = self.source()
        with patch.object(source, 'start') as start:
            for identity, error in (('', FlowObservationWindowError), (None, TypeError)):
                with self.assertRaises(error):
                    run_end_to_end_validation(source, configuration=settings(), capture_session_id=identity,
                                             ground_truth=GroundTruth((), ()))
            start.assert_not_called()

    def test_local_pcap_execution_needs_no_timing_randomness_or_network(self):
        source = self.source((wire(),))
        with ExitStack() as stack:
            for name in ('time.time', 'time.monotonic', 'time.perf_counter', 'random.random', 'uuid.uuid4',
                         'socket.socket', 'socket.gethostname', 'os.getenv', 'os.getpid'):
                stack.enter_context(patch(name, side_effect=AssertionError(name)))
            result = self.execute(source)
            self.assertEqual(result.report.metrics.flow_metrics.false_positives, 1)
            self.assertEqual(result.pipeline_result.packet_findings[0].raw_evidence.outcome.observation.captured_at,
                             timestamp(1))

    def test_public_exports_resolve(self):
        self.assertIs(application.EndToEndValidationResult, EndToEndValidationResult)
        self.assertIs(application.run_end_to_end_validation, run_end_to_end_validation)
        self.assertIn('EndToEndValidationResult', application.__all__)
        self.assertIn('run_end_to_end_validation', application.__all__)


if __name__ == '__main__':
    unittest.main()
