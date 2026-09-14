import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta
from unittest.mock import patch

import application
from application.detection_configuration import DetectionConfiguration
from detection import (
    FlowVolumeMetric,
    FlowVolumeThresholdConfiguration,
    PacketIntegrityConfiguration,
    TCPControlMetric,
    TCPControlThresholdConfiguration,
)


def configuration():
    return DetectionConfiguration(
        PacketIntegrityConfiguration('integrity', 'packet-v1'),
        FlowVolumeThresholdConfiguration('volume', 'volume-v2', FlowVolumeMetric.PACKET_COUNT, 10),
        timedelta(seconds=30),
        TCPControlThresholdConfiguration('control', 'tcp-v3', TCPControlMetric.FORWARD_SYN, 5),
    )


class DetectionConfigurationTests(unittest.TestCase):
    def test_valid_explicit_configuration(self):
        value = configuration()
        self.assertEqual(value.packet_configuration.detector_id, 'integrity')
        self.assertEqual(value.flow_volume_configuration.threshold, 10)
        self.assertEqual(value.tcp_control_configuration.threshold, 5)
        self.assertEqual(value.inactivity_timeout, timedelta(seconds=30))

    def test_packet_configuration_retains_exact_reference(self):
        packet = PacketIntegrityConfiguration('packet', 'revision')
        self.assertIs(replace(configuration(), packet_configuration=packet).packet_configuration, packet)

    def test_volume_configuration_retains_exact_reference(self):
        volume = FlowVolumeThresholdConfiguration('volume', 'revision', FlowVolumeMetric.ORIGINAL_BYTES, 100)
        self.assertIs(replace(configuration(), flow_volume_configuration=volume).flow_volume_configuration, volume)

    def test_tcp_configuration_retains_exact_reference(self):
        tcp = TCPControlThresholdConfiguration('control', 'revision', TCPControlMetric.REVERSE_ACK, 100)
        self.assertIs(replace(configuration(), tcp_control_configuration=tcp).tcp_control_configuration, tcp)

    def test_tcp_omission_is_explicit_absence_without_default_detector(self):
        value = configuration()
        omitted = DetectionConfiguration(value.packet_configuration, value.flow_volume_configuration, value.inactivity_timeout)
        self.assertIsNone(omitted.tcp_control_configuration)
        self.assertEqual(omitted, replace(value, tcp_control_configuration=None))

    def test_packet_configuration_is_required(self):
        value = configuration()
        with self.assertRaises(TypeError):
            DetectionConfiguration(flow_volume_configuration=value.flow_volume_configuration, inactivity_timeout=value.inactivity_timeout)

    def test_volume_configuration_is_required(self):
        value = configuration()
        with self.assertRaises(TypeError):
            DetectionConfiguration(packet_configuration=value.packet_configuration, inactivity_timeout=value.inactivity_timeout)

    def test_timeout_is_required_without_an_implicit_default(self):
        value = configuration()
        with self.assertRaises(TypeError):
            DetectionConfiguration(value.packet_configuration, value.flow_volume_configuration)

    def test_invalid_packet_references_are_not_coerced(self):
        for invalid in (None, 'packet', {}, (), [], True, 1):
            with self.subTest(value=invalid), self.assertRaisesRegex(TypeError, 'packet_configuration must be exactly'):
                replace(configuration(), packet_configuration=invalid)

    def test_invalid_volume_references_are_not_coerced(self):
        for invalid in (None, 'volume', {}, (), [], True, 1):
            with self.subTest(value=invalid), self.assertRaisesRegex(TypeError, 'flow_volume_configuration must be exactly'):
                replace(configuration(), flow_volume_configuration=invalid)

    def test_invalid_tcp_references_are_not_coerced(self):
        for invalid in ('tcp', {}, (), [], True, 1):
            with self.subTest(value=invalid), self.assertRaisesRegex(TypeError, 'tcp_control_configuration must be exactly'):
                replace(configuration(), tcp_control_configuration=invalid)

    def test_configuration_families_cannot_be_substituted(self):
        value = configuration()
        names = ('packet_configuration', 'flow_volume_configuration', 'tcp_control_configuration')
        for name in names:
            for other in names:
                if name != other:
                    with self.subTest(field=name, other=other), self.assertRaises(TypeError):
                        replace(value, **{name: getattr(value, other)})

    def test_configuration_subclasses_are_rejected(self):
        class PacketSubclass(PacketIntegrityConfiguration):
            pass
        class VolumeSubclass(FlowVolumeThresholdConfiguration):
            pass
        class TCPSubclass(TCPControlThresholdConfiguration):
            pass
        for name, value in (
            ('packet_configuration', PacketSubclass('packet', '1')),
            ('flow_volume_configuration', VolumeSubclass('volume', '1', FlowVolumeMetric.PACKET_COUNT, 1)),
            ('tcp_control_configuration', TCPSubclass('tcp', '1', TCPControlMetric.FORWARD_SYN, 1)),
        ):
            with self.subTest(field=name), self.assertRaises(TypeError):
                replace(configuration(), **{name: value})

    def test_timeout_requires_duration_not_numeric_or_timestamp(self):
        for invalid in (None, True, 30, 30.0, '30', datetime(2026, 1, 1), (), {}):
            with self.subTest(value=invalid), self.assertRaisesRegex(TypeError, 'inactivity_timeout must be exactly a timedelta'):
                replace(configuration(), inactivity_timeout=invalid)

    def test_duration_subclasses_are_rejected(self):
        class OtherDuration(timedelta):
            pass
        with self.assertRaises(TypeError):
            replace(configuration(), inactivity_timeout=OtherDuration(seconds=1))

    def test_zero_timeout_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'inactivity_timeout must be positive'):
            replace(configuration(), inactivity_timeout=timedelta(0))

    def test_negative_timeout_is_rejected(self):
        for duration in (timedelta(microseconds=-1), timedelta(days=-1), timedelta.min):
            with self.subTest(duration=duration), self.assertRaisesRegex(ValueError, 'inactivity_timeout must be positive'):
                replace(configuration(), inactivity_timeout=duration)

    def test_smallest_positive_duration_is_not_rounded(self):
        duration = timedelta(microseconds=1)
        self.assertEqual(replace(configuration(), inactivity_timeout=duration).inactivity_timeout, duration)

    def test_largest_duration_is_not_arbitrarily_capped(self):
        self.assertEqual(replace(configuration(), inactivity_timeout=timedelta.max).inactivity_timeout, timedelta.max)

    def test_duration_precision_and_reference_are_preserved(self):
        duration = timedelta(days=3, seconds=17, microseconds=123457)
        self.assertIs(replace(configuration(), inactivity_timeout=duration).inactivity_timeout, duration)

    def test_independent_equivalent_configurations_compare_equal(self):
        first, second = configuration(), configuration()
        self.assertIsNot(first.packet_configuration, second.packet_configuration)
        self.assertEqual(first, second)

    def test_packet_identity_and_version_participate_in_equality(self):
        value = configuration()
        for name in ('detector_id', 'detector_version'):
            self.assertNotEqual(value, replace(value, packet_configuration=replace(value.packet_configuration, **{name: 'other'})))

    def test_volume_identity_and_version_participate_in_equality(self):
        value = configuration()
        for name in ('detector_id', 'detector_version'):
            self.assertNotEqual(value, replace(value, flow_volume_configuration=replace(value.flow_volume_configuration, **{name: 'other'})))

    def test_tcp_identity_and_version_participate_in_equality(self):
        value = configuration()
        for name in ('detector_id', 'detector_version'):
            self.assertNotEqual(value, replace(value, tcp_control_configuration=replace(value.tcp_control_configuration, **{name: 'other'})))

    def test_selected_metrics_participate_in_equality(self):
        value = configuration()
        self.assertNotEqual(value, replace(value, flow_volume_configuration=replace(value.flow_volume_configuration, metric=FlowVolumeMetric.CAPTURED_BYTES)))
        self.assertNotEqual(value, replace(value, tcp_control_configuration=replace(value.tcp_control_configuration, metric=TCPControlMetric.REVERSE_SYN)))

    def test_thresholds_participate_in_equality(self):
        value = configuration()
        self.assertNotEqual(value, replace(value, flow_volume_configuration=replace(value.flow_volume_configuration, threshold=11)))
        self.assertNotEqual(value, replace(value, tcp_control_configuration=replace(value.tcp_control_configuration, threshold=6)))

    def test_timeout_participates_in_equality(self):
        value = configuration()
        self.assertNotEqual(value, replace(value, inactivity_timeout=value.inactivity_timeout + timedelta(microseconds=1)))

    def test_absent_tcp_configuration_differs_from_present(self):
        value = configuration()
        self.assertNotEqual(value, replace(value, tcp_control_configuration=None))

    def test_supplied_detector_identity_strings_are_not_normalized(self):
        value = configuration()
        for name in ('packet_configuration', 'flow_volume_configuration', 'tcp_control_configuration'):
            nested = replace(getattr(value, name), detector_id=' Détecteur ', detector_version=' Revision A ')
            actual = getattr(replace(value, **{name: nested}), name)
            self.assertEqual((actual.detector_id, actual.detector_version), (' Détecteur ', ' Revision A '))

    def test_zero_and_large_integer_thresholds_remain_exact(self):
        for threshold in (0, 10 ** 100):
            value = configuration()
            value = replace(value, flow_volume_configuration=replace(value.flow_volume_configuration, threshold=threshold),
                            tcp_control_configuration=replace(value.tcp_control_configuration, threshold=threshold))
            self.assertEqual(value.flow_volume_configuration.threshold, threshold)
            self.assertEqual(value.tcp_control_configuration.threshold, threshold)
            self.assertIs(type(value.flow_volume_configuration.threshold), int)
            self.assertIs(type(value.tcp_control_configuration.threshold), int)

    def test_fractional_rate_threshold_is_not_rounded_or_coerced(self):
        volume = FlowVolumeThresholdConfiguration('rate', '1', FlowVolumeMetric.PACKETS_PER_SECOND, 1.23456789012345)
        value = replace(configuration(), flow_volume_configuration=volume)
        self.assertIs(value.flow_volume_configuration.threshold, volume.threshold)
        self.assertIs(type(value.flow_volume_configuration.threshold), float)

    def test_existing_metric_vocabularies_are_preserved(self):
        value = configuration()
        for metric in FlowVolumeMetric:
            threshold = 1.0 if metric.value.endswith('_per_second') else 1
            nested = replace(value.flow_volume_configuration, metric=metric, threshold=threshold)
            self.assertIs(replace(value, flow_volume_configuration=nested).flow_volume_configuration.metric, metric)
        for metric in TCPControlMetric:
            nested = replace(value.tcp_control_configuration, metric=metric)
            self.assertIs(replace(value, tcp_control_configuration=nested).tcp_control_configuration.metric, metric)

    def test_all_configuration_fields_are_frozen(self):
        value = configuration()
        for field in fields(value):
            with self.subTest(field=field.name), self.assertRaises(FrozenInstanceError):
                setattr(value, field.name, None)

    def test_nested_configurations_remain_immutable(self):
        value = configuration()
        for nested in (value.packet_configuration, value.flow_volume_configuration, value.tcp_control_configuration):
            with self.assertRaises(FrozenInstanceError):
                nested.detector_version = 'changed'

    def test_caller_owned_inputs_are_preserved(self):
        original = configuration()
        inputs = dict(packet_configuration=original.packet_configuration,
                      flow_volume_configuration=original.flow_volume_configuration,
                      inactivity_timeout=original.inactivity_timeout,
                      tcp_control_configuration=original.tcp_control_configuration)
        before = inputs.copy()
        result = DetectionConfiguration(**inputs)
        self.assertEqual(inputs, before)
        inputs.clear()
        self.assertEqual(result, original)
        for name, value in before.items():
            self.assertIs(getattr(result, name), value)

    def test_existing_configuration_validation_is_not_reexecuted(self):
        original = configuration()
        with ExitStack() as stack:
            guards = [stack.enter_context(patch.object(kind, '__post_init__', side_effect=AssertionError('revalidation')))
                      for kind in (PacketIntegrityConfiguration, FlowVolumeThresholdConfiguration, TCPControlThresholdConfiguration)]
            self.assertEqual(replace(original), original)
            for guard in guards:
                guard.assert_not_called()

    def test_independent_construction_and_inspection_has_no_retained_state(self):
        original = configuration()
        for _ in range(3):
            replace(original, inactivity_timeout=timedelta(seconds=1), tcp_control_configuration=None)
            with self.assertRaises(ValueError):
                replace(original, inactivity_timeout=timedelta(0))
            other = configuration()
            self.assertEqual(other, original)
            self.assertEqual(tuple(getattr(other, field.name) for field in fields(other)),
                             tuple(getattr(original, field.name) for field in fields(original)))

    def test_runtime_and_result_objects_cannot_replace_configuration(self):
        value = configuration()
        session = application.DetectionSession(value.packet_configuration, value.flow_volume_configuration, value.tcp_control_configuration)
        for invalid in (session, application.DetectionPipelineResult((), ()), lambda: value):
            with self.assertRaises(TypeError):
                replace(value, packet_configuration=invalid)

    def test_configuration_exposes_only_semantic_settings(self):
        value = configuration()
        self.assertEqual(tuple(field.name for field in fields(value)),
                         ('packet_configuration', 'flow_volume_configuration', 'inactivity_timeout', 'tcp_control_configuration',
                          'max_active_windows'))
        self.assertFalse(callable(value))

    def test_construction_and_inspection_do_not_execute_or_access_external_state(self):
        original = configuration()
        targets = (
            'application.detection_session.DetectionSession.__post_init__',
            'application.detection_session.DetectionSession.run_packets', 'application.detection_session.DetectionSession.run_closed_flows',
            'application.detection_pipeline.run_detection_pipeline', 'application.capture_execution.run_capture_execution',
            'application.flow_observation_session.run_flow_observation_session',
            'application.detection_evaluation.evaluate_detection_result', 'application.detection_metrics.calculate_detection_metrics',
            'application.detection_benchmark.run_detection_benchmark', 'application.detection_experiment.DetectionExperiment.__post_init__',
            'application.detector_orchestration.run_packet_detectors', 'application.detector_orchestration.run_closed_flow_detectors',
            'analysis.packet_analysis.analyze_packet', 'analysis.packet_analysis_outcome.analyze_packet_outcome',
            'analysis.flow_feature_snapshot.extract_flow_feature_snapshot', 'analysis.ipv6.decode_ipv6',
            'analysis.flow_observation_window.FlowObservationWindowManager.__init__',
            'detection.packet_integrity.evaluate_packet_integrity', 'detection.flow_volume_threshold.evaluate_flow_volume_threshold',
            'detection.tcp_control_threshold.evaluate_tcp_control_threshold', 'capture.packet_ingestion.consume',
            'capture.pcap_packet_source.PcapPacketSource.start', 'builtins.open', 'pathlib.Path.open', 'pathlib.Path.stat',
            'pathlib.Path.write_text', 'socket.socket', 'socket.gethostname', 'os.getpid', 'os.getenv',
            'time.time', 'time.monotonic', 'time.perf_counter', 'random.random', 'uuid.uuid4', 'sqlite3.connect',
            'threading.Thread.start', 'multiprocessing.Process.start',
        )
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(target, side_effect=AssertionError(target))) for target in targets]
            first, second = replace(original), replace(original)
            self.assertEqual(first, second)
            self.assertEqual(first.inactivity_timeout, timedelta(seconds=30))
            self.assertEqual(first.packet_configuration.detector_version, 'packet-v1')
            for guard in guards:
                guard.assert_not_called()

    def test_public_export_resolves(self):
        self.assertIn('DetectionConfiguration', application.__all__)
        self.assertIs(application.DetectionConfiguration, DetectionConfiguration)


if __name__ == '__main__':
    unittest.main()
