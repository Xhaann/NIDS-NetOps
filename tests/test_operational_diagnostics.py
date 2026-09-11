import io
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError, fields, replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

import analysis
import application
from analysis import (
    EthernetDecodeError, FeatureContractVersion, FlowFeatureSnapshotError, FlowIdentityError,
    FlowObservationWindowKey, PacketAnalysisError, PacketAnalysisFailureClassification, analyze_packet, analyze_packet_outcome,
)
from application import (
    DetectionDataset, DetectionDatasetCase, DetectionEvaluationResult, DetectionExperiment,
    DetectionMetrics, DetectionSession, EvaluationReport, GroundTruth, OperationalDiagnostic, OperationalErrorCategory,
    PerformanceBenchmarkConfiguration, diagnose_error, evaluate_detection_result,
    run_capture_execution, run_detection_benchmark, run_detection_pipeline, run_end_to_end_validation, run_performance_benchmark,
)
from application import cli, detection_pipeline, detector_orchestration, end_to_end_validation
from application import operational_diagnostics as diagnostics_module
from capture import CaptureError, CaptureSource, PcapPacketSource
from detection import DetectionFindingError, DetectorVersion, FlowVolumeThresholdError, PacketIntegrityError, TCPControlThresholdError
from tests.test_end_to_end_validation import settings, wire
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_ground_truth import packet_target
from tests.test_ipv6_transport import fragment_header, observation_for
from tests.test_packet_analysis import make_observation


def describe(error, **changes):
    arguments = dict(operation_id='explicit-operation', message='Operation failed', context=())
    arguments.update(changes)
    return diagnose_error(error, **arguments)


def observe_failure(operation, diagnostics, **context):
    try:
        return operation()
    except Exception as error:
        diagnostics.append(describe(error, **context))
        raise


def pipeline(source):
    config = settings()
    session = DetectionSession(config.packet_configuration, config.flow_volume_configuration, config.tcp_control_configuration)
    return run_detection_pipeline(source, detection_session=session, capture_session_id='diagnostic-session',
                                  inactivity_timeout=config.inactivity_timeout)


class OperationalDiagnosticTests(unittest.TestCase):
    def test_explicit_diagnostic_construction(self):
        value = OperationalDiagnostic(OperationalErrorCategory.CAPTURE_FAILURE, 'capture', 'Input unavailable')
        self.assertEqual((value.category.value, value.operation_id, value.message, value.context),
                         ('capture_failure', 'capture', 'Input unavailable', ()))

    def test_categories_are_bounded_operational_domains(self):
        self.assertEqual([category.value for category in OperationalErrorCategory],
                         ['capture_failure', 'packet_analysis_failure', 'flow_processing_failure',
                          'detection_failure', 'unclassified_failure'])

    def test_invalid_category_is_not_coerced(self):
        for category in ('capture_failure', None, True, PacketAnalysisFailureClassification.UNSUPPORTED):
            with self.assertRaises(TypeError):
                OperationalDiagnostic(category, 'capture', 'Failed')

    def test_blank_operation_or_message_is_rejected(self):
        for name in ('operation_id', 'message'):
            for value in ('', ' ', '\t\n'):
                with self.assertRaises(ValueError):
                    describe(CaptureError(), **{name: value})

    def test_string_fields_require_exact_types(self):
        class String(str):
            pass
        for name in ('operation_id', 'message'):
            for value in (None, 1, True, b'name', String('name')):
                with self.assertRaises(TypeError):
                    describe(CaptureError(), **{name: value})

    def test_operation_and_message_are_preserved_exactly(self):
        value = describe(CaptureError(), operation_id=' Capture A ', message=' Étude failed\ninput unavailable ')
        self.assertEqual(value.operation_id, ' Capture A ')
        self.assertEqual(value.message, ' Étude failed\ninput unavailable ')

    def test_diagnostic_fields_and_context_are_immutable(self):
        value = describe(CaptureError(), context=(CaptureSource('source'),))
        for field in fields(value):
            with self.assertRaises(FrozenInstanceError):
                setattr(value, field.name, None)
        with self.assertRaises(TypeError):
            value.context[0] = CaptureSource('other')
        with self.assertRaises(FrozenInstanceError):
            value.context[0].identifier = 'other'

    def test_equivalent_independent_failures_have_equal_diagnostics(self):
        first = describe(CaptureError('first process'), context=(CaptureSource('same'),))
        second = describe(CaptureError('second process'), context=(CaptureSource('same'),))
        self.assertEqual(first, second)
        self.assertEqual(repr(first), repr(second))
        self.assertNotEqual(first, replace(first, operation_id='other'))
        self.assertNotEqual(first, replace(first, message='Different explanation'))

    def test_context_retains_existing_objects_order_and_multiplicity(self):
        source = CaptureSource('source')
        key = FlowObservationWindowKey('session', 4)
        config = settings()
        data = DetectionDataset('data', (DetectionDatasetCase('packet', packet_target()),))
        experiment = DetectionExperiment('study', data, 'operation', '1')
        version = config.packet_configuration.version_reference
        contract = FeatureContractVersion('flow-feature-snapshot', '1')
        context = (source, key, config, data, experiment, version, contract, source)
        value = describe(CaptureError(), context=context)
        self.assertIs(value.context, context)
        for supplied, retained in zip(context, value.context):
            self.assertIs(retained, supplied)
        self.assertNotEqual(value, replace(value, context=tuple(reversed(context))))
        self.assertEqual(data.cases[0].case_id, 'packet')

    def test_empty_context_does_not_discover_metadata(self):
        value = describe(CaptureError())
        self.assertEqual(value.context, ())
        self.assertEqual([field.name for field in fields(value)], ['category', 'operation_id', 'message', 'context'])

    def test_context_rejects_mutable_collections_and_arbitrary_payloads(self):
        for context in ([], {}, iter(()), ([],), ({},), (wire(),), (b'payload',), ('raw text',), (Exception(),)):
            with self.assertRaises(TypeError):
                describe(CaptureError(), context=context)
        class Source(CaptureSource):
            pass
        with self.assertRaises(TypeError):
            describe(CaptureError(), context=(Source('source'),))

    def test_error_must_be_an_exception_not_an_outcome_or_finding(self):
        outcome = analyze_packet_outcome(wire())
        finding = pipeline(MemoryPacketSource((wire(),))).packet_findings[0]
        for error in (None, 'error', outcome, finding, KeyboardInterrupt(), SystemExit(2)):
            with self.assertRaises(TypeError):
                describe(error)

    def test_capture_exception_has_capture_category(self):
        self.assertIs(describe(CaptureError()).category, OperationalErrorCategory.CAPTURE_FAILURE)

    def test_existing_packet_domain_exceptions_have_analysis_category(self):
        names = ('PacketAnalysisError', 'PacketAnalysisOutcomeError', 'EthernetDecodeError', 'IPv4DecodeError',
                 'IPv6DecodeError', 'TCPDecodeError', 'UDPDecodeError', 'ICMPDecodeError', 'TCPChecksumValidationError',
                 'UDPChecksumValidationError', 'ICMPChecksumValidationError')
        for name in names:
            with self.subTest(error=name):
                self.assertIs(describe(getattr(analysis, name)()).category, OperationalErrorCategory.PACKET_ANALYSIS_FAILURE)

    def test_existing_flow_and_feature_exceptions_have_flow_category(self):
        names = ('FlowIdentityError', 'FlowDirectionError', 'FlowTrackingError', 'FlowStatisticsError',
                 'DirectionalFlowStatisticsError', 'FlowCoordinationError', 'FlowObservationWindowError',
                 'FlowPacketSizeStatisticsError', 'FlowInterArrivalStatisticsError', 'DirectionalInterArrivalStatisticsError',
                 'TCPControlStatisticsError', 'FlowFeatureInputError', 'FlowVolumeFeaturesError', 'PacketSizeFeaturesError',
                 'FlowDurationFeaturesError', 'FlowRateFeaturesError', 'InterArrivalFeaturesError',
                 'DirectionalInterArrivalFeaturesError', 'FlowFeatureSnapshotError')
        for name in names:
            with self.subTest(error=name):
                self.assertIs(describe(getattr(analysis, name)()).category, OperationalErrorCategory.FLOW_PROCESSING_FAILURE)

    def test_existing_detector_exceptions_have_detection_category(self):
        for error_type in (PacketIntegrityError, FlowVolumeThresholdError, TCPControlThresholdError, DetectionFindingError):
            self.assertIs(describe(error_type()).category, OperationalErrorCategory.DETECTION_FAILURE)

    def test_generic_errors_are_not_guessed_to_be_input_or_configuration_failures(self):
        for error in (TypeError(), ValueError(), OverflowError(), RuntimeError(), AssertionError(), OSError(), Exception()):
            self.assertIs(describe(error).category, OperationalErrorCategory.UNCLASSIFIED_FAILURE)

    def test_unrecognized_subclasses_are_not_silently_classified(self):
        class CustomCaptureError(CaptureError):
            pass
        class CustomFlowError(FlowIdentityError):
            pass
        for error in (CustomCaptureError(), CustomFlowError()):
            self.assertIs(describe(error).category, OperationalErrorCategory.UNCLASSIFIED_FAILURE)

    def test_arbitrary_exception_text_and_repr_are_never_accessed(self):
        class Error(Exception):
            def __str__(self):
                raise AssertionError('exception text accessed')
            def __repr__(self):
                raise AssertionError('exception representation accessed')
        value = describe(Error(object()), message='Explicit safe explanation')
        self.assertEqual(value.message, 'Explicit safe explanation')
        self.assertIs(value.category, OperationalErrorCategory.UNCLASSIFIED_FAILURE)

    def test_exception_args_cause_context_and_traceback_remain_unchanged(self):
        original = CaptureError('private source detail')
        cause = OSError('private path')
        try:
            raise original from cause
        except CaptureError as error:
            before = error.args, error.__cause__, error.__context__, error.__traceback__, dict(error.__dict__)
            value = describe(error)
            after = error.args, error.__cause__, error.__context__, error.__traceback__, dict(error.__dict__)
            self.assertEqual(before, after)
            self.assertIs(error.__traceback__, before[3])
        self.assertNotIn('private', repr(value))

    def test_caller_reraises_original_failure_once_without_success_value(self):
        error = CaptureError('failed')
        operation = Mock(side_effect=error)
        diagnostics = []
        with self.assertRaises(CaptureError) as raised:
            observe_failure(operation, diagnostics)
        self.assertIs(raised.exception, error)
        operation.assert_called_once()
        self.assertEqual(len(diagnostics), 1)
        self.assertIs(diagnostics[0].category, OperationalErrorCategory.CAPTURE_FAILURE)

    def test_unexpected_failure_remains_unclassified_and_propagates(self):
        error = RuntimeError('unexpected bug')
        operation = Mock(side_effect=error)
        diagnostics = []
        with self.assertRaises(RuntimeError) as raised:
            observe_failure(operation, diagnostics, operation_id='detection')
        self.assertIs(raised.exception, error)
        operation.assert_called_once()
        self.assertIs(diagnostics[0].category, OperationalErrorCategory.UNCLASSIFIED_FAILURE)

    def test_success_is_returned_exactly_without_diagnosing(self):
        output = object()
        diagnostics = []
        self.assertIs(observe_failure(lambda: output, diagnostics), output)
        self.assertEqual(diagnostics, [])

    def test_interrupts_are_not_caught_by_exception_diagnostic_usage(self):
        diagnostics = []
        with self.assertRaises(KeyboardInterrupt):
            observe_failure(Mock(side_effect=KeyboardInterrupt()), diagnostics)
        self.assertEqual(diagnostics, [])

    def test_capture_execution_start_iteration_and_stop_failure_compatibility(self):
        for phase in ('start', 'iteration', 'stop'):
            error = CaptureError(phase)
            source = MemoryPacketSource((), **{phase + '_error': error})
            diagnostics = []
            with self.assertRaises(CaptureError) as raised:
                observe_failure(lambda: run_capture_execution(source, Mock()), diagnostics, context=(CaptureSource('input'),))
            self.assertIs(raised.exception, error)
            self.assertEqual(source.events.count('start'), 1)
            self.assertEqual(source.events.count('stop'), 1)
            self.assertIs(diagnostics[0].category, OperationalErrorCategory.CAPTURE_FAILURE)

    def test_missing_pcap_is_diagnosable_without_path_disclosure(self):
        with TemporaryDirectory() as directory:
            source = PcapPacketSource(Path(directory) / 'missing.pcap')
            diagnostics = []
            with self.assertRaises(CaptureError):
                observe_failure(lambda: pipeline(source), diagnostics, operation_id='pipeline', message='Capture unavailable')
            self.assertNotIn(directory, repr(diagnostics[0]))
        self.assertEqual(list(source), [])

    def test_direct_packet_analysis_exception_is_diagnosable(self):
        observation = replace(wire(), raw_bytes=b'', captured_length=0, original_length=0)
        diagnostics = []
        with self.assertRaises(EthernetDecodeError):
            observe_failure(lambda: analyze_packet(observation), diagnostics, operation_id='packet-analysis')
        self.assertIs(diagnostics[0].category, OperationalErrorCategory.PACKET_ANALYSIS_FAILURE)

    def test_malformed_packet_outcome_remains_an_outcome_not_an_operational_failure(self):
        observation = replace(wire(), raw_bytes=b'', captured_length=0, original_length=0)
        diagnostics = []
        outcome = observe_failure(lambda: analyze_packet_outcome(observation), diagnostics)
        self.assertIs(outcome.observation, observation)
        self.assertIsNone(outcome.analysis)
        self.assertIs(outcome.failure_classification, PacketAnalysisFailureClassification.INCOMPLETE)
        self.assertEqual(diagnostics, [])

    def test_unrecognized_analysis_exception_is_not_replaced_by_an_outcome(self):
        error = PacketAnalysisError('unrecognized implementation failure')
        diagnostics = []
        with patch('analysis.packet_analysis_outcome.analyze_packet', side_effect=error) as operation:
            with self.assertRaises(PacketAnalysisError) as raised:
                observe_failure(lambda: analyze_packet_outcome(wire()), diagnostics)
            operation.assert_called_once()
        self.assertIs(raised.exception, error)
        self.assertIs(diagnostics[0].category, OperationalErrorCategory.PACKET_ANALYSIS_FAILURE)

    def test_unsupported_flow_transport_preserves_admission_failure(self):
        source = MemoryPacketSource((make_observation(99, b''),))
        diagnostics = []
        with self.assertRaises(FlowIdentityError):
            observe_failure(lambda: pipeline(source), diagnostics, context=(FlowObservationWindowKey('diagnostic-session', 0),))
        self.assertIs(diagnostics[0].category, OperationalErrorCategory.FLOW_PROCESSING_FAILURE)
        self.assertEqual(source.events.count('stop'), 1)

    def test_non_initial_ipv6_fragment_preserves_flow_failure(self):
        observation = observation_for(6, b'fragment', fragment_header(6, offset=1, more=True), 44)
        diagnostics = []
        with self.assertRaises(FlowIdentityError):
            observe_failure(lambda: pipeline(MemoryPacketSource((observation,))), diagnostics)
        self.assertIs(diagnostics[0].category, OperationalErrorCategory.FLOW_PROCESSING_FAILURE)

    def test_feature_failure_stops_before_detector_execution(self):
        diagnostics = []
        error = FlowFeatureSnapshotError('feature contract invalid')
        with patch.object(detection_pipeline, 'extract_flow_feature_snapshot', side_effect=error) as features, \
             patch.object(detector_orchestration, 'evaluate_flow_volume_threshold') as detector:
            with self.assertRaises(FlowFeatureSnapshotError) as raised:
                observe_failure(lambda: pipeline(MemoryPacketSource((wire(),))), diagnostics)
            features.assert_called_once()
            detector.assert_not_called()
        self.assertIs(raised.exception, error)
        self.assertIs(diagnostics[0].category, OperationalErrorCategory.FLOW_PROCESSING_FAILURE)

    def test_detector_failure_does_not_fabricate_finding_or_run_evaluation(self):
        error = PacketIntegrityError('detector contract failed')
        diagnostics = []
        source = MemoryPacketSource((wire(), wire()))
        with patch.object(detector_orchestration, 'evaluate_packet_integrity', side_effect=error) as detector, \
             patch.object(end_to_end_validation, 'evaluate_detection_result') as evaluation:
            with self.assertRaises(PacketIntegrityError) as raised:
                observe_failure(lambda: run_end_to_end_validation(source, configuration=settings(), capture_session_id='session',
                                                                  ground_truth=GroundTruth((), ())), diagnostics)
            detector.assert_called_once()
            evaluation.assert_not_called()
        self.assertIs(raised.exception, error)
        self.assertIs(diagnostics[0].category, OperationalErrorCategory.DETECTION_FAILURE)
        self.assertEqual(source.events.count('stop'), 1)

    def test_cleanup_error_precedence_and_original_chain_are_preserved(self):
        detector_error, stop_error = PacketIntegrityError('detector'), CaptureError('stop')
        source = MemoryPacketSource((wire(),), stop_error=stop_error)
        diagnostics = []
        with patch.object(DetectionSession, 'run_packets', side_effect=detector_error):
            with self.assertRaises(CaptureError) as raised:
                observe_failure(lambda: pipeline(source), diagnostics)
        self.assertIs(raised.exception, stop_error)
        self.assertIs(raised.exception.__context__, detector_error)
        self.assertIs(diagnostics[0].category, OperationalErrorCategory.CAPTURE_FAILURE)

    def test_invalid_configuration_retains_generic_exception_and_explicit_boundary(self):
        diagnostics = []
        with self.assertRaises(ValueError):
            observe_failure(lambda: replace(settings(), inactivity_timeout=timedelta(0)), diagnostics,
                            operation_id='configuration', message='Inactivity timeout must be positive')
        self.assertEqual(diagnostics[0].operation_id, 'configuration')
        self.assertIs(diagnostics[0].category, OperationalErrorCategory.UNCLASSIFIED_FAILURE)

    def test_evaluation_invalid_input_is_not_a_negative_detection(self):
        diagnostics = []
        with self.assertRaises(TypeError):
            observe_failure(lambda: evaluate_detection_result(None, None), diagnostics, operation_id='evaluation')
        self.assertIs(diagnostics[0].category, OperationalErrorCategory.UNCLASSIFIED_FAILURE)
        self.assertEqual(diagnostics[0].operation_id, 'evaluation')

    def test_reporting_error_does_not_change_supplied_evaluation(self):
        evaluation = DetectionEvaluationResult((), ())
        diagnostics = []
        with self.assertRaises(TypeError):
            observe_failure(lambda: EvaluationReport(evaluation, metrics='invalid'), diagnostics, operation_id='report')
        self.assertEqual(evaluation, DetectionEvaluationResult((), ()))
        self.assertIs(diagnostics[0].category, OperationalErrorCategory.UNCLASSIFIED_FAILURE)

    def test_end_to_end_evaluation_failure_stops_before_metrics(self):
        diagnostics = []
        error = ValueError('invalid expectations')
        with patch.object(end_to_end_validation, 'evaluate_detection_result', side_effect=error) as evaluation, \
             patch.object(end_to_end_validation, 'calculate_detection_metrics') as metrics:
            with self.assertRaises(ValueError) as raised:
                observe_failure(lambda: run_end_to_end_validation(MemoryPacketSource(()), configuration=settings(),
                                                                  capture_session_id='session', ground_truth=GroundTruth((), ())), diagnostics)
            evaluation.assert_called_once()
            metrics.assert_not_called()
        self.assertIs(raised.exception, error)

    def test_empty_pipeline_remains_empty_and_has_no_diagnostic(self):
        diagnostics = []
        result = observe_failure(lambda: pipeline(MemoryPacketSource(())), diagnostics)
        self.assertEqual((result.packet_findings, result.flow_findings), ((), ()))
        self.assertEqual(diagnostics, [])

    def test_ipv4_ipv6_tcp_udp_successful_validation_remains_deterministic(self):
        for ipv6, protocol in ((False, 6), (False, 17), (True, 6), (True, 17)):
            observations = (wire(ipv6, protocol),)
            diagnostics = []
            def operation():
                return run_end_to_end_validation(MemoryPacketSource(observations), configuration=settings(),
                                                capture_session_id='session', ground_truth=GroundTruth((), ()))
            first = observe_failure(operation, diagnostics)
            second = observe_failure(operation, diagnostics)
            self.assertEqual(first, second)
            self.assertEqual(diagnostics, [])
            self.assertEqual(first.pipeline_result.flow_findings[0].raw_evidence.identity.ip_version, 6 if ipv6 else 4)
            self.assertEqual(len(first.pipeline_result.flow_findings), 2 if protocol == 6 else 1)
            self.assertEqual(first.pipeline_result.flow_findings[0].raw_evidence.snapshot.feature_contract,
                             FeatureContractVersion('flow-feature-snapshot', '1'))
            self.assertEqual(first.pipeline_result.packet_findings[0].version_reference,
                             settings().packet_configuration.version_reference)

    def test_not_evaluable_and_metrics_are_not_operational_categories(self):
        observation = replace(wire(), link_type=None)
        diagnostics = []
        result = observe_failure(lambda: run_end_to_end_validation(MemoryPacketSource((observation,)), configuration=settings(),
                                                                  capture_session_id='session', ground_truth=GroundTruth((), ())), diagnostics)
        self.assertEqual(result.pipeline_result.packet_findings[0].decision.value, 'not_evaluable')
        self.assertEqual(result.report.metrics.packet_metrics, DetectionMetrics(0, 0, 0, 0, 1))
        self.assertEqual(diagnostics, [])

    def test_dataset_case_failure_retains_order_without_later_execution(self):
        cases = tuple(DetectionDatasetCase(name, packet_target(packet_index=i)) for i, name in enumerate(('z', 'a')))
        data = DetectionDataset('data', cases)
        operation = Mock(side_effect=RuntimeError('case failed'))
        diagnostics = []
        with self.assertRaises(RuntimeError):
            observe_failure(lambda: run_detection_benchmark(data, operation), diagnostics, context=(data,))
        operation.assert_called_once_with(cases[0])
        self.assertIs(diagnostics[0].context[0], data)
        self.assertEqual([case.case_id for case in data.cases], ['z', 'a'])

    def test_performance_failure_has_no_end_read_retry_or_success_summary(self):
        operation = Mock(side_effect=CaptureError('capture'))
        clock = Mock(side_effect=(0.0, 1.0, 2.0, 3.0))
        diagnostics = []
        with self.assertRaises(CaptureError):
            run_performance_benchmark(lambda: observe_failure(operation, diagnostics),
                                      configuration=PerformanceBenchmarkConfiguration('op', '1', 2), clock=clock)
        operation.assert_called_once()
        clock.assert_called_once()
        self.assertEqual(len(diagnostics), 1)

    def test_performance_warmup_failure_remains_untimed(self):
        operation = Mock(side_effect=CaptureError('warmup'))
        clock, diagnostics = Mock(), []
        with self.assertRaises(CaptureError):
            run_performance_benchmark(lambda: observe_failure(operation, diagnostics),
                                      configuration=PerformanceBenchmarkConfiguration('op', '1', 2, 1), clock=clock)
        operation.assert_called_once()
        clock.assert_not_called()

    def test_performance_success_preserves_exact_counts_and_observations(self):
        operation, diagnostics = Mock(return_value=None), []
        clock = Mock(side_effect=(0.0, 2.0, 3.0, 4.0))
        result = run_performance_benchmark(lambda: observe_failure(operation, diagnostics),
                                           configuration=PerformanceBenchmarkConfiguration('op', '1', 2, 1), clock=clock)
        self.assertEqual((operation.call_count, clock.call_count), (3, 4))
        self.assertEqual(result.elapsed_seconds, (2.0, 1.0))
        self.assertEqual(diagnostics, [])

    def test_cli_capture_failure_keeps_existing_status_and_output(self):
        args = ['unused.pcap', '--capture-session-id', 'session', '--inactivity-timeout-microseconds', '1000',
                '--packet-detector-id', 'packet', '--packet-detector-version', '1',
                '--volume-detector-id', 'volume', '--volume-detector-version', '1', '--volume-metric', 'packet_count',
                '--volume-threshold', '0', '--tcp-detector-id', 'tcp', '--tcp-detector-version', '1',
                '--tcp-metric', 'forward_syn_count', '--tcp-threshold', '0']
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(cli, 'run_detection_pipeline', side_effect=CaptureError('private detail')) as operation, \
             redirect_stdout(stdout), redirect_stderr(stderr):
            status = cli.main(args)
        self.assertEqual((status, stdout.getvalue(), stderr.getvalue()), (1, '', '{"error":"capture_error"}\n'))
        operation.assert_called_once()

    def test_diagnosis_has_no_execution_external_state_or_logging_side_effects(self):
        error = CaptureError('detail')
        context = (settings(), DetectorVersion('detector', '1'), FeatureContractVersion('flow-feature-snapshot', '1'))
        stdout, stderr = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(redirect_stdout(stdout))
            stack.enter_context(redirect_stderr(stderr))
            for name in ('builtins.open', 'pathlib.Path.open', 'socket.socket', 'socket.gethostname', 'os.getenv', 'os.getpid',
                         'time.time', 'time.monotonic', 'time.perf_counter', 'random.random', 'uuid.uuid4', 'logging.Logger._log',
                         'subprocess.Popen', 'importlib.metadata.version', 'application.performance_benchmark.perf_counter',
                         'application.detection_pipeline.run_detection_pipeline', 'application.end_to_end_validation.run_end_to_end_validation',
                         'application.detection_evaluation.evaluate_detection_result', 'application.detection_metrics.calculate_detection_metrics'):
                stack.enter_context(patch(name, side_effect=AssertionError(name)))
            first = describe(error, context=context)
            second = describe(error, context=context)
            self.assertEqual(first, second)
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ('', ''))
        self.assertIs(first.context, context)

    def test_public_exports_resolve_without_exposing_helpers(self):
        for name in ('OperationalDiagnostic', 'OperationalErrorCategory', 'diagnose_error'):
            self.assertIn(name, application.__all__)
            self.assertIs(getattr(application, name), getattr(diagnostics_module, name))
        self.assertNotIn('_category', application.__all__)


if __name__ == '__main__':
    unittest.main()
