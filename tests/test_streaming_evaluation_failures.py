from contextlib import contextmanager, ExitStack
from dataclasses import replace
import unittest
from unittest.mock import patch

from analysis import FlowObservationWindowUpdate
from application import (
    GroundTruth, IncrementalDetectionEvaluator, IncrementalDetectionMetrics, run_streaming_evaluation,
)
from application import detection_session, incremental_detection_evaluation, streaming_evaluation
from capture import CaptureError
from tests.test_flow_capacity import capacity_packet
from tests.test_flow_observation_session import MemoryPacketSource
from tests.test_incremental_evaluation_stream import external_truth
from tests.test_streaming_evaluation import configuration, execute


@contextmanager
def observe_owners():
    owners, events = {}, []

    def evaluator(*args, **kwargs):
        owner = IncrementalDetectionEvaluator(*args, **kwargs)
        owners['evaluator'] = owner
        return owner

    def metrics():
        owner = IncrementalDetectionMetrics()
        owners['metrics'] = owner
        return owner

    def tracked(original, label):
        def operation(owner):
            events.append(label)
            return original(owner)
        return operation

    with ExitStack() as stack:
        stack.enter_context(patch.object(streaming_evaluation, 'IncrementalDetectionEvaluator', evaluator))
        stack.enter_context(patch.object(streaming_evaluation, 'IncrementalDetectionMetrics', metrics))
        for owner_type, name in ((IncrementalDetectionEvaluator, 'evaluator'), (IncrementalDetectionMetrics, 'metrics')):
            for operation in ('finish', 'abort'):
                original = getattr(owner_type, operation)
                stack.enter_context(patch.object(owner_type, operation, tracked(original, name + '.' + operation)))
        yield owners, events


class StreamingEvaluationFailureTests(unittest.TestCase):
    def assert_aborted(self, owners, events):
        for name in ('evaluator', 'metrics'):
            self.assertFalse(owners[name].finished)
            self.assertEqual(events.count(name + '.abort'), 1)
            with self.assertRaises(ValueError):
                owners[name].finish()
        self.assertEqual(owners['evaluator'].pending_flow_count, 0)

    def test_configuration_and_truth_type_validation_precedes_owner_construction_and_capture(self):
        for name in ('configuration', 'ground_truth'):
            for invalid in (None, (), {}, object()):
                source = MemoryPacketSource(())
                arguments = dict(configuration=configuration(), capture_session_id='stream', ground_truth=GroundTruth((), ()))
                arguments[name] = invalid
                with patch.object(streaming_evaluation, 'IncrementalDetectionMetrics', side_effect=AssertionError('owner construction')):
                    with self.assertRaises(TypeError):
                        run_streaming_evaluation(source, **arguments)
                self.assertEqual(source.events, [])

    def test_session_id_validation_and_invalid_source_abort_without_completed_metrics(self):
        for source, session_id, error_type in ((MemoryPacketSource(()), '', ValueError), (object(), 'stream', AttributeError)):
            with observe_owners() as (owners, events):
                with self.assertRaises(error_type):
                    run_streaming_evaluation(source, configuration=configuration(), capture_session_id=session_id,
                                             ground_truth=GroundTruth((), ()))
                self.assertNotIn('evaluator.finish', events)
                self.assertNotIn('metrics.finish', events)
                self.assert_aborted(owners, events)

    def test_expectation_and_session_construction_failures_do_not_start_capture(self):
        for target in ('ExpectedDetectionResult', 'DetectionSession', 'IncrementalDetectionMetrics'):
            source = MemoryPacketSource(())
            error = MemoryError(target)
            with patch.object(streaming_evaluation, target, side_effect=error):
                with self.assertRaises(MemoryError) as caught:
                    execute(source)
            self.assertIs(caught.exception, error)
            self.assertEqual(source.events, [])

    def test_evaluator_constructor_failure_aborts_created_metrics_without_capture(self):
        source = MemoryPacketSource(())
        metrics = IncrementalDetectionMetrics()
        error = MemoryError('evaluator initialization')
        with patch.object(streaming_evaluation, 'IncrementalDetectionMetrics', return_value=metrics), \
             patch.object(streaming_evaluation, 'IncrementalDetectionEvaluator', side_effect=error), \
             patch.object(metrics, 'abort', wraps=metrics.abort) as abort:
            with self.assertRaises(MemoryError) as caught:
                execute(source)
        self.assertIs(caught.exception, error)
        self.assertEqual(abort.call_count, 1)
        self.assertEqual(source.events, [])
        with self.assertRaises(ValueError):
            metrics.finish()

    def test_capture_start_iteration_and_stop_failures_never_finalize_incomplete_evaluation(self):
        for phase in ('start', 'iteration', 'stop'):
            error = CaptureError(phase)
            source = MemoryPacketSource((capacity_packet(0),), **{phase + '_error': error})
            with observe_owners() as (owners, events):
                with self.assertRaises(CaptureError) as caught:
                    execute(source)
                self.assertIs(caught.exception, error)
                self.assertNotIn('evaluator.finish', events)
                self.assertNotIn('metrics.finish', events)
                self.assert_aborted(owners, events)
            self.assertEqual(source.events.count('stop'), 1)

    def test_packet_detector_failure_after_partial_delivery_aborts_both_owners(self):
        original = detection_session.DetectionSession.run_packets
        count = []
        error = RuntimeError('packet detector')

        def detect(owner, outcomes):
            count.append(None)
            if len(count) == 2:
                raise error
            return original(owner, outcomes)

        source = MemoryPacketSource(tuple(capacity_packet(index, index) for index in range(3)))
        with observe_owners() as (owners, events), patch.object(detection_session.DetectionSession, 'run_packets', detect):
            with self.assertRaises(RuntimeError) as caught:
                execute(source)
            self.assertIs(caught.exception, error)
            self.assertNotIn('metrics.finish', events)
            self.assert_aborted(owners, events)
        self.assertEqual(source.events, ['start', 'produce:0', 'produce:1', 'stop'])

    def test_flow_detector_and_final_window_publication_failures_abort_without_retry(self):
        for target in ('application.detector_orchestration.evaluate_tcp_control_threshold',
                       'analysis.flow_observation_window.FlowObservationWindow.__post_init__'):
            error = MemoryError('final flow')
            source = MemoryPacketSource((capacity_packet(0, protocol=6),))
            with observe_owners() as (owners, events), patch(target, side_effect=error) as failure:
                with self.assertRaises(MemoryError) as caught:
                    execute(source)
                self.assertIs(caught.exception, error)
                self.assertEqual(failure.call_count, 1)
                self.assertNotIn('evaluator.finish', events)
                self.assert_aborted(owners, events)
            self.assertTrue(source.stopped)

    def test_capacity_publication_error_keeps_existing_exception_and_aborts_partial_delivery(self):
        original = FlowObservationWindowUpdate.__post_init__
        error = MemoryError('capacity publication')

        def validate(update):
            original(update)
            if update.closed_windows:
                raise error

        source = MemoryPacketSource((capacity_packet(0), capacity_packet(1, 1)))
        with observe_owners() as (owners, events), patch.object(FlowObservationWindowUpdate, '__post_init__', validate):
            with self.assertRaises(MemoryError) as caught:
                execute(source, config=replace(configuration(), max_active_windows=1))
            self.assertIs(caught.exception, error)
            self.assertNotIn('metrics.finish', events)
            self.assert_aborted(owners, events)

    def test_evaluator_or_metric_record_failure_stops_capture_without_finishing(self):
        for owner_type in (IncrementalDetectionEvaluator, IncrementalDetectionMetrics):
            for channel in ('packet', 'flow'):
                for error in (RuntimeError('record'), MemoryError('record'), KeyboardInterrupt()):
                    source = MemoryPacketSource((capacity_packet(0), capacity_packet(1, 1)))
                    with observe_owners() as (owners, events), patch.object(owner_type, 'record_' + channel, side_effect=error) as record:
                        with self.assertRaises(type(error)) as caught:
                            execute(source)
                        self.assertIs(caught.exception, error)
                        self.assertEqual(record.call_count, 1)
                        self.assertNotIn('metrics.finish', events)
                        self.assert_aborted(owners, events)
                    self.assertTrue(source.stopped)

    def test_evaluation_finalization_failure_releases_pending_suffix_and_aborts_metrics(self):
        packets = (capacity_packet(0),)
        config = configuration()
        config = replace(config, flow_volume_configuration=replace(config.flow_volume_configuration, threshold=99))
        truth = external_truth(packets, False, 17)
        truth = replace(truth, flow_records=tuple(replace(record, target=replace(record.target,
                        configuration=config.flow_volume_configuration)) for record in truth.flow_records))
        error = MemoryError('final assignment')
        original = incremental_detection_evaluation._match_findings

        def matching(findings, expectations, identities, used=()):
            if isinstance(findings, list):
                raise error
            return original(findings, expectations, identities, used)

        with observe_owners() as (owners, events):
            with patch.object(incremental_detection_evaluation, '_match_findings', matching):
                with self.assertRaises(MemoryError) as caught:
                    execute(MemoryPacketSource(packets), truth, config)
            self.assertIs(caught.exception, error)
            self.assertEqual(events.count('evaluator.finish'), 1)
            self.assertNotIn('metrics.finish', events)
            self.assert_aborted(owners, events)

    def test_metric_record_failure_during_missing_expectations_prevents_metrics_finalization(self):
        packet = capacity_packet(0)
        truth = external_truth((packet,), False, 17)
        error = RuntimeError('final entry')
        with observe_owners() as (owners, events), patch.object(IncrementalDetectionMetrics, 'record_packet', side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                execute(MemoryPacketSource(()), truth)
            self.assertIs(caught.exception, error)
            self.assertEqual(events.count('evaluator.finish'), 1)
            self.assertNotIn('metrics.finish', events)
            self.assert_aborted(owners, events)

    def test_metrics_finalization_failure_preserves_completed_evaluator_and_returns_nothing(self):
        error = MemoryError('metric result')
        with observe_owners() as (owners, events), patch('application.incremental_detection_metrics.DetectionEvaluationMetrics', side_effect=error):
            with self.assertRaises(MemoryError) as caught:
                execute(MemoryPacketSource((capacity_packet(0),)))
            self.assertIs(caught.exception, error)
            self.assertTrue(owners['evaluator'].finished)
            self.assertFalse(owners['metrics'].finished)
            self.assertEqual(events, ['evaluator.finish', 'metrics.finish', 'metrics.abort'])
            with self.assertRaises(ValueError):
                owners['metrics'].finish()

    def test_source_stop_failure_preserves_existing_precedence_and_exception_context(self):
        original_error, stop_error = RuntimeError('evaluation'), CaptureError('stop')
        source = MemoryPacketSource((capacity_packet(0),), stop_error=stop_error)
        with observe_owners() as (owners, events), patch.object(IncrementalDetectionEvaluator, 'record_packet', side_effect=original_error):
            with self.assertRaises(CaptureError) as caught:
                execute(source)
            self.assertIs(caught.exception, stop_error)
            self.assertIs(caught.exception.__context__, original_error)
            self.assert_aborted(owners, events)

    def test_failed_execution_does_not_poison_fresh_replay(self):
        packet = capacity_packet(0)
        with self.assertRaises(CaptureError):
            execute(MemoryPacketSource((packet,), iteration_error=CaptureError('capture')))
        self.assertEqual(execute(MemoryPacketSource((packet,))), execute(MemoryPacketSource((packet,))))
