import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from application import GroundTruth, run_capture_execution, run_end_to_end_validation
from application import end_to_end_validation
from capture import CaptureError, IterablePacketSource, LinkType, consume
from capture import iterable_packet_source
from tests.test_end_to_end_validation import settings
from tests.test_iterable_packet_source import FailingIterable
from tests.test_packet_analysis import UDP_BYTES, make_observation


class InterruptingRecords:
    def __init__(self, error):
        self.error = error
        self.reads = 0
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        self.reads += 1
        if self.reads == 1:
            raise self.error
        return b'next record'

    def close(self):
        self.closed = True


class IterableFailureStateTests(unittest.TestCase):
    def assert_failed_until_stopped(self, source):
        with self.assertRaises(RuntimeError):
            iter(source)
        with self.assertRaises(RuntimeError):
            next(source)
        with self.assertRaises(RuntimeError):
            source.start()
        source.stop()
        source.stop()
        self.assertEqual(list(source), [])
        self.assertIsNone(source._iterator)
        self.assertEqual(source._records, ())

    def test_startup_interruptions_are_terminal_and_preserve_exact_exception(self):
        for error in (KeyboardInterrupt('startup'), SystemExit('startup'), GeneratorExit('startup')):
            with self.subTest(error=type(error).__name__):
                source = IterablePacketSource(FailingIterable(error))
                with self.assertRaises(type(error)) as failure:
                    source.start()
                self.assertIs(failure.exception, error)
                self.assert_failed_until_stopped(source)

    def test_acquisition_interruptions_do_not_allow_following_record_delivery(self):
        for error in (KeyboardInterrupt('read'), SystemExit('read'), GeneratorExit('read')):
            with self.subTest(error=type(error).__name__):
                records = InterruptingRecords(error)
                source = IterablePacketSource(records)
                source.start()
                with self.assertRaises(type(error)) as failure:
                    next(source)
                self.assertIs(failure.exception, error)
                self.assert_failed_until_stopped(source)
                self.assertEqual(records.reads, 1)
                self.assertFalse(records.closed)
                self.assertEqual(next(records), b'next record')

    def test_invalid_clock_observation_marks_failure_without_skipping_record(self):
        records = iter((b'first', b'second'))
        source = IterablePacketSource(records)
        source.start()
        clock = SimpleNamespace(now=Mock(return_value=datetime(2026, 1, 1)))
        with patch.object(iterable_packet_source, 'datetime', clock):
            with self.assertRaisesRegex(ValueError, 'timezone-aware UTC'):
                next(source)
        clock.now.assert_called_once_with(timezone.utc)
        self.assert_failed_until_stopped(source)
        self.assertEqual(next(records), b'second')

    def test_observation_construction_errors_are_terminal_without_reclassification(self):
        for error in (ValueError('construction'), OSError('clock'), KeyboardInterrupt('clock')):
            with self.subTest(error=type(error).__name__):
                records = iter((b'first', b'second'))
                source = IterablePacketSource(records)
                source.start()
                with patch.object(iterable_packet_source, 'PacketObservation', side_effect=error):
                    with self.assertRaises(type(error)) as failure:
                        next(source)
                self.assertIs(failure.exception, error)
                self.assert_failed_until_stopped(source)
                self.assertEqual(next(records), b'second')

    def test_construction_stop_iteration_is_a_capture_failure_not_successful_exhaustion(self):
        for operation in (consume, run_capture_execution):
            with self.subTest(operation=operation.__name__):
                records = iter((b'first', b'second'))
                source = IterablePacketSource(records)
                error = StopIteration('construction')
                delivered = []
                with patch.object(iterable_packet_source, 'PacketObservation', side_effect=error):
                    with self.assertRaises(CaptureError) as failure:
                        operation(source, delivered.append)
                self.assertIs(failure.exception.__cause__, error)
                self.assertEqual(str(failure.exception), 'packet observation construction signaled exhaustion')
                self.assertEqual(delivered, [])
                self.assertEqual(list(source), [])
                self.assertEqual(next(records), b'second')

    def test_real_producer_exhaustion_stays_permanent_and_successful(self):
        records = Mock()
        records.__iter__ = Mock(return_value=records)
        records.__next__ = Mock(side_effect=(StopIteration(), b'later'))
        source = IterablePacketSource(records)
        delivered = []
        consume(source, delivered.append)
        self.assertEqual(delivered, [])
        self.assertEqual(list(source), [])
        records.__next__.assert_called_once_with()

    def test_consumer_interruption_still_stops_source_without_taking_caller_ownership(self):
        for operation in (consume, run_capture_execution):
            error = KeyboardInterrupt('consumer')
            records = iter((make_observation(17, UDP_BYTES).raw_bytes, b'next'))
            source = IterablePacketSource(records, link_type=LinkType(1))
            consumer = Mock(side_effect=error)
            with self.assertRaises(KeyboardInterrupt) as failure:
                operation(source, consumer)
            self.assertIs(failure.exception, error)
            consumer.assert_called_once()
            self.assertEqual(list(source), [])
            self.assertEqual(next(records), b'next')

    def test_observation_failure_cannot_complete_pipeline_evaluation(self):
        for error in (KeyboardInterrupt('clock'), StopIteration('clock')):
            with self.subTest(error=type(error).__name__):
                original = iterable_packet_source.PacketObservation
                calls = []

                def construct(**values):
                    calls.append(values)
                    if len(calls) == 2:
                        raise error
                    return original(**values)

                raw = make_observation(17, UDP_BYTES).raw_bytes
                records = iter((raw, raw, b'undelivered'))
                source = IterablePacketSource(records, link_type=LinkType(1))
                clock = SimpleNamespace(now=Mock(return_value=datetime(2026, 1, 1, tzinfo=timezone.utc)))
                expected = CaptureError if isinstance(error, StopIteration) else KeyboardInterrupt
                with patch.object(iterable_packet_source, 'PacketObservation', side_effect=construct), \
                        patch.object(iterable_packet_source, 'datetime', clock), \
                        patch.object(end_to_end_validation, 'evaluate_detection_result') as evaluate:
                    with self.assertRaises(expected):
                        run_end_to_end_validation(source, configuration=settings(), capture_session_id='failure',
                                                  ground_truth=GroundTruth((), ()))
                evaluate.assert_not_called()
                self.assertEqual(len(calls), 2)
                self.assertEqual(list(source), [])
                self.assertEqual(next(records), b'undelivered')
