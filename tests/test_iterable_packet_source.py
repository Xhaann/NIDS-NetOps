import unittest
from datetime import datetime, timedelta, timezone
from typing import Iterator, cast
from unittest.mock import patch

from capture import (
    CaptureError,
    CaptureSource,
    IterablePacketSource,
    LinkType,
    PacketObservation,
    PacketSource,
    consume,
)


class FailingIterable:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def __iter__(self) -> Iterator[bytes]:
        raise self.error


def interrupted_records(error: Exception) -> Iterator[bytes]:
    yield b"first"
    raise error


class IterablePacketSourceTests(unittest.TestCase):
    def test_configured_link_type_is_preserved_through_ingestion(self) -> None:
        link_type = LinkType(65001)
        identity = CaptureSource("local-metadata-test")
        binary = b"\x00\xff\x80\n\r"
        records = (binary, b"", b"last", binary)
        source = IterablePacketSource(records, source=identity, link_type=link_type)
        observations: list[PacketObservation] = []
        consume(source, observations.append)
        self.assertEqual(len(observations), len(records))
        for observation, record in zip(observations, records):
            self.assertIs(observation.link_type, link_type)
            self.assertIs(observation.source, identity)
            self.assertIs(observation.raw_bytes, record)
            self.assertEqual(observation.captured_length, len(record))
            self.assertEqual(observation.original_length, len(record))
            self.assertEqual(observation.captured_at.utcoffset(), timedelta(0))
        self.assertEqual(link_type.value, 65001)
        self.assertEqual(identity.identifier, "local-metadata-test")
        self.assertEqual(list(source), [])
        source.stop()
        with self.assertRaises(RuntimeError):
            source.start()

    def test_sources_keep_independent_link_types(self) -> None:
        first_type = LinkType(0)
        second_type = LinkType(1)
        first = IterablePacketSource((b"one", b"two"), link_type=first_type)
        second = IterablePacketSource((b"one", b"two"), link_type=second_type)
        try:
            first.start()
            second.start()
            for _ in range(2):
                self.assertIs(next(first).link_type, first_type)
                self.assertIs(next(second).link_type, second_type)
        finally:
            first.stop()
            second.stop()

    def test_invalid_link_type_is_rejected_before_acquisition(self) -> None:
        for value in (0, 1, True, "ethernet", b"1"):
            for records in ((), (b"packet",)):
                with self.subTest(value=value, records=records):
                    iterator = iter(records)
                    with self.assertRaisesRegex(
                        TypeError, "link_type must be a LinkType or None"
                    ):
                        IterablePacketSource(iterator, link_type=cast(LinkType, value))
                    self.assertEqual(tuple(iterator), records)

    def test_records_create_distinct_observations_without_copying(self) -> None:
        binary = b"\x00\xff\x80\n\r"
        records = (binary, b"", b"last", binary)
        source = IterablePacketSource(records)
        source.start()
        try:
            observations = list(source)
        finally:
            source.stop()
        self.assertEqual(len(observations), len(records))
        self.assertEqual(len({id(value) for value in observations}), len(records))
        for observation, record in zip(observations, records):
            self.assertIsInstance(observation, PacketObservation)
            self.assertIs(observation.raw_bytes, record)
            self.assertEqual(observation.captured_length, len(record))
            self.assertEqual(observation.original_length, len(record))
            self.assertIsInstance(observation.captured_at, datetime)
            self.assertIsNotNone(observation.captured_at.tzinfo)
            self.assertEqual(observation.captured_at.utcoffset(), timedelta(0))
            self.assertEqual(observation.source, CaptureSource("local-iterable"))
            self.assertIs(observation.source, observations[0].source)
            self.assertIsNone(observation.link_type)

    def test_each_observation_reads_the_clock_at_creation(self) -> None:
        first_time = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)
        second_time = first_time + timedelta(seconds=1)
        source = IterablePacketSource((b"first", b"second"))
        with patch("capture.iterable_packet_source.datetime") as clock:
            clock.now.side_effect = (first_time, second_time)
            source.start()
            clock.now.assert_not_called()
            self.assertEqual(next(source).captured_at, first_time)
            self.assertEqual(next(source).captured_at, second_time)
            source.stop()

    def test_consume_preserves_order_and_explicit_source_identity(self) -> None:
        identity = CaptureSource("local-test-stream")
        records = (b"third", b"first", b"second")
        source: PacketSource = IterablePacketSource(iter(records), source=identity)
        observations: list[PacketObservation] = []
        self.assertIsNone(consume(source, observations.append))
        self.assertEqual([value.raw_bytes for value in observations], list(records))
        for observation in observations:
            self.assertIs(observation.source, identity)
        self.assertEqual(list(source), [])
        with self.assertRaises(RuntimeError):
            source.start()

    def test_empty_source_completes_normally(self) -> None:
        source = IterablePacketSource(())
        observations: list[PacketObservation] = []
        self.assertIsNone(consume(source, observations.append))
        self.assertEqual(observations, [])

    def test_start_is_required_before_iteration(self) -> None:
        source = IterablePacketSource((b"packet",))
        with self.assertRaises(RuntimeError):
            iter(source)
        with self.assertRaises(RuntimeError):
            next(source)
        source.start()
        self.assertEqual(next(source).raw_bytes, b"packet")
        source.stop()

    def test_repeated_start_does_not_restart_active_session(self) -> None:
        source = IterablePacketSource((b"first", b"second"))
        source.start()
        self.assertEqual(next(source).raw_bytes, b"first")
        with self.assertRaises(RuntimeError):
            source.start()
        self.assertEqual([value.raw_bytes for value in source], [b"second"])
        source.stop()

    def test_exhaustion_is_permanent_and_cannot_restart(self) -> None:
        source = IterablePacketSource((b"packet",))
        source.start()
        self.assertEqual(next(source).raw_bytes, b"packet")
        for _ in range(2):
            with self.assertRaises(StopIteration):
                next(source)
        self.assertEqual(list(source), [])
        with self.assertRaises(RuntimeError):
            source.start()
        source.stop()

    def test_stop_before_start_is_repeatable_and_terminal(self) -> None:
        source = IterablePacketSource((b"packet",))
        source.stop()
        source.stop()
        self.assertEqual(list(source), [])
        with self.assertRaises(StopIteration):
            next(source)
        with self.assertRaises(RuntimeError):
            source.start()

    def test_early_stop_ends_delivery_without_advancing_caller_iterator(self) -> None:
        records = iter((b"first", b"second"))
        source = IterablePacketSource(records)
        source.start()
        observations = iter(source)
        self.assertEqual(next(observations).raw_bytes, b"first")
        source.stop()
        source.stop()
        with self.assertRaises(StopIteration):
            next(observations)
        self.assertEqual(next(records), b"second")

    def test_start_defers_iterator_creation_and_handles_acquisition_failure(self) -> None:
        error = OSError("local input unavailable")
        source = IterablePacketSource(FailingIterable(error))
        with self.assertRaises(CaptureError) as failure:
            source.start()
        self.assertIs(failure.exception.__cause__, error)
        with self.assertRaises(RuntimeError):
            source.start()
        with self.assertRaises(RuntimeError):
            next(source)
        source.stop()
        source.stop()

    def test_iteration_acquisition_failure_is_chained_and_terminal(self) -> None:
        error = OSError("local read failed")
        source = IterablePacketSource(interrupted_records(error))
        source.start()
        self.assertEqual(next(source).raw_bytes, b"first")
        with self.assertRaises(CaptureError) as failure:
            next(source)
        self.assertIs(failure.exception.__cause__, error)
        with self.assertRaises(RuntimeError):
            next(source)
        with self.assertRaises(RuntimeError):
            iter(source)
        source.stop()

    def test_capture_and_programming_errors_are_not_relabelled(self) -> None:
        for stage in ("startup", "iteration"):
            for error in (CaptureError("capture failed"), ValueError("invalid producer")):
                with self.subTest(stage=stage, error=type(error).__name__):
                    records = (
                        FailingIterable(error)
                        if stage == "startup"
                        else interrupted_records(error)
                    )
                    source = IterablePacketSource(records)
                    with self.assertRaises(type(error)) as failure:
                        consume(source, lambda observation: None)
                    self.assertIs(failure.exception, error)
                    self.assertEqual(list(source), [])

    def test_invalid_records_are_rejected_without_skipping(self) -> None:
        for value in ("text", bytearray(b"data"), memoryview(b"data"), None, 42):
            with self.subTest(value=value):
                records = iter((b"first", cast(bytes, value), b"last"))
                source = IterablePacketSource(records)
                observations: list[PacketObservation] = []
                with self.assertRaisesRegex(TypeError, "raw_bytes must be immutable bytes"):
                    consume(source, observations.append)
                self.assertEqual([item.raw_bytes for item in observations], [b"first"])
                self.assertEqual(list(source), [])
                self.assertEqual(next(records), b"last")

    def test_source_identity_requires_capture_source(self) -> None:
        with self.assertRaises(TypeError):
            IterablePacketSource((), source=cast(CaptureSource, "local-input"))

    def test_ingestion_propagates_acquisition_failure_and_stops_adapter(self) -> None:
        error = OSError("local read failed")
        source = IterablePacketSource(interrupted_records(error))
        observations: list[PacketObservation] = []
        with self.assertRaises(CaptureError) as failure:
            consume(source, observations.append)
        self.assertIs(failure.exception.__cause__, error)
        self.assertEqual([value.raw_bytes for value in observations], [b"first"])
        self.assertEqual(list(source), [])

    def test_consumer_failure_does_not_read_ahead(self) -> None:
        records = iter((b"first", b"second"))
        source = IterablePacketSource(records)
        error = ValueError("consumer failed")

        def receive(observation: PacketObservation) -> None:
            raise error

        with self.assertRaises(ValueError) as failure:
            consume(source, receive)
        self.assertIs(failure.exception, error)
        self.assertEqual(list(source), [])
        self.assertEqual(next(records), b"second")
