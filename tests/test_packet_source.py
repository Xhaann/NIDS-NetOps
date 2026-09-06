import unittest
from datetime import datetime, timezone
from typing import Iterable, Iterator

from capture import CaptureError, CaptureSource, PacketObservation, PacketSource


class MemoryPacketSource:
    def __init__(self, observations: Iterable[PacketObservation]) -> None:
        self._observations = iter(observations)
        self.started = False
        self.stopped = False

    def start(self) -> None:
        if self.started or self.stopped:
            raise RuntimeError("source cannot be restarted")
        self.started = True

    def __iter__(self) -> Iterator[PacketObservation]:
        if not self.started and not self.stopped:
            raise RuntimeError("source has not been started")
        return self

    def __next__(self) -> PacketObservation:
        if self.stopped:
            raise StopIteration
        if not self.started:
            raise RuntimeError("source has not been started")
        return next(self._observations)

    def stop(self) -> None:
        self.stopped = True


class StartupFailureSource(MemoryPacketSource):
    def start(self) -> None:
        super().start()
        raise CaptureError("acquisition could not start")


class ShutdownFailureSource(MemoryPacketSource):
    def stop(self) -> None:
        was_stopped = self.stopped
        super().stop()
        if not was_stopped:
            raise CaptureError("acquisition cleanup failed")


def collect_observations(source: PacketSource) -> list[PacketObservation]:
    try:
        source.start()
        return list(source)
    finally:
        source.stop()


def interrupted_observations(
    observation: PacketObservation,
) -> Iterator[PacketObservation]:
    yield observation
    try:
        raise OSError("synthetic acquisition failure")
    except OSError as error:
        raise CaptureError("acquisition interrupted") from error


class PacketSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.observations = tuple(
            PacketObservation(
                captured_at=datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc),
                link_type=None,
                captured_length=1,
                original_length=1,
                raw_bytes=bytes([value]),
                source=CaptureSource("test-input"),
            )
            for value in (3, 1, 2)
        )

    def test_consumer_accepts_structural_source_and_preserves_observations(self) -> None:
        implementation = MemoryPacketSource(self.observations)
        source: PacketSource = implementation
        observations = collect_observations(source)
        self.assertEqual(observations, list(self.observations))
        for actual, expected in zip(observations, self.observations):
            self.assertIs(actual, expected)
        self.assertTrue(implementation.started)
        self.assertTrue(implementation.stopped)

    def test_empty_source_completes_normally(self) -> None:
        source = MemoryPacketSource(())
        self.assertEqual(collect_observations(source), [])
        self.assertTrue(source.stopped)

    def test_completion_is_permanent_iterator_exhaustion(self) -> None:
        source = MemoryPacketSource(self.observations[:1])
        try:
            source.start()
            observations = iter(source)
            self.assertIs(next(observations), self.observations[0])
            for _ in range(2):
                with self.assertRaises(StopIteration):
                    next(observations)
        finally:
            source.stop()

    def test_iteration_does_not_restart_acquisition(self) -> None:
        source = MemoryPacketSource(self.observations)
        try:
            source.start()
            self.assertIs(next(iter(source)), self.observations[0])
            self.assertEqual(list(source), list(self.observations[1:]))
            self.assertEqual(list(source), [])
        finally:
            source.stop()

    def test_iteration_requires_start(self) -> None:
        source = MemoryPacketSource(())
        with self.assertRaises(RuntimeError):
            iter(source)
        source.stop()

    def test_repeated_start_is_lifecycle_misuse(self) -> None:
        source = MemoryPacketSource(())
        try:
            source.start()
            with self.assertRaises(RuntimeError):
                source.start()
        finally:
            source.stop()

    def test_early_stop_ends_existing_and_subsequent_iteration(self) -> None:
        source = MemoryPacketSource(self.observations)
        source.start()
        observations = iter(source)
        self.assertIs(next(observations), self.observations[0])
        source.stop()
        with self.assertRaises(StopIteration):
            next(observations)
        self.assertEqual(list(source), [])
        with self.assertRaises(RuntimeError):
            source.start()

    def test_stop_is_safe_before_start_and_repeatable(self) -> None:
        source = MemoryPacketSource(self.observations)
        source.stop()
        source.stop()
        self.assertFalse(source.started)
        self.assertEqual(list(source), [])
        with self.assertRaises(RuntimeError):
            source.start()

    def test_acquisition_failure_is_not_normal_completion(self) -> None:
        source = MemoryPacketSource(interrupted_observations(self.observations[0]))
        try:
            source.start()
            observations = iter(source)
            self.assertIs(next(observations), self.observations[0])
            with self.assertRaises(CaptureError) as failure:
                next(observations)
            self.assertIsInstance(failure.exception.__cause__, OSError)
        finally:
            source.stop()

    def test_consumer_propagates_acquisition_failure_and_stops(self) -> None:
        source = MemoryPacketSource(interrupted_observations(self.observations[0]))
        with self.assertRaisesRegex(CaptureError, "acquisition interrupted"):
            collect_observations(source)
        self.assertTrue(source.stopped)

    def test_consumer_stops_after_startup_failure(self) -> None:
        source = StartupFailureSource(())
        with self.assertRaisesRegex(CaptureError, "acquisition could not start"):
            collect_observations(source)
        self.assertTrue(source.stopped)
        source.stop()

    def test_consumer_does_not_hide_cleanup_failure(self) -> None:
        source = ShutdownFailureSource(())
        with self.assertRaisesRegex(CaptureError, "acquisition cleanup failed"):
            collect_observations(source)
        self.assertTrue(source.stopped)
        source.stop()
