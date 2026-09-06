import unittest
from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional

from capture import CaptureError, CaptureSource, PacketObservation, consume


class MemoryPacketSource:
    def __init__(
        self,
        observations: Iterable[PacketObservation],
        *,
        start_error: Optional[Exception] = None,
        stop_error: Optional[Exception] = None,
    ) -> None:
        self._observations = iter(observations)
        self._start_error = start_error
        self._stop_error = stop_error
        self._started = False
        self._stopped = False
        self.events: list[str] = []
        self.produced: list[PacketObservation] = []

    def start(self) -> None:
        self.events.append("start")
        if self._started or self._stopped:
            raise RuntimeError("source cannot be restarted")
        self._started = True
        if self._start_error is not None:
            raise self._start_error

    def __iter__(self) -> Iterator[PacketObservation]:
        if not self._started and not self._stopped:
            raise RuntimeError("source has not been started")
        return self

    def __next__(self) -> PacketObservation:
        if self._stopped:
            raise StopIteration
        if not self._started:
            raise RuntimeError("source has not been started")
        observation = next(self._observations)
        self.produced.append(observation)
        self.events.append("produce")
        return observation

    def stop(self) -> None:
        self.events.append("stop")
        was_stopped = self._stopped
        self._stopped = True
        if not was_stopped and self._stop_error is not None:
            raise self._stop_error


def interrupted_observations(
    observation: PacketObservation, error: Exception
) -> Iterator[PacketObservation]:
    yield observation
    raise error


class PacketIngestionTests(unittest.TestCase):
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

    def test_delivers_every_observation_unchanged_in_order(self) -> None:
        observations = self.observations + self.observations[:1]
        source = MemoryPacketSource(observations)
        delivered: list[PacketObservation] = []

        def receive(observation: PacketObservation) -> None:
            source.events.append("consume")
            delivered.append(observation)

        self.assertIsNone(consume(source, receive))
        self.assertEqual(len(delivered), len(observations))
        for actual, expected in zip(delivered, observations):
            self.assertIs(actual, expected)
        self.assertEqual(
            source.events,
            ["start"] + ["produce", "consume"] * len(observations) + ["stop"],
        )

    def test_empty_source_completes_and_stops(self) -> None:
        source = MemoryPacketSource(())
        delivered: list[PacketObservation] = []
        self.assertIsNone(consume(source, delivered.append))
        self.assertEqual(delivered, [])
        self.assertEqual(source.events, ["start", "stop"])

    def test_startup_failures_propagate_and_stop_source(self) -> None:
        for error in (CaptureError("startup failed"), RuntimeError("invalid lifecycle")):
            with self.subTest(error=type(error).__name__):
                source = MemoryPacketSource(self.observations, start_error=error)
                delivered: list[PacketObservation] = []
                with self.assertRaises(type(error)) as failure:
                    consume(source, delivered.append)
                self.assertIs(failure.exception, error)
                self.assertEqual(delivered, [])
                self.assertEqual(source.produced, [])
                self.assertEqual(source.events, ["start", "stop"])

    def test_iteration_failure_preserves_capture_error_and_stops_source(self) -> None:
        error = CaptureError("acquisition interrupted")
        source = MemoryPacketSource(interrupted_observations(self.observations[0], error))
        delivered: list[PacketObservation] = []
        with self.assertRaises(CaptureError) as failure:
            consume(source, delivered.append)
        self.assertIs(failure.exception, error)
        self.assertEqual(delivered, [self.observations[0]])
        self.assertEqual(source.events, ["start", "produce", "stop"])

    def test_consumer_failure_stops_delivery_and_preserves_exception(self) -> None:
        for error in (ValueError("consumer failed"), StopIteration("consumer failed")):
            with self.subTest(error=type(error).__name__):
                source = MemoryPacketSource(self.observations)
                delivered: list[PacketObservation] = []

                def receive(observation: PacketObservation) -> None:
                    delivered.append(observation)
                    raise error

                with self.assertRaises(type(error)) as failure:
                    consume(source, receive)
                self.assertIs(failure.exception, error)
                self.assertEqual(delivered, [self.observations[0]])
                self.assertEqual(source.produced, [self.observations[0]])
                self.assertEqual(source.events, ["start", "produce", "stop"])

    def test_cleanup_failure_after_delivery_propagates(self) -> None:
        error = CaptureError("cleanup failed")
        source = MemoryPacketSource(self.observations, stop_error=error)
        delivered: list[PacketObservation] = []
        with self.assertRaises(CaptureError) as failure:
            consume(source, delivered.append)
        self.assertIs(failure.exception, error)
        self.assertEqual(delivered, list(self.observations))
        self.assertEqual(source.events[-1], "stop")

    def test_cleanup_failure_retains_active_exception_context(self) -> None:
        for stage in ("startup", "iteration", "consumer"):
            with self.subTest(stage=stage):
                original_error = (
                    ValueError("consumer failed")
                    if stage == "consumer"
                    else CaptureError(f"{stage} failed")
                )
                cleanup_error = CaptureError("cleanup failed")
                observations = (
                    interrupted_observations(self.observations[0], original_error)
                    if stage == "iteration"
                    else self.observations
                )
                source = MemoryPacketSource(
                    observations,
                    start_error=original_error if stage == "startup" else None,
                    stop_error=cleanup_error,
                )

                def receive(observation: PacketObservation) -> None:
                    if stage == "consumer":
                        raise original_error

                with self.assertRaises(CaptureError) as failure:
                    consume(source, receive)
                self.assertIs(failure.exception, cleanup_error)
                self.assertIs(failure.exception.__context__, original_error)
                self.assertFalse(failure.exception.__suppress_context__)
                self.assertEqual(source.events[-1], "stop")
