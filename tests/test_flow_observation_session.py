import inspect
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from struct import pack
from typing import Iterable, Iterator, Optional
from unittest.mock import patch

from analysis import (
    EthernetDecodeError,
    FlowIdentityError,
    FlowObservationWindowClosureReason,
    FlowObservationWindowError,
    FlowObservationWindowManager,
    FlowStatisticsError,
    PacketAnalysisError,
    analyze_packet,
)
from application import run_flow_observation_session
from capture import CaptureError, CaptureSource, LinkType, PacketObservation


TIMESTAMP = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
SOURCE = CaptureSource("test-flow-observation-session")
ETHERNET_HEADER = bytes.fromhex("00112233445566778899aabb0800")


def observation_at(
    seconds: float,
    *,
    protocol: int = 6,
    source_port: int = 12345,
    destination_port: int = 443,
    reverse: bool = False,
    original_length: Optional[int] = 100,
    ns: bool = False,
    cwr: bool = False,
    ece: bool = False,
    urg: bool = False,
    ack: bool = False,
    psh: bool = False,
    rst: bool = False,
    syn: bool = False,
    fin: bool = False,
) -> PacketObservation:
    source_address = b"\x0a\x00\x00\x01"
    destination_address = b"\x0a\x00\x00\x02"
    if reverse:
        source_address, destination_address = destination_address, source_address
        source_port, destination_port = destination_port, source_port
    if protocol == 6:
        control = 5 << 12
        for enabled, mask in (
            (ns, 0x100),
            (cwr, 0x080),
            (ece, 0x040),
            (urg, 0x020),
            (ack, 0x010),
            (psh, 0x008),
            (rst, 0x004),
            (syn, 0x002),
            (fin, 0x001),
        ):
            if enabled:
                control |= mask
        transport = pack(
            "!HHIIHHHH",
            source_port,
            destination_port,
            0,
            0,
            control,
            0,
            0,
            0,
        )
    elif protocol == 17:
        transport = pack("!HHHH", source_port, destination_port, 8, 0)
    else:
        transport = bytes.fromhex("0800000000000000")
    ipv4 = pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(transport),
        0,
        0,
        64,
        protocol,
        0,
        source_address,
        destination_address,
    )
    raw_bytes = ETHERNET_HEADER + ipv4 + transport
    return PacketObservation(
        captured_at=TIMESTAMP + timedelta(seconds=seconds),
        link_type=LinkType(1),
        captured_length=len(raw_bytes),
        original_length=original_length,
        raw_bytes=raw_bytes,
        source=SOURCE,
    )


class MemoryPacketSource:
    def __init__(
        self,
        observations: Iterable[PacketObservation],
        *,
        start_error: Optional[BaseException] = None,
        iteration_error: Optional[BaseException] = None,
        stop_error: Optional[BaseException] = None,
    ) -> None:
        self._observations = tuple(observations)
        self._start_error = start_error
        self._iteration_error = iteration_error
        self._stop_error = stop_error
        self._index = 0
        self._started = False
        self._stopped = False
        self._iteration_failed = False
        self.events: list[str] = []

    def start(self) -> None:
        self.events.append("start")
        self._started = True
        if self._start_error is not None:
            raise self._start_error

    def __iter__(self) -> Iterator[PacketObservation]:
        return self

    def __next__(self) -> PacketObservation:
        if self._index < len(self._observations):
            observation = self._observations[self._index]
            self.events.append(f"produce:{self._index}")
            self._index += 1
            return observation
        if self._iteration_error is not None and not self._iteration_failed:
            self._iteration_failed = True
            raise self._iteration_error
        raise StopIteration

    def stop(self) -> None:
        self.events.append("stop")
        self._stopped = True
        if self._stop_error is not None:
            raise self._stop_error

    @property
    def stopped(self) -> bool:
        return self._stopped


class FlowObservationSessionTests(unittest.TestCase):
    def test_public_signature_and_manager_validation_are_preserved(self) -> None:
        signature = inspect.signature(run_flow_observation_session)
        self.assertEqual(
            tuple(signature.parameters),
            (
                "source",
                "capture_session_id",
                "inactivity_timeout",
                "closed_window_consumer",
                "max_active_windows",
            ),
        )
        self.assertEqual(signature.return_annotation, None)
        for session_id, timeout, error in (
            ("", timedelta(seconds=1), FlowObservationWindowError),
            ("capture", timedelta(0), FlowObservationWindowError),
            (1, timedelta(seconds=1), TypeError),
            ("capture", 1, TypeError),
        ):
            with self.subTest(session_id=session_id, timeout=timeout):
                source = MemoryPacketSource(())
                with self.assertRaises(error):
                    run_flow_observation_session(
                        source,
                        capture_session_id=session_id,
                        inactivity_timeout=timeout,
                        closed_window_consumer=lambda window: None,
                    )
                self.assertEqual(source.events, [])

    def test_empty_and_one_packet_sessions_stop_before_final_delivery(self) -> None:
        empty = MemoryPacketSource(())
        empty_windows = []
        self.assertIsNone(
            run_flow_observation_session(
                empty,
                capture_session_id="empty",
                inactivity_timeout=timedelta(seconds=10),
                closed_window_consumer=empty_windows.append,
            )
        )
        self.assertEqual(empty.events, ["start", "stop"])
        self.assertEqual(empty_windows, [])

        source = MemoryPacketSource((observation_at(0),))
        windows = []

        def receive(window) -> None:
            self.assertTrue(source.stopped)
            source.events.append("deliver")
            windows.append(window)

        self.assertIsNone(
            run_flow_observation_session(
                source,
                capture_session_id="caller-session",
                inactivity_timeout=timedelta(seconds=10),
                closed_window_consumer=receive,
            )
        )
        self.assertEqual(source.events, ["start", "produce:0", "stop", "deliver"])
        self.assertEqual(len(windows), 1)
        window = windows[0]
        self.assertEqual(window.key.capture_session_id, "caller-session")
        self.assertEqual(window.key.sequence_number, 0)
        self.assertIs(
            window.closure_reason,
            FlowObservationWindowClosureReason.CAPTURE_SESSION_END,
        )
        self.assertEqual(window.coordinated_state.flow_statistics.packet_count, 1)

    def test_source_stop_precedes_manager_closure(self) -> None:
        source = MemoryPacketSource((observation_at(0),))
        manager = FlowObservationWindowManager("ordering", timedelta(seconds=10))
        original_end = manager.end_capture_session

        def end_capture_session():
            self.assertTrue(source.stopped)
            source.events.append("end")
            return original_end()

        with patch(
            "application.flow_observation_session.FlowObservationWindowManager",
            return_value=manager,
        ), patch.object(
            manager,
            "end_capture_session",
            side_effect=end_capture_session,
        ):
            run_flow_observation_session(
                source,
                capture_session_id="ordering",
                inactivity_timeout=timedelta(seconds=10),
                closed_window_consumer=lambda window: source.events.append("deliver"),
            )
        self.assertEqual(
            source.events,
            ["start", "produce:0", "stop", "end", "deliver"],
        )

    def test_exact_analysis_result_is_passed_unchanged_to_manager(self) -> None:
        observation = observation_at(0)
        source = MemoryPacketSource((observation,))
        manager = FlowObservationWindowManager("identity", timedelta(seconds=10))
        original_record = manager.record
        analysis = analyze_packet(observation)
        recorded = []

        def record(value):
            recorded.append(value)
            return original_record(value)

        with patch(
            "application.flow_observation_session.FlowObservationWindowManager",
            return_value=manager,
        ), patch(
            "application.flow_observation_session.analyze_packet",
            return_value=analysis,
        ), patch.object(manager, "record", side_effect=record):
            run_flow_observation_session(
                source,
                capture_session_id="identity",
                inactivity_timeout=timedelta(seconds=10),
                closed_window_consumer=lambda window: None,
            )
        self.assertEqual(recorded, [analysis])
        self.assertIs(recorded[0], analysis)

    def test_multiple_identities_preserve_admission_and_final_sequence_order(self) -> None:
        observations = (
            observation_at(0, source_port=1000),
            observation_at(1, source_port=2000),
            observation_at(2, source_port=1000),
            observation_at(3, source_port=3000),
        )
        source = MemoryPacketSource(observations)
        windows = []
        analyzed = []

        def analyze(observation):
            analyzed.append(observation)
            return analyze_packet(observation)

        with patch(
            "application.flow_observation_session.analyze_packet",
            side_effect=analyze,
        ):
            run_flow_observation_session(
                source,
                capture_session_id="ordered",
                inactivity_timeout=timedelta(seconds=10),
                closed_window_consumer=windows.append,
            )
        self.assertEqual(analyzed, list(observations))
        self.assertEqual([window.key.sequence_number for window in windows], [0, 1, 2])
        self.assertEqual(
            [window.coordinated_state.flow_statistics.packet_count for window in windows],
            [2, 1, 1],
        )
        self.assertEqual(
            sum(
                window.coordinated_state.flow_statistics.packet_count
                for window in windows
            ),
            len(observations),
        )

    def test_inactivity_delivery_is_synchronous_unique_and_excludes_boundary_gap(self) -> None:
        observations = tuple(observation_at(value) for value in (0, 1, 11, 12))
        source = MemoryPacketSource(observations)
        windows = []

        def receive(window) -> None:
            if not windows:
                self.assertEqual(source.events[-1], "produce:2")
                self.assertNotIn("produce:3", source.events)
            windows.append(window)

        run_flow_observation_session(
            source,
            capture_session_id="inactivity",
            inactivity_timeout=timedelta(seconds=10),
            closed_window_consumer=receive,
        )
        self.assertEqual([window.key.sequence_number for window in windows], [0, 1])
        self.assertEqual(
            [window.closure_reason for window in windows],
            [
                FlowObservationWindowClosureReason.INACTIVITY,
                FlowObservationWindowClosureReason.CAPTURE_SESSION_END,
            ],
        )
        first, second = windows
        self.assertEqual(first.coordinated_state.flow_statistics.packet_count, 2)
        self.assertEqual(second.coordinated_state.flow_statistics.packet_count, 2)
        self.assertEqual(
            first.coordinated_state.flow_inter_arrival_statistics.inter_arrival_sum_seconds,
            1.0,
        )
        self.assertEqual(
            second.coordinated_state.flow_inter_arrival_statistics.inter_arrival_sum_seconds,
            1.0,
        )
        self.assertEqual(len({window.key for window in windows}), 2)

    def test_tcp_flags_do_not_control_lifecycle(self) -> None:
        source = MemoryPacketSource(
            (
                observation_at(0, syn=True),
                observation_at(1, fin=True),
                observation_at(2, rst=True),
            )
        )
        windows = []
        run_flow_observation_session(
            source,
            capture_session_id="tcp",
            inactivity_timeout=timedelta(seconds=10),
            closed_window_consumer=windows.append,
        )
        self.assertEqual(len(windows), 1)
        state = windows[0].coordinated_state
        self.assertEqual(state.flow_statistics.packet_count, 3)
        self.assertEqual(state.tcp_control_statistics.forward_syn_count, 1)
        self.assertEqual(state.tcp_control_statistics.forward_fin_count, 1)
        self.assertEqual(state.tcp_control_statistics.forward_rst_count, 1)

    def test_udp_uses_same_lifecycle_and_has_no_tcp_state(self) -> None:
        source = MemoryPacketSource(
            (
                observation_at(0, protocol=17),
                observation_at(1, protocol=17, reverse=True),
            )
        )
        windows = []
        run_flow_observation_session(
            source,
            capture_session_id="udp",
            inactivity_timeout=timedelta(seconds=10),
            closed_window_consumer=windows.append,
        )
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0].coordinated_state.flow_statistics.packet_count, 2)
        self.assertIsNone(windows[0].coordinated_state.tcp_control_statistics)

    def test_start_failure_stops_source_ends_manager_and_emits_nothing(self) -> None:
        error = CaptureError("start failed")
        source = MemoryPacketSource((), start_error=error)
        manager = FlowObservationWindowManager("start", timedelta(seconds=10))
        with patch(
            "application.flow_observation_session.FlowObservationWindowManager",
            return_value=manager,
        ):
            with self.assertRaises(CaptureError) as failure:
                run_flow_observation_session(
                    source,
                    capture_session_id="start",
                    inactivity_timeout=timedelta(seconds=10),
                    closed_window_consumer=lambda window: self.fail(),
                )
        self.assertIs(failure.exception, error)
        self.assertEqual(source.events, ["start", "stop"])
        self.assertEqual(manager.end_capture_session(), ())
        with self.assertRaises(FlowObservationWindowError):
            manager.record(analyze_packet(observation_at(0)))

    def test_iteration_failure_stops_then_delivers_final_window_and_propagates(self) -> None:
        error = CaptureError("iteration failed")
        source = MemoryPacketSource((observation_at(0),), iteration_error=error)
        windows = []

        def receive(window) -> None:
            self.assertTrue(source.stopped)
            windows.append(window)

        with self.assertRaises(CaptureError) as failure:
            run_flow_observation_session(
                source,
                capture_session_id="iteration",
                inactivity_timeout=timedelta(seconds=10),
                closed_window_consumer=receive,
            )
        self.assertIs(failure.exception, error)
        self.assertEqual(len(windows), 1)
        self.assertIs(
            windows[0].closure_reason,
            FlowObservationWindowClosureReason.CAPTURE_SESSION_END,
        )

    def test_stop_failure_preserves_consume_precedence_and_still_finalizes(self) -> None:
        cases = (
            (CaptureError("start failed"), None, "start"),
            (None, CaptureError("iteration failed"), "iteration"),
        )
        for start_error, iteration_error, name in cases:
            with self.subTest(name=name):
                stop_error = CaptureError("stop failed")
                observations = () if start_error is not None else (observation_at(0),)
                source = MemoryPacketSource(
                    observations,
                    start_error=start_error,
                    iteration_error=iteration_error,
                    stop_error=stop_error,
                )
                windows = []
                with self.assertRaises(CaptureError) as failure:
                    run_flow_observation_session(
                        source,
                        capture_session_id=name,
                        inactivity_timeout=timedelta(seconds=10),
                        closed_window_consumer=windows.append,
                    )
                self.assertIs(failure.exception, stop_error)
                expected_context = start_error or iteration_error
                self.assertIs(failure.exception.__context__, expected_context)
                self.assertEqual(len(windows), 0 if start_error is not None else 1)

        stop_error = CaptureError("stop failed after completion")
        source = MemoryPacketSource((observation_at(0),), stop_error=stop_error)
        windows = []
        with self.assertRaises(CaptureError) as failure:
            run_flow_observation_session(
                source,
                capture_session_id="stop",
                inactivity_timeout=timedelta(seconds=10),
                closed_window_consumer=windows.append,
            )
        self.assertIs(failure.exception, stop_error)
        self.assertEqual(len(windows), 1)

    def test_analysis_failures_reject_packet_then_finalize_prior_state(self) -> None:
        valid = observation_at(0)
        malformed = replace(
            valid,
            captured_at=TIMESTAMP + timedelta(seconds=1),
            captured_length=0,
            original_length=0,
            raw_bytes=b"",
        )
        unsupported = replace(
            valid,
            captured_at=TIMESTAMP + timedelta(seconds=1),
            link_type=None,
        )
        for observation, error in (
            (malformed, EthernetDecodeError),
            (unsupported, PacketAnalysisError),
        ):
            with self.subTest(error=error.__name__):
                source = MemoryPacketSource((valid, observation))
                windows = []
                with self.assertRaises(error):
                    run_flow_observation_session(
                        source,
                        capture_session_id=error.__name__,
                        inactivity_timeout=timedelta(seconds=10),
                        closed_window_consumer=windows.append,
                    )
                self.assertEqual(len(windows), 1)
                self.assertEqual(
                    windows[0].coordinated_state.flow_statistics.packet_count,
                    1,
                )

    def test_icmp_identity_failure_propagates_and_finalizes_prior_state(self) -> None:
        source = MemoryPacketSource((observation_at(0), observation_at(1, protocol=1)))
        windows = []
        with self.assertRaises(FlowIdentityError):
            run_flow_observation_session(
                source,
                capture_session_id="icmp",
                inactivity_timeout=timedelta(seconds=10),
                closed_window_consumer=windows.append,
            )
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0].coordinated_state.flow_statistics.packet_count, 1)

    def test_timestamp_regression_rejects_packet_and_finalizes_prior_state(self) -> None:
        source = MemoryPacketSource(
            (
                observation_at(10, source_port=1000),
                observation_at(9, source_port=2000),
            )
        )
        windows = []
        with self.assertRaises(FlowObservationWindowError):
            run_flow_observation_session(
                source,
                capture_session_id="regression",
                inactivity_timeout=timedelta(seconds=10),
                closed_window_consumer=windows.append,
            )
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0].key.sequence_number, 0)
        self.assertEqual(windows[0].coordinated_state.flow_statistics.packet_count, 1)

    def test_coordinator_failure_rejects_packet_and_finalizes_prior_state(self) -> None:
        source = MemoryPacketSource(
            (observation_at(0), observation_at(1, original_length=None))
        )
        windows = []
        with self.assertRaises(FlowStatisticsError):
            run_flow_observation_session(
                source,
                capture_session_id="coordinator",
                inactivity_timeout=timedelta(seconds=10),
                closed_window_consumer=windows.append,
            )
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0].coordinated_state.flow_statistics.packet_count, 1)

    def test_downstream_failure_is_not_retried_and_remaining_state_is_finalized(self) -> None:
        error = ValueError("downstream failed")
        source = MemoryPacketSource(
            (observation_at(0), observation_at(20), observation_at(21))
        )
        manager = FlowObservationWindowManager("downstream", timedelta(seconds=10))
        attempted = []

        def receive(window) -> None:
            attempted.append(window)
            raise error

        with patch(
            "application.flow_observation_session.FlowObservationWindowManager",
            return_value=manager,
        ):
            with self.assertRaises(ValueError) as failure:
                run_flow_observation_session(
                    source,
                    capture_session_id="downstream",
                    inactivity_timeout=timedelta(seconds=10),
                    closed_window_consumer=receive,
                )
        self.assertIs(failure.exception, error)
        self.assertEqual(len(attempted), 1)
        self.assertEqual(source.events, ["start", "produce:0", "produce:1", "stop"])
        self.assertEqual(manager.active_windows(), ())
        self.assertEqual(manager.end_capture_session(), ())

    def test_downstream_and_stop_failure_preserve_cleanup_precedence(self) -> None:
        downstream_error = ValueError("downstream failed")
        stop_error = CaptureError("stop failed")
        source = MemoryPacketSource(
            (observation_at(0), observation_at(20)),
            stop_error=stop_error,
        )
        attempted = []

        def receive(window) -> None:
            attempted.append(window)
            raise downstream_error

        with self.assertRaises(CaptureError) as failure:
            run_flow_observation_session(
                source,
                capture_session_id="consumer-stop",
                inactivity_timeout=timedelta(seconds=10),
                closed_window_consumer=receive,
            )
        self.assertIs(failure.exception, stop_error)
        self.assertIs(failure.exception.__context__, downstream_error)
        self.assertEqual(len(attempted), 1)

    def test_session_end_delivery_failure_is_not_retried_and_supersedes_source_error(self) -> None:
        iteration_error = CaptureError("iteration failed")
        delivery_error = ValueError("final delivery failed")
        source = MemoryPacketSource((observation_at(0),), iteration_error=iteration_error)
        attempted = []

        def receive(window) -> None:
            attempted.append(window)
            raise delivery_error

        with self.assertRaises(ValueError) as failure:
            run_flow_observation_session(
                source,
                capture_session_id="final-delivery",
                inactivity_timeout=timedelta(seconds=10),
                closed_window_consumer=receive,
            )
        self.assertIs(failure.exception, delivery_error)
        self.assertIs(failure.exception.__context__, iteration_error)
        self.assertEqual(len(attempted), 1)
        self.assertTrue(source.stopped)


if __name__ == "__main__":
    unittest.main()
