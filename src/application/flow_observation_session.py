from datetime import timedelta
from typing import Callable

from analysis.flow_observation_window import (
    FlowObservationWindow,
    FlowObservationWindowManager,
)
from analysis.packet_analysis import analyze_packet
from capture.packet_ingestion import consume
from capture.packet_observation import PacketObservation
from capture.packet_source import PacketSource


def run_flow_observation_session(
    source: PacketSource,
    *,
    capture_session_id: str,
    inactivity_timeout: timedelta,
    closed_window_consumer: Callable[[FlowObservationWindow], None],
) -> None:
    manager = FlowObservationWindowManager(
        capture_session_id,
        inactivity_timeout,
    )
    downstream_delivery_failed = False

    def record_observation(observation: PacketObservation) -> None:
        nonlocal downstream_delivery_failed
        analysis = analyze_packet(observation)
        update = manager.record(analysis)
        for window in update.closed_windows:
            try:
                closed_window_consumer(window)
            except BaseException:
                downstream_delivery_failed = True
                raise

    try:
        consume(source, record_observation)
    finally:
        closed_windows = manager.end_capture_session()
        if not downstream_delivery_failed:
            for window in closed_windows:
                closed_window_consumer(window)
