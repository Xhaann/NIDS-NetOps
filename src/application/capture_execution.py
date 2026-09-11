from typing import Callable, TypeVar

from analysis.packet_analysis_outcome import PacketAnalysisOutcome, analyze_packet_outcome
from capture.packet_ingestion import consume
from capture.packet_observation import PacketObservation
from capture.packet_source import PacketSource


_AnalysisResult = TypeVar("_AnalysisResult")


def run_capture_execution(
    source: PacketSource,
    consumer: Callable[[PacketAnalysisOutcome], None],
) -> None:
    _execute_capture(source, consumer, analyze_observation=analyze_packet_outcome)


def _execute_capture(
    source: PacketSource,
    consumer: Callable[[_AnalysisResult], None],
    *,
    analyze_observation: Callable[[PacketObservation], _AnalysisResult],
) -> None:
    def deliver(observation: PacketObservation) -> None:
        consumer(analyze_observation(observation))

    consume(source, deliver)
