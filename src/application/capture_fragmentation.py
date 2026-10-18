from analysis.ipv4_fragmentation_statistics import IPv4FragmentationStatistics, update_ipv4_fragmentation_statistics
from analysis.packet_analysis_outcome import PacketAnalysisOutcome
from application.capture_execution import run_capture_execution
from capture.packet_source import PacketSource


def run_capture_fragmentation_statistics(source: PacketSource) -> IPv4FragmentationStatistics:
    statistics = IPv4FragmentationStatistics()

    def receive_outcome(outcome: PacketAnalysisOutcome) -> None:
        nonlocal statistics
        statistics = update_ipv4_fragmentation_statistics(statistics, outcome)

    run_capture_execution(source, receive_outcome)
    return statistics
