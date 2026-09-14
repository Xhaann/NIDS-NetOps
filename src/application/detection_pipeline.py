from dataclasses import dataclass
from datetime import timedelta
from typing import Callable, Optional

from analysis.flow_feature_snapshot import extract_flow_feature_snapshot
from analysis.flow_observation_window import DEFAULT_MAX_ACTIVE_WINDOWS, FlowObservationWindow
from analysis.packet_analysis import PacketAnalysis
from analysis.packet_analysis_outcome import PacketAnalysisOutcome
from application.capture_execution import run_capture_execution
from application.detection_session import DetectionSession
from application.flow_observation_session import _run_flow_observation_session
from capture.packet_source import PacketSource
from detection.detection_finding import DetectionFinding


@dataclass(frozen=True)
class DetectionPipelineResult:
    packet_findings: tuple[DetectionFinding, ...]
    flow_findings: tuple[DetectionFinding, ...]

    def __post_init__(self) -> None:
        for name, findings in (("packet_findings", self.packet_findings), ("flow_findings", self.flow_findings)):
            if type(findings) is not tuple:
                raise TypeError(f"{name} must be exactly a tuple")
            if any(type(finding) is not DetectionFinding for finding in findings):
                raise TypeError(f"{name} must contain exactly DetectionFinding values")


def run_detection_pipeline(
    source: PacketSource,
    *,
    detection_session: DetectionSession,
    capture_session_id: str,
    inactivity_timeout: timedelta,
    max_active_windows: int = DEFAULT_MAX_ACTIVE_WINDOWS,
) -> DetectionPipelineResult:
    packet_findings = []
    flow_findings = []
    run_detection_stream(
        source,
        detection_session=detection_session,
        capture_session_id=capture_session_id,
        inactivity_timeout=inactivity_timeout,
        max_active_windows=max_active_windows,
        packet_finding_consumer=packet_findings.append,
        flow_finding_consumer=flow_findings.append,
    )
    return DetectionPipelineResult(tuple(packet_findings), tuple(flow_findings))


def run_detection_stream(
    source: PacketSource,
    *,
    detection_session: DetectionSession,
    capture_session_id: str,
    inactivity_timeout: timedelta,
    packet_finding_consumer: Callable[[DetectionFinding], None],
    flow_finding_consumer: Callable[[DetectionFinding], None],
    max_active_windows: int = DEFAULT_MAX_ACTIVE_WINDOWS,
) -> None:
    if type(detection_session) is not DetectionSession:
        raise TypeError("detection_session must be exactly a DetectionSession")
    for name, consumer in (("packet_finding_consumer", packet_finding_consumer),
                           ("flow_finding_consumer", flow_finding_consumer)):
        if not callable(consumer):
            raise TypeError(f"{name} must be callable")
    packet_delivery_failed = False

    def execute_analysis(
        packet_source: PacketSource,
        admit: Callable[[Optional[PacketAnalysis]], None],
    ) -> None:
        def receive_outcome(outcome: PacketAnalysisOutcome) -> None:
            nonlocal packet_delivery_failed
            try:
                for finding in detection_session.run_packets((outcome,)):
                    packet_finding_consumer(finding)
            except BaseException:
                packet_delivery_failed = True
                raise
            admit(outcome.analysis)

        run_capture_execution(packet_source, receive_outcome)

    def detect_closed_window(window: FlowObservationWindow) -> None:
        if packet_delivery_failed:
            return
        snapshot = extract_flow_feature_snapshot(window)
        for finding in detection_session.run_closed_flows((snapshot,)):
            flow_finding_consumer(finding)

    _run_flow_observation_session(
        source,
        capture_session_id=capture_session_id,
        inactivity_timeout=inactivity_timeout,
        closed_window_consumer=detect_closed_window,
        execute_analysis=execute_analysis,
        max_active_windows=max_active_windows,
    )
