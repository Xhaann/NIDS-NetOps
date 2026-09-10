from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from analysis.flow_feature_snapshot import extract_flow_feature_snapshot
from analysis.flow_observation_window import FlowObservationWindow
from analysis.packet_analysis import PacketAnalysis
from analysis.packet_analysis_outcome import analyze_packet_outcome
from application.detection_session import DetectionSession
from application.flow_observation_session import _run_flow_observation_session
from capture.packet_observation import PacketObservation
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
) -> DetectionPipelineResult:
    if type(detection_session) is not DetectionSession:
        raise TypeError("detection_session must be exactly a DetectionSession")
    packet_findings = []
    flow_findings = []
    packet_detection_failed = False

    def analyze_observation(observation: PacketObservation) -> Optional[PacketAnalysis]:
        nonlocal packet_detection_failed
        outcome = analyze_packet_outcome(observation)
        try:
            packet_findings.extend(detection_session.run_packets((outcome,)))
        except BaseException:
            packet_detection_failed = True
            raise
        return outcome.analysis

    def detect_closed_window(window: FlowObservationWindow) -> None:
        if packet_detection_failed:
            return
        snapshot = extract_flow_feature_snapshot(window)
        flow_findings.extend(detection_session.run_closed_flows((snapshot,)))

    _run_flow_observation_session(
        source,
        capture_session_id=capture_session_id,
        inactivity_timeout=inactivity_timeout,
        closed_window_consumer=detect_closed_window,
        analyze_observation=analyze_observation,
    )
    return DetectionPipelineResult(tuple(packet_findings), tuple(flow_findings))
