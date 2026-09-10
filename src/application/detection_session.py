from dataclasses import dataclass
from typing import Iterable, Optional

from analysis.flow_feature_snapshot import FlowFeatureSnapshot
from analysis.packet_analysis_outcome import PacketAnalysisOutcome
from application.detector_orchestration import run_closed_flow_detectors, run_packet_detectors
from detection.detection_finding import DetectionFinding
from detection.flow_volume_threshold import FlowVolumeThresholdConfiguration
from detection.packet_integrity import PacketIntegrityConfiguration
from detection.tcp_control_threshold import TCPControlThresholdConfiguration


@dataclass(frozen=True)
class DetectionSession:
    packet_configuration: PacketIntegrityConfiguration
    flow_volume_configuration: FlowVolumeThresholdConfiguration
    tcp_control_configuration: Optional[TCPControlThresholdConfiguration] = None

    def __post_init__(self) -> None:
        if type(self.packet_configuration) is not PacketIntegrityConfiguration:
            raise TypeError("packet_configuration must be exactly a PacketIntegrityConfiguration")
        if type(self.flow_volume_configuration) is not FlowVolumeThresholdConfiguration:
            raise TypeError("flow_volume_configuration must be exactly a FlowVolumeThresholdConfiguration")
        if self.tcp_control_configuration is not None and type(
            self.tcp_control_configuration
        ) is not TCPControlThresholdConfiguration:
            raise TypeError("tcp_control_configuration must be exactly a TCPControlThresholdConfiguration or None")

    def run_packets(
        self, outcomes: Iterable[PacketAnalysisOutcome],
    ) -> tuple[DetectionFinding, ...]:
        findings = []
        for outcome in outcomes:
            findings.extend(run_packet_detectors(outcome, self.packet_configuration))
        return tuple(findings)

    def run_closed_flows(
        self, snapshots: Iterable[FlowFeatureSnapshot],
    ) -> tuple[DetectionFinding, ...]:
        findings = []
        for snapshot in snapshots:
            findings.extend(run_closed_flow_detectors(
                snapshot,
                flow_volume_configuration=self.flow_volume_configuration,
                tcp_control_configuration=self.tcp_control_configuration,
            ))
        return tuple(findings)
