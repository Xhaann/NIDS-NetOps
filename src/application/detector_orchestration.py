from typing import Optional

from analysis.flow_feature_snapshot import FlowFeatureSnapshot
from analysis.packet_analysis_outcome import PacketAnalysisOutcome
from detection.detection_finding import (
    DetectionFinding,
    detection_finding_from_evaluation,
)
from detection.flow_volume_threshold import (
    FlowVolumeThresholdConfiguration,
    evaluate_flow_volume_threshold,
)
from detection.packet_integrity import (
    PacketIntegrityConfiguration,
    evaluate_packet_integrity,
)
from detection.tcp_control_threshold import (
    TCPControlThresholdConfiguration,
    evaluate_tcp_control_threshold,
)


def run_packet_detectors(
    outcome: PacketAnalysisOutcome,
    configuration: PacketIntegrityConfiguration,
) -> tuple[DetectionFinding, ...]:
    evaluation = evaluate_packet_integrity(outcome, configuration)
    return (detection_finding_from_evaluation(evaluation),)


def run_closed_flow_detectors(
    snapshot: FlowFeatureSnapshot,
    *,
    flow_volume_configuration: FlowVolumeThresholdConfiguration,
    tcp_control_configuration: Optional[TCPControlThresholdConfiguration] = None,
) -> tuple[DetectionFinding, ...]:
    if tcp_control_configuration is not None and type(
        tcp_control_configuration
    ) is not TCPControlThresholdConfiguration:
        raise TypeError(
            "tcp_control_configuration must be exactly a "
            "TCPControlThresholdConfiguration or None"
        )
    volume_evaluation = evaluate_flow_volume_threshold(
        snapshot, flow_volume_configuration
    )
    volume_finding = detection_finding_from_evaluation(volume_evaluation)
    if snapshot.identity.protocol == 6:
        if tcp_control_configuration is None:
            raise TypeError("TCP windows require tcp_control_configuration")
        control_evaluation = evaluate_tcp_control_threshold(
            snapshot.observation_window, tcp_control_configuration
        )
        return (
            volume_finding,
            detection_finding_from_evaluation(control_evaluation),
        )
    return (volume_finding,)
