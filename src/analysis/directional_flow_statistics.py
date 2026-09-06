from dataclasses import dataclass
from typing import Optional

from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity
from analysis.packet_analysis import PacketAnalysis


class DirectionalFlowStatisticsError(ValueError):
    pass


@dataclass(frozen=True)
class DirectionalFlowStatistics:
    identity: FlowIdentity
    forward_packet_count: int
    reverse_packet_count: int
    forward_captured_bytes: int
    reverse_captured_bytes: int
    forward_original_bytes: int
    reverse_original_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.identity, FlowIdentity):
            raise TypeError("identity must be a FlowIdentity")
        for name, value in (
            ("forward_packet_count", self.forward_packet_count),
            ("reverse_packet_count", self.reverse_packet_count),
            ("forward_captured_bytes", self.forward_captured_bytes),
            ("reverse_captured_bytes", self.reverse_captured_bytes),
            ("forward_original_bytes", self.forward_original_bytes),
            ("reverse_original_bytes", self.reverse_original_bytes),
        ):
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
            if value < 0:
                raise DirectionalFlowStatisticsError(f"{name} must not be negative")
        if self.forward_original_bytes < self.forward_captured_bytes:
            raise DirectionalFlowStatisticsError("forward_original_bytes must be at least forward_captured_bytes")
        if self.reverse_original_bytes < self.reverse_captured_bytes:
            raise DirectionalFlowStatisticsError("reverse_original_bytes must be at least reverse_captured_bytes")


def update_directional_flow_statistics(
    current: Optional[DirectionalFlowStatistics],
    analysis: PacketAnalysis,
    identity: FlowIdentity,
) -> DirectionalFlowStatistics:
    if current is not None and not isinstance(current, DirectionalFlowStatistics):
        raise TypeError("current must be a DirectionalFlowStatistics or None")
    if not isinstance(analysis, PacketAnalysis):
        raise TypeError("analysis must be a PacketAnalysis")
    if not isinstance(identity, FlowIdentity):
        raise TypeError("identity must be a FlowIdentity")
    direction = flow_direction_from_packet(analysis, identity)
    if current is not None and current.identity != identity:
        raise DirectionalFlowStatisticsError("current identity must match the supplied identity")
    observation = analysis.observation
    if observation.original_length is None:
        raise DirectionalFlowStatisticsError("directional statistics require a known original_length")
    forward_packet_count = 0 if current is None else current.forward_packet_count
    reverse_packet_count = 0 if current is None else current.reverse_packet_count
    forward_captured_bytes = 0 if current is None else current.forward_captured_bytes
    reverse_captured_bytes = 0 if current is None else current.reverse_captured_bytes
    forward_original_bytes = 0 if current is None else current.forward_original_bytes
    reverse_original_bytes = 0 if current is None else current.reverse_original_bytes
    if direction is FlowDirection.FORWARD:
        forward_packet_count += 1
        forward_captured_bytes += observation.captured_length
        forward_original_bytes += observation.original_length
    else:
        reverse_packet_count += 1
        reverse_captured_bytes += observation.captured_length
        reverse_original_bytes += observation.original_length
    return DirectionalFlowStatistics(
        identity=identity,
        forward_packet_count=forward_packet_count,
        reverse_packet_count=reverse_packet_count,
        forward_captured_bytes=forward_captured_bytes,
        reverse_captured_bytes=reverse_captured_bytes,
        forward_original_bytes=forward_original_bytes,
        reverse_original_bytes=reverse_original_bytes,
    )
