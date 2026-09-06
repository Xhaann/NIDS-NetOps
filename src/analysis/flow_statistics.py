from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from analysis.flow_identity import FlowIdentity, flow_identity_from_packet
from analysis.packet_analysis import PacketAnalysis


class FlowStatisticsError(ValueError):
    pass


@dataclass(frozen=True)
class FlowStatistics:
    identity: FlowIdentity
    packet_count: int
    captured_bytes: int
    original_bytes: int
    first_captured_at: datetime
    last_captured_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.identity, FlowIdentity):
            raise TypeError("identity must be a FlowIdentity")
        for name, value in (
            ("packet_count", self.packet_count),
            ("captured_bytes", self.captured_bytes),
            ("original_bytes", self.original_bytes),
        ):
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
        if self.packet_count < 1:
            raise FlowStatisticsError("packet_count must be at least 1")
        if self.captured_bytes < 0:
            raise FlowStatisticsError("captured_bytes must not be negative")
        if self.original_bytes < self.captured_bytes:
            raise FlowStatisticsError("original_bytes must be at least captured_bytes")
        for name, value in (
            ("first_captured_at", self.first_captured_at),
            ("last_captured_at", self.last_captured_at),
        ):
            if not isinstance(value, datetime):
                raise TypeError(f"{name} must be a datetime")
            if value.tzinfo is None or value.utcoffset() is None:
                raise FlowStatisticsError(f"{name} must be timezone-aware")
        if self.last_captured_at < self.first_captured_at:
            raise FlowStatisticsError("last_captured_at must not precede first_captured_at")


def update_flow_statistics(
    current: Optional[FlowStatistics],
    analysis: PacketAnalysis,
    identity: FlowIdentity,
) -> FlowStatistics:
    if current is not None and not isinstance(current, FlowStatistics):
        raise TypeError("current must be a FlowStatistics or None")
    if not isinstance(analysis, PacketAnalysis):
        raise TypeError("analysis must be a PacketAnalysis")
    if not isinstance(identity, FlowIdentity):
        raise TypeError("identity must be a FlowIdentity")
    if flow_identity_from_packet(analysis) != identity:
        raise FlowStatisticsError("identity must match the analysis")
    if current is not None and current.identity != identity:
        raise FlowStatisticsError("current identity must match the supplied identity")
    observation = analysis.observation
    if observation.original_length is None:
        raise FlowStatisticsError("statistics require a known original_length")
    if current is not None and observation.captured_at < current.first_captured_at:
        raise FlowStatisticsError("capture timestamp must not precede first_captured_at")
    return FlowStatistics(
        identity=identity,
        packet_count=1 if current is None else current.packet_count + 1,
        captured_bytes=observation.captured_length if current is None
        else current.captured_bytes + observation.captured_length,
        original_bytes=observation.original_length if current is None
        else current.original_bytes + observation.original_length,
        first_captured_at=observation.captured_at if current is None else current.first_captured_at,
        last_captured_at=observation.captured_at,
    )
