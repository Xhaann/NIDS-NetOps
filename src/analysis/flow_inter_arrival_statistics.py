from dataclasses import dataclass
from datetime import datetime
from math import isfinite
from typing import Optional

from analysis.flow_identity import FlowIdentity, flow_identity_from_packet
from analysis.packet_analysis import PacketAnalysis


class FlowInterArrivalStatisticsError(ValueError):
    pass


@dataclass(frozen=True)
class FlowInterArrivalStatistics:
    identity: FlowIdentity
    packet_count: int
    first_captured_at: datetime
    last_captured_at: datetime
    inter_arrival_count: int
    inter_arrival_sum_seconds: float
    inter_arrival_sum_seconds_squared: float
    min_inter_arrival_seconds: float
    max_inter_arrival_seconds: float

    def __post_init__(self) -> None:
        if type(self.identity) is not FlowIdentity:
            raise TypeError("identity must be exactly a FlowIdentity")
        for name, value in (
            ("packet_count", self.packet_count),
            ("inter_arrival_count", self.inter_arrival_count),
        ):
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
        if self.packet_count < 1:
            raise FlowInterArrivalStatisticsError("packet_count must be at least 1")
        if self.inter_arrival_count < 0 or self.inter_arrival_count != self.packet_count - 1:
            raise FlowInterArrivalStatisticsError("inter_arrival_count must equal packet_count - 1")
        for name, value in (
            ("first_captured_at", self.first_captured_at),
            ("last_captured_at", self.last_captured_at),
        ):
            if not isinstance(value, datetime):
                raise TypeError(f"{name} must be a datetime")
            if value.tzinfo is None or value.utcoffset() is None:
                raise FlowInterArrivalStatisticsError(f"{name} must be timezone-aware")
        if self.last_captured_at < self.first_captured_at:
            raise FlowInterArrivalStatisticsError("last_captured_at must not precede first_captured_at")
        for name, value in (
            ("inter_arrival_sum_seconds", self.inter_arrival_sum_seconds),
            ("inter_arrival_sum_seconds_squared", self.inter_arrival_sum_seconds_squared),
            ("min_inter_arrival_seconds", self.min_inter_arrival_seconds),
            ("max_inter_arrival_seconds", self.max_inter_arrival_seconds),
        ):
            if type(value) is not float:
                raise TypeError(f"{name} must be a float")
            if not isfinite(value) or value < 0.0:
                raise FlowInterArrivalStatisticsError(f"{name} must be finite and nonnegative")
            if self.inter_arrival_count == 0 and value != 0.0:
                raise FlowInterArrivalStatisticsError("no intervals requires zero interval aggregates")
        if self.min_inter_arrival_seconds > self.max_inter_arrival_seconds:
            raise FlowInterArrivalStatisticsError("minimum interval must not exceed maximum interval")


def update_flow_inter_arrival_statistics(
    current: Optional[FlowInterArrivalStatistics],
    analysis: PacketAnalysis,
    identity: FlowIdentity,
) -> FlowInterArrivalStatistics:
    if current is not None and not isinstance(current, FlowInterArrivalStatistics):
        raise TypeError("current must be a FlowInterArrivalStatistics or None")
    if not isinstance(analysis, PacketAnalysis):
        raise TypeError("analysis must be a PacketAnalysis")
    if type(identity) is not FlowIdentity:
        raise TypeError("identity must be exactly a FlowIdentity")
    if flow_identity_from_packet(analysis) != identity:
        raise FlowInterArrivalStatisticsError("identity must match the analysis")
    if current is not None and current.identity != identity:
        raise FlowInterArrivalStatisticsError("current identity must match the supplied identity")
    timestamp = analysis.observation.captured_at
    if current is None:
        return FlowInterArrivalStatistics(
            identity=identity,
            packet_count=1,
            first_captured_at=timestamp,
            last_captured_at=timestamp,
            inter_arrival_count=0,
            inter_arrival_sum_seconds=0.0,
            inter_arrival_sum_seconds_squared=0.0,
            min_inter_arrival_seconds=0.0,
            max_inter_arrival_seconds=0.0,
        )
    interval_seconds = (timestamp - current.last_captured_at).total_seconds()
    if not isfinite(interval_seconds) or interval_seconds < 0.0:
        raise FlowInterArrivalStatisticsError("interval must be finite and nonnegative")
    return FlowInterArrivalStatistics(
        identity=current.identity,
        packet_count=current.packet_count + 1,
        first_captured_at=current.first_captured_at,
        last_captured_at=timestamp,
        inter_arrival_count=current.inter_arrival_count + 1,
        inter_arrival_sum_seconds=current.inter_arrival_sum_seconds + interval_seconds,
        inter_arrival_sum_seconds_squared=(
            current.inter_arrival_sum_seconds_squared + interval_seconds * interval_seconds
        ),
        min_inter_arrival_seconds=interval_seconds if current.inter_arrival_count == 0
        else min(current.min_inter_arrival_seconds, interval_seconds),
        max_inter_arrival_seconds=interval_seconds if current.inter_arrival_count == 0
        else max(current.max_inter_arrival_seconds, interval_seconds),
    )
