from dataclasses import dataclass
from datetime import datetime
from math import isfinite
from typing import Optional

from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity, flow_identity_from_packet
from analysis.packet_analysis import PacketAnalysis


class DirectionalInterArrivalStatisticsError(ValueError):
    pass


@dataclass(frozen=True)
class DirectionalInterArrivalStatistics:
    identity: FlowIdentity
    packet_count: int
    first_captured_at: datetime
    last_captured_at: datetime
    last_forward_captured_at: Optional[datetime]
    last_reverse_captured_at: Optional[datetime]
    forward_inter_arrival_count: int
    reverse_inter_arrival_count: int
    forward_inter_arrival_sum_seconds: float
    reverse_inter_arrival_sum_seconds: float
    forward_inter_arrival_sum_seconds_squared: float
    reverse_inter_arrival_sum_seconds_squared: float
    forward_min_inter_arrival_seconds: float
    forward_max_inter_arrival_seconds: float
    reverse_min_inter_arrival_seconds: float
    reverse_max_inter_arrival_seconds: float

    def __post_init__(self) -> None:
        if type(self.identity) is not FlowIdentity:
            raise TypeError("identity must be exactly a FlowIdentity")
        for name, value in (
            ("packet_count", self.packet_count),
            ("forward_inter_arrival_count", self.forward_inter_arrival_count),
            ("reverse_inter_arrival_count", self.reverse_inter_arrival_count),
        ):
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
            if value < 0:
                raise DirectionalInterArrivalStatisticsError(f"{name} must not be negative")
        if self.packet_count < 1:
            raise DirectionalInterArrivalStatisticsError("packet_count must be at least 1")
        for name, timestamp, optional in (
            ("first_captured_at", self.first_captured_at, False),
            ("last_captured_at", self.last_captured_at, False),
            ("last_forward_captured_at", self.last_forward_captured_at, True),
            ("last_reverse_captured_at", self.last_reverse_captured_at, True),
        ):
            if optional and timestamp is None:
                continue
            if not isinstance(timestamp, datetime):
                raise TypeError(f"{name} must be a datetime")
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise DirectionalInterArrivalStatisticsError(f"{name} must be timezone-aware")
        if self.last_captured_at < self.first_captured_at:
            raise DirectionalInterArrivalStatisticsError("last_captured_at must not precede first_captured_at")
        for direction, timestamp, count, total, squares, minimum, maximum in (
            ("forward", self.last_forward_captured_at, self.forward_inter_arrival_count,
             self.forward_inter_arrival_sum_seconds, self.forward_inter_arrival_sum_seconds_squared,
             self.forward_min_inter_arrival_seconds, self.forward_max_inter_arrival_seconds),
            ("reverse", self.last_reverse_captured_at, self.reverse_inter_arrival_count,
             self.reverse_inter_arrival_sum_seconds, self.reverse_inter_arrival_sum_seconds_squared,
             self.reverse_min_inter_arrival_seconds, self.reverse_max_inter_arrival_seconds),
        ):
            if timestamp is not None and not self.first_captured_at <= timestamp <= self.last_captured_at:
                raise DirectionalInterArrivalStatisticsError(f"{direction} timestamp must lie within global timestamps")
            if timestamp is None and count != 0:
                raise DirectionalInterArrivalStatisticsError(f"unobserved {direction} direction cannot have intervals")
            for name, value in (("sum", total), ("sum of squares", squares), ("minimum", minimum), ("maximum", maximum)):
                if type(value) is not float:
                    raise TypeError(f"{direction} {name} must be a float")
                if not isfinite(value) or value < 0.0:
                    raise DirectionalInterArrivalStatisticsError(f"{direction} {name} must be finite and nonnegative")
                if count == 0 and value != 0.0:
                    raise DirectionalInterArrivalStatisticsError(f"zero {direction} intervals require zero aggregates")
            if minimum > maximum:
                raise DirectionalInterArrivalStatisticsError(f"{direction} minimum must not exceed maximum")
        observed = int(self.last_forward_captured_at is not None) + int(self.last_reverse_captured_at is not None)
        if self.forward_inter_arrival_count + self.reverse_inter_arrival_count != self.packet_count - observed:
            raise DirectionalInterArrivalStatisticsError("interval counts must equal packet_count minus observed directions")


def update_directional_inter_arrival_statistics(
    current: Optional[DirectionalInterArrivalStatistics],
    analysis: PacketAnalysis,
    identity: FlowIdentity,
) -> DirectionalInterArrivalStatistics:
    if current is not None and not isinstance(current, DirectionalInterArrivalStatistics):
        raise TypeError("current must be a DirectionalInterArrivalStatistics or None")
    if not isinstance(analysis, PacketAnalysis):
        raise TypeError("analysis must be a PacketAnalysis")
    if type(identity) is not FlowIdentity:
        raise TypeError("identity must be exactly a FlowIdentity")
    if flow_identity_from_packet(analysis) != identity:
        raise DirectionalInterArrivalStatisticsError("identity must match the analysis")
    if current is not None and current.identity != identity:
        raise DirectionalInterArrivalStatisticsError("current identity must match the supplied identity")
    direction = flow_direction_from_packet(analysis, identity)
    timestamp = analysis.observation.captured_at
    forward = direction is FlowDirection.FORWARD
    if current is None:
        return DirectionalInterArrivalStatistics(
            identity=identity, packet_count=1, first_captured_at=timestamp, last_captured_at=timestamp,
            last_forward_captured_at=timestamp if forward else None,
            last_reverse_captured_at=None if forward else timestamp,
            forward_inter_arrival_count=0, reverse_inter_arrival_count=0,
            forward_inter_arrival_sum_seconds=0.0, reverse_inter_arrival_sum_seconds=0.0,
            forward_inter_arrival_sum_seconds_squared=0.0, reverse_inter_arrival_sum_seconds_squared=0.0,
            forward_min_inter_arrival_seconds=0.0, forward_max_inter_arrival_seconds=0.0,
            reverse_min_inter_arrival_seconds=0.0, reverse_max_inter_arrival_seconds=0.0,
        )
    if timestamp < current.last_captured_at:
        raise DirectionalInterArrivalStatisticsError("capture timestamp must not precede the latest packet")
    if forward:
        previous = current.last_forward_captured_at
        count = current.forward_inter_arrival_count
        total = current.forward_inter_arrival_sum_seconds
        squares = current.forward_inter_arrival_sum_seconds_squared
        minimum = current.forward_min_inter_arrival_seconds
        maximum = current.forward_max_inter_arrival_seconds
    else:
        previous = current.last_reverse_captured_at
        count = current.reverse_inter_arrival_count
        total = current.reverse_inter_arrival_sum_seconds
        squares = current.reverse_inter_arrival_sum_seconds_squared
        minimum = current.reverse_min_inter_arrival_seconds
        maximum = current.reverse_max_inter_arrival_seconds
    if previous is not None:
        interval = (timestamp - previous).total_seconds()
        if not isfinite(interval) or interval < 0.0:
            raise DirectionalInterArrivalStatisticsError("interval must be finite and nonnegative")
        total += interval
        squares += interval * interval
        minimum = interval if count == 0 else min(minimum, interval)
        maximum = interval if count == 0 else max(maximum, interval)
        count += 1
    return DirectionalInterArrivalStatistics(
        identity=current.identity,
        packet_count=current.packet_count + 1,
        first_captured_at=current.first_captured_at,
        last_captured_at=timestamp,
        last_forward_captured_at=timestamp if forward else current.last_forward_captured_at,
        last_reverse_captured_at=current.last_reverse_captured_at if forward else timestamp,
        forward_inter_arrival_count=count if forward else current.forward_inter_arrival_count,
        reverse_inter_arrival_count=current.reverse_inter_arrival_count if forward else count,
        forward_inter_arrival_sum_seconds=total if forward else current.forward_inter_arrival_sum_seconds,
        reverse_inter_arrival_sum_seconds=current.reverse_inter_arrival_sum_seconds if forward else total,
        forward_inter_arrival_sum_seconds_squared=squares if forward else current.forward_inter_arrival_sum_seconds_squared,
        reverse_inter_arrival_sum_seconds_squared=current.reverse_inter_arrival_sum_seconds_squared if forward else squares,
        forward_min_inter_arrival_seconds=minimum if forward else current.forward_min_inter_arrival_seconds,
        forward_max_inter_arrival_seconds=maximum if forward else current.forward_max_inter_arrival_seconds,
        reverse_min_inter_arrival_seconds=current.reverse_min_inter_arrival_seconds if forward else minimum,
        reverse_max_inter_arrival_seconds=current.reverse_max_inter_arrival_seconds if forward else maximum,
    )
