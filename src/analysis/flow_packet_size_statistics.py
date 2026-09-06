from dataclasses import dataclass, fields
from typing import Optional

from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity
from analysis.packet_analysis import PacketAnalysis


class FlowPacketSizeStatisticsError(ValueError):
    pass


@dataclass(frozen=True)
class FlowPacketSizeStatistics:
    identity: FlowIdentity
    packet_count: int
    captured_bytes: int
    original_bytes: int
    min_captured_length: int
    max_captured_length: int
    sum_captured_length_squares: int
    min_original_length: int
    max_original_length: int
    sum_original_length_squares: int
    forward_packet_count: int
    reverse_packet_count: int
    forward_captured_bytes: int
    reverse_captured_bytes: int
    forward_min_captured_length: int
    forward_max_captured_length: int
    forward_sum_captured_length_squares: int
    reverse_min_captured_length: int
    reverse_max_captured_length: int
    reverse_sum_captured_length_squares: int
    forward_original_bytes: int
    reverse_original_bytes: int
    forward_min_original_length: int
    forward_max_original_length: int
    forward_sum_original_length_squares: int
    reverse_min_original_length: int
    reverse_max_original_length: int
    reverse_sum_original_length_squares: int

    def __post_init__(self) -> None:
        if not isinstance(self.identity, FlowIdentity):
            raise TypeError("identity must be a FlowIdentity")
        for field in fields(self):
            if field.name == "identity":
                continue
            value = getattr(self, field.name)
            if type(value) is not int:
                raise TypeError(f"{field.name} must be an integer")
            if value < 0:
                raise FlowPacketSizeStatisticsError(f"{field.name} must not be negative")
        if self.packet_count < 1:
            raise FlowPacketSizeStatisticsError("packet_count must be at least 1")
        for prefix in ("", "forward_", "reverse_"):
            captured = getattr(self, f"{prefix}captured_bytes")
            original = getattr(self, f"{prefix}original_bytes")
            if original < captured:
                raise FlowPacketSizeStatisticsError(f"{prefix}original_bytes must be at least {prefix}captured_bytes")
            for kind in ("captured", "original"):
                minimum = getattr(self, f"{prefix}min_{kind}_length")
                maximum = getattr(self, f"{prefix}max_{kind}_length")
                if minimum > maximum:
                    raise FlowPacketSizeStatisticsError(f"{prefix}min_{kind}_length must not exceed its maximum")
                if prefix and getattr(self, f"{prefix}packet_count") == 0:
                    total = getattr(self, f"{prefix}{kind}_bytes")
                    squares = getattr(self, f"{prefix}sum_{kind}_length_squares")
                    if any((total, minimum, maximum, squares)):
                        raise FlowPacketSizeStatisticsError(f"unused {prefix}direction must have zero aggregates")


def update_flow_packet_size_statistics(
    current: Optional[FlowPacketSizeStatistics],
    analysis: PacketAnalysis,
    identity: FlowIdentity,
) -> FlowPacketSizeStatistics:
    if current is not None and not isinstance(current, FlowPacketSizeStatistics):
        raise TypeError("current must be a FlowPacketSizeStatistics or None")
    if not isinstance(analysis, PacketAnalysis):
        raise TypeError("analysis must be a PacketAnalysis")
    if not isinstance(identity, FlowIdentity):
        raise TypeError("identity must be a FlowIdentity")
    direction = flow_direction_from_packet(analysis, identity)
    if current is not None and current.identity != identity:
        raise FlowPacketSizeStatisticsError("current identity must match the supplied identity")
    captured = analysis.observation.captured_length
    original = analysis.observation.original_length
    if original is None:
        raise FlowPacketSizeStatisticsError("packet-size statistics require a known original_length")
    directional = {}
    for prefix, selected in (("forward", direction is FlowDirection.FORWARD),
                             ("reverse", direction is FlowDirection.REVERSE)):
        count = 0 if current is None else getattr(current, f"{prefix}_packet_count")
        directional[f"{prefix}_packet_count"] = count + (1 if selected else 0)
        for kind, length in (("captured", captured), ("original", original)):
            total_name = f"{prefix}_{kind}_bytes"
            min_name = f"{prefix}_min_{kind}_length"
            max_name = f"{prefix}_max_{kind}_length"
            squares_name = f"{prefix}_sum_{kind}_length_squares"
            total = 0 if current is None else getattr(current, total_name)
            minimum = 0 if current is None else getattr(current, min_name)
            maximum = 0 if current is None else getattr(current, max_name)
            squares = 0 if current is None else getattr(current, squares_name)
            if selected:
                total += length
                minimum = length if count == 0 else min(minimum, length)
                maximum = length if count == 0 else max(maximum, length)
                squares += length * length
            directional[total_name] = total
            directional[min_name] = minimum
            directional[max_name] = maximum
            directional[squares_name] = squares
    return FlowPacketSizeStatistics(
        identity=identity,
        packet_count=1 if current is None else current.packet_count + 1,
        captured_bytes=captured if current is None else current.captured_bytes + captured,
        original_bytes=original if current is None else current.original_bytes + original,
        min_captured_length=captured if current is None else min(current.min_captured_length, captured),
        max_captured_length=captured if current is None else max(current.max_captured_length, captured),
        sum_captured_length_squares=captured * captured if current is None
        else current.sum_captured_length_squares + captured * captured,
        min_original_length=original if current is None else min(current.min_original_length, original),
        max_original_length=original if current is None else max(current.max_original_length, original),
        sum_original_length_squares=original * original if current is None
        else current.sum_original_length_squares + original * original,
        **directional,
    )
