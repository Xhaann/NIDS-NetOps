from dataclasses import dataclass

from analysis.directional_flow_statistics import DirectionalFlowStatistics
from analysis.flow_identity import FlowIdentity
from analysis.flow_statistics import FlowStatistics


class FlowFeatureInputError(ValueError):
    pass


@dataclass(frozen=True)
class FlowFeatureInput:
    identity: FlowIdentity
    packet_count: int
    captured_bytes: int
    original_bytes: int
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
            ("packet_count", self.packet_count),
            ("captured_bytes", self.captured_bytes),
            ("original_bytes", self.original_bytes),
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
                raise FlowFeatureInputError(f"{name} must not be negative")
        if self.original_bytes < self.captured_bytes:
            raise FlowFeatureInputError("original_bytes must be at least captured_bytes")
        if self.forward_original_bytes < self.forward_captured_bytes:
            raise FlowFeatureInputError("forward_original_bytes must be at least forward_captured_bytes")
        if self.reverse_original_bytes < self.reverse_captured_bytes:
            raise FlowFeatureInputError("reverse_original_bytes must be at least reverse_captured_bytes")


def flow_feature_input_from_statistics(
    statistics: FlowStatistics,
    directional: DirectionalFlowStatistics,
) -> FlowFeatureInput:
    if not isinstance(statistics, FlowStatistics):
        raise TypeError("statistics must be a FlowStatistics")
    if not isinstance(directional, DirectionalFlowStatistics):
        raise TypeError("directional must be a DirectionalFlowStatistics")
    if statistics.identity != directional.identity:
        raise FlowFeatureInputError("statistics and directional identities must match")
    return FlowFeatureInput(
        identity=statistics.identity,
        packet_count=statistics.packet_count,
        captured_bytes=statistics.captured_bytes,
        original_bytes=statistics.original_bytes,
        forward_packet_count=directional.forward_packet_count,
        reverse_packet_count=directional.reverse_packet_count,
        forward_captured_bytes=directional.forward_captured_bytes,
        reverse_captured_bytes=directional.reverse_captured_bytes,
        forward_original_bytes=directional.forward_original_bytes,
        reverse_original_bytes=directional.reverse_original_bytes,
    )
