from dataclasses import dataclass
from math import isfinite

from analysis.flow_feature_input import FlowFeatureInput


class FlowVolumeFeaturesError(ValueError):
    pass


@dataclass(frozen=True)
class FlowVolumeFeatures:
    packet_count: int
    captured_bytes: int
    original_bytes: int
    forward_packet_count: int
    reverse_packet_count: int
    forward_captured_bytes: int
    reverse_captured_bytes: int
    forward_original_bytes: int
    reverse_original_bytes: int
    forward_packet_ratio: float
    reverse_packet_ratio: float
    forward_captured_byte_ratio: float
    reverse_captured_byte_ratio: float
    forward_original_byte_ratio: float
    reverse_original_byte_ratio: float
    capture_ratio: float

    def __post_init__(self) -> None:
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
                raise FlowVolumeFeaturesError(f"{name} must not be negative")
        for name, value in (
            ("forward_packet_ratio", self.forward_packet_ratio),
            ("reverse_packet_ratio", self.reverse_packet_ratio),
            ("forward_captured_byte_ratio", self.forward_captured_byte_ratio),
            ("reverse_captured_byte_ratio", self.reverse_captured_byte_ratio),
            ("forward_original_byte_ratio", self.forward_original_byte_ratio),
            ("reverse_original_byte_ratio", self.reverse_original_byte_ratio),
            ("capture_ratio", self.capture_ratio),
        ):
            if type(value) is not float:
                raise TypeError(f"{name} must be a float")
            if not isfinite(value) or not 0.0 <= value <= 1.0:
                raise FlowVolumeFeaturesError(f"{name} must be finite and between 0.0 and 1.0")


def extract_flow_volume_features(input_data: FlowFeatureInput) -> FlowVolumeFeatures:
    if not isinstance(input_data, FlowFeatureInput):
        raise TypeError("input_data must be a FlowFeatureInput")
    return FlowVolumeFeatures(
        packet_count=input_data.packet_count,
        captured_bytes=input_data.captured_bytes,
        original_bytes=input_data.original_bytes,
        forward_packet_count=input_data.forward_packet_count,
        reverse_packet_count=input_data.reverse_packet_count,
        forward_captured_bytes=input_data.forward_captured_bytes,
        reverse_captured_bytes=input_data.reverse_captured_bytes,
        forward_original_bytes=input_data.forward_original_bytes,
        reverse_original_bytes=input_data.reverse_original_bytes,
        forward_packet_ratio=input_data.forward_packet_count / input_data.packet_count
        if input_data.packet_count != 0 else 0.0,
        reverse_packet_ratio=input_data.reverse_packet_count / input_data.packet_count
        if input_data.packet_count != 0 else 0.0,
        forward_captured_byte_ratio=input_data.forward_captured_bytes / input_data.captured_bytes
        if input_data.captured_bytes != 0 else 0.0,
        reverse_captured_byte_ratio=input_data.reverse_captured_bytes / input_data.captured_bytes
        if input_data.captured_bytes != 0 else 0.0,
        forward_original_byte_ratio=input_data.forward_original_bytes / input_data.original_bytes
        if input_data.original_bytes != 0 else 0.0,
        reverse_original_byte_ratio=input_data.reverse_original_bytes / input_data.original_bytes
        if input_data.original_bytes != 0 else 0.0,
        capture_ratio=input_data.captured_bytes / input_data.original_bytes
        if input_data.original_bytes != 0 else 0.0,
    )
