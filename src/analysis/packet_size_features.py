from dataclasses import dataclass, fields
from math import isfinite, sqrt, ulp

from analysis.flow_packet_size_statistics import FlowPacketSizeStatistics


class PacketSizeFeaturesError(ValueError):
    pass


@dataclass(frozen=True)
class PacketSizeFeatures:
    min_captured_length: int
    max_captured_length: int
    mean_captured_length: float
    variance_captured_length: float
    standard_deviation_captured_length: float
    min_original_length: int
    max_original_length: int
    mean_original_length: float
    variance_original_length: float
    standard_deviation_original_length: float
    forward_mean_captured_length: float
    reverse_mean_captured_length: float
    forward_variance_captured_length: float
    reverse_variance_captured_length: float

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if field.name in ("min_captured_length", "max_captured_length",
                              "min_original_length", "max_original_length"):
                if type(value) is not int:
                    raise TypeError(f"{field.name} must be an integer")
            else:
                if type(value) is not float:
                    raise TypeError(f"{field.name} must be a float")
                if not isfinite(value):
                    raise PacketSizeFeaturesError(f"{field.name} must be finite")
            if value < 0:
                raise PacketSizeFeaturesError(f"{field.name} must not be negative")
        if self.min_captured_length > self.max_captured_length:
            raise PacketSizeFeaturesError("min_captured_length must not exceed max_captured_length")
        if self.min_original_length > self.max_original_length:
            raise PacketSizeFeaturesError("min_original_length must not exceed max_original_length")


def extract_packet_size_features(statistics: FlowPacketSizeStatistics) -> PacketSizeFeatures:
    if not isinstance(statistics, FlowPacketSizeStatistics):
        raise TypeError("statistics must be a FlowPacketSizeStatistics")
    derived = {}
    for prefix, kind, count, total, squares in (
        ("", "captured", statistics.packet_count, statistics.captured_bytes,
         statistics.sum_captured_length_squares),
        ("", "original", statistics.packet_count, statistics.original_bytes,
         statistics.sum_original_length_squares),
        ("forward_", "captured", statistics.forward_packet_count, statistics.forward_captured_bytes,
         statistics.forward_sum_captured_length_squares),
        ("reverse_", "captured", statistics.reverse_packet_count, statistics.reverse_captured_bytes,
         statistics.reverse_sum_captured_length_squares),
    ):
        if prefix and count == 0:
            mean = 0.0
            variance = 0.0
        else:
            try:
                mean = total / count
                second_moment = squares / count
            except OverflowError as error:
                raise PacketSizeFeaturesError("packet-size moments exceed finite float range") from error
            mean_squared = mean * mean
            if not all(isfinite(value) for value in (mean, second_moment, mean_squared)):
                raise PacketSizeFeaturesError("packet-size moments must be finite")
            variance = second_moment - mean_squared
            mean_error = ulp(mean)
            roundoff_bound = (ulp(second_moment) + ulp(mean_squared)
                              + mean_error * (2 * abs(mean) + mean_error))
            if abs(variance) <= roundoff_bound:
                numerator = count * squares - total * total
                if numerator < 0:
                    raise PacketSizeFeaturesError(f"{prefix}{kind} population variance is materially negative")
                variance = numerator / (count * count)
            if variance < 0.0:
                raise PacketSizeFeaturesError(f"{prefix}{kind} population variance is materially negative")
        derived[f"{prefix}mean_{kind}_length"] = mean
        derived[f"{prefix}variance_{kind}_length"] = variance
        if not prefix:
            derived[f"standard_deviation_{kind}_length"] = sqrt(variance)
    return PacketSizeFeatures(
        min_captured_length=statistics.min_captured_length,
        max_captured_length=statistics.max_captured_length,
        min_original_length=statistics.min_original_length,
        max_original_length=statistics.max_original_length,
        **derived,
    )
