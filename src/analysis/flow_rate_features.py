from dataclasses import dataclass
from math import isfinite

from analysis.flow_statistics import FlowStatistics


class FlowRateFeaturesError(ValueError):
    pass


@dataclass(frozen=True)
class FlowRateFeatures:
    packets_per_second: float
    captured_bytes_per_second: float
    original_bytes_per_second: float

    def __post_init__(self) -> None:
        for name, value in (
            ("packets_per_second", self.packets_per_second),
            ("captured_bytes_per_second", self.captured_bytes_per_second),
            ("original_bytes_per_second", self.original_bytes_per_second),
        ):
            if type(value) is not float:
                raise TypeError(f"{name} must be a float")
            if not isfinite(value) or value < 0.0:
                raise FlowRateFeaturesError(f"{name} must be finite and nonnegative")


def extract_flow_rate_features(statistics: FlowStatistics) -> FlowRateFeatures:
    if type(statistics) is not FlowStatistics:
        raise TypeError("statistics must be exactly a FlowStatistics")
    duration_seconds = (statistics.last_captured_at - statistics.first_captured_at).total_seconds()
    if not isfinite(duration_seconds) or duration_seconds < 0.0:
        raise FlowRateFeaturesError("duration must be finite and nonnegative")
    if duration_seconds == 0.0:
        if statistics.packet_count == 0 and statistics.captured_bytes == 0 and statistics.original_bytes == 0:
            return FlowRateFeatures(0.0, 0.0, 0.0)
        raise FlowRateFeaturesError("zero duration requires all rate numerators to be zero")
    try:
        return FlowRateFeatures(
            packets_per_second=statistics.packet_count / duration_seconds,
            captured_bytes_per_second=statistics.captured_bytes / duration_seconds,
            original_bytes_per_second=statistics.original_bytes / duration_seconds,
        )
    except OverflowError as error:
        raise FlowRateFeaturesError("flow rates exceed finite float range") from error
