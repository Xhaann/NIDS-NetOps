from dataclasses import dataclass
from math import isfinite

from analysis.flow_statistics import FlowStatistics


class FlowDurationFeaturesError(ValueError):
    pass


@dataclass(frozen=True)
class FlowDurationFeatures:
    duration_seconds: float

    def __post_init__(self) -> None:
        if type(self.duration_seconds) is not float:
            raise TypeError("duration_seconds must be a float")
        if not isfinite(self.duration_seconds) or self.duration_seconds < 0.0:
            raise FlowDurationFeaturesError("duration_seconds must be finite and nonnegative")


def extract_flow_duration_features(statistics: FlowStatistics) -> FlowDurationFeatures:
    if type(statistics) is not FlowStatistics:
        raise TypeError("statistics must be exactly a FlowStatistics")
    return FlowDurationFeatures(
        duration_seconds=(statistics.last_captured_at - statistics.first_captured_at).total_seconds(),
    )
