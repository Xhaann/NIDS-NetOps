from dataclasses import dataclass, fields
from math import isfinite, sqrt, ulp

from analysis.flow_inter_arrival_statistics import FlowInterArrivalStatistics


class InterArrivalFeaturesError(ValueError):
    pass


@dataclass(frozen=True)
class InterArrivalFeatures:
    mean_inter_arrival_seconds: float
    variance_inter_arrival_seconds: float
    standard_deviation_inter_arrival_seconds: float
    min_inter_arrival_seconds: float
    max_inter_arrival_seconds: float

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not float:
                raise TypeError(f"{field.name} must be a float")
            if not isfinite(value) or value < 0.0:
                raise InterArrivalFeaturesError(f"{field.name} must be finite and nonnegative")
        if self.min_inter_arrival_seconds > self.max_inter_arrival_seconds:
            raise InterArrivalFeaturesError("minimum interval must not exceed maximum interval")


def extract_inter_arrival_features(statistics: FlowInterArrivalStatistics) -> InterArrivalFeatures:
    if type(statistics) is not FlowInterArrivalStatistics:
        raise TypeError("statistics must be exactly a FlowInterArrivalStatistics")
    if statistics.inter_arrival_count == 0:
        return InterArrivalFeatures(0.0, 0.0, 0.0, 0.0, 0.0)
    try:
        mean = statistics.inter_arrival_sum_seconds / statistics.inter_arrival_count
        second_moment = statistics.inter_arrival_sum_seconds_squared / statistics.inter_arrival_count
    except OverflowError as error:
        raise InterArrivalFeaturesError("inter-arrival moments exceed finite float range") from error
    mean_squared = mean * mean
    if not all(isfinite(value) for value in (mean, second_moment, mean_squared)):
        raise InterArrivalFeaturesError("inter-arrival moments must be finite")
    variance = second_moment - mean_squared
    if not isfinite(variance):
        raise InterArrivalFeaturesError("inter-arrival variance must be finite")
    if variance < 0.0:
        mean_error = ulp(mean)
        roundoff_bound = (ulp(second_moment) + ulp(mean_squared)
                          + mean_error * (2 * abs(mean) + mean_error))
        if -variance > roundoff_bound:
            raise InterArrivalFeaturesError("inter-arrival population variance is materially negative")
        variance = 0.0
    return InterArrivalFeatures(
        mean_inter_arrival_seconds=mean,
        variance_inter_arrival_seconds=variance,
        standard_deviation_inter_arrival_seconds=sqrt(variance),
        min_inter_arrival_seconds=statistics.min_inter_arrival_seconds,
        max_inter_arrival_seconds=statistics.max_inter_arrival_seconds,
    )
