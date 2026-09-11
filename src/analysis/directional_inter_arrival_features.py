from dataclasses import dataclass
from math import isfinite, sqrt, ulp
from typing import Optional

from analysis.directional_inter_arrival_statistics import DirectionalInterArrivalStatistics


class DirectionalInterArrivalFeaturesError(ValueError):
    pass


@dataclass(frozen=True)
class DirectionalInterArrivalFeatures:
    forward_mean_inter_arrival_seconds: Optional[float]
    forward_variance_inter_arrival_seconds: Optional[float]
    forward_standard_deviation_inter_arrival_seconds: Optional[float]
    forward_min_inter_arrival_seconds: Optional[float]
    forward_max_inter_arrival_seconds: Optional[float]
    reverse_mean_inter_arrival_seconds: Optional[float]
    reverse_variance_inter_arrival_seconds: Optional[float]
    reverse_standard_deviation_inter_arrival_seconds: Optional[float]
    reverse_min_inter_arrival_seconds: Optional[float]
    reverse_max_inter_arrival_seconds: Optional[float]

    def __post_init__(self) -> None:
        for direction in ("forward", "reverse"):
            values = tuple(
                getattr(self, f"{direction}_{name}_inter_arrival_seconds")
                for name in ("mean", "variance", "standard_deviation", "min", "max")
            )
            if all(value is None for value in values):
                continue
            if any(value is None for value in values):
                raise DirectionalInterArrivalFeaturesError(
                    f"{direction} inter-arrival features must be all available or all unavailable"
                )
            for name, value in zip(
                ("mean", "variance", "standard deviation", "minimum", "maximum"), values
            ):
                if type(value) is not float:
                    raise TypeError(f"{direction} {name} inter-arrival seconds must be a float or None")
                if not isfinite(value) or value < 0.0:
                    raise DirectionalInterArrivalFeaturesError(
                        f"{direction} {name} inter-arrival seconds must be finite and nonnegative"
                    )
            if values[3] > values[4]:
                raise DirectionalInterArrivalFeaturesError(
                    f"{direction} minimum interval must not exceed maximum interval"
                )


def _direction_features(
    direction: str,
    count: int,
    total: float,
    squares: float,
    minimum: float,
    maximum: float,
) -> tuple[Optional[float], Optional[float], Optional[float], Optional[float], Optional[float]]:
    for name, value in (
        ("sum", total),
        ("sum of squares", squares),
        ("minimum", minimum),
        ("maximum", maximum),
    ):
        if type(value) is not float:
            raise TypeError(f"{direction} {name} must be a float")
        if not isfinite(value) or value < 0.0:
            raise DirectionalInterArrivalFeaturesError(
                f"{direction} {name} must be finite and nonnegative"
            )
    if minimum > maximum:
        raise DirectionalInterArrivalFeaturesError(
            f"{direction} minimum interval must not exceed maximum interval"
        )
    if count == 0:
        if any(value != 0.0 for value in (total, squares, minimum, maximum)):
            raise DirectionalInterArrivalFeaturesError(
                f"zero {direction} intervals require zero aggregates"
            )
        return None, None, None, None, None
    try:
        mean = total / count
        second_moment = squares / count
    except OverflowError as error:
        raise DirectionalInterArrivalFeaturesError(
            f"{direction} inter-arrival moments exceed finite float range"
        ) from error
    mean_squared = mean * mean
    if not all(isfinite(value) for value in (mean, second_moment, mean_squared)):
        raise DirectionalInterArrivalFeaturesError(
            f"{direction} inter-arrival moments must be finite"
        )
    variance = second_moment - mean_squared
    if not isfinite(variance):
        raise DirectionalInterArrivalFeaturesError(
            f"{direction} inter-arrival variance must be finite"
        )
    if variance < 0.0:
        mean_error = count * ulp(mean)
        roundoff_bound = (
            count * ulp(second_moment)
            + ulp(mean_squared)
            + mean_error * (2 * abs(mean) + mean_error)
        )
        if -variance > roundoff_bound:
            raise DirectionalInterArrivalFeaturesError(
                f"{direction} inter-arrival population variance is materially negative"
            )
        variance = 0.0
    return mean, variance, sqrt(variance), minimum, maximum


def extract_directional_inter_arrival_features(
    statistics: DirectionalInterArrivalStatistics,
) -> DirectionalInterArrivalFeatures:
    if type(statistics) is not DirectionalInterArrivalStatistics:
        raise TypeError("statistics must be exactly a DirectionalInterArrivalStatistics")
    for name, value in (
        ("packet_count", statistics.packet_count),
        ("forward_inter_arrival_count", statistics.forward_inter_arrival_count),
        ("reverse_inter_arrival_count", statistics.reverse_inter_arrival_count),
    ):
        if type(value) is not int:
            raise TypeError(f"{name} must be an integer")
        if value < 0:
            raise DirectionalInterArrivalFeaturesError(f"{name} must not be negative")
    if statistics.packet_count < 1:
        raise DirectionalInterArrivalFeaturesError("packet_count must be at least 1")
    observed_directions = int(statistics.last_forward_captured_at is not None) + int(
        statistics.last_reverse_captured_at is not None
    )
    if (
        statistics.forward_inter_arrival_count + statistics.reverse_inter_arrival_count
        != statistics.packet_count - observed_directions
    ):
        raise DirectionalInterArrivalFeaturesError(
            "interval counts must equal packet_count minus observed directions"
        )
    for direction, timestamp, count in (
        ("forward", statistics.last_forward_captured_at, statistics.forward_inter_arrival_count),
        ("reverse", statistics.last_reverse_captured_at, statistics.reverse_inter_arrival_count),
    ):
        if timestamp is None and count != 0:
            raise DirectionalInterArrivalFeaturesError(
                f"unobserved {direction} direction cannot have intervals"
            )
    forward = _direction_features(
        "forward",
        statistics.forward_inter_arrival_count,
        statistics.forward_inter_arrival_sum_seconds,
        statistics.forward_inter_arrival_sum_seconds_squared,
        statistics.forward_min_inter_arrival_seconds,
        statistics.forward_max_inter_arrival_seconds,
    )
    reverse = _direction_features(
        "reverse",
        statistics.reverse_inter_arrival_count,
        statistics.reverse_inter_arrival_sum_seconds,
        statistics.reverse_inter_arrival_sum_seconds_squared,
        statistics.reverse_min_inter_arrival_seconds,
        statistics.reverse_max_inter_arrival_seconds,
    )
    return DirectionalInterArrivalFeatures(*forward, *reverse)
