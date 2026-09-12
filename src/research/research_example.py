from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from analysis.flow_observation_window import FlowObservationWindow
from ml.feature_projection import MLFeatureProjection


@dataclass(frozen=True)
class ResearchExample:
    projection: MLFeatureProjection
    ground_truth: Optional[str] = None
    observation_window: Optional[FlowObservationWindow] = None

    def __post_init__(self) -> None:
        if type(self.projection) is not MLFeatureProjection:
            raise TypeError("projection must be exactly an MLFeatureProjection")
        if self.ground_truth is not None:
            if type(self.ground_truth) is not str:
                raise TypeError("ground_truth must be exactly a string or None")
            if not self.ground_truth.strip():
                raise ValueError("ground_truth must not be blank")
        if self.observation_window is not None:
            if type(self.observation_window) is not FlowObservationWindow:
                raise TypeError("observation_window must be exactly a FlowObservationWindow or None")
            if self.observation_window.closure_reason is None:
                raise ValueError("observation_window must be closed")
            state = self.observation_window.coordinated_state
            for aggregate_name, timestamp_names in (
                ("flow_statistics", ("first_captured_at", "last_captured_at")),
                ("flow_inter_arrival_statistics", ("first_captured_at", "last_captured_at")),
                ("directional_inter_arrival_statistics", (
                    "first_captured_at", "last_captured_at",
                    "last_forward_captured_at", "last_reverse_captured_at",
                )),
            ):
                aggregate = getattr(state, aggregate_name)
                for timestamp_name in timestamp_names:
                    timestamp = getattr(aggregate, timestamp_name)
                    if timestamp is None and timestamp_name in (
                        "last_forward_captured_at", "last_reverse_captured_at",
                    ):
                        continue
                    name = f"observation_window.coordinated_state.{aggregate_name}.{timestamp_name}"
                    if type(timestamp) is not datetime:
                        raise TypeError(f"{name} must be a datetime of the exact built-in type")
                    if timestamp.tzinfo is None:
                        raise ValueError(f"{name} must be timezone-aware UTC")
                    if type(timestamp.tzinfo) is not timezone:
                        raise ValueError(f"{name} must use a fixed UTC datetime.timezone")
                    if timestamp.utcoffset() != timedelta(0):
                        raise ValueError(f"{name} must have a zero UTC offset")
