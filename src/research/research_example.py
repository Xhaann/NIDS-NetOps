from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from analysis.flow_feature_snapshot import extract_flow_feature_snapshot
from analysis.flow_observation_window import FlowObservationWindow
from ml.feature_projection import MLFeatureProjection, project_flow_features


@dataclass(frozen=True)
class ResearchExample:
    projection: MLFeatureProjection
    ground_truth: Optional[str] = None
    observation_window: Optional[FlowObservationWindow] = None

    def __post_init__(self) -> None:
        if type(self.projection) is not MLFeatureProjection:
            raise TypeError("projection must be exactly an MLFeatureProjection")
        _validate_ground_truth(self.ground_truth)
        if self.observation_window is not None:
            _validate_observation_window(self.observation_window)


def research_example_from_window(
    window: FlowObservationWindow,
    ground_truth: Optional[str] = None,
) -> ResearchExample:
    if type(window) is not FlowObservationWindow:
        raise TypeError("window must be exactly a FlowObservationWindow")
    _validate_ground_truth(ground_truth)
    _validate_observation_window(window)
    snapshot = extract_flow_feature_snapshot(window)
    projection = project_flow_features(snapshot)
    return ResearchExample(projection, ground_truth, window)


def _validate_ground_truth(ground_truth: Optional[str]) -> None:
    if ground_truth is not None:
        if type(ground_truth) is not str:
            raise TypeError("ground_truth must be exactly a string or None")
        if not ground_truth.strip():
            raise ValueError("ground_truth must not be blank")


def _validate_observation_window(window: FlowObservationWindow) -> None:
    if type(window) is not FlowObservationWindow:
        raise TypeError("observation_window must be exactly a FlowObservationWindow or None")
    if window.closure_reason is None:
        raise ValueError("observation_window must be closed")
    state = window.coordinated_state
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
