from dataclasses import dataclass
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
