from dataclasses import dataclass
from typing import Optional

from ml.feature_projection import MLFeatureProjection


@dataclass(frozen=True)
class ResearchExample:
    projection: MLFeatureProjection
    ground_truth: Optional[str] = None

    def __post_init__(self) -> None:
        if type(self.projection) is not MLFeatureProjection:
            raise TypeError("projection must be exactly an MLFeatureProjection")
        if self.ground_truth is not None:
            if type(self.ground_truth) is not str:
                raise TypeError("ground_truth must be exactly a string or None")
            if not self.ground_truth.strip():
                raise ValueError("ground_truth must not be blank")
