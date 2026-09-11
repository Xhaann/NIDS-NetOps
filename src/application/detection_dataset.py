from dataclasses import dataclass
from typing import Optional, Union

from application.detection_evaluation import FlowDetectionIdentity, PacketDetectionIdentity
from application.ground_truth import GroundTruthRecord


def _identity(value: str, name: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{name} must be exactly a string")
    if not value.strip():
        raise ValueError(f"{name} must not be blank")


@dataclass(frozen=True)
class DetectionDatasetCase:
    case_id: str
    target: Union[PacketDetectionIdentity, FlowDetectionIdentity]
    ground_truth: Optional[GroundTruthRecord] = None

    def __post_init__(self) -> None:
        _identity(self.case_id, "case_id")
        if type(self.target) not in (PacketDetectionIdentity, FlowDetectionIdentity):
            raise TypeError("target must be exactly a packet or flow detection identity")
        if self.ground_truth is not None:
            if type(self.ground_truth) is not GroundTruthRecord:
                raise TypeError("ground_truth must be exactly a GroundTruthRecord or None")
            if self.ground_truth.target != self.target:
                raise ValueError("ground_truth target must equal case target")


@dataclass(frozen=True)
class DetectionDataset:
    name: str
    cases: tuple[DetectionDatasetCase, ...]

    def __post_init__(self) -> None:
        _identity(self.name, "name")
        if type(self.cases) is not tuple:
            raise TypeError("cases must be exactly a tuple")
        seen = set()
        for case in self.cases:
            if type(case) is not DetectionDatasetCase:
                raise TypeError("cases must contain exactly DetectionDatasetCase values")
            if case.case_id in seen:
                raise ValueError("cases contain a duplicate case_id")
            seen.add(case.case_id)
