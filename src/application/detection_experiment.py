from dataclasses import dataclass

from application.detection_dataset import DetectionDataset


@dataclass(frozen=True)
class DetectionExperiment:
    experiment_id: str
    dataset: DetectionDataset
    benchmark_operation_id: str
    benchmark_operation_version: str

    def __post_init__(self) -> None:
        for name, value in (("experiment_id", self.experiment_id),
                            ("benchmark_operation_id", self.benchmark_operation_id),
                            ("benchmark_operation_version", self.benchmark_operation_version)):
            if type(value) is not str:
                raise TypeError(f"{name} must be exactly a string")
            if not value.strip():
                raise ValueError(f"{name} must not be blank")
        if type(self.dataset) is not DetectionDataset:
            raise TypeError("dataset must be exactly a DetectionDataset")
