from dataclasses import dataclass
from typing import Optional, Union

from application.detection_benchmark import DetectionBenchmarkResult
from application.detection_configuration import DetectionConfiguration
from application.detection_dataset import DetectionDataset
from application.detection_evaluation import DetectionEvaluationResult
from application.detection_experiment import DetectionExperiment
from application.detection_metrics import DetectionEvaluationMetrics


@dataclass(frozen=True)
class EvaluationReport:
    result: Union[DetectionEvaluationResult, DetectionBenchmarkResult]
    metrics: Optional[DetectionEvaluationMetrics] = None
    experiment: Optional[DetectionExperiment] = None
    configuration: Optional[DetectionConfiguration] = None

    def __post_init__(self) -> None:
        if type(self.result) not in (DetectionEvaluationResult, DetectionBenchmarkResult):
            raise TypeError("result must be exactly a DetectionEvaluationResult or DetectionBenchmarkResult")
        if self.metrics is not None and type(self.metrics) is not DetectionEvaluationMetrics:
            raise TypeError("metrics must be exactly a DetectionEvaluationMetrics or None")
        if type(self.result) is DetectionBenchmarkResult and self.metrics is not None:
            raise ValueError("benchmark reports retain metrics only in their case results")
        if self.experiment is not None and type(self.experiment) is not DetectionExperiment:
            raise TypeError("experiment must be exactly a DetectionExperiment or None")
        if self.configuration is not None and type(self.configuration) is not DetectionConfiguration:
            raise TypeError("configuration must be exactly a DetectionConfiguration or None")
        if type(self.result) is DetectionBenchmarkResult and self.experiment is not None:
            if self.result.dataset != self.experiment.dataset:
                raise ValueError("experiment dataset must equal benchmark dataset")

    @property
    def dataset(self) -> Optional[DetectionDataset]:
        if type(self.result) is DetectionBenchmarkResult:
            return self.result.dataset
        return None if self.experiment is None else self.experiment.dataset

    @property
    def dataset_case_count(self) -> Optional[int]:
        if type(self.result) is DetectionBenchmarkResult:
            return self.result.total_case_count
        dataset = self.dataset
        return None if dataset is None else len(dataset.cases)
