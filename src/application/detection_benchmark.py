from dataclasses import dataclass
from typing import Callable, Optional

from application.detection_dataset import DetectionDataset, DetectionDatasetCase
from application.detection_evaluation import DetectionEvaluationResult
from application.detection_metrics import DetectionEvaluationMetrics


@dataclass(frozen=True)
class DetectionBenchmarkCaseResult:
    case: DetectionDatasetCase
    evaluation: Optional[DetectionEvaluationResult] = None
    metrics: Optional[DetectionEvaluationMetrics] = None

    def __post_init__(self) -> None:
        if type(self.case) is not DetectionDatasetCase:
            raise TypeError("case must be exactly a DetectionDatasetCase")
        if self.evaluation is not None and type(self.evaluation) is not DetectionEvaluationResult:
            raise TypeError("evaluation must be exactly a DetectionEvaluationResult or None")
        if self.metrics is not None and type(self.metrics) is not DetectionEvaluationMetrics:
            raise TypeError("metrics must be exactly a DetectionEvaluationMetrics or None")


def _validate_case_result(result: DetectionBenchmarkCaseResult, case: DetectionDatasetCase) -> None:
    if type(result) is not DetectionBenchmarkCaseResult:
        raise TypeError("case result must be exactly a DetectionBenchmarkCaseResult")
    if result.case != case:
        raise ValueError("case result must correspond to the source dataset case")


@dataclass(frozen=True)
class DetectionBenchmarkResult:
    dataset: DetectionDataset
    case_results: tuple[DetectionBenchmarkCaseResult, ...]

    def __post_init__(self) -> None:
        if type(self.dataset) is not DetectionDataset:
            raise TypeError("dataset must be exactly a DetectionDataset")
        if type(self.case_results) is not tuple:
            raise TypeError("case_results must be exactly a tuple")
        if len(self.case_results) != len(self.dataset.cases):
            raise ValueError("case_results must contain one result per dataset case")
        for result, case in zip(self.case_results, self.dataset.cases):
            _validate_case_result(result, case)

    @property
    def dataset_name(self) -> str:
        return self.dataset.name

    @property
    def total_case_count(self) -> int:
        return len(self.case_results)


def run_detection_benchmark(
    dataset: DetectionDataset,
    operation: Callable[[DetectionDatasetCase], DetectionBenchmarkCaseResult],
) -> DetectionBenchmarkResult:
    if type(dataset) is not DetectionDataset:
        raise TypeError("dataset must be exactly a DetectionDataset")
    if not callable(operation):
        raise TypeError("operation must be callable")
    results = []
    for case in dataset.cases:
        result = operation(case)
        _validate_case_result(result, case)
        results.append(result)
    return DetectionBenchmarkResult(dataset, tuple(results))
