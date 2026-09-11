from dataclasses import dataclass
from math import fsum, isfinite
from statistics import median
from time import perf_counter
from typing import Callable, Optional

from application.detection_configuration import DetectionConfiguration
from application.detection_dataset import DetectionDataset
from application.detection_experiment import DetectionExperiment


@dataclass(frozen=True)
class PerformanceBenchmarkConfiguration:
    operation_id: str
    operation_version: str
    measured_executions: int
    warmup_executions: int = 0
    dataset: Optional[DetectionDataset] = None
    experiment: Optional[DetectionExperiment] = None
    detection_configuration: Optional[DetectionConfiguration] = None

    def __post_init__(self) -> None:
        for name, value in (("operation_id", self.operation_id), ("operation_version", self.operation_version)):
            if type(value) is not str:
                raise TypeError(f"{name} must be exactly a string")
            if not value.strip():
                raise ValueError(f"{name} must not be blank")
        for name, value, minimum in (("measured_executions", self.measured_executions, 1),
                                     ("warmup_executions", self.warmup_executions, 0)):
            if type(value) is not int:
                raise TypeError(f"{name} must be exactly an integer")
            if value < minimum:
                raise ValueError(f"{name} must be at least {minimum}")
        if self.dataset is not None and type(self.dataset) is not DetectionDataset:
            raise TypeError("dataset must be exactly a DetectionDataset or None")
        if self.experiment is not None:
            if type(self.experiment) is not DetectionExperiment:
                raise TypeError("experiment must be exactly a DetectionExperiment or None")
            if (self.operation_id, self.operation_version) != (
                self.experiment.benchmark_operation_id, self.experiment.benchmark_operation_version
            ):
                raise ValueError("experiment operation identity and version must match")
            if self.dataset is not None and self.dataset != self.experiment.dataset:
                raise ValueError("dataset must equal experiment dataset")
        if self.detection_configuration is not None and type(self.detection_configuration) is not DetectionConfiguration:
            raise TypeError("detection_configuration must be exactly a DetectionConfiguration or None")

    @property
    def total_executions(self) -> int:
        return self.warmup_executions + self.measured_executions


@dataclass(frozen=True)
class PerformanceBenchmarkResult:
    configuration: PerformanceBenchmarkConfiguration
    elapsed_seconds: tuple[float, ...]

    def __post_init__(self) -> None:
        if type(self.configuration) is not PerformanceBenchmarkConfiguration:
            raise TypeError("configuration must be exactly a PerformanceBenchmarkConfiguration")
        if type(self.elapsed_seconds) is not tuple:
            raise TypeError("elapsed_seconds must be exactly a tuple")
        if len(self.elapsed_seconds) != self.configuration.measured_executions:
            raise ValueError("elapsed_seconds must contain one observation per measured execution")
        for value in self.elapsed_seconds:
            if type(value) is not float:
                raise TypeError("elapsed observations must be exactly floats")
            if not isfinite(value) or value < 0.0:
                raise ValueError("elapsed observations must be finite and nonnegative")
        fsum(self.elapsed_seconds)

    @property
    def minimum_elapsed_seconds(self) -> float:
        return min(self.elapsed_seconds)

    @property
    def maximum_elapsed_seconds(self) -> float:
        return max(self.elapsed_seconds)

    @property
    def total_elapsed_seconds(self) -> float:
        return fsum(self.elapsed_seconds)

    @property
    def mean_elapsed_seconds(self) -> float:
        return self.total_elapsed_seconds / self.configuration.measured_executions

    @property
    def median_elapsed_seconds(self) -> float:
        return median(self.elapsed_seconds)

    @property
    def dataset(self) -> Optional[DetectionDataset]:
        if self.configuration.dataset is not None:
            return self.configuration.dataset
        experiment = self.configuration.experiment
        return None if experiment is None else experiment.dataset

    @property
    def dataset_case_count(self) -> Optional[int]:
        dataset = self.dataset
        return None if dataset is None else len(dataset.cases)


def _read_clock(clock: Callable[[], float], previous: Optional[float]) -> float:
    value = clock()
    if type(value) is not float:
        raise TypeError("clock readings must be exactly floats")
    if not isfinite(value):
        raise ValueError("clock readings must be finite")
    if previous is not None and value < previous:
        raise ValueError("clock readings must be nondecreasing")
    return value


def run_performance_benchmark(
    operation: Callable[[], object],
    *,
    configuration: PerformanceBenchmarkConfiguration,
    clock: Optional[Callable[[], float]] = None,
) -> PerformanceBenchmarkResult:
    if type(configuration) is not PerformanceBenchmarkConfiguration:
        raise TypeError("configuration must be exactly a PerformanceBenchmarkConfiguration")
    if not callable(operation):
        raise TypeError("operation must be callable")
    timer = perf_counter if clock is None else clock
    if not callable(timer):
        raise TypeError("clock must be callable or None")
    for _ in range(configuration.warmup_executions):
        operation()
    observations = []
    previous = None
    for _ in range(configuration.measured_executions):
        start = _read_clock(timer, previous)
        output = operation()
        end = _read_clock(timer, start)
        elapsed = end - start
        if not isfinite(elapsed):
            raise ValueError("elapsed observation must be finite")
        del output
        observations.append(elapsed)
        previous = end
    return PerformanceBenchmarkResult(configuration, tuple(observations))
