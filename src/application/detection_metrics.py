from dataclasses import dataclass
from typing import Optional

from application.detection_evaluation import DetectionClassification, DetectionEvaluationEntry, DetectionEvaluationResult


@dataclass(frozen=True)
class DetectionMetrics:
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    unclassified_count: int = 0

    def __post_init__(self) -> None:
        for value in (self.true_positives, self.false_positives, self.false_negatives,
                      self.true_negatives, self.unclassified_count):
            if type(value) is not int:
                raise TypeError("metric counts must be exactly integers")
            if value < 0:
                raise ValueError("metric counts must be nonnegative")

    @property
    def precision(self) -> Optional[float]:
        denominator = self.true_positives + self.false_positives
        return None if denominator == 0 else self.true_positives / denominator

    @property
    def recall(self) -> Optional[float]:
        denominator = self.true_positives + self.false_negatives
        return None if denominator == 0 else self.true_positives / denominator

    @property
    def f1(self) -> Optional[float]:
        precision, recall = self.precision, self.recall
        if precision is None or recall is None or precision + recall == 0.0:
            return None
        return 2 * precision * recall / (precision + recall)

    @property
    def accuracy(self) -> Optional[float]:
        denominator = self.true_positives + self.false_positives + self.false_negatives + self.true_negatives
        return None if denominator == 0 else (self.true_positives + self.true_negatives) / denominator


@dataclass(frozen=True)
class DetectionEvaluationMetrics:
    packet_metrics: DetectionMetrics
    flow_metrics: DetectionMetrics

    def __post_init__(self) -> None:
        if type(self.packet_metrics) is not DetectionMetrics or type(self.flow_metrics) is not DetectionMetrics:
            raise TypeError("packet_metrics and flow_metrics must be exactly DetectionMetrics values")


def _aggregate(entries: tuple[DetectionEvaluationEntry, ...]) -> DetectionMetrics:
    counts = {classification: 0 for classification in DetectionClassification}
    unclassified = 0
    for entry in entries:
        if entry.classification is None:
            unclassified += 1
        else:
            counts[entry.classification] += 1
    return DetectionMetrics(
        counts[DetectionClassification.TRUE_POSITIVE],
        counts[DetectionClassification.FALSE_POSITIVE],
        counts[DetectionClassification.FALSE_NEGATIVE],
        counts[DetectionClassification.TRUE_NEGATIVE],
        unclassified,
    )


def calculate_detection_metrics(result: DetectionEvaluationResult) -> DetectionEvaluationMetrics:
    if type(result) is not DetectionEvaluationResult:
        raise TypeError("result must be exactly a DetectionEvaluationResult")
    return DetectionEvaluationMetrics(_aggregate(result.packet_evaluations), _aggregate(result.flow_evaluations))
