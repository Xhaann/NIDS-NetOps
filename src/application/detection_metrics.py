from dataclasses import dataclass
from sys import float_info
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
        numerator = 2 * precision * recall
        if numerator < float_info.min:
            doubled_positives = 2 * self.true_positives
            return doubled_positives / (doubled_positives + self.false_positives + self.false_negatives)
        return numerator / (precision + recall)

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


class _MetricCounts:
    def __init__(self) -> None:
        self.counts = {classification: 0 for classification in DetectionClassification}
        self.unclassified = 0

    def record(self, entry: DetectionEvaluationEntry) -> None:
        if entry.classification is None:
            self.unclassified += 1
        else:
            self.counts[entry.classification] += 1

    def finish(self) -> DetectionMetrics:
        return DetectionMetrics(
            self.counts[DetectionClassification.TRUE_POSITIVE],
            self.counts[DetectionClassification.FALSE_POSITIVE],
            self.counts[DetectionClassification.FALSE_NEGATIVE],
            self.counts[DetectionClassification.TRUE_NEGATIVE],
            self.unclassified,
        )


def _aggregate(entries: tuple[DetectionEvaluationEntry, ...]) -> DetectionMetrics:
    counts = _MetricCounts()
    for entry in entries:
        counts.record(entry)
    return counts.finish()


def calculate_detection_metrics(result: DetectionEvaluationResult) -> DetectionEvaluationMetrics:
    if type(result) is not DetectionEvaluationResult:
        raise TypeError("result must be exactly a DetectionEvaluationResult")
    return DetectionEvaluationMetrics(_aggregate(result.packet_evaluations), _aggregate(result.flow_evaluations))
