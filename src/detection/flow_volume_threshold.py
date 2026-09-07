from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from math import isfinite
from typing import Optional, Union

from analysis.flow_feature_snapshot import FlowFeatureSnapshot
from analysis.flow_identity import FlowIdentity
from analysis.flow_observation_window import (
    FlowObservationWindow,
    FlowObservationWindowClosureReason,
)


class FlowVolumeThresholdError(ValueError):
    pass


class FlowVolumeMetric(Enum):
    PACKET_COUNT = "packet_count"
    CAPTURED_BYTES = "captured_bytes"
    ORIGINAL_BYTES = "original_bytes"
    FORWARD_PACKET_COUNT = "forward_packet_count"
    REVERSE_PACKET_COUNT = "reverse_packet_count"
    FORWARD_CAPTURED_BYTES = "forward_captured_bytes"
    REVERSE_CAPTURED_BYTES = "reverse_captured_bytes"
    FORWARD_ORIGINAL_BYTES = "forward_original_bytes"
    REVERSE_ORIGINAL_BYTES = "reverse_original_bytes"
    PACKETS_PER_SECOND = "packets_per_second"
    CAPTURED_BYTES_PER_SECOND = "captured_bytes_per_second"
    ORIGINAL_BYTES_PER_SECOND = "original_bytes_per_second"


class FlowVolumeThresholdComparison(Enum):
    GREATER_THAN = ">"


class FlowVolumeThresholdDecision(Enum):
    MATCH = "match"
    NO_MATCH = "no_match"
    NOT_EVALUABLE = "not_evaluable"


class FlowVolumeThresholdInterpretation(Enum):
    THRESHOLD_EXCEEDED = "Configured flow-volume or flow-rate threshold exceeded."
    THRESHOLD_NOT_EXCEEDED = "Configured threshold was not exceeded."
    METRIC_NOT_EVALUABLE = (
        "Configured metric could not be evaluated for this observation window."
    )


_RATE_METRICS = (
    FlowVolumeMetric.PACKETS_PER_SECOND,
    FlowVolumeMetric.CAPTURED_BYTES_PER_SECOND,
    FlowVolumeMetric.ORIGINAL_BYTES_PER_SECOND,
)


@dataclass(frozen=True)
class FlowVolumeThresholdConfiguration:
    detector_id: str
    detector_version: str
    metric: FlowVolumeMetric
    threshold: Union[int, float]

    def __post_init__(self) -> None:
        for name, value in (
            ("detector_id", self.detector_id),
            ("detector_version", self.detector_version),
        ):
            if type(value) is not str:
                raise TypeError(f"{name} must be exactly a string")
            if not value.strip():
                raise FlowVolumeThresholdError(f"{name} must not be blank")
        if type(self.metric) is not FlowVolumeMetric:
            raise TypeError("metric must be exactly a FlowVolumeMetric")
        if self.metric in _RATE_METRICS:
            if type(self.threshold) is not float:
                raise TypeError("rate threshold must be exactly a float")
            if not isfinite(self.threshold) or self.threshold < 0.0:
                raise FlowVolumeThresholdError(
                    "rate threshold must be finite and nonnegative"
                )
        else:
            if type(self.threshold) is not int:
                raise TypeError("count and byte threshold must be exactly an integer")
            if self.threshold < 0:
                raise FlowVolumeThresholdError(
                    "count and byte threshold must be nonnegative"
                )


def _validate_snapshot(snapshot: FlowFeatureSnapshot) -> None:
    if type(snapshot) is not FlowFeatureSnapshot:
        raise TypeError("snapshot must be exactly a FlowFeatureSnapshot")
    if snapshot.observation_window.closure_reason is None:
        raise FlowVolumeThresholdError("snapshot observation window must be closed")
    if snapshot.identity.protocol not in (6, 17):
        raise FlowVolumeThresholdError("snapshot must represent IPv4 TCP or UDP")


def _observed_value(
    snapshot: FlowFeatureSnapshot,
    metric: FlowVolumeMetric,
) -> Optional[Union[int, float]]:
    if metric in _RATE_METRICS:
        rates = snapshot.flow_rate_features
        if rates is None:
            return None
        value = getattr(rates, metric.value)
        if type(value) is not float or not isfinite(value) or value < 0.0:
            raise FlowVolumeThresholdError(
                "snapshot rate metric must be a finite nonnegative float"
            )
        return value
    value = getattr(snapshot.flow_volume_features, metric.value)
    if type(value) is not int or value < 0:
        raise FlowVolumeThresholdError(
            "snapshot count and byte metric must be a nonnegative integer"
        )
    return value


@dataclass(frozen=True)
class FlowVolumeThresholdEvidence:
    snapshot: FlowFeatureSnapshot
    configuration: FlowVolumeThresholdConfiguration
    observed_value: Optional[Union[int, float]]
    comparison_operator: FlowVolumeThresholdComparison

    def __post_init__(self) -> None:
        _validate_snapshot(self.snapshot)
        if type(self.configuration) is not FlowVolumeThresholdConfiguration:
            raise TypeError(
                "configuration must be exactly a FlowVolumeThresholdConfiguration"
            )
        if type(self.comparison_operator) is not FlowVolumeThresholdComparison:
            raise TypeError(
                "comparison_operator must be exactly a FlowVolumeThresholdComparison"
            )
        if self.comparison_operator is not FlowVolumeThresholdComparison.GREATER_THAN:
            raise FlowVolumeThresholdError("comparison operator must be greater than")
        expected = _observed_value(self.snapshot, self.configuration.metric)
        if (
            self.observed_value != expected
            or type(self.observed_value) is not type(expected)
        ):
            raise FlowVolumeThresholdError(
                "observed_value must equal the selected snapshot metric"
            )

    @property
    def observation_window(self) -> FlowObservationWindow:
        return self.snapshot.observation_window

    @property
    def capture_session_id(self) -> str:
        return self.observation_window.key.capture_session_id

    @property
    def sequence_number(self) -> int:
        return self.observation_window.key.sequence_number

    @property
    def closure_reason(self) -> FlowObservationWindowClosureReason:
        closure_reason = self.observation_window.closure_reason
        if closure_reason is None:
            raise FlowVolumeThresholdError("evidence observation window must be closed")
        return closure_reason

    @property
    def identity(self) -> FlowIdentity:
        return self.observation_window.identity

    @property
    def first_captured_at(self) -> datetime:
        return self.observation_window.first_captured_at

    @property
    def last_captured_at(self) -> datetime:
        return self.observation_window.last_captured_at

    @property
    def selected_metric(self) -> FlowVolumeMetric:
        return self.configuration.metric

    @property
    def threshold(self) -> Union[int, float]:
        return self.configuration.threshold

    @property
    def detector_id(self) -> str:
        return self.configuration.detector_id

    @property
    def detector_version(self) -> str:
        return self.configuration.detector_version

    @property
    def protocol(self) -> int:
        return self.identity.protocol

    @property
    def total_packet_count(self) -> int:
        return self.snapshot.flow_volume_features.packet_count

    @property
    def forward_packet_count(self) -> int:
        return self.snapshot.flow_volume_features.forward_packet_count

    @property
    def reverse_packet_count(self) -> int:
        return self.snapshot.flow_volume_features.reverse_packet_count

    @property
    def captured_byte_total(self) -> int:
        return self.snapshot.flow_volume_features.captured_bytes

    @property
    def original_byte_total(self) -> int:
        return self.snapshot.flow_volume_features.original_bytes


@dataclass(frozen=True)
class FlowVolumeThresholdEvaluation:
    decision: FlowVolumeThresholdDecision
    raw_evidence: FlowVolumeThresholdEvidence
    security_interpretation: FlowVolumeThresholdInterpretation

    def __post_init__(self) -> None:
        if type(self.decision) is not FlowVolumeThresholdDecision:
            raise TypeError("decision must be exactly a FlowVolumeThresholdDecision")
        if type(self.raw_evidence) is not FlowVolumeThresholdEvidence:
            raise TypeError("raw_evidence must be exactly a FlowVolumeThresholdEvidence")
        if type(self.security_interpretation) is not FlowVolumeThresholdInterpretation:
            raise TypeError(
                "security_interpretation must be exactly a FlowVolumeThresholdInterpretation"
            )
        observed = self.raw_evidence.observed_value
        threshold = self.raw_evidence.threshold
        if observed is None:
            expected_decision = FlowVolumeThresholdDecision.NOT_EVALUABLE
            expected_interpretation = (
                FlowVolumeThresholdInterpretation.METRIC_NOT_EVALUABLE
            )
        elif observed > threshold:
            expected_decision = FlowVolumeThresholdDecision.MATCH
            expected_interpretation = FlowVolumeThresholdInterpretation.THRESHOLD_EXCEEDED
        else:
            expected_decision = FlowVolumeThresholdDecision.NO_MATCH
            expected_interpretation = (
                FlowVolumeThresholdInterpretation.THRESHOLD_NOT_EXCEEDED
            )
        if self.decision is not expected_decision:
            raise FlowVolumeThresholdError(
                "decision must match the configured threshold predicate"
            )
        if self.security_interpretation is not expected_interpretation:
            raise FlowVolumeThresholdError(
                "security interpretation must match the detector decision"
            )


def evaluate_flow_volume_threshold(
    snapshot: FlowFeatureSnapshot,
    configuration: FlowVolumeThresholdConfiguration,
) -> FlowVolumeThresholdEvaluation:
    _validate_snapshot(snapshot)
    if type(configuration) is not FlowVolumeThresholdConfiguration:
        raise TypeError(
            "configuration must be exactly a FlowVolumeThresholdConfiguration"
        )
    observed = _observed_value(snapshot, configuration.metric)
    if observed is None:
        decision = FlowVolumeThresholdDecision.NOT_EVALUABLE
        interpretation = FlowVolumeThresholdInterpretation.METRIC_NOT_EVALUABLE
    elif observed > configuration.threshold:
        decision = FlowVolumeThresholdDecision.MATCH
        interpretation = FlowVolumeThresholdInterpretation.THRESHOLD_EXCEEDED
    else:
        decision = FlowVolumeThresholdDecision.NO_MATCH
        interpretation = FlowVolumeThresholdInterpretation.THRESHOLD_NOT_EXCEEDED
    evidence = FlowVolumeThresholdEvidence(
        snapshot,
        configuration,
        observed,
        FlowVolumeThresholdComparison.GREATER_THAN,
    )
    return FlowVolumeThresholdEvaluation(decision, evidence, interpretation)
