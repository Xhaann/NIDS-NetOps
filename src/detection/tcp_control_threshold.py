from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from analysis.flow_identity import FlowIdentity
from analysis.flow_observation_window import (
    FlowObservationWindow,
    FlowObservationWindowClosureReason,
)
from analysis.tcp_control_statistics import TCPControlStatistics


class TCPControlThresholdError(ValueError):
    pass


class TCPControlMetric(Enum):
    FORWARD_NS = "forward_ns_count"
    FORWARD_CWR = "forward_cwr_count"
    FORWARD_ECE = "forward_ece_count"
    FORWARD_URG = "forward_urg_count"
    FORWARD_ACK = "forward_ack_count"
    FORWARD_PSH = "forward_psh_count"
    FORWARD_RST = "forward_rst_count"
    FORWARD_SYN = "forward_syn_count"
    FORWARD_FIN = "forward_fin_count"
    FORWARD_SYN_ACK = "forward_syn_ack_count"
    REVERSE_NS = "reverse_ns_count"
    REVERSE_CWR = "reverse_cwr_count"
    REVERSE_ECE = "reverse_ece_count"
    REVERSE_URG = "reverse_urg_count"
    REVERSE_ACK = "reverse_ack_count"
    REVERSE_PSH = "reverse_psh_count"
    REVERSE_RST = "reverse_rst_count"
    REVERSE_SYN = "reverse_syn_count"
    REVERSE_FIN = "reverse_fin_count"
    REVERSE_SYN_ACK = "reverse_syn_ack_count"


class TCPControlThresholdComparison(Enum):
    GREATER_THAN = ">"


class TCPControlThresholdDecision(Enum):
    MATCH = "match"
    NO_MATCH = "no_match"
    NOT_EVALUABLE = "not_evaluable"


class TCPControlThresholdInterpretation(Enum):
    THRESHOLD_EXCEEDED = "Configured TCP control-counter threshold exceeded."
    THRESHOLD_NOT_EXCEEDED = (
        "Configured TCP control-counter threshold was not exceeded."
    )


@dataclass(frozen=True)
class TCPControlThresholdConfiguration:
    detector_id: str
    detector_version: str
    metric: TCPControlMetric
    threshold: int

    def __post_init__(self) -> None:
        for name, value in (
            ("detector_id", self.detector_id),
            ("detector_version", self.detector_version),
        ):
            if type(value) is not str:
                raise TypeError(f"{name} must be exactly a string")
            if not value.strip():
                raise TCPControlThresholdError(f"{name} must not be blank")
        if type(self.metric) is not TCPControlMetric:
            raise TypeError("metric must be exactly a TCPControlMetric")
        if type(self.threshold) is not int:
            raise TypeError("threshold must be exactly an integer")
        if self.threshold < 0:
            raise TCPControlThresholdError("threshold must be nonnegative")


def _tcp_control_statistics(window: FlowObservationWindow) -> TCPControlStatistics:
    if type(window) is not FlowObservationWindow:
        raise TypeError("window must be exactly a FlowObservationWindow")
    if window.closure_reason is None:
        raise TCPControlThresholdError("observation window must be closed")
    if window.identity.protocol != 6 or window.identity.ip_version not in (4, 6):
        raise TCPControlThresholdError("observation window must represent IPv4 or IPv6 TCP")
    statistics = window.coordinated_state.tcp_control_statistics
    if type(statistics) is not TCPControlStatistics:
        raise TCPControlThresholdError(
            "TCP observation window must contain TCP control statistics"
        )
    return statistics


def _observed_value(
    statistics: TCPControlStatistics,
    metric: TCPControlMetric,
) -> int:
    value = getattr(statistics, metric.value)
    if type(value) is not int or value < 0:
        raise TCPControlThresholdError(
            "selected TCP control counter must be a nonnegative integer"
        )
    return value


@dataclass(frozen=True)
class TCPControlThresholdEvidence:
    observation_window: FlowObservationWindow
    configuration: TCPControlThresholdConfiguration
    observed_value: int
    comparison_operator: TCPControlThresholdComparison

    def __post_init__(self) -> None:
        statistics = _tcp_control_statistics(self.observation_window)
        if type(self.configuration) is not TCPControlThresholdConfiguration:
            raise TypeError(
                "configuration must be exactly a TCPControlThresholdConfiguration"
            )
        if type(self.comparison_operator) is not TCPControlThresholdComparison:
            raise TypeError(
                "comparison_operator must be exactly a TCPControlThresholdComparison"
            )
        if self.comparison_operator is not TCPControlThresholdComparison.GREATER_THAN:
            raise TCPControlThresholdError("comparison operator must be greater than")
        expected = _observed_value(statistics, self.configuration.metric)
        if type(self.observed_value) is not int or self.observed_value != expected:
            raise TCPControlThresholdError(
                "observed_value must equal the selected TCP control counter"
            )

    @property
    def tcp_control_statistics(self) -> TCPControlStatistics:
        statistics = self.observation_window.coordinated_state.tcp_control_statistics
        if type(statistics) is not TCPControlStatistics:
            raise TCPControlThresholdError(
                "evidence window must contain TCP control statistics"
            )
        return statistics

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
            raise TCPControlThresholdError("evidence observation window must be closed")
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
    def selected_metric(self) -> TCPControlMetric:
        return self.configuration.metric

    @property
    def threshold(self) -> int:
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
        return self.tcp_control_statistics.packet_count

    @property
    def forward_packet_count(self) -> int:
        return self.tcp_control_statistics.forward_packet_count

    @property
    def reverse_packet_count(self) -> int:
        return self.tcp_control_statistics.reverse_packet_count


@dataclass(frozen=True)
class TCPControlThresholdEvaluation:
    decision: TCPControlThresholdDecision
    raw_evidence: TCPControlThresholdEvidence
    security_interpretation: TCPControlThresholdInterpretation

    def __post_init__(self) -> None:
        if type(self.decision) is not TCPControlThresholdDecision:
            raise TypeError("decision must be exactly a TCPControlThresholdDecision")
        if type(self.raw_evidence) is not TCPControlThresholdEvidence:
            raise TypeError("raw_evidence must be exactly a TCPControlThresholdEvidence")
        if type(self.security_interpretation) is not TCPControlThresholdInterpretation:
            raise TypeError(
                "security_interpretation must be exactly a TCPControlThresholdInterpretation"
            )
        if self.raw_evidence.observed_value > self.raw_evidence.threshold:
            expected_decision = TCPControlThresholdDecision.MATCH
            expected_interpretation = (
                TCPControlThresholdInterpretation.THRESHOLD_EXCEEDED
            )
        else:
            expected_decision = TCPControlThresholdDecision.NO_MATCH
            expected_interpretation = (
                TCPControlThresholdInterpretation.THRESHOLD_NOT_EXCEEDED
            )
        if self.decision is not expected_decision:
            raise TCPControlThresholdError(
                "decision must match the configured threshold predicate"
            )
        if self.security_interpretation is not expected_interpretation:
            raise TCPControlThresholdError(
                "security interpretation must match the detector decision"
            )


def evaluate_tcp_control_threshold(
    window: FlowObservationWindow,
    configuration: TCPControlThresholdConfiguration,
) -> TCPControlThresholdEvaluation:
    statistics = _tcp_control_statistics(window)
    if type(configuration) is not TCPControlThresholdConfiguration:
        raise TypeError(
            "configuration must be exactly a TCPControlThresholdConfiguration"
        )
    observed = _observed_value(statistics, configuration.metric)
    if observed > configuration.threshold:
        decision = TCPControlThresholdDecision.MATCH
        interpretation = TCPControlThresholdInterpretation.THRESHOLD_EXCEEDED
    else:
        decision = TCPControlThresholdDecision.NO_MATCH
        interpretation = TCPControlThresholdInterpretation.THRESHOLD_NOT_EXCEEDED
    evidence = TCPControlThresholdEvidence(
        window,
        configuration,
        observed,
        TCPControlThresholdComparison.GREATER_THAN,
    )
    return TCPControlThresholdEvaluation(decision, evidence, interpretation)
