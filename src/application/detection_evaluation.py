from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional, Union

from analysis.flow_identity import FlowIdentity
from analysis.flow_observation_window import FlowObservationWindowKey
from application.detection_pipeline import DetectionPipelineResult
from detection.detection_finding import DetectionFinding
from detection.flow_volume_threshold import FlowVolumeThresholdConfiguration, FlowVolumeThresholdEvidence
from detection.packet_integrity import PacketIntegrityConfiguration, PacketIntegrityEvidence
from detection.tcp_control_threshold import TCPControlThresholdConfiguration, TCPControlThresholdEvidence


def _timestamp(value: datetime) -> None:
    if type(value) is not datetime or type(value.tzinfo) is not timezone:
        raise TypeError("timestamp must be an exact datetime with fixed UTC timezone")
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must have zero UTC offset")


def _index(value: int) -> None:
    if type(value) is not int:
        raise TypeError("index must be exactly an integer")
    if value < 0:
        raise ValueError("index must be nonnegative")


@dataclass(frozen=True)
class PacketDetectionIdentity:
    configuration: PacketIntegrityConfiguration
    packet_index: int
    captured_at: datetime
    capture_source: str
    link_type: Optional[int]
    captured_length: int
    original_length: Optional[int]

    def __post_init__(self) -> None:
        if type(self.configuration) is not PacketIntegrityConfiguration:
            raise TypeError("configuration must be exactly a PacketIntegrityConfiguration")
        _index(self.packet_index)
        _timestamp(self.captured_at)
        if type(self.capture_source) is not str:
            raise TypeError("capture_source must be exactly a string")
        if not self.capture_source.strip():
            raise ValueError("capture_source must not be blank")
        if self.link_type is not None:
            _index(self.link_type)
            if self.link_type > 65535:
                raise ValueError("link_type must be at most 65535")
        _index(self.captured_length)
        if self.original_length is not None:
            _index(self.original_length)
            if self.original_length < self.captured_length:
                raise ValueError("original_length must not be smaller than captured_length")


@dataclass(frozen=True)
class FlowDetectionIdentity:
    configuration: Union[FlowVolumeThresholdConfiguration, TCPControlThresholdConfiguration]
    window_key: FlowObservationWindowKey
    flow_identity: FlowIdentity
    first_captured_at: datetime
    last_captured_at: datetime

    def __post_init__(self) -> None:
        if type(self.configuration) not in (FlowVolumeThresholdConfiguration, TCPControlThresholdConfiguration):
            raise TypeError("configuration must be exactly a supported flow detector configuration")
        if type(self.window_key) is not FlowObservationWindowKey:
            raise TypeError("window_key must be exactly a FlowObservationWindowKey")
        if type(self.flow_identity) is not FlowIdentity:
            raise TypeError("flow_identity must be exactly a FlowIdentity")
        if type(self.configuration) is TCPControlThresholdConfiguration and self.flow_identity.protocol != 6:
            raise ValueError("TCP-control identity requires a TCP flow")
        _timestamp(self.first_captured_at)
        _timestamp(self.last_captured_at)
        if self.last_captured_at < self.first_captured_at:
            raise ValueError("last timestamp must not precede first timestamp")


_Identity = Union[PacketDetectionIdentity, FlowDetectionIdentity]


def detection_identity(finding: DetectionFinding, *, packet_index: Optional[int] = None) -> _Identity:
    if type(finding) is not DetectionFinding:
        raise TypeError("finding must be exactly a DetectionFinding")
    evidence = finding.raw_evidence
    if type(evidence) is PacketIntegrityEvidence:
        if packet_index is None:
            raise ValueError("packet findings require their packet result index")
        return PacketDetectionIdentity(
            evidence.configuration, packet_index, evidence.captured_at, evidence.capture_source.identifier,
            None if evidence.link_type is None else evidence.link_type.value,
            evidence.captured_length, evidence.original_length,
        )
    if type(evidence) not in (FlowVolumeThresholdEvidence, TCPControlThresholdEvidence):
        raise TypeError("finding must retain supported evidence")
    if packet_index is not None:
        raise ValueError("flow findings do not accept a packet index")
    return FlowDetectionIdentity(evidence.configuration, evidence.observation_window.key, evidence.identity,
                                 evidence.first_captured_at, evidence.last_captured_at)


@dataclass(frozen=True)
class ExpectedDetection:
    identity: _Identity
    positive: bool

    def __post_init__(self) -> None:
        if type(self.identity) not in (PacketDetectionIdentity, FlowDetectionIdentity):
            raise TypeError("identity must be exactly a packet or flow detection identity")
        if type(self.positive) is not bool:
            raise TypeError("positive must be exactly a bool")


def _tuple_of(values: tuple, element_type: type) -> None:
    if type(values) is not tuple or any(type(value) is not element_type for value in values):
        raise TypeError("collection must be exactly a tuple of the supported values")


@dataclass(frozen=True)
class ExpectedDetectionResult:
    packet_expectations: tuple[ExpectedDetection, ...]
    flow_expectations: tuple[ExpectedDetection, ...]

    def __post_init__(self) -> None:
        for expectations, identity_type in ((self.packet_expectations, PacketDetectionIdentity),
                                            (self.flow_expectations, FlowDetectionIdentity)):
            _tuple_of(expectations, ExpectedDetection)
            seen = {}
            for expectation in expectations:
                if type(expectation.identity) is not identity_type:
                    raise ValueError("expectation identity belongs to the other finding channel")
                previous = seen.get(expectation.identity)
                if previous is not None and previous != expectation.positive:
                    raise ValueError("contradictory expectations are not supported")
                seen[expectation.identity] = expectation.positive


class DetectionClassification(Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    TRUE_NEGATIVE = "true_negative"


def _classification(expectation: Optional[ExpectedDetection], finding: Optional[DetectionFinding]) -> Optional[DetectionClassification]:
    if finding is not None and finding.decision.value == "match":
        return DetectionClassification.TRUE_POSITIVE if expectation is not None and expectation.positive else DetectionClassification.FALSE_POSITIVE
    if expectation is not None and expectation.positive:
        return DetectionClassification.FALSE_NEGATIVE
    if expectation is not None and finding is not None and finding.decision.value == "no_match":
        return DetectionClassification.TRUE_NEGATIVE
    return None


@dataclass(frozen=True)
class DetectionEvaluationEntry:
    classification: Optional[DetectionClassification]
    expectation_index: Optional[int]
    expectation: Optional[ExpectedDetection]
    actual_index: Optional[int]
    finding: Optional[DetectionFinding]

    def __post_init__(self) -> None:
        if self.classification is not None and type(self.classification) is not DetectionClassification:
            raise TypeError("classification must be exactly a DetectionClassification or None")
        for index, value, value_type in ((self.expectation_index, self.expectation, ExpectedDetection),
                                          (self.actual_index, self.finding, DetectionFinding)):
            if value is None:
                if index is not None:
                    raise ValueError("absent value must have absent index")
            else:
                if type(value) is not value_type:
                    raise TypeError("entry contains an unsupported value")
                _index(index)
        if self.expectation is None and self.finding is None:
            raise ValueError("entry must retain an expectation or finding")
        if self.finding is not None and self.expectation is not None:
            packet_index = self.actual_index if type(self.expectation.identity) is PacketDetectionIdentity else None
            if detection_identity(self.finding, packet_index=packet_index) != self.expectation.identity:
                raise ValueError("entry finding must match expectation identity")
        if self.classification is not _classification(self.expectation, self.finding):
            raise ValueError("classification must agree with expectation and decision")


@dataclass(frozen=True)
class DetectionEvaluationResult:
    packet_evaluations: tuple[DetectionEvaluationEntry, ...]
    flow_evaluations: tuple[DetectionEvaluationEntry, ...]

    def __post_init__(self) -> None:
        for entries, identity_type in ((self.packet_evaluations, PacketDetectionIdentity),
                                       (self.flow_evaluations, FlowDetectionIdentity)):
            _tuple_of(entries, DetectionEvaluationEntry)
            for entry in entries:
                if entry.expectation is not None and type(entry.expectation.identity) is not identity_type:
                    raise ValueError("entry expectation belongs to the other finding channel")
                if entry.finding is not None:
                    is_packet = type(entry.finding.raw_evidence) is PacketIntegrityEvidence
                    if is_packet != (identity_type is PacketDetectionIdentity):
                        raise ValueError("entry finding belongs to the other finding channel")


def _indexable_identity(identity: _Identity) -> bool:
    return type(identity) is PacketDetectionIdentity or (
        type(identity.flow_identity.source_address) is bytes
        and type(identity.flow_identity.destination_address) is bytes
    )


def _match_findings(findings, expectations, identities, used=()):
    finding_indices = None
    if all(_indexable_identity(identity) for identity in identities) and all(
        _indexable_identity(expectation.identity) for expectation in expectations
    ):
        finding_indices = {}
        for actual_index, identity in enumerate(identities):
            key = (identity, findings[actual_index].decision.value)
            finding_indices.setdefault(key, deque()).append(actual_index)
    assignments = {}
    used = set(used)
    for phase in ("required", "opposite", "not_evaluable"):
        for expected_index, expectation in enumerate(expectations):
            if expected_index in used:
                continue
            required = "match" if expectation.positive else "no_match"
            decision = required if phase == "required" else ("no_match" if expectation.positive else "match")
            if phase == "not_evaluable":
                decision = phase
            if finding_indices is None:
                for actual_index, finding in enumerate(findings):
                    if actual_index not in assignments and finding.decision.value == decision and expectation.identity == identities[actual_index]:
                        assignments[actual_index] = expected_index
                        used.add(expected_index)
                        break
            else:
                candidates = finding_indices.get((expectation.identity, decision))
                if candidates:
                    actual_index = candidates.popleft()
                    assignments[actual_index] = expected_index
                    used.add(expected_index)
    return assignments, used


def _evaluate_channel(findings: tuple, expectations: tuple, packet: bool) -> tuple[DetectionEvaluationEntry, ...]:
    identities = []
    for index, finding in enumerate(findings):
        if (type(finding.raw_evidence) is PacketIntegrityEvidence) != packet:
            raise ValueError("pipeline finding belongs to the other finding channel")
        identities.append(detection_identity(finding, packet_index=index if packet else None))
    assignments, used = _match_findings(findings, expectations, identities)
    entries = []
    for actual_index, finding in enumerate(findings):
        expected_index = assignments.get(actual_index)
        expectation = None if expected_index is None else expectations[expected_index]
        entries.append(DetectionEvaluationEntry(_classification(expectation, finding), expected_index,
                                                expectation, actual_index, finding))
    for expected_index, expectation in enumerate(expectations):
        if expected_index not in used:
            entries.append(DetectionEvaluationEntry(_classification(expectation, None), expected_index,
                                                    expectation, None, None))
    return tuple(entries)


def evaluate_detection_result(actual: DetectionPipelineResult, expected: ExpectedDetectionResult) -> DetectionEvaluationResult:
    if type(actual) is not DetectionPipelineResult:
        raise TypeError("actual must be exactly a DetectionPipelineResult")
    if type(expected) is not ExpectedDetectionResult:
        raise TypeError("expected must be exactly an ExpectedDetectionResult")
    return DetectionEvaluationResult(
        _evaluate_channel(actual.packet_findings, expected.packet_expectations, True),
        _evaluate_channel(actual.flow_findings, expected.flow_expectations, False),
    )
