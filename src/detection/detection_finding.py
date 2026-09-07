from dataclasses import dataclass
from typing import Union

from detection.flow_volume_threshold import (
    FlowVolumeThresholdDecision,
    FlowVolumeThresholdEvaluation,
    FlowVolumeThresholdEvidence,
    FlowVolumeThresholdInterpretation,
)
from detection.packet_integrity import (
    PacketIntegrityDecision,
    PacketIntegrityEvaluation,
    PacketIntegrityEvidence,
    PacketIntegrityInterpretation,
)
from detection.tcp_control_threshold import (
    TCPControlThresholdDecision,
    TCPControlThresholdEvaluation,
    TCPControlThresholdEvidence,
    TCPControlThresholdInterpretation,
)


class DetectionFindingError(ValueError):
    pass


_DetectorDecision = Union[
    PacketIntegrityDecision,
    FlowVolumeThresholdDecision,
    TCPControlThresholdDecision,
]

_DetectorEvidence = Union[
    PacketIntegrityEvidence,
    FlowVolumeThresholdEvidence,
    TCPControlThresholdEvidence,
]

_DetectorInterpretation = Union[
    PacketIntegrityInterpretation,
    FlowVolumeThresholdInterpretation,
    TCPControlThresholdInterpretation,
]

_DetectorEvaluation = Union[
    PacketIntegrityEvaluation,
    FlowVolumeThresholdEvaluation,
    TCPControlThresholdEvaluation,
]


def _is_supported_decision(decision: _DetectorDecision) -> bool:
    return decision in (
        PacketIntegrityDecision.MATCH,
        PacketIntegrityDecision.NO_MATCH,
        PacketIntegrityDecision.NOT_EVALUABLE,
        FlowVolumeThresholdDecision.MATCH,
        FlowVolumeThresholdDecision.NO_MATCH,
        FlowVolumeThresholdDecision.NOT_EVALUABLE,
        TCPControlThresholdDecision.MATCH,
        TCPControlThresholdDecision.NO_MATCH,
        TCPControlThresholdDecision.NOT_EVALUABLE,
    )


def _validate_family(
    decision: _DetectorDecision,
    raw_evidence: _DetectorEvidence,
    security_interpretation: _DetectorInterpretation,
) -> None:
    if type(raw_evidence) is PacketIntegrityEvidence:
        if type(decision) is not PacketIntegrityDecision:
            raise DetectionFindingError(
                "packet-integrity evidence requires a packet-integrity decision"
            )
        if type(security_interpretation) is not PacketIntegrityInterpretation:
            raise DetectionFindingError(
                "packet-integrity evidence requires a packet-integrity interpretation"
            )
        if raw_evidence.decision is not decision:
            raise DetectionFindingError(
                "decision must match the packet-integrity evidence decision"
            )
        expected = {
            PacketIntegrityDecision.MATCH: (
                PacketIntegrityInterpretation.STRUCTURAL_OR_INTEGRITY_VIOLATION_OBSERVED
            ),
            PacketIntegrityDecision.NO_MATCH: (
                PacketIntegrityInterpretation.NO_INTEGRITY_OR_STRUCTURAL_VIOLATION
            ),
            PacketIntegrityDecision.NOT_EVALUABLE: (
                PacketIntegrityInterpretation.ANALYSIS_NOT_EVALUABLE
            ),
        }[decision]
    elif type(raw_evidence) is FlowVolumeThresholdEvidence:
        if type(decision) is not FlowVolumeThresholdDecision:
            raise DetectionFindingError(
                "flow-volume evidence requires a flow-volume decision"
            )
        if type(security_interpretation) is not FlowVolumeThresholdInterpretation:
            raise DetectionFindingError(
                "flow-volume evidence requires a flow-volume interpretation"
            )
        expected = {
            FlowVolumeThresholdDecision.MATCH: (
                FlowVolumeThresholdInterpretation.THRESHOLD_EXCEEDED
            ),
            FlowVolumeThresholdDecision.NO_MATCH: (
                FlowVolumeThresholdInterpretation.THRESHOLD_NOT_EXCEEDED
            ),
            FlowVolumeThresholdDecision.NOT_EVALUABLE: (
                FlowVolumeThresholdInterpretation.METRIC_NOT_EVALUABLE
            ),
        }[decision]
    elif type(raw_evidence) is TCPControlThresholdEvidence:
        if type(decision) is not TCPControlThresholdDecision:
            raise DetectionFindingError(
                "TCP-control evidence requires a TCP-control decision"
            )
        if type(security_interpretation) is not TCPControlThresholdInterpretation:
            raise DetectionFindingError(
                "TCP-control evidence requires a TCP-control interpretation"
            )
        if decision is TCPControlThresholdDecision.MATCH:
            expected = TCPControlThresholdInterpretation.THRESHOLD_EXCEEDED
        elif decision is TCPControlThresholdDecision.NO_MATCH:
            expected = TCPControlThresholdInterpretation.THRESHOLD_NOT_EXCEEDED
        else:
            raise DetectionFindingError(
                "TCP-control evidence has no not-evaluable interpretation"
            )
    else:
        raise TypeError("raw_evidence must be exactly a supported detector evidence")
    if security_interpretation is not expected:
        raise DetectionFindingError(
            "security interpretation must match the detector decision"
        )


@dataclass(frozen=True)
class DetectionFinding:
    detector_id: str
    detector_version: str
    decision: _DetectorDecision
    raw_evidence: _DetectorEvidence
    security_interpretation: _DetectorInterpretation

    def __post_init__(self) -> None:
        for name, value in (
            ("detector_id", self.detector_id),
            ("detector_version", self.detector_version),
        ):
            if type(value) is not str:
                raise TypeError(f"{name} must be exactly a string")
            if not value.strip():
                raise DetectionFindingError(f"{name} must not be blank")
        if type(self.decision) not in (
            PacketIntegrityDecision,
            FlowVolumeThresholdDecision,
            TCPControlThresholdDecision,
        ):
            raise TypeError("decision must be exactly a supported detector decision")
        if not _is_supported_decision(self.decision):
            raise DetectionFindingError("decision must be an approved semantic member")
        if type(self.raw_evidence) not in (
            PacketIntegrityEvidence,
            FlowVolumeThresholdEvidence,
            TCPControlThresholdEvidence,
        ):
            raise TypeError("raw_evidence must be exactly a supported detector evidence")
        if type(self.security_interpretation) not in (
            PacketIntegrityInterpretation,
            FlowVolumeThresholdInterpretation,
            TCPControlThresholdInterpretation,
        ):
            raise TypeError(
                "security_interpretation must be exactly a supported detector "
                "interpretation"
            )
        if self.raw_evidence.detector_id != self.detector_id:
            raise DetectionFindingError(
                "detector_id must match the detector evidence"
            )
        if self.raw_evidence.detector_version != self.detector_version:
            raise DetectionFindingError(
                "detector_version must match the detector evidence"
            )
        _validate_family(
            self.decision,
            self.raw_evidence,
            self.security_interpretation,
        )


def detection_finding_from_evaluation(
    evaluation: _DetectorEvaluation,
) -> DetectionFinding:
    if type(evaluation) not in (
        PacketIntegrityEvaluation,
        FlowVolumeThresholdEvaluation,
        TCPControlThresholdEvaluation,
    ):
        raise TypeError("evaluation must be exactly a supported detector evaluation")
    return DetectionFinding(
        detector_id=evaluation.raw_evidence.detector_id,
        detector_version=evaluation.raw_evidence.detector_version,
        decision=evaluation.decision,
        raw_evidence=evaluation.raw_evidence,
        security_interpretation=evaluation.security_interpretation,
    )
