from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

from analysis.packet_analysis import PacketAnalysis
from analysis.packet_analysis_outcome import (
    PacketAnalysisFailureClassification,
    PacketAnalysisOutcome,
)
from capture.packet_observation import CaptureSource, LinkType, PacketObservation


class PacketIntegrityError(ValueError):
    pass


class PacketIntegrityDecision(Enum):
    MATCH = "match"
    NO_MATCH = "no_match"
    NOT_EVALUABLE = "not_evaluable"


class PacketIntegrityInterpretation(Enum):
    NO_INTEGRITY_OR_STRUCTURAL_VIOLATION = (
        "No supported integrity or structural violation was observed."
    )
    STRUCTURAL_OR_INTEGRITY_VIOLATION_OBSERVED = (
        "A supported structural or integrity violation was observed."
    )
    ANALYSIS_NOT_EVALUABLE = (
        "The packet analysis outcome was incomplete or unsupported."
    )


@dataclass(frozen=True)
class PacketIntegrityConfiguration:
    detector_id: str
    detector_version: str

    def __post_init__(self) -> None:
        for name, value in (
            ("detector_id", self.detector_id),
            ("detector_version", self.detector_version),
        ):
            if type(value) is not str:
                raise TypeError(f"{name} must be exactly a string")
            if not value.strip():
                raise PacketIntegrityError(f"{name} must not be blank")


def _decision_for(outcome: PacketAnalysisOutcome) -> PacketIntegrityDecision:
    if outcome.analysis is not None:
        return PacketIntegrityDecision.NO_MATCH
    if outcome.failure_classification in (
        PacketAnalysisFailureClassification.STRUCTURAL_FAILURE,
        PacketAnalysisFailureClassification.INTEGRITY_FAILURE,
    ):
        return PacketIntegrityDecision.MATCH
    if outcome.failure_classification in (
        PacketAnalysisFailureClassification.INCOMPLETE,
        PacketAnalysisFailureClassification.UNSUPPORTED,
    ):
        return PacketIntegrityDecision.NOT_EVALUABLE
    raise PacketIntegrityError("outcome does not represent a supported analytical state")


def _interpretation_for(
    decision: PacketIntegrityDecision,
) -> PacketIntegrityInterpretation:
    if decision is PacketIntegrityDecision.MATCH:
        return PacketIntegrityInterpretation.STRUCTURAL_OR_INTEGRITY_VIOLATION_OBSERVED
    if decision is PacketIntegrityDecision.NO_MATCH:
        return PacketIntegrityInterpretation.NO_INTEGRITY_OR_STRUCTURAL_VIOLATION
    if decision is PacketIntegrityDecision.NOT_EVALUABLE:
        return PacketIntegrityInterpretation.ANALYSIS_NOT_EVALUABLE
    raise PacketIntegrityError("decision does not represent a supported detector state")


@dataclass(frozen=True)
class PacketIntegrityEvidence:
    outcome: PacketAnalysisOutcome
    configuration: PacketIntegrityConfiguration

    def __post_init__(self) -> None:
        if type(self.outcome) is not PacketAnalysisOutcome:
            raise TypeError("outcome must be exactly a PacketAnalysisOutcome")
        if type(self.configuration) is not PacketIntegrityConfiguration:
            raise TypeError(
                "configuration must be exactly a PacketIntegrityConfiguration"
            )

    @property
    def observation(self) -> PacketObservation:
        return self.outcome.observation

    @property
    def captured_at(self) -> datetime:
        return self.observation.captured_at

    @property
    def capture_source(self) -> CaptureSource:
        return self.observation.source

    @property
    def link_type(self) -> Optional[LinkType]:
        return self.observation.link_type

    @property
    def captured_length(self) -> int:
        return self.observation.captured_length

    @property
    def original_length(self) -> Optional[int]:
        return self.observation.original_length

    @property
    def analysis(self) -> Optional[PacketAnalysis]:
        return self.outcome.analysis

    @property
    def failure_classification(
        self,
    ) -> Optional[PacketAnalysisFailureClassification]:
        return self.outcome.failure_classification

    @property
    def failure_description(self) -> Optional[str]:
        return self.outcome.failure_description

    @property
    def detector_id(self) -> str:
        return self.configuration.detector_id

    @property
    def detector_version(self) -> str:
        return self.configuration.detector_version

    @property
    def decision(self) -> PacketIntegrityDecision:
        return _decision_for(self.outcome)

    @property
    def protocol(self) -> Optional[int]:
        if self.analysis is None:
            return None
        if self.analysis.ipv4 is not None:
            return self.analysis.ipv4.protocol
        chain = self.analysis.ipv6_extension_headers
        return None if chain is None else chain.terminating_next_header


@dataclass(frozen=True)
class PacketIntegrityEvaluation:
    decision: PacketIntegrityDecision
    raw_evidence: PacketIntegrityEvidence
    security_interpretation: PacketIntegrityInterpretation

    def __post_init__(self) -> None:
        if type(self.decision) is not PacketIntegrityDecision:
            raise TypeError("decision must be exactly a PacketIntegrityDecision")
        if type(self.raw_evidence) is not PacketIntegrityEvidence:
            raise TypeError("raw_evidence must be exactly a PacketIntegrityEvidence")
        if type(self.security_interpretation) is not PacketIntegrityInterpretation:
            raise TypeError(
                "security_interpretation must be exactly a "
                "PacketIntegrityInterpretation"
            )
        if self.decision is not self.raw_evidence.decision:
            raise PacketIntegrityError(
                "decision must match the packet-analysis outcome predicate"
            )
        if self.security_interpretation is not _interpretation_for(self.decision):
            raise PacketIntegrityError(
                "security interpretation must match the detector decision"
            )


def evaluate_packet_integrity(
    outcome: PacketAnalysisOutcome,
    configuration: PacketIntegrityConfiguration,
) -> PacketIntegrityEvaluation:
    if type(outcome) is not PacketAnalysisOutcome:
        raise TypeError("outcome must be exactly a PacketAnalysisOutcome")
    if type(configuration) is not PacketIntegrityConfiguration:
        raise TypeError(
            "configuration must be exactly a PacketIntegrityConfiguration"
        )
    decision = _decision_for(outcome)
    evidence = PacketIntegrityEvidence(outcome, configuration)
    return PacketIntegrityEvaluation(
        decision,
        evidence,
        _interpretation_for(decision),
    )
