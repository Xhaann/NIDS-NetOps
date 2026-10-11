from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from analysis.feature_contract_version import FeatureContractVersion
from analysis.flow_identity import FlowIdentity
from analysis.flow_observation_window import (
    FlowObservationWindow,
    FlowObservationWindowClosureReason,
    FlowObservationWindowKey,
)


class FlowFeatureProvenanceError(ValueError):
    pass


@dataclass(frozen=True)
class FlowFeatureProvenance:
    feature_contract: FeatureContractVersion
    window_key: FlowObservationWindowKey
    flow_identity: FlowIdentity
    closure_reason: Optional[FlowObservationWindowClosureReason]
    first_captured_at: datetime
    last_captured_at: datetime

    def __post_init__(self) -> None:
        if type(self.feature_contract) is not FeatureContractVersion:
            raise TypeError("feature_contract must be exactly a FeatureContractVersion")
        if type(self.window_key) is not FlowObservationWindowKey:
            raise TypeError("window_key must be exactly a FlowObservationWindowKey")
        if type(self.flow_identity) is not FlowIdentity:
            raise TypeError("flow_identity must be exactly a FlowIdentity")
        if self.closure_reason is not None and type(
            self.closure_reason
        ) is not FlowObservationWindowClosureReason:
            raise TypeError(
                "closure_reason must be exactly a FlowObservationWindowClosureReason or None"
            )
        for name in ("first_captured_at", "last_captured_at"):
            value = getattr(self, name)
            if type(value) is not datetime or type(value.tzinfo) is not timezone:
                raise TypeError(f"{name} must be an exact datetime with fixed UTC timezone")
            if value.utcoffset() != timedelta(0):
                raise FlowFeatureProvenanceError(f"{name} must have zero UTC offset")
        if self.last_captured_at < self.first_captured_at:
            raise FlowFeatureProvenanceError("last_captured_at must not precede first_captured_at")


def flow_feature_provenance_from_window(
    window: FlowObservationWindow,
    feature_contract: FeatureContractVersion,
) -> FlowFeatureProvenance:
    if type(window) is not FlowObservationWindow:
        raise TypeError("window must be exactly a FlowObservationWindow")
    return FlowFeatureProvenance(
        feature_contract=feature_contract,
        window_key=window.key,
        flow_identity=window.identity,
        closure_reason=window.closure_reason,
        first_captured_at=window.first_captured_at,
        last_captured_at=window.last_captured_at,
    )
