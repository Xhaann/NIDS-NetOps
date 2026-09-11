from dataclasses import dataclass
from enum import Enum
from typing import Union

from analysis import (
    DirectionalFlowStatisticsError, DirectionalInterArrivalFeaturesError, DirectionalInterArrivalStatisticsError,
    EthernetDecodeError, FeatureContractVersion, FlowCoordinationError, FlowDirectionError, FlowDurationFeaturesError,
    FlowFeatureInputError, FlowFeatureSnapshotError, FlowIdentityError, FlowInterArrivalStatisticsError,
    FlowObservationWindowError, FlowObservationWindowKey, FlowPacketSizeStatisticsError, FlowRateFeaturesError,
    FlowStatisticsError, FlowTrackingError, FlowVolumeFeaturesError, ICMPChecksumValidationError, ICMPDecodeError,
    IPv4DecodeError, IPv6DecodeError, InterArrivalFeaturesError, PacketAnalysisError, PacketAnalysisOutcomeError,
    PacketSizeFeaturesError, TCPChecksumValidationError, TCPControlStatisticsError, TCPDecodeError,
    UDPChecksumValidationError, UDPDecodeError,
)
from application.detection_configuration import DetectionConfiguration
from application.detection_dataset import DetectionDataset
from application.detection_experiment import DetectionExperiment
from capture import CaptureError, CaptureSource
from detection import DetectionFindingError, DetectorVersion, FlowVolumeThresholdError, PacketIntegrityError, TCPControlThresholdError


class OperationalErrorCategory(Enum):
    CAPTURE_FAILURE = "capture_failure"
    PACKET_ANALYSIS_FAILURE = "packet_analysis_failure"
    FLOW_PROCESSING_FAILURE = "flow_processing_failure"
    DETECTION_FAILURE = "detection_failure"
    UNCLASSIFIED_FAILURE = "unclassified_failure"


_Context = Union[CaptureSource, FlowObservationWindowKey, DetectionConfiguration, DetectionDataset,
                 DetectionExperiment, DetectorVersion, FeatureContractVersion]


@dataclass(frozen=True)
class OperationalDiagnostic:
    category: OperationalErrorCategory
    operation_id: str
    message: str
    context: tuple[_Context, ...] = ()

    def __post_init__(self) -> None:
        if type(self.category) is not OperationalErrorCategory:
            raise TypeError("category must be exactly an OperationalErrorCategory")
        for name, value in (("operation_id", self.operation_id), ("message", self.message)):
            if type(value) is not str:
                raise TypeError(f"{name} must be exactly a string")
            if not value.strip():
                raise ValueError(f"{name} must not be blank")
        if type(self.context) is not tuple:
            raise TypeError("context must be exactly a tuple")
        if any(type(value) not in (CaptureSource, FlowObservationWindowKey, DetectionConfiguration, DetectionDataset,
                                  DetectionExperiment, DetectorVersion, FeatureContractVersion) for value in self.context):
            raise TypeError("context must contain supported immutable context values")


def _category(error: Exception) -> OperationalErrorCategory:
    error_type = type(error)
    if error_type is CaptureError:
        return OperationalErrorCategory.CAPTURE_FAILURE
    if error_type in (PacketAnalysisError, PacketAnalysisOutcomeError, EthernetDecodeError, IPv4DecodeError,
                      IPv6DecodeError, TCPDecodeError, UDPDecodeError, ICMPDecodeError, TCPChecksumValidationError,
                      UDPChecksumValidationError, ICMPChecksumValidationError):
        return OperationalErrorCategory.PACKET_ANALYSIS_FAILURE
    if error_type in (FlowIdentityError, FlowDirectionError, FlowTrackingError, FlowStatisticsError,
                      DirectionalFlowStatisticsError, FlowCoordinationError, FlowObservationWindowError,
                      FlowPacketSizeStatisticsError, FlowInterArrivalStatisticsError, DirectionalInterArrivalStatisticsError,
                      TCPControlStatisticsError, FlowFeatureInputError, FlowVolumeFeaturesError, PacketSizeFeaturesError,
                      FlowDurationFeaturesError, FlowRateFeaturesError, InterArrivalFeaturesError,
                      DirectionalInterArrivalFeaturesError, FlowFeatureSnapshotError):
        return OperationalErrorCategory.FLOW_PROCESSING_FAILURE
    if error_type in (PacketIntegrityError, FlowVolumeThresholdError, TCPControlThresholdError, DetectionFindingError):
        return OperationalErrorCategory.DETECTION_FAILURE
    return OperationalErrorCategory.UNCLASSIFIED_FAILURE


def diagnose_error(
    error: Exception,
    *,
    operation_id: str,
    message: str,
    context: tuple[_Context, ...] = (),
) -> OperationalDiagnostic:
    if not isinstance(error, Exception):
        raise TypeError("error must be an Exception")
    return OperationalDiagnostic(_category(error), operation_id, message, context)
