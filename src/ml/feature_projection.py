from dataclasses import dataclass
from typing import Optional, Union

from analysis.feature_contract_version import FeatureContractVersion
from analysis.flow_feature_snapshot import FlowFeatureSnapshot


_SUPPORTED_FEATURE_CONTRACT = FeatureContractVersion("flow-feature-snapshot", "1")

_FEATURE_GROUPS = (
    ("flow_volume_features", (
        "packet_count", "captured_bytes", "original_bytes",
        "forward_packet_count", "reverse_packet_count",
        "forward_captured_bytes", "reverse_captured_bytes",
        "forward_original_bytes", "reverse_original_bytes",
        "forward_packet_ratio", "reverse_packet_ratio",
        "forward_captured_byte_ratio", "reverse_captured_byte_ratio",
        "forward_original_byte_ratio", "reverse_original_byte_ratio", "capture_ratio",
    )),
    ("packet_size_features", (
        "min_captured_length", "max_captured_length", "mean_captured_length",
        "variance_captured_length", "standard_deviation_captured_length",
        "min_original_length", "max_original_length", "mean_original_length",
        "variance_original_length", "standard_deviation_original_length",
        "forward_mean_captured_length", "reverse_mean_captured_length",
        "forward_variance_captured_length", "reverse_variance_captured_length",
    )),
    ("flow_duration_features", ("duration_seconds",)),
    ("flow_rate_features", (
        "packets_per_second", "captured_bytes_per_second", "original_bytes_per_second",
    )),
    ("inter_arrival_features", (
        "mean_inter_arrival_seconds", "variance_inter_arrival_seconds",
        "standard_deviation_inter_arrival_seconds",
        "min_inter_arrival_seconds", "max_inter_arrival_seconds",
    )),
    ("directional_inter_arrival_features", (
        "forward_mean_inter_arrival_seconds", "forward_variance_inter_arrival_seconds",
        "forward_standard_deviation_inter_arrival_seconds",
        "forward_min_inter_arrival_seconds", "forward_max_inter_arrival_seconds",
        "reverse_mean_inter_arrival_seconds", "reverse_variance_inter_arrival_seconds",
        "reverse_standard_deviation_inter_arrival_seconds",
        "reverse_min_inter_arrival_seconds", "reverse_max_inter_arrival_seconds",
    )),
)

_FEATURE_NAMES = tuple(
    group + "." + name for group, names in _FEATURE_GROUPS for name in names
)


@dataclass(frozen=True, init=False)
class MLFeatureProjection:
    feature_contract: FeatureContractVersion
    values: tuple[Optional[Union[int, float]], ...]

    def __init__(self) -> None:
        raise TypeError("use project_flow_features(snapshot)")

    @property
    def feature_names(self) -> tuple[str, ...]:
        return _FEATURE_NAMES


def project_flow_features(snapshot: FlowFeatureSnapshot) -> MLFeatureProjection:
    if type(snapshot) is not FlowFeatureSnapshot:
        raise TypeError("snapshot must be exactly a FlowFeatureSnapshot")
    contract = snapshot.feature_contract
    if type(contract) is not FeatureContractVersion:
        raise TypeError("snapshot feature contract must be exactly a FeatureContractVersion")
    if contract != _SUPPORTED_FEATURE_CONTRACT:
        raise ValueError("unsupported snapshot feature contract")
    values = []
    for group, names in _FEATURE_GROUPS:
        features = getattr(snapshot, group)
        if group == "flow_rate_features" and features is None:
            values.extend((None,) * len(names))
        else:
            values.extend(getattr(features, name) for name in names)
    projection = object.__new__(MLFeatureProjection)
    object.__setattr__(projection, "feature_contract", contract)
    object.__setattr__(projection, "values", tuple(values))
    return projection
