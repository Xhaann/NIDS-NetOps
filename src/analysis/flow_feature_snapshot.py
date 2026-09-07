from dataclasses import dataclass
from typing import Optional

from analysis.directional_inter_arrival_features import (
    DirectionalInterArrivalFeatures,
    extract_directional_inter_arrival_features,
)
from analysis.flow_duration_features import FlowDurationFeatures, extract_flow_duration_features
from analysis.flow_feature_input import flow_feature_input_from_statistics
from analysis.flow_identity import FlowIdentity
from analysis.flow_rate_features import FlowRateFeatures, extract_flow_rate_features
from analysis.flow_state_coordinator import CoordinatedFlowState, FlowStateCoordinator
from analysis.flow_volume_features import FlowVolumeFeatures, extract_flow_volume_features
from analysis.inter_arrival_features import InterArrivalFeatures, extract_inter_arrival_features
from analysis.packet_size_features import PacketSizeFeatures, extract_packet_size_features


class FlowFeatureSnapshotError(ValueError):
    pass


@dataclass(frozen=True, init=False)
class FlowFeatureSnapshot:
    coordinated_state: CoordinatedFlowState
    flow_volume_features: FlowVolumeFeatures
    packet_size_features: PacketSizeFeatures
    flow_duration_features: FlowDurationFeatures
    flow_rate_features: Optional[FlowRateFeatures]
    inter_arrival_features: InterArrivalFeatures
    directional_inter_arrival_features: DirectionalInterArrivalFeatures

    def __init__(self) -> None:
        raise TypeError("use extract_flow_feature_snapshot(coordinator)")

    @property
    def identity(self) -> FlowIdentity:
        return self.coordinated_state.identity


def extract_flow_feature_snapshot(coordinator: FlowStateCoordinator) -> FlowFeatureSnapshot:
    if type(coordinator) is not FlowStateCoordinator:
        raise TypeError("coordinator must be exactly a FlowStateCoordinator")
    state = coordinator.state
    if state is None:
        raise FlowFeatureSnapshotError("coordinator has no published state")
    if type(state) is not CoordinatedFlowState:
        raise TypeError("published state must be exactly a CoordinatedFlowState")
    volume_input = flow_feature_input_from_statistics(
        state.flow_statistics, state.directional_flow_statistics,
    )
    volume = extract_flow_volume_features(volume_input)
    sizes = extract_packet_size_features(state.flow_packet_size_statistics)
    duration = extract_flow_duration_features(state.flow_statistics)
    if type(duration) is not FlowDurationFeatures:
        raise TypeError("duration extractor must return exactly a FlowDurationFeatures")
    rates = None if duration.duration_seconds == 0.0 else extract_flow_rate_features(state.flow_statistics)
    intervals = extract_inter_arrival_features(state.flow_inter_arrival_statistics)
    directional_intervals = extract_directional_inter_arrival_features(
        state.directional_inter_arrival_statistics
    )
    for value, expected in (
        (volume, FlowVolumeFeatures),
        (sizes, PacketSizeFeatures),
        (intervals, InterArrivalFeatures),
        (directional_intervals, DirectionalInterArrivalFeatures),
    ):
        if type(value) is not expected:
            raise TypeError(f"extractor must return exactly a {expected.__name__}")
    if duration.duration_seconds != 0.0 and type(rates) is not FlowRateFeatures:
        raise TypeError("rate extractor must return exactly a FlowRateFeatures")
    snapshot = object.__new__(FlowFeatureSnapshot)
    object.__setattr__(snapshot, "coordinated_state", state)
    object.__setattr__(snapshot, "flow_volume_features", volume)
    object.__setattr__(snapshot, "packet_size_features", sizes)
    object.__setattr__(snapshot, "flow_duration_features", duration)
    object.__setattr__(snapshot, "flow_rate_features", rates)
    object.__setattr__(snapshot, "inter_arrival_features", intervals)
    object.__setattr__(snapshot, "directional_inter_arrival_features", directional_intervals)
    return snapshot
