from dataclasses import dataclass
from typing import Optional

from analysis.directional_flow_statistics import DirectionalFlowStatistics, update_directional_flow_statistics
from analysis.directional_inter_arrival_statistics import (
    DirectionalInterArrivalStatistics,
    update_directional_inter_arrival_statistics,
)
from analysis.flow_identity import FlowIdentity, flow_identity_from_packet
from analysis.flow_inter_arrival_statistics import FlowInterArrivalStatistics, update_flow_inter_arrival_statistics
from analysis.flow_packet_size_statistics import FlowPacketSizeStatistics, update_flow_packet_size_statistics
from analysis.flow_statistics import FlowStatistics, update_flow_statistics
from analysis.packet_analysis import PacketAnalysis


class FlowCoordinationError(ValueError):
    pass


@dataclass(frozen=True)
class CoordinatedFlowState:
    flow_statistics: FlowStatistics
    directional_flow_statistics: DirectionalFlowStatistics
    flow_packet_size_statistics: FlowPacketSizeStatistics
    flow_inter_arrival_statistics: FlowInterArrivalStatistics
    directional_inter_arrival_statistics: DirectionalInterArrivalStatistics

    def __post_init__(self) -> None:
        for name, value, expected in (
            ("flow_statistics", self.flow_statistics, FlowStatistics),
            ("directional_flow_statistics", self.directional_flow_statistics, DirectionalFlowStatistics),
            ("flow_packet_size_statistics", self.flow_packet_size_statistics, FlowPacketSizeStatistics),
            ("flow_inter_arrival_statistics", self.flow_inter_arrival_statistics, FlowInterArrivalStatistics),
            ("directional_inter_arrival_statistics", self.directional_inter_arrival_statistics,
             DirectionalInterArrivalStatistics),
        ):
            if type(value) is not expected:
                raise TypeError(f"{name} must be exactly a {expected.__name__}")
        for value in (
            self.directional_flow_statistics,
            self.flow_packet_size_statistics,
            self.flow_inter_arrival_statistics,
            self.directional_inter_arrival_statistics,
        ):
            if value.identity != self.identity:
                raise FlowCoordinationError("all accumulator identities must match")

    @property
    def identity(self) -> FlowIdentity:
        return self.flow_statistics.identity


class FlowStateCoordinator:
    def __init__(self) -> None:
        self._state: Optional[CoordinatedFlowState] = None

    @property
    def state(self) -> Optional[CoordinatedFlowState]:
        return self._state

    def record(self, analysis: PacketAnalysis) -> CoordinatedFlowState:
        if type(analysis) is not PacketAnalysis:
            raise TypeError("analysis must be exactly a PacketAnalysis")
        derived_identity = flow_identity_from_packet(analysis)
        current = self._state
        if current is not None and current.identity != derived_identity:
            raise FlowCoordinationError("analysis must belong to the coordinator's flow")
        identity = derived_identity if current is None else current.identity
        candidate = CoordinatedFlowState(
            flow_statistics=update_flow_statistics(
                None if current is None else current.flow_statistics, analysis, identity,
            ),
            directional_flow_statistics=update_directional_flow_statistics(
                None if current is None else current.directional_flow_statistics, analysis, identity,
            ),
            flow_packet_size_statistics=update_flow_packet_size_statistics(
                None if current is None else current.flow_packet_size_statistics, analysis, identity,
            ),
            flow_inter_arrival_statistics=update_flow_inter_arrival_statistics(
                None if current is None else current.flow_inter_arrival_statistics, analysis, identity,
            ),
            directional_inter_arrival_statistics=update_directional_inter_arrival_statistics(
                None if current is None else current.directional_inter_arrival_statistics, analysis, identity,
            ),
        )
        self._state = candidate
        return candidate
