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
        packet_count = self.flow_statistics.packet_count
        if any(value.packet_count != packet_count for value in (
            self.flow_packet_size_statistics,
            self.flow_inter_arrival_statistics,
            self.directional_inter_arrival_statistics,
        )):
            raise FlowCoordinationError("all accumulator packet counts must match")
        directional = self.directional_flow_statistics
        packet_sizes = self.flow_packet_size_statistics
        directional_intervals = self.directional_inter_arrival_statistics
        if directional.forward_packet_count + directional.reverse_packet_count != packet_count:
            raise FlowCoordinationError("directional packet counts must sum to packet_count")
        for direction in ("forward", "reverse"):
            directional_packet_count = getattr(directional, f"{direction}_packet_count")
            if getattr(packet_sizes, f"{direction}_packet_count") != directional_packet_count:
                raise FlowCoordinationError("packet-size directional counts must match directional flow counts")
            interval_count = getattr(directional_intervals, f"{direction}_inter_arrival_count")
            observed = int(getattr(directional_intervals, f"last_{direction}_captured_at") is not None)
            if interval_count + observed != directional_packet_count:
                raise FlowCoordinationError("directional interval counts must match directional packet counts")
        for length in ("captured", "original"):
            total_name = f"{length}_bytes"
            total = getattr(self.flow_statistics, total_name)
            if getattr(packet_sizes, total_name) != total:
                raise FlowCoordinationError(f"global {length}-byte totals must match")
            directional_total = (
                getattr(directional, f"forward_{length}_bytes")
                + getattr(directional, f"reverse_{length}_bytes")
            )
            if directional_total != total:
                raise FlowCoordinationError(f"directional {length}-byte totals must sum to the global total")
            for direction in ("forward", "reverse"):
                if getattr(packet_sizes, f"{direction}_{length}_bytes") != getattr(
                    directional, f"{direction}_{length}_bytes",
                ):
                    raise FlowCoordinationError(
                        f"packet-size {direction} {length}-byte totals must match directional flow totals"
                    )
        for name in ("first_captured_at", "last_captured_at"):
            timestamp = getattr(self.flow_statistics, name)
            if any(getattr(value, name) != timestamp for value in (
                self.flow_inter_arrival_statistics,
                directional_intervals,
            )):
                raise FlowCoordinationError(f"all accumulator {name} values must match")

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
