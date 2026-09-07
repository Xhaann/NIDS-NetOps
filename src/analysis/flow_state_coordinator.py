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
from analysis.tcp_control_statistics import TCPControlStatistics, update_tcp_control_statistics


class FlowCoordinationError(ValueError):
    pass


@dataclass(frozen=True)
class CoordinatedFlowState:
    flow_statistics: FlowStatistics
    directional_flow_statistics: DirectionalFlowStatistics
    flow_packet_size_statistics: FlowPacketSizeStatistics
    flow_inter_arrival_statistics: FlowInterArrivalStatistics
    directional_inter_arrival_statistics: DirectionalInterArrivalStatistics
    tcp_control_statistics: Optional[TCPControlStatistics]

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
        tcp_control = self.tcp_control_statistics
        if tcp_control is not None and type(tcp_control) is not TCPControlStatistics:
            raise TypeError("tcp_control_statistics must be exactly a TCPControlStatistics or None")
        if self.identity.protocol == 6 and tcp_control is None:
            raise FlowCoordinationError("TCP coordinated state requires TCP control statistics")
        if self.identity.protocol == 17 and tcp_control is not None:
            raise FlowCoordinationError("UDP coordinated state requires absent TCP control statistics")
        if tcp_control is not None and tcp_control.identity.protocol != 6:
            raise FlowCoordinationError("TCP control statistics must represent TCP protocol 6")
        for value in (
            self.directional_flow_statistics,
            self.flow_packet_size_statistics,
            self.flow_inter_arrival_statistics,
            self.directional_inter_arrival_statistics,
        ):
            if value.identity != self.identity:
                raise FlowCoordinationError("all accumulator identities must match")
        if tcp_control is not None and tcp_control.identity != self.identity:
            raise FlowCoordinationError("TCP control statistics identity must match")
        packet_count = self.flow_statistics.packet_count
        if any(value.packet_count != packet_count for value in (
            self.flow_packet_size_statistics,
            self.flow_inter_arrival_statistics,
            self.directional_inter_arrival_statistics,
        )):
            raise FlowCoordinationError("all accumulator packet counts must match")
        if tcp_control is not None and tcp_control.packet_count != packet_count:
            raise FlowCoordinationError("TCP control packet count must match")
        directional = self.directional_flow_statistics
        packet_sizes = self.flow_packet_size_statistics
        directional_intervals = self.directional_inter_arrival_statistics
        if directional.forward_packet_count + directional.reverse_packet_count != packet_count:
            raise FlowCoordinationError("directional packet counts must sum to packet_count")
        for direction in ("forward", "reverse"):
            directional_packet_count = getattr(directional, f"{direction}_packet_count")
            if getattr(packet_sizes, f"{direction}_packet_count") != directional_packet_count:
                raise FlowCoordinationError("packet-size directional counts must match directional flow counts")
            if tcp_control is not None and getattr(
                tcp_control, f"{direction}_packet_count"
            ) != directional_packet_count:
                raise FlowCoordinationError("TCP control directional counts must match directional flow counts")
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
            tcp_control_statistics=update_tcp_control_statistics(
                None if current is None else current.tcp_control_statistics, analysis, identity,
            ) if identity.protocol == 6 else None,
        )
        self._state = candidate
        return candidate
