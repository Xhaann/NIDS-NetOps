from dataclasses import dataclass
from typing import Optional

from analysis.flow_identity import FlowIdentity, flow_identity_from_packet
from analysis.packet_analysis import PacketAnalysis


class FlowTrackingError(ValueError):
    pass


@dataclass(frozen=True)
class FlowPacket:
    identity: FlowIdentity
    analysis: PacketAnalysis

    def __post_init__(self) -> None:
        if not isinstance(self.identity, FlowIdentity):
            raise TypeError("identity must be a FlowIdentity")
        if not isinstance(self.analysis, PacketAnalysis):
            raise TypeError("analysis must be a PacketAnalysis")


@dataclass(frozen=True)
class FlowSnapshot:
    identity: FlowIdentity
    packet_count: int
    first_analysis: PacketAnalysis
    last_analysis: PacketAnalysis

    def __post_init__(self) -> None:
        if not isinstance(self.identity, FlowIdentity):
            raise TypeError("identity must be a FlowIdentity")
        if type(self.packet_count) is not int:
            raise TypeError("packet_count must be an integer")
        if self.packet_count < 1:
            raise FlowTrackingError("packet_count must be at least 1")
        if not isinstance(self.first_analysis, PacketAnalysis):
            raise TypeError("first_analysis must be a PacketAnalysis")
        if not isinstance(self.last_analysis, PacketAnalysis):
            raise TypeError("last_analysis must be a PacketAnalysis")


class FlowTracker:
    def __init__(self) -> None:
        self._flows: dict[FlowIdentity, FlowSnapshot] = {}

    def record(self, analysis: PacketAnalysis) -> FlowSnapshot:
        if not isinstance(analysis, PacketAnalysis):
            raise TypeError("analysis must be a PacketAnalysis")
        identity = flow_identity_from_packet(analysis)
        previous = self._flows.get(identity)
        snapshot = FlowSnapshot(
            identity=identity,
            packet_count=1 if previous is None else previous.packet_count + 1,
            first_analysis=analysis if previous is None else previous.first_analysis,
            last_analysis=analysis,
        )
        self._flows[identity] = snapshot
        return snapshot

    def get(self, identity: FlowIdentity) -> Optional[FlowSnapshot]:
        if not isinstance(identity, FlowIdentity):
            raise TypeError("identity must be a FlowIdentity")
        return self._flows.get(identity)

    def flow_count(self) -> int:
        return len(self._flows)

    def identities(self) -> tuple[FlowIdentity, ...]:
        return tuple(self._flows)

    def snapshots(self) -> tuple[FlowSnapshot, ...]:
        return tuple(self._flows.values())
