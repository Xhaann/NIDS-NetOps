from enum import Enum

from analysis.flow_identity import FlowIdentity, _flow_packet_endpoints
from analysis.packet_analysis import PacketAnalysis


class FlowDirectionError(ValueError):
    pass


class FlowDirection(Enum):
    FORWARD = "forward"
    REVERSE = "reverse"


def flow_direction_from_packet(
    analysis: PacketAnalysis,
    identity: FlowIdentity,
) -> FlowDirection:
    if not isinstance(analysis, PacketAnalysis):
        raise TypeError("analysis must be a PacketAnalysis")
    if not isinstance(identity, FlowIdentity):
        raise TypeError("identity must be a FlowIdentity")
    source_address, destination_address, source_port, destination_port, protocol = _flow_packet_endpoints(analysis)
    if protocol != identity.protocol:
        raise FlowDirectionError("packet protocol must match the supplied identity")
    source = (source_address, source_port)
    destination = (destination_address, destination_port)
    first = (identity.source_address, identity.source_port)
    second = (identity.destination_address, identity.destination_port)
    if source == first and destination == second:
        return FlowDirection.FORWARD
    if source == second and destination == first:
        return FlowDirection.REVERSE
    raise FlowDirectionError("packet endpoints must match the supplied identity")
