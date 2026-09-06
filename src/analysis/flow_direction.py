from enum import Enum

from analysis.flow_identity import FlowIdentity, FlowIdentityError
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
    ipv4 = analysis.ipv4
    if ipv4 is None:
        raise FlowIdentityError("Flow identity requires a decoded IPv4Packet")
    if ipv4.protocol == 6:
        if analysis.tcp is None:
            raise FlowIdentityError("TCP flow identity requires a decoded TCPPacket")
        if analysis.udp is not None or analysis.icmp is not None:
            raise FlowIdentityError("TCP flow identity requires only the TCP transport model")
        transport = analysis.tcp
    elif ipv4.protocol == 17:
        if analysis.udp is None:
            raise FlowIdentityError("UDP flow identity requires a decoded UDPPacket")
        if analysis.tcp is not None or analysis.icmp is not None:
            raise FlowIdentityError("UDP flow identity requires only the UDP transport model")
        transport = analysis.udp
    else:
        raise FlowIdentityError("Flow identity supports only IPv4 TCP (6) and UDP (17)")
    if ipv4.protocol != identity.protocol:
        raise FlowDirectionError("packet protocol must match the supplied identity")
    source = (ipv4.source_address, transport.source_port)
    destination = (ipv4.destination_address, transport.destination_port)
    first = (identity.source_address, identity.source_port)
    second = (identity.destination_address, identity.destination_port)
    if source == first and destination == second:
        return FlowDirection.FORWARD
    if source == second and destination == first:
        return FlowDirection.REVERSE
    raise FlowDirectionError("packet endpoints must match the supplied identity")
