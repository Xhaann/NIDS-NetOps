from dataclasses import dataclass, fields
from typing import Optional

from analysis.flow_direction import FlowDirection, flow_direction_from_packet
from analysis.flow_identity import FlowIdentity, flow_identity_from_packet
from analysis.packet_analysis import PacketAnalysis
from analysis.tcp import TCPPacket


class TCPControlStatisticsError(ValueError):
    pass


@dataclass(frozen=True)
class TCPControlStatistics:
    identity: FlowIdentity
    packet_count: int
    forward_packet_count: int
    reverse_packet_count: int
    forward_ns_count: int
    forward_cwr_count: int
    forward_ece_count: int
    forward_urg_count: int
    forward_ack_count: int
    forward_psh_count: int
    forward_rst_count: int
    forward_syn_count: int
    forward_fin_count: int
    reverse_ns_count: int
    reverse_cwr_count: int
    reverse_ece_count: int
    reverse_urg_count: int
    reverse_ack_count: int
    reverse_psh_count: int
    reverse_rst_count: int
    reverse_syn_count: int
    reverse_fin_count: int
    forward_syn_ack_count: int
    reverse_syn_ack_count: int

    def __post_init__(self) -> None:
        if type(self.identity) is not FlowIdentity:
            raise TypeError("identity must be exactly a FlowIdentity")
        if self.identity.protocol != 6:
            raise TCPControlStatisticsError("identity must represent TCP protocol 6")
        for field in fields(self):
            if field.name == "identity":
                continue
            value = getattr(self, field.name)
            if type(value) is not int:
                raise TypeError(f"{field.name} must be an integer")
            if value < 0:
                raise TCPControlStatisticsError(f"{field.name} must not be negative")
        if self.packet_count < 1:
            raise TCPControlStatisticsError("packet_count must be at least 1")
        if self.forward_packet_count + self.reverse_packet_count != self.packet_count:
            raise TCPControlStatisticsError(
                "forward_packet_count plus reverse_packet_count must equal packet_count"
            )
        for direction in ("forward", "reverse"):
            packet_count = getattr(self, f"{direction}_packet_count")
            for flag in ("ns", "cwr", "ece", "urg", "ack", "psh", "rst", "syn", "fin"):
                if getattr(self, f"{direction}_{flag}_count") > packet_count:
                    raise TCPControlStatisticsError(
                        f"{direction}_{flag}_count must not exceed {direction}_packet_count"
                    )
            syn_ack_count = getattr(self, f"{direction}_syn_ack_count")
            if syn_ack_count > getattr(self, f"{direction}_syn_count"):
                raise TCPControlStatisticsError(
                    f"{direction}_syn_ack_count must not exceed {direction}_syn_count"
                )
            if syn_ack_count > getattr(self, f"{direction}_ack_count"):
                raise TCPControlStatisticsError(
                    f"{direction}_syn_ack_count must not exceed {direction}_ack_count"
                )


def update_tcp_control_statistics(
    current: Optional[TCPControlStatistics],
    analysis: PacketAnalysis,
    identity: FlowIdentity,
) -> TCPControlStatistics:
    if current is not None and type(current) is not TCPControlStatistics:
        raise TypeError("current must be exactly a TCPControlStatistics or None")
    if type(analysis) is not PacketAnalysis:
        raise TypeError("analysis must be exactly a PacketAnalysis")
    if type(identity) is not FlowIdentity:
        raise TypeError("identity must be exactly a FlowIdentity")
    if identity.protocol != 6:
        raise TCPControlStatisticsError("identity must represent TCP protocol 6")
    derived_identity = flow_identity_from_packet(analysis)
    if derived_identity.protocol != 6:
        raise TCPControlStatisticsError("analysis must represent TCP protocol 6")
    if derived_identity != identity:
        raise TCPControlStatisticsError("identity must match the analysis")
    direction = flow_direction_from_packet(analysis, identity)
    tcp = analysis.tcp
    if type(tcp) is not TCPPacket:
        raise TypeError("analysis.tcp must be exactly a TCPPacket")
    if current is not None and current.identity != identity:
        raise TCPControlStatisticsError("current identity must match the supplied identity")
    forward = direction is FlowDirection.FORWARD
    reverse = direction is FlowDirection.REVERSE
    return TCPControlStatistics(
        identity=identity if current is None else current.identity,
        packet_count=1 if current is None else current.packet_count + 1,
        forward_packet_count=(0 if current is None else current.forward_packet_count) + int(forward),
        reverse_packet_count=(0 if current is None else current.reverse_packet_count) + int(reverse),
        forward_ns_count=(0 if current is None else current.forward_ns_count) + int(forward and tcp.ns),
        forward_cwr_count=(0 if current is None else current.forward_cwr_count) + int(forward and tcp.cwr),
        forward_ece_count=(0 if current is None else current.forward_ece_count) + int(forward and tcp.ece),
        forward_urg_count=(0 if current is None else current.forward_urg_count) + int(forward and tcp.urg),
        forward_ack_count=(0 if current is None else current.forward_ack_count) + int(forward and tcp.ack),
        forward_psh_count=(0 if current is None else current.forward_psh_count) + int(forward and tcp.psh),
        forward_rst_count=(0 if current is None else current.forward_rst_count) + int(forward and tcp.rst),
        forward_syn_count=(0 if current is None else current.forward_syn_count) + int(forward and tcp.syn),
        forward_fin_count=(0 if current is None else current.forward_fin_count) + int(forward and tcp.fin),
        reverse_ns_count=(0 if current is None else current.reverse_ns_count) + int(reverse and tcp.ns),
        reverse_cwr_count=(0 if current is None else current.reverse_cwr_count) + int(reverse and tcp.cwr),
        reverse_ece_count=(0 if current is None else current.reverse_ece_count) + int(reverse and tcp.ece),
        reverse_urg_count=(0 if current is None else current.reverse_urg_count) + int(reverse and tcp.urg),
        reverse_ack_count=(0 if current is None else current.reverse_ack_count) + int(reverse and tcp.ack),
        reverse_psh_count=(0 if current is None else current.reverse_psh_count) + int(reverse and tcp.psh),
        reverse_rst_count=(0 if current is None else current.reverse_rst_count) + int(reverse and tcp.rst),
        reverse_syn_count=(0 if current is None else current.reverse_syn_count) + int(reverse and tcp.syn),
        reverse_fin_count=(0 if current is None else current.reverse_fin_count) + int(reverse and tcp.fin),
        forward_syn_ack_count=(0 if current is None else current.forward_syn_ack_count)
        + int(forward and tcp.syn and tcp.ack),
        reverse_syn_ack_count=(0 if current is None else current.reverse_syn_ack_count)
        + int(reverse and tcp.syn and tcp.ack),
    )
