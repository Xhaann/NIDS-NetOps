from dataclasses import dataclass
from typing import Optional

from analysis.ethernet import EthernetFrame, decode_ethernet
from analysis.icmp import ICMPMessage, decode_icmp
from analysis.icmp_checksum import validate_icmp_checksum
from analysis.ipv4 import IPv4Packet, decode_ipv4
from analysis.ipv4_checksum import validate_ipv4_checksum
from analysis.ipv6 import IPv6Packet, decode_ipv6
from analysis.ipv6_extension_headers import IPv6ExtensionHeaderChain, validate_ipv6_extension_headers
from analysis.tcp import TCPPacket, decode_tcp
from analysis.tcp_checksum import validate_tcp_checksum
from analysis.udp import UDPPacket, decode_udp
from analysis.udp_checksum import validate_udp_checksum
from capture.packet_observation import LinkType, PacketObservation


class PacketAnalysisError(ValueError):
    pass


@dataclass(frozen=True)
class PacketAnalysis:
    observation: PacketObservation
    ethernet: Optional[EthernetFrame] = None
    ipv4: Optional[IPv4Packet] = None
    tcp: Optional[TCPPacket] = None
    udp: Optional[UDPPacket] = None
    icmp: Optional[ICMPMessage] = None
    ipv4_checksum_valid: Optional[bool] = None
    tcp_checksum_valid: Optional[bool] = None
    udp_checksum_valid: Optional[bool] = None
    icmp_checksum_valid: Optional[bool] = None
    ipv6: Optional[IPv6Packet] = None
    ipv6_extension_headers: Optional[IPv6ExtensionHeaderChain] = None

    def __post_init__(self) -> None:
        if not isinstance(self.observation, PacketObservation):
            raise TypeError("observation must be a PacketObservation")
        for name, value, model in (
            ("ethernet", self.ethernet, EthernetFrame),
            ("ipv4", self.ipv4, IPv4Packet),
            ("ipv6", self.ipv6, IPv6Packet),
            ("ipv6_extension_headers", self.ipv6_extension_headers, IPv6ExtensionHeaderChain),
            ("tcp", self.tcp, TCPPacket),
            ("udp", self.udp, UDPPacket),
            ("icmp", self.icmp, ICMPMessage),
        ):
            if value is not None and not isinstance(value, model):
                raise TypeError(f"{name} must be a {model.__name__} or None")
        if self.ipv6_extension_headers is not None:
            if self.ipv6_extension_headers.packet is not self.ipv6:
                raise PacketAnalysisError("IPv6 extension headers must retain the exact IPv6 packet")
        for name, value in (
            ("ipv4_checksum_valid", self.ipv4_checksum_valid),
            ("tcp_checksum_valid", self.tcp_checksum_valid),
            ("udp_checksum_valid", self.udp_checksum_valid),
            ("icmp_checksum_valid", self.icmp_checksum_valid),
        ):
            if value is not None and type(value) is not bool:
                raise TypeError(f"{name} must be a boolean or None")
        if self.ipv6 is not None and any(value is not None for value in (
            self.ipv4, self.tcp, self.udp, self.icmp, self.ipv4_checksum_valid,
            self.tcp_checksum_valid, self.udp_checksum_valid, self.icmp_checksum_valid,
        )):
            raise PacketAnalysisError(
                "IPv6 base-header analysis cannot include IPv4, transport, or checksum results"
            )


def analyze_packet(observation: PacketObservation) -> PacketAnalysis:
    if not isinstance(observation, PacketObservation):
        raise TypeError("observation must be a PacketObservation")
    if observation.link_type != LinkType(1):
        raise PacketAnalysisError("Packet analysis requires Ethernet LinkType(1)")
    ethernet = decode_ethernet(observation)
    if ethernet.ether_type == 0x86DD:
        ipv6 = decode_ipv6(ethernet)
        extensions = validate_ipv6_extension_headers(ipv6)
        return PacketAnalysis(
            observation=observation, ethernet=ethernet, ipv6=ipv6,
            ipv6_extension_headers=extensions,
        )
    if ethernet.ether_type != 0x0800:
        raise PacketAnalysisError("Packet analysis requires IPv4 EtherType 0x0800 or IPv6 EtherType 0x86DD")
    ipv4 = decode_ipv4(ethernet)
    ipv4_checksum_valid = validate_ipv4_checksum(ipv4)
    tcp = None
    udp = None
    icmp = None
    tcp_checksum_valid = None
    udp_checksum_valid = None
    icmp_checksum_valid = None
    if ipv4.protocol == 6:
        tcp = decode_tcp(ipv4)
        if ipv4.fragment_offset == 0:
            tcp_checksum_valid = validate_tcp_checksum(ipv4, tcp)
    elif ipv4.protocol == 17:
        udp = decode_udp(ipv4)
        if ipv4.fragment_offset == 0:
            udp_checksum_valid = validate_udp_checksum(ipv4, udp)
    elif ipv4.protocol == 1:
        icmp = decode_icmp(ipv4)
        if ipv4.fragment_offset == 0:
            icmp_checksum_valid = validate_icmp_checksum(ipv4, icmp)
    return PacketAnalysis(
        observation=observation,
        ethernet=ethernet,
        ipv4=ipv4,
        tcp=tcp,
        udp=udp,
        icmp=icmp,
        ipv4_checksum_valid=ipv4_checksum_valid,
        tcp_checksum_valid=tcp_checksum_valid,
        udp_checksum_valid=udp_checksum_valid,
        icmp_checksum_valid=icmp_checksum_valid,
    )
