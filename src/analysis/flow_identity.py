from dataclasses import dataclass
from ipaddress import ip_address

from analysis.packet_analysis import PacketAnalysis


class FlowIdentityError(ValueError):
    pass


@dataclass(frozen=True)
class FlowIdentity:
    source_address: bytes
    destination_address: bytes
    source_port: int
    destination_port: int
    protocol: int

    def __post_init__(self) -> None:
        for name, address in (
            ("source_address", self.source_address),
            ("destination_address", self.destination_address),
        ):
            if not isinstance(address, bytes):
                raise TypeError(f"{name} must be immutable bytes")
            if len(address) not in (4, 16):
                raise ValueError(f"{name} must contain exactly 4 or 16 bytes")
        if len(self.source_address) != len(self.destination_address):
            raise ValueError("source and destination addresses must use the same IP version")
        for name, value in (
            ("source_port", self.source_port),
            ("destination_port", self.destination_port),
            ("protocol", self.protocol),
        ):
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
        if not 0 <= self.source_port <= 65535:
            raise ValueError("source_port must be between 0 and 65535")
        if not 0 <= self.destination_port <= 65535:
            raise ValueError("destination_port must be between 0 and 65535")
        if self.protocol not in (6, 17):
            raise ValueError("protocol must be 6 or 17")
        source = (self.source_address, self.source_port)
        destination = (self.destination_address, self.destination_port)
        if destination < source:
            object.__setattr__(self, "source_address", destination[0])
            object.__setattr__(self, "source_port", destination[1])
            object.__setattr__(self, "destination_address", source[0])
            object.__setattr__(self, "destination_port", source[1])

    @property
    def ip_version(self) -> int:
        return 4 if len(self.source_address) == 4 else 6


def _packed_ip_address(address: str) -> bytes:
    if type(address) is not str:
        raise TypeError("address must be exactly a string")
    parsed = ip_address(address)
    if parsed.version == 6 and parsed.scope_id is not None:
        raise ValueError("scoped IPv6 addresses are not supported by flow identity")
    return parsed.packed


def flow_identity_from_addresses(
    source_address: str,
    destination_address: str,
    source_port: int,
    destination_port: int,
    protocol: int,
) -> FlowIdentity:
    return FlowIdentity(
        source_address=_packed_ip_address(source_address),
        destination_address=_packed_ip_address(destination_address),
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
    )


def _flow_packet_endpoints(analysis: PacketAnalysis) -> tuple[bytes, bytes, int, int, int]:
    if not isinstance(analysis, PacketAnalysis):
        raise TypeError("analysis must be a PacketAnalysis")
    network = analysis.ipv4
    tcp = analysis.tcp
    udp = analysis.udp
    icmp = analysis.icmp
    if analysis.ipv6 is not None:
        if any(value is not None for value in (
            network, tcp, udp, icmp, analysis.ipv4_checksum_valid,
            analysis.tcp_checksum_valid, analysis.udp_checksum_valid, analysis.icmp_checksum_valid,
        )):
            raise FlowIdentityError("IPv6 flow identity cannot include IPv4 results")
        network = analysis.ipv6
        chain = analysis.ipv6_extension_headers
        if chain is None or chain.packet is not network:
            raise FlowIdentityError("IPv6 flow identity requires the exact IPv6 extension-header context")
        fragmentation = analysis.ipv6_fragmentation
        if fragmentation is not None:
            if fragmentation.extension_headers is not chain:
                raise FlowIdentityError("IPv6 flow identity requires the exact fragmentation context")
            if any(header.is_non_first_fragment for header in fragmentation.headers):
                raise FlowIdentityError("IPv6 flow identity requires an initial fragment")
        protocol = chain.terminating_next_header
        tcp = analysis.ipv6_tcp
        udp = analysis.ipv6_udp
        icmp = analysis.ipv6_icmpv6
    else:
        if network is None:
            raise FlowIdentityError("Flow identity requires a decoded IPv4Packet")
        protocol = network.protocol
    if protocol == 6:
        if tcp is None:
            raise FlowIdentityError("TCP flow identity requires a decoded TCPPacket")
        if udp is not None or icmp is not None:
            raise FlowIdentityError("TCP flow identity requires only the TCP transport model")
        transport = tcp
    elif protocol == 17:
        if udp is None:
            raise FlowIdentityError("UDP flow identity requires a decoded UDPPacket")
        if tcp is not None or icmp is not None:
            raise FlowIdentityError("UDP flow identity requires only the UDP transport model")
        transport = udp
    else:
        raise FlowIdentityError(f"Flow identity supports only IPv{network.version} TCP (6) and UDP (17)")
    return (
        network.source_address, network.destination_address,
        transport.source_port, transport.destination_port, protocol,
    )


def flow_identity_from_packet(analysis: PacketAnalysis) -> FlowIdentity:
    return FlowIdentity(*_flow_packet_endpoints(analysis))
