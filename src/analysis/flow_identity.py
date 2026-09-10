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


def flow_identity_from_packet(analysis: PacketAnalysis) -> FlowIdentity:
    if not isinstance(analysis, PacketAnalysis):
        raise TypeError("analysis must be a PacketAnalysis")
    ipv4 = analysis.ipv4
    if ipv4 is None:
        raise FlowIdentityError("Flow identity requires a decoded IPv4Packet")
    if ipv4.protocol == 6:
        if analysis.tcp is None:
            raise FlowIdentityError("TCP flow identity requires a decoded TCPPacket")
        if analysis.udp is not None or analysis.icmp is not None:
            raise FlowIdentityError("TCP flow identity requires only the TCP transport model")
        source_port = analysis.tcp.source_port
        destination_port = analysis.tcp.destination_port
    elif ipv4.protocol == 17:
        if analysis.udp is None:
            raise FlowIdentityError("UDP flow identity requires a decoded UDPPacket")
        if analysis.tcp is not None or analysis.icmp is not None:
            raise FlowIdentityError("UDP flow identity requires only the UDP transport model")
        source_port = analysis.udp.source_port
        destination_port = analysis.udp.destination_port
    else:
        raise FlowIdentityError("Flow identity supports only IPv4 TCP (6) and UDP (17)")
    return FlowIdentity(
        source_address=ipv4.source_address,
        destination_address=ipv4.destination_address,
        source_port=source_port,
        destination_port=destination_port,
        protocol=ipv4.protocol,
    )
