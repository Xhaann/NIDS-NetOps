from dataclasses import dataclass, field
from typing import Union

from analysis.ipv4 import IPv4Packet
from analysis.ipv6_fragmentation import IPv6Fragmentation


class UDPDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class UDPPacket:
    source_port: int
    destination_port: int
    length: int
    checksum: int
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        for name, value, minimum, maximum in (
            ("source_port", self.source_port, 0, 65535),
            ("destination_port", self.destination_port, 0, 65535),
            ("length", self.length, 8, 65535),
            ("checksum", self.checksum, 0, 65535),
        ):
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
            if not minimum <= value <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")
        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be immutable bytes")
        if self.length != 8 + len(self.payload):
            raise ValueError("length must equal 8 plus payload length")


def decode_udp(packet: Union[IPv4Packet, IPv6Fragmentation]) -> UDPPacket:
    if isinstance(packet, IPv4Packet):
        if packet.protocol != 17:
            raise UDPDecodeError("UDP decoding requires IPv4 protocol 17")
        if packet.fragment_offset != 0:
            raise UDPDecodeError("UDP decoding requires an initial IPv4 fragment")
        raw_bytes = packet.payload
        ip_version = 4
    elif type(packet) is IPv6Fragmentation:
        chain = packet.extension_headers
        if chain.terminating_next_header != 17:
            raise UDPDecodeError("UDP decoding requires terminal IPv6 Next Header 17")
        if any(header.is_non_first_fragment for header in packet.headers):
            raise UDPDecodeError("UDP decoding requires an initial IPv6 fragment")
        offset = packet.packet.header_length
        if chain.headers:
            last_header = chain.headers[-1]
            offset = last_header.offset + last_header.declared_length
        raw_bytes = packet.packet.payload[offset - packet.packet.header_length:]
        ip_version = 6
    else:
        raise TypeError("packet must be an IPv4Packet or exactly an IPv6Fragmentation")
    if len(raw_bytes) < 8:
        raise UDPDecodeError("UDP header is too short: expected at least 8 bytes")
    length = int.from_bytes(raw_bytes[4:6], byteorder="big")
    if length < 8:
        raise UDPDecodeError("UDP length must be at least 8 bytes")
    if length > len(raw_bytes):
        raise UDPDecodeError(f"UDP length exceeds available IPv{ip_version} payload")
    return UDPPacket(
        source_port=int.from_bytes(raw_bytes[:2], byteorder="big"),
        destination_port=int.from_bytes(raw_bytes[2:4], byteorder="big"),
        length=length,
        checksum=int.from_bytes(raw_bytes[6:8], byteorder="big"),
        payload=raw_bytes[8:length],
    )
