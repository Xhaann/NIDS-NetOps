from dataclasses import dataclass, field

from analysis.ipv4 import IPv4Packet


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


def decode_udp(packet: IPv4Packet) -> UDPPacket:
    if not isinstance(packet, IPv4Packet):
        raise TypeError("packet must be an IPv4Packet")
    if packet.protocol != 17:
        raise UDPDecodeError("UDP decoding requires IPv4 protocol 17")
    if packet.fragment_offset != 0:
        raise UDPDecodeError("UDP decoding requires an initial IPv4 fragment")
    raw_bytes = packet.payload
    if len(raw_bytes) < 8:
        raise UDPDecodeError("UDP header is too short: expected at least 8 bytes")
    length = int.from_bytes(raw_bytes[4:6], byteorder="big")
    if length < 8:
        raise UDPDecodeError("UDP length must be at least 8 bytes")
    if length > len(raw_bytes):
        raise UDPDecodeError("UDP length exceeds available IPv4 payload")
    return UDPPacket(
        source_port=int.from_bytes(raw_bytes[:2], byteorder="big"),
        destination_port=int.from_bytes(raw_bytes[2:4], byteorder="big"),
        length=length,
        checksum=int.from_bytes(raw_bytes[6:8], byteorder="big"),
        payload=raw_bytes[8:length],
    )
