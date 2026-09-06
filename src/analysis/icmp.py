from dataclasses import dataclass, field

from analysis.ipv4 import IPv4Packet


class ICMPDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class ICMPMessage:
    icmp_type: int
    code: int
    checksum: int
    rest_of_header: bytes
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        for name, value, maximum in (
            ("icmp_type", self.icmp_type, 255),
            ("code", self.code, 255),
            ("checksum", self.checksum, 65535),
        ):
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
            if not 0 <= value <= maximum:
                raise ValueError(f"{name} must be between 0 and {maximum}")
        if not isinstance(self.rest_of_header, bytes):
            raise TypeError("rest_of_header must be immutable bytes")
        if len(self.rest_of_header) != 4:
            raise ValueError("rest_of_header must contain exactly 4 bytes")
        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be immutable bytes")


def decode_icmp(packet: IPv4Packet) -> ICMPMessage:
    if not isinstance(packet, IPv4Packet):
        raise TypeError("packet must be an IPv4Packet")
    if packet.protocol != 1:
        raise ICMPDecodeError("ICMP decoding requires IPv4 protocol 1")
    if packet.fragment_offset != 0:
        raise ICMPDecodeError("ICMP decoding requires an initial IPv4 fragment")
    raw_bytes = packet.payload
    if len(raw_bytes) < 8:
        raise ICMPDecodeError("ICMP header is too short: expected at least 8 bytes")
    return ICMPMessage(
        icmp_type=raw_bytes[0],
        code=raw_bytes[1],
        checksum=int.from_bytes(raw_bytes[2:4], byteorder="big"),
        rest_of_header=raw_bytes[4:8],
        payload=raw_bytes[8:],
    )
