from dataclasses import dataclass, field

from analysis.ethernet import EthernetFrame


class IPv6DecodeError(ValueError):
    pass


@dataclass(frozen=True)
class IPv6Packet:
    version: int
    traffic_class: int
    flow_label: int
    payload_length: int
    next_header: int
    hop_limit: int
    source_address: bytes
    destination_address: bytes
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        for name, value, minimum, maximum in (
            ("version", self.version, 6, 6),
            ("traffic_class", self.traffic_class, 0, 255),
            ("flow_label", self.flow_label, 0, 1048575),
            ("payload_length", self.payload_length, 0, 65535),
            ("next_header", self.next_header, 0, 255),
            ("hop_limit", self.hop_limit, 0, 255),
        ):
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
            if not minimum <= value <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")
        for name, address in (
            ("source_address", self.source_address),
            ("destination_address", self.destination_address),
        ):
            if not isinstance(address, bytes):
                raise TypeError(f"{name} must be immutable bytes")
            if len(address) != 16:
                raise ValueError(f"{name} must contain exactly 16 bytes")
        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be immutable bytes")
        if self.payload_length != len(self.payload):
            raise ValueError("payload_length must equal payload length")

    @property
    def header_length(self) -> int:
        return 40


def decode_ipv6(frame: EthernetFrame) -> IPv6Packet:
    if not isinstance(frame, EthernetFrame):
        raise TypeError("frame must be an EthernetFrame")
    if frame.ether_type != 0x86DD:
        raise IPv6DecodeError("IPv6 decoding requires EtherType 0x86DD")
    raw_bytes = frame.payload
    if len(raw_bytes) < 40:
        raise IPv6DecodeError("IPv6 header is too short: expected at least 40 bytes")
    version = raw_bytes[0] >> 4
    if version != 6:
        raise IPv6DecodeError("IPv6 version must be 6")
    payload_length = int.from_bytes(raw_bytes[4:6], byteorder="big")
    packet_length = 40 + payload_length
    if packet_length > len(raw_bytes):
        raise IPv6DecodeError("IPv6 payload length exceeds available bytes")
    first_word = int.from_bytes(raw_bytes[:4], byteorder="big")
    return IPv6Packet(
        version=version,
        traffic_class=(first_word >> 20) & 0xFF,
        flow_label=first_word & 0xFFFFF,
        payload_length=payload_length,
        next_header=raw_bytes[6],
        hop_limit=raw_bytes[7],
        source_address=raw_bytes[8:24],
        destination_address=raw_bytes[24:40],
        payload=raw_bytes[40:packet_length],
    )
