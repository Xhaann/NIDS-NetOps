from dataclasses import dataclass, field

from analysis.ethernet import EthernetFrame


class IPv4DecodeError(ValueError):
    pass


@dataclass(frozen=True)
class IPv4Packet:
    version: int
    ihl: int
    dscp: int
    ecn: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    header_checksum: int
    source_address: bytes
    destination_address: bytes
    options: bytes = field(repr=False)
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        for name, value, minimum, maximum in (
            ("version", self.version, 4, 4),
            ("ihl", self.ihl, 5, 15),
            ("dscp", self.dscp, 0, 63),
            ("ecn", self.ecn, 0, 3),
            ("total_length", self.total_length, 0, 65535),
            ("identification", self.identification, 0, 65535),
            ("flags", self.flags, 0, 7),
            ("fragment_offset", self.fragment_offset, 0, 8191),
            ("ttl", self.ttl, 0, 255),
            ("protocol", self.protocol, 0, 255),
            ("header_checksum", self.header_checksum, 0, 65535),
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
            if len(address) != 4:
                raise ValueError(f"{name} must contain exactly 4 bytes")
        if not isinstance(self.options, bytes):
            raise TypeError("options must be immutable bytes")
        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be immutable bytes")
        if len(self.options) != self.header_length - 20:
            raise ValueError("options length must match ihl")
        if self.total_length < self.header_length:
            raise ValueError("total_length must not be smaller than header_length")
        if self.total_length != self.header_length + len(self.payload):
            raise ValueError("total_length must equal header_length plus payload length")

    @property
    def header_length(self) -> int:
        return self.ihl * 4


def _validate_ipv4_options(packet: IPv4Packet) -> None:
    options = packet.options
    offset = 0
    while offset < len(options):
        kind = options[offset]
        if kind == 0:
            if any(options[offset + 1:]):
                raise IPv4DecodeError("IPv4 option padding must be zero")
            return
        if kind == 1:
            offset += 1
            continue
        if offset + 1 >= len(options):
            raise IPv4DecodeError("IPv4 option length field exceeds option area")
        length = options[offset + 1]
        if length < 2:
            raise IPv4DecodeError("IPv4 option length must be at least 2 bytes")
        if offset + length > len(options):
            raise IPv4DecodeError("IPv4 option length exceeds option area")
        offset += length


def decode_ipv4(frame: EthernetFrame) -> IPv4Packet:
    if not isinstance(frame, EthernetFrame):
        raise TypeError("frame must be an EthernetFrame")
    if frame.ether_type != 0x0800:
        raise IPv4DecodeError("IPv4 decoding requires EtherType 0x0800")
    raw_bytes = frame.payload
    if len(raw_bytes) < 20:
        raise IPv4DecodeError("IPv4 header is too short: expected at least 20 bytes")
    version = raw_bytes[0] >> 4
    ihl = raw_bytes[0] & 0x0F
    if version != 4:
        raise IPv4DecodeError("IPv4 version must be 4")
    if ihl < 5:
        raise IPv4DecodeError("IPv4 IHL must be at least 5")
    header_length = ihl * 4
    if len(raw_bytes) < header_length:
        raise IPv4DecodeError("IPv4 header length exceeds available bytes")
    total_length = int.from_bytes(raw_bytes[2:4], byteorder="big")
    if total_length < header_length:
        raise IPv4DecodeError("IPv4 total length is smaller than header length")
    if total_length > len(raw_bytes):
        raise IPv4DecodeError("IPv4 total length exceeds available bytes")
    fragment_field = int.from_bytes(raw_bytes[6:8], byteorder="big")
    return IPv4Packet(
        version=version,
        ihl=ihl,
        dscp=raw_bytes[1] >> 2,
        ecn=raw_bytes[1] & 0x03,
        total_length=total_length,
        identification=int.from_bytes(raw_bytes[4:6], byteorder="big"),
        flags=fragment_field >> 13,
        fragment_offset=fragment_field & 0x1FFF,
        ttl=raw_bytes[8],
        protocol=raw_bytes[9],
        header_checksum=int.from_bytes(raw_bytes[10:12], byteorder="big"),
        source_address=raw_bytes[12:16],
        destination_address=raw_bytes[16:20],
        options=raw_bytes[20:header_length],
        payload=raw_bytes[header_length:total_length],
    )
