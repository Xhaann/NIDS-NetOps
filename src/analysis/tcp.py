from dataclasses import dataclass, field
from typing import Union

from analysis.ipv4 import IPv4Packet
from analysis.ipv6_fragmentation import IPv6Fragmentation
from analysis.option_envelope import _validate_option_envelope


class TCPDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class TCPPacket:
    source_port: int
    destination_port: int
    sequence_number: int
    acknowledgment_number: int
    data_offset: int
    reserved_bits: int
    ns: bool
    cwr: bool
    ece: bool
    urg: bool
    ack: bool
    psh: bool
    rst: bool
    syn: bool
    fin: bool
    window_size: int
    checksum: int
    urgent_pointer: int
    options: bytes = field(repr=False)
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        for name, value, minimum, maximum in (
            ("source_port", self.source_port, 0, 65535),
            ("destination_port", self.destination_port, 0, 65535),
            ("sequence_number", self.sequence_number, 0, 0xFFFFFFFF),
            ("acknowledgment_number", self.acknowledgment_number, 0, 0xFFFFFFFF),
            ("data_offset", self.data_offset, 5, 15),
            ("reserved_bits", self.reserved_bits, 0, 7),
            ("window_size", self.window_size, 0, 65535),
            ("checksum", self.checksum, 0, 65535),
            ("urgent_pointer", self.urgent_pointer, 0, 65535),
        ):
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
            if not minimum <= value <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")
        for name, value in (
            ("ns", self.ns),
            ("cwr", self.cwr),
            ("ece", self.ece),
            ("urg", self.urg),
            ("ack", self.ack),
            ("psh", self.psh),
            ("rst", self.rst),
            ("syn", self.syn),
            ("fin", self.fin),
        ):
            if type(value) is not bool:
                raise TypeError(f"{name} must be a boolean")
        if not isinstance(self.options, bytes):
            raise TypeError("options must be immutable bytes")
        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be immutable bytes")
        if len(self.options) != self.header_length - 20:
            raise ValueError("options length must match data_offset")

    @property
    def header_length(self) -> int:
        return self.data_offset * 4


def _validate_tcp_options(segment: TCPPacket) -> None:
    _validate_option_envelope(segment.options, "TCP", TCPDecodeError)


def decode_tcp(packet: Union[IPv4Packet, IPv6Fragmentation]) -> TCPPacket:
    if isinstance(packet, IPv4Packet):
        if packet.protocol != 6:
            raise TCPDecodeError("TCP decoding requires IPv4 protocol 6")
        if packet.fragment_offset != 0:
            raise TCPDecodeError("TCP decoding requires an initial IPv4 fragment")
        raw_bytes = packet.payload
        ip_version = 4
    elif type(packet) is IPv6Fragmentation:
        chain = packet.extension_headers
        if chain.terminating_next_header != 6:
            raise TCPDecodeError("TCP decoding requires terminal IPv6 Next Header 6")
        if any(header.is_non_first_fragment for header in packet.headers):
            raise TCPDecodeError("TCP decoding requires an initial IPv6 fragment")
        offset = packet.packet.header_length
        if chain.headers:
            last_header = chain.headers[-1]
            offset = last_header.offset + last_header.declared_length
        raw_bytes = packet.packet.payload[offset - packet.packet.header_length:]
        ip_version = 6
    else:
        raise TypeError("packet must be an IPv4Packet or exactly an IPv6Fragmentation")
    if len(raw_bytes) < 20:
        raise TCPDecodeError("TCP header is too short: expected at least 20 bytes")
    control_field = int.from_bytes(raw_bytes[12:14], byteorder="big")
    data_offset = control_field >> 12
    if data_offset < 5:
        raise TCPDecodeError("TCP data offset must be at least 5")
    header_length = data_offset * 4
    if header_length > len(raw_bytes):
        raise TCPDecodeError(f"TCP header length exceeds available IPv{ip_version} payload")
    return TCPPacket(
        source_port=int.from_bytes(raw_bytes[:2], byteorder="big"),
        destination_port=int.from_bytes(raw_bytes[2:4], byteorder="big"),
        sequence_number=int.from_bytes(raw_bytes[4:8], byteorder="big"),
        acknowledgment_number=int.from_bytes(raw_bytes[8:12], byteorder="big"),
        data_offset=data_offset,
        reserved_bits=(control_field >> 9) & 0x07,
        ns=bool(control_field & 0x0100),
        cwr=bool(control_field & 0x0080),
        ece=bool(control_field & 0x0040),
        urg=bool(control_field & 0x0020),
        ack=bool(control_field & 0x0010),
        psh=bool(control_field & 0x0008),
        rst=bool(control_field & 0x0004),
        syn=bool(control_field & 0x0002),
        fin=bool(control_field & 0x0001),
        window_size=int.from_bytes(raw_bytes[14:16], byteorder="big"),
        checksum=int.from_bytes(raw_bytes[16:18], byteorder="big"),
        urgent_pointer=int.from_bytes(raw_bytes[18:20], byteorder="big"),
        options=raw_bytes[20:header_length],
        payload=raw_bytes[header_length:],
    )
