from dataclasses import dataclass, field

from analysis.ipv6 import IPv6DecodeError, IPv6Packet
from analysis.ipv6_extension_headers import IPv6ExtensionHeaderChain
from analysis.ipv6_fragmentation import analyze_ipv6_fragmentation


@dataclass(frozen=True)
class ICMPv6Packet:
    extension_headers: IPv6ExtensionHeaderChain
    offset: int = field(init=False)
    raw_bytes: bytes = field(init=False, repr=False)
    icmp_type: int = field(init=False)
    code: int = field(init=False)
    checksum: int = field(init=False)
    body: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        fragmentation = analyze_ipv6_fragmentation(self.extension_headers)
        if self.extension_headers.terminating_next_header != 58:
            raise IPv6DecodeError("ICMPv6 decoding requires terminal Next Header 58")
        if any(not header.is_whole_datagram for header in fragmentation.headers):
            raise IPv6DecodeError("ICMPv6 decoding requires an unfragmented or whole-datagram packet")
        offset = self.packet.header_length
        if self.extension_headers.headers:
            last_header = self.extension_headers.headers[-1]
            offset = last_header.offset + last_header.declared_length
        raw_bytes = self.packet.payload[offset - self.packet.header_length:]
        if len(raw_bytes) < 4:
            raise IPv6DecodeError("ICMPv6 header is too short: expected at least 4 bytes")
        object.__setattr__(self, "offset", offset)
        object.__setattr__(self, "raw_bytes", raw_bytes)
        object.__setattr__(self, "icmp_type", raw_bytes[0])
        object.__setattr__(self, "code", raw_bytes[1])
        object.__setattr__(self, "checksum", int.from_bytes(raw_bytes[2:4], byteorder="big"))
        object.__setattr__(self, "body", raw_bytes[4:])

    @property
    def packet(self) -> IPv6Packet:
        return self.extension_headers.packet

    @property
    def is_error_message(self) -> bool:
        return self.icmp_type < 128

    @property
    def is_informational_message(self) -> bool:
        return self.icmp_type >= 128


def decode_icmpv6(extension_headers: IPv6ExtensionHeaderChain) -> ICMPv6Packet:
    return ICMPv6Packet(extension_headers)
