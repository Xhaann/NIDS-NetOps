from dataclasses import dataclass, field

from analysis.ipv6 import IPv6Packet
from analysis.ipv6_extension_headers import (
    IPv6ExtensionHeader,
    IPv6ExtensionHeaderChain,
    validate_ipv6_extension_headers,
)


@dataclass(frozen=True)
class IPv6FragmentHeader:
    extension_header: IPv6ExtensionHeader

    def __post_init__(self) -> None:
        if type(self.extension_header) is not IPv6ExtensionHeader:
            raise TypeError("extension_header must be exactly an IPv6ExtensionHeader")
        if self.extension_header.header_type != 44:
            raise ValueError("Fragment Header requires extension header type 44")
        if self.extension_header.declared_length != 8 or len(self.extension_header.raw_bytes) != 8:
            raise ValueError("Fragment Header requires exactly 8 bytes and declared length 8")
        if self.extension_header.next_header != self.extension_header.raw_bytes[0]:
            raise ValueError("Fragment Header Next Header must match its raw byte")

    @property
    def next_header(self) -> int:
        return self.extension_header.raw_bytes[0]

    @property
    def reserved(self) -> int:
        return self.extension_header.raw_bytes[1]

    @property
    def fragment_offset(self) -> int:
        return int.from_bytes(self.extension_header.raw_bytes[2:4], byteorder="big") >> 3

    @property
    def reserved_bits(self) -> int:
        return (self.extension_header.raw_bytes[3] >> 1) & 3

    @property
    def more_fragments(self) -> bool:
        return bool(self.extension_header.raw_bytes[3] & 1)

    @property
    def identification(self) -> int:
        return int.from_bytes(self.extension_header.raw_bytes[4:8], byteorder="big")

    @property
    def is_whole_datagram(self) -> bool:
        return self.fragment_offset == 0 and not self.more_fragments

    @property
    def is_first_fragment(self) -> bool:
        return self.fragment_offset == 0 and self.more_fragments

    @property
    def is_non_first_fragment(self) -> bool:
        return self.fragment_offset > 0

    @property
    def is_last_fragment(self) -> bool:
        return not self.more_fragments

    @property
    def is_intermediate_fragment(self) -> bool:
        return self.fragment_offset > 0 and self.more_fragments


@dataclass(frozen=True)
class IPv6Fragmentation:
    extension_headers: IPv6ExtensionHeaderChain
    headers: tuple[IPv6FragmentHeader, ...] = field(init=False)

    def __post_init__(self) -> None:
        if type(self.extension_headers) is not IPv6ExtensionHeaderChain:
            raise TypeError("extension_headers must be exactly an IPv6ExtensionHeaderChain")
        validated = validate_ipv6_extension_headers(self.extension_headers.packet)
        if self.extension_headers != validated:
            raise ValueError("extension_headers must match the validated IPv6 packet chain")
        object.__setattr__(self, "headers", tuple(
            IPv6FragmentHeader(header)
            for header in self.extension_headers.headers
            if header.header_type == 44
        ))

    @property
    def packet(self) -> IPv6Packet:
        return self.extension_headers.packet


def analyze_ipv6_fragmentation(extension_headers: IPv6ExtensionHeaderChain) -> IPv6Fragmentation:
    return IPv6Fragmentation(extension_headers)
