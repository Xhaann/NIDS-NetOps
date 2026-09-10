from dataclasses import dataclass, field
from typing import Optional

from analysis.ipv6 import IPv6Packet


@dataclass(frozen=True)
class IPv6ExtensionHeader:
    header_type: int
    offset: int
    declared_length: Optional[int]
    raw_bytes: bytes = field(repr=False)
    next_header: Optional[int]

    def __post_init__(self) -> None:
        if type(self.header_type) is not int:
            raise TypeError("header_type must be exactly an integer")
        if not 0 <= self.header_type <= 255:
            raise ValueError("header_type must be between 0 and 255")
        if type(self.offset) is not int:
            raise TypeError("offset must be exactly an integer")
        if self.offset < 0:
            raise ValueError("offset must not be negative")
        if self.declared_length is not None:
            if type(self.declared_length) is not int:
                raise TypeError("declared_length must be exactly an integer or None")
            if self.declared_length < 0:
                raise ValueError("declared_length must not be negative")
        if type(self.raw_bytes) is not bytes:
            raise TypeError("raw_bytes must be exactly immutable bytes")
        if self.next_header is not None:
            if type(self.next_header) is not int:
                raise TypeError("next_header must be exactly an integer or None")
            if not 0 <= self.next_header <= 255:
                raise ValueError("next_header must be between 0 and 255")


@dataclass(frozen=True)
class IPv6ExtensionHeaderChain:
    packet: IPv6Packet
    headers: tuple[IPv6ExtensionHeader, ...]

    def __post_init__(self) -> None:
        if type(self.packet) is not IPv6Packet:
            raise TypeError("packet must be exactly an IPv6Packet")
        if type(self.headers) is not tuple:
            raise TypeError("headers must be exactly a tuple")
        for header in self.headers:
            if type(header) is not IPv6ExtensionHeader:
                raise TypeError("headers members must be exactly IPv6ExtensionHeader values")
