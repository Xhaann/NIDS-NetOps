from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class CaptureSource:
    identifier: str

    def __post_init__(self) -> None:
        if not isinstance(self.identifier, str):
            raise TypeError("identifier must be a string")
        if not self.identifier.strip():
            raise ValueError("identifier must not be empty or whitespace-only")


@dataclass(frozen=True)
class LinkType:
    value: int

    def __post_init__(self) -> None:
        if type(self.value) is not int:
            raise TypeError("link type value must be an integer")
        if not 0 <= self.value <= 65535:
            raise ValueError("link type value must be between 0 and 65535")


@dataclass(frozen=True)
class PacketObservation:
    captured_at: datetime
    link_type: Optional[LinkType]
    captured_length: int
    original_length: Optional[int]
    raw_bytes: bytes = field(repr=False)
    source: CaptureSource

    def __post_init__(self) -> None:
        if not isinstance(self.captured_at, datetime):
            raise TypeError("captured_at must be a datetime")
        if self.captured_at.tzinfo is None or self.captured_at.utcoffset() is None:
            raise ValueError("captured_at must be timezone-aware")
        if self.link_type is not None and not isinstance(self.link_type, LinkType):
            raise TypeError("link_type must be a LinkType or None")
        if not isinstance(self.source, CaptureSource):
            raise TypeError("source must be a CaptureSource")
        if not isinstance(self.raw_bytes, bytes):
            raise TypeError("raw_bytes must be immutable bytes")
        if type(self.captured_length) is not int:
            raise TypeError("captured_length must be an integer")
        if self.captured_length < 0:
            raise ValueError("captured_length must not be negative")
        if self.captured_length != len(self.raw_bytes):
            raise ValueError("captured_length must equal the length of raw_bytes")
        if self.original_length is not None:
            if type(self.original_length) is not int:
                raise TypeError("original_length must be an integer or None")
            if self.original_length < 0:
                raise ValueError("original_length must not be negative")
            if self.original_length < self.captured_length:
                raise ValueError("original_length must not be smaller than captured_length")
