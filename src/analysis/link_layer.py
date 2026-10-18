from dataclasses import dataclass, field
from typing import Optional

from capture.packet_observation import LinkType, PacketObservation


RAW_IP_LINK_TYPE = 101
LINUX_COOKED_LINK_TYPE = 113
LINUX_COOKED_HEADER_LENGTH = 16


class LinkLayerDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class LinkLayerFrame:
    link_type: int
    ether_type: int
    payload: bytes = field(repr=False)
    packet_type: Optional[int] = None
    hardware_type: Optional[int] = None

    def __post_init__(self) -> None:
        for name, value in (("link_type", self.link_type), ("ether_type", self.ether_type)):
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
        if self.link_type not in (RAW_IP_LINK_TYPE, LINUX_COOKED_LINK_TYPE):
            raise ValueError("link_type must be 101 or 113")
        if not 0 <= self.ether_type <= 65535:
            raise ValueError("ether_type must be between 0 and 65535")
        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be immutable bytes")
        cooked = self.link_type == LINUX_COOKED_LINK_TYPE
        for name, value in (("packet_type", self.packet_type), ("hardware_type", self.hardware_type)):
            if (value is None) == cooked:
                raise ValueError(f"{name} is required exactly for Linux cooked frames")
            if value is None:
                continue
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
            if not 0 <= value <= 65535:
                raise ValueError(f"{name} must be between 0 and 65535")


def decode_link_layer(observation: PacketObservation) -> LinkLayerFrame:
    if not isinstance(observation, PacketObservation):
        raise TypeError("observation must be a PacketObservation")
    raw_bytes = observation.raw_bytes
    if observation.link_type == LinkType(RAW_IP_LINK_TYPE):
        if not raw_bytes:
            raise LinkLayerDecodeError(f"Raw IP packet is too short: expected at least 1 byte, got {len(raw_bytes)}")
        ether_types = {4: 0x0800, 6: 0x86DD}
        version = raw_bytes[0] >> 4
        if version not in ether_types:
            raise LinkLayerDecodeError("Raw IP version must be 4 or 6")
        return LinkLayerFrame(link_type=RAW_IP_LINK_TYPE, ether_type=ether_types[version], payload=raw_bytes)
    if observation.link_type == LinkType(LINUX_COOKED_LINK_TYPE):
        if len(raw_bytes) < LINUX_COOKED_HEADER_LENGTH:
            raise LinkLayerDecodeError(
                f"Linux cooked frame is too short: expected at least {LINUX_COOKED_HEADER_LENGTH} bytes, "
                f"got {len(raw_bytes)}"
            )
        return LinkLayerFrame(
            link_type=LINUX_COOKED_LINK_TYPE,
            ether_type=int.from_bytes(raw_bytes[14:16], byteorder="big"),
            payload=raw_bytes[LINUX_COOKED_HEADER_LENGTH:],
            packet_type=int.from_bytes(raw_bytes[0:2], byteorder="big"),
            hardware_type=int.from_bytes(raw_bytes[2:4], byteorder="big"),
        )
    raise LinkLayerDecodeError("Link layer decoding requires LinkType(101) or LinkType(113)")
