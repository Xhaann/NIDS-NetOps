from dataclasses import dataclass, field

from capture.packet_observation import LinkType, PacketObservation


class EthernetDecodeError(ValueError):
    pass


VLAN_TPIDS = (0x8100, 0x88A8)
MAX_VLAN_TAGS = 2


@dataclass(frozen=True)
class VLANTag:
    tpid: int
    pcp: int
    dei: int
    vid: int

    def __post_init__(self) -> None:
        for name, value in (("tpid", self.tpid), ("pcp", self.pcp), ("dei", self.dei), ("vid", self.vid)):
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer")
        if self.tpid not in VLAN_TPIDS:
            raise ValueError("tpid must be 0x8100 or 0x88A8")
        for name, value, maximum in (("pcp", self.pcp, 7), ("dei", self.dei, 1), ("vid", self.vid, 4095)):
            if not 0 <= value <= maximum:
                raise ValueError(f"{name} must be between 0 and {maximum}")


@dataclass(frozen=True)
class EthernetFrame:
    destination_mac: bytes
    source_mac: bytes
    ether_type: int
    payload: bytes = field(repr=False)
    vlan_tags: tuple[VLANTag, ...] = ()

    def __post_init__(self) -> None:
        for name, address in (
            ("destination_mac", self.destination_mac),
            ("source_mac", self.source_mac),
        ):
            if not isinstance(address, bytes):
                raise TypeError(f"{name} must be immutable bytes")
            if len(address) != 6:
                raise ValueError(f"{name} must contain exactly 6 bytes")
        if type(self.ether_type) is not int:
            raise TypeError("ether_type must be an integer")
        if not 0 <= self.ether_type <= 65535:
            raise ValueError("ether_type must be between 0 and 65535")
        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be immutable bytes")
        if type(self.vlan_tags) is not tuple:
            raise TypeError("vlan_tags must be an immutable tuple")
        if len(self.vlan_tags) > MAX_VLAN_TAGS:
            raise ValueError("vlan_tags exceeds the supported VLAN tag depth")
        if any(type(tag) is not VLANTag for tag in self.vlan_tags):
            raise TypeError("vlan_tags must contain only VLANTag values")


def decode_ethernet(observation: PacketObservation) -> EthernetFrame:
    if not isinstance(observation, PacketObservation):
        raise TypeError("observation must be a PacketObservation")
    if observation.link_type != LinkType(1):
        raise EthernetDecodeError("Ethernet decoding requires LinkType(1)")
    raw_bytes = observation.raw_bytes
    if len(raw_bytes) < 14:
        raise EthernetDecodeError(
            f"Ethernet frame is too short: expected at least 14 bytes, got {len(raw_bytes)}"
        )
    ether_type = int.from_bytes(raw_bytes[12:14], byteorder="big")
    offset = 14
    tags = []
    while ether_type in VLAN_TPIDS:
        if len(tags) == MAX_VLAN_TAGS:
            raise EthernetDecodeError("Ethernet frame exceeds the supported VLAN tag depth")
        if len(raw_bytes) < offset + 4:
            raise EthernetDecodeError(
                f"Ethernet VLAN tag is too short: expected at least {offset + 4} bytes, got {len(raw_bytes)}"
            )
        tci = int.from_bytes(raw_bytes[offset:offset + 2], byteorder="big")
        tags.append(VLANTag(tpid=ether_type, pcp=tci >> 13, dei=(tci >> 12) & 1, vid=tci & 0x0FFF))
        ether_type = int.from_bytes(raw_bytes[offset + 2:offset + 4], byteorder="big")
        offset += 4
    return EthernetFrame(
        destination_mac=raw_bytes[:6],
        source_mac=raw_bytes[6:12],
        ether_type=ether_type,
        payload=raw_bytes[offset:],
        vlan_tags=tuple(tags),
    )
