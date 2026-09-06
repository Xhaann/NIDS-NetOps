from dataclasses import dataclass, field

from capture.packet_observation import LinkType, PacketObservation


class EthernetDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class EthernetFrame:
    destination_mac: bytes
    source_mac: bytes
    ether_type: int
    payload: bytes = field(repr=False)

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
    return EthernetFrame(
        destination_mac=raw_bytes[:6],
        source_mac=raw_bytes[6:12],
        ether_type=int.from_bytes(raw_bytes[12:14], byteorder="big"),
        payload=raw_bytes[14:],
    )
