from typing import Iterator, Protocol

from capture.packet_observation import PacketObservation


class CaptureError(Exception):
    pass


class PacketSource(Protocol):
    def start(self) -> None:
        ...

    def __iter__(self) -> Iterator[PacketObservation]:
        ...

    def stop(self) -> None:
        ...
