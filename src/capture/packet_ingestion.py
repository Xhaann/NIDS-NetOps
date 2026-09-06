from typing import Callable

from capture.packet_observation import PacketObservation
from capture.packet_source import PacketSource


def consume(
    source: PacketSource, consumer: Callable[[PacketObservation], None]
) -> None:
    try:
        source.start()
        for observation in source:
            consumer(observation)
    finally:
        source.stop()
