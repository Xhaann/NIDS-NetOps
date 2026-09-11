from dataclasses import dataclass
from enum import Enum
from typing import Union

from application.detection_evaluation import FlowDetectionIdentity, PacketDetectionIdentity


class GroundTruthPolarity(Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"


@dataclass(frozen=True)
class GroundTruthRecord:
    target: Union[PacketDetectionIdentity, FlowDetectionIdentity]
    polarity: GroundTruthPolarity

    def __post_init__(self) -> None:
        if type(self.target) not in (PacketDetectionIdentity, FlowDetectionIdentity):
            raise TypeError("target must be exactly a packet or flow detection identity")
        if type(self.polarity) is not GroundTruthPolarity:
            raise TypeError("polarity must be exactly a GroundTruthPolarity")


@dataclass(frozen=True)
class GroundTruth:
    packet_records: tuple[GroundTruthRecord, ...]
    flow_records: tuple[GroundTruthRecord, ...]

    def __post_init__(self) -> None:
        for name, records, target_type in (
            ("packet_records", self.packet_records, PacketDetectionIdentity),
            ("flow_records", self.flow_records, FlowDetectionIdentity),
        ):
            if type(records) is not tuple:
                raise TypeError(f"{name} must be exactly a tuple")
            labels = {}
            for record in records:
                if type(record) is not GroundTruthRecord:
                    raise TypeError(f"{name} must contain exactly GroundTruthRecord values")
                if type(record.target) is not target_type:
                    raise ValueError(f"{name} contains a target from the other domain")
                previous = labels.get(record.target)
                if previous is not None:
                    if previous is not record.polarity:
                        raise ValueError(f"{name} contains contradictory labels for the same target")
                    raise ValueError(f"{name} contains a duplicate target")
                labels[record.target] = record.polarity
