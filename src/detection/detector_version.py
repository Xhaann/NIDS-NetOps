from dataclasses import dataclass


@dataclass(frozen=True)
class DetectorVersion:
    detector_id: str
    detector_version: str

    def __post_init__(self) -> None:
        for name, value in (("detector_id", self.detector_id), ("detector_version", self.detector_version)):
            if type(value) is not str:
                raise TypeError(f"{name} must be exactly a string")
            if not value.strip():
                raise ValueError(f"{name} must not be blank")
