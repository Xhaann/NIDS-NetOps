from dataclasses import dataclass


@dataclass(frozen=True)
class FeatureContractVersion:
    contract_id: str
    contract_version: str

    def __post_init__(self) -> None:
        for name, value in (("contract_id", self.contract_id), ("contract_version", self.contract_version)):
            if type(value) is not str:
                raise TypeError(f"{name} must be exactly a string")
            if not value.strip():
                raise ValueError(f"{name} must not be blank")
