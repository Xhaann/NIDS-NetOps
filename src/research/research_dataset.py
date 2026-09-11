from dataclasses import dataclass
from typing import Union

from research.research_example import ResearchExample


@dataclass(frozen=True, init=False)
class ResearchDataset:
    examples: tuple[ResearchExample, ...]

    def __init__(self, examples: Union[list[ResearchExample], tuple[ResearchExample, ...]]) -> None:
        if type(examples) not in (list, tuple):
            raise TypeError("examples must be exactly a list or tuple")
        members = tuple(examples)
        if any(type(example) is not ResearchExample for example in members):
            raise TypeError("examples must contain exactly ResearchExample values")
        object.__setattr__(self, "examples", members)
