from uuid import UUID

from typing import List, Union

from threat_modeling.data_flow import Element
from threat_modeling.exceptions import DuplicateIdentifier
from threat_modeling.threats import Threat


class ThreatModel:
    def __init__(self) -> None:
        self.elements: List[Element] = []
        self.threats: List[Threat] = []

    def __contains__(self, other: Union[str, UUID]) -> bool:
        if other in [x.identifier for x in self.elements]:
            return True

        if other in [x.identifier for x in self.threats]:
            return True

        return False

    def __getitem__(self, item: Union[str, UUID]) -> Union[Element, Threat]:
        """Allow []-based retrieval of elements and threats from this object
        based on their ID"""
        for element in self.elements:
            if element.identifier == item:
                return element

        # concatenating elements and threats causes a mypy error:
        # https://github.com/python/mypy/issues/5492
        for threat in self.threats:
            if threat.identifier == item:
                return threat

        raise KeyError

    def add_element(self, element: Element) -> None:
        if element.identifier in [x.identifier for x in self.elements]:
            raise DuplicateIdentifier

        if element.identifier in [x.identifier for x in self.threats]:
            raise DuplicateIdentifier

        self.elements.append(element)

    def add_threat(self, threat: Threat) -> None:
        if threat.identifier in [x.identifier for x in self.elements]:
            raise DuplicateIdentifier

        if threat.identifier in [x.identifier for x in self.threats]:
            raise DuplicateIdentifier

        self.threats.append(threat)
