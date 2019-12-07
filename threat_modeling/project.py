from typing import List, Optional

from threat_modeling.data_flow import Element
from threat_modeling.exceptions import DuplicateIdentifier


class ThreatModel:
    def __init__(self) -> None:
        self.elements: List[Element] = []

    def __contains__(self, other: Element) -> bool:
        if other in self.elements:
            return True
        return False

    def __getitem__(self, item: str) -> Element:
        for element in self.elements:
            if element.identifier == item:
                return element
        raise KeyError

    def add_element(self, element: Element) -> None:
        if element in self.elements:
            raise DuplicateIdentifier
        self.elements.append(element)
