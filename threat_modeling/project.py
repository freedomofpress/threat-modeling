import pygraphviz
from uuid import UUID

from typing import List, Union

from threat_modeling.data_flow import Element, Dataflow, BidirectionalDataflow
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

        if isinstance(element, (Dataflow, BidirectionalDataflow)):
            for item in [element.first_id, element.second_id]:
                try:
                    self[item]
                except KeyError:
                    raise ValueError(
                        "Node {} not found, add it before the Dataflow.".format(item)
                    )

        self.elements.append(element)

    def add_threat(self, threat: Threat) -> None:
        if threat.identifier in [x.identifier for x in self.elements]:
            raise DuplicateIdentifier

        if threat.identifier in [x.identifier for x in self.threats]:
            raise DuplicateIdentifier

        self.threats.append(threat)

    def draw(self, output: str = "dfd.png") -> None:
        dfd = pygraphviz.AGraph()
        for element in self.elements:
            element.draw(dfd)
        dfd.draw(output, prog="dot", args="-Gdpi=300")
