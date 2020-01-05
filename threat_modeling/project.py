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

        if isinstance(element, Dataflow):
            for item in [element.source_id, element.dest_id]:
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
            if isinstance(element, Dataflow):
                source_node = dfd.get_node(element.source_id)
                dest_node = dfd.get_node(element.dest_id)
                dfd.add_edge(source_node, dest_node, dir="forward", arrowhead="normal")
            elif isinstance(element, BidirectionalDataflow):
                node_1 = dfd.get_node(element.first_id)
                node_2 = dfd.get_node(element.second_id)
                dfd.add_edge(node_1, node_2, dir="both", arrowhead="normal")
            else:
                dfd.add_node(element.identifier)

        dfd.draw(output, prog="dot")
