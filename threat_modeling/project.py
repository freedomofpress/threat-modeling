import pygraphviz
from uuid import UUID

from typing import Dict, List, Optional, Union

from threat_modeling.data_flow import (
    Boundary,
    Element,
    Dataflow,
    BidirectionalDataflow,
    FONTFACE,
)
from threat_modeling.exceptions import DuplicateIdentifier
from threat_modeling.threats import Threat


class ThreatModel:
    def __init__(
        self, name: Optional[str] = None, description: Optional[str] = None
    ) -> None:
        self.name = name
        self.description = description
        self.elements: List[Element] = []
        self.threats: List[Threat] = []
        self.boundaries: List[Boundary] = []

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
            raise DuplicateIdentifier(
                "already have {} in this threat model".format(element.identifier)
            )

        if element.identifier in [x.identifier for x in self.threats]:
            raise DuplicateIdentifier(
                "already have {} in this threat model".format(element.identifier)
            )

        if isinstance(element, (Dataflow, BidirectionalDataflow)):
            for item in [element.first_id, element.second_id]:
                try:
                    self[item]
                except KeyError:
                    raise ValueError(
                        "Node {} not found, add it before the Dataflow.".format(item)
                    )

        if isinstance(element, Boundary):
            self.boundaries.append(element)
            for child in element.members:
                boundary = self[child]
                if isinstance(boundary, Boundary):
                    # Set Boundary.nodes to consist of the nodes
                    # TODO: investigate this mypy error, could be legitimate TypeError
                    element.nodes += boundary.members  # type: ignore
                else:
                    # child_element = self[child]
                    # TODO: remove below type: ignore when we create an
                    #  ElementCollection type?
                    element.nodes.append(child)  # type: ignore

        self.elements.append(element)

    def add_threat(self, threat: Threat) -> None:
        if threat.identifier in [x.identifier for x in self.elements]:
            raise DuplicateIdentifier

        if threat.identifier in [x.identifier for x in self.threats]:
            raise DuplicateIdentifier

        self.threats.append(threat)

    def draw(self, output: str = "dfd.png") -> None:
        dfd = pygraphviz.AGraph(fontname=FONTFACE)

        elements_to_draw = self.elements.copy()

        # Iterate through the boundaries. If there's a a boundary in the members,
        # set the parent attribute.
        for boundary in self.boundaries:
            elements_to_draw.remove(boundary)
            for child in boundary.members:
                child_boundary = self[child]
                if isinstance(child_boundary, Boundary):
                    child_boundary.parent = boundary

        # Construct a dict based on the child-parent relationships.
        boundary_tree: Dict[
            Optional[Union[Boundary, Element]], List[Union[Boundary, Element]]
        ] = {}
        boundary_tree[None] = []
        for boundary in self.boundaries:
            try:
                boundary_tree[boundary.parent].append(boundary)
            except KeyError:
                boundary_tree[boundary.parent] = [boundary]

        for element in elements_to_draw:
            element.draw(dfd)

        # Draw the boundaries beginning with the top-level boundaries of the
        # boundary tree.
        boundaries_to_draw = boundary_tree[None]
        while len(boundaries_to_draw) != 0:
            boundary_to_draw = boundaries_to_draw[0]
            boundary_to_draw.draw(dfd)
            boundaries_to_draw.remove(boundary_to_draw)
            try:
                for child_boundary in boundary_tree[boundary_to_draw]:
                    boundaries_to_draw.append(child_boundary)
            except KeyError:  # We're at a leaf.
                pass

        dfd.draw(output, prog="dot", args="-Gdpi=300")
