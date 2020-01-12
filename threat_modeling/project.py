import pygraphviz
from uuid import UUID

from typing import Dict, List, Optional, Type, TypeVar, Union, Sequence

from threat_modeling.data_flow import (
    Boundary,
    Element,
    Dataflow,
    BidirectionalDataflow,
    ExternalEntity,
    Process,
    Datastore,
    FONTFACE,
)
from threat_modeling.exceptions import DuplicateIdentifier
from threat_modeling.serialization import load
from threat_modeling.threats import Threat

TM = TypeVar("TM", bound="ThreatModel")


class ThreatModel:
    def __init__(
        self, name: Optional[str] = None, description: Optional[str] = None
    ) -> None:
        self.name = name
        self.description = description
        self.elements: List[
            Union[
                Element,
                ExternalEntity,
                Process,
                Datastore,
                Boundary,
                Dataflow,
                BidirectionalDataflow,
            ]
        ] = []
        self.threats: List[Threat] = []
        self.boundaries: List[Boundary] = []
        self._generated_dot: str = ""

    @classmethod
    def load(cls: Type[TM], config: str) -> TM:
        (name, description, nodes, boundaries, dataflows) = load(config)
        threat_model = cls(name, description)
        threat_model.add_elements(nodes)
        threat_model.add_elements(boundaries)
        threat_model.add_elements(dataflows)
        return threat_model

    def __contains__(self, other: Union[str, UUID]) -> bool:
        if other in [x.identifier for x in self.elements]:
            return True

        if other in [x.identifier for x in self.threats]:
            return True

        return False

    def __getitem__(
        self, item: Union[str, UUID]
    ) -> Union[
        Element,
        ExternalEntity,
        Process,
        Datastore,
        Boundary,
        Dataflow,
        BidirectionalDataflow,
        Threat,
    ]:
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

        raise KeyError("Item {} not found".format(item))

    def add_element(
        self,
        element: Union[
            Element,
            ExternalEntity,
            Process,
            Datastore,
            Boundary,
            Dataflow,
            BidirectionalDataflow,
        ],
    ) -> None:
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
            # Members of an element will be Union[str, UUID]
            for child in element.members:
                child_obj = self[child]

                if isinstance(child_obj, Boundary):
                    # Set Boundary.nodes to consist of the nodes
                    # TODO: investigate this mypy error, could be legitimate TypeError
                    element.nodes += child_obj.members  # type: ignore
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

    def add_elements(
        self,
        elements: Sequence[
            Union[
                Element,
                ExternalEntity,
                Process,
                Datastore,
                Boundary,
                Dataflow,
                BidirectionalDataflow,
            ]
        ],
    ) -> None:
        for element in elements:
            self.add_element(element)

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
        self._generated_dot = str(dfd)
