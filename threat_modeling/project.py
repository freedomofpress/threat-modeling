import pygraphviz
import reprlib
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
from threat_modeling.serialization import load, save
from threat_modeling.threats import AttackTree, Threat

TM = TypeVar("TM", bound="ThreatModel")


class ThreatModel:
    def __init__(
        self, name: Optional[str] = None, description: Optional[str] = None
    ) -> None:
        self.name = name
        self.description = description
        self.elements: Dict[
            Union[str, UUID],
            Union[
                Element,
                ExternalEntity,
                Process,
                Datastore,
                Boundary,
                Dataflow,
                BidirectionalDataflow,
            ],
        ] = {}
        self.threats: Dict[Union[str, UUID], Threat] = {}

        self._generated_dot: str = ""
        self._boundaries: List[Boundary] = []

    def __str__(self) -> str:
        return "<ThreatModel {}>".format(self.name)

    def __repr__(self) -> str:
        return "ThreatModel('{}', '{}', {}, {})".format(
            self.name,
            reprlib.repr(self.description),
            reprlib.repr(self.elements),
            reprlib.repr(self.threats),
        )

    def __contains__(self, other: Union[str, UUID]) -> bool:
        threat = self.threats.get(other, None)
        element = self.elements.get(other, None)
        if threat or element:
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
        element = self.elements.get(item, None)
        if element:
            return element

        threat = self.threats.get(item, None)
        if threat:
            return threat
        raise KeyError("Item {} not found".format(item))

    @classmethod
    def load(cls: Type[TM], config: str) -> TM:
        (name, description, nodes, boundaries, dataflows, threats) = load(config)
        threat_model = cls(name, description)
        threat_model.add_elements(nodes)
        threat_model.add_elements(boundaries)
        threat_model.add_elements(dataflows)
        threat_model.add_threats(threats)
        return threat_model

    def save(self, config: Optional[str] = None) -> str:
        config = save(
            list(self.elements.values()),
            list(self.threats.values()),
            self.name,
            self.description,
            config,
        )
        return config

    def _check_for_duplicate_items(
        self,
        element: Union[
            Element,
            ExternalEntity,
            Process,
            Datastore,
            Boundary,
            Dataflow,
            BidirectionalDataflow,
            Threat,
        ],
    ) -> None:
        try:
            self.elements[element.identifier]
        except KeyError:
            pass
        else:
            raise DuplicateIdentifier(
                "already have {} in this threat model".format(element.identifier)
            )

        try:
            self.threats[element.identifier]
        except KeyError:
            pass
        else:
            raise DuplicateIdentifier(
                "already have {} in this threat model".format(element.identifier)
            )

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
        self._check_for_duplicate_items(element)

        if isinstance(element, (Dataflow, BidirectionalDataflow)):
            for item in [element.first_id, element.second_id]:
                try:
                    self[item]
                except KeyError:
                    raise ValueError(
                        "Node {} not found, add it before the Dataflow.".format(item)
                    )

        if isinstance(element, Boundary):
            if element.parent:
                if isinstance(element.parent, str):
                    parent_element = self[element.parent]
                    element.parent = parent_element

            self._boundaries.append(element)

            # Members of an element will be Union[str, UUID]
            for child in element.members:
                child_obj = self[child]

                if isinstance(child_obj, Boundary):
                    # Set Boundary.nodes to consist of the individual nodes
                    element.nodes += child_obj.members
                else:
                    element.nodes.append(child)

        self.elements.update({element.identifier: element})

    def add_threat(self, threat: Threat) -> None:
        self._check_for_duplicate_items(threat)
        if not threat.child_threats:
            for child_threat_id in threat.child_threat_ids:
                threat_obj = self[child_threat_id]
                # TODO: Figure out expected "Type[<nothing>]" mypy
                # reports below.
                threat.add_child_threat(threat_obj)  # type: ignore
        self.threats.update({threat.identifier: threat})

    def add_threats(self, threats: List[Threat]) -> None:
        for threat in threats:
            self.add_threat(threat)

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

        elements_to_draw = list(self.elements.values()).copy()

        # Iterate through the boundaries. If there's a a boundary in the members,
        # set the parent attribute.
        for boundary in self._boundaries:
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
        for boundary in self._boundaries:
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

    def draw_attack_trees(self) -> None:
        """
        Draw all attack trees and all subtrees, provided there
        is at least one node in the tree.
        """
        for threat in list(self.threats.values()):
            if threat.child_threats:
                attack_tree = AttackTree(threat)
                attack_tree.draw()
