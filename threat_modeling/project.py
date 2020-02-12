import os
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
    """
    Primary threat model object. Users add elements and threats to this model
    and can call its utility methods to draw useful diagrams or perform analysis
    on the threat model as a whole.

    One should use the add_element and add_threat methods to add elements
    or threats:

    >>> threat_model = ThreatModel("example")
    >>> element = Element("Server", "1")
    >>> threat_model.add_element(element)

    Adding the same threat or element will raise an exception:

    >>> threat_model.add_element(element)
    Traceback (most recent call last):
        ...
    threat_modeling.exceptions.DuplicateIdentifier: already have 1 in this threat model

    Args:
      name (str, optional): threat model's name
      description (str, optional): threat model's description
    """

    def __init__(
        self, name: Optional[str] = None, description: Optional[str] = None
    ) -> None:
        self.name = name
        self.description = description
        self._elements: Dict[
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
        self._threats: Dict[Union[str, UUID], Threat] = {}

        self._generated_dot: str = ""
        self._boundaries: List[Boundary] = []

    def __str__(self) -> str:
        return "<ThreatModel {}>".format(self.name)

    def __repr__(self) -> str:
        return "ThreatModel('{}', '{}', {}, {})".format(
            self.name,
            reprlib.repr(self.description),
            reprlib.repr(self._elements),
            reprlib.repr(self._threats),
        )

    def __contains__(self, other: Union[str, UUID]) -> bool:
        threat = self._threats.get(other, None)
        element = self._elements.get(other, None)
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
        element = self._elements.get(item, None)
        if element:
            return element

        threat = self._threats.get(item, None)
        if threat:
            return threat
        raise KeyError("Item {} not found".format(item))

    @classmethod
    def load(cls: Type[TM], config: str) -> TM:
        """
        Alternative constructor for loading a threat model object
        from YAML.

        Args:
          config (str): Location on disk the YAML to load from is.

        Returns:
           threat_model (ThreatModel): threat model object
        """
        (name, description, nodes, boundaries, dataflows, threats) = load(config)
        threat_model = cls(name, description)
        threat_model.add_elements(nodes)
        threat_model.add_elements(boundaries)
        threat_model.add_elements(dataflows)
        threat_model.add_threats(threats)
        return threat_model

    def save(self, config: Optional[str] = None) -> str:
        """
        Method to save the threat model (elements + threats)
        to YAML.

        Args:
          config (str, optional): Location on disk to save the YAML.

        Returns:
          config (str): Location on disk the YAML was saved.
        """
        config = save(
            list(self._elements.values()),
            list(self._threats.values()),
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
        """
        Method to check for duplicate elements or threats in the threat model.
        """
        try:
            self._elements[element.identifier]
        except KeyError:
            pass
        else:
            raise DuplicateIdentifier(
                "already have {} in this threat model".format(element.identifier)
            )

        try:
            self._threats[element.identifier]
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
        """
        Method to add an element to the threat model.
        It will raise an exception if the element has already been
        added.

        Args:
          element (Element): element to add
        """
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

        self._elements.update({element.identifier: element})

    def add_threat(self, threat: Threat) -> None:
        """
        Method to add a threat to the threat model.
        It will raise an exception if the threat has already been
        added.

        Args:
          threat (Threat): threat to add
        """
        self._check_for_duplicate_items(threat)
        if not threat.child_threats:
            for child_threat_id in threat.child_threat_ids:
                threat_obj = self[child_threat_id]
                # TODO: Figure out expected "Type[<nothing>]" mypy
                # reports below.
                threat.add_child_threat(threat_obj)  # type: ignore
        self._threats.update({threat.identifier: threat})

    def add_threats(self, threats: List[Threat]) -> None:
        """
        Method to add multiple threats to the threat model.

        Args:
          threats (list of Threat): threats to be added
        """
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
        """
        Method to add multiple elements to the threat model.

        Args:
          elements (list of Element): elements to be added
        """
        for element in elements:
            self.add_element(element)

    def draw(self, output: str = "dfd.png") -> None:
        """
        Method to draw the data flow diagram based on the elements
        in the ThreatModel.

        Args:
          output (str): Location to write the output PNG
        """
        dfd = pygraphviz.AGraph(fontname=FONTFACE, rankdir="LR")

        elements_to_draw = list(self._elements.values()).copy()

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

    def draw_attack_trees(self, output_dir: Optional[str] = "") -> None:
        """
        Draw all attack trees and all subtrees, provided there
        is at least one node in the tree.

        Args:
          output_dir (str): All output PNGs will go into this directory
        """
        for threat in list(self._threats.values()):
            if threat.child_threats:
                if output_dir and not os.path.exists(output_dir):
                    output = "{}.png".format(threat.identifier)
                    raise FileNotFoundError("Directory {} not found".format(output_dir))
                else:
                    output = "{}/{}.png".format(output_dir, threat.identifier)

                attack_tree = AttackTree(threat)
                attack_tree.draw(output)
