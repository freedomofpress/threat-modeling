from enum import Enum
import pygraphviz
import reprlib
from uuid import uuid4, UUID

from typing import List, Optional, Union

from threat_modeling.data_flow import FONTFACE, FONTSIZE, ELEMENT_COLOR
from threat_modeling.mitigations import Mitigation


class ThreatStatus(Enum):
    """
    ThreatStatus describes the statuses each threat can be in.
    """

    UNMANAGED = "Unmanaged"
    MANAGED_INFORM = "Managed: Inform"
    MANAGED_TRANSFERRED = "Managed: Transferred"
    MANAGED_AVOIDED = "Managed: Avoided"
    MANAGED_ACCEPTED = "Managed: Accepted"
    MANAGED_MITIGATED = "Managed: Mitigated"
    MANAGED_PARTIALLY_MITIGATED = "Managed: Partially Mitigated"
    OUT_OF_SCOPE = "Out of scope"


class OrdinalScore(Enum):
    """
    Ordinal scores are used for the impact and exploitaility scores on
    threats.
    """

    NONE = 0
    VERY_LOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class ThreatCategory(Enum):
    """
    ThreatCategory describes the high-level type of the threat.
    """

    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    UNKNOWN = "Unknown"


class Threat:
    """
    Each threat object represents a possible attack or "thing that can go
    wrong". Multiple mitigations can map to a given threat. Each Threat object
    applies to a single DFD element. If a given attack can be applied to
    multiple DFD elements, one Threat must be generated for each DFD element.

    Args:
      identifier (str, UUID, optional): this is a short ID that is used
        to map the threat to other objects (mitigations, DFD elements,
        and other threats). If one is not provided it will be generated.
      name (str): a short name that is used when drawing the threat in
        diagrams.
      description (str, optional): an optional description containing
        more information about the given threat.
      child_threats (list[Threat], optional): threats that become possible if this
        threat is successfully exploited. This is used for the construction
        and display of attack trees.
      status (str, optional): the mitigation status of this threat.
        Defaults to unmanaged if no status is provided.
      base_impact (str, optional): the impact of this vulnerability
        before any mitigations have been applied.
      base_exploitability (str, optional): the ease of exploiting
        this threat.
      child_threat_ids (list[str, UUID], optional): used for specifying child
        threats by ID. This is used when adding a threat to the threat model,
        to populate child_threats (done via a method on ThreatModel).
      threat_category (str, optional): see possible choices in ThreatCategory.
      dfd_element (str, optional): ID of the threat that this threat corresponds to.
      mitigations (List[Mitigation], optional): mitigations applied to this threat.
    """

    STYLE = "filled"
    COLOR = ELEMENT_COLOR
    SHAPE = "rectangle"

    def __init__(
        self,
        name: str,
        identifier: Optional[Union[str, UUID]] = None,
        description: str = "",
        child_threats: Optional[List["Threat"]] = None,
        status: Optional[str] = None,
        base_impact: Optional[str] = None,
        base_exploitability: Optional[str] = None,
        child_threat_ids: Optional[List[Union[str, UUID]]] = None,
        threat_category: Optional[str] = None,
        dfd_element: Optional[str] = None,
        mitigations: Optional[List[Mitigation]] = None,
        mitigation_ids: Optional[List[Union[str, UUID]]] = None,
    ):
        self.name = name
        self.identifier = identifier or uuid4()
        self.description = description
        if status:
            status_lookup = ThreatStatus[status.replace(" ", "_").upper()]
            self.status: Optional[ThreatStatus] = status_lookup
        else:  # No status provided
            self.status = ThreatStatus.UNMANAGED

        if threat_category:
            threat_category_lookup = ThreatCategory[
                threat_category.replace(" ", "_").upper()
            ]
            self.threat_category: Optional[ThreatCategory] = threat_category_lookup
        else:
            self.threat_category = ThreatCategory.UNKNOWN

        if child_threats:
            self.child_threats = child_threats.copy()
        else:
            self.child_threats = []

        if child_threat_ids:
            self.child_threat_ids = child_threat_ids.copy()
        else:
            self.child_threat_ids = [x.identifier for x in self.child_threats]

        # Metrics
        if base_impact:
            base_impact_lookup = OrdinalScore[base_impact.replace(" ", "_").upper()]
            self.base_impact: Optional[OrdinalScore] = base_impact_lookup
        else:
            self.base_impact = None

        if base_exploitability:
            base_exploitability_lookup = OrdinalScore[
                base_exploitability.replace(" ", "_").upper()
            ]
            self.base_exploitability: Optional[
                OrdinalScore
            ] = base_exploitability_lookup
        else:
            self.base_exploitability = None

        if not self.base_impact or not self.base_exploitability:
            self.base_risk = None
        else:
            self.base_risk = self.base_impact.value * self.base_exploitability.value

        self.dfd_element = dfd_element
        if mitigations:
            self.mitigations = mitigations.copy()
        else:
            self.mitigations = []

        if mitigation_ids:
            self.mitigation_ids = mitigation_ids.copy()
        else:
            self.mitigation_ids = [x.identifier for x in self.mitigations]

    def __str__(self) -> str:
        return "<Threat {}: {}>".format(self.identifier, self.name)

    def __repr__(self) -> str:
        return "Threat({}, {}, {})".format(
            self.name, self.identifier, reprlib.repr(self.description)
        )

    def add_child_threat(self, child_threat: "Threat") -> None:
        """
        Adds a child threat to this threat. Child threats represent attacks
        that become possible when this threat is successfully exploited.
        They are used for the rendering of attack trees.

        Args:
          child_threat (Threat): threat object that is a child
        """
        self.child_threats.append(child_threat)

    def draw(self, graph: pygraphviz.AGraph) -> None:
        """
        This method is called when we try to draw an AttackTree object.

        Args:
          graph (AGraph): the graphviz object that we will add a node to.
        """
        graph.add_node(
            self.identifier,
            label=self.name,
            fontsize=FONTSIZE,
            fontname=FONTFACE,
            style=self.STYLE,
            fillcolor=self.COLOR,
            shape=self.SHAPE,
        )

        for child_threat in self.child_threats:
            child_threat.draw(graph)
            parent_node = graph.get_node(self.identifier)
            child_node = graph.get_node(child_threat.identifier)
            graph.add_edge(
                parent_node,
                child_node,
                dir="forward",
                arrowhead="normal",
                fontsize=FONTSIZE - 2,
                fontname=FONTFACE,
            )


class AttackTree:
    """
    Represents a possible attack path through the system.

    Args:
      root_threat (Threat): the root threat in the tree.
    """

    def __init__(self, root_threat: Threat):
        self.root_threat = root_threat

    def draw(self, output: str) -> None:
        """
        This method is called when we try to draw an attack tree object.

        Args:
          output (str): the location to save the rendered attack tree on disk.
        """
        graph = pygraphviz.AGraph(fontname=FONTFACE)

        # Recursively draw all child nodes.
        self.root_threat.draw(graph)

        graph.draw(output, prog="dot", args="-Gdpi=300")
        self._generated_dot = str(graph)
