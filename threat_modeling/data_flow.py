from pygraphviz import AGraph
import reprlib
from uuid import UUID, uuid4

from typing import List, Optional, Type, TypeVar, Union


FONTSIZE = 10.0
FONTFACE = "Times-Roman"

# Colors here loosely based on seaborn
ELEMENT_COLOR = "#DF9AA4"
PROCESS_COLOR = "#C1DECA"
EXTERNAL_COLOR = "#65A9A4"
DATASTORE_COLOR = "#B3AAE6"


T = TypeVar("T", bound="Dataflow")


class Element:
    SHAPE: Optional[str] = None  # Default
    STYLE = "filled"
    COLOR = ELEMENT_COLOR

    def __init__(
        self,
        name: str,
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
    ):

        if not identifier:
            identifier = uuid4()
        self.identifier = identifier

        # The name is what appears on the DFD node
        self.name = name

        # Extended information about this elements can be stored in the description
        self.description = description

    def __str__(self) -> str:
        return "<{}: {}>".format(self.__class__.__name__, self.name)

    def __repr__(self) -> str:
        return '{}("{}", "{}", "{}")'.format(
            self.__class__.__name__,
            self.name,
            self.identifier,
            reprlib.repr(self.description),
        )

    def __eq__(self, other: object) -> bool:
        if (
            self.name == getattr(other, "name", None)
            and self.identifier == getattr(other, "identifier", None)
            and self.description == getattr(other, "description", None)
        ):
            return True
        return False

    def __hash__(self) -> int:
        return hash(self.name) ^ hash(self.identifier) ^ hash(self.description)

    def draw(self, graph: AGraph) -> None:
        kwargs = {
            "label": self.name,
            "fontsize": FONTSIZE,
            "fontname": FONTFACE,
            "style": self.STYLE,
            "fillcolor": self.COLOR,
        }
        if self.SHAPE:
            graph.add_node(
                self.identifier, **kwargs, shape=self.SHAPE,
            )
        else:
            graph.add_node(
                self.identifier, **kwargs,
            )


class Dataflow(Element):
    DIRECTION = "forward"

    def __init__(
        self,
        first_id: Union[str, UUID],
        second_id: Union[str, UUID],
        name: str,
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
    ):
        super().__init__(name, identifier, description)

        if not first_id or not second_id:
            raise ValueError("two nodes required to define a dataflow")
        self.first_id = first_id
        self.second_id = second_id

    @classmethod
    def from_elements(
        cls: Type[T],
        first_element: Element,
        second_element: Element,
        name: str,
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
    ) -> T:
        return cls(
            first_element.identifier,
            second_element.identifier,
            name,
            identifier,
            description,
        )

    def __str__(self) -> str:
        return "<Dataflow {}: {} -> {}>".format(
            self.name, self.first_id, self.second_id
        )

    def __repr__(self) -> str:
        return '{}("{}", "{}, "{}", "{}", "{}")'.format(
            self.__class__.__name__,
            self.first_id,
            self.second_id,
            self.name,
            self.identifier,
            reprlib.repr(self.description),
        )

    def draw(self, graph: AGraph) -> None:
        source_node = graph.get_node(self.first_id)
        dest_node = graph.get_node(self.second_id)
        # We draw edges with a bit of padding around the label to prevent overlapping.
        graph.add_edge(
            source_node,
            dest_node,
            dir=self.DIRECTION,
            arrowhead="normal",
            label=" " + self.name + " ",
            fontsize=FONTSIZE - 2,
            fontname=FONTFACE,
        )


class BidirectionalDataflow(Dataflow):
    DIRECTION = "both"

    def __init__(
        self,
        first_id: Union[str, UUID],
        second_id: Union[str, UUID],
        name: str,
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
    ):
        super().__init__(first_id, second_id, name, identifier, description)

    def __str__(self) -> str:
        return "<BidirectionalDataflow {}: {} <-> {}>".format(
            self.name, self.first_id, self.second_id
        )


class Process(Element):
    SHAPE = "circle"
    STYLE = "filled"
    COLOR = PROCESS_COLOR

    def __init__(
        self,
        name: str,
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
    ):
        super().__init__(name, identifier, description)


class ExternalEntity(Element):
    SHAPE = "rectangle"
    STYLE = "filled"
    COLOR = EXTERNAL_COLOR

    def __init__(
        self,
        name: str,
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
    ):
        super().__init__(name, identifier, description)


class Datastore(Element):
    SHAPE = "cylinder"
    STYLE = "filled"
    COLOR = DATASTORE_COLOR

    def __init__(
        self,
        name: str,
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
    ):
        super().__init__(name, identifier, description)


class Boundary(Element):
    def __init__(
        self,
        name: str,
        members: List[Union[str, UUID]],
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
        parent: Optional[Element] = None,
        nodes: Optional[List[Union[str, UUID]]] = None,
    ):
        super().__init__(name, identifier, description)
        self.members = (
            members  # Contains identifiers for boundaries, nodes in this boundary
        )
        self.parent = parent
        self.nodes: List[Union[str, UUID]] = []

    def __str__(self) -> str:
        return "<Boundary {}: {}>".format(self.name, reprlib.repr(self.members))

    def __repr__(self) -> str:
        return 'Boundary("{}", {}, "{}", "{}", {}, {})'.format(
            self.name,
            reprlib.repr(self.members),
            self.identifier,
            reprlib.repr(self.description),
            self.parent,
            reprlib.repr(self.nodes),
        )

    def draw(self, graph: AGraph) -> None:
        # This will raise KeyError if a node is not present in the graph
        graphviz_nodes = [graph.get_node(x) for x in self.nodes]

        # Handle nested subgraphs
        subgraphs_to_use = set()
        for subgraph in graph.subgraphs():
            for member in self.members:
                if subgraph.has_node(member):
                    subgraphs_to_use.add(subgraph)

        if len(subgraphs_to_use) == 1:
            graph = subgraphs_to_use.pop()

        # Graphviz convention is that subgraphs are named with the prefix "cluster"
        graph.add_subgraph(
            graphviz_nodes,
            name="cluster_{}".format(str(self.identifier)),
            label=self.name,
            style="rounded, filled",
            fillcolor="#55555522",
            fontsize=FONTSIZE + 2,
            fontname=FONTFACE,
            labeljust="l",
        )
