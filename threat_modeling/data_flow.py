from pygraphviz import AGraph
import reprlib
from uuid import UUID, uuid4

from typing import List, Optional, Type, TypeVar, Union


FONTSIZE = 20.0
FONTFACE = "Times-Roman"

# Colors here loosely based on seaborn
ELEMENT_COLOR = "#DF9AA4"
PROCESS_COLOR = "#C1DECA"
EXTERNAL_COLOR = "#65A9A4"
DATASTORE_COLOR = "#B3AAE6"


T = TypeVar("T", bound="Dataflow")


class Element:
    """
    Element is the base class for all objects in the data flow diagram.
    It is a concrete implementation you can use directly (for example if no
    other Data flow diagram element fits your situation), or you can subclass
    and reimplement the `draw()` method to modify how the item will appear in
    the generated DFD.

    Args:
      name (str): a short name for the object. It does not need to be unique.
      identifier (str, UUID, optional): a unique ID for the object. If one is
         not provided it will be generated.
      description (str, optional): a longer description of the element.

    Examples:
      >>> elem = Element("Primary server")
      >>> str(elem)
      '<Element: Primary server>'
    """

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
        """
        This method is called when we try to draw a ThreatModel object.

        Args:
          graph (AGraph): the graphviz object that we will add a node to.
        """
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
    """
    Dataflow represents a flow of information from one element to another.
    The first node is the source and the second node is the sink.
    Bidirectional flows should use the BidirectionalDataflow object.

    Args:
      first_id (str, UUID): identifier for the first node (source)
      second_id (str, UUID): identifier for the second node (sink)
      name (str): a short name for the object. It does not need to be unique.
      identifier (str, UUID, optional): a unique ID for the object. If one is
         not provided it will be generated.
      description (str, optional): a longer description of the element.

    Examples:
      >>> source = Element("Client", "SOURCE1")
      >>> sink = Element("Server", "SOURCE2")
      >>> df = Dataflow("SOURCE1", "SOURCE2", "Client sends data to client")
    """

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
        """
        Alternative constructor for the Dataflow, where the source / first node
        and sink / second node are passed to the dataflow as an object instead of an
        ID.

        Args:
          first_element (Element): identifier for the first node (source)
          second_element (Element): identifier for the second node (sink)
          name (str): a short name for the object. It does not need to be unique.
          identifier (str, UUID, optional): a unique ID for the object. If one is
            not provided it will be generated.
          description (str, optional): a longer description of the element.

        Returns:
          dataflow instance

        Examples:
          >>> source = Element("Client", "SOURCE1")
          >>> sink = Element("Server", "SOURCE2")
          >>> df = Dataflow.from_elements(source, sink, "Client sends data to client")
        """
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
        """
        This method is called when we try to draw a ThreatModel object.

        Args:
          graph (AGraph): the graphviz object that we will add an edge to.
        """
        source_node = graph.get_node(self.first_id)
        dest_node = graph.get_node(self.second_id)
        graph.add_edge(
            source_node,
            dest_node,
            dir=self.DIRECTION,
            arrowhead="normal",
            label=self.name,
            fontsize=FONTSIZE - 2,
            fontname=FONTFACE,
        )


class BidirectionalDataflow(Dataflow):
    """
    BidirectionalDataflow is just like Dataflow except is treated where each
    connected node is both a source and a sink.

    It provides the same API as Dataflow.
    """

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
    """
    Process represents a component of the system that transforms data in
    some way.

    It provides the same API as Element.
    """

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
    """
    ExternalEntity represents an object that is outside of the system but otherwise
    interacts with it in some way. It could be a user, an external server or
    organization.

    It provides the same API as Element.
    """

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
    """
    Datastore represents a store of data for later use. It could be a configuration
    file, a database, a physical store of data like a magnetic tape, or some other
    format used to store data.

    It provides the same API as Element.
    """

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
    """
    Boundary represents a trust boundary in a system. For example, a boundary could
    exist around all elements inside the datacenter, or all elements on a given physical
    machine.

    Args:
      name (str): a short name for the object. It does not need to be unique.
      members (list[str, UUID]): a list of identifiers that correspond to nodes that
        are inside this boundary. The identifiers can include another boundary.
      identifier (str, UUID, optional): a unique ID for the object. If one is
         not provided it will be generated.
      description (str, optional): a longer description of the element.

    Examples:
      >>> source = Element("Client", "SOURCE1")
      >>> sink = Element("Server", "SOURCE2")
      >>> df = Dataflow("SOURCE1", "SOURCE2", "Client sends data to client")
    """

    def __init__(
        self,
        name: str,
        members: List[Union[str, UUID]],
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
        parent: Optional[Element] = None,
    ):
        super().__init__(name, identifier, description)
        self.members = (
            members  # Contains identifiers for boundaries, nodes in this boundary
        )
        self.parent = parent
        self.__nodes: List[Union[str, UUID]] = []

    def __str__(self) -> str:
        return "<Boundary {}: {}>".format(self.name, reprlib.repr(self.members))

    def __repr__(self) -> str:
        return 'Boundary("{}", {}, "{}", "{}", {})'.format(
            self.name,
            reprlib.repr(self.members),
            self.identifier,
            reprlib.repr(self.description),
            self.parent,
        )

    @property
    def nodes(self) -> List[Union[str, UUID]]:
        return self.__nodes

    @nodes.setter
    def nodes(self, nodes: List[Union[str, UUID]]) -> None:
        self.__nodes = nodes

    def draw(self, graph: AGraph) -> None:
        """
        This method is called when we try to draw a ThreatModel object.

        Args:
          graph (AGraph): the graphviz object that we will add a subgraph to.
        """
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
