from pygraphviz import AGraph
from uuid import UUID, uuid4

from typing import Optional, Union


class Element:
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

    def draw(self, graph: AGraph) -> None:
        graph.add_node(self.identifier, label=self.name)


class Dataflow(Element):
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

    def draw(self, graph: AGraph) -> None:
        source_node = graph.get_node(self.first_id)
        dest_node = graph.get_node(self.second_id)
        graph.add_edge(source_node, dest_node, dir="forward", arrowhead="normal")


class BidirectionalDataflow(Dataflow):
    def __init__(
        self,
        first_id: Union[str, UUID],
        second_id: Union[str, UUID],
        name: str,
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
    ):
        super().__init__(first_id, second_id, name, identifier, description)

    def draw(self, graph: AGraph) -> None:
        node_1 = graph.get_node(self.first_id)
        node_2 = graph.get_node(self.second_id)
        graph.add_edge(node_1, node_2, dir="both", arrowhead="normal", label=self.name)


class Process(Element):
    def __init__(
        self,
        name: str,
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
    ):
        super().__init__(name, identifier, description)

    def draw(self, graph: AGraph) -> None:
        graph.add_node(self.identifier, shape="circle", label=self.name)


class ExternalEntity(Element):
    def __init__(
        self,
        name: str,
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
    ):
        super().__init__(name, identifier, description)

    def draw(self, graph: AGraph) -> None:
        graph.add_node(self.identifier, shape="rectangle", label=self.name)


class Datastore(Element):
    def __init__(
        self,
        name: str,
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
    ):
        super().__init__(name, identifier, description)

    def draw(self, graph: AGraph) -> None:
        graph.add_node(self.identifier, shape="cylinder", label=self.name)
