from pygraphviz import AGraph
from uuid import UUID

from typing import Optional, Union


class Element:
    def __init__(self, identifier: Optional[str] = None):
        self.identifier = identifier

    def draw(self, graph: AGraph) -> None:
        graph.add_node(self.identifier)


class Dataflow(Element):
    def __init__(
        self,
        first_id: Union[str, UUID],
        second_id: Union[str, UUID],
        identifier: Optional[str] = None,
    ):
        super().__init__(identifier)

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
        identifier: Optional[str] = None,
    ):
        super().__init__(first_id, second_id, identifier)

    def draw(self, graph: AGraph) -> None:
        node_1 = graph.get_node(self.first_id)
        node_2 = graph.get_node(self.second_id)
        graph.add_edge(node_1, node_2, dir="both", arrowhead="normal")


class Process(Element):
    def __init__(self, identifier: Optional[str] = None):
        self.identifier = identifier

    def draw(self, graph: AGraph) -> None:
        graph.add_node(self.identifier, shape="circle")
