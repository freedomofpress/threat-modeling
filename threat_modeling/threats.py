import pygraphviz
import reprlib
from uuid import uuid4, UUID

from typing import List, Optional, Union, Type, TypeVar

from threat_modeling.data_flow import FONTFACE, FONTSIZE, ELEMENT_COLOR

TH = TypeVar("TH", bound="Threat")


class Threat:
    STYLE = "filled"
    COLOR = ELEMENT_COLOR
    SHAPE = "rectangle"

    def __init__(
        self,
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
        child_threats: Optional[List[Type[TH]]] = None,
    ):
        if not identifier:
            identifier = uuid4()

        self.identifier = identifier

        if description:
            self.description = description

        # Child threats are those that become exploitable if _this_
        # threat is successfully exploited. This is used for the
        # construction and display of AttackTrees.
        if child_threats:
            self.child_threats = child_threats.copy()
        else:
            self.child_threats = []

    def __str__(self) -> str:
        return "<Threat {}: {}>".format(self.identifier, self.description)

    def __repr__(self) -> str:
        return "Threat({}, {})".format(self.identifier, reprlib.repr(self.description))

    def draw(self, graph: pygraphviz.AGraph) -> None:
        graph.add_node(
            self.identifier,
            label=self.description,
            fontsize=FONTSIZE,
            fontname=FONTFACE,
            style=self.STYLE,
            fillcolor=self.COLOR,
            shape=self.SHAPE,
        )

        for child_threat in self.child_threats:
            # The below line mypy reports error: Too few arguments for "draw" of
            # "Threat".
            # TODO: This is a false positive but I'm not sure why (something to do with
            # the custom TypeDef for TH... ?).
            child_threat.draw(graph)  # type: ignore
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
    def __init__(self, root_threat: Threat):
        self.root_threat = root_threat

    def draw(self, output: Optional[str] = None) -> str:
        if not output:
            output = "{}.png".format(self.root_threat.identifier)

        graph = pygraphviz.AGraph(fontname=FONTFACE)

        # This will recursively draw all child nodes.
        self.root_threat.draw(graph)

        graph.draw(output, prog="dot", args="-Gdpi=300")
        self._generated_dot = str(graph)

        return output
