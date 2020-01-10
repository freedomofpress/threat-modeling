import yaml

from typing import List, Tuple, Union

from threat_modeling.data_flow import (
    Element,
    Dataflow,
    BidirectionalDataflow,
    Process,
    ExternalEntity,
    Datastore,
    Boundary,
)


node_dispatch = {
    "ExternalEntity": ExternalEntity,
    "Process": Process,
    "Element": Element,
    "Datastore": Datastore,
}


def load(
    config: str,
) -> Tuple[
    str,
    str,
    List[Union[Element, ExternalEntity, Process, Datastore]],
    List[Boundary],
    List[Union[Dataflow, BidirectionalDataflow]],
]:
    with open(config) as f:
        config_data = yaml.load(f, Loader=yaml.SafeLoader)

    nodes = []
    for node in config_data.get("nodes", []):
        if node["type"] not in node_dispatch.keys():
            raise TypeError("Invalid type for node: {}".format(node["type"]))
        identifier = node.get("id", None)
        description = node.get("description", None)
        node_obj = node_dispatch[node["type"]](node["name"], identifier, description)
        nodes.append(node_obj)

    boundaries = []
    for boundary in config_data.get("boundaries", []):
        identifier = boundary.get("id", None)
        name = boundary.get("name", None)
        description = boundary.get("description", None)
        members = boundary.get("members", [])
        parent = boundary.get("parent", None)
        boundary_obj = Boundary(name, members, identifier, description, parent)
        boundaries.append(boundary_obj)

    dataflows: List[Union[Dataflow, BidirectionalDataflow]] = []
    for dataflow in config_data.get("dataflows", []):
        bidirectional = dataflow.get("bidirectional", False)
        identifier = dataflow.get("id", None)
        description = dataflow.get("description", None)
        if bidirectional:
            bidataflow_obj = BidirectionalDataflow(
                dataflow["first_node"],
                dataflow["second_node"],
                dataflow["name"],
                identifier,
                description,
            )
            dataflows.append(bidataflow_obj)
        else:
            dataflow_obj = Dataflow(
                dataflow["first_node"],
                dataflow["second_node"],
                dataflow["name"],
                identifier,
                description,
            )
            dataflows.append(dataflow_obj)

    name = config_data.get("name", None)
    description = config_data.get("description", None)

    return (name, description, nodes, boundaries, dataflows)
