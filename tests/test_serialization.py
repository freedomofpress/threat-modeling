import os
import pytest

from threat_modeling.data_flow import BidirectionalDataflow
from threat_modeling.serialization import load


def test_load_simple_yaml_boundaries_nodes_flows():
    test_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "files/simple.yaml"
    )

    (name, description, nodes, boundaries, dataflows) = load(test_file)

    assert name == "Example"
    assert description == "Example threat model"
    assert len(nodes) == 2
    for node in nodes:
        assert node.name
        assert node.identifier
    assert len(boundaries) == 1
    assert len(dataflows) == 1


def test_load_invalid_node_type():
    test_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "files/invalid_type.yaml"
    )

    with pytest.raises(TypeError):
        load(test_file)


def test_load_simple_yaml_bidirectional():
    test_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "files/bidirectional.yaml"
    )

    (name, description, nodes, boundaries, dataflows) = load(test_file)

    assert name == "Example"
    assert description == "Example threat model"
    assert len(nodes) == 2
    for node in nodes:
        assert node.name
        assert node.identifier
    assert len(boundaries) == 1
    assert len(dataflows) == 1
    assert type(dataflows[0]) == BidirectionalDataflow
