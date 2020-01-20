import os
import pytest

from threat_modeling.data_flow import BidirectionalDataflow
from threat_modeling.serialization import load  # , save
from threat_modeling.project import ThreatModel


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


def test_save_simple_yaml_boundaries_nodes_flows(request, tmpdir):
    test_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "files/simple_all_ids.yaml"
    )

    tm = ThreatModel.load(test_file)

    test_save_file = "{}.yaml".format(request.node.name)

    tm.save(test_save_file)

    (
        saved_name,
        saved_description,
        saved_nodes,
        saved_boundaries,
        saved_dataflows,
    ) = load(test_save_file)

    assert tm.name == saved_name
    assert tm.description == saved_description
    assert (
        list(tm.elements.values()) == saved_nodes + saved_boundaries + saved_dataflows
    )
