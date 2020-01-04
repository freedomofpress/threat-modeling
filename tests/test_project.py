import pytest

from threat_modeling.data_flow import Element, Dataflow
from threat_modeling.exceptions import DuplicateIdentifier
from threat_modeling.project import ThreatModel
from threat_modeling.threats import Threat


def test_threat_model_saves_elements():
    server = Element(identifier="Server")
    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)

    assert server.identifier in my_threat_model


def test_threat_model_get_element_by_id():
    test_id = "Server"
    server = Element(identifier=test_id)
    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)

    assert my_threat_model[test_id]


def test_threat_model_disallows_adding_duplicate_elements():
    test_id = "Server"
    server = Element(identifier=test_id)
    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)

    with pytest.raises(DuplicateIdentifier):
        my_threat_model.add_element(server)


def test_threat_model_saves_threats():
    """This is used by an enumeration method or if the user wants to
    manually define threats"""

    tamper_traffic = Threat(description="Attacker tampers with user's network traffic")

    # Ensures that an identifying uuid has been generated if it wasn't provided
    assert tamper_traffic.identifier

    my_threat_model = ThreatModel()

    my_threat_model.add_threat(tamper_traffic)

    assert tamper_traffic.identifier in my_threat_model


def test_threat_model_contains_threat_not_in():
    tamper_traffic = Threat(description="Attacker tampers with user's network traffic")

    my_threat_model = ThreatModel()

    assert tamper_traffic.identifier not in my_threat_model


def test_threat_model_getitem_threat_not_in():
    tamper_traffic = Threat(description="Attacker tampers with user's network traffic")

    my_threat_model = ThreatModel()

    with pytest.raises(KeyError):
        my_threat_model[tamper_traffic.identifier]


def test_threat_model_get_threat_by_id():
    tamper_traffic = Threat(description="Attacker tampers with user's network traffic")
    my_threat_model = ThreatModel()

    my_threat_model.add_threat(tamper_traffic)

    assert my_threat_model[tamper_traffic.identifier]


def test_threat_model_disallows_adding_duplicate_threats():
    tamper_traffic = Threat(identifier='a', description="foo")
    my_threat_model = ThreatModel()

    my_threat_model.add_threat(tamper_traffic)

    with pytest.raises(DuplicateIdentifier):
        my_threat_model.add_threat(tamper_traffic)


def test_threat_model_disallows_adding_threats_that_duplicate_an_element():
    tamper_traffic = Threat(identifier="a", description="This doesn't really matter")
    server = Element(identifier="a")
    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)

    with pytest.raises(DuplicateIdentifier):
        my_threat_model.add_threat(tamper_traffic)


def test_threat_model_disallows_adding_elements_that_duplicate_a_threat():
    tamper_traffic = Threat(identifier="a", description="This doesn't really matter")
    server = Element(identifier="a")
    my_threat_model = ThreatModel()

    my_threat_model.add_threat(tamper_traffic)

    with pytest.raises(DuplicateIdentifier):
        my_threat_model.add_element(server)


def test_threat_model_disallows_adding_dataflows_without_corresponding_source():
    test_id_1 = "Server"
    server = Element(identifier=test_id_1)
    test_id_2 = "Client"
    dataflow_id = "HTTP"
    http_traffic = Dataflow(identifier=dataflow_id,
                            source_id=test_id_2,
                            dest_id=test_id_1)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)
    with pytest.raises(ValueError):
        my_threat_model.add_element(http_traffic)


def test_threat_model_draws_data_flow_diagram_two_elements():
    test_id_1 = "Server"
    server = Element(identifier=test_id_1)
    test_id_2 = "Client"
    client = Element(identifier=test_id_2)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)
    my_threat_model.add_element(client)

    my_threat_model.draw()


def test_threat_model_draws_data_flow_diagram_two_elements_single_dataflow():
    test_id_1 = "Server"
    server = Element(identifier=test_id_1)
    test_id_2 = "Client"
    client = Element(identifier=test_id_2)
    dataflow_id = "HTTP"
    http_traffic = Dataflow(identifier=dataflow_id,
                            source_id=test_id_2,
                            dest_id=test_id_1)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)
    my_threat_model.add_element(client)
    my_threat_model.add_element(http_traffic)

    my_threat_model.draw()
