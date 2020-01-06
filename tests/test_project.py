import pytest

from threat_modeling.data_flow import (Element, Dataflow, BidirectionalDataflow,
                                       Process, ExternalEntity, Datastore, Boundary)
from threat_modeling.exceptions import DuplicateIdentifier
from threat_modeling.project import ThreatModel
from threat_modeling.threats import Threat


def test_threat_model_saves_elements():
    server = Element(name="server", identifier="ELEMENT1", description="My test server")
    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)

    assert server.identifier in my_threat_model


def test_threat_model_get_element_by_id():
    test_id = "Server"
    server = Element(name="Primary server", identifier=test_id,
                     description="My test server")
    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)

    assert my_threat_model[test_id]


def test_threat_model_disallows_adding_duplicate_elements():
    test_id = "Server"
    server = Element(name="Primary server", identifier=test_id)
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
    server = Element(name="Primary server", identifier="a")
    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)

    with pytest.raises(DuplicateIdentifier):
        my_threat_model.add_threat(tamper_traffic)


def test_threat_model_disallows_adding_elements_that_duplicate_a_threat():
    tamper_traffic = Threat(identifier="a", description="This doesn't really matter")
    server = Element(name="Primary server", identifier="a")
    my_threat_model = ThreatModel()

    my_threat_model.add_threat(tamper_traffic)

    with pytest.raises(DuplicateIdentifier):
        my_threat_model.add_element(server)


def test_threat_model_disallows_adding_dataflows_without_corresponding_source():
    test_id_1 = "Server"
    server = Element(name="Primary server", identifier=test_id_1)
    test_id_2 = "Client"
    dataflow_id = "HTTP"
    http_traffic = Dataflow(name=dataflow_id, identifier=dataflow_id,
                            first_id=test_id_2,
                            second_id=test_id_1)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)
    with pytest.raises(ValueError):
        my_threat_model.add_element(http_traffic)


def test_threat_model_draws_data_flow_diagram_two_elements():
    test_id_1 = "Server"
    server = Element(name=test_id_1, identifier=test_id_1)
    test_id_2 = "Client"
    client = Element(name=test_id_2, identifier=test_id_2)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)
    my_threat_model.add_element(client)

    my_threat_model.draw()


def test_threat_model_draws_data_flow_diagram_two_elements_single_dataflow():
    test_id_1 = "Server"
    server = Element(name=test_id_1, identifier=test_id_1)
    test_id_2 = "Client"
    client = Element(name=test_id_1, identifier=test_id_2)
    dataflow_id = "HTTP"
    http_traffic = Dataflow(name=dataflow_id, identifier=dataflow_id,
                            first_id=test_id_2,
                            second_id=test_id_1)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)
    my_threat_model.add_element(client)
    my_threat_model.add_element(http_traffic)

    my_threat_model.draw()


def test_threat_model_draws_data_flow_diagram_two_elements_bidirectionaldataflow():
    test_id_1 = "Server"
    server = Element(name=test_id_1, identifier=test_id_1)
    test_id_2 = "Client"
    client = Element(name=test_id_2, identifier=test_id_2)
    dataflow_id = "HTTP"
    http_traffic = BidirectionalDataflow(test_id_2, test_id_1, dataflow_id, dataflow_id)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)
    my_threat_model.add_element(client)
    my_threat_model.add_element(http_traffic)

    my_threat_model.draw()


def test_threat_model_draws_data_flow_diagram_process():
    test_id_1 = "sshd"
    server = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "ssh client"
    client = Element(name=test_id_2, identifier=test_id_2)
    dataflow_id = "ssh traffic"
    traffic = BidirectionalDataflow(test_id_2, test_id_1, dataflow_id, dataflow_id)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)
    my_threat_model.add_element(client)
    my_threat_model.add_element(traffic)

    my_threat_model.draw()


def test_threat_model_draws_data_flow_diagram_external_entity():
    test_id_1 = "cron-apt"
    cron = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "apt server"
    server = ExternalEntity(name=test_id_2, identifier=test_id_2)
    dataflow_id = "apt traffic"
    traffic = Dataflow(test_id_2, test_id_1, dataflow_id, dataflow_id)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(cron)
    my_threat_model.add_element(server)
    my_threat_model.add_element(traffic)

    my_threat_model.draw()


def test_threat_model_draws_data_flow_diagram_duplicate_elements():
    name_1 = "apt server"
    test_id_1 = "APT_EXTERNAL_1"
    server_1 = ExternalEntity(name=name_1, identifier=test_id_1)
    name_2 = "apt server"
    test_id_2 = "APT_EXTERNAL_2"
    server_2 = ExternalEntity(name=name_2, identifier=test_id_2)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(server_1)
    my_threat_model.add_element(server_2)

    my_threat_model.draw()


def test_threat_model_draws_data_flow_diagram_data_store():
    test_id_1 = "Web application"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    dataflow_id = "SQL"
    traffic = Dataflow(test_id_1, test_id_2, dataflow_id, dataflow_id)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(webapp)
    my_threat_model.add_element(db)
    my_threat_model.add_element(traffic)

    my_threat_model.draw()


def test_threat_model_draws_data_flow_diagram_boundary():
    test_id_1 = "Web application"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)

    # Dataflows should not be in graphs
    boundary = Boundary([test_id_1, test_id_2], 'trust')

    my_threat_model = ThreatModel()

    my_threat_model.add_element(webapp)
    my_threat_model.add_element(db)
    my_threat_model.add_element(boundary)

    my_threat_model.draw()


def test_threat_model_draws_data_flow_diagram_nested_boundary():
    test_id_1 = "Web application frontend"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    test_id_3 = "Web application backend"
    webapp_2 = Process(name=test_id_3, identifier=test_id_3)

    boundary = Boundary([test_id_1, test_id_3, test_id_2], 'trust')
    boundary_2 = Boundary([test_id_1, test_id_3], 'webapp')

    my_threat_model = ThreatModel()

    my_threat_model.add_element(webapp)
    my_threat_model.add_element(db)
    my_threat_model.add_element(webapp_2)
    my_threat_model.add_element(boundary)
    my_threat_model.add_element(boundary_2)

    my_threat_model.draw()
