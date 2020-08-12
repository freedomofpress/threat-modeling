import os
import pytest
import yaml

from threat_modeling.data_flow import (
    Element,
    Dataflow,
    BidirectionalDataflow,
    Process,
    ExternalEntity,
    Datastore,
    Boundary,
)
from threat_modeling.enumeration.stride import NaiveSTRIDE
from threat_modeling.exceptions import DuplicateIdentifier
from threat_modeling.project import ThreatModel
from threat_modeling.mitigations import Mitigation
from threat_modeling.threats import Threat


def test_threat_model_str():
    my_threat_model = ThreatModel("my name")
    assert "my name" in str(my_threat_model)


def test_threat_model_repr():
    my_threat_model = ThreatModel("my name")
    assert "my name" in repr(my_threat_model)


def test_threat_model_saves_elements():
    server = Element(name="server", identifier="ELEMENT1", description="My test server")
    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)

    assert server.identifier in my_threat_model


def test_threat_model_get_element_by_id():
    test_id = "Server"
    server = Element(
        name="Primary server", identifier=test_id, description="My test server"
    )
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

    tamper_traffic = Threat(name="Attacker tampers with user's network traffic")

    # Ensures that an identifying uuid has been generated if it wasn't provided
    assert tamper_traffic.identifier

    my_threat_model = ThreatModel()

    my_threat_model.add_threat(tamper_traffic)

    assert tamper_traffic.identifier in my_threat_model


def test_threat_model_contains_threat_not_in():
    tamper_traffic = Threat(name="Attacker tampers with user's network traffic")

    my_threat_model = ThreatModel()

    assert tamper_traffic.identifier not in my_threat_model


def test_threat_model_getitem_threat_not_in():
    tamper_traffic = Threat(name="Attacker tampers with user's network traffic")

    my_threat_model = ThreatModel()

    with pytest.raises(KeyError):
        my_threat_model[tamper_traffic.identifier]


def test_threat_model_get_threat_by_id():
    tamper_traffic = Threat(name="Attacker tampers with user's network traffic")
    my_threat_model = ThreatModel()

    my_threat_model.add_threat(tamper_traffic)

    assert my_threat_model[tamper_traffic.identifier]


def test_threat_model_get_mitigation_by_id():
    mitig = Mitigation(name="countermeasure McCountermeasure")
    my_threat_model = ThreatModel()

    my_threat_model.add_mitigation(mitig)

    assert my_threat_model[mitig.identifier]


def test_threat_model_disallows_adding_duplicate_threats():
    tamper_traffic = Threat(identifier="a", name="foo")
    my_threat_model = ThreatModel()

    my_threat_model.add_threat(tamper_traffic)

    with pytest.raises(DuplicateIdentifier):
        my_threat_model.add_threat(tamper_traffic)


def test_threat_model_disallows_adding_threats_that_duplicate_an_element():
    tamper_traffic = Threat(identifier="a", name="This doesn't really matter")
    server = Element(name="Primary server", identifier="a")
    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)

    with pytest.raises(DuplicateIdentifier):
        my_threat_model.add_threat(tamper_traffic)


def test_threat_model_disallows_adding_elements_that_duplicate_a_threat():
    tamper_traffic = Threat(identifier="a", name="This doesn't really matter")
    server = Element(name="Primary server", identifier="a")
    my_threat_model = ThreatModel()

    my_threat_model.add_threat(tamper_traffic)

    with pytest.raises(DuplicateIdentifier):
        my_threat_model.add_element(server)


def test_threat_model_disallows_adding_elements_that_duplicate_a_mitigation():
    mitig = Mitigation(identifier="a", name="This doesn't really matter")
    server = Element(name="Primary server", identifier="a")
    my_threat_model = ThreatModel()

    my_threat_model.add_mitigation(mitig)

    with pytest.raises(DuplicateIdentifier):
        my_threat_model.add_element(server)


def test_threat_model_disallows_adding_dataflows_without_corresponding_source():
    test_id_1 = "Server"
    server = Element(name="Primary server", identifier=test_id_1)
    test_id_2 = "Client"
    dataflow_id = "HTTP"
    http_traffic = Dataflow(
        name=dataflow_id,
        identifier=dataflow_id,
        first_id=test_id_2,
        second_id=test_id_1,
    )

    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)
    with pytest.raises(ValueError):
        my_threat_model.add_element(http_traffic)


def test_threat_model_draws_data_flow_diagram_two_elements(request, tmpdir):
    test_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "files/{}.dot".format(request.node.name),
    )
    with open(test_file) as f:
        expected_dot = f.read()

    test_id_1 = "Server"
    server = Element(name=test_id_1, identifier=test_id_1)
    test_id_2 = "Client"
    client = Element(name=test_id_2, identifier=test_id_2)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)
    my_threat_model.add_element(client)

    my_threat_model.draw("{}/test.png".format(str(tmpdir)))
    assert my_threat_model._generated_dot == expected_dot


def test_threat_model_draws_data_flow_diagram_two_elements_single_dataflow(tmpdir):
    test_id_1 = "Server"
    server = Element(name=test_id_1, identifier=test_id_1)
    test_id_2 = "Client"
    client = Element(name=test_id_1, identifier=test_id_2)
    dataflow_id = "HTTP"
    http_traffic = Dataflow(
        name=dataflow_id,
        identifier=dataflow_id,
        first_id=test_id_2,
        second_id=test_id_1,
    )

    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)
    my_threat_model.add_element(client)
    my_threat_model.add_element(http_traffic)

    my_threat_model.draw("{}/test.png".format(str(tmpdir)))


def test_threat_model_draws_data_flow_diagram_two_elements_bidirectionaldataflow(
    tmpdir,
):
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

    my_threat_model.draw("{}/test.png".format(str(tmpdir)))


def test_threat_model_draws_data_flow_diagram_process(tmpdir):
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

    my_threat_model.draw("{}/test.png".format(str(tmpdir)))


def test_threat_model_draws_data_flow_diagram_external_entity(tmpdir):
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

    my_threat_model.draw("{}/test.png".format(str(tmpdir)))


def test_threat_model_draws_data_flow_diagram_duplicate_elements(tmpdir):
    name_1 = "apt server"
    test_id_1 = "APT_EXTERNAL_1"
    server_1 = ExternalEntity(name=name_1, identifier=test_id_1)
    name_2 = "apt server"
    test_id_2 = "APT_EXTERNAL_2"
    server_2 = ExternalEntity(name=name_2, identifier=test_id_2)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(server_1)
    my_threat_model.add_element(server_2)

    my_threat_model.draw("{}/test.png".format(str(tmpdir)))


def test_threat_model_draws_data_flow_diagram_data_store(tmpdir):
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

    my_threat_model.draw("{}/test.png".format(str(tmpdir)))


def test_threat_model_draws_data_flow_diagram_boundary(tmpdir):
    test_id_1 = "Web application"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)

    # Dataflows should not be in graphs
    boundary = Boundary("trust", [test_id_1, test_id_2])

    my_threat_model = ThreatModel()

    my_threat_model.add_element(webapp)
    my_threat_model.add_element(db)
    my_threat_model.add_element(boundary)

    my_threat_model.draw("{}/test.png".format(str(tmpdir)))


def test_threat_model_draws_data_flow_diagram_nested_boundary(tmpdir):
    test_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "files/nested.dot"
    )
    with open(test_file) as f:
        expected_dot = f.read()

    test_id_1 = "Web application frontend"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    test_id_3 = "Web application backend"
    webapp_2 = Process(name=test_id_3, identifier=test_id_3)

    boundary = Boundary("trust", [test_id_1, test_id_3, test_id_2], identifier="trust")
    boundary_2 = Boundary(
        "webapp", [test_id_1, test_id_3], parent=boundary, identifier="webapp"
    )

    my_threat_model = ThreatModel()

    my_threat_model.add_element(webapp)
    my_threat_model.add_element(db)
    my_threat_model.add_element(webapp_2)

    # Parent is added before child
    my_threat_model.add_element(boundary)
    my_threat_model.add_element(boundary_2)

    my_threat_model.draw("{}/test.png".format(str(tmpdir)))
    assert my_threat_model._generated_dot == expected_dot


def test_threat_model_draws_data_flow_diagram_nested_boundary_reverse_order(tmpdir):
    test_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "files/nested.dot"
    )
    with open(test_file) as f:
        expected_dot = f.read()

    test_id_1 = "Web application frontend"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    test_id_3 = "Web application backend"
    webapp_2 = Process(name=test_id_3, identifier=test_id_3)

    boundary = Boundary("trust", [test_id_1, test_id_3, test_id_2], identifier="trust")
    boundary_2 = Boundary(
        "webapp", [test_id_1, test_id_3], parent=boundary, identifier="webapp"
    )

    my_threat_model = ThreatModel()

    my_threat_model.add_element(webapp)
    my_threat_model.add_element(db)
    my_threat_model.add_element(webapp_2)

    # Child is added before parent.
    my_threat_model.add_element(boundary_2)
    my_threat_model.add_element(boundary)

    my_threat_model.draw("{}/test.png".format(str(tmpdir)))
    assert my_threat_model._generated_dot == expected_dot


def test_threat_model_draws_data_flow_diagram_nested_boundary_add_by_boundary(tmpdir):
    test_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "files/nested.dot"
    )
    with open(test_file) as f:
        expected_dot = f.read()

    test_id_1 = "Web application frontend"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    test_id_3 = "Web application backend"
    webapp_2 = Process(name=test_id_3, identifier=test_id_3)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(webapp)
    my_threat_model.add_element(db)
    my_threat_model.add_element(webapp_2)

    boundary_2 = Boundary("webapp", [test_id_1, test_id_3], identifier="webapp")
    my_threat_model.add_element(boundary_2)
    boundary = Boundary("trust", [boundary_2.identifier, test_id_2], identifier="trust")
    my_threat_model.add_element(boundary)

    my_threat_model.draw("{}/test.png".format(str(tmpdir)))
    assert my_threat_model._generated_dot == expected_dot


def test_project_load_simple_yaml_boundaries_nodes_flows():
    test_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "files/simple.yaml"
    )

    model = ThreatModel.load(test_file)

    assert len(model._elements) == 4
    assert len(model._boundaries) == 1


def test_threat_model_draws_data_flow_diagram_nested_boundary_add_by_boundary_save(
    tmpdir,
):
    test_id_1 = "Web application frontend"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    test_id_3 = "Web application backend"
    webapp_2 = Process(name=test_id_3, identifier=test_id_3)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(webapp)
    my_threat_model.add_element(db)
    my_threat_model.add_element(webapp_2)

    boundary_2 = Boundary("webapp", [test_id_1, test_id_3], identifier="webapp")
    my_threat_model.add_element(boundary_2)
    boundary = Boundary("trust", [boundary_2.identifier, test_id_2], identifier="trust")
    my_threat_model.add_element(boundary)

    my_threat_model.save("{}/test.yaml".format(str(tmpdir)))


def test_threat_model_load_threats_from_yaml():
    test_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "files/simple_with_threats.yaml"
    )

    model = ThreatModel.load(test_file)

    assert len(model._elements) == 4
    assert len(model._boundaries) == 1
    assert len(model._threats) == 2


def test_threat_model_save_threats(tmpdir,):
    test_id_1 = "Web application frontend"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    test_id_3 = "Web application backend"
    webapp_2 = Process(name=test_id_3, identifier=test_id_3)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(webapp)
    my_threat_model.add_element(db)
    my_threat_model.add_element(webapp_2)

    threat_2 = Threat(
        name="Weak password hashing used",
        identifier="THREAT2",
        status="unmanaged",
        base_exploitability="medium",
        base_impact="medium",
    )
    threat = Threat(
        name="SQLi in web application",
        identifier="THREAT1",
        description="Attacker can dump the user table",
        status="unmanaged",
        base_impact="medium",
        base_exploitability="medium",
        child_threats=[threat_2],
    )
    my_threat_model.add_threat(threat)
    my_threat_model.add_threat(threat_2)

    output_file = "{}/test.yaml".format(str(tmpdir))
    my_threat_model.save(output_file)

    with open(output_file) as f:
        result = yaml.load(f, Loader=yaml.SafeLoader)

    for item in result["threats"]:
        assert item["status"].lower() == "unmanaged"
        assert item["base_exploitability"].lower() == "medium"
        assert item["base_impact"].lower() == "medium"


def test_threat_model_generates_attack_trees(tmpdir):
    test_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "files/threat_tree.yaml"
    )
    threat_model = ThreatModel.load(test_file)
    threat_model.draw_attack_trees(str(tmpdir))


def test_threat_model_generates_attack_trees_no_output_directory(tmpdir):
    test_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "files/threat_tree.yaml"
    )
    threat_model = ThreatModel.load(test_file)
    with pytest.raises(FileNotFoundError):
        threat_model.draw_attack_trees(str(tmpdir) + "teehee")


def test_threat_model_threat_enumeration(tmpdir,):
    test_id_1 = "Web application frontend"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    test_id_3 = "Web application backend"
    webapp_2 = Process(name=test_id_3, identifier=test_id_3)

    my_threat_model = ThreatModel()

    my_threat_model.add_element(webapp)
    my_threat_model.add_element(db)
    my_threat_model.add_element(webapp_2)

    method = NaiveSTRIDE()
    threats = my_threat_model.generate_threats(method)

    assert len(threats) == 6 * 3


def test_threat_model_check_fail_on_unmanaged_threats(tmpdir):
    test_id_1 = "Web application frontend"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    test_id_3 = "Web application backend"
    webapp_2 = Process(name=test_id_3, identifier=test_id_3)

    threat_2 = Threat(
        name="Weak password hashing used",
        identifier="THREAT2",
        status="unmanaged",
        base_exploitability="medium",
        base_impact="medium",
    )
    threat = Threat(
        name="SQLi in web application",
        identifier="THREAT1",
        description="Attacker can dump the user table",
        status="unmanaged",
        base_impact="medium",
        base_exploitability="medium",
        child_threats=[threat_2],
    )

    my_threat_model = ThreatModel()

    my_threat_model.add_threat(threat)
    my_threat_model.add_threat(threat_2)

    my_threat_model.add_element(webapp)
    my_threat_model.add_element(db)
    my_threat_model.add_element(webapp_2)

    result, is_passed = my_threat_model.check()

    assert not is_passed


def test_threat_model_check_populates_child_threats(tmpdir):
    test_id_1 = "Web application frontend"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    test_id_3 = "Web application backend"
    webapp_2 = Process(name=test_id_3, identifier=test_id_3)

    threat_2 = Threat(
        name="Weak password hashing used",
        identifier="THREAT2",
        status="Managed Accepted",
        base_exploitability="medium",
        base_impact="medium",
    )
    threat = Threat(
        name="SQLi in web application",
        identifier="THREAT1",
        description="Attacker can dump the user table",
        status="Managed Accepted",
        base_impact="medium",
        base_exploitability="medium",
        child_threat_ids=["THREAT2"],
    )

    my_threat_model = ThreatModel()

    my_threat_model.add_threat(threat)
    my_threat_model.add_threat(threat_2)

    assert threat_2 not in threat.child_threats
    assert threat.child_threat_ids == ["THREAT2"]

    my_threat_model.add_element(webapp)
    my_threat_model.add_element(db)
    my_threat_model.add_element(webapp_2)

    result, is_passed = my_threat_model.check()

    assert is_passed
    assert threat_2 in threat.child_threats
    assert threat.child_threat_ids == ["THREAT2"]


def test_threat_model_check_fails_on_unknown_child_threats(tmpdir):
    test_id_1 = "Web application frontend"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    test_id_3 = "Web application backend"
    webapp_2 = Process(name=test_id_3, identifier=test_id_3)

    threat = Threat(
        name="SQLi in web application",
        identifier="THREAT1",
        description="Attacker can dump the user table",
        status="Managed Accepted",
        base_impact="medium",
        base_exploitability="medium",
        child_threat_ids=["THREAT3"],
    )

    my_threat_model = ThreatModel()

    my_threat_model.add_threat(threat)

    assert threat.child_threat_ids == ["THREAT3"]

    my_threat_model.add_element(webapp)
    my_threat_model.add_element(db)
    my_threat_model.add_element(webapp_2)

    result, is_passed = my_threat_model.check()

    assert not is_passed
    assert threat.child_threat_ids == ["THREAT3"]


def test_threat_model_check_populates_child_threat_ids(tmpdir):
    test_id_1 = "Web application frontend"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    test_id_3 = "Web application backend"
    webapp_2 = Process(name=test_id_3, identifier=test_id_3)

    threat_2 = Threat(
        name="Weak password hashing used",
        identifier="THREAT2",
        status="Managed Accepted",
        base_exploitability="medium",
        base_impact="medium",
    )
    threat = Threat(
        name="SQLi in web application",
        identifier="THREAT1",
        description="Attacker can dump the user table",
        status="Managed Accepted",
        base_impact="medium",
        base_exploitability="medium",
        child_threats=[threat_2],
    )
    threat.child_threat_ids = []

    my_threat_model = ThreatModel()

    my_threat_model.add_threat(threat)
    my_threat_model.add_threat(threat_2)

    assert "THREAT2" not in threat.child_threat_ids

    my_threat_model.add_element(webapp)
    my_threat_model.add_element(db)
    my_threat_model.add_element(webapp_2)

    result, is_passed = my_threat_model.check()

    assert is_passed
    assert threat.child_threat_ids == ["THREAT2"]


def test_threat_model_check_populates_mitigations(tmpdir):
    threat_2 = Threat(
        name="Weak password hashing used",
        identifier="THREAT2",
        status="Managed Accepted",
        base_exploitability="medium",
        base_impact="medium",
    )
    threat = Threat(
        name="SQLi in web application",
        identifier="THREAT1",
        description="Attacker can dump the user table",
        status="Managed Accepted",
        base_impact="medium",
        base_exploitability="medium",
        child_threat_ids=["THREAT2"],
        mitigation_ids=["MITIG1"],
    )

    mitig = Mitigation("prepared statements", "MITIG1")

    my_threat_model = ThreatModel()

    my_threat_model.add_threat(threat)
    my_threat_model.add_threat(threat_2)
    my_threat_model.add_mitigation(mitig)

    result, is_passed = my_threat_model.check()

    assert is_passed
    assert mitig in threat.mitigations
    assert threat.mitigation_ids == ["MITIG1"]


def test_threat_model_check_fails_on_unknown_mitigations(tmpdir):
    threat_2 = Threat(
        name="Weak password hashing used",
        identifier="THREAT2",
        status="Managed Accepted",
        base_exploitability="medium",
        base_impact="medium",
    )
    threat = Threat(
        name="SQLi in web application",
        identifier="THREAT1",
        description="Attacker can dump the user table",
        status="Managed Accepted",
        base_impact="medium",
        base_exploitability="medium",
        child_threat_ids=["THREAT2"],
        mitigation_ids=["MITIG1"],
    )

    my_threat_model = ThreatModel()

    my_threat_model.add_threat(threat)
    my_threat_model.add_threat(threat_2)

    result, is_passed = my_threat_model.check()

    assert not is_passed


def test_threat_model_check_populates_mitigation_ids(tmpdir):
    mitig = Mitigation("prepared statements", "MITIG1")
    threat_2 = Threat(
        name="Weak password hashing used",
        identifier="THREAT2",
        status="Managed Accepted",
        base_exploitability="medium",
        base_impact="medium",
    )
    threat = Threat(
        name="SQLi in web application",
        identifier="THREAT1",
        description="Attacker can dump the user table",
        status="Managed Accepted",
        base_impact="medium",
        base_exploitability="medium",
        child_threat_ids=["THREAT2"],
        mitigations=[mitig],
    )
    threat.mitigation_ids = []

    my_threat_model = ThreatModel()

    my_threat_model.add_threat(threat)
    my_threat_model.add_threat(threat_2)
    my_threat_model.add_mitigation(mitig)

    result, is_passed = my_threat_model.check()

    assert is_passed
    assert mitig in threat.mitigations
    assert "MITIG1" in threat.mitigation_ids
