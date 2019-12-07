import pytest

from threat_modeling.data_flow import Element
from threat_modeling.exceptions import DuplicateIdentifier
from threat_modeling.project import ThreatModel


def test_threat_model_saves_elements():
    server = Element(identifier="Server")
    my_threat_model = ThreatModel()

    my_threat_model.add_element(server)

    assert server in my_threat_model


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
