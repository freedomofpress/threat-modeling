from threat_modeling.enumeration.stride import NaiveSTRIDE
from threat_modeling.data_flow import (
    Boundary,
    Process,
    Datastore,
)
from threat_modeling.project import ThreatModel


def test_naive_stride_generation():
    test_id_1 = "Web application frontend"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    test_id_3 = "Web application backend"
    webapp_2 = Process(name=test_id_3, identifier=test_id_3)

    method = NaiveSTRIDE()
    threats = method.generate([webapp, db, webapp_2])

    assert len(threats) == 6 * 3


def test_naive_stride_generation_excludes_boundary():
    test_id_1 = "Web application frontend"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    test_id_3 = "Web application backend"
    webapp_2 = Process(name=test_id_3, identifier=test_id_3)
    boundary = Boundary(name="foo", members=[])

    method = NaiveSTRIDE()
    threats = method.generate([webapp, db, webapp_2, boundary])

    assert len(threats) == 6 * 3


def test_naive_stride_generation_does_not_duplicate_threats_if_called_again():
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

    # If we call generate_threats again, we don't add any duplicates.
    threats = my_threat_model.generate_threats(method)

    assert len(threats) == 6 * 3
