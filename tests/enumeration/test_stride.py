from threat_modeling.enumeration.stride import NaiveSTRIDE
from threat_modeling.data_flow import (
    Process,
    Datastore,
)


def test_naive_stride_generation():
    test_id_1 = "Web application frontend"
    webapp = Process(name=test_id_1, identifier=test_id_1)
    test_id_2 = "db"
    db = Datastore(name=test_id_2, identifier=test_id_2)
    test_id_3 = "Web application backend"
    webapp_2 = Process(name=test_id_3, identifier=test_id_3)

    method = NaiveSTRIDE()
    threats = method.generate([], [webapp, db, webapp_2])

    assert len(threats) == 6 * 3
