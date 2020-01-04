import pytest

from threat_modeling.data_flow import Element, Dataflow


def test_element_can_be_defined():
    test_id_1 = "Server"
    Element(identifier=test_id_1)


def test_dataflow_without_source_id_disallowed():
    test_id_1 = "Server"
    with pytest.raises(ValueError):
        Dataflow(identifier=test_id_1, source_id='', dest_id='teehee')


def test_dataflow_without_dest_id_disallowed():
    test_id_1 = "Server"
    with pytest.raises(ValueError):
        Dataflow(identifier=test_id_1, source_id='teehee', dest_id='')
