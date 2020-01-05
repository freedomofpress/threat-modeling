import pytest

from threat_modeling.data_flow import Element, Dataflow, BidirectionalDataflow


def test_element_can_be_defined():
    test_id = "Server"
    Element(name="Primary server", identifier=test_id)


def test_element_can_be_defined_with_just_a_name():
    name = "Server"
    Element(name=name)


def test_dataflow_without_source_id_disallowed():
    test_id_1 = "Server"
    with pytest.raises(ValueError):
        Dataflow(name="Primary Server", identifier=test_id_1, first_id='',
                 second_id='teehee')


def test_dataflow_without_dest_id_disallowed():
    test_id_1 = "Server"
    with pytest.raises(ValueError):
        Dataflow(name="Primary Server", identifier=test_id_1, first_id='teehee',
                 second_id='')


def test_bidirectional_dataflow_with_missing_id():
    test_id_1 = "Server"
    with pytest.raises(ValueError):
        BidirectionalDataflow('Primary Server', '', 'teehee', test_id_1)
