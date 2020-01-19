import pytest

from threat_modeling.data_flow import (
    Element,
    Dataflow,
    BidirectionalDataflow,
    Process,
    ExternalEntity,
    Datastore,
    Boundary,
)


def test_element_can_be_defined():
    test_id = "Server"
    Element(name="Primary server", identifier=test_id)


def test_element_str():
    test_id = "Server"
    element = Element(name="Primary server", identifier=test_id)
    assert "Element" in str(element)


def test_element_repr():
    test_id = "Server"
    element = Element(name="Primary server", identifier=test_id)
    assert "Element" in repr(element)


def test_element_can_be_defined_with_just_a_name():
    name = "Server"
    Element(name=name)


def test_dataflow_from_element_constructor():
    test_id_1 = "Server"
    element = Element(name="Primary server", identifier=test_id_1)
    test_id_2 = "Server 2"
    element_2 = Element(name="Secondary server", identifier=test_id_2)

    Dataflow.from_elements(element, element_2, name="foo", identifier="bar")


def test_dataflow_without_source_id_disallowed():
    test_id_1 = "Server"
    with pytest.raises(ValueError):
        Dataflow(
            name="Primary Server", identifier=test_id_1, first_id="", second_id="teehee"
        )


def test_dataflow_without_dest_id_disallowed():
    test_id_1 = "Server"
    with pytest.raises(ValueError):
        Dataflow(
            name="Primary Server", identifier=test_id_1, first_id="teehee", second_id=""
        )


def test_dataflow_str():
    test_id = "Server"
    element = Dataflow(
        name="Primary Server", identifier=test_id, first_id="teehee", second_id="butts"
    )
    assert "Dataflow" in str(element)
    assert "->" in str(element)


def test_dataflow_repr():
    test_id = "Server"
    element = Dataflow(
        name="Primary Server", identifier=test_id, first_id="teehee", second_id="butts"
    )
    assert "Dataflow" in repr(element)
    assert element.name in repr(element)
    assert element.identifier in repr(element)
    assert element.first_id in repr(element)
    assert element.second_id in repr(element)


def test_bidirectional_dataflow_with_missing_id():
    test_id_1 = "Server"
    with pytest.raises(ValueError):
        BidirectionalDataflow("Primary Server", "", "teehee", test_id_1)


def test_bidirectionaldataflow_str():
    test_id = "Server"
    element = BidirectionalDataflow(
        name="Primary Server", identifier=test_id, first_id="teehee", second_id="butts"
    )
    assert "BidirectionalDataflow" in str(element)


def test_process_str():
    element = Process(name="foo")
    assert "Process" in str(element)


def test_externalentity_str():
    element = ExternalEntity(name="foo")
    assert "ExternalEntity" in str(element)


def test_datastore_str():
    element = Datastore(name="foo")
    assert "Datastore" in str(element)


def test_boundary_str():
    element = Boundary("foo", [])
    assert "Boundary" in str(element)


def test_boundary_repr():
    element = Boundary("foo", [])
    assert "Boundary" in repr(element)
    assert "foo" in repr(element)
