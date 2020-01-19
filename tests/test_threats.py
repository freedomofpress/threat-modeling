from threat_modeling.threats import Threat


def test_threat_str():
    my_threat = Threat("THREAT1", "Attacker breaks into datacenter")
    assert my_threat.description in str(my_threat)


def test_threat_repr():
    my_threat = Threat("THREAT1", "Attacker breaks into datacenter")
    assert my_threat.identifier in repr(my_threat)
