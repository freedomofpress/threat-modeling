import os

from threat_modeling.threats import Threat, AttackTree


def test_threat_str():
    my_threat = Threat("Attacker breaks into datacenter", "THREAT1")
    assert my_threat.description in str(my_threat)


def test_threat_repr():
    my_threat = Threat("Attacker breaks into datacenter", "THREAT1")
    assert my_threat.identifier in repr(my_threat)


def test_attack_trees():
    test_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "files/attack_tree.dot"
    )
    with open(test_file) as f:
        expected_dot = f.read()

    my_threat_3 = Threat("Attacker patches code running on server", "THREAT3")
    my_threat_2 = Threat(
        "Attacker picks lock on server cabinet", "THREAT2", child_threats=[my_threat_3]
    )
    my_threat = Threat(
        "Attacker breaks into datacenter", "THREAT1", child_threats=[my_threat_2]
    )
    assert my_threat_2 in my_threat.child_threats

    attack_tree = AttackTree(my_threat)
    attack_tree.draw()
    assert attack_tree._generated_dot == expected_dot
