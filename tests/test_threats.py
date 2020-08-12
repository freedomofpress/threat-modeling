import os

from threat_modeling.mitigations import Mitigation
from threat_modeling.threats import AttackTree, Threat, ThreatCategory


def test_threat_str():
    my_threat = Threat("Attacker breaks into datacenter", "THREAT1")
    assert my_threat.description in str(my_threat)


def test_threat_repr():
    my_threat = Threat("Attacker breaks into datacenter", "THREAT1")
    assert my_threat.identifier in repr(my_threat)


def test_attack_trees(tmpdir):
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
    attack_tree.draw("{}_test.png".format(str(tmpdir)))
    assert attack_tree._generated_dot == expected_dot


def test_set_metrics():
    my_threat = Threat(
        "Attacker breaks into datacenter",
        "THREAT1",
        base_impact="high",
        base_exploitability="low",
    )
    assert my_threat.base_risk == 8


def test_threat_categories():
    my_threat = Threat(
        "Attacker breaks into datacenter",
        "THREAT1",
        base_impact="high",
        base_exploitability="low",
        threat_category="privilege escalation",
    )
    assert my_threat.threat_category == ThreatCategory.PRIVILEGE_ESCALATION

    my_threat = Threat(
        "Attacker breaks into datacenter",
        "THREAT1",
        base_impact="high",
        base_exploitability="low",
    )
    assert my_threat.threat_category == ThreatCategory.UNKNOWN


def test_threat_by_mitigation_obj():
    mitig = Mitigation(
        "Datacenter entirely encased in stone, only xorn can enter", "MITIG1"
    )
    my_threat = Threat(
        "Attacker breaks into datacenter",
        "THREAT1",
        base_impact="high",
        base_exploitability="low",
        threat_category="privilege escalation",
        mitigations=[mitig],
    )
    assert mitig in my_threat.mitigations


def test_threat_by_mitigation_id():
    my_threat = Threat(
        "Attacker breaks into datacenter",
        "THREAT1",
        base_impact="high",
        base_exploitability="low",
        threat_category="privilege escalation",
        mitigation_ids=["MITIG1"],
    )
    assert "MITIG1" in my_threat.mitigation_ids
