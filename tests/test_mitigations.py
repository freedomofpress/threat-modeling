from threat_modeling.mitigations import Mitigation


def test_mitigation_str():
    item = Mitigation("Sshd PasswordAuthentication no", "MITIG1")
    assert item.description in str(item)


def test_mitigation_repr():
    item = Mitigation("Sshd PasswordAuthentication no", "MITIG1")
    assert item.identifier in repr(item)
