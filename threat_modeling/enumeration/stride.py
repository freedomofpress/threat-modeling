from threat_modeling.data_flow import Boundary
from threat_modeling.enumeration.base import ThreatEnumerationMethod
from threat_modeling.threats import Threat, ThreatCategory

from typing import List


STRIDE_THREATS = [
    ThreatCategory.SPOOFING,
    ThreatCategory.TAMPERING,
    ThreatCategory.REPUDIATION,
    ThreatCategory.INFORMATION_DISCLOSURE,
    ThreatCategory.DENIAL_OF_SERVICE,
    ThreatCategory.PRIVILEGE_ESCALATION,
]


class NaiveSTRIDE(ThreatEnumerationMethod):
    """Naive STRIDE"""

    def __init__(self):
        pass

    def generate(self, dfd_elements: List["Element"]) -> List[Threat]:

        generated_threats = []
        for element in dfd_elements:
            if not isinstance(element, Boundary):
                for threat_category in STRIDE_THREATS:
                    threat = Threat(
                        identifier=f"{threat_category.name}_{element.name}",
                        name=f"{threat_category.name} of {element.name}",
                        threat_category=threat_category.name,
                    )
                    generated_threats.append(threat)

        return generated_threats
