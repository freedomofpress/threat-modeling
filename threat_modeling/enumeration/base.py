import abc

from typing import List

from threat_modeling.threats import Threat


class ThreatEnumerationMethod(abc.ABC):
    """
    ThreatEnumerationMethod enables pluggable threat generation methods: we take
    all DFD elements, and return threats. These should be added to the threat model.
    """

    @abc.abstractmethod
    def generate(self, dfd_elements: List["Element"]) -> List[Threat]:
        """Method to generate new threats"""
