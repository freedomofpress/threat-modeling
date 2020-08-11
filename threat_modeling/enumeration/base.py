import abc

from typing import List

from threat_modeling.threats import Threat


class ThreatEnumerationMethod(abc.ABC):
    """
    The idea here is to enable pluggable threat generation methods: we take
    all threats and all DFD elements, and return only new threats. These should
    be added to the threat model.
    """

    @abc.abstractmethod
    def generate(
        self, threats: List[Threat], dfd_elements: List["Element"]
    ) -> List[Threat]:
        """Method to generate new threats"""
