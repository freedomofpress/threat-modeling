import reprlib
from uuid import UUID, uuid4

from typing import Optional, Union


class Mitigation:
    """
    Represents a mitigation/countermeasure. Each mitigation
    can be applied to one or more threats.

    Args:
      identifier (str, UUID, optional): this is a short ID that is used
        to map the mitigation to other objects. If one is not provided
        it will be generated.
      name (str): a short, human-readable name for the mitigation.
      description (str, optional): an optional description containing
        more information about the mitigation.
    """

    def __init__(
        self,
        name: str,
        identifier: Optional[Union[str, UUID]] = None,
        description: str = "",
    ) -> None:
        self.name = name
        self.identifier = identifier or uuid4()
        self.description = description

    def __str__(self) -> str:
        return "<Mitigation {}: {}>".format(self.identifier, self.name)

    def __repr__(self) -> str:
        return "Mitigation({}, {}, {})".format(
            self.name, self.identifier, reprlib.repr(self.description)
        )
