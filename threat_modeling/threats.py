import reprlib
from uuid import uuid4, UUID

from typing import Optional, Union


class Threat:
    def __init__(
        self,
        identifier: Optional[Union[str, UUID]] = None,
        description: Optional[str] = None,
    ):
        if not identifier:
            identifier = uuid4()

        self.identifier = identifier

        if description:
            self.description = description

    def __str__(self) -> str:
        return "<Threat {}: {}>".format(self.identifier, self.description)

    def __repr__(self) -> str:
        return "Threat({}, {})".format(self.identifier, reprlib.repr(self.description))
