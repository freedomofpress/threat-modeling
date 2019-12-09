from uuid import uuid4, UUID

from typing import Optional


class Threat:
    def __init__(
        self, identifier: Optional[UUID] = None, description: Optional[str] = None
    ):
        if not identifier:
            identifier = uuid4()

        self.identifier = identifier

        if description:
            self.description = description
