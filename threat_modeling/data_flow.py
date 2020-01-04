from uuid import UUID

from typing import Optional, Union


class Element:
    def __init__(self, identifier: Optional[str] = None):
        self.identifier = identifier


class Dataflow(Element):
    def __init__(
        self,
        source_id: Union[str, UUID],
        dest_id: Union[str, UUID],
        identifier: Optional[str] = None,
    ):
        super().__init__(identifier)

        if not source_id:
            raise ValueError("source_id required to define Dataflow")

        if not dest_id:
            raise ValueError("dest_id required to define Dataflow")
        self.source_id = source_id
        self.dest_id = dest_id
