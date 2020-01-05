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


class BidirectionalDataflow(Element):
    def __init__(
        self,
        first_id: Union[str, UUID],
        second_id: Union[str, UUID],
        identifier: Optional[str] = None,
    ):
        super().__init__(identifier)

        if not first_id or not second_id:
            raise ValueError("two nodes required to define a BidirectionalDataflow")
        self.first_id = first_id
        self.second_id = second_id
