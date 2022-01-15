from enum import IntEnum
from typing import Any, Optional, TypedDict


class ResponseType(IntEnum):
    # https://www.postgresql.org/docs/14/protocol-message-formats.html
    ErrorResponse = ord("E")
    AuthenticationRequest = ord("R")
    ParameterStatus = ord("S")
    BackendKeyData = ord("K")
    ReadyForQuery = ord("Z")
    RowDescription = ord("T")
    RowData = ord("D")
    CommandComplete = ord("C")
    EmptyQueryResponse = ord("I")


PG_TYPE_MAPPING = {23: int, 25: bytes}


class Field(TypedDict):
    table_id: int
    attr_num: int
    type_id: int
    type_size: int
    type_mod: int
    format_code: int

    value: Optional[Any]


class Row(TypedDict):
    fields: list[tuple[str, Field]]


class Command(TypedDict):
    query: str
    rows: list[Row]

    has_result: bool


class PGClient:
    def __init__(self) -> None:
        self.parameters: dict[str, str] = {}

        self.shutting_down = False
        self.authenticating = False
        self.authenticated = False
        self.ready_for_query = False

        self.process_id: Optional[int] = None
        self.secret_key: Optional[int] = None

        self.packet_buffer = bytearray()

        self.command: Optional[Command] = None
