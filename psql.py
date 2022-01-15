#!/usr/bin/env python3.9
"""A program for playing with the postgres 3.0 protocol - for learning purposes.
"""

__author__ = "Joshua Smith (cmyui)"
__email__ = "cmyuiosu@gmail.com"


import hashlib
import socket
import struct
from enum import IntEnum
from typing import Any, Callable, Optional, TypeVar, TypedDict, Type

# config

DB_NAME = b"gulag"
DB_USER = b"cmyui"
DB_PASS = b"lol123"

DEBUG_MODE = True

# NOTE: program only supports 3.0 at the moment
PROTO_MAJOR = 3
PROTO_MINOR = 0


class PacketReader:
    def __init__(self, data_view: memoryview) -> None:
        self.data_view = data_view

    def read(self, fmt: str) -> tuple[Any, ...]:
        size = struct.calcsize(fmt)
        vals = struct.unpack_from(fmt, self.data_view[size:])
        self.data_view = self.data_view[:size]
        return vals

    def read_bytes(self, count: int) -> bytes:
        val = self.data_view[:count].tobytes()
        self.data_view = self.data_view[count:]
        return val

    def read_u8(self) -> int:
        val = self.data_view[0]
        self.data_view = self.data_view[1:]
        return val

    def read_i16(self) -> int:
        (val,) = struct.unpack(">h", self.data_view[:2])
        self.data_view = self.data_view[2:]
        return val

    def read_i32(self) -> int:
        (val,) = struct.unpack(">i", self.data_view[:4])
        self.data_view = self.data_view[4:]
        return val

    def read_variadic_string(self) -> str:
        length = self.read_i32()
        val = self.data_view[:length].tobytes().decode()
        self.data_view = self.data_view[length:]
        return val

    def read_nullterm_string(self) -> str:
        # TODO: use a better method than bytes.find to avoid copy
        remainder = self.data_view.tobytes()
        length = remainder.find(b"\x00")
        val = remainder[:length].decode()
        self.data_view = self.data_view[length + 1 :]
        return val


# TODO: pg packet writer functions


def md5hex(s: bytes) -> bytes:
    return hashlib.md5(s).hexdigest().encode()


def write_startup_packet() -> bytes:
    startup_packet = bytearray()
    startup_packet += struct.pack(">hh", PROTO_MAJOR, PROTO_MINOR)

    for param_name, param_value in (
        (b"user", DB_USER),
        (b"database", DB_NAME),
    ):
        startup_packet += param_name + b"\x00" + param_value + b"\x00"

    # zero byte is required as terminator
    # after the last name/value pair
    startup_packet += b"\x00"

    # insert packet length at startup
    startup_packet[0:0] = struct.pack(">i", len(startup_packet) + 4)

    return startup_packet


class ResponseType(IntEnum):
    ErrorResponse = ord("E")
    AuthenticationRequest = ord("R")
    ParameterStatus = ord("S")
    BackendKeyData = ord("K")
    ReadyForQuery = ord("Z")
    RowDescription = ord("T")
    RowData = ord("D")
    CommandComplete = ord("C")
    EmptyQueryResponse = ord("I")


PG_TYPE_MAPPING = {23: int}


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
        self.parameters = {}

        self.shutting_down = False
        self.authenticating = False
        self.authenticated = False
        self.ready_for_query = False

        self.process_id: Optional[int] = None
        self.secret_key: Optional[int] = None

        self.packet_buffer = bytearray()

        self.command: Optional[Command] = None


# packet handling

Handler = Callable[[PacketReader, PGClient], None]
RESPONSE_HANDLERS: dict[ResponseType, Handler] = {}

T = TypeVar("T", bound=Handler)


def register(response_type: ResponseType) -> Callable[[T], T]:
    def wrapper(f: T) -> T:
        RESPONSE_HANDLERS[response_type] = f
        return f

    return wrapper


# TODO: context class? maybe some of the clients
# attributes don't make much sense being in there


@register(ResponseType.ErrorResponse)
def handle_error_response(reader: PacketReader, client: PGClient) -> None:
    # https://www.postgresql.org/docs/14.1/protocol-error-fields.html
    err_fields: dict[str, Optional[str]] = {t: None for t in "SVCMDHPqWstcdnFLR"}

    while (field_type := reader.read_u8()) != 0:
        field_value = reader.read_nullterm_string()
        err_fields[chr(field_type)] = field_value

    print("[{S}] {M} ({R}:{L})".format(**err_fields))

    if not client.authenticated:
        client.shutting_down = True


@register(ResponseType.AuthenticationRequest)
def handle_authentication_request(reader: PacketReader, client: PGClient) -> None:

    authentication_type = reader.read_i32()

    if authentication_type == 5:  # md5 password
        print("Handling salted MD5 authentication")
        salt = reader.read_bytes(4)

        # our next packet will be a password message
        # TODO: function to write this packet
        client.packet_buffer += b"p"
        client.packet_buffer += struct.pack(">i", 4 + 3 + 32 + 1)  # length

        client.packet_buffer += b"md5"
        client.packet_buffer += md5hex(md5hex(DB_PASS + DB_USER) + salt)
        client.packet_buffer += b"\x00"

        client.authenticating = True
    elif authentication_type == 0:
        assert client.authenticating is True

        # auth went ok
        client.authenticating = False
        client.authenticated = True
        print("\x1b[0;92mAuthentication successful\x1b[0m")

    else:
        print(f"[\x1b[0;91mUnhandled authentication type\x1b[0m] {authentication_type}")


@register(ResponseType.ParameterStatus)
def handle_parameter_status(reader: PacketReader, client: PGClient) -> None:
    key = reader.read_nullterm_string()
    val = reader.read_nullterm_string()
    client.parameters[key] = val
    print(f"Read param {key}={val}")


@register(ResponseType.BackendKeyData)
def handle_backend_key_data(reader: PacketReader, client: PGClient) -> None:
    client.process_id = reader.read_i32()
    client.secret_key = reader.read_i32()


@register(ResponseType.ReadyForQuery)
def handle_ready_for_query(reader: PacketReader, client: PGClient) -> None:
    assert not client.ready_for_query
    client.ready_for_query = True


@register(ResponseType.RowDescription)
def handle_row_description(reader: PacketReader, client: PGClient) -> None:
    assert client.command is not None
    num_fields = reader.read_i16()

    row: Row = {"fields": []}

    for _ in range(num_fields):
        field_name = reader.read_nullterm_string()
        field: Field = {
            "table_id": reader.read_i32(),
            "attr_num": reader.read_i16(),
            "type_id": reader.read_i32(),
            "type_size": reader.read_i16(),  # pg_type.typlen
            "type_mod": reader.read_i32(),  # pg_attribute.atttypmod
            "format_code": reader.read_i16(),  # 0 for text, 1 for bin
            "value": None,
        }

        row["fields"].append((field_name, field))

    client.command["rows"].append(row)


@register(ResponseType.RowData)
def handle_row_data(reader: PacketReader, client: PGClient) -> None:
    assert client.command is not None
    assert len(client.command["rows"]) != 0  # TODO: this might happen?

    num_values = reader.read_i16()

    row = client.command["rows"][-1]
    assert num_values == len(row["fields"])

    for field_name, field in row["fields"]:
        value_len = reader.read_i32()
        value_bytes = reader.read_bytes(value_len)

        py_field_type = PG_TYPE_MAPPING[field["type_id"]]
        field["value"] = py_field_type(value_bytes)


@register(ResponseType.EmptyQueryResponse)
def handle_empty_query_response(reader: PacketReader, client: PGClient) -> None:
    assert client.command is not None
    command_tag = reader.read_nullterm_string()
    client.command["has_result"] = True

    print("Received")  # TODO: print py row mapping


@register(ResponseType.CommandComplete)
def handle_command_complete(reader: PacketReader, client: PGClient) -> None:
    print("Empty query response")


# running client


def run_client(server_sock: socket.socket) -> int:
    """Run the client until shut down programmatically."""
    print("Initiating postgres protocol startup")

    client = PGClient()

    # initiate communication with a startup packet
    client.packet_buffer = bytearray(write_startup_packet())

    while not client.shutting_down:
        if client.ready_for_query:
            # prompt the user for a query
            client.command = {
                "query": input("λ "),
                "rows": [],
                "has_result": False,
            }
            client.ready_for_query = False

            client.packet_buffer += b"Q"
            client.packet_buffer += struct.pack(">i", len(client.command["query"]) + 1 + 4)
            client.packet_buffer += client.command["query"].encode() + b"\x00"

        if client.packet_buffer:
            # we have packets to send
            to_send = bytes(client.packet_buffer)
            client.packet_buffer.clear()

            if DEBUG_MODE:
                print("[\x1b[0;96msend\x1b[0m]", to_send)

            server_sock.send(to_send)

        # read response type & lengths
        header_bytes = server_sock.recv(5)
        response_type = ResponseType(header_bytes[0])
        response_len = struct.unpack(">i", header_bytes[1:])[0]

        # allocate buffer for the remainder of our response
        to_read = response_len - 4  # (don't include length)
        buf = bytearray(b"\x00" * to_read)

        # read response data
        with memoryview(buf) as buf_view:
            bytes_read = server_sock.recv_into(buf_view, to_read)
            buf_view = buf_view[:bytes_read]
            to_read -= bytes_read

        if DEBUG_MODE:
            print("[\x1b[0;95mrecv\x1b[0m]", header_bytes + buf_view.tobytes())

        # handle response
        with memoryview(buf) as data_view:
            reader = PacketReader(data_view.toreadonly())

            packet_handler = RESPONSE_HANDLERS.get(response_type)

            if packet_handler is None:
                print(
                    f"[\x1b[0;91mUnhandled response_type\x1b[0m] {chr(response_type)}={data_view.tobytes()}"
                )
                continue

            # TODO: this will currently always return none
            # would it make sense to return some response?
            result = packet_handler(reader, client)

    return 0


def main() -> int:
    # connect to the postgres server
    with socket.create_connection(("127.0.0.1", 5432)) as sock:
        # and run our client until stopped
        return run_client(sock)


if __name__ == "__main__":
    # use GNU readline interface
    import readline  # type: ignore

    raise SystemExit(main())
