import struct
from enum import IntEnum
from typing import Any

import helpers

# binary deserialization (reading)


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


def read_packet_header(data: bytes) -> tuple[ResponseType, int]:
    assert len(data) == 5

    response_type = ResponseType(data[0])
    response_len = struct.unpack(">i", data[1:])[0]
    return response_type, response_len


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


# binary serialization (writing)
# TODO: some sort of ordering of these packets


def fe_startup_packet(
    proto_ver_major: int,
    proto_ver_minor: int,
    db_params: dict[bytes, bytes],
) -> bytes:
    packet = bytearray()
    packet += struct.pack(">hh", proto_ver_major, proto_ver_minor)

    for param_name, param_value in db_params.items():
        packet += param_name + b"\x00" + param_value + b"\x00"

    # zero byte is required as terminator
    # after the last name/value pair
    packet += b"\x00"

    # insert packet length at startup
    packet[0:0] = struct.pack(">i", len(packet) + 4)
    return packet


def fe_termination_packet() -> bytes:
    packet = bytearray()
    packet += b"X"
    packet += struct.pack(">i", 4)
    return packet


def fe_query_packet(query: str) -> bytes:
    packet = bytearray()
    packet += b"Q"
    packet += struct.pack(">i", len(query) + 1 + 4)
    packet += query.encode() + b"\x00"
    return packet


def fe_md5_auth_packet(db_user: bytes, db_pass: bytes, salt: bytes) -> bytes:
    packet = bytearray()
    packet += b"p"
    packet += struct.pack(">i", 4 + 3 + 32 + 1)  # length

    packet += b"md5"
    packet += helpers.md5hex(helpers.md5hex(db_pass + db_user) + salt)
    packet += b"\x00"
    return packet
