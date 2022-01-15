import struct

import helpers


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
