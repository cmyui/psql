#!/usr/bin/env python3.9
"""A program for playing with the postgres 3.0 protocol.
"""

__author__ = "Joshua Smith (cmyui)"
__email__ = "cmyuiosu@gmail.com"


import hashlib
import socket
import struct
from typing import Optional

# config

DB_NAME = b"gulag"
DB_USER = b"cmyui"
DB_PASS = b"lol123"

DEBUG_MODE = False
SOCKET_TIMEOUT = 1.0

# NOTE: program only supports 3.0 at the moment
PROTO_MAJOR = 3
PROTO_MINOR = 0

# TODO: binary (packet) reader class
# TODO: pg packet writer functions


def write_startup_packet() -> bytes:
    startup_packet = bytearray()
    startup_packet += struct.pack(
        ">hh", PROTO_MAJOR, PROTO_MINOR
    )  # protocol version (major, minor)

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


def run_client(server_sock: socket.socket) -> int:
    """Run the client until shut down programmatically."""
    print("Initiating postgres protocol startup")
    packet_buffer = bytearray(write_startup_packet())
    shutting_down = False

    while not shutting_down:
        if packet_buffer:
            # we have packets to send
            to_send = bytes(packet_buffer)
            packet_buffer.clear()

            if DEBUG_MODE:
                print("[send]", to_send)

            server_sock.send(to_send)

        # read response type & length
        response_type = ord(server_sock.recv(1))
        response_len = struct.unpack(">i", server_sock.recv(4))[0]

        # allocate buffer for the remainder of our response
        to_read = response_len - 4  # (don't include length)
        buf = bytearray(b"\x00" * to_read)

        # read response data
        with memoryview(buf) as buf_view:
            bytes_read = server_sock.recv_into(buf_view, to_read)
            buf_view = buf_view[:bytes_read]
            to_read -= bytes_read

        if DEBUG_MODE:
            print("[recv]", buf_view.tobytes())

        # handle response
        with memoryview(buf) as data_view:
            if response_type == ord("E"):  # error response
                # https://www.postgresql.org/docs/14.1/protocol-error-fields.html
                fields: dict[str, Optional[str]] = {
                    t: None for t in "SVCMDHPqWstcdnFLR"
                }

                field_type = data_view[0]
                data_view = data_view[1:]

                while field_type != 0:
                    value_length = bytes(data_view).find(b"\x00")
                    field_value = data_view[:value_length].tobytes().decode()
                    data_view = data_view[value_length + 1 :]

                    fields[chr(field_type)] = field_value

                    field_type = data_view[0]
                    data_view = data_view[1:]

                print("[{S}] {M} ({R}:{L})".format(**fields))
            elif response_type == ord("R"):  # authentication request
                authentication_type = struct.unpack(">i", data_view[:4])[0]
                data_view = data_view[4:]

                if authentication_type == 5:  # md5 password
                    print("Handling salted MD5 authentication")
                    salt = data_view[:4].tobytes()
                    data_view = data_view[4:]

                    # our next packet will be a password message
                    packet_buffer += b"p"
                    packet_buffer += struct.pack(">i", 32 + 4 + 1 + 3)  # length

                    packet_buffer += (
                        b"md5"
                        + hashlib.md5(
                            hashlib.md5(DB_PASS + DB_USER).hexdigest().encode() + salt
                        )
                        .hexdigest()
                        .encode()
                    ) + b"\x00"
                else:
                    print(
                        f"[\x1b[0;91mUnhandled authentication type\x1b[0m] {authentication_type}"
                    )
            else:
                print(
                    f"[\x1b[0;91mUnhandled response_type\x1b[0m] {chr(response_type)}={data_view.tobytes()}"
                )

    return 0


def main() -> int:
    # connect to the postgres server
    with socket.create_connection(
        ("127.0.0.1", 5432),
        timeout=SOCKET_TIMEOUT,
    ) as sock:
        # and run our client until stopped
        return run_client(sock)


if __name__ == "__main__":
    raise SystemExit(main())
