#!/usr/bin/env python3.9
"""A program for playing with the postgres 3.0 protocol - for learning purposes.

I've been wanting to make a database client for a while now, this is pretty fun!
"""

__author__ = "Joshua Smith (cmyui)"
__email__ = "cmyuiosu@gmail.com"


import signal
import socket
import struct
from types import FrameType
from typing import Optional

import config
import handlers
import log
import objects
import packets


def run_client(server_sock: socket.socket) -> int:
    """Run the client until shut down programmatically."""
    log.status("initiating postgres protocol startup")

    client = objects.PGClient()

    # initiate communication with a startup packet
    client.packet_buffer += packets.fe_startup_packet(
        proto_ver_major=config.PROTO_MAJOR,
        proto_ver_minor=config.PROTO_MINOR,
        db_params={
            b"user": config.DB_USER,
            b"database": config.DB_NAME,
        },
    )

    while not client.shutting_down:
        if client.ready_for_query:
            # prompt the user for a query
            try:
                user_input = input(f"{config.PS1} ")
            except (KeyboardInterrupt, EOFError):
                # shutdown the client gracefully
                client.shutting_down = True

                print("\x1b[0;91mreceived interrupt signal\x1b[0m")

                # send the conn termination packet
                client.packet_buffer += packets.fe_termination_packet()
            else:
                # we received user input, issue a command (query) to the backend
                client.command = {
                    "query": user_input,
                    "rows": [],
                    "has_result": False,
                }
                client.ready_for_query = False
                client.packet_buffer += packets.fe_query_packet(client.command["query"])

        if client.packet_buffer:
            # we have packets to send
            to_send = bytes(client.packet_buffer)
            client.packet_buffer.clear()

            if config.DEBUG_MODE:
                log.send(to_send)

            server_sock.send(to_send)

        if client.shutting_down:
            log.status("connection terminated")
            break

        # read response type & lengths
        header_bytes = server_sock.recv(5)
        response_type = objects.ResponseType(header_bytes[0])
        response_len = struct.unpack(">i", header_bytes[1:])[0]

        # allocate buffer for the remainder of our response
        to_read = response_len - 4  # (don't include length)
        buf = bytearray(b"\x00" * to_read)

        # read response data
        with memoryview(buf) as buf_view:
            bytes_read = server_sock.recv_into(buf_view, to_read)
            buf_view = buf_view[:bytes_read]
            to_read -= bytes_read

        if config.DEBUG_MODE:
            log.recv((header_bytes + buf_view.tobytes()))

        # handle response
        with memoryview(buf) as data_view:
            packet_handler = handlers.RESPONSE_HANDLERS.get(response_type)
            if packet_handler is None:
                # we don't have a handler for this packet
                log.error(f"{chr(response_type)}={data_view.tobytes()}")
                continue

            if config.DEBUG_MODE:
                log.handler(packet_handler.__name__)

            reader = packets.PacketReader(data_view.toreadonly())

            # TODO: this will currently always return none
            # would it make sense to return some response?
            result = packet_handler(reader, client)

    return 0


def handle_sigterm_as_keyboard_interrupt() -> None:
    def signal_handler(signum: int, frame: Optional[FrameType] = None) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, signal_handler)


def main() -> int:
    # use GNU readline interface
    import readline  # type: ignore

    handle_sigterm_as_keyboard_interrupt()

    # connect to the postgres server
    with socket.create_connection(("127.0.0.1", 5432)) as sock:
        # and run our client until stopped
        return run_client(sock)


if __name__ == "__main__":
    raise SystemExit(main())
