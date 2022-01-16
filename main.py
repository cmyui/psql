#!/usr/bin/env python3.9
"""A program for playing with the postgres 3.0 protocol - for learning purposes.

I've been wanting to make a database client for a while now, this is pretty fun!

References
1. PG Protocol Flow https://www.postgresql.org/docs/14/protocol-flow.html
"""

__author__ = "Joshua Smith (cmyui)"
__email__ = "cmyuiosu@gmail.com"


import socket

import config
import handlers
import helpers
import log
import objects
import packets


def run_client(server_sock: socket.socket) -> int:
    """Run the client until shut down programmatically."""
    log.status(
        f"initiating postgres protocol startup "
        f"(v{config.PROTO_MAJOR}.{config.PROTO_MINOR})"
    )

    client = objects.PGClient()

    # initiate communication with a startup packet
    client.packet_buffer += packets.startup(
        proto_ver_major=config.PROTO_MAJOR,
        proto_ver_minor=config.PROTO_MINOR,
        db_params={
            b"user": config.DB_USER,
            b"database": config.DB_NAME,
            # TODO: other params
        },
    )

    # run the program as a command-line interface,
    # closing on SIGINT, SIGTERM, SIGHUP or EOFError.
    while not client.shutting_down:
        if client.ready_for_query:
            # prompt the user for a query
            try:
                user_input = input(f"{config.PS1} ")
            except (helpers.SignalError, EOFError):
                # shutdown the client gracefully
                client.shutting_down = True

                print("\x1b[0;91mreceived interrupt signal\x1b[0m")

                # send the conn termination packet
                client.packet_buffer += packets.termination()
            else:
                # we received user input, issue a command (query) to the backend
                client.command = {
                    "query": user_input,
                    "rows": [],
                    "has_result": False,
                }
                client.ready_for_query = False
                client.packet_buffer += packets.query(client.command["query"])

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
        response_type, response_len = packets.read_header(header_bytes)

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

            # call our packet handler
            packet_handler(reader, client)

    return 0


def main() -> int:
    # use GNU readline interface
    import readline  # type: ignore

    # ensure the server is notified
    # of any client disconnections
    helpers.setup_shutdown_signal_handlers()

    # connect to the postgres server
    # and run our client until stopped
    with socket.create_connection(
        (config.DB_HOST, config.DB_PORT),
    ) as sock:
        return run_client(sock)


if __name__ == "__main__":
    raise SystemExit(main())
