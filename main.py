#!/usr/bin/env python3.9
"""A command-line interface (currently) for postgresql - for learning learning purposes

I've been wanting to make a database client for a while now, this is pretty fun!

I've left the design open to support other sql dialects (e.g. mysql) in the future,
and perhaps I'll add support into the codebase in as i go. i want to learn it all!

References
1. PG Protocol Flow https://www.postgresql.org/docs/14/protocol-flow.html
"""

__author__ = "Joshua Smith (cmyui)"
__email__ = "cmyuiosu@gmail.com"


import argparse
import socket
import sys
from typing import Sequence, cast

import config
import handlers
import helpers
import log
import objects
import packets

VERSION = "0.0.5"
SUPPORTED_BACKNEDS = ["postgresql"]  # TODO: more!!??


def run_command_line_interface(server_sock: socket.socket) -> int:
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


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="pysql")

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s v{VERSION}",
    )

    parser.add_argument(
        "-D",
        "--debug",
        action="store_true",
        help="Enable logging of additional information for debugging purposes",
    )

    subparsers = parser.add_subparsers(dest="command")

    # <> represent required args, () for optional

    # $ pysql cli <backend> (-U/--user) (-H/--host) (-P/--port)
    cli_parser = subparsers.add_parser("cli", help="Auth into backend and open a cli.")
    cli_parser.add_argument(
        "backend",
        help="The database backend you'd like to connect to (only postgresql)",
        choices=SUPPORTED_BACKNEDS,
    )
    cli_parser.add_argument("-U", "--user", default=None)
    cli_parser.add_argument("-H", "--host", default=None)
    cli_parser.add_argument("-P", "--port", default=None)
    cli_parser.add_argument("-D", "--database", default=None)
    # TODO: passwd input with getpass()

    if len(argv) == 0:
        argv = ["--help"]

    args = parser.parse_args(argv)

    if args.debug:
        config.DEBUG_MODE = True

    if args.command == "cli":
        """Auth into backend & open a command line interface."""
        # authenticate & open a command line interface

        # parse cli-specific arguments
        if args.user:
            config.DB_USER = cast(str, args.user).encode()
        if args.host:
            config.DB_HOST = cast(str, args.host)
        if args.port:
            config.DB_PORT = int(cast(str, args.port))
        if args.database:
            config.DB_NAME = cast(str, args.database).encode()

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
            exit_code = run_command_line_interface(sock)
    else:
        # XXX: this is impossible to reach
        exit_code = 1

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))  # [1:] to remove executable
