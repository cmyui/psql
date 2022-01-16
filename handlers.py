from enum import IntEnum
from typing import Callable, Optional, TypeVar

import config
import log
import objects
import packets
from objects import PGClient
from packets import PacketReader, ResponseType

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

    log.error("[{S}] {M} ({R}:{L})".format(**err_fields))

    if not client.authenticated:
        client.shutting_down = True


class AuthenticationRequest(IntEnum):
    SUCCESSFUL = 0

    KEREBEROS_V5 = 2
    CLEAR_TEXT_PASS = 3
    MD5_PASS = 5
    SCM_CREDENTIAL = 6
    GSS = 7
    GSS_CONTINUE = 8
    SSPI = 9

    # https://www.postgresql.org/docs/14/sasl-authentication.html
    SASL = 10
    SASL_CONTINUE = 11
    SASL_FINAL = 12


# TODO: perhaps for packets with multiple subtypes like this,
#       could we use class with decorated methods to handle subtypes?
@register(ResponseType.AuthenticationRequest)
def handle_authentication_request(reader: PacketReader, client: PGClient) -> None:
    authentication_type = reader.read_i32()

    if authentication_type == AuthenticationRequest.SUCCESSFUL:
        """Response to previous auth request - we authed successfully."""
        assert client.authenticating is True

        client.authenticating = False
        client.authenticated = True
        log.success("authentication successful")
    elif authentication_type == AuthenticationRequest.MD5_PASS:
        """The backend is requesting our authentication with an md5ed password."""
        if config.DEBUG_MODE:
            log.status("handling salted md5 authentication")

        # send md5 password authentication packet
        client.packet_buffer += packets.fe_md5_auth_packet(
            db_user=config.DB_USER,
            db_pass=config.DB_PASS,
            salt=reader.read_bytes(4),
        )

        client.authenticating = True
    # TODO: add support for & test other auth types
    else:
        log.error(f"unhandled authentication type {authentication_type}")


@register(ResponseType.ParameterStatus)
def handle_parameter_status(reader: PacketReader, client: PGClient) -> None:
    key = reader.read_nullterm_string()
    val = reader.read_nullterm_string()

    client.parameters[key] = val
    if config.DEBUG_MODE:
        log.status(f"read param {key}={val}")


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

    row: objects.Row = {"fields": []}

    for _ in range(num_fields):
        field_name = reader.read_nullterm_string()
        field: objects.Field = {
            "table_id": reader.read_i32(),
            "attr_num": reader.read_i16(),
            "type_id": reader.read_i32(),
            "type_size": reader.read_i16(),  # pg_type.typlen
            "type_mod": reader.read_i32(),  # pg_attribute.atttypmod
            "format_code": reader.read_i16(),  # 0 for text, 1 for bin
            "value": None,  # assigned in the following (RowData) packet
        }

        row["fields"].append((field_name, field))

    client.command["rows"].append(row)


@register(ResponseType.RowData)
def handle_row_data(reader: PacketReader, client: PGClient) -> None:
    assert client.command is not None
    assert len(client.command["rows"]) != 0  # TODO: might this happen?

    num_values = reader.read_i16()

    row = client.command["rows"][-1]
    assert num_values == len(row["fields"])

    for field_name, field in row["fields"]:
        value_len = reader.read_i32()
        value_bytes = reader.read_bytes(value_len)

        # look up & retrieve the correct python type for this value
        py_field_type = objects.PG_TYPE_MAPPING[field["type_id"]]

        # cast it from the bytes to the python type
        # TODO: this soln likely does not always work
        field["value"] = py_field_type(value_bytes)

        log.status(f"read field {field_name}={field['value']}")


@register(ResponseType.EmptyQueryResponse)
def handle_empty_query_response(reader: PacketReader, client: PGClient) -> None:
    assert client.command is not None
    command_tag = reader.read_nullterm_string()
    client.command["has_result"] = True

    log.status(f"received empty query response for `{command_tag}`")


@register(ResponseType.CommandComplete)
def handle_command_complete(reader: PacketReader, client: PGClient) -> None:
    log.success("command complete")
