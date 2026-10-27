#!/usr/bin/env python3
"""Independent gRPC Python and websockets client interoperability checks."""

from __future__ import annotations

import argparse
import base64
import json
import platform
import ssl
from typing import Any, Iterable

import grpc
import websockets
from websockets.sync.client import connect


GRPC_METHOD = "/bonvoyage.test.v1.Echo/Unary"


def encode_varint(value: int) -> bytes:
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def decode_varint(payload: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(payload) and shift <= 63:
        current = payload[offset]
        offset += 1
        value |= (current & 0x7F) << shift
        if current & 0x80 == 0:
            return value, offset
        shift += 7
    raise ValueError("invalid protobuf varint")


def encode_string_value(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return b"\x0a" + encode_varint(len(encoded)) + encoded


def decode_string_value(payload: bytes) -> str:
    if not payload or payload[0] != 0x0A:
        raise ValueError("unexpected StringValue field tag")
    length, offset = decode_varint(payload, 1)
    if offset + length != len(payload):
        raise ValueError("unexpected StringValue payload length")
    return payload[offset:].decode("utf-8")


def metadata_values(metadata: Iterable[tuple[str, Any]], key: str) -> list[Any]:
    return [value for name, value in metadata if name.lower() == key]


def json_metadata(values: Iterable[Any]) -> list[str]:
    result = []
    for value in values:
        if isinstance(value, bytes):
            result.append(base64.b64encode(value).decode("ascii"))
        else:
            result.append(str(value))
    return result


def grpc_channel(target: str, ca_file: str, server_name: str) -> grpc.Channel:
    with open(ca_file, "rb") as source:
        credentials = grpc.ssl_channel_credentials(source.read())
    options = (
        ("grpc.ssl_target_name_override", server_name),
        ("grpc.default_authority", server_name),
    )
    return grpc.secure_channel(target, credentials, options=options)


def run_grpc(arguments: argparse.Namespace) -> dict[str, Any]:
    channel = grpc_channel(arguments.target, arguments.ca, arguments.server_name)
    try:
        grpc.channel_ready_future(channel).result(timeout=5)
        rpc = channel.unary_unary(
            GRPC_METHOD,
            request_serializer=lambda payload: payload,
            response_deserializer=lambda payload: payload,
        )
        response, call = rpc.with_call(
            encode_string_value("python"),
            timeout=5,
            metadata=(
                ("x-test-ascii", "python"),
                ("x-test-bin", b"\x07\x08\x09"),
            ),
        )
        if decode_string_value(response) != "echo:python":
            raise AssertionError("gRPC Python success payload changed")
        initial = tuple(call.initial_metadata() or ())
        trailing = tuple(call.trailing_metadata() or ())
        if metadata_values(initial, "x-upstream") != ["grpc-unary-fixture"]:
            raise AssertionError("gRPC initial metadata changed")
        if metadata_values(trailing, "x-trace-id") != ["trace-1"]:
            raise AssertionError("gRPC trailing metadata changed")
        raw_repeated = metadata_values(trailing, "x-repeat")
        repeated = [
            part.strip()
            for value in raw_repeated
            for part in str(value).split(",")
        ]
        if repeated != ["one", "two"]:
            raise AssertionError(
                f"gRPC repeated trailing metadata changed: {raw_repeated!r}"
            )
        if metadata_values(trailing, "trace-bin") != [b"\x04\x05\x06"]:
            raise AssertionError("gRPC binary trailing metadata changed")

        try:
            rpc(encode_string_value("error"), timeout=5)
            raise AssertionError("gRPC application error unexpectedly succeeded")
        except grpc.RpcError as error:
            if error.code() is not grpc.StatusCode.INVALID_ARGUMENT:
                raise AssertionError(f"unexpected gRPC status: {error.code()}")
            if error.details() != "declined":
                raise AssertionError(f"unexpected gRPC details: {error.details()}")
            error_trailing = tuple(error.trailing_metadata() or ())
            if metadata_values(error_trailing, "x-error") != ["declined"]:
                raise AssertionError("gRPC error metadata changed")

        large = rpc(encode_string_value("large"), timeout=5)
        if len(decode_string_value(large)) != 128 * 1024:
            raise AssertionError("gRPC large response changed")
        recovered = rpc(encode_string_value("recovery"), timeout=5)
        if decode_string_value(recovered) != "echo:recovery":
            raise AssertionError("gRPC recovery payload changed")
        return {
            "application_error": grpc.StatusCode.INVALID_ARGUMENT.name,
            "binary_trailer_base64": json_metadata(
                metadata_values(trailing, "trace-bin")
            ),
            "client": "grpcio",
            "client_version": grpc.__version__,
            "large_response_bytes": 128 * 1024,
            "recovery": "passed",
            "repeated_trailers_normalized": repeated,
            "repeated_trailers_raw": json_metadata(raw_repeated),
            "success_payload": "echo:python",
            "tls_verification": "custom CA and hostname verified",
        }
    finally:
        channel.close()


def run_grpc_tls_negative(arguments: argparse.Namespace) -> dict[str, Any]:
    channel = grpc_channel(arguments.target, arguments.ca, "wrong.example.test")
    try:
        try:
            grpc.channel_ready_future(channel).result(timeout=2)
        except grpc.FutureTimeoutError:
            return {
                "client": "grpcio",
                "result": "expected hostname rejection",
                "server_name": "wrong.example.test",
            }
        raise AssertionError("gRPC accepted a certificate for the wrong hostname")
    finally:
        channel.close()


def run_websocket(arguments: argparse.Namespace) -> dict[str, Any]:
    context = None
    if arguments.uri.startswith("wss://"):
        context = ssl.create_default_context(cafile=arguments.ca)
    with connect(
        arguments.uri,
        ssl=context,
        subprotocols=["chat"],
        compression=None,
        proxy=None,
        open_timeout=5,
        close_timeout=5,
    ) as connection:
        if connection.subprotocol != "chat":
            raise AssertionError("WebSocket subprotocol negotiation changed")
        if connection.recv(timeout=5) != "ready":
            raise AssertionError("WebSocket immediate message changed")
        connection.send("python-text")
        if connection.recv(timeout=5) != "python-text":
            raise AssertionError("WebSocket text echo changed")
        binary = b"\x00\x01\x02python"
        connection.send(binary)
        if connection.recv(timeout=5) != binary:
            raise AssertionError("WebSocket binary echo changed")
        pong = connection.ping(b"interop")
        if not pong.wait(timeout=5):
            raise AssertionError("WebSocket ping was not acknowledged")
        return {
            "binary_bytes": len(binary),
            "client": "websockets",
            "client_version": websockets.__version__,
            "immediate_message": "ready",
            "ping_pong": "passed",
            "subprotocol": connection.subprotocol,
            "text_echo": "python-text",
            "transport": "tls" if context else "cleartext",
            "tls_verification": (
                "custom CA and hostname verified" if context else "not applicable"
            ),
        }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("versions")

    for command in ("grpc", "grpc-tls-negative"):
        child = subparsers.add_parser(command)
        child.add_argument("--target", required=True)
        child.add_argument("--ca", required=True)
        child.add_argument("--server-name", default="api.example.test")

    websocket = subparsers.add_parser("websocket")
    websocket.add_argument("--uri", required=True)
    websocket.add_argument("--ca")
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    if arguments.command == "versions":
        result = {
            "grpcio": grpc.__version__,
            "python": platform.python_version(),
            "websockets": websockets.__version__,
        }
    elif arguments.command == "grpc":
        result = run_grpc(arguments)
    elif arguments.command == "grpc-tls-negative":
        result = run_grpc_tls_negative(arguments)
    else:
        result = run_websocket(arguments)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
