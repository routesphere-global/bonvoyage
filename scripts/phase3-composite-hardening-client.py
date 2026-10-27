#!/usr/bin/env python3
"""Dependency-free HTTP/1.1 and WebSocket churn client."""

from __future__ import annotations

import base64
import collections
import concurrent.futures
import hashlib
import http.client
import json
import os
import socket
import struct
import sys
import time
from typing import Any


GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def http_request(host: str, path: str) -> dict[str, Any]:
    connection = http.client.HTTPConnection(host, 8080, timeout=10)
    try:
        connection.request(
            "GET",
            path,
            headers={"Host": "api.example.test", "Connection": "close"},
        )
        response = connection.getresponse()
        body = response.read()
        headers = {name.lower(): value for name, value in response.getheaders()}
        return {
            "status": response.status,
            "upstream": headers.get("x-upstream-id", ""),
            "body": body.decode("utf-8", errors="replace").strip(),
        }
    finally:
        connection.close()


def run_http(host: str, path: str, count: int, concurrency: int) -> None:
    started = time.monotonic()
    errors: list[str] = []
    results: list[dict[str, Any]] = []

    def execute(_: int) -> None:
        try:
            results.append(http_request(host, path))
        except Exception as error:  # noqa: BLE001 - evidence retains exact failures.
            errors.append(f"{type(error).__name__}: {error}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        list(executor.map(execute, range(count)))

    print(
        json.dumps(
            {
                "mode": "http",
                "path": path,
                "requested": count,
                "completed": len(results),
                "duration_seconds": round(time.monotonic() - started, 3),
                "statuses": collections.Counter(str(item["status"]) for item in results),
                "upstreams": collections.Counter(
                    item["upstream"] for item in results if item["upstream"]
                ),
                "errors": collections.Counter(errors),
            },
            indent=2,
            sort_keys=True,
        )
    )


def masked_frame(opcode: int, payload: bytes) -> bytes:
    mask = os.urandom(4)
    encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    if len(payload) < 126:
        prefix = bytes((0x80 | opcode, 0x80 | len(payload)))
    else:
        prefix = bytes((0x80 | opcode, 0x80 | 126)) + struct.pack("!H", len(payload))
    return prefix + mask + encoded


def read_head(connection: socket.socket) -> tuple[int, dict[str, str], bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            raise ConnectionError("response ended before its header block")
        data += chunk
        if len(data) > 65536:
            raise ValueError("response head exceeded the client bound")
    raw_head, buffered = data.split(b"\r\n\r\n", 1)
    lines = raw_head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return status, headers, buffered


def read_frame(connection: socket.socket, buffered: bytes) -> tuple[int, bytes, bytes]:
    while len(buffered) < 2:
        buffered += connection.recv(4096)
    first, second = buffered[0], buffered[1]
    if first & 0x70 or not first & 0x80 or second & 0x80:
        raise ValueError("invalid upstream frame flags")
    length = second & 0x7F
    offset = 2
    if length == 126:
        while len(buffered) < offset + 2:
            buffered += connection.recv(4096)
        length = struct.unpack("!H", buffered[offset : offset + 2])[0]
        offset += 2
    elif length == 127:
        while len(buffered) < offset + 8:
            buffered += connection.recv(4096)
        length = struct.unpack("!Q", buffered[offset : offset + 8])[0]
        offset += 8
    while len(buffered) < offset + length:
        chunk = connection.recv(4096)
        if not chunk:
            raise ConnectionError("WebSocket frame was truncated")
        buffered += chunk
    return first & 0x0F, buffered[offset : offset + length], buffered[offset + length :]


def websocket_cycle(host: str, index: int) -> None:
    connection = socket.create_connection((host, 8080), timeout=10)
    connection.settimeout(10)
    try:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            "GET /socket HTTP/1.1\r\n"
            "Host: ws.example.test\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key}\r\n\r\n"
        ).encode("ascii")
        connection.sendall(request)
        status, headers, buffered = read_head(connection)
        expected = base64.b64encode(
            hashlib.sha1((key + GUID).encode("ascii")).digest()
        ).decode("ascii")
        if status != 101 or headers.get("sec-websocket-accept") != expected:
            raise ValueError(f"invalid WebSocket handshake: {status} {headers}")
        opcode, payload, buffered = read_frame(connection, buffered)
        if (opcode, payload) != (0x1, b"ready"):
            raise ValueError(f"unexpected ready frame: {opcode} {payload!r}")
        message = f"cycle-{index}".encode("ascii")
        connection.sendall(masked_frame(0x1, message))
        opcode, payload, buffered = read_frame(connection, buffered)
        if (opcode, payload) != (0x1, message):
            raise ValueError(f"unexpected echo frame: {opcode} {payload!r}")
        close_payload = b"\x03\xe8"
        connection.sendall(masked_frame(0x8, close_payload))
        opcode, payload, _ = read_frame(connection, buffered)
        if (opcode, payload) != (0x8, close_payload):
            raise ValueError(f"unexpected close frame: {opcode} {payload!r}")
    finally:
        connection.close()


def run_websocket(host: str, count: int, concurrency: int) -> None:
    started = time.monotonic()
    errors: list[str] = []

    def execute(index: int) -> None:
        try:
            websocket_cycle(host, index)
        except Exception as error:  # noqa: BLE001 - evidence retains exact failures.
            errors.append(f"{type(error).__name__}: {error}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        list(executor.map(execute, range(count)))
    print(
        json.dumps(
            {
                "mode": "websocket",
                "requested": count,
                "successes": count - len(errors),
                "duration_seconds": round(time.monotonic() - started, 3),
                "errors": collections.Counter(errors),
            },
            indent=2,
            sort_keys=True,
        )
    )


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise ValueError("value must be positive")
    return parsed


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "http":
        run_http(
            sys.argv[2],
            sys.argv[3],
            positive_integer(sys.argv[4]),
            positive_integer(sys.argv[5]),
        )
    elif mode == "websocket":
        run_websocket(
            sys.argv[2],
            positive_integer(sys.argv[3]),
            positive_integer(sys.argv[4]),
        )
    else:
        raise SystemExit(f"unknown mode: {mode}")
