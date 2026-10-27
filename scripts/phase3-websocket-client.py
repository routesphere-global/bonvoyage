#!/usr/bin/env python3
"""Dependency-free client assertions for BonVoyage WebSocket tunneling."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import time
from dataclasses import dataclass


GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def masked_frame(opcode: int, payload: bytes) -> bytes:
    mask = os.urandom(4)
    encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    if len(payload) < 126:
        prefix = bytes((0x80 | opcode, 0x80 | len(payload)))
    elif len(payload) <= 0xFFFF:
        prefix = bytes((0x80 | opcode, 0x80 | 126)) + struct.pack("!H", len(payload))
    else:
        prefix = bytes((0x80 | opcode, 0x80 | 127)) + struct.pack("!Q", len(payload))
    return prefix + mask + encoded


def connect(host: str, port: int, ca_file: str | None = None) -> socket.socket:
    raw = socket.create_connection((host, port), timeout=5)
    if ca_file is None:
        return raw
    context = ssl.create_default_context(cafile=ca_file)
    return context.wrap_socket(raw, server_hostname="api.example.test")


def read_head(connection: socket.socket) -> tuple[int, dict[str, str], bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            raise ConnectionError("response ended before its header block")
        data += chunk
        if len(data) > 65536:
            raise ValueError("response head exceeded the test bound")
    raw_head, remainder = data.split(b"\r\n\r\n", 1)
    lines = raw_head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return status, headers, remainder


def read_http_response(connection: socket.socket) -> tuple[int, dict[str, str], bytes]:
    status, headers, body = read_head(connection)
    length = int(headers.get("content-length", "0"))
    while len(body) < length:
        chunk = connection.recv(length - len(body))
        if not chunk:
            raise ConnectionError("response body was truncated")
        body += chunk
    connection.close()
    return status, headers, body[:length]


@dataclass
class WebSocket:
    connection: socket.socket
    buffered: bytes
    headers: dict[str, str]

    def read_frame(self) -> tuple[int, bytes]:
        while len(self.buffered) < 2:
            chunk = self.connection.recv(4096)
            if not chunk:
                raise ConnectionError("WebSocket closed before its frame header")
            self.buffered += chunk
        first, second = self.buffered[0], self.buffered[1]
        assert first & 0x80 and not first & 0x70 and not second & 0x80
        length = second & 0x7F
        offset = 2
        if length == 126:
            while len(self.buffered) < offset + 2:
                chunk = self.connection.recv(4096)
                if not chunk:
                    raise ConnectionError("WebSocket closed during its frame length")
                self.buffered += chunk
            length = struct.unpack("!H", self.buffered[offset : offset + 2])[0]
            offset += 2
        elif length == 127:
            while len(self.buffered) < offset + 8:
                chunk = self.connection.recv(4096)
                if not chunk:
                    raise ConnectionError("WebSocket closed during its frame length")
                self.buffered += chunk
            length = struct.unpack("!Q", self.buffered[offset : offset + 8])[0]
            offset += 8
        while len(self.buffered) < offset + length:
            chunk = self.connection.recv(4096)
            if not chunk:
                raise ConnectionError("WebSocket frame was truncated")
            self.buffered += chunk
        payload = self.buffered[offset : offset + length]
        self.buffered = self.buffered[offset + length :]
        return first & 0x0F, payload

    def send(self, opcode: int, payload: bytes) -> None:
        self.connection.sendall(masked_frame(opcode, payload))

    def close(self) -> None:
        self.send(0x8, b"\x03\xe8")
        opcode, payload = self.read_frame()
        assert opcode == 0x8 and payload == b"\x03\xe8"
        self.connection.close()


def handshake_bytes(
    path: str,
    *,
    version: str = "13",
    key: str | None = None,
    protocols: str = "chat",
    extensions: str = "permessage-deflate; client_max_window_bits",
    body: bytes = b"",
    duplicate_key: bool = False,
) -> tuple[bytes, str]:
    key = key or base64.b64encode(os.urandom(16)).decode("ascii")
    lines = [
        f"GET {path} HTTP/1.1",
        "Host: api.example.test",
        "Connection: keep-alive, Upgrade",
        "Upgrade: websocket",
        f"Sec-WebSocket-Version: {version}",
        f"Sec-WebSocket-Key: {key}",
    ]
    if duplicate_key:
        lines.append(f"Sec-WebSocket-Key: {key}")
    if protocols:
        lines.append(f"Sec-WebSocket-Protocol: {protocols}")
    if extensions:
        lines.append(f"Sec-WebSocket-Extensions: {extensions}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body, key


def open_websocket(
    host: str,
    path: str,
    *,
    port: int = 8080,
    ca_file: str | None = None,
    immediate_payload: bytes | None = None,
) -> WebSocket:
    request, key = handshake_bytes(path)
    connection = connect(host, port, ca_file)
    if immediate_payload is not None:
        request += masked_frame(0x1, immediate_payload)
    connection.sendall(request)
    status, headers, remainder = read_head(connection)
    assert status == 101, (status, headers, remainder)
    expected = base64.b64encode(
        hashlib.sha1((key + GUID).encode("ascii")).digest()
    ).decode("ascii")
    assert headers["sec-websocket-accept"] == expected
    assert headers["sec-websocket-protocol"] == "chat"
    assert headers["sec-websocket-extensions"] == "permessage-deflate"
    return WebSocket(connection, remainder, headers)


def raw_request(host: str, request: bytes) -> tuple[int, dict[str, str], bytes]:
    connection = connect(host, 8080)
    connection.sendall(request)
    return read_http_response(connection)


def valid_upgrade_response(host: str, path: str) -> tuple[int, dict[str, str], bytes]:
    request, _ = handshake_bytes(path)
    return raw_request(host, request)


def error_code(body: bytes) -> str:
    return json.loads(body)["error"]["code"]


def run_suite(host: str, ca_file: str) -> None:
    clear = open_websocket(host, "/socket?source=clear", immediate_payload=b"first")
    assert clear.headers["x-gateway-policy"] == "enforced"
    assert clear.headers["x-upstream-target"] == "/echo?source=clear"
    assert clear.headers["x-seen-route-action"] == "websocket"
    assert clear.read_frame() == (0x1, b"ready")
    assert clear.read_frame() == (0x1, b"first")
    clear.send(0x2, b"\x00\x01binary")
    assert clear.read_frame() == (0x2, b"\x00\x01binary")
    clear.close()

    secure = open_websocket(
        host,
        "/socket?source=tls",
        port=8443,
        ca_file=ca_file,
        immediate_payload=b"secure",
    )
    assert secure.read_frame() == (0x1, b"ready")
    assert secure.read_frame() == (0x1, b"secure")
    secure.close()

    request, _ = handshake_bytes("/socket", version="12")
    status, headers, body = raw_request(host, request)
    assert status == 426 and headers["sec-websocket-version"] == "13"
    assert error_code(body) == "unsupported_websocket_version"

    request, _ = handshake_bytes("/socket", key="not-base64")
    status, _, body = raw_request(host, request)
    assert status == 400 and error_code(body) == "invalid_websocket_handshake"

    request, _ = handshake_bytes("/socket", body=b"x")
    status, _, body = raw_request(host, request)
    assert status == 400 and error_code(body) == "invalid_websocket_handshake"

    status, headers, body = raw_request(
        host,
        b"GET /socket HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n",
    )
    assert status == 426 and headers["sec-websocket-version"] == "13"
    assert error_code(body) == "websocket_upgrade_required"

    request, _ = handshake_bytes("/socket", duplicate_key=True)
    status, _, body = raw_request(host, request)
    assert status == 400 and error_code(body) == "duplicate_websocket_header"

    status, _, body = valid_upgrade_response(host, "/ordinary")
    assert status == 426 and error_code(body) == "websocket_not_enabled"

    for path in ("/bad-accept", "/bad-protocol", "/bad-extension", "/framed"):
        status, _, body = valid_upgrade_response(host, path)
        assert status == 502 and error_code(body) == "upstream_failure", (path, body)

    status, _, body = valid_upgrade_response(host, "/reject")
    assert status == 403 and body == b"denied\n"

    started = time.monotonic()
    status, _, body = valid_upgrade_response(host, "/stall")
    assert status == 504 and error_code(body) == "request_timeout"
    assert time.monotonic() - started < 3.0

    held = open_websocket(host, "/hold")
    assert held.read_frame() == (0x1, b"ready")
    status, _, body = valid_upgrade_response(host, "/hold")
    assert status == 503 and error_code(body) == "route_overloaded"
    held.close()
    recovered_hold = open_websocket(host, "/hold")
    assert recovered_hold.read_frame() == (0x1, b"ready")
    recovered_hold.close()

    idle = open_websocket(host, "/idle")
    assert idle.read_frame() == (0x1, b"ready")
    idle.connection.settimeout(3)
    try:
        closed = idle.connection.recv(1) == b""
    except (ConnectionResetError, ssl.SSLError):
        closed = True
    assert closed
    idle.connection.close()

    recovered = open_websocket(host, "/socket?source=recovery")
    assert recovered.read_frame() == (0x1, b"ready")
    recovered.close()

    status, _, body = raw_request(
        host,
        b"GET /ordinary HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n",
    )
    assert status == 200 and body == b"ordinary\n"

    print(
        json.dumps(
            {
                "cleartext_and_tls_tunnels": "passed",
                "immediate_bidirectional_bytes": "passed",
                "text_binary_and_close_frames": "passed",
                "strict_client_and_upstream_handshakes": "passed",
                "ordinary_upstream_rejection": "passed",
                "request_deadline": "passed",
                "route_concurrency_and_recovery": "passed",
                "idle_timeout_and_recovery": "passed",
            },
            indent=2,
            sort_keys=True,
        )
    )


def hold_until_drain(host: str, ready_file: str) -> None:
    held = open_websocket(host, "/hold")
    assert held.read_frame() == (0x1, b"ready")
    with open(ready_file, "w", encoding="utf-8") as destination:
        destination.write("ready\n")
    held.connection.settimeout(10)
    started = time.monotonic()
    try:
        closed = held.connection.recv(1) == b""
    except (ConnectionResetError, ssl.SSLError):
        closed = True
    assert closed
    print(
        json.dumps(
            {
                "drain_closed_tunnel": True,
                "close_latency_seconds": round(time.monotonic() - started, 3),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    mode, gateway = sys.argv[1:3]
    if mode == "suite":
        run_suite(gateway, sys.argv[3])
    elif mode == "hold":
        hold_until_drain(gateway, sys.argv[3])
    else:
        raise SystemExit(f"unknown mode: {mode}")
