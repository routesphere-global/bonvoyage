#!/usr/bin/env python3
"""Controlled raw RFC 6455 upstream for the WebSocket checkpoint."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import socketserver
import struct
import time


GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_HEAD_BYTES = 32768
MAX_FRAME_BYTES = 1024 * 1024


def read_head(connection: socket.socket) -> tuple[bytes, bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            raise ConnectionError("request ended before its header block")
        data += chunk
        if len(data) > MAX_HEAD_BYTES:
            raise ValueError("request header block exceeded its bound")
    head, remainder = data.split(b"\r\n\r\n", 1)
    return head, remainder


def parse_head(head: bytes) -> tuple[str, dict[str, str]]:
    lines = head.decode("iso-8859-1").split("\r\n")
    method, target, version = lines[0].split(" ", 2)
    if method != "GET" or version != "HTTP/1.1":
        raise ValueError("unexpected request line")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return target, headers


def response(status: int, reason: str, body: bytes) -> bytes:
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Content-Type: text/plain\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body


def frame(opcode: int, payload: bytes) -> bytes:
    if len(payload) < 126:
        return bytes((0x80 | opcode, len(payload))) + payload
    if len(payload) <= 0xFFFF:
        return bytes((0x80 | opcode, 126)) + struct.pack("!H", len(payload)) + payload
    return bytes((0x80 | opcode, 127)) + struct.pack("!Q", len(payload)) + payload


def take_client_frame(data: bytes) -> tuple[int, bytes, bytes] | None:
    if len(data) < 2:
        return None
    first, second = data[0], data[1]
    if first & 0x70 or not first & 0x80 or not second & 0x80:
        raise ValueError("controlled client sent invalid frame flags")
    length = second & 0x7F
    offset = 2
    if length == 126:
        if len(data) < offset + 2:
            return None
        length = struct.unpack("!H", data[offset : offset + 2])[0]
        offset += 2
    elif length == 127:
        if len(data) < offset + 8:
            return None
        length = struct.unpack("!Q", data[offset : offset + 8])[0]
        offset += 8
    if length > MAX_FRAME_BYTES:
        raise ValueError("controlled client frame exceeded its bound")
    if len(data) < offset + 4 + length:
        return None
    mask = data[offset : offset + 4]
    offset += 4
    masked = data[offset : offset + length]
    payload = bytes(value ^ mask[index % 4] for index, value in enumerate(masked))
    return first & 0x0F, payload, data[offset + length :]


def websocket_accept(key: str) -> str:
    digest = hashlib.sha1((key + GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        connection: socket.socket = self.request
        connection.settimeout(15)
        try:
            head, buffered = read_head(connection)
            target, headers = parse_head(head)
            if target == "/healthz":
                connection.sendall(response(200, "OK", b"ready\n"))
                return

            print(
                "REQUEST "
                + json.dumps({"target": target, "headers": headers}, sort_keys=True),
                flush=True,
            )
            if target == "/ordinary":
                connection.sendall(response(200, "OK", b"ordinary\n"))
                return
            if target == "/reject":
                connection.sendall(response(403, "Forbidden", b"denied\n"))
                return
            if target == "/stall":
                time.sleep(2.5)
                return

            key = headers["sec-websocket-key"]
            accept = websocket_accept(key)
            response_headers = [
                "HTTP/1.1 101 Switching Protocols",
                "Connection: Upgrade",
                "Upgrade: websocket",
                f"Sec-WebSocket-Accept: {accept}",
                f"X-Upstream-Target: {target}",
                f"X-Seen-Route-Action: {headers.get('x-route-action', '')}",
            ]
            if target == "/bad-accept":
                response_headers[3] = "Sec-WebSocket-Accept: invalid"
            if "chat" in headers.get("sec-websocket-protocol", ""):
                response_headers.append("Sec-WebSocket-Protocol: chat")
            if "permessage-deflate" in headers.get("sec-websocket-extensions", ""):
                response_headers.append("Sec-WebSocket-Extensions: permessage-deflate")
            if target == "/bad-protocol":
                response_headers = [
                    line
                    for line in response_headers
                    if not line.lower().startswith("sec-websocket-protocol:")
                ]
                response_headers.append("Sec-WebSocket-Protocol: admin")
            if target == "/bad-extension":
                response_headers = [
                    line
                    for line in response_headers
                    if not line.lower().startswith("sec-websocket-extensions:")
                ]
                response_headers.append("Sec-WebSocket-Extensions: x-unoffered")
            if target == "/framed":
                response_headers.append("Content-Length: 0")

            response_head = ("\r\n".join(response_headers) + "\r\n\r\n").encode(
                "ascii"
            )
            if target in {"/bad-accept", "/bad-protocol", "/bad-extension", "/framed"}:
                connection.sendall(response_head)
                return

            connection.sendall(response_head + frame(0x1, b"ready"))
            if target == "/idle":
                while connection.recv(4096):
                    pass
                return

            while True:
                parsed = take_client_frame(buffered)
                if parsed is None:
                    chunk = connection.recv(4096)
                    if not chunk:
                        return
                    buffered += chunk
                    continue
                opcode, payload, buffered = parsed
                if opcode == 0x8:
                    connection.sendall(frame(0x8, payload))
                    return
                if opcode == 0x9:
                    connection.sendall(frame(0xA, payload))
                elif opcode in {0x1, 0x2}:
                    connection.sendall(frame(opcode, payload))
                else:
                    raise ValueError("controlled client sent an unsupported opcode")
        except (ConnectionError, OSError, ValueError, KeyError) as error:
            print(f"CONNECTION {type(error).__name__}: {error}", flush=True)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    # Keep the controlled fixture outside saturation during multi-shard churn.
    request_queue_size = 1024


if __name__ == "__main__":
    port = int(os.environ.get("BONVOYAGE_WEBSOCKET_FIXTURE_PORT", "8081"))
    if port < 1 or port > 65535:
        raise SystemExit("BONVOYAGE_WEBSOCKET_FIXTURE_PORT must be between 1 and 65535")
    print(f"BonVoyage WebSocket fixture listening on 0.0.0.0:{port}", flush=True)
    Server(("0.0.0.0", port), Handler).serve_forever()
