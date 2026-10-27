#!/usr/bin/env python3
"""HTTP/1.1 assertions for bounded route request-content policy."""

from __future__ import annotations

import http.client
import json
import socket
import sys


HOST = sys.argv[1]
PORT = 8080
ORIGIN = "https://app.example.com"
ACCEPTED_TYPES = "application/json, application/problem+json"


def values(headers: list[tuple[str, str]], name: str) -> list[str]:
    target = name.lower()
    return [value for key, value in headers if key.lower() == target]


def error_code(body: bytes) -> str:
    return json.loads(body)["error"]["code"]


def request(
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, list[tuple[str, str]], bytes]:
    connection = http.client.HTTPConnection(HOST, PORT, timeout=5)
    configured = {"Host": "api.example.test"}
    configured.update(headers or {})
    connection.request(method, path, body=body, headers=configured)
    response = connection.getresponse()
    result = response.status, response.getheaders(), response.read()
    connection.close()
    return result


def raw_request(message: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
    with socket.create_connection((HOST, PORT), timeout=5) as connection:
        connection.sendall(message)
        connection.shutdown(socket.SHUT_WR)
        received = bytearray()
        while True:
            data = connection.recv(65536)
            if not data:
                break
            received.extend(data)
    head, separator, body = bytes(received).partition(b"\r\n\r\n")
    assert separator, received
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ", 2)[1])
    headers = []
    for line in lines[1:]:
        name, value = line.split(b":", 1)
        headers.append((name.decode("ascii"), value.strip().decode("ascii")))
    return status, headers, body


status, _, body = request("GET", "/public")
assert status == 200 and body == b"public ready\n"

status, _, body = request(
    "POST", "/content/declared", {"Content-Type": "application/json"}, b"12345678"
)
assert status == 200 and body == b"12345678"

status, headers, body = request(
    "POST", "/content/declared", {"Content-Type": "application/json"}, b"123456789"
)
assert status == 413 and error_code(body) == "request_body_too_large"
assert values(headers, "connection") == ["close"]

status, headers, body = request("POST", "/content/declared", body=b"x")
assert status == 415 and error_code(body) == "content_type_required"
assert values(headers, "accept") == [ACCEPTED_TYPES]
assert values(headers, "connection") == ["close"]

status, headers, body = request(
    "POST",
    "/content/declared",
    {"Content-Type": "text/plain", "Origin": ORIGIN},
    b"x",
)
assert status == 415 and error_code(body) == "unsupported_media_type"
assert values(headers, "accept") == [ACCEPTED_TYPES]
assert values(headers, "access-control-allow-origin") == [ORIGIN]

status, _, body = request(
    "POST", "/content/declared", {"Content-Type": "application/json;"}, b"x"
)
assert status == 400 and error_code(body) == "invalid_content_type"

duplicate = (
    b"POST /content/declared HTTP/1.1\r\n"
    b"Host: api.example.test\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Type: application/problem+json\r\n"
    b"Content-Length: 1\r\n"
    b"Connection: close\r\n\r\nx"
)
status, _, body = raw_request(duplicate)
assert status == 400 and error_code(body) == "invalid_content_type"

large_content_type = "application/" + "x" * 1013
assert len(large_content_type) == 1025
status, _, body = request(
    "POST", "/content/declared", {"Content-Type": large_content_type}, b"x"
)
assert status == 431 and error_code(body) == "content_type_too_large"

status, _, body = request(
    "POST",
    "/content/declared",
    {"Content-Type": 'Application/JSON; charset="utf-8"'},
    b"12345678",
)
assert status == 200 and body == b"12345678"

connection = http.client.HTTPConnection(HOST, PORT, timeout=5)
connection.request(
    "POST",
    "/content/declared",
    body=b"",
    headers={
        "Host": "api.example.test",
        "Content-Length": "0",
        "Content-Type": "text/plain",
    },
)
response = connection.getresponse()
body = response.read()
assert response.status == 415 and error_code(body) == "unsupported_media_type"
first_port = connection.sock.getsockname()[1]
connection.request("GET", "/public", headers={"Host": "api.example.test"})
response = connection.getresponse()
body = response.read()
second_port = connection.sock.getsockname()[1]
connection.close()
assert response.status == 200 and body == b"public ready\n"
assert first_port == second_port

status, _, body = request(
    "POST", "/content/size-only", {"Content-Type": "not a media type"}, b"1234"
)
assert status == 200 and body == b"1234"

status, _, body = request(
    "POST", "/content/type-only", {"Content-Type": "application/json"}, b"123456789"
)
assert status == 200 and body == b"123456789"

chunked_exact = (
    b"POST /content/fixed HTTP/1.1\r\n"
    b"Host: api.example.test\r\n"
    b"Content-Type: application/json\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Connection: close\r\n\r\n"
    b"4\r\n1234\r\n4\r\n5678\r\n0\r\n\r\n"
)
status, _, body = raw_request(chunked_exact)
assert status == 200 and body == b"fixed ready\n"

chunked_over = (
    b"POST /content/fixed HTTP/1.1\r\n"
    b"Host: api.example.test\r\n"
    b"Content-Type: application/json\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Connection: close\r\n\r\n"
    b"5\r\n12345\r\n4\r\n6789\r\n0\r\n\r\n"
)
status, _, body = raw_request(chunked_over)
assert status == 413 and error_code(body) == "request_body_too_large"

print(
    json.dumps(
        {
            "bodyless_rejection_kept_connection": True,
            "case_and_parameters_accepted": True,
            "chunked_exact_and_over_limit": True,
            "content_type_errors": [400, 415, 431],
            "cors_error_context_preserved": True,
            "declared_body_exact_and_over_limit": True,
            "duplicate_content_type_rejected": True,
            "size_only_policy_did_not_parse_content_type": True,
            "type_only_policy_inherited_global_limit": True,
        },
        indent=2,
        sort_keys=True,
    )
)
