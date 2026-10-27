#!/usr/bin/env python3
"""HTTP/1.1 assertions for the bounded route-level CORS checkpoint."""

from __future__ import annotations

import http.client
import json
import socket
import sys


HOST = sys.argv[1]
ORIGIN = "https://app.example.com"


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
    connection = http.client.HTTPConnection(HOST, 8080, timeout=5)
    configured = {"Host": "api.example.test"}
    configured.update(headers or {})
    connection.request(method, path, body=body, headers=configured)
    response = connection.getresponse()
    result = response.status, response.getheaders(), response.read()
    connection.close()
    return result


status, headers, body = request("GET", "/public")
assert status == 200 and body == b"public ready\n", (status, headers, body)

status, headers, body = request("GET", "/cors/fixed")
assert status == 200 and body == b"cors fixed ready\n", (status, headers, body)
assert not any(name.lower().startswith("access-control-") for name, _ in headers)

status, headers, body = request("GET", "/cors/fixed", {"Origin": ORIGIN})
assert status == 200 and body == b"cors fixed ready\n", (status, headers, body)
assert values(headers, "access-control-allow-origin") == [ORIGIN]
assert values(headers, "access-control-allow-credentials") == ["true"]
assert values(headers, "access-control-expose-headers") == [
    "x-request-id, x-trace-id"
]
assert values(headers, "vary") == ["Origin"]

status, headers, body = request(
    "GET", "/cors/fixed", {"Origin": "https://denied.example.com"}
)
assert status == 403 and error_code(body) == "cors_origin_denied"
assert not values(headers, "access-control-allow-origin")

preflight = {
    "Origin": ORIGIN,
    "Access-Control-Request-Method": "POST",
    "Access-Control-Request-Headers": "X-Request-Id, Authorization",
}
status, headers, body = request("OPTIONS", "/cors-observation", preflight)
assert status == 204 and body == b""
assert values(headers, "access-control-allow-origin") == [ORIGIN]
assert values(headers, "access-control-allow-credentials") == ["true"]
assert values(headers, "access-control-allow-methods") == ["GET, POST"]
assert values(headers, "access-control-allow-headers") == [
    "authorization, content-type, x-request-id"
]
assert values(headers, "access-control-max-age") == ["600"]
assert values(headers, "vary") == [
    "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
]

status, _, body = request(
    "OPTIONS",
    "/cors-observation",
    {
        "Origin": ORIGIN,
        "Access-Control-Request-Method": "DELETE",
    },
)
assert status == 403 and error_code(body) == "cors_method_denied"

status, _, body = request(
    "OPTIONS",
    "/cors-observation",
    {
        "Origin": ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "X-Private",
    },
)
assert status == 403 and error_code(body) == "cors_headers_denied"

status, _, body = request(
    "OPTIONS",
    "/cors-observation",
    {
        "Origin": ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authorization,,X-Request-Id",
    },
)
assert status == 400 and error_code(body) == "invalid_cors_request"

status, headers, body = request(
    "OPTIONS",
    "/cors-observation",
    {
        "Origin": ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Content-Type": "text/plain",
    },
    b"x",
)
assert status == 400 and error_code(body) == "invalid_cors_request"
assert values(headers, "connection") == ["close"]

# Browser preflight is answered before route authentication.
status, headers, body = request(
    "OPTIONS",
    "/cors/auth",
    {"Origin": ORIGIN, "Access-Control-Request-Method": "GET"},
)
assert status == 204 and body == b""
assert values(headers, "access-control-allow-origin") == [ORIGIN]

# An actual auth rejection retains the already validated CORS response fields.
status, headers, body = request("GET", "/cors/auth", {"Origin": ORIGIN})
assert status == 401 and error_code(body) == "unauthorized"
assert values(headers, "www-authenticate") == ["ApiKey"]
assert values(headers, "access-control-allow-origin") == [ORIGIN]

# A configured route strips conflicting upstream policy and emits one owner.
status, headers, body = request("GET", "/cors-observation", {"Origin": ORIGIN})
assert status == 200
assert json.loads(body) == {
    "origin": ORIGIN,
    "preflight_headers_present": False,
    "preflight_method_present": False,
}
assert values(headers, "access-control-allow-origin") == [ORIGIN]
assert values(headers, "access-control-allow-credentials") == ["true"]
assert values(headers, "access-control-expose-headers") == [
    "x-request-id, x-trace-id"
]
assert values(headers, "x-request-id") == ["upstream-request-id"]
assert "https://upstream.invalid" not in str(headers)
assert "x-upstream-secret" not in str(headers)

# Policy ownership also strips upstream fields when this request has no Origin.
status, headers, _ = request("GET", "/cors-observation")
assert status == 200
assert not any(name.lower().startswith("access-control-") for name, _ in headers)

status, headers, body = request(
    "GET", "/cors/wildcard", {"Origin": "https://any.example.net"}
)
assert status == 200 and body == b"wildcard ready\n"
assert values(headers, "access-control-allow-origin") == ["*"]
assert not values(headers, "access-control-allow-credentials")
assert not values(headers, "vary")

status, headers, body = request("GET", "/public", {"Origin": ORIGIN})
assert status == 200 and body == b"public ready\n"
assert not any(name.lower().startswith("access-control-") for name, _ in headers)

# A parser failure must not inherit policy from the preceding request on a
# persistent connection.
for path, origin in (
    ("/cors/fixed", ORIGIN),
    ("/cors/wildcard", "https://any.example.net"),
):
    with socket.create_connection((HOST, 8080), timeout=5) as connection:
        connection.sendall(
            f"GET {path} HTTP/1.1\r\nHost: api.example.test\r\n"
            f"Origin: {origin}\r\n\r\n".encode()
        )
        response = http.client.HTTPResponse(connection)
        response.begin()
        assert response.status == 200
        response.read()
        response.close()
        connection.sendall(
            b"GET /public HTTP/1.1\r\nHost: api.example.test\r\n"
            b"invalid header\r\n\r\n"
        )
        response = http.client.HTTPResponse(connection)
        response.begin()
        assert response.status == 400
        assert error_code(response.read()) == "malformed_request"
        assert not values(response.getheaders(), "access-control-allow-origin"), (
            "parser failure inherited CORS context", response.getheaders()
        )
        assert not values(response.getheaders(), "vary")
        response.close()

# The owning request coroutine has unwound before the outer error serializer.
for _ in range(8):
    status, headers, body = request("GET", "/cors/unavailable", {"Origin": ORIGIN})
    assert status == 502, (status, headers, body)
    assert values(headers, "access-control-allow-origin") == [ORIGIN], headers
    assert values(headers, "access-control-allow-credentials") == ["true"]

connection = http.client.HTTPConnection(HOST, 8080, timeout=5)
try:
    persistent_socket = None
    for origin in (ORIGIN, "http://localhost:3000", None):
        request_headers = {"Host": "api.example.test"}
        if origin is not None:
            request_headers["Origin"] = origin
        connection.request("GET", "/cors/fixed", headers=request_headers)
        if persistent_socket is None:
            persistent_socket = connection.sock
        assert connection.sock is persistent_socket
        response = connection.getresponse()
        assert response.status == 200
        assert not response.will_close
        response.read()
        assert values(response.getheaders(), "access-control-allow-origin") == (
            [origin] if origin is not None else []
        )
finally:
    connection.close()

print(
    json.dumps(
        {
            "actual_exact_origin": True,
            "auth_preflight_bypass": True,
            "credential_wildcard_prevented": True,
            "fixed_and_proxied_actions": True,
            "gateway_error_headers": True,
            "malformed_preflight_rejected": True,
            "method_and_header_denials": True,
            "preflight_answered_locally": True,
            "preflight_body_forced_connection_close": True,
            "upstream_policy_stripped": True,
            "upstream_failure_origin_lifetime": True,
            "keepalive_parser_error_cors_reset": True,
            "keepalive_origin_change_and_removal": True,
        },
        indent=2,
        sort_keys=True,
    )
)
