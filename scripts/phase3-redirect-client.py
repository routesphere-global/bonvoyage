#!/usr/bin/env python3
"""HTTP/1.1 assertions for bounded static route redirects."""

from __future__ import annotations

import http.client
import json
import sys


HOST = sys.argv[1]
API_KEY = sys.argv[2]
PORT = 8080
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
    connection = http.client.HTTPConnection(HOST, PORT, timeout=5)
    configured = {"Host": "api.example.test"}
    configured.update(headers or {})
    connection.request(method, path, body=body, headers=configured)
    response = connection.getresponse()
    result = response.status, response.getheaders(), response.read()
    connection.close()
    return result


def assert_redirect(
    result: tuple[int, list[tuple[str, str]], bytes],
    status: int,
    location: str,
) -> None:
    actual_status, headers, body = result
    assert actual_status == status, result
    assert values(headers, "location") == [location], headers
    assert values(headers, "content-length") == ["0"], headers
    assert body == b"", body


# A valid bounded body is consumed before the redirect so this connection can
# immediately carry another request without losing framing alignment.
connection = http.client.HTTPConnection(HOST, PORT, timeout=5)
connection.request(
    "POST",
    "/redirect/relative",
    body=b"12345678",
    headers={
        "Host": "api.example.test",
        "Content-Type": "application/json",
    },
)
response = connection.getresponse()
first = response.status, response.getheaders(), response.read()
first_port = connection.sock.getsockname()[1]
assert_redirect(first, 307, "/v2/orders?source=legacy")
connection.request("GET", "/redirect/dns", headers={"Host": "api.example.test"})
response = connection.getresponse()
second = response.status, response.getheaders(), response.read()
second_port = connection.sock.getsockname()[1]
connection.close()
assert_redirect(second, 308, "https://api-v2.example.test:9443/v2/orders?source=legacy")
assert first_port == second_port

status, headers, body = request(
    "POST",
    "/redirect/relative",
    {"Content-Type": "application/json"},
    b"123456789",
)
assert status == 413 and error_code(body) == "request_body_too_large"
assert values(headers, "location") == []

assert_redirect(
    request("GET", "/redirect/ipv4"),
    302,
    "http://192.0.2.10:8080/moved",
)
assert_redirect(
    request("GET", "/redirect/ipv6"),
    301,
    "https://[2001:db8::10]:9443/moved/%7Eowner",
)
assert_redirect(request("POST", "/redirect/see-other"), 303, "/result")

cors = request("GET", "/redirect/cors", {"Origin": ORIGIN})
assert_redirect(cors, 307, "/v2/browser")
assert values(cors[1], "access-control-allow-origin") == [ORIGIN]
status, headers, body = request(
    "OPTIONS",
    "/redirect/cors",
    {"Origin": ORIGIN, "Access-Control-Request-Method": "GET"},
)
assert status == 204 and body == b""
assert values(headers, "location") == []
assert values(headers, "access-control-allow-methods") == ["GET"]

status, headers, body = request("GET", "/redirect/auth")
assert status == 401 and error_code(body) == "unauthorized"
assert values(headers, "location") == []
assert_redirect(
    request("GET", "/redirect/auth", {"X-Api-Key": API_KEY}),
    308,
    "/v2/private",
)

status, headers, body = request("GET", "/fixed/301")
assert status == 301 and body == b"fixed three hundred\n"
assert values(headers, "location") == []

status, _, body = request("GET", "/identity")
assert status == 200 and body == b"upstream\n"

print(
    json.dumps(
        {
            "all_redirect_statuses": [301, 302, 303, 307, 308],
            "auth_precedes_redirect": True,
            "bounded_body_consumed_on_keep_alive": True,
            "cors_actual_and_preflight_order": True,
            "fixed_301_regression_exercised": True,
            "locations": ["relative", "dns", "ipv4", "ipv6"],
            "oversized_body_precedes_redirect": True,
            "upstream_recovery_request": True,
        },
        indent=2,
        sort_keys=True,
    )
)
