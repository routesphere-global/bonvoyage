#!/usr/bin/env python3
"""HTTP/1.1 assertions for the bounded header-transformation checkpoint."""

from __future__ import annotations

import http.client
import json
import sys
from typing import Any


def header_map(response: http.client.HTTPResponse) -> dict[str, str]:
    return {name.lower(): value for name, value in response.getheaders()}


def request(
    connection: http.client.HTTPConnection,
    path: str,
    headers: dict[str, str],
) -> tuple[int, dict[str, str], bytes]:
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    body = response.read()
    return response.status, header_map(response), body


def assert_transformed(record: dict[str, Any], protocol: str) -> None:
    headers = record["headers"]
    assert headers["x-request-set"] == "gateway-set"
    assert headers["x-request-append"] == "client-append, gateway-append"
    assert headers["x-request-added"] == "gateway-added"
    assert headers["x-client-protocol"] == protocol
    assert headers["x-forwarded-proto"] == "http"
    assert "x-forwarded-for" in headers
    assert "x-request-remove" not in headers
    assert "x-api-key" not in headers


def assert_plain_response(headers: dict[str, str], body: bytes) -> None:
    plain = json.loads(body)
    assert plain["headers"]["x-request-set"] == "client-set"
    assert plain["headers"]["x-request-append"] == "client-append"
    assert plain["headers"]["x-request-remove"] == "client-remove"
    assert "x-request-added" not in plain["headers"]
    assert headers["x-response-set"] == "upstream-set"
    assert headers["x-response-append"] == "upstream-append"
    assert headers["x-response-remove"] == "upstream-remove"
    assert "x-response-added" not in headers


def main() -> None:
    host, api_key = sys.argv[1:3]
    connection = http.client.HTTPConnection(host, 8080, timeout=5)
    common = {
        "Host": "api.example.test",
        "X-Request-Set": "client-set",
        "X-Request-Append": "client-append",
        "X-Request-Remove": "client-remove",
        "X-Client-Protocol": "h1",
    }

    valid_headers = dict(common)
    valid_headers["X-API-Key"] = api_key
    valid_headers["Origin"] = "https://app.example.com"
    status, headers, body = request(connection, "/headers", valid_headers)
    assert status == 200
    assert headers["x-response-set"] == "gateway-set"
    assert headers["x-response-append"] == "upstream-append, gateway-append"
    assert headers["x-response-added"] == "gateway-added"
    assert headers["x-response-unchanged"] == "upstream-keep"
    assert "x-response-remove" not in headers
    assert headers["access-control-allow-origin"] == "https://app.example.com"
    assert headers["access-control-expose-headers"] == "x-response-added"
    transformed = json.loads(body)
    assert_transformed(transformed, "h1")

    status, headers, body = request(connection, "/headers", common)
    assert status == 401
    assert b"unauthorized" in body
    assert "x-response-added" not in headers

    status, headers, body = request(connection, "/plain", common)
    assert status == 200
    assert_plain_response(headers, body)

    status, _, body = request(connection, "/request-limit", common)
    assert status == 431
    assert b"transformed_request_headers_too_large" in body

    status, headers, body = request(connection, "/plain", common)
    assert status == 200
    assert_plain_response(headers, body)

    status, _, body = request(connection, "/response-limit", common)
    assert status == 502
    assert b"upstream_failure" in body
    connection.close()

    connection = http.client.HTTPConnection(host, 8080, timeout=5)
    status, headers, body = request(connection, "/plain", common)
    assert status == 200
    assert_plain_response(headers, body)
    connection.close()

    print(json.dumps({
        "http1_valid_transformation": "passed",
        "http1_auth_ordering": "passed",
        "http1_unconfigured_route": "passed",
        "http1_transformed_request_limit_431": "passed",
        "http1_transformed_response_limit_502": "passed",
        "http1_post_rejection_recovery": "passed",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
