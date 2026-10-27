#!/usr/bin/env python3
"""HTTP/1.1 assertions for static weighted route traffic splitting."""

from __future__ import annotations

import http.client
import json
import sys
from typing import Any


def request(
    connection: http.client.HTTPConnection,
    method: str,
    path: str,
    headers: dict[str, str],
) -> tuple[int, dict[str, str], bytes]:
    connection.request(method, path, headers=headers)
    response = connection.getresponse()
    body = response.read()
    return (
        response.status,
        {name.lower(): value for name, value in response.getheaders()},
        body,
    )


def record(body: bytes) -> dict[str, Any]:
    return json.loads(body)


def main() -> None:
    host, api_key = sys.argv[1:3]
    connection = http.client.HTTPConnection(host, 8080, timeout=5)
    base = {
        "Host": "api.example.test",
        "X-Client-Protocol": "h1",
    }

    status, _, body = request(
        connection, "GET", "/split/item?request=h1-missing", base
    )
    assert status == 401 and b"unauthorized" in body

    preflight = dict(base)
    preflight.update(
        {
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "GET",
        }
    )
    status, headers, _ = request(connection, "OPTIONS", "/split/item", preflight)
    assert status == 204
    assert headers["access-control-allow-origin"] == "https://app.example.com"

    expected = ["stable", "stable", "canary", "stable"] * 2
    observed: list[str] = []
    for index, upstream in enumerate(expected):
        authorized = dict(base)
        authorized.update(
            {
                "X-API-Key": api_key,
                "Origin": "https://app.example.com",
            }
        )
        status, headers, body = request(
            connection,
            "GET",
            f"/split/item?request=h1-{index}",
            authorized,
        )
        assert status == 200 and headers["x-upstream-id"] == upstream
        value = record(body)
        assert value["upstream"] == upstream
        assert value["path"] == f"/weighted/item?request=h1-{index}"
        assert value["headers"]["x-route-action"] == "weighted"
        assert "x-api-key" not in value["headers"]
        observed.append(upstream)

    retry_headers = dict(base)
    retry_headers["X-Request-ID"] = "retry-h1"
    status, headers, body = request(connection, "GET", "/retry", retry_headers)
    assert status == 200 and headers["x-upstream-id"] == "stable"
    retry = record(body)
    assert retry["upstream"] == "stable"
    assert retry["path"] == "/weighted-retry"
    assert retry["headers"]["x-route-action"] == "weighted-retry"

    long_target = "/bounded?padding=" + ("q" * 400)
    status, _, body = request(connection, "GET", long_target, base)
    assert status == 414 and b"rewritten_request_target_too_large" in body
    status, headers, body = request(connection, "GET", "/bounded?ok=h1", base)
    assert status == 200 and headers["x-upstream-id"] == "stable"
    assert record(body)["upstream"] == "stable"

    status, headers, body = request(connection, "GET", "/direct", base)
    assert status == 200 and headers["x-upstream-id"] == "stable"
    assert record(body)["path"] == "/direct"
    connection.close()

    print(
        json.dumps(
            {
                "http1_auth_and_preflight_do_not_advance": "passed",
                "http1_expected_sequence": expected,
                "http1_observed_sequence": observed,
                "http1_retry_pinned_to_stable": "passed",
                "http1_rewrite_limit_does_not_advance": "passed",
                "http1_untouched_direct_route": "passed",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
