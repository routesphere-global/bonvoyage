#!/usr/bin/env python3
"""HTTP/1.1 assertions for the bounded route-rewrite checkpoint."""

from __future__ import annotations

import http.client
import json
import sys
from typing import Any


def request(
    connection: http.client.HTTPConnection,
    path: str,
    headers: dict[str, str],
) -> tuple[int, dict[str, str], bytes]:
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    body = response.read()
    return (
        response.status,
        {name.lower(): value for name, value in response.getheaders()},
        body,
    )


def record(body: bytes) -> dict[str, Any]:
    return json.loads(body)


def assert_forwarding(
    value: dict[str, Any],
    expected_host: str,
    expected_path: str,
    forwarded_host: str | None,
) -> None:
    headers = value["headers"]
    assert value["path"] == expected_path, value
    assert headers["host"] == expected_host, value
    assert headers["x-forwarded-proto"] == "http", value
    assert "x-forwarded-for" in headers, value
    assert headers["x-client-protocol"] == "h1", value
    assert "x-api-key" not in headers, value
    if forwarded_host is None:
        assert "x-forwarded-host" not in headers, value
    else:
        assert headers["x-forwarded-host"] == forwarded_host, value


def main() -> None:
    host, api_key = sys.argv[1:3]
    common = {
        "Host": "api.example.test",
        "X-Client-Protocol": "h1",
        "X-Forwarded-Host": "spoofed.example",
    }
    connection = http.client.HTTPConnection(host, 8080, timeout=5)

    authorized = dict(common)
    authorized["X-API-Key"] = api_key
    authorized["Origin"] = "https://app.example.com"
    status, headers, body = request(
        connection,
        "/legacy/orders/%7Eopen?cursor=a%2Fb",
        authorized,
    )
    assert status == 200
    assert headers["access-control-allow-origin"] == "https://app.example.com"
    rewritten = record(body)
    assert_forwarding(
        rewritten,
        "orders.internal.test:9443",
        "/v2/orders/%7Eopen?cursor=a%2Fb",
        "api.example.test",
    )
    assert rewritten["headers"]["x-route-tier"] == "gold"

    status, _, body = request(
        connection,
        "/legacy/orders/%7Eopen?cursor=a%2Fb",
        common,
    )
    assert status == 401 and b"unauthorized" in body

    status, _, body = request(
        connection,
        "/catalog?view=%2Fraw&empty=",
        common,
    )
    assert status == 200
    assert_forwarding(
        record(body),
        "api.example.test",
        "/internal/catalog?view=%2Fraw&empty=",
        None,
    )

    status, _, body = request(connection, "/authority?mode=raw", common)
    assert status == 200
    assert_forwarding(
        record(body),
        "authority.internal.test:8088",
        "/authority?mode=raw",
        "api.example.test",
    )

    status, _, body = request(connection, "/plain?keep=%2Fraw", common)
    assert status == 200
    assert_forwarding(
        record(body),
        "api.example.test",
        "/plain?keep=%2Fraw",
        None,
    )

    status, _, body = request(connection, "/retry?attempt=stable", common)
    assert status == 200
    assert_forwarding(
        record(body),
        "retry.internal.test",
        "/internal/retry?attempt=stable",
        "api.example.test",
    )

    limit_target = "/limit?padding=" + ("q" * 300)
    status, _, body = request(connection, limit_target, common)
    assert status == 414 and b"rewritten_request_target_too_large" in body
    connection.close()

    connection = http.client.HTTPConnection(host, 8080, timeout=5)
    status, _, body = request(connection, "/plain?after=limit", common)
    assert status == 200
    assert_forwarding(
        record(body),
        "api.example.test",
        "/plain?after=limit",
        None,
    )
    connection.close()

    print(
        json.dumps(
            {
                "http1_auth_before_rewrite": "passed",
                "http1_authority_rewrite": "passed",
                "http1_full_path_and_raw_query": "passed",
                "http1_prefix_suffix_and_raw_query": "passed",
                "http1_retry_determinism": "passed",
                "http1_rewritten_target_limit_414": "passed",
                "http1_untouched_route": "passed",
                "http1_post_rejection_recovery": "passed",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
