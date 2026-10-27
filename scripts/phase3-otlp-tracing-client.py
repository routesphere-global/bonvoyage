#!/usr/bin/env python3
"""Deterministic HTTP/1 workload for the Phase 3 OTLP isolation gate."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import socket
import urllib.request


HOST = "api.example.test"
REMOTE_TRACEPARENT = "00-11111111111111111111111111111111-2222222222222222-01"


def request(url: str, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    combined = {"Host": HOST}
    combined.update(headers or {})
    with urllib.request.urlopen(
        urllib.request.Request(url, headers=combined), timeout=10
    ) as response:
        return response.status, response.read()


def run_failure_load(gateway: str, count: int) -> dict[str, object]:
    def one(index: int) -> int:
        status, body = request(f"http://{gateway}:8080/failure/{index}")
        assert status == 200 and body
        return status

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        statuses = list(executor.map(one, range(count)))
    return {
        "requests": len(statuses),
        "status_counts": {"200": statuses.count(200)},
    }


def run_recovery(gateway: str) -> dict[str, object]:
    synthetic_private_headers = {
        "Authorization": "Bearer private-auth-do-not-export",
        "Baggage": "private-baggage-do-not-export=value",
        "Cookie": "session=private-cookie-do-not-export",
        "Traceparent": REMOTE_TRACEPARENT,
        "Tracestate": "vendor=trace-state-do-not-export",
        "X-Private-Header": "private-header-do-not-export",
    }
    valid_status, _ = request(
        f"http://{gateway}:8080/private-path-do-not-export"
        "?token=private-query-do-not-export",
        synthetic_private_headers,
    )
    invalid_status, _ = request(
        f"http://{gateway}:8080/invalid-context",
        {"Traceparent": "not-a-valid-traceparent"},
    )

    padding = "x" * 900
    wire_request = (
        "GET /propagation-limit HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"X-Padding: {padding}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    with socket.create_connection((gateway, 8080), timeout=10) as connection:
        connection.sendall(wire_request)
        response = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    status_line = bytes(response).split(b"\r\n", 1)[0].decode("ascii")
    assert status_line.startswith("HTTP/1.1 431 "), status_line

    recovery_status, _ = request(
        f"http://{gateway}:8080/post-limit-recovery"
    )
    assert {valid_status, invalid_status, recovery_status} == {200}
    return {
        "invalid_traceparent_status": invalid_status,
        "post_limit_recovery_status": recovery_status,
        "propagation_limit_status": 431,
        "remote_traceparent": REMOTE_TRACEPARENT,
        "valid_remote_parent_status": valid_status,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("failure", "recovery"))
    parser.add_argument("gateway")
    parser.add_argument("--count", type=int, default=64)
    arguments = parser.parse_args()
    if arguments.mode == "failure":
        result = run_failure_load(arguments.gateway, arguments.count)
    else:
        result = run_recovery(arguments.gateway)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
