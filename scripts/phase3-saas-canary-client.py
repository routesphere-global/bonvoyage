#!/usr/bin/env python3
"""Dependency-free client for the bounded SaaS canary profile."""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import http.client
import json
import math
import socket
import threading
import time
from pathlib import Path
from typing import Any


def read_key(path: str) -> str:
    value = Path(path).read_text(encoding="ascii").strip()
    if not value or "\n" in value or "\r" in value:
        raise ValueError(f"credential file must contain exactly one key: {path}")
    return value


def request(
    gateway: str,
    authority: str,
    path: str,
    key: str | None,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    headers = {"Host": authority, "Connection": "close"}
    if key is not None:
        headers["X-API-Key"] = key
    headers.update(extra_headers or {})
    connection = http.client.HTTPConnection(gateway, 8080, timeout=10)
    started = time.perf_counter()
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read(4096)
        response_headers = {
            name.lower(): value for name, value in response.getheaders()
        }
        return {
            "status": response.status,
            "upstream": response_headers.get("x-upstream-id", ""),
            "body_bytes_observed": len(body),
            "latency_ms": (time.perf_counter() - started) * 1000,
        }
    finally:
        connection.close()


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * fraction) - 1)
    return round(ordered[index], 3)


def run_batch(arguments: argparse.Namespace) -> None:
    key = read_key(arguments.key_file) if arguments.key_file else None
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    lock = threading.Lock()
    started = time.monotonic()

    def execute(_: int) -> None:
        try:
            result = request(
                arguments.gateway,
                arguments.authority,
                arguments.path,
                key,
            )
            with lock:
                results.append(result)
        except Exception as error:  # noqa: BLE001 - evidence retains the class.
            with lock:
                errors.append(f"{type(error).__name__}: {error}")

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=arguments.concurrency
    ) as executor:
        list(executor.map(execute, range(arguments.count)))

    latencies = [float(item["latency_ms"]) for item in results]
    print(
        json.dumps(
            {
                "mode": "batch",
                "authority_profile": arguments.profile,
                "path_profile": arguments.path_profile,
                "requested": arguments.count,
                "completed": len(results),
                "duration_seconds": round(time.monotonic() - started, 3),
                "statuses": collections.Counter(
                    str(item["status"]) for item in results
                ),
                "upstreams": collections.Counter(
                    item["upstream"] for item in results if item["upstream"]
                ),
                "latency_ms": {
                    "p50": percentile(latencies, 0.50),
                    "p95": percentile(latencies, 0.95),
                    "p99": percentile(latencies, 0.99),
                    "max": round(max(latencies, default=0.0), 3),
                },
                "errors": collections.Counter(errors),
            },
            indent=2,
            sort_keys=True,
        )
    )


def run_isolation(arguments: argparse.Namespace) -> None:
    tenant_a_key = read_key(arguments.tenant_a_key_file)
    tenant_b_key = read_key(arguments.tenant_b_key_file)
    cases = (
        ("tenant_a_valid", arguments.tenant_a_authority, tenant_a_key),
        ("tenant_b_valid", arguments.tenant_b_authority, tenant_b_key),
        ("tenant_a_missing_key", arguments.tenant_a_authority, None),
        ("tenant_b_missing_key", arguments.tenant_b_authority, None),
        ("tenant_a_with_tenant_b_key", arguments.tenant_a_authority, tenant_b_key),
        ("tenant_b_with_tenant_a_key", arguments.tenant_b_authority, tenant_a_key),
    )
    output: dict[str, dict[str, Any]] = {}
    for name, authority, key in cases:
        result = request(arguments.gateway, authority, "/v1/data", key)
        output[name] = {
            "status": result["status"],
            "upstream_profile": result["upstream"],
        }
    print(json.dumps(output, indent=2, sort_keys=True))


def run_privacy(arguments: argparse.Namespace) -> None:
    result = request(
        arguments.gateway,
        arguments.authority,
        "/privacy-path-marker-bv-saas?customer=privacy-query-marker-bv-saas",
        None,
        {
            "Authorization": "Bearer privacy-bearer-marker-bv-saas",
            "Cookie": "session=privacy-cookie-marker-bv-saas",
            "X-Forwarded-For": "203.0.113.219",
            "X-Privacy-Marker": "privacy-header-marker-bv-saas",
            "X-Tenant-ID": "privacy-tenant-marker-bv-saas",
        },
    )
    print(
        json.dumps(
            {
                "expected_local_rejection": result["status"] == 404,
                "status": result["status"],
                "upstream_selected": bool(result["upstream"]),
            },
            indent=2,
            sort_keys=True,
        )
    )


def run_slow_metrics(arguments: argparse.Namespace) -> None:
    barrier = threading.Barrier(arguments.connections)
    established = 0
    errors: list[str] = []
    lock = threading.Lock()

    def consume(_: int) -> None:
        nonlocal established
        stream: socket.socket | None = None
        try:
            stream = socket.create_connection(
                (arguments.gateway, 9090), timeout=5
            )
            stream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            stream.sendall(
                b"GET /metrics HTTP/1.1\r\n"
                + f"Host: {arguments.gateway}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
            )
            with lock:
                established += 1
            barrier.wait(timeout=5)
            time.sleep(arguments.hold_seconds)
        except Exception as error:  # noqa: BLE001 - evidence retains the class.
            with lock:
                errors.append(f"{type(error).__name__}: {error}")
        finally:
            if stream is not None:
                stream.close()

    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=arguments.connections
    ) as executor:
        list(executor.map(consume, range(arguments.connections)))
    print(
        json.dumps(
            {
                "mode": "slow_metrics_consumers",
                "requested_connections": arguments.connections,
                "established_connections": established,
                "hold_seconds": arguments.hold_seconds,
                "duration_seconds": round(time.monotonic() - started, 3),
                "bytes_read_per_connection": 0,
                "errors": collections.Counter(errors),
            },
            indent=2,
            sort_keys=True,
        )
    )


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    subparsers = root.add_subparsers(dest="command", required=True)

    batch = subparsers.add_parser("batch")
    batch.add_argument("--gateway", required=True)
    batch.add_argument("--authority", required=True)
    batch.add_argument("--path", required=True)
    batch.add_argument("--key-file")
    batch.add_argument("--count", type=positive_integer, required=True)
    batch.add_argument("--concurrency", type=positive_integer, required=True)
    batch.add_argument("--profile", required=True)
    batch.add_argument("--path-profile", required=True)
    batch.set_defaults(function=run_batch)

    isolation = subparsers.add_parser("isolation")
    isolation.add_argument("--gateway", required=True)
    isolation.add_argument("--tenant-a-authority", required=True)
    isolation.add_argument("--tenant-b-authority", required=True)
    isolation.add_argument("--tenant-a-key-file", required=True)
    isolation.add_argument("--tenant-b-key-file", required=True)
    isolation.set_defaults(function=run_isolation)

    privacy = subparsers.add_parser("privacy")
    privacy.add_argument("--gateway", required=True)
    privacy.add_argument("--authority", required=True)
    privacy.set_defaults(function=run_privacy)

    slow_metrics = subparsers.add_parser("slow-metrics")
    slow_metrics.add_argument("--gateway", required=True)
    slow_metrics.add_argument(
        "--connections", type=positive_integer, required=True
    )
    slow_metrics.add_argument(
        "--hold-seconds", type=positive_integer, required=True
    )
    slow_metrics.set_defaults(function=run_slow_metrics)
    return root


if __name__ == "__main__":
    parsed = parser().parse_args()
    parsed.function(parsed)
