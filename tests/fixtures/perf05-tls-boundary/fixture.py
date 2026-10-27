#!/usr/bin/env python3
"""Deterministic PERF-05 TLS response-boundary fixture and client."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import socket
import ssl
import sys
import time
import urllib.request
from typing import Any


PAYLOAD_BYTES = (15 * 1024, 16 * 1024, 17 * 1024, 64 * 1024)
HOSTNAME = "api.example.test"
GATEWAY_PORT = 8443
UPSTREAM_CONNECTIONS_PER_SHARD = 8
UPSTREAM_PENDING_REQUESTS_PER_SHARD = 64
DOWNSTREAM_CONNECTIONS_PER_SHARD = 64
METRIC_PREFIX = "bonvoyage_bonvoyage_gateway_"
ACTIVE_METRICS = (
    "active_requests",
    "active_route_requests",
    "active_upstream_requests",
    "active_upstream_http1_requests",
    "active_http2_streams",
)


class FixtureError(RuntimeError):
    """Raised when a fixture observation violates the frozen contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FixtureError(message)


def build_config() -> dict[str, Any]:
    routes: list[dict[str, Any]] = []
    for size in PAYLOAD_BYTES:
        routes.append(
            {
                "name": f"fixed-{size}",
                "match": {"path_exact": f"/perf05/fixed/{size}", "methods": ["GET"]},
                "fixed_response": {
                    "status_code": 200,
                    "body": "x" * size,
                    "content_type": "application/octet-stream",
                },
            }
        )
        routes.append(
            {
                "name": f"proxied-{size}",
                "match": {"path_exact": f"/perf05/proxied/{size}", "methods": ["GET"]},
                "cluster": "controlled-upstream",
                "rewrite": {"path": f"/payload/{size}"},
            }
        )

    return {
        "server": {
            "node_id": "phase5-tls-boundary-node",
            "admin_addr": "0.0.0.0:9901",
            "metrics_addr": "0.0.0.0:9090",
        },
        "snapshot": {
            "schema_version": 1,
            "snapshot_id": "phase5-tls-boundary-local-preflight",
            "generation": 1,
            "minimum_dataplane_version": "0.2.0",
        },
        "listeners": [
            {
                "name": "tls-http1",
                "address": "0.0.0.0",
                "port": GATEWAY_PORT,
                "protocol": "http1",
                "virtual_hosts": ["boundary-api"],
                "downstream_tls": {
                    "certificate_chain_secret": "server-chain.pem",
                    "private_key_secret": "server-key.pem",
                },
            }
        ],
        "virtual_hosts": [
            {
                "name": "boundary-api",
                "domains": [HOSTNAME],
                "routes": routes,
            }
        ],
        "clusters": [
            {
                "name": "controlled-upstream",
                "load_balancing_policy": "round_robin",
                "connect_timeout_ms": 200,
                "max_connections_per_shard": UPSTREAM_CONNECTIONS_PER_SHARD,
                "max_pending_requests_per_shard": (
                    UPSTREAM_PENDING_REQUESTS_PER_SHARD
                ),
                "endpoints": [
                    {
                        "name": "controlled-upstream",
                        "address": "upstream",
                        "port": 8081,
                        "weight": 1,
                    }
                ],
            }
        ],
        "runtime_limits": {
            "max_downstream_connections_per_shard": DOWNSTREAM_CONNECTIONS_PER_SHARD,
            "max_request_header_bytes": 32768,
            "max_request_body_bytes": 1048576,
            "max_upstream_response_header_bytes": 32768,
            "max_upstream_chunk_metadata_bytes": 32768,
            "request_timeout_ms": 2000,
            "downstream_idle_timeout_ms": 3000,
        },
    }


def tls_context(ca_path: str | None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=ca_path)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.set_alpn_protocols(["http/1.1"])
    return context


def transport_observation(stream: ssl.SSLSocket) -> dict[str, Any]:
    cipher = stream.cipher()
    require(cipher is not None, "TLS cipher was not reported")
    certificate = stream.getpeercert()
    sans = sorted(
        value
        for kind, value in certificate.get("subjectAltName", ())
        if kind == "DNS"
    )
    result = {
        "tls_version": stream.version(),
        "cipher": cipher[0],
        "alpn": stream.selected_alpn_protocol(),
        "peer_dns_names": sans,
        "ca_verified": True,
        "hostname_verified": True,
    }
    validate_transport(result)
    return result


def validate_transport(observation: dict[str, Any]) -> None:
    cipher = str(observation.get("cipher", ""))
    require(observation.get("tls_version") == "TLSv1.3", "TLS 1.3 was not negotiated")
    require(cipher.startswith("TLS_AES_"), f"non-AES TLS cipher negotiated: {cipher}")
    require("CHACHA" not in cipher.upper(), f"ChaCha cipher negotiated: {cipher}")
    require(observation.get("alpn") == "http/1.1", "HTTP/1.1 ALPN was not negotiated")
    require(HOSTNAME in observation.get("peer_dns_names", []), "expected certificate SAN is absent")
    require(observation.get("ca_verified") is True, "CA verification was not observed")
    require(observation.get("hostname_verified") is True, "hostname verification was not observed")


def validate_response(
    mode: str,
    size: int,
    status: int,
    headers: list[tuple[str, str]],
    body: bytes,
) -> dict[str, Any]:
    normalized: dict[str, list[str]] = {}
    for name, value in headers:
        normalized.setdefault(name.lower(), []).append(value)

    require(status == 200, f"{mode}/{size} returned HTTP {status}")
    require(body == b"x" * size, f"{mode}/{size} payload bytes differ")
    require(
        normalized.get("content-length") == [str(size)],
        f"{mode}/{size} Content-Length is not exact",
    )
    require(
        normalized.get("content-type") == ["application/octet-stream"],
        f"{mode}/{size} Content-Type is not exact",
    )
    upstream_marker = bool(normalized.get("x-upstream-connection"))
    require(
        upstream_marker == (mode == "proxied"),
        f"{mode}/{size} route action marker is incorrect",
    )
    return {
        "status": status,
        "content_length": size,
        "content_type": normalized["content-type"][0],
        "payload_sha256": hashlib.sha256(body).hexdigest(),
        "upstream_marker_present": upstream_marker,
    }


def request_case(
    host: str,
    port: int,
    ca_path: str,
    mode: str,
    size: int,
    connect_address: str | None = None,
) -> dict[str, Any]:
    connection = http.client.HTTPConnection(host, port, timeout=5)
    try:
        raw = socket.create_connection((connect_address or host, port), timeout=5)
        connection.sock = tls_context(ca_path).wrap_socket(raw, server_hostname=host)
        require(isinstance(connection.sock, ssl.SSLSocket), "client socket is not TLS")
        transport = transport_observation(connection.sock)
        path = f"/perf05/{mode}/{size}"
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read(size + 1)
        result = validate_response(mode, size, response.status, response.getheaders(), body)
        result.update(
            {
                "mode": mode,
                "payload_bytes": size,
                "path": path,
                "transport": transport,
            }
        )
        return result
    finally:
        connection.close()


def expect_tls_rejection(
    host: str,
    port: int,
    context: ssl.SSLContext,
    connect_address: str | None = None,
) -> str:
    try:
        with socket.create_connection((connect_address or host, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError as error:
        return str(error.verify_message)
    raise FixtureError(f"TLS trust probe unexpectedly accepted {host}")


def fetch_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=2) as response:
        require(response.status == 200, f"{url} returned HTTP {response.status}")
        return response.read(4 * 1024 * 1024).decode("ascii")


def parse_metrics(text: str) -> dict[str, float]:
    found: dict[str, float] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or not fields[0].startswith(METRIC_PREFIX):
            continue
        name = fields[0][len(METRIC_PREFIX) :].split("{", 1)[0]
        if name in ACTIVE_METRICS:
            found[name] = found.get(name, 0.0) + float(fields[1])
    for name in ACTIVE_METRICS:
        require(name in found, f"gateway metric is missing: {name}")
    return found


def wait_for_drain(metrics_url: str) -> tuple[dict[str, float], float]:
    started = time.monotonic()
    deadline = started + 2.0
    while True:
        metrics = parse_metrics(fetch_text(metrics_url))
        if all(metrics[name] == 0 for name in ACTIVE_METRICS):
            return metrics, (time.monotonic() - started) * 1000
        if time.monotonic() >= deadline:
            raise FixtureError("gateway work did not drain within two seconds")
        time.sleep(0.02)


def run_client(host: str, port: int, ca_path: str, metrics_url: str) -> dict[str, Any]:
    cases = [
        request_case(host, port, ca_path, mode, size)
        for mode in ("fixed", "proxied")
        for size in PAYLOAD_BYTES
    ]

    hostname_context = tls_context(ca_path)
    wrong_hostname_rejection = expect_tls_rejection("gateway", port, hostname_context)
    untrusted_context = tls_context(None)
    untrusted_ca_rejection = expect_tls_rejection(host, port, untrusted_context)
    final_metrics, drain_ms = wait_for_drain(metrics_url)

    return {
        "schema_version": 1,
        "profile": "P5-T01",
        "status": "pass",
        "cases": cases,
        "negative_probes": {
            "wrong_hostname_rejected": True,
            "wrong_hostname_reason": wrong_hostname_rejection,
            "untrusted_ca_rejected": True,
            "untrusted_ca_reason": untrusted_ca_rejection,
        },
        "cleanup": {
            "drain_ms": round(drain_ms, 3),
            "final_active_metrics": final_metrics,
        },
    }


def run_native_probe(
    connect_address: str,
    host: str,
    port: int,
    ca_path: str,
    mode: str,
    size: int,
) -> dict[str, Any]:
    require(mode in ("fixed", "proxied"), "native probe mode is invalid")
    require(size in PAYLOAD_BYTES, "native probe payload is outside P5-T01")
    case = request_case(host, port, ca_path, mode, size, connect_address)
    wrong_hostname = expect_tls_rejection(
        "wrong.example.test", port, tls_context(ca_path), connect_address
    )
    untrusted = expect_tls_rejection(
        host, port, tls_context(None), connect_address
    )
    return {
        "schema_version": 1,
        "profile": "P5-T01",
        "status": "pass",
        "cases": [case],
        "negative_probes": {
            "wrong_hostname_rejected": True,
            "wrong_hostname_reason": wrong_hostname,
            "untrusted_ca_rejected": True,
            "untrusted_ca_reason": untrusted,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode", choices=("render-config", "ready", "metrics", "client", "native-probe")
    )
    parser.add_argument("--url", default="http://gateway:9901/health/ready")
    parser.add_argument("--host", default=HOSTNAME)
    parser.add_argument("--port", type=int, default=GATEWAY_PORT)
    parser.add_argument("--ca", default="/secrets/ca.pem")
    parser.add_argument("--metrics-url", default="http://gateway:9090/metrics")
    parser.add_argument("--connect-address")
    parser.add_argument("--case-mode", choices=("fixed", "proxied"))
    parser.add_argument("--payload-bytes", type=int)
    arguments = parser.parse_args()

    if arguments.mode == "render-config":
        json.dump(build_config(), sys.stdout, sort_keys=True, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    if arguments.mode == "ready":
        sys.stdout.write(fetch_text(arguments.url))
        return 0
    if arguments.mode == "metrics":
        sys.stdout.write(fetch_text(arguments.url))
        return 0

    if arguments.mode == "native-probe":
        require(arguments.connect_address is not None, "--connect-address is required")
        require(arguments.case_mode is not None, "--case-mode is required")
        require(arguments.payload_bytes is not None, "--payload-bytes is required")
        value = run_native_probe(
            arguments.connect_address,
            arguments.host,
            arguments.port,
            arguments.ca,
            arguments.case_mode,
            arguments.payload_bytes,
        )
        json.dump(value, sys.stdout, sort_keys=True, indent=2)
        sys.stdout.write("\n")
        return 0

    json.dump(
        run_client(arguments.host, arguments.port, arguments.ca, arguments.metrics_url),
        sys.stdout,
        sort_keys=True,
        indent=2,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FixtureError, OSError, ValueError) as error:
        print(f"PERF-05 TLS boundary fixture: {error}", file=sys.stderr)
        raise SystemExit(1) from error
