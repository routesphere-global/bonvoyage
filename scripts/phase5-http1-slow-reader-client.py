#!/usr/bin/env python3
"""Exercise bounded HTTP/1 response cancellation without reading the body."""

import argparse
import http.client
import json
import socket
import ssl
import time
import urllib.request


METRIC_PREFIX = "bonvoyage_bonvoyage_gateway_"
GAUGES = (
    "active_requests",
    "active_route_requests",
    "active_upstream_requests",
    "active_connections",
)


def metrics(url):
    totals = {}
    with urllib.request.urlopen(url, timeout=2) as response:
        payload = response.read().decode("ascii")
    for line in payload.splitlines():
        if not line.startswith(METRIC_PREFIX) or line.startswith("#"):
            continue
        field, value = line.split(None, 1)
        name = field.split("{", 1)[0][len(METRIC_PREFIX) :]
        totals[name] = totals.get(name, 0.0) + float(value)
    return totals


def selected(snapshot):
    names = GAUGES + ("request_timeouts_total",)
    return {name: snapshot.get(name, 0.0) for name in names}


def wait_for(url, predicate, timeout):
    deadline = time.monotonic() + timeout
    last = {}
    while time.monotonic() < deadline:
        last = metrics(url)
        if predicate(last):
            return last
        time.sleep(0.025)
    return last


def connect(protocol, address, ca_path):
    host, port_text = address.rsplit(":", 1)
    raw = socket.create_connection((host, int(port_text)), timeout=2)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    if protocol == "plain":
        return raw
    context = ssl.create_default_context(cafile=ca_path)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    return context.wrap_socket(raw, server_hostname="api.example.test")


def request(protocol, address, ca_path, path):
    connection = connect(protocol, address, ca_path)
    try:
        connection.sendall(
            f"GET {path} HTTP/1.1\r\n".encode("ascii")
            + b"Host: api.example.test\r\n"
            b"Connection: close\r\n\r\n"
        )
        response = http.client.HTTPResponse(connection)
        response.begin()
        body = response.read()
        return response.status, body.decode("ascii", "replace")
    finally:
        connection.close()


def stalled_body(protocol, address, ca_path, metrics_url):
    before = metrics(metrics_url)
    peer = connect(protocol, address, ca_path)
    peer.sendall(
        b"POST /stalled-body HTTP/1.1\r\n"
        b"Host: api.example.test\r\n"
        b"Content-Length: 524288\r\n"
        b"Connection: close\r\n\r\n"
    )
    active = wait_for(
        metrics_url,
        lambda value: value.get("active_requests", 0) >= 1
        and value.get("active_connections", 0) >= 1,
        2.0,
    )
    released = wait_for(
        metrics_url,
        lambda value: value.get("request_timeouts_total", 0)
        >= before.get("request_timeouts_total", 0) + 1
        and all(value.get(name, 0) == 0 for name in GAUGES),
        2.0,
    )
    peer.close()
    return {
        "pass": (
            active.get("active_requests", 0) >= 1
            and active.get("active_connections", 0) >= 1
            and released.get("request_timeouts_total", 0)
            >= before.get("request_timeouts_total", 0) + 1
            and all(released.get(name, 0) == 0 for name in GAUGES)
        ),
        "before": selected(before),
        "active": selected(active),
        "released": selected(released),
    }


def run_case(args):
    before = metrics(args.metrics)
    peer = connect(args.protocol, args.address, args.ca)
    peer.settimeout(2)
    peer.sendall(
        b"GET /stream-payload/33554432 HTTP/1.1\r\n"
        b"Host: api.example.test\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )

    active = wait_for(
        args.metrics,
        lambda value: value.get("active_route_requests", 0) >= 1
        and value.get("active_upstream_requests", 0) >= 1,
        2.0,
    )
    observed_active = (
        active.get("active_route_requests", 0) >= 1
        and active.get("active_upstream_requests", 0) >= 1
    )
    released = wait_for(
        args.metrics,
        lambda value: value.get("request_timeouts_total", 0)
        >= before.get("request_timeouts_total", 0) + 1
        and all(value.get(name, 0) == 0 for name in GAUGES),
        args.release_timeout,
    )
    released_while_peer_open = (
        released.get("request_timeouts_total", 0)
        >= before.get("request_timeouts_total", 0) + 1
        and all(released.get(name, 0) == 0 for name in GAUGES)
    )

    peer.close()
    after_close = wait_for(
        args.metrics,
        lambda value: all(value.get(name, 0) == 0 for name in GAUGES),
        2.0,
    )
    stalled_body_result = stalled_body(
        args.protocol, args.address, args.ca, args.metrics
    )
    before_timeout = metrics(args.metrics)
    timeout_status, timeout_body = request(
        args.protocol, args.address, args.ca, "/slow/1000"
    )
    try:
        timeout_code = json.loads(timeout_body)["error"]["code"]
    except (json.JSONDecodeError, KeyError, TypeError):
        timeout_code = ""
    timeout_contract = timeout_status == 504 and timeout_code == "request_timeout"
    after_timeout = wait_for(
        args.metrics,
        lambda value: value.get("request_timeouts_total", 0)
        >= before_timeout.get("request_timeouts_total", 0) + 1
        and all(value.get(name, 0) == 0 for name in GAUGES),
        2.0,
    )
    timeout_released = (
        after_timeout.get("request_timeouts_total", 0)
        >= before_timeout.get("request_timeouts_total", 0) + 1
        and all(after_timeout.get(name, 0) == 0 for name in GAUGES)
    )
    status, body = request(args.protocol, args.address, args.ca, "/healthz")
    final = wait_for(
        args.metrics,
        lambda value: all(value.get(name, 0) == 0 for name in GAUGES),
        2.0,
    )
    recovered = status == 200 and body == "ok\n"
    drained = all(final.get(name, 0) == 0 for name in GAUGES)
    passed = (
        observed_active
        and released_while_peer_open
        and stalled_body_result["pass"]
        and timeout_contract
        and timeout_released
        and recovered
        and drained
    )
    return {
        "protocol": args.protocol,
        "pass": passed,
        "observed_active": observed_active,
        "released_while_peer_open": released_while_peer_open,
        "stalled_body": stalled_body_result,
        "timeout_response_status": timeout_status,
        "timeout_response_code": timeout_code,
        "timeout_response_contract": timeout_contract,
        "timeout_response_released": timeout_released,
        "recovery_status": status,
        "recovery_body": body,
        "drained": drained,
        "before": selected(before),
        "active": selected(active),
        "release_observation": selected(released),
        "after_peer_close": selected(after_close),
        "after_timeout_response": selected(after_timeout),
        "final": selected(final),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", choices=("plain", "tls"), required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--metrics", default="http://gateway:9090/metrics")
    parser.add_argument("--ca", default="/secrets/server-chain.pem")
    parser.add_argument("--release-timeout", type=float, default=2.0)
    args = parser.parse_args()
    result = run_case(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
