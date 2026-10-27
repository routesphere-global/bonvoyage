#!/usr/bin/env python3
"""Protocol clients used inside the controlled source-policy smoke network."""

from __future__ import annotations

import json
import socket
import ssl
import sys
import urllib.error
import urllib.request


MODE = sys.argv[1]
HOST = sys.argv[2]
KEY_PATH = "/tls/phase3-source-api-keys.txt"


def error_code(body: bytes) -> str:
    return json.loads(body)["error"]["code"]


def http1() -> dict[str, object]:
    with open(KEY_PATH, encoding="ascii") as source:
        api_key = source.read().strip()

    def request(
        port: int,
        path: str,
        forwarded_for: str | None = None,
        key: str | None = None,
        request_id: str | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        headers = {"Host": "api.example.test"}
        if forwarded_for is not None:
            headers["X-Forwarded-For"] = forwarded_for
        if key is not None:
            headers["X-API-Key"] = key
        if request_id is not None:
            headers["X-Request-ID"] = request_id
        configured = urllib.request.Request(
            f"http://{HOST}:{port}{path}", headers=headers
        )
        try:
            with urllib.request.urlopen(configured, timeout=5) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as failure:
            return failure.code, dict(failure.headers), failure.read()

    status, _, body = request(8080, "/fixed", "198.51.100.10")
    assert status == 403 and error_code(body) == "source_ip_denied"

    status, _, body = request(8081, "/fixed", "198.51.100.10")
    assert status == 200 and body == b"source allowed\n"
    for address in ("198.51.100.200", "203.0.113.10"):
        status, _, body = request(8081, "/fixed", address)
        assert status == 403 and error_code(body) == "source_ip_denied"

    status, _, body = request(8081, "/api-key-observation", "198.51.100.200")
    assert status == 403 and error_code(body) == "source_ip_denied"
    status, headers, body = request(
        8081, "/api-key-observation", "198.51.100.10"
    )
    assert status == 401 and headers["WWW-Authenticate"] == "ApiKey"
    assert error_code(body) == "unauthorized"
    status, _, body = request(
        8081,
        "/api-key-observation",
        "198.51.100.10",
        api_key,
        "source-http1",
    )
    assert status == 200
    observation = json.loads(body)
    assert observation == {
        "api_key_header_present": False,
        "request_id": "source-http1",
    }

    status, _, body = request(8081, "/deny-only", "203.0.113.8")
    assert status == 403 and error_code(body) == "source_ip_denied"
    status, _, body = request(8081, "/deny-only", "198.51.100.8")
    assert status == 200 and body == b"deny-only allowed\n"

    status, _, body = request(8081, "/ipv6", "2001:db8:1:beef::1")
    assert status == 200 and body == b"ipv6 allowed\n"
    for address in ("2001:db8:1:dead::1", "2001:db8:2::1"):
        status, _, body = request(8081, "/ipv6", address)
        assert status == 403 and error_code(body) == "source_ip_denied"

    status, _, body = request(8081, "/public")
    assert status == 200 and body == b"public ready\n"
    status, _, body = request(8081, "/fixed", "unknown")
    assert status == 400 and error_code(body) == "invalid_forwarded_for"

    lines = [
        "POST /fixed HTTP/1.1",
        "Host: api.example.test",
        "X-Forwarded-For: 198.51.100.200",
        "Content-Length: 4",
        "Connection: keep-alive",
        "",
        "data",
    ]
    with socket.create_connection((HOST, 8081), timeout=5) as stream:
        stream.sendall("\r\n".join(lines).encode("ascii"))
        response = bytearray()
        while chunk := stream.recv(65536):
            response.extend(chunk)
    head, body = bytes(response).split(b"\r\n\r\n", 1)
    assert int(head.split(b"\r\n", 1)[0].split()[1]) == 403
    assert b"connection: close" in head.lower()
    assert error_code(body) == "source_ip_denied"

    return {
        "allow_only_default_deny": True,
        "api_key_header_forwarded": observation["api_key_header_present"],
        "denied_before_authentication": True,
        "deny_only_default_allow": True,
        "deny_precedence": True,
        "ipv4_and_ipv6": True,
        "malformed_trusted_chain_status": 400,
        "public_route_without_policy": True,
        "rejected_body_forced_connection_close": True,
        "untrusted_forwarding_spoof_rejected": True,
    }


def integer(value: int, prefix_bits: int, first: int) -> bytes:
    maximum = (1 << prefix_bits) - 1
    if value < maximum:
        return bytes([first | value])
    output = bytearray([first | maximum])
    value -= maximum
    while value >= 128:
        output.append((value % 128) + 128)
        value //= 128
    output.append(value)
    return bytes(output)


def text(value: str) -> bytes:
    encoded = value.encode("ascii")
    return integer(len(encoded), 7, 0) + encoded


def literal(name: str, value: str) -> bytes:
    return b"\x00" + text(name) + text(value)


def literal_indexed_name(index: int, value: str) -> bytes:
    return integer(index, 4, 0) + text(value)


def frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + stream_id.to_bytes(4, "big")
        + payload
    )


def read_exact(stream: ssl.SSLSocket, amount: int) -> bytes:
    value = bytearray()
    while len(value) < amount:
        chunk = stream.recv(amount - len(value))
        if not chunk:
            raise AssertionError("HTTP/2 connection ended early")
        value.extend(chunk)
    return bytes(value)


def http2_request(path: str, headers: list[tuple[str, str]]) -> bytes:
    block = b"".join(
        (
            b"\x82",
            b"\x87",
            literal_indexed_name(4, path),
            literal_indexed_name(1, "api.example.test"),
            *(literal(name, value) for name, value in headers),
        )
    )
    context = ssl.create_default_context(cafile="/tls/ca.pem")
    context.set_alpn_protocols(["h2"])
    with socket.create_connection((HOST, 8443), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname="api.example.test") as secure:
            assert secure.selected_alpn_protocol() == "h2"
            secure.sendall(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                + frame(4, 0, 0)
                + frame(1, 5, 1, block)
            )
            body = bytearray()
            while True:
                header = read_exact(secure, 9)
                length = int.from_bytes(header[:3], "big")
                frame_type = header[3]
                flags = header[4]
                stream_id = int.from_bytes(header[5:], "big") & 0x7FFFFFFF
                payload = read_exact(secure, length)
                if frame_type == 4 and flags & 1 == 0:
                    secure.sendall(frame(4, 1, 0))
                if frame_type == 0 and stream_id == 1:
                    body.extend(payload)
                if stream_id == 1 and flags & 1:
                    return bytes(body)


def http2() -> dict[str, object]:
    with open(KEY_PATH, encoding="ascii") as source:
        api_key = source.read().strip()

    def request(path: str, address: str | None = None,
                key: str | None = None,
                request_id: str | None = None) -> bytes:
        headers: list[tuple[str, str]] = []
        if address is not None:
            headers.append(("x-forwarded-for", address))
        if key is not None:
            headers.append(("x-api-key", key))
        if request_id is not None:
            headers.append(("x-request-id", request_id))
        return http2_request(path, headers)

    assert request("/public") == b"public ready\n"
    assert request("/fixed", "198.51.100.10") == b"source allowed\n"
    for address in ("198.51.100.200", "203.0.113.10"):
        assert error_code(request("/fixed", address)) == "source_ip_denied"

    assert error_code(
        request("/api-key-observation", "198.51.100.200")
    ) == "source_ip_denied"
    assert error_code(
        request("/api-key-observation", "198.51.100.10")
    ) == "unauthorized"
    observation = json.loads(
        request(
            "/api-key-observation",
            "198.51.100.10",
            api_key,
            "source-http2",
        )
    )
    assert observation == {
        "api_key_header_present": False,
        "request_id": "source-http2",
    }

    assert error_code(request("/deny-only", "203.0.113.8")) == "source_ip_denied"
    assert request("/deny-only", "198.51.100.8") == b"deny-only allowed\n"
    assert request("/ipv6", "2001:db8:1:beef::1") == b"ipv6 allowed\n"
    for address in ("2001:db8:1:dead::1", "2001:db8:2::1"):
        assert error_code(request("/ipv6", address)) == "source_ip_denied"
    assert error_code(request("/fixed", "unknown")) == "invalid_forwarded_for"

    return {
        "allow_only_default_deny": True,
        "api_key_header_forwarded": observation["api_key_header_present"],
        "denied_before_authentication": True,
        "deny_only_default_allow": True,
        "deny_precedence": True,
        "ipv4_and_ipv6": True,
        "malformed_trusted_chain_rejected": True,
        "public_route_without_policy": True,
    }


if MODE == "http1":
    print(json.dumps(http1(), indent=2, sort_keys=True))
elif MODE == "http2":
    print(json.dumps(http2(), indent=2, sort_keys=True))
else:
    raise SystemExit(f"unsupported mode: {MODE}")
