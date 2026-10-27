#!/usr/bin/env python3
"""Protocol clients used inside the controlled upstream for JWT smoke checks."""

from __future__ import annotations

import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request


HOST = sys.argv[2]
MODE = sys.argv[1]
TOKENS_PATH = "/tls/jwt-tokens.json"


def load_tokens() -> dict[str, str]:
    with open(TOKENS_PATH, encoding="ascii") as source:
        return json.load(source)


def error_code(body: bytes) -> str:
    return json.loads(body)["error"]["code"]


def http1() -> dict[str, object]:
    tokens = load_tokens()

    def request(path: str, token: str | None = None,
                extra: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        headers = {"Host": "api.example.test"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        headers.update(extra or {})
        configured = urllib.request.Request(f"http://{HOST}:8080{path}", headers=headers)
        try:
            with urllib.request.urlopen(configured, timeout=5) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as failure:
            return failure.code, dict(failure.headers), failure.read()

    def repeated(path: str, first: str, second: str) -> tuple[int, dict[str, str], bytes]:
        lines = [
            f"GET {path} HTTP/1.1",
            "Host: api.example.test",
            f"Authorization: Bearer {first}",
            f"Authorization: Bearer {second}",
            "Connection: close",
            "",
            "",
        ]
        with socket.create_connection((HOST, 8080), timeout=5) as stream:
            stream.sendall("\r\n".join(lines).encode("ascii"))
            response = bytearray()
            while chunk := stream.recv(65536):
                response.extend(chunk)
        head, body = bytes(response).split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        status = int(lines[0].split()[1])
        headers = {}
        for line in lines[1:]:
            name, value = line.split(b":", 1)
            headers[name.decode("ascii").lower()] = value.strip().decode("ascii")
        return status, headers, body

    status, _, body = request("/public")
    assert status == 200 and body == b"public ready\n"

    invalid_names = [
        "bad_signature", "wrong_issuer", "wrong_audience", "wrong_type",
        "expired", "future_iat", "future_nbf", "excessive_lifetime",
        "unknown_kid", "remote_jku", "remote_x5u", "embedded_jwk",
        "embedded_nul", "duplicate_header", "duplicate_payload",
        "none_algorithm",
    ]
    invalid_responses: list[bytes] = []
    status, headers, body = request("/protected-fixed")
    assert status == 401 and headers["WWW-Authenticate"] == "Bearer"
    invalid_responses.append(body)
    for name in invalid_names:
        status, headers, body = request("/protected-fixed", tokens[name])
        assert status == 401 and headers["WWW-Authenticate"] == "Bearer", name
        invalid_responses.append(body)
    status, headers, body = repeated(
        "/protected-fixed", tokens["valid"], tokens["valid"]
    )
    assert status == 401 and headers["www-authenticate"] == "Bearer"
    invalid_responses.append(body)
    assert len(set(invalid_responses)) == 1
    assert error_code(invalid_responses[0]) == "unauthorized"

    status, _, body = request("/protected-fixed", tokens["valid"])
    assert status == 200 and body == b"protected ready\n"

    authorization_responses: list[bytes] = []
    for name in ("missing_scope", "wrong_scope", "wrong_claim"):
        status, headers, body = request("/protected-fixed", tokens[name])
        assert status == 403, name
        assert headers["WWW-Authenticate"] == 'Bearer error="insufficient_scope"'
        authorization_responses.append(body)
    assert len(set(authorization_responses)) == 1
    assert error_code(authorization_responses[0]) == "forbidden"

    status, _, body = request(
        "/jwt-observation", tokens["valid"], {"X-Request-ID": "http1-preserved"}
    )
    assert status == 200
    observation = json.loads(body)
    assert observation == {
        "authorization_header_present": False,
        "request_id": "http1-preserved",
    }

    overload = [request("/verification-overload", tokens["bad_signature"])[0]
                for _ in range(3)]
    assert overload == [401, 401, 503], overload
    time.sleep(1.2)
    recovered = request("/verification-overload", tokens["bad_signature"])[0]
    assert recovered == 401

    return {
        "authorization_header_forwarded": observation["authorization_header_present"],
        "authorization_rejections": 3,
        "invalid_token_rejections": len(invalid_responses) + 3,
        "public_route_without_token": True,
        "repeated_field_rejected": True,
        "request_id_preserved": True,
        "verification_budget_recovered_without_restart": True,
        "verification_overload_rejections": 1,
        "valid_tokens_accepted": 2,
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
    tokens = load_tokens()

    def bearer(name: str) -> list[tuple[str, str]]:
        return [("authorization", "Bearer " + tokens[name])]

    assert http2_request("/public", []) == b"public ready\n"
    invalid_names = [
        "bad_signature", "wrong_issuer", "wrong_audience", "wrong_type",
        "expired", "future_iat", "future_nbf", "excessive_lifetime",
        "unknown_kid", "remote_jku", "remote_x5u", "embedded_jwk",
        "embedded_nul", "duplicate_header", "duplicate_payload",
        "none_algorithm",
    ]
    failures = [http2_request("/protected-fixed", [])]
    failures.extend(
        http2_request("/protected-fixed", bearer(name)) for name in invalid_names
    )
    failures.append(
        http2_request(
            "/protected-fixed",
            bearer("valid") + bearer("valid"),
        )
    )
    assert len(set(failures)) == 1
    assert error_code(failures[0]) == "unauthorized"
    assert http2_request(
        "/protected-fixed", bearer("valid")
    ) == b"protected ready\n"

    forbidden = [
        http2_request("/protected-fixed", bearer(name))
        for name in ("missing_scope", "wrong_scope", "wrong_claim")
    ]
    assert len(set(forbidden)) == 1
    assert error_code(forbidden[0]) == "forbidden"

    observation = json.loads(
        http2_request(
            "/jwt-observation",
            bearer("valid") + [("x-request-id", "http2-preserved")],
        )
    )
    assert observation == {
        "authorization_header_present": False,
        "request_id": "http2-preserved",
    }
    return {
        "authorization_header_forwarded": observation["authorization_header_present"],
        "authorization_rejections": 3,
        "invalid_token_rejections": len(failures),
        "public_route_without_token": True,
        "repeated_field_rejected": True,
        "request_id_preserved": True,
        "valid_tokens_accepted": 2,
    }


if MODE == "http1":
    print(json.dumps(http1(), indent=2, sort_keys=True))
elif MODE == "http2":
    print(json.dumps(http2(), indent=2, sort_keys=True))
else:
    raise SystemExit(f"unsupported mode: {MODE}")
