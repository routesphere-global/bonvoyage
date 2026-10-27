import json
import os
import socket
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from time import sleep


MAX_FIXTURE_BYTES = 1024 * 1024
MAX_STREAM_FIXTURE_BYTES = 64 * 1024 * 1024
STREAM_CHUNK_BYTES = 64 * 1024
UPSTREAM_ID = os.environ.get("BONVOYAGE_UPSTREAM_ID", "upstream").strip()
RETRY_FIXTURE_LOCK = Lock()
RETRY_FIXTURE_ATTEMPTS = {}
MAX_RETRY_FIXTURE_KEYS = 256


class ControlledThreadingHTTPServer(ThreadingHTTPServer):
    # Keep the test upstream outside connection saturation during gateway
    # recovery and churn checks. The stdlib default listen backlog is only 5.
    request_queue_size = 1024
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/healthz":
            self._write_response(b"ok\n", "text/plain")
            return

        if self.path == "/identity" or self.path.startswith("/identity/"):
            self._write_response(
                (UPSTREAM_ID + "\n").encode("ascii"), "text/plain"
            )
            return

        retry_prefix = "/retry/fail-once/"
        if self.path.startswith(retry_prefix):
            key = self._retry_fixture_key(self.path[len(retry_prefix) :])
            if key is None:
                return
            attempt = self._record_retry_fixture_attempt(key)
            if attempt is None:
                return
            if attempt == 1:
                self._close_without_response()
                return
            self._write_response(
                f"attempt={attempt}\n".encode("ascii"), "text/plain"
            )
            return

        attempts_prefix = "/retry/attempts/"
        if self.path.startswith(attempts_prefix):
            key = self._retry_fixture_key(self.path[len(attempts_prefix) :])
            if key is None:
                return
            with RETRY_FIXTURE_LOCK:
                attempt = RETRY_FIXTURE_ATTEMPTS.get(key, 0)
            self._write_response(
                f"{attempt}\n".encode("ascii"), "text/plain"
            )
            return

        if self.path in (
            "/circuit-http1/always-fail",
            "/circuit-http2/always-fail",
        ):
            self._close_without_response()
            return

        for slow_prefix in (
            "/circuit-http1/slow/",
            "/endpoint-overload/slow/",
            "/cluster-overload/slow/",
        ):
            if self.path.startswith(slow_prefix):
                delay_ms = self._parse_size(self.path[len(slow_prefix) :])
                if delay_ms is None:
                    return
                if delay_ms > 5000:
                    self.send_error(400, "delay exceeds 5000 ms")
                    return
                sleep(delay_ms / 1000)
                self._write_response(
                    (UPSTREAM_ID + "\n").encode("ascii"), "text/plain"
                )
                return

        if self.path in (
            "/circuit-http1/identity",
            "/circuit-http2/identity",
            "/endpoint-overload/identity",
            "/cluster-overload/identity",
        ):
            self._write_response(
                (UPSTREAM_ID + "\n").encode("ascii"), "text/plain"
            )
            return

        slow_identity_prefix = "/slow-identity/"
        if self.path.startswith(slow_identity_prefix):
            delay_ms = self._parse_size(self.path[len(slow_identity_prefix) :])
            if delay_ms is None:
                return
            if delay_ms > 5000:
                self.send_error(400, "delay exceeds 5000 ms")
                return
            sleep(delay_ms / 1000)
            self._write_response(
                (UPSTREAM_ID + "\n").encode("ascii"), "text/plain"
            )
            return

        if self.path == "/forwarded-proto":
            value = self.headers.get("x-forwarded-proto", "").encode("ascii")
            self._write_response(value, "text/plain")
            return

        if self.path == "/client-identity":
            names = (
                "forwarded",
                "x-forwarded-for",
                "x-forwarded-proto",
                "x-forwarded-host",
                "x-forwarded-port",
                "x-real-ip",
                "true-client-ip",
                "client-ip",
                "cf-connecting-ip",
                "x-request-id",
            )
            details = {
                name: self.headers.get_all(name, []) for name in names
            }
            value = json.dumps(
                details, separators=(",", ":"), sort_keys=True
            ).encode("ascii")
            self._write_response(value, "application/json")
            return

        if self.path == "/api-key-observation":
            # Report credential presence only. Test evidence must never echo a key.
            details = {
                "api_key_header_present": bool(
                    self.headers.get_all("x-api-key", [])
                ),
                "request_id": self.headers.get("x-request-id", ""),
            }
            value = json.dumps(
                details, separators=(",", ":"), sort_keys=True
            ).encode("ascii")
            self._write_response(value, "application/json")
            return

        if self.path == "/jwt-observation":
            # Report bearer-field presence only. Evidence must never echo a JWT.
            details = {
                "authorization_header_present": bool(
                    self.headers.get_all("authorization", [])
                ),
                "request_id": self.headers.get("x-request-id", ""),
            }
            value = json.dumps(
                details, separators=(",", ":"), sort_keys=True
            ).encode("ascii")
            self._write_response(value, "application/json")
            return

        if self.path == "/cors-observation":
            self._write_cors_observation()
            return

        if self.path == "/tls-info":
            secure = isinstance(self.connection, ssl.SSLSocket)
            details = {
                "alpn": self.connection.selected_alpn_protocol() if secure else None,
                "client_certificate": bool(
                    self.connection.getpeercert(binary_form=True)
                ) if secure else False,
                "tls_version": self.connection.version() if secure else None,
            }
            value = json.dumps(
                details, separators=(",", ":"), sort_keys=True
            ).encode("ascii")
            self._write_response(value, "application/json")
            return

        if self.path == "/reset-content":
            self.send_response(205)
            self.send_header("content-length", "0")
            self.send_header(
                "x-upstream-connection", str(self.client_address[1])
            )
            self.end_headers()
            return

        if self.path == "/reset-content-invalid":
            self.close_connection = True
            self.wfile.write(
                b"HTTP/1.1 205 Reset Content\r\n"
                b"Content-Length: 1\r\n"
                b"Connection: close\r\n\r\nx"
            )
            return

        if self.path == "/informational-final":
            self.wfile.write(
                b"HTTP/1.1 103 Early Hints\r\n"
                b"Link: </style.css>; rel=preload\r\n\r\n"
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 6\r\n\r\nfinal\n"
            )
            return

        if self.path == "/switching-protocols":
            self.close_connection = True
            self.wfile.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Connection: upgrade\r\n"
                b"Upgrade: websocket\r\n\r\n"
            )
            return

        if self.path == "/informational-flood":
            self.close_connection = True
            self.wfile.write(
                b"HTTP/1.1 103 Early Hints\r\n\r\n" * 9
                + b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            )
            return

        if self.path.startswith("/response-overrun/"):
            variants = {
                "/response-overrun/bodyless": (
                    b"HTTP/1.1 204 No Content\r\n"
                    b"Connection: keep-alive\r\n\r\n"
                ),
                "/response-overrun/content-length": (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: keep-alive\r\n\r\nok"
                ),
                "/response-overrun/chunked": (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Transfer-Encoding: chunked\r\n"
                    b"Connection: keep-alive\r\n\r\n"
                    b"2\r\nok\r\n0\r\n\r\n"
                ),
            }
            first = variants.get(self.path)
            if first is None:
                self.send_error(404)
                return
            forged = (
                b"HTTP/1.1 299 Forged\r\n"
                b"Content-Length: 7\r\n"
                b"X-BonVoyage-Forged: yes\r\n"
                b"Connection: keep-alive\r\n\r\nforged\n"
            )
            self.wfile.write(first + forged)
            self.wfile.flush()
            return

        if self.path.startswith("/response-overrun-delayed/"):
            connection = str(self.client_address[1]).encode("ascii")
            variants = {
                "/response-overrun-delayed/bodyless": (
                    b"HTTP/1.1 204 No Content\r\n"
                    b"X-Upstream-Connection: " + connection + b"\r\n"
                    b"Connection: keep-alive\r\n\r\n"
                ),
                "/response-overrun-delayed/content-length": (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 2\r\n"
                    b"X-Upstream-Connection: " + connection + b"\r\n"
                    b"Connection: keep-alive\r\n\r\nok"
                ),
                "/response-overrun-delayed/chunked": (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Transfer-Encoding: chunked\r\n"
                    b"X-Upstream-Connection: " + connection + b"\r\n"
                    b"Connection: keep-alive\r\n\r\n"
                    b"2\r\nok\r\n0\r\n\r\n"
                ),
            }
            first = variants.get(self.path)
            if first is None:
                self.send_error(404)
                return
            forged = (
                b"HTTP/1.1 299 Forged\r\n"
                b"Content-Length: 7\r\n"
                b"X-BonVoyage-Forged: delayed\r\n"
                b"Connection: keep-alive\r\n\r\nforged\n"
            )
            try:
                self.wfile.write(first)
                self.wfile.flush()
                sleep(0.25)
                self.wfile.write(forged)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True
            return

        response_header_prefix = "/large-response-header/"
        if self.path.startswith(response_header_prefix):
            size = self._parse_size(self.path[len(response_header_prefix) :])
            if size is None:
                return
            self.send_response(200)
            self.send_header("content-length", "0")
            self.send_header("x-large", "x" * size)
            self.end_headers()
            return

        close_delimited_prefix = "/close-delimited/"
        if self.path.startswith(close_delimited_prefix):
            size = self._parse_size(self.path[len(close_delimited_prefix) :])
            if size is None:
                return
            self.close_connection = True
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/octet-stream\r\n"
                b"Connection: close\r\n\r\n" + b"x" * size
            )
            return

        chunk_extension_prefix = "/chunked-extension/"
        if self.path.startswith(chunk_extension_prefix):
            size = self._parse_size(self.path[len(chunk_extension_prefix) :])
            if size is None:
                return
            self._start_chunked_response()
            self.wfile.write(b"1;pad=" + b"x" * size + b"\r\nx\r\n0\r\n\r\n")
            return

        chunk_trailer_prefix = "/chunked-trailer/"
        if self.path.startswith(chunk_trailer_prefix):
            size = self._parse_size(self.path[len(chunk_trailer_prefix) :])
            if size is None:
                return
            self._start_chunked_response("x-checksum")
            self.wfile.write(
                b"4\r\ndata\r\n0\r\nx-checksum: " + b"x" * size + b"\r\n\r\n"
            )
            return

        chunked_truncated_prefix = "/chunked-truncated/"
        if self.path.startswith(chunked_truncated_prefix):
            size = self._parse_size(self.path[len(chunked_truncated_prefix) :])
            if size is None:
                return
            self.close_connection = True
            self._start_chunked_response()
            self.wfile.write(f"{size + 1:x}\r\n".encode() + b"x" * size)
            return

        chunked_with_trailers_prefix = "/chunked-with-trailers/"
        if self.path.startswith(chunked_with_trailers_prefix):
            size = self._parse_size(
                self.path[len(chunked_with_trailers_prefix) :]
            )
            if size is None:
                return
            self._write_chunked_response(size, trailer=("x-checksum", "ok"))
            return

        chunked_prefix = "/chunked/"
        if self.path.startswith(chunked_prefix):
            size = self._parse_size(self.path[len(chunked_prefix) :])
            if size is None:
                return
            self._write_chunked_response(size)
            return

        slow_prefix = "/slow/"
        if self.path.startswith(slow_prefix):
            delay_ms = self._parse_size(self.path[len(slow_prefix) :])
            if delay_ms is None:
                return
            if delay_ms > 5000:
                self.send_error(400, "delay exceeds 5000 ms")
                return
            sleep(delay_ms / 1000)
            self._write_response(b"slow\n", "text/plain")
            return

        stream_prefix = "/stream-payload/"
        if self.path.startswith(stream_prefix):
            size = self._parse_bounded_size(
                self.path[len(stream_prefix) :], MAX_STREAM_FIXTURE_BYTES
            )
            if size is None:
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            chunk = b"x" * STREAM_CHUNK_BYTES
            remaining = size
            try:
                while remaining:
                    current = min(remaining, len(chunk))
                    self.wfile.write(chunk[:current])
                    remaining -= current
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True
            return

        prefix = "/payload/"
        if not self.path.startswith(prefix):
            self.send_error(404)
            return

        size = self._parse_size(self.path[len(prefix) :])
        if size is None:
            return
        self._write_response(b"x" * size, "application/octet-stream")

    def do_POST(self):
        self._handle_body_request()

    def do_PUT(self):
        self._handle_body_request()

    def _handle_body_request(self):
        body = self._read_body()
        if body is None:
            return
        retry_prefix = "/retry/fail-once/"
        if self.path.startswith(retry_prefix):
            key = self._retry_fixture_key(self.path[len(retry_prefix) :])
            if key is None:
                return
            attempt = self._record_retry_fixture_attempt(key)
            if attempt is None:
                return
            if attempt == 1:
                self._close_without_response()
                return
        self._write_response(body, "application/octet-stream")

    def _retry_fixture_key(self, value):
        if not value or len(value) > 64 or not all(
            character.isalnum() or character in "-_" for character in value
        ):
            self.send_error(400, "invalid retry fixture key")
            return None
        return value

    def _record_retry_fixture_attempt(self, key):
        with RETRY_FIXTURE_LOCK:
            if (
                key not in RETRY_FIXTURE_ATTEMPTS
                and len(RETRY_FIXTURE_ATTEMPTS) >= MAX_RETRY_FIXTURE_KEYS
            ):
                self.send_error(429, "retry fixture key limit reached")
                return None
            attempt = RETRY_FIXTURE_ATTEMPTS.get(key, 0) + 1
            RETRY_FIXTURE_ATTEMPTS[key] = attempt
            return attempt

    def _close_without_response(self):
        self.close_connection = True
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.connection.close()

    def _parse_size(self, value):
        return self._parse_bounded_size(value, MAX_FIXTURE_BYTES)

    def _parse_bounded_size(self, value, maximum):
        try:
            size = int(value)
        except ValueError:
            self.send_error(400, "payload size must be an integer")
            return None
        if size < 0 or size > maximum:
            self.send_error(400, "payload size outside fixture bounds")
            return None
        return size

    def _read_body(self):
        if self.headers.get("transfer-encoding", "").lower() == "chunked":
            body = bytearray()
            while True:
                line = self.rfile.readline(128)
                try:
                    size = int(line.split(b";", 1)[0].strip(), 16)
                except ValueError:
                    self.send_error(400, "invalid chunk size")
                    return None
                if size == 0:
                    while self.rfile.readline(8192) not in (b"\r\n", b""):
                        pass
                    return bytes(body)
                if len(body) + size > MAX_FIXTURE_BYTES:
                    self.send_error(413)
                    return None
                body.extend(self.rfile.read(size))
                if self.rfile.read(2) != b"\r\n":
                    self.send_error(400, "invalid chunk delimiter")
                    return None

        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            self.send_error(400, "invalid content length")
            return None
        if length < 0 or length > MAX_FIXTURE_BYTES:
            self.send_error(413)
            return None
        return self.rfile.read(length)

    def _write_response(self, body, content_type):
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.send_header("x-upstream-connection", str(self.client_address[1]))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # Gateway rejection tests intentionally abort some in-flight
            # upstream attempts after strict streaming validation fails.
            self.close_connection = True

    def _write_cors_observation(self):
        details = {
            "origin": self.headers.get("origin", ""),
            "preflight_method_present": bool(
                self.headers.get_all("access-control-request-method", [])
            ),
            "preflight_headers_present": bool(
                self.headers.get_all("access-control-request-headers", [])
            ),
        }
        body = json.dumps(
            details, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        # The gateway qualification deliberately verifies that a configured
        # route removes these conflicting upstream-owned policy fields.
        self.send_header(
            "access-control-allow-origin", "https://upstream.invalid"
        )
        self.send_header("access-control-allow-credentials", "true")
        self.send_header("access-control-expose-headers", "x-upstream-secret")
        self.send_header("x-request-id", "upstream-request-id")
        self.end_headers()
        self.wfile.write(body)

    def _start_chunked_response(self, trailer_name=None):
        self.send_response(200)
        self.send_header("content-type", "application/octet-stream")
        self.send_header("transfer-encoding", "chunked")
        self.send_header("x-upstream-connection", str(self.client_address[1]))
        if trailer_name:
            self.send_header("trailer", trailer_name)
        self.end_headers()

    def _write_chunked_response(self, size, trailer=None):
        self._start_chunked_response(trailer[0] if trailer else None)
        remaining = size
        while remaining:
            chunk_size = min(remaining, 4096)
            self.wfile.write(f"{chunk_size:x}\r\n".encode())
            self.wfile.write(b"x" * chunk_size + b"\r\n")
            remaining -= chunk_size
        self.wfile.write(b"0\r\n")
        if trailer:
            self.wfile.write(f"{trailer[0]}: {trailer[1]}\r\n".encode("ascii"))
        self.wfile.write(b"\r\n")

    def log_message(self, format, *args):
        print(f"{self.client_address[0]} - {format % args}", flush=True)


if __name__ == "__main__":
    if not UPSTREAM_ID or len(UPSTREAM_ID) > 64 or not UPSTREAM_ID.isascii():
        raise ValueError("BONVOYAGE_UPSTREAM_ID must contain 1 to 64 ASCII bytes")
    port = int(os.environ.get("BONVOYAGE_UPSTREAM_PORT", "8081"))
    certificate = os.environ.get(
        "BONVOYAGE_UPSTREAM_TLS_CERTIFICATE", ""
    ).strip()
    private_key = os.environ.get(
        "BONVOYAGE_UPSTREAM_TLS_PRIVATE_KEY", ""
    ).strip()
    client_ca = os.environ.get("BONVOYAGE_UPSTREAM_TLS_CLIENT_CA", "").strip()
    if bool(certificate) != bool(private_key):
        raise ValueError("TLS certificate and private key must be configured together")
    if client_ca and not certificate:
        raise ValueError("a client CA requires a TLS listener")

    server = ControlledThreadingHTTPServer(("0.0.0.0", port), Handler)
    if certificate:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_COMPRESSION
        context.set_alpn_protocols(["http/1.1"])
        context.load_cert_chain(certificate, private_key)
        if client_ca:
            context.load_verify_locations(cafile=client_ca)
            context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
