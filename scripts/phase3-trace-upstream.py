#!/usr/bin/env python3
"""Controlled HTTP/1 upstream that records bounded tracing observations."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAXIMUM_OBSERVATIONS = 4096
LOCK = threading.Lock()
OBSERVATIONS: list[dict[str, object]] = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract.
        if self.path == "/healthz":
            self._send(200, b"ready\n", "text/plain")
            return
        if self.path == "/observations":
            with LOCK:
                snapshot = list(OBSERVATIONS)
            body = json.dumps(
                {"observations": snapshot, "requests": len(snapshot)},
                sort_keys=True,
            ).encode("utf-8")
            self._send(200, body, "application/json")
            return

        record = {
            "headers": {name.lower(): value for name, value in self.headers.items()},
            "path": self.path,
        }
        with LOCK:
            if len(OBSERVATIONS) < MAXIMUM_OBSERVATIONS:
                OBSERVATIONS.append(record)
        print("REQUEST " + json.dumps(record, sort_keys=True), flush=True)
        body = json.dumps(record, sort_keys=True).encode("utf-8")
        self._send(200, body, "application/json")

    def log_message(self, format_string: str, *args: object) -> None:
        print("HTTP " + format_string % args, flush=True)


class Server(ThreadingHTTPServer):
    # Admit cold connection bursts without testing TCP backlog loss instead of
    # OTLP exporter isolation. This matches the other controlled upstreams.
    request_queue_size = 1024
    daemon_threads = True


if __name__ == "__main__":
    Server(("0.0.0.0", 8081), Handler).serve_forever()
