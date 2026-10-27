#!/usr/bin/env python3
"""Controlled upstream for static weighted route traffic splitting."""

from __future__ import annotations

import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    upstream_id = os.environ["BONVOYAGE_UPSTREAM_ID"]
    retry_attempts: dict[str, int] = {}
    retry_lock = threading.Lock()

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract.
        if self.path == "/healthz":
            self._respond(b"ready\n", "text/plain")
            return

        headers = {name.lower(): value for name, value in self.headers.items()}
        record = {
            "upstream": self.upstream_id,
            "path": self.path,
            "headers": headers,
        }
        print("REQUEST " + json.dumps(record, sort_keys=True), flush=True)

        if self.path == "/weighted-retry":
            request_id = headers.get("x-request-id", "missing")
            with self.retry_lock:
                attempt = self.retry_attempts.get(request_id, 0) + 1
                self.retry_attempts[request_id] = attempt
            if attempt == 1:
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.connection.close()
                return

        self._respond(
            json.dumps(record, sort_keys=True).encode("utf-8"),
            "application/json",
        )

    def _respond(self, body: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Upstream-ID", self.upstream_id)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string: str, *args: object) -> None:
        print("HTTP " + format_string % args, flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
