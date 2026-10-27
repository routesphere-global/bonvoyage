#!/usr/bin/env python3
"""Controlled upstream for the bounded header-transformation checkpoint."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract.
        if self.path == "/healthz":
            body = b"ready\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        headers = {name.lower(): value for name, value in self.headers.items()}
        record = {"path": self.path, "headers": headers}
        print("REQUEST " + json.dumps(record, sort_keys=True), flush=True)
        body = json.dumps(record, sort_keys=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Response-Set", "upstream-set")
        self.send_header("X-Response-Append", "upstream-append")
        self.send_header("X-Response-Remove", "upstream-remove")
        self.send_header("X-Response-Unchanged", "upstream-keep")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string: str, *args: object) -> None:
        print("HTTP " + format_string % args, flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
