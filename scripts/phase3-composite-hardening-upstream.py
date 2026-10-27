#!/usr/bin/env python3
"""Controllable HTTP/1.1 upstream for the composite hardening matrix."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


UPSTREAM_ID = os.environ["BONVOYAGE_UPSTREAM_ID"]
LOG_REQUESTS = os.environ.get("BONVOYAGE_UPSTREAM_LOG_REQUESTS", "1") == "1"
MAX_DELAY_MS = 5000


class State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.fail = False
        self.requests = 0
        self.successes = 0
        self.forced_failures = 0
        self.active = 0
        self.maximum_active = 0

    def begin(self) -> bool:
        with self.lock:
            self.requests += 1
            self.active += 1
            self.maximum_active = max(self.maximum_active, self.active)
            return self.fail

    def finish(self, *, success: bool, forced_failure: bool) -> None:
        with self.lock:
            self.active -= 1
            if success:
                self.successes += 1
            if forced_failure:
                self.forced_failures += 1

    def set_failure(self, enabled: bool) -> None:
        with self.lock:
            self.fail = enabled

    def snapshot(self) -> dict[str, int | bool | str]:
        with self.lock:
            return {
                "upstream": UPSTREAM_ID,
                "fail": self.fail,
                "requests": self.requests,
                "successes": self.successes,
                "forced_failures": self.forced_failures,
                "active": self.active,
                "maximum_active": self.maximum_active,
            }


STATE = State()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API.
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/healthz":
            self._respond(200, b"ready\n", "text/plain")
            return
        if parsed.path == "/control/failure":
            values = urllib.parse.parse_qs(parsed.query)
            enabled = values.get("enabled", [""])[0]
            if enabled not in {"0", "1"}:
                self._respond(400, b"enabled must be 0 or 1\n", "text/plain")
                return
            STATE.set_failure(enabled == "1")
            self._respond(200, json.dumps(STATE.snapshot()).encode(), "application/json")
            return
        if parsed.path == "/stats":
            self._respond(200, json.dumps(STATE.snapshot()).encode(), "application/json")
            return

        forced_failure = STATE.begin()
        success = False
        try:
            if forced_failure:
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.connection.close()
                return

            if parsed.path.startswith("/slow/"):
                raw_delay = parsed.path.removeprefix("/slow/")
                if not raw_delay.isdigit() or int(raw_delay) > MAX_DELAY_MS:
                    self._respond(400, b"invalid delay\n", "text/plain")
                    return
                time.sleep(int(raw_delay) / 1000)

            body = (UPSTREAM_ID + "\n").encode("ascii")
            self._respond(200, body, "text/plain", {"X-Upstream-ID": UPSTREAM_ID})
            success = True
        finally:
            STATE.finish(success=success, forced_failure=forced_failure)

    def _respond(
        self,
        status: int,
        body: bytes,
        content_type: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string: str, *args: object) -> None:
        if LOG_REQUESTS:
            print("HTTP " + format_string % args, flush=True)


class Server(ThreadingHTTPServer):
    request_queue_size = 1024
    daemon_threads = True


if __name__ == "__main__":
    Server(("0.0.0.0", 8081), Handler).serve_forever()
