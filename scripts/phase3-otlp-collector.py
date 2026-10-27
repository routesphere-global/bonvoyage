#!/usr/bin/env python3
"""Bounded failure/recovery OTLP receiver used only by the Phase 3 gate."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


MAXIMUM_REQUEST_BYTES = 1024 * 1024
MAXIMUM_OBSERVATIONS = 2048
MAXIMUM_PAYLOAD_FILES = int(os.environ.get("BONVOYAGE_OTLP_MAX_PAYLOAD_FILES", "2048"))
EVIDENCE_DIRECTORY = Path(os.environ.get("BONVOYAGE_EVIDENCE_DIR", "/evidence"))


class CollectorState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.healthy = False
        self.attempts = 0
        self.accepted = 0
        self.rejected = 0
        self.payload_files_written = 0
        self.observations: list[dict[str, object]] = []

    def recover(self) -> None:
        with self.lock:
            self.healthy = True

    def fail(self) -> None:
        with self.lock:
            self.healthy = False

    def record(
        self,
        payload: bytes,
        content_type: str,
        connection_header: str,
        connection_id: int,
        peer_port: int,
    ) -> tuple[bool, int]:
        digest = hashlib.sha256(payload).hexdigest()
        with self.lock:
            self.attempts += 1
            sequence = self.attempts
            accepted = self.healthy
            if accepted:
                self.accepted += 1
            else:
                self.rejected += 1
            retain_payload = accepted and self.payload_files_written < MAXIMUM_PAYLOAD_FILES
            if retain_payload:
                self.payload_files_written += 1
            if len(self.observations) < MAXIMUM_OBSERVATIONS:
                self.observations.append(
                    {
                        "accepted": accepted,
                        "connection_header": connection_header,
                        "connection_id": connection_id,
                        "content_type": content_type,
                        "peer_port": peer_port,
                        "sequence": sequence,
                        "sha256": digest,
                        "size": len(payload),
                    }
                )
        if retain_payload:
            EVIDENCE_DIRECTORY.mkdir(parents=True, exist_ok=True)
            destination = EVIDENCE_DIRECTORY / f"otlp-payload-{sequence:04d}.bin"
            destination.write_bytes(payload)
        return accepted, sequence

    def snapshot(self) -> dict[str, object]:
        with self.lock:
            return {
                "accepted": self.accepted,
                "attempts": self.attempts,
                "healthy": self.healthy,
                "maximum_payload_files": MAXIMUM_PAYLOAD_FILES,
                "observations": list(self.observations),
                "payload_files_written": self.payload_files_written,
                "rejected": self.rejected,
            }


STATE = CollectorState()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, body: bytes = b"", content_type: str = "") -> None:
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract.
        if self.path == "/healthz":
            self._send(200, b"ready\n", "text/plain")
            return
        if self.path == "/observations":
            body = json.dumps(STATE.snapshot(), sort_keys=True).encode("utf-8")
            self._send(200, body, "application/json")
            return
        self._send(404)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract.
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400)
            return
        if length < 0 or length > MAXIMUM_REQUEST_BYTES:
            self._send(413)
            return
        payload = self.rfile.read(length)
        if len(payload) != length:
            self._send(400)
            return
        if self.path == "/fail":
            STATE.fail()
            self._send(200, b"{}", "application/json")
            return
        if self.path == "/recover":
            STATE.recover()
            self._send(200, b"{}", "application/json")
            return
        if self.path != "/v1/traces":
            self._send(404)
            return
        content_type = self.headers.get("Content-Type", "")
        if content_type != "application/x-protobuf":
            self._send(415)
            return
        accepted, sequence = STATE.record(
            payload,
            content_type,
            self.headers.get("Connection", ""),
            self.server.connection_id(self.connection),
            self.client_address[1],
        )
        print(
            json.dumps(
                {
                    "accepted": accepted,
                    "event": "otlp_attempt",
                    "sequence": sequence,
                    "size": len(payload),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        if accepted:
            # An empty body is a valid ExportTraceServiceResponse protobuf.
            self._send(200, b"", "application/x-protobuf")
        else:
            self._send(503)

    def log_message(self, format_string: str, *args: object) -> None:
        print("HTTP " + format_string % args, flush=True)


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args: object, **kwargs: object) -> None:
        self._connection_lock = threading.Lock()
        self._next_connection_id = 0
        self._connection_ids: dict[int, int] = {}
        super().__init__(*args, **kwargs)

    def get_request(self):  # type: ignore[no-untyped-def]
        request, client_address = super().get_request()
        with self._connection_lock:
            self._next_connection_id += 1
            self._connection_ids[id(request)] = self._next_connection_id
        return request, client_address

    def connection_id(self, request: object) -> int:
        with self._connection_lock:
            return self._connection_ids[id(request)]

    def shutdown_request(self, request: object) -> None:
        try:
            super().shutdown_request(request)
        finally:
            with self._connection_lock:
                self._connection_ids.pop(id(request), None)


if __name__ == "__main__":
    Server(("0.0.0.0", 4318), Handler).serve_forever()
