#!/usr/bin/env python3
"""Exercise runtime logging transport and recovery in the builder image."""

import argparse
import fcntl
import http.server
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request


METRIC = re.compile(r"^(bonvoyage_bonvoyage_runtime_log_[a-z_]+)(?:\{[^}]*\})?\s+([0-9]+(?:\.[0-9]+)?)$")
RECORD = re.compile(r"^<(?P<priority>\d{1,3})>bonvoyage\[\d+\]: (?P<body>.+)$", re.DOTALL)
EVENT = re.compile(r"(?:^| )event=([a-z_]+)(?: |$)")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def fetch(path, timeout=0.5):
    with urllib.request.urlopen("http://127.0.0.1:" + path, timeout=timeout) as response:
        return response.read().decode("utf-8")


def metrics():
    values = {}
    body = fetch("9090/metrics", 3)
    for line in body.splitlines():
        match = METRIC.fullmatch(line)
        if match:
            require(match[1] not in values, "duplicate metric " + match[1])
            values[match[1]] = float(match[2])
    names = ("records_attempted_total", "records_sent_total", "records_dropped_total",
             "queue_depth", "queue_capacity", "sink_healthy",
             "would_block_events_total", "unavailable_events_total")
    result = {}
    for name in names:
        key = "bonvoyage_bonvoyage_runtime_log_" + name
        require(key in values, "missing metric " + key + ": " + repr(
            [line for line in body.splitlines() if "runtime_log" in line and not line.startswith("#")][:4]))
        result[name] = values[key]
    require(0 <= result["queue_depth"] <= result["queue_capacity"], "invalid queue bounds")
    return result


def wait_for(predicate, process, seconds, description):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        require(process.poll() is None, "gateway exited during " + description)
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("timed out waiting for " + description)


def read_socket(receiver, records):
    while True:
        try:
            records.append(receiver.recv(4096))
        except BlockingIOError:
            return


def read_pipe(reader, data):
    while True:
        try:
            chunk = os.read(reader, 8192)
            if not chunk:
                return
            data.extend(chunk)
        except BlockingIOError:
            return


def events(records):
    parsed = []
    for raw in records:
        text = raw.decode("utf-8").rstrip("\n")
        require(0 < len(text.encode("utf-8")) <= 2048, "record exceeds runtime log bound")
        match = RECORD.fullmatch(text)
        require(match is not None, "untyped runtime log record: " + repr(text))
        require(0 <= int(match["priority"]) <= 191, "invalid syslog priority")
        event = EVENT.search(match["body"])
        parsed.append({"event": event[1] if event else None, "record": text})
    return parsed


def proxy_requests(mode, phase, count, upstream_count):
    durations = []
    for index in range(count):
        path = "/runtime-log-fixture/" + mode + "/" + phase + "/" + str(index)
        started = time.monotonic()
        with urllib.request.urlopen("http://127.0.0.1:8080" + path, timeout=2) as response:
            require(response.status == 200, "proxy response was not 200")
            require(response.read() == ("fixture:" + path).encode(),
                    "proxy response did not match controlled upstream")
        durations.append((time.monotonic() - started) * 1000)
    require(upstream_count() >= count, "requests did not reach controlled upstream")
    return {"successful": count, "max_ms": round(max(durations), 3)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("healthy-unix", "unix-arrival", "unix-replacement", "full-pipe"), required=True)
    parser.add_argument("--gateway", default="/opt/bonvoyage/bin/bonvoyage-dataplane")
    parser.add_argument("--snapshot", default="/tmp/snapshot.pb")
    args = parser.parse_args()
    require(os.path.isfile(args.snapshot), "snapshot missing: " + args.snapshot)
    require(os.path.isfile(args.gateway), "gateway missing: " + args.gateway)

    receiver = None
    reader = writer = None
    process = None
    upstream = None
    upstream_thread = None
    upstream_requests = 0
    upstream_lock = threading.Lock()
    records = []
    initial_receiver_records = 0
    before_loss = None
    pipe_data = bytearray()
    filler = 0
    with tempfile.TemporaryDirectory(prefix="bonvoyage-runtime-log-") as directory:
        path = os.path.join(directory, "logger.sock")
        try:
            class UpstreamHandler(http.server.BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def do_GET(self):
                    nonlocal upstream_requests
                    require(self.path.startswith("/runtime-log-fixture/"),
                            "unexpected upstream request path")
                    with upstream_lock:
                        upstream_requests += 1
                    body = ("fixture:" + self.path).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, format, *arguments):
                    pass

            upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 8081), UpstreamHandler)
            upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
            upstream_thread.start()

            def upstream_count():
                with upstream_lock:
                    return upstream_requests

            if args.mode in ("healthy-unix", "unix-replacement"):
                receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                receiver.bind(path)
                receiver.setblocking(False)
            elif args.mode == "full-pipe":
                reader, writer = os.pipe()
                fcntl.fcntl(writer, fcntl.F_SETPIPE_SZ, 4096)
                require(fcntl.fcntl(writer, fcntl.F_GETPIPE_SZ) == 4096, "pipe capacity is not 4096")
                for fd in (reader, writer):
                    fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
                while filler < 4096:
                    filler += os.write(writer, b"X" * (4096 - filler))
                require(filler == 4096, "pipe was not filled with 4096 bytes")

            command = [args.gateway, "--snapshot", args.snapshot,
                       "--runtime-log-transport", "stderr-pipe" if writer is not None else "unix",
                       "--admin-address", "127.0.0.1", "--metrics-address", "127.0.0.1",
                       "--smp", "1", "--memory", "256M", "--overprovisioned"]
            if writer is None:
                command += ["--runtime-log-socket", path]
            if args.mode == "unix-replacement":
                command += ["--logger-log-level", "bonvoyage-gateway=debug"]
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=writer if writer is not None else subprocess.PIPE)
            if writer is not None:
                os.close(writer)
                writer = None

            def ready():
                if receiver is not None:
                    read_socket(receiver, records)
                try:
                    return json.loads(fetch("9901/health/ready"))["status"] == "ok"
                except (urllib.error.URLError, TimeoutError, ValueError, KeyError):
                    return False

            wait_for(ready, process, 8, "admin readiness")
            if args.mode in ("healthy-unix", "unix-replacement"):
                wait_for(lambda: (read_socket(receiver, records) or
                                  any(b"event=dataplane_ready" in x for x in records)),
                         process, 5, "ready record")
            if args.mode == "unix-replacement":
                before_loss = metrics()
                require(before_loss["queue_depth"] == 0 and before_loss["sink_healthy"] == 1,
                        "initial receiver was not healthy")
                initial_receiver_records = len(records)
                receiver.close()
                receiver = None
                os.unlink(path)
                pressure_requests = proxy_requests(args.mode, "pressure", 16, upstream_count)
            elif args.mode != "healthy-unix":
                def pressure():
                    current = metrics()
                    return current["queue_depth"] >= 1 and current[
                        "would_block_events_total" if args.mode == "full-pipe" else "unavailable_events_total"] >= 1
                wait_for(pressure, process, 5, "queued transport pressure")
            if args.mode == "unix-replacement":
                wait_for(lambda: (metrics()["queue_depth"] >= 1 and
                                  metrics()["unavailable_events_total"] > before_loss["unavailable_events_total"]),
                         process, 5, "lost receiver and queued request logs")
            before = metrics()
            require(before["records_attempted_total"] >= 1, "no log attempts")
            if args.mode != "unix-replacement":
                pressure_requests = proxy_requests(args.mode, "pressure", 16,
                                                   upstream_count)
            if args.mode in ("unix-arrival", "unix-replacement"):
                require(before["queue_depth"] >= 1 and before["unavailable_events_total"] >= 1,
                        "unavailable receiver not observed")
                receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                receiver.bind(path)
                receiver.setblocking(False)
            elif args.mode == "full-pipe":
                require(before["queue_depth"] >= 1 and before["would_block_events_total"] >= 1,
                        "full pipe backpressure not observed")
                read_pipe(reader, pipe_data)
                require(len(pipe_data) >= filler and pipe_data[:filler] == b"X" * filler,
                        "prefill was not drained intact")

            def recovered():
                if receiver is not None:
                    read_socket(receiver, records)
                    if args.mode == "unix-replacement":
                        seen = any(b"handling request" in x for x in records[initial_receiver_records:])
                    else:
                        seen = any(b"event=dataplane_ready" in x for x in records)
                else:
                    read_pipe(reader, pipe_data)
                    seen = b"event=dataplane_ready" in pipe_data[filler:]
                return seen and metrics()["queue_depth"] == 0

            wait_for(recovered, process, 5, "ready record and queue recovery")
            after = metrics()
            require(after["queue_depth"] == 0 and after["sink_healthy"] == 1,
                    "sink did not recover")
            require(after["records_sent_total"] > (before_loss["records_sent_total"]
                     if before_loss is not None else 0), "no records sent after recovery")
            if args.mode == "unix-replacement":
                require(after["records_dropped_total"] == 0,
                        "receiver replacement dropped queued request logs")
            recovered_requests = proxy_requests(args.mode, "recovered", 16,
                                                upstream_count)
            if args.mode == "unix-replacement":
                read_socket(receiver, records)
                wait_for(lambda: (read_socket(receiver, records) or
                                  (metrics()["queue_depth"] == 0 and
                                   metrics()["sink_healthy"] == 1)),
                         process, 5, "post-recovery debug queue drain")
            before_stop = metrics() if args.mode == "unix-replacement" else None
            require(upstream_count() == 32, "controlled upstream request count mismatch")
            require(process.poll() is None, "gateway restarted or exited before shutdown")
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=8)
            require(process.returncode == 0, "gateway exit was " + str(process.returncode))
            require(not stdout and (reader is not None or not stderr), "unexpected gateway stdout/stderr")

            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if receiver is not None:
                    read_socket(receiver, records)
                else:
                    read_pipe(reader, pipe_data)
                raw = records if receiver is not None else pipe_data[filler:].splitlines()
                if any(b"event=runtime_log_final" in item for item in raw):
                    break
                time.sleep(0.05)
            parsed = events(records if receiver is not None else pipe_data[filler:].splitlines())
            names = [item["event"] for item in parsed if item["event"] is not None]
            require("dataplane_ready" in names, "ready event missing")
            require("dataplane_stopped" in names, "stop event missing: " + repr({
                "events": names, "received": len(records), "before_stop": before_stop}))
            finals = [item["record"] for item in parsed if item["event"] == "runtime_log_final"]
            require(len(finals) == 1, "expected one final accounting record")
            fields = dict(re.findall(r"\b(attempted|sent|dropped|shutdown_drops|queued)=(\d+)\b", finals[0]))
            require(set(fields) == {"attempted", "sent", "dropped", "shutdown_drops", "queued"},
                    "incomplete final accounting")
            final = {key: int(value) for key, value in fields.items()}
            require(final["shutdown_drops"] == 0 and final["queued"] == 0,
                    "shutdown lost queued records")
            require(final["attempted"] >= final["sent"] >= 1,
                    "invalid final record counts")
            if args.mode == "unix-replacement":
                require(final["attempted"] == final["sent"] and final["dropped"] == 0,
                        "receiver replacement did not drain all attempted records")
            print(json.dumps({"mode": args.mode, "gateway_exit": process.returncode,
                              "counters": {"before_loss": before_loss, "before": before,
                                           "after": after, "before_stop": before_stop,
                                           "final": final},
                              "events": names, "filler_bytes": filler if reader is not None else None,
                              "proxy": {"pressure": pressure_requests,
                                        "recovered": recovered_requests,
                                        "upstream_requests": upstream_count()},
                              "status": "passed"}, sort_keys=True))
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()
            if receiver is not None:
                receiver.close()
            for fd in (reader, writer):
                if fd is not None:
                    os.close(fd)
            if upstream is not None:
                upstream.shutdown()
                upstream.server_close()
            if upstream_thread is not None:
                upstream_thread.join(timeout=2)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"status": "failed", "error": str(error)}), file=sys.stderr)
        sys.exit(1)
