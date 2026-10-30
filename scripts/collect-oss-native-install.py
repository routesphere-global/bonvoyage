#!/usr/bin/env python3
"""Exercise one destructive OSS fresh install on a disposable Ubuntu host.

This runner is intentionally narrower than a general installer. It accepts one
checksum-bound Debian technical candidate and one precompiled test snapshot,
requires a pristine disposable Ubuntu 24.04 AMD64 host, and emits the exact raw
evidence inventory consumed by verify-oss-native-install.py. It never purges
operator state and never grants release or publication authority.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from email.parser import Parser
import hashlib
import http.client
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import pwd
import grp
import re
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = Path(__file__).with_name("verify-oss-native-install.py")
DEFAULT_CONTRACT = ROOT / "packaging/release/debian/oss-native-fresh-install-contract.json"
CONFIRM_RETAINED_STATE = "RETAIN_BONVOYAGE_OPERATOR_STATE"
PACKAGE_NAME = "bonvoyage-gateway"
SERVICE = "bonvoyage.service"
SERVICE_USER = "bonvoyage"
SERVICE_GROUP = "bonvoyage"
SNAPSHOT_TARGET = Path("/etc/bonvoyage/snapshot.pb")
STATE_PATHS = (
    Path("/etc/bonvoyage"),
    Path("/var/lib/bonvoyage"),
    Path("/var/log/bonvoyage"),
)
SHADOW_PATHS = (
    Path("/etc/systemd/system/bonvoyage.service"),
    Path("/etc/systemd/system/bonvoyage.service.d"),
    Path("/run/systemd/system/bonvoyage.service"),
    Path("/run/systemd/system/bonvoyage.service.d"),
)
PORTS = (8080, 9090, 9901, 18081)
REQUESTS_PER_ROUTE = 25
COMMAND_TIMEOUT_SECONDS = 120
INSTALL_TIMEOUT_SECONDS = 600
START_TIMEOUT_SECONDS = 45
HTTP_TIMEOUT_SECONDS = 5
ADMIN_READY_BODY = b'{"status":"ok"}\n'
MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_RETAINED_STATE_BYTES = 128 * 1024 * 1024
MAX_RETAINED_STATE_ENTRIES = 2048
TRUSTED_EVIDENCE_PARENTS = (Path("/root"), Path("/var/tmp"))
RAW_FILES = (
    "raw/commands.jsonl",
    "raw/installed-state.txt",
    "raw/journal.txt",
    "raw/metrics-after.txt",
    "raw/metrics-before.txt",
    "raw/os-release.txt",
    "raw/package-control.txt",
    "raw/package-files.txt",
    "raw/preflight.txt",
    "raw/process-status.txt",
    "raw/removed-state.txt",
    "raw/service-properties.txt",
    "raw/socket-state.txt",
    "raw/stopped-state.txt",
    "raw/traffic.txt",
)
METRICS = {
    "requests": "bonvoyage_bonvoyage_gateway_requests_total",
    "responses_2xx": "bonvoyage_bonvoyage_gateway_responses_2xx_total",
    "upstream_selections": "bonvoyage_bonvoyage_gateway_upstream_endpoint_selections_total",
    "configured_routes": "bonvoyage_bonvoyage_gateway_configured_routes",
    "ready": "bonvoyage_bonvoyage_gateway_ready",
    "responses_4xx": "bonvoyage_bonvoyage_gateway_responses_4xx_total",
    "responses_5xx": "bonvoyage_bonvoyage_gateway_responses_5xx_total",
    "route_misses": "bonvoyage_bonvoyage_gateway_route_misses_total",
    "request_timeouts": "bonvoyage_bonvoyage_gateway_request_timeouts_total",
    "overload_rejections": "bonvoyage_bonvoyage_gateway_overload_rejections_total",
    "upstream_failures": "bonvoyage_bonvoyage_gateway_upstream_failures_total",
    "allocator_failures": "bonvoyage_memory_malloc_failed",
    "abandoned_failed_futures": "bonvoyage_reactor_abandoned_failed_futures",
    "reactor_stalls": "bonvoyage_stall_detector_reported",
}
HARDENING = {
    "User": "bonvoyage",
    "Group": "bonvoyage",
    "NoNewPrivileges": "yes",
    "PrivateTmp": "yes",
    "ProtectHome": "yes",
    "ProtectSystem": "strict",
    "ProtectKernelTunables": "yes",
    "ProtectKernelModules": "yes",
    "ProtectControlGroups": "yes",
    "RestrictSUIDSGID": "yes",
    "LockPersonality": "yes",
    "RestrictRealtime": "yes",
    "SystemCallArchitectures": "native",
    "LimitNOFILE": "1048576",
    "Restart": "on-failure",
}
SYSTEMCTL_PROPERTIES = tuple(HARDENING) + (
    "Id", "ActiveState", "SubState", "UnitFileState", "MainPID", "NRestarts",
    "FragmentPath", "DropInPaths", "InvocationID", "Result", "ExecMainCode",
    "ExecMainStatus", "ExecMainStartTimestampMonotonic", "ReadWritePaths",
)
FIXTURE_PROGRAM = r'''import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

parser = argparse.ArgumentParser()
parser.add_argument("--bind", required=True)
parser.add_argument("--port", required=True, type=int)
args = parser.parse_args()

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        body = b"oss-native-upstream\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, _format, *_args):
        return

server = ThreadingHTTPServer((args.bind, args.port), Handler)
server.daemon_threads = True
server.serve_forever()
'''


class Rejected(RuntimeError):
    """The host, input, or observed lifecycle violated the native contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Rejected(message)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json(path: Path) -> tuple[dict, bytes]:
    raw = read_regular(path, "JSON input", 4 * 1024 * 1024)

    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, f"duplicate JSON field: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda token: require(False, f"non-finite JSON value: {token}"),
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise Rejected(f"invalid JSON input: {error}") from error
    require(isinstance(value, dict), "JSON input must be an object")
    return value, raw


def read_regular(path: Path, label: str, maximum: int = MAX_INPUT_BYTES) -> bytes:
    require(path.is_absolute() and path == path.resolve(), f"{label} must be a canonical absolute path")
    require(path.exists() and not path.is_symlink(), f"missing or linked {label}: {path}")
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
                f"{label} must be a bounded regular file")
        body = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    require(len(body) <= maximum, f"{label} exceeds size limit")
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
             after.st_ctime_ns), f"{label} changed while reading")
    return body


def checked_digest(path: Path, expected: str, label: str,
                   maximum: int = MAX_INPUT_BYTES) -> tuple[bytes, dict]:
    require(isinstance(expected, str) and len(expected) == 64 and
            all(character in "0123456789abcdef" for character in expected),
            f"invalid {label} SHA-256")
    body = read_regular(path, label, maximum)
    actual = sha256_bytes(body)
    require(actual == expected, f"{label} SHA-256 mismatch")
    return body, {"bytes": len(body), "sha256": actual}


def load_verifier():
    spec = importlib.util.spec_from_file_location("verify_oss_native_install", VERIFIER_PATH)
    require(spec is not None and spec.loader is not None, "native verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    temporary = path.with_name(path.name + ".tmp")
    require(not temporary.exists() and not temporary.is_symlink(),
            f"temporary output already exists: {temporary}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    path.chmod(mode)


def secure_parent(path: Path, label: str) -> None:
    """Require a parent an unprivileged peer cannot replace beneath us."""
    metadata = path.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    require(stat.S_ISDIR(metadata.st_mode) and not path.is_symlink() and
            path == path.resolve(), f"canonical {label} directory required")
    require(metadata.st_uid == os.geteuid(), f"{label} directory must be owned by the runner")
    writable_by_peer = bool(mode & (stat.S_IWGRP | stat.S_IWOTH))
    require(not writable_by_peer or bool(mode & stat.S_ISVTX),
            f"{label} directory must not be replaceable by an unprivileged peer")


def stage_verified_inputs(inputs: dict, parent: Path = Path("/var/tmp")) -> tuple[dict, Path]:
    """Copy verified bytes into one private directory used by privileged tools."""
    secure_parent(parent, "staging parent")
    stage = Path(tempfile.mkdtemp(prefix="bonvoyage-oss-native-", dir=parent)).resolve()
    stage.chmod(0o700)
    paths = {
        "contract_path": stage / "contract.json",
        "package_path": stage / inputs["package_path"].name,
        "receipt_path": stage / "build-receipt.json",
        "snapshot_path": stage / "snapshot.pb",
    }
    bodies = {
        "contract_path": inputs["contract_raw"],
        "package_path": inputs["package_raw"],
        "receipt_path": inputs["receipt_raw"],
        "snapshot_path": inputs["snapshot_raw"],
    }
    try:
        require(len(set(paths.values())) == len(paths), "staged input filenames collide")
        for key, path in paths.items():
            atomic_write(path, bodies[key])
            observed = read_regular(path, f"staged {key}")
            require(observed == bodies[key], f"staged {key} differs from verified bytes")
    except BaseException:
        cleanup_staged_inputs(stage)
        raise
    staged = dict(inputs)
    staged.update(paths)
    return staged, stage


def cleanup_staged_inputs(stage: Path) -> None:
    """Remove only regular files from the exact private staging directory."""
    require(stage.is_absolute() and stage.name.startswith("bonvoyage-oss-native-"),
            "refusing to clean an unexpected staging path")
    if not stage.exists():
        return
    require(stage.is_dir() and not stage.is_symlink(), "staging path is not a directory")
    for child in tuple(stage.iterdir()):
        metadata = child.lstat()
        require(stat.S_ISREG(metadata.st_mode) and not child.is_symlink(),
                "unexpected staging entry; retained for inspection")
        child.unlink()
    stage.rmdir()


def write_json(path: Path, value: object) -> None:
    atomic_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def parse_os_release(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        require(key not in fields, f"duplicate os-release field: {key}")
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        fields[key] = value
    return fields


def validate_platform(os_release: str, machine: str, effective_uid: int,
                      pid_one: str) -> None:
    fields = parse_os_release(os_release)
    require(fields.get("ID") == "ubuntu" and fields.get("VERSION_ID") == "24.04",
            "Ubuntu 24.04 host required")
    require(machine == "x86_64", "AMD64 host required")
    require(effective_uid == 0, "root execution required")
    require(pid_one == "systemd", "systemd must be PID 1")


def parse_key_values(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line:
            continue
        key, separator, value = line.partition("=")
        require(separator == "=" and key and key not in fields,
                "invalid or duplicate key-value output")
        fields[key] = value
    return fields


def parse_owned_listeners(text: str, gateway_pid: int, fixture_pid: int) -> list[dict]:
    require(gateway_pid > 1 and fixture_pid > 1 and gateway_pid != fixture_pid,
            "distinct gateway and fixture PIDs required")
    roles = {gateway_pid: "gateway", fixture_pid: "upstream"}
    records: list[dict] = []
    for line in text.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 6 or fields[0] != "LISTEN":
            continue
        observed_pids = {int(value) for value in re.findall(r"pid=(\d+)", fields[5])}
        owned = observed_pids.intersection(roles)
        if not owned:
            continue
        require(len(owned) == 1, "listener ownership is ambiguous")
        host, separator, port_text = fields[3].rpartition(":")
        require(separator == ":" and port_text.isdigit(), "invalid listener endpoint")
        host = host.strip("[]")
        if host == "*":
            host = "0.0.0.0"
        pid = next(iter(owned))
        records.append({"role": roles[pid], "pid": pid, "host": host,
                        "port": int(port_text)})
    expected = {
        ("gateway", gateway_pid, "0.0.0.0", 8080),
        ("gateway", gateway_pid, "127.0.0.1", 9090),
        ("gateway", gateway_pid, "127.0.0.1", 9901),
        ("upstream", fixture_pid, "127.0.0.1", 18081),
    }
    observed = {(item["role"], item["pid"], item["host"], item["port"])
                for item in records}
    require(observed == expected and len(records) == len(expected),
            "owned listener topology differs from the qualification fixture")
    return sorted(records, key=lambda item: (item["role"], item["port"]))


def metric_sum(text: str, metric: str) -> int:
    values = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        name = fields[0].split("{", 1)[0]
        if name != metric:
            continue
        try:
            value = Decimal(fields[1])
        except InvalidOperation as error:
            raise Rejected(f"invalid metric value: {metric}") from error
        require(value.is_finite(), f"non-finite metric value: {metric}")
        values.append(value)
    require(values, f"required metric is absent: {metric}")
    total = sum(values, Decimal(0))
    require(total == total.to_integral_value(), f"non-integral metric value: {metric}")
    return int(total)


def analyze_metrics(before: str, after: str, requests_per_route: int,
                    expected_configured_routes: int = 2) -> dict:
    require(type(requests_per_route) is int and requests_per_route >= REQUESTS_PER_ROUTE,
            "insufficient bounded request count")
    require(type(expected_configured_routes) is int and expected_configured_routes > 0,
            "invalid configured-route expectation")
    before_values = {name: metric_sum(before, metric) for name, metric in METRICS.items()}
    after_values = {name: metric_sum(after, metric) for name, metric in METRICS.items()}
    expected = requests_per_route * 2
    request_delta = after_values["requests"] - before_values["requests"]
    response_delta = after_values["responses_2xx"] - before_values["responses_2xx"]
    selection_delta = after_values["upstream_selections"] - before_values["upstream_selections"]
    require(request_delta == expected, "request counter delta mismatch")
    require(response_delta == expected, "2xx response counter delta mismatch")
    require(selection_delta == requests_per_route, "upstream selection counter delta mismatch")
    require(before_values["ready"] == 1 and after_values["ready"] == 1,
            "gateway readiness metric changed")
    require(before_values["configured_routes"] == expected_configured_routes and
            after_values["configured_routes"] == expected_configured_routes,
            "configured route metric mismatch")
    zero = {name: after_values[name] for name in (
        "responses_4xx", "responses_5xx", "route_misses", "request_timeouts",
        "overload_rejections", "upstream_failures", "allocator_failures",
        "abandoned_failed_futures", "reactor_stalls",
    )}
    require(all(value == 0 for value in zero.values()),
            "runtime error counters are nonzero")
    return {
        "fixed_requests": requests_per_route,
        "proxied_requests": requests_per_route,
        "request_delta": request_delta,
        "response_2xx_delta": response_delta,
        "upstream_selection_delta": selection_delta,
        "configured_routes": after_values["configured_routes"],
        "zero_counters": zero,
    }


def process_identity(pid: int) -> dict:
    require(type(pid) is int and pid > 1, "valid main PID required")
    status_path = Path(f"/proc/{pid}/status")
    stat_path = Path(f"/proc/{pid}/stat")
    exe_path = Path(f"/proc/{pid}/exe")
    status_text = status_path.read_text(encoding="utf-8")
    status = {}
    for line in status_text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            status[key] = value.strip()
    uid_fields = status.get("Uid", "").split()
    require(len(uid_fields) == 4 and all(field.isdigit() for field in uid_fields),
            "process UID observation missing")
    rss = status.get("VmRSS", "").split()
    require(len(rss) == 2 and rss[0].isdigit() and rss[1] == "kB",
            "process RSS observation missing")
    raw_stat = stat_path.read_text(encoding="ascii")
    require(raw_stat.startswith(f"{pid} (") and ") " in raw_stat,
            "process stat identity mismatch")
    suffix = raw_stat[raw_stat.rfind(")") + 2:].split()
    require(len(suffix) > 19 and suffix[19].isdigit(), "process start time missing")
    executable = exe_path.resolve(strict=True)
    executable_raw = read_regular(executable, "installed gateway executable")
    return {
        "pid": pid,
        "start_ticks": suffix[19],
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip(),
        "uid": int(uid_fields[0]),
        "rss_kib": int(rss[0]),
        "descriptors": sum(1 for _ in Path(f"/proc/{pid}/fd").iterdir()),
        "executable": str(executable),
        "executable_sha256": sha256_bytes(executable_raw),
        "status": status_text,
    }


class CommandLog:
    def __init__(self, path: Path, maximum_output_bytes: int = MAX_COMMAND_OUTPUT_BYTES):
        self.path = path
        self.ids: set[str] = set()
        require(type(maximum_output_bytes) is int and maximum_output_bytes > 0,
                "positive command-output bound required")
        self.maximum_output_bytes = maximum_output_bytes

    def append(self, record: dict) -> None:
        with self.path.open("ab") as stream:
            stream.write((json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())

    def run(self, command_id: str, argv: list[str], *, timeout: int = COMMAND_TIMEOUT_SECONDS,
            allowed: tuple[int, ...] = (0,), env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        require(command_id not in self.ids, f"duplicate command ID: {command_id}")
        require(argv and all(isinstance(value, str) and value and "\x00" not in value for value in argv),
                "fixed nonempty command arguments required")
        self.ids.add(command_id)
        started = utc_now()
        monotonic = time.monotonic()
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "TZ": "UTC",
        }
        if env:
            environment.update(env)
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            start_new_session=True,
        )
        require(process.stdout is not None and process.stderr is not None,
                "command output pipes are unavailable")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = monotonic + timeout
        timed_out = False
        output_limit_exceeded = False
        try:
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                if selector.get_map():
                    events = selector.select(min(remaining, 0.25))
                else:
                    time.sleep(min(remaining, 0.05))
                    events = ()
                for key, _ in events:
                    chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    destination = buffers[key.data]
                    available = self.maximum_output_bytes - len(destination)
                    if len(chunk) > available:
                        destination.extend(chunk[:max(available, 0)])
                        output_limit_exceeded = True
                        break
                    destination.extend(chunk)
                if output_limit_exceeded:
                    break
            if timed_out or output_limit_exceeded:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=5)
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()
        result = subprocess.CompletedProcess(
            argv, process.returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]))
        self.append({
            "schema_version": 1, "id": command_id, "argv": argv,
            "started_at": started,
            "duration_ms": math.ceil((time.monotonic() - monotonic) * 1000),
            "timed_out": timed_out,
            "output_limit_exceeded": output_limit_exceeded,
            "returncode": result.returncode,
            "stdout_bytes": len(result.stdout), "stdout_sha256": sha256_bytes(result.stdout),
            "stderr_bytes": len(result.stderr), "stderr_sha256": sha256_bytes(result.stderr),
        })
        require(not timed_out, f"command timed out: {command_id}")
        require(not output_limit_exceeded, f"command output exceeded bound: {command_id}")
        require(result.returncode in allowed,
                f"command failed ({command_id}) with exit code {result.returncode}")
        return result


def exact_http(port: int, path: str, expected: bytes) -> dict:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=HTTP_TIMEOUT_SECONDS)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read(1024 * 1024 + 1)
    finally:
        connection.close()
    require(response.status == 200 and body == expected,
            f"unexpected HTTP response for 127.0.0.1:{port}{path}")
    return {
        "path": path,
        "status": response.status,
        "body_bytes": len(body),
        "body_sha256": sha256_bytes(body),
    }


def fetch_text(port: int, path: str) -> str:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=HTTP_TIMEOUT_SECONDS)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read(16 * 1024 * 1024 + 1)
    finally:
        connection.close()
    require(response.status == 200 and 0 < len(body) <= 16 * 1024 * 1024,
            f"HTTP capture failed for 127.0.0.1:{port}{path}")
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Rejected(f"non-UTF-8 HTTP capture for {path}") from error


def wait_http(port: int, path: str, expected: bytes, timeout: int) -> dict:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return exact_http(port, path, expected)
        except (OSError, Rejected, http.client.HTTPException) as error:
            last_error = error
            time.sleep(0.25)
    raise Rejected(f"HTTP endpoint did not become ready: {port}{path}: {last_error}")


def phase_record(phase_id: str, checks: dict[str, bool], contract: dict) -> dict:
    expected = next((item for item in contract["phases"] if item["id"] == phase_id), None)
    require(expected is not None, f"unknown lifecycle phase: {phase_id}")
    require(set(checks) == set(expected["required_checks"]),
            f"phase check inventory mismatch: {phase_id}")
    require(all(type(value) is bool and value for value in checks.values()),
            f"phase check failed: {phase_id}")
    return {"id": phase_id, "passed": True, "checks": checks}


def stat_record(path: Path) -> dict:
    metadata = path.lstat()
    require(not stat.S_ISLNK(metadata.st_mode), f"linked path is not allowed: {path}")
    return {
        "path": str(path),
        "type": "directory" if stat.S_ISDIR(metadata.st_mode) else "file",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
    }


def path_absent(path: Path) -> bool:
    return not path.exists() and not path.is_symlink()


def service_identity() -> dict:
    account = pwd.getpwnam(SERVICE_USER)
    group = grp.getgrnam(SERVICE_GROUP)
    return {
        "user": {
            "name": account.pw_name,
            "passwd": account.pw_passwd,
            "uid": account.pw_uid,
            "gid": account.pw_gid,
            "gecos": account.pw_gecos,
            "home": account.pw_dir,
            "shell": account.pw_shell,
        },
        "group": {
            "name": group.gr_name,
            "passwd": group.gr_passwd,
            "gid": group.gr_gid,
            "members": sorted(group.gr_mem),
        },
    }


def retained_state_inventory(paths: tuple[Path, ...] = STATE_PATHS) -> dict[str, dict]:
    records: dict[str, dict] = {}
    total_bytes = 0
    for root in paths:
        require(root.exists() and root.is_dir() and not root.is_symlink(),
                f"retained state directory is absent or unsafe: {root}")
        candidates = (root, *sorted(root.rglob("*")))
        for path in candidates:
            require(len(records) < MAX_RETAINED_STATE_ENTRIES,
                    "retained state entry bound exceeded")
            metadata = path.lstat()
            require(not stat.S_ISLNK(metadata.st_mode),
                    f"linked retained state is not allowed: {path}")
            record = {
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "mode": stat.S_IMODE(metadata.st_mode),
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "links": metadata.st_nlink,
                "mtime_ns": metadata.st_mtime_ns,
                "ctime_ns": metadata.st_ctime_ns,
            }
            if stat.S_ISDIR(metadata.st_mode):
                record["type"] = "directory"
            elif stat.S_ISREG(metadata.st_mode):
                body = read_regular(path.resolve(), f"retained state file {path}",
                                    MAX_RETAINED_STATE_BYTES)
                total_bytes += len(body)
                require(total_bytes <= MAX_RETAINED_STATE_BYTES,
                        "retained state byte bound exceeded")
                record.update({"type": "file", "bytes": len(body),
                               "sha256": sha256_bytes(body)})
            else:
                raise Rejected(f"unsupported retained state object: {path}")
            records[str(path)] = record
    return records


def prepare_output(output: Path,
                   trusted_parents: tuple[Path, ...] = TRUSTED_EVIDENCE_PARENTS) -> None:
    require(output.is_absolute() and output == output.resolve(),
            "evidence output must be a canonical absolute path")
    require(not output.exists() and not output.is_symlink(),
            "new evidence output directory required")
    forbidden_roots = (*STATE_PATHS, Path("/usr"), Path("/run"), Path("/etc/systemd"), ROOT.resolve())
    require(not any(output.is_relative_to(root) for root in forbidden_roots),
            "evidence output must remain outside source, package, and gateway state paths")
    parent = output.parent
    require(parent.exists(), "existing evidence parent required")
    allowed = {path.resolve() for path in trusted_parents if path.exists()}
    require(parent.resolve() in allowed,
            "evidence output must be a direct child of /root or /var/tmp")
    secure_parent(parent, "evidence parent")
    output.mkdir(mode=0o700)
    (output / "raw").mkdir(mode=0o700)
    for relative in RAW_FILES:
        path = output / relative
        path.write_text("pending\n", encoding="utf-8")
        path.chmod(0o600)


def package_fields(text: str) -> dict[str, str]:
    fields = Parser().parsestr(text)
    required = ("Package", "Version", "Architecture")
    require(all(len(fields.get_all(name, [])) == 1 for name in required),
            "unique package control fields required")
    return {name: fields[name].strip() for name in required}


def package_is_installed(result: subprocess.CompletedProcess) -> bool:
    if result.returncode != 0:
        return False
    fields = Parser().parsestr(result.stdout.decode("utf-8"))
    return fields.get("Status") == "install ok installed"


def package_is_fresh_absent(result: subprocess.CompletedProcess) -> bool:
    """A fresh install requires no dpkg database record, including config-files."""
    return result.returncode != 0 and not result.stdout.strip()


def file_inventory(output: Path) -> dict[str, dict]:
    records = {}
    for relative in RAW_FILES:
        path = output / relative
        body = read_regular(path.resolve(), f"evidence file {relative}", 16 * 1024 * 1024)
        records[relative] = {"bytes": len(body), "sha256": sha256_bytes(body)}
    return records


def validate_inputs(contract_path: Path, contract_sha256: str, package: Path,
                    package_sha256: str, receipt_path: Path, receipt_sha256: str,
                    snapshot: Path, snapshot_sha256: str) -> dict:
    verifier = load_verifier()
    contract_raw, contract_record = checked_digest(
        contract_path, contract_sha256, "native contract", 4 * 1024 * 1024)
    contract, strict_contract_raw = strict_json(contract_path)
    require(strict_contract_raw == contract_raw, "native contract changed during validation")
    verifier.validate_contract(contract)
    package_raw, package_record = checked_digest(
        package, package_sha256, "Debian package", MAX_INPUT_BYTES)
    receipt_raw, receipt_record = checked_digest(
        receipt_path, receipt_sha256, "Debian build receipt", 4 * 1024 * 1024)
    receipt, strict_receipt_raw = strict_json(receipt_path)
    require(strict_receipt_raw == receipt_raw, "Debian build receipt changed during validation")
    build = verifier.validate_build_receipt(receipt, package, package_raw)
    snapshot_raw, snapshot_record = checked_digest(
        snapshot, snapshot_sha256, "compiled snapshot", 64 * 1024 * 1024)
    expected_snapshot = contract["fixture"]["snapshot"]
    require(snapshot_record["bytes"] == expected_snapshot["bytes"] and
            snapshot_record["sha256"] == expected_snapshot["sha256"],
            "compiled snapshot does not match the contract-bound fixture")
    require(len({str(path) for path in (contract_path, package, receipt_path, snapshot)}) == 4,
            "contract, package, receipt, and snapshot must be distinct files")
    return {
        "verifier": verifier,
        "contract": contract,
        "contract_path": contract_path,
        "contract_raw": contract_raw,
        "contract_record": contract_record,
        "package_path": package,
        "package_raw": package_raw,
        "package_record": package_record,
        "receipt_path": receipt_path,
        "receipt_raw": receipt_raw,
        "receipt_record": receipt_record,
        "receipt": receipt,
        "build": build,
        "snapshot_path": snapshot,
        "snapshot_raw": snapshot_raw,
        "snapshot_record": snapshot_record,
    }


class NativeHost:
    """Concrete privileged adapter for one disposable native lifecycle."""

    def __init__(self, inputs: dict, output: Path, os_release: str):
        self.inputs = inputs
        self.output = output
        self.raw = output / "raw"
        self.log = CommandLog(self.raw / "commands.jsonl")
        (self.raw / "commands.jsonl").write_bytes(b"")
        (self.raw / "commands.jsonl").chmod(0o600)
        self.os_release = os_release
        self.fixture: subprocess.Popen | None = None
        self.fixture_started_at: str | None = None
        self.service_started = False
        self.service_enabled = False
        self.package_install_started = False
        self.lifecycle_complete = False
        self.phase_records: list[dict] = []

    def write_raw(self, name: str, text: str) -> None:
        require(name in RAW_FILES and name != "raw/commands.jsonl",
                f"unsupported raw evidence path: {name}")
        atomic_write(self.output / name, text.encode("utf-8"))

    def systemctl_show(self, command_id: str) -> tuple[dict[str, str], str]:
        argv = ["/usr/bin/systemctl", "show", SERVICE]
        for name in SYSTEMCTL_PROPERTIES:
            argv.extend(("--property", name))
        result = self.log.run(command_id, argv)
        text = result.stdout.decode("utf-8")
        return parse_key_values(text), text

    @staticmethod
    def port_available(port: int) -> bool:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("0.0.0.0", port))
        except OSError:
            return False
        finally:
            listener.close()
        return True

    def preflight(self, confirmed_hostname: str) -> dict:
        actual_hostname = socket.gethostname()
        require(confirmed_hostname == actual_hostname,
                "disposable-host acknowledgement must equal the current hostname")
        package_status = self.log.run(
            "preflight-package-status",
            ["/usr/bin/dpkg-query", "--status", PACKAGE_NAME],
            allowed=(0, 1),
        )
        passwd_status = self.log.run(
            "preflight-service-user",
            ["/usr/bin/getent", "passwd", SERVICE_USER],
            allowed=(0, 2),
        )
        group_status = self.log.run(
            "preflight-service-group",
            ["/usr/bin/getent", "group", SERVICE_GROUP],
            allowed=(0, 2),
        )
        package_absent = package_is_fresh_absent(package_status)
        account_absent = passwd_status.returncode != 0 and group_status.returncode != 0
        state_absent = all(not path.exists() and not path.is_symlink() for path in STATE_PATHS)
        shadow_absent = all(not path.exists() and not path.is_symlink() for path in SHADOW_PATHS)
        ports_available = all(self.port_available(port) for port in PORTS)
        require(package_absent, "gateway package is already installed")
        require(account_absent, "gateway service account or group already exists")
        require(state_absent, "gateway configuration or state already exists")
        require(shadow_absent, "gateway shadow unit or drop-in already exists")
        require(ports_available, "one or more qualification ports are already in use")
        lines = [
            "classification=oss-native-fresh-install-preflight",
            f"captured_at={utc_now()}",
            f"hostname_sha256={sha256_bytes(actual_hostname.encode())}",
            "disposable_host_confirmed=true",
            "package_absent=true",
            "service_account_absent=true",
            "state_absent=true",
            "shadow_unit_absent=true",
            "qualification_ports_available=true",
            f"package_sha256={self.inputs['package_record']['sha256']}",
            f"build_receipt_sha256={self.inputs['receipt_record']['sha256']}",
            f"snapshot_sha256={self.inputs['snapshot_record']['sha256']}",
            f"contract_sha256={self.inputs['contract_record']['sha256']}",
        ]
        self.write_raw("raw/preflight.txt", "\n".join(lines) + "\n")
        self.phase_records.append(phase_record("preflight", {
            "disposable_host_confirmed": True,
            "package_absent": True,
            "service_account_absent": True,
            "state_absent": True,
            "shadow_unit_absent": True,
        }, self.inputs["contract"]))
        return {
            "distribution": "ubuntu",
            "version_id": "24.04",
            "architecture": "amd64",
            "root_execution": True,
            "hostname_sha256": sha256_bytes(actual_hostname.encode()),
            "kernel": platform.release(),
        }

    def verify_service_identity(self, fields: dict[str, str], expected_state: str) -> None:
        require(fields.get("Id") == SERVICE and fields.get("ActiveState") == expected_state,
                f"unexpected service state: {expected_state}")
        require(all(fields.get(name) == value for name, value in HARDENING.items()),
                "effective service hardening differs from the package contract")
        require(set(shlex.split(fields.get("ReadWritePaths", ""))) ==
                {"/var/lib/bonvoyage", "/var/log/bonvoyage"},
                "service writable paths differ from the package contract")
        require(fields.get("DropInPaths", "") == "", "service drop-ins are not allowed")

    def install(self) -> dict:
        package = self.inputs["package_path"]
        archive = self.log.run(
            "archive-control",
            ["/usr/bin/dpkg-deb", "--field", str(package)],
        ).stdout.decode("utf-8")
        archive_fields = package_fields(archive)
        build = self.inputs["build"]
        require(archive_fields == {
            "Package": PACKAGE_NAME,
            "Version": build["package"]["version"],
            "Architecture": "amd64",
        }, "Debian archive control differs from the build receipt")
        self.package_install_started = True
        install = self.log.run(
            "install-package",
            ["/usr/bin/apt-get", "install", "-y", "--no-install-recommends", str(package)],
            timeout=INSTALL_TIMEOUT_SECONDS,
            env={"DEBIAN_FRONTEND": "noninteractive", "APT_LISTCHANGES_FRONTEND": "none"},
        )
        self.log.run("install-daemon-reload", ["/usr/bin/systemctl", "daemon-reload"])
        status_result = self.log.run(
            "installed-package-status",
            ["/usr/bin/dpkg-query", "--status", PACKAGE_NAME],
        )
        status_text = status_result.stdout.decode("utf-8")
        status_fields = Parser().parsestr(status_text)
        installed_fields = package_fields(status_text)
        require(status_fields.get("Status") == "install ok installed" and
                installed_fields == archive_fields,
                "installed package identity mismatch")
        file_result = self.log.run(
            "installed-package-files",
            ["/usr/bin/dpkg-query", "--listfiles", PACKAGE_NAME],
        )
        package_files = [line for line in file_result.stdout.decode("utf-8").splitlines()
                         if line.startswith("/")]
        require("/usr/bin/bonvoyage-dataplane" in package_files,
                "installed package does not own the gateway binary")
        unit_candidates = [name for name in package_files if name.endswith("/bonvoyage.service")]
        require(len(unit_candidates) == 1, "exactly one package unit is required")
        package_unit = Path(unit_candidates[0])
        require(package_unit.exists() and package_unit.is_file() and not package_unit.is_symlink(),
                "package unit is not a regular file")
        binary = Path("/usr/bin/bonvoyage-dataplane")
        binary_raw = read_regular(binary, "installed gateway binary")
        require(sha256_bytes(binary_raw) == build["binary"]["sha256"],
                "installed gateway binary differs from the build receipt")

        account = pwd.getpwnam(SERVICE_USER)
        group = grp.getgrnam(SERVICE_GROUP)
        identity = service_identity()
        require(account.pw_uid != 0 and account.pw_gid == group.gr_gid and
                account.pw_dir == "/var/lib/bonvoyage" and
                account.pw_shell in ("/usr/sbin/nologin", "/bin/false"),
                "unsafe service account")
        etc_state = stat_record(Path("/etc/bonvoyage"))
        var_state = stat_record(Path("/var/lib/bonvoyage"))
        require(etc_state == {"path": "/etc/bonvoyage", "type": "directory",
                              "uid": 0, "gid": group.gr_gid, "mode": 0o750},
                "unsafe configuration directory ownership or mode")
        require(var_state == {"path": "/var/lib/bonvoyage", "type": "directory",
                              "uid": account.pw_uid, "gid": group.gr_gid, "mode": 0o750},
                "unsafe state directory ownership or mode")

        enabled = self.log.run(
            "installed-service-enabled",
            ["/usr/bin/systemctl", "is-enabled", SERVICE],
            allowed=(0, 1, 3, 4),
        )
        active = self.log.run(
            "installed-service-active",
            ["/usr/bin/systemctl", "is-active", SERVICE],
            allowed=(0, 3, 4),
        )
        require(enabled.returncode != 0 and enabled.stdout.strip() in (b"disabled", b"static", b"indirect"),
                "fresh package unexpectedly enabled the service")
        require(active.returncode != 0 and active.stdout.strip() in (b"inactive", b"unknown"),
                "fresh package unexpectedly started the service")
        fields, service_text = self.systemctl_show("installed-service-properties")
        self.verify_service_identity(fields, "inactive")
        require(fields.get("UnitFileState") in ("disabled", "static", "indirect"),
                "fresh package unit is unexpectedly enabled")
        invocation = fields.get("InvocationID", "")
        require(fields.get("MainPID") == "0" and fields.get("NRestarts") == "0" and
                fields.get("ExecMainStartTimestampMonotonic") in ("", "0") and
                (not invocation or invocation == "0" * len(invocation)),
                "fresh package service was started before explicit commissioning")
        fragment = Path(fields.get("FragmentPath", ""))
        require(fragment.is_absolute() and fragment.resolve() == package_unit.resolve(),
                "package unit is not the authoritative service fragment")
        owner = self.log.run(
            "installed-unit-owner",
            ["/usr/bin/dpkg-query", "--search", str(package_unit)],
        ).stdout.decode("utf-8")
        require(owner.split(":", 1)[0] == PACKAGE_NAME,
                "service fragment is not package-owned")

        self.write_raw("raw/package-control.txt",
                       "[archive]\n" + archive + "\n[installed]\n" + status_text)
        self.write_raw("raw/package-files.txt",
                       file_result.stdout.decode("utf-8"))
        self.write_raw("raw/installed-state.txt", "\n".join([
            "classification=oss-native-installed-inactive",
            f"captured_at={utc_now()}",
            f"package_version={installed_fields['Version']}",
            f"installed_binary_sha256={sha256_bytes(binary_raw)}",
            f"service_uid={account.pw_uid}",
            f"service_gid={group.gr_gid}",
            f"config_state={json.dumps(etc_state, sort_keys=True)}",
            f"runtime_state={json.dumps(var_state, sort_keys=True)}",
            f"service_enabled=false",
            f"service_active=false",
            f"fragment_path={fragment}",
            f"package_unit={package_unit}",
            f"apt_stdout_sha256={sha256_bytes(install.stdout)}",
            f"apt_stderr_sha256={sha256_bytes(install.stderr)}",
        ]) + "\n")
        self.write_raw("raw/service-properties.txt", "[installed-inactive]\n" + service_text)
        self.phase_records.append(phase_record("installed-inactive", {
            "package_identity_exact": True,
            "payload_identity_exact": True,
            "service_account_non_root": True,
            "state_modes_safe": True,
            "service_disabled": True,
            "service_inactive": True,
            "package_unit_authoritative": True,
        }, self.inputs["contract"]))
        return {
            "version": installed_fields["Version"],
            "binary_sha256": sha256_bytes(binary_raw),
            "uid": account.pw_uid,
            "gid": group.gr_gid,
            "identity": identity,
            "package_unit": package_unit,
        }

    def install_snapshot(self, gid: int) -> None:
        require(not SNAPSHOT_TARGET.exists() and not SNAPSHOT_TARGET.is_symlink(),
                "snapshot target must be absent before commissioning")
        descriptor = os.open(
            SNAPSHOT_TARGET,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o640,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(self.inputs["snapshot_raw"])
                stream.flush()
                os.fsync(stream.fileno())
            os.fchown(descriptor, 0, gid)
            os.fchmod(descriptor, 0o640)
        finally:
            os.close(descriptor)
        observed = read_regular(SNAPSHOT_TARGET, "installed snapshot", 64 * 1024 * 1024)
        metadata = stat_record(SNAPSHOT_TARGET)
        require(sha256_bytes(observed) == self.inputs["snapshot_record"]["sha256"] and
                metadata["uid"] == 0 and metadata["gid"] == gid and metadata["mode"] == 0o640,
                "installed snapshot identity or mode mismatch")

    def start_fixture(self, uid: int, gid: int) -> None:
        require(self.fixture is None, "controlled upstream already started")
        argv = ["/usr/bin/python3", "-c", FIXTURE_PROGRAM,
                "--bind", "127.0.0.1", "--port", "18081"]
        self.fixture_started_at = utc_now()
        self.fixture = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "TZ": "UTC"},
            close_fds=True,
            start_new_session=True,
            user=uid,
            group=gid,
        )
        self.log.append({
            "schema_version": 1,
            "id": "start-controlled-upstream",
            "argv": ["/usr/bin/python3", "-c", f"sha256:{sha256_bytes(FIXTURE_PROGRAM.encode())}",
                     "--bind", "127.0.0.1", "--port", "18081"],
            "started_at": self.fixture_started_at,
            "duration_ms": 0,
            "timed_out": False,
            "output_limit_exceeded": False,
            "returncode": None,
            "stdout_bytes": 0,
            "stdout_sha256": sha256_bytes(b""),
            "stderr_bytes": 0,
            "stderr_sha256": sha256_bytes(b""),
            "pid": self.fixture.pid,
            "uid": uid,
            "gid": gid,
        })
        wait_http(18081, "/healthz", b"oss-native-upstream\n", 10)

    def stop_fixture(self) -> None:
        if self.fixture is None:
            return
        process = self.fixture
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        self.log.append({
            "schema_version": 1,
            "id": "stop-controlled-upstream",
            "argv": ["signal", "controlled-upstream", "TERM"],
            "started_at": utc_now(),
            "duration_ms": 0,
            "timed_out": False,
            "output_limit_exceeded": False,
            "returncode": process.returncode,
            "stdout_bytes": 0,
            "stdout_sha256": sha256_bytes(b""),
            "stderr_bytes": 0,
            "stderr_sha256": sha256_bytes(b""),
        })
        self.fixture = None
        require(process.returncode in (0, -signal.SIGTERM),
                "controlled upstream did not stop as requested")

    def commission(self, installed: dict) -> tuple[dict, dict[str, str]]:
        self.install_snapshot(installed["gid"])
        self.start_fixture(installed["uid"], installed["gid"])
        self.log.run("enable-service", ["/usr/bin/systemctl", "enable", SERVICE])
        self.service_enabled = True
        # From this point onward failure cleanup must attempt a stop even when
        # systemctl start itself reports a timeout or failure.
        self.service_started = True
        self.log.run("start-service", ["/usr/bin/systemctl", "start", SERVICE], timeout=60)
        wait_http(9901, "/health/ready", ADMIN_READY_BODY, START_TIMEOUT_SECONDS)
        fixed_probe = exact_http(8080, "/bonvoyage/ready", b"ready\n")
        proxied_probe = exact_http(8080, "/healthz", b"oss-native-upstream\n")
        fields, service_text = self.systemctl_show("commissioned-service-properties")
        self.verify_service_identity(fields, "active")
        require(fields.get("UnitFileState") == "enabled" and
                fields.get("MainPID", "").isdigit() and int(fields["MainPID"]) > 1 and
                fields.get("NRestarts") == "0" and fields.get("InvocationID") and
                fields.get("InvocationID") != "0" * len(fields.get("InvocationID", "")),
                "commissioned service identity is invalid")
        state = process_identity(int(fields["MainPID"]))
        require(state["uid"] == installed["uid"] and
                state["executable"] == "/usr/bin/bonvoyage-dataplane" and
                state["executable_sha256"] == installed["binary_sha256"],
                "commissioned process identity mismatch")
        sockets = self.log.run(
            "commissioned-sockets",
            ["/usr/bin/ss", "--listening", "--numeric", "--tcp", "--processes"],
        ).stdout.decode("utf-8")
        require(self.fixture is not None and self.fixture.poll() is None,
                "controlled upstream exited before socket qualification")
        socket_records = parse_owned_listeners(sockets, state["pid"], self.fixture.pid)
        self.write_raw("raw/socket-state.txt", "\n".join(
            json.dumps(item, sort_keys=True) for item in socket_records) + "\n")
        self.write_raw("raw/service-properties.txt",
                       (self.raw / "service-properties.txt").read_text(encoding="utf-8") +
                       "\n[commissioned]\n" + service_text)
        self.phase_records.append(phase_record("commissioned", {
            "snapshot_identity_exact": True,
            "snapshot_mode_safe": True,
            "service_enabled": True,
            "service_active": True,
            "effective_hardening_exact": True,
            "process_non_root": True,
            "process_binary_exact": True,
            "loopback_admin": True,
            "loopback_metrics": True,
        }, self.inputs["contract"]))
        return state, {
            "fields": fields,
            "invocation_id": fields["InvocationID"],
            "fixed_probe": json.dumps(fixed_probe, sort_keys=True),
            "proxied_probe": json.dumps(proxied_probe, sort_keys=True),
        }

    def traffic(self, start_state: dict, commissioned: dict[str, str]) -> tuple[dict, dict, dict, dict]:
        before = fetch_text(9090, "/metrics")
        self.write_raw("raw/metrics-before.txt", before)
        records = [
            "classification=oss-native-fresh-install-traffic",
            f"captured_at={utc_now()}",
            f"fixed_probe={commissioned['fixed_probe']}",
            f"proxied_probe={commissioned['proxied_probe']}",
        ]
        for index in range(REQUESTS_PER_ROUTE):
            fixed = exact_http(8080, "/bonvoyage/ready", b"ready\n")
            proxied = exact_http(8080, "/healthz", b"oss-native-upstream\n")
            records.append(json.dumps({"index": index + 1, "route": "fixed", **fixed}, sort_keys=True))
            records.append(json.dumps({"index": index + 1, "route": "proxied", **proxied}, sort_keys=True))
        admin = exact_http(9901, "/health/ready", ADMIN_READY_BODY)
        after = fetch_text(9090, "/metrics")
        self.write_raw("raw/metrics-after.txt", after)
        traffic = analyze_metrics(
            before, after, REQUESTS_PER_ROUTE,
            self.inputs["contract"]["traffic"]["expected_configured_routes"])
        end_fields, end_service_text = self.systemctl_show("traffic-service-properties")
        self.verify_service_identity(end_fields, "active")
        end_state = process_identity(int(end_fields["MainPID"]))
        stable = all(start_state[name] == end_state[name]
                     for name in ("pid", "start_ticks", "boot_id", "executable", "executable_sha256"))
        require(stable and end_fields.get("NRestarts") == "0",
                "gateway process changed or restarted during traffic")
        records.extend((
            f"admin_ready={json.dumps(admin, sort_keys=True)}",
            f"traffic={json.dumps(traffic, sort_keys=True)}",
            "process_identity_stable=true",
            "automatic_restarts=0",
        ))
        self.write_raw("raw/traffic.txt", "\n".join(records) + "\n")
        self.write_raw("raw/process-status.txt", "".join((
            "[before]\n", start_state["status"], "\n[after]\n", end_state["status"],
            f"\nbefore_identity={json.dumps({key: value for key, value in start_state.items() if key != 'status'}, sort_keys=True)}\n",
            f"after_identity={json.dumps({key: value for key, value in end_state.items() if key != 'status'}, sort_keys=True)}\n",
        )))
        self.write_raw("raw/service-properties.txt",
                       (self.raw / "service-properties.txt").read_text(encoding="utf-8") +
                       "\n[after-traffic]\n" + end_service_text)
        self.phase_records.append(phase_record("traffic", {
            "fixed_route_exact": True,
            "proxied_route_exact": True,
            "admin_ready": True,
            "metrics_accounting_exact": True,
            "runtime_error_counters_zero": True,
            "process_identity_stable": True,
            "automatic_restarts_zero": True,
        }, self.inputs["contract"]))
        process = {
            "main_pid": start_state["pid"],
            "stable_identity": True,
            "automatic_restarts": 0,
            "non_root": True,
            "binary_exact": True,
            "graceful_stop": False,
        }
        resources = {
            "rss_start_kib": start_state["rss_kib"],
            "rss_end_kib": end_state["rss_kib"],
            "descriptor_start": start_state["descriptors"],
            "descriptor_end": end_state["descriptors"],
        }
        return traffic, process, resources, end_state

    def stop(self, process: dict, invocation_id: str) -> dict:
        pid = process["main_pid"]
        self.log.run("stop-service", ["/usr/bin/systemctl", "stop", SERVICE], timeout=60)
        fields, service_text = self.systemctl_show("stopped-service-properties")
        require(fields.get("ActiveState") == "inactive" and fields.get("MainPID") == "0" and
                fields.get("Result") == "success" and fields.get("ExecMainCode") == "exited" and
                fields.get("ExecMainStatus") == "0" and fields.get("NRestarts") == "0" and
                not Path(f"/proc/{pid}").exists(),
                "gateway did not stop gracefully")
        self.service_started = False
        journal = self.log.run(
            "service-journal",
            ["/usr/bin/journalctl", f"_SYSTEMD_INVOCATION_ID={invocation_id}",
             "--no-pager", "--output=short-iso-precise"],
        ).stdout.decode("utf-8")
        require(journal.strip(), "service journal is empty")
        self.write_raw("raw/journal.txt", journal)
        self.write_raw("raw/stopped-state.txt", service_text +
                       f"process_path_absent={str(not Path(f'/proc/{pid}').exists()).lower()}\n")
        process["graceful_stop"] = True
        self.phase_records.append(phase_record("stopped", {
            "graceful_stop": True,
            "service_inactive": True,
            "process_absent": True,
        }, self.inputs["contract"]))
        self.stop_fixture()
        return {
            "identity": service_identity(),
            "state": retained_state_inventory(),
        }

    def remove(self, installed: dict, retained_before: dict) -> None:
        self.log.run("disable-service", ["/usr/bin/systemctl", "disable", SERVICE])
        disabled = self.log.run(
            "removed-service-enabled",
            ["/usr/bin/systemctl", "is-enabled", SERVICE],
            allowed=(0, 1, 3, 4),
        )
        require(disabled.returncode != 0 and
                disabled.stdout.strip() in (b"disabled", b"static", b"indirect"),
                "gateway service remains enabled before package removal")
        self.service_enabled = False
        self.log.run(
            "remove-package",
            ["/usr/bin/apt-get", "remove", "-y", PACKAGE_NAME],
            timeout=INSTALL_TIMEOUT_SECONDS,
            env={"DEBIAN_FRONTEND": "noninteractive", "APT_LISTCHANGES_FRONTEND": "none"},
        )
        self.log.run("remove-daemon-reload", ["/usr/bin/systemctl", "daemon-reload"])
        package_status = self.log.run(
            "removed-package-status",
            ["/usr/bin/dpkg-query", "--status", PACKAGE_NAME],
            allowed=(0, 1),
        )
        require(not package_is_installed(package_status), "gateway package remains installed")
        binary_absent = path_absent(Path("/usr/bin/bonvoyage-dataplane"))
        package_unit_absent = path_absent(installed["package_unit"])
        identity_after = service_identity()
        account_retained = (retained_before["identity"] == installed["identity"] ==
                            identity_after)
        snapshot = read_regular(SNAPSHOT_TARGET, "retained snapshot", 64 * 1024 * 1024)
        snapshot_retained = sha256_bytes(snapshot) == self.inputs["snapshot_record"]["sha256"]
        state_after = retained_state_inventory()
        state_retained = retained_before["state"] == state_after
        require(binary_absent, "package binary remains after removal")
        require(package_unit_absent, "package unit remains after removal")
        require(account_retained, "service identity was removed or changed")
        require(snapshot_retained, "operator snapshot was removed or changed")
        require(state_retained, "operator state directory was removed")
        removed_text = "\n".join((
            "classification=oss-native-fresh-install-removed",
            f"captured_at={utc_now()}",
            "package_absent=true",
            "binary_absent=true",
            "package_unit_absent=true",
            "service_account_retained=true",
            "snapshot_retained=true",
            "operator_state_retained=true",
            f"retained_snapshot_sha256={sha256_bytes(snapshot)}",
            f"retained_identity_sha256={sha256_bytes(json.dumps(identity_after, sort_keys=True).encode())}",
            f"retained_state_inventory_sha256={sha256_bytes(json.dumps(state_after, sort_keys=True).encode())}",
            f"retained_state={json.dumps(state_after, sort_keys=True)}",
        )) + "\n"
        self.write_raw("raw/removed-state.txt", removed_text)
        self.phase_records.append(phase_record("removed", {
            "package_absent": True,
            "binary_absent": True,
            "package_unit_absent": True,
            "service_account_retained": True,
            "snapshot_retained": True,
            "operator_state_retained": True,
        }, self.inputs["contract"]))
        self.lifecycle_complete = True

    def safe_stop(self) -> list[str]:
        errors: list[str] = []
        if self.package_install_started:
            for command_id, action in (
                ("failure-stop-service", "stop"),
                ("failure-disable-service", "disable"),
            ):
                try:
                    self.log.run(
                        command_id,
                        ["/usr/bin/systemctl", action, SERVICE],
                        timeout=60,
                        allowed=(0, 1, 3, 4, 5),
                    )
                except Exception as error:
                    errors.append(f"{action}: {error}")
            try:
                active = self.log.run(
                    "failure-service-active",
                    ["/usr/bin/systemctl", "is-active", SERVICE],
                    allowed=(0, 3, 4),
                )
                require(active.returncode != 0 and
                        active.stdout.strip() in (b"inactive", b"failed", b"unknown"),
                        "failure cleanup left the service active")
            except Exception as error:
                errors.append(f"verify inactive: {error}")
            try:
                enabled = self.log.run(
                    "failure-service-enabled",
                    ["/usr/bin/systemctl", "is-enabled", SERVICE],
                    allowed=(0, 1, 3, 4),
                )
                require(enabled.returncode != 0 and
                        enabled.stdout.strip() in (b"disabled", b"static", b"indirect", b"unknown"),
                        "failure cleanup left the service enabled")
            except Exception as error:
                errors.append(f"verify disabled: {error}")
            if not errors:
                self.service_started = False
                self.service_enabled = False
        if self.fixture is not None:
            try:
                self.stop_fixture()
            except Exception as error:
                errors.append(f"controlled upstream: {error}")
        return errors

    def execute(self, confirmed_hostname: str) -> dict:
        self.write_raw("raw/os-release.txt", self.os_release)
        host = self.preflight(confirmed_hostname)
        installed = self.install()
        start_state, commissioned = self.commission(installed)
        traffic, process, resources, end_state = self.traffic(start_state, commissioned)
        fields, _ = self.systemctl_show("pre-stop-service-properties")
        invocation_id = fields.get("InvocationID", "")
        final_state = process_identity(int(fields.get("MainPID", "0")))
        stable_before_stop = all(end_state[name] == final_state[name]
                                 for name in ("pid", "start_ticks", "boot_id",
                                              "executable", "executable_sha256"))
        require(invocation_id == commissioned["invocation_id"] and
                fields.get("NRestarts") == "0" and stable_before_stop,
                "gateway restarted or changed immediately before stop")
        retained_before = self.stop(process, invocation_id)
        require(retained_before["identity"] == installed["identity"],
                "service identity changed before package removal")
        self.remove(installed, retained_before)
        return {
            "host": host,
            "package": {
                "name": PACKAGE_NAME,
                "version": installed["version"],
                "architecture": "amd64",
                "bytes": self.inputs["package_record"]["bytes"],
                "sha256": self.inputs["package_record"]["sha256"],
                "build_receipt_sha256": self.inputs["receipt_record"]["sha256"],
                "installed_binary_sha256": installed["binary_sha256"],
            },
            "phases": self.phase_records,
            "traffic": traffic,
            "process": process,
            "resources": resources,
        }


def failure_observation(error: BaseException, completed_phases: list[dict],
                        cleanup_errors: tuple[str, ...] = ()) -> dict:
    return {
        "schema_version": 1,
        "classification": "routesphere-bonvoyage-oss-native-fresh-install-diagnostic",
        "outcome": "failed",
        "captured_at": utc_now(),
        "error_type": type(error).__name__,
        "error": str(error)[:4096],
        "cleanup_complete": not cleanup_errors,
        "cleanup_errors": list(cleanup_errors),
        "completed_phases": [item.get("id") for item in completed_phases],
        "fresh_install_qualified": False,
        "release_admitted": False,
        "publishable": False,
    }


def collect(*, contract_path: Path, contract_sha256: str, package: Path,
            package_sha256: str, receipt_path: Path, receipt_sha256: str,
            snapshot: Path, snapshot_sha256: str, output: Path,
            confirmed_hostname: str, retained_state_confirmation: str,
            host_factory=NativeHost) -> dict:
    require(retained_state_confirmation == CONFIRM_RETAINED_STATE,
            "explicit retained-state acknowledgement is required")
    os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    pid_one = Path("/proc/1/comm").read_text(encoding="ascii").strip()
    validate_platform(os_release, platform.machine(), os.geteuid(), pid_one)
    original_inputs = validate_inputs(
        contract_path, contract_sha256, package, package_sha256,
        receipt_path, receipt_sha256, snapshot, snapshot_sha256,
    )
    prepare_output(output)
    host = None
    staging = None
    try:
        inputs, staging = stage_verified_inputs(original_inputs)
        host = host_factory(inputs, output, os_release)
        observed = host.execute(confirmed_hostname)
        require(set(observed) == {"host", "package", "phases", "traffic", "process", "resources"},
                "native host returned an incomplete observation")
        require(len(observed["phases"]) == len(inputs["contract"]["phases"]),
                "native lifecycle did not complete every phase")
        # Re-read every immutable input after the destructive lifecycle. The
        # observation is not emitted if a package, receipt, contract, or
        # snapshot changed while it was being exercised.
        for path, expected, label, maximum in (
            (contract_path, contract_sha256, "native contract", 4 * 1024 * 1024),
            (package, package_sha256, "Debian package", MAX_INPUT_BYTES),
            (receipt_path, receipt_sha256, "Debian build receipt", 4 * 1024 * 1024),
            (snapshot, snapshot_sha256, "compiled snapshot", 64 * 1024 * 1024),
        ):
            checked_digest(path, expected, label, maximum)
        build_source = inputs["build"]["source"]
        observation = {
            "schema_version": 1,
            "classification": inputs["verifier"].OBSERVATION_CLASS,
            "outcome": "passed",
            "captured_at": utc_now(),
            "contract": {
                "path": "packaging/release/debian/oss-native-fresh-install-contract.json",
                "sha256": inputs["contract_record"]["sha256"],
            },
            "source": {
                "repository": build_source["repository"],
                "commit": build_source["commit"],
                "tag": build_source["tag"],
                "dirty": build_source["dirty"],
            },
            **observed,
            "evidence_files": file_inventory(output),
            "qualifications": inputs["contract"]["qualifications"],
        }
        write_json(output / "observation.json", observation)
        report = inputs["verifier"].verify(
            inputs["contract_path"], output, inputs["package_path"], inputs["receipt_path"])
        require(report["outcome"] == "verified" and report["fresh_install_qualified"] is True and
                report["release_admitted"] is False and report["publishable"] is False,
                "independent native verifier did not accept the collected evidence")
        cleanup_staged_inputs(staging)
        staging = None
        return {"observation": observation, "verification": report}
    except BaseException as error:
        cleanup_errors: list[str] = []
        if host is not None:
            cleanup_errors.extend(host.safe_stop())
        if staging is not None:
            try:
                cleanup_staged_inputs(staging)
            except BaseException as cleanup_error:
                cleanup_errors.append(f"verified inputs: {cleanup_error}")
        write_json(output / "observation.json",
                   failure_observation(error, getattr(host, "phase_records", []),
                                       tuple(cleanup_errors)))
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--build-receipt-sha256", required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--snapshot-sha256", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument(
        "--confirm-disposable-host",
        required=True,
        help="Must exactly equal the current hostname.",
    )
    parser.add_argument(
        "--confirm-retained-state",
        required=True,
        help=f"Must equal {CONFIRM_RETAINED_STATE}.",
    )
    arguments = parser.parse_args(argv)
    os.umask(0o077)
    try:
        result = collect(
            contract_path=arguments.contract.absolute(),
            contract_sha256=arguments.contract_sha256,
            package=arguments.package.absolute(),
            package_sha256=arguments.package_sha256,
            receipt_path=arguments.build_receipt.absolute(),
            receipt_sha256=arguments.build_receipt_sha256,
            snapshot=arguments.snapshot.absolute(),
            snapshot_sha256=arguments.snapshot_sha256,
            output=arguments.evidence.absolute(),
            confirmed_hostname=arguments.confirm_disposable_host,
            retained_state_confirmation=arguments.confirm_retained_state,
        )
    except (OSError, Rejected, ValueError) as error:
        print(f"OSS native fresh-install collection failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({
        "outcome": "verified-fresh-install",
        "source_commit": result["verification"]["source_commit"],
        "source_tag": result["verification"]["source_tag"],
        "package_sha256": result["verification"]["package_sha256"],
        "fresh_install_qualified": True,
        "release_admitted": False,
        "publishable": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


