#!/usr/bin/env python3
"""Capture helpers for PERF-03 downstream TCP output attribution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import struct
import sys
from pathlib import Path


SAFE_INTEGER_MAX = (1 << 53) - 1
SUMMARY_FIELDS = (
    "calls",
    "requested_bytes",
    "completed_bytes",
    "partial_writes",
    "would_block",
    "fatal_errors",
    "entry_collisions",
    "zero_returns",
    "oversized_returns",
    "inflight",
)
AGGREGATE_FIELDS = SUMMARY_FIELDS[:-1]
END_SUMMARY = re.compile(r"^BONVOYAGE_SOCKET_OUTPUT_END inflight=([0-9]+)$")
AGGREGATE = re.compile(r"^@([a-z_]+):\s+([0-9]+)$")
LOST_EVENTS = re.compile(r"\blost\s+([0-9]+)\s+events?\b", re.IGNORECASE)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BOOT_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
IDENTITY_FIELDS = {
    "interval_id", "pid", "start_ticks", "restart_count", "boot_id",
    "executable_path", "executable_sha256", "snapshot_path",
    "snapshot_sha256", "cmdline_sha256", "response_path_diagnostics",
}
STABLE_RUNTIME_FIELDS = (
    "boot_id", "executable_path", "executable_sha256", "snapshot_path",
    "snapshot_sha256", "cmdline_sha256", "response_path_diagnostics",
)
MAX_DESCRIPTOR_ENTRIES = 4096
SOCKET_TARGET = re.compile(r"^socket:\[([0-9]+)\]$")
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def nonnegative_integer(value: object, label: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool),
            f"{label} must be an integer")
    require(0 <= value <= SAFE_INTEGER_MAX,
            f"{label} is outside the JSON safe-integer range")
    return value


def exact_keys(value: object, expected: set[str], label: str) -> dict:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == expected,
            f"{label} has missing or unexpected keys")
    return value


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def runtime_artifacts(pid: int, snapshot_file: Path,
                      proc_root: Path = Path("/proc")) -> dict:
    process_root = proc_root / str(pid)
    executable_link = process_root / "exe"
    executable_path = str(executable_link.resolve(strict=True))
    snapshot_path = str(snapshot_file.resolve(strict=True))
    cmdline = (process_root / "cmdline").read_bytes()
    require(cmdline.endswith(b"\0"), "gateway command line is incomplete")
    argv = cmdline[:-1].split(b"\0")
    require(argv and all(argv), "gateway command line is malformed")

    snapshot_arguments = []
    for index, argument in enumerate(argv):
        if argument == b"--snapshot":
            require(index + 1 < len(argv),
                    "gateway --snapshot argument has no value")
            snapshot_arguments.append(os.fsdecode(argv[index + 1]))
        elif argument.startswith(b"--snapshot="):
            snapshot_arguments.append(os.fsdecode(argument.split(b"=", 1)[1]))
    require(len(snapshot_arguments) == 1,
            "gateway must declare exactly one snapshot path")
    require(os.path.samefile(snapshot_arguments[0], snapshot_path),
            "gateway snapshot argument differs from the collector snapshot")

    boot_id = (proc_root / "sys/kernel/random/boot_id").read_text(
        encoding="ascii").strip().lower()
    require(BOOT_ID.fullmatch(boot_id) is not None,
            "kernel boot id is malformed")
    return {
        "boot_id": boot_id,
        "executable_path": executable_path,
        "executable_sha256": file_sha256(executable_link),
        "snapshot_path": snapshot_path,
        "snapshot_sha256": file_sha256(Path(snapshot_path)),
        "cmdline_sha256": hashlib.sha256(cmdline).hexdigest(),
        "response_path_diagnostics":
            b"--response-path-diagnostics" in argv,
    }


def load_identity(path: Path, interval_id: str, label: str) -> dict:
    value = exact_keys(json.loads(path.read_text(encoding="utf-8")),
                       IDENTITY_FIELDS, label)
    require(value["interval_id"] == interval_id,
            f"{label} interval differs from collector")
    require(nonnegative_integer(value["pid"], f"{label} pid") > 1,
            f"{label} pid must identify a process")
    require(nonnegative_integer(value["start_ticks"],
                                f"{label} start_ticks") > 0,
            f"{label} start_ticks must be positive")
    nonnegative_integer(value["restart_count"], f"{label} restart_count")
    require(isinstance(value["boot_id"], str) and
            BOOT_ID.fullmatch(value["boot_id"]) is not None,
            f"{label} boot_id is malformed")
    for field in ("executable_path", "snapshot_path"):
        require(isinstance(value[field], str) and value[field].startswith("/"),
                f"{label} {field} must be an absolute path")
    for field in ("executable_sha256", "snapshot_sha256", "cmdline_sha256"):
        require(isinstance(value[field], str) and
                SHA256.fullmatch(value[field]) is not None,
                f"{label} {field} is malformed")
    require(isinstance(value["response_path_diagnostics"], bool),
            f"{label} response_path_diagnostics must be a boolean")
    return value


def parse_trace(trace: str, stderr: str) -> tuple[dict[str, int], dict]:
    require(trace.splitlines().count("BONVOYAGE_SOCKET_OUTPUT_READY") == 1,
            "bpftrace readiness marker is missing or duplicated")
    end_matches = [match for line in trace.splitlines()
                   if (match := END_SUMMARY.fullmatch(line)) is not None]
    require(len(end_matches) == 1,
            "bpftrace end summary is missing or duplicated")
    values = {field: 0 for field in AGGREGATE_FIELDS}
    seen = set()
    for line in trace.splitlines():
        match = AGGREGATE.fullmatch(line)
        if match is None:
            require(not line.startswith("@"),
                    "bpftrace emitted an unexpected aggregate")
            continue
        field = match.group(1)
        require(field in values,
                "bpftrace emitted an unexpected aggregate")
        require(field not in seen,
                "bpftrace aggregate is duplicated")
        values[field] = nonnegative_integer(int(match.group(2)), field)
        seen.add(field)
    values["inflight"] = nonnegative_integer(
        int(end_matches[0].group(1)), "inflight")
    reported_lost_events = sum(
        int(match.group(1)) for match in LOST_EVENTS.finditer(stderr)
    )
    nonnegative_integer(reported_lost_events, "reported_lost_events")
    require("ERROR:" not in stderr,
            "bpftrace reported a collector error")

    require(values["calls"] > 0,
            "downstream TCP collector observed no calls")
    require(values["completed_bytes"] <= values["requested_bytes"],
            "completed bytes exceed requested bytes")
    require(values["partial_writes"] + values["would_block"] +
            values["fatal_errors"] <= values["calls"],
            "socket output classifications exceed calls")

    lost_events = (
        reported_lost_events
        + values["entry_collisions"]
        + values["zero_returns"]
        + values["oversized_returns"]
        + values["inflight"]
    )
    nonnegative_integer(lost_events, "lost_events")
    diagnostics = {
        "schema_version": 1,
        "collector": "bpftrace-tcp-sendmsg",
        "reported_lost_events": reported_lost_events,
        "entry_collisions": values["entry_collisions"],
        "zero_returns": values["zero_returns"],
        "oversized_returns": values["oversized_returns"],
        "inflight_at_detach": values["inflight"],
    }
    return {**values, "lost_events": lost_events}, diagnostics


def build_socket_output(
        trace: str,
        stderr: str,
        before: dict,
        after: dict,
        interval_id: str,
        duration_nanoseconds: int) -> tuple[dict, dict]:
    require(before["pid"] == after["pid"] and
            before["start_ticks"] == after["start_ticks"],
            "gateway process changed during socket collection")
    require(before["restart_count"] == after["restart_count"],
            "gateway service restarted during socket collection")
    for field in STABLE_RUNTIME_FIELDS:
        require(before[field] == after[field],
                f"gateway runtime identity changed: {field}")
    duration_nanoseconds = nonnegative_integer(
        duration_nanoseconds, "duration_nanoseconds")
    require(duration_nanoseconds > 0,
            "duration_nanoseconds must be positive")
    values, diagnostics = parse_trace(trace, stderr)
    diagnostics["service_restart_count"] = before["restart_count"]
    diagnostics["boot_id"] = before["boot_id"]
    diagnostics["executable_sha256"] = before["executable_sha256"]
    diagnostics["snapshot_sha256"] = before["snapshot_sha256"]
    diagnostics["cmdline_sha256"] = before["cmdline_sha256"]
    diagnostics["response_path_diagnostics"] = \
        before["response_path_diagnostics"]
    diagnostics["runtime_identity_stable"] = True
    output = {
        "interval_id": interval_id,
        "duration_nanoseconds": duration_nanoseconds,
        "scope": "gateway-downstream-sockets",
        "pid": before["pid"],
        "start_ticks": before["start_ticks"],
        "calls": values["calls"],
        "requested_bytes": values["requested_bytes"],
        "completed_bytes": values["completed_bytes"],
        "partial_writes": values["partial_writes"],
        "would_block": values["would_block"],
        "fatal_errors": values["fatal_errors"],
        "lost_events": values["lost_events"],
    }
    return output, diagnostics


def process_identity(service: str, interval_id: str,
                     snapshot_file: Path) -> dict:
    raw = subprocess.run([
        "systemctl", "show", service,
        "-p", "ActiveState", "-p", "MainPID", "-p", "NRestarts",
    ], check=True, text=True, capture_output=True).stdout
    fields = dict(line.split("=", 1) for line in raw.splitlines())
    require(fields.get("ActiveState") == "active",
            f"{service} is not active")
    pid = int(fields.get("MainPID", "0"))
    require(pid > 1, f"{service} has no live main process")
    stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    start_ticks = int(stat[stat.rfind(")") + 2:].split()[19])
    restart_count = int(fields.get("NRestarts", "0"))
    return {
        "interval_id": interval_id,
        "pid": pid,
        "start_ticks": start_ticks,
        "restart_count": restart_count,
        **runtime_artifacts(pid, snapshot_file),
    }


def resource_observation(identity: dict,
                         proc_root: Path = Path("/proc"),
                         descriptor_count: int | None = None) -> dict:
    process_root = proc_root / str(identity["pid"])
    status = (process_root / "status").read_text(encoding="ascii")
    rss_matches = [line.split() for line in status.splitlines()
                   if line.startswith("VmRSS:")]
    require(len(rss_matches) == 1 and len(rss_matches[0]) == 3 and
            rss_matches[0][2] == "kB",
            "gateway VmRSS is missing or malformed")
    rss_bytes = int(rss_matches[0][1]) * 1024
    descriptors = descriptor_count
    if descriptors is None:
        descriptors = sum(1 for _ in (process_root / "fd").iterdir())
    nonnegative_integer(rss_bytes, "rss_bytes")
    nonnegative_integer(descriptors, "file_descriptors")
    return {
        "identity": f"{identity['boot_id']}:{identity['pid']}:{identity['start_ticks']}",
        "pid": identity["pid"],
        "start_ticks": identity["start_ticks"],
        "restart_count": identity["restart_count"],
        "rss_bytes": rss_bytes,
        "file_descriptors": descriptors,
    }


def decode_proc_address(value: str, family: str) -> tuple[str, int]:
    encoded_address, encoded_port = value.split(":", 1)
    require(re.fullmatch(r"[0-9A-F]+", encoded_address) is not None and
            re.fullmatch(r"[0-9A-F]{4}", encoded_port) is not None,
            "TCP address is malformed")
    if family == "ipv4":
        require(len(encoded_address) == 8, "IPv4 TCP address is malformed")
        packed = bytes.fromhex(encoded_address)[::-1]
        address_family = socket.AF_INET
    else:
        require(family == "ipv6" and len(encoded_address) == 32,
                "IPv6 TCP address is malformed")
        words = [int(encoded_address[index:index + 8], 16)
                 for index in range(0, 32, 8)]
        packed = struct.pack("=4I", *words)
        address_family = socket.AF_INET6
    return socket.inet_ntop(address_family, packed), int(encoded_port, 16)


def tcp_socket_table(path: Path, family: str) -> dict[int, dict]:
    lines = path.read_text(encoding="ascii").splitlines()
    header = set(lines[0].split()) if lines else set()
    remote_labels = header & {"rem_address", "remote_address"}
    require("local_address" in header and len(remote_labels) == 1,
            "TCP table header is malformed")
    sockets = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        fields = line.split()
        require(len(fields) >= 10, "TCP table row is malformed")
        local_address, local_port = decode_proc_address(fields[1], family)
        remote_address, remote_port = decode_proc_address(fields[2], family)
        state_code = fields[3].upper()
        require(state_code in TCP_STATES, "TCP state is unsupported")
        queues = fields[4].split(":", 1)
        require(len(queues) == 2 and all(
            re.fullmatch(r"[0-9A-F]+", value) is not None
            for value in queues), "TCP queue counters are malformed")
        inode = nonnegative_integer(int(fields[9]), "TCP socket inode")
        # TIME_WAIT and other namespace-owned rows can carry inode zero. They
        # cannot identify a process descriptor and may legitimately repeat.
        if inode == 0:
            continue
        require(inode not in sockets, "TCP socket inode is duplicated")
        sockets[inode] = {
            "family": family,
            "local_address": local_address,
            "local_port": local_port,
            "remote_address": remote_address,
            "remote_port": remote_port,
            "state": TCP_STATES[state_code],
            "tx_queue_bytes": int(queues[0], 16),
            "rx_queue_bytes": int(queues[1], 16),
        }
    return sockets


def descriptor_observation(identity: dict,
                           proc_root: Path = Path("/proc")) -> dict:
    process_root = proc_root / str(identity["pid"])
    tcp_sockets = tcp_socket_table(process_root / "net/tcp", "ipv4")
    for inode, value in tcp_socket_table(
            process_root / "net/tcp6", "ipv6").items():
        require(inode not in tcp_sockets,
                "TCP socket inode appears in multiple protocol tables")
        tcp_sockets[inode] = value

    descriptor_root = process_root / "fd"
    entries = None
    for _ in range(3):
        names = sorted((entry.name for entry in descriptor_root.iterdir()
                        if entry.name.isdecimal()), key=int)
        require(len(names) <= MAX_DESCRIPTOR_ENTRIES,
                "gateway descriptor count exceeds collector bound")
        candidate_entries = []
        try:
            for name in names:
                target = os.readlink(descriptor_root / name)
                require(len(target) <= 4096,
                        "descriptor target exceeds collector bound")
                socket_match = SOCKET_TARGET.fullmatch(target)
                socket_inode = int(socket_match.group(1)) \
                    if socket_match else None
                tcp = tcp_sockets.get(socket_inode) \
                    if socket_inode is not None else None
                if tcp is not None:
                    kind = "tcp-socket"
                elif socket_inode is not None:
                    kind = "socket"
                elif target.startswith("pipe:["):
                    kind = "pipe"
                elif target.startswith("anon_inode:"):
                    kind = "anon-inode"
                elif target.startswith("/"):
                    kind = "file"
                else:
                    kind = "other"
                candidate_entries.append({
                    "fd": int(name),
                    "target": target,
                    "kind": kind,
                    "socket_inode": socket_inode,
                    "tcp": tcp,
                })
            entries = candidate_entries
            break
        except FileNotFoundError:
            # A just-closed socket can disappear between listing and readlink.
            continue
    require(entries is not None,
            "gateway descriptor table changed during bounded capture retries")
    return {
        "identity": f"{identity['boot_id']}:{identity['pid']}:{identity['start_ticks']}",
        "pid": identity["pid"],
        "start_ticks": identity["start_ticks"],
        "restart_count": identity["restart_count"],
        "total": len(entries),
        "entries": entries,
    }


def runtime_state_observation(identity: dict,
                              proc_root: Path = Path("/proc")) -> dict:
    descriptors = descriptor_observation(identity, proc_root)
    resource = resource_observation(identity, proc_root, descriptors["total"])
    return {"resource": resource, "descriptors": descriptors}


def reactor_tids(identity: dict, expected_count: int,
                 proc_root: Path = Path("/proc")) -> list[int]:
    require(0 < expected_count <= 512, "expected reactor count is invalid")
    task_root = proc_root / str(identity["pid"]) / "task"
    main_tid = int(identity["pid"])
    main_thread_seen = False
    reactors = {}
    for entry in task_root.iterdir():
        if not entry.is_dir() or not entry.name.isdecimal():
            continue
        tid = int(entry.name)
        name = (entry / "comm").read_text(encoding="ascii").strip()
        if tid == main_tid:
            main_thread_seen = True
        match = re.fullmatch(r"reactor-([0-9]+)", name)
        if match is None:
            continue
        shard = int(match.group(1))
        require(shard != 0 or tid == main_tid,
                "Seastar shard 0 must be the process main thread")
        require(shard not in reactors, "duplicate Seastar reactor shard")
        reactors[shard] = tid
    if 0 not in reactors:
        require(main_thread_seen,
                "Seastar process main thread is missing")
        reactors[0] = main_tid
    require(set(reactors) == set(range(expected_count)),
            "stable Seastar reactor thread set is incomplete")
    return [reactors[shard] for shard in range(expected_count)]


def cpu_list(value: str) -> list[int]:
    require(bool(re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", value)),
            "CPU list syntax is invalid")
    result = []
    for item in value.split(","):
        bounds = [int(part) for part in item.split("-")]
        require(len(bounds) in (1, 2), "CPU list range is invalid")
        first, last = bounds[0], bounds[-1]
        require(0 <= first <= last and last - first < 4096,
                "CPU list range is invalid")
        result.extend(range(first, last + 1))
    require(result and len(result) == len(set(result)),
            "CPU list is empty or duplicated")
    return result


def thread_processor(path: Path) -> int:
    body = path.read_text(encoding="ascii")
    require(body.startswith(path.parent.name + " (") and ") " in body,
            "reactor stat identity is malformed")
    fields = body[body.rfind(")") + 2:].split()
    require(len(fields) > 36 and fields[36].isdecimal(),
            "reactor current CPU is missing")
    return int(fields[36])


def reactor_placement(identity: dict, expected_count: int,
                      proc_root: Path = Path("/proc")) -> dict:
    tids = reactor_tids(identity, expected_count, proc_root)
    task_root = proc_root / str(identity["pid"]) / "task"
    bindings = []
    for shard, tid in enumerate(tids):
        thread = task_root / str(tid)
        matches = [line.split(":", 1)[1].strip()
                   for line in (thread / "status").read_text(
                       encoding="ascii").splitlines()
                   if line.startswith("Cpus_allowed_list:")]
        require(len(matches) == 1, "reactor allowed CPU list is missing")
        allowed = cpu_list(matches[0])
        require(len(allowed) == 1,
                "Seastar reactor must be pinned to exactly one CPU")
        current = thread_processor(thread / "stat")
        require(current in allowed,
                "reactor current CPU is outside its allowed CPU set")
        bindings.append({
            "shard": shard,
            "tid": tid,
            "allowed_cpus": allowed,
            "current_cpu": current,
        })
    return {"reactor_tids": tids, "reactor_bindings": bindings}


def write_json(path: Path, value: dict) -> None:
    serialized = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if path == Path("-"):
        sys.stdout.write(serialized)
        return
    path.write_text(serialized, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    identity = subparsers.add_parser("identity")
    identity.add_argument("--service", required=True)
    identity.add_argument("--interval-id", required=True)
    identity.add_argument("--snapshot-file", required=True, type=Path)
    identity.add_argument("--output", required=True, type=Path)

    resource = subparsers.add_parser("resource")
    resource.add_argument("--service", required=True)
    resource.add_argument("--interval-id", required=True)
    resource.add_argument("--snapshot-file", required=True, type=Path)
    resource.add_argument("--output", required=True, type=Path)

    state = subparsers.add_parser("state")
    state.add_argument("--service", required=True)
    state.add_argument("--interval-id", required=True)
    state.add_argument("--snapshot-file", required=True, type=Path)
    state.add_argument("--output", required=True, type=Path)

    reactors = subparsers.add_parser("reactors")
    reactors.add_argument("--service", required=True)
    reactors.add_argument("--interval-id", required=True)
    reactors.add_argument("--snapshot-file", required=True, type=Path)
    reactors.add_argument("--expected-count", required=True, type=int)
    reactors.add_argument("--output", required=True, type=Path)

    parse = subparsers.add_parser("parse")
    parse.add_argument("--trace", required=True, type=Path)
    parse.add_argument("--stderr", required=True, type=Path)
    parse.add_argument("--process-before", required=True, type=Path)
    parse.add_argument("--process-after", required=True, type=Path)
    parse.add_argument("--interval-id", required=True)
    parse.add_argument("--duration-nanoseconds", required=True, type=int)
    parse.add_argument("--output", required=True, type=Path)
    parse.add_argument("--diagnostics", required=True, type=Path)

    args = parser.parse_args()
    if args.command == "identity":
        write_json(args.output, process_identity(args.service,
                                                 args.interval_id,
                                                 args.snapshot_file))
        return

    if args.command in ("resource", "state", "reactors"):
        identity_value = process_identity(args.service, args.interval_id,
                                          args.snapshot_file)
        if args.command == "resource":
            write_json(args.output, resource_observation(identity_value))
        elif args.command == "state":
            write_json(args.output, runtime_state_observation(identity_value))
        else:
            write_json(args.output, reactor_placement(
                identity_value, args.expected_count))
        return

    before = load_identity(args.process_before, args.interval_id,
                           "process_before")
    after = load_identity(args.process_after, args.interval_id,
                          "process_after")
    output, diagnostics = build_socket_output(
        args.trace.read_text(encoding="utf-8"),
        args.stderr.read_text(encoding="utf-8"),
        before,
        after,
        args.interval_id,
        args.duration_nanoseconds,
    )
    write_json(args.output, output)
    write_json(args.diagnostics, diagnostics)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError, ValueError,
            json.JSONDecodeError) as error:
        print(f"linux-socket-output: {error}", file=sys.stderr)
        raise SystemExit(1) from error
