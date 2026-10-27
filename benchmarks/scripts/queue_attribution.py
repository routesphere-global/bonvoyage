#!/usr/bin/env python3
"""Capture and compare read-only Linux gateway queue-attribution snapshots."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


METRIC_NAMES = {
    "bonvoyage_bonvoyage_gateway_requests_total",
    "bonvoyage_bonvoyage_gateway_responses_2xx_total",
    "bonvoyage_bonvoyage_gateway_responses_3xx_total",
    "bonvoyage_bonvoyage_gateway_responses_4xx_total",
    "bonvoyage_bonvoyage_gateway_responses_5xx_total",
    "bonvoyage_bonvoyage_gateway_downstream_connections_accepted_total",
    "bonvoyage_bonvoyage_gateway_downstream_connection_rejections_total",
    "bonvoyage_bonvoyage_gateway_overload_rejections_total",
    "bonvoyage_bonvoyage_gateway_route_overload_rejections_total",
    "bonvoyage_bonvoyage_gateway_route_rate_limit_rejections_total",
    "bonvoyage_bonvoyage_gateway_jwt_verification_overload_rejections_total",
    "bonvoyage_bonvoyage_gateway_cluster_overload_rejections_total",
    "bonvoyage_bonvoyage_gateway_endpoint_overload_rejections_total",
    "bonvoyage_bonvoyage_gateway_endpoint_circuit_probe_rejections_total",
    "bonvoyage_bonvoyage_gateway_upstream_failures_total",
    "bonvoyage_bonvoyage_gateway_request_timeouts_total",
    "bonvoyage_bonvoyage_gateway_upstream_endpoint_selections_total",
    "bonvoyage_bonvoyage_gateway_upstream_http1_pool_waits_total",
    "bonvoyage_bonvoyage_gateway_upstream_http2_pool_waits_total",
    "bonvoyage_bonvoyage_gateway_response_path_flush_wait_operations_total",
    "bonvoyage_bonvoyage_gateway_response_path_flush_wait_nanoseconds_total",
    "bonvoyage_bonvoyage_gateway_response_path_diagnostics_enabled",
    "bonvoyage_bonvoyage_gateway_active_requests",
    "bonvoyage_bonvoyage_gateway_active_route_requests",
    "bonvoyage_bonvoyage_gateway_active_connections",
    "bonvoyage_bonvoyage_gateway_active_upstream_requests",
    "bonvoyage_bonvoyage_gateway_active_upstream_http1_requests",
    "bonvoyage_bonvoyage_gateway_active_upstream_http2_streams",
    "bonvoyage_bonvoyage_gateway_configured_upstream_http1_connections",
    "bonvoyage_reactor_cpu_busy_ms",
    "bonvoyage_reactor_cpu_steal_time_ms",
    "bonvoyage_reactor_tasks_pending",
    "bonvoyage_reactor_tasks_processed",
    "bonvoyage_reactor_utilization",
    "bonvoyage_scheduler_queue_length",
    "bonvoyage_scheduler_runtime_ms",
    "bonvoyage_scheduler_starvetime_ms",
    "bonvoyage_scheduler_waittime_ms",
    "bonvoyage_network_bytes_received",
    "bonvoyage_network_bytes_sent",
    "bonvoyage_memory_malloc_operations",
}

COUNTER_METRICS = {
    name for name in METRIC_NAMES
    if name.endswith("_total") or name in {
        "bonvoyage_reactor_cpu_busy_ms",
        "bonvoyage_reactor_cpu_steal_time_ms",
        "bonvoyage_reactor_tasks_processed",
        "bonvoyage_scheduler_runtime_ms",
        "bonvoyage_scheduler_starvetime_ms",
        "bonvoyage_scheduler_waittime_ms",
        "bonvoyage_network_bytes_received",
        "bonvoyage_network_bytes_sent",
        "bonvoyage_memory_malloc_operations",
    }
}

# ENA exposes this availability value beside monotonic packet and allowance
# counters. It may move in either direction as flows are opened and released.
ETHTOOL_GAUGE_NAMES = {"conntrack_allowance_available"}

TRACE_GAUGE_METRICS = {
    "bonvoyage_reactor_utilization",
    "bonvoyage_reactor_tasks_pending",
    "bonvoyage_scheduler_queue_length",
    "bonvoyage_bonvoyage_gateway_response_path_diagnostics_enabled",
    "bonvoyage_bonvoyage_gateway_active_requests",
    "bonvoyage_bonvoyage_gateway_active_route_requests",
    "bonvoyage_bonvoyage_gateway_active_connections",
    "bonvoyage_bonvoyage_gateway_active_upstream_requests",
    "bonvoyage_bonvoyage_gateway_active_upstream_http1_requests",
    "bonvoyage_bonvoyage_gateway_active_upstream_http2_streams",
    "bonvoyage_bonvoyage_gateway_configured_upstream_http1_connections",
}

LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')
SAMPLE = re.compile(
    r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+"
    r"([-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?|NaN|[+-]Inf)$"
)

CLOCKSOURCE_ROOT = Path("/sys/devices/system/clocksource/clocksource0")
TSC_CAPABILITY_FLAGS = (
    "tsc",
    "rdtscp",
    "constant_tsc",
    "nonstop_tsc",
    "tsc_known_freq",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def run(*argv: str) -> str:
    return subprocess.run(argv, check=True, text=True, capture_output=True).stdout


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def parse_prometheus(text: str) -> list[dict]:
    samples = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = SAMPLE.fullmatch(line.strip())
        if match is None or match.group(1) not in METRIC_NAMES:
            continue
        labels = {
            key: bytes(value, "utf-8").decode("unicode_escape")
            for key, value in LABEL.findall(match.group(2) or "")
        }
        value = float(match.group(3))
        require(value == value and abs(value) != float("inf"),
                f"non-finite metric sample: {line}")
        samples.append({"name": match.group(1), "labels": labels, "value": value})
    names = {sample["name"] for sample in samples}
    missing = METRIC_NAMES - names
    require(not missing, "missing attribution metrics: " + ", ".join(sorted(missing)))
    return sorted(samples, key=lambda item: (
        item["name"], json.dumps(item["labels"], sort_keys=True)))


def parse_cpu_table(text: str) -> dict:
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    require(lines and lines[0].split()[0].startswith("CPU"),
            "CPU table header is missing")
    cpus = lines[0].split()
    rows = {}
    for line in lines[1:]:
        name, separator, rest = line.partition(":")
        if not separator:
            continue
        fields = rest.split()
        if len(fields) < len(cpus) or not all(
                field.isdigit() for field in fields[:len(cpus)]):
            continue
        rows[name.strip()] = {
            "counts": [int(value) for value in fields[:len(cpus)]],
            "description": " ".join(fields[len(cpus):]),
        }
    require(rows, "CPU table contains no numeric rows")
    return {"cpus": cpus, "rows": rows}


def parse_softnet(text: str) -> list[dict]:
    names = (
        "processed", "dropped", "time_squeeze", "zero3", "zero4",
        "zero5", "zero6", "zero7", "cpu_collision", "received_rps",
        "flow_limit_count",
    )
    result = []
    for cpu, line in enumerate(line for line in text.splitlines() if line.strip()):
        values = [int(field, 16) for field in line.split()]
        require(len(values) >= len(names), "softnet row has too few fields")
        result.append({"cpu": cpu, **dict(zip(names, values)), "raw": values})
    require(result, "softnet statistics are empty")
    return result


def parse_proc_stat(text: str) -> dict:
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields or not re.fullmatch(r"cpu[0-9]+", fields[0]):
            continue
        require(all(field.isdigit() for field in fields[1:]),
                "invalid /proc/stat CPU row")
        result[fields[0]] = [int(field) for field in fields[1:]]
    require(result, "/proc/stat contains no per-CPU rows")
    return result


def parse_ethtool_stats(text: str) -> dict[str, int]:
    result = {}
    for line in text.splitlines():
        key, separator, value = line.strip().partition(":")
        if separator and value.strip().isdigit():
            result[key.strip()] = int(value.strip())
    return result


def parse_clock_identity(current: str, available: str, cpu_flags: str) -> dict:
    current_name = current.strip()
    available_names = available.split()
    flags = set(cpu_flags.split())
    require(bool(current_name), "current clocksource is empty")
    require(current_name in available_names,
            "current clocksource is not listed as available")
    return {
        "current_clocksource": current_name,
        "available_clocksources": available_names,
        "tsc_capabilities": {
            name: name in flags for name in TSC_CAPABILITY_FLAGS
        },
    }


def first_cpu_flags() -> str:
    cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    for line in cpuinfo.splitlines():
        name, separator, value = line.partition(":")
        if separator and name.strip() in {"flags", "Features"}:
            flags = value.strip()
            require(bool(flags), "CPU capability flags are empty")
            return flags + "\n"
    raise ValueError("CPU capability flags are unavailable")


def process_identity(service: str) -> tuple[dict, str]:
    raw = run("systemctl", "show", service, "-p", "Id", "-p", "ActiveState",
              "-p", "MainPID", "-p", "NRestarts")
    fields = dict(line.split("=", 1) for line in raw.splitlines())
    require(fields.get("ActiveState") == "active", f"{service} is not active")
    pid = int(fields.get("MainPID", "0"))
    require(pid > 1, f"{service} has no live main process")
    stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    start_ticks = stat[stat.rfind(")") + 2:].split()[19]
    status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    executable = Path(f"/proc/{pid}/exe").resolve()
    affinity = next(
        line.split(":", 1)[1].strip() for line in status.splitlines()
        if line.startswith("Cpus_allowed_list:")
    )
    rss_line = next(
        (line for line in status.splitlines() if line.startswith("VmRSS:")),
        None,
    )
    require(rss_line is not None, f"{service} process RSS is unavailable")
    rss_fields = rss_line.split()
    require(len(rss_fields) >= 2 and rss_fields[1].isdigit(),
            f"{service} process RSS is invalid")
    fd_count = sum(1 for _ in Path(f"/proc/{pid}/fd").iterdir())
    return ({
        "service": fields["Id"],
        "pid": pid,
        "start_ticks": int(start_ticks),
        "restarts": int(fields.get("NRestarts", "0")),
        "cpu_affinity": affinity,
        "executable": str(executable),
        "executable_sha256": sha256(executable),
        "rss_kib": int(rss_fields[1]),
        "fd_count": fd_count,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="utf-8").strip(),
    }, raw)


def default_interface() -> str:
    for line in Path("/proc/net/route").read_text(encoding="utf-8").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 2:
            return fields[0]
    raise ValueError("default-route interface was not found")


def source_identity(repository: Path) -> dict:
    try:
        commit = run("git", "-C", str(repository), "rev-parse", "HEAD").strip()
        dirty = bool(run("git", "-C", str(repository), "status", "--porcelain"))
        return {"commit": commit, "dirty": dirty}
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {"commit": None, "dirty": None}


def write_capture(args: argparse.Namespace) -> None:
    output = args.output.resolve()
    require(not output.exists(), f"output already exists: {output}")
    output.mkdir(mode=0o700, parents=True)
    interface = args.interface or default_interface()
    identity, service_raw = process_identity(args.service)
    sources = {
        "interrupts.txt": Path("/proc/interrupts").read_text(encoding="utf-8"),
        "softirqs.txt": Path("/proc/softirqs").read_text(encoding="utf-8"),
        "softnet-stat.txt": Path("/proc/net/softnet_stat").read_text(encoding="utf-8"),
        "proc-stat.txt": Path("/proc/stat").read_text(encoding="utf-8"),
        "clocksource-current.txt": (CLOCKSOURCE_ROOT / "current_clocksource")
            .read_text(encoding="utf-8"),
        "clocksource-available.txt": (CLOCKSOURCE_ROOT / "available_clocksource")
            .read_text(encoding="utf-8"),
        "cpu-flags.txt": first_cpu_flags(),
        "ethtool-stats.txt": run("ethtool", "-S", interface),
        "service.txt": service_raw,
        "metrics.prom": urllib.request.urlopen(args.metrics_url, timeout=5).read().decode("utf-8"),
    }
    for name, value in sources.items():
        (output / name).write_text(value, encoding="utf-8")
    interrupts = parse_cpu_table(sources["interrupts.txt"])
    nic_irqs = {
        irq: row for irq, row in interrupts["rows"].items()
        if interface in row["description"] or "ena" in row["description"].lower()
    }
    snapshot = {
        "schema_version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "monotonic_ns": time.monotonic_ns(),
        "hostname": socket.gethostname(),
        "interface": interface,
        "clock": parse_clock_identity(
            sources["clocksource-current.txt"],
            sources["clocksource-available.txt"],
            sources["cpu-flags.txt"],
        ),
        "process": identity,
        "source": source_identity(args.repository.resolve()),
        "collector_sha256": sha256(Path(__file__).resolve()),
        "metrics": parse_prometheus(sources["metrics.prom"]),
        "interrupts": {"cpus": interrupts["cpus"], "rows": nic_irqs},
        "softirqs": parse_cpu_table(sources["softirqs.txt"]),
        "softnet": parse_softnet(sources["softnet-stat.txt"]),
        "proc_stat": parse_proc_stat(sources["proc-stat.txt"]),
        "ethtool": parse_ethtool_stats(sources["ethtool-stats.txt"]),
    }
    (output / "snapshot.json").write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    files = []
    for path in sorted(output.iterdir()):
        if path.is_file():
            files.append({"path": path.name, "bytes": path.stat().st_size,
                          "sha256": sha256(path)})
            path.chmod(0o600)
    (output / "checksums.json").write_text(
        json.dumps({"schema_version": 1, "files": files}, indent=2,
                   sort_keys=True) + "\n", encoding="utf-8")
    (output / "checksums.json").chmod(0o600)


def verify_capture(path: Path) -> dict:
    manifest_path = path / "checksums.json"
    require(manifest_path.is_file(), f"checksum manifest is missing: {path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("schema_version") == 1,
            "unsupported checksum manifest schema")
    entries = manifest.get("files")
    require(isinstance(entries, list) and entries,
            "checksum manifest contains no files")
    verified = set()
    for entry in entries:
        relative = entry.get("path")
        require(isinstance(relative, str) and relative and "/" not in relative,
                "checksum manifest contains an invalid path")
        file_path = path / relative
        require(file_path.is_file(), f"captured file is missing: {relative}")
        require(file_path.stat().st_size == entry.get("bytes"),
                f"captured file size changed: {relative}")
        require(sha256(file_path) == entry.get("sha256"),
                f"captured file checksum changed: {relative}")
        verified.add(relative)
    require("snapshot.json" in verified,
            "checksum manifest does not bind snapshot.json")
    return json.loads((path / "snapshot.json").read_text(encoding="utf-8"))


def series_key(sample: dict) -> tuple:
    return sample["name"], tuple(sorted(sample["labels"].items()))


def delta_map(before: dict, after: dict, label: str) -> dict:
    require(before.keys() == after.keys(), f"{label} identity changed")
    result = {}
    for key in before:
        left = before[key]
        right = after[key]
        if isinstance(left, list) or isinstance(right, list):
            require(isinstance(left, list) and isinstance(right, list),
                    f"{label} counter shape changed: {key}")
            require(len(left) == len(right),
                    f"{label} CPU count changed: {key}")
            values = [value - left[index] for index, value in enumerate(right)]
            require(all(value >= 0 for value in values),
                    f"{label} counter regressed: {key}")
            result[key] = values
            continue
        value = right - left
        require(value >= 0, f"{label} counter regressed: {key}")
        result[key] = value
    return result


def imbalance(values: dict) -> float | None:
    if not values:
        return None
    mean = sum(values.values()) / len(values)
    return None if mean == 0 else (max(values.values()) - min(values.values())) / mean


def metric_by_shard(samples: list[dict], name: str) -> dict[int, float]:
    result = {}
    for sample in samples:
        if sample["name"] != name or "shard" not in sample["labels"]:
            continue
        if sample["labels"].get("group", "main") != "main":
            continue
        shard = int(sample["labels"]["shard"])
        result[shard] = result.get(shard, 0.0) + sample["value"]
    return result


def trace_gauge_summary(rows: list[tuple[datetime, list[dict]]],
                        name: str) -> dict:
    series = [metric_by_shard(samples, name) for _, samples in rows]
    require(series and series[0], f"trace metric has no shard samples: {name}")
    shard_ids = set(series[0])
    require(all(set(values) == shard_ids for values in series),
            f"trace metric shard identity changed: {name}")
    by_shard = {
        shard: [values[shard] for values in series]
        for shard in sorted(shard_ids)
    }
    totals = [sum(values.values()) for values in series]
    return {
        "total_peak": max(totals),
        "total_mean": sum(totals) / len(totals),
        "per_shard_mean": {
            str(shard): sum(values) / len(values)
            for shard, values in by_shard.items()
        },
        "per_shard_peak": {
            str(shard): max(values) for shard, values in by_shard.items()
        },
    }


def analyze_trace(rows: list[tuple[datetime, list[dict]]]) -> dict:
    require(len(rows) >= 2, "trace interval requires at least two samples")
    require(all(rows[index][0] < rows[index + 1][0]
                for index in range(len(rows) - 1)),
            "trace timestamps are not strictly increasing")
    request_name = "bonvoyage_bonvoyage_gateway_requests_total"
    request_series = [
        (captured_at, sum(metric_by_shard(samples, request_name).values()))
        for captured_at, samples in rows
    ]
    interval_rates = []
    for (left_time, left), (right_time, right) in zip(
            request_series, request_series[1:]):
        elapsed = (right_time - left_time).total_seconds()
        require(elapsed > 0, "trace interval is not positive")
        delta = right - left
        require(delta >= 0, "trace request counter regressed")
        interval_rates.append(delta / elapsed)
    duration = (rows[-1][0] - rows[0][0]).total_seconds()
    request_delta = request_series[-1][1] - request_series[0][1]
    return {
        "schema_version": 1,
        "evidence_class": "diagnostic_time_series_not_capacity_qualification",
        "analyzer_sha256": sha256(Path(__file__).resolve()),
        "window": {
            "start": rows[0][0].isoformat(),
            "end": rows[-1][0].isoformat(),
            "duration_seconds": duration,
            "samples": len(rows),
        },
        "requests": {
            "delta": request_delta,
            "mean_per_second": request_delta / duration,
            "minimum_interval_per_second": min(interval_rates),
            "maximum_interval_per_second": max(interval_rates),
        },
        "gauges": {
            name: trace_gauge_summary(rows, name)
            for name in sorted(TRACE_GAUGE_METRICS)
        },
        "limits": [
            "Prometheus gauges are point samples and may miss sub-second peaks.",
            "This time series supports attribution; it is not a capacity verdict.",
        ],
    }


def cpu_busy(before: list[int], after: list[int]) -> float:
    deltas = [right - left for left, right in zip(before, after)]
    require(deltas and all(value >= 0 for value in deltas), "CPU counters regressed")
    total = sum(deltas)
    idle = sum(deltas[index] for index in (3, 4) if index < len(deltas))
    return 0.0 if total == 0 else (total - idle) / total


def analyze(before: dict, after: dict) -> dict:
    require(before["schema_version"] == after["schema_version"] == 1,
            "unsupported attribution snapshot schema")
    for field in ("hostname", "interface", "collector_sha256"):
        require(before[field] == after[field], f"{field} changed during interval")
    before_clock = before.get("clock")
    after_clock = after.get("clock")
    require((before_clock is None) == (after_clock is None),
            "clock identity availability changed during interval")
    if before_clock is not None:
        require(isinstance(before_clock, dict) and isinstance(after_clock, dict),
                "clock identity is invalid")
        require(before_clock == after_clock,
                "clock identity changed during interval")
    for field in ("service", "pid", "start_ticks", "restarts", "boot_id",
                  "executable", "executable_sha256"):
        require(before["process"][field] == after["process"][field],
                f"gateway process identity changed: {field}")
    duration = (after["monotonic_ns"] - before["monotonic_ns"]) / 1e9
    require(duration > 0, "attribution interval is not positive")

    before_series = {series_key(item): item["value"] for item in before["metrics"]}
    after_series = {series_key(item): item["value"] for item in after["metrics"]}
    require(before_series.keys() == after_series.keys(), "metric series changed")
    metric_deltas = {}
    for key, left in before_series.items():
        if key[0] not in COUNTER_METRICS:
            continue
        value = after_series[key] - left
        require(value >= 0, f"metric counter regressed: {key}")
        metric_deltas[key] = value

    def shard_delta(name: str) -> dict[int, float]:
        left = metric_by_shard(before["metrics"], name)
        right = metric_by_shard(after["metrics"], name)
        return delta_map(left, right, name)

    def shard_edges(name: str) -> dict[int, dict[str, float]]:
        left = metric_by_shard(before["metrics"], name)
        right = metric_by_shard(after["metrics"], name)
        require(left.keys() == right.keys(), f"{name} shard identity changed")
        return {
            shard: {
                "before": left[shard],
                "after": right[shard],
                "change": right[shard] - left[shard],
            }
            for shard in sorted(left)
        }

    requests = shard_delta("bonvoyage_bonvoyage_gateway_requests_total")
    accepts = shard_delta(
        "bonvoyage_bonvoyage_gateway_downstream_connections_accepted_total")
    pool_waits = shard_delta(
        "bonvoyage_bonvoyage_gateway_upstream_http1_pool_waits_total")
    perf04_counter_names = {
        name.removeprefix("bonvoyage_bonvoyage_gateway_")
        .removeprefix("bonvoyage_"): name
        for name in METRIC_NAMES if name in COUNTER_METRICS
    }
    perf04_counters = {
        short_name: shard_delta(metric_name)
        for short_name, metric_name in sorted(perf04_counter_names.items())
    }
    perf04_gauge_names = {
        name.removeprefix("bonvoyage_bonvoyage_gateway_")
        .removeprefix("bonvoyage_"): name
        for name in TRACE_GAUGE_METRICS
    }
    perf04_gauges = {
        short_name: shard_edges(metric_name)
        for short_name, metric_name in sorted(perf04_gauge_names.items())
    }
    reactor_busy = shard_delta("bonvoyage_reactor_cpu_busy_ms")
    scheduler_runtime = shard_delta("bonvoyage_scheduler_runtime_ms")
    scheduler_wait = shard_delta("bonvoyage_scheduler_waittime_ms")
    malloc_operations = shard_delta("bonvoyage_memory_malloc_operations")
    network_rx = shard_delta("bonvoyage_network_bytes_received")
    network_tx = shard_delta("bonvoyage_network_bytes_sent")

    irq_before = {
        irq: row["counts"] for irq, row in before["interrupts"]["rows"].items()}
    irq_after = {
        irq: row["counts"] for irq, row in after["interrupts"]["rows"].items()}
    require(before["interrupts"]["cpus"] == after["interrupts"]["cpus"],
            "interrupt CPU columns changed")
    irq_deltas = delta_map(irq_before, irq_after, "NIC IRQ")

    softirq = {}
    for name in ("NET_RX", "NET_TX"):
        left = before["softirqs"]["rows"].get(name, {}).get("counts")
        right = after["softirqs"]["rows"].get(name, {}).get("counts")
        require(left is not None and right is not None and len(left) == len(right),
                f"softirq row changed: {name}")
        softirq[name] = [value - left[index] for index, value in enumerate(right)]
        require(all(value >= 0 for value in softirq[name]),
                f"softirq counter regressed: {name}")

    require(len(before["softnet"]) == len(after["softnet"]),
            "softnet CPU count changed")
    softnet = []
    for left, right in zip(before["softnet"], after["softnet"]):
        require(left["cpu"] == right["cpu"], "softnet CPU identity changed")
        record = {"cpu": left["cpu"]}
        for name in ("processed", "dropped", "time_squeeze", "received_rps",
                     "flow_limit_count"):
            record[name] = right[name] - left[name]
            require(record[name] >= 0, f"softnet counter regressed: {name}")
        softnet.append(record)

    require(before["ethtool"].keys() == after["ethtool"].keys(),
            "ethtool identity changed")
    ethtool_counter_before = {
        key: value for key, value in before["ethtool"].items()
        if key not in ETHTOOL_GAUGE_NAMES
    }
    ethtool_counter_after = {
        key: value for key, value in after["ethtool"].items()
        if key not in ETHTOOL_GAUGE_NAMES
    }
    ethtool = delta_map(
        ethtool_counter_before, ethtool_counter_after, "ethtool")
    ethtool_gauges = {
        key: {
            "before": before["ethtool"][key],
            "after": after["ethtool"][key],
            "change": after["ethtool"][key] - before["ethtool"][key],
        }
        for key in sorted(ETHTOOL_GAUGE_NAMES & before["ethtool"].keys())
    }
    require(before["proc_stat"].keys() == after["proc_stat"].keys(),
            "CPU identity changed")
    cpu = {
        name: cpu_busy(values, after["proc_stat"][name])
        for name, values in before["proc_stat"].items()
    }
    irq_cpu = {}
    for name, values in before["proc_stat"].items():
        deltas = [right - left for left, right in
                  zip(values[:8], after["proc_stat"][name][:8])]
        total = sum(deltas)
        irq_cpu[name] = 0.0 if total == 0 else (
            sum(deltas[index] for index in (5, 6) if index < len(deltas)) / total)

    request_imbalance = imbalance(requests)
    connection_imbalance = imbalance(accepts)
    if sum(pool_waits.values()) > 0:
        observation = "upstream_http1_pool_pressure_observed"
    elif (connection_imbalance or 0) > 0.20 and (request_imbalance or 0) > 0.20:
        observation = "connection_acceptance_imbalance_observed"
    elif (request_imbalance or 0) > 0.20:
        observation = "request_distribution_imbalance_observed"
    else:
        observation = "no_primary_imbalance_observed"

    return {
        "schema_version": 1,
        "analyzer_sha256": sha256(Path(__file__).resolve()),
        "capture_collector_sha256": before["collector_sha256"],
        "evidence_class": "diagnostic_attribution_not_capacity_qualification",
        "hostname": before["hostname"],
        "duration_seconds": duration,
        "clock": before_clock,
        "process_identity_stable": True,
        "process": before["process"],
        "source": before["source"],
        "source_unchanged": before["source"] == after["source"],
        "observation": observation,
        "limits": [
            "Thresholds classify the observed interval; they do not prove root cause.",
            "ENA, IRQ, softirq, reactor, connection, request and pool signals require time correlation.",
            "The collector does not tune, restart or mutate the gateway or host.",
        ],
        "gateway": {
            "requests_by_shard": requests,
            "accepted_connections_by_shard": accepts,
            "upstream_http1_pool_waits_by_shard": pool_waits,
            "reactor_cpu_busy_ms_by_shard": reactor_busy,
            "scheduler_runtime_ms_by_shard": scheduler_runtime,
            "scheduler_waittime_ms_by_shard": scheduler_wait,
            "memory_malloc_operations_by_shard": malloc_operations,
            "network_rx_bytes_by_shard": network_rx,
            "network_tx_bytes_by_shard": network_tx,
            "request_imbalance_ratio": request_imbalance,
            "connection_imbalance_ratio": connection_imbalance,
            "perf04_counter_deltas_by_shard": perf04_counters,
            "perf04_gauge_edges_by_shard": perf04_gauges,
        },
        "resources": {
            "rss_kib": {
                "before": before["process"].get("rss_kib"),
                "after": after["process"].get("rss_kib"),
                "change": (
                    after["process"]["rss_kib"] - before["process"]["rss_kib"]
                    if "rss_kib" in before["process"] and
                    "rss_kib" in after["process"] else None
                ),
            },
            "file_descriptors": {
                "before": before["process"].get("fd_count"),
                "after": after["process"].get("fd_count"),
                "change": (
                    after["process"]["fd_count"] - before["process"]["fd_count"]
                    if "fd_count" in before["process"] and
                    "fd_count" in after["process"] else None
                ),
            },
        },
        "host": {
            "cpu_busy_ratio": cpu,
            "irq_cpu_busy_ratio": irq_cpu,
            "nic_irq_deltas": irq_deltas,
            "softirq_deltas": softirq,
            "softnet_deltas": softnet,
            "ethtool_deltas": ethtool,
            "ethtool_gauges": ethtool_gauges,
        },
    }


def write_analysis(args: argparse.Namespace) -> None:
    before = verify_capture(args.before)
    after = verify_capture(args.after)
    result = analyze(before, after)
    require(not args.output.exists(), f"output already exists: {args.output}")
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, "trace timestamp requires a timezone")
    return parsed


def write_trace_analysis(args: argparse.Namespace) -> None:
    start = parse_timestamp(args.start)
    end = parse_timestamp(args.end)
    require(start < end, "trace start must precede trace end")
    rows = []
    timestamp_paths = sorted(args.trace_dir.glob("*.utc"))
    require(timestamp_paths, "trace contains no timestamp files")
    for timestamp_path in timestamp_paths:
        captured_at = parse_timestamp(
            timestamp_path.read_text(encoding="utf-8").strip())
        if captured_at < start or captured_at > end:
            continue
        metrics_path = timestamp_path.with_suffix(".prom.gz")
        require(metrics_path.is_file(),
                f"trace metrics are missing: {metrics_path.name}")
        with gzip.open(metrics_path, "rt", encoding="utf-8") as source:
            rows.append((captured_at, parse_prometheus(source.read())))
    result = analyze_trace(rows)
    require(not args.output.exists(), f"output already exists: {args.output}")
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture")
    capture.add_argument("--output", required=True, type=Path)
    capture.add_argument("--metrics-url", default="http://127.0.0.1:9090/metrics")
    capture.add_argument("--interface")
    capture.add_argument("--service", default="bonvoyage.service")
    capture.add_argument("--repository", type=Path,
                         default=Path(__file__).resolve().parents[2])
    capture.set_defaults(function=write_capture)
    compare = subparsers.add_parser("analyze")
    compare.add_argument("--before", required=True, type=Path)
    compare.add_argument("--after", required=True, type=Path)
    compare.add_argument("--output", required=True, type=Path)
    compare.set_defaults(function=write_analysis)
    trace = subparsers.add_parser("analyze-trace")
    trace.add_argument("--trace-dir", required=True, type=Path)
    trace.add_argument("--start", required=True)
    trace.add_argument("--end", required=True)
    trace.add_argument("--output", required=True, type=Path)
    trace.set_defaults(function=write_trace_analysis)
    args = parser.parse_args()
    try:
        args.function(args)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
