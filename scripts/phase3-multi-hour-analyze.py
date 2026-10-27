#!/usr/bin/env python3
"""Validate one retained Phase 3 multi-hour local hardening run."""

from __future__ import annotations

import argparse
import csv
import glob
import json
import math
import os
import statistics
import sys
from pathlib import Path
from typing import Any


PREFIX = "bonvoyage_bonvoyage_gateway_"
ZERO_FINAL_GAUGES = (
    "active_connections",
    "active_http2_connections",
    "active_http2_streams",
    "active_requests",
    "active_route_requests",
    "active_upstream_requests",
    "active_upstream_http2_streams",
    "active_retries",
    "active_tls_handshakes",
    "active_upstream_tls_handshakes",
    "active_unhealthy_endpoints",
    "active_websocket_connections",
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--duration-seconds", required=True, type=int)
    parser.add_argument("--qps", required=True, type=int)
    parser.add_argument("--h2-max-deadline-aborts", required=True, type=int)
    parser.add_argument("--shards", required=True, type=int)
    parser.add_argument("--rss-max-growth-bytes", required=True, type=int)
    parser.add_argument("--rss-max-growth-percent", required=True, type=int)
    parser.add_argument("--rss-max-slope-kib-per-hour", required=True, type=float)
    parser.add_argument("--fd-max-growth", required=True, type=int)
    parser.add_argument("--fd-max-slope-per-hour", required=True, type=float)
    return parser.parse_args()


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def metric_totals(path: Path) -> dict[str, float]:
    totals: dict[str, float] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        name = line.split("{", 1)[0].split()[0]
        totals[name] = totals.get(name, 0.0) + float(line.split()[-1])
    return totals


def metric_by_shard(path: Path, name: str) -> dict[int, float]:
    values: dict[int, float] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith(name + "{"):
            continue
        labels, raw = line.split(None, 1)
        shard_label = next(
            item for item in labels.split("{", 1)[1].rstrip("}").split(",")
            if item.startswith('shard="')
        )
        shard = int(shard_label.split('"', 2)[1])
        values[shard] = values.get(shard, 0.0) + float(raw)
    return values


def regression_slope_per_hour(
    samples: list[dict[str, str]], field: str
) -> float:
    points = [
        (float(sample["elapsed_seconds"]), float(sample[field]))
        for sample in samples
    ]
    if len(points) < 2:
        return 0.0
    mean_x = statistics.fmean(point[0] for point in points)
    mean_y = statistics.fmean(point[1] for point in points)
    denominator = sum((point[0] - mean_x) ** 2 for point in points)
    if denominator == 0:
        return 0.0
    numerator = sum(
        (point[0] - mean_x) * (point[1] - mean_y) for point in points
    )
    return numerator / denominator * 3600.0


def median_field(samples: list[dict[str, str]], field: str) -> float:
    return statistics.median(float(sample[field]) for sample in samples)


def require_http_success(path: Path) -> int:
    result = load_json(path)
    assert result["completed"] == result["requested"], (path.name, result)
    assert result["statuses"] == {"200": result["requested"]}, (
        path.name,
        result,
    )
    assert not result["errors"], (path.name, result)
    return int(result["requested"])


def require_saturation(path: Path) -> tuple[int, int]:
    result = load_json(path)
    assert result["completed"] == result["requested"], (path.name, result)
    assert not result["errors"], (path.name, result)
    assert set(result["statuses"]) <= {"200", "503"}, (path.name, result)
    successes = int(result["statuses"].get("200", 0))
    rejections = int(result["statuses"].get("503", 0))
    assert successes > 0 and rejections > 0, (path.name, result)
    assert successes + rejections == result["requested"], (path.name, result)
    return successes, rejections


def require_failure_window(path: Path) -> tuple[int, int]:
    result = load_json(path)
    assert result["completed"] == result["requested"], (path.name, result)
    assert not result["errors"], (path.name, result)
    assert set(result["statuses"]) <= {"200", "502", "503"}, (
        path.name,
        result,
    )
    successes = int(result["statuses"].get("200", 0))
    failures = sum(int(result["statuses"].get(code, 0)) for code in ("502", "503"))
    assert successes > 0 and failures > 0, (path.name, result)
    assert successes + failures == result["requested"], (path.name, result)
    return successes, failures


def require_recovery_probe(path: Path) -> tuple[int, int]:
    result = load_json(path)
    assert result["completed"] == result["requested"], (path.name, result)
    assert not result["errors"], (path.name, result)
    assert set(result["statuses"]) <= {"200", "503"}, (path.name, result)
    successes = int(result["statuses"].get("200", 0))
    rejections = int(result["statuses"].get("503", 0))
    assert successes > 0, (path.name, result)
    assert successes + rejections == result["requested"], (path.name, result)
    return successes, rejections


def recovery_probe_cycle(path: Path, prefix: str) -> str:
    suffix = path.stem.removeprefix(prefix)
    cycle_label, separator, attempt_label = suffix.rpartition("-")
    assert separator and cycle_label.isdigit() and attempt_label.isdigit(), path.name
    return cycle_label


def main() -> None:
    if sys.flags.optimize != 0:
        raise RuntimeError("hardening analysis requires Python assertions")
    arguments = parse_arguments()
    root = arguments.evidence

    with (root / "resource-samples.csv").open(encoding="utf-8", newline="") as source:
        resource_samples = list(csv.DictReader(source))
    assert len(resource_samples) >= 4, "too few resource samples"
    assert all(sample["running"] == "true" for sample in resource_samples)
    assert all(int(sample["restart_count"]) == 0 for sample in resource_samples)
    identities = {sample["identity"] for sample in resource_samples}
    assert len(identities) == 1, identities

    warmup_seconds = min(max(arguments.duration_seconds * 0.1, 60.0), 900.0)
    stable_samples = [
        sample
        for sample in resource_samples
        if float(sample["elapsed_seconds"]) >= warmup_seconds
    ]
    assert len(stable_samples) >= 3, "too few post-warmup resource samples"
    window_size = min(3, max(1, len(stable_samples) // 2))
    first_window = stable_samples[:window_size]
    final_window = stable_samples[-window_size:]

    baseline_rss_kib = median_field(first_window, "rss_kib")
    final_rss_kib = median_field(final_window, "rss_kib")
    retained_rss_growth_kib = max(0.0, final_rss_kib - baseline_rss_kib)
    rss_growth_limit_kib = max(
        math.ceil(arguments.rss_max_growth_bytes / 1024),
        math.ceil(baseline_rss_kib * arguments.rss_max_growth_percent / 100),
    )
    assert retained_rss_growth_kib <= rss_growth_limit_kib, (
        retained_rss_growth_kib,
        rss_growth_limit_kib,
    )
    rss_slope_kib_per_hour = regression_slope_per_hour(stable_samples, "rss_kib")

    baseline_fd_count = median_field(first_window, "fd_count")
    final_fd_count = median_field(final_window, "fd_count")
    retained_fd_growth = max(0.0, final_fd_count - baseline_fd_count)
    assert retained_fd_growth <= arguments.fd_max_growth, (
        retained_fd_growth,
        arguments.fd_max_growth,
    )
    fd_slope_per_hour = regression_slope_per_hour(stable_samples, "fd_count")

    slope_gate_enforced = arguments.duration_seconds >= 3600
    if slope_gate_enforced:
        assert rss_slope_kib_per_hour <= arguments.rss_max_slope_kib_per_hour, (
            rss_slope_kib_per_hour,
            arguments.rss_max_slope_kib_per_hour,
        )
        assert fd_slope_per_hour <= arguments.fd_max_slope_per_hour, (
            fd_slope_per_hour,
            arguments.fd_max_slope_per_hour,
        )

    http_paths = sorted(root.glob("cycles/http1-*.json"))
    websocket_paths = sorted(root.glob("cycles/websocket-*.json"))
    grpc_paths = sorted(root.glob("cycles/grpc-*.json"))
    assert http_paths and len(http_paths) == len(websocket_paths) == len(grpc_paths)
    expected_cycles = len(http_paths)
    healthy_http_requests = require_http_success(root / "warmup.json")
    healthy_http_requests += sum(require_http_success(path) for path in http_paths)
    healthy_http_requests += require_http_success(root / "final-recovery.json")

    websocket_cycles = 0
    for path in websocket_paths:
        result = load_json(path)
        assert result["successes"] == result["requested"], (path.name, result)
        assert not result["errors"], (path.name, result)
        websocket_cycles += int(result["requested"])

    grpc_requests = 0
    for path in grpc_paths:
        result = load_json(path)
        assert result["case"] == "concurrent", (path.name, result)
        assert result["code"] == "OK", (path.name, result)
        assert result["successful_requests"] == 16, (path.name, result)
        grpc_requests += int(result["successful_requests"])

    saturation_paths = sorted(root.glob("cycles/saturation-[0-9]*.json"))
    assert saturation_paths, "route saturation was not exercised"
    saturation_successes = 0
    saturation_rejections = 0
    for path in saturation_paths:
        successes, rejections = require_saturation(path)
        saturation_successes += successes
        saturation_rejections += rejections
        require_http_success(path.with_name(path.name.replace("saturation-", "saturation-recovery-")))

    weighted_failure_paths = sorted(root.glob("cycles/weighted-failure-*.json"))
    balancing_failure_paths = sorted(root.glob("cycles/load-balancing-failure-*.json"))
    assert weighted_failure_paths
    assert len(weighted_failure_paths) == len(balancing_failure_paths)
    intentional_failure_responses = 0
    for path in weighted_failure_paths + balancing_failure_paths:
        _, failures = require_failure_window(path)
        intentional_failure_responses += failures
    failure_labels = {
        path.stem.removeprefix("weighted-failure-")
        for path in weighted_failure_paths
    }
    weighted_probe_paths = sorted(root.glob("cycles/weighted-recovery-probe-*.json"))
    balancing_probe_paths = sorted(
        root.glob("cycles/load-balancing-recovery-probe-*.json")
    )
    assert weighted_probe_paths and balancing_probe_paths
    assert {
        recovery_probe_cycle(path, "weighted-recovery-probe-")
        for path in weighted_probe_paths
    } == failure_labels
    assert {
        recovery_probe_cycle(path, "load-balancing-recovery-probe-")
        for path in balancing_probe_paths
    } == failure_labels
    recovery_probe_successes = 0
    recovery_probe_rejections = 0
    for path in weighted_probe_paths + balancing_probe_paths:
        successes, rejections = require_recovery_probe(path)
        recovery_probe_successes += successes
        recovery_probe_rejections += rejections
    circuit_ready_paths = sorted(
        root.glob("metrics/circuit-recovery-ready-*.prom")
    )
    assert {
        path.stem.removeprefix("circuit-recovery-ready-")
        for path in circuit_ready_paths
    } == failure_labels
    expected_shards = set(range(arguments.shards))
    for path in circuit_ready_paths:
        for suffix in ("open_endpoint_circuits", "half_open_endpoint_circuits"):
            values = metric_by_shard(path, PREFIX + suffix)
            assert set(values) == expected_shards, (path.name, suffix, values)
            assert all(value == 0 for value in values.values()), (
                path.name,
                suffix,
                values,
            )
    for path in sorted(root.glob("cycles/weighted-recovery-[0-9]*.json")):
        require_http_success(path)
    for path in sorted(root.glob("cycles/load-balancing-recovery-[0-9]*.json")):
        require_http_success(path)

    collector_loss_paths = sorted(root.glob("cycles/collector-loss-*.json"))
    collector_recovery_paths = sorted(root.glob("cycles/collector-recovery-*.json"))
    assert collector_loss_paths
    assert len(collector_loss_paths) == len(collector_recovery_paths)
    for path in collector_loss_paths + collector_recovery_paths:
        healthy_http_requests += require_http_success(path)

    collector_before_paths = sorted(root.glob("metrics/collector-before-*.prom"))
    collector_failed_paths = sorted(root.glob("metrics/collector-failed-*.prom"))
    collector_recovered_paths = sorted(root.glob("metrics/collector-recovered-*.prom"))
    assert len(collector_before_paths) == len(collector_loss_paths)
    assert len(collector_failed_paths) == len(collector_loss_paths)
    assert len(collector_recovered_paths) == len(collector_loss_paths)
    failure_metric = PREFIX + "otlp_trace_export_failures_total"
    recovery_metric = PREFIX + "otlp_trace_exporter_recoveries_total"
    health_metric = PREFIX + "otlp_trace_exporter_healthy"
    for before_path, failed_path, recovered_path in zip(
        collector_before_paths,
        collector_failed_paths,
        collector_recovered_paths,
    ):
        failures_before = metric_by_shard(before_path, failure_metric)
        failures_after = metric_by_shard(failed_path, failure_metric)
        recoveries_before = metric_by_shard(before_path, recovery_metric)
        recoveries_after = metric_by_shard(recovered_path, recovery_metric)
        failed_health = metric_by_shard(failed_path, health_metric)
        recovered_health = metric_by_shard(recovered_path, health_metric)
        for values in (
            failures_before,
            failures_after,
            recoveries_before,
            recoveries_after,
            failed_health,
            recovered_health,
        ):
            assert set(values) == expected_shards, (before_path.name, values)
        assert all(
            failures_after[shard] > failures_before[shard]
            for shard in expected_shards
        ), before_path.name
        assert all(failed_health[shard] == 0 for shard in expected_shards)
        assert all(
            recoveries_after[shard] > recoveries_before[shard]
            for shard in expected_shards
        ), recovered_path.name
        assert all(recovered_health[shard] == 1 for shard in expected_shards)

    h2 = load_json(root / "http2-soak.oha.json")
    h2_summary = h2["summary"]
    h2_distribution = h2.get("statusCodeDistribution", {})
    h2_errors = h2.get("errorDistribution", {})
    assert h2_summary["successRate"] == 1, h2_summary
    assert set(h2_distribution) <= {"200"}, h2_distribution
    unexpected_h2_errors = {
        name: count
        for name, count in h2_errors.items()
        if name != "aborted due to deadline"
    }
    assert not unexpected_h2_errors, unexpected_h2_errors
    h2_deadline_aborts = int(h2_errors.get("aborted due to deadline", 0))
    assert h2_deadline_aborts <= arguments.h2_max_deadline_aborts, (
        h2_deadline_aborts,
        arguments.h2_max_deadline_aborts,
    )
    h2_requests = int(h2_distribution.get("200", 0))
    minimum_h2_requests = math.floor(
        arguments.duration_seconds * arguments.qps * 0.90
    )
    assert h2_requests >= minimum_h2_requests, (h2_requests, minimum_h2_requests)

    final_metrics = metric_totals(root / "metrics-final.prom")

    def total(suffix: str) -> float:
        name = PREFIX + suffix
        assert name in final_metrics, f"required metric is absent: {name}"
        return final_metrics[name]

    assert total("access_log_enabled") == arguments.shards
    assert total("access_log_sink_healthy") == arguments.shards
    assert total("access_log_queue_depth") == 0
    assert total("access_log_records_enqueued_total") > 0
    assert total("access_log_records_written_total") == total(
        "access_log_records_enqueued_total"
    )
    assert total("access_log_records_dropped_total") == 0
    assert total("access_log_queue_overflows_total") == 0
    assert total("access_log_write_failures_total") == 0
    assert total("access_log_capacity_exhaustions_total") == 0

    assert total("otlp_traces_enabled") == arguments.shards
    assert total("otlp_trace_exporter_healthy") == arguments.shards
    assert total("otlp_trace_queue_depth") == 0
    assert total("otlp_trace_export_failures_total") > 0
    assert total("otlp_trace_retry_exhaustions_total") > 0
    assert total("otlp_trace_exporter_recoveries_total") > 0
    assert total("otlp_trace_queue_overflows_total") == 0
    assert total("otlp_trace_spans_sampled_total") > 0
    assert total("otlp_trace_spans_exported_total") > 0
    assert total("otlp_trace_spans_sampled_total") + total(
        "otlp_trace_spans_sampled_out_total"
    ) == total("otlp_trace_spans_started_total")
    assert total("otlp_trace_spans_exported_total") + total(
        "otlp_trace_spans_dropped_total"
    ) == total("otlp_trace_spans_sampled_total")

    for suffix in ZERO_FINAL_GAUGES:
        assert total(suffix) == 0, (suffix, total(suffix))
    assert "bonvoyage_memory_malloc_failed" in final_metrics
    assert final_metrics["bonvoyage_memory_malloc_failed"] == 0

    collector = load_json(root / "collector-observations.json")
    assert collector["healthy"] is True, collector
    assert collector["accepted"] > 0, collector
    assert collector["rejected"] > 0, collector
    assert collector["payload_files_written"] <= collector["maximum_payload_files"]
    payload_files = glob.glob(str(root / "otlp-payload-*.bin"))
    assert len(payload_files) == collector["payload_files_written"], collector

    access_log = load_json(root / "access-log-validation.json")
    assert access_log["invalid_records"] == 0, access_log
    assert access_log["forbidden_fields_present"] == [], access_log
    assert access_log["records"] == int(total("access_log_records_written_total"))

    summary = {
        "access_log_records": access_log["records"],
        "collector_accepted_batches": collector["accepted"],
        "collector_rejected_batches": collector["rejected"],
        "cycles_completed": expected_cycles,
        "duration_seconds_configured": arguments.duration_seconds,
        "fd": {
            "baseline_median": baseline_fd_count,
            "final_median": final_fd_count,
            "maximum": max(int(sample["fd_count"]) for sample in stable_samples),
            "retained_growth": retained_fd_growth,
            "slope_per_hour": fd_slope_per_hour,
        },
        "grpc_unary_requests": grpc_requests,
        "healthy_http1_requests": healthy_http_requests,
        "http2_deadline_aborts": h2_deadline_aborts,
        "http2_deadline_abort_limit": arguments.h2_max_deadline_aborts,
        "http2_requests": h2_requests,
        "intentional_failure_responses": intentional_failure_responses,
        "outcome": "PASS",
        "resource_samples": len(resource_samples),
        "recovery_probe_rejections": recovery_probe_rejections,
        "recovery_probe_successes": recovery_probe_successes,
        "rss_kib": {
            "baseline_median": baseline_rss_kib,
            "final_median": final_rss_kib,
            "maximum": max(int(sample["rss_kib"]) for sample in stable_samples),
            "retained_growth": retained_rss_growth_kib,
            "slope_per_hour": rss_slope_kib_per_hour,
        },
        "route_saturation_rejections": saturation_rejections,
        "route_saturation_successes": saturation_successes,
        "slope_gate_enforced": slope_gate_enforced,
        "websocket_cycles": websocket_cycles,
    }
    with (root / "validation-summary.json").open("w", encoding="utf-8") as output:
        json.dump(summary, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
