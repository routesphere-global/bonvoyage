#!/usr/bin/env python3
"""Validate matched runtime-log cost samples and sustained pressure evidence."""

import argparse
import json
import math
import os
import re
import statistics
import time
from pathlib import Path


FINAL = re.compile(
    r"event=runtime_log_final\b.*\battempted=(\d+) sent=(\d+) "
    r"dropped=(\d+) shutdown_drops=(\d+) queued=(\d+)"
)

ENVIRONMENT_PROFILES = {
    "local-docker-desktop-arm64": {
        "scope": "local-runtime-log-cost-and-sustained-pressure",
        "limitations": ["Docker Desktop ARM64 local engineering evidence"],
    },
    "aws-shared-amd64": {
        "scope": "aws-shared-amd64-runtime-log-cost-and-sustained-pressure",
        "limitations": [
            "AWS shared EC2 AMD64 single-host Docker engineering evidence",
            "load generator, gateway, and receiver use separate CPU sets but share one VM",
        ],
    },
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_json(path):
    with Path(path).open(encoding="utf-8") as source:
        return json.load(source)


def process_observation(proc_root="/proc/1"):
    root = Path(proc_root)
    stat = (root / "stat").read_text(encoding="ascii")
    remainder = stat[stat.rfind(")") + 2 :].split()
    status = (root / "status").read_text(encoding="ascii")
    rss = re.search(r"^VmRSS:\s+(\d+)\s+kB$", status, re.MULTILINE)
    require(rss is not None, "VmRSS missing from process status")
    result = {
        "captured_at_unix_ms": time.time_ns() // 1_000_000,
        "pid": int(stat.split(" ", 1)[0]),
        "cpu_ticks": int(remainder[11]) + int(remainder[12]),
        "clock_ticks_per_second": int(os.sysconf("SC_CLK_TCK")),
        "rss_kib": int(rss.group(1)),
        "fd_count": len(list((root / "fd").iterdir())),
    }
    print(json.dumps(result, sort_keys=True))


def verify_oha(result, expected_requests=None, minimum_requests=None,
               allow_duration_deadline_aborts=False):
    distribution = result.get("statusCodeDistribution", {})
    requests = sum(int(value) for value in distribution.values())
    errors = result.get("errorDistribution", {})
    require(result["summary"]["successRate"] == 1, "load success rate was not one")
    if allow_duration_deadline_aborts:
        require(set(errors).issubset({"aborted due to deadline"}),
                "duration load client reported an unexpected error")
    else:
        require(errors == {}, "load client reported errors")
    require(set(distribution) == {"200"}, "load returned a non-200 response")
    if expected_requests is not None:
        require(requests == expected_requests, "load request count mismatch")
    if minimum_requests is not None:
        require(requests >= minimum_requests, "sustained load request count below floor")
    require(result["summary"]["totalData"] == requests * 1024,
            "load response byte count mismatch")
    return {
        "requests": requests,
        "rps": float(result["summary"]["requestsPerSec"]),
        "elapsed_seconds": float(result["summary"]["total"]),
        "p99_ms": float(result["latencyPercentiles"]["p99"]) * 1000,
        "p99_9_ms": float(result["latencyPercentiles"]["p99.9"]) * 1000,
        "end_window_client_aborts": int(errors.get("aborted due to deadline", 0)),
    }


def delta(before, after, name):
    value = after[name] - before[name]
    require(value >= 0, name + " counter moved backwards")
    return value


def build_sample(args):
    require(args.mode in ("info", "debug"), "invalid cost mode")
    before_process = read_json(args.before_process)
    after_process = read_json(args.after_process)
    before_metrics = read_json(args.before_metrics)
    after_metrics = read_json(args.after_metrics)
    before_receiver = read_json(args.before_receiver)
    after_receiver = read_json(args.after_receiver)
    load = verify_oha(read_json(args.oha), expected_requests=args.requests)
    require(before_process["pid"] == after_process["pid"], "gateway process changed")
    require(before_process["clock_ticks_per_second"] ==
            after_process["clock_ticks_per_second"], "process clock changed")
    require(after_metrics["queue_depth"] == 0 and after_metrics["sink_healthy"] == 1,
            "healthy cost sample did not finish drained")

    counters = {
        name: delta(before_metrics, after_metrics, name)
        for name in (
            "records_attempted_total", "records_sent_total",
            "records_dropped_total", "queue_overflows_total",
            "would_block_events_total", "unavailable_events_total",
        )
    }
    require(counters["records_dropped_total"] == 0, "healthy sample dropped records")
    require(counters["queue_overflows_total"] == 0, "healthy sample overflowed its queue")
    require(counters["would_block_events_total"] == 0,
            "healthy sample observed receiver backpressure")
    require(counters["unavailable_events_total"] == 0,
            "healthy sample observed an unavailable receiver")
    receiver_delta = after_receiver["received"] - before_receiver["received"]
    require(receiver_delta == counters["records_sent_total"],
            "receiver and sent-counter deltas differ")
    if args.mode == "info":
        require(counters["records_attempted_total"] == 0,
                "normal info-level requests unexpectedly emitted runtime records")
    else:
        require(counters["records_attempted_total"] >= args.requests,
                "debug sample did not exercise a per-request runtime-log path")

    cpu_ticks = after_process["cpu_ticks"] - before_process["cpu_ticks"]
    require(cpu_ticks >= 0, "gateway CPU counter moved backwards")
    cpu_seconds = cpu_ticks / before_process["clock_ticks_per_second"]
    sample = {
        "status": "passed",
        "mode": args.mode,
        "pair": args.pair,
        "order": args.order,
        "load": load,
        "gateway": {
            "cpu_seconds": cpu_seconds,
            "cpu_microseconds_per_request": cpu_seconds * 1_000_000 / args.requests,
            "rss_before_kib": before_process["rss_kib"],
            "rss_after_kib": after_process["rss_kib"],
            "fd_before": before_process["fd_count"],
            "fd_after": after_process["fd_count"],
        },
        "runtime_log_delta": counters,
        "receiver_delta": receiver_delta,
    }
    print(json.dumps(sample, sort_keys=True))


def percent_delta(candidate, baseline):
    require(baseline > 0, "cannot calculate percentage from zero baseline")
    return (candidate - baseline) * 100 / baseline


def median(values):
    return float(statistics.median(values))


def load_records(path):
    records = []
    with Path(path).open(encoding="utf-8") as source:
        for line in source:
            records.append(json.loads(line)["record"])
    return records


def build_report(args):
    root = Path(args.directory)
    environment = ENVIRONMENT_PROFILES[args.environment]
    samples = [read_json(path) for path in sorted(root.glob("cost-*.sample.json"))]
    require(len(samples) == args.repetitions * 2, "incomplete cost sample set")
    pairs = {}
    for sample in samples:
        require(sample.get("status") == "passed", "cost sample did not pass")
        require(sample["mode"] in ("info", "debug"), "unexpected cost mode")
        pairs.setdefault(int(sample["pair"]), {})[sample["mode"]] = sample
    require(set(pairs) == set(range(1, args.repetitions + 1)), "cost pair IDs differ")
    require(all(set(pair) == {"info", "debug"} for pair in pairs.values()),
            "cost pair lacks one variant")

    modes = {
        mode: [sample for sample in samples if sample["mode"] == mode]
        for mode in ("info", "debug")
    }
    cost = {}
    for mode, items in modes.items():
        cost[mode] = {
            "samples": len(items),
            "median_rps": median([item["load"]["rps"] for item in items]),
            "median_p99_ms": median([item["load"]["p99_ms"] for item in items]),
            "median_p99_9_ms": median([item["load"]["p99_9_ms"] for item in items]),
            "median_cpu_microseconds_per_request": median([
                item["gateway"]["cpu_microseconds_per_request"] for item in items
            ]),
            "runtime_records_attempted": sum(
                item["runtime_log_delta"]["records_attempted_total"] for item in items
            ),
            "runtime_records_dropped": sum(
                item["runtime_log_delta"]["records_dropped_total"] for item in items
            ),
        }
    paired = []
    for pair_id in sorted(pairs):
        info = pairs[pair_id]["info"]
        debug = pairs[pair_id]["debug"]
        paired.append({
            "pair": pair_id,
            "debug_cpu_delta_percent": percent_delta(
                debug["gateway"]["cpu_microseconds_per_request"],
                info["gateway"]["cpu_microseconds_per_request"],
            ),
            "debug_p99_9_delta_percent": percent_delta(
                debug["load"]["p99_9_ms"], info["load"]["p99_9_ms"]
            ),
        })
    cost["paired_directional"] = {
        "median_debug_cpu_delta_percent": median([
            item["debug_cpu_delta_percent"] for item in paired
        ]),
        "median_debug_p99_9_delta_percent": median([
            item["debug_p99_9_delta_percent"] for item in paired
        ]),
        "pairs": paired,
        "acceptance_threshold_applied": False,
    }

    pressure_before = read_json(root / "pressure-before.metrics.json")
    pressure_paused = read_json(root / "pressure-paused.metrics.json")
    recovered = read_json(root / "pressure-recovered.metrics.json")
    quiescent = read_json(root / "pressure-quiescent.metrics.json")
    timeline = [read_json(path) for path in sorted(root.glob("pressure-timeline-*.json"))]
    minimum_requests = math.floor(args.pressure_seconds * args.pressure_qps * 0.95)
    pressure_load = verify_oha(read_json(root / "pressure.oha.json"),
                               minimum_requests=minimum_requests,
                               allow_duration_deadline_aborts=True)
    recovery_load = verify_oha(read_json(root / "recovery.oha.json"),
                               expected_requests=args.recovery_requests)
    require(len(timeline) >= 3, "pressure timeline too short")
    require(all(item["queue_depth"] <= item["queue_capacity"] for item in timeline),
            "runtime-log queue exceeded capacity")
    unhealthy = [item for item in timeline if item["sink_healthy"] == 0]
    require(len(unhealthy) >= 2, "receiver pressure was not observed repeatedly")
    unhealthy_span = (unhealthy[-1]["captured_at_unix_ms"] -
                      unhealthy[0]["captured_at_unix_ms"]) / 1000
    require(unhealthy_span >= args.alert_hold_seconds,
            "sink-unhealthy condition did not span the alert hold")
    require(pressure_paused["queue_depth"] <= pressure_paused["queue_capacity"],
            "paused queue exceeded capacity")
    require(pressure_paused["records_dropped_total"] >
            pressure_before["records_dropped_total"], "pressure caused no bounded loss")
    require(pressure_paused["queue_overflows_total"] >
            pressure_before["queue_overflows_total"], "pressure caused no queue overflow")
    require(pressure_paused["would_block_events_total"] >
            pressure_before["would_block_events_total"], "pressure caused no would-block")
    require(recovered["queue_depth"] == 0 and recovered["sink_healthy"] == 1,
            "runtime logger did not recover and drain")
    require(recovered["records_dropped_total"] == pressure_paused["records_dropped_total"],
            "healthy recovery continued dropping records")
    require(all(quiescent[name] == 0 for name in (
        "active_requests", "active_connections", "active_http2_connections",
        "active_upstream_requests",
    )), "gateway did not become request-quiescent")

    lifecycle = read_json(root / "pressure-lifecycle.json")
    require(lifecycle["pid_before"] == lifecycle["pid_after"],
            "gateway process changed during pressure")
    require(lifecycle["restart_count"] == 0 and lifecycle["exit_code"] == 0,
            "gateway restarted or exited unsuccessfully")
    before_process = read_json(root / "pressure-before.process.json")
    after_process = read_json(root / "pressure-after.process.json")
    settled_process = read_json(root / "pressure-settled.process.json")
    require(after_process["pid"] == settled_process["pid"],
            "gateway process changed while resources settled")
    require(settled_process["rss_kib"] - before_process["rss_kib"] <= args.rss_growth_kib,
            "RSS growth exceeded the local pressure bound")
    require(settled_process["fd_count"] - before_process["fd_count"] <= args.fd_growth,
            "descriptor growth exceeded the local pressure bound")
    require(settled_process["fd_count"] <= after_process["fd_count"],
            "descriptor count continued growing after request quiescence")

    receiver_start = read_json(root / "pressure-receiver-start.json")
    receiver_final = read_json(root / "pressure-receiver-final.json")
    require(receiver_final["invalid"] == 0, "receiver observed invalid records")
    records = load_records(args.records)
    scoped = records[receiver_start["received"]:receiver_final["received"]]
    finals = [match for text in scoped if (match := FINAL.search(text)) is not None]
    require(len(finals) == 1, "pressure gateway final accounting missing or duplicated")
    attempted, sent, dropped, shutdown_drops, queued = map(int, finals[0].groups())
    require(attempted == sent + dropped, "final runtime-log accounting is imbalanced")
    require(shutdown_drops == 0 and queued == 0,
            "recovered shutdown retained or discarded queued records")

    report = {
        "status": "passed",
        "scope": environment["scope"],
        "cost": cost,
        "pressure": {
            "load": pressure_load,
            "recovery_load": recovery_load,
            "unhealthy_span_seconds": unhealthy_span,
            "queue_capacity": int(pressure_paused["queue_capacity"]),
            "queue_high_observed": int(max(item["queue_depth"] for item in timeline)),
            "records_dropped": int(pressure_paused["records_dropped_total"] -
                                   pressure_before["records_dropped_total"]),
            "queue_overflows": int(pressure_paused["queue_overflows_total"] -
                                   pressure_before["queue_overflows_total"]),
            "would_block_events": int(pressure_paused["would_block_events_total"] -
                                      pressure_before["would_block_events_total"]),
            "same_process": True,
            "restart_count": 0,
            "rss_growth_kib": settled_process["rss_kib"] - before_process["rss_kib"],
            "fd_growth": settled_process["fd_count"] - before_process["fd_count"],
            "fd_growth_limit": args.fd_growth,
            "request_quiescent": True,
            "final": {
                "attempted": attempted, "sent": sent, "dropped": dropped,
                "shutdown_drops": shutdown_drops, "queued": queued,
            },
        },
        "alert_conditions": {
            "sink_unhealthy_hold_observed": True,
            "bounded_drop_increase_observed": True,
            "prometheus_rule_evaluation_separate": True,
        },
        "limitations": environment["limitations"] + [
            "info-versus-debug logging-level comparison, not logging-off versus logging-on",
            "directional CPU and latency deltas have no acceptance threshold",
            "not dedicated-host or publication-authorized performance evidence",
        ],
    }
    print(json.dumps(report, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    process = commands.add_parser("process")
    process.add_argument("--proc-root", default="/proc/1")
    sample = commands.add_parser("sample")
    sample.add_argument("--mode", required=True)
    sample.add_argument("--pair", required=True, type=int)
    sample.add_argument("--order", required=True, type=int)
    sample.add_argument("--requests", required=True, type=int)
    for name in ("before-process", "after-process", "before-metrics", "after-metrics",
                 "before-receiver", "after-receiver", "oha"):
        sample.add_argument("--" + name, required=True)
    report = commands.add_parser("report")
    report.add_argument("--directory", required=True)
    report.add_argument("--records", required=True)
    report.add_argument("--repetitions", required=True, type=int)
    report.add_argument("--pressure-seconds", required=True, type=int)
    report.add_argument("--pressure-qps", required=True, type=int)
    report.add_argument("--recovery-requests", required=True, type=int)
    report.add_argument("--alert-hold-seconds", type=int, default=120)
    report.add_argument("--rss-growth-kib", type=int, default=16384)
    report.add_argument("--fd-growth", type=int, default=32)
    report.add_argument("--environment", choices=sorted(ENVIRONMENT_PROFILES),
                        default="local-docker-desktop-arm64")
    args = parser.parse_args()
    if args.action == "process":
        process_observation(args.proc_root)
    elif args.action == "sample":
        build_sample(args)
    else:
        build_report(args)


if __name__ == "__main__":
    main()
