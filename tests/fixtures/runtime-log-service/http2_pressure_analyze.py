#!/usr/bin/env python3
"""Check local TLS/HTTP/2 requests and runtime-log pressure/recovery evidence."""

import argparse
import json
import re
import time
import urllib.request
from pathlib import Path


METRIC = re.compile(
    r"^bonvoyage_bonvoyage_runtime_log_([a-z_]+)(?:\{[^}]*\})?\s+([0-9]+(?:\.[0-9]+)?)$"
)
GATEWAY_METRIC = re.compile(
    r"^bonvoyage_bonvoyage_gateway_(active_requests|active_connections|"
    r"active_http2_connections|active_upstream_requests)(?:\{[^}]*\})?\s+"
    r"([0-9]+(?:\.[0-9]+)?)$"
)
FINAL = re.compile(
    r"event=runtime_log_final\b.*\battempted=(\d+) sent=(\d+) "
    r"dropped=(\d+) shutdown_drops=(\d+) queued=(\d+)"
)
METRICS = ("records_attempted_total", "records_sent_total", "records_dropped_total",
           "queue_overflows_total", "queue_depth", "queue_capacity", "sink_healthy",
           "would_block_events_total", "unavailable_events_total")
GATEWAY_METRICS = ("active_requests", "active_connections",
                   "active_http2_connections", "active_upstream_requests")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def capture(gateway):
    with urllib.request.urlopen("http://" + gateway + ":9901/health/ready", timeout=3) as response:
        readiness = json.load(response)
    require(readiness["status"] == "ok", "gateway readiness was not ok")
    with urllib.request.urlopen("http://" + gateway + ":9090/metrics", timeout=3) as response:
        body = response.read().decode("utf-8")
    found = {}
    gateway_found = {}
    for line in body.splitlines():
        match = METRIC.fullmatch(line)
        if match:
            require(match[1] not in found, "duplicate runtime log metric " + match[1])
            found[match[1]] = float(match[2])
            continue
        match = GATEWAY_METRIC.fullmatch(line)
        if match:
            gateway_found[match[1]] = gateway_found.get(match[1], 0) + float(match[2])
    require(all(name in found for name in METRICS), "missing runtime log metric")
    require(all(name in gateway_found for name in GATEWAY_METRICS),
            "missing gateway activity metric")
    result = {name: found[name] for name in METRICS}
    result.update({name: gateway_found[name] for name in GATEWAY_METRICS})
    result["captured_at_unix_ms"] = time.time_ns() // 1_000_000
    require(0 <= result["queue_depth"] <= result["queue_capacity"], "queue exceeded capacity")
    print(json.dumps(result, sort_keys=True))


def read_json(path):
    with Path(path).open(encoding="utf-8") as source:
        return json.load(source)


def verify_oha(path, count):
    result = read_json(path)
    require(result["summary"]["successRate"] == 1, "HTTP/2 requests failed: " + path)
    require(result["statusCodeDistribution"] == {"200": int(count)},
            "HTTP/2 status distribution mismatch: " + path)
    require(result["errorDistribution"] == {}, "HTTP/2 client errors: " + path)
    require(result["summary"]["totalData"] == int(count) * 1024,
            "HTTP/2 payload byte count mismatch: " + path)
    return {"requests": int(count), "success_rate": result["summary"]["successRate"],
            "response_bytes": result["summary"]["totalData"]}


def analyze(directory):
    root = Path(directory)
    oha = {phase: verify_oha(str(root / (phase + ".oha.json")), count)
           for phase, count in (("healthy", "32"), ("paused", "64"), ("recovered", "32"))}
    metrics = {phase: read_json(root / (phase + ".metrics.json"))
               for phase in ("healthy", "paused", "recovered", "before-stop")}
    healthy, paused, recovered, before_stop = (
        metrics[name] for name in ("healthy", "paused", "recovered", "before-stop")
    )
    require(healthy["queue_depth"] == 0 and healthy["sink_healthy"] == 1,
            "healthy receiver did not drain")
    require(paused["records_attempted_total"] > healthy["records_attempted_total"],
            "paused HTTP/2 requests generated no runtime records")
    require(paused["queue_depth"] > 0 and paused["sink_healthy"] == 0,
            "stalled receiver did not backpressure the bounded queue")
    require(paused["would_block_events_total"] > healthy["would_block_events_total"],
            "stalled receiver did not report would-block")
    require(recovered["queue_depth"] == 0 and recovered["sink_healthy"] == 1,
            "receiver did not recover after resume")
    require(recovered["records_sent_total"] > paused["records_sent_total"],
            "queued records were not sent after receiver resume")
    require(before_stop["queue_depth"] == 0 and before_stop["sink_healthy"] == 1,
            "runtime log queue was not drained before stop")
    require(all(item["queue_depth"] <= item["queue_capacity"] for item in metrics.values()),
            "runtime log queue exceeded capacity")

    records = []
    with Path("/runtime-log/records.jsonl").open(encoding="utf-8") as source:
        for line in source:
            records.append(json.loads(line)["record"])
    require(any("event=dataplane_ready" in text for text in records), "ready record missing")
    require(any("event=dataplane_stopped" in text for text in records), "stop record missing")
    finals = [FINAL.search(text) for text in records]
    finals = [match for match in finals if match is not None]
    require(len(finals) == 1, "expected one complete final accounting record")
    attempted, sent, dropped, shutdown_drops, queued = map(int, finals[0].groups())
    require(attempted == sent and dropped == shutdown_drops == queued == 0,
            "receiver recovery lost runtime log records")
    require(len(records) == sent + 1, "delivered record count differs from final accounting")
    result = {"status": "passed", "transport": "unix", "protocol": "tls-http2",
              "oha": oha, "metrics": metrics,
              "final": {"attempted": attempted, "sent": sent, "dropped": dropped,
                        "shutdown_drops": shutdown_drops, "queued": queued,
                        "received_datagrams": len(records)}}
    print(json.dumps(result, sort_keys=True))


def analyze_stalled(directory):
    root = Path(directory)
    oha = {phase: verify_oha(str(root / (phase + ".oha.json")), count)
           for phase, count in (("healthy", "32"), ("paused", "64"))}
    healthy = read_json(root / "healthy.metrics.json")
    paused = read_json(root / "paused.metrics.json")
    shutdown = read_json(root / "shutdown.json")
    receiver = read_json(root / "receiver-after-shutdown.json")
    require(healthy["queue_depth"] == 0 and healthy["sink_healthy"] == 1,
            "healthy receiver did not drain")
    require(paused["records_attempted_total"] > healthy["records_attempted_total"],
            "paused HTTP/2 requests generated no runtime records")
    require(paused["queue_depth"] > 0 and paused["sink_healthy"] == 0,
            "stalled receiver did not backpressure the bounded queue")
    require(paused["would_block_events_total"] > healthy["would_block_events_total"],
            "stalled receiver did not report would-block")
    require(paused["queue_depth"] <= paused["queue_capacity"],
            "stalled runtime log queue exceeded capacity")
    require(shutdown["exit_code"] == 0 and shutdown["restart_count"] == 0,
            "gateway did not stop cleanly without restart")
    require(shutdown["elapsed_ms"] <= shutdown["limit_ms"],
            "gateway shutdown exceeded its bounded stop interval")
    require(receiver["paused"] is False and receiver["invalid"] == 0,
            "receiver did not resume cleanly after gateway exit")

    records = []
    with Path("/runtime-log/records.jsonl").open(encoding="utf-8") as source:
        for line in source:
            records.append(json.loads(line)["record"])
    require(len(records) == receiver["received"],
            "receiver status differs from its retained records")
    require(any("event=dataplane_ready" in text for text in records),
            "ready record missing")
    require(not any("event=dataplane_stopped" in text for text in records),
            "stalled receiver unexpectedly accepted the clean-stop event")
    require(not any("event=runtime_log_final" in text for text in records),
            "stalled receiver unexpectedly accepted the final report")
    result = {
        "status": "passed",
        "transport": "unix",
        "protocol": "tls-http2",
        "shutdown_condition": "receiver-stalled",
        "oha": oha,
        "metrics": {"healthy": healthy, "paused": paused},
        "shutdown": shutdown,
        "receiver": receiver,
        "observable_conclusion": {
            "queued_before_stop": int(paused["queue_depth"]),
            "clean_stop_delivered": False,
            "final_report_delivered": False,
            "post_stop_metrics_available": False,
        },
    }
    print(json.dumps(result, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    capture_parser = commands.add_parser("capture")
    capture_parser.add_argument("--gateway", required=True)
    analyze_parser = commands.add_parser("analyze")
    analyze_parser.add_argument("--directory", default="/evidence")
    stalled_parser = commands.add_parser("analyze-stalled")
    stalled_parser.add_argument("--directory", default="/evidence")
    args = parser.parse_args()
    if args.action == "capture":
        capture(args.gateway)
    elif args.action == "analyze":
        analyze(args.directory)
    else:
        analyze_stalled(args.directory)


if __name__ == "__main__":
    main()
