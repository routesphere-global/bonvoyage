#!/usr/bin/env python3
"""Regression tests for the sustained runtime-log evidence analyzer."""

import copy
import importlib.util
import io
import json
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/runtime-log-service/runtime_log_sustained_analyze.py"
SPEC = importlib.util.spec_from_file_location("runtime_log_sustained_analyze", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def oha(requests=100, success=1.0, status="200", errors=None):
    return {
        "summary": {
            "successRate": success,
            "total": 10.0,
            "requestsPerSec": requests / 10,
            "totalData": requests * 1024,
        },
        "latencyPercentiles": {"p99": 0.010, "p99.9": 0.012},
        "statusCodeDistribution": {status: requests},
        "errorDistribution": errors or {},
    }


def metrics(**overrides):
    result = {
        "captured_at_unix_ms": 0,
        "records_attempted_total": 0,
        "records_sent_total": 0,
        "records_dropped_total": 0,
        "queue_overflows_total": 0,
        "queue_depth": 0,
        "queue_capacity": 256,
        "sink_healthy": 1,
        "would_block_events_total": 0,
        "unavailable_events_total": 0,
        "active_requests": 0,
        "active_connections": 0,
        "active_http2_connections": 0,
        "active_upstream_requests": 0,
    }
    result.update(overrides)
    return result


class SustainedAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        return str(path)

    def sample_args(self, mode="info"):
        attempts = 0 if mode == "info" else 100
        before = metrics()
        after = metrics(records_attempted_total=attempts, records_sent_total=attempts)
        return Namespace(
            mode=mode, pair=1, order=1, requests=100,
            before_process=self.write("before-process.json", {
                "pid": 1, "cpu_ticks": 100, "clock_ticks_per_second": 100,
                "rss_kib": 1000, "fd_count": 10,
            }),
            after_process=self.write("after-process.json", {
                "pid": 1, "cpu_ticks": 200, "clock_ticks_per_second": 100,
                "rss_kib": 1001, "fd_count": 10,
            }),
            before_metrics=self.write("before-metrics.json", before),
            after_metrics=self.write("after-metrics.json", after),
            before_receiver=self.write("before-receiver.json", {"received": 5}),
            after_receiver=self.write("after-receiver.json", {"received": 5 + attempts}),
            oha=self.write("oha.json", oha()),
        )

    def capture_sample(self, args):
        output = io.StringIO()
        with redirect_stdout(output):
            MODULE.build_sample(args)
        return json.loads(output.getvalue())

    def test_valid_info_and_debug_samples(self):
        self.assertEqual(self.capture_sample(self.sample_args())["mode"], "info")
        self.assertEqual(self.capture_sample(self.sample_args("debug"))["mode"], "debug")

    def test_sample_rejects_failed_request(self):
        args = self.sample_args()
        args.oha = self.write("failed-oha.json", oha(success=0.99, status="500"))
        with self.assertRaisesRegex(AssertionError, "success rate"):
            MODULE.build_sample(args)

    def test_counted_sample_rejects_deadline_abort(self):
        args = self.sample_args()
        args.oha = self.write(
            "aborted-oha.json", oha(errors={"aborted due to deadline": 1})
        )
        with self.assertRaisesRegex(AssertionError, "client reported errors"):
            MODULE.build_sample(args)

    def test_sample_rejects_receiver_mismatch(self):
        args = self.sample_args("debug")
        args.after_receiver = self.write("bad-receiver.json", {"received": 104})
        with self.assertRaisesRegex(AssertionError, "receiver"):
            MODULE.build_sample(args)

    def test_sample_rejects_healthy_drop(self):
        args = self.sample_args("debug")
        args.after_metrics = self.write(
            "drop-metrics.json",
            metrics(records_attempted_total=100, records_sent_total=99,
                    records_dropped_total=1, queue_overflows_total=1),
        )
        with self.assertRaisesRegex(AssertionError, "dropped"):
            MODULE.build_sample(args)

    def report_args(self):
        for pair in (1, 2):
            for mode, cpu in (("info", 2.0), ("debug", 3.0)):
                self.write(f"cost-{pair:02d}-{mode}.sample.json", {
                    "status": "passed", "mode": mode, "pair": pair,
                    "load": {"rps": 10.0, "p99_ms": 10.0, "p99_9_ms": 12.0},
                    "gateway": {"cpu_microseconds_per_request": cpu},
                    "runtime_log_delta": {
                        "records_attempted_total": 0 if mode == "info" else 100,
                        "records_dropped_total": 0,
                    },
                })
        self.write("pressure-before.metrics.json", metrics())
        paused = metrics(captured_at_unix_ms=3000, records_attempted_total=100,
                         records_sent_total=50, records_dropped_total=50,
                         queue_overflows_total=50, queue_depth=256, sink_healthy=0,
                         would_block_events_total=5)
        self.write("pressure-paused.metrics.json", paused)
        self.write("pressure-recovered.metrics.json", metrics(
            captured_at_unix_ms=4000, records_attempted_total=110,
            records_sent_total=60, records_dropped_total=50))
        self.write("pressure-quiescent.metrics.json", metrics(
            captured_at_unix_ms=4100, records_attempted_total=110,
            records_sent_total=60, records_dropped_total=50))
        for number, captured in enumerate((0, 1500, 3000), start=1):
            item = copy.deepcopy(paused)
            item["captured_at_unix_ms"] = captured
            self.write(f"pressure-timeline-{number:03d}.json", item)
        self.write("pressure.oha.json", oha())
        self.write("recovery.oha.json", oha(requests=10))
        self.write("pressure-lifecycle.json", {
            "pid_before": 99, "pid_after": 99, "restart_count": 0, "exit_code": 0,
        })
        self.write("pressure-before.process.json", {"rss_kib": 1000, "fd_count": 10})
        self.write("pressure-after.process.json", {
            "pid": 99, "rss_kib": 1001, "fd_count": 10,
        })
        self.write("pressure-settled.process.json", {
            "pid": 99, "rss_kib": 1001, "fd_count": 10,
        })
        self.write("pressure-receiver-start.json", {"received": 0})
        self.write("pressure-receiver-final.json", {"received": 1, "invalid": 0})
        records = self.root / "records.jsonl"
        records.write_text(json.dumps({
            "record": "event=runtime_log_final attempted=100 sent=50 dropped=50 shutdown_drops=0 queued=0"
        }) + "\n", encoding="utf-8")
        return Namespace(
            directory=str(self.root), records=str(records), repetitions=2,
            pressure_seconds=10, pressure_qps=10, recovery_requests=10,
            alert_hold_seconds=2, rss_growth_kib=16384, fd_growth=32,
            environment="local-docker-desktop-arm64",
        )

    def capture_report(self, args):
        output = io.StringIO()
        with redirect_stdout(output):
            MODULE.build_report(args)
        return json.loads(output.getvalue())

    def test_valid_report(self):
        report = self.capture_report(self.report_args())
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["pressure"]["records_dropped"], 50)
        self.assertFalse(report["cost"]["paired_directional"]["acceptance_threshold_applied"])

    def test_duration_report_records_end_window_aborts(self):
        args = self.report_args()
        self.write(
            "pressure.oha.json", oha(errors={"aborted due to deadline": 3})
        )
        report = self.capture_report(args)
        self.assertEqual(report["pressure"]["load"]["end_window_client_aborts"], 3)

    def test_duration_report_rejects_other_client_error(self):
        args = self.report_args()
        self.write("pressure.oha.json", oha(errors={"connection reset": 1}))
        with self.assertRaisesRegex(AssertionError, "unexpected error"):
            MODULE.build_report(args)

    def test_report_rejects_short_alert_hold(self):
        args = self.report_args()
        args.alert_hold_seconds = 4
        with self.assertRaisesRegex(AssertionError, "alert hold"):
            MODULE.build_report(args)

    def test_report_rejects_missing_bounded_loss(self):
        args = self.report_args()
        self.write("pressure-paused.metrics.json", metrics(queue_depth=256, sink_healthy=0,
                                                           would_block_events_total=5))
        with self.assertRaisesRegex(AssertionError, "bounded loss"):
            MODULE.build_report(args)

    def test_report_rejects_restart(self):
        args = self.report_args()
        self.write("pressure-lifecycle.json", {
            "pid_before": 99, "pid_after": 99, "restart_count": 1, "exit_code": 0,
        })
        with self.assertRaisesRegex(AssertionError, "restarted"):
            MODULE.build_report(args)

    def test_report_rejects_unbounded_rss_growth(self):
        args = self.report_args()
        self.write("pressure-settled.process.json", {
            "pid": 99, "rss_kib": 20000, "fd_count": 10,
        })
        with self.assertRaisesRegex(AssertionError, "RSS growth"):
            MODULE.build_report(args)

    def test_report_rejects_unbounded_fd_growth(self):
        args = self.report_args()
        self.write("pressure-settled.process.json", {
            "pid": 99, "rss_kib": 1001, "fd_count": 50,
        })
        with self.assertRaisesRegex(AssertionError, "descriptor growth"):
            MODULE.build_report(args)

    def test_report_rejects_non_quiescent_gateway(self):
        args = self.report_args()
        self.write("pressure-quiescent.metrics.json", metrics(active_connections=1))
        with self.assertRaisesRegex(AssertionError, "request-quiescent"):
            MODULE.build_report(args)

    def test_report_rejects_final_accounting_mismatch(self):
        args = self.report_args()
        Path(args.records).write_text(json.dumps({
            "record": "event=runtime_log_final attempted=101 sent=50 dropped=50 shutdown_drops=0 queued=0"
        }) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "imbalanced"):
            MODULE.build_report(args)


if __name__ == "__main__":
    unittest.main()
