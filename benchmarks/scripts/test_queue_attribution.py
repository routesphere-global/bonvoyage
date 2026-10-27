#!/usr/bin/env python3
"""Unit tests for the read-only Linux queue-attribution collector."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("queue_attribution.py")
SPEC = importlib.util.spec_from_file_location("queue_attribution", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def sample(name: str, shard: int, value: float) -> dict:
    return {"name": name, "labels": {"shard": str(shard)}, "value": value}


def metrics(offset: float) -> list[dict]:
    result = []
    for name in sorted(MODULE.METRIC_NAMES):
        for shard in (0, 1):
            value = offset
            if name == "bonvoyage_bonvoyage_gateway_requests_total":
                value += (300, 100)[shard]
            elif name == (
                    "bonvoyage_bonvoyage_gateway_downstream_connections_accepted_total"):
                value += (30, 10)[shard]
            elif name == "bonvoyage_bonvoyage_gateway_upstream_http1_pool_waits_total":
                value += (5, 0)[shard]
            elif name in MODULE.COUNTER_METRICS:
                value += (20, 10)[shard]
            else:
                value = (2, 1)[shard]
            result.append(sample(name, shard, value))
    return result


def snapshot(offset: float, monotonic_ns: int = 1_000_000_000) -> dict:
    return {
        "schema_version": 1,
        "captured_at": "2026-09-18T00:00:00+00:00",
        "monotonic_ns": monotonic_ns,
        "hostname": "gateway",
        "interface": "ens5",
        "clock": {
            "current_clocksource": "tsc",
            "available_clocksources": ["tsc", "kvm-clock", "hpet"],
            "tsc_capabilities": {
                "tsc": True,
                "rdtscp": True,
                "constant_tsc": True,
                "nonstop_tsc": True,
                "tsc_known_freq": True,
            },
        },
        "process": {
            "service": "bonvoyage.service",
            "pid": 123,
            "start_ticks": 456,
            "restarts": 0,
            "cpu_affinity": "8-31",
            "executable": "/usr/local/bin/bonvoyage-dataplane",
            "executable_sha256": "binary",
            "rss_kib": 44000 + int(offset),
            "fd_count": 20 + int(offset),
            "boot_id": "boot",
        },
        "source": {"commit": "abc", "dirty": False},
        "collector_sha256": "collector",
        "metrics": metrics(offset),
        "interrupts": {
            "cpus": ["CPU0", "CPU1"],
            "rows": {"100": {"counts": [int(offset) + 10, int(offset) + 20]}},
        },
        "softirqs": {
            "cpus": ["CPU0", "CPU1"],
            "rows": {
                "NET_RX": {"counts": [int(offset) + 1, int(offset) + 2]},
                "NET_TX": {"counts": [int(offset) + 3, int(offset) + 4]},
            },
        },
        "softnet": [{
            "cpu": cpu,
            "processed": int(offset) + cpu + 10,
            "dropped": 0,
            "time_squeeze": 0,
            "received_rps": 0,
            "flow_limit_count": 0,
        } for cpu in (0, 1)],
        "proc_stat": {
            "cpu0": [int(offset) + 10, 0, 10, int(offset) + 80, 0, 0, 0, 0],
            "cpu1": [int(offset) + 20, 0, 10, int(offset) + 70, 0, 0, 0, 0],
        },
        "ethtool": {
            "rx_packets": int(offset) + 100,
            "conntrack_allowance_available": 10_000 - int(offset),
        },
    }


class QueueAttributionTest(unittest.TestCase):
    def test_clock_identity_records_kernel_source_and_tsc_capabilities(self) -> None:
        identity = MODULE.parse_clock_identity(
            "tsc\n",
            "tsc kvm-clock hpet acpi_pm\n",
            "fpu tsc rdtscp constant_tsc nonstop_tsc tsc_known_freq\n",
        )
        self.assertEqual(identity["current_clocksource"], "tsc")
        self.assertEqual(identity["available_clocksources"],
                         ["tsc", "kvm-clock", "hpet", "acpi_pm"])
        self.assertTrue(all(identity["tsc_capabilities"].values()))

        with self.assertRaisesRegex(ValueError, "not listed as available"):
            MODULE.parse_clock_identity("tsc", "hpet acpi_pm", "tsc")

    def test_prometheus_parser_requires_and_retains_selected_metrics(self) -> None:
        text = "\n".join(
            f'{name}{{shard="0"}} 1' for name in sorted(MODULE.METRIC_NAMES))
        parsed = MODULE.parse_prometheus(text)
        self.assertEqual(len(parsed), len(MODULE.METRIC_NAMES))
        self.assertEqual({item["name"] for item in parsed}, MODULE.METRIC_NAMES)

    def test_cpu_table_and_softnet_parsers(self) -> None:
        table = MODULE.parse_cpu_table(
            "           CPU0 CPU1\n100: 10 20 PCI-MSI ens5-Tx-Rx-0\n")
        self.assertEqual(table["rows"]["100"]["counts"], [10, 20])
        softnet = MODULE.parse_softnet("00000001 00000002 00000003 0 0 0 0 0 0 0 0\n")
        self.assertEqual(softnet[0]["dropped"], 2)
        self.assertEqual(softnet[0]["time_squeeze"], 3)

    def test_analysis_attributes_pool_pressure_and_per_cpu_irq_deltas(self) -> None:
        before = snapshot(0)
        after = snapshot(100, 11_000_000_000)
        result = MODULE.analyze(before, after)
        self.assertEqual(result["observation"],
                         "upstream_http1_pool_pressure_observed")
        self.assertEqual(result["duration_seconds"], 10.0)
        self.assertEqual(result["host"]["nic_irq_deltas"]["100"], [100, 100])
        self.assertEqual(result["host"]["ethtool_deltas"]["rx_packets"], 100)
        self.assertEqual(
            result["host"]["ethtool_gauges"]["conntrack_allowance_available"],
            {"before": 10_000, "after": 9_900, "change": -100})
        self.assertEqual(result["gateway"]["requests_by_shard"], {0: 100, 1: 100})
        self.assertEqual(result["gateway"]["memory_malloc_operations_by_shard"],
                         {0: 100, 1: 100})
        self.assertEqual(result["gateway"]["scheduler_waittime_ms_by_shard"],
                         {0: 100, 1: 100})
        self.assertEqual(
            result["gateway"]["perf04_counter_deltas_by_shard"]
            ["overload_rejections_total"], {0: 100, 1: 100})
        self.assertEqual(
            result["gateway"]["perf04_gauge_edges_by_shard"]
            ["active_requests"][0],
            {"before": 2, "after": 2, "change": 0})
        self.assertEqual(result["resources"]["rss_kib"]["change"], 100)
        self.assertEqual(result["resources"]["file_descriptors"]["change"],
                         100)
        self.assertEqual(result["host"]["irq_cpu_busy_ratio"],
                         {"cpu0": 0.0, "cpu1": 0.0})
        self.assertTrue(result["process_identity_stable"])

    def test_analysis_rejects_actual_ethtool_counter_regression(self) -> None:
        before = snapshot(0)
        after = snapshot(100, 11_000_000_000)
        after["ethtool"]["rx_packets"] = before["ethtool"]["rx_packets"] - 1
        with self.assertRaisesRegex(ValueError, "ethtool counter regressed"):
            MODULE.analyze(before, after)

    def test_trace_analysis_retains_rates_and_shard_gauge_peaks(self) -> None:
        started = datetime(2026, 9, 18, tzinfo=timezone.utc)
        rows = [
            (started, metrics(0)),
            (started + timedelta(seconds=1), metrics(100)),
            (started + timedelta(seconds=3), metrics(300)),
        ]
        result = MODULE.analyze_trace(rows)
        self.assertEqual(result["window"]["duration_seconds"], 3.0)
        self.assertEqual(result["requests"]["delta"], 600)
        self.assertEqual(result["requests"]["mean_per_second"], 200.0)
        self.assertEqual(result["requests"]["minimum_interval_per_second"],
                         200.0)
        queue = result["gauges"]["bonvoyage_scheduler_queue_length"]
        self.assertEqual(queue["total_peak"], 3)
        self.assertEqual(queue["per_shard_peak"], {"0": 2, "1": 1})

    def test_analysis_rejects_process_identity_change(self) -> None:
        before = snapshot(0)
        after = snapshot(100, 11_000_000_000)
        after["process"]["pid"] = 124
        with self.assertRaisesRegex(ValueError, "process identity changed"):
            MODULE.analyze(before, after)

    def test_analysis_rejects_clock_identity_change(self) -> None:
        before = snapshot(0)
        after = snapshot(100, 11_000_000_000)
        after["clock"]["current_clocksource"] = "kvm-clock"
        with self.assertRaisesRegex(ValueError, "clock identity changed"):
            MODULE.analyze(before, after)

    def test_analysis_keeps_legacy_snapshots_without_clock_identity(self) -> None:
        before = snapshot(0)
        after = snapshot(100, 11_000_000_000)
        del before["clock"]
        del after["clock"]
        self.assertIsNone(MODULE.analyze(before, after)["clock"])

    def test_delta_map_rejects_irq_cpu_shape_change(self) -> None:
        with self.assertRaisesRegex(ValueError, "CPU count changed"):
            MODULE.delta_map({"100": [1, 2]}, {"100": [2]}, "NIC IRQ")

    def test_capture_verification_rejects_modified_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = b'{"schema_version": 1}\n'
            (root / "snapshot.json").write_bytes(content)
            manifest = {
                "schema_version": 1,
                "files": [{
                    "path": "snapshot.json",
                    "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }],
            }
            (root / "checksums.json").write_text(json.dumps(manifest),
                                                   encoding="utf-8")
            self.assertEqual(MODULE.verify_capture(root)["schema_version"], 1)
            (root / "snapshot.json").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "changed"):
                MODULE.verify_capture(root)


if __name__ == "__main__":
    unittest.main()
