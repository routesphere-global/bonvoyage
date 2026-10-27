#!/usr/bin/env python3
"""Tests for the PERF-03 downstream TCP output collector."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("linux_socket_output.py")
SPEC = importlib.util.spec_from_file_location("linux_socket_output", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def summary(**changes: int) -> str:
    values = {
        "calls": 2000,
        "requested_bytes": 17_000_000,
        "completed_bytes": 16_800_000,
        "partial_writes": 20,
        "would_block": 40,
        "fatal_errors": 0,
        "entry_collisions": 0,
        "zero_returns": 0,
        "oversized_returns": 0,
        "inflight": 0,
        **changes,
    }
    aggregates = "\n".join(
        f"@{name}: {values[name]}"
        for name in MODULE.AGGREGATE_FIELDS if values[name] != 0
    )
    return "Attaching 3 probes...\nBONVOYAGE_SOCKET_OUTPUT_READY\n" \
           f"BONVOYAGE_SOCKET_OUTPUT_END inflight={values['inflight']}\n" \
           f"{aggregates}\n"


def identity(pid: int = 100, start_ticks: int = 200,
             restart_count: int = 0, **changes: object) -> dict:
    return {
        "interval_id": "interval-1",
        "pid": pid,
        "start_ticks": start_ticks,
        "restart_count": restart_count,
        "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
        "executable_path": "/usr/bin/bonvoyage-dataplane",
        "executable_sha256": "a" * 64,
        "snapshot_path": "/etc/bonvoyage/snapshot.pb",
        "snapshot_sha256": "b" * 64,
        "cmdline_sha256": "c" * 64,
        "response_path_diagnostics": True,
        **changes,
    }


class LinuxSocketOutputTest(unittest.TestCase):
    def test_valid_trace_builds_exact_analyzer_socket_shape(self) -> None:
        output, diagnostics = MODULE.build_socket_output(
            summary(), "", identity(), identity(), "interval-1",
            10_000_000_000)
        self.assertEqual(output, {
            "interval_id": "interval-1",
            "duration_nanoseconds": 10_000_000_000,
            "scope": "gateway-downstream-sockets",
            "pid": 100,
            "start_ticks": 200,
            "calls": 2000,
            "requested_bytes": 17_000_000,
            "completed_bytes": 16_800_000,
            "partial_writes": 20,
            "would_block": 40,
            "fatal_errors": 0,
            "lost_events": 0,
        })
        self.assertEqual(diagnostics["collector"],
                         "bpftrace-tcp-sendmsg")
        self.assertTrue(diagnostics["runtime_identity_stable"])
        self.assertEqual(diagnostics["executable_sha256"], "a" * 64)
        self.assertEqual(diagnostics["snapshot_sha256"], "b" * 64)

    def test_internal_pairing_anomalies_and_tracer_loss_are_retained(self) -> None:
        output, diagnostics = MODULE.build_socket_output(
            summary(entry_collisions=1, zero_returns=2,
                    oversized_returns=3, inflight=4),
            "Lost 5 events\n", identity(), identity(), "interval-1", 1)
        self.assertEqual(output["lost_events"], 15)
        self.assertEqual(diagnostics["reported_lost_events"], 5)
        self.assertEqual(diagnostics["inflight_at_detach"], 4)

    def test_missing_duplicate_and_error_output_fail_closed(self) -> None:
        duplicate_summary = summary() + summary().split(
            "BONVOYAGE_SOCKET_OUTPUT_READY\n", 1)[1]
        for trace, stderr, message in [
            (summary().replace("BONVOYAGE_SOCKET_OUTPUT_READY\n", ""), "",
             "readiness"),
            (duplicate_summary, "", "summary"),
            (summary(), "ERROR: probe attachment failed", "collector error"),
        ]:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    MODULE.parse_trace(trace, stderr)

    def test_unknown_and_duplicate_aggregates_fail_closed(self) -> None:
        for trace, message in [
            (summary() + "@foreign: 1\n", "unexpected aggregate"),
            (summary() + "@calls: 2\n", "aggregate is duplicated"),
        ]:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    MODULE.parse_trace(trace, "")

    def test_invalid_accounting_fails_closed(self) -> None:
        for trace, message in [
            (summary(calls=0), "no calls"),
            (summary(completed_bytes=17_000_001), "exceed requested"),
            (summary(calls=10, partial_writes=5, would_block=5,
                     fatal_errors=1), "classifications exceed"),
        ]:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    MODULE.parse_trace(trace, "")

    def test_process_replacement_and_restart_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "process changed"):
            MODULE.build_socket_output(summary(), "", identity(),
                                       identity(pid=101), "interval-1", 1)
        with self.assertRaisesRegex(ValueError, "restarted"):
            MODULE.build_socket_output(summary(), "", identity(),
                                       identity(restart_count=1),
                                       "interval-1", 1)

        output, diagnostics = MODULE.build_socket_output(
            summary(), "", identity(restart_count=3),
            identity(restart_count=3), "interval-1", 1)
        self.assertEqual(output["pid"], 100)
        self.assertEqual(diagnostics["service_restart_count"], 3)

    def test_runtime_artifact_drift_fails_closed(self) -> None:
        for field, changed in [
            ("executable_sha256", "d" * 64),
            ("snapshot_sha256", "e" * 64),
            ("cmdline_sha256", "f" * 64),
            ("response_path_diagnostics", False),
            ("boot_id", "11111111-2222-3333-4444-555555555555"),
        ]:
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, field):
                    MODULE.build_socket_output(
                        summary(), "", identity(), identity(**{field: changed}),
                        "interval-1", 1)

    def test_runtime_artifacts_bind_binary_snapshot_and_hashed_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "proc"
            process = proc / "321"
            (proc / "sys/kernel/random").mkdir(parents=True)
            process.mkdir(parents=True)
            binary = root / "bonvoyage-dataplane"
            snapshot = root / "snapshot.pb"
            binary.write_bytes(b"gateway-binary")
            snapshot.write_bytes(b"compiled-snapshot")
            os.symlink(binary, process / "exe")
            argv = [
                str(binary).encode(), b"--snapshot", str(snapshot).encode(),
                b"--response-path-diagnostics", b"--api-key=secret-value",
            ]
            cmdline = b"\0".join(argv) + b"\0"
            (process / "cmdline").write_bytes(cmdline)
            (proc / "sys/kernel/random/boot_id").write_text(
                "01234567-89ab-cdef-0123-456789abcdef\n", encoding="ascii")

            value = MODULE.runtime_artifacts(321, snapshot, proc)
            self.assertEqual(value["executable_sha256"], hashlib.sha256(
                b"gateway-binary").hexdigest())
            self.assertEqual(value["snapshot_sha256"], hashlib.sha256(
                b"compiled-snapshot").hexdigest())
            self.assertEqual(value["cmdline_sha256"], hashlib.sha256(
                cmdline).hexdigest())
            self.assertTrue(value["response_path_diagnostics"])
            self.assertNotIn("secret-value", json.dumps(value))

    def test_identity_files_require_exact_schema_and_interval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            path.write_text(json.dumps(identity()), encoding="utf-8")
            self.assertEqual(MODULE.load_identity(
                path, "interval-1", "identity")["pid"], 100)
            value = identity()
            value["extra"] = True
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected keys"):
                MODULE.load_identity(path, "interval-1", "identity")

    def test_resource_and_reactor_observations_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory) / "proc"
            process = proc / "100"
            (process / "fd").mkdir(parents=True)
            for descriptor in ("0", "1", "2"):
                (process / "fd" / descriptor).write_text("", encoding="ascii")
            (process / "status").write_text(
                "Name:\tbonvoyage\nVmRSS:\t4096 kB\n", encoding="ascii")
            task = process / "task"
            for tid, name, cpu in ((100, "bonvoyage-datap", 8),
                                   (101, "reactor-1", 9),
                                   (102, "alien-store", 10)):
                thread = task / str(tid)
                thread.mkdir(parents=True)
                (thread / "comm").write_text(name + "\n", encoding="ascii")
                (thread / "status").write_text(
                    f"Name:\t{name}\nCpus_allowed_list:\t{cpu}\n",
                    encoding="ascii")
                stat_fields = ["S", *("0" for _ in range(35)), str(cpu)]
                (thread / "stat").write_text(
                    f"{tid} ({name}) {' '.join(stat_fields)}\n",
                    encoding="ascii")

            resource = MODULE.resource_observation(identity(), proc)
            self.assertEqual(resource["rss_bytes"], 4096 * 1024)
            self.assertEqual(resource["file_descriptors"], 3)
            self.assertEqual(resource["identity"],
                             "01234567-89ab-cdef-0123-456789abcdef:100:200")
            self.assertEqual(MODULE.reactor_tids(identity(), 2, proc),
                             [100, 101])
            self.assertEqual(MODULE.reactor_placement(identity(), 2, proc), {
                "reactor_tids": [100, 101],
                "reactor_bindings": [
                    {"shard": 0, "tid": 100, "allowed_cpus": [8],
                     "current_cpu": 8},
                    {"shard": 1, "tid": 101, "allowed_cpus": [9],
                     "current_cpu": 9},
                ],
            })
            (task / "100" / "comm").write_text(
                "reactor-0\n", encoding="ascii")
            self.assertEqual(MODULE.reactor_tids(identity(), 2, proc),
                             [100, 101])
            (task / "100" / "comm").write_text(
                "bonvoyage-datap\n", encoding="ascii")
            (task / "101" / "status").write_text(
                "Name:\treactor-1\nCpus_allowed_list:\t9-10\n",
                encoding="ascii")
            with self.assertRaisesRegex(ValueError, "exactly one CPU"):
                MODULE.reactor_placement(identity(), 2, proc)
            with self.assertRaisesRegex(ValueError, "incomplete"):
                MODULE.reactor_tids(identity(), 3, proc)

    def test_runtime_state_resolves_tcp_peer_and_descriptor_classes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory) / "proc"
            process = proc / "100"
            descriptor_root = process / "fd"
            descriptor_root.mkdir(parents=True)
            os.symlink("/dev/null", descriptor_root / "0")
            os.symlink("socket:[111]", descriptor_root / "5")
            os.symlink("socket:[222]", descriptor_root / "6")
            os.symlink("anon_inode:[eventpoll]", descriptor_root / "7")
            (process / "status").write_text(
                "Name:\tbonvoyage\nVmRSS:\t4096 kB\n", encoding="ascii")
            network = process / "net"
            network.mkdir()
            header = ("  sl  local_address rem_address   st tx_queue "
                      "rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
            (network / "tcp").write_text(
                header +
                "   0: 0100007F:20FB 1E0200C0:1F91 01 "
                "00000000:00000000 00:00000000 00000000 1000 0 111\n",
                encoding="ascii")
            (network / "tcp6").write_text(
                header.replace("rem_address", "remote_address") +
                "   1: 00000000000000000000000001000000:20FC "
                "00000000000000000000000001000000:1F92 01 "
                "00000000:00000000 00:00000000 00000000 1000 0 222\n",
                encoding="ascii")

            state = MODULE.runtime_state_observation(identity(), proc)
            self.assertEqual(state["resource"]["file_descriptors"], 4)
            descriptors = state["descriptors"]
            self.assertEqual(descriptors["total"], 4)
            by_fd = {entry["fd"]: entry for entry in descriptors["entries"]}
            self.assertEqual(by_fd[0]["kind"], "file")
            self.assertEqual(by_fd[5]["kind"], "tcp-socket")
            self.assertEqual(by_fd[5]["tcp"]["remote_address"],
                             "192.0.2.30")
            self.assertEqual(by_fd[5]["tcp"]["remote_port"], 8081)
            self.assertEqual(by_fd[5]["tcp"]["state"], "ESTABLISHED")
            self.assertEqual(by_fd[6]["kind"], "tcp-socket")
            self.assertEqual(by_fd[6]["tcp"]["family"], "ipv6")
            self.assertEqual(by_fd[6]["tcp"]["remote_address"], "::1")
            self.assertEqual(by_fd[6]["tcp"]["remote_port"], 8082)
            self.assertEqual(by_fd[7]["kind"], "anon-inode")

    def test_tcp_table_ignores_zero_inodes_but_rejects_real_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            table = Path(directory) / "tcp"
            header = ("  sl  local_address rem_address   st tx_queue "
                      "rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
            zero_inode = ("   0: 140200C0:C001 1E0200C0:1F91 06 "
                          "00000000:00000000 03:00000000 00000000 "
                          "1000 0 0\n")
            owned = ("   1: 140200C0:C002 1E0200C0:1F91 01 "
                     "00000000:00000000 00:00000000 00000000 "
                     "1000 0 111\n")
            table.write_text(header + zero_inode + zero_inode + owned,
                             encoding="ascii")

            sockets = MODULE.tcp_socket_table(table, "ipv4")
            self.assertEqual(set(sockets), {111})
            self.assertEqual(sockets[111]["state"], "ESTABLISHED")

            table.write_text(header + owned + owned, encoding="ascii")
            with self.assertRaisesRegex(ValueError,
                                        "TCP socket inode is duplicated"):
                MODULE.tcp_socket_table(table, "ipv4")

    def test_probe_and_wrapper_keep_collection_bounded_and_vector_safe(self) -> None:
        probe = Path(__file__).with_name(
            "response-path-socket-output.bt").read_text(encoding="utf-8")
        wrapper = Path(__file__).with_name(
            "phase5-socket-output-collector.sh").read_text(encoding="utf-8")
        self.assertIn("pid == $1", probe)
        self.assertIn("skc_num == $2", probe)
        self.assertIn("kprobe:tcp_sendmsg", probe)
        self.assertIn("kretprobe:tcp_sendmsg", probe)
        self.assertIn("@active[tid] == 1", probe)
        self.assertNotIn("has_key(", probe)
        self.assertIn("BONVOYAGE_SOCKET_OUTPUT_END", probe)
        event_paths = probe.split("END", 1)[0]
        self.assertNotIn("printf(", event_paths.replace(
            'printf("BONVOYAGE_SOCKET_OUTPUT_READY\\n");', ""))
        self.assertIn('"$@" >"$output/client.stdout"', wrapper)
        self.assertNotIn("eval ", wrapper)
        self.assertIn("clean source required", wrapper)
        self.assertIn("--snapshot-file", wrapper)
        self.assertIn("capture_identity", wrapper)
        self.assertIn("--output -", wrapper)
        self.assertIn("client-argv.json", wrapper)
        self.assertIn("source-status-after.txt", wrapper)
        self.assertIn("collector-exit-code.txt", wrapper)
        self.assertIn("finalize_checksums", wrapper)
        self.assertIn("tracer-stop-signal.txt", wrapper)

    def test_native_reconciliation_covers_all_stable_gateway_threads(self) -> None:
        runner = Path(__file__).with_name(
            "phase5-response-path-native.sh").read_text(encoding="utf-8")
        self.assertIn("capture_threads", runner)
        self.assertIn('thread-ids-before.txt', runner)
        self.assertIn('thread-ids-after.txt', runner)
        self.assertIn('-t "$thread_ids"', runner)
        self.assertNotIn('-p "$pid"', runner)
        self.assertIn('application-before.prom', runner)
        self.assertIn('application-after.prom', runner)
        self.assertIn('runtime-manifest-sha256', runner)
        self.assertIn('assemble-native', runner)
        self.assertIn('"$@"', runner)
        self.assertNotIn("eval ", runner)


if __name__ == "__main__":
    unittest.main()
