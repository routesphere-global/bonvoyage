#!/usr/bin/env python3
"""Synthetic scanner orchestration tests. No Docker, AWS or real database."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("pair", Path(__file__).with_name("scan-runtime-sbom-pair.py"))
pair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pair)


class PairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.out = self.root / "out"
        self.tooling = self.root / "tooling"
        self.tooling.mkdir()
        for name in ("scan-runtime-sbom-pair.py", "verify-runtime-image-binding.py",
                     "verify-runtime-scan-parity.mjs", "summarize-vulnerability-scan.mjs"):
            (self.tooling / name).write_text("synthetic tooling: " + name)

    def test_scanner_is_offline_readonly_unprivileged_without_socket(self):
        for image, kwargs in ((pair.SYFT, {}), (pair.GRYPE, {"database": self.root})):
            command = pair.container(image, **kwargs)
            for flag, value in (("--network", "none"), ("--pull", "never"), ("--cap-drop", "ALL"),
                                ("--security-opt", "no-new-privileges"), ("--user", f"{os.getuid()}:{os.getgid()}")):
                self.assertEqual(command[command.index(flag) + 1], value)
            self.assertIn("--read-only", command)
            self.assertNotIn("--cap-add", command)
            self.assertNotIn("--group-add", command)
            self.assertNotIn("docker.sock", " ".join(command))
        self.assertIn(f"{self.root}:/database:ro", command)
        for value in ("GRYPE_DB_AUTO_UPDATE=false", "GRYPE_DB_VALIDATE_BY_HASH_ON_START=true",
                      "GRYPE_DB_VALIDATE_AGE=true", "GRYPE_DB_MAX_ALLOWED_BUILT_AGE=48h"):
            self.assertIn(value, command)

    def test_only_database_hydration_can_use_network_and_write_cache(self):
        command = pair.container(pair.GRYPE, database=self.root, online=True)
        self.assertIn("bridge", command)
        self.assertIn(f"{self.root}:/database:rw", command)
        with self.assertRaises(ValueError):
            pair.container(pair.SYFT, online=True)
        with self.assertRaises(ValueError):
            pair.container("untrusted-scanner", database=self.root)

    def test_database_hashes_detect_content_drift_and_reject_symlinks(self):
        db = self.root / "6"
        db.mkdir()
        payload = db / "vulnerability.db"
        payload.write_bytes(b"database fixture")
        before = pair.database_snapshot(self.root)
        payload.write_bytes(b"database changed")
        self.assertNotEqual(before, pair.database_snapshot(self.root))
        payload.unlink()
        payload.symlink_to(__file__)
        with self.assertRaisesRegex(ValueError, "symlink"):
            pair.database_snapshot(self.root)

    def test_command_preserves_nonzero_receipts(self):
        self.out.mkdir()
        self.assertEqual(pair.command(self.out, "blocked", [sys.executable, "-c", "print('{}'); exit(1)"], allowed=(0, 1)), 1)
        receipt = json.loads((self.out / "blocked.command.json").read_text())
        self.assertEqual(receipt["exit_code"], 1)
        self.assertEqual(receipt["stdout_sha256"], pair.file_hash(self.out / "blocked.stdout"))
        with self.assertRaises(ValueError):
            pair.command(self.out, "invalid", [sys.executable, "-c", "exit(2)"])
        self.assertTrue((self.out / "invalid.command.json").exists())

    def assert_failed_command_receipt(self, out, failure):
        receipt = json.loads((out / "failed.command.json").read_text())
        self.assertIsNone(receipt["exit_code"])
        self.assertEqual(receipt["failure"], failure)
        self.assertGreater(receipt["started_unix"], 0)
        self.assertGreaterEqual(receipt["elapsed_seconds"], 0)
        for stream in ("stdout", "stderr"):
            self.assertEqual(receipt[stream + "_sha256"], pair.file_hash(out / ("failed." + stream)))
        return receipt

    def test_docker_timeout_retains_primary_and_cleanup_receipts(self):
        cases = [
            ("success", pair.subprocess.CompletedProcess([], 0, b"removed", b""), 0, None),
            ("nonzero", pair.subprocess.CompletedProcess([], 1, b"", b"daemon error"), 1, None),
            ("timeout", pair.subprocess.TimeoutExpired("cleanup", 30, output=b"partial", stderr=b"\xff"),
             None, "container cleanup timed out"),
            ("empty-timeout", pair.subprocess.TimeoutExpired("cleanup", 30), None, "container cleanup timed out"),
            ("oserror", OSError("cleanup unavailable"), None, "cleanup unavailable"),
        ]
        for name, outcome, exit_code, failure in cases:
            with self.subTest(cleanup=name):
                out = self.root / name
                out.mkdir()
                argv = pair.container(pair.SYFT) + [pair.SYFT, "version"]
                def run(args, **kwargs):
                    if args[:2] == ["docker", "run"]:
                        kwargs["stdout"].write(b"partial scan output")
                        kwargs["stderr"].write(b"partial scan error")
                        raise pair.subprocess.TimeoutExpired(args, kwargs["timeout"])
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome
                with patch.object(pair.subprocess, "run", side_effect=run) as mocked:
                    with self.assertRaisesRegex(ValueError, "failed failed"):
                        pair.command(out, "failed", argv, allowed=(0, 1, None), timeout=7)
                receipt = self.assert_failed_command_receipt(out, "command timed out")
                cleanup = json.loads((out / "failed.cleanup.json").read_text())
                allocated = receipt["argv"][receipt["argv"].index("--name") + 1]
                self.assertTrue(allocated.startswith("bonvoyage-sbom-"))
                self.assertNotIn("--name", argv)
                self.assertEqual(cleanup["container"], allocated)
                self.assertEqual(cleanup["exit_code"], exit_code)
                self.assertEqual(cleanup["failure"], failure)
                for stream in ("stdout", "stderr"):
                    expected = (getattr(outcome, stream, None) or b"").decode(errors="replace")
                    self.assertEqual(cleanup[stream], expected)
                    self.assertTrue((out / ("failed." + stream)).read_bytes().startswith(b"partial scan"))
                self.assertEqual(mocked.call_count, 2)
                self.assertEqual(mocked.call_args_list[0].kwargs["timeout"], 7)
                self.assertEqual(mocked.call_args.args[0], ["docker", "rm", "--force", allocated])
                self.assertEqual(mocked.call_args.kwargs["timeout"], 30)

    def test_noncontainer_timeout_and_launch_error_retain_receipt_without_cleanup(self):
        for name, error, failure in (
            ("timeout", pair.subprocess.TimeoutExpired("tool", 1), "command timed out"),
            ("oserror", OSError("tool unavailable"), "tool unavailable"),
        ):
            with self.subTest(failure=name):
                out = self.root / name
                out.mkdir()
                with patch.object(pair.subprocess, "run", side_effect=error) as run:
                    with self.assertRaises(ValueError):
                        pair.command(out, "failed", ["tool"])
                self.assert_failed_command_receipt(out, failure)
                self.assertEqual(run.call_count, 1)
                self.assertFalse((out / "failed.cleanup.json").exists())

    def test_cleanup_receipt_write_failure_does_not_lose_command_receipt(self):
        self.out.mkdir()
        write_json = pair.write_json
        def write(path, data):
            if path.name == "failed.cleanup.json":
                raise OSError("cleanup receipt unavailable")
            write_json(path, data)
        with patch.object(pair.subprocess, "run", side_effect=[
            pair.subprocess.TimeoutExpired("scanner", 1), pair.subprocess.CompletedProcess([], 0, b"", b"")
        ]), patch.object(pair, "write_json", side_effect=write):
            with self.assertRaisesRegex(OSError, "cleanup receipt unavailable"):
                pair.command(self.out, "failed", pair.container(pair.SYFT) + [pair.SYFT, "version"])
        self.assert_failed_command_receipt(self.out, "command timed out")

    def exercise(self, *, code=0, drift=False, inputs_drift=False, low_disk=False,
                 command_hook=None, verify_hook=None):
        calls = []
        def command(out, name, argv, **kwargs):
            calls.append((name, argv))
            if name == "database-update":
                db = out / "database/6"
                db.mkdir()
                (db / "vulnerability.db").write_bytes(b"synthetic payload")
                (db / "metadata.json").write_text('{"synthetic": true}')
            if name == "scan-cdx" and drift:
                (out / "database/6/vulnerability.db").write_bytes(b"drift")
            (out / (name + ".stdout")).write_text(json.dumps({"gate": {"passed": code == 0}}))
            if command_hook:
                command_hook(name)
            return code if name == "scan-parity" else 0
        identity = {"input_sha256": {"archive": "fixture"}}
        second = {"input_sha256": {"archive": "changed"}} if inputs_drift else identity
        identities = iter((identity, second))
        def verify_inputs(*args):
            if verify_hook:
                verify_hook()
            return next(identities)
        with patch.object(pair.binding, "verify", side_effect=verify_inputs) as verify, \
             patch.object(pair, "command", side_effect=command), \
             patch.object(pair, "ROOT", self.tooling), \
             patch.object(pair.shutil, "disk_usage") as disk:
            disk.return_value.free = 0 if low_disk else 16 * 1024**3
            result = pair.scan_pair(self.root, self.out, "independently-selected-lock", "linux/amd64")
            self.assertEqual(verify.call_count, 2)
            self.assertEqual(verify.call_args.args[1], "independently-selected-lock")
        return result, calls

    def assert_complete_evidence(self):
        result = json.loads((self.out / "result.json").read_text())
        tooling = {path.name: pair.file_hash(path) for path in self.tooling.iterdir()}
        self.assertEqual(result["runner_sha256"], tooling)
        for name in ("tooling-before.json", "tooling-after.json"):
            self.assertEqual(json.loads((self.out / name).read_text()), tooling)
        for name in ("database-before.json", "database-after-cdx.json", "database-after-spdx.json", "database-final.json"):
            self.assertEqual(json.loads((self.out / name).read_text()), result["database_files"])
        seal = json.loads((self.out / "evidence-checksums.json").read_text())
        self.assertEqual(seal, {str(p.relative_to(self.out)): pair.file_hash(p)
                               for p in self.out.rglob("*") if p.is_file() and p.name != "evidence-checksums.json"})
        self.assertEqual({name: digest for name, digest in seal.items() if name.startswith("database/")},
                         {"database/" + name: record["sha256"] for name, record in result["database_files"].items()})

    def test_passing_scan_retains_consistent_tooling_database_and_seal(self):
        code, _ = self.exercise()
        self.assertEqual(code, 0)
        self.assertTrue(json.loads((self.out / "result.json").read_text())["gate"]["passed"])
        self.assert_complete_evidence()

    def test_order_one_update_two_offline_scans_and_high_failure_evidence(self):
        code, calls = self.exercise(code=1)
        self.assertEqual(code, 1)
        self.assertEqual([name for name, _ in calls], ["decode-cdx", "decode-spdx", "decoder-parity",
            "database-update", "database-status", "scan-cdx", "scan-spdx", "scan-parity"])
        for name, argv in calls:
            if name.startswith("scan-") and name != "scan-parity":
                self.assertEqual(argv[argv.index("--network") + 1], "none")
                self.assertIn(f"{self.out.resolve()}/database:/database:ro", argv)
        result = json.loads((self.out / "result.json").read_text())
        self.assertFalse(result["gate"]["passed"])
        self.assertIn("6/vulnerability.db", result["database_files"])
        self.assertTrue((self.out / "evidence-checksums.json").exists())
        self.assert_complete_evidence()

    def assert_no_completed_evidence(self):
        self.assertFalse((self.out / "result.json").exists())
        self.assertFalse((self.out / "evidence-checksums.json").exists())

    def test_each_tooling_file_drift_fails_without_result_or_seal(self):
        for path in sorted(self.tooling.iterdir()):
            with self.subTest(tool=path.name):
                self.out = self.root / ("out-" + path.name)
                def mutate(name):
                    if name == "scan-parity":
                        path.write_text("changed tooling")
                with self.assertRaisesRegex(ValueError, "scan tooling changed"):
                    self.exercise(command_hook=mutate)
                before = json.loads((self.out / "tooling-before.json").read_text())
                after = json.loads((self.out / "tooling-after.json").read_text())
                self.assertNotEqual(before[path.name], after[path.name])
                self.assertEqual(after[path.name], pair.file_hash(path))
                self.assert_no_completed_evidence()

    def test_tooling_snapshot_precedes_initial_binding_verification(self):
        def mutate():
            self.assertTrue((self.out / "tooling-before.json").exists())
            (self.tooling / "verify-runtime-image-binding.py").write_text("changed binding tooling")
        with self.assertRaisesRegex(ValueError, "scan tooling changed"):
            self.exercise(verify_hook=mutate)
        self.assert_no_completed_evidence()

    def test_tooling_drift_during_sealing_fails_without_result_or_seal(self):
        file_hash = pair.file_hash
        def mutate(path):
            if path == self.out / "binding.json":
                (self.tooling / "summarize-vulnerability-scan.mjs").write_text("changed during sealing")
            return file_hash(path)
        with patch.object(pair, "file_hash", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "scan tooling changed"):
                self.exercise()
        self.assert_no_completed_evidence()

    def test_database_drift_after_scans_fails_without_result_or_seal(self):
        def mutate(name):
            if name == "scan-parity":
                (self.out / "database/6/vulnerability.db").write_bytes(b"late drift")
        with self.assertRaisesRegex(ValueError, "database changed before evidence seal"):
            self.exercise(command_hook=mutate)
        self.assertNotEqual(json.loads((self.out / "database-before.json").read_text()),
                            json.loads((self.out / "database-final.json").read_text()))
        self.assert_no_completed_evidence()

    def test_database_drift_after_seal_hash_fails_without_result_or_seal(self):
        file_hash = pair.file_hash
        def mutate(path):
            if path == self.out / "scan-parity.stdout":
                (self.out / "database/6/vulnerability.db").write_bytes(b"post-hash drift")
            return file_hash(path)
        with patch.object(pair, "file_hash", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "database changed before evidence seal"):
                self.exercise()
        self.assert_no_completed_evidence()

    def test_database_seal_hash_mismatch_rejected_even_if_final_snapshot_matches(self):
        file_hash = pair.file_hash
        changed = False
        def mutate(path):
            nonlocal changed
            if path == self.out / "database/6/vulnerability.db" and \
                    (self.out / "database-after-spdx.json").exists() and not changed:
                changed = True
                original = path.read_bytes()
                path.write_bytes(b"temporary seal-time drift")
                digest = file_hash(path)
                path.write_bytes(original)
                return digest
            return file_hash(path)
        with patch.object(pair, "file_hash", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "database changed while sealing evidence"):
                self.exercise()
        self.assertTrue(changed)
        self.assertEqual(json.loads((self.out / "database-before.json").read_text()),
                         json.loads((self.out / "database-final.json").read_text()))
        self.assert_no_completed_evidence()

    def test_database_seal_file_set_mismatch_rejected_even_if_final_snapshot_matches(self):
        file_hash = pair.file_hash
        for drift in ("extra", "missing"):
            with self.subTest(drift=drift):
                self.out = self.root / drift
                extra = self.out / "database/6/extra.json"
                metadata = self.out / "database/6/metadata.json"
                def before_seal(name):
                    if name == "scan-parity":
                        if drift == "extra":
                            extra.write_text("{}")
                        else:
                            metadata.unlink()
                def during_seal(path):
                    digest = file_hash(path)
                    if drift == "extra" and path == extra:
                        extra.unlink()
                    if drift == "missing" and path == self.out / "database/6/vulnerability.db":
                        metadata.write_text('{"synthetic": true}')
                    return digest
                with patch.object(pair, "file_hash", side_effect=during_seal):
                    with self.assertRaisesRegex(ValueError, "database changed while sealing evidence"):
                        self.exercise(command_hook=before_seal)
                self.assertEqual(json.loads((self.out / "database-before.json").read_text()),
                                 json.loads((self.out / "database-final.json").read_text()))
                self.assert_no_completed_evidence()

    def test_database_drift_fails_without_result(self):
        with self.assertRaisesRegex(ValueError, "database changed"):
            self.exercise(drift=True)
        self.assertFalse((self.out / "result.json").exists())

    def test_input_drift_fails_without_result(self):
        with self.assertRaisesRegex(ValueError, "inputs changed"):
            self.exercise(inputs_drift=True)
        self.assertFalse((self.out / "result.json").exists())

    def test_low_disk_fails_before_hydration(self):
        with self.assertRaisesRegex(ValueError, "free disk"):
            self.exercise(low_disk=True)
        self.assertFalse((self.out / "database").exists())

    def test_existing_output_is_never_reused(self):
        self.out.mkdir()
        with self.assertRaisesRegex(ValueError, "new scan-pair"):
            pair.scan_pair(self.root, self.out, "lock", "linux/amd64")


if __name__ == "__main__":
    unittest.main()
