import copy
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


SOURCE = Path(__file__).with_name("collect-oss-native-install.py")
FIXTURE_SNAPSHOT = SOURCE.parents[1] / "tests/fixtures/oss-native-fresh-install.pb"
SPEC = importlib.util.spec_from_file_location("collect_oss_native_install", SOURCE)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class NativeInstallCollectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.contract = self.root / "contract.json"
        self.contract.write_bytes(collector.DEFAULT_CONTRACT.read_bytes())
        self.package = self.root / "bonvoyage-gateway_1.0.0-1_amd64.deb"
        self.package.write_bytes(b"fixture package\n")
        self.snapshot = self.root / "snapshot.pb"
        self.snapshot.write_bytes(FIXTURE_SNAPSHOT.read_bytes())
        self.receipt = self.root / "build-receipt.json"
        self.receipt_document = self.make_receipt()
        self.write_json(self.receipt, self.receipt_document)

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def make_receipt(self):
        package = self.package.read_bytes()
        return {
            "schema_version": 1,
            "classification": "routesphere-bonvoyage-oss-deb-build",
            "outcome": "built-technical-candidate",
            "builder_id": "fixture-builder",
            "source": {
                "repository": "https://github.com/routesphere-global/bonvoyage",
                "commit": "1" * 40,
                "tag": "v1.0.0",
                "source_date_epoch": 1700000000,
                "dirty": False,
                "status_sha256": digest(b""),
            },
            "binding": {"input_manifest_sha256": "2" * 64},
            "distribution": "ubuntu-24.04",
            "architecture": "amd64",
            "release_version": "1.0.0",
            "debian_version": "1.0.0-1",
            "command": ["dpkg-buildpackage", "-us", "-uc", "-b"],
            "exit_code": 0,
            "payload": {
                "usr/bin/bonvoyage-dataplane": {
                    "bytes": 123,
                    "sha256": digest(b"installed binary\n"),
                }
            },
            "control": {"control": {"bytes": 10, "sha256": "3" * 64}},
            "package": {
                "path": self.package.name,
                "bytes": len(package),
                "sha256": digest(package),
                "version": "1.0.0-1",
                "architecture": "amd64",
            },
            "technical_candidate_built": True,
            "reproducibility_qualified": False,
            "sbom_qualified": False,
            "scan_qualified": False,
            "signature_qualified": False,
            "provenance_qualified": False,
            "lifecycle_qualified": False,
            "release_admitted": False,
            "publishable": False,
        }

    def input_arguments(self):
        return {
            "contract_path": self.contract,
            "contract_sha256": digest(self.contract.read_bytes()),
            "package": self.package,
            "package_sha256": digest(self.package.read_bytes()),
            "receipt_path": self.receipt,
            "receipt_sha256": digest(self.receipt.read_bytes()),
            "snapshot": self.snapshot,
            "snapshot_sha256": digest(self.snapshot.read_bytes()),
        }

    @staticmethod
    def metric_text(values):
        lines = []
        for name, metric in collector.METRICS.items():
            value = values.get(name, 0)
            lines.append(f'{metric}{{shard="0"}} {value}')
        return "\n".join(lines) + "\n"

    def test_accepts_exact_checksum_bound_inputs(self):
        result = collector.validate_inputs(**self.input_arguments())
        self.assertEqual(result["build"]["package"]["version"], "1.0.0-1")
        self.assertEqual(result["snapshot_record"]["sha256"],
                         digest(self.snapshot.read_bytes()))
        self.assertFalse(result["build"]["source"]["dirty"])

    def test_stages_exact_verified_bytes_for_privileged_tools(self):
        inputs = collector.validate_inputs(**self.input_arguments())
        staging_parent = self.root / "staging"
        staging_parent.mkdir(mode=0o700)
        staged, stage = collector.stage_verified_inputs(inputs, staging_parent)
        try:
            self.assertEqual(staged["package_path"].name, self.package.name)
            self.assertEqual(staged["package_path"].read_bytes(), inputs["package_raw"])
            self.assertEqual(staged["receipt_path"].read_bytes(), inputs["receipt_raw"])
            self.package.write_bytes(b"replaced after verification\n")
            self.assertEqual(staged["package_path"].read_bytes(), inputs["package_raw"])
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600
                                for path in stage.iterdir()))
        finally:
            collector.cleanup_staged_inputs(stage)
        self.assertFalse(stage.exists())

    def test_staging_cleanup_rejects_unexpected_directory(self):
        stage = self.root / "bonvoyage-oss-native-test"
        stage.mkdir(mode=0o700)
        (stage / "unexpected").mkdir()
        with self.assertRaisesRegex(collector.Rejected, "unexpected staging entry"):
            collector.cleanup_staged_inputs(stage)

    def test_staging_rejects_colliding_package_filename(self):
        inputs = collector.validate_inputs(**self.input_arguments())
        inputs["package_path"] = self.root / "contract.json"
        staging_parent = self.root / "staging-collision"
        staging_parent.mkdir(mode=0o700)
        with self.assertRaisesRegex(collector.Rejected, "filenames collide"):
            collector.stage_verified_inputs(inputs, staging_parent)
        self.assertEqual(tuple(staging_parent.iterdir()), ())

    def test_rejects_changed_input_or_authority_escalation(self):
        arguments = self.input_arguments()
        arguments["snapshot_sha256"] = "0" * 64
        with self.assertRaisesRegex(collector.Rejected, "snapshot SHA-256 mismatch"):
            collector.validate_inputs(**arguments)

        self.snapshot.write_bytes(b"different but checksum-bound snapshot\n")
        arguments = self.input_arguments()
        with self.assertRaisesRegex(collector.Rejected, "contract-bound fixture"):
            collector.validate_inputs(**arguments)
        self.snapshot.write_bytes(FIXTURE_SNAPSHOT.read_bytes())

        changed = copy.deepcopy(self.receipt_document)
        changed["publishable"] = True
        self.write_json(self.receipt, changed)
        arguments = self.input_arguments()
        with self.assertRaisesRegex(Exception, "escalates publishable"):
            collector.validate_inputs(**arguments)

    def test_rejects_duplicate_contract_fields_before_execution(self):
        raw = self.contract.read_text(encoding="utf-8").replace(
            '  "schema_version": 1,',
            '  "schema_version": 1,\n  "schema_version": 1,',
            1,
        )
        self.contract.write_text(raw, encoding="utf-8")
        with self.assertRaisesRegex(collector.Rejected, "duplicate JSON field"):
            collector.validate_inputs(**self.input_arguments())

    def test_rejects_symlinked_input(self):
        real = self.root / "real-snapshot.pb"
        real.write_bytes(self.snapshot.read_bytes())
        self.snapshot.unlink()
        os.symlink(real, self.snapshot)
        with self.assertRaisesRegex(collector.Rejected, "canonical absolute path|linked"):
            collector.validate_inputs(**self.input_arguments())

    def test_platform_is_exact_and_privileged(self):
        release = 'ID=ubuntu\nVERSION_ID="24.04"\n'
        collector.validate_platform(release, "x86_64", 0, "systemd")
        variants = (
            ('ID=debian\nVERSION_ID="24.04"\n', "x86_64", 0, "systemd"),
            (release, "aarch64", 0, "systemd"),
            (release, "x86_64", 1000, "systemd"),
            (release, "x86_64", 0, "launchd"),
        )
        for values in variants:
            with self.subTest(values=values), self.assertRaises(collector.Rejected):
                collector.validate_platform(*values)

    def test_admin_readiness_body_matches_the_dataplane_contract(self):
        self.assertEqual(collector.ADMIN_READY_BODY, b'{"status":"ok"}\n')
        source = (SOURCE.parents[1] / "dataplane/src/main.cc").read_text(encoding="utf-8")
        self.assertIn(r'return seastar::sstring{"{\"status\":\"ok\"}\n"};', source)

    def test_os_release_and_systemd_output_reject_duplicates(self):
        with self.assertRaisesRegex(collector.Rejected, "duplicate os-release"):
            collector.parse_os_release("ID=ubuntu\nID=ubuntu\n")
        with self.assertRaisesRegex(collector.Rejected, "duplicate key-value"):
            collector.parse_key_values("MainPID=1\nMainPID=2\n")

    def test_clean_stop_uses_numeric_systemd_exec_code(self):
        fields = {
            "ActiveState": "inactive",
            "MainPID": "0",
            "Result": "success",
            "ExecMainCode": "1",
            "ExecMainStatus": "0",
            "NRestarts": "0",
        }
        self.assertTrue(collector.clean_service_stop(fields, False))
        fields["ExecMainCode"] = "exited"
        self.assertFalse(collector.clean_service_stop(fields, False))
        fields["ExecMainCode"] = "1"
        self.assertFalse(collector.clean_service_stop(fields, True))

    def test_socket_inventory_is_exact_owned_and_filtered(self):
        sockets = "\n".join((
            'LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("bonvoyage",pid=4242,fd=10))',
            'LISTEN 0 128 127.0.0.1:9090 0.0.0.0:* users:(("bonvoyage",pid=4242,fd=11))',
            'LISTEN 0 128 127.0.0.1:9901 0.0.0.0:* users:(("bonvoyage",pid=4242,fd=12))',
            'LISTEN 0 128 127.0.0.1:18081 0.0.0.0:* users:(("python3",pid=5252,fd=3))',
            'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=4))',
        ))
        records = collector.parse_owned_listeners(sockets, 4242, 5252)
        self.assertEqual(len(records), 4)
        self.assertNotIn("sshd", json.dumps(records))
        with self.assertRaisesRegex(collector.Rejected, "topology differs"):
            collector.parse_owned_listeners(
                sockets + '\nLISTEN 0 128 127.0.0.1:7000 0.0.0.0:* users:(("bonvoyage",pid=4242,fd=13))',
                4242, 5252)

    def test_accepts_exact_metric_accounting(self):
        before = self.metric_text({
            "requests": 10,
            "responses_2xx": 10,
            "upstream_selections": 5,
            "configured_routes": 2,
            "ready": 1,
        })
        after = self.metric_text({
            "requests": 60,
            "responses_2xx": 60,
            "upstream_selections": 30,
            "configured_routes": 2,
            "ready": 1,
        })
        result = collector.analyze_metrics(before, after, 25)
        self.assertEqual(result["request_delta"], 50)
        self.assertEqual(result["upstream_selection_delta"], 25)
        self.assertTrue(all(value == 0 for value in result["zero_counters"].values()))

    def test_rejects_metric_mismatch_missing_or_error_counter(self):
        baseline = {
            "requests": 10,
            "responses_2xx": 10,
            "upstream_selections": 5,
            "configured_routes": 2,
            "ready": 1,
        }
        good = {
            "requests": 60,
            "responses_2xx": 60,
            "upstream_selections": 30,
            "configured_routes": 2,
            "ready": 1,
        }
        variants = []
        mismatch = dict(good)
        mismatch["responses_2xx"] = 59
        variants.append(self.metric_text(mismatch))
        errors = dict(good)
        errors["responses_5xx"] = 1
        variants.append(self.metric_text(errors))
        missing = self.metric_text(good).replace(
            collector.METRICS["reactor_stalls"] + '{shard="0"} 0\n', "")
        variants.append(missing)
        for after in variants:
            with self.subTest(after=after), self.assertRaises(collector.Rejected):
                collector.analyze_metrics(self.metric_text(baseline), after, 25)

    def test_rejects_non_integral_metric(self):
        before = self.metric_text({"configured_routes": 2, "ready": 1})
        after = self.metric_text({
            "requests": "50.5",
            "responses_2xx": 50,
            "upstream_selections": 25,
            "configured_routes": 2,
            "ready": 1,
        })
        with self.assertRaisesRegex(collector.Rejected, "non-integral"):
            collector.analyze_metrics(before, after, 25)

    def test_phase_records_require_exact_all_true_checks(self):
        contract = json.loads(self.contract.read_text(encoding="utf-8"))
        required = contract["phases"][0]["required_checks"]
        checks = {name: True for name in required}
        self.assertTrue(collector.phase_record("preflight", checks, contract)["passed"])
        missing = dict(checks)
        missing.pop(required[0])
        with self.assertRaisesRegex(collector.Rejected, "inventory mismatch"):
            collector.phase_record("preflight", missing, contract)
        failed = dict(checks)
        failed[required[0]] = False
        with self.assertRaisesRegex(collector.Rejected, "phase check failed"):
            collector.phase_record("preflight", failed, contract)

    def test_output_must_be_new_and_owner_private(self):
        output = self.root / "evidence"
        collector.prepare_output(output, (self.root,))
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((output / "raw").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((output / collector.RAW_FILES[0]).stat().st_mode), 0o600)
        with self.assertRaisesRegex(collector.Rejected, "new evidence"):
            collector.prepare_output(output, (self.root,))

    def test_output_rejects_peer_writable_non_sticky_parent(self):
        parent = self.root / "unsafe-parent"
        parent.mkdir(mode=0o700)
        parent.chmod(0o777)
        try:
            with self.assertRaisesRegex(collector.Rejected, "replaceable by an unprivileged peer"):
                collector.prepare_output(parent / "evidence", (parent,))
        finally:
            parent.chmod(0o700)

    def test_output_rejects_untrusted_parent_by_default(self):
        with self.assertRaisesRegex(collector.Rejected, "direct child of /root or /var/tmp"):
            collector.prepare_output(self.root / "untrusted-evidence")

    def test_output_rejects_source_and_gateway_state_paths(self):
        with self.assertRaisesRegex(collector.Rejected, "outside source"):
            collector.prepare_output(collector.ROOT / "build/native-evidence-new")
        with self.assertRaisesRegex(collector.Rejected, "canonical absolute|outside source"):
            collector.prepare_output(Path("/etc/bonvoyage/evidence"))

    def test_retained_state_inventory_detects_content_and_recreation(self):
        first = self.root / "state-a"
        second = self.root / "state-b"
        for path in (first, second):
            path.mkdir(mode=0o750)
        payload = first / "snapshot.pb"
        payload.write_bytes(b"bound state\n")
        before = collector.retained_state_inventory((first, second))
        self.assertEqual(before, collector.retained_state_inventory((first, second)))
        payload.write_bytes(b"changed state\n")
        self.assertNotEqual(before, collector.retained_state_inventory((first, second)))

    def test_absence_rejects_dangling_symlink(self):
        path = self.root / "dangling"
        os.symlink(self.root / "missing", path)
        self.assertFalse(collector.path_absent(path))

    def test_fresh_install_rejects_removed_metadata_and_installed_state(self):
        installed = type("Result", (), {
            "returncode": 0,
            "stdout": b"Package: bonvoyage-gateway\nStatus: install ok installed\n",
        })()
        removed = type("Result", (), {
            "returncode": 0,
            "stdout": b"Package: bonvoyage-gateway\nStatus: deinstall ok config-files\n",
        })()
        missing = type("Result", (), {"returncode": 1, "stdout": b""})()
        self.assertTrue(collector.package_is_installed(installed))
        self.assertFalse(collector.package_is_installed(removed))
        self.assertFalse(collector.package_is_installed(missing))
        self.assertFalse(collector.package_is_fresh_absent(installed))
        self.assertFalse(collector.package_is_fresh_absent(removed))
        self.assertTrue(collector.package_is_fresh_absent(missing))

    def test_command_log_uses_argv_and_rejects_duplicate_ids(self):
        path = self.root / "commands.jsonl"
        path.write_bytes(b"")
        log = collector.CommandLog(path)
        result = log.run("python", [sys.executable, "-c", "print('ok')"])
        self.assertEqual(result.stdout, b"ok\n")
        record = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(record["argv"], [sys.executable, "-c", "print('ok')"])
        self.assertFalse(record["timed_out"])
        with self.assertRaisesRegex(collector.Rejected, "duplicate command ID"):
            log.run("python", [sys.executable, "-c", "print('again')"])

    def test_command_log_terminates_output_above_bound(self):
        path = self.root / "bounded-commands.jsonl"
        path.write_bytes(b"")
        log = collector.CommandLog(path, maximum_output_bytes=128)
        with self.assertRaisesRegex(collector.Rejected, "output exceeded bound"):
            log.run("too-loud", [sys.executable, "-c", "import os; os.write(1, b'x' * 4096)"])
        record = json.loads(path.read_text(encoding="utf-8"))
        self.assertTrue(record["output_limit_exceeded"])
        self.assertLessEqual(record["stdout_bytes"], 128)

    def test_failure_record_never_grants_authority(self):
        result = collector.failure_observation(
            collector.Rejected("fixture failure"),
            [{"id": "preflight", "passed": True, "checks": {}}],
        )
        self.assertEqual(result["outcome"], "failed")
        self.assertFalse(result["fresh_install_qualified"])
        self.assertFalse(result["release_admitted"])
        self.assertFalse(result["publishable"])
        self.assertTrue(result["cleanup_complete"])
        failed_cleanup = collector.failure_observation(
            collector.Rejected("fixture failure"), [], ("service remained active",))
        self.assertFalse(failed_cleanup["cleanup_complete"])
        self.assertEqual(failed_cleanup["cleanup_errors"], ["service remained active"])

    def test_failure_cleanup_stops_and_disables_after_install_attempt(self):
        class FakeLog:
            def __init__(self):
                self.calls = []

            def run(self, command_id, argv, **_kwargs):
                self.calls.append((command_id, tuple(argv)))
                if argv[1] == "is-active":
                    return type("Result", (), {"returncode": 3, "stdout": b"inactive\n"})()
                if argv[1] == "is-enabled":
                    return type("Result", (), {"returncode": 1, "stdout": b"disabled\n"})()
                return type("Result", (), {"returncode": 0, "stdout": b""})()

        host = object.__new__(collector.NativeHost)
        host.log = FakeLog()
        host.package_install_started = True
        host.service_started = True
        host.service_enabled = True
        host.fixture = None
        self.assertEqual(host.safe_stop(), [])
        actions = [argv[1] for _, argv in host.log.calls]
        self.assertEqual(actions, ["stop", "disable", "is-active", "is-enabled"])
        self.assertFalse(host.service_started)
        self.assertFalse(host.service_enabled)

    def test_runner_has_no_purge_autoremove_or_shell_execution(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertNotIn('"purge"', source)
        self.assertNotIn('"autoremove"', source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("rm -rf", source)
        self.assertIn('["/usr/bin/apt-get", "remove", "-y", PACKAGE_NAME]', source)

    def test_public_fixture_uses_only_loopback_upstream(self):
        fixture = SOURCE.parents[1] / "tests/fixtures/oss-native-fresh-install.yaml"
        text = fixture.read_text(encoding="utf-8")
        self.assertIn('address: "127.0.0.1"', text)
        self.assertIn("port: 18081", text)
        self.assertIn('path_exact: "/bonvoyage/ready"', text)
        self.assertIn('path_exact: "/healthz"', text)


if __name__ == "__main__":
    unittest.main()
