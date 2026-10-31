import copy
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


SOURCE = Path(__file__).with_name("verify-oss-native-install.py")
SPEC = importlib.util.spec_from_file_location("verify_oss_native_install", SOURCE)
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class NativeInstallVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.contract = self.root / "contract.json"
        self.contract.write_bytes(verifier.DEFAULT_CONTRACT.read_bytes())
        self.package = self.root / "bonvoyage-gateway_1.0.0-1_amd64.deb"
        self.package.write_bytes(b"fixture Debian package bytes\n")
        self.binary_digest = digest(b"installed gateway bytes\n")
        self.receipt = self.root / "build-receipt.json"
        self.receipt_document = self.make_receipt()
        self.write_json(self.receipt, self.receipt_document)
        self.evidence = self.root / "evidence"
        (self.evidence / "raw").mkdir(parents=True)
        for relative in verifier.EVIDENCE_FILES:
            path = self.evidence / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"fixture evidence for {relative}\n", encoding="utf-8")
        (self.evidence / "raw/commands.jsonl").write_text(
            self.command_journal(), encoding="utf-8")
        (self.evidence / "raw/metrics-before.txt").write_text(
            self.metric_text({"requests": 10, "responses_2xx": 10,
                              "upstream_selections": 5, "configured_routes": 2,
                              "ready": 1}), encoding="utf-8")
        (self.evidence / "raw/metrics-after.txt").write_text(
            self.metric_text({"requests": 60, "responses_2xx": 60,
                              "upstream_selections": 30, "configured_routes": 2,
                              "ready": 1}), encoding="utf-8")
        (self.evidence / "raw/socket-state.txt").write_text("\n".join((
            json.dumps({"role": "gateway", "pid": 4242, "host": "0.0.0.0", "port": 8080}),
            json.dumps({"role": "gateway", "pid": 4242, "host": "127.0.0.1", "port": 9090}),
            json.dumps({"role": "gateway", "pid": 4242, "host": "127.0.0.1", "port": 9901}),
            json.dumps({"role": "upstream", "pid": 5252, "host": "127.0.0.1", "port": 18081}),
        )) + "\n", encoding="utf-8")
        (self.evidence / "raw/removed-state.txt").write_text("\n".join((
            "classification=oss-native-fresh-install-removed",
            "captured_at=2026-10-16T04:00:00Z",
            "package_absent=true",
            "binary_absent=true",
            "package_unit_absent=true",
            "service_account_retained=true",
            "snapshot_retained=true",
            "operator_state_retained=true",
            f"retained_snapshot_sha256={verifier.FIXTURE['snapshot']['sha256']}",
            f"retained_identity_sha256={'4' * 64}",
            f"retained_state_inventory_sha256={'5' * 64}",
            "retained_state={}",
        )) + "\n", encoding="utf-8")
        self.observation_path = self.evidence / "observation.json"
        self.observation = self.make_observation()
        self.write_observation()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")

    def make_receipt(self):
        package_data = self.package.read_bytes()
        return {
            "schema_version": 1,
            "classification": verifier.BUILD_CLASS,
            "outcome": "built-technical-candidate",
            "builder_id": "fixture-builder-a",
            "source": {
                "repository": verifier.PUBLIC_REPOSITORY,
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
                    "sha256": self.binary_digest,
                }
            },
            "control": {"control": {"bytes": 10, "sha256": "3" * 64}},
            "package": {
                "path": self.package.name,
                "bytes": len(package_data),
                "sha256": digest(package_data),
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

    @staticmethod
    def command_journal():
        returncodes = {
            "preflight-package-status": 1,
            "preflight-service-user": 2,
            "preflight-service-group": 2,
            "installed-service-enabled": 1,
            "installed-service-active": 3,
            "start-controlled-upstream": None,
            "stop-controlled-upstream": -15,
            "removed-service-enabled": 1,
            "removed-package-status": 1,
        }
        empty = digest(b"")
        records = []
        for command_id in verifier.COMMAND_IDS:
            record = {
                "schema_version": 1,
                "id": command_id,
                "argv": ["/usr/bin/true"],
                "started_at": "2026-10-16T04:00:00Z",
                "duration_ms": 1,
                "timed_out": False,
                "output_limit_exceeded": False,
                "returncode": returncodes.get(command_id, 0),
                "stdout_bytes": 0,
                "stdout_sha256": empty,
                "stderr_bytes": 0,
                "stderr_sha256": empty,
            }
            if command_id == "start-controlled-upstream":
                record.update({"pid": 5252, "uid": 998, "gid": 998})
            records.append(json.dumps(record, sort_keys=True, separators=(",", ":")))
        return "\n".join(records) + "\n"

    @staticmethod
    def metric_text(values):
        return "\n".join(
            f'{metric}{{shard="0"}} {values.get(name, 0)}'
            for name, metric in verifier.METRICS.items()
        ) + "\n"

    def evidence_records(self):
        records = {}
        for relative in verifier.EVIDENCE_FILES:
            data = (self.evidence / relative).read_bytes()
            records[relative] = {"bytes": len(data), "sha256": digest(data)}
        return records

    def make_observation(self):
        package_data = self.package.read_bytes()
        receipt_data = self.receipt.read_bytes()
        contract_data = self.contract.read_bytes()
        return {
            "schema_version": 1,
            "classification": verifier.OBSERVATION_CLASS,
            "outcome": "passed",
            "captured_at": "2026-10-16T04:00:00Z",
            "contract": {
                "path": "packaging/release/debian/oss-native-fresh-install-contract.json",
                "sha256": digest(contract_data),
            },
            "source": {
                "repository": verifier.PUBLIC_REPOSITORY,
                "commit": "1" * 40,
                "tag": "v1.0.0",
                "dirty": False,
            },
            "host": {
                "distribution": "ubuntu",
                "version_id": "24.04",
                "architecture": "amd64",
                "root_execution": True,
                "hostname_sha256": digest(b"disposable-host"),
                "kernel": "6.8.0-fixture-generic",
            },
            "package": {
                "name": "bonvoyage-gateway",
                "version": "1.0.0-1",
                "architecture": "amd64",
                "bytes": len(package_data),
                "sha256": digest(package_data),
                "build_receipt_sha256": digest(receipt_data),
                "installed_binary_sha256": self.binary_digest,
                "runtime_identity": {
                    "dataplane_version": "0.2.0",
                    "release_version": "1.0.0",
                    "upstream_http1_client": "seastar-reference",
                },
            },
            "phases": [
                {
                    "id": phase,
                    "passed": True,
                    "checks": {check: True for check in checks},
                }
                for phase, checks in verifier.PHASE_CHECKS.items()
            ],
            "traffic": {
                "fixed_requests": 25,
                "proxied_requests": 25,
                "request_delta": 50,
                "response_2xx_delta": 50,
                "upstream_selection_delta": 25,
                "configured_routes": 2,
                "zero_counters": {name: 0 for name in verifier.ZERO_COUNTERS},
            },
            "process": {
                "main_pid": 4242,
                "stable_identity": True,
                "automatic_restarts": 0,
                "non_root": True,
                "binary_exact": True,
                "graceful_stop": True,
            },
            "resources": {
                "rss_start_kib": 40000,
                "rss_end_kib": 40512,
                "descriptor_start": 11,
                "descriptor_end": 11,
            },
            "evidence_files": self.evidence_records(),
            "qualifications": copy.deepcopy(verifier.QUALIFICATIONS),
        }

    def write_observation(self):
        self.write_json(self.observation_path, self.observation)

    def verify(self):
        return verifier.verify(self.contract, self.evidence, self.package, self.receipt)

    def test_accepts_complete_checksum_bound_fresh_install_evidence(self):
        report = self.verify()
        self.assertEqual(report["outcome"], "verified")
        self.assertTrue(report["fresh_install_qualified"])
        self.assertFalse(report["release_admitted"])
        self.assertFalse(report["publishable"])

    def test_requires_runtime_identity_observation_in_command_journal(self):
        version_index = verifier.COMMAND_IDS.index("installed-binary-version")
        self.assertEqual(
            verifier.COMMAND_IDS[version_index - 1],
            "installed-package-files",
        )
        self.assertEqual(
            verifier.COMMAND_IDS[version_index + 1],
            "installed-service-enabled",
        )
        path = self.evidence / "raw/commands.jsonl"
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        records.pop(version_index)
        path.write_text("\n".join(json.dumps(item) for item in records) + "\n",
                        encoding="utf-8")
        self.observation["evidence_files"] = self.evidence_records()
        self.write_observation()
        with self.assertRaisesRegex(verifier.Rejected, "command journal length mismatch"):
            self.verify()

    def test_rejects_incomplete_or_failed_command_journal(self):
        path = self.evidence / "raw/commands.jsonl"
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        records[4]["output_limit_exceeded"] = True
        path.write_text("\n".join(json.dumps(item) for item in records) + "\n",
                        encoding="utf-8")
        self.observation["evidence_files"] = self.evidence_records()
        self.write_observation()
        with self.assertRaisesRegex(verifier.Rejected, "incomplete command"):
            self.verify()

    def test_rejects_raw_metric_or_socket_drift(self):
        metrics = self.evidence / "raw/metrics-after.txt"
        metrics.write_text(self.metric_text({
            "requests": 59, "responses_2xx": 60, "upstream_selections": 30,
            "configured_routes": 2, "ready": 1,
        }), encoding="utf-8")
        self.observation["evidence_files"] = self.evidence_records()
        self.write_observation()
        with self.assertRaisesRegex(verifier.Rejected, "raw metrics"):
            self.verify()

    def test_rejects_changed_package_bytes(self):
        self.package.write_bytes(b"changed package bytes\n")
        with self.assertRaisesRegex(verifier.Rejected, "package size|package digest"):
            self.verify()

    def test_rejects_dirty_or_authority_escalating_build_receipt(self):
        for field, value, message in (
            ("dirty", True, "clean public-origin"),
            ("publishable", True, "escalates publishable"),
            ("lifecycle_qualified", True, "escalates lifecycle_qualified"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.receipt_document)
                if field == "dirty":
                    changed["source"][field] = value
                else:
                    changed[field] = value
                self.write_json(self.receipt, changed)
                self.observation = self.make_observation()
                self.write_observation()
                with self.assertRaisesRegex(verifier.Rejected, message):
                    self.verify()
                self.write_json(self.receipt, self.receipt_document)
                self.observation = self.make_observation()
                self.write_observation()

    def test_rejects_wrong_host_or_unprivileged_observation(self):
        for field, value in (("version_id", "22.04"), ("architecture", "arm64"),
                             ("root_execution", False)):
            with self.subTest(field=field):
                self.observation["host"][field] = value
                self.write_observation()
                with self.assertRaisesRegex(verifier.Rejected, "unsupported or unprivileged"):
                    self.verify()
                self.observation = self.make_observation()

    def test_rejects_missing_reordered_or_failed_phase(self):
        variants = []
        missing = copy.deepcopy(self.observation)
        missing["phases"].pop()
        variants.append(missing)
        reordered = copy.deepcopy(self.observation)
        reordered["phases"][0], reordered["phases"][1] = \
            reordered["phases"][1], reordered["phases"][0]
        variants.append(reordered)
        failed = copy.deepcopy(self.observation)
        failed["phases"][3]["checks"]["admin_ready"] = False
        variants.append(failed)
        for candidate in variants:
            with self.subTest(candidate=candidate["phases"]):
                self.observation = candidate
                self.write_observation()
                with self.assertRaises(verifier.Rejected):
                    self.verify()

    def test_rejects_incomplete_or_nonzero_traffic_accounting(self):
        variants = []
        insufficient = copy.deepcopy(self.observation)
        insufficient["traffic"]["fixed_requests"] = 24
        insufficient["traffic"]["request_delta"] = 49
        insufficient["traffic"]["response_2xx_delta"] = 49
        variants.append(insufficient)
        mismatch = copy.deepcopy(self.observation)
        mismatch["traffic"]["upstream_selection_delta"] = 24
        variants.append(mismatch)
        errors = copy.deepcopy(self.observation)
        errors["traffic"]["zero_counters"]["responses_5xx"] = 1
        variants.append(errors)
        for candidate in variants:
            with self.subTest(candidate=candidate["traffic"]):
                self.observation = candidate
                self.write_observation()
                with self.assertRaises(verifier.Rejected):
                    self.verify()

    def test_rejects_restart_rss_and_descriptor_bound_violations(self):
        variants = []
        restarted = copy.deepcopy(self.observation)
        restarted["process"]["automatic_restarts"] = 1
        variants.append(restarted)
        rss = copy.deepcopy(self.observation)
        rss["resources"]["rss_end_kib"] = rss["resources"]["rss_start_kib"] + 16385
        variants.append(rss)
        descriptors = copy.deepcopy(self.observation)
        descriptors["resources"]["descriptor_end"] = \
            descriptors["resources"]["descriptor_start"] + 3
        variants.append(descriptors)
        for candidate in variants:
            with self.subTest(candidate=candidate):
                self.observation = candidate
                self.write_observation()
                with self.assertRaises(verifier.Rejected):
                    self.verify()

    def test_rejects_changed_missing_or_unexpected_raw_evidence(self):
        changed = self.evidence / verifier.EVIDENCE_FILES[0]
        changed.write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(verifier.Rejected, "digest mismatch|size mismatch"):
            self.verify()
        changed.write_text(f"fixture evidence for {verifier.EVIDENCE_FILES[0]}\n",
                           encoding="utf-8")
        missing = self.evidence / verifier.EVIDENCE_FILES[1]
        missing.unlink()
        with self.assertRaisesRegex(verifier.Rejected, "inventory mismatch"):
            self.verify()
        missing.write_text(f"fixture evidence for {verifier.EVIDENCE_FILES[1]}\n",
                           encoding="utf-8")
        (self.evidence / "raw/unexpected.txt").write_text("unexpected\n", encoding="utf-8")
        with self.assertRaisesRegex(verifier.Rejected, "inventory mismatch"):
            self.verify()

    def test_rejects_symlinked_raw_evidence(self):
        target = self.evidence / verifier.EVIDENCE_FILES[0]
        body = target.read_bytes()
        target.unlink()
        backing = self.root / "backing"
        backing.write_bytes(body)
        os.symlink(backing, target)
        with self.assertRaisesRegex(verifier.Rejected, "unsupported evidence filesystem object"):
            self.verify()

    def test_rejects_symlinked_raw_directory(self):
        raw = self.evidence / "raw"
        backing = self.root / "raw-backing"
        raw.rename(backing)
        os.symlink(backing, raw)
        with self.assertRaisesRegex(verifier.Rejected,
                                    "unsupported evidence filesystem object"):
            self.verify()

    def test_rejects_boolean_integer_type_confusion(self):
        contract = json.loads(self.contract.read_text(encoding="utf-8"))
        contract["schema_version"] = True
        self.write_json(self.contract, contract)
        self.observation["contract"]["sha256"] = digest(self.contract.read_bytes())
        self.write_observation()
        with self.assertRaisesRegex(verifier.Rejected, "unsupported contract schema"):
            self.verify()

        self.contract.write_bytes(verifier.DEFAULT_CONTRACT.read_bytes())
        self.observation = self.make_observation()
        self.observation["process"]["automatic_restarts"] = False
        self.write_observation()
        with self.assertRaisesRegex(verifier.Rejected, "must be an integer"):
            self.verify()

    def test_rejects_duplicate_json_fields(self):
        raw = self.contract.read_text(encoding="utf-8").replace(
            '  "schema_version": 1,',
            '  "schema_version": 1,\n  "schema_version": 1,',
            1,
        )
        self.contract.write_text(raw, encoding="utf-8")
        self.observation["contract"]["sha256"] = digest(self.contract.read_bytes())
        self.write_observation()
        with self.assertRaisesRegex(verifier.Rejected, "duplicate JSON field"):
            self.verify()

    def test_rejects_contract_weakening_even_when_observation_rebinds_it(self):
        contract = json.loads(self.contract.read_text(encoding="utf-8"))
        contract["traffic"]["minimum_requests_per_route"] = 1
        self.write_json(self.contract, contract)
        self.observation["contract"]["sha256"] = digest(self.contract.read_bytes())
        self.write_observation()
        with self.assertRaisesRegex(verifier.Rejected, "traffic contract drift"):
            self.verify()

    def test_rejects_qualification_escalation(self):
        self.observation["qualifications"]["publishable"] = True
        self.write_observation()
        with self.assertRaisesRegex(verifier.Rejected, "qualification boundary"):
            self.verify()

    def test_writes_new_owner_private_report_outside_evidence(self):
        output = self.root / "verification.json"
        result = verifier.main([
            "--contract", str(self.contract),
            "--evidence", str(self.evidence),
            "--package", str(self.package),
            "--build-receipt", str(self.receipt),
            "--output", str(output),
        ])
        self.assertEqual(result, 0)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(output.read_text())["outcome"], "verified")
        self.assertEqual(verifier.main([
            "--contract", str(self.contract),
            "--evidence", str(self.evidence),
            "--package", str(self.package),
            "--build-receipt", str(self.receipt),
            "--output", str(output),
        ]), 2)

    def test_rejects_output_inside_evidence(self):
        result = verifier.main([
            "--contract", str(self.contract),
            "--evidence", str(self.evidence),
            "--package", str(self.package),
            "--build-receipt", str(self.receipt),
            "--output", str(self.evidence / "verification.json"),
        ])
        self.assertEqual(result, 2)
        self.assertFalse((self.evidence / "verification.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
