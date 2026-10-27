#!/usr/bin/env python3
"""Fixture-based inventory guards; these tests are not native scan evidence."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_runtime", Path(__file__).with_name("collect-native-runtime.py"))
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)
COMMIT = "a" * 40


class NativeRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.binary = self.file("binary", b"fixture ELF identity, not an executable")
        self.sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
        sbom = self.file("producer-sbom.json", json.dumps(self.sbom).encode())
        producer = self.file("producer.json", json.dumps({"classification": "private-native-rc-handoff",
            "source_commit": COMMIT, "source_dirty_at_acceptance": False,
            "runtime_scan": {"gate": {"passed": True}}, "files": [
                {**self.binary, "path": "artifacts/bonvoyage-dataplane"},
                {**sbom, "path": "runtime-security/runtime.cdx.json"}]}).encode())
        package = self.file("gateway.deb", b"fixture package, not a Debian archive")
        inputs = self.file("inputs.json", json.dumps({"classification": "private-native-gateway-input",
            "producer_source_commit": COMMIT, "architecture": "amd64", "distribution": "ubuntu-24.04",
            "version": "0.2.0-1", "files": {"dataplane": self.binary}}).encode())
        receipt = self.file("receipt.json", json.dumps({"classification": "private-native-gateway-build",
            "outcome": "built-unaccepted", "exit_code": 0, "payload_files_verified": 5,
            "producer_source_commit": COMMIT, "packaging_source": {"commit": "b" * 40, "dirty": False},
            "architecture": "amd64", "distribution": "ubuntu-24.04",
            "binding": {"manifest_sha256": inputs["sha256"]},
            "package": {**package, "path": "gateway.deb"}, **{flag: False for flag in runtime.FLAGS}}).encode())
        self.request = {"schema_version": 1, "classification": "private-native-runtime-inventory-input",
            "producer_source_commit": COMMIT, "runtime_profile": "source-install", "files": {
                "binary": self.binary, "producer_manifest": producer, "producer_sbom": sbom,
                "package": package, "build_receipt": receipt, "build_inputs": inputs}}
        self.baseline = {name: Path(record["path"]).read_bytes() for name, record in self.request["files"].items()}

    def file(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return runtime.identity(path)

    def load(self, request=None):
        record = self.file("request.json", json.dumps(request or self.request).encode())
        return runtime.load_request(Path(record["path"]), record["sha256"])

    def mutate_file(self, name, mutate):
        record = self.request["files"][name]
        value = runtime.decode(self.baseline[name])
        mutate(value)
        self.request["files"][name] = self.file(Path(record["path"]).name, json.dumps(value).encode())

    def test_request_accepts_bound_distinct_inputs(self):
        self.assertEqual(self.load()[0], self.request)

    def test_reviewed_anchor_required(self):
        record = self.file("request.json", json.dumps(self.request).encode())
        for anchor in ("0" * 64, "invalid", None):
            with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                runtime.load_request(Path(record["path"]), anchor)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            runtime.decode(b'{"source":1,"source":2}')

    def test_schema_and_unknown_fields_rejected(self):
        for name, value in (("schema_version", True), ("classification", "public"),
                            ("producer_source_commit", "main; id"), ("runtime_profile", "auto"), ("unknown", 1)):
            request = copy.deepcopy(self.request)
            request[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.load(request)

    def test_file_record_type_and_hash_guards(self):
        for name, value in (("bytes", True), ("bytes", 0), ("sha256", "oops"), ("path", 7)):
            record = dict(self.binary)
            record[name] = value
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                runtime.anchored(record)

    def test_changed_file_rejected(self):
        Path(self.binary["path"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            self.load()

    def test_symlink_and_noncanonical_inputs_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.binary["path"])
        for name in (str(link), str(self.root) + "/../" + self.root.name + "/binary", "binary"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                runtime.identity(name)

    def test_empty_and_oversized_inputs_rejected(self):
        path = self.root / "empty"
        path.touch()
        with self.assertRaises(ValueError):
            runtime.identity(path)
        with self.assertRaises(ValueError):
            runtime.identity(self.binary["path"], 1)

    def test_duplicate_input_paths_rejected(self):
        self.request["files"]["package"] = self.binary
        with self.assertRaisesRegex(ValueError, "distinct"):
            self.load()

    def test_realistic_large_notice_remains_bounded(self):
        path = self.root / "copyright"
        path.write_bytes(b"x" * 2175464)
        self.assertEqual(runtime.identity(path, runtime.NOTICE_LIMIT)["bytes"], 2175464)
        with self.assertRaises(ValueError):
            runtime.identity(path, 1024 * 1024)
        path.write_bytes(b"x" * (runtime.NOTICE_LIMIT + 1))
        with self.assertRaises(ValueError):
            runtime.identity(path, runtime.NOTICE_LIMIT)

    def test_clean_package_binding_without_scan_inheritance(self):
        receipt, _, sbom = runtime.verify_binding(self.request)
        self.assertEqual(sbom, self.sbom)
        self.assertNotIn("runtime_scan", receipt)
        self.assertTrue(all(receipt[flag] is False for flag in runtime.FLAGS))

    def test_producer_binary_and_sbom_mismatch_rejected(self):
        for index in (0, 1):
            original = copy.deepcopy(self.request)
            self.mutate_file("producer_manifest", lambda p: p["files"][index].update(sha256="0" * 64))
            with self.subTest(index=index), self.assertRaises(ValueError):
                runtime.verify_binding(self.request)
            self.request = original

    def test_duplicate_producer_binary_rejected(self):
        self.mutate_file("producer_manifest", lambda p: p["files"].append(p["files"][0]))
        with self.assertRaises(ValueError):
            runtime.verify_binding(self.request)

    def test_dirty_producer_rejected(self):
        self.mutate_file("producer_manifest", lambda p: p.update(source_dirty_at_acceptance=True))
        with self.assertRaises(ValueError):
            runtime.verify_binding(self.request)

    def test_package_qualification_flags_cannot_be_imported(self):
        for flag in runtime.FLAGS:
            original = copy.deepcopy(self.request)
            self.mutate_file("build_receipt", lambda p: p.update({flag: True}))
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                runtime.verify_binding(self.request)
            self.request = original

    def test_dirty_packaging_and_wrong_package_digest_rejected(self):
        for mutate in (lambda p: p["packaging_source"].update(dirty=True),
                       lambda p: p["package"].update(sha256="0" * 64),
                       lambda p: p["binding"].update(manifest_sha256="0" * 64),
                       lambda p: p.update(exit_code=True)):
            original = copy.deepcopy(self.request)
            self.mutate_file("build_receipt", mutate)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                runtime.verify_binding(self.request)
            self.request = original

    def test_package_input_binary_mismatch_rejected(self):
        self.mutate_file("build_inputs", lambda p: p["files"]["dataplane"].update(sha256="0" * 64))
        self.mutate_file("build_receipt", lambda p: p["binding"].update(manifest_sha256=self.request["files"]["build_inputs"]["sha256"]))
        with self.assertRaisesRegex(ValueError, "input binary mismatch"):
            runtime.verify_binding(self.request)

    def test_ldd_paths_and_loader(self):
        self.assertEqual(runtime.parse_ldd(" linux-vdso.so.1 (0x7abc)\n liba.so => /lib/liba.so (0x7def)\n /lib/loader.so (0x7fff)\n"),
                         ["/lib/liba.so", "/lib/loader.so"])

    def test_ldd_unresolved_and_unexpected_output_rejected(self):
        for text in ("liba.so => not found", "not a dynamic executable", "", "liba => ./liba (0x1)"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                runtime.parse_ldd(text)

    def test_maps_numeric_identity_and_anonymous_skip(self):
        maps = runtime.parse_maps("1000-2000 r-xp 0000 103:01 659 /usr/bin/gateway\n2000-3000 rw-p 0000 00:00 0 [heap]\n")
        self.assertEqual(maps, {"/usr/bin/gateway": {"device_major": 259, "device_minor": 1, "inode": 659}})

    def test_maps_deleted_corrupt_and_inconsistent_rejected(self):
        row = "1000-2000 r-xp 0000 103:01 659 /usr/bin/gateway"
        for text in (row + " (deleted)", row.replace("103:01", "oops"), row + "\n" + row.replace("659", "660"), "bad", ""):
            with self.subTest(text=text), self.assertRaises(ValueError):
                runtime.parse_maps(text)

    def test_kernel_aio_non_executable_pseudo_mapping_is_not_a_library(self):
        row = "1000-2000 r-xp 0000 103:01 659 /usr/bin/gateway"
        self.assertEqual(len(runtime.parse_maps(row + "\n2000-3000 rw-s 0000 00:16 123 /[aio] (deleted)")), 1)
        for value in ("r-xs 0000 00:16", "rw-s 0001 00:16", "rw-s 0000 103:01"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                runtime.parse_maps(row + "\n2000-3000 " + value + " 123 /[aio] (deleted)")

    def test_mapping_inode_matches_and_replacement_rejected(self):
        path = Path(self.binary["path"])
        value = path.stat()
        record = {"device_major": os.major(value.st_dev), "device_minor": os.minor(value.st_dev), "inode": value.st_ino}
        runtime.verify_mapping(path, record)
        with self.assertRaises(ValueError):
            runtime.verify_mapping(path, {**record, "inode": value.st_ino + 1})

    def test_owner_exact_path_and_diversion_lines(self):
        self.assertEqual(runtime.package_owner("diversion by usr-is-merged from: /usr/lib/a.so\nliba:amd64: /usr/lib/a.so\n", "/usr/lib/a.so"), "liba:amd64")

    def test_owner_missing_ambiguous_and_argument_injection_rejected(self):
        for text in ("liba: /other", "liba: /lib/a\nlibb: /lib/a", "--evil: /lib/a", ""):
            with self.subTest(text=text), self.assertRaises(ValueError):
                runtime.package_owner(text, "/lib/a")

    def test_deb822_installed_control(self):
        value = runtime.package_control("Package: libc6\nVersion: 2.39-1\nArchitecture: amd64\nStatus: install ok installed\nDescription: fixture\n continuation\n", "libc6:amd64")
        self.assertEqual(value, {"name": "libc6", "version": "2.39-1", "architecture": "amd64"})

    def test_deb822_duplicate_missing_wrong_arch_and_not_installed(self):
        good = "Package: libc6\nVersion: 2.39-1\nArchitecture: amd64\nStatus: install ok installed\n"
        for text in (good + "Version: second\n", good.replace("amd64", "arm64"), good.replace("installed", "half-configured"), good.replace("Version: 2.39-1\n", "")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                runtime.package_control(text, "libc6:amd64")

    def component_fixture(self):
        sha = runtime.digest(b"patch")
        record = {"name": "seastar", "version": "25.05.0", "source": {"commit": COMMIT}, "license": {"spdx": "Apache-2.0"},
                  "build": {"linkage": "static", "local_patches": [{"file": "patches/seastar.patch", "sha256": sha}]},
                  "patches": [{"path": "patches/other.patch", "sha256": sha}], "review": {"automated_scan": "passed"}}
        sbom = {"components": [{"name": "seastar", "version": "25.05.0",
                  "licenses": [{"license": {"id": "Apache-2.0"}}], "properties": [
                      {"name": "bonvoyage:source:commit", "value": COMMIT},
                      {"name": "bonvoyage:build:linkage", "value": "static"}]}]}
        return record, sbom

    def test_both_patch_layouts_verified_without_review_inheritance(self):
        record, sbom = self.component_fixture()
        result = runtime.declared_component(json.dumps(record).encode(), sbom, lambda p: b"patch")
        self.assertEqual(len(result["verified_producer_patches"]), 2)
        self.assertNotIn("review", result)
        self.assertNotIn("automated_scan", json.dumps(result))

    def test_static_version_commit_duplicates_and_patch_mismatch_rejected(self):
        record, sbom = self.component_fixture()
        for mutate in (lambda s: s["components"][0].update(version="wrong"),
                       lambda s: s["components"][0]["properties"][0].update(value="b" * 40),
                       lambda s: s["components"].append(s["components"][0])):
            value = copy.deepcopy(sbom)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                runtime.declared_component(json.dumps(record).encode(), value, lambda p: b"patch")
        with self.assertRaisesRegex(ValueError, "patch checksum"):
            runtime.declared_component(json.dumps(record).encode(), sbom, lambda p: b"changed")

    def test_static_license_and_linkage_declaration_mismatch_rejected(self):
        record, sbom = self.component_fixture()
        for mutate in (lambda s: s["components"][0]["licenses"][0]["license"].update(id="MIT"),
                       lambda s: s["components"][0]["properties"][1].update(value="dynamic")):
            value = copy.deepcopy(sbom)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaisesRegex(ValueError, "license/linkage"):
                runtime.declared_component(json.dumps(record).encode(), value, lambda p: b"patch")

    def test_cares_pin_cpe_and_archive_binding(self):
        record, sbom = self.component_fixture()
        record.update(name="c-ares", version="1.34.8", source={"commit": runtime.CARES_COMMIT,
            "archive_sha256": runtime.CARES_ARCHIVE_SHA}, license={"spdx": "MIT"}, matching={
            "cpe": "cpe:2.3:a:c-ares_project:c-ares:1.34.8:*:*:*:*:*:*:*"})
        component = sbom["components"][0]
        component.update(name=record["name"], version=record["version"], cpe=record["matching"]["cpe"],
            licenses=[{"license": {"id": "MIT"}}], hashes=[{"alg": "SHA-256", "content": runtime.CARES_ARCHIVE_SHA}])
        component["properties"][0]["value"] = runtime.CARES_COMMIT
        result = runtime.declared_component(json.dumps(record).encode(), sbom, lambda p: b"patch")
        self.assertEqual(result["matching"], record["matching"])
        for mutate in (lambda c: c.pop("cpe"), lambda c: c.update(cpe="wrong"), lambda c: c.pop("hashes"),
                       lambda c: c["hashes"][0].update(content="0" * 64)):
            value = copy.deepcopy(sbom)
            mutate(value["components"][0])
            with self.assertRaises(ValueError):
                runtime.declared_component(json.dumps(record).encode(), value, lambda p: b"patch")
        for key in ("commit", "archive_sha256"):
            value = copy.deepcopy(record)
            value["source"][key] = "0" * len(value["source"][key])
            with self.assertRaises(ValueError):
                runtime.validate_record(json.dumps(value).encode())

    def test_unknown_static_cpe_not_admitted(self):
        record, _ = self.component_fixture()
        record["matching"] = {"cpe": "cpe:2.3:a:unreviewed:seastar:25.05.0:*:*:*:*:*:*:*"}
        with self.assertRaisesRegex(ValueError, "unreviewed"):
            runtime.validate_record(json.dumps(record).encode())

    def test_vendored_proto_and_license_actual_repository_paths(self):
        record, sbom = self.component_fixture()
        record.update(name="opentelemetry-proto", patches=[])
        record["build"].pop("local_patches")
        record["source"]["files"] = {"opentelemetry/proto/test.proto": runtime.digest(b"proto")}
        record["license"].update(source_file="third_party/opentelemetry-proto/LICENSE", sha256=runtime.digest(b"license"))
        sbom["components"][0]["name"] = "opentelemetry-proto"
        source = {"third_party/opentelemetry-proto/opentelemetry/proto/test.proto": b"proto", "third_party/opentelemetry-proto/LICENSE": b"license"}
        result = runtime.declared_component(json.dumps(record).encode(), sbom, source.__getitem__)
        self.assertEqual(len(result["verified_vendored_files"]), 2)

    def test_git_paths_reject_traversal_and_injection(self):
        for name in ("../secret", "/etc/passwd", "x/../y", "", "./x"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                runtime.git_file(COMMIT, name)

    def test_native_platform_guard_does_not_create_output(self):
        output = self.root / "evidence"
        with patch.object(runtime.platform, "system", return_value="Darwin"), self.assertRaises(ValueError):
            runtime.collect(self.root / "request.json", "0" * 64, output)
        self.assertFalse(output.exists())

    def test_subprocess_uses_fixed_argv_locale_and_timeout(self):
        with patch.object(runtime.subprocess, "run") as execute:
            execute.return_value.stdout = b"ok"
            self.assertEqual(runtime.run("dpkg-query", "--status", "libc6:amd64"), b"ok")
            self.assertEqual(execute.call_args.args[0], ("dpkg-query", "--status", "libc6:amd64"))
            self.assertTrue(execute.call_args.kwargs["check"])
            self.assertEqual(execute.call_args.kwargs["timeout"], 60)
            self.assertEqual(execute.call_args.kwargs["env"]["LC_ALL"], "C")


class ProducerDeclarationHistoryTests(unittest.TestCase):
    """Use disposable Git history to prove producer/checkout separation."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.git("init", "-q")
        for path in runtime.RECORDS:
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            # The ancestry contract needs valid declarations, not private repository history.
            target.write_bytes((ROOT / path).read_bytes())
        self.legacy = self.commit()
        boundary = patch.object(runtime, "LEGACY_SOURCE_BOUNDARY", self.legacy)
        boundary.start()
        self.addCleanup(boundary.stop)
        self.cares = {"name": "c-ares", "version": "1.34.8", "source": {"commit": runtime.CARES_COMMIT,
            "archive_sha256": runtime.CARES_ARCHIVE_SHA}, "license": {"spdx": "MIT"}, "build": {"linkage": "static"},
            "matching": {"cpe": "cpe:2.3:a:c-ares_project:c-ares:1.34.8:*:*:*:*:*:*:*"}}

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture",
            "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", *args],
            check=True, capture_output=True, timeout=10).stdout.decode().strip()

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "Synthetic declaration fixture")
        return self.git("rev-parse", "HEAD")

    def add_cares(self):
        (self.root / runtime.CARES_RECORD).write_text(json.dumps(self.cares))

    def add_llhttp(self):
        target = self.root / runtime.LLHTTP_RECORD
        target.write_bytes((ROOT / runtime.LLHTTP_RECORD).read_bytes())

    def test_historical_producer_ignores_current_checkout_addition(self):
        self.add_cares()
        records = runtime.producer_records(self.legacy, self.root)
        self.assertEqual(set(records), set(runtime.RECORDS))

    def test_new_producer_requires_cares_even_when_all_old_records_present(self):
        (self.root / "unrelated.txt").write_text("new producer")
        with self.assertRaisesRegex(ValueError, "must declare c-ares"):
            runtime.producer_records(self.commit(), self.root)

    def test_new_producer_uses_committed_bytes_despite_checkout_drift(self):
        self.add_cares()
        commit = self.commit()
        (self.root / runtime.CARES_RECORD).write_text("changed")
        records = runtime.producer_records(commit, self.root)
        self.assertEqual(json.loads(records[runtime.CARES_RECORD]), self.cares)
        self.assertEqual(len(records), 7)

    def test_promoted_llhttp_is_a_normal_root_declaration(self):
        self.add_cares()
        self.add_llhttp()
        records = runtime.producer_records(self.commit(), self.root)
        self.assertIn(runtime.LLHTTP_RECORD, records)
        self.assertEqual(len(records), 8)

    def test_new_producer_cannot_delete_cares_to_select_legacy_profile(self):
        self.add_cares()
        self.commit()
        (self.root / runtime.CARES_RECORD).unlink()
        with self.assertRaisesRegex(ValueError, "must declare c-ares"):
            runtime.producer_records(self.commit(), self.root)

    def test_missing_or_unknown_root_record_rejected(self):
        self.add_cares()
        (self.root / runtime.RECORDS[0]).unlink()
        with self.assertRaisesRegex(ValueError, "missing/unknown"):
            runtime.producer_records(self.commit(), self.root)
        (self.root / "security/dependencies/unknown.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "missing/unknown"):
            runtime.producer_records(self.commit(), self.root)

    def test_alias_and_duplicate_name_rejected(self):
        self.add_cares()
        self.cares["name"] = "seastar"
        self.add_cares()
        with self.assertRaises(ValueError):
            runtime.producer_records(self.commit(), self.root)

    def test_symlink_producer_record_rejected(self):
        (self.root / runtime.CARES_RECORD).symlink_to("seastar-25.05.0.json")
        with self.assertRaisesRegex(ValueError, "regular"):
            runtime.producer_records(self.commit(), self.root)

    def test_candidate_directory_is_not_a_required_root_declaration(self):
        candidate = self.root / runtime.LEGACY_LLHTTP_CANDIDATE_RECORD
        candidate.parent.mkdir()
        candidate.write_text("{}")
        self.add_cares()
        self.assertNotIn(runtime.LEGACY_LLHTTP_CANDIDATE_RECORD,
                         runtime.producer_records(self.commit(), self.root))


if __name__ == "__main__":
    unittest.main(verbosity=2)
