#!/usr/bin/env python3
"""Native SBOM fixture guards; not evidence that tools, scans or native workloads ran."""

import copy
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("native_sbom", Path(__file__).with_name("native-runtime-sbom.py"))
sbom = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sbom)


class NativeSbomTests(unittest.TestCase):
    def setUp(self):
        self.inventory = {"producer_source_commit": "a" * 40, "runtime_profile": "source-install",
            "files": {"binary": {"path": "/usr/local/bin/bonvoyage-dataplane", "bytes": 64, "sha256": "b" * 64},
                      "package": {"path": "/var/tmp/gateway.deb", "bytes": 32, "sha256": "c" * 64}},
            "ubuntu_packages": {"libc6:amd64": {"name": "libc6", "version": "2.39-0ubuntu8.9",
                                               "architecture": "amd64", "control_sha256": "d" * 64}},
            "dynamic_libraries": [{"path": "/usr/lib/x86_64-linux-gnu/libc.so.6", "bytes": 64, "sha256": "e" * 64,
                                   "owner": "libc6:amd64", "observed_in_process": True, "resolved_by_ldd": True}],
            "declared_components": [{"name": name, "version": "1.0", "declared_license": "MIT", "declared_linkage": "static",
                "source": {"commit": "f" * 40, "archive_sha256": "1" * 64}, "record_sha256": "2" * 64,
                "record_path": "security/dependencies/" + name + ".json",
                "evidence_kind": "producer-declared-static-or-generated-component",
                "verified_producer_patches": [{"path": "patches/fix.patch", "sha256": sbom.runtime.digest(b"patch")}],
                "verified_vendored_files": []} for name in ("seastar", "nghttp2", "libjwt", "abseil", "re2", "opentelemetry-proto", "c-ares")]}
        cares = self.inventory["declared_components"][-1]
        cares.update(version="1.34.8", source={"commit": sbom.runtime.CARES_COMMIT,
            "archive_sha256": sbom.runtime.CARES_ARCHIVE_SHA}, matching={
            "cpe": "cpe:2.3:a:c-ares_project:c-ares:1.34.8:*:*:*:*:*:*:*"})
        self.records = {}
        for item in self.inventory["declared_components"]:
            item["record_path"] = "security/dependencies/" + item["name"] + "-" + item["version"] + ".json"
            record = {"name": item["name"], "version": item["version"], "source": item["source"],
                "license": {"spdx": item["declared_license"]}, "build": {"linkage": item["declared_linkage"]},
                "patches": item["verified_producer_patches"], **({"matching": item["matching"]} if "matching" in item else {})}
            data = json.dumps(record).encode()
            self.records[item["record_path"]] = data
            item["record_sha256"] = sbom.runtime.digest(data)
        records_patch = patch.object(sbom.runtime, "producer_records", side_effect=lambda *args: copy.deepcopy(self.records))
        records_patch.start()
        self.addCleanup(records_patch.stop)
        self.inputs = {"version": "0.2.0~rehearsal-1"}
        self.manifest = [{"path": "usr/bin/bonvoyage-dataplane", "bytes": 64, "sha256": "b" * 64,
                          "sha1": "4" * 40, "subject": "native-executable", "host_path": "/usr/local/bin/bonvoyage-dataplane"},
                         {"path": "usr/lib/x86_64-linux-gnu/libc.so.6", "bytes": 64, "sha256": "e" * 64,
                          "sha1": "5" * 40, "subject": "observed-runtime-library",
                          "host_path": "/usr/lib/x86_64-linux-gnu/libc.so.6", "owner": "libc6:amd64"}]
        self.binding = {"inventory_sha256": "6" * 64, "tooling_dirty": "true"}
        purl = "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.9?arch=amd64&distro=ubuntu-24.04&upstream=glibc"
        self.cdx_raw = {"bomFormat": "CycloneDX", "specVersion": "1.6",
                        "components": [{"type": "library", "name": "libc6", "version": "2.39-0ubuntu8.9", "purl": purl},
                                       {"type": "operating-system", "name": "ubuntu", "version": "24.04"}]}
        self.spdx_raw = {"spdxVersion": "SPDX-2.3", "packages": [
            {"name": "bonvoyage-native-runtime", "primaryPackagePurpose": "FILE"},
            {"name": "libc6", "versionInfo": "2.39-0ubuntu8.9", "externalRefs": [
                {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}]}]}
        self.cdx, self.spdx = self.generate()

    def generate(self):
        return sbom.enrich(self.inventory, self.inputs, self.manifest, self.cdx_raw, self.spdx_raw, self.binding)

    def check(self, cdx=None, spdx=None):
        return sbom.complete(self.inventory, self.inputs, self.manifest,
                             cdx if cdx is not None else self.cdx, spdx if spdx is not None else self.spdx,
                             self.binding, self.cdx_raw, self.spdx_raw)

    def test_valid_fixture_is_complete(self):
        self.assertEqual(self.check()["runtime_files"], 2)
        self.assertEqual(self.check()["declared_components"], 7)

    def test_cares_cpe_is_preserved_in_both_formats(self):
        cpe = self.inventory["declared_components"][-1]["matching"]["cpe"]
        cares = next(c for c in self.cdx["components"] if c["name"] == "c-ares")
        self.assertEqual(cares["cpe"], cpe)
        package = next(p for p in self.spdx["packages"] if p["name"] == "c-ares")
        self.assertIn({"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": cpe}, package["externalRefs"])
        self.assertNotIn("hashes", cares)
        self.assertEqual(package["licenseConcluded"], "NOASSERTION")

    def test_historical_six_component_inventory_is_complete_against_its_producer(self):
        self.inventory["declared_components"].pop()
        self.records.pop(sbom.runtime.CARES_RECORD)
        cdx, spdx = self.generate()
        self.assertEqual(self.check(cdx, spdx)["declared_components"], 6)

    def test_resealed_inventory_cannot_change_producer_declaration_fields(self):
        for key, value in (("source", {"commit": "0" * 40}), ("record_sha256", "0" * 64),
                           ("declared_license", "Other"), ("record_path", "wrong.json"),
                           ("matching", {"cpe": "cpe:2.3:a:wrong:c-ares:1.34.8:*:*:*:*:*:*:*"})):
            inventory = copy.deepcopy(self.inventory)
            inventory["declared_components"][-1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                sbom.validate_closure(inventory)

    def test_spdx_package_references_preserved(self):
        package = next(p for p in self.spdx["packages"] if p["name"] == "libc6")
        self.assertEqual(package["externalRefs"], self.spdx_raw["packages"][1]["externalRefs"])
        package["externalRefs"].clear()
        with self.assertRaises(ValueError):
            self.check()

    def test_cross_format_purl_and_qualifier_mutations_rejected(self):
        original = self.cdx_raw["components"][0]["purl"]
        for value in ("", original.replace("amd64", "arm64"), original.replace("24.04", "22.04"),
                      original.replace("libc6@", "wrong@"), original.replace("2.39", "old"), original + "&arch=amd64"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.cdx_raw["components"][0]["purl"] = value
                self.spdx_raw["packages"][1]["externalRefs"][0]["referenceLocator"] = value
                self.generate()

    def test_raw_purl_reference_missing_duplicate_wrong_category_or_disagreement_rejected(self):
        original = copy.deepcopy(self.spdx_raw)
        for mutation in (lambda r: r.clear(), lambda r: r.append(r[0]),
                         lambda r: r[0].update(referenceCategory="SECURITY"),
                         lambda r: r[0].update(referenceLocator="pkg:generic/wrong@1")):
            self.spdx_raw = copy.deepcopy(original)
            mutation(self.spdx_raw["packages"][1]["externalRefs"])
            with self.assertRaises(ValueError):
                self.generate()

    def test_cpe_references_preserved_without_invention(self):
        cpe = "cpe:2.3:a:gnu:glibc:2.39:*:*:*:*:*:*:*"
        self.cdx_raw["components"][0]["cpe"] = cpe
        self.spdx_raw["packages"][1]["externalRefs"].append(
            {"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": cpe})
        self.cdx, self.spdx = self.generate()
        self.check()
        self.spdx_raw["packages"][1]["externalRefs"].pop()
        with self.assertRaises(ValueError):
            self.generate()

    def test_os_generator_metadata_is_preserved_and_bound(self):
        self.cdx_raw["components"][-1]["swid"] = {"tagId": "ubuntu", "name": "ubuntu", "version": "24.04"}
        self.cdx_raw["components"][-1]["properties"] = [{"name": "syft:distro:id", "value": "ubuntu"}]
        self.cdx, self.spdx = self.generate()
        self.check()
        self.cdx["components"][0]["swid"]["version"] = "old"
        with self.assertRaises(ValueError):
            self.check()

    def test_transformed_purl_is_bound_to_raw_generator(self):
        self.cdx["components"][1]["purl"] = "pkg:generic/libc6@1"
        with self.assertRaises(ValueError):
            self.check()

    def test_real_decoder_identity_fixture_and_rejections(self):
        libraries = [c for c in self.cdx["components"] if c["type"] == "library"]
        decoded = {"distro": {"id": "ubuntu", "versionID": "24.04"}, "artifacts": [
            {"name": c["name"], "version": c["version"], "purl": c["purl"],
             "cpes": [{"cpe": c["cpe"]}] if c.get("cpe") else [],
             "type": "deb" if c["name"] == "libc6" else "UnknownPackage", "metadata": {"architecture": "amd64"}}
            for c in libraries]}
        self.assertFalse(sbom.decoded_identity(self.inventory, self.cdx, decoded)["static_advisory_coverage_established"])
        for mutation in (lambda d: d.update(distro={}), lambda d: d["artifacts"].pop(),
                         lambda d: d["artifacts"][0].update(type="UnknownPackage"),
                         lambda d: d["artifacts"][0].update(purl=""),
                         lambda d: d["artifacts"][0].update(metadata={"architecture": "arm64"})):
            value = copy.deepcopy(decoded)
            mutation(value)
            with self.assertRaises(ValueError):
                sbom.decoded_identity(self.inventory, self.cdx, value)
        decoded["artifacts"][0]["metadata"]["architecture"] = ""
        sbom.decoded_identity(self.inventory, self.cdx, decoded)
        self.cdx["components"][1]["cpe"] = "fixture-cpe"
        with self.assertRaises(ValueError):
            sbom.decoded_identity(self.inventory, self.cdx, decoded)
        decoded["artifacts"][0]["cpes"] = [{"cpe": "fixture-cpe", "source": "declared"}]
        sbom.decoded_identity(self.inventory, self.cdx, decoded)
        next(a for a in decoded["artifacts"] if a["name"] == "c-ares")["cpes"] = []
        with self.assertRaisesRegex(ValueError, "static CPE"):
            sbom.decoded_identity(self.inventory, self.cdx, decoded)

    def test_inventory_cannot_omit_cares_with_recomputed_seal(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = self.sealed_inventory(Path(tmp).resolve(), mutate=lambda i: i["declared_components"].pop())
            with self.assertRaisesRegex(ValueError, "producer-bound"):
                self.load_fixture(*values)

    def test_inventory_cannot_rewrite_patch_evidence_with_recomputed_seal(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = self.sealed_inventory(Path(tmp).resolve(), mutate=lambda i:
                i["declared_components"][0]["verified_producer_patches"].clear())
            with self.assertRaisesRegex(ValueError, "producer-bound"):
                self.load_fixture(*values)

    def test_checksum_subjects_are_distinct(self):
        root = self.cdx["metadata"]["component"]
        archive = next(p for p in self.cdx["components"] if p["bom-ref"] == sbom.DEB)
        self.assertEqual(root["hashes"][0]["content"], "b" * 64)
        self.assertEqual(archive["hashes"][0]["content"], "c" * 64)
        self.assertNotIn("hashes", next(p for p in self.cdx["components"] if p["name"] == "seastar"))

    def test_declared_static_source_and_patch_provenance(self):
        item = next(p for p in self.cdx["components"] if p["name"] == "seastar")
        values = {p["name"]: p["value"] for p in item["properties"]}
        self.assertEqual(values["bonvoyage:native:source_archive_sha256"], "1" * 64)
        self.assertIn(sbom.runtime.digest(b"patch"), values["bonvoyage:native:patches"])
        self.assertEqual(values["bonvoyage:native:evidence_kind"], "producer-declared-static-or-generated-component")

    def test_no_license_clearance_is_claimed(self):
        self.assertTrue(all(p["licenseConcluded"] == "NOASSERTION" for p in self.spdx["packages"]))
        self.assertTrue(all(f["licenseConcluded"] == "NOASSERTION" for f in self.spdx["files"]))

    def test_files_have_sha1_and_sha256(self):
        self.assertTrue(all({c["algorithm"] for c in f["checksums"]} == {"SHA1", "SHA256"} for f in self.spdx["files"]))
        self.assertTrue(all(f["fileName"].startswith("./") for f in self.spdx["files"]))

    def test_verification_code_is_sorted_sha1_of_staged_subset(self):
        self.assertEqual(sbom.verification(self.manifest), sbom.verification(list(reversed(self.manifest))))
        libc = next(p for p in self.spdx["packages"] if p["name"] == "libc6")
        self.assertEqual(libc["packageVerificationCode"]["packageVerificationCodeValue"], sbom.verification([self.manifest[1]]))

    def test_metadata_only_packages_do_not_claim_files(self):
        self.assertTrue(all("packageVerificationCode" not in p and "licenseInfoFromFiles" not in p
                            for p in self.spdx["packages"] if not p["filesAnalyzed"]))

    def test_application_dynamic_and_static_links(self):
        types = {r["relationshipType"] for r in self.spdx["relationships"]}
        self.assertTrue({"DESCRIBES", "DEPENDS_ON", "DYNAMIC_LINK", "STATIC_LINK", "CONTAINS"} <= types)

    def test_missing_static_declared_component_rejected(self):
        self.inventory["declared_components"].pop()
        with self.assertRaises(ValueError):
            self.generate()

    def test_duplicate_static_declaration_rejected(self):
        self.inventory["declared_components"].append(self.inventory["declared_components"][0])
        with self.assertRaises(ValueError):
            self.generate()

    def test_unobserved_or_duplicate_libraries_rejected(self):
        for mutation in (lambda i: i["dynamic_libraries"][0].update(observed_in_process=False),
                         lambda i: i["dynamic_libraries"].append(i["dynamic_libraries"][0])):
            value = copy.deepcopy(self.inventory)
            mutation(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                sbom.validate_closure(value)

    def test_unknown_or_orphan_owner_rejected(self):
        for mutation in (lambda i: i["dynamic_libraries"][0].update(owner="unknown"),
                         lambda i: i["ubuntu_packages"].update({"extra:amd64": {"name": "extra", "version": "1", "architecture": "amd64"}})):
            value = copy.deepcopy(self.inventory)
            mutation(value)
            with self.assertRaises(ValueError):
                sbom.validate_closure(value)

    def test_wrong_architecture_rejected(self):
        self.inventory["ubuntu_packages"]["libc6:amd64"]["architecture"] = "arm64"
        with self.assertRaises(ValueError):
            self.generate()

    def test_raw_generator_missing_added_duplicate_or_wrong_version_rejected(self):
        for components in ([], self.cdx_raw["components"] * 2,
                           [{"name": "libc6", "version": "old"}],
                           self.cdx_raw["components"] + [{"name": "toolchain", "version": "1"}]):
            self.cdx_raw["components"] = components
            with self.subTest(components=components), self.assertRaises(ValueError):
                self.generate()

    def test_raw_generator_wrong_schema_rejected(self):
        for name, value in (("bomFormat", "Other"), ("specVersion", "1.7")):
            raw = copy.deepcopy(self.cdx_raw)
            raw[name] = value
            with self.assertRaises(ValueError):
                sbom.enrich(self.inventory, self.inputs, self.manifest, raw, self.spdx_raw, self.binding)

    def test_spdx_raw_generator_completeness_rejected(self):
        self.spdx_raw["packages"].pop()
        with self.assertRaises(ValueError):
            self.generate()

    def test_cdx_missing_component_rejected(self):
        self.cdx["components"].pop()
        with self.assertRaises(ValueError):
            self.check()

    def test_cdx_duplicate_id_rejected(self):
        self.cdx["components"][1]["bom-ref"] = self.cdx["components"][0]["bom-ref"]
        with self.assertRaises(ValueError):
            self.check()

    def test_cdx_wrong_wellformed_library_hash_rejected(self):
        item = next(p for p in self.cdx["components"] if p["type"] == "file")
        item["hashes"][0]["content"] = "0" * 64
        with self.assertRaises(ValueError):
            self.check()

    def test_cdx_wrong_package_version_rejected(self):
        self.cdx["components"][1]["version"] = "older"
        with self.assertRaises(ValueError):
            self.check()

    def test_cdx_missing_or_duplicate_property_rejected(self):
        for duplicate in (False, True):
            value = copy.deepcopy(self.cdx)
            properties = next(p for p in value["components"] if p["name"] == "seastar")["properties"]
            properties.append(properties[0]) if duplicate else properties.pop()
            with self.assertRaises(ValueError):
                self.check(cdx=value)

    def test_syft_multiple_cpe_values_are_preserved_and_accepted(self):
        package = next(p for p in self.cdx["components"] if p["name"] == "libc6")
        package["properties"] += [{"name": "syft:cpe23", "value": "fixture-cpe-one"},
                                  {"name": "syft:cpe23", "value": "fixture-cpe-two"}]
        self.assertEqual(self.check()["ubuntu_packages"], 1)

    def test_raw_distribution_missing_wrong_or_duplicate_rejected(self):
        for mutation in (lambda c: c["components"].pop(),
                         lambda c: c["components"][-1].update(version="22.04"),
                         lambda c: c["components"].append(c["components"][-1])):
            value = copy.deepcopy(self.cdx_raw)
            mutation(value)
            with self.assertRaises(ValueError):
                sbom.enrich(self.inventory, self.inputs, self.manifest, value, self.spdx_raw, self.binding)

    def test_cdx_missing_or_dangling_relationship_rejected(self):
        self.cdx["dependencies"][0]["dependsOn"] = ["missing"]
        with self.assertRaises(ValueError):
            self.check()

    def test_cdx_root_binding_rejected(self):
        self.cdx["metadata"]["component"]["properties"].pop()
        with self.assertRaises(ValueError):
            self.check()

    def test_spdx_missing_or_duplicate_package_rejected(self):
        for duplicate in (False, True):
            value = copy.deepcopy(self.spdx)
            value["packages"].append(value["packages"][0]) if duplicate else value["packages"].pop()
            with self.assertRaises(ValueError):
                self.check(spdx=value)

    def test_spdx_missing_file_sha1_rejected(self):
        self.spdx["files"][0]["checksums"].pop(0)
        with self.assertRaises(ValueError):
            self.check()

    def test_spdx_wrong_file_sha256_rejected(self):
        self.spdx["files"][0]["checksums"][1]["checksumValue"] = "0" * 64
        with self.assertRaises(ValueError):
            self.check()

    def test_spdx_missing_or_incorrect_verification_code_rejected(self):
        for missing in (False, True):
            value = copy.deepcopy(self.spdx)
            if missing:
                del value["packages"][0]["packageVerificationCode"]
            else:
                value["packages"][0]["packageVerificationCode"]["packageVerificationCodeValue"] = "0" * 40
            with self.assertRaises(ValueError):
                self.check(spdx=value)

    def test_spdx_false_analyzed_containing_files_rejected(self):
        self.spdx["packages"][0]["filesAnalyzed"] = False
        with self.assertRaises(ValueError):
            self.check()

    def test_spdx_dangling_or_missing_relationship_rejected(self):
        for missing in (False, True):
            value = copy.deepcopy(self.spdx)
            value["relationships"].pop() if missing else value["relationships"][0].update(relatedSpdxElement="SPDXRef-Missing")
            with self.assertRaises(ValueError):
                self.check(spdx=value)

    def test_spdx_empty_package_name_rejected(self):
        self.spdx["packages"][0]["name"] = ""
        with self.assertRaises(ValueError):
            self.check()

    def test_spdx_version_and_data_license_rejected(self):
        self.spdx["dataLicense"] = "MIT"
        with self.assertRaises(ValueError):
            self.check()

    def test_safe_evidence_paths(self):
        for path in ("/absolute", "../outside", "dir/../outside", "dir//file", "", 7):
            with self.subTest(path=path), self.assertRaises(ValueError):
                sbom.relative(path)

    def test_strict_json_rejects_duplicate_keys(self):
        with self.assertRaises(ValueError):
            sbom.runtime.decode(b'{"a":1,"a":2}')

    def test_containers_are_readonly_bounded_without_network_or_socket(self):
        argv = sbom.container(sbom.SYFT, [(Path("/var/tmp/snapshot"), "/snapshot", "ro")])
        self.assertIn("none", argv)
        self.assertIn("--read-only", argv)
        self.assertIn("--cpus", argv)
        self.assertIn("--memory", argv)
        self.assertNotIn("/var/run/docker.sock", " ".join(argv))
        self.assertIn(",readonly", argv[-2])

    def test_command_exit_and_diagnostics_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = sbom.execute(Path(tmp).resolve(), "fixture", ["sh", "-c", "printf diagnostic >&2; exit 3"])
            self.assertEqual(result.returncode, 3)
            self.assertEqual((Path(tmp) / "commands/fixture.stderr").read_bytes(), b"diagnostic")
            self.assertEqual(json.loads((Path(tmp) / "commands/fixture.json").read_text())["exit_code"], 3)

    def test_runtime_manifest_wrong_subject_identity_rejected(self):
        for name, value in (("sha256", "0" * 64), ("bytes", 1), ("host_path", "/elsewhere"),
                            ("owner", "other"), ("sha1", "invalid")):
            manifest = copy.deepcopy(self.manifest)
            manifest[1][name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                sbom.validate_manifest(self.inventory, manifest)

    def test_runtime_manifest_duplicate_missing_or_extra_rejected(self):
        for manifest in (self.manifest[:1], self.manifest * 2, self.manifest + [self.manifest[0]]):
            with self.assertRaises(ValueError):
                sbom.validate_manifest(self.inventory, manifest)

    def snapshot(self, directory):
        path = directory / "usr/bin/file"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"real snapshot checksum fixture")
        record = sbom.file_record(path)
        return [{"path": "usr/bin/file", "bytes": record["bytes"], "sha256": record["sha256"],
                 "sha1": sbom.hashlib.sha1(path.read_bytes()).hexdigest()}]

    def test_snapshot_exact_hash_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            manifest = self.snapshot(root)
            sbom.verify_snapshot(root, manifest)

    def test_snapshot_extra_changed_symlink_and_duplicate_rejected(self):
        for kind in ("extra", "changed", "symlink", "duplicate", "sha1"):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                manifest = self.snapshot(root)
                if kind == "extra":
                    (root / "extra").write_bytes(b"unexpected")
                elif kind == "changed":
                    (root / "usr/bin/file").write_bytes(b"changed")
                elif kind == "symlink":
                    (root / "link").symlink_to(root / "usr/bin/file")
                elif kind == "duplicate":
                    manifest *= 2
                else:
                    manifest[0]["sha1"] = "0" * 40
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    sbom.verify_snapshot(root, manifest)

    def sealed_inventory(self, directory, mutate=None, seal_mutate=None):
        request = directory / "request.json"
        request.write_text("{}")
        inventory = copy.deepcopy(self.inventory)
        inventory.update({"schema_version": 1, "classification": "private-native-runtime-inventory",
                          "outcome": "collected-unqualified", "packaging_source_commit": "7" * 40,
                          "collector_source": {"commit": "8" * 40, "dirty": False,
                                               "status_sha256": sbom.runtime.digest(b"")},
                          "collector": {"sha256": sbom.runtime.digest(b"committed-collector")},
                          "request": sbom.file_record(request), **{flag: False for flag in sbom.runtime.FLAGS}})
        if mutate:
            mutate(inventory)
        path = directory / "inventory.json"
        path.write_text(json.dumps(inventory))
        files = []
        for item in (path, request):
            files.append({**sbom.file_record(item), "path": item.name})
        seal = {"schema_version": 1, "files": files}
        if seal_mutate:
            seal_mutate(seal)
        seal_path = directory / "checksums.json"
        seal_path.write_text(json.dumps(seal))
        return inventory, path, sbom.file_record(path)["sha256"], sbom.file_record(seal_path)["sha256"]

    def load_fixture(self, inventory, path, sha, seal):
        spec = {"files": inventory["files"], "producer_source_commit": inventory["producer_source_commit"],
                "runtime_profile": inventory["runtime_profile"]}
        with ExitStack() as stack:
            stack.enter_context(patch.object(sbom.runtime, "git_file", side_effect=lambda commit, name, *args:
                b"committed-collector" if name == "scripts/collect-native-runtime.py" else b"patch"))
            stack.enter_context(patch.object(sbom.runtime, "load_request", return_value=(spec, {})))
            producer_sbom = {"components": [{"name": item["name"], "version": item["version"],
                "licenses": [{"license": {"id": item["declared_license"]}}], "properties": [
                    {"name": "bonvoyage:source:commit", "value": item["source"]["commit"]},
                    {"name": "bonvoyage:build:linkage", "value": item["declared_linkage"]}],
                **({"cpe": item["matching"]["cpe"], "hashes": [{"alg": "SHA-256",
                    "content": item["source"]["archive_sha256"]}]} if item.get("matching") else {})}
                for item in self.inventory["declared_components"]]}
            stack.enter_context(patch.object(sbom.runtime, "verify_binding", return_value=(
                {"packaging_source": {"commit": inventory["packaging_source_commit"]}}, self.inputs, producer_sbom)))
            return sbom.load_inventory(path, sha, seal)

    def test_checksum_bound_clean_inventory_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = self.sealed_inventory(Path(tmp).resolve())
            self.assertEqual(self.load_fixture(*values)[0], values[0])

    def test_inventory_and_seal_wrong_anchor_rejected(self):
        for index in (2, 3):
            with tempfile.TemporaryDirectory() as tmp:
                values = list(self.sealed_inventory(Path(tmp).resolve()))
                values[index] = "0" * 64
                with self.assertRaises(ValueError):
                    self.load_fixture(*values)

    def test_seal_duplicate_missing_and_traversal_rejected(self):
        for mutation in (lambda s: s["files"].append(s["files"][0]), lambda s: s["files"].pop(),
                         lambda s: s["files"][0].update(path="../outside")):
            with tempfile.TemporaryDirectory() as tmp:
                values = self.sealed_inventory(Path(tmp).resolve(), seal_mutate=mutation)
                with self.assertRaises(ValueError):
                    self.load_fixture(*values)

    def test_inventory_extra_or_symlink_evidence_rejected(self):
        for kind in ("extra", "symlink"):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                values = self.sealed_inventory(root)
                (root / "link").symlink_to(root / "inventory.json") if kind == "symlink" else (root / "extra").write_bytes(b"extra")
                with self.assertRaises(ValueError):
                    self.load_fixture(*values)

    def test_dirty_wrong_profile_and_imported_qualification_rejected(self):
        mutations = [lambda i: i["collector_source"].update(dirty=True), lambda i: i.update(runtime_profile="automatic")]
        mutations += [lambda i, flag=flag: i.update({flag: True}) for flag in sbom.runtime.FLAGS]
        for mutation in mutations:
            with tempfile.TemporaryDirectory() as tmp:
                values = self.sealed_inventory(Path(tmp).resolve(), mutate=mutation)
                with self.assertRaises(ValueError):
                    self.load_fixture(*values)

    def test_committed_collector_checksum_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = self.sealed_inventory(Path(tmp).resolve(), mutate=lambda i: i["collector"].update(sha256="0" * 64))
            with self.assertRaises(ValueError):
                self.load_fixture(*values)

    def test_safe_json_write_rejects_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            target = root / "outside"
            target.write_bytes(b"preserve")
            target.chmod(0o755)
            link = root / "generated.json"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                sbom.write_json(link, {"bad": True})
            self.assertEqual(target.read_bytes(), b"preserve")
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)
            with self.assertRaises(ValueError):
                sbom.safe_tree(root)

    def test_safe_json_write_rejects_hardlink_before_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            target = root / "outside"
            target.write_bytes(b"preserve")
            os.link(target, root / "generated.json")
            with self.assertRaises(ValueError):
                sbom.write_json(root / "generated.json", {"bad": True})
            self.assertEqual(target.read_bytes(), b"preserve")

    def test_safe_json_write_is_private_and_rewritable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "receipt.json"
            sbom.write_json(path, {"outcome": "running"})
            sbom.write_json(path, {"outcome": "done"})
            self.assertEqual(json.loads(path.read_text()), {"outcome": "done"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            sbom.safe_tree(root)

    def test_empty_diagnostic_is_sealed_but_not_a_valid_runtime_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / "empty.stderr"
            path.touch()
            record = sbom.evidence_record(path)
            self.assertEqual(record["bytes"], 0)
            self.assertEqual(record["sha256"], sbom.runtime.digest(b""))
            with self.assertRaises(ValueError):
                sbom.file_record(path)

    def test_evidence_seal_rejects_symlink_or_hardlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            target = root / "target"
            target.write_bytes(b"fixture")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                sbom.evidence_record(link)
            link.unlink()
            os.link(target, link)
            with self.assertRaises(ValueError):
                sbom.evidence_record(link)

    def live_fixture(self, directory, extra=False):
        binary = directory / "binary"
        library = directory / "library"
        binary.write_bytes(b"\x7fELFfixture-executable")
        library.write_bytes(b"\x7fELFfixture-library")
        state = {"pid": 999, "restarts": 0}
        inventory = {"process": state, "files": {"binary": {"path": str(binary)}},
                     "dynamic_libraries": [{"path": str(library), "resolved_by_ldd": True}]}

        def mapping(path):
            value = path.stat()
            return "1000-2000 r-xp 00000000 %02x:%02x %d %s\n" % (
                os.major(value.st_dev), os.minor(value.st_dev), value.st_ino, path)
        expected = mapping(binary) + mapping(library)
        (directory / "process-maps.txt").write_text(expected)
        live = expected
        if extra:
            added = directory / "new-dlopen-library"
            added.write_bytes(b"\x7fELFextra-library")
            live += mapping(added)
        return inventory, state, live, str(library)

    def check_live_fixture(self, directory, extra):
        inventory, state, live, library = self.live_fixture(directory, extra)
        original = Path.read_text

        def read(path, *args, **kwargs):
            return live if str(path) == "/proc/999/maps" else original(path, *args, **kwargs)
        with patch.object(sbom.runtime, "process_state", return_value=(state, b"")), \
             patch.object(Path, "read_text", new=read), \
             patch.object(sbom.runtime, "run", return_value=("libfixture => " + library + " (0xabc)\n").encode()):
            sbom.verify_live(inventory, directory)

    def test_same_pid_original_live_elf_closure_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.check_live_fixture(Path(tmp).resolve(), False)

    def test_same_pid_new_dlopen_elf_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "live ELF mapping identity changed|closure changed"):
                self.check_live_fixture(Path(tmp).resolve(), True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
