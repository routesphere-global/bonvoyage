#!/usr/bin/env python3
"""Synthetic mutation tests; no Docker, scanner, network or VM is used."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("bind-runtime-glibc-reachability.py")
SPEC = importlib.util.spec_from_file_location("glibc_binding", SCRIPT)
binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binding)
COMMIT = "2" * 40
IMAGE_ID = "sha256:" + "1" * 64


def digest(data):
    return hashlib.sha256(data).hexdigest()


class RuntimeGlibcBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.evidence = self.root / "evidence"
        self.repo.mkdir()
        (self.evidence / "dual-format").mkdir(parents=True)
        self.sources = sorted(binding.REQUIRED_SOURCE_FILES)
        for name in self.sources:
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture " + name + "\n")
        (self.evidence / "source-files.txt").write_text("\n".join(self.sources) + "\n")
        (self.evidence / "source-checksums.sha256").write_text("".join(
            f"{digest((self.repo / name).read_bytes())}  {name}\n" for name in self.sources))
        (self.evidence / "environment.txt").write_text(
            "captured_at_utc=20260930T000000Z\n"
            f"source_commit={COMMIT}\nsource_dirty=false\n"
            "runtime_platform=linux/amd64\n"
            f"runtime_image_id={IMAGE_ID}\n"
            f"runtime_source_revision={COMMIT}\nruntime_source_dirty=false\n")
        (self.evidence / "runtime.oci.tar").write_bytes(b"OCI fixture")
        self.write_json("runtime.raw.syft.json", {"source": "fixture"})
        self.write_json("runtime.cdx.json", {"bomFormat": "CycloneDX"})
        self.write_json("runtime.syft.spdx.json", {"spdxVersion": "SPDX-2.3"})
        self.write_json("dual-format/scan-cdx.stdout", {"matches": []})
        self.write_json("dual-format/scan-spdx.stdout", {"matches": []})
        (self.evidence / "vulnerabilities.grype.json").write_bytes(
            (self.evidence / "dual-format/scan-cdx.stdout").read_bytes())
        scan_inputs = {
            "archive": "sha256:" + digest((self.evidence / "runtime.oci.tar").read_bytes()),
            "syft": "sha256:" + digest((self.evidence / "runtime.raw.syft.json").read_bytes()),
            "cyclonedx": "sha256:" + digest((self.evidence / "runtime.cdx.json").read_bytes()),
            "spdx": "sha256:" + digest(
                (self.evidence / "runtime.syft.spdx.json").read_bytes()),
        }
        labels = {
            "io.routesphere.bonvoyage.upstream-http1-client": "seastar-reference",
            "io.routesphere.bonvoyage.source-dirty": "false",
            "org.opencontainers.image.revision": COMMIT,
        }
        self.image = [{"Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64",
                       "Config": {"Labels": labels}}]
        self.write_json("runtime-image-inspect.json", self.image)
        self.write_json("runtime-container-inspect.json", [{"Image": IMAGE_ID}])
        (self.evidence / "runtime-rootfs.tar").write_bytes(b"rootfs fixture")
        (self.evidence / "runtime-gateway.bin").write_bytes(b"gateway fixture")
        image_receipt = binding.receipt(self.evidence / "runtime-image-inspect.json")
        container_receipt = binding.receipt(self.evidence / "runtime-container-inspect.json")
        self.analyzer = {
            "schema_version": 1,
            "source_commit": COMMIT,
            "evidence_qualified": True,
            "runtime_identity": {"image_id": IMAGE_ID, "platform": "linux/amd64",
                                 "source_revision": COMMIT, "source_dirty_label": "false"},
            "inspection_receipts": {"image_inspect": image_receipt,
                                    "container_inspect": container_receipt},
            "rootfs_export": binding.receipt(self.evidence / "runtime-rootfs.tar"),
            "gateway": {"sha256": digest(b"gateway fixture")},
            "finding_status": {
                "CVE-2026-8674": {"status": "under_review"},
                "CVE-2026-18374": {"status": "under_review"},
            },
            "source_binding_verified": False,
            "reachability_closed": False,
            "vex_authorized": False,
            "scanner_suppression_authorized": False,
            "release_authorized": False,
        }
        self.write_json("runtime-glibc-reachability.json", self.analyzer)
        self.write_json("image-binding-verification.json", {
            "schema_version": 1, "image_binding_qualified": True,
            "locked_image_id": IMAGE_ID, "platform": "linux/amd64",
            "input_sha256": scan_inputs})
        scan_result = {
            "schema_version": 1, "scanner_parity_qualified": True,
            "status": "passed", "coverage_qualified": False,
            "input_sha256": scan_inputs,
            "counts": {"High": 0, "Critical": 0},
            "blocking": [], "gate": {"threshold": "High", "passed": True},
        }
        self.write_json("dual-format/result.json", scan_result)
        self.write_json("dual-format/evidence-checksums.json", {
            "result.json": digest((self.evidence / "dual-format/result.json").read_bytes()),
            "scan-cdx.stdout": digest(
                (self.evidence / "dual-format/scan-cdx.stdout").read_bytes()),
            "scan-spdx.stdout": digest(
                (self.evidence / "dual-format/scan-spdx.stdout").read_bytes()),
        })
        self.write_json("vulnerability-summary.json", {
            "schema_version": 1,
            "source": {"target": {"manifestDigest": IMAGE_ID[7:], "labels": labels}},
            "report_sha256": digest((self.evidence / "vulnerabilities.grype.json").read_bytes()),
            "counts": scan_result["counts"], "blocking": scan_result["blocking"],
            "gate": scan_result["gate"]})

    def write_json(self, name, value):
        path = self.evidence / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, separators=(",", ":")))

    def bind(self, status=""):
        return binding.bind(self.evidence, self.repo, COMMIT, status)

    def test_clean_source_scan_and_analyzer_are_bound_without_vex(self):
        result = self.bind()
        self.assertTrue(result["source_binding_verified"])
        self.assertTrue(result["scan_binding_verified"])
        self.assertTrue(result["reachability_evidence_binding_verified"])
        self.assertFalse(result["reachability_closed"])
        self.assertFalse(result["vex_authorized"])
        self.assertFalse(result["release_authorized"])
        self.assertFalse(result["scan"]["coverage_qualified"])

    def test_dirty_or_drifted_source_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "clean source"):
            self.bind(" M scripts/file\n")
        (self.repo / self.sources[0]).write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "source checksum mismatch"):
            self.bind()

    def test_image_scan_and_authorization_drift_are_rejected(self):
        cases = [
            ("revision", "runtime-image-inspect.json", lambda value:
             value[0]["Config"]["Labels"].update({"org.opencontainers.image.revision": "0" * 40})),
            ("image input", "image-binding-verification.json", lambda value:
             value["input_sha256"].update({"archive": "sha256:" + "0" * 64})),
            ("scan parity", "dual-format/result.json", lambda value:
             value.update(scanner_parity_qualified=False)),
            ("scan target", "vulnerability-summary.json", lambda value:
             value["source"]["target"].update(manifestDigest="0" * 64)),
            ("VEX", "runtime-glibc-reachability.json", lambda value:
             value.update(vex_authorized=True)),
            ("disposition", "runtime-glibc-reachability.json", lambda value:
             value["finding_status"]["CVE-2026-8674"].update(status="not_affected")),
        ]
        originals = {name: (self.evidence / name).read_bytes()
                     for _, name, _ in cases}
        for label, name, mutation in cases:
            with self.subTest(label=label):
                for path, data in originals.items():
                    (self.evidence / path).write_bytes(data)
                value = json.loads((self.evidence / name).read_text())
                mutation(value)
                self.write_json(name, value)
                with self.assertRaises(ValueError):
                    self.bind()

        for path, data in originals.items():
            (self.evidence / path).write_bytes(data)
        (self.evidence / "dual-format/scan-cdx.stdout").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "checksum seal"):
            self.bind()

    def test_missing_tool_source_or_duplicate_metadata_is_rejected(self):
        lines = (self.evidence / "source-files.txt").read_text().splitlines()
        (self.evidence / "source-files.txt").write_text("\n".join(lines[:-1]) + "\n")
        with self.assertRaises(ValueError):
            self.bind()

        self.setUp()
        with (self.evidence / "environment.txt").open("a") as output:
            output.write(f"source_commit={COMMIT}\n")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.bind()

    def test_output_is_private_and_never_overwritten(self):
        output = self.root / "binding.json"
        binding.write_private(output, self.bind())
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        before = output.read_bytes()
        with self.assertRaisesRegex(ValueError, "output must be new"):
            binding.write_private(output, self.bind())
        self.assertEqual(output.read_bytes(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
