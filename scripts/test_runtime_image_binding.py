#!/usr/bin/env python3
"""Synthetic, bounded OCI corruption tests; no Docker, scanner or VM is used."""
import base64
import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("verify-runtime-image-binding.py")
spec = importlib.util.spec_from_file_location("binding", SCRIPT)
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


class ImageBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self, change=None, direct=False, arch="amd64", extra=None):
        blobs = {}
        def blob(data, media):
            sha = digest(data)
            blobs["blobs/sha256/" + sha[7:]] = data
            return {"mediaType": media, "digest": sha, "size": len(data)}
        payloads = [b"fixture layer A" * 100, b"fixture layer B" * 100]
        layer_descriptors = [blob(gzip.compress(data, mtime=0), binding.OCI_GZIP) for data in payloads]
        config = {"os": "linux", "architecture": arch,
                  "rootfs": {"type": "layers", "diff_ids": [digest(data) for data in payloads]}}
        state = {"layers": layer_descriptors, "config": config, "platform": {"architecture": arch, "os": "linux"}}
        if change:
            change(state)
        config_bytes = state.get("config_bytes", encoded(state["config"]))
        config_descriptor = blob(config_bytes, binding.OCI_CONFIG)
        manifest = {"schemaVersion": 2, "mediaType": binding.OCI_MANIFEST,
                    "config": config_descriptor, "layers": state["layers"]}
        selected = blob(encoded(manifest), binding.OCI_MANIFEST)
        selected["platform"] = state["platform"]
        root_descriptor = selected if direct else blob(encoded({"schemaVersion": 2, "mediaType": binding.OCI_INDEX,
            "manifests": [selected] * state.get("platform_copies", 1)}), binding.OCI_INDEX)
        image_id = root_descriptor["digest"]
        index = {"schemaVersion": 2, "mediaType": binding.OCI_INDEX, "manifests": [root_descriptor]}
        archive_entries = {"oci-layout": encoded({"imageLayoutVersion": "1.0.0"}), "index.json": encoded(index), **blobs}
        if extra:
            extra(archive_entries)
        archive_path = self.root / "image.tar"
        with tarfile.open(archive_path, "w") as archive:
            for name, data in archive_entries.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        descriptor = {"schemaVersion": 2, "mediaType": binding.DOCKER_MANIFEST,
            "config": {"mediaType": binding.DOCKER_CONFIG, "size": len(config_bytes), "digest": config_descriptor["digest"]},
            "layers": [{"mediaType": binding.DOCKER_GZIP, "size": layer["size"], "digest": diff}
                       for layer, diff in zip(state["layers"], config["rootfs"]["diff_ids"])]}
        descriptor_bytes = encoded(descriptor)
        descriptor_sha = digest(descriptor_bytes)
        metadata = {"userInput": image_id, "os": "linux", "architecture": arch,
                    "imageID": config_descriptor["digest"], "config": base64.b64encode(config_bytes).decode(),
                    "manifest": base64.b64encode(descriptor_bytes).decode(), "manifestDigest": descriptor_sha,
                    "mediaType": binding.DOCKER_MANIFEST, "layers": descriptor["layers"]}
        raw = {"descriptor": {"name": "syft", "version": "1.44.0"},
               "source": {"type": "image", "name": "sha256", "version": image_id[7:],
                          "id": descriptor_sha[7:], "metadata": metadata}}
        cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {
            "type": "container", "name": "sha256", "version": image_id[7:], "bom-ref": binding.config_bom_ref(config_descriptor["digest"])}}}
        spdx = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Root"}],
            "packages": [{"primaryPackagePurpose": "CONTAINER", "SPDXID": "SPDXRef-Root",
            "name": "sha256", "versionInfo": image_id[7:], "checksums": [{"algorithm": "SHA256", "checksumValue": descriptor_sha[7:]}],
            "externalRefs": [{"referenceType": "purl", "referenceCategory": "PACKAGE-MANAGER",
                "referenceLocator": f"pkg:oci/sha256@sha256%3A{descriptor_sha[7:]}?arch={arch}&tag={image_id[7:]}"}]}]}
        paths = []
        for name, document in [("raw", raw), ("cdx", cdx), ("spdx", spdx)]:
            path = self.root / (name + ".json")
            path.write_bytes(encoded(document))
            paths.append(path)
        return archive_path, image_id, paths, [raw, cdx, spdx]

    def test_index_and_direct_manifest_roots(self):
        for direct in [False, True]:
            with self.subTest(direct=direct):
                archive, expected, paths, _ = self.fixture(direct=direct)
                result = binding.verify(archive, expected, *paths)
                self.assertTrue(result["image_binding_qualified"])
                self.assertFalse(result["syft_descriptor_is_registry_manifest"])
                self.assertFalse(result["formal_rc_accepted"])
                self.assertFalse(result["scanner_parity_qualified"])
                self.assertFalse(result["publisher_authenticity_verified"])
                self.assertNotEqual(result["platform_manifest"], result["syft_docker_descriptor_sha256"])
                self.assertEqual(len(result["layers"]), 2)

    def test_explicit_arm64_does_not_masquerade_as_amd64(self):
        archive, expected, paths, _ = self.fixture(arch="arm64")
        with self.assertRaises(ValueError):
            binding.verify(archive, expected, *paths)
        self.assertEqual(binding.verify(archive, expected, *paths, platform="linux/arm64")["platform"], "linux/arm64")

    def test_wrong_external_lock_or_tag(self):
        archive, _, paths, _ = self.fixture()
        for expected in ["gateway:latest", "sha256:short", "sha256:" + "0" * 64]:
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                binding.verify(archive, expected, *paths)

    def test_corrupt_graph_and_platform_rejected(self):
        cases = [
            ("wrong config architecture", lambda s: s["config"].update(architecture="arm64")),
            ("duplicate target", lambda s: s.update(platform_copies=2)),
            ("missing target", lambda s: s.update(platform_copies=0)),
            ("wrong diffID", lambda s: s["config"]["rootfs"]["diff_ids"].__setitem__(0, "sha256:" + "0" * 64)),
            ("layer order", lambda s: s["layers"].reverse()),
            ("descriptor size", lambda s: s["layers"][0].update(size=0)),
            ("missing layer", lambda s: s["layers"][0].update(digest="sha256:" + "0" * 64)),
            ("unsupported encoding", lambda s: s["layers"][0].update(mediaType="application/vnd.oci.image.layer.v1.tar+zstd")),
            ("duplicate JSON key", lambda s: s.update(config_bytes=b'{"os":"linux","os":"windows"}')),
            ("diffID count", lambda s: s["config"]["rootfs"]["diff_ids"].pop()),
        ]
        for label, change in cases:
            with self.subTest(label=label):
                archive, expected, paths, _ = self.fixture(change=change)
                with self.assertRaises(ValueError):
                    binding.verify(archive, expected, *paths)

    def test_changed_blob_and_unsafe_archive_paths_rejected(self):
        for label, change in [
            ("changed bytes", lambda entries: entries.update({next(k for k in entries if k.startswith("blobs/")): b"tampered"})),
            ("traversal", lambda entries: entries.update({"../outside": b"bad"})),
            ("unexpected file", lambda entries: entries.update({"unexpected": b"bad"})),
            ("alias path", lambda entries: entries.update({"./index.json": entries["index.json"]})),
        ]:
            with self.subTest(label=label):
                archive, expected, paths, _ = self.fixture(extra=change)
                with self.assertRaises(ValueError):
                    binding.verify(archive, expected, *paths)

    def test_duplicate_archive_members_and_links_rejected(self):
        for kind in [tarfile.REGTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE,
                     tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_SPARSE]:
            with self.subTest(kind=kind):
                archive, expected, paths, _ = self.fixture()
                with tarfile.open(archive, "a") as writer:
                    member = tarfile.TarInfo("index.json" if kind == tarfile.REGTYPE else "unsafe")
                    member.type, member.linkname = kind, "/etc/passwd"
                    writer.addfile(member)
                with self.assertRaises(ValueError):
                    binding.verify(archive, expected, *paths)

    def test_decompression_budget(self):
        archive, expected, paths, _ = self.fixture()
        with patch.object(binding, "LAYER_LIMIT", 8), self.assertRaisesRegex(ValueError, "byte budget"):
            binding.verify(archive, expected, *paths)

    def test_spoofed_report_identities_rejected(self):
        cases = [
            ("raw target", lambda r, c, s: r["source"].update(version="0" * 64)),
            ("config substitution", lambda r, c, s: r["source"]["metadata"].update(config=base64.b64encode(b"{}").decode())),
            ("manifest substitution", lambda r, c, s: r["source"]["metadata"].update(manifest=base64.b64encode(b"{}").decode())),
            ("malformed base64", lambda r, c, s: r["source"]["metadata"].update(config="!")),
            ("raw sequence", lambda r, c, s: r["source"]["metadata"]["layers"].reverse()),
            ("cdx target", lambda r, c, s: c["metadata"]["component"].update(version="0" * 64)),
            ("cdx config reference", lambda r, c, s: c["metadata"]["component"].update({"bom-ref": "arbitrary"})),
            ("missing root relation", lambda r, c, s: s.update(relationships=[])),
            ("redirected root", lambda r, c, s: s["relationships"][0].update(relatedSpdxElement="SPDXRef-Other")),
            ("duplicate root relation", lambda r, c, s: s["relationships"].append(copy.deepcopy(s["relationships"][0]))),
            ("spdx checksum", lambda r, c, s: s["packages"][0]["checksums"][0].update(checksumValue="0" * 64)),
            ("spdx PURL", lambda r, c, s: s["packages"][0]["externalRefs"][0].update(referenceLocator="pkg:oci/other@latest")),
            ("duplicate root", lambda r, c, s: s["packages"].append(copy.deepcopy(s["packages"][0]))),
            ("unknown Syft", lambda r, c, s: r["descriptor"].update(version="1.45.0")),
        ]
        for label, change in cases:
            with self.subTest(label=label):
                archive, expected, paths, documents = self.fixture()
                change(*documents)
                for path, document in zip(paths, documents):
                    path.write_bytes(encoded(document))
                with self.assertRaises(ValueError):
                    binding.verify(archive, expected, *paths)

    def test_input_changes_during_verification_rejected(self):
        archive, expected, paths, _ = self.fixture()
        original = binding.bind
        def changed(*args):
            result = original(*args)
            paths[0].write_bytes(b"changed during verification")
            return result
        with patch.object(binding, "bind", side_effect=changed), self.assertRaisesRegex(ValueError, "inputs changed"):
            binding.verify(archive, expected, *paths)

    def test_known_real_config_reference(self):
        self.assertEqual(binding.config_bom_ref("sha256:051b33724cef6d515a9833a1be98f2a9337cdb0a18643cfad3f795485939ab58"),
                         "f741c2deeac8e021")

    def test_nested_index_branch_is_not_silently_skipped(self):
        archive, _, _, _ = self.fixture()
        with tarfile.open(archive) as reader:
            entries = {m.name: reader.extractfile(m).read() for m in reader if m.isfile()}
        index = json.loads(entries["index.json"])
        root = index["manifests"][0]
        root_doc = json.loads(entries["blobs/sha256/" + root["digest"][7:]])
        root_doc["manifests"].append({"mediaType": binding.OCI_INDEX, "digest": root["digest"], "size": root["size"]})
        data = encoded(root_doc)
        root.update(digest=digest(data), size=len(data))
        entries["blobs/sha256/" + root["digest"][7:]] = data
        entries["index.json"] = encoded(index)
        with tarfile.open(archive, "w") as writer:
            for name, content in entries.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                writer.addfile(member, io.BytesIO(content))
        with self.assertRaisesRegex(ValueError, "nested indexes"):
            binding.inspect_archive(archive, root["digest"])

    def test_unbounded_extension_is_rejected_before_tarfile_parsing(self):
        archive, expected, paths, _ = self.fixture()
        member = tarfile.TarInfo("huge-pax")
        member.type, member.size = tarfile.XHDTYPE, binding.ARCHIVE_LIMIT
        archive.write_bytes(member.tobuf() + bytes(1024))
        with patch.object(binding.tarfile, "open", side_effect=AssertionError("must not parse extension")), \
                self.assertRaisesRegex(ValueError, "physical tar header"):
            binding.verify(archive, expected, *paths)

    def test_cli_writes_only_new_success_receipts(self):
        archive, expected, paths, _ = self.fixture()
        output = self.root / "result.json"
        argv = [sys.executable, "-B", str(SCRIPT), "--archive", str(archive), "--expected-image-id", expected,
                "--syft", str(paths[0]), "--cyclonedx", str(paths[1]), "--spdx", str(paths[2]), "--output", str(output)]
        result = subprocess.run(argv, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        original = output.read_bytes()
        self.assertNotEqual(subprocess.run(argv, capture_output=True, timeout=10).returncode, 0)
        self.assertEqual(output.read_bytes(), original)
        output.unlink()
        paths[0].write_bytes(b"invalid")
        self.assertNotEqual(subprocess.run(argv, capture_output=True, timeout=10).returncode, 0)
        self.assertFalse(output.exists())

    def test_collector_requires_binding_before_grype_without_lowering_threshold(self):
        source = SCRIPT.with_name("qualify-runtime-dependencies.sh").read_text()
        self.assertIn('docker image save --output "$evidence_dir/runtime.oci.tar" "$image_id"', source)
        self.assertIn('--expected-image-id "$image_id"', source)
        self.assertLess(source.index("python3 -B scripts/verify-runtime-image-binding.py"),
                        source.index('python3 -B scripts/scan-runtime-sbom-pair.py'))
        self.assertEqual(source.count("runtime.oci.tar image-binding-verification.json"), 1)
        self.assertIn('for evidence_file do', source)
        self.assertIn('done > evidence-checksums.sha256', source)


if __name__ == "__main__":
    unittest.main()
