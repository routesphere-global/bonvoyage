"""Focused tests for deterministic OSS OCI assembly and reproducibility."""

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest


def load_module(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


oci = load_module("bonvoyage_oss_oci_builder_test", "build-oss-oci.py")
reproducibility = load_module(
    "bonvoyage_oss_oci_reproducibility_test", "verify-oss-oci-reproducibility.py",
)


class OssOciBuilderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.rootfs = self.base / "rootfs"
        self.rootfs.mkdir()
        self.contract = oci.load_contract()
        self.commit = "1" * 40
        self.tag = "v1.0.0-rc.1"
        self.version = "1.0.0-rc.1"
        self.epoch = 1700000000
        self.populate_rootfs()

    def write(self, relative, data=b"fixture\n", mode=0o644):
        path = self.rootfs / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def populate_rootfs(self):
        binary = bytearray(128)
        binary[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", binary, 16, 3, 62)
        struct.pack_into("<Q", binary, 24, 4096)
        for relative in self.contract["rootfs"]["required_files"]:
            if relative == "usr/local/bin/bonvoyage-dataplane":
                self.write(relative, bytes(binary), 0o755)
            elif relative == "usr/share/licenses/bonvoyage/LICENSE":
                self.write(relative, b"Copyright 2026 RouteSphere project authors.\n"
                           b"Test-only fixture; no publication authority is granted.\n")
            else:
                self.write(relative)
        for name in self.contract["rootfs"]["required_dependency_records"]:
            self.write("usr/share/bonvoyage/dependencies/" + name,
                       json.dumps({"name": name}, sort_keys=True).encode() + b"\n")
        (self.rootfs / "var/lib/bonvoyage").mkdir(parents=True)

    def build(self, name):
        path = self.base / name
        result = oci.build_archive(
            self.rootfs, path, self.contract, self.commit, self.tag,
            self.version, self.epoch,
        )
        return path, result

    @staticmethod
    def layout_files(path):
        with tarfile.open(path, "r:") as archive:
            return {
                member.name.rstrip("/") if member.isdir() else member.name:
                None if member.isdir() else archive.extractfile(member).read()
                for member in archive.getmembers()
            }

    def rewrite_layout(self, path, files):
        replacement = path.with_name(path.name + ".new")
        with tarfile.open(replacement, "w", format=tarfile.USTAR_FORMAT) as archive:
            for name in sorted(files):
                data = files[name]
                if data is None:
                    archive.addfile(oci.tar_info(name, self.epoch, 0o755, directory=True))
                else:
                    archive.addfile(
                        oci.tar_info(name, self.epoch, 0o644, size=len(data)), io.BytesIO(data),
                    )
        replacement.replace(path)

    def test_two_builds_are_byte_identical_and_verified(self):
        first, first_result = self.build("first.oci.tar")
        second, second_result = self.build("second.oci.tar")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first_result["archive"], second_result["archive"])
        self.assertEqual(first_result["platform"], {"architecture": "amd64", "os": "linux"})
        self.assertEqual(first_result["source"]["commit"], self.commit)
        self.assertFalse(first_result["release_admitted"])
        self.assertFalse(first_result["publishable"])
        self.assertEqual(oci.verify_archive(
            first, self.contract, self.commit, self.tag, self.version, self.epoch,
        )["archive"], first_result["archive"])
        layer, uncompressed, _, _ = oci.build_layer(
            self.rootfs, self.contract, self.epoch,
        )
        self.assertEqual(
            oci.bounded_gzip_decompress(layer, len(uncompressed)), uncompressed,
        )
        with self.assertRaisesRegex(ValueError, "trailing or concatenated"):
            oci.bounded_gzip_decompress(layer + b"not-a-second-member", len(uncompressed))
        with self.assertRaisesRegex(ValueError, "rootfs ceiling"):
            oci.bounded_gzip_decompress(layer, len(uncompressed) - 1)

    def test_rootfs_links_special_modes_and_secret_paths_are_rejected(self):
        target = self.write("tmp/target")
        link = self.rootfs / "tmp/link"
        link.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            self.build("link.oci.tar")
        link.unlink()
        target.chmod(0o666)
        with self.assertRaisesRegex(ValueError, "unsafe rootfs mode"):
            self.build("mode.oci.tar")
        target.chmod(0o644)
        self.write("etc/server-private-key.pem")
        with self.assertRaisesRegex(ValueError, "secret-like"):
            self.build("secret.oci.tar")

    def test_required_files_dependencies_and_amd64_elf_are_enforced(self):
        required = self.rootfs / "etc/os-release"
        required.unlink()
        with self.assertRaisesRegex(ValueError, "missing required rootfs"):
            self.build("missing.oci.tar")
        self.write("etc/os-release")
        dependency = self.rootfs / "usr/share/bonvoyage/dependencies/abseil-20250512.1.json"
        dependency.unlink()
        with self.assertRaisesRegex(ValueError, "missing dependency"):
            self.build("dependency.oci.tar")
        self.write("usr/share/bonvoyage/dependencies/abseil-20250512.1.json")
        binary = self.rootfs / "usr/local/bin/bonvoyage-dataplane"
        data = bytearray(binary.read_bytes())
        struct.pack_into("<H", data, 18, 183)
        binary.write_bytes(data)
        binary.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "AMD64"):
            self.build("architecture.oci.tar")

    def test_source_version_and_new_output_are_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "40-character"):
            oci.build_archive(self.rootfs, self.base / "bad.oci.tar", self.contract,
                              "g" * 40, self.tag, self.version, self.epoch)
        with self.assertRaisesRegex(ValueError, "version-matching"):
            oci.build_archive(self.rootfs, self.base / "bad.oci.tar", self.contract,
                              self.commit, "v1.0.1", self.version, self.epoch)
        path, _ = self.build("existing.oci.tar")
        before = path.read_bytes()
        with self.assertRaisesRegex(ValueError, "new OCI archive"):
            oci.build_archive(self.rootfs, path, self.contract, self.commit,
                              self.tag, self.version, self.epoch)
        self.assertEqual(path.read_bytes(), before)

    def test_contract_cannot_grant_release_authority(self):
        contract = copy.deepcopy(self.contract)
        contract["authority"]["publishable"] = True
        path = self.base / "contract.json"
        path.write_text(json.dumps(contract))
        with self.assertRaisesRegex(ValueError, "must not grant"):
            oci.load_contract(path)

    def test_noncanonical_index_and_unexpected_members_are_rejected(self):
        path, _ = self.build("changed.oci.tar")
        files = self.layout_files(path)
        index = json.loads(files["index.json"])
        files["index.json"] = json.dumps(index, indent=2).encode()
        self.rewrite_layout(path, files)
        with self.assertRaisesRegex(ValueError, "canonical single-manifest"):
            oci.verify_archive(path, self.contract, self.commit, self.tag,
                               self.version, self.epoch)
        path.unlink()
        path, _ = self.build("changed.oci.tar")
        files = self.layout_files(path)
        files["unexpected"] = b"not allowed"
        self.rewrite_layout(path, files)
        with self.assertRaisesRegex(ValueError, "unexpected OCI layout"):
            oci.verify_archive(path, self.contract, self.commit, self.tag,
                               self.version, self.epoch)

    def test_changed_blob_and_resealed_false_source_label_are_rejected(self):
        path, _ = self.build("mutated.oci.tar")
        files = self.layout_files(path)
        index = json.loads(files["index.json"])
        manifest_path = "blobs/sha256/" + index["manifests"][0]["digest"][7:]
        manifest = json.loads(files[manifest_path])
        layer_path = "blobs/sha256/" + manifest["layers"][0]["digest"][7:]
        changed = bytearray(files[layer_path])
        changed[-9] ^= 1
        files[layer_path] = bytes(changed)
        self.rewrite_layout(path, files)
        with self.assertRaisesRegex(ValueError, "descriptor byte identity"):
            oci.verify_archive(path, self.contract, self.commit, self.tag,
                               self.version, self.epoch)

        path.unlink()
        path, _ = self.build("mutated.oci.tar")
        files = self.layout_files(path)
        index = json.loads(files["index.json"])
        old_manifest_path = "blobs/sha256/" + index["manifests"][0]["digest"][7:]
        manifest = json.loads(files.pop(old_manifest_path))
        old_config_path = "blobs/sha256/" + manifest["config"]["digest"][7:]
        config = json.loads(files.pop(old_config_path))
        config["config"]["Labels"]["io.routesphere.bonvoyage.source-dirty"] = "true"
        config_bytes = oci.canonical_json(config)
        config_digest = hashlib.sha256(config_bytes).hexdigest()
        files["blobs/sha256/" + config_digest] = config_bytes
        manifest["config"]["digest"] = "sha256:" + config_digest
        manifest["config"]["size"] = len(config_bytes)
        manifest_bytes = oci.canonical_json(manifest)
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        files["blobs/sha256/" + manifest_digest] = manifest_bytes
        index["manifests"][0]["digest"] = "sha256:" + manifest_digest
        index["manifests"][0]["size"] = len(manifest_bytes)
        files["index.json"] = oci.canonical_json(index)
        self.rewrite_layout(path, files)
        with self.assertRaisesRegex(ValueError, "source or platform identity"):
            oci.verify_archive(path, self.contract, self.commit, self.tag,
                               self.version, self.epoch)

    def test_reproducibility_comparator_requires_distinct_builders(self):
        archive, result = self.build("candidate.oci.tar")
        directories = []
        for builder_id in ("builder-a", "builder-b"):
            directory = self.base / builder_id
            directory.mkdir()
            target = directory / "bonvoyage.oci.tar"
            target.write_bytes(archive.read_bytes())
            receipt = {
                **result,
                "classification": reproducibility.BUILD_CLASS,
                "outcome": "built-tested-technical-candidate",
                "builder_id": builder_id,
                "builder_image": "ghcr.io/routesphere-global/bonvoyage-oci-builder@sha256:" + "2" * 64,
                "archive": {**result["archive"], "path": target.name},
            }
            (directory / "oci-builder-execution.json").write_text(
                json.dumps(receipt, sort_keys=True) + "\n",
            )
            directories.append(directory)
        comparison = reproducibility.compare(*directories)
        self.assertTrue(comparison["technical_reproducibility_observed"])
        self.assertEqual(comparison["platform"], receipt["platform"])
        self.assertEqual(comparison["version"], receipt["version"])
        self.assertEqual(comparison["builder_image"], receipt["builder_image"])
        self.assertFalse(comparison["hosted_builder_independence_qualified"])
        self.assertFalse(comparison["publishable"])
        same = json.loads((directories[1] / "oci-builder-execution.json").read_text())
        same["builder_id"] = "builder-a"
        (directories[1] / "oci-builder-execution.json").write_text(json.dumps(same))
        with self.assertRaisesRegex(ValueError, "distinct OCI builder IDs"):
            reproducibility.compare(*directories)


if __name__ == "__main__":
    unittest.main()
