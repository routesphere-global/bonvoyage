"""Focused tests for public Debian input, assembly and reproducibility contracts."""

import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


def load_module(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


builder = load_module("bonvoyage_oss_deb_builder_test", "build-oss-deb.py")
input_creator = load_module("bonvoyage_oss_deb_input_test", "create-oss-deb-input.py")
reproducibility = load_module(
    "bonvoyage_oss_deb_reproducibility_test", "verify-oss-deb-reproducibility.py",
)


class OssDebBuilderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.manifest = self.inputs / "inputs.json"

        elf = bytearray(128)
        elf[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", elf, 16, 3, 62)
        struct.pack_into("<Q", elf, 24, 4096)
        (self.inputs / "bonvoyage-dataplane").write_bytes(elf)
        (self.inputs / "LICENSE").write_text(
            "Copyright 2026 RouteSphere project authors.\n"
            "Test-only license fixture with no publication or redistribution authority.\n",
            encoding="utf-8",
        )
        (self.inputs / "THIRD_PARTY_NOTICES.md").write_text(
            "# Third-party notices\n\nlibjwt is distributed under MPL-2.0.\n" + "n" * 80,
            encoding="utf-8",
        )
        (self.inputs / "THIRD_PARTY_SOURCE.md").write_text(
            "# Third-party source availability\n\nlibjwt source is available under the "
            "Mozilla Public License 2.0.\n" + "s" * 80,
            encoding="utf-8",
        )
        (self.inputs / "THIRD_PARTY_LICENSES.txt").write_text(
            "Bundled licenses\n\nlibjwt\nMozilla Public License Version 2.0\n" + "l" * 80,
            encoding="utf-8",
        )
        self.toolchain = self.valid_toolchain()
        (self.inputs / "toolchain.json").write_text(
            json.dumps(self.toolchain, sort_keys=True) + "\n", encoding="utf-8",
        )
        self.document = {
            "schema_version": 1,
            "classification": builder.INPUT_CLASS,
            "product": builder.PRODUCT,
            "source_repository": builder.PUBLIC_REPOSITORY,
            "source_commit": "1" * 40,
            "source_tag": "v1.0.0-rc.1",
            "release_version": "1.0.0-rc.1",
            "package_revision": 1,
            "distribution": "ubuntu-24.04",
            "architecture": "amd64",
            "maintainer": "RouteSphere Release <release@routesphere.global>",
            "source_date_epoch": 1700000000,
            "files": {
                "dataplane": self.record("bonvoyage-dataplane"),
                "copyright": self.record("LICENSE"),
                "third_party_notices": self.record("THIRD_PARTY_NOTICES.md"),
                "third_party_source": self.record("THIRD_PARTY_SOURCE.md"),
                "third_party_licenses": self.record("THIRD_PARTY_LICENSES.txt"),
                "toolchain_lock": self.record("toolchain.json"),
            },
        }
        self.seal()

    @staticmethod
    def valid_toolchain():
        tools = []
        for name in sorted(builder.REQUIRED_TOOLS):
            tools.append({"name": name, "path": "/usr/bin/" + name,
                          "resolved_path": "/usr/bin/" + name, "bytes": 100,
                          "sha256": "2" * 64})
        return {
            "schema_version": 1,
            "classification": builder.TOOLCHAIN_CLASS,
            "distribution": "ubuntu-24.04",
            "architecture": "amd64",
            "builder_image": "ghcr.io/routesphere-global/bonvoyage-deb-builder@sha256:" + "3" * 64,
            "os_release": {"path": "/etc/os-release", "bytes": 100, "sha256": "4" * 64},
            "packages": [{"name": "debhelper", "version": "13.14.1ubuntu5"}],
            "tools": tools,
        }

    def record(self, name):
        data = (self.inputs / name).read_bytes()
        return {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def seal(self):
        self.manifest.write_text(json.dumps(self.document), encoding="utf-8")
        self.anchor = hashlib.sha256(self.manifest.read_bytes()).hexdigest()

    def load(self):
        return builder.load_inputs(self.manifest, self.anchor)

    def test_valid_explicit_input_and_debian_version(self):
        specification, payload = self.load()
        self.assertEqual(specification["debian_version"], "1.0.0~rc.1-1")
        self.assertEqual(payload["toolchain_lock"], self.toolchain)
        self.assertEqual(builder.semver_to_debian("1.2.3", 4), "1.2.3-4")

    def test_semver_rejects_build_metadata_and_malformed_versions(self):
        for value in ["1.0", "01.0.0", "1.0.0+build", "v1.0.0", "1.0.0-", "1.0.0-01"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                builder.semver_to_debian(value, 1)
        for revision in [True, 0, 10000]:
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                builder.semver_to_debian("1.0.0", revision)

    def test_manifest_digest_duplicate_keys_and_unknown_fields(self):
        with self.assertRaisesRegex(ValueError, "manifest digest"):
            builder.load_inputs(self.manifest, "0" * 64)
        self.manifest.write_text(self.manifest.read_text().replace(
            '"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1,
        ))
        self.anchor = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            self.load()
        self.document["publishable"] = True
        self.seal()
        with self.assertRaisesRegex(ValueError, "manifest fields"):
            self.load()

    def test_identity_and_platform_fields_are_fail_closed(self):
        original = copy.deepcopy(self.document)
        mutations = [
            ("classification", "private-native-gateway-input"),
            ("product", "Other"),
            ("source_repository", "https://example.invalid/repository"),
            ("source_commit", "g" * 40),
            ("source_tag", "v1.0.1"),
            ("release_version", "1.0.0+unsigned"),
            ("package_revision", True),
            ("distribution", "ubuntu-26.04"),
            ("architecture", "arm64"),
            ("maintainer", "Injected\nField: value"),
            ("source_date_epoch", True),
        ]
        for field, value in mutations:
            with self.subTest(field=field):
                self.document = copy.deepcopy(original)
                self.document[field] = value
                self.seal()
                with self.assertRaises(ValueError):
                    self.load()

    def test_unsafe_paths_symlinks_and_changed_bytes_are_rejected(self):
        original = copy.deepcopy(self.document)
        for value in ["/etc/passwd", "../LICENSE", "./LICENSE", "a/../LICENSE", "a//LICENSE"]:
            with self.subTest(path=value):
                self.document = copy.deepcopy(original)
                self.document["files"]["copyright"]["path"] = value
                self.seal()
                with self.assertRaises(ValueError):
                    self.load()
        link = self.inputs / "license-link"
        link.symlink_to("LICENSE")
        self.document = copy.deepcopy(original)
        self.document["files"]["copyright"]["path"] = "license-link"
        self.seal()
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.load()
        self.document = copy.deepcopy(original)
        self.document["files"]["copyright"]["sha256"] = "0" * 64
        self.seal()
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.load()

    def test_elf_and_license_are_validated(self):
        original_elf = (self.inputs / "bonvoyage-dataplane").read_bytes()
        bad = bytearray(original_elf)
        bad[18] = 183
        (self.inputs / "bonvoyage-dataplane").write_bytes(bad)
        self.document["files"]["dataplane"] = self.record("bonvoyage-dataplane")
        self.seal()
        with self.assertRaisesRegex(ValueError, "AMD64"):
            self.load()
        (self.inputs / "bonvoyage-dataplane").write_bytes(original_elf)
        self.document["files"]["dataplane"] = self.record("bonvoyage-dataplane")
        (self.inputs / "LICENSE").write_text("placeholder\n", encoding="utf-8")
        self.document["files"]["copyright"] = self.record("LICENSE")
        self.seal()
        with self.assertRaisesRegex(ValueError, "substantive"):
            self.load()

    def test_toolchain_lock_schema_is_exact_sorted_and_digest_pinned(self):
        original = copy.deepcopy(self.toolchain)
        mutations = []
        changed = copy.deepcopy(original)
        changed["builder_image"] = "ghcr.io/routesphere/builder:latest"
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["packages"].append({"name": "apt", "version": "2"})
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["tools"] = list(reversed(changed["tools"]))
        mutations.append(changed)
        changed = copy.deepcopy(original)
        changed["publishable"] = True
        mutations.append(changed)
        for document in mutations:
            with self.subTest(document=document):
                with self.assertRaises(ValueError):
                    builder.load_toolchain_document(json.dumps(document).encode("utf-8"))

    def test_host_toolchain_requires_exact_observation(self):
        expected = {key: self.toolchain[key] for key in (
            "distribution", "architecture", "os_release", "packages", "tools",
        )}
        with mock.patch.object(builder, "observe_toolchain", return_value=copy.deepcopy(expected)):
            self.assertEqual(builder.verify_host_toolchain(self.toolchain), expected)
        changed = copy.deepcopy(expected)
        changed["packages"][0]["version"] = "different"
        with mock.patch.object(builder, "observe_toolchain", return_value=changed):
            with self.assertRaisesRegex(ValueError, "immutable toolchain"):
                builder.verify_host_toolchain(self.toolchain)

    def test_prepare_tree_uses_public_notice_and_preserves_inputs(self):
        output = self.root / "output"
        specification, _, binding, unit, readme, changelog = builder.prepare_tree(
            self.manifest, self.anchor, output,
        )
        self.assertEqual(specification["debian_version"], "1.0.0~rc.1-1")
        self.assertEqual((output / "work/input/bonvoyage-dataplane").read_bytes(),
                         (self.inputs / "bonvoyage-dataplane").read_bytes())
        self.assertIn(b"ExecStart=/usr/bin/bonvoyage-dataplane", unit)
        self.assertIn(b"Documentation=https://docs.routesphere.global/", unit)
        self.assertNotIn(b"docs.routesphere.io", unit)
        self.assertIn(b"technical candidate", readme)
        self.assertNotIn(b"Private rehearsal", readme)
        self.assertIn(b"OSS technical candidate", changelog)
        self.assertEqual(binding["input_manifest_sha256"], self.anchor)
        self.assertEqual((output / "toolchain-lock.json").read_bytes(),
                         (self.inputs / "toolchain.json").read_bytes())
        self.assertEqual((output / "work/input/THIRD_PARTY_SOURCE.md").read_bytes(),
                         (self.inputs / "THIRD_PARTY_SOURCE.md").read_bytes())

    def test_prepare_never_overwrites_or_writes_inside_source(self):
        output = self.root / "output"
        output.mkdir()
        (output / "sentinel").write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "new output"):
            builder.prepare_tree(self.manifest, self.anchor, output)
        self.assertEqual((output / "sentinel").read_text(), "keep")
        inside = builder.ROOT / ".test-oss-deb-output"
        self.addCleanup(lambda: shutil.rmtree(inside, ignore_errors=True))
        with self.assertRaisesRegex(ValueError, "outside"):
            builder.prepare_tree(self.manifest, self.anchor, inside)

    def git(self, repository, *arguments, environment=None):
        return subprocess.run(
            ["git", "-C", str(repository), *arguments], check=True, capture_output=True,
            text=True, env=environment,
        ).stdout.strip()

    def source_repository(self):
        repository = self.root / "source"
        repository.mkdir()
        self.git(repository, "init", "-b", "main")
        self.git(repository, "config", "user.name", "Release Test")
        self.git(repository, "config", "user.email", "release@example.invalid")
        self.git(repository, "remote", "add", "origin", builder.PUBLIC_REPOSITORY + ".git")
        (repository / "tracked").write_text("source\n", encoding="utf-8")
        self.git(repository, "add", "tracked")
        environment = {**os.environ, "GIT_AUTHOR_DATE": "@1700000000 +0000",
                       "GIT_COMMITTER_DATE": "@1700000000 +0000"}
        self.git(repository, "commit", "-m", "release fixture", environment=environment)
        commit = self.git(repository, "rev-parse", "HEAD")
        self.git(repository, "tag", "v1.0.0-rc.1")
        specification = copy.deepcopy(self.document)
        specification["source_commit"] = commit
        return repository, specification

    def test_source_state_binds_clean_commit_tag_remote_and_epoch(self):
        repository, specification = self.source_repository()
        state = builder.source_state(specification, repository)
        self.assertEqual(state["commit"], specification["source_commit"])
        self.assertFalse(state["dirty"])
        (repository / "tracked").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "clean source"):
            builder.source_state(specification, repository)

    def test_source_state_rejects_wrong_remote_tag_commit_or_epoch(self):
        repository, specification = self.source_repository()
        mutations = [
            ("source_commit", "0" * 40),
            ("source_tag", "v1.0.1"),
            ("source_date_epoch", 1700000001),
        ]
        for field, value in mutations:
            with self.subTest(field=field):
                changed = copy.deepcopy(specification)
                changed[field] = value
                with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                    builder.source_state(changed, repository)
        self.git(repository, "remote", "set-url", "origin", "https://example.invalid/repository.git")
        with self.assertRaisesRegex(ValueError, "public repository"):
            builder.source_state(specification, repository)

    def test_input_creator_binds_clean_source_and_reviewed_files(self):
        repository, specification = self.source_repository()
        output = self.inputs / "generated-input.json"
        document, manifest_digest = input_creator.create(
            repository, "1.0.0-rc.1", 1,
            "RouteSphere Release <release@routesphere.global>",
            self.inputs / "bonvoyage-dataplane", self.inputs / "LICENSE",
            self.inputs / "THIRD_PARTY_NOTICES.md",
            self.inputs / "THIRD_PARTY_SOURCE.md",
            self.inputs / "THIRD_PARTY_LICENSES.txt",
            self.inputs / "toolchain.json", output,
        )
        self.assertEqual(document["source_commit"], specification["source_commit"])
        self.assertEqual(manifest_digest, hashlib.sha256(output.read_bytes()).hexdigest())
        loaded, _ = builder.load_inputs(output, manifest_digest)
        self.assertEqual(loaded["debian_version"], "1.0.0~rc.1-1")

    def test_input_creator_rejects_artifacts_outside_manifest_directory(self):
        repository, _ = self.source_repository()
        outside = self.root / "outside-license"
        outside.write_text("x" * 100, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "inside the manifest"):
            input_creator.create(
                repository, "1.0.0-rc.1", 1,
                "RouteSphere Release <release@routesphere.global>",
                self.inputs / "bonvoyage-dataplane", outside,
                self.inputs / "THIRD_PARTY_NOTICES.md",
                self.inputs / "THIRD_PARTY_SOURCE.md",
                self.inputs / "THIRD_PARTY_LICENSES.txt",
                self.inputs / "toolchain.json", self.inputs / "generated-input.json",
            )

    def data_tar(self, specification, unit, readme, changelog, extra=None, bad_mode=False):
        files = {
            "usr/bin/bonvoyage-dataplane": (self.inputs / "bonvoyage-dataplane").read_bytes(),
            "usr/lib/systemd/system/bonvoyage.service": unit,
            "usr/share/doc/bonvoyage-gateway/copyright": (self.inputs / "LICENSE").read_bytes(),
            "usr/share/doc/bonvoyage-gateway/THIRD_PARTY_NOTICES.md":
                (self.inputs / "THIRD_PARTY_NOTICES.md").read_bytes(),
            "usr/share/doc/bonvoyage-gateway/THIRD_PARTY_SOURCE.md":
                (self.inputs / "THIRD_PARTY_SOURCE.md").read_bytes(),
            "usr/share/doc/bonvoyage-gateway/THIRD_PARTY_LICENSES.txt":
                (self.inputs / "THIRD_PARTY_LICENSES.txt").read_bytes(),
            "usr/share/doc/bonvoyage-gateway/README.Debian": readme,
            "usr/share/doc/bonvoyage-gateway/changelog.Debian.gz": gzip.compress(changelog, mtime=0),
        }
        if extra:
            files[extra] = b"unexpected"
        directories = ["usr", "usr/bin", "usr/lib", "usr/lib/systemd", "usr/lib/systemd/system",
                       "usr/share", "usr/share/doc", "usr/share/doc/bonvoyage-gateway"]
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            root = tarfile.TarInfo(".")
            root.type, root.mode, root.uid, root.gid = tarfile.DIRTYPE, 0o755, 0, 0
            archive.addfile(root)
            for name in directories:
                member = tarfile.TarInfo("./" + name)
                member.type, member.mode, member.uid, member.gid = tarfile.DIRTYPE, 0o755, 0, 0
                archive.addfile(member)
            for name, data in files.items():
                member = tarfile.TarInfo("./" + name)
                member.size, member.uid, member.gid = len(data), 0, 0
                member.mode = 0o755 if name == "usr/bin/bonvoyage-dataplane" else 0o644
                if bad_mode and name == "usr/bin/bonvoyage-dataplane":
                    member.mode = 0o4755
                archive.addfile(member, io.BytesIO(data))
        return output.getvalue()

    def test_payload_inventory_is_exact_root_owned_and_content_bound(self):
        specification, _ = self.load()
        unit = builder.render_service()
        readme = (builder.ROOT / "packaging/release/debian/README.Debian").read_bytes()
        changelog = builder.expected_changelog(specification)
        verified = builder.verify_payload_tar(
            self.data_tar(specification, unit, readme, changelog),
            specification, unit, readme, changelog,
        )
        self.assertEqual(len(verified), 8)
        with self.assertRaises(ValueError):
            builder.verify_payload_tar(
                self.data_tar(specification, unit, readme, changelog, extra="etc/secret"),
                specification, unit, readme, changelog,
            )
        with self.assertRaisesRegex(ValueError, "mode"):
            builder.verify_payload_tar(
                self.data_tar(specification, unit, readme, changelog, bad_mode=True),
                specification, unit, readme, changelog,
            )

    @staticmethod
    def control_tar(forbidden=False, preserved_enable=False):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            root = tarfile.TarInfo(".")
            root.type, root.mode, root.uid, root.gid = tarfile.DIRTYPE, 0o755, 0, 0
            archive.addfile(root)
            for name in ["control", "md5sums", "preinst", "postinst", "postrm"]:
                body = b"Package: bonvoyage-gateway\n" if name == "control" else b"hash  path\n"
                if name in {"preinst", "postinst", "prerm", "postrm"}:
                    body = b"#!/bin/sh\nexit 0\n"
                if forbidden and name == "postinst":
                    body = b"#!/bin/sh\nsystemctl start bonvoyage.service\n"
                if preserved_enable and name == "postinst":
                    body = (
                        b"#!/bin/sh\n"
                        b"if deb-systemd-helper debian-installed 'bonvoyage.service'; then\n"
                        b"  if deb-systemd-helper --quiet was-enabled 'bonvoyage.service'; then\n"
                        b"    deb-systemd-helper enable 'bonvoyage.service'\n"
                        b"  fi\n"
                        b"fi\n"
                    )
                member = tarfile.TarInfo("./" + name)
                member.size, member.uid, member.gid = len(body), 0, 0
                member.mode = 0o755 if name in {"preinst", "postinst", "prerm", "postrm"} else 0o644
                archive.addfile(member, io.BytesIO(body))
        return output.getvalue()

    def test_control_inventory_and_no_automatic_start_policy(self):
        self.assertEqual(len(builder.verify_control_tar(self.control_tar())), 5)
        self.assertEqual(len(builder.verify_control_tar(self.control_tar(preserved_enable=True))), 5)
        with self.assertRaisesRegex(ValueError, "host mutation"):
            builder.verify_control_tar(self.control_tar(forbidden=True))
        with self.assertRaisesRegex(ValueError, "unbounded service-enable"):
            builder.verify_maintainer_script(
                "postinst", b"#!/bin/sh\ndeb-systemd-helper enable 'bonvoyage.service'\n",
            )

    def test_builder_receipt_cannot_grant_release_authority(self):
        specification, _ = self.load()
        receipt = builder.receipt_template(
            specification, {"commit": "1" * 40}, {"input_manifest_sha256": self.anchor}, "test-a",
        )
        self.assertEqual(receipt["outcome"], "building")
        for gate in ("reproducibility_qualified", "sbom_qualified", "scan_qualified",
                     "signature_qualified", "provenance_qualified", "lifecycle_qualified",
                     "release_admitted", "publishable"):
            self.assertIs(receipt[gate], False)

    def reproducible_directory(self, name, builder_id, data=b"deb-bytes"):
        directory = self.root / name
        directory.mkdir()
        package_name = "bonvoyage-gateway_1.0.0-1_amd64.deb"
        (directory / package_name).write_bytes(data)
        package = {"path": package_name, "bytes": len(data),
                   "sha256": hashlib.sha256(data).hexdigest(), "version": "1.0.0-1",
                   "architecture": "amd64"}
        receipt = {
            "schema_version": 1,
            "classification": builder.BUILD_CLASS,
            "outcome": "built-technical-candidate",
            "builder_id": builder_id,
            "source": {"repository": builder.PUBLIC_REPOSITORY, "commit": "1" * 40,
                       "dirty": False},
            "binding": {"input_manifest_sha256": "2" * 64},
            "distribution": "ubuntu-24.04",
            "architecture": "amd64",
            "release_version": "1.0.0",
            "debian_version": "1.0.0-1",
            "command": ["dpkg-buildpackage", "-us", "-uc", "-b"],
            "exit_code": 0,
            "payload": {"file": {"sha256": "3" * 64}},
            "control": {"control": {"sha256": "4" * 64}},
            "package": package,
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
        (directory / "build-receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        return directory

    def test_reproducibility_comparator_requires_exact_bytes_and_distinct_builders(self):
        first = self.reproducible_directory("first", "local-a")
        second = self.reproducible_directory("second", "local-b")
        result = reproducibility.compare(first, second)
        self.assertTrue(result["technical_reproducibility_observed"])
        self.assertFalse(result["hosted_builder_independence_qualified"])
        self.assertFalse(result["publishable"])
        third = self.reproducible_directory("third", "local-c", b"changed")
        with self.assertRaises(ValueError):
            reproducibility.compare(first, third)
        fourth = self.reproducible_directory("fourth", "local-a")
        with self.assertRaisesRegex(ValueError, "distinct builder IDs"):
            reproducibility.compare(first, fourth)

    def test_machine_readable_schemas_are_strict_and_parseable(self):
        for name in ("oss-deb-input.schema.json", "oss-deb-toolchain.schema.json"):
            document = json.loads((builder.ROOT / "packaging/release/debian" / name).read_text())
            self.assertFalse(document["additionalProperties"])
            self.assertEqual(document["type"], "object")


if __name__ == "__main__":
    unittest.main(verbosity=2)
