"""Focused tests for the source-free offline OSS OCI builder entrypoint."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


def load_module(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


entrypoint = load_module(
    "bonvoyage_oss_oci_builder_entrypoint_test", "oss-oci-builder-entrypoint.py",
)


class OssOciBuilderEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", self.source], check=True)
        subprocess.run([
            "git", "-C", self.source, "config", "user.email", "test@example.invalid",
        ], check=True)
        subprocess.run(["git", "-C", self.source, "config", "user.name", "Test"], check=True)
        (self.source / "README.md").write_text("fixture\n")
        subprocess.run(["git", "-C", self.source, "add", "README.md"], check=True)
        environment = dict(os.environ, GIT_AUTHOR_DATE="1700000000 +0000",
                           GIT_COMMITTER_DATE="1700000000 +0000")
        subprocess.run(["git", "-C", self.source, "commit", "-qm", "fixture"],
                       check=True, env=environment)
        self.commit = subprocess.check_output(
            ["git", "-C", self.source, "rev-parse", "HEAD"], text=True,
        ).strip()
        subprocess.run(["git", "-C", self.source, "tag", "v1.0.0-rc.1"], check=True)
        subprocess.run([
            "git", "-C", self.source, "remote", "add", "origin",
            "git@github.com:routesphere-global/bonvoyage.git",
        ], check=True)

    def test_clean_exact_public_source_identity(self):
        identity = entrypoint.source_identity(
            self.source, self.commit, "v1.0.0-rc.1",
        )
        self.assertEqual(identity["repository"], entrypoint.PUBLIC_REPOSITORY)
        self.assertEqual(identity["commit"], self.commit)
        self.assertFalse(identity["dirty"])
        self.assertEqual(identity["source_date_epoch"], 1700000000)

    def test_dirty_wrong_origin_commit_and_tag_are_rejected(self):
        (self.source / "dirty").write_text("changed")
        with self.assertRaisesRegex(ValueError, "clean source"):
            entrypoint.source_identity(self.source, self.commit, "v1.0.0-rc.1")
        (self.source / "dirty").unlink()
        with self.assertRaisesRegex(ValueError, "commit does not match"):
            entrypoint.source_identity(self.source, "0" * 40, "v1.0.0-rc.1")
        with self.assertRaises(subprocess.CalledProcessError):
            entrypoint.source_identity(self.source, self.commit, "v1.0.1")
        subprocess.run([
            "git", "-C", self.source, "remote", "set-url", "origin",
            "https://example.invalid/bonvoyage",
        ], check=True)
        with self.assertRaisesRegex(ValueError, "public repository"):
            entrypoint.source_identity(self.source, self.commit, "v1.0.0-rc.1")

    def test_runtime_library_parser_is_bounded_and_rejects_shared_cares(self):
        binary = self.root / "bonvoyage"
        binary.write_bytes(b"binary")
        completed = mock.Mock(stdout=(
            "linux-vdso.so.1 (0x0000)\n"
            "libssl.so.3 => /lib/x86_64-linux-gnu/libssl.so.3 (0x0000)\n"
            "/lib64/ld-linux-x86-64.so.2 (0x0000)\n"
        ))
        with mock.patch.object(entrypoint.subprocess, "run", return_value=completed):
            self.assertEqual(entrypoint.runtime_libraries(binary), [
                "/lib/x86_64-linux-gnu/libssl.so.3",
                "/lib64/ld-linux-x86-64.so.2",
            ])
        completed.stdout += "libcares.so.2 => /lib/libcares.so.2 (0x0000)\n"
        with mock.patch.object(entrypoint.subprocess, "run", return_value=completed), \
                self.assertRaisesRegex(ValueError, "shared c-ares"):
            entrypoint.runtime_libraries(binary)
        completed.stdout = "libssl.so.3 => not found\n"
        with mock.patch.object(entrypoint.subprocess, "run", return_value=completed), \
                self.assertRaisesRegex(ValueError, "unresolved"):
            entrypoint.runtime_libraries(binary)

    def test_builder_image_reference_is_exact_and_digest_pinned(self):
        valid = "ghcr.io/routesphere-global/bonvoyage-oci-builder@sha256:" + "1" * 64
        with mock.patch.dict(os.environ, {"BONVOYAGE_BUILDER_IMAGE": valid}):
            self.assertEqual(entrypoint.environment_value(
                "BONVOYAGE_BUILDER_IMAGE", entrypoint.BUILDER_IMAGE,
            ), valid)
        for value in (
            "ghcr.io/routesphere-global/bonvoyage-oci-builder:latest",
            "ghcr.io/routesphere/other@sha256:" + "1" * 64,
            "bonvoyage-oci-builder@sha256:" + "1" * 64,
        ):
            self.assertIsNone(entrypoint.BUILDER_IMAGE.fullmatch(value))
            with mock.patch.dict(os.environ, {"BONVOYAGE_BUILDER_IMAGE": value}):
                with self.assertRaisesRegex(ValueError, "invalid or missing"):
                    entrypoint.environment_value(
                        "BONVOYAGE_BUILDER_IMAGE", entrypoint.BUILDER_IMAGE,
                    )

    def test_docker_target_is_source_free_and_non_authoritative(self):
        dockerfile = Path(__file__).resolve().parent.parent / "deploy/docker/bonvoyage/Dockerfile"
        text = dockerfile.read_text()
        self.assertIn("FROM oss-deb-builder AS oss-oci-builder", text)
        stage = text.split("FROM oss-deb-builder AS oss-oci-builder", 1)[1].split("\nFROM ", 1)[0]
        self.assertNotIn("COPY dataplane/", stage)
        self.assertNotIn("COPY api/", stage)
        self.assertNotIn("bonvoyage-build", stage)
        self.assertIn('io.routesphere.bonvoyage.role="oss-oci-builder"', stage)
        self.assertIn('io.routesphere.bonvoyage.release-authority="false"', stage)
        self.assertIn("USER 65532:65532", stage)
        self.assertIn('ENTRYPOINT ["/usr/local/bin/bonvoyage-oss-oci-builder"]', stage)

    def test_contract_and_entrypoint_never_authorize_release(self):
        contract = json.loads((
            Path(__file__).resolve().parent.parent /
            "packaging/release/oci/oss-oci-image-contract.json"
        ).read_text())
        self.assertIn(
            "usr/share/bonvoyage/THIRD_PARTY_SOURCE.md",
            contract["rootfs"]["required_files"],
        )
        self.assertEqual(contract["authority"], {
            "release_admitted": False, "publishable": False,
        })
        source = Path(__file__).with_name("oss-oci-builder-entrypoint.py").read_text()
        self.assertIn('"release_admitted": False', source)
        self.assertIn('"publishable": False', source)


if __name__ == "__main__":
    unittest.main()
