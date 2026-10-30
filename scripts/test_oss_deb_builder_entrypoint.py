"""Focused tests for the offline OSS Debian builder entrypoint."""

import importlib.util
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("oss-deb-builder-entrypoint.py")
SPEC = importlib.util.spec_from_file_location("bonvoyage_oss_deb_builder_entrypoint", SCRIPT)
ENTRYPOINT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENTRYPOINT)
IMAGE = "ghcr.io/routesphere-global/bonvoyage-debian-builder@sha256:" + "a" * 64


class OssDebBuilderEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    @staticmethod
    def git(root, *arguments):
        return subprocess.run(
            ["git", "-C", str(root), *arguments], check=True,
            capture_output=True, text=True, timeout=30,
        ).stdout.strip()

    def repository(self, license_file=True):
        source = self.root / "source"
        source.mkdir()
        self.git(source, "init", "-q")
        self.git(source, "config", "user.name", "BonVoyage Test")
        self.git(source, "config", "user.email", "test@routesphere.invalid")
        (source / "README.md").write_text("fixture\n", encoding="utf-8")
        if license_file:
            (source / "LICENSE").write_text("reviewed fixture license\n" * 8, encoding="utf-8")
        license_root = source / "packaging/release/licenses"
        license_root.mkdir(parents=True)
        (license_root / "THIRD_PARTY_NOTICES.md").write_text(
            "third-party notices\n" * 8, encoding="utf-8")
        (license_root / "THIRD_PARTY_SOURCE.md").write_text(
            "libjwt Mozilla Public License source\n" * 8, encoding="utf-8")
        otel = source / "third_party/opentelemetry-proto"
        otel.mkdir(parents=True)
        (otel / "LICENSE").write_text("OpenTelemetry fixture license\n" * 8, encoding="utf-8")
        self.git(source, "add", ".")
        self.git(source, "commit", "-q", "-m", "fixture")
        self.git(source, "tag", "v1.2.3-rc.1")
        self.git(source, "remote", "add", "origin", ENTRYPOINT.PUBLIC_REPOSITORY)
        return source, self.git(source, "rev-parse", "HEAD")

    def environment(self, commit="1" * 40, jobs="2"):
        return {
            "BONVOYAGE_SOURCE_COMMIT": commit,
            "BONVOYAGE_SOURCE_TAG": "v1.2.3-rc.1",
            "BONVOYAGE_BUILDER_IMAGE": IMAGE,
            "BONVOYAGE_BUILDER_ID": "fixture-builder-a",
            "BONVOYAGE_BUILD_JOBS": jobs,
        }

    def test_public_repository_and_release_identity_are_exact(self):
        self.assertEqual(
            ENTRYPOINT.normalized_repository("git@github.com:routesphere-global/bonvoyage.git"),
            ENTRYPOINT.PUBLIC_REPOSITORY,
        )
        self.assertIsNotNone(ENTRYPOINT.SEMVER_TAG.fullmatch("v1.2.3-rc.1"))
        self.assertIsNone(ENTRYPOINT.SEMVER_TAG.fullmatch("v01.2.3"))
        self.assertIsNone(ENTRYPOINT.BUILDER_IMAGE.fullmatch(
            "ghcr.io/routesphere-global/bonvoyage-debian-builder:latest"))

    def test_clean_tagged_public_source_identity_and_dirty_rejection(self):
        source, commit = self.repository()
        identity = ENTRYPOINT.source_identity(source, commit, "v1.2.3-rc.1")
        self.assertEqual(identity["commit"], commit)
        self.assertEqual(identity["repository"], ENTRYPOINT.PUBLIC_REPOSITORY)
        self.assertFalse(identity["dirty"])
        (source / "untracked").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "clean source"):
            ENTRYPOINT.source_identity(source, commit, "v1.2.3-rc.1")

    def test_git_trust_is_scoped_to_the_exact_source_directory(self):
        source, commit = self.repository()
        with mock.patch("subprocess.run", wraps=subprocess.run) as run:
            ENTRYPOINT.source_identity(source, commit, "v1.2.3-rc.1")
        git_commands = [call.args[0] for call in run.call_args_list]
        self.assertTrue(git_commands)
        for command in git_commands:
            self.assertEqual(command[:3], [
                "git", "-c", f"safe.directory={source}",
            ])
            self.assertNotIn("safe.directory=*", command)

    def test_wrong_commit_tag_and_origin_are_rejected(self):
        source, commit = self.repository()
        with self.assertRaisesRegex(ValueError, "commit"):
            ENTRYPOINT.source_identity(source, "0" * 40, "v1.2.3-rc.1")
        with self.assertRaises(subprocess.CalledProcessError):
            ENTRYPOINT.source_identity(source, commit, "v1.2.4")
        self.git(source, "remote", "set-url", "origin", "https://example.invalid/fork")
        with self.assertRaisesRegex(ValueError, "public repository"):
            ENTRYPOINT.source_identity(source, commit, "v1.2.3-rc.1")

    def test_work_and_output_boundaries_fail_closed(self):
        work = self.root / "work"
        output = self.root / "output"
        work.mkdir()
        output.mkdir()
        (output / "sentinel").write_text("keep\n", encoding="utf-8")
        with mock.patch.object(ENTRYPOINT, "WORK_ROOT", work), \
             mock.patch.object(ENTRYPOINT, "OUTPUT_ROOT", output), \
             mock.patch.object(ENTRYPOINT, "self_check"), \
             mock.patch.dict(os.environ, self.environment(), clear=True):
            with self.assertRaisesRegex(ValueError, "empty output"):
                ENTRYPOINT.build()
        self.assertEqual((output / "sentinel").read_text(encoding="utf-8"), "keep\n")

    def test_public_license_is_required_before_compilation(self):
        source, commit = self.repository(license_file=False)
        work = self.root / "work"
        output = self.root / "output"
        work.mkdir()
        output.mkdir()
        with mock.patch.object(ENTRYPOINT, "SOURCE_ROOT", source), \
             mock.patch.object(ENTRYPOINT, "WORK_ROOT", work), \
             mock.patch.object(ENTRYPOINT, "OUTPUT_ROOT", output), \
             mock.patch.object(ENTRYPOINT, "self_check"), \
             mock.patch.dict(os.environ, self.environment(commit), clear=True):
            with self.assertRaisesRegex(ValueError, "LICENSE"):
                ENTRYPOINT.build()
        self.assertFalse(any(output.iterdir()))

    def test_parallelism_is_bounded(self):
        for value in ("0", "9", "many"):
            with self.subTest(value=value), \
                 mock.patch.object(ENTRYPOINT, "self_check"), \
                 mock.patch.dict(os.environ, self.environment(jobs=value), clear=True):
                with self.assertRaisesRegex(ValueError, "1 through 8"):
                    ENTRYPOINT.build()

    def test_release_version_is_bound_into_the_compiled_dataplane(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('f"-DBONVOYAGE_RELEASE_VERSION={version}"', source)

    def test_runtime_identity_requires_the_exact_release_version(self):
        binary = self.root / "bonvoyage-dataplane"
        binary.write_bytes(b"fixture")
        binary.chmod(0o700)
        accepted = subprocess.CompletedProcess(
            [], 0,
            stdout=("RouteSphere BonVoyage dataplane 0.2.0 "
                    "release=1.2.3-rc.1 upstream-http1-client=seastar-reference\n"),
            stderr="bounded warning\n",
        )
        with mock.patch.object(ENTRYPOINT.subprocess, "run", return_value=accepted):
            identity = ENTRYPOINT.runtime_identity(binary, "1.2.3-rc.1", {"PATH": "/bin"})
        self.assertEqual(identity["dataplane_version"], "0.2.0")
        self.assertEqual(identity["release_version"], "1.2.3-rc.1")
        self.assertEqual(identity["upstream_http1_client"], "seastar-reference")

        stale = subprocess.CompletedProcess(
            [], 0,
            stdout=("RouteSphere BonVoyage dataplane 0.2.0 "
                    "release=0.2.0 upstream-http1-client=seastar-reference\n"),
            stderr="",
        )
        with mock.patch.object(ENTRYPOINT.subprocess, "run", return_value=stale), \
                self.assertRaisesRegex(ValueError, "release identity"):
            ENTRYPOINT.runtime_identity(binary, "1.2.3-rc.1", {"PATH": "/bin"})

    def test_failure_log_is_tail_bounded(self):
        source = self.root / "source.log"
        destination = self.root / "failure.log"
        source.write_bytes(b"a" * 200)
        ENTRYPOINT.bounded_log(source, destination, maximum=64)
        data = destination.read_bytes()
        self.assertTrue(data.startswith(b"[earlier output omitted]"))
        self.assertLessEqual(len(data), 96)

    def test_dependency_license_bundle_is_deterministic_and_complete(self):
        source, _ = self.repository()
        installed = []
        for name in ("seastar", "libjwt"):
            path = self.root / f"{name}.LICENSE"
            path.write_text(f"{name} fixture license\n" * 8, encoding="utf-8")
            installed.append((name, path))
        with mock.patch.object(ENTRYPOINT, "INSTALLED_LICENSES", tuple(installed)):
            first = ENTRYPOINT.third_party_license_bundle(source)
            second = ENTRYPOINT.third_party_license_bundle(source)
        self.assertEqual(first, second)
        text = first.decode("utf-8")
        for name in ("libjwt", "opentelemetry-proto", "seastar"):
            self.assertIn(name, text)

    def test_builder_image_preserves_seastar_license_before_source_cleanup(self):
        dockerfile = Path(__file__).resolve().parent.parent / "deploy/docker/bonvoyage/Dockerfile"
        stage = dockerfile.read_text().split(
            "FROM seastar-build AS oss-deb-builder", 1)[1].split("\nFROM ", 1)[0]
        preserve = "install -D -m 0644 /usr/src/seastar/LICENSE"
        cleanup = "rm -rf /usr/src/seastar"
        self.assertIn(preserve, stage)
        self.assertLess(stage.index(preserve), stage.index(cleanup))


if __name__ == "__main__":
    unittest.main()
