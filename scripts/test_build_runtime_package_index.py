#!/usr/bin/env python3
"""Synthetic ownership tests. Actual dpkg/Syft acceptance is separate."""
import importlib.util
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("runtime_index", Path(__file__).with_name("build-runtime-package-index.py"))
index = importlib.util.module_from_spec(spec)
spec.loader.exec_module(index)
spec = importlib.util.spec_from_file_location("overlap", Path(__file__).with_name("verify-runtime-package-overlap.py"))
overlap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(overlap)


class RuntimeIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.root = base / "root"
        self.root.mkdir()
        self.source = base / "builder/libsample.so"
        self.source.parent.mkdir()
        self.source.write_bytes(b"synthetic shared library")
        self.alias = base / "alias.so"
        self.alias.symlink_to(self.source)
        self.copied = self.root / self.alias.relative_to("/")
        self.copied.parent.mkdir(parents=True)
        self.copied.write_bytes(self.source.read_bytes())
        self.libraries = base / "libraries.txt"
        self.libraries.write_text(f"{self.alias}\n")
        self.owner = "libsample1:amd64"
        self.record = "libsample1\tamd64\t1.2-3ubuntu1\tsample\t1.2-3ubuntu1\tinstall ok installed"
        self.checksums = base / "package.md5sums"
        self.checksums.write_text(f'{index.digest(self.source, "md5")}  {str(self.source).lstrip("/")}\n')
        self.calls = []

    def query(self, *args):
        self.calls.append(args)
        if args[0] == "--control-path":
            self.assertEqual(args, ("--control-path", self.owner, "md5sums"))
            return str(self.checksums)
        if args[0] == "-S":
            self.assertEqual(args[1], str(self.source))
            return f"{self.owner}: {self.source}"
        self.assertEqual(args[0], "-W")
        self.assertEqual(args[-1], self.owner)
        return self.record

    def run_index(self):
        return index.build_index(self.root, self.libraries, self.query)

    def test_copied_alias_ownership_and_source_identity(self):
        packages = self.run_index()
        info = self.root / "var/lib/dpkg/info/libsample1:amd64.list"
        self.assertEqual(info.read_text(), f"{self.alias}\n")
        status = (self.root / "var/lib/dpkg/status").read_text()
        self.assertIn("Source: sample (1.2-3ubuntu1)\n", status)
        self.assertIn("Package: libsample1\n", status)
        manifest = json.loads((self.root / "usr/share/bonvoyage/runtime-package-ownership.json").read_text())
        self.assertEqual(manifest["packages"], packages)
        self.assertEqual(packages[self.owner]["files"], [{"path": str(self.alias),
            "build_path": str(self.source), "sha256": index.digest(self.source),
            "package_md5": index.digest(self.source, "md5")}])
        self.assertEqual(info.with_suffix(".md5sums").read_text(),
                         f'{index.digest(self.source, "md5")}  {str(self.alias).lstrip("/")}\n')
        self.assertEqual(len(self.calls), 3)

    def test_existing_index_is_not_overwritten(self):
        self.run_index()
        status = self.root / "var/lib/dpkg/status"
        before = status.read_bytes()
        with self.assertRaisesRegex(ValueError, "must be new"):
            self.run_index()
        self.assertEqual(status.read_bytes(), before)

    def test_invalid_inputs_fail_before_index_creation(self):
        mutations = [
            ("mismatched bytes", lambda: self.copied.write_bytes(b"different")),
            ("missing copy", lambda: self.copied.unlink()),
            ("copied symlink", lambda: (self.copied.unlink(), self.copied.symlink_to(self.source))),
            ("duplicate path", lambda: self.libraries.write_text(f"{self.alias}\n{self.alias}\n")),
            ("empty closure", lambda: self.libraries.write_text("")),
            ("missing original checksum", lambda: self.checksums.write_text("")),
            ("changed original checksum", lambda: self.checksums.write_text(f'{"0" * 32}  {str(self.source).lstrip("/")}\n')),
            ("relative path", lambda: self.libraries.write_text("relative.so\n")),
            ("traversal", lambda: self.libraries.write_text("/lib/../escape.so\n")),
            ("ambiguous owner", lambda: setattr(self, "owner", "one:amd64, two:amd64")),
            ("missing source", lambda: setattr(self, "record", self.record.replace("\tsample\t", "\t\t"))),
            ("wrong owner", lambda: setattr(self, "owner", "different:amd64")),
            ("uninstalled", lambda: setattr(self, "record", self.record.replace("install ok installed", "deinstall ok config-files"))),
        ]
        for label, mutate in mutations:
            with self.subTest(label=label):
                self.setUp()
                mutate()
                with self.assertRaises((ValueError, FileNotFoundError)):
                    self.run_index()
                self.assertFalse((self.root / "var/lib/dpkg/status").exists())

    def test_ambiguous_dpkg_search_is_rejected(self):
        for result in ("", f"{self.owner}: {self.source}\nother: {self.source}", "diversion by package"):
            with self.subTest(result=result), self.assertRaisesRegex(ValueError, "one dpkg owner"):
                index.build_index(self.root, self.libraries, lambda *args: result)

    def test_stale_package_fails_before_any_index_output(self):
        self.owner = "libudev1:amd64"
        self.record = "libudev1\tamd64\t255.4-1ubuntu8.16\tsystemd\t255.4-1ubuntu8.16\tinstall ok installed"
        with mock.patch.object(index.subprocess, "run", return_value=mock.Mock(returncode=1)):
            with self.assertRaisesRegex(ValueError, "USN-8626-1"):
                self.run_index()
        self.assertFalse((self.root / "var/lib/dpkg").exists())
        self.assertFalse((self.root / "usr/share/bonvoyage").exists())
        self.assertEqual(self.copied.read_bytes(), self.source.read_bytes())

    def test_fixed_and_newer_package_are_indexed(self):
        for version in ("255.4-1ubuntu8.17", "255.4-1ubuntu8.18"):
            with self.subTest(version=version):
                self.setUp()
                self.owner = "libudev1:amd64"
                self.record = f"libudev1\tamd64\t{version}\tsystemd\t{version}\tinstall ok installed"
                with mock.patch.object(index.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
                    packages = self.run_index()
                self.assertEqual(run.call_count, 2)
                self.assertEqual(packages[self.owner]["version"], version)
                self.assertIn(f"Source: systemd ({version})\n", (self.root / "var/lib/dpkg/status").read_text())

    def test_source_only_staleness_fails_before_output(self):
        self.owner = "libudev1:amd64"
        self.record = "libudev1\tamd64\t255.4-1ubuntu8.17\tsystemd\t255.4-1ubuntu8.16\tinstall ok installed"
        with mock.patch.object(index.subprocess, "run", side_effect=[mock.Mock(returncode=0), mock.Mock(returncode=1)]):
            with self.assertRaisesRegex(ValueError, "source_version.*USN-8626-1"):
                self.run_index()
        self.assertFalse((self.root / "var/lib/dpkg").exists())
        self.assertFalse((self.root / "usr/share/bonvoyage").exists())

    def test_comparator_failure_fails_before_output(self):
        self.owner = "libudev1:amd64"
        self.record = "libudev1\tamd64\t255.4-1ubuntu8.17\tsystemd\t255.4-1ubuntu8.17\tinstall ok installed"
        with mock.patch.object(index.subprocess, "run", return_value=mock.Mock(returncode=2, stderr="failure")):
            with self.assertRaisesRegex(ValueError, "comparison failed"):
                self.run_index()
        self.assertFalse((self.root / "var/lib/dpkg").exists())
        self.assertFalse((self.root / "usr/share/bonvoyage").exists())


class PackageFloorTests(unittest.TestCase):
    def test_runtime_build_explicitly_refreshes_libudev(self):
        dockerfile = Path(__file__).resolve().parent.parent / "deploy/docker/bonvoyage/Dockerfile"
        stage = dockerfile.read_text().split("AS seastar-build\n", 1)[1].split("\nFROM ", 1)[0]
        self.assertIn("ca-certificates git libjansson4 libudev1", stage)
        self.assertLess(stage.index("ca-certificates git libjansson4 libudev1"),
                        stage.index("/usr/src/seastar/install-dependencies.sh"))

    def package(self, **changes):
        package = {"name": "libudev1", "source": "systemd",
                   "version": "255.4-1ubuntu8.17", "source_version": "255.4-1ubuntu8.17"}
        package.update(changes)
        return {"libudev1:amd64": package}

    def test_both_binary_and_source_versions_are_checked(self):
        compare = mock.Mock(return_value=True)
        index.verify_package_floors(self.package(), compare)
        self.assertEqual(compare.call_args_list, [mock.call("255.4-1ubuntu8.17", "255.4-1ubuntu8.17")] * 2)

    def test_either_stale_version_is_rejected(self):
        for field in ("version", "source_version"):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                index.verify_package_floors(self.package(**{field: "255.4-1ubuntu8.16"}),
                                            lambda version, minimum: version == minimum)

    def test_source_identity_cannot_bypass_floor(self):
        compare = mock.Mock()
        with self.assertRaisesRegex(ValueError, "source package systemd"):
            index.verify_package_floors(self.package(source="other"), compare)
        compare.assert_not_called()

    def test_absent_package_does_not_add_a_dependency(self):
        compare = mock.Mock()
        index.verify_package_floors({}, compare)
        index.verify_package_floors({"other": {"name": "libsample1"}}, compare)
        compare.assert_not_called()

    def test_real_comparator_arguments_and_exit_codes(self):
        for code, expected in ((0, True), (1, False)):
            with self.subTest(code=code), mock.patch.object(index.subprocess, "run",
                    return_value=mock.Mock(returncode=code)) as run:
                self.assertIs(index.debian_version_at_least("255.4-1ubuntu8.17", "255.4-1ubuntu8.16"), expected)
                run.assert_called_once_with(["dpkg", "--compare-versions", "255.4-1ubuntu8.17",
                                             "ge", "255.4-1ubuntu8.16"],
                                            capture_output=True, text=True, timeout=10)

    def test_comparator_errors_cannot_pass(self):
        for code in (2, -9):
            with self.subTest(code=code), mock.patch.object(index.subprocess, "run",
                    return_value=mock.Mock(returncode=code, stderr="invalid")):
                with self.assertRaisesRegex(ValueError, "comparison failed"):
                    index.debian_version_at_least("invalid", "255.4-1ubuntu8.17")
        for error in (FileNotFoundError("dpkg"), subprocess.TimeoutExpired("dpkg", 10)):
            with self.subTest(error=type(error)), mock.patch.object(index.subprocess, "run", side_effect=error):
                with self.assertRaises(type(error)):
                    index.verify_package_floors(self.package())

    @unittest.skipUnless(shutil.which("dpkg"), "real Debian comparator requires Linux dpkg")
    def test_real_debian_version_ordering(self):
        for version, expected in (("255.4-1ubuntu8.16", False), ("255.4-1ubuntu8.17~rc1", False),
                                  ("255.4-1ubuntu8.17", True), ("255.4-1ubuntu8.18", True),
                                  ("255.4-1ubuntu8.100", True), ("1:255.4-1ubuntu8.16", True)):
            with self.subTest(version=version):
                self.assertIs(index.debian_version_at_least(version, "255.4-1ubuntu8.17"), expected)


class OverlapTests(unittest.TestCase):
    def fixture(self):
        package = {"name": "libsample1", "architecture": "amd64", "version": "1.2",
                   "source": "sample", "source_version": "1.2", "files": [
                       {"path": "/lib/sample.so", "sha256": "a" * 64, "package_md5": "b" * 32}]}
        artifact = {"id": "installed", "name": "libsample1", "version": "1.2", "foundBy": "dpkg-db-cataloger",
                    "metadata": {"architecture": "amd64", "source": "sample", "sourceVersion": "1.2",
                                 "files": [{"path": "/lib/sample.so", "digest": {"algorithm": "md5", "value": "b" * 32}}]}}
        note = {"id": "elf", "name": "sample", "version": "1.2", "type": "deb",
                "foundBy": "elf-binary-package-cataloger", "metadataType": "elf-binary-package-note-json-payload",
                "metadata": {"architecture": "amd64", "os": "Ubuntu"}, "locations": [{"path": "/lib/sample.so"}]}
        source = {"id": "fixture-image", "type": "image"}
        standard = {"source": source, "distro": {"id": "ubuntu", "versionID": "24.04"},
                    "descriptor": {"name": "syft", "version": "1.44.0", "configuration": {"relationships": {
                        "exclude-binary-packages-with-file-ownership-overlap": True,
                        "package-file-ownership": True, "package-file-ownership-overlap": True}}},
                    "artifacts": [artifact]}
        diagnostic = copy.deepcopy(standard)
        diagnostic["descriptor"]["configuration"]["relationships"]["exclude-binary-packages-with-file-ownership-overlap"] = False
        diagnostic["artifacts"].append(note)
        diagnostic["files"] = [{"location": {"path": "/lib/sample.so"}, "digests": [{"algorithm": "sha256", "value": "a" * 64}]}]
        return diagnostic, standard, {"schema_version": 1, "packages": {"libsample1:amd64": package}}

    def test_full_ownership_passes_without_claiming_scanner_or_image_acceptance(self):
        result = overlap.verify(*self.fixture())
        self.assertEqual(result["diagnostic_packages"], 2)
        self.assertEqual(result["standard_packages"], 1)
        self.assertEqual(result["owned_files"], 1)
        self.assertEqual(result["removed"][0]["name"], "sample")
        self.assertIs(result["image_binding_qualified"], False)
        self.assertIs(result["scanner_parity_qualified"], False)

    def test_incomplete_or_conflicting_evidence_rejected(self):
        cases = [
            ("partial aggregate", lambda d, s, o: d["artifacts"][-1]["locations"].append({"path": "/unowned.so"})),
            ("wrong producer version", lambda d, s, o: d["artifacts"][-1].update(version="0.1")),
            ("wrong evidence layer", lambda d, s, o: d["artifacts"][-1]["locations"][0].update(layerID="other")),
            ("wrong architecture", lambda d, s, o: d["artifacts"][-1]["metadata"].update(architecture="arm64")),
            ("wrong distro", lambda d, s, o: d["artifacts"][-1]["metadata"].update(os="Debian")),
            ("unsupported pruning", lambda d, s, o: d["artifacts"][-1].update(foundBy="different-cataloger")),
            ("missing effective diagnostic", lambda d, s, o: d["descriptor"]["configuration"]["relationships"].update({"exclude-binary-packages-with-file-ownership-overlap": True})),
            ("wrong source", lambda d, s, o: d.update(source={"id": "other", "type": "image"})),
            ("duplicate id", lambda d, s, o: s["artifacts"].append(s["artifacts"][0])),
            ("list only", lambda d, s, o: s["artifacts"][0]["metadata"].update(files=[])),
            ("wrong file SHA", lambda d, s, o: d["files"][0]["digests"][0].update(value="c" * 64)),
            ("wrong original MD5", lambda d, s, o: o["packages"]["libsample1:amd64"]["files"][0].update(package_md5="c" * 32)),
            ("duplicate owner", lambda d, s, o: o["packages"].update(duplicate=copy.deepcopy(o["packages"]["libsample1:amd64"]))),
        ]
        for label, mutate in cases:
            with self.subTest(label=label):
                d, s, o = self.fixture()
                mutate(d, s, o)
                with self.assertRaises(ValueError):
                    overlap.verify(d, s, o)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            json.loads('{"id":"one","id":"two"}', object_pairs_hook=overlap.strict_pairs)


if __name__ == "__main__":
    unittest.main()
