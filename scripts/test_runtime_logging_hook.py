"""Pure candidate evidence/coverage checks; no Docker or host writes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/runtime-log-hook"
spec = importlib.util.spec_from_file_location("hook_fixture", FIXTURE / "verify.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
METADATA = json.loads((FIXTURE / "patch.json").read_text())


def receipt():
    hashes = {"release": "a" * 64, "sanitize": "b" * 64, "reactor": "c" * 64}
    data = {"classification": "isolated-seastar-runtime-log-candidate", "gateway_integrated": False,
            "patch_metadata": copy.deepcopy(METADATA), "sanitizer_environment": dict(fixture.SANITIZER_ENV),
            "binary_sha256": hashes, "runs": [], "documentation_generated": True, "compiler": "test compiler", "doxygen_version": "test version",
            "library_binding": {"commit": METADATA["commit"], "patch_sha256": METADATA["patch_sha256"], "patched": dict(METADATA["patched"]),
                "release_library_sha256": "d" * 64, "commands": [{"argv": ["ninja", "-C", "build/release", "-j", "2", "install"]}]},
            "test_binding": {"sanitizer_scope": fixture.SANITIZER_SCOPE, "sanitizer_library_sha256": "e" * 64,
                             "binary_sha256": dict(hashes)}}
    for name in ["release", "sanitize", "reactor", "doxygen"]:
        argv = ["doxygen", "/fixture/Doxyfile"] if name == "doxygen" else ["/fixture/hook-" + name]
        groups = fixture.REACTOR_GROUPS if name == "reactor" else fixture.GROUPS
        if name == "reactor":
            argv += fixture.REACTOR_ARGS
        stdout = "" if name == "doxygen" else json.dumps({"status": "passed", "groups": groups, "assertions": 100, "shards": [0, 1]})
        data["runs"].append({"name": name, "argv": argv, "exit_code": 0, "stdout": stdout, "stderr": "", "started_at": "start", "ended_at": "end"})
    return data


class HookEvidenceTests(unittest.TestCase):
    def reject(self, change):
        data = receipt()
        change(data)
        with self.assertRaises((ValueError, TypeError)):
            fixture.validate_result(data, METADATA)

    def test_valid_receipt(self):
        self.assertEqual(fixture.validate_result(receipt(), METADATA)["reactor"]["groups"], fixture.REACTOR_GROUPS)

    def test_status_alone_is_not_evidence(self):
        with self.assertRaises(ValueError):
            fixture.validate_result({"status": "passed"}, METADATA)

    def test_patch_bytes_are_bound(self):
        self.assertEqual(hashlib.sha256((ROOT / METADATA["patch"]).read_bytes()).hexdigest(), METADATA["patch_sha256"])
        expected = {"include/seastar/util/log.hh", "include/seastar/util/log-impl.hh", "src/util/log.cc"}
        self.assertEqual(set(METADATA["original"]), expected)
        self.assertEqual(set(METADATA["patched"]), expected)
        for values in [METADATA["original"], METADATA["patched"]]:
            self.assertTrue(all(fixture.valid_hash(value) for value in values.values()))

    def test_empty_source_inventory_cannot_bypass_binding(self):
        for phase in ["original", "patched"]:
            data = receipt()
            metadata = copy.deepcopy(METADATA)
            metadata[phase] = {}
            data["patch_metadata"] = metadata
            if phase == "patched":
                data["library_binding"]["patched"] = {}
            with self.assertRaises(ValueError):
                fixture.validate_result(data, metadata)

    def test_scope_and_binding_mutations_fail(self):
        mutations = [
            lambda d: d.update(gateway_integrated=True),
            lambda d: d.update(classification="production"),
            lambda d: d["patch_metadata"].update(production_selected=True),
            lambda d: d["library_binding"].update(commit="different"),
            lambda d: d["library_binding"].update(patch_sha256="f" * 64),
            lambda d: d["library_binding"].update(patched={}),
            lambda d: d["library_binding"].update(release_library_sha256="bad"),
            lambda d: d["library_binding"].update(commands=[]),
            lambda d: d["test_binding"].update(sanitizer_scope="full-Seastar"),
            lambda d: d["test_binding"].update(sanitizer_library_sha256="bad"),
            lambda d: d["binary_sha256"].update(release="f" * 64),
            lambda d: d["binary_sha256"].pop("reactor"),
            lambda d: d["sanitizer_environment"].update(ASAN_OPTIONS="detect_leaks=0"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self.reject(mutate)

    def test_failed_or_missing_executions_fail(self):
        mutations = [
            lambda d: d["runs"].pop(1),
            lambda d: d["runs"].append(copy.deepcopy(d["runs"][0])),
            lambda d: d["runs"][0].update(exit_code=1),
            lambda d: d["runs"][1].update(exit_code=False),
            lambda d: d["runs"][1].update(error="timeout"),
            lambda d: d["runs"][1].update(stderr="AddressSanitizer error"),
            lambda d: d["runs"][1].pop("ended_at"),
            lambda d: d["runs"][1].update(argv=["/fixture/hook-release"]),
            lambda d: d["runs"][0].update(stdout=""),
            lambda d: d["runs"][2].update(argv=["/fixture/hook-reactor", "--smp", "1"]),
            lambda d: d["runs"][3].update(stderr="undocumented member"),
            lambda d: d.update(documentation_generated=False),
            lambda d: d.pop("compiler"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self.reject(mutate)

    def test_missing_duplicate_or_failed_groups_fail(self):
        for result in [
            {"status": "passed", "groups": fixture.GROUPS[:-1], "assertions": 100},
            {"status": "passed", "groups": fixture.GROUPS + fixture.GROUPS[:1], "assertions": 100},
            {"status": "failed", "groups": fixture.GROUPS, "assertions": 100},
            {"status": "passed", "groups": fixture.GROUPS, "assertions": False},
            {"status": "passed", "groups": fixture.GROUPS, "assertions": 0},
        ]:
            with self.subTest(result=result):
                self.reject(lambda d: d["runs"][0].update(stdout=json.dumps(result)))

    def test_distinct_shards_required(self):
        self.reject(lambda d: d["runs"][2].update(stdout=json.dumps(
            {"status": "passed", "groups": fixture.REACTOR_GROUPS, "assertions": 20, "shards": [0, 0]})))

    def test_candidate_receipt_remains_historical(self):
        self.assertFalse(METADATA["production_selected"])
        self.assertFalse(receipt()["gateway_integrated"])
        self.assertIn("install_runtime_log_dispatcher", (ROOT / "dataplane/src/main.cc").read_text())
        self.assertIn("seastar-bounded-log-hook.patch", (ROOT / "deploy/docker/bonvoyage/Dockerfile").read_text())

    def test_safety_guards(self):
        for file in ["build.py", "verify.py"]:
            result = subprocess.run([sys.executable, "-B", str(FIXTURE / file)], env={}, capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing non-fixture execution", result.stderr)

    def test_required_sources_are_allowlisted_and_frozen(self):
        allowlist = (FIXTURE / "Dockerfile.dockerignore").read_text().splitlines()
        runner = (ROOT / "scripts/test-native-logging.py").read_text()
        for path in ["dataplane/include/bonvoyage/runtime/runtime_log_binding.hh", "dataplane/src/runtime_log_binding.cc",
                     "dataplane/tests/runtime_log_binding_test.cc", "dataplane/tests/runtime_log_binding_reactor_test.cc", METADATA["patch"]]:
            self.assertIn("!" + path, allowlist)
            self.assertIn(path, runner)


if __name__ == "__main__":
    unittest.main(verbosity=2)
