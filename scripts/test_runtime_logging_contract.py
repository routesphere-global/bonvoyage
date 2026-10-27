"""Fail-closed checks for standalone transport evidence; never alters the host."""
import copy
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/native-logging/transport.py"
spec = importlib.util.spec_from_file_location("transport_fixture", SOURCE)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def receipt():
    data = {"scope": "standalone-runtime-log-transport", "gateway_integrated": False,
            "sanitizer_environment": dict(fixture.SANITIZER_ENV), "runs": [],
            "binary_sha256": {"release": "a" * 64, "sanitize": "b" * 64},
            "compiler": "test compiler", "doxygen_version": "test version", "documentation_generated": True}
    for name, path in fixture.BINARIES.items():
        data["runs"].append({"name": name, "argv": [path], "started_at": "start", "ended_at": "end",
                             "exit_code": 0, "stderr": "", "stdout": json.dumps(
                                 {"status": "passed", "groups": fixture.GROUPS, "assertions": 100}) + "\n"})
    data["runs"].append({"name": "doxygen", "argv": ["doxygen", "/fixture/Doxyfile"], "started_at": "start",
                         "ended_at": "end", "exit_code": 0, "stdout": "", "stderr": ""})
    data["build_binding"] = "".join(f"{data['binary_sha256'][name]}  {path}\n" for name, path in fixture.BINARIES.items())
    return data


class RuntimeLoggingContractTests(unittest.TestCase):
    def reject(self, change):
        data = receipt()
        change(data)
        with self.assertRaises((ValueError, TypeError)):
            fixture.validate_result(data)

    def test_valid_receipt(self):
        self.assertEqual(fixture.validate_result(receipt())["release"]["assertions"], 100)

    def test_status_alone_is_not_evidence(self):
        with self.assertRaises(ValueError):
            fixture.validate_result({"status": "passed"})

    def test_no_gateway_claim(self):
        self.reject(lambda d: d.update(gateway_integrated=True))

    def test_exact_scope(self):
        self.reject(lambda d: d.update(scope="gateway-load"))

    def test_sanitizers_cannot_be_disabled(self):
        self.reject(lambda d: d["sanitizer_environment"].update(ASAN_OPTIONS="detect_leaks=0"))

    def test_no_missing_execution(self):
        self.reject(lambda d: d["runs"].pop(1))

    def test_no_duplicate_execution(self):
        self.reject(lambda d: d["runs"].insert(1, copy.deepcopy(d["runs"][0])))

    def test_nonzero_exit_rejected(self):
        self.reject(lambda d: d["runs"][1].update(exit_code=1))

    def test_boolean_exit_rejected(self):
        self.reject(lambda d: d["runs"][1].update(exit_code=False))

    def test_timeout_rejected(self):
        self.reject(lambda d: d["runs"][1].update(error="timed out"))

    def test_sanitizer_diagnostics_rejected(self):
        self.reject(lambda d: d["runs"][1].update(stderr="runtime error"))

    def test_incomplete_execution_rejected(self):
        self.reject(lambda d: d["runs"][0].pop("ended_at"))

    def test_wrong_binary_rejected(self):
        self.reject(lambda d: d["runs"][1].update(argv=["/fixture/runtime-log-release"]))

    def test_empty_output_rejected(self):
        self.reject(lambda d: d["runs"][0].update(stdout=""))

    def test_missing_group_rejected(self):
        self.reject(lambda d: d["runs"][0].update(stdout=json.dumps(
            {"status": "passed", "groups": fixture.GROUPS[:-1], "assertions": 100})))

    def test_duplicate_group_rejected(self):
        self.reject(lambda d: d["runs"][0].update(stdout=json.dumps(
            {"status": "passed", "groups": fixture.GROUPS + [fixture.GROUPS[0]], "assertions": 100})))

    def test_failed_test_status_rejected(self):
        self.reject(lambda d: d["runs"][0].update(stdout=json.dumps(
            {"status": "failed", "groups": fixture.GROUPS, "assertions": 100})))

    def test_boolean_assertions_rejected(self):
        self.reject(lambda d: d["runs"][0].update(stdout=json.dumps(
            {"status": "passed", "groups": fixture.GROUPS, "assertions": True})))

    def test_zero_assertions_rejected(self):
        self.reject(lambda d: d["runs"][0].update(stdout=json.dumps(
            {"status": "passed", "groups": fixture.GROUPS, "assertions": 0})))

    def test_variant_coverage_mismatch_rejected(self):
        self.reject(lambda d: d["runs"][0].update(stdout=json.dumps(
            {"status": "passed", "groups": fixture.GROUPS + ["extra"], "assertions": 100})))

    def test_doxygen_warning_rejected(self):
        self.reject(lambda d: d["runs"][2].update(stderr="undocumented member"))

    def test_missing_html_rejected(self):
        self.reject(lambda d: d.update(documentation_generated=False))

    def test_wrong_build_binding_rejected(self):
        self.reject(lambda d: d.update(build_binding="different"))

    def test_missing_binary_hash_rejected(self):
        self.reject(lambda d: d["binary_sha256"].pop("sanitize"))

    def test_malformed_binary_hash_rejected(self):
        self.reject(lambda d: d["binary_sha256"].update(sanitize="x" * 64))

    def test_build_tools_required(self):
        self.reject(lambda d: d.pop("compiler"))

    def test_refuses_host_execution(self):
        result = subprocess.run([sys.executable, "-B", str(SOURCE)],
                                env={"BONVOYAGE_ISOLATED_LOGGING_FIXTURE": "0"},
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing non-fixture execution", result.stderr)

    def test_production_service_and_shutdown_regression_are_linked(self):
        source = (ROOT / "dataplane/CMakeLists.txt").read_text()
        links = re.findall(r"target_link_libraries\(\s*bonvoyage-dataplane\s+([^)]*)\)", source)
        self.assertTrue(links, "gateway link target must exist")
        self.assertTrue(any("bonvoyage-runtime-log-service" in link for link in links))
        self.assertIn("add_test(NAME bonvoyage-runtime-log COMMAND bonvoyage-runtime-log-test)", source)
        self.assertIn("add_test(NAME bonvoyage-runtime-log-service-reactor", source)
        self.assertIn("add_test(NAME bonvoyage-shutdown-sequence-reactor", source)

    def test_failed_shutdown_cannot_claim_clean_stop_or_outlive_logging(self):
        main = (ROOT / "dataplane/src/main.cc").read_text()
        sequence = main.index("ShutdownSequence shutdown")
        rethrow = main.index("shutdown.rethrow_if_failed()", sequence)
        clean = main.index("event=dataplane_stopped", rethrow)
        failed = main.index("event=dataplane_failed", clean)
        logging_stop = main.index("logging.stop().get()", failed)
        final_rethrow = main.index("completion.rethrow_if_failed()", logging_stop)
        self.assertLess(sequence, rethrow)
        self.assertLess(rethrow, clean)
        self.assertLess(clean, failed)
        self.assertLess(failed, logging_stop)
        self.assertLess(logging_stop, final_rethrow)
        for step in ("admin_server.stop().get()", "metrics_server.stop().get()",
                     "stop_maintenance().get()", "gateway.stop().get()"):
            self.assertIn("shutdown.attempt", main[sequence:main.index(step, sequence)])

    def test_container_smoke_selects_stderr_transport_for_log_assertions(self):
        smoke = (ROOT / "scripts/smoke-dataplane-container.sh").read_text()
        self.assertIn("--runtime-log-transport stderr-pipe", smoke)
        self.assertIn('grep -F "event=dataplane_ready"', smoke)
        self.assertIn('grep -F "event=dataplane_stopped"', smoke)

    def test_sources_in_static_analysis(self):
        source = (ROOT / "deploy/docker/bonvoyage/Dockerfile").read_text().split("AS static-analysis", 1)[1]
        for path in ["dataplane/src/runtime_log.cc", "dataplane/tests/runtime_log_test.cc",
                     "dataplane/tests/runtime_log_service_reactor_test.cc",
                     "dataplane/tests/shutdown_sequence_reactor_test.cc"]:
            self.assertIn(path + " \\", source)

    def test_fixture_allows_required_sources(self):
        source = (ROOT / "tests/fixtures/native-logging/Dockerfile.dockerignore").read_text().splitlines()
        for path in ["dataplane/include/bonvoyage/runtime/runtime_log.hh", "dataplane/src/runtime_log.cc",
                     "dataplane/tests/runtime_log_test.cc"]:
            self.assertIn("!" + path, source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
