#!/usr/bin/env python3

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/analyze-runtime-glibc-call-trace.py"
SPEC = importlib.util.spec_from_file_location("glibc_trace", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def event(function, caller=None, argument=None):
    encode = lambda value: "-" if value is None else value.encode().hex()
    return ("BONVOYAGE_GLIBC_TRACE_V1"
            f"\tfunction={function}"
            f"\tcaller_hex={encode(caller)}"
            f"\targument_hex={encode(argument)}\n")


class RuntimeGlibcCallTraceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.control = self.write("control.log", "".join([
            event("process_start"),
            event("fopen", "/selftest", "r"),
            event("getaddrinfo", "/selftest"),
            event("process_stop"),
        ]))
        self.gateway = self.write("gateway.log", "".join([
            "ordinary gateway output\n",
            event("process_start"),
            event("fopen", "/usr/local/bin/bonvoyage-dataplane", "rb"),
            event("process_stop"),
        ]))

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, value):
        path = self.root / name
        path.write_text(value, encoding="utf-8")
        return path

    def test_bounded_observation_passes_without_closing_findings(self):
        result = MODULE.analyze({"selftest": self.control}, {"gateway": self.gateway})
        self.assertTrue(result["observations"]["observation_gate_passed"])
        self.assertEqual(result["observations"]["gateway_resolver_call_count"], 0)
        self.assertEqual(result["gateway_scenarios"]["gateway"]["file_mode_counts"],
                         {"rb": 1})
        self.assertFalse(result["reachability_closed"])
        self.assertFalse(result["vex_authorized"])
        self.assertEqual(result["finding_status"]["CVE-2026-8674"]["status"],
                         "under_review")

    def test_gateway_resolver_call_keeps_observation_gate_open(self):
        gateway = self.write("resolver.log", "".join([
            event("process_start"), event("getaddrinfo", "/lib/libcrypto.so.3"),
            event("process_stop"),
        ]))
        result = MODULE.analyze({"selftest": self.control}, {"gateway": gateway})
        self.assertFalse(result["observations"]["observation_gate_passed"])
        self.assertEqual(result["observations"]["gateway_resolver_call_count"], 1)

    def test_any_ccs_mode_keeps_observation_gate_open(self):
        gateway = self.write("ccs.log", "".join([
            event("process_start"),
            event("fopen64", "/lib/libcrypto.so.3", "r,ccs="),
            event("process_stop"),
        ]))
        result = MODULE.analyze({"selftest": self.control}, {"gateway": gateway})
        self.assertFalse(result["observations"]["observation_gate_passed"])
        self.assertEqual(result["observations"]["gateway_ccs_modes"], ["r,ccs="])

    def test_control_must_demonstrate_both_interposition_classes(self):
        control = self.write("weak-control.log", "".join([
            event("process_start"), event("fopen", "/selftest", "r"),
            event("process_stop"),
        ]))
        result = MODULE.analyze({"selftest": control}, {"gateway": self.gateway})
        self.assertFalse(result["observations"]["observer_control_passed"])
        self.assertFalse(result["observations"]["observation_gate_passed"])

    def test_incomplete_lifecycle_or_unattributed_call_keeps_gate_open(self):
        restarted = self.write("restarted.log", "".join([
            event("process_start"), event("process_stop"),
            event("process_start"), event("process_stop"),
        ]))
        unattributed = self.write("unattributed.log", "".join([
            event("process_start"), event("fopen", None, "rb"),
            event("process_stop"),
        ]))
        for name, gateway in (("restarted", restarted),
                              ("unattributed", unattributed)):
            with self.subTest(name=name):
                result = MODULE.analyze(
                    {"selftest": self.control}, {"gateway": gateway})
                self.assertFalse(
                    result["observations"]["observation_gate_passed"])
                self.assertFalse(
                    result["observations"]["gateway_scenarios_complete"])

    def test_malformed_duplicate_and_sensitive_arguments_are_rejected(self):
        cases = {
            "duplicate": "BONVOYAGE_GLIBC_TRACE_V1\tfunction=fopen\tfunction=fopen\tcaller_hex=-\targument_hex=72\n",
            "unknown": event("process_start").replace("process_start", "execve"),
            "resolver-argument": event("getaddrinfo", "/selftest", "secret.example"),
            "bad-hex": "BONVOYAGE_GLIBC_TRACE_V1\tfunction=fopen\tcaller_hex=-\targument_hex=xyz\n",
        }
        for name, content in cases.items():
            with self.subTest(name=name):
                path = self.write(name + ".log", content)
                with self.assertRaises(ValueError):
                    MODULE.parse_trace(path)

    def test_symlinks_duplicate_names_and_existing_output_are_rejected(self):
        link = self.root / "link.log"
        link.symlink_to(self.gateway)
        with self.assertRaises(ValueError):
            MODULE.parse_trace(link)

        output = self.write("result.json", "keep\n")
        command = [
            "python3", "-B", str(SCRIPT),
            "--control", f"same={self.control}",
            "--control", f"same={self.control}",
            "--scenario", f"gateway={self.gateway}",
            "--output", str(output),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(output.read_text(encoding="utf-8"), "keep\n")

    def test_cli_writes_private_new_result_and_reports_open_gate(self):
        output = self.root / "result.json"
        command = [
            "python3", "-B", str(SCRIPT),
            "--control", f"selftest={self.control}",
            "--scenario", f"gateway={self.gateway}",
            "--output", str(output),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
        value = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(value["observations"]["observation_gate_passed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
