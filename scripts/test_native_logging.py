"""Pure decoder and safety guard checks; no Docker or host configuration writes."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "tests/fixtures/native-logging/verify.py"
spec = importlib.util.spec_from_file_location("logging_fixture", SOURCE)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class NativeLoggingTests(unittest.TestCase):
    def test_plain_message(self):
        self.assertEqual(fixture.message({"MESSAGE": "<0>literal"}), "<0>literal")

    def test_binary_message_retains_raw_bytes(self):
        payload = "BVLOG-warn\n<0>input\x1b[31m %s"
        record = {"MESSAGE": list(payload.encode()), "PRIORITY": "4"}
        self.assertEqual(fixture.message(record), payload)
        self.assertEqual(fixture.marked([record], "BVLOG-warn"), [record])
        self.assertIsInstance(record["MESSAGE"], list)
        self.assertEqual(record["PRIORITY"], "4")

    def test_invalid_binary_is_not_silently_ignored(self):
        with self.assertRaises(UnicodeDecodeError):
            fixture.message({"MESSAGE": [255]})
        with self.assertRaises(ValueError):
            fixture.message({"MESSAGE": [256]})

    def test_missing_and_unrelated_records(self):
        self.assertEqual(fixture.marked([{}, {"MESSAGE": "unrelated"}], "BVLOG-"), [])

    def test_refuses_normal_host_execution(self):
        result = subprocess.run([sys.executable, "-B", str(SOURCE)],
                                env={"BONVOYAGE_ISOLATED_LOGGING_FIXTURE": "0"},
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing non-fixture execution", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
