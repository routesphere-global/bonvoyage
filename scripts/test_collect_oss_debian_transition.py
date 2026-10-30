import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("collect-oss-debian-transition.py")
SPEC = importlib.util.spec_from_file_location("debian_transition", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DebianTransitionStructureTest(unittest.TestCase):
    def test_package_transition_requires_clean_stop_without_new_invocation(self):
        previous = {
            "fields": {"InvocationID": "baseline-invocation"},
            "process": {"pid": 1234},
        }
        fields = {
            "ActiveState": "inactive",
            "MainPID": "0",
            "Result": "success",
            "ExecMainCode": "1",
            "ExecMainStatus": "0",
            "NRestarts": "0",
            "InvocationID": "baseline-invocation",
        }
        self.assertTrue(MODULE.clean_package_transition_stop(fields, previous, False))
        self.assertFalse(MODULE.clean_package_transition_stop(
            {**fields, "InvocationID": "unexpected-new-invocation"}, previous, False))
        self.assertFalse(MODULE.clean_package_transition_stop(
            {**fields, "ActiveState": "active", "MainPID": "5678"}, previous, False))
        self.assertFalse(MODULE.clean_package_transition_stop(fields, previous, True))

    def test_phase_writer_rejects_missing_checks_and_emits_canonical_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / "raw").mkdir()
            checks = {name: True for name in MODULE.PHASE_CHECKS["rollback-to-baseline"]}
            relative = MODULE.write_phase(output, "rollback-to-baseline", checks,
                                          {"restored": True})
            self.assertEqual(relative, "raw/rollback-to-baseline.json")
            text = (output / relative).read_text(encoding="utf-8")
            self.assertTrue(text.endswith("\n"))
            checks.pop(next(iter(checks)))
            with self.assertRaises(MODULE.Rejected):
                MODULE.write_phase(output, "rollback-to-baseline", checks, {})

    def test_every_transition_has_a_nonempty_exact_check_inventory(self):
        self.assertEqual(list(MODULE.PHASE_CHECKS), [
            "upgrade-from-baseline", "rollback-to-baseline",
            "candidate-reactivation", "shutdown-remove",
        ])
        self.assertTrue(all(values for values in MODULE.PHASE_CHECKS.values()))
        self.assertEqual(len(set().union(*MODULE.PHASE_CHECKS.values())), 16)


if __name__ == "__main__":
    unittest.main()
