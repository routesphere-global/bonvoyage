import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("collect-oss-oci-lifecycle.py")
SPEC = importlib.util.spec_from_file_location("oci_lifecycle", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OciLifecycleStructureTest(unittest.TestCase):
    def test_phase_writer_requires_the_exact_check_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / "raw").mkdir()
            checks = {name: True for name in MODULE.PHASE_CHECKS["candidate-reactivation"]}
            relative = MODULE.write_phase(output, "candidate-reactivation", checks,
                                          {"candidate": True})
            self.assertEqual(relative, "raw/candidate-reactivation.json")
            checks.pop(next(iter(checks)))
            with self.assertRaises(MODULE.Rejected):
                MODULE.write_phase(output, "candidate-reactivation", checks, {})

    def test_gateway_runtime_arguments_are_hardened_and_snapshot_bound(self):
        arguments = MODULE.gateway_argv("gateway", "candidate:tag", "upstream")
        self.assertEqual(arguments[:6], [
            "run", "--detach", "--name", "gateway", "--network", "container:upstream",
        ])
        self.assertIn("--read-only", arguments)
        self.assertIn("no-new-privileges", arguments)
        self.assertIn("65532:65532", arguments)
        self.assertIn("nofile=65536:65536", arguments)
        self.assertIn(
            f"type=bind,src={MODULE.SNAPSHOT},dst=/etc/bonvoyage/snapshot.pb,readonly",
            arguments,
        )
        self.assertEqual(arguments[-1], "candidate:tag")

    def test_import_is_networkless_digest_pinned_read_only_and_daemon_compatible(self):
        arguments = MODULE.import_argv(Path("/tmp/candidate.tar"), "candidate:tag")
        self.assertIn(MODULE.SKOPEO_IMAGE, arguments)
        self.assertEqual(arguments[arguments.index("--network") + 1], "none")
        self.assertIn("--read-only", arguments)
        self.assertNotIn("--preserve-digests", arguments)
        self.assertEqual(arguments[arguments.index("--format") + 1], "v2s2")
        self.assertIn(
            f"/var/tmp:rw,noexec,nosuid,nodev,size={MODULE.IMPORT_TMPFS_BYTES}",
            arguments,
        )
        self.assertGreater(MODULE.IMPORT_TMPFS_BYTES, 80_212_890)
        self.assertEqual(arguments[-2:], [
            "oci-archive:/input/candidate.tar", "docker-daemon:candidate:tag",
        ])

    def test_runtime_probes_use_the_exact_newline_terminated_admin_body(self):
        expected = "b'{\"status\":\"ok\"}\\n'"
        self.assertIn(expected, MODULE.PROBE_PROGRAM)
        self.assertIn(expected, MODULE.WAIT_PROGRAM)

    def test_tmpfs_validation_accepts_order_changes_but_not_semantic_drift(self):
        self.assertTrue(MODULE.tmpfs_is_exact(
            "nodev,size=16777216,rw,nosuid,noexec", 16 * 1024 * 1024))
        self.assertTrue(MODULE.tmpfs_is_exact(
            "rw,noexec,nosuid,nodev,size=16m", 16 * 1024 * 1024))
        self.assertFalse(MODULE.tmpfs_is_exact(
            "rw,noexec,nosuid,size=16m", 16 * 1024 * 1024))
        self.assertFalse(MODULE.tmpfs_is_exact(
            "rw,noexec,nosuid,nodev,size=32m", 16 * 1024 * 1024))
        self.assertFalse(MODULE.tmpfs_is_exact(
            "rw,rw,noexec,nosuid,nodev,size=16m", 16 * 1024 * 1024))

    def test_all_contract_phases_have_exact_nonempty_check_sets(self):
        self.assertEqual(list(MODULE.PHASE_CHECKS), [
            "candidate-fresh-start", "replace-baseline-with-candidate",
            "rollback-to-baseline", "candidate-reactivation", "shutdown-remove",
        ])
        self.assertTrue(all(values for values in MODULE.PHASE_CHECKS.values()))
        self.assertEqual(len(set().union(*MODULE.PHASE_CHECKS.values())), 17)


if __name__ == "__main__":
    unittest.main()
