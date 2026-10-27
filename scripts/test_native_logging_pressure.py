"""Pure receipt-rejection and guard tests; no live sockets or Docker work."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/native-logging/pressure.py"
spec = importlib.util.spec_from_file_location("pressure", SOURCE)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def case(mode="syslog", count=32, paused=False, missing=False, name="sample", repetition=None):
    delivered = mode != "disabled" and not missing
    return dict(mode=mode, count=count, payload_bytes=256, paused=paused, missing_receiver=missing,
                name=name, repetition=repetition, pid=123, exit_code=0,
                received=[f"BVLOG_PRESSURE seq={i} payload={'x' * 256}\n" for i in range(count)] if delivered else [],
                events=[dict(event="begin", pid=123), dict(event="complete", pid=123, calls_returned=count,
                        cpu_us=500, wall_ns=400000000, max_call_ns=300000000)],
                filled_units=11, saturation_errno="EAGAIN", blocked_wait_channel="unix_wait_for_peer" if mode == "syslog" else "pipe_write",
                alive_before_resume=True, completed_before_resume=0, held_seconds=0.26)


def result():
    return dict(classification="isolated-logging-backpressure-cost",
                cases=[case(paused=True, name="syslog-paused"), case("stdout", paused=True, name="stdout-paused"),
                       case(missing=True, name="syslog-missing")],
                warmups=[case(mode, 64) for mode in fixture.MODES],
                cost_samples=[case(mode, fixture.COST_COUNT, repetition=r)
                              for r in range(1, 6) for mode in fixture.MODES[r % 3:] + fixture.MODES[:r % 3]])


class LoggingPressureTests(unittest.TestCase):
    def rejected(self, mutate, *, matrix=False):
        value = result() if matrix else case(paused=True)
        mutate(value)
        with self.assertRaises((RuntimeError, KeyError, TypeError, ValueError)):
            (fixture.validate_result if matrix else fixture.validate_case)(value)

    def test_valid_pressure_and_cost_matrix(self):
        self.assertEqual(set(fixture.validate_result(result())), set(fixture.MODES))

    def test_missing_receiver_is_return_not_delivery(self):
        value = case(missing=True)
        self.assertEqual(fixture.validate_case(value)["calls_returned"], 32)
        self.assertEqual(value["received"], [])

    def test_disabled_logger_is_not_delivery(self):
        self.assertEqual(fixture.validate_case(case("disabled"))["calls_returned"], 32)

    def test_reject_nonzero_emitter_exit(self):
        self.rejected(lambda c: c.update(exit_code=1))

    def test_reject_missing_completion(self):
        self.rejected(lambda c: c["events"].pop())

    def test_reject_duplicate_completion(self):
        self.rejected(lambda c: c["events"].append(copy.deepcopy(c["events"][-1])))

    def test_reject_changed_pid(self):
        self.rejected(lambda c: c.update(pid=999))

    def test_reject_incomplete_calls(self):
        self.rejected(lambda c: c["events"][-1].update(calls_returned=31))

    def test_reject_missing_delivery(self):
        self.rejected(lambda c: c["received"].pop())

    def test_reject_duplicate_delivery(self):
        self.rejected(lambda c: c["received"].append(c["received"][0]))

    def test_reject_unparsed_extra_record(self):
        self.rejected(lambda c: c["received"].append("BVLOG_PRESSURE seq=invalid payload=x\n"))

    def test_reject_unexpected_filtered_output(self):
        value = case("disabled")
        value["received"] = ["unexpected sink output"]
        with self.assertRaisesRegex(RuntimeError, "unexpected output"):
            fixture.validate_case(value)

    def test_reject_reordered_delivery(self):
        self.rejected(lambda c: c["received"].reverse())

    def test_reject_truncated_payload(self):
        self.rejected(lambda c: c["received"].__setitem__(0, "BVLOG_PRESSURE seq=0 payload=x\n"))

    def test_reject_absent_saturation(self):
        self.rejected(lambda c: c.update(saturation_errno=None))

    def test_reject_zero_prefill(self):
        self.rejected(lambda c: c.update(filled_units=0))

    def test_reject_nonblocked_channel(self):
        self.rejected(lambda c: c.update(blocked_wait_channel="0"))

    def test_reject_dead_sender(self):
        self.rejected(lambda c: c.update(alive_before_resume=False))

    def test_reject_already_completed_sender(self):
        self.rejected(lambda c: c.update(completed_before_resume=32))

    def test_reject_short_hold(self):
        self.rejected(lambda c: c.update(held_seconds=0.01))

    def test_reject_short_call(self):
        self.rejected(lambda c: c["events"][-1].update(max_call_ns=1000))

    def test_reject_invalid_timing(self):
        for change in [dict(cpu_us=-1), dict(wall_ns=0), dict(max_call_ns=500000001), dict(cpu_us=True)]:
            with self.subTest(change=change):
                self.rejected(lambda c: c["events"][-1].update(change))

    def test_reject_out_of_bounds_work(self):
        for change in [dict(count=0), dict(count=4097), dict(count=True), dict(payload_bytes=0), dict(payload_bytes=1025), dict(mode="unknown")]:
            with self.subTest(change=change):
                self.rejected(lambda c: c.update(change))

    def test_reject_missing_pressure_case(self):
        self.rejected(lambda r: r["cases"].pop(), matrix=True)

    def test_reject_fake_pressure_mode(self):
        self.rejected(lambda r: r["cases"][0].update(paused=False), matrix=True)

    def test_reject_missing_warmup(self):
        self.rejected(lambda r: r["warmups"].pop(), matrix=True)

    def test_reject_missing_cost_sample(self):
        self.rejected(lambda r: r["cost_samples"].pop(), matrix=True)

    def test_reject_reused_repetition(self):
        self.rejected(lambda r: r["cost_samples"][-1].update(repetition=1), matrix=True)

    def test_reject_unmatched_cost_work(self):
        self.rejected(lambda r: r["cost_samples"].__setitem__(0, case("syslog", 32, repetition=1)), matrix=True)

    def test_refuses_normal_host_execution(self):
        proc = subprocess.run([sys.executable, "-B", str(SOURCE)], env={"BONVOYAGE_ISOLATED_LOGGING_FIXTURE": "0"},
                              capture_output=True, text=True, timeout=5)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("refusing non-fixture execution", proc.stderr)

    def test_runner_preserves_container_boundaries(self):
        runner = (ROOT / "scripts/test-native-logging.py").read_text()
        for flag in ['"--network=none"', '"--read-only"', '"--cap-drop=ALL"', '"--cpus=1"', '"--memory=512m"', '"--pids-limit=128"']:
            self.assertIn(flag, runner)
        self.assertIn('module.validate_result(data)', runner)
        self.assertNotIn('--privileged', runner)
        self.assertNotIn('--mount', runner)

    def test_make_wires_pure_tests_and_live_fixture(self):
        makefile = (ROOT / "Makefile").read_text()
        normalized = " ".join(makefile.replace("\\\n", " ").split())
        self.assertTrue(
            '@python3 -B scripts/test_native_logging_pressure.py' in makefile
            or "@python3 -B -m unittest discover -s scripts -p 'test_*.py'" in makefile
        )
        self.assertIn('native-logging-backpressure-ci:\n\t@docker build', makefile)
        self.assertIn('--scenario backpressure --build-image bonvoyage-native-logging-build:ci', normalized)

    def test_explicit_stream_and_optimized_probe(self):
        self.assertIn('"--logger-ostream-type", "stdout"', SOURCE.read_text())
        dockerfile = (ROOT / "tests/fixtures/native-logging/Dockerfile").read_text()
        self.assertIn('-O3 -DNDEBUG -o /fixture/pressure-emitter', dockerfile)


if __name__ == "__main__":
    unittest.main(verbosity=2)
