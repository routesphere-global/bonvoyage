#!/usr/bin/env python3
"""Execute authored transport tests inside the isolated Linux fixture only."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

GROUPS = ["options_before_allocation", "typed_priorities_and_escaping", "copied_message_lifetime",
          "whole_record_size_limits", "bounded_fifo_wraparound", "scripted_send_results",
          "finite_drain_batches", "stop_and_accounting", "unix_path_and_record_validation",
          "unix_receiver_recovery_and_fd_lifecycle", "unix_backpressure_lossless_recovery",
          "independent_owner_threads", "callback_reentry", "errno_preservation"]
BINARIES = {"release": "/fixture/runtime-log-release", "sanitize": "/fixture/runtime-log-sanitize"}
SANITIZER_ENV = {"ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                 "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"}


def validate_result(data):
    """Recompute acceptance from captured executions; status alone is insufficient."""
    if data.get("scope") != "standalone-runtime-log-transport" or data.get("gateway_integrated") is not False:
        raise ValueError("incorrect transport scope")
    if data.get("sanitizer_environment") != SANITIZER_ENV:
        raise ValueError("sanitizer settings changed")
    runs = data.get("runs", [])
    if [r.get("name") for r in runs] != ["release", "sanitize", "doxygen"]:
        raise ValueError("missing or duplicate execution")
    summaries = {}
    for run in runs:
        if type(run.get("exit_code")) is not int or run["exit_code"] != 0 or run.get("error"):
            raise ValueError("execution did not finish successfully")
        if not run.get("started_at") or not run.get("ended_at") or run.get("stderr") != "":
            raise ValueError("incomplete or diagnostic-bearing execution")
        name = run["name"]
        expected = [BINARIES[name]] if name in BINARIES else ["doxygen", "/fixture/Doxyfile"]
        if run.get("argv") != expected:
            raise ValueError("unexpected tested program")
        if name in BINARIES:
            lines = run.get("stdout", "").splitlines()
            if not lines:
                raise ValueError("missing test assertions")
            result = json.loads(lines[-1])
            groups = result.get("groups", [])
            if (result.get("status") != "passed" or not isinstance(groups, list)
                    or any(not isinstance(group, str) for group in groups)
                    or len(set(groups)) != len(groups) or not set(GROUPS).issubset(groups)):
                raise ValueError("missing or duplicate required test group")
            assertions = result.get("assertions")
            if type(assertions) is not int or assertions < len(GROUPS):
                raise ValueError("missing test assertion count")
            summaries[name] = {"groups": groups, "assertions": assertions}
    if summaries["release"]["groups"] != summaries["sanitize"]["groups"]:
        raise ValueError("release and sanitizer coverage differ")
    hashes = data.get("binary_sha256", {})
    if set(hashes) != set(BINARIES) or any(not isinstance(h, str) or len(h) != 64
            or any(c not in "0123456789abcdef" for c in h) for h in hashes.values()):
        raise ValueError("missing binary identity")
    expected_binding = "".join(f"{hashes[name]}  {path}\n" for name, path in BINARIES.items())
    if data.get("build_binding") != expected_binding:
        raise ValueError("executed binary differs from build binding")
    if not data.get("compiler") or not data.get("doxygen_version") or data.get("documentation_generated") is not True:
        raise ValueError("missing build/documentation evidence")
    return summaries


def main():
    if not Path("/.dockerenv").exists() or os.environ.get("BONVOYAGE_ISOLATED_LOGGING_FIXTURE") != "1":
        raise SystemExit("refusing non-fixture execution")
    data = {"status": "failed", "scope": "standalone-runtime-log-transport", "gateway_integrated": False,
            "sanitizer_environment": SANITIZER_ENV, "runs": []}
    try:
        data["unit_sha256"] = hashlib.sha256(Path("/fixture/bonvoyage.service").read_bytes()).hexdigest()
        data["binary_sha256"] = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest() for name, path in BINARIES.items()}
        data["build_binding"] = Path("/fixture/runtime-log-binding.txt").read_text()
        data["compiler"] = subprocess.check_output(["g++", "--version"], text=True, timeout=5)
        data["doxygen_version"] = subprocess.check_output(["doxygen", "--version"], text=True, timeout=5).strip()
        for name, argv in [(name, [path]) for name, path in BINARIES.items()] + [("doxygen", ["doxygen", "/fixture/Doxyfile"])]:
            run = {"name": name, "argv": argv, "started_at": datetime.now(timezone.utc).isoformat()}
            data["runs"].append(run)
            try:
                result = subprocess.run(argv, capture_output=True, text=True, timeout=30,
                                        env={**os.environ, **SANITIZER_ENV})
                run.update(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
            except (OSError, subprocess.TimeoutExpired) as error:
                run["error"] = str(error)
                if isinstance(error, subprocess.TimeoutExpired):
                    run["stdout"] = (error.stdout or b"").decode(errors="replace")
                    run["stderr"] = (error.stderr or b"").decode(errors="replace")
            finally:
                run["ended_at"] = datetime.now(timezone.utc).isoformat()
        data["documentation_generated"] = Path("/tmp/runtime-log-doxygen/html/index.html").is_file()
        data["test_summary"] = validate_result(data)
        data["status"] = "passed"
    except Exception as error:
        data["error"] = str(error)
    print(json.dumps(data, indent=2))
    return 0 if data["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
