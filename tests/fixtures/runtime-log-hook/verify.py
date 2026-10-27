#!/usr/bin/env python3
"""Run and independently validate the isolated candidate, not a gateway RC."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

GROUPS = ["install_validation", "log_buf_bounds", "severity_mapping", "filtering", "borrowed_lifetime",
          "whole_record_overflow", "escaping", "formatter_errors_and_recursion", "binding_lifecycle",
          "errno_preservation", "unbound_dispatch", "parallel_owners", "pressure_and_recovery", "legacy_sink_isolation"]
REACTOR_GROUPS = ["pre_reactor", "two_shards", "unwind", "post_reactor"]
REACTOR_ARGS = ["--smp", "2", "--memory", "128M", "--reserve-memory", "0M", "--overprovisioned", "--reactor-backend", "epoll"]
SANITIZER_SCOPE = "logger-TU-binding-transport-test; remaining-Seastar-release"
SANITIZER_ENV = {"ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                 "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def valid_hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def validate_result(data, metadata):
    require(data.get("classification") == "isolated-seastar-runtime-log-candidate"
            and data.get("gateway_integrated") is False, "incorrect candidate scope")
    require(metadata.get("production_selected") is False and metadata.get("schema_version") == 1, "invalid patch scope")
    expected_files = {"include/seastar/util/log.hh", "include/seastar/util/log-impl.hh", "src/util/log.cc"}
    require(all(set(metadata.get(phase, {})) == expected_files
                and all(valid_hash(value) for value in metadata[phase].values()) for phase in ["original", "patched"]),
            "complete source inventory required")
    require(data.get("patch_metadata") == metadata, "patch metadata mismatch")
    library = data.get("library_binding", {})
    require(library.get("commit") == metadata["commit"] and library.get("patch_sha256") == metadata["patch_sha256"]
            and library.get("patched") == metadata["patched"], "upstream source binding mismatch")
    require(valid_hash(library.get("release_library_sha256")), "missing rebuilt release archive")
    require(any(c.get("argv") == ["ninja", "-C", "build/release", "-j", "2", "install"]
                for c in library.get("commands", [])), "full release rebuild not recorded")
    binding = data.get("test_binding", {})
    require(binding.get("sanitizer_scope") == SANITIZER_SCOPE, "sanitizer scope is misstated")
    require(valid_hash(binding.get("sanitizer_library_sha256")), "missing instrumented logger archive")
    hashes = data.get("binary_sha256", {})
    require(set(hashes) == {"release", "sanitize", "reactor"} and all(valid_hash(v) for v in hashes.values())
            and hashes == binding.get("binary_sha256"), "executed binary/build mismatch")
    require(data.get("sanitizer_environment") == SANITIZER_ENV, "sanitizer options changed")
    require(bool(GROUPS), "required test groups have not been bound")
    runs = data.get("runs", [])
    require([r.get("name") for r in runs] == ["release", "sanitize", "reactor", "doxygen"], "missing or duplicate execution")
    summaries = {}
    for run in runs:
        name = run["name"]
        expected = ["doxygen", "/fixture/Doxyfile"] if name == "doxygen" else ["/fixture/hook-" + name]
        if name == "reactor":
            expected += REACTOR_ARGS
        require(run.get("argv") == expected, "unexpected tested program")
        require(type(run.get("exit_code")) is int and run["exit_code"] == 0 and not run.get("error"), "execution failed")
        require(run.get("started_at") and run.get("ended_at") and run.get("stderr") == "", "missing execution or diagnostics")
        if name == "doxygen":
            continue
        lines = run.get("stdout", "").splitlines()
        require(bool(lines), "missing assertion output")
        summary = json.loads(lines[-1])
        groups = summary.get("groups", [])
        require(summary.get("status") == "passed" and isinstance(groups, list)
                and all(isinstance(g, str) for g in groups) and len(set(groups)) == len(groups)
                and set(REACTOR_GROUPS if name == "reactor" else GROUPS).issubset(groups), "required groups missing or repeated")
        require(type(summary.get("assertions")) is int and summary["assertions"] >= len(groups), "missing assertions")
        if name == "reactor":
            require(summary.get("shards") == [0, 1], "two distinct reactor owners were not tested")
        summaries[name] = {"groups": groups, "assertions": summary["assertions"]}
    require(summaries["release"]["groups"] == summaries["sanitize"]["groups"], "variant coverage mismatch")
    require(data.get("documentation_generated") is True and data.get("compiler") and data.get("doxygen_version"), "missing documentation/tool evidence")
    return summaries


def main():
    if not Path("/.dockerenv").exists() or os.environ.get("BONVOYAGE_ISOLATED_LOGGING_FIXTURE") != "1":
        raise SystemExit("refusing non-fixture execution")
    data = {"status": "failed", "classification": "isolated-seastar-runtime-log-candidate", "gateway_integrated": False,
            "sanitizer_environment": SANITIZER_ENV, "runs": []}
    try:
        for field, file in [("patch_metadata", "patch.json"), ("library_binding", "library-binding.json"), ("test_binding", "test-binding.json")]:
            data[field] = json.loads((Path("/fixture") / file).read_text())
        data["binary_sha256"] = {v: hashlib.sha256(Path("/fixture/hook-" + v).read_bytes()).hexdigest() for v in ["release", "sanitize", "reactor"]}
        data["compiler"] = subprocess.check_output(["g++", "--version"], text=True, timeout=5)
        data["doxygen_version"] = subprocess.check_output(["doxygen", "--version"], text=True, timeout=5).strip()
        for name in ["release", "sanitize", "reactor", "doxygen"]:
            argv = ["doxygen", "/fixture/Doxyfile"] if name == "doxygen" else ["/fixture/hook-" + name]
            if name == "reactor":
                argv += REACTOR_ARGS
            run = {"name": name, "argv": argv, "started_at": datetime.now(timezone.utc).isoformat()}
            data["runs"].append(run)
            try:
                result = subprocess.run(argv, capture_output=True, text=True, timeout=30, env={**os.environ, **SANITIZER_ENV})
                run.update(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
            except (OSError, subprocess.TimeoutExpired) as error:
                run["error"] = str(error)
                if isinstance(error, subprocess.TimeoutExpired):
                    run["stdout"] = (error.stdout or b"").decode(errors="replace")
                    run["stderr"] = (error.stderr or b"").decode(errors="replace")
            finally:
                run["ended_at"] = datetime.now(timezone.utc).isoformat()
        data["documentation_generated"] = Path("/tmp/runtime-log-doxygen/html/index.html").is_file()
        data["test_summary"] = validate_result(data, data["patch_metadata"])
        data["status"] = "passed"
    except Exception as error:
        data["error"] = str(error)
    print(json.dumps(data, indent=2))
    return 0 if data["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
