#!/usr/bin/env python3
"""Build and run an isolated logging fixture with private, checksum-bound output."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-image", required=True, help="Existing Seastar build image, never a runtime image")
    parser.add_argument("--output", required=True, type=Path, help="New private evidence directory")
    parser.add_argument("--scenario", choices=("delivery", "backpressure", "transport", "hook"), default="delivery")
    args = parser.parse_args()
    if args.build_image.startswith("-") or any(c.isspace() for c in args.build_image):
        parser.error("invalid build image")
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    out = args.output.resolve()
    name = "bonvoyage-logging-" + uuid.uuid4().hex[:16]
    commands = []

    def execute(label, argv, timeout):
        record = {"label": label, "argv": argv, "started_at": datetime.now(timezone.utc).isoformat()}
        commands.append(record)
        try:
            with (out / (label + ".stdout")).open("wb") as stdout, (out / (label + ".stderr")).open("wb") as stderr:
                result = subprocess.run(argv, cwd=ROOT, stdout=stdout, stderr=stderr, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            record.update(error=str(error), ended_at=datetime.now(timezone.utc).isoformat())
            raise
        record.update(exit_code=result.returncode, ended_at=datetime.now(timezone.utc).isoformat())
        if result.returncode:
            raise RuntimeError(f"{label} failed: see {out / (label + '.stderr')}")
        return (out / (label + ".stdout")).read_text()

    status = "failed"
    try:
        execute("source-commit", ["git", "rev-parse", "HEAD"], 10)
        execute("source-status", ["git", "status", "--porcelain=v1", "--untracked-files=all"], 10)
        execute("source-diff", ["git", "diff", "--binary", "HEAD"], 10)
        sources = [ROOT / "packaging/systemd/bonvoyage.service",
                   ROOT / "packaging/systemd/90-bonvoyage-no-wall.conf.example", Path(__file__)]
        sources += sorted((ROOT / "tests/fixtures/native-logging").glob("*"))
        sources += [ROOT / path for path in ("dataplane/include/bonvoyage/runtime/runtime_log.hh",
                    "dataplane/src/runtime_log.cc", "dataplane/tests/runtime_log_test.cc", "dataplane/CMakeLists.txt")]
        fixture_path = "tests/fixtures/native-logging"
        if args.scenario == "hook":
            fixture_path = "tests/fixtures/runtime-log-hook"
            sources += sorted((ROOT / fixture_path).glob("*"))
            sources += [ROOT / path for path in (
                "dataplane/include/bonvoyage/runtime/runtime_log_binding.hh",
                "dataplane/src/runtime_log_binding.cc", "dataplane/tests/runtime_log_binding_test.cc",
                "dataplane/tests/runtime_log_binding_reactor_test.cc",
                "deploy/docker/bonvoyage/patches/seastar-bounded-log-hook.patch")]
        for source in sources:
            destination = out / "source" / source.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        base = json.loads(execute("build-image", ["docker", "image", "inspect", args.build_image], 20))[0]
        # Dockerfile FROM cannot resolve a bare local image ID. Use a unique
        # local tag of that ID; retain both identities with the build evidence.
        execute("pin-build-image", ["docker", "image", "tag", base["Id"], name + "-base"], 20)
        execute("build", ["docker", "build", "--progress=plain", "--build-arg", "SEASTAR_BUILD_IMAGE=" + name + "-base",
                          "-t", name, "-f", str(out / "source" / fixture_path / "Dockerfile"),
                          str(out / "source")], 2400 if args.scenario == "hook" else 600)
        image = json.loads(execute("fixture-image", ["docker", "image", "inspect", name], 20))[0]
        argv = ["docker", "run", "--rm", "--name", name, "--network=none",
                "--cpus=1", "--memory=512m", "--pids-limit=128", "--security-opt=no-new-privileges"]
        if args.scenario == "hook":
            argv += ["--read-only", "--cap-drop=ALL", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", image["Id"]]
        elif args.scenario == "transport":
            argv += ["--read-only", "--cap-drop=ALL", "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m",
                     "--entrypoint=python3", image["Id"], "-B", "/fixture/transport.py"]
        elif args.scenario == "backpressure":
            argv += ["--read-only", "--cap-drop=ALL", "--entrypoint=python3", image["Id"], "-B", "/fixture/pressure.py"]
        else:
            argv += [image["Id"]]
        data = json.loads(execute("fixture", argv, 180 if args.scenario == "hook" else 120))
        if data.get("status") != "passed":
            raise RuntimeError("incomplete logging fixture receipt")
        if args.scenario == "hook":
            spec = importlib.util.spec_from_file_location("hook", out / "source/tests/fixtures/runtime-log-hook/verify.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            metadata = json.loads((out / "source/tests/fixtures/runtime-log-hook/patch.json").read_text())
            if module.validate_result(data, metadata) != data.get("test_summary"):
                raise RuntimeError("hook summary does not match executed assertions and pinned source")
        elif args.scenario == "transport":
            spec = importlib.util.spec_from_file_location("transport", out / "source/tests/fixtures/native-logging/transport.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if module.validate_result(data) != data.get("test_summary"):
                raise RuntimeError("transport summary does not match executed assertions")
        elif args.scenario == "backpressure":
            # Revalidate raw observations using the exact frozen fixture source,
            # not just the child process's self-reported status flag.
            spec = importlib.util.spec_from_file_location("pressure", out / "source/tests/fixtures/native-logging/pressure.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if module.validate_result(data) != data.get("cost_summary"):
                raise RuntimeError("logging cost summary does not match raw samples")
        elif [p["name"] for p in data["phases"]] != ["baseline", "no-wall", "rollback"]:
            raise RuntimeError("incomplete logging delivery phases")
        if args.scenario != "hook" and data["unit_sha256"] != hashlib.sha256((out / "source/packaging/systemd/bonvoyage.service").read_bytes()).hexdigest():
            raise RuntimeError("fixture tested different unit bytes")
        status = "passed"
    finally:
        # The unique container is always disposable and has no host bind mounts.
        try:
            inspect = subprocess.run(["docker", "container", "inspect", name], capture_output=True, timeout=20)
            if inspect.returncode == 0:
                execute("cleanup", ["docker", "container", "rm", "--force", name], 20)
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            status = "failed"
            raise
        finally:
            (out / "receipt.json").write_text(json.dumps({"status": status, "scenario": args.scenario, "commands": commands}, indent=2) + "\n")
            files = [{"path": str(p.relative_to(out)), "bytes": p.stat().st_size,
                      "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                     for p in sorted(out.rglob("*")) if p.is_file()]
            (out / "checksums.json").write_text(json.dumps({"files": files}, indent=2) + "\n")
            print(f"{status}: {out}")


if __name__ == "__main__":
    main()
