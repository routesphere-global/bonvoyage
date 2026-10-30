#!/usr/bin/env python3
"""Exercise exact Debian upgrade, rollback, reactivation, and removal transitions."""

from __future__ import annotations

import argparse
from email.parser import Parser
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import grp
import signal
import socket
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
FRESH_PATH = Path(__file__).with_name("collect-oss-artifact-lifecycle-fresh.py")
NATIVE_PATH = Path(__file__).with_name("collect-oss-native-install.py")
SNAPSHOT = ROOT / "tests/fixtures/oss-native-fresh-install.pb"
PACKAGE = "bonvoyage-gateway"
SERVICE = "bonvoyage.service"
SERVICE_USER = "bonvoyage"
SERVICE_GROUP = "bonvoyage"
SNAPSHOT_TARGET = Path("/etc/bonvoyage/snapshot.pb")
STATE_PATHS = (Path("/etc/bonvoyage"), Path("/var/lib/bonvoyage"), Path("/var/log/bonvoyage"))
CONFIRM = "RETAIN_BONVOYAGE_OPERATOR_STATE"
INSTALL_TIMEOUT = 600
START_TIMEOUT = 45
REQUESTS = 25


def load_module(name: str, module_path: Path):
    specification = importlib.util.spec_from_file_location(name, module_path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"could not load {module_path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


fresh = load_module("bonvoyage_lifecycle_fresh", FRESH_PATH)
native = load_module("bonvoyage_native_install", NATIVE_PATH)
Rejected = native.Rejected
require = native.require


PHASE_CHECKS = {
    "upgrade-from-baseline": {
        "baseline_active", "candidate_package_installed", "service_not_implicitly_restarted",
        "candidate_activated_after_explicit_restart", "fixed_route_exact",
        "proxied_route_exact", "automatic_restarts_zero",
    },
    "rollback-to-baseline": {
        "baseline_package_restored", "service_not_implicitly_restarted",
        "baseline_activated_after_explicit_restart", "traffic_restored",
        "automatic_restarts_zero",
    },
    "candidate-reactivation": {
        "candidate_package_restored", "candidate_activated_after_explicit_restart",
        "traffic_restored", "automatic_restarts_zero",
    },
    "shutdown-remove": {
        "graceful_stop", "process_absent", "package_absent", "package_payload_absent",
        "operator_state_retained",
    },
}


def canonical_write(path: Path, value: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def prepare_output(output: Path) -> None:
    require(output.is_absolute() and output == output.resolve(),
            "canonical absolute evidence path required")
    require(output.parent in (Path("/root"), Path("/var/tmp")) and
            output.parent.exists(), "evidence must be a direct child of /root or /var/tmp")
    native.secure_parent(output.parent, "evidence parent")
    require(not output.exists() and not output.is_symlink(), "new evidence output required")
    output.mkdir(mode=0o700)
    (output / "raw").mkdir(mode=0o700)
    commands = output / "raw/commands.jsonl"
    commands.write_bytes(b"")
    commands.chmod(0o600)


def package_control(log, command_id: str, package_path: Path) -> dict[str, str]:
    text = log.run(command_id, ["/usr/bin/dpkg-deb", "--field", str(package_path)]).stdout.decode()
    fields = Parser().parsestr(text)
    result = {name: fields.get(name, "").strip() for name in ("Package", "Version", "Architecture")}
    require(result["Package"] == PACKAGE and result["Architecture"] == "amd64" and
            result["Version"], "Debian archive control identity changed")
    return result


def package_status(log, command_id: str) -> dict[str, str]:
    text = log.run(command_id, ["/usr/bin/dpkg-query", "--status", PACKAGE]).stdout.decode()
    fields = Parser().parsestr(text)
    require(fields.get("Status") == "install ok installed", "gateway package is not installed")
    return {name: fields.get(name, "").strip() for name in ("Package", "Version", "Architecture")}


def installed_payload(log, command_id: str) -> dict:
    files = log.run(command_id, ["/usr/bin/dpkg-query", "--listfiles", PACKAGE]).stdout.decode()
    names = [line for line in files.splitlines() if line.startswith("/")]
    require("/usr/bin/bonvoyage-dataplane" in names, "gateway binary is not package-owned")
    units = [Path(name) for name in names if name.endswith("/bonvoyage.service")]
    require(len(units) == 1 and units[0].is_file() and not units[0].is_symlink(),
            "one package-owned service unit is required")
    binary = native.read_regular(Path("/usr/bin/bonvoyage-dataplane"), "installed binary")
    return {"binary_sha256": native.sha256_bytes(binary), "unit": units[0], "files": names}


def install(log, command_id: str, package_path: Path, expected: dict[str, str],
            allow_downgrade: bool = False) -> dict:
    argv = ["/usr/bin/apt-get", "install", "-y", "--no-install-recommends"]
    if allow_downgrade:
        argv.append("--allow-downgrades")
    argv.append(str(package_path))
    log.run(command_id, argv, timeout=INSTALL_TIMEOUT,
            env={"DEBIAN_FRONTEND": "noninteractive", "APT_LISTCHANGES_FRONTEND": "none"})
    log.run(command_id + "-daemon-reload", ["/usr/bin/systemctl", "daemon-reload"])
    observed = package_status(log, command_id + "-status")
    require(observed == expected, f"installed package identity mismatch after {command_id}")
    return {**observed, **installed_payload(log, command_id + "-files")}


def service_fields(log, command_id: str) -> dict[str, str]:
    properties = tuple(native.HARDENING) + (
        "Id", "ActiveState", "SubState", "UnitFileState", "MainPID", "NRestarts",
        "FragmentPath", "InvocationID", "Result", "ExecMainCode", "ExecMainStatus",
    )
    argv = ["/usr/bin/systemctl", "show", SERVICE]
    for name in properties:
        argv.extend(("--property", name))
    fields = native.parse_key_values(log.run(command_id, argv).stdout.decode())
    require(fields.get("Id") == SERVICE and
            all(fields.get(name) == value for name, value in native.HARDENING.items()),
            "effective service hardening changed")
    return fields


def process_identity(pid: int) -> dict:
    require(pid > 1, "valid gateway PID required")
    status_text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    status = dict(line.split(":", 1) for line in status_text.splitlines() if ":" in line)
    uids = status.get("Uid", "").split()
    require(len(uids) == 4 and all(item.isdigit() for item in uids),
            "gateway process UID is unavailable")
    raw_stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    suffix = raw_stat[raw_stat.rfind(")") + 2:].split()
    require(len(suffix) > 19, "gateway process start time is unavailable")
    descriptor = os.open(f"/proc/{pid}/exe", os.O_RDONLY)
    try:
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return {
        "pid": pid,
        "start_ticks": suffix[19],
        "uid": int(uids[0]),
        "executable_sha256": digest.hexdigest(),
        "executable_link": os.readlink(f"/proc/{pid}/exe"),
    }


def active_identity(log, command_id: str) -> dict:
    fields = service_fields(log, command_id)
    require(fields.get("ActiveState") == "active" and fields.get("MainPID", "").isdigit() and
            int(fields["MainPID"]) > 1 and fields.get("NRestarts") == "0" and
            fields.get("InvocationID"), "gateway service is not stably active")
    process = process_identity(int(fields["MainPID"]))
    require(process["uid"] == pwd.getpwnam(SERVICE_USER).pw_uid,
            "gateway process does not use the service identity")
    return {"fields": fields, "process": process}


def same_invocation(before: dict, after: dict) -> bool:
    return (before["fields"]["InvocationID"] == after["fields"]["InvocationID"] and
            before["fields"]["MainPID"] == after["fields"]["MainPID"] and
            before["fields"]["NRestarts"] == after["fields"]["NRestarts"] == "0" and
            before["process"]["start_ticks"] == after["process"]["start_ticks"] and
            before["process"]["executable_sha256"] == after["process"]["executable_sha256"])


def traffic(log, command_id: str) -> dict:
    before = native.fetch_text(9090, "/metrics")
    for _ in range(REQUESTS):
        native.exact_http(8080, "/bonvoyage/ready", b"ready\n")
        native.exact_http(8080, "/healthz", b"oss-native-upstream\n")
    native.exact_http(9901, "/health/ready", native.ADMIN_READY_BODY)
    after = native.fetch_text(9090, "/metrics")
    metrics = native.analyze_metrics(before, after, REQUESTS, 2)
    identity = active_identity(log, command_id + "-service")
    return {"metrics": metrics, "identity": identity}


def start_fixture(log):
    account = pwd.getpwnam(SERVICE_USER)
    group = grp.getgrnam(SERVICE_GROUP)
    process = subprocess.Popen(
        ["/usr/bin/python3", "-c", native.FIXTURE_PROGRAM,
         "--bind", "127.0.0.1", "--port", "18081"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "TZ": "UTC"},
        close_fds=True, start_new_session=True, user=account.pw_uid, group=group.gr_gid,
    )
    log.append({"schema_version": 1, "id": "start-controlled-upstream",
                "argv": ["python3", "sha256:" + native.sha256_bytes(native.FIXTURE_PROGRAM.encode())],
                "started_at": native.utc_now(), "duration_ms": 0, "timed_out": False,
                "output_limit_exceeded": False, "returncode": None,
                "stdout_bytes": 0, "stdout_sha256": native.sha256_bytes(b""),
                "stderr_bytes": 0, "stderr_sha256": native.sha256_bytes(b""),
                "pid": process.pid})
    native.wait_http(18081, "/healthz", b"oss-native-upstream\n", 10)
    return process


def stop_fixture(log, process) -> None:
    if process is None:
        return
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    log.append({"schema_version": 1, "id": "stop-controlled-upstream",
                "argv": ["signal", "controlled-upstream", "TERM"],
                "started_at": native.utc_now(), "duration_ms": 0, "timed_out": False,
                "output_limit_exceeded": False, "returncode": process.returncode,
                "stdout_bytes": 0, "stdout_sha256": native.sha256_bytes(b""),
                "stderr_bytes": 0, "stderr_sha256": native.sha256_bytes(b"")})
    require(process.returncode in (0, -signal.SIGTERM), "controlled upstream did not stop")


def write_phase(output: Path, phase_id: str, checks: dict[str, bool], details: dict) -> str:
    require(set(checks) == PHASE_CHECKS[phase_id] and all(checks.values()),
            f"phase check inventory failed: {phase_id}")
    relative = f"raw/{phase_id}.json"
    canonical_write(output / relative, {
        "schema_version": 1,
        "classification": "routesphere-bonvoyage-oss-debian-transition-phase",
        "captured_at": native.utc_now(),
        "phase": phase_id,
        "checks": checks,
        "details": details,
    })
    return relative


def platform_preflight(confirmed_hostname: str) -> None:
    native.validate_platform(Path("/etc/os-release").read_text(), platform.machine(),
                             os.geteuid(), Path("/proc/1/comm").read_text().strip())
    require(confirmed_hostname == socket.gethostname(),
            "disposable-host acknowledgement must equal hostname")
    status = subprocess.run(["/usr/bin/dpkg-query", "--status", PACKAGE],
                            check=False, capture_output=True)
    require(native.package_is_fresh_absent(status), "gateway package is already present")
    require(all(not path.exists() and not path.is_symlink() for path in STATE_PATHS),
            "gateway operator state is already present")
    require(all(native.NativeHost.port_available(port) for port in native.PORTS),
            "qualification port is already in use")


def collect(candidate_root: Path, baseline_root: Path, output: Path,
            confirmed_hostname: str, retained_state_confirmation: str) -> dict:
    require(retained_state_confirmation == CONFIRM, "retained-state acknowledgement required")
    platform_preflight(confirmed_hostname)
    candidate = fresh.intake(candidate_root, "gateway-deb-linux-amd64")
    baseline = fresh.intake(baseline_root, "gateway-deb-linux-amd64")
    require(candidate["source"]["commit"] != baseline["source"]["commit"] and
            candidate["artifact"]["sha256"] != baseline["artifact"]["sha256"],
            "candidate must differ from rollback baseline")
    prepare_output(output)
    log = native.CommandLog(output / "raw/commands.jsonl")
    staging = output / "inputs"
    staging.mkdir(mode=0o700)
    staged_paths = []
    fixture = None
    phase_records = []
    try:
        baseline_package = fresh.stage_file(
            baseline["path"], staging / "baseline.deb",
            baseline["artifact"]["bytes"], baseline["artifact"]["sha256"],
        )["path"]
        staged_paths.append(baseline_package)
        candidate_package = fresh.stage_file(
            candidate["path"], staging / "candidate.deb",
            candidate["artifact"]["bytes"], candidate["artifact"]["sha256"],
        )["path"]
        staged_paths.append(candidate_package)
        baseline_control = package_control(log, "baseline-archive-control", baseline_package)
        candidate_control = package_control(log, "candidate-archive-control", candidate_package)
        require(baseline_control["Version"] != candidate_control["Version"],
                "baseline and candidate package versions must differ")
        baseline_installed = install(log, "install-baseline", baseline_package, baseline_control)
        baseline_binary = baseline_installed["binary_sha256"]
        require(not SNAPSHOT_TARGET.exists() and not SNAPSHOT_TARGET.is_symlink(),
                "snapshot target must be absent")
        SNAPSHOT_TARGET.write_bytes(native.read_regular(SNAPSHOT, "fixture snapshot"))
        group = grp.getgrnam(SERVICE_GROUP)
        os.chown(SNAPSHOT_TARGET, 0, group.gr_gid)
        SNAPSHOT_TARGET.chmod(0o640)
        fixture = start_fixture(log)
        log.run("enable-service", ["/usr/bin/systemctl", "enable", SERVICE])
        log.run("start-baseline", ["/usr/bin/systemctl", "start", SERVICE], timeout=60)
        native.wait_http(9901, "/health/ready", native.ADMIN_READY_BODY, START_TIMEOUT)
        baseline_active = active_identity(log, "baseline-active")
        require(baseline_active["process"]["executable_sha256"] == baseline_binary,
                "baseline process does not execute the baseline payload")
        traffic(log, "baseline-traffic")

        candidate_installed = install(log, "install-candidate", candidate_package,
                                      candidate_control)
        candidate_binary = candidate_installed["binary_sha256"]
        require(candidate_binary != baseline_binary, "candidate binary must differ from baseline")
        post_upgrade = active_identity(log, "post-upgrade-before-restart")
        require(same_invocation(baseline_active, post_upgrade),
                "package upgrade implicitly restarted the service")
        log.run("restart-candidate", ["/usr/bin/systemctl", "restart", SERVICE], timeout=60)
        native.wait_http(9901, "/health/ready", native.ADMIN_READY_BODY, START_TIMEOUT)
        candidate_active = traffic(log, "candidate-upgrade-traffic")["identity"]
        require(candidate_active["process"]["executable_sha256"] == candidate_binary and
                candidate_active["fields"]["InvocationID"] != baseline_active["fields"]["InvocationID"],
                "explicit restart did not activate the candidate payload")
        evidence = write_phase(output, "upgrade-from-baseline", {
            "baseline_active": True, "candidate_package_installed": True,
            "service_not_implicitly_restarted": True,
            "candidate_activated_after_explicit_restart": True,
            "fixed_route_exact": True, "proxied_route_exact": True,
            "automatic_restarts_zero": True,
        }, {"baseline_version": baseline_control["Version"],
            "candidate_version": candidate_control["Version"],
            "baseline_binary_sha256": baseline_binary,
            "candidate_binary_sha256": candidate_binary})
        phase_records.append({"id": "upgrade-from-baseline", "status": "PASS",
                              "checks": {name: True for name in PHASE_CHECKS["upgrade-from-baseline"]},
                              "evidence": [evidence]})

        rollback_installed = install(log, "rollback-baseline", baseline_package,
                                     baseline_control, allow_downgrade=True)
        post_rollback_install = active_identity(log, "post-rollback-before-restart")
        require(rollback_installed["binary_sha256"] == baseline_binary and
                same_invocation(candidate_active, post_rollback_install),
                "package rollback implicitly restarted or changed the active service")
        log.run("restart-rollback", ["/usr/bin/systemctl", "restart", SERVICE], timeout=60)
        native.wait_http(9901, "/health/ready", native.ADMIN_READY_BODY, START_TIMEOUT)
        rollback_active = traffic(log, "rollback-traffic")["identity"]
        require(rollback_active["process"]["executable_sha256"] == baseline_binary,
                "explicit restart did not reactivate the baseline payload")
        evidence = write_phase(output, "rollback-to-baseline", {
            "baseline_package_restored": True, "service_not_implicitly_restarted": True,
            "baseline_activated_after_explicit_restart": True, "traffic_restored": True,
            "automatic_restarts_zero": True,
        }, {"restored_version": baseline_control["Version"],
            "active_binary_sha256": baseline_binary})
        phase_records.append({"id": "rollback-to-baseline", "status": "PASS",
                              "checks": {name: True for name in PHASE_CHECKS["rollback-to-baseline"]},
                              "evidence": [evidence]})

        reinstalled = install(log, "reactivate-candidate", candidate_package,
                              candidate_control)
        post_reactivation_install = active_identity(log, "post-reactivation-before-restart")
        require(reinstalled["binary_sha256"] == candidate_binary and
                same_invocation(rollback_active, post_reactivation_install),
                "candidate reinstallation implicitly restarted the service")
        log.run("restart-reactivated-candidate", ["/usr/bin/systemctl", "restart", SERVICE],
                timeout=60)
        native.wait_http(9901, "/health/ready", native.ADMIN_READY_BODY, START_TIMEOUT)
        reactivated = traffic(log, "reactivated-candidate-traffic")["identity"]
        require(reactivated["process"]["executable_sha256"] == candidate_binary,
                "candidate payload was not reactivated")
        evidence = write_phase(output, "candidate-reactivation", {
            "candidate_package_restored": True,
            "candidate_activated_after_explicit_restart": True,
            "traffic_restored": True, "automatic_restarts_zero": True,
        }, {"restored_version": candidate_control["Version"],
            "active_binary_sha256": candidate_binary})
        phase_records.append({"id": "candidate-reactivation", "status": "PASS",
                              "checks": {name: True for name in PHASE_CHECKS["candidate-reactivation"]},
                              "evidence": [evidence]})

        final_pid = reactivated["process"]["pid"]
        log.run("stop-service", ["/usr/bin/systemctl", "stop", SERVICE], timeout=60)
        stopped = service_fields(log, "stopped-service")
        graceful = (stopped.get("ActiveState") == "inactive" and stopped.get("MainPID") == "0" and
                    stopped.get("Result") == "success" and stopped.get("ExecMainStatus") == "0" and
                    not Path(f"/proc/{final_pid}").exists())
        require(graceful, "gateway did not stop gracefully")
        stop_fixture(log, fixture)
        fixture = None
        retained_identity = native.service_identity()
        retained_state = native.retained_state_inventory()
        log.run("disable-service", ["/usr/bin/systemctl", "disable", SERVICE], allowed=(0, 1))
        log.run("remove-package", ["/usr/bin/apt-get", "remove", "-y", PACKAGE],
                timeout=INSTALL_TIMEOUT,
                env={"DEBIAN_FRONTEND": "noninteractive", "APT_LISTCHANGES_FRONTEND": "none"})
        log.run("remove-daemon-reload", ["/usr/bin/systemctl", "daemon-reload"])
        removed = log.run("removed-package-status",
                          ["/usr/bin/dpkg-query", "--status", PACKAGE], allowed=(0, 1))
        package_absent = not native.package_is_installed(removed)
        payload_absent = (not Path("/usr/bin/bonvoyage-dataplane").exists() and
                          not candidate_installed["unit"].exists())
        state_retained = (native.service_identity() == retained_identity and
                          native.retained_state_inventory() == retained_state and
                          native.sha256_bytes(native.read_regular(SNAPSHOT_TARGET,
                              "retained snapshot")) == native.sha256_bytes(
                                  native.read_regular(SNAPSHOT, "fixture snapshot")))
        require(package_absent and payload_absent and state_retained,
                "package removal did not preserve the operator boundary")
        evidence = write_phase(output, "shutdown-remove", {
            "graceful_stop": True, "process_absent": True, "package_absent": True,
            "package_payload_absent": True, "operator_state_retained": True,
        }, {"final_pid": final_pid, "snapshot_retained": True,
            "service_identity_retained": True})
        phase_records.append({"id": "shutdown-remove", "status": "PASS",
                              "checks": {name: True for name in PHASE_CHECKS["shutdown-remove"]},
                              "evidence": [evidence, "raw/commands.jsonl"]})

        lane = {
            "schema_version": 1,
            "classification": fresh.LANE_CLASSIFICATION,
            "outcome": "passed",
            "job": "debian-transition",
            "candidate": candidate["source"],
            "baseline": baseline["source"],
            "artifact": {
                "id": "gateway-deb-linux-amd64", "kind": "debian-package",
                "candidate_sha256": candidate["artifact"]["sha256"],
                "baseline_sha256": baseline["artifact"]["sha256"],
            },
            "phases": phase_records,
            "authority": fresh.AUTHORITY,
        }
        canonical_write(output / "lane.json", lane)
        return lane
    except BaseException:
        try:
            log.run("failure-stop-service", ["/usr/bin/systemctl", "stop", SERVICE],
                    allowed=(0, 1, 3, 4, 5), timeout=60)
        except BaseException:
            pass
        raise
    finally:
        if fixture is not None:
            try:
                stop_fixture(log, fixture)
            except BaseException:
                pass
        for staged_path in reversed(staged_paths):
            staged_path.unlink(missing_ok=True)
        staging.rmdir()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--confirm-disposable-host", required=True)
    parser.add_argument("--confirm-retained-state", required=True)
    arguments = parser.parse_args(argv)
    os.umask(0o077)
    try:
        lane = collect(arguments.candidate.absolute(), arguments.baseline.absolute(),
                       arguments.evidence.absolute(), arguments.confirm_disposable_host,
                       arguments.confirm_retained_state)
    except (OSError, ValueError, Rejected) as error:
        print(f"OSS Debian transition rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"outcome": "verified-debian-transition", "job": lane["job"],
                      "release_admitted": False, "publishable": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
