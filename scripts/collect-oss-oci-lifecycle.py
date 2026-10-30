#!/usr/bin/env python3
"""Exercise exact OCI start, replacement, rollback, reactivation, and cleanup."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
FRESH_PATH = Path(__file__).with_name("collect-oss-artifact-lifecycle-fresh.py")
NATIVE_PATH = Path(__file__).with_name("collect-oss-native-install.py")
OCI_PATH = Path(__file__).with_name("build-oss-oci.py")
OCI_CONTRACT = ROOT / "packaging/release/oci/oss-oci-image-contract.json"
SNAPSHOT = ROOT / "tests/fixtures/oss-native-fresh-install.pb"
SKOPEO_IMAGE = (
    "quay.io/skopeo/stable@"
    "sha256:35bf578e3fa75a1f23bbec819fc1bd9745eacb4a0594dea203e426da66e95e5a"
)
PYTHON_IMAGE = (
    "python:3.12-slim@"
    "sha256:1148dbb014615300fa7e713b2f94f550c0d1c69780c0805f84f093ceee34dd0b"
)
REQUESTS = 25
DOCKER_TIMEOUT = 180
# Skopeo expands the checksum-verified archive before writing to Docker.
IMPORT_TMPFS_BYTES = 256 * 1024 * 1024
SHA256 = re.compile(r"^[a-f0-9]{64}$")
PHASE_CHECKS = {
    "candidate-fresh-start": {
        "archive_identity_exact", "image_manifest_exact", "hardened_runtime_exact",
        "fixed_route_exact", "proxied_route_exact", "runtime_error_counters_zero",
    },
    "replace-baseline-with-candidate": {
        "baseline_digest_active", "candidate_digest_active", "old_container_absent",
        "fixed_route_exact", "proxied_route_exact",
    },
    "rollback-to-baseline": {
        "candidate_container_absent", "baseline_digest_active", "traffic_restored",
    },
    "candidate-reactivation": {
        "baseline_container_absent", "candidate_digest_active", "traffic_restored",
    },
    "shutdown-remove": {
        "graceful_stop", "container_absent", "qualification_network_absent",
        "loaded_candidate_image_absent", "loaded_baseline_image_absent",
    },
}


def load_module(name: str, module_path: Path):
    specification = importlib.util.spec_from_file_location(name, module_path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"could not load {module_path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


fresh = load_module("bonvoyage_lifecycle_fresh", FRESH_PATH)
native = load_module("bonvoyage_native_install", NATIVE_PATH)
oci = load_module("bonvoyage_oci_builder", OCI_PATH)
Rejected = native.Rejected
require = native.require


PROBE_PROGRAM = r'''import http.client
import json

REQUESTS = 25

def fetch(port, path):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read()
        return response.status, body
    finally:
        connection.close()

status, before = fetch(9090, "/metrics")
assert status == 200
for _ in range(REQUESTS):
    assert fetch(8080, "/bonvoyage/ready") == (200, b"ready\n")
    assert fetch(8080, "/healthz") == (200, b"oss-native-upstream\n")
assert fetch(9901, "/health/ready") == (200, b'{"status":"ok"}\n')
status, after = fetch(9090, "/metrics")
assert status == 200
print(json.dumps({"before": before.decode(), "after": after.decode()}, sort_keys=True))
'''

WAIT_PROGRAM = r'''import http.client
import sys
import time

deadline = time.monotonic() + 45
while time.monotonic() < deadline:
    try:
        connection = http.client.HTTPConnection("127.0.0.1", 9901, timeout=2)
        connection.request("GET", "/health/ready", headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read()
        connection.close()
        if response.status == 200 and body == b'{"status":"ok"}\n':
            sys.exit(0)
    except OSError:
        pass
    time.sleep(0.25)
sys.exit(1)
'''


def canonical_write(path: Path, value: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def prepare_output(output: Path) -> None:
    require(output.is_absolute() and output == output.resolve(),
            "canonical absolute evidence path required")
    require(output.parent in (Path("/root"), Path("/var/tmp")) and output.parent.exists(),
            "evidence must be a direct child of /root or /var/tmp")
    native.secure_parent(output.parent, "evidence parent")
    require(not output.exists() and not output.is_symlink(), "new evidence output required")
    output.mkdir(mode=0o700)
    (output / "raw").mkdir(mode=0o700)
    commands = output / "raw/commands.jsonl"
    commands.write_bytes(b"")
    commands.chmod(0o600)


def source_version(source: dict) -> str:
    tag = source.get("tag", "")
    require(isinstance(tag, str) and tag.startswith("v") and len(tag) > 1,
            "v-prefixed source tag required")
    return tag[1:]


def execution(root: Path, artifact: dict) -> dict:
    path = root / "evidence/oci/oss-oci-build-a/oci-builder-execution.json"
    value = fresh.read_json(path, "OCI builder execution")
    source = value.get("source")
    intake_source = artifact["source"]
    require(isinstance(source, dict) and
            all(source.get(name) == intake_source.get(name)
                for name in ("repository", "commit", "tag", "dirty")),
            "OCI execution source does not match intake")
    archive = value.get("archive")
    require(isinstance(archive, dict) and archive.get("bytes") == artifact["artifact"]["bytes"] and
            archive.get("sha256") == artifact["artifact"]["sha256"],
            "OCI execution archive does not match intake")
    require(value.get("version") == source_version(source) and
            type(source.get("source_date_epoch")) is int and
            0 < source["source_date_epoch"] < 4102444800,
            "OCI execution version or source epoch changed")
    return value


def verify_archive(item: dict, receipt: dict) -> dict:
    contract = oci.load_contract(OCI_CONTRACT)
    observed = oci.verify_archive(
        item["path"], contract, item["source"]["commit"], item["source"]["tag"],
        receipt["version"], receipt["source"]["source_date_epoch"],
    )
    artifact = item["artifact"]
    require(observed.get("archive", {}).get("bytes") == artifact["bytes"] and
            observed.get("archive", {}).get("sha256") == artifact["sha256"] and
            observed.get("manifest") == artifact.get("manifest") and
            observed.get("config") == artifact.get("config") and
            observed.get("layer") == artifact.get("layer") and
            observed.get("release_admitted") is False and
            observed.get("publishable") is False,
            "OCI archive verification does not match the accepted intake")
    return observed


class Docker:
    def __init__(self, log):
        self.log = log

    def run(self, command_id: str, args: list[str], *, allowed=(0,), timeout=DOCKER_TIMEOUT):
        return self.log.run(command_id, ["/usr/bin/docker", *args],
                            allowed=allowed, timeout=timeout)

    def json(self, command_id: str, args: list[str]) -> object:
        raw = self.run(command_id, args).stdout
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise Rejected(f"docker returned invalid JSON for {command_id}") from error

    def absent(self, command_id: str, kind: str, value: str) -> bool:
        result = self.run(command_id, [kind, "inspect", value], allowed=(0, 1))
        return result.returncode == 1


def import_argv(archive: Path, local_tag: str) -> list[str]:
    # Docker's daemon transport accepts schema 2; archive identity is verified
    # independently before this transport-only conversion.
    return [
        "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "0:0",
        "--tmpfs", "/run:rw,noexec,nosuid,nodev,size=16m",
        "--tmpfs", f"/var/tmp:rw,noexec,nosuid,nodev,size={IMPORT_TMPFS_BYTES}",
        "--mount", "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock",
        "--mount", f"type=bind,src={archive.parent},dst=/input,readonly",
        SKOPEO_IMAGE, "copy", "--format", "v2s2",
        f"oci-archive:/input/{archive.name}", f"docker-daemon:{local_tag}",
    ]


def gateway_argv(name: str, image: str, upstream: str) -> list[str]:
    return [
        "run", "--detach", "--name", name, "--network", f"container:{upstream}",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", "65532:65532", "--pids-limit", "256", "--memory", "512m",
        "--cpus", "2", "--ulimit", "nofile=65536:65536",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--tmpfs", "/var/lib/bonvoyage:rw,noexec,nosuid,nodev,size=16m",
        "--mount", f"type=bind,src={SNAPSHOT},dst=/etc/bonvoyage/snapshot.pb,readonly",
        image,
    ]


def inspect_image(docker: Docker, command_id: str, tag: str, item: dict) -> dict:
    values = docker.json(command_id, ["image", "inspect", tag])
    require(isinstance(values, list) and len(values) == 1 and isinstance(values[0], dict),
            "one imported OCI image is required")
    image = values[0]
    contract = oci.load_contract(OCI_CONTRACT)
    runtime = contract["runtime"]
    config = image.get("Config")
    expected_id = item["artifact"]["config"]["digest"]
    require(image.get("Id") == expected_id and image.get("Architecture") == "amd64" and
            image.get("Os") == "linux" and isinstance(config, dict) and
            config.get("User") == runtime["user"] and
            config.get("WorkingDir") == runtime["working_directory"] and
            config.get("Entrypoint") == runtime["entrypoint"] and
            config.get("Cmd") == runtime["command"] and
            config.get("Env") == runtime["environment"] and
            config.get("ExposedPorts") == {name: {} for name in runtime["exposed_ports"]} and
            config.get("Labels", {}).get("org.opencontainers.image.revision") ==
            item["source"]["commit"] and
            config.get("Labels", {}).get("org.opencontainers.image.version") ==
            source_version(item["source"]) and
            config.get("Labels", {}).get("io.routesphere.bonvoyage.release-authority") == "false",
            "imported OCI image identity changed")
    return {"id": image["Id"], "config": expected_id}


def tmpfs_is_exact(value: object, expected_bytes: int) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.split(",")
    if len(parts) != len(set(parts)):
        return False
    flags = {part for part in parts if not part.startswith("size=")}
    sizes = [part.removeprefix("size=") for part in parts if part.startswith("size=")]
    if flags != {"rw", "noexec", "nosuid", "nodev"} or len(sizes) != 1:
        return False
    size = sizes[0].lower()
    if size.endswith("m") and size[:-1].isdigit():
        observed_bytes = int(size[:-1]) * 1024 * 1024
    elif size.isdigit():
        observed_bytes = int(size)
    else:
        return False
    return observed_bytes == expected_bytes


def validate_container(value: object, expected_image: str, upstream: str) -> dict:
    require(isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict),
            "one gateway container is required")
    container = value[0]
    state = container.get("State")
    host = container.get("HostConfig")
    mounts = container.get("Mounts")
    config = container.get("Config")
    require(isinstance(state, dict) and state.get("Running") is True and
            state.get("OOMKilled") is False and container.get("RestartCount") == 0 and
            container.get("Image") == expected_image and isinstance(config, dict) and
            config.get("User") == "65532:65532" and isinstance(host, dict) and
            host.get("ReadonlyRootfs") is True and host.get("CapDrop") == ["ALL"] and
            "no-new-privileges" in (host.get("SecurityOpt") or []) and
            host.get("NetworkMode") == f"container:{upstream}" and
            host.get("PidsLimit") == 256 and host.get("Memory") == 536870912 and
            host.get("NanoCpus") == 2000000000 and
            host.get("RestartPolicy") == {"Name": "no", "MaximumRetryCount": 0} and
            isinstance(host.get("Tmpfs"), dict) and
            set(host["Tmpfs"]) == {"/tmp", "/var/lib/bonvoyage"} and
            all(tmpfs_is_exact(options, 16 * 1024 * 1024)
                for options in host["Tmpfs"].values()) and
            isinstance(mounts, list) and len(mounts) == 1 and
            mounts[0].get("Source") == str(SNAPSHOT) and
            mounts[0].get("Destination") == "/etc/bonvoyage/snapshot.pb" and
            mounts[0].get("RW") is False,
            "gateway container hardening changed")
    return {"id": container.get("Id"), "image": container.get("Image")}


def traffic(docker: Docker, command_id: str, upstream: str) -> dict:
    result = docker.run(command_id, ["exec", upstream, "python3", "-c", PROBE_PROGRAM])
    try:
        payload = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Rejected("container traffic probe returned invalid JSON") from error
    require(isinstance(payload, dict) and isinstance(payload.get("before"), str) and
            isinstance(payload.get("after"), str), "container traffic probe output changed")
    return native.analyze_metrics(payload["before"], payload["after"], REQUESTS, 2)


def start_gateway(docker: Docker, command_id: str, name: str, tag: str,
                  expected_image: str, upstream: str) -> dict:
    container_id = docker.run(command_id, gateway_argv(name, tag, upstream)).stdout.decode().strip()
    require(re.fullmatch(r"[a-f0-9]{64}", container_id) is not None,
            "docker did not return a full container ID")
    docker.run(command_id + "-wait", ["exec", upstream, "python3", "-c", WAIT_PROGRAM],
               timeout=60)
    inspected = docker.json(command_id + "-inspect", ["container", "inspect", name])
    identity = validate_container(inspected, expected_image, upstream)
    require(identity["id"] == container_id, "gateway container identity changed")
    metrics = traffic(docker, command_id + "-traffic", upstream)
    return {"container_id": container_id, "image_id": expected_image, "metrics": metrics}


def stop_remove(docker: Docker, command_id: str, name: str) -> dict:
    docker.run(command_id + "-stop", ["container", "stop", "--time", "10", name], timeout=30)
    values = docker.json(command_id + "-stopped", ["container", "inspect", name])
    require(isinstance(values, list) and len(values) == 1 and
            values[0].get("State", {}).get("Running") is False and
            values[0].get("State", {}).get("OOMKilled") is False and
            values[0].get("State", {}).get("ExitCode") == 0,
            "gateway container did not stop gracefully")
    container_id = values[0].get("Id")
    docker.run(command_id + "-remove", ["container", "rm", name])
    require(docker.absent(command_id + "-absent", "container", name),
            "old gateway container remains present")
    return {"container_id": container_id, "graceful": True, "absent": True}


def write_phase(output: Path, phase_id: str, checks: dict[str, bool], details: dict) -> str:
    require(set(checks) == PHASE_CHECKS[phase_id] and all(checks.values()),
            f"phase check inventory failed: {phase_id}")
    relative = f"raw/{phase_id}.json"
    canonical_write(output / relative, {
        "schema_version": 1,
        "classification": "routesphere-bonvoyage-oss-oci-lifecycle-phase",
        "captured_at": native.utc_now(),
        "phase": phase_id,
        "checks": checks,
        "details": details,
    })
    return relative


def phase_record(output: Path, phase_id: str, details: dict) -> dict:
    checks = {name: True for name in PHASE_CHECKS[phase_id]}
    evidence = write_phase(output, phase_id, checks, details)
    return {"id": phase_id, "status": "PASS", "checks": checks, "evidence": [evidence]}


def cleanup_owned(names: dict[str, str]) -> None:
    commands = (
        ["/usr/bin/docker", "container", "rm", "--force", names["gateway"]],
        ["/usr/bin/docker", "container", "rm", "--force", names["fresh"]],
        ["/usr/bin/docker", "container", "rm", "--force", names["upstream"]],
        ["/usr/bin/docker", "network", "rm", names["network"]],
        ["/usr/bin/docker", "image", "rm", "--force", names["candidate_tag"]],
        ["/usr/bin/docker", "image", "rm", "--force", names["baseline_tag"]],
    )
    for argv in commands:
        try:
            subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False, timeout=30)
        except (OSError, subprocess.SubprocessError):
            pass


def collect(candidate_root: Path, baseline_root: Path, output: Path) -> dict:
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "Linux AMD64 runner required")
    candidate = fresh.intake(candidate_root, "gateway-oci-linux-amd64")
    baseline = fresh.intake(baseline_root, "gateway-oci-linux-amd64")
    require(candidate["source"]["commit"] != baseline["source"]["commit"] and
            candidate["artifact"]["sha256"] != baseline["artifact"]["sha256"],
            "candidate must differ from rollback baseline")
    candidate_receipt = execution(candidate_root, candidate)
    baseline_receipt = execution(baseline_root, baseline)
    prepare_output(output)
    log = native.CommandLog(output / "raw/commands.jsonl")
    docker = Docker(log)
    staging = output / "inputs"
    staging.mkdir(mode=0o700)
    staged_paths = []
    suffix = candidate["artifact"]["sha256"][:12]
    names = {
        "network": f"bonvoyage-lifecycle-{suffix}",
        "upstream": f"bonvoyage-lifecycle-upstream-{suffix}",
        "fresh": f"bonvoyage-lifecycle-fresh-{suffix}",
        "gateway": f"bonvoyage-lifecycle-gateway-{suffix}",
        "candidate_tag": f"bonvoyage-lifecycle-candidate:{suffix}",
        "baseline_tag": f"bonvoyage-lifecycle-baseline:{suffix}",
    }
    phases = []
    try:
        candidate_archive = fresh.stage_file(
            candidate["path"], staging / "candidate.tar",
            candidate["artifact"]["bytes"], candidate["artifact"]["sha256"],
        )["path"]
        staged_paths.append(candidate_archive)
        baseline_archive = fresh.stage_file(
            baseline["path"], staging / "baseline.tar",
            baseline["artifact"]["bytes"], baseline["artifact"]["sha256"],
        )["path"]
        staged_paths.append(baseline_archive)
        candidate_staged = {**candidate, "path": candidate_archive}
        baseline_staged = {**baseline, "path": baseline_archive}
        candidate_verified = verify_archive(candidate_staged, candidate_receipt)
        verify_archive(baseline_staged, baseline_receipt)
        docker.json("docker-server", ["version", "--format", "{{json .Server}}"])
        for key in ("network", "upstream", "fresh", "gateway"):
            kind = "network" if key == "network" else "container"
            require(docker.absent(f"preflight-{key}", kind, names[key]),
                    f"owned Docker {key} already exists")
        for key in ("candidate_tag", "baseline_tag"):
            require(docker.absent(f"preflight-{key}", "image", names[key]),
                    f"owned Docker image tag already exists: {names[key]}")
        for label, item in (("candidate", candidate), ("baseline", baseline)):
            require(docker.absent(f"preflight-{label}-image-id", "image",
                                  item["artifact"]["config"]["digest"]),
                    f"{label} image ID is already loaded")

        docker.run("pull-skopeo", ["image", "pull", SKOPEO_IMAGE], timeout=300)
        docker.run("pull-python", ["image", "pull", PYTHON_IMAGE], timeout=300)
        docker.run("import-candidate", import_argv(candidate_archive, names["candidate_tag"]),
                   timeout=300)
        docker.run("import-baseline", import_argv(baseline_archive, names["baseline_tag"]),
                   timeout=300)
        candidate_image = inspect_image(docker, "inspect-candidate-image",
                                        names["candidate_tag"], candidate)
        baseline_image = inspect_image(docker, "inspect-baseline-image",
                                       names["baseline_tag"], baseline)

        docker.run("create-network", ["network", "create", "--driver", "bridge", "--internal",
                                              names["network"]])
        network = docker.json("inspect-network", ["network", "inspect", names["network"]])
        require(isinstance(network, list) and len(network) == 1 and
                network[0].get("Internal") is True and network[0].get("Driver") == "bridge",
                "qualification network is not an internal bridge")
        docker.run("start-upstream", [
            "run", "--detach", "--name", names["upstream"], "--network", names["network"],
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65532:65532", "--pids-limit", "64", "--memory", "128m",
            "--cpus", "1", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
            PYTHON_IMAGE, "python3", "-c", native.FIXTURE_PROGRAM,
            "--bind", "127.0.0.1", "--port", "18081",
        ])

        fresh_active = start_gateway(docker, "candidate-fresh-start", names["fresh"],
                                     names["candidate_tag"], candidate_image["id"],
                                     names["upstream"])
        fresh_stopped = stop_remove(docker, "candidate-fresh", names["fresh"])
        phases.append(phase_record(output, "candidate-fresh-start", {
            "archive_sha256": candidate_verified["archive"]["sha256"],
            "manifest_digest": candidate_verified["manifest"]["digest"],
            "image_id": candidate_image["id"],
            "container_id": fresh_active["container_id"],
            "graceful_stop": fresh_stopped["graceful"],
        }))

        baseline_active = start_gateway(docker, "replacement-baseline-start", names["gateway"],
                                        names["baseline_tag"], baseline_image["id"],
                                        names["upstream"])
        old_baseline = stop_remove(docker, "replacement-baseline", names["gateway"])
        candidate_active = start_gateway(docker, "replacement-candidate-start", names["gateway"],
                                         names["candidate_tag"], candidate_image["id"],
                                         names["upstream"])
        phases.append(phase_record(output, "replace-baseline-with-candidate", {
            "baseline_image_id": baseline_active["image_id"],
            "candidate_image_id": candidate_active["image_id"],
            "old_container_id": old_baseline["container_id"],
            "new_container_id": candidate_active["container_id"],
        }))

        removed_candidate = stop_remove(docker, "rollback-candidate", names["gateway"])
        rollback_active = start_gateway(docker, "rollback-baseline-start", names["gateway"],
                                        names["baseline_tag"], baseline_image["id"],
                                        names["upstream"])
        phases.append(phase_record(output, "rollback-to-baseline", {
            "removed_candidate_container_id": removed_candidate["container_id"],
            "baseline_container_id": rollback_active["container_id"],
            "baseline_image_id": rollback_active["image_id"],
        }))

        removed_baseline = stop_remove(docker, "reactivation-baseline", names["gateway"])
        reactivated = start_gateway(docker, "reactivation-candidate-start", names["gateway"],
                                    names["candidate_tag"], candidate_image["id"],
                                    names["upstream"])
        phases.append(phase_record(output, "candidate-reactivation", {
            "removed_baseline_container_id": removed_baseline["container_id"],
            "candidate_container_id": reactivated["container_id"],
            "candidate_image_id": reactivated["image_id"],
        }))

        final = stop_remove(docker, "shutdown-candidate", names["gateway"])
        docker.run("remove-upstream", ["container", "rm", "--force", names["upstream"]])
        require(docker.absent("upstream-absent", "container", names["upstream"]),
                "qualification upstream remains present")
        docker.run("remove-network", ["network", "rm", names["network"]])
        require(docker.absent("network-absent", "network", names["network"]),
                "qualification network remains present")
        docker.run("remove-candidate-image", ["image", "rm", names["candidate_tag"]])
        docker.run("remove-baseline-image", ["image", "rm", names["baseline_tag"]])
        require(docker.absent("candidate-image-absent", "image", candidate_image["id"]) and
                docker.absent("baseline-image-absent", "image", baseline_image["id"]),
                "loaded lifecycle image remains present")
        phases.append(phase_record(output, "shutdown-remove", {
            "final_container_id": final["container_id"],
            "network": names["network"],
            "candidate_image_id": candidate_image["id"],
            "baseline_image_id": baseline_image["id"],
        }))
        phases[-1]["evidence"].append("raw/commands.jsonl")

        lane = {
            "schema_version": 1,
            "classification": fresh.LANE_CLASSIFICATION,
            "outcome": "passed",
            "job": "oci-lifecycle",
            "candidate": candidate["source"],
            "baseline": baseline["source"],
            "artifact": {
                "id": "gateway-oci-linux-amd64", "kind": "oci-image",
                "candidate_sha256": candidate["artifact"]["sha256"],
                "baseline_sha256": baseline["artifact"]["sha256"],
            },
            "phases": phases,
            "authority": fresh.AUTHORITY,
        }
        canonical_write(output / "lane.json", lane)
        return lane
    except BaseException:
        cleanup_owned(names)
        raise
    finally:
        for staged_path in reversed(staged_paths):
            staged_path.unlink(missing_ok=True)
        staging.rmdir()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    arguments = parser.parse_args(argv)
    os.umask(0o077)
    try:
        lane = collect(arguments.candidate.absolute(), arguments.baseline.absolute(),
                       arguments.evidence.absolute())
    except (OSError, ValueError, Rejected) as error:
        print(f"OSS OCI lifecycle rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"outcome": "verified-oci-lifecycle", "job": lane["job"],
                      "release_admitted": False, "publishable": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
