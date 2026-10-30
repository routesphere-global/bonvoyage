#!/usr/bin/env python3
"""Run the accepted native fresh-install collector for one lifecycle candidate."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
NATIVE_COLLECTOR = Path(__file__).with_name("collect-oss-native-install.py")
NATIVE_CONTRACT = ROOT / "packaging/release/debian/oss-native-fresh-install-contract.json"
SNAPSHOT = ROOT / "tests/fixtures/oss-native-fresh-install.pb"
LANE_CLASSIFICATION = "routesphere-bonvoyage-oss-artifact-lifecycle-lane"
INTAKE_CLASSIFICATION = "routesphere-bonvoyage-oss-candidate-intake-receipt"
REPOSITORY = "https://github.com/routesphere-global/bonvoyage"
SHA256 = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
MAX_FILE_BYTES = 512 * 1024 * 1024
AUTHORITY = {
    "release_admitted": False,
    "publishable": False,
    "github_release_created": False,
    "package_uploaded": False,
    "container_uploaded": False,
    "signature_created": False,
    "provenance_created": False,
}
CHECKS = {
    "package_identity_exact": True,
    "payload_identity_exact": True,
    "runtime_release_identity_exact": True,
    "service_inactive_after_install": True,
    "commissioned_non_root": True,
    "fixed_route_exact": True,
    "proxied_route_exact": True,
    "runtime_error_counters_zero": True,
}


class Rejected(RuntimeError):
    """The intake or accepted collector output violated the lifecycle boundary."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Rejected(message)


def read_file(path: Path, maximum: int = MAX_FILE_BYTES, *, retain: bool = False):
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                0 < before.st_size <= maximum,
                f"bounded regular single-link file required: {path}")
        digest = hashlib.sha256()
        size = 0
        retained = bytearray() if retain else None
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if retained is not None:
                retained.extend(chunk)
        after = os.fstat(descriptor)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns, before.st_nlink) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                 after.st_ctime_ns, after.st_nlink) and size == after.st_size,
                f"file changed while read: {path}")
        return size, digest.hexdigest(), bytes(retained) if retained is not None else None
    finally:
        os.close(descriptor)


def sha256_file(path: Path, maximum: int = MAX_FILE_BYTES) -> tuple[int, str]:
    size, digest, _ = read_file(path, maximum)
    return size, digest


def read_json(path: Path, label: str) -> dict:
    size, _, content = read_file(path, 8 * 1024 * 1024, retain=True)
    require(size > 0, f"{label} is empty")
    require(content is not None, f"{label} could not be retained")
    raw = content.decode("utf-8")

    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, f"duplicate JSON field in {label}: {key}")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(value, dict) and raw == json.dumps(
        value, indent=2, ensure_ascii=False) + "\n", f"{label} must be canonical JSON")
    return value


def stage_file(source: Path, destination: Path, expected_size: int,
               expected_sha256: str) -> dict[str, object]:
    require(type(expected_size) is int and 0 < expected_size <= MAX_FILE_BYTES and
            isinstance(expected_sha256, str) and SHA256.fullmatch(expected_sha256),
            "valid staged artifact identity required")
    require(destination.is_absolute() and destination.parent.is_dir() and
            not destination.parent.is_symlink() and not destination.exists() and
            not destination.is_symlink(), "new private staging path required")
    parent_mode = destination.parent.stat().st_mode
    require(stat.S_IMODE(parent_mode) == 0o700,
            "private staging directory must have mode 0700")
    source_descriptor = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    destination_descriptor = None
    try:
        before = os.fstat(source_descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                before.st_size == expected_size,
                f"staged source identity changed: {source}")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            copied += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                require(written > 0, f"staged artifact write stalled: {destination}")
                view = view[written:]
        after = os.fstat(source_descriptor)
        staged = os.fstat(destination_descriptor)
        observed_sha256 = digest.hexdigest()
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns, before.st_nlink) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                 after.st_ctime_ns, after.st_nlink) and copied == expected_size and
                observed_sha256 == expected_sha256 and stat.S_ISREG(staged.st_mode) and
                staged.st_nlink == 1 and staged.st_size == expected_size,
                f"staged artifact identity mismatch: {source}")
        os.fsync(destination_descriptor)
        return {"path": destination, "bytes": copied, "sha256": observed_sha256}
    except BaseException:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
            destination_descriptor = None
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        os.close(source_descriptor)


def safe_relative(value: object, label: str) -> str:
    require(isinstance(value, str) and value and value == value.strip() and "\\" not in value,
            f"{label} must be a normalized relative path")
    candidate = Path(value)
    require(not candidate.is_absolute() and candidate.as_posix() == value and
            all(part not in ("", ".", "..") for part in candidate.parts),
            f"{label} must be a normalized relative path")
    return value


def intake(root: Path, artifact_id: str) -> dict:
    require(root.is_absolute() and root.is_dir() and not root.is_symlink(),
            "intake root must be a real absolute directory")
    resolved_root = root.resolve()
    receipt = read_json(root / "candidate-intake-receipt.json", "candidate intake receipt")
    require(receipt.get("schema_version") == 1 and
            receipt.get("classification") == INTAKE_CLASSIFICATION and
            receipt.get("authority") == AUTHORITY, "candidate intake identity changed")
    source = receipt.get("source")
    require(isinstance(source, dict) and source.get("repository") == REPOSITORY and
            COMMIT.fullmatch(source.get("commit", "")) and
            isinstance(source.get("tag"), str) and source.get("tag", "").startswith("v") and
            source.get("dirty") is False, "candidate intake source changed")
    artifacts = receipt.get("artifacts")
    require(isinstance(artifacts, list), "candidate intake artifacts must be a list")
    matches = [item for item in artifacts if isinstance(item, dict) and
               item.get("id") == artifact_id]
    require(len(matches) == 1, f"candidate intake must contain one {artifact_id}")
    artifact = matches[0]
    relative = safe_relative(artifact.get("path"), "candidate artifact path")
    artifact_path = resolved_root / relative
    current = resolved_root
    for part in Path(relative).parts:
        current = current / part
        require(not current.is_symlink(), "candidate artifact path contains a symlink")
    size, digest = sha256_file(artifact_path)
    require(artifact.get("bytes") == size and artifact.get("sha256") == digest and
            SHA256.fullmatch(digest), "candidate artifact identity changed")
    return {"source": source, "artifact": artifact, "path": artifact_path}


def load_native_collector():
    specification = importlib.util.spec_from_file_location(
        "bonvoyage_native_install_collector", NATIVE_COLLECTOR)
    require(specification is not None and specification.loader is not None,
            "native collector could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def inventory(root: Path) -> list[str]:
    values = []
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1,
                f"unsafe fresh-lane evidence path: {path}")
        relative = path.relative_to(root).as_posix()
        if relative != "lane.json":
            values.append(relative)
    require(values, "fresh lane must retain evidence")
    return values


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    path.chmod(0o600)


def collect(*, candidate_root: Path, baseline_root: Path, output: Path,
            confirmed_hostname: str, retained_state_confirmation: str,
            collector=None) -> dict:
    candidate = intake(candidate_root, "gateway-deb-linux-amd64")
    baseline = intake(baseline_root, "gateway-deb-linux-amd64")
    require(candidate["source"]["commit"] != baseline["source"]["commit"] and
            candidate["artifact"]["sha256"] != baseline["artifact"]["sha256"],
            "fresh candidate must differ from the rollback baseline")
    build_receipt = candidate_root / "evidence/debian/oss-deb-build-a/build-receipt.json"
    contract_size, contract_digest = sha256_file(NATIVE_CONTRACT, 8 * 1024 * 1024)
    package_size, package_digest = sha256_file(candidate["path"])
    receipt_size, receipt_digest = sha256_file(build_receipt, 8 * 1024 * 1024)
    snapshot_size, snapshot_digest = sha256_file(SNAPSHOT, 64 * 1024 * 1024)
    require(contract_size > 0 and package_size == candidate["artifact"]["bytes"] and
            package_digest == candidate["artifact"]["sha256"] and receipt_size > 0 and
            snapshot_size > 0, "fresh lifecycle immutable inputs changed")
    native = collector or load_native_collector().collect
    result = native(
        contract_path=NATIVE_CONTRACT,
        contract_sha256=contract_digest,
        package=candidate["path"],
        package_sha256=package_digest,
        receipt_path=build_receipt,
        receipt_sha256=receipt_digest,
        snapshot=SNAPSHOT,
        snapshot_sha256=snapshot_digest,
        output=output,
        confirmed_hostname=confirmed_hostname,
        retained_state_confirmation=retained_state_confirmation,
    )
    verification = result.get("verification") if isinstance(result, dict) else None
    require(isinstance(verification, dict) and
            verification.get("fresh_install_qualified") is True and
            verification.get("source_commit") == candidate["source"]["commit"] and
            verification.get("source_tag") == candidate["source"]["tag"] and
            verification.get("package_sha256") == package_digest and
            verification.get("release_admitted") is False and
            verification.get("publishable") is False,
            "accepted native fresh-install collector did not verify the exact candidate")
    evidence = inventory(output)
    lane = {
        "schema_version": 1,
        "classification": LANE_CLASSIFICATION,
        "outcome": "passed",
        "job": "debian-candidate-fresh",
        "candidate": candidate["source"],
        "baseline": baseline["source"],
        "artifact": {
            "id": "gateway-deb-linux-amd64",
            "kind": "debian-package",
            "candidate_sha256": candidate["artifact"]["sha256"],
            "baseline_sha256": baseline["artifact"]["sha256"],
        },
        "phases": [{
            "id": "candidate-fresh-install",
            "status": "PASS",
            "checks": CHECKS,
            "evidence": evidence,
        }],
        "authority": AUTHORITY,
    }
    write_json(output / "lane.json", lane)
    return lane


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--confirm-disposable-host", required=True)
    parser.add_argument("--confirm-retained-state", required=True)
    arguments = parser.parse_args(argv)
    os.umask(0o077)
    try:
        lane = collect(
            candidate_root=arguments.candidate.absolute(),
            baseline_root=arguments.baseline.absolute(),
            output=arguments.evidence.absolute(),
            confirmed_hostname=arguments.confirm_disposable_host,
            retained_state_confirmation=arguments.confirm_retained_state,
        )
    except (OSError, ValueError, Rejected) as error:
        print(f"OSS lifecycle fresh lane rejected: {error}", file=sys.stderr)
        return 2
    print(json.dumps({
        "outcome": "verified-lifecycle-fresh-lane",
        "job": lane["job"],
        "candidate_sha256": lane["artifact"]["candidate_sha256"],
        "release_admitted": False,
        "publishable": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
