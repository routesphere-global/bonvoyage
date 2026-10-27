#!/usr/bin/env python3
"""Bind a clean Git revision, runtime scan and glibc inventory to one image.

This verifies evidence identity only. It never closes reachability, creates a
VEX disposition, suppresses a scanner finding or authorizes a release.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess


COMMIT = re.compile(r"[a-f0-9]{40}\Z")
IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}\Z")
HEX_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
JSON_LIMIT = 64 * 1024 * 1024
FILE_LIMIT = 4 * 1024 * 1024 * 1024
REQUIRED_SOURCE_FILES = {
    "deploy/docker/bonvoyage/Dockerfile",
    "scripts/build-dataplane-container.sh",
    "scripts/qualify-runtime-dependencies.sh",
    "scripts/inspect-runtime-glibc-reachability.py",
    "scripts/bind-runtime-glibc-reachability.py",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode_json(data):
    def reject_constant(value):
        raise ValueError(f"non-JSON constant: {value}")

    return json.loads(data, object_pairs_hook=unique_pairs,
                      parse_constant=reject_constant)


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def read_file(path, limit=FILE_LIMIT):
    require(path.is_file() and not path.is_symlink(),
            f"regular non-symlink file required: {path}")
    size = path.stat().st_size
    require(0 < size <= limit, f"bounded nonempty file required: {path}")
    data = path.read_bytes()
    require(len(data) == size, f"file changed while reading: {path}")
    return data


def receipt(path, limit=FILE_LIMIT):
    require(path.is_file() and not path.is_symlink(),
            f"regular non-symlink file required: {path}")
    before = path.stat()
    require(0 < before.st_size <= limit, f"bounded nonempty file required: {path}")
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            count += len(block)
            require(count <= limit, f"file exceeds byte budget: {path}")
            digest.update(block)
    after = path.stat()
    require(count == before.st_size and
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            f"file changed while hashing: {path}")
    return {"sha256": digest.hexdigest(), "bytes": count}


def read_json(path):
    data = read_file(path, JSON_LIMIT)
    return decode_json(data), {"sha256": digest_bytes(data), "bytes": len(data)}


def canonical_relative(value):
    parsed = PurePosixPath(value)
    require(value and not parsed.is_absolute() and ".." not in parsed.parts and
            str(parsed) == value and not value.startswith("./"),
            f"canonical relative path required: {value}")
    return value


def parse_environment(path):
    result = {}
    for raw in read_file(path, JSON_LIMIT).decode("utf-8").splitlines():
        require(raw and "=" in raw, "environment record must contain key=value lines")
        key, value = raw.split("=", 1)
        require(key and key not in result, f"duplicate or empty environment key: {key}")
        result[key] = value
    return result


def parse_source_files(path):
    values = []
    for raw in read_file(path, JSON_LIMIT).decode("utf-8").splitlines():
        value = canonical_relative(raw)
        require(value not in values, f"duplicate source file: {value}")
        values.append(value)
    return values


def parse_checksums(path):
    result = {}
    for raw in read_file(path, JSON_LIMIT).decode("utf-8").splitlines():
        parts = raw.split("  ", 1)
        require(len(parts) == 2 and HEX_SHA256.fullmatch(parts[0]),
                "canonical SHA-256 manifest line required")
        name = canonical_relative(parts[1])
        require(name not in result, f"duplicate checksum path: {name}")
        result[name] = parts[0]
    return result


def git_state(repo):
    def run(*arguments):
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments], capture_output=True,
            check=False, timeout=10, env={**os.environ, "LC_ALL": "C"})
        require(result.returncode == 0,
                "git state query failed: " + result.stderr.decode("utf-8", "replace"))
        return result.stdout.decode("utf-8")

    return (run("rev-parse", "HEAD").strip(),
            run("status", "--porcelain=v1", "--untracked-files=all"))


def bind(evidence, repo, current_commit, current_status):
    require(COMMIT.fullmatch(current_commit or ""), "exact lowercase Git HEAD required")
    require(current_status == "", "clean source including untracked files required")

    paths = {
        "environment": evidence / "environment.txt",
        "source_files": evidence / "source-files.txt",
        "source_checksums": evidence / "source-checksums.sha256",
        "archive": evidence / "runtime.oci.tar",
        "raw_syft": evidence / "runtime.raw.syft.json",
        "cyclonedx": evidence / "runtime.cdx.json",
        "spdx": evidence / "runtime.syft.spdx.json",
        "image_inspect": evidence / "runtime-image-inspect.json",
        "container_inspect": evidence / "runtime-container-inspect.json",
        "rootfs": evidence / "runtime-rootfs.tar",
        "gateway": evidence / "runtime-gateway.bin",
        "analyzer": evidence / "runtime-glibc-reachability.json",
        "image_binding": evidence / "image-binding-verification.json",
        "scan": evidence / "dual-format/result.json",
        "scan_checksums": evidence / "dual-format/evidence-checksums.json",
        "scan_cdx": evidence / "dual-format/scan-cdx.stdout",
        "scan_spdx": evidence / "dual-format/scan-spdx.stdout",
        "vulnerability_report": evidence / "vulnerabilities.grype.json",
        "vulnerability_summary": evidence / "vulnerability-summary.json",
    }
    before = {name: receipt(path) for name, path in paths.items()}

    environment = parse_environment(paths["environment"])
    source_files = parse_source_files(paths["source_files"])
    source_checksums = parse_checksums(paths["source_checksums"])
    require(set(source_files) == set(source_checksums),
            "source file and checksum manifests differ")
    require(REQUIRED_SOURCE_FILES <= set(source_files),
            "source manifest omits a source-binding implementation file")
    for name, expected in source_checksums.items():
        source = repo / name
        require(receipt(source)["sha256"] == expected,
                f"source checksum mismatch: {name}")

    source_commit = environment.get("source_commit")
    image_id = environment.get("runtime_image_id")
    require(source_commit == current_commit and environment.get("source_dirty") == "false",
            "environment is not bound to the current clean source")
    require(IMAGE_ID.fullmatch(image_id or "") and
            environment.get("runtime_platform") == "linux/amd64" and
            environment.get("runtime_source_revision") == source_commit and
            environment.get("runtime_source_dirty") == "false",
            "environment runtime/source identity is incomplete")

    image, _ = read_json(paths["image_inspect"])
    require(isinstance(image, list) and len(image) == 1 and isinstance(image[0], dict),
            "one image inspection record required")
    labels = image[0].get("Config", {}).get("Labels", {})
    require(image[0].get("Id") == image_id and image[0].get("Os") == "linux" and
            image[0].get("Architecture") == "amd64" and
            labels.get("org.opencontainers.image.revision") == source_commit and
            labels.get("io.routesphere.bonvoyage.source-dirty") == "false",
            "image labels do not bind the clean source and AMD64 identity")

    analyzer, _ = read_json(paths["analyzer"])
    require(analyzer.get("schema_version") == 1 and analyzer.get("evidence_qualified") is True and
            analyzer.get("source_commit") == source_commit,
            "qualified analyzer result for this source is required")
    identity = analyzer.get("runtime_identity", {})
    require(identity.get("image_id") == image_id and identity.get("platform") == "linux/amd64" and
            identity.get("source_revision") == source_commit and
            identity.get("source_dirty_label") == "false",
            "analyzer runtime identity differs from the clean image")
    for key in ("source_binding_verified", "reachability_closed", "vex_authorized",
                "scanner_suppression_authorized", "release_authorized"):
        require(analyzer.get(key) is False,
                f"standalone analyzer must not authorize {key}")
    findings = analyzer.get("finding_status")
    require(isinstance(findings, dict) and set(findings) ==
            {"CVE-2026-8674", "CVE-2026-18374"} and
            all(value.get("status") == "under_review" for value in findings.values()),
            "both bounded glibc findings must remain under review")
    inspections = analyzer.get("inspection_receipts", {})
    require(inspections.get("image_inspect") == before["image_inspect"] and
            inspections.get("container_inspect") == before["container_inspect"] and
            analyzer.get("rootfs_export", {}).get("sha256") == before["rootfs"]["sha256"] and
            analyzer.get("rootfs_export", {}).get("bytes") == before["rootfs"]["bytes"] and
            analyzer.get("gateway", {}).get("sha256") == before["gateway"]["sha256"],
            "analyzer receipts differ from retained runtime bytes")

    image_binding, _ = read_json(paths["image_binding"])
    require(image_binding.get("schema_version") == 1 and
            image_binding.get("image_binding_qualified") is True and
            image_binding.get("locked_image_id") == image_id and
            image_binding.get("platform") == "linux/amd64",
            "saved OCI image binding did not qualify")
    scan_inputs = {
        "archive": "sha256:" + before["archive"]["sha256"],
        "syft": "sha256:" + before["raw_syft"]["sha256"],
        "cyclonedx": "sha256:" + before["cyclonedx"]["sha256"],
        "spdx": "sha256:" + before["spdx"]["sha256"],
    }
    require(image_binding.get("input_sha256") == scan_inputs,
            "saved-image binding receipts differ from retained OCI/SBOM bytes")
    scan, _ = read_json(paths["scan"])
    require(scan.get("schema_version") == 1 and
            scan.get("scanner_parity_qualified") is True and
            scan.get("status") in ("passed", "blocked") and
            scan.get("input_sha256") == scan_inputs,
            "dual-format scanner parity result is not qualified")
    scan_checksums, _ = read_json(paths["scan_checksums"])
    require(scan_checksums.get("result.json") == before["scan"]["sha256"] and
            scan_checksums.get("scan-cdx.stdout") == before["scan_cdx"]["sha256"] and
            scan_checksums.get("scan-spdx.stdout") == before["scan_spdx"]["sha256"],
            "dual-format checksum seal differs from retained scan outputs")
    require(before["scan_cdx"] == before["vulnerability_report"],
            "compatibility vulnerability report differs from the bound CDX scan")
    summary, _ = read_json(paths["vulnerability_summary"])
    target = summary.get("source", {}).get("target", {})
    summary_labels = target.get("labels", {})
    require(target.get("manifestDigest") == image_id.removeprefix("sha256:") and
            summary_labels.get("org.opencontainers.image.revision") == source_commit and
            summary_labels.get("io.routesphere.bonvoyage.source-dirty") == "false" and
            summary.get("report_sha256") == before["vulnerability_report"]["sha256"] and
            summary.get("counts") == scan.get("counts") and
            summary.get("blocking") == scan.get("blocking") and
            summary.get("gate") == scan.get("gate"),
            "vulnerability summary is not bound to the clean runtime image")

    after = {name: receipt(path) for name, path in paths.items()}
    require(before == after, "binding inputs changed during verification")
    return {
        "schema_version": 1,
        "classification": "clean-source-runtime-scan-glibc-binding",
        "source": {"commit": source_commit, "dirty": False},
        "runtime": {"image_id": image_id, "platform": "linux/amd64",
                    "source_revision_label": source_commit,
                    "source_dirty_label": False},
        "evidence_receipts": before,
        "scan": {
            "status": scan["status"],
            "scanner_parity_qualified": True,
            "high_critical_gate_passed": summary.get("gate", {}).get("passed") is True,
            "coverage_qualified": scan.get("coverage_qualified") is True,
        },
        "finding_status": findings,
        "source_binding_verified": True,
        "scan_binding_verified": True,
        "reachability_evidence_binding_verified": True,
        "reachability_closed": False,
        "vex_authorized": False,
        "scanner_suppression_authorized": False,
        "release_authorized": False,
        "publisher_authenticity_verified": False,
        "limitations": [
            "The Git/image link is a clean-build revision label and local evidence contract, not a signed SLSA provenance attestation.",
            "Binding the scan and static inventory does not prove runtime call reachability or safe fopen mode arguments.",
            "Native package contents, host configuration and future runtime mounts remain separate qualification scopes.",
        ],
    }


def write_private(path, value):
    require(not path.exists() and not path.is_symlink(), "output must be new")
    os.umask(0o077)
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        repo = args.repo_root.resolve(strict=True)
        evidence = args.evidence_dir.resolve(strict=True)
        start = git_state(repo)
        result = bind(evidence, repo, *start)
        require(git_state(repo) == start, "Git source changed during binding")
        write_private(args.output, result)
        print("Verified clean-source runtime scan and glibc inventory binding; both findings remain under review.")
    except (ValueError, OSError, KeyError, TypeError, UnicodeError,
            subprocess.SubprocessError) as error:
        print("Invalid runtime glibc binding evidence: " + str(error))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
