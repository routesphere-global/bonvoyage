#!/usr/bin/env python3
"""Verify a checksum-bound BonVoyage OSS native fresh-install evidence set."""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "packaging/release/debian/oss-native-fresh-install-contract.json"
OBSERVATION_CLASS = "routesphere-bonvoyage-oss-native-fresh-install-observation"
BUILD_CLASS = "routesphere-bonvoyage-oss-deb-build"
REPORT_CLASS = "routesphere-bonvoyage-oss-native-fresh-install-verification"
PUBLIC_REPOSITORY = "https://github.com/routesphere-global/bonvoyage"
SHA256 = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
TAG = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$")
VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:[~+.-][0-9A-Za-z.+~-]+)?$")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024

TARGET = {
    "distribution": "ubuntu",
    "version_id": "24.04",
    "architecture": "amd64",
    "package": "bonvoyage-gateway",
    "service": "bonvoyage.service",
}
FIXTURE = {
    "path": "tests/fixtures/oss-native-fresh-install.yaml",
    "bytes": 1338,
    "sha256": "8dc182a0b554f161828539dc847753b26d08c43efdbfad42cca70545f34b2e3f",
    "snapshot": {
        "path": "tests/fixtures/oss-native-fresh-install.pb",
        "snapshot_id": "oss-native-fresh-install",
        "generation": 1,
        "bytes": 300,
        "sha256": "994c972fec3feeae03d0b93e81a95db5a86cf2d6193f7785edd36bfc1085bb09",
    },
}
PHASE_CHECKS = {
    "preflight": [
        "disposable_host_confirmed",
        "package_absent",
        "service_account_absent",
        "state_absent",
        "shadow_unit_absent",
    ],
    "installed-inactive": [
        "package_identity_exact",
        "payload_identity_exact",
        "service_account_non_root",
        "state_modes_safe",
        "service_disabled",
        "service_inactive",
        "package_unit_authoritative",
    ],
    "commissioned": [
        "snapshot_identity_exact",
        "snapshot_mode_safe",
        "service_enabled",
        "service_active",
        "effective_hardening_exact",
        "process_non_root",
        "process_binary_exact",
        "loopback_admin",
        "loopback_metrics",
    ],
    "traffic": [
        "fixed_route_exact",
        "proxied_route_exact",
        "admin_ready",
        "metrics_accounting_exact",
        "runtime_error_counters_zero",
        "process_identity_stable",
        "automatic_restarts_zero",
    ],
    "stopped": [
        "graceful_stop",
        "service_inactive",
        "process_absent",
    ],
    "removed": [
        "package_absent",
        "binary_absent",
        "package_unit_absent",
        "service_account_retained",
        "snapshot_retained",
        "operator_state_retained",
    ],
}
EVIDENCE_FILES = [
    "raw/commands.jsonl",
    "raw/installed-state.txt",
    "raw/journal.txt",
    "raw/metrics-after.txt",
    "raw/metrics-before.txt",
    "raw/os-release.txt",
    "raw/package-control.txt",
    "raw/package-files.txt",
    "raw/preflight.txt",
    "raw/process-status.txt",
    "raw/removed-state.txt",
    "raw/service-properties.txt",
    "raw/socket-state.txt",
    "raw/stopped-state.txt",
    "raw/traffic.txt",
]
COMMAND_IDS = [
    "preflight-package-status",
    "preflight-service-user",
    "preflight-service-group",
    "archive-control",
    "install-package",
    "install-daemon-reload",
    "installed-package-status",
    "installed-package-files",
    "installed-service-enabled",
    "installed-service-active",
    "installed-service-properties",
    "installed-unit-owner",
    "start-controlled-upstream",
    "enable-service",
    "start-service",
    "commissioned-service-properties",
    "commissioned-sockets",
    "traffic-service-properties",
    "pre-stop-service-properties",
    "stop-service",
    "stopped-service-properties",
    "service-journal",
    "stop-controlled-upstream",
    "disable-service",
    "removed-service-enabled",
    "remove-package",
    "remove-daemon-reload",
    "removed-package-status",
]
ZERO_COUNTERS = [
    "responses_4xx",
    "responses_5xx",
    "route_misses",
    "request_timeouts",
    "overload_rejections",
    "upstream_failures",
    "allocator_failures",
    "abandoned_failed_futures",
    "reactor_stalls",
]
METRICS = {
    "requests": "bonvoyage_bonvoyage_gateway_requests_total",
    "responses_2xx": "bonvoyage_bonvoyage_gateway_responses_2xx_total",
    "upstream_selections": "bonvoyage_bonvoyage_gateway_upstream_endpoint_selections_total",
    "configured_routes": "bonvoyage_bonvoyage_gateway_configured_routes",
    "ready": "bonvoyage_bonvoyage_gateway_ready",
    "responses_4xx": "bonvoyage_bonvoyage_gateway_responses_4xx_total",
    "responses_5xx": "bonvoyage_bonvoyage_gateway_responses_5xx_total",
    "route_misses": "bonvoyage_bonvoyage_gateway_route_misses_total",
    "request_timeouts": "bonvoyage_bonvoyage_gateway_request_timeouts_total",
    "overload_rejections": "bonvoyage_bonvoyage_gateway_overload_rejections_total",
    "upstream_failures": "bonvoyage_bonvoyage_gateway_upstream_failures_total",
    "allocator_failures": "bonvoyage_memory_malloc_failed",
    "abandoned_failed_futures": "bonvoyage_reactor_abandoned_failed_futures",
    "reactor_stalls": "bonvoyage_stall_detector_reported",
}
RESOURCE_BOUNDS = {
    "maximum_rss_growth_kib": 16384,
    "maximum_descriptor_growth": 2,
    "maximum_automatic_restarts": 0,
}
QUALIFICATIONS = {
    "fresh_install_qualified": True,
    "upgrade_qualified": False,
    "rollback_qualified": False,
    "kubernetes_qualified": False,
    "benchmark_reproduction_qualified": False,
    "release_admitted": False,
    "publishable": False,
}


class Rejected(ValueError):
    """Evidence or contract failed a release-bound invariant."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Rejected(message)


def exact_keys(value: object, expected: set[str], label: str) -> dict:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == expected, f"invalid {label} fields")
    return value


def strict_json_equal(value: object, expected: object) -> bool:
    """Compare JSON values without Python's bool/int equivalence."""
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return (set(value) == set(expected) and
                all(strict_json_equal(value[key], expected[key]) for key in expected))
    if isinstance(expected, list):
        return (len(value) == len(expected) and
                all(strict_json_equal(left, right)
                    for left, right in zip(value, expected)))
    return value == expected


def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON field: {key}")
        result[key] = value
    return result


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular(path: Path, label: str, maximum: int = MAX_JSON_BYTES) -> bytes:
    require(path.exists(), f"missing {label}: {path}")
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink(),
            f"{label} must be a regular non-link file")
    require(0 < metadata.st_size <= maximum, f"invalid {label} size")
    return path.read_bytes()


def read_json(path: Path, label: str) -> tuple[dict, bytes]:
    raw = read_regular(path, label)
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Rejected(f"invalid {label} JSON") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value, raw


def safe_text(value: object, label: str, maximum: int = 512) -> str:
    require(isinstance(value, str) and 0 < len(value) <= maximum,
            f"invalid {label}")
    require("\x00" not in value and "\n" not in value and "\r" not in value,
            f"invalid {label}")
    return value


def positive_int(value: object, label: str, allow_zero: bool = False) -> int:
    require(type(value) is int, f"{label} must be an integer")
    require(value >= (0 if allow_zero else 1), f"invalid {label}")
    return value


def canonical_path(value: object, label: str) -> str:
    text = safe_text(value, label, 256)
    candidate = PurePosixPath(text)
    require(not candidate.is_absolute() and text == candidate.as_posix(),
            f"unsafe {label}")
    require(text not in ("", ".") and ".." not in candidate.parts,
            f"unsafe {label}")
    return text


def parse_time(value: object) -> str:
    text = safe_text(value, "capture timestamp", 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise Rejected("invalid capture timestamp") from error
    require(parsed.tzinfo is not None and parsed.utcoffset() is not None,
            "capture timestamp must include a timezone")
    return text


def validate_contract(contract: dict) -> None:
    exact_keys(contract, {
        "schema_version", "classification", "product", "target", "fixture", "phases",
        "required_evidence_files", "traffic", "resource_bounds", "qualifications",
    }, "contract")
    require(type(contract["schema_version"]) is int and
            contract["schema_version"] == 1, "unsupported contract schema")
    require(contract["classification"] ==
            "routesphere-bonvoyage-oss-native-fresh-install-contract",
            "unexpected contract classification")
    require(contract["product"] == "BonVoyage API Gateway",
            "unexpected contract product")
    require(strict_json_equal(contract["target"], TARGET),
            "native target contract drift")
    require(strict_json_equal(contract["fixture"], FIXTURE),
            "native fixture contract drift")
    require(isinstance(contract["phases"], list), "contract phases must be an array")
    expected_phases = [
        {"id": phase, "required_checks": checks}
        for phase, checks in PHASE_CHECKS.items()
    ]
    require(strict_json_equal(contract["phases"], expected_phases),
            "native phase contract drift")
    require(strict_json_equal(contract["required_evidence_files"], EVIDENCE_FILES),
            "native evidence inventory drift")
    require(strict_json_equal(contract["traffic"], {
        "minimum_requests_per_route": 25,
        "expected_configured_routes": 2,
        "zero_counters": ZERO_COUNTERS,
    }), "native traffic contract drift")
    require(strict_json_equal(contract["resource_bounds"], RESOURCE_BOUNDS),
            "native resource bounds drift")
    require(strict_json_equal(contract["qualifications"], QUALIFICATIONS),
            "native qualification boundary drift")


def validate_build_receipt(receipt: dict, package: Path, package_raw: bytes) -> dict:
    required = {
        "schema_version", "classification", "outcome", "source", "distribution",
        "architecture", "debian_version", "package", "payload",
        "technical_candidate_built", "reproducibility_qualified", "sbom_qualified",
        "scan_qualified", "signature_qualified", "provenance_qualified",
        "lifecycle_qualified", "release_admitted", "publishable",
    }
    require(required.issubset(receipt), "incomplete Debian build receipt")
    require(type(receipt["schema_version"]) is int and
            receipt["schema_version"] == 1 and
            receipt["classification"] == BUILD_CLASS,
            "unexpected Debian build receipt")
    require(receipt["outcome"] == "built-technical-candidate" and
            receipt["technical_candidate_built"] is True,
            "Debian package is not a completed technical candidate")
    for field in (
        "reproducibility_qualified", "sbom_qualified", "scan_qualified",
        "signature_qualified", "provenance_qualified", "lifecycle_qualified",
        "release_admitted", "publishable",
    ):
        require(receipt[field] is False, f"build receipt escalates {field}")
    require(receipt["distribution"] == "ubuntu-24.04" and
            receipt["architecture"] == "amd64", "unsupported package target")

    source = exact_keys(receipt["source"], {
        "repository", "commit", "tag", "source_date_epoch", "dirty", "status_sha256",
    }, "build source")
    require(source["repository"] == PUBLIC_REPOSITORY and source["dirty"] is False,
            "package source is not a clean public-origin candidate")
    require(isinstance(source["commit"], str) and COMMIT.fullmatch(source["commit"]),
            "invalid package source commit")
    require(isinstance(source["tag"], str) and TAG.fullmatch(source["tag"]),
            "invalid package source tag")
    positive_int(source["source_date_epoch"], "source date epoch")
    require(isinstance(source["status_sha256"], str) and
            SHA256.fullmatch(source["status_sha256"]), "invalid source status digest")

    package_record = exact_keys(receipt["package"], {
        "path", "bytes", "sha256", "version", "architecture",
    }, "build package")
    require(package_record["path"] == package.name, "package filename does not match receipt")
    require(package_record["bytes"] == len(package_raw), "package size does not match receipt")
    require(package_record["sha256"] == sha256_bytes(package_raw),
            "package digest does not match receipt")
    require(package_record["version"] == receipt["debian_version"] and
            package_record["architecture"] == "amd64", "package identity mismatch")

    payload = receipt["payload"]
    require(isinstance(payload, dict), "build payload must be an object")
    binary = payload.get("usr/bin/bonvoyage-dataplane")
    require(isinstance(binary, dict) and isinstance(binary.get("sha256"), str) and
            SHA256.fullmatch(binary["sha256"]), "build receipt lacks dataplane identity")
    return {"source": source, "package": package_record, "binary": binary}


def validate_phases(phases: object) -> None:
    require(isinstance(phases, list) and len(phases) == len(PHASE_CHECKS),
            "incomplete native phase observations")
    for observed, (phase_id, required_checks) in zip(phases, PHASE_CHECKS.items()):
        item = exact_keys(observed, {"id", "passed", "checks"}, f"phase {phase_id}")
        require(item["id"] == phase_id and item["passed"] is True,
                f"phase did not pass: {phase_id}")
        checks = exact_keys(item["checks"], set(required_checks), f"phase {phase_id} checks")
        require(all(value is True for value in checks.values()),
                f"phase contains a failed check: {phase_id}")


def validate_evidence_files(evidence: Path, records: object) -> None:
    records = exact_keys(records, set(EVIDENCE_FILES), "evidence file inventory")
    actual: set[str] = set()
    total = 0
    for path in evidence.rglob("*"):
        relative = path.relative_to(evidence).as_posix()
        metadata = path.lstat()
        require(not stat.S_ISLNK(metadata.st_mode),
                f"unsupported evidence filesystem object: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        require(stat.S_ISREG(metadata.st_mode),
                f"unsupported evidence filesystem object: {relative}")
        if relative == "observation.json":
            continue
        actual.add(relative)
    require(actual == set(EVIDENCE_FILES), "evidence directory inventory mismatch")

    for relative in EVIDENCE_FILES:
        canonical_path(relative, "evidence path")
        record = exact_keys(records[relative], {"bytes", "sha256"},
                            f"evidence record {relative}")
        data = read_regular(evidence / relative, f"evidence file {relative}",
                            MAX_EVIDENCE_FILE_BYTES)
        positive_int(record["bytes"], f"evidence size {relative}")
        require(record["bytes"] == len(data), f"evidence size mismatch: {relative}")
        require(isinstance(record["sha256"], str) and SHA256.fullmatch(record["sha256"]),
                f"invalid evidence digest: {relative}")
        require(record["sha256"] == sha256_bytes(data),
                f"evidence digest mismatch: {relative}")
        total += len(data)
    require(total <= MAX_EVIDENCE_BYTES, "evidence set exceeds size bound")


def validate_command_log(evidence: Path) -> None:
    raw = read_regular(evidence / "raw/commands.jsonl", "command journal",
                       MAX_EVIDENCE_FILE_BYTES)
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise Rejected("command journal is not UTF-8") from error
    require(len(lines) == len(COMMAND_IDS), "command journal length mismatch")
    expected_returncodes = {
        "preflight-package-status": {1},
        "preflight-service-user": {2},
        "preflight-service-group": {2},
        "installed-service-enabled": {1},
        "installed-service-active": {3},
        "start-controlled-upstream": {None},
        "stop-controlled-upstream": {0, -15},
        "removed-service-enabled": {1},
        "removed-package-status": {0, 1},
    }
    for index, (line, command_id) in enumerate(zip(lines, COMMAND_IDS), start=1):
        try:
            record = json.loads(line, object_pairs_hook=reject_duplicate_pairs)
        except json.JSONDecodeError as error:
            raise Rejected(f"invalid command journal JSON at line {index}") from error
        common = {
            "schema_version", "id", "argv", "started_at", "duration_ms",
            "timed_out", "output_limit_exceeded", "returncode", "stdout_bytes",
            "stdout_sha256", "stderr_bytes", "stderr_sha256",
        }
        if command_id == "start-controlled-upstream":
            common.update({"pid", "uid", "gid"})
        item = exact_keys(record, common, f"command journal line {index}")
        require(item["schema_version"] == 1 and item["id"] == command_id,
                f"command journal order or schema mismatch at line {index}")
        require(isinstance(item["argv"], list) and item["argv"] and
                all(isinstance(value, str) and value and "\x00" not in value
                    for value in item["argv"]), "invalid command argument record")
        parse_time(item["started_at"])
        positive_int(item["duration_ms"], "command duration", allow_zero=True)
        positive_int(item["stdout_bytes"], "command stdout size", allow_zero=True)
        positive_int(item["stderr_bytes"], "command stderr size", allow_zero=True)
        require(item["stdout_bytes"] <= MAX_EVIDENCE_FILE_BYTES and
                item["stderr_bytes"] <= MAX_EVIDENCE_FILE_BYTES,
                "command output bound exceeded")
        require(isinstance(item["stdout_sha256"], str) and
                SHA256.fullmatch(item["stdout_sha256"]) and
                isinstance(item["stderr_sha256"], str) and
                SHA256.fullmatch(item["stderr_sha256"]),
                "invalid command output digest")
        require(item["timed_out"] is False and item["output_limit_exceeded"] is False,
                "command journal contains an incomplete command")
        allowed = expected_returncodes.get(command_id, {0})
        require(item["returncode"] in allowed,
                f"command journal contains a failed command: {command_id}")
        if command_id == "start-controlled-upstream":
            positive_int(item["pid"], "controlled upstream PID")
            positive_int(item["uid"], "controlled upstream UID")
            positive_int(item["gid"], "controlled upstream GID")


def metric_sum(text: str, metric: str) -> int:
    values: list[Decimal] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 2 or fields[0].split("{", 1)[0] != metric:
            continue
        try:
            value = Decimal(fields[1])
        except InvalidOperation as error:
            raise Rejected(f"invalid raw metric value: {metric}") from error
        require(value.is_finite(), f"non-finite raw metric value: {metric}")
        values.append(value)
    require(values, f"raw metric is absent: {metric}")
    total = sum(values, Decimal(0))
    require(total == total.to_integral_value(), f"non-integral raw metric: {metric}")
    return int(total)


def read_evidence_text(evidence: Path, relative: str) -> str:
    raw = read_regular(evidence / relative, f"evidence file {relative}",
                       MAX_EVIDENCE_FILE_BYTES)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Rejected(f"non-UTF-8 evidence file: {relative}") from error


def validate_raw_runtime_evidence(evidence: Path, traffic: dict,
                                  process: dict, contract: dict) -> None:
    before_text = read_evidence_text(evidence, "raw/metrics-before.txt")
    after_text = read_evidence_text(evidence, "raw/metrics-after.txt")
    before = {name: metric_sum(before_text, metric) for name, metric in METRICS.items()}
    after = {name: metric_sum(after_text, metric) for name, metric in METRICS.items()}
    require(after["requests"] - before["requests"] == traffic["request_delta"] and
            after["responses_2xx"] - before["responses_2xx"] ==
            traffic["response_2xx_delta"] and
            after["upstream_selections"] - before["upstream_selections"] ==
            traffic["upstream_selection_delta"],
            "raw metrics do not match the traffic observation")
    require(before["ready"] == after["ready"] == 1 and
            before["configured_routes"] == after["configured_routes"] ==
            contract["traffic"]["expected_configured_routes"],
            "raw readiness or route metrics mismatch")
    require(all(before[name] == after[name] == traffic["zero_counters"][name] == 0
                for name in ZERO_COUNTERS), "raw runtime error metrics are nonzero")

    socket_lines = read_evidence_text(evidence, "raw/socket-state.txt").splitlines()
    require(len(socket_lines) == 4, "filtered socket evidence length mismatch")
    sockets = []
    for index, line in enumerate(socket_lines, start=1):
        try:
            item = json.loads(line, object_pairs_hook=reject_duplicate_pairs)
        except json.JSONDecodeError as error:
            raise Rejected(f"invalid socket evidence at line {index}") from error
        sockets.append(exact_keys(item, {"role", "pid", "host", "port"},
                                  f"socket evidence line {index}"))
    gateway_pid = process["main_pid"]
    upstream_pids = {item["pid"] for item in sockets if item["role"] == "upstream"}
    require(len(upstream_pids) == 1, "controlled upstream socket identity mismatch")
    upstream_pid = next(iter(upstream_pids))
    positive_int(upstream_pid, "controlled upstream socket PID")
    observed_sockets = {(item["role"], item["pid"], item["host"], item["port"])
                        for item in sockets}
    expected_sockets = {
        ("gateway", gateway_pid, "0.0.0.0", 8080),
        ("gateway", gateway_pid, "127.0.0.1", 9090),
        ("gateway", gateway_pid, "127.0.0.1", 9901),
        ("upstream", upstream_pid, "127.0.0.1", 18081),
    }
    require(observed_sockets == expected_sockets,
            "filtered socket evidence topology mismatch")

    removed = {}
    for line in read_evidence_text(evidence, "raw/removed-state.txt").splitlines():
        key, separator, value = line.partition("=")
        require(separator == "=" and key and key not in removed,
                "invalid removed-state evidence")
        removed[key] = value
    require(removed.get("classification") == "oss-native-fresh-install-removed",
            "removed-state classification mismatch")
    for key in ("package_absent", "binary_absent", "package_unit_absent",
                "service_account_retained", "snapshot_retained",
                "operator_state_retained"):
        require(removed.get(key) == "true", f"removed-state invariant failed: {key}")
    require(removed.get("retained_snapshot_sha256") ==
            contract["fixture"]["snapshot"]["sha256"],
            "removed-state snapshot binding mismatch")
    for key in ("retained_identity_sha256", "retained_state_inventory_sha256"):
        require(isinstance(removed.get(key), str) and SHA256.fullmatch(removed[key]),
                f"invalid removed-state digest: {key}")


def verify(contract_path: Path, evidence: Path, package: Path, receipt_path: Path) -> dict:
    contract, contract_raw = read_json(contract_path, "native contract")
    validate_contract(contract)
    package_raw = read_regular(package, "Debian package", 512 * 1024 * 1024)
    receipt, receipt_raw = read_json(receipt_path, "Debian build receipt")
    build = validate_build_receipt(receipt, package, package_raw)
    observation_path = evidence / "observation.json"
    observation, observation_raw = read_json(observation_path, "native observation")

    exact_keys(observation, {
        "schema_version", "classification", "outcome", "captured_at", "contract",
        "source", "host", "package", "phases", "traffic", "process", "resources",
        "evidence_files", "qualifications",
    }, "native observation")
    require(type(observation["schema_version"]) is int and
            observation["schema_version"] == 1 and
            observation["classification"] == OBSERVATION_CLASS and
            observation["outcome"] == "passed", "native observation did not pass")
    parse_time(observation["captured_at"])

    contract_record = exact_keys(observation["contract"], {"path", "sha256"},
                                 "observation contract")
    require(contract_record["path"] == "packaging/release/debian/oss-native-fresh-install-contract.json",
            "unexpected contract path")
    require(contract_record["sha256"] == sha256_bytes(contract_raw),
            "observation contract digest mismatch")

    source = exact_keys(observation["source"], {"repository", "commit", "tag", "dirty"},
                        "observation source")
    require(strict_json_equal(
        source, {key: build["source"][key] for key in source}),
            "observation source does not match package source")

    host = exact_keys(observation["host"], {
        "distribution", "version_id", "architecture", "root_execution",
        "hostname_sha256", "kernel",
    }, "host observation")
    require(host["distribution"] == TARGET["distribution"] and
            host["version_id"] == TARGET["version_id"] and
            host["architecture"] == TARGET["architecture"] and
            host["root_execution"] is True, "unsupported or unprivileged native host")
    require(isinstance(host["hostname_sha256"], str) and
            SHA256.fullmatch(host["hostname_sha256"]), "invalid hostname digest")
    safe_text(host["kernel"], "kernel identity", 256)

    package_record = exact_keys(observation["package"], {
        "name", "version", "architecture", "bytes", "sha256",
        "build_receipt_sha256", "installed_binary_sha256",
    }, "package observation")
    positive_int(package_record["bytes"], "observed package size")
    require(package_record["name"] == TARGET["package"] and
            package_record["version"] == build["package"]["version"] and
            package_record["architecture"] == "amd64" and
            package_record["bytes"] == len(package_raw) and
            package_record["sha256"] == sha256_bytes(package_raw) and
            package_record["build_receipt_sha256"] == sha256_bytes(receipt_raw) and
            package_record["installed_binary_sha256"] == build["binary"]["sha256"],
            "observed package identity mismatch")
    require(VERSION.fullmatch(package_record["version"]) is not None,
            "invalid installed package version")

    validate_phases(observation["phases"])

    traffic = exact_keys(observation["traffic"], {
        "fixed_requests", "proxied_requests", "request_delta", "response_2xx_delta",
        "upstream_selection_delta", "configured_routes", "zero_counters",
    }, "traffic observation")
    fixed = positive_int(traffic["fixed_requests"], "fixed request count")
    proxied = positive_int(traffic["proxied_requests"], "proxied request count")
    require(fixed >= contract["traffic"]["minimum_requests_per_route"] and
            proxied >= contract["traffic"]["minimum_requests_per_route"],
            "insufficient bounded traffic")
    request_delta = positive_int(traffic["request_delta"], "request delta")
    response_2xx_delta = positive_int(traffic["response_2xx_delta"],
                                      "2xx response delta")
    upstream_selection_delta = positive_int(
        traffic["upstream_selection_delta"], "upstream selection delta")
    require(request_delta == fixed + proxied and
            response_2xx_delta == fixed + proxied and
            upstream_selection_delta == proxied,
            "traffic accounting mismatch")
    require(positive_int(traffic["configured_routes"], "configured route count") ==
            contract["traffic"]["expected_configured_routes"],
            "configured route count mismatch")
    counters = exact_keys(traffic["zero_counters"], set(ZERO_COUNTERS),
                          "runtime error counters")
    require(all(type(value) is int and value == 0 for value in counters.values()),
            "runtime error counters are nonzero")

    process = exact_keys(observation["process"], {
        "main_pid", "stable_identity", "automatic_restarts", "non_root",
        "binary_exact", "graceful_stop",
    }, "process observation")
    positive_int(process["main_pid"], "main process ID")
    require(process["stable_identity"] is True and process["non_root"] is True and
            process["binary_exact"] is True and process["graceful_stop"] is True,
            "process lifecycle invariant failed")
    automatic_restarts = positive_int(
        process["automatic_restarts"], "automatic restart count", allow_zero=True)
    require(automatic_restarts ==
            contract["resource_bounds"]["maximum_automatic_restarts"],
            "automatic restart bound exceeded")

    resources = exact_keys(observation["resources"], {
        "rss_start_kib", "rss_end_kib", "descriptor_start", "descriptor_end",
    }, "resource observation")
    rss_start = positive_int(resources["rss_start_kib"], "starting RSS")
    rss_end = positive_int(resources["rss_end_kib"], "ending RSS")
    fd_start = positive_int(resources["descriptor_start"], "starting descriptors")
    fd_end = positive_int(resources["descriptor_end"], "ending descriptors")
    require(rss_end - rss_start <= contract["resource_bounds"]["maximum_rss_growth_kib"],
            "RSS growth bound exceeded")
    require(fd_end - fd_start <=
            contract["resource_bounds"]["maximum_descriptor_growth"],
            "descriptor growth bound exceeded")

    require(strict_json_equal(observation["qualifications"], QUALIFICATIONS),
            "observation qualification boundary mismatch")
    validate_evidence_files(evidence, observation["evidence_files"])
    validate_command_log(evidence)
    validate_raw_runtime_evidence(evidence, traffic, process, contract)

    return {
        "schema_version": 1,
        "classification": REPORT_CLASS,
        "outcome": "verified",
        "source_commit": source["commit"],
        "source_tag": source["tag"],
        "contract_sha256": sha256_bytes(contract_raw),
        "observation_sha256": sha256_bytes(observation_raw),
        "package_sha256": sha256_bytes(package_raw),
        "build_receipt_sha256": sha256_bytes(receipt_raw),
        "fresh_install_qualified": True,
        "upgrade_qualified": False,
        "rollback_qualified": False,
        "kubernetes_qualified": False,
        "benchmark_reproduction_qualified": False,
        "release_admitted": False,
        "publishable": False,
    }


def write_new(path: Path, document: dict) -> None:
    require(not path.exists() and not path.is_symlink(), "verification output must be new")
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    try:
        require(arguments.evidence.is_dir() and not arguments.evidence.is_symlink(),
                "evidence must be a real directory")
        if arguments.output is not None:
            require(not is_within(arguments.output, arguments.evidence),
                    "verification output must remain outside observed evidence")
        report = verify(arguments.contract, arguments.evidence,
                        arguments.package, arguments.build_receipt)
        if arguments.output is None:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            write_new(arguments.output, report)
            print(str(arguments.output))
        return 0
    except (OSError, Rejected) as error:
        print(f"OSS native fresh-install evidence rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
