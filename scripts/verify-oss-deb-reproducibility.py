#!/usr/bin/env python3
"""Compare two OSS Debian builder outputs without granting release authority."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re


SHA256 = re.compile(r"[a-f0-9]{64}")
BUILD_CLASS = "routesphere-bonvoyage-oss-deb-build"
REPRO_CLASS = "routesphere-bonvoyage-oss-deb-reproducibility"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def object_pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def load_receipt(directory):
    require(directory.is_dir() and not directory.is_symlink(), "regular build directory required")
    path = directory / "build-receipt.json"
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4 * 1024 * 1024,
            "bounded regular build receipt required")
    raw = path.read_bytes()
    try:
        receipt = json.loads(raw, object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid build receipt JSON") from error
    require(isinstance(receipt, dict) and receipt.get("classification") == BUILD_CLASS and
            receipt.get("outcome") == "built-technical-candidate" and
            receipt.get("technical_candidate_built") is True,
            "successful OSS Debian technical-candidate receipt required")
    source = receipt.get("source")
    require(isinstance(source, dict) and source.get("repository") ==
            "https://github.com/routesphere-global/bonvoyage" and source.get("dirty") is False,
            "clean public source identity required")
    for gate in ("reproducibility_qualified", "sbom_qualified", "scan_qualified",
                 "signature_qualified", "provenance_qualified", "lifecycle_qualified",
                 "release_admitted", "publishable"):
        require(receipt.get(gate) is False, "builder receipt must not grant release authority")
    package = receipt.get("package")
    require(isinstance(package, dict) and set(package) == {
        "path", "bytes", "sha256", "version", "architecture"}, "invalid package identity")
    require(isinstance(package["sha256"], str) and SHA256.fullmatch(package["sha256"]) and
            type(package["bytes"]) is int and package["bytes"] > 0,
            "invalid package byte identity")
    package_path = directory / package["path"]
    require(package_path.parent == directory and package_path.is_file() and not package_path.is_symlink(),
            "regular package file required")
    data = package_path.read_bytes()
    require(len(data) == package["bytes"] and digest(data) == package["sha256"],
            "package bytes do not match builder receipt")
    return receipt, data, digest(raw)


def compare(first_directory, second_directory):
    require(first_directory.resolve() != second_directory.resolve(), "two distinct build directories required")
    first, first_bytes, first_receipt_sha256 = load_receipt(first_directory)
    second, second_bytes, second_receipt_sha256 = load_receipt(second_directory)
    require(first.get("builder_id") != second.get("builder_id"), "two distinct builder IDs required")
    for field in ("source", "binding", "distribution", "architecture", "release_version",
                  "debian_version", "command", "exit_code", "payload", "control", "package"):
        require(first.get(field) == second.get(field), "build receipts differ at " + field)
    require(first_bytes == second_bytes, "Debian package bytes are not reproducible")
    package = first["package"]
    return {
        "schema_version": 1,
        "classification": REPRO_CLASS,
        "outcome": "byte-identical-technical-candidates",
        "source": first["source"],
        "binding": first["binding"],
        "builders": [first["builder_id"], second["builder_id"]],
        "build_receipts": [
            {"builder_id": first["builder_id"], "sha256": first_receipt_sha256},
            {"builder_id": second["builder_id"], "sha256": second_receipt_sha256},
        ],
        "verifier_sha256": digest(Path(__file__).read_bytes()),
        "package": package,
        "technical_reproducibility_observed": True,
        "hosted_builder_independence_qualified": False,
        "release_admitted": False,
        "publishable": False,
    }


def write_receipt(path, receipt):
    require(not path.exists() and not path.is_symlink(), "new reproducibility receipt required")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    require(not temporary.exists() and not temporary.is_symlink(),
            "new temporary reproducibility receipt required")
    temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first", required=True, type=Path)
    parser.add_argument("--second", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    os.umask(0o077)
    try:
        result = compare(arguments.first.absolute(), arguments.second.absolute())
        write_receipt(arguments.output.absolute(), result)
    except (OSError, ValueError) as error:
        raise SystemExit("OSS Debian reproducibility check rejected: " + str(error)) from error
    print(json.dumps(result, indent=2, sort_keys=True))
