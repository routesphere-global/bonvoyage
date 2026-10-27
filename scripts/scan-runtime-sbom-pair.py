#!/usr/bin/env python3
"""Rebind one image and scan both SBOM representations against one offline DB.

This is format/matcher qualification, not a complete SBOM coverage, package,
publisher-authenticity or release acceptance assertion. No gateway is started.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parent
TOOLING_FILES = ("scan-runtime-sbom-pair.py", "verify-runtime-image-binding.py",
                 "verify-runtime-scan-parity.mjs", "summarize-vulnerability-scan.mjs")
SYFT = "anchore/syft:v1.44.0@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6"
GRYPE = "anchore/grype:v0.116.1@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db"
spec = importlib.util.spec_from_file_location("binding", ROOT / "verify-runtime-image-binding.py")
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)


def write_json(path, data):
    with path.open("x") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tooling_snapshot():
    return {name: file_hash(ROOT / name) for name in TOOLING_FILES}


def database_snapshot(directory):
    """Hash the actual retained DB and import metadata, not just its date label."""
    binding.require((directory / "6/vulnerability.db").is_file(), "v6 database payload required")
    files = {}
    for path in sorted(directory.rglob("*")):
        binding.require(not path.is_symlink(), "database symlink rejected")
        if path.is_dir():
            continue
        binding.require(path.is_file() and path.stat().st_size <= 8 * 1024**3,
                        "bounded regular database file required")
        files[str(path.relative_to(directory))] = {"sha256": file_hash(path), "bytes": path.stat().st_size}
    return files


def container(image, *, database=None, online=False):
    uid, gid = os.getuid(), os.getgid()
    args = ["docker", "run", "--rm", "--pull", "never", "--network", "bridge" if online else "none",
            "--read-only", "--user", f"{uid}:{gid}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--cpus", "2", "--memory", "4g", "--pids-limit", "256",
            "--tmpfs", f"/tmp:rw,noexec,nosuid,size=768m,mode=0700,uid={uid},gid={gid}",
            "--tmpfs", f"/.cache:rw,noexec,nosuid,size=32m,mode=0700,uid={uid},gid={gid}"]
    if image == SYFT:
        binding.require(not online and database is None, "decoder must be offline without a database")
        args += ["--env", "SYFT_CHECK_FOR_APP_UPDATE=false"]
    else:
        binding.require(image == GRYPE and database is not None, "pinned scanner and explicit database required")
        args += ["--volume", f"{database}:/database:{'rw' if online else 'ro'}"]
        for env in ["GRYPE_CHECK_FOR_APP_UPDATE=false", "GRYPE_TIMESTAMP=true", "GRYPE_DB_CACHE_DIR=/database",
                    "GRYPE_EXTERNAL_SOURCES_ENABLE=false", "GRYPE_ADD_CPES_IF_NONE=false",
                    "GRYPE_DB_AUTO_UPDATE=false", "GRYPE_DB_VALIDATE_BY_HASH_ON_START=true",
                    "GRYPE_DB_VALIDATE_AGE=true", "GRYPE_DB_MAX_ALLOWED_BUILT_AGE=48h"]:
            args += ["--env", env]
    return args


def command(out, name, argv, allowed=(0,), timeout=600):
    container_name = None
    if argv[:2] == ["docker", "run"]:
        container_name = "bonvoyage-sbom-" + uuid.uuid4().hex
        argv = [*argv[:2], "--name", container_name, *argv[2:]]
    started = time.time()
    code = None
    failure = None
    cleanup_receipt = None
    with (out / (name + ".stdout")).open("xb") as stdout, (out / (name + ".stderr")).open("xb") as stderr:
        try:
            code = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout, check=False).returncode
        except subprocess.TimeoutExpired:
            failure = "command timed out"
            if container_name:
                # A timed-out Docker client does not necessarily stop its
                # container. Remove only the exact name allocated by this call.
                cleanup_receipt = {"container": container_name, "exit_code": None,
                                   "failure": None, "stdout": "", "stderr": ""}
                try:
                    cleanup = subprocess.run(["docker", "rm", "--force", container_name],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
                    cleanup_receipt.update(exit_code=cleanup.returncode,
                        stdout=cleanup.stdout.decode(errors="replace"), stderr=cleanup.stderr.decode(errors="replace"))
                except subprocess.TimeoutExpired as error:
                    cleanup_receipt.update(failure="container cleanup timed out",
                        stdout=(error.stdout or b"").decode(errors="replace"),
                        stderr=(error.stderr or b"").decode(errors="replace"))
                except OSError as error:
                    cleanup_receipt["failure"] = str(error)
        except OSError as error:
            failure = str(error)
    write_json(out / (name + ".command.json"), {"argv": argv, "exit_code": code, "failure": failure,
               "started_unix": started, "elapsed_seconds": time.time() - started,
               "stdout_sha256": file_hash(out / (name + ".stdout")),
               "stderr_sha256": file_hash(out / (name + ".stderr"))})
    if cleanup_receipt is not None:
        write_json(out / (name + ".cleanup.json"), cleanup_receipt)
    binding.require(failure is None and code in allowed, f"{name} failed; retained command and stderr explain why")
    binding.require((out / (name + ".stdout")).stat().st_size <= 64 * 1024**2, "bounded command JSON required")
    return code


def scan_pair(evidence, out, image_id, platform):
    evidence = evidence.resolve(strict=True)
    binding.require(not out.exists(), "new scan-pair output directory required")
    out.mkdir(mode=0o700)
    out = out.resolve(strict=True)
    tooling_before = tooling_snapshot()
    write_json(out / "tooling-before.json", tooling_before)
    inputs = [evidence / name for name in
              ("runtime.oci.tar", "runtime.raw.syft.json", "runtime.cdx.json", "runtime.syft.spdx.json")]
    # Never accept a supplied binding receipt as the trust anchor. Recompute
    # it from the independently selected image lock and current input bytes.
    verified = binding.verify(inputs[0], image_id, *inputs[1:], platform)
    write_json(out / "binding.json", verified)
    for kind, source in (("cdx", inputs[2]), ("spdx", inputs[3])):
        command(out, "decode-" + kind, container(SYFT) +
                ["--volume", f"{source}:/input.json:ro", SYFT, "convert", "/input.json", "-o", "syft-json"])
    compare = ["node", str(ROOT / "verify-runtime-scan-parity.mjs"), str(out / "binding.json"),
               str(out / "decode-cdx.stdout"), str(out / "decode-spdx.stdout")]
    command(out, "decoder-parity", compare)
    binding.require(shutil.disk_usage(out).free >= 8 * 1024**3, "8 GiB free disk required before database hydration")
    database = out / "database"
    database.mkdir(mode=0o700)
    # Only hydration has network access. Both scans get the same read-only DB,
    # no Docker socket and no writable SBOM mount; retain it for offline replay.
    command(out, "database-update", container(GRYPE, database=database, online=True) + [GRYPE, "db", "update"])
    before = database_snapshot(database)
    write_json(out / "database-before.json", before)
    command(out, "database-status", container(GRYPE, database=database) + [GRYPE, "db", "status", "-o", "json"])
    for kind, source in (("cdx", inputs[2]), ("spdx", inputs[3])):
        command(out, "scan-" + kind, container(GRYPE, database=database) +
                ["--volume", f"{source}:/input.json:ro", GRYPE, "sbom:/input.json", "-o", "json"])
        snapshot = database_snapshot(database)
        write_json(out / ("database-after-" + kind + ".json"), snapshot)
        binding.require(snapshot == before, "database changed between scans")
    code = command(out, "scan-parity", compare + [str(out / "scan-cdx.stdout"), str(out / "scan-spdx.stdout")], allowed=(0, 1))
    binding.require(verified == binding.verify(inputs[0], image_id, *inputs[1:], platform), "scan inputs changed")
    result = json.loads((out / "scan-parity.stdout").read_text())
    result["database_files"] = before
    result["input_sha256"] = verified["input_sha256"]
    result["tool_images"] = {"syft": SYFT, "grype": GRYPE}
    result["runner_sha256"] = tooling_before
    # Build the seal before publishing a result, then recheck the retained DB
    # and tooling so late drift cannot produce a completed qualification.
    checksums = {str(p.relative_to(out)): file_hash(p)
                 for p in sorted(out.rglob("*")) if p.is_file()}
    final_database = database_snapshot(database)
    write_json(out / "database-final.json", final_database)
    tooling_after = tooling_snapshot()
    write_json(out / "tooling-after.json", tooling_after)
    binding.require(tooling_before == tooling_after, "scan tooling changed")
    binding.require(final_database == before, "database changed before evidence seal")
    sealed_database = {name[len("database/"):]: digest for name, digest in checksums.items()
                       if name.startswith("database/")}
    binding.require(sealed_database == {name: record["sha256"] for name, record in before.items()},
                    "database changed while sealing evidence")
    write_json(out / "result.json", result)
    for name in ("database-final.json", "tooling-after.json", "result.json"):
        checksums[name] = file_hash(out / name)
    write_json(out / "evidence-checksums.json", checksums)
    return code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-image-id", required=True)
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), default="linux/amd64")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        sys.exit(scan_pair(args.evidence_dir, args.output, args.expected_image_id, args.platform))
    except (ValueError, OSError, RuntimeError) as error:
        print(f"invalid dual-format scan: {error}", file=sys.stderr)
        sys.exit(2)
