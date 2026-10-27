#!/usr/bin/env python3
"""Create a checksum-bound OSS Debian input manifest from reviewed files."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess


BUILDER_PATH = Path(__file__).with_name("build-oss-deb.py")
SPEC = importlib.util.spec_from_file_location("bonvoyage_oss_deb_builder", BUILDER_PATH)
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


def git_text(root, *arguments):
    return subprocess.run(
        ["git", "-C", str(root), *arguments], check=True, capture_output=True,
        text=True, timeout=30,
    ).stdout.strip()


def file_record(base, path, maximum):
    BUILDER.require(path.is_file() and not path.is_symlink(), "regular input file required")
    resolved_base = base.resolve()
    resolved = path.resolve()
    BUILDER.require(resolved.is_relative_to(resolved_base),
                    "input files must be inside the manifest directory")
    relative = resolved.relative_to(resolved_base).as_posix()
    data = path.read_bytes()
    BUILDER.require(0 < len(data) <= maximum, "input file has invalid size")
    return {"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def create(source_root, release_version, package_revision, maintainer,
           dataplane, copyright_path, toolchain_lock, output):
    BUILDER.semver_to_debian(release_version, package_revision)
    BUILDER.require(BUILDER.MAINTAINER.fullmatch(maintainer) is not None,
                    "explicit single-line maintainer required")
    BUILDER.require(not output.exists() and not output.is_symlink(), "new manifest output required")
    BUILDER.require(output.parent.is_dir(), "manifest output directory must already exist")
    BUILDER.require(not output.parent.resolve().is_relative_to(source_root.resolve()),
                    "manifest and artifact inputs must remain outside the source repository")
    commit = git_text(source_root, "rev-parse", "HEAD")
    epoch = int(git_text(source_root, "show", "-s", "--format=%ct", "HEAD"))
    document = {
        "schema_version": 1,
        "classification": BUILDER.INPUT_CLASS,
        "product": BUILDER.PRODUCT,
        "source_repository": BUILDER.PUBLIC_REPOSITORY,
        "source_commit": commit,
        "source_tag": "v" + release_version,
        "release_version": release_version,
        "package_revision": package_revision,
        "distribution": "ubuntu-24.04",
        "architecture": "amd64",
        "maintainer": maintainer,
        "source_date_epoch": epoch,
        "files": {
            "dataplane": file_record(output.parent, dataplane, 512 * 1024 * 1024),
            "copyright": file_record(output.parent, copyright_path, 2 * 1024 * 1024),
            "toolchain_lock": file_record(output.parent, toolchain_lock, 4 * 1024 * 1024),
        },
    }
    BUILDER.source_state(document, source_root)
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = output.with_name(output.name + ".tmp")
    BUILDER.require(not temporary.exists() and not temporary.is_symlink(),
                    "new temporary manifest output required")
    temporary.write_bytes(encoded)
    temporary.replace(output)
    return document, hashlib.sha256(encoded).hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--package-revision", required=True, type=int)
    parser.add_argument("--maintainer", required=True)
    parser.add_argument("--dataplane", required=True, type=Path)
    parser.add_argument("--copyright", required=True, type=Path)
    parser.add_argument("--toolchain-lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    os.umask(0o077)
    try:
        document, manifest_digest = create(
            arguments.source_root.absolute(), arguments.release_version,
            arguments.package_revision, arguments.maintainer,
            arguments.dataplane.absolute(), arguments.copyright.absolute(),
            arguments.toolchain_lock.absolute(), arguments.output.absolute(),
        )
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise SystemExit("OSS Debian input creation rejected: " + str(error)) from error
    print(json.dumps({"source_commit": document["source_commit"],
                      "source_tag": document["source_tag"],
                      "manifest_sha256": manifest_digest}, indent=2, sort_keys=True))
