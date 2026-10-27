#!/usr/bin/env python3
"""Preserve dpkg ownership for the copied runtime closure, not the build image."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def query(*args):
    return subprocess.check_output(["dpkg-query", *args], text=True).rstrip("\n")


def digest(path, algorithm="sha256"):
    checksum = hashlib.new(algorithm, usedforsecurity=False)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


# Ubuntu 24.04 runtime floor from USN-8626-1. This prevents stale build
# dependencies from reintroducing known fixes; it is not a scanner waiver.
PACKAGE_FLOORS = {"libudev1": ("systemd", "255.4-1ubuntu8.17", "USN-8626-1")}


def debian_version_at_least(version, minimum):
    result = subprocess.run(["dpkg", "--compare-versions", version, "ge", minimum],
                            capture_output=True, text=True, timeout=10)
    if result.returncode not in (0, 1):
        raise ValueError(f"dpkg version comparison failed: {result.stderr.strip()}")
    return result.returncode == 0


def verify_package_floors(packages, compare=debian_version_at_least):
    for package in packages.values():
        floor = PACKAGE_FLOORS.get(package["name"])
        if floor is None:
            continue
        source, minimum, advisory = floor
        if package["source"] != source:
            raise ValueError(f"{package['name']} requires source package {source}")
        for field in ("version", "source_version"):
            if not compare(package[field], minimum):
                raise ValueError(f"{package['name']} {field} {package[field]} is below "
                                 f"{minimum} ({advisory}); refresh build dependencies")


def build_index(root, libraries, lookup=query):
    root = root.resolve(strict=True)
    paths = libraries.read_text().splitlines()
    if not paths or len(paths) > 1024 or len(set(paths)) != len(paths):
        raise ValueError("bounded, nonempty, unique runtime library paths required")
    packages = {}
    package_checksums = {}
    for value in paths:
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts or str(path) != value:
            raise ValueError("canonical absolute runtime path required")
        source = path.resolve(strict=True)
        copied = root / path.relative_to("/")
        if (not source.is_file() or not copied.is_file() or copied.is_symlink()
                or not copied.resolve().is_relative_to(root)):
            raise ValueError("regular copied library within runtime root required")
        sha256 = digest(source)
        if digest(copied) != sha256:
            raise ValueError(f"copied library differs from dpkg-owned file: {value}")
        # A build-host /lib alias may resolve to /usr/lib. Query the real owner,
        # but record the path that actually exists in the scratch filesystem.
        ownership = lookup("-S", str(source)).splitlines()
        if len(ownership) != 1 or not ownership[0].endswith(f": {source}"):
            raise ValueError(f"exactly one dpkg owner required: {value}")
        owner = ownership[0].removesuffix(f": {source}")
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?", owner):
            raise ValueError(f"ambiguous dpkg owner: {owner}")
        if owner not in packages:
            fields = lookup("-W", "-f=${Package}\t${Architecture}\t${Version}\t"
                            "${source:Package}\t${source:Version}\t${Status}", owner).split("\t")
            if len(fields) != 6 or any(not v or "\n" in v or "\r" in v for v in fields):
                raise ValueError("complete binary/source package identity required")
            name, arch, version, source_name, source_version, status = fields
            if (owner not in (name, f"{name}:{arch}") or status != "install ok installed"
                    or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name)
                    or not re.fullmatch(r"[a-z0-9-]+", arch)
                    or not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", source_name)):
                raise ValueError("installed, unambiguous dpkg identity required")
            packages[owner] = dict(name=name, architecture=arch, version=version,
                                   source=source_name, source_version=source_version, files=[])
            checksum_file = Path(lookup("--control-path", owner, "md5sums"))
            package_checksums[owner] = {}
            for line in checksum_file.read_text().splitlines():
                match = re.fullmatch(r"([a-f0-9]{32})  (.+)", line)
                if not match or match[2] in package_checksums[owner]:
                    raise ValueError("unambiguous original dpkg checksums required")
                package_checksums[owner][match[2]] = match[1]
        expected_md5 = package_checksums[owner].get(str(source).lstrip("/"))
        if not expected_md5 or digest(source, "md5") != expected_md5:
            raise ValueError(f"library does not match original dpkg checksum: {value}")
        packages[owner]["files"].append(dict(path=value, build_path=str(source),
                                           sha256=sha256, package_md5=expected_md5))

    # Validate everything before creating output; never rewrite an old index.
    verify_package_floors(packages)
    info = root / "var/lib/dpkg/info"
    if info.exists() or (root / "var/lib/dpkg/status").exists():
        raise ValueError("runtime package index destination must be new")
    info.mkdir(parents=True)
    stanzas = []
    for owner, package in sorted(packages.items()):
        package["files"].sort(key=lambda item: item["path"])
        (info / f"{owner}.list").write_text("".join(f'{f["path"]}\n' for f in package["files"]))
        # Syft consumes md5sums for dpkg file ownership, not .list. MD5 here is
        # the original package integrity record, not our evidence trust anchor.
        (info / f"{owner}.md5sums").write_text("".join(
            f'{f["package_md5"]}  {f["path"].lstrip("/")}\n' for f in package["files"]))
        stanzas.append(f'Package: {package["name"]}\nStatus: install ok installed\n'
                       f'Architecture: {package["architecture"]}\nVersion: {package["version"]}\n'
                       f'Source: {package["source"]} ({package["source_version"]})\n\n')
    (root / "var/lib/dpkg/status").write_text("".join(stanzas))
    manifest = root / "usr/share/bonvoyage/runtime-package-ownership.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("x") as stream:
        json.dump({"schema_version": 1, "scope": "copied runtime shared-library closure",
                   "packages": packages}, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return packages


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--libraries", type=Path, required=True)
    args = parser.parse_args()
    build_index(args.root, args.libraries)
