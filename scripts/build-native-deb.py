#!/usr/bin/env python3
"""Assemble a private Ubuntu AMD64 gateway package from checksum-reviewed inputs."""

import argparse
from datetime import datetime, timezone
import email.utils
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import struct
import subprocess
import tarfile
from email.parser import Parser

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ("control", "rules", "postinst", "preinst", "README.Debian")
SHA = re.compile(r"[a-f0-9]{64}")
COMMIT = re.compile(r"[a-f0-9]{40}")
VERSION = re.compile(r"[0-9][0-9A-Za-z.+~]*-[1-9][0-9]*")


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


def read_input(root, record, maximum):
    require(isinstance(record, dict) and set(record) == {"path", "sha256", "bytes"}, "invalid file record")
    name = record["path"]
    require(isinstance(name, str), "invalid file path")
    relative = PurePosixPath(name)
    require(name and str(relative) == name and not relative.is_absolute() and
            all(part not in (".", "..") for part in relative.parts), "unsafe file path")
    require(isinstance(record["sha256"], str) and SHA.fullmatch(record["sha256"]), "invalid file digest")
    require(type(record["bytes"]) is int and 0 < record["bytes"] <= maximum, "invalid file size")
    target = root.joinpath(*relative.parts)
    for part in (target, *target.parents):
        if part == root:
            break
        require(not part.is_symlink(), "symlink in input path")
    require(target.is_file() and target.resolve().is_relative_to(root.resolve()), "missing/unsafe input file")
    require(target.stat().st_size == record["bytes"], "input size mismatch")
    data = target.read_bytes()
    require(len(data) == record["bytes"] and digest(data) == record["sha256"], "input digest mismatch")
    return data


def load_inputs(manifest, anchor):
    require(isinstance(anchor, str) and SHA.fullmatch(anchor), "reviewed manifest digest required")
    require(manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_size <= 1024 * 1024,
            "bounded regular manifest required")
    raw = manifest.read_bytes()
    require(digest(raw) == anchor, "manifest digest mismatch")
    spec = json.loads(raw, object_pairs_hook=object_pairs)
    require(isinstance(spec, dict) and set(spec) == {
        "schema_version", "classification", "distribution", "architecture", "version", "maintainer",
        "producer_source_commit", "source_date_epoch", "files"}, "invalid input manifest fields")
    require(type(spec["schema_version"]) is int and spec["schema_version"] == 1, "unsupported manifest schema")
    require(spec["classification"] == "private-native-gateway-input", "unsupported package class")
    require(spec["distribution"] == "ubuntu-24.04" and spec["architecture"] == "amd64", "unsupported native platform")
    require(isinstance(spec["version"], str) and VERSION.fullmatch(spec["version"]), "invalid Debian version")
    require(isinstance(spec["maintainer"], str) and len(spec["maintainer"]) <= 200 and
            re.fullmatch(r"[A-Za-z0-9 ._-]+ <[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+>", spec["maintainer"]),
            "explicit single-line maintainer required")
    require(isinstance(spec["producer_source_commit"], str) and COMMIT.fullmatch(spec["producer_source_commit"]),
            "producer source commit required")
    require(type(spec["source_date_epoch"]) is int and 0 < spec["source_date_epoch"] <= 4102444800,
            "invalid source date epoch")
    require(isinstance(spec["files"], dict) and set(spec["files"]) == {"dataplane", "copyright"}, "invalid payload files")
    require(spec["files"]["dataplane"] != spec["files"]["copyright"], "duplicate payload record")
    data = {"dataplane": read_input(manifest.parent, spec["files"]["dataplane"], 256 * 1024 * 1024),
            "copyright": read_input(manifest.parent, spec["files"]["copyright"], 1024 * 1024)}
    elf = data["dataplane"]
    require(len(elf) >= 64 and elf[:7] == b"\x7fELF\x02\x01\x01" and
            struct.unpack_from("<HH", elf, 16)[0] in (2, 3) and
            struct.unpack_from("<H", elf, 18)[0] == 62 and struct.unpack_from("<Q", elf, 24)[0] > 0,
            "AMD64 executable ELF required")
    require(b"\x00" not in data["copyright"] and data["copyright"].decode("utf-8").strip(),
            "explicit copyright/license text required; no automatic OSS license grant")
    return spec, data


def source_state(root):
    def git(*args):
        return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout
    status = git("status", "--porcelain=v1", "--untracked-files=all")
    return {"commit": git("rev-parse", "HEAD").strip(), "dirty": bool(status.strip()),
            "status_sha256": digest(status.encode())}


def verify_payload_tar(data, spec, unit, readme):
    expected = {
        "usr/bin/bonvoyage-dataplane": spec["files"]["dataplane"]["sha256"],
        "usr/share/doc/bonvoyage-gateway/copyright": spec["files"]["copyright"]["sha256"],
        "usr/share/doc/bonvoyage-gateway/README.Debian": digest(readme),
    }
    found = {}
    root_seen = False
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            if member.name in (".", "./"):
                require(not root_seen and member.isdir() and member.uid == 0 and member.gid == 0 and
                        member.mode == 0o755, "invalid/duplicate archive root")
                root_seen = True
                continue
            name = member.name.removeprefix("./").rstrip("/")
            require(str(PurePosixPath(name)) == name and not name.startswith("/") and
                    ".." not in PurePosixPath(name).parts and name not in found, "unsafe/duplicate package member")
            require(member.uid == 0 and member.gid == 0, "package ownership must be root")
            require(member.isfile() or member.isdir(), "links/special files not allowed in package payload")
            require(member.mode == (0o755 if member.isdir() or name == "usr/bin/bonvoyage-dataplane" else 0o644),
                    "unexpected package mode")
            found[name] = member.isdir()
            if member.isdir():
                require(name in {"usr", "usr/bin", "lib", "lib/systemd", "lib/systemd/system",
                                 "usr/lib", "usr/lib/systemd", "usr/lib/systemd/system", "usr/share",
                                 "usr/share/doc", "usr/share/doc/bonvoyage-gateway"}, "unexpected package directory")
                continue
            require(member.size <= 256 * 1024 * 1024, "oversized package payload")
            with archive.extractfile(member) as stream:
                body = stream.read()
            if name in {"lib/systemd/system/bonvoyage.service", "usr/lib/systemd/system/bonvoyage.service"}:
                require(body == unit, "packaged service contract mismatch")
            elif name == "usr/share/doc/bonvoyage-gateway/changelog.Debian.gz":
                require(member.size <= 1024 * 1024, "oversized changelog")
            else:
                require(name in expected and digest(body) == expected[name], "unexpected/corrupt package file")
    require(all(name in found for name in expected), "missing package payload")
    require(sum(name in found for name in ["lib/systemd/system/bonvoyage.service",
                                           "usr/lib/systemd/system/bonvoyage.service"]) == 1, "one packaged unit required")
    return len([name for name, directory in found.items() if not directory])


def prepare_tree(manifest, anchor, output, root=ROOT):
    spec, payload = load_inputs(manifest, anchor)
    templates = {name: (root / "packaging/debian" / name).read_bytes() for name in TEMPLATES}
    unit = (root / "packaging/systemd/bonvoyage.service").read_bytes()
    require(unit.count(b"/usr/local/bin/bonvoyage-dataplane") == 1, "source service contract drift")
    require(not output.exists() and not output.is_symlink(), "new output directory required")
    output.mkdir(mode=0o700)
    tree = output / "work"
    (tree / "debian/source").mkdir(parents=True)
    (tree / "input").mkdir()
    for name, data in templates.items():
        text = data.decode("utf-8")
        if name == "control":
            text = text.replace("@MAINTAINER@", spec["maintainer"])
        filename = {"postinst": "bonvoyage-gateway.postinst", "preinst": "bonvoyage-gateway.preinst",
                    "README.Debian": "bonvoyage-gateway.README.Debian"}.get(name, name)
        (tree / "debian" / filename).write_text(text, encoding="utf-8")
    (tree / "debian/rules").chmod(0o755)
    for script in ("postinst", "preinst"):
        (tree / "debian" / ("bonvoyage-gateway." + script)).chmod(0o755)
    (tree / "debian/bonvoyage-gateway.bonvoyage.service").write_bytes(
        unit.replace(b"/usr/local/bin/bonvoyage-dataplane", b"/usr/bin/bonvoyage-dataplane"))
    (tree / "input/bonvoyage-dataplane").write_bytes(payload["dataplane"])
    (tree / "input/bonvoyage-dataplane").chmod(0o755)
    (tree / "debian/copyright").write_bytes(payload["copyright"])
    (tree / "debian/source/format").write_text("3.0 (quilt)\n", encoding="ascii")
    date = email.utils.format_datetime(datetime.fromtimestamp(spec["source_date_epoch"], timezone.utc))
    changelog = (f"bonvoyage-gateway ({spec['version']}) noble; urgency=medium\n\n"
                 f"  * Private packaging of a reviewed executable; not a signed public release.\n\n"
                 f" -- {spec['maintainer']}  {date}\n")
    (tree / "debian/changelog").write_text(changelog, encoding="ascii")
    (output / "input-manifest.json").write_bytes(manifest.read_bytes())
    return spec, {"manifest_sha256": anchor, "source_files": {
        "packaging/debian/" + name: digest(data) for name, data in templates.items()},
        "source_unit_sha256": digest(unit), "builder_sha256": digest(Path(__file__).read_bytes())}


def build(manifest, anchor, output):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Ubuntu AMD64 build host required")
    os_release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    require(os_release.get("ID", "").strip('"') == "ubuntu" and
            os_release.get("VERSION_ID", "").strip('"') == "24.04", "Ubuntu 24.04 build host required")
    for command in ("dpkg-buildpackage", "dh", "dpkg-deb"):
        require(shutil.which(command), "missing native build tool: " + command)
    before = source_state(ROOT)
    spec, binding = prepare_tree(manifest, anchor, output)
    receipt = {"schema_version": 1, "classification": "private-native-gateway-build",
               "outcome": "building", "packaging_source": before, "producer_source_commit": spec["producer_source_commit"],
               "binding": binding, "architecture": "amd64", "distribution": "ubuntu-24.04",
               "package_accepted": False, "sbom_qualified": False, "scan_qualified": False,
               "tuning_adapter_compatible": False, "publishable": False}
    receipt_path = output / "build-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    command = ["dpkg-buildpackage", "-us", "-uc", "-b"]
    env = {**os.environ, "SOURCE_DATE_EPOCH": str(spec["source_date_epoch"]), "LC_ALL": "C.UTF-8",
           "DEB_BUILD_OPTIONS": "nostrip"}
    with (output / "build.stdout").open("wb") as stdout, (output / "build.stderr").open("wb") as stderr:
        result = subprocess.run(command, cwd=output / "work", env=env, stdout=stdout, stderr=stderr, timeout=600)
    receipt["command"] = command
    receipt["exit_code"] = result.returncode
    receipt["outcome"] = "failed"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    require(result.returncode == 0, "native package build failed; retained output remains")
    load_inputs(manifest, anchor)
    require(source_state(ROOT) == before, "packaging source changed during build")
    for name in TEMPLATES:
        require(digest((ROOT / "packaging/debian" / name).read_bytes()) == binding["source_files"]["packaging/debian/" + name],
                "packaging template changed during build")
    require(digest((ROOT / "packaging/systemd/bonvoyage.service").read_bytes()) == binding["source_unit_sha256"], "source unit changed")
    require(digest(Path(__file__).read_bytes()) == binding["builder_sha256"], "builder changed during build")
    debs = list(output.glob("*.deb"))
    require(len(debs) == 1, "exactly one gateway package required")
    control = subprocess.run(["dpkg-deb", "--field", str(debs[0])], check=True, capture_output=True, text=True)
    fields = Parser().parsestr(control.stdout)
    require(fields["Package"] == "bonvoyage-gateway" and fields["Architecture"] == "amd64" and
            fields["Version"] == spec["version"] and fields["Depends"], "package control mismatch")
    (output / "package-control.txt").write_text(control.stdout, encoding="utf-8")
    tar = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(debs[0])], check=True, capture_output=True)
    unit = (output / "work/debian/bonvoyage-gateway.bonvoyage.service").read_bytes()
    require(unit == (ROOT / "packaging/systemd/bonvoyage.service").read_bytes().replace(
        b"/usr/local/bin/bonvoyage-dataplane", b"/usr/bin/bonvoyage-dataplane"), "staged unit changed")
    receipt["payload_files_verified"] = verify_payload_tar(tar.stdout, spec, unit,
        (ROOT / "packaging/debian/README.Debian").read_bytes())
    receipt["package"] = {"path": debs[0].name, "bytes": debs[0].stat().st_size, "sha256": digest(debs[0].read_bytes())}
    receipt["outcome"] = "built-unaccepted"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(build(args.inputs.absolute(), args.manifest_sha256, args.output.absolute()), indent=2))
