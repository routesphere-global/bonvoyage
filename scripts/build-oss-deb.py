#!/usr/bin/env python3
"""Build a non-authoritative BonVoyage OSS Debian technical candidate."""

import argparse
from datetime import datetime, timezone
import email.utils
from email.parser import Parser
import gzip
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


ROOT = Path(__file__).resolve().parent.parent
PUBLIC_REPOSITORY = "https://github.com/routesphere-global/bonvoyage"
PRODUCT = "RouteSphere BonVoyage API Gateway"
INPUT_CLASS = "routesphere-bonvoyage-oss-deb-input"
TOOLCHAIN_CLASS = "routesphere-bonvoyage-oss-deb-toolchain"
BUILD_CLASS = "routesphere-bonvoyage-oss-deb-build"
REQUIRED_TOOLS = ("dh", "dpkg-buildpackage", "dpkg-deb", "dpkg-query", "python3")
PACKAGE_TEMPLATES = ("control", "rules", "postinst", "preinst")
SOURCE_INPUTS = (
    "packaging/debian/control",
    "packaging/debian/rules",
    "packaging/debian/postinst",
    "packaging/debian/preinst",
    "packaging/systemd/bonvoyage.service",
    "packaging/release/debian/README.Debian",
    "packaging/release/debian/oss-deb-input.schema.json",
    "packaging/release/debian/oss-deb-toolchain.schema.json",
    "scripts/build-oss-deb.py",
    "scripts/create-oss-deb-input.py",
)
SHA256 = re.compile(r"[a-f0-9]{64}")
COMMIT = re.compile(r"[a-f0-9]{40}")
SEMVER = re.compile(
    r"(?P<core>0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(?P<pre>[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*))?"
)
BUILDER_IMAGE = re.compile(r"[^@\s]+@sha256:[a-f0-9]{64}")
MAINTAINER = re.compile(r"[A-Za-z0-9 ._-]+ <[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+>")
BUILDER_ID = re.compile(r"[A-Za-z0-9._:/-]{1,128}")
PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?")


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


def parse_json(raw, label):
    try:
        value = json.loads(raw, object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid {label} JSON") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def safe_text(value, label, maximum=256):
    require(isinstance(value, str) and 0 < len(value) <= maximum, f"invalid {label}")
    require(not any(ord(character) < 32 or ord(character) == 127 for character in value),
            f"control character in {label}")
    return value


def file_identity(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": digest(data)}


def read_input(root, record, maximum):
    require(isinstance(record, dict) and set(record) == {"path", "sha256", "bytes"},
            "invalid file record")
    name = record["path"]
    require(isinstance(name, str) and len(name) <= 512, "invalid file path")
    relative = PurePosixPath(name)
    require(name and str(relative) == name and not relative.is_absolute() and
            all(part not in ("", ".", "..") for part in relative.parts), "unsafe file path")
    require(isinstance(record["sha256"], str) and SHA256.fullmatch(record["sha256"]),
            "invalid file digest")
    require(type(record["bytes"]) is int and 0 < record["bytes"] <= maximum,
            "invalid file size")
    target = root.joinpath(*relative.parts)
    for part in (target, *target.parents):
        if part == root:
            break
        require(not part.is_symlink(), "symlink in input path")
    require(target.is_file() and target.resolve().is_relative_to(root.resolve()),
            "missing or unsafe input file")
    require(target.stat().st_size == record["bytes"], "input size mismatch")
    data = target.read_bytes()
    require(len(data) == record["bytes"] and digest(data) == record["sha256"],
            "input digest mismatch")
    return data


def semver_to_debian(version, revision):
    match = SEMVER.fullmatch(version) if isinstance(version, str) else None
    require(match is not None, "release version must be SemVer without build metadata")
    require(type(revision) is int and 1 <= revision <= 9999, "invalid package revision")
    prerelease = match.group("pre")
    if prerelease:
        for identifier in prerelease.split("."):
            require(not (identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0")),
                    "numeric SemVer prerelease identifiers cannot contain leading zeroes")
    # Debian sorts '~' before the stable version, preserving SemVer prerelease order.
    base = version.split("-", 1)[0]
    return f"{base}{'~' + prerelease if prerelease else ''}-{revision}"


def load_toolchain_document(raw):
    lock = parse_json(raw, "toolchain lock")
    require(set(lock) == {"schema_version", "classification", "distribution", "architecture",
                          "builder_image", "os_release", "packages", "tools"},
            "invalid toolchain lock fields")
    require(type(lock["schema_version"]) is int and lock["schema_version"] == 1,
            "unsupported toolchain schema")
    require(lock["classification"] == TOOLCHAIN_CLASS, "unsupported toolchain class")
    require(lock["distribution"] == "ubuntu-24.04" and lock["architecture"] == "amd64",
            "unsupported toolchain platform")
    require(isinstance(lock["builder_image"], str) and BUILDER_IMAGE.fullmatch(lock["builder_image"]),
            "digest-pinned builder image required")

    os_release = lock["os_release"]
    require(isinstance(os_release, dict) and set(os_release) == {"path", "bytes", "sha256"} and
            os_release["path"] == "/etc/os-release", "invalid os-release identity")
    require(type(os_release["bytes"]) is int and 0 < os_release["bytes"] <= 1024 * 1024 and
            isinstance(os_release["sha256"], str) and SHA256.fullmatch(os_release["sha256"]),
            "invalid os-release identity")

    packages = lock["packages"]
    require(isinstance(packages, list) and packages, "complete package inventory required")
    package_pairs = []
    for package in packages:
        require(isinstance(package, dict) and set(package) == {"name", "version"},
                "invalid toolchain package")
        name = safe_text(package["name"], "package name")
        version = safe_text(package["version"], "package version")
        require(PACKAGE_NAME.fullmatch(name), "invalid package name")
        package_pairs.append((name, version))
    require(package_pairs == sorted(package_pairs) and
            len({name for name, _ in package_pairs}) == len(package_pairs),
            "toolchain packages must be sorted and unique")

    tools = lock["tools"]
    require(isinstance(tools, list), "tool inventory required")
    tool_names = []
    for tool in tools:
        require(isinstance(tool, dict) and set(tool) == {
            "name", "path", "resolved_path", "bytes", "sha256"}, "invalid tool identity")
        name = safe_text(tool["name"], "tool name")
        require(name in REQUIRED_TOOLS, "unexpected build tool")
        for field in ("path", "resolved_path"):
            path = safe_text(tool[field], f"tool {field}", 1024)
            require(path.startswith("/") and str(PurePosixPath(path)) == path,
                    f"invalid tool {field}")
        require(type(tool["bytes"]) is int and tool["bytes"] > 0 and
                isinstance(tool["sha256"], str) and SHA256.fullmatch(tool["sha256"]),
                "invalid tool byte identity")
        tool_names.append(name)
    require(tool_names == sorted(REQUIRED_TOOLS), "tool inventory must be exact and sorted")
    return lock


def observe_toolchain():
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "Ubuntu AMD64 build host required")
    os_release_path = Path("/etc/os-release")
    require(os_release_path.is_file(), "readable /etc/os-release required")
    resolved_os_release = os_release_path.resolve()
    require(resolved_os_release in (Path("/etc/os-release"), Path("/usr/lib/os-release")),
            "unexpected /etc/os-release target")
    os_release_bytes = os_release_path.read_bytes()
    release_fields = dict(
        line.split("=", 1) for line in os_release_bytes.decode("utf-8").splitlines() if "=" in line
    )
    require(release_fields.get("ID", "").strip('"') == "ubuntu" and
            release_fields.get("VERSION_ID", "").strip('"') == "24.04",
            "Ubuntu 24.04 build host required")

    package_result = subprocess.run(
        ["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"],
        check=True, capture_output=True, text=True, timeout=30,
    )
    packages = []
    for line in package_result.stdout.splitlines():
        parts = line.split("\t")
        require(len(parts) == 2 and parts[0] and parts[1], "invalid dpkg package inventory")
        packages.append({"name": parts[0], "version": parts[1]})
    packages.sort(key=lambda item: (item["name"], item["version"]))

    tools = []
    for name in REQUIRED_TOOLS:
        command_path = shutil.which(name)
        require(command_path is not None, "missing native build tool: " + name)
        path = Path(command_path)
        require(path.is_file(), "invalid native build tool: " + name)
        resolved = path.resolve()
        data = resolved.read_bytes()
        tools.append({"name": name, "path": str(path), "resolved_path": str(resolved),
                      "bytes": len(data), "sha256": digest(data)})
    tools.sort(key=lambda item: item["name"])
    return {
        "distribution": "ubuntu-24.04",
        "architecture": "amd64",
        "os_release": {"path": "/etc/os-release", "bytes": len(os_release_bytes),
                       "sha256": digest(os_release_bytes)},
        "packages": packages,
        "tools": tools,
    }


def capture_toolchain(builder_image):
    require(isinstance(builder_image, str) and BUILDER_IMAGE.fullmatch(builder_image),
            "digest-pinned builder image required")
    observed = observe_toolchain()
    return {"schema_version": 1, "classification": TOOLCHAIN_CLASS,
            "distribution": observed["distribution"], "architecture": observed["architecture"],
            "builder_image": builder_image, "os_release": observed["os_release"],
            "packages": observed["packages"], "tools": observed["tools"]}


def verify_host_toolchain(lock):
    expected = {key: lock[key] for key in ("distribution", "architecture", "os_release", "packages", "tools")}
    observed = observe_toolchain()
    require(observed == expected, "build host does not match the immutable toolchain lock")
    return observed


def load_inputs(manifest, anchor):
    require(isinstance(anchor, str) and SHA256.fullmatch(anchor),
            "reviewed manifest digest required")
    require(manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_size <= 1024 * 1024,
            "bounded regular manifest required")
    raw = manifest.read_bytes()
    require(digest(raw) == anchor, "manifest digest mismatch")
    spec = parse_json(raw, "input manifest")
    require(set(spec) == {"schema_version", "classification", "product", "source_repository",
                          "source_commit", "source_tag", "release_version", "package_revision",
                          "distribution", "architecture", "maintainer", "source_date_epoch", "files"},
            "invalid input manifest fields")
    require(type(spec["schema_version"]) is int and spec["schema_version"] == 1,
            "unsupported manifest schema")
    require(spec["classification"] == INPUT_CLASS and spec["product"] == PRODUCT,
            "unsupported package class")
    require(spec["source_repository"] == PUBLIC_REPOSITORY, "unexpected source repository")
    require(isinstance(spec["source_commit"], str) and COMMIT.fullmatch(spec["source_commit"]),
            "source commit required")
    release_version = safe_text(spec["release_version"], "release version")
    debian_version = semver_to_debian(release_version, spec["package_revision"])
    require(spec["source_tag"] == "v" + release_version, "source tag must match release version")
    require(spec["distribution"] == "ubuntu-24.04" and spec["architecture"] == "amd64",
            "unsupported native platform")
    require(isinstance(spec["maintainer"], str) and MAINTAINER.fullmatch(spec["maintainer"]),
            "explicit single-line maintainer required")
    require(type(spec["source_date_epoch"]) is int and 0 < spec["source_date_epoch"] <= 4102444800,
            "invalid source date epoch")
    require(isinstance(spec["files"], dict) and set(spec["files"]) == {
        "dataplane", "copyright", "third_party_notices", "third_party_source",
        "third_party_licenses", "toolchain_lock"}, "invalid payload files")
    records = [json.dumps(spec["files"][name], sort_keys=True) for name in sorted(spec["files"])]
    require(len(set(records)) == len(records), "duplicate payload record")

    payload = {
        "dataplane": read_input(manifest.parent, spec["files"]["dataplane"], 512 * 1024 * 1024),
        "copyright": read_input(manifest.parent, spec["files"]["copyright"], 2 * 1024 * 1024),
        "third_party_notices": read_input(
            manifest.parent, spec["files"]["third_party_notices"], 2 * 1024 * 1024),
        "third_party_source": read_input(
            manifest.parent, spec["files"]["third_party_source"], 2 * 1024 * 1024),
        "third_party_licenses": read_input(
            manifest.parent, spec["files"]["third_party_licenses"], 8 * 1024 * 1024),
        "toolchain_lock_raw": read_input(
            manifest.parent, spec["files"]["toolchain_lock"], 4 * 1024 * 1024),
    }
    elf = payload["dataplane"]
    require(len(elf) >= 64 and elf[:7] == b"\x7fELF\x02\x01\x01" and
            struct.unpack_from("<HH", elf, 16)[0] in (2, 3) and
            struct.unpack_from("<H", elf, 18)[0] == 62 and
            struct.unpack_from("<Q", elf, 24)[0] > 0, "AMD64 executable ELF required")
    decoded = {}
    for name in ("copyright", "third_party_notices", "third_party_source",
                 "third_party_licenses"):
        require(b"\x00" not in payload[name], f"{name} text contains NUL")
        try:
            decoded[name] = payload[name].decode("utf-8").strip()
        except UnicodeDecodeError as error:
            raise ValueError(f"{name} text must be UTF-8") from error
        require(len(decoded[name]) >= 80, f"substantive {name} text required")
    require("libjwt" in decoded["third_party_source"] and
            "Mozilla Public License" in decoded["third_party_source"],
            "MPL source-availability instructions required")
    require("libjwt" in decoded["third_party_licenses"] and
            "Mozilla Public License" in decoded["third_party_licenses"],
            "MPL license text required")
    payload["toolchain_lock"] = load_toolchain_document(payload["toolchain_lock_raw"])
    spec = {**spec, "debian_version": debian_version}
    return spec, payload


def normalize_repository(value):
    value = value.strip()
    if value.endswith(".git"):
        value = value[:-4]
    aliases = {
        "git@github.com:routesphere-global/bonvoyage": PUBLIC_REPOSITORY,
        "ssh://git@github.com/routesphere-global/bonvoyage": PUBLIC_REPOSITORY,
        PUBLIC_REPOSITORY: PUBLIC_REPOSITORY,
    }
    return aliases.get(value, value)


def source_state(spec, root=ROOT):
    def git_text(*args):
        return subprocess.run(["git", "-C", str(root), *args], check=True,
                              capture_output=True, text=True, timeout=30).stdout.strip()

    status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all", "-z"],
        check=True, capture_output=True, timeout=30,
    ).stdout
    commit = git_text("rev-parse", "HEAD")
    remote = normalize_repository(git_text("remote", "get-url", "origin"))
    tag_commit = git_text("rev-parse", "--verify", f"refs/tags/{spec['source_tag']}^{{commit}}")
    commit_epoch = int(git_text("show", "-s", "--format=%ct", "HEAD"))
    require(not status, "clean source tree required")
    require(commit == spec["source_commit"], "source commit does not match build input")
    require(remote == spec["source_repository"] == PUBLIC_REPOSITORY,
            "source origin does not match public repository")
    require(tag_commit == commit, "release tag does not resolve to source commit")
    require(commit_epoch == spec["source_date_epoch"],
            "source date epoch must equal the source commit timestamp")
    return {"repository": remote, "commit": commit, "tag": spec["source_tag"],
            "source_date_epoch": commit_epoch, "dirty": False,
            "status_sha256": digest(status)}


def source_bindings(root=ROOT):
    bindings = {}
    for relative in SOURCE_INPUTS:
        path = root / relative
        require(path.is_file() and not path.is_symlink(), "missing regular build source: " + relative)
        data = path.read_bytes()
        bindings[relative] = {"bytes": len(data), "sha256": digest(data)}
    return bindings


def render_service(root=ROOT):
    source = (root / "packaging/systemd/bonvoyage.service").read_bytes()
    require(source.count(b"/usr/local/bin/bonvoyage-dataplane") == 1,
            "source service executable contract drift")
    require(source.count(b"https://docs.routesphere.io/bonvoyage/") == 1,
            "source service documentation contract drift")
    return source.replace(
        b"/usr/local/bin/bonvoyage-dataplane", b"/usr/bin/bonvoyage-dataplane"
    ).replace(
        b"https://docs.routesphere.io/bonvoyage/", b"https://docs.routesphere.global/"
    )


def expected_changelog(spec):
    date = email.utils.format_datetime(datetime.fromtimestamp(spec["source_date_epoch"], timezone.utc))
    return (
        f"bonvoyage-gateway ({spec['debian_version']}) noble; urgency=medium\n\n"
        "  * Assemble the RouteSphere BonVoyage OSS technical candidate from reviewed inputs.\n\n"
        f" -- {spec['maintainer']}  {date}\n"
    ).encode("ascii")


def prepare_tree(manifest, anchor, output, root=ROOT):
    spec, payload = load_inputs(manifest, anchor)
    require(not output.exists() and not output.is_symlink(), "new output directory required")
    resolved_output_parent = output.parent.resolve()
    require(not resolved_output_parent.is_relative_to(root.resolve()),
            "build output must be outside the source repository")
    bindings = source_bindings(root)
    output.mkdir(mode=0o700)
    tree = output / "work"
    (tree / "debian/source").mkdir(parents=True)
    (tree / "input").mkdir()

    for name in PACKAGE_TEMPLATES:
        data = (root / "packaging/debian" / name).read_bytes()
        text = data.decode("utf-8")
        if name == "control":
            text = text.replace("@MAINTAINER@", spec["maintainer"])
        filename = {"postinst": "bonvoyage-gateway.postinst",
                    "preinst": "bonvoyage-gateway.preinst"}.get(name, name)
        (tree / "debian" / filename).write_text(text, encoding="utf-8")
    (tree / "debian/rules").chmod(0o755)
    for script in ("postinst", "preinst"):
        (tree / "debian" / ("bonvoyage-gateway." + script)).chmod(0o755)

    public_readme = (root / "packaging/release/debian/README.Debian").read_bytes()
    (tree / "debian/bonvoyage-gateway.README.Debian").write_bytes(public_readme)
    unit = render_service(root)
    (tree / "debian/bonvoyage-gateway.bonvoyage.service").write_bytes(unit)
    (tree / "input/bonvoyage-dataplane").write_bytes(payload["dataplane"])
    (tree / "input/bonvoyage-dataplane").chmod(0o755)
    for name, filename in (
        ("third_party_notices", "THIRD_PARTY_NOTICES.md"),
        ("third_party_source", "THIRD_PARTY_SOURCE.md"),
        ("third_party_licenses", "THIRD_PARTY_LICENSES.txt"),
    ):
        (tree / "input" / filename).write_bytes(payload[name])
    (tree / "debian/copyright").write_bytes(payload["copyright"])
    (tree / "debian/source/format").write_text("3.0 (quilt)\n", encoding="ascii")
    changelog = expected_changelog(spec)
    (tree / "debian/changelog").write_bytes(changelog)
    (output / "input-manifest.json").write_bytes(manifest.read_bytes())
    (output / "toolchain-lock.json").write_bytes(payload["toolchain_lock_raw"])
    return spec, payload, {
        "input_manifest_sha256": anchor,
        "toolchain_lock_sha256": digest(payload["toolchain_lock_raw"]),
        "source_files": bindings,
    }, unit, public_readme, changelog


def safe_archive_name(member):
    name = member.name.removeprefix("./").rstrip("/")
    require(name and str(PurePosixPath(name)) == name and not name.startswith("/") and
            ".." not in PurePosixPath(name).parts, "unsafe package member")
    return name


def verify_payload_tar(data, spec, unit, readme, changelog):
    expected = {
        "usr/bin/bonvoyage-dataplane": spec["files"]["dataplane"]["sha256"],
        "usr/share/doc/bonvoyage-gateway/copyright": spec["files"]["copyright"]["sha256"],
        "usr/share/doc/bonvoyage-gateway/THIRD_PARTY_NOTICES.md":
            spec["files"]["third_party_notices"]["sha256"],
        "usr/share/doc/bonvoyage-gateway/THIRD_PARTY_SOURCE.md":
            spec["files"]["third_party_source"]["sha256"],
        "usr/share/doc/bonvoyage-gateway/THIRD_PARTY_LICENSES.txt":
            spec["files"]["third_party_licenses"]["sha256"],
        "usr/share/doc/bonvoyage-gateway/README.Debian": digest(readme),
    }
    allowed_directories = {
        "usr", "usr/bin", "lib", "lib/systemd", "lib/systemd/system", "usr/lib",
        "usr/lib/systemd", "usr/lib/systemd/system", "usr/share", "usr/share/doc",
        "usr/share/doc/bonvoyage-gateway",
    }
    files = {}
    root_seen = False
    service_seen = 0
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            if member.name in (".", "./"):
                require(not root_seen and member.isdir() and member.uid == 0 and member.gid == 0 and
                        member.mode == 0o755, "invalid or duplicate archive root")
                root_seen = True
                continue
            name = safe_archive_name(member)
            require(name not in files, "duplicate package member")
            require(member.uid == 0 and member.gid == 0, "package ownership must be root")
            require(member.isfile() or member.isdir(), "links and special files are not allowed")
            require(member.mode == (0o755 if member.isdir() or name == "usr/bin/bonvoyage-dataplane" else 0o644),
                    "unexpected package mode")
            if member.isdir():
                require(name in allowed_directories, "unexpected package directory")
                files[name] = {"type": "directory"}
                continue
            require(member.size <= 512 * 1024 * 1024, "oversized package payload")
            with archive.extractfile(member) as stream:
                body = stream.read()
            if name in {"lib/systemd/system/bonvoyage.service",
                        "usr/lib/systemd/system/bonvoyage.service"}:
                require(body == unit, "packaged service contract mismatch")
                service_seen += 1
            elif name == "usr/share/doc/bonvoyage-gateway/changelog.Debian.gz":
                require(len(body) <= 1024 * 1024 and gzip.decompress(body) == changelog,
                        "packaged changelog mismatch")
            else:
                require(name in expected and digest(body) == expected[name],
                        "unexpected or corrupt package file")
            files[name] = {"type": "file", "bytes": len(body), "sha256": digest(body)}
    require(root_seen, "archive root required")
    require(all(name in files for name in expected), "missing package payload")
    require(service_seen == 1, "one packaged unit required")
    return {name: identity for name, identity in sorted(files.items()) if identity["type"] == "file"}


def verify_maintainer_script(name, body):
    text = body.decode("utf-8")
    forbidden = (
        r"\b(?:systemctl|deb-systemd-invoke)\s+(?:--[^\s]+\s+)*(?:start|restart|enable)\b",
        r"\b(?:sysctl|ethtool|irqbalance|tuned-adm|cpupower|taskset|cset)\b",
        r"/proc/irq/",
    )
    for pattern in forbidden:
        require(re.search(pattern, text) is None, f"forbidden automatic host mutation in {name}")
    helper_enable = "deb-systemd-helper enable 'bonvoyage.service'"
    if helper_enable in text:
        require(name == "postinst" and text.count(helper_enable) == 1 and
                "deb-systemd-helper debian-installed 'bonvoyage.service'" in text and
                "deb-systemd-helper --quiet was-enabled 'bonvoyage.service'" in text,
                "unbounded service-enable action in maintainer script")


def verify_control_tar(data):
    allowed = {"control", "md5sums", "preinst", "postinst", "postrm"}
    scripts = {"preinst", "postinst", "postrm"}
    files = {}
    root_seen = False
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            if member.name in (".", "./"):
                require(not root_seen and member.isdir() and member.uid == 0 and member.gid == 0 and
                        member.mode == 0o755, "invalid or duplicate control root")
                root_seen = True
                continue
            name = safe_archive_name(member)
            require(name in allowed and name not in files and member.isfile(),
                    "unexpected, duplicate or non-file control member")
            require(member.uid == 0 and member.gid == 0, "control ownership must be root")
            require(member.mode == (0o755 if name in scripts else 0o644), "unexpected control mode")
            require(member.size <= 1024 * 1024, "oversized control member")
            with archive.extractfile(member) as stream:
                body = stream.read()
            if name in scripts:
                verify_maintainer_script(name, body)
            files[name] = {"bytes": len(body), "sha256": digest(body)}
    require(root_seen, "control archive root required")
    require(set(files) == allowed, "incomplete control archive")
    return {name: files[name] for name in sorted(files)}


def receipt_template(spec, source, binding, builder_id):
    return {
        "schema_version": 1,
        "classification": BUILD_CLASS,
        "outcome": "building",
        "builder_id": builder_id,
        "source": source,
        "binding": binding,
        "distribution": "ubuntu-24.04",
        "architecture": "amd64",
        "release_version": spec["release_version"],
        "debian_version": spec["debian_version"],
        "technical_candidate_built": False,
        "reproducibility_qualified": False,
        "sbom_qualified": False,
        "scan_qualified": False,
        "signature_qualified": False,
        "provenance_qualified": False,
        "lifecycle_qualified": False,
        "release_admitted": False,
        "publishable": False,
    }


def write_receipt(path, receipt):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def build(manifest, anchor, output, builder_id, root=ROOT):
    require(isinstance(builder_id, str) and BUILDER_ID.fullmatch(builder_id),
            "explicit bounded builder ID required")
    spec, payload = load_inputs(manifest, anchor)
    source = source_state(spec, root)
    observed_toolchain = verify_host_toolchain(payload["toolchain_lock"])
    spec, payload, binding, unit, readme, changelog = prepare_tree(
        manifest, anchor, output, root,
    )
    binding["observed_toolchain_sha256"] = digest(
        (json.dumps(observed_toolchain, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    )
    binding["builder_image"] = payload["toolchain_lock"]["builder_image"]
    binding["builder_image_verified_externally"] = False
    receipt = receipt_template(spec, source, binding, builder_id)
    command = ["dpkg-buildpackage", "-us", "-uc", "-b"]
    receipt["command"] = command
    receipt_path = output / "build-receipt.json"
    write_receipt(receipt_path, receipt)

    home = output / "home"
    home.mkdir(mode=0o700)
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": str(home),
        "SOURCE_DATE_EPOCH": str(spec["source_date_epoch"]),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "TZ": "UTC",
        "DEB_BUILD_OPTIONS": "nostrip noautodbgsym",
        "DPKG_COLORS": "never",
    }
    try:
        with (output / "build.stdout").open("wb") as stdout, (output / "build.stderr").open("wb") as stderr:
            result = subprocess.run(command, cwd=output / "work", env=environment,
                                    stdout=stdout, stderr=stderr, timeout=900)
        receipt["exit_code"] = result.returncode
        require(result.returncode == 0, "Debian package build failed; retained output remains")

        second_spec, second_payload = load_inputs(manifest, anchor)
        require(second_spec == spec and all(
                    second_payload[name] == payload[name] for name in (
                        "dataplane", "copyright", "third_party_notices",
                        "third_party_source", "third_party_licenses", "toolchain_lock_raw")),
                "build inputs changed during assembly")
        require(source_state(spec, root) == source, "source identity changed during assembly")
        require(source_bindings(root) == binding["source_files"], "build source changed during assembly")
        verify_host_toolchain(payload["toolchain_lock"])

        packages = sorted(output.glob("*.deb"))
        require(len(packages) == 1, "exactly one gateway package required")
        package = packages[0]
        expected_name = f"bonvoyage-gateway_{spec['debian_version']}_amd64.deb"
        require(package.name == expected_name, "unexpected Debian package filename")
        control_result = subprocess.run(
            ["dpkg-deb", "--field", str(package)], check=True, capture_output=True,
            text=True, timeout=30,
        )
        fields = Parser().parsestr(control_result.stdout)
        require(fields["Package"] == "bonvoyage-gateway" and fields["Architecture"] == "amd64" and
                fields["Version"] == spec["debian_version"] and fields["Maintainer"] == spec["maintainer"] and
                bool(fields["Depends"]), "package control mismatch")
        (output / "package-control.txt").write_text(control_result.stdout, encoding="utf-8")

        payload_tar = subprocess.run(
            ["dpkg-deb", "--fsys-tarfile", str(package)], check=True, capture_output=True,
            timeout=30,
        ).stdout
        control_tar = subprocess.run(
            ["dpkg-deb", "--ctrl-tarfile", str(package)], check=True, capture_output=True,
            timeout=30,
        ).stdout
        receipt["payload"] = verify_payload_tar(payload_tar, spec, unit, readme, changelog)
        receipt["control"] = verify_control_tar(control_tar)
        package_bytes = package.read_bytes()
        receipt["package"] = {"path": package.name, "bytes": len(package_bytes),
                              "sha256": digest(package_bytes), "version": spec["debian_version"],
                              "architecture": "amd64"}
        receipt["outcome"] = "built-technical-candidate"
        receipt["technical_candidate_built"] = True
        write_receipt(receipt_path, receipt)
        return receipt
    except Exception as error:
        receipt["outcome"] = "failed"
        receipt["failure"] = {"type": type(error).__name__, "message": str(error)[:1000]}
        write_receipt(receipt_path, receipt)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--builder-id", required=True)
    arguments = parser.parse_args()
    os.umask(0o077)
    try:
        result = build(arguments.inputs.absolute(), arguments.manifest_sha256,
                       arguments.output.absolute(), arguments.builder_id)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise SystemExit("OSS Debian build rejected: " + str(error)) from error
    print(json.dumps(result, indent=2, sort_keys=True))
