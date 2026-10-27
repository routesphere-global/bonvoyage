#!/usr/bin/env python3
"""Collect a private, host-bound native inventory; never grant release acceptance."""

import argparse
from datetime import datetime, timezone
from email.parser import Parser
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import struct
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SHA = re.compile(r"[a-f0-9]{64}")
COMMIT = re.compile(r"[a-f0-9]{40}")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]+(?::amd64)?")
FLAGS = ("package_accepted", "sbom_qualified", "scan_qualified", "tuning_adapter_compatible", "publishable")
NOTICE_LIMIT = 8 * 1024 * 1024
RECORDS = (
    "security/dependencies/seastar-25.05.0.json", "security/dependencies/nghttp2-1.70.0.json",
    "security/dependencies/libjwt-3.6.1.json", "security/dependencies/abseil-20250512.1.json",
    "security/dependencies/re2-2025-11-05.json", "security/dependencies/opentelemetry-proto-1.11.0.json",
)
CARES_RECORD = "security/dependencies/c-ares-1.34.8.json"
LLHTTP_RECORD = "security/dependencies/llhttp-9.4.3.json"
LEGACY_LLHTTP_CANDIDATE_RECORD = "security/dependencies/candidates/llhttp-9.4.3.json"
LEGACY_SOURCE_BOUNDARY = "e28579ad11bb2af52e3c17f7e6dc72904ebc0736"
CARES_COMMIT = "c7a3138dcfe3bb0eaaf10c0c24c36dc66dc790ab"
CARES_ARCHIVE_SHA = "c222b6d681096f9444d2c4863d2c1174019e27cacca0a4a5c114d36dd7d7bf78"
LLHTTP_COMMIT = "0e815792b167a9bd8ace259b95b7da953776c288"
LLHTTP_ARCHIVE_SHA = "1eb813c7437b31a87496a1cd3ed79f00746720f5e7e29c79b42c02cb69f36c39"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda value: require(False, "non-finite JSON: " + value))


def run(*argv):
    return subprocess.run(argv, check=True, capture_output=True, timeout=60,
                          env={**os.environ, "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}).stdout


def source_state(root):
    status = run("git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all")
    return {"commit": run("git", "-C", str(root), "rev-parse", "HEAD").decode().strip(),
            "dirty": bool(status.strip()), "status_sha256": digest(status)}


def identity(path, maximum=256 * 1024 * 1024):
    path = Path(path)
    require(path.is_absolute() and str(PurePosixPath(str(path))) == str(path) and
            ".." not in path.parts and path.resolve() == path, "canonical absolute file required")
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, "bounded regular file required")
        value = hashlib.sha256()
        size = 0
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            require(size <= maximum, "file grew beyond size limit")
            value.update(chunk)
        after = os.fstat(stream.fileno())
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "file changed while hashing")
    return {"path": str(path), "bytes": after.st_size, "sha256": value.hexdigest()}


def anchored(record):
    require(isinstance(record, dict) and set(record) == {"path", "bytes", "sha256"}, "invalid file record")
    require(isinstance(record["path"], str) and type(record["bytes"]) is int and
            isinstance(record["sha256"], str) and SHA.fullmatch(record["sha256"]), "invalid file identity")
    require(identity(record["path"]) == record, "input identity mismatch")
    return Path(record["path"])


def load_request(path, anchor):
    require(isinstance(anchor, str) and SHA.fullmatch(anchor), "reviewed request digest required")
    record = identity(path, 1024 * 1024)
    require(record["sha256"] == anchor, "request digest mismatch")
    spec = decode(Path(path).read_bytes())
    require(isinstance(spec, dict) and set(spec) == {"schema_version", "classification", "producer_source_commit",
            "runtime_profile", "files"}, "invalid request fields")
    require(type(spec["schema_version"]) is int and spec["schema_version"] == 1 and
            spec["classification"] == "private-native-runtime-inventory-input", "unsupported request schema")
    require(isinstance(spec["producer_source_commit"], str) and COMMIT.fullmatch(spec["producer_source_commit"]),
            "producer commit required")
    require(spec["runtime_profile"] in ("source-install", "package-install"), "explicit runtime profile required")
    require(isinstance(spec["files"], dict) and set(spec["files"]) == {
        "binary", "producer_manifest", "producer_sbom", "package", "build_receipt", "build_inputs"}, "invalid input files")
    paths = [str(anchored(value)) for value in spec["files"].values()]
    require(len(set(paths)) == len(paths), "distinct input files required")
    return spec, record


def verify_binding(spec):
    files = spec["files"]
    producer = decode(Path(files["producer_manifest"]["path"]).read_bytes())
    receipt = decode(Path(files["build_receipt"]["path"]).read_bytes())
    inputs = decode(Path(files["build_inputs"]["path"]).read_bytes())
    sbom = decode(Path(files["producer_sbom"]["path"]).read_bytes())
    commit = spec["producer_source_commit"]
    require(producer.get("classification") == "private-native-rc-handoff" and
            producer.get("source_commit") == commit and producer.get("source_dirty_at_acceptance") is False,
            "clean accepted producer identity required")
    require(isinstance(producer.get("files"), list), "producer file inventory required")
    matches = [f for f in producer["files"] if f.get("path") == "artifacts/bonvoyage-dataplane"]
    require(len(matches) == 1 and all(matches[0].get(k) == files["binary"][k] for k in ("bytes", "sha256")),
            "binary differs from producer")
    matches = [f for f in producer["files"] if f.get("path") == "runtime-security/runtime.cdx.json"]
    require(len(matches) == 1 and all(matches[0].get(k) == files["producer_sbom"][k] for k in ("bytes", "sha256")),
            "producer SBOM differs from handoff")
    require(receipt.get("classification") == "private-native-gateway-build" and
            receipt.get("outcome") == "built-unaccepted" and receipt.get("exit_code") == 0 and
            type(receipt.get("exit_code")) is int and receipt.get("payload_files_verified") == 5 and
            receipt.get("producer_source_commit") == commit and
            receipt.get("packaging_source", {}).get("dirty") is False and
            COMMIT.fullmatch(receipt.get("packaging_source", {}).get("commit", "")) and
            all(receipt.get(flag) is False for flag in FLAGS), "clean unaccepted package receipt required")
    require(receipt.get("architecture") == "amd64" and receipt.get("distribution") == "ubuntu-24.04" and
            receipt.get("binding", {}).get("manifest_sha256") == files["build_inputs"]["sha256"] and
            all(receipt.get("package", {}).get(k) == files["package"][k] for k in ("bytes", "sha256")) and
            receipt["package"].get("path") == Path(files["package"]["path"]).name, "package receipt identity mismatch")
    require(inputs.get("classification") == "private-native-gateway-input" and
            inputs.get("producer_source_commit") == commit and inputs.get("architecture") == "amd64" and
            inputs.get("distribution") == "ubuntu-24.04" and
            all(inputs.get("files", {}).get("dataplane", {}).get(k) == files["binary"][k] for k in ("bytes", "sha256")),
            "package input binary mismatch")
    require(sbom.get("bomFormat") == "CycloneDX" and sbom.get("specVersion") == "1.6" and
            isinstance(sbom.get("components"), list), "producer CycloneDX declaration required")
    return receipt, inputs, sbom


def git_file(commit, name, root=ROOT):
    require(COMMIT.fullmatch(commit) and isinstance(name, str) and name and
            str(PurePosixPath(name)) == name and not name.startswith("/") and
            ".." not in PurePosixPath(name).parts, "unsafe producer source path")
    return run("git", "-C", str(root), "show", commit + ":" + name)


def producer_records(commit, root=ROOT):
    """Read declarations from the binary producer, never the collector checkout."""
    require(isinstance(commit, str) and COMMIT.fullmatch(commit), "producer commit required")
    entries = run("git", "-C", str(root), "ls-tree", "-z", commit + ":security/dependencies")
    records = {}
    for entry in entries.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.decode().split("\t", 1)
        if not name.endswith(".json"):
            continue
        mode, kind, _ = metadata.split()
        require(mode == "100644" and kind == "blob" and "/" not in name, "regular producer declaration required")
        path = "security/dependencies/" + name
        require(path not in records, "duplicate producer declaration path")
        records[path] = git_file(commit, path, root)
    legacy = set(RECORDS)
    with_cares = legacy | {CARES_RECORD}
    require(set(records) in (legacy, with_cares, with_cares | {LLHTTP_RECORD}),
            "missing/unknown producer declaration file")
    if CARES_RECORD not in records:
        # An arbitrary future producer cannot opt into the historical six-file profile.
        require(run("git", "-C", str(root), "merge-base", commit, LEGACY_SOURCE_BOUNDARY).decode().strip() == commit,
                "new producer must declare c-ares")
    names = set()
    for path, raw in records.items():
        record = validate_record(raw)
        require(path == "security/dependencies/" + record["name"] + "-" + record["version"] + ".json" and
                record["name"] not in names, "producer declaration filename/name mismatch or duplicate")
        names.add(record["name"])
    return records


def matching_cpe(record):
    matching = record.get("matching", {})
    require(isinstance(matching, dict), "matching declaration object required")
    if record["name"] == "c-ares":
        cpe = "cpe:2.3:a:c-ares_project:c-ares:1.34.8:*:*:*:*:*:*:*"
        require(matching.get("cpe") == cpe, "source-established c-ares CPE required")
        return cpe
    require("cpe" not in matching, "unreviewed static CPE declaration")
    return None


def validate_record(raw):
    record = decode(raw)
    require(isinstance(record, dict) and isinstance(record.get("name"), str) and
            re.fullmatch(r"[a-z0-9][a-z0-9.-]*", record["name"]) and
            isinstance(record.get("version"), str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]*", record["version"]) and
            isinstance(record.get("source"), dict) and isinstance(record["source"].get("commit"), str) and
            COMMIT.fullmatch(record["source"]["commit"]) and isinstance(record.get("license"), dict) and
            isinstance(record["license"].get("spdx"), str) and record["license"]["spdx"] and
            isinstance(record.get("build"), dict) and record["build"].get("linkage") in
            ("static", "generated C++ messages linked into the dataplane"),
            "complete static/generated declaration required")
    if record["name"] == "c-ares":
        require(record["version"] == "1.34.8" and record["source"]["commit"] == CARES_COMMIT and
                record["source"].get("archive_sha256") == CARES_ARCHIVE_SHA and
                record["license"]["spdx"] == "MIT" and record["build"]["linkage"] == "static",
                "pinned static c-ares identity required")
    elif record["name"] == "llhttp":
        require(record["version"] == "9.4.3" and record["source"]["commit"] == LLHTTP_COMMIT and
                record["source"].get("archive_sha256") == LLHTTP_ARCHIVE_SHA and
                record["license"]["spdx"] == "MIT" and record["build"]["linkage"] == "static",
                "pinned static llhttp identity required")
    matching_cpe(record)
    return record


def producer_declarations(commit, sbom, root=ROOT):
    records = producer_records(commit, root)
    require(isinstance(sbom.get("components"), list) and all(isinstance(c, dict) for c in sbom["components"]),
            "producer component array required")
    if any(c.get("name") == "llhttp" for c in sbom["components"]) and LLHTTP_RECORD not in records:
        # Preserve replay of pre-correction evidence whose exact producer commit
        # carried llhttp only under the historical candidate path.
        records[LEGACY_LLHTTP_CANDIDATE_RECORD] = git_file(
            commit, LEGACY_LLHTTP_CANDIDATE_RECORD, root)
        candidate = validate_record(records[LEGACY_LLHTTP_CANDIDATE_RECORD])
        require(candidate["name"] == "llhttp", "legacy llhttp declaration identity mismatch")
    expected = {validate_record(raw)["name"] for raw in records.values()}
    for component in sbom["components"]:
        if any(p.get("name") == "bonvoyage:source:commit" for p in component.get("properties", [])):
            require(component.get("name") in expected, "unknown producer static declaration")
    result = []
    for path, raw in sorted(records.items()):
        item = declared_component(raw, sbom, lambda p: git_file(commit, p, root))
        result.append({**item, "record_path": path})
    return result


def declared_component(raw, sbom, read_source):
    record = validate_record(raw)
    matches = [c for c in sbom["components"] if c.get("name") == record["name"]]
    require(len(matches) == 1 and matches[0].get("version") == record["version"], "static version declaration mismatch")
    properties = matches[0].get("properties", [])
    commits = [p.get("value") for p in properties if p.get("name") == "bonvoyage:source:commit"]
    require(commits == [record["source"]["commit"]], "static source declaration mismatch")
    licenses = [item.get("license", {}).get("id") for item in matches[0].get("licenses", [])]
    linkages = [p.get("value") for p in properties if p.get("name") == "bonvoyage:build:linkage"]
    require(licenses == [record["license"]["spdx"]] and linkages == [record["build"]["linkage"]],
            "static license/linkage declaration mismatch")
    cpe = matching_cpe(record)
    if cpe:
        require(matches[0].get("cpe") == cpe and matches[0].get("hashes") == [
            {"alg": "SHA-256", "content": record["source"]["archive_sha256"]}],
            "static c-ares CPE/archive declaration mismatch")
    patches = []
    # Seastar carries build.local_patches; other dependencies use top-level patches.
    for patch in record.get("patches", []) + record.get("build", {}).get("local_patches", []):
        name = patch.get("path", patch.get("file"))
        sha = patch.get("sha256")
        require(isinstance(sha, str) and SHA.fullmatch(sha) and digest(read_source(name)) == sha,
                "producer patch checksum mismatch")
        patches.append({"path": name, "sha256": sha})
    vendored = []
    for name, sha in record["source"].get("files", {}).items():
        source_name = "third_party/opentelemetry-proto/" + name if record["name"] == "opentelemetry-proto" else name
        require(isinstance(sha, str) and SHA.fullmatch(sha) and digest(read_source(source_name)) == sha,
                "producer vendored source checksum mismatch")
        vendored.append({"path": source_name, "sha256": sha})
    if record["license"].get("sha256"):
        name, sha = record["license"]["source_file"], record["license"]["sha256"]
        require(SHA.fullmatch(sha) and digest(read_source(name)) == sha, "vendored license checksum mismatch")
        vendored.append({"path": name, "sha256": sha})
    return {"name": record["name"], "version": record["version"], "record_sha256": digest(raw),
            "evidence_kind": "producer-declared-static-or-generated-component",
            "source": record["source"], "declared_license": record["license"]["spdx"],
            "declared_linkage": record["build"]["linkage"], "verified_producer_patches": patches,
            "verified_vendored_files": vendored, **({"matching": {"cpe": cpe}} if cpe else {})}


def parse_ldd(text):
    paths = set()
    for line in text.splitlines():
        line = line.strip()
        require("not found" not in line, "unresolved runtime library")
        if not line or re.fullmatch(r"linux-vdso\.so\.\d+ \(0x[0-9a-f]+\)", line):
            continue
        match = re.fullmatch(r"(?:[^\s]+ => )?(/[^\s]+) \(0x[0-9a-f]+\)", line)
        require(match, "unsupported ldd output")
        paths.add(match.group(1))
    require(paths, "runtime dynamic closure is empty")
    return sorted(paths)


def parse_maps(text):
    records = {}
    for line in text.splitlines():
        fields = line.split(None, 5)
        require(len(fields) >= 5 and re.fullmatch(r"[0-9a-f]+-[0-9a-f]+", fields[0]) and
                re.fullmatch(r"[r-][w-][x-][ps]", fields[1]) and
                re.fullmatch(r"[0-9a-f]+", fields[2]) and re.fullmatch(r"[0-9a-f]+:[0-9a-f]+", fields[3]) and
                fields[4].isdigit(), "malformed process map")
        if fields[4] == "0":
            continue
        # Linux AIO uses anonymous pseudo-files, not a deleted userspace ELF.
        if len(fields) == 6 and fields[5] == "/[aio] (deleted)":
            require(fields[1] == "rw-s" and int(fields[2], 16) == 0 and
                    int(fields[3].split(":")[0], 16) == 0, "unexpected kernel AIO mapping")
            continue
        require(len(fields) == 6 and fields[5].startswith("/") and not fields[5].endswith(" (deleted)") and
                "\\" not in fields[5], "unsupported/deleted file mapping")
        major, minor = [int(n, 16) for n in fields[3].split(":")]
        value = {"device_major": major, "device_minor": minor, "inode": int(fields[4])}
        require(fields[5] not in records or records[fields[5]] == value, "inconsistent process map identity")
        records[fields[5]] = value
    require(records, "process file mappings missing")
    return records


def verify_mapping(path, record):
    value = Path(path).stat()
    require((os.major(value.st_dev), os.minor(value.st_dev), value.st_ino) ==
            (record["device_major"], record["device_minor"], record["inode"]), "mapped file device/inode mismatch")


def package_owner(text, path):
    owners = []
    for line in text.splitlines():
        owner, separator, name = line.partition(": ")
        if separator and name == path and PACKAGE.fullmatch(owner):
            owners.append(owner)
    require(len(set(owners)) == 1, "exact unambiguous Ubuntu package owner required")
    return owners[0]


def package_control(text, owner):
    fields = Parser().parsestr(text)
    require(all(len(fields.get_all(k, [])) == 1 for k in ("Package", "Version", "Architecture", "Status")),
            "unique package control fields required")
    require(fields["Package"] == owner.split(":")[0] and fields["Architecture"] == "amd64" and
            fields["Status"] == "install ok installed" and fields["Version"].strip(), "installed AMD64 package required")
    return {"name": fields["Package"], "version": fields["Version"], "architecture": fields["Architecture"]}


def process_state():
    raw = run("systemctl", "show", "bonvoyage.service", "-p", "Id", "-p", "ActiveState", "-p", "MainPID",
              "-p", "NRestarts", "-p", "FragmentPath")
    fields = dict(line.split("=", 1) for line in raw.decode().splitlines())
    require(fields.get("Id") == "bonvoyage.service" and fields.get("ActiveState") == "active" and
            fields.get("MainPID", "").isdigit() and int(fields["MainPID"]) > 1 and
            fields.get("NRestarts", "").isdigit(), "active gateway service required")
    pid = int(fields["MainPID"])
    body = Path(f"/proc/{pid}/stat").read_text()
    require(body.startswith(str(pid) + " ("), "process identity mismatch")
    ticks = body[body.rfind(")") + 2:].split()[19]
    require(ticks.isdigit(), "process start time required")
    return {"pid": pid, "start_ticks": ticks, "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "restarts": int(fields["NRestarts"]), "unit": identity(Path(fields["FragmentPath"]).resolve()),
            "executable": str(Path(f"/proc/{pid}/exe").resolve(strict=True))}, raw


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def collect(request, anchor, output):
    require(platform.system() == "Linux" and platform.machine() == "x86_64" and os.geteuid() == 0,
            "root read access on Ubuntu AMD64 required")
    release = Path("/etc/os-release").read_text()
    require(re.search(r'^ID=ubuntu$', release, re.M) and re.search(r'^VERSION_ID="24\.04"$', release, re.M),
            "Ubuntu 24.04 host required")
    spec, request_record = load_request(request, anchor)
    before = source_state(ROOT)
    collector_record = identity(Path(__file__).resolve())
    receipt, inputs, sbom = verify_binding(spec)
    binary = Path(spec["files"]["binary"]["path"])
    expected = "/usr/local/bin/bonvoyage-dataplane" if spec["runtime_profile"] == "source-install" else "/usr/bin/bonvoyage-dataplane"
    require(str(binary) == expected, "runtime profile path mismatch")
    packaging_commit = receipt["packaging_source"]["commit"]
    for name, sha in receipt["binding"]["source_files"].items():
        require(digest(git_file(packaging_commit, name)) == sha, "packaging source checksum mismatch")
    require(digest(git_file(packaging_commit, "packaging/systemd/bonvoyage.service")) == receipt["binding"]["source_unit_sha256"] and
            digest(git_file(packaging_commit, "scripts/build-native-deb.py")) == receipt["binding"]["builder_sha256"],
            "package builder identity mismatch")
    control = run("dpkg-deb", "--field", spec["files"]["package"]["path"]).decode()
    fields = Parser().parsestr(control)
    require(all(len(fields.get_all(k, [])) == 1 for k in ("Package", "Architecture", "Version")) and
            fields["Package"] == "bonvoyage-gateway" and fields["Architecture"] == "amd64" and
            fields["Version"] == inputs["version"], "native archive control mismatch")
    if spec["runtime_profile"] == "package-install":
        installed = package_control(run("dpkg-query", "--status", "bonvoyage-gateway").decode(), "bonvoyage-gateway")
        require(installed["version"] == inputs["version"], "installed gateway version mismatch")
        require(package_owner(run("dpkg-query", "--search", str(binary)).decode(), str(binary)) == "bonvoyage-gateway",
                "installed executable owner mismatch")
    state, service_raw = process_state()
    require(state["executable"] == str(binary), "service executable differs from bound binary")
    with binary.open("rb") as stream:
        header = stream.read(64)
        require(len(header) == 64 and header[:7] == b"\x7fELF\x02\x01\x01" and
                struct.unpack_from("<H", header, 18)[0] == 62 and struct.unpack_from("<H", header, 16)[0] in (2, 3),
                "AMD64 ELF executable required")
    require(not output.exists() and not output.is_symlink(), "new private output directory required")
    require(output.is_absolute() and output.resolve() == output, "canonical output directory required")
    output.mkdir(mode=0o700)
    (output / "provenance").mkdir(mode=0o700)
    result = {"schema_version": 1, "classification": "private-native-runtime-inventory", "outcome": "collecting",
              "collector_source": before, "collector": collector_record, "request": request_record,
              "producer_source_commit": spec["producer_source_commit"], "packaging_source_commit": packaging_commit,
              "runtime_profile": spec["runtime_profile"], "files": spec["files"], "process": state,
              **{flag: False for flag in FLAGS}}
    write_json(output / "inventory.json", result)
    try:
        (output / "service.txt").write_bytes(service_raw)
        (output / "os-release").write_text(release, encoding="utf-8")
        (output / "package-control.txt").write_text(control, encoding="utf-8")
        ldd = run("ldd", str(binary)).decode()
        (output / "ldd.txt").write_text(ldd, encoding="utf-8")
        maps_raw = Path(f"/proc/{state['pid']}/maps").read_text()
        (output / "process-maps.txt").write_text(maps_raw, encoding="utf-8")
        maps = parse_maps(maps_raw)
        result["excluded_kernel_aio_mapping_count"] = sum(line.endswith("/[aio] (deleted)") for line in maps_raw.splitlines())
        resolved = {str(Path(p).resolve(strict=True)) for p in parse_ldd(ldd)}
        mapped = set()
        for name, record in maps.items():
            verify_mapping(name, record)
            path = Path(name).resolve(strict=True)
            with path.open("rb") as stream:
                if stream.read(4) == b"\x7fELF" and path != binary:
                    mapped.add(str(path))
        require(str(binary) in maps and resolved and mapped and resolved <= mapped,
                "declared closure not fully present in live ELF mappings")
        packages, libraries = {}, []
        for name in sorted(resolved | mapped):
            path = Path(name)
            mode = path.stat()
            require(mode.st_uid == 0 and not mode.st_mode & 0o022, "root-owned non-writable library required")
            library = identity(path)
            owner_raw = run("dpkg-query", "--search", name).decode()
            owner = package_owner(owner_raw, name)
            if owner not in packages:
                package_raw = run("dpkg-query", "--status", owner).decode()
                package = package_control(package_raw, owner)
                notice = Path("/usr/share/doc") / package["name"] / "copyright"
                notice = notice.resolve(strict=True)
                require(notice.is_relative_to(Path("/usr/share/doc")), "copyright path outside Ubuntu documentation")
                package["copyright"] = identity(notice, NOTICE_LIMIT)
                package["control_sha256"] = digest(package_raw.encode())
                (output / "provenance" / (owner + ".control")).write_text(package_raw, encoding="utf-8")
                (output / "provenance" / (owner + ".copyright")).write_bytes(notice.read_bytes())
                packages[owner] = package
            library.update({"owner": owner, "resolved_by_ldd": name in resolved, "observed_in_process": name in mapped})
            libraries.append(library)
        static = producer_declarations(spec["producer_source_commit"], sbom)
        for name, record in maps.items():
            verify_mapping(name, record)
        for library in libraries:
            require(identity(library["path"]) == {k: library[k] for k in ("path", "bytes", "sha256")}, "library changed")
        for owner, package in packages.items():
            require(digest(run("dpkg-query", "--status", owner)) == package["control_sha256"] and
                    identity(package["copyright"]["path"], NOTICE_LIMIT) == package["copyright"], "package metadata changed")
        require(process_state()[0] == state, "gateway process/service changed during collection")
        require(source_state(ROOT) == before and identity(Path(__file__).resolve()) == collector_record,
                "collector source changed")
        require(load_request(request, anchor)[0] == spec, "request changed")
        result.update({"outcome": "collected-unqualified", "dynamic_libraries": libraries, "ubuntu_packages": packages,
                       "declared_components": static, "collected_at": datetime.now(timezone.utc).isoformat(),
                       "limitations": ["Read-only source-install is byte-equivalent to the bound package input, not an installed-package acceptance." if
                           spec["runtime_profile"] == "source-install" else "Installed-package observation is not full lifecycle acceptance.",
                           "Static/generated components are producer declarations, not independent binary discovery.",
                           "Package ownership and hashes do not establish signed APT provenance or license clearance.",
                           "No inherited container scan, SBOM schema validation, fresh native scan, performance or release qualification.",
                           "Observed ELF closure excludes unexercised dynamic loading, whole-host software and private configuration."]})
        write_json(output / "inventory.json", result)
        seal = {"schema_version": 1, "files": []}
        for path in sorted(output.rglob("*")):
            if path.is_file():
                path.chmod(0o600)
                record = identity(path)
                record["path"] = str(path.relative_to(output))
                seal["files"].append(record)
        write_json(output / "checksums.json", seal)
        return result
    except Exception as error:
        result.update({"outcome": "failed", "error": str(error)})
        write_json(output / "inventory.json", result)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    result = collect(args.inputs.absolute(), args.manifest_sha256, args.output.absolute())
    print(json.dumps({"outcome": result["outcome"], "libraries": len(result["dynamic_libraries"]),
                      "packages": len(result["ubuntu_packages"]), "declared_components": len(result["declared_components"]),
                      "collector_source": result["collector_source"], **{flag: result[flag] for flag in FLAGS}}, indent=2))
