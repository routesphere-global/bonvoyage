#!/usr/bin/env python3
"""Generate private native SBOMs from a fresh host inventory, without release promotion."""

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from urllib.parse import quote, urlsplit, parse_qsl, unquote
import uuid

MODULE = importlib.util.spec_from_file_location("native_inventory", Path(__file__).with_name("collect-native-runtime.py"))
runtime = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(runtime)
ROOT = runtime.ROOT
require = runtime.require
SYFT = "anchore/syft:v1.44.0@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6"
CDX = "cyclonedx/cyclonedx-cli:0.33.1@sha256:9a37575fb51fcaed3a4c62dddba091c46ffc867712e46bdb6cdf219a7e90a061"
SPDX_SCHEMA_SHA = "239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b"
APP = "SPDXRef-BonVoyage"
DEB = "SPDXRef-BonVoyageArchive"
LIMIT = 32 * 1024 * 1024


def file_record(path):
    return runtime.identity(path)


def evidence_record(path):
    require(path.resolve() == path, "canonical evidence file required")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                0 <= before.st_size <= 256 * 1024 * 1024, "bounded regular evidence file required")
        value = hashlib.sha256()
        size = 0
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            require(size <= 256 * 1024 * 1024, "evidence file grew")
            value.update(chunk)
        after = os.fstat(stream.fileno())
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and size == after.st_size,
            "evidence changed while hashing")
    return {"path": str(path), "bytes": size, "sha256": value.hexdigest()}


def read_json(path, maximum=LIMIT):
    record = runtime.identity(path, maximum)
    data = Path(path).read_bytes()
    require(runtime.digest(data) == record["sha256"], "JSON changed while reading")
    return runtime.decode(data)


def relative(name):
    require(isinstance(name, str) and name and not name.startswith("/") and
            str(Path(name)) == name and ".." not in Path(name).parts, "safe relative path required")
    return name


def safe_tree(directory):
    require(directory.is_absolute() and directory.resolve() == directory and not directory.is_symlink(),
            "canonical private tree required")
    for item in [directory] + list(directory.rglob("*")):
        mode = item.lstat()
        require(not stat.S_ISLNK(mode.st_mode) and (stat.S_ISDIR(mode.st_mode) or stat.S_ISREG(mode.st_mode)),
                "unsafe generated report entry")
        require(not stat.S_ISREG(mode.st_mode) or mode.st_nlink == 1, "hard-linked generated report")


def write_json(path, value):
    require(path.parent.resolve() == path.parent, "unsafe output parent")
    descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        mode = os.fstat(stream.fileno())
        require(stat.S_ISREG(mode.st_mode) and mode.st_nlink == 1, "unsafe JSON output file")
        stream.truncate(0)
        stream.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
        stream.flush()
        os.fchmod(stream.fileno(), 0o600)


def verify_live(inventory, directory):
    state, _ = runtime.process_state()
    require(state == inventory["process"], "fresh live process inventory required")
    expected_maps = runtime.parse_maps((directory / "process-maps.txt").read_text())
    live_maps = runtime.parse_maps(Path("/proc", str(state["pid"]), "maps").read_text())
    actual = set()
    binary = inventory["files"]["binary"]["path"]
    for name, record in live_maps.items():
        runtime.verify_mapping(name, record)
        path = Path(name).resolve(strict=True)
        with path.open("rb") as stream:
            if stream.read(4) == b"\x7fELF":
                actual.add(str(path))
                require(name in expected_maps and expected_maps[name] == record, "live ELF mapping identity changed")
    expected = {binary} | {item["path"] for item in inventory["dynamic_libraries"]}
    require(actual == expected, "same-PID live ELF closure changed")
    resolved = {str(Path(name).resolve(strict=True)) for name in runtime.parse_ldd(runtime.run("ldd", binary).decode())}
    require(resolved == {p["path"] for p in inventory["dynamic_libraries"] if p["resolved_by_ldd"]},
            "runtime linker resolution changed")
    require(runtime.process_state()[0] == state, "gateway changed during live closure check")


def load_inventory(path, sha, seal_sha):
    record = runtime.identity(path, LIMIT)
    require(record["sha256"] == sha and runtime.SHA.fullmatch(seal_sha), "reviewed inventory/seal digests required")
    directory = Path(path).parent
    seal_path = directory / "checksums.json"
    require(file_record(seal_path)["sha256"] == seal_sha, "inventory seal digest mismatch")
    seal = read_json(seal_path)
    require(seal.get("schema_version") == 1 and isinstance(seal.get("files"), list) and seal["files"],
            "inventory seal required")
    names = set()
    for entry in seal["files"]:
        name = relative(entry["path"])
        require(name not in names and name != "checksums.json", "duplicate/self inventory seal entry")
        names.add(name)
        require(file_record(directory / name) == {**entry, "path": str(directory / name)}, "sealed inventory file changed")
    actual = set()
    for item in directory.rglob("*"):
        require(not item.is_symlink(), "symlink in inventory evidence")
        require(item.is_file() or item.is_dir(), "special inventory evidence file")
        if item.is_file() and item != seal_path:
            actual.add(str(item.relative_to(directory)))
    require(actual == names and "inventory.json" in names, "inventory seal coverage mismatch")
    inventory = read_json(path)
    require(inventory.get("classification") == "private-native-runtime-inventory" and
            type(inventory.get("schema_version")) is int and inventory["schema_version"] == 1 and
            inventory.get("outcome") == "collected-unqualified" and
            all(inventory.get(flag) is False for flag in runtime.FLAGS), "unqualified native inventory required")
    source = inventory.get("collector_source", {})
    require(source.get("dirty") is False and runtime.COMMIT.fullmatch(source.get("commit", "")) and
            source.get("status_sha256") == runtime.digest(b""), "clean collector source required")
    require(runtime.digest(runtime.git_file(source["commit"], "scripts/collect-native-runtime.py")) ==
            inventory["collector"]["sha256"], "committed collector checksum mismatch")
    require(inventory.get("runtime_profile") in ("source-install", "package-install"), "explicit native profile required")
    request_path = runtime.anchored(inventory["request"])
    spec, _ = runtime.load_request(request_path, inventory["request"]["sha256"])
    require(spec["files"] == inventory["files"] and spec["producer_source_commit"] == inventory["producer_source_commit"] and
            spec["runtime_profile"] == inventory["runtime_profile"], "inventory input binding mismatch")
    receipt, inputs, producer_sbom = runtime.verify_binding(spec)
    require(receipt["packaging_source"]["commit"] == inventory["packaging_source_commit"], "package source mismatch")
    expected = runtime.producer_declarations(inventory["producer_source_commit"], producer_sbom)
    declarations = inventory.get("declared_components", [])
    require(isinstance(declarations, list) and all(isinstance(d, dict) and isinstance(d.get("name"), str) for d in declarations) and
            sorted(declarations, key=lambda d: d["name"]) == sorted(expected, key=lambda d: d["name"]),
            "inventory differs from producer-bound declarations")
    return inventory, inputs, record, file_record(seal_path)


def validate_closure(inventory):
    packages = inventory.get("ubuntu_packages")
    libraries = inventory.get("dynamic_libraries")
    declarations = inventory.get("declared_components")
    require(isinstance(packages, dict) and packages and len(packages) <= 128 and
            isinstance(libraries, list) and libraries and len(libraries) <= 256 and
            isinstance(declarations, list), "bounded native closure required")
    paths = set()
    owners = set()
    for owner, package in packages.items():
        require(runtime.PACKAGE.fullmatch(owner) and package["name"] == owner.split(":")[0] and
                package["architecture"] == "amd64" and package["version"], "AMD64 package identity required")
    for library in libraries:
        name = library["path"]
        require(name.startswith("/usr/lib/") and name not in paths and library["owner"] in packages and
                type(library["observed_in_process"]) is bool and type(library["resolved_by_ldd"]) is bool and
                library["observed_in_process"], "unique observed owned native library required")
        paths.add(name)
        owners.add(library["owner"])
    require(owners == set(packages), "orphan/missing native package owner")
    names = [item.get("name") for item in declarations]
    records = runtime.producer_records(inventory.get("producer_source_commit"))
    if "llhttp" in names and runtime.LLHTTP_RECORD not in records:
        records[runtime.LEGACY_LLHTTP_CANDIDATE_RECORD] = runtime.git_file(
            inventory["producer_source_commit"], runtime.LEGACY_LLHTTP_CANDIDATE_RECORD)
    expected = {runtime.validate_record(raw)["name"]: (path, raw) for path, raw in records.items()}
    require(len(names) == len(set(names)) and set(names) == set(expected), "complete producer declaration set required")
    for item in declarations:
        path, raw = expected[item["name"]]
        record = runtime.validate_record(raw)
        cpe = runtime.matching_cpe(record)
        require(item.get("evidence_kind") == "producer-declared-static-or-generated-component" and
                item.get("record_path") == path and item.get("record_sha256") == runtime.digest(raw) and
                item.get("version") == record["version"] and item.get("source") == record["source"] and
                item.get("declared_license") == record["license"]["spdx"] and
                item.get("declared_linkage") == record["build"]["linkage"] and
                item.get("matching", {}) == ({"cpe": cpe} if cpe else {}), "producer declaration identity required")


def verify_snapshot(snapshot, manifest):
    names = set()
    for item in manifest:
        name = relative(item["path"])
        require(name not in names, "duplicate snapshot file")
        names.add(name)
        value = file_record(snapshot / name)
        require(value["sha256"] == item["sha256"] and value["bytes"] == item["bytes"], "snapshot changed")
        if "sha1" in item:
            require(hashlib.sha1((snapshot / name).read_bytes()).hexdigest() == item["sha1"], "snapshot SHA1 changed")
    actual = set()
    for item in snapshot.rglob("*"):
        require(not item.is_symlink() and (item.is_dir() or item.is_file()), "unsafe snapshot file")
        if item.is_file():
            actual.add(str(item.relative_to(snapshot)))
    require(actual == names, "snapshot coverage mismatch")


def validate_manifest(inventory, manifest):
    expected = {"usr/bin/bonvoyage-dataplane": inventory["files"]["binary"]}
    expected.update({p["path"].lstrip("/"): p for p in inventory["dynamic_libraries"]})
    actual = [p for p in manifest if p["subject"] in ("native-executable", "observed-runtime-library")]
    require(len(actual) == len(expected) and {p["path"] for p in actual} == set(expected), "runtime manifest coverage mismatch")
    for item in actual:
        bound = expected[item["path"]]
        require(item["sha256"] == bound["sha256"] and item["bytes"] == bound["bytes"] and
                item["host_path"] == bound["path"] and
                item.get("owner") == bound.get("owner") and re.fullmatch("[a-f0-9]{40}", item["sha1"]),
                "runtime manifest identity mismatch")


def stage(inventory, output):
    validate_closure(inventory)
    verify_live(inventory, output / "inventory")
    snapshot = output / "snapshot"
    snapshot.mkdir(mode=0o700)
    manifest = []

    def copy_record(record, destination, subject, owner=None):
        source = runtime.anchored({k: record[k] for k in ("path", "bytes", "sha256")})
        require(source.stat().st_uid == 0 and not source.stat().st_mode & 0o022, "root-owned immutable runtime input required")
        target = snapshot / relative(destination)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if target.exists():
            require(file_record(target)["sha256"] == record["sha256"], "snapshot path collision")
        else:
            shutil.copyfile(source, target)
            target.chmod(0o600)
        require(file_record(target)["sha256"] == record["sha256"] and file_record(target)["bytes"] == record["bytes"] and
                file_record(source) == {k: record[k] for k in ("path", "bytes", "sha256")}, "runtime input changed during staging")
        entry = {"path": destination, "bytes": record["bytes"], "sha256": record["sha256"],
                 "sha1": hashlib.sha1(target.read_bytes()).hexdigest(), "subject": subject, "host_path": str(source)}
        if owner:
            entry["owner"] = owner
        if not any(value["path"] == destination for value in manifest):
            manifest.append(entry)

    copy_record(inventory["files"]["binary"], "usr/bin/bonvoyage-dataplane", "native-executable")
    for library in inventory["dynamic_libraries"]:
        copy_record(library, library["path"].lstrip("/"), "observed-runtime-library", library["owner"])
    controls = []
    for owner, package in sorted(inventory["ubuntu_packages"].items()):
        raw = runtime.run("dpkg-query", "--status", owner)
        require(runtime.digest(raw) == package["control_sha256"] and
                runtime.package_control(raw.decode(), owner) ==
                {k: package[k] for k in ("name", "version", "architecture")}, "live package metadata changed")
        require(raw == (output / "inventory" / "provenance" / (owner + ".control")).read_bytes(),
                "sealed package control differs from live host")
        controls.append(raw.rstrip() + b"\n\n")
        copy_record(package["copyright"], package["copyright"]["path"].lstrip("/"), "package-notice")
    status = snapshot / "var/lib/dpkg/status"
    status.parent.mkdir(mode=0o700, parents=True)
    status.write_bytes(b"".join(controls))
    release = snapshot / "etc/os-release"
    release.parent.mkdir(mode=0o700)
    release.write_bytes((output / "inventory" / "os-release").read_bytes())
    require(release.read_bytes() == Path("/etc/os-release").read_bytes(), "host distribution changed")
    # Catalogers see only the observed runtime closure, not the host toolchain or private config.
    for item in (status, release):
        item.chmod(0o600)
        record = file_record(item)
        manifest.append({**record, "path": str(item.relative_to(snapshot)), "subject": "staged-package-metadata"})
    commit = inventory["producer_source_commit"]
    for item in inventory["declared_components"]:
        require(runtime.digest(runtime.git_file(commit, item["record_path"])) == item["record_sha256"],
                "producer record changed")
        for value in item["verified_producer_patches"] + item["verified_vendored_files"]:
            require(runtime.digest(runtime.git_file(commit, value["path"])) == value["sha256"], "producer source evidence changed")
    write_json(output / "snapshot-manifest.json", {"schema_version": 1, "files": sorted(manifest, key=lambda v: v["path"]),
                       "scope": "observed ELF closure and selected host package metadata, not complete package payloads"})
    return manifest


def identifiers(inventory):
    owners = sorted(inventory["ubuntu_packages"])
    return {owner: "SPDXRef-Ubuntu-" + str(index) for index, owner in enumerate(owners)}


def properties(**values):
    return [{"name": "bonvoyage:native:" + name, "value": str(value)} for name, value in values.items()]


def declaration_properties(item):
    return properties(evidence_kind=item["evidence_kind"], source_commit=item["source"]["commit"],
                      record_sha256=item["record_sha256"], linkage=item["declared_linkage"],
                      patches=json.dumps(item["verified_producer_patches"], sort_keys=True),
                      vendored_files=json.dumps(item["verified_vendored_files"], sort_keys=True),
                      source_archive_sha256=item["source"].get("archive_sha256", "not-declared"))


def verification(files):
    return hashlib.sha1("".join(sorted(item["sha1"] for item in files)).encode()).hexdigest()


def package_references(cdx, spdx, package):
    refs = spdx.get("externalRefs", [])
    require(isinstance(refs, list) and all(isinstance(r, dict) for r in refs), "raw SPDX references required")
    purls = [r for r in refs if r.get("referenceType") == "purl"]
    require(len(purls) == 1 and purls[0].get("referenceCategory") == "PACKAGE-MANAGER" and
            purls[0].get("referenceLocator") == cdx.get("purl"), "raw cross-format PURL identity mismatch")
    purl = urlsplit(cdx.get("purl", ""))
    qualifiers = parse_qsl(purl.query, strict_parsing=True)
    require(purl.scheme == "pkg" and not purl.netloc and not purl.fragment and
            unquote(purl.path) == "deb/ubuntu/" + package["name"] + "@" + package["version"] and
            len(dict(qualifiers)) == len(qualifiers) and dict(qualifiers).get("arch") == "amd64" and
            dict(qualifiers).get("distro") == "ubuntu-24.04", "raw Ubuntu package PURL qualifiers required")
    cpes = [r for r in refs if r.get("referenceType") == "cpe23Type"]
    require(all(r.get("referenceCategory") == "SECURITY" and
                isinstance(r.get("referenceLocator"), str) and r["referenceLocator"].startswith("cpe:2.3:") for r in cpes) and
            (not cdx.get("cpe") or any(r["referenceLocator"] == cdx["cpe"] for r in cpes)),
            "raw CPE reference identity mismatch")
    require(len({json.dumps(r, sort_keys=True) for r in refs}) == len(refs), "duplicate raw package references")
    return copy.deepcopy(refs)


def enrich(inventory, inputs, manifest, raw_cdx, raw_spdx, binding):
    validate_closure(inventory)
    validate_manifest(inventory, manifest)
    require(raw_cdx.get("bomFormat") == "CycloneDX" and raw_cdx.get("specVersion") == "1.6" and
            raw_spdx.get("spdxVersion") == "SPDX-2.3", "generator emitted wrong format version")
    packages = inventory["ubuntu_packages"]
    expected = {(p["name"], p["version"]) for p in packages.values()}
    raw_components = raw_cdx.get("components", [])
    operating_system = [p for p in raw_components if p.get("type") == "operating-system"]
    require(len(operating_system) == 1 and operating_system[0].get("name") == "ubuntu" and
            operating_system[0].get("version") == "24.04", "raw Ubuntu distribution identity required")
    cdx_packages = [p for p in raw_components if p.get("type") != "operating-system"]
    raw_packages = raw_spdx.get("packages", [])
    roots = [p for p in raw_packages if p.get("name") == "bonvoyage-native-runtime"]
    require(len(roots) <= 1 and all(p.get("primaryPackagePurpose") == "FILE" for p in roots),
            "unexpected raw SPDX source root")
    spdx_packages = [p for p in raw_packages if p.get("name") != "bonvoyage-native-runtime"]
    require(len(cdx_packages) == len(expected) and {(p.get("name"), p.get("version")) for p in cdx_packages} == expected and
            len(spdx_packages) == len(expected) and {(p.get("name"), p.get("versionInfo")) for p in spdx_packages} == expected,
            "raw generator omitted/duplicated/added selected Ubuntu packages")
    owner_ids = identifiers(inventory)
    by_name = {p["name"]: owner for owner, p in packages.items()}
    raw_spdx_by_name = {p["name"]: p for p in spdx_packages}
    references = {p["name"]: package_references(p, raw_spdx_by_name[p["name"]], packages[by_name[p["name"]]])
                  for p in cdx_packages}
    runtime_files = [item for item in manifest if item["subject"] in ("native-executable", "observed-runtime-library")]
    require(len(runtime_files) == len(inventory["dynamic_libraries"]) + 1, "snapshot runtime file completeness")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    binary = inventory["files"]["binary"]
    root = {"type": "application", "bom-ref": APP, "name": "bonvoyage-dataplane",
            "version": inputs["version"], "hashes": [{"alg": "SHA-256", "content": binary["sha256"]}],
            "properties": properties(checksum_subject="native-executable", **binding)}
    os_component = copy.deepcopy(operating_system[0])
    os_component["bom-ref"] = "SPDXRef-UbuntuOS"
    os_component["properties"] = os_component.get("properties", []) + properties(evidence_kind="live-Ubuntu-release-metadata")
    components = [os_component]
    dependencies = []
    for raw in cdx_packages:
        item = copy.deepcopy(raw)
        owner = by_name[item["name"]]
        item["bom-ref"] = owner_ids[owner]
        item["properties"] = item.get("properties", []) + properties(
            evidence_kind="host-dpkg-control-and-observed-ELF", architecture="amd64",
            control_sha256=packages[owner]["control_sha256"], payload_scope="observed-runtime-subset")
        components.append(item)
    components.append({"type": "application", "bom-ref": DEB, "name": "bonvoyage-gateway", "version": inputs["version"],
                       "purl": "pkg:generic/bonvoyage-gateway@" + quote(inputs["version"], safe=""),
                       "hashes": [{"alg": "SHA-256", "content": inventory["files"]["package"]["sha256"]}],
                       "properties": properties(evidence_kind="bound-private-debian-archive", checksum_subject="complete-debian-archive",
                                                installation_profile=inventory["runtime_profile"])})
    for index, item in enumerate(inventory["declared_components"]):
        components.append({"type": "library", "bom-ref": "SPDXRef-Static-" + str(index), "name": item["name"],
                           "version": item["version"], "purl": "pkg:generic/" + item["name"] + "@" + quote(item["version"], safe=""),
                           "licenses": [{"license": {"id": item["declared_license"]}}],
                           "properties": declaration_properties(item),
                           **({"cpe": item["matching"]["cpe"]} if item.get("matching", {}).get("cpe") else {})})
    for index, item in enumerate(runtime_files):
        components.append({"type": "file", "bom-ref": "SPDXRef-File-" + str(index), "name": "./" + item["path"],
                           "hashes": [{"alg": "SHA-256", "content": item["sha256"]}, {"alg": "SHA-1", "content": item["sha1"]}],
                           "properties": properties(evidence_kind=item["subject"], host_path=item["host_path"],
                                                    owner=item.get("owner", "bonvoyage-dataplane"))})
    deps = ["SPDXRef-UbuntuOS"] + list(owner_ids.values()) + ["SPDXRef-Static-" + str(i) for i in range(len(inventory["declared_components"]))]
    dependencies.append({"ref": APP, "dependsOn": sorted(deps)})
    dependencies.append({"ref": DEB, "dependsOn": [APP]})
    for owner, ref in owner_ids.items():
        dependencies.append({"ref": ref, "dependsOn": sorted("SPDXRef-File-" + str(i) for i, f in enumerate(runtime_files)
                                                           if f.get("owner") == owner)})
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
           "metadata": {"timestamp": timestamp, "component": root,
                        "tools": {"components": [{"type": "application", "name": "syft", "version": "1.44.0"}]}},
           "components": components, "dependencies": dependencies}
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": APP},
                     {"spdxElementId": DEB, "relationshipType": "CONTAINS", "relatedSpdxElement": APP}]
    spdx_files = []
    for index, item in enumerate(runtime_files):
        ref = "SPDXRef-File-" + str(index)
        spdx_files.append({"SPDXID": ref, "fileName": "./" + item["path"], "fileTypes": ["BINARY"],
                           "checksums": [{"algorithm": "SHA1", "checksumValue": item["sha1"]},
                                         {"algorithm": "SHA256", "checksumValue": item["sha256"]}],
                           "licenseConcluded": "NOASSERTION", "licenseInfoInFiles": ["NOASSERTION"],
                           "copyrightText": "NOASSERTION", "comment": json.dumps({k: item[k] for k in ("subject", "host_path")})})
        owner = owner_ids.get(item.get("owner"), APP)
        relationships.append({"spdxElementId": owner, "relationshipType": "CONTAINS", "relatedSpdxElement": ref})

    def package(ref, name, version, purpose, files=None, license_declared="NOASSERTION", source_info=None):
        result = {"SPDXID": ref, "name": name, "versionInfo": version, "downloadLocation": "NOASSERTION",
                  "primaryPackagePurpose": purpose, "filesAnalyzed": files is not None,
                  "licenseDeclared": license_declared, "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION",
                  "licenseComments": "Declaration/notice evidence only; no license clearance conclusion.",
                  "sourceInfo": source_info or "Native observed runtime subset; not a complete package payload."}
        if files is not None:
            result["packageVerificationCode"] = {"packageVerificationCodeValue": verification(files)}
            result["licenseInfoFromFiles"] = ["NOASSERTION"]
        return result
    spdx_packages = [package(APP, "bonvoyage-dataplane", inputs["version"], "APPLICATION",
                             [f for f in runtime_files if f["subject"] == "native-executable"],
                             source_info=json.dumps(binding, sort_keys=True)),
                     package(DEB, "bonvoyage-gateway", inputs["version"], "APPLICATION",
                             source_info="Bound private Debian archive; installation profile " + inventory["runtime_profile"])]
    spdx_packages[0]["checksums"] = [{"algorithm": "SHA256", "checksumValue": binary["sha256"]}]
    spdx_packages[1]["checksums"] = [{"algorithm": "SHA256", "checksumValue": inventory["files"]["package"]["sha256"]}]
    spdx_packages.append(package("SPDXRef-UbuntuOS", "ubuntu", "24.04", "OPERATING_SYSTEM",
                                 source_info="Live Ubuntu release metadata; not an inventory of the whole operating system."))
    relationships.append({"spdxElementId": APP, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-UbuntuOS"})
    for owner, ref in owner_ids.items():
        item = packages[owner]
        spdx_packages.append(package(ref, item["name"], item["version"], "LIBRARY",
                                     [f for f in runtime_files if f.get("owner") == owner],
                                     source_info="Host package control SHA256=" + item["control_sha256"] +
                                     "; observed ELF subset only; SHA1 verification code is not a complete Ubuntu package checksum."))
        spdx_packages[-1]["externalRefs"] = references[item["name"]]
        relationships.extend([{"spdxElementId": APP, "relationshipType": relation, "relatedSpdxElement": ref}
                              for relation in ("DEPENDS_ON", "DYNAMIC_LINK")])
    for index, item in enumerate(inventory["declared_components"]):
        ref = "SPDXRef-Static-" + str(index)
        spdx_packages.append(package(ref, item["name"], item["version"], "LIBRARY",
                                     license_declared=item["declared_license"], source_info=json.dumps(item, sort_keys=True)))
        spdx_packages[-1]["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
            "referenceLocator": "pkg:generic/" + item["name"] + "@" + quote(item["version"], safe="")}]
        if item.get("matching", {}).get("cpe"):
            spdx_packages[-1]["externalRefs"].append({"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                                                    "referenceLocator": item["matching"]["cpe"]})
        relationships.append({"spdxElementId": APP, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": ref})
        if item["declared_linkage"] == "static":
            relationships.append({"spdxElementId": APP, "relationshipType": "STATIC_LINK", "relatedSpdxElement": ref})
    spdx = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "bonvoyage-native-runtime", "documentNamespace": "https://routesphere.invalid/private/native/" + str(uuid.uuid4()),
            "creationInfo": {"created": timestamp, "creators": ["Tool: syft-1.44.0", "Tool: bonvoyage-native-runtime-sbom"]},
            "packages": spdx_packages, "files": spdx_files, "relationships": relationships}
    return cdx, spdx


def complete(inventory, inputs, manifest, cdx, spdx, binding, raw_cdx, raw_spdx):
    # Consistency check against the anchored inventory; this is not an independent audit.
    expected_cdx, expected_spdx = enrich(inventory, inputs, manifest, raw_cdx, raw_spdx, binding)
    require(cdx.get("bomFormat") == "CycloneDX" and cdx.get("specVersion") == "1.6" and
            spdx.get("spdxVersion") == "SPDX-2.3" and spdx.get("dataLicense") == "CC0-1.0", "SBOM version/data license changed")
    actual = cdx.get("components", [])
    expected = expected_cdx["components"]
    require(len(actual) == len(expected), "CycloneDX component completeness")
    by_ref = {item.get("bom-ref"): item for item in actual}
    require(len(by_ref) == len(actual) and set(by_ref) == {item["bom-ref"] for item in expected}, "CycloneDX unique complete IDs")
    for item in expected:
        value = by_ref[item["bom-ref"]]
        require(all(value.get(key) == val for key, val in item.items() if key != "properties"),
                "CycloneDX component version/hash/license identity mismatch")
        values = value.get("properties", [])
        native = [p for p in values if p["name"].startswith("bonvoyage:native:")]
        require(len({p["name"] for p in native}) == len(native) and
                all(prop in values for prop in item.get("properties", [])), "CycloneDX provenance completeness")
    require(cdx.get("metadata", {}).get("component") == expected_cdx["metadata"]["component"] and
            cdx.get("dependencies") == expected_cdx["dependencies"], "CycloneDX root/dependency linkage mismatch")
    for name in ("packages", "files", "relationships"):
        require(spdx.get(name) == expected_spdx[name], "SPDX " + name + " completeness/identity/linkage mismatch")
    return {"ubuntu_packages": len(inventory["ubuntu_packages"]), "dynamic_libraries": len(inventory["dynamic_libraries"]),
            "declared_components": len(inventory["declared_components"]), "runtime_files": len(spdx["files"]),
            "cyclonedx_components": len(actual), "spdx_packages": len(spdx["packages"])}


def decoded_identity(inventory, cdx, decoded):
    # Validate the real decoder's identity output, not just the JSON schema.
    distro = decoded.get("distro", {})
    require(distro.get("id") == "ubuntu" and distro.get("versionID") == "24.04", "decoded Ubuntu identity missing")
    artifacts = decoded.get("artifacts", [])
    require(isinstance(artifacts, list), "decoded artifact list required")
    deb = [a for a in artifacts if a.get("type") == "deb"]
    expected = {p["name"]: p["version"] for p in inventory["ubuntu_packages"].values()}
    require(len(deb) == len(expected) and {a.get("name"): a.get("version") for a in deb} == expected,
            "decoded Ubuntu package completeness/version mismatch")
    components = {c["name"]: c for c in cdx["components"] if c["type"] == "library"}
    for artifact in deb:
        # CycloneDX decoding can leave metadata.architecture blank; the anchored
        # PURL retains the architecture. Reject contradictory populated metadata.
        require(artifact.get("purl") == components[artifact["name"]]["purl"] and
                dict(parse_qsl(urlsplit(artifact.get("purl", "")).query)).get("arch") == "amd64" and
                artifact.get("metadata", {}).get("architecture", "") in ("", "amd64"), "decoded package PURL/architecture mismatch")
        cpe = components[artifact["name"]].get("cpe")
        require(not cpe or any(c.get("cpe") == cpe for c in artifact.get("cpes", [])), "decoded generator CPE missing")
    for declaration in inventory["declared_components"]:
        matches = [a for a in artifacts if a.get("name") == declaration["name"]]
        require(len(matches) == 1 and matches[0].get("version") == declaration["version"] and
                matches[0].get("purl") == components[declaration["name"]]["purl"], "decoded declaration identity missing")
        cpe = declaration.get("matching", {}).get("cpe")
        require(not cpe or any(c.get("cpe") == cpe for c in matches[0].get("cpes", [])), "decoded static CPE missing")
    return {"ubuntu_packages": len(deb), "declared_components": len(inventory["declared_components"]),
            "static_advisory_coverage_established": False}


def execute(output, name, argv, timeout=300):
    require(re.fullmatch("[a-z0-9-]+", name), "safe command record name")
    directory = output / "commands"
    directory.mkdir(mode=0o700, exist_ok=True)
    result = subprocess.run(argv, capture_output=True, timeout=timeout, env={**os.environ, "LC_ALL": "C"})
    (directory / (name + ".stdout")).write_bytes(result.stdout)
    (directory / (name + ".stderr")).write_bytes(result.stderr)
    write_json(directory / (name + ".json"), {"argv": argv, "exit_code": result.returncode})
    return result


def container(image, mounts):
    argv = ["/usr/bin/docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
            "--cpus", "2", "--memory", "1g", "--pids-limit", "128",
            "-e", "SYFT_CHECK_FOR_APP_UPDATE=false", "-e", "XDG_CACHE_HOME=/tmp"]
    for host, guest, mode in mounts:
        require(Path(host).is_absolute() and "," not in str(host), "canonical mount path required")
        argv += ["--mount", "type=bind,src=" + str(host) + ",dst=" + guest + (",readonly" if mode == "ro" else "")]
    return argv + [image]


def qualify(path, sha, seal_sha, output, validator_python, schema):
    require(os.geteuid() == 0 and not output.exists() and not output.is_symlink() and
            output.is_absolute() and output.resolve() == output, "root and new canonical private output required")
    inventory, inputs, inventory_record, seal_record = load_inventory(path, sha, seal_sha)
    before = runtime.source_state(ROOT)
    tooling = {name: file_record(ROOT / name) for name in
               ("scripts/native-runtime-sbom.py", "scripts/validate-native-spdx.py", "scripts/collect-native-runtime.py",
                "scripts/test_native_runtime_sbom.py", "Makefile", "security/tools/native-sbom-python.lock",
                "security/tools/native-sbom-python.provenance.json")}
    require(file_record(schema)["sha256"] == SPDX_SCHEMA_SHA, "official SPDX schema byte pin mismatch")
    require(validator_python.is_absolute() and validator_python.parent.name == "bin" and
            validator_python.name == "python" and validator_python.exists(), "reviewed validator virtual environment required")
    for item in (validator_python.parent, validator_python.parent.parent, validator_python.resolve(), schema):
        value = item.stat()
        require(value.st_uid == 0 and not value.st_mode & 0o022, "root-owned protected validator runtime required")
    output.mkdir(mode=0o700)
    receipt = {"schema_version": 1, "classification": "private-native-runtime-sbom",
               "outcome": "generating", "tooling_source": before, "tooling": tooling,
               "inventory": inventory_record, "inventory_seal": seal_record, "tools": {"syft": SYFT, "cyclonedx": CDX},
               "producer_source_commit": inventory["producer_source_commit"],
               "packaging_source_commit": inventory["packaging_source_commit"],
               **{flag: False for flag in runtime.FLAGS}}
    write_json(output / "result.json", receipt)
    try:
        shutil.copytree(Path(path).parent, output / "inventory")
        load_inventory(output / "inventory/inventory.json", sha, seal_sha)
        manifest = stage(inventory, output)
        reports = output / "reports"
        reports.mkdir(mode=0o700)
        argv = container(SYFT, [(output / "snapshot", "/snapshot", "ro"), (reports, "/reports", "rw")])
        argv += ["scan", "dir:/snapshot", "--override-default-catalogers", "dpkg-db-cataloger",
                 "--select-catalogers=-file",
                 "--source-name", "bonvoyage-native-runtime",
                 "-o", "cyclonedx-json@1.6=/reports/raw.cdx.json", "-o", "spdx-json@2.3=/reports/raw.spdx.json"]
        require(execute(output, "generate", argv).returncode == 0, "native generator failed")
        safe_tree(reports)
        binding = {"inventory_sha256": sha, "inventory_seal_sha256": seal_sha,
                   "snapshot_manifest_sha256": file_record(output / "snapshot-manifest.json")["sha256"],
                   "producer_commit": inventory["producer_source_commit"], "packaging_commit": inventory["packaging_source_commit"],
                   "tooling_commit": before["commit"], "tooling_dirty": str(before["dirty"]).lower(),
                   "scope": "observed-native-runtime-not-whole-host"}
        raw_cdx, raw_spdx = read_json(reports / "raw.cdx.json"), read_json(reports / "raw.spdx.json")
        cdx, spdx = enrich(inventory, inputs, manifest, raw_cdx, raw_spdx, binding)
        write_json(reports / "runtime.cdx.json", cdx)
        write_json(reports / "runtime.spdx.json", spdx)
        counts = complete(inventory, inputs, manifest, cdx, spdx, binding, raw_cdx, raw_spdx)
        decoder_checks = {}
        for kind in ("cdx", "spdx"):
            decoder = container(SYFT, [(reports, "/reports", "ro")]) + [
                "convert", "/reports/runtime." + kind + ".json", "-o", "syft-json"]
            result = execute(output, kind + "-decode", decoder)
            require(result.returncode == 0, "official SBOM decoder failed")
            decoder_checks[kind] = decoded_identity(inventory, cdx, runtime.decode(result.stdout))
        cdx_argv = container(CDX, [(reports, "/reports", "ro")]) + [
            "validate", "--input-file", "/reports/runtime.cdx.json", "--input-format", "json",
            "--input-version", "v1_6", "--fail-on-errors"]
        require(execute(output, "cyclonedx-validate", cdx_argv).returncode == 0, "official CycloneDX validation failed")
        spdx_argv = [str(validator_python), str(ROOT / "scripts/validate-native-spdx.py"),
                     "--input", str(reports / "runtime.spdx.json"), "--schema", str(schema)]
        require(execute(output, "spdx-validate", spdx_argv).returncode == 0, "official SPDX validation failed")
        rejected = []
        for kind in ("cdx", "spdx"):
            value = copy.deepcopy(cdx if kind == "cdx" else spdx)
            value["bomFormat" if kind == "cdx" else "dataLicense"] = "deliberately-invalid"
            target = reports / ("invalid." + kind + ".json")
            write_json(target, value)
            command = [arg.replace("runtime.cdx.json", "invalid.cdx.json") for arg in cdx_argv] if kind == "cdx" else [
                arg.replace("runtime.spdx.json", "invalid.spdx.json") for arg in spdx_argv]
            require(execute(output, kind + "-invalid-rejection", command).returncode == 1,
                    "official validator did not demonstrate invalid-input rejection")
            rejected.append(kind + "-invalid-format")
        for kind in ("cdx", "spdx"):
            value = copy.deepcopy(cdx if kind == "cdx" else spdx)
            value["components" if kind == "cdx" else "packages"].pop()
            try:
                complete(inventory, inputs, manifest, value if kind == "cdx" else cdx,
                         value if kind == "spdx" else spdx, binding, raw_cdx, raw_spdx)
            except ValueError:
                rejected.append(kind + "-missing-component")
            else:
                raise ValueError("semantic completeness rejection failed")
        verify_live(inventory, output / "inventory")
        require(load_inventory(path, sha, seal_sha)[0] == inventory, "native inventory inputs changed")
        for item in inventory["dynamic_libraries"] + [inventory["files"]["binary"]]:
            require(file_record(item["path"]) == {k: item[k] for k in ("path", "bytes", "sha256")}, "live runtime bytes changed")
        for owner, package in inventory["ubuntu_packages"].items():
            require(runtime.digest(runtime.run("dpkg-query", "--status", owner)) == package["control_sha256"] and
                    file_record(package["copyright"]["path"]) == package["copyright"], "live package metadata changed")
        require(runtime.source_state(ROOT) == before and
                all(file_record(ROOT / name) == value for name, value in tooling.items()), "SBOM tooling source changed")
        verify_snapshot(output / "snapshot", manifest)
        receipt.update({"outcome": "validated-unqualified", "counts": counts, "rejection_probes": rejected,
                        "decoder_checks": decoder_checks,
                        "validated_at": datetime.now(timezone.utc).isoformat(),
                        "limitations": ["No fresh native vulnerability scan or inherited container result.",
                                        "Schema/semantic checks are not compliance, license clearance or signed provenance.",
                                        "Static/generated components remain verified producer declarations, not binary discovery.",
                                        "Observed ELF subset excludes unexercised dynamic loading and whole-host software.",
                                        "Dirty tooling requires a subsequent clean-source acceptance."]})
        write_json(output / "result.json", receipt)
        seal = []
        safe_tree(output)
        for item in sorted(output.rglob("*")):
            if item.is_file():
                with os.fdopen(os.open(item, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
                    require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode) and os.fstat(stream.fileno()).st_nlink == 1,
                            "unsafe sealed file")
                    os.fchmod(stream.fileno(), 0o600)
                record = evidence_record(item)
                record["path"] = str(item.relative_to(output))
                seal.append(record)
        write_json(output / "checksums.json", {"schema_version": 1, "files": seal})
        return receipt
    except Exception as error:
        receipt.update({"outcome": "failed", "error": str(error)})
        write_json(output / "result.json", receipt)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--inventory-sha256", required=True)
    parser.add_argument("--seal-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--validator-python", required=True, type=Path)
    parser.add_argument("--spdx-schema", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(qualify(args.inventory.absolute(), args.inventory_sha256, args.seal_sha256,
                     args.output.absolute(), args.validator_python.absolute(), args.spdx_schema.absolute()), indent=2))
