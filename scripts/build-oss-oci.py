#!/usr/bin/env python3
"""Build and verify one deterministic, non-publishable BonVoyage OCI archive."""

import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile
import zlib


SCRIPT_ROOT = Path(__file__).resolve().parent
DEFAULT_CONTRACT = SCRIPT_ROOT.parent / "packaging/release/oci/oss-oci-image-contract.json"
LAYOUT_VERSION = "1.0.0"
SHA256 = re.compile(r"[a-f0-9]{64}")
COMMIT = re.compile(r"[a-f0-9]{40}")
SEMVER = re.compile(
    r"(?P<version>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?)"
)
BUILD_CLASS = "routesphere-bonvoyage-oss-oci-build"


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


def canonical_json(document):
    return json.dumps(
        document, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")


def load_json_bytes(raw, label, maximum=4 * 1024 * 1024):
    require(0 < len(raw) <= maximum, f"bounded {label} JSON required")
    try:
        return json.loads(raw, object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid {label} JSON") from error


def load_contract(path=DEFAULT_CONTRACT):
    require(path.is_file() and not path.is_symlink(), "regular OCI contract required")
    contract = load_json_bytes(path.read_bytes(), "OCI contract")
    require(contract.get("schema_version") == 1 and
            contract.get("classification") ==
            "routesphere-bonvoyage-oss-oci-image-contract",
            "unsupported OCI image contract")
    require(contract.get("authority") == {
        "publishable": False, "release_admitted": False,
    }, "OCI foundation must not grant release authority")
    return contract


def rfc3339(epoch):
    require(type(epoch) is int and 0 < epoch < 4102444800,
            "bounded source-date epoch required")
    return datetime.datetime.fromtimestamp(
        epoch, tz=datetime.timezone.utc,
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_path(value):
    require(isinstance(value, str) and value and not value.startswith("/"),
            "relative OCI path required")
    path = PurePosixPath(value)
    require(str(path) == value and not any(part in ("", ".", "..") for part in path.parts),
            "canonical OCI path required")
    return path


def normalized_mode(path):
    mode = stat.S_IMODE(path.lstat().st_mode)
    require(not mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX) and
            not mode & 0o022, "unsafe rootfs mode rejected")
    return 0o755 if mode & 0o111 else 0o644


def rootfs_entries(root, contract):
    require(root.is_dir() and not root.is_symlink() and root.resolve() == root,
            "regular canonical rootfs directory required")
    entries = []
    total = 0
    maximum_entries = contract["rootfs"]["maximum_entries"]
    maximum_bytes = contract["rootfs"]["maximum_uncompressed_bytes"]
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        canonical_path(relative)
        require(not path.is_symlink(), "rootfs symbolic links are prohibited")
        mode = path.lstat().st_mode
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode),
                "rootfs special files are prohibited")
        data = None
        if stat.S_ISREG(mode):
            data = path.read_bytes()
            total += len(data)
            require(total <= maximum_bytes, "rootfs byte ceiling exceeded")
        entries.append((relative, path, data))
        require(len(entries) <= maximum_entries, "rootfs entry ceiling exceeded")
    require(entries, "nonempty rootfs required")
    names = {item[0] for item in entries}
    for required in contract["rootfs"]["required_files"]:
        require(required in names and (root / required).is_file(),
                f"missing required rootfs file: {required}")
    dependencies = "usr/share/bonvoyage/dependencies"
    for record in contract["rootfs"]["required_dependency_records"]:
        required = f"{dependencies}/{record}"
        require(required in names and (root / required).is_file(),
                f"missing dependency record: {record}")
    for name in names:
        for prefix in contract["rootfs"]["forbidden_prefixes"]:
            require(name != prefix and not name.startswith(prefix + "/"),
                    f"forbidden rootfs path: {name}")
        lowered = name.lower()
        basename = PurePosixPath(lowered).name
        require(not (basename.endswith((".pem", ".key", ".p12", ".pfx")) or
                     "private-key" in basename or "private_key" in basename or
                     basename in ("id_rsa", "id_ed25519")),
                f"secret-like rootfs path rejected: {name}")
    binary = (root / "usr/local/bin/bonvoyage-dataplane").read_bytes()
    require(len(binary) >= 64 and binary[:7] == b"\x7fELF\x02\x01\x01" and
            struct.unpack_from("<H", binary, 18)[0] == 62,
            "Linux AMD64 dataplane ELF required")
    require(normalized_mode(root / "usr/local/bin/bonvoyage-dataplane") == 0o755,
            "executable dataplane mode required")
    return sorted(entries, key=lambda item: item[0]), total


def tar_info(name, epoch, mode, directory=False, size=0):
    info = tarfile.TarInfo(name)
    info.mtime = epoch
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mode = mode
    info.size = 0 if directory else size
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.pax_headers = {}
    return info


def build_layer(root, contract, epoch):
    entries, payload_bytes = rootfs_entries(root, contract)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, path, data in entries:
            if data is None:
                archive.addfile(tar_info(name, epoch, 0o755, directory=True))
            else:
                mode = normalized_mode(path)
                archive.addfile(tar_info(name, epoch, mode, size=len(data)), io.BytesIO(data))
    uncompressed = stream.getvalue()
    compressed_stream = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", compresslevel=9, fileobj=compressed_stream, mtime=epoch,
    ) as compressed:
        compressed.write(uncompressed)
    layer = bytearray(compressed_stream.getvalue())
    require(layer[:3] == b"\x1f\x8b\x08", "deterministic gzip output required")
    layer[9] = 255
    return bytes(layer), uncompressed, len(entries), payload_bytes


def add_blob(blobs, data):
    sha256 = digest(data)
    blobs[sha256] = data
    return {"digest": "sha256:" + sha256, "size": len(data)}


def build_archive(root, output, contract, source_commit, source_tag, version,
                  source_date_epoch):
    require(COMMIT.fullmatch(source_commit) is not None, "40-character source commit required")
    require(SEMVER.fullmatch(version) is not None and source_tag == "v" + version,
            "version-matching source tag required")
    require(not output.exists() and not output.is_symlink(), "new OCI archive output required")
    require(output.parent.is_dir() and not output.parent.is_symlink(),
            "regular OCI output directory required")
    created = rfc3339(source_date_epoch)
    layer, uncompressed, entry_count, payload_bytes = build_layer(root, contract, source_date_epoch)
    blobs = {}
    layer_descriptor = add_blob(blobs, layer)
    layer_descriptor["mediaType"] = contract["artifact"]["layer_media_type"]
    identity = contract["identity"]
    runtime = contract["runtime"]
    labels = {
        "io.routesphere.bonvoyage.release-authority": "false",
        "io.routesphere.bonvoyage.source-dirty": "false",
        "io.routesphere.bonvoyage.upstream-http1-client":
            identity["upstream_http1_client"],
        "org.opencontainers.image.created": created,
        "org.opencontainers.image.description":
            "Independent C++/Seastar API gateway dataplane",
        "org.opencontainers.image.revision": source_commit,
        "org.opencontainers.image.source": identity["source_repository"],
        "org.opencontainers.image.title": identity["product"],
        "org.opencontainers.image.vendor": identity["vendor"],
        "org.opencontainers.image.version": version,
    }
    config = {
        "architecture": contract["artifact"]["platform"]["architecture"],
        "config": {
            "Cmd": runtime["command"],
            "Entrypoint": runtime["entrypoint"],
            "Env": runtime["environment"],
            "ExposedPorts": {port: {} for port in runtime["exposed_ports"]},
            "Labels": labels,
            "User": runtime["user"],
            "WorkingDir": runtime["working_directory"],
        },
        "created": created,
        "history": [{
            "comment": "deterministic RouteSphere BonVoyage OSS OCI assembly",
            "created": created,
            "created_by": "scripts/build-oss-oci.py",
        }],
        "os": contract["artifact"]["platform"]["os"],
        "rootfs": {"diff_ids": ["sha256:" + digest(uncompressed)], "type": "layers"},
    }
    config_bytes = canonical_json(config)
    config_descriptor = add_blob(blobs, config_bytes)
    config_descriptor["mediaType"] = contract["artifact"]["config_media_type"]
    manifest = {
        "config": config_descriptor,
        "layers": [layer_descriptor],
        "mediaType": contract["artifact"]["media_type"],
        "schemaVersion": 2,
    }
    manifest_bytes = canonical_json(manifest)
    manifest_descriptor = add_blob(blobs, manifest_bytes)
    manifest_descriptor.update({
        "annotations": {
            "org.opencontainers.image.ref.name":
                contract["identity"]["image_repository"] + ":" + version,
        },
        "mediaType": contract["artifact"]["media_type"],
        "platform": contract["artifact"]["platform"],
    })
    index = {"manifests": [manifest_descriptor], "schemaVersion": 2}
    files = {
        "index.json": canonical_json(index),
        "oci-layout": canonical_json({"imageLayoutVersion": LAYOUT_VERSION}),
    }
    files.update({f"blobs/sha256/{name}": data for name, data in blobs.items()})
    temporary = output.with_name(output.name + ".tmp")
    require(not temporary.exists() and not temporary.is_symlink(),
            "new temporary OCI archive required")
    with tarfile.open(temporary, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for directory in ("blobs", "blobs/sha256"):
            archive.addfile(tar_info(directory, source_date_epoch, 0o755, directory=True))
        for name in sorted(files):
            data = files[name]
            archive.addfile(
                tar_info(name, source_date_epoch, 0o644, size=len(data)), io.BytesIO(data),
            )
    temporary.replace(output)
    result = verify_archive(
        output, contract, source_commit, source_tag, version, source_date_epoch,
    )
    result["rootfs_entries"] = entry_count
    result["rootfs_payload_bytes"] = payload_bytes
    return result


def tar_members(data, label, maximum_entries, maximum_bytes):
    require(len(data) <= maximum_bytes, f"{label} byte ceiling exceeded")
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except tarfile.TarError as error:
        raise ValueError(f"invalid {label} tar") from error
    members = archive.getmembers()
    require(0 < len(members) <= maximum_entries, f"bounded {label} members required")
    values = {}
    ordered = []
    for member in members:
        name = member.name.rstrip("/") if member.isdir() else member.name
        canonical_path(name)
        require(name not in values, f"duplicate {label} member")
        require(member.uid == 0 and member.gid == 0 and not member.uname and not member.gname,
                f"normalized {label} ownership required")
        require(member.isfile() or member.isdir(), f"{label} links and special files prohibited")
        require(not member.pax_headers, f"{label} extended metadata prohibited")
        values[name] = None if member.isdir() else archive.extractfile(member).read()
        ordered.append(name)
    archive.close()
    require(ordered == sorted(ordered), f"sorted {label} members required")
    return members, values


def descriptor_blob(descriptor, blobs, media_type):
    require(isinstance(descriptor, dict) and descriptor.get("mediaType") == media_type,
            "descriptor media type mismatch")
    value = descriptor.get("digest", "")
    require(isinstance(value, str) and value.startswith("sha256:") and
            SHA256.fullmatch(value[7:]) is not None,
            "SHA-256 descriptor required")
    path = "blobs/sha256/" + value[7:]
    require(path in blobs and blobs[path] is not None, "descriptor blob missing")
    data = blobs[path]
    require(descriptor.get("size") == len(data) and digest(data) == value[7:],
            "descriptor byte identity mismatch")
    return data


def bounded_gzip_decompress(data, maximum):
    require(type(maximum) is int and maximum > 0, "positive gzip output ceiling required")
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    output = bytearray()
    pending = data
    while pending:
        before = len(pending)
        output.extend(decompressor.decompress(
            pending, maximum - len(output) + 1,
        ))
        require(len(output) <= maximum, "inflated layer exceeds rootfs ceiling")
        require(not decompressor.unused_data,
                "trailing or concatenated gzip data prohibited")
        pending = decompressor.unconsumed_tail
        require(len(pending) < before or decompressor.eof,
                "gzip decompression made no progress")
    require(decompressor.eof and not decompressor.unused_data and
            not decompressor.unconsumed_tail,
            "complete single-member gzip layer required")
    return bytes(output)


def verify_layer(layer, contract, epoch):
    require(len(layer) >= 18 and layer[:4] == b"\x1f\x8b\x08\x00" and layer[9] == 255,
            "normalized gzip header required")
    require(struct.unpack_from("<I", layer, 4)[0] == epoch,
            "gzip timestamp must equal source-date epoch")
    try:
        inflated = bounded_gzip_decompress(
            layer, contract["rootfs"]["maximum_uncompressed_bytes"],
        )
    except zlib.error as error:
        raise ValueError("invalid OCI gzip layer") from error
    members, values = tar_members(
        inflated, "rootfs", contract["rootfs"]["maximum_entries"],
        contract["rootfs"]["maximum_uncompressed_bytes"],
    )
    files = {name for name, value in values.items() if value is not None}
    for required in contract["rootfs"]["required_files"]:
        require(required in files, f"missing required layer file: {required}")
    for record in contract["rootfs"]["required_dependency_records"]:
        require(f"usr/share/bonvoyage/dependencies/{record}" in files,
                f"missing layer dependency record: {record}")
    for member in members:
        name = member.name.rstrip("/") if member.isdir() else member.name
        require(member.mtime == epoch, "rootfs timestamp must equal source-date epoch")
        if member.isdir():
            require(member.mode == 0o755, "normalized rootfs directory mode required")
        else:
            require(member.mode in (0o644, 0o755),
                    "normalized rootfs file mode required")
        if name == "usr/local/bin/bonvoyage-dataplane":
            require(member.mode == 0o755, "executable dataplane mode required")
        for prefix in contract["rootfs"]["forbidden_prefixes"]:
            require(name != prefix and not name.startswith(prefix + "/"),
                    f"forbidden layer path: {name}")
    binary = values["usr/local/bin/bonvoyage-dataplane"]
    require(len(binary) >= 64 and binary[:7] == b"\x7fELF\x02\x01\x01" and
            struct.unpack_from("<H", binary, 18)[0] == 62,
            "Linux AMD64 layer dataplane required")
    return (
        len(members),
        sum(len(value) for value in values.values() if value is not None),
        "sha256:" + digest(inflated),
    )


def verify_archive(archive_path, contract, source_commit, source_tag, version,
                   source_date_epoch):
    require(archive_path.is_file() and not archive_path.is_symlink(),
            "regular OCI archive required")
    raw = archive_path.read_bytes()
    require(0 < len(raw) <= 2 * 1024 * 1024 * 1024, "bounded OCI archive required")
    members, values = tar_members(raw, "OCI archive", 16, len(raw))
    for member in members:
        require(member.mtime == source_date_epoch, "OCI archive timestamp mismatch")
        require(member.mode == (0o755 if member.isdir() else 0o644),
                "normalized OCI archive mode required")
    require(set(values) >= {"blobs", "blobs/sha256", "index.json", "oci-layout"},
            "incomplete OCI image layout")
    layout = load_json_bytes(values["oci-layout"], "OCI layout")
    require(layout == {"imageLayoutVersion": LAYOUT_VERSION} and
            canonical_json(layout) == values["oci-layout"], "canonical OCI layout required")
    index = load_json_bytes(values["index.json"], "OCI index")
    require(canonical_json(index) == values["index.json"] and set(index) == {
        "manifests", "schemaVersion"} and index["schemaVersion"] == 2 and
        isinstance(index["manifests"], list) and len(index["manifests"]) == 1,
        "canonical single-manifest OCI index required")
    selected = index["manifests"][0]
    require(selected.get("platform") == contract["artifact"]["platform"] and
            selected.get("annotations") == {
                "org.opencontainers.image.ref.name":
                    contract["identity"]["image_repository"] + ":" + version,
            }, "exact Linux AMD64 tagged manifest selection required")
    manifest_bytes = descriptor_blob(selected, values, contract["artifact"]["media_type"])
    manifest = load_json_bytes(manifest_bytes, "OCI manifest")
    require(canonical_json(manifest) == manifest_bytes and set(manifest) == {
        "config", "layers", "mediaType", "schemaVersion"} and
        manifest["schemaVersion"] == 2 and
        manifest["mediaType"] == contract["artifact"]["media_type"] and
        isinstance(manifest["layers"], list) and len(manifest["layers"]) == 1,
        "canonical one-layer OCI manifest required")
    config_bytes = descriptor_blob(
        manifest["config"], values, contract["artifact"]["config_media_type"],
    )
    layer = descriptor_blob(
        manifest["layers"][0], values, contract["artifact"]["layer_media_type"],
    )
    config = load_json_bytes(config_bytes, "OCI config")
    require(canonical_json(config) == config_bytes and set(config) == {
        "architecture", "config", "created", "history", "os", "rootfs"},
        "canonical exact OCI config required")
    created = rfc3339(source_date_epoch)
    runtime = contract["runtime"]
    expected_config = {
        "Cmd": runtime["command"],
        "Entrypoint": runtime["entrypoint"],
        "Env": runtime["environment"],
        "ExposedPorts": {port: {} for port in runtime["exposed_ports"]},
        "User": runtime["user"],
        "WorkingDir": runtime["working_directory"],
    }
    runtime_config = config["config"]
    require(all(runtime_config.get(key) == value for key, value in expected_config.items()) and
            set(runtime_config) == set(expected_config) | {"Labels"},
            "OCI runtime contract mismatch")
    labels = runtime_config["Labels"]
    identity = contract["identity"]
    expected_labels = {
        "io.routesphere.bonvoyage.release-authority": "false",
        "io.routesphere.bonvoyage.source-dirty": "false",
        "io.routesphere.bonvoyage.upstream-http1-client": identity["upstream_http1_client"],
        "org.opencontainers.image.created": created,
        "org.opencontainers.image.description":
            "Independent C++/Seastar API gateway dataplane",
        "org.opencontainers.image.revision": source_commit,
        "org.opencontainers.image.source": identity["source_repository"],
        "org.opencontainers.image.title": identity["product"],
        "org.opencontainers.image.vendor": identity["vendor"],
        "org.opencontainers.image.version": version,
    }
    require(labels == expected_labels and config["created"] == created and
            config["architecture"] == "amd64" and config["os"] == "linux",
            "OCI source or platform identity mismatch")
    require(config["history"] == [{
        "comment": "deterministic RouteSphere BonVoyage OSS OCI assembly",
        "created": created,
        "created_by": "scripts/build-oss-oci.py",
    }], "exact deterministic OCI history required")
    entry_count, payload_bytes, diff_id = verify_layer(
        layer, contract, source_date_epoch,
    )
    require(config["rootfs"] == {
        "diff_ids": [diff_id], "type": "layers",
    }, "OCI layer diff ID mismatch")
    expected_paths = {"blobs", "blobs/sha256", "index.json", "oci-layout"}
    expected_paths.update({
        "blobs/sha256/" + selected["digest"][7:],
        "blobs/sha256/" + manifest["config"]["digest"][7:],
        "blobs/sha256/" + manifest["layers"][0]["digest"][7:],
    })
    require(set(values) == expected_paths, "unexpected OCI layout member")
    return {
        "schema_version": 1,
        "classification": BUILD_CLASS,
        "outcome": "verified-deterministic-technical-candidate",
        "archive": {"bytes": len(raw), "sha256": digest(raw)},
        "manifest": {"bytes": len(manifest_bytes), "digest": selected["digest"]},
        "config": {"bytes": len(config_bytes), "digest": manifest["config"]["digest"]},
        "layer": {
            "bytes": len(layer),
            "digest": manifest["layers"][0]["digest"],
            "diff_id": config["rootfs"]["diff_ids"][0],
        },
        "platform": contract["artifact"]["platform"],
        "source": {
            "commit": source_commit,
            "dirty": False,
            "repository": contract["identity"]["source_repository"],
            "source_date_epoch": source_date_epoch,
            "tag": source_tag,
        },
        "version": version,
        "rootfs_entries": entry_count,
        "rootfs_payload_bytes": payload_bytes,
        "technical_candidate_built": True,
        "reproducibility_qualified": False,
        "sbom_qualified": False,
        "scan_qualified": False,
        "signature_qualified": False,
        "provenance_qualified": False,
        "lifecycle_qualified": False,
        "release_admitted": False,
        "publishable": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("build", "verify"):
        child = subparsers.add_parser(command)
        child.add_argument("--archive", required=True, type=Path)
        child.add_argument("--contract", default=DEFAULT_CONTRACT, type=Path)
        child.add_argument("--source-commit", required=True)
        child.add_argument("--source-tag", required=True)
        child.add_argument("--version", required=True)
        child.add_argument("--source-date-epoch", required=True, type=int)
        if command == "build":
            child.add_argument("--rootfs", required=True, type=Path)
    arguments = parser.parse_args()
    os.umask(0o077)
    try:
        contract = load_contract(arguments.contract.absolute())
        if arguments.command == "build":
            result = build_archive(
                arguments.rootfs.absolute(), arguments.archive.absolute(), contract,
                arguments.source_commit, arguments.source_tag, arguments.version,
                arguments.source_date_epoch,
            )
        else:
            result = verify_archive(
                arguments.archive.absolute(), contract, arguments.source_commit,
                arguments.source_tag, arguments.version, arguments.source_date_epoch,
            )
    except (OSError, tarfile.TarError, ValueError) as error:
        raise SystemExit("OSS OCI image rejected: " + str(error)) from error
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
