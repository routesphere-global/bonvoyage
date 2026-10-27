#!/usr/bin/env python3
"""Verify a private RC handoff's bytes and selected OCI platform, without loading images."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest_stream(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def digest_file(path):
    with path.open("rb") as stream:
        return digest_stream(stream)


def contained_file(root, name):
    relative = PurePosixPath(name)
    require(name and not relative.is_absolute() and ".." not in relative.parts,
            f"unsafe package path: {name}")
    target = root.joinpath(*relative.parts)
    for part in [target, *target.parents]:
        if part == root:
            break
        require(not part.is_symlink(), f"symlink in package path: {name}")
    require(target.resolve().is_relative_to(root.resolve()) and target.is_file(),
            f"missing or unsafe package file: {name}")
    return target


def inspect_oci_archive(path, identities):
    """Resolve platform manifests from the saved OCI index, not mutable Docker tags."""
    with tarfile.open(path, "r:*") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        require(len(names) == len(set(names)), "duplicate OCI archive members")
        for member in members:
            require(member.isfile() or member.isdir(), "non-file OCI archive member")
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and ".." not in name.parts, "unsafe OCI member")
            if member.isfile() and member.name.startswith("blobs/sha256/"):
                with archive.extractfile(member) as stream:
                    require(digest_stream(stream) == name.name, f"corrupt blob: {member.name}")

        def read_json(name):
            member = archive.getmember(name)
            require(member.isfile() and member.size <= 4 * 1024 * 1024, "invalid OCI JSON")
            with archive.extractfile(member) as stream:
                return json.load(stream)

        def blob(descriptor):
            digest = descriptor["digest"]
            require(digest.startswith("sha256:") and len(digest) == 71, "invalid OCI digest")
            name = "blobs/sha256/" + digest[7:]
            require(archive.getmember(name).size == descriptor["size"], "OCI size mismatch")
            return read_json(name)

        roots = {item["digest"]: item for item in read_json("index.json")["manifests"]}
        result = []
        for image_id in identities:
            require(image_id in roots, f"image absent from archive: {image_id}")
            descriptor = roots[image_id]
            document = blob(descriptor)
            if "manifests" in document:
                selected = [item for item in document["manifests"]
                            if item.get("platform") == {"architecture": "amd64", "os": "linux"}]
                require(len(selected) == 1, "exactly one Linux AMD64 manifest required")
                descriptor = selected[0]
                document = blob(descriptor)
            config = blob(document["config"])
            require(config["os"] == "linux" and config["architecture"] == "amd64",
                    "wrong image platform")
            for layer in document["layers"]:
                name = "blobs/sha256/" + layer["digest"].removeprefix("sha256:")
                require(archive.getmember(name).size == layer["size"], "layer size mismatch")
            result.append({"image_id": image_id, "platform_manifest": descriptor["digest"],
                           "config_digest": document["config"]["digest"],
                           "layer_digests": [layer["digest"] for layer in document["layers"]]})
        return result


def verify(root, expected_manifest_sha256):
    root = root.resolve()
    manifest_path = contained_file(root, "rc-package.json")
    require(digest_file(manifest_path) == expected_manifest_sha256, "manifest digest mismatch")
    manifest = json.loads(manifest_path.read_text())
    require(manifest["schema_version"] == 1, "unsupported package version")
    require(manifest["classification"] == "private-native-rc-handoff", "wrong package class")
    for field in ["formal_rc_accepted", "allocation_authorized", "publishable"]:
        require(manifest[field] is False, f"handoff cannot authorize {field}")
    seen = set()
    for record in manifest["files"]:
        target = contained_file(root, record["path"])
        require(target not in seen, "duplicate package path")
        seen.add(target)
        require(target.stat().st_size == record["bytes"], f"size mismatch: {record['path']}")
        require(digest_file(target) == record["sha256"], f"digest mismatch: {record['path']}")
    actual = {p for p in root.rglob("*") if p.is_file() or p.is_symlink()}
    require(actual == seen | {manifest_path}, "unbound package file")
    images = inspect_oci_archive(contained_file(root, manifest["image_archive"]),
                                 [item["image_id"] for item in manifest["images"]])
    require(images == manifest["images"], "selected image identity mismatch")
    require(manifest["runtime_image"] in {item["image_id"] for item in images},
            "runtime image is not packaged")
    for name in manifest["executables"]:
        with contained_file(root, name).open("rb") as stream:
            header = stream.read(20)
        require(header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\x3e\x00",
                f"not an AMD64 ELF executable: {name}")
    return {"outcome": "PASS", "files_verified": len(seen), "images_verified": len(images),
            "source_commit": manifest["source_commit"], "runtime_image": manifest["runtime_image"],
            "formal_rc_accepted": False, "allocation_authorized": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.package, args.manifest_sha256), indent=2))
