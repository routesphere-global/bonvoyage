#!/usr/bin/env python3
"""Bind pinned Syft's Docker representation to independently saved OCI bytes.

This is an integrity/representation gate, not signature, provenance, SBOM
coverage, vulnerability, native-installation or release acceptance.
"""
import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
DOCKER_INDEX = "application/vnd.docker.distribution.manifest.list.v2+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
DOCKER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"
JSON_LIMIT = 4 * 1024 * 1024
ARCHIVE_LIMIT = 4 * 1024 * 1024 * 1024
LAYER_LIMIT = 1024 * 1024 * 1024
TOTAL_LAYER_LIMIT = 2 * 1024 * 1024 * 1024
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode(data):
    def reject_constant(value):
        raise ValueError(f"non-JSON constant: {value}")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=reject_constant)


def hashed(stream, limit):
    digest, size = hashlib.sha256(), 0
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        size += len(block)
        require(size <= limit, "content exceeds byte budget")
        digest.update(block)
    return "sha256:" + digest.hexdigest(), size


def file_hash(path):
    with path.open("rb") as stream:
        return hashed(stream, ARCHIVE_LIMIT)[0]


def check_physical_tar(path):
    """Bound physical headers before tarfile can allocate PAX/GNU payloads."""
    total, count = path.stat().st_size, 0
    with path.open("rb") as stream:
        while stream.tell() < total:
            header = stream.read(512)
            require(len(header) == 512, "truncated tar header")
            if header == bytes(512):
                require(stream.read(512) == bytes(512), "missing tar end markers")
                for tail in iter(lambda: stream.read(1024 * 1024), b""):
                    require(not any(tail), "nonzero trailing archive data")
                return
            count += 1
            require(count <= 4096, "physical header budget exceeded")
            require(header[156:157] in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE),
                    "extended/special physical tar header rejected")
            info = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            require(0 <= info.size <= ARCHIVE_LIMIT, "physical member byte budget exceeded")
            next_header = stream.tell() + ((info.size + 511) // 512) * 512
            require(next_header <= total, "truncated physical member")
            stream.seek(next_header)
    raise ValueError("missing tar end markers")


def config_bom_ref(config_digest):
    # Pinned Syft IDByHash -> hashstructure v0.6.0 hashes string bytes with
    # FNV-1 64. This opaque reference is NOT a cryptographic trust anchor.
    value = 14695981039346656037
    for byte in config_digest.encode("ascii"):
        value = ((value * 1099511628211) & ((1 << 64) - 1)) ^ byte
    return f"{value:016x}"


def inspect_archive(path, expected, platform="linux/amd64"):
    require(isinstance(expected, str) and DIGEST.fullmatch(expected), "explicit locked image digest required")
    require(platform in ("linux/amd64", "linux/arm64"), "reviewed Linux platform required")
    architecture = platform.split("/")[1]
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= ARCHIVE_LIMIT,
            "bounded regular OCI archive required")
    check_physical_tar(path)
    # Never extract archive paths or follow links. Hash every blob before use.
    with tarfile.open(path, "r:") as archive:
        members = {}
        for item in archive:
            require(len(members) < 4096, "archive member budget exceeded")
            name = item.name.rstrip("/")
            parsed = PurePosixPath(name)
            require(name and not parsed.is_absolute() and ".." not in parsed.parts and
                    str(parsed) == name and name not in members, "unsafe/duplicate archive member")
            require((item.isfile() or item.isdir()) and not item.issparse(), "archive links/special entries rejected")
            members[name] = item
            if item.isfile():
                require(0 <= item.size <= ARCHIVE_LIMIT, "archive member too large")
                if name.startswith("blobs/"):
                    require(re.fullmatch(r"blobs/sha256/[a-f0-9]{64}", name), "unsupported blob address")
                    with archive.extractfile(item) as stream:
                        actual, count = hashed(stream, ARCHIVE_LIMIT)
                    require(actual == "sha256:" + parsed.name and count == item.size, "blob hash/size mismatch")
                else:
                    require(name in ("index.json", "oci-layout", "manifest.json"), "unexpected archive file")

        def read(name):
            item = members.get(name)
            require(item is not None and item.isfile() and item.size <= JSON_LIMIT, "missing/bounded OCI JSON required")
            return archive.extractfile(item).read()

        def blob(descriptor):
            require(isinstance(descriptor, dict) and isinstance(descriptor.get("digest"), str) and
                    DIGEST.fullmatch(descriptor["digest"]) and type(descriptor.get("size")) is int and
                    descriptor["size"] >= 0, "invalid blob descriptor")
            name = "blobs/sha256/" + descriptor["digest"][7:]
            require(name in members and members[name].isfile() and members[name].size == descriptor["size"],
                    "descriptor size/blob mismatch")
            return name

        require(decode(read("oci-layout")) == {"imageLayoutVersion": "1.0.0"}, "unsupported OCI layout")
        index = decode(read("index.json"))
        roots = index.get("manifests", [])
        require(index.get("schemaVersion") == 2 and index.get("mediaType") == OCI_INDEX and
                len(roots) == 1 and roots[0].get("digest") == expected, "locked root absent/ambiguous")
        descriptor, chain = roots[0], []
        for depth in range(2):
            document = decode(read(blob(descriptor)))
            media = descriptor.get("mediaType")
            require(document.get("schemaVersion") == 2 and document.get("mediaType") == media,
                    "descriptor/document media type mismatch")
            chain.append(descriptor["digest"])
            if media in (OCI_MANIFEST, DOCKER_MANIFEST):
                break
            require(media in (OCI_INDEX, DOCKER_INDEX), "unsupported root/index type")
            require(depth == 0 and all(item.get("mediaType") in (OCI_MANIFEST, DOCKER_MANIFEST)
                    for item in document["manifests"]), "nested indexes require a reviewed adapter")
            selected = [item for item in document["manifests"] if
                        item.get("platform", {}).get("architecture") == architecture and
                        item.get("platform", {}).get("os") == "linux"]
            require(len(selected) == 1, "exactly one requested Linux platform manifest required")
            descriptor = selected[0]
        else:
            raise ValueError("nested index budget exceeded")
        config_descriptor = document["config"]
        require(config_descriptor.get("mediaType") in (OCI_CONFIG, DOCKER_CONFIG), "unsupported config type")
        config_bytes = read(blob(config_descriptor))
        config = decode(config_bytes)
        require(config.get("os") == "linux" and config.get("architecture") == architecture and
                config.get("rootfs", {}).get("type") == "layers", "requested Linux platform config required")
        layers, diffs = document["layers"], config["rootfs"]["diff_ids"]
        require(isinstance(layers, list) and isinstance(diffs, list) and 0 < len(layers) == len(diffs) <= 128,
                "ordered layer/diffID count mismatch")
        verified, total = [], 0
        for layer, diff in zip(layers, diffs):
            require(layer.get("mediaType") in (OCI_GZIP, DOCKER_GZIP), "only reviewed gzip layers supported")
            require(isinstance(diff, str) and DIGEST.fullmatch(diff), "invalid config diffID")
            member = members[blob(layer)]
            with archive.extractfile(member) as stream, gzip.GzipFile(fileobj=stream) as expanded:
                actual, size = hashed(expanded, min(LAYER_LIMIT, TOTAL_LAYER_LIMIT - total))
            total += size
            require(actual == diff, "decompressed layer differs from ordered config diffID")
            verified.append({"blob_digest": layer["digest"], "compressed_bytes": layer["size"],
                             "diff_id": diff, "tar_bytes": size})
    return {"locked_image_id": expected, "platform": platform, "index_chain": chain[:-1], "platform_manifest": chain[-1],
            "config_digest": config_descriptor["digest"], "config_bytes": config_bytes,
            "layers": verified}


def bind(identity, raw, cdx, spdx):
    require(raw["descriptor"]["name"] == "syft" and raw["descriptor"]["version"] == "1.44.0",
            "pinned Syft representation required")
    source, expected = raw["source"], identity["locked_image_id"]
    architecture = identity["platform"].split("/")[1]
    metadata = source["metadata"]
    require(source["type"] == "image" and source["name"] == "sha256" and source["version"] == expected[7:] and
            metadata["userInput"] == expected and metadata["os"] == "linux" and metadata["architecture"] == architecture,
            "Syft target/platform mismatch")
    require(metadata["imageID"] == identity["config_digest"] and
            base64.b64decode(metadata["config"], validate=True) == identity["config_bytes"], "Syft config bytes mismatch")
    # Stereoscope's Docker adapter synthesizes this object with diffIDs in its
    # layer digest fields, while sizes describe compressed blobs. Reconstruct
    # it from independently verified OCI data; do not call it a registry digest.
    representation = {"schemaVersion": 2, "mediaType": DOCKER_MANIFEST,
                      "config": {"mediaType": DOCKER_CONFIG, "size": len(identity["config_bytes"]),
                                 "digest": identity["config_digest"]}, "layers": [
                          {"mediaType": DOCKER_GZIP, "size": layer["compressed_bytes"], "digest": layer["diff_id"]}
                          for layer in identity["layers"]]}
    expected_bytes = json.dumps(representation, separators=(",", ":")).encode()
    representation_sha = "sha256:" + hashlib.sha256(expected_bytes).hexdigest()
    require(base64.b64decode(metadata["manifest"], validate=True) == expected_bytes and
            metadata["mediaType"] == DOCKER_MANIFEST and metadata["manifestDigest"] == representation_sha and
            source["id"] == representation_sha[7:], "Syft descriptor bytes/identity mismatch")
    require([layer["digest"] for layer in metadata["layers"]] == [layer["diff_id"] for layer in identity["layers"]],
            "Syft layer sequence mismatch")
    component = cdx["metadata"]["component"]
    require(cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.6" and
            component["type"] == "container" and component["name"] == "sha256" and
            component["version"] == expected[7:] and component["bom-ref"] == config_bom_ref(identity["config_digest"]),
            "CycloneDX root identity mismatch")
    require(all(c.get("bom-ref") != component["bom-ref"] for c in cdx.get("components", [])),
            "duplicate CycloneDX root reference")
    require(spdx["spdxVersion"] == "SPDX-2.3", "SPDX 2.3 required")
    ids = [p["SPDXID"] for p in spdx["packages"]]
    require(all(isinstance(value, str) and value.startswith("SPDXRef-") for value in ids) and
            len(set(ids)) == len(ids) and "SPDXRef-DOCUMENT" not in ids and
            spdx["SPDXID"] == "SPDXRef-DOCUMENT", "unique SPDX package/document IDs required")
    roots = [p for p in spdx["packages"] if p.get("primaryPackagePurpose") == "CONTAINER"]
    require(len(roots) == 1, "unique SPDX image root required")
    root = roots[0]
    described = []
    for rel in spdx["relationships"]:
        if rel["relationshipType"] == "DESCRIBES" and rel["spdxElementId"] == "SPDXRef-DOCUMENT":
            described.append(rel["relatedSpdxElement"])
        elif rel["relationshipType"] == "DESCRIBED_BY" and rel["relatedSpdxElement"] == "SPDXRef-DOCUMENT":
            described.append(rel["spdxElementId"])
    require(described == [root["SPDXID"]], "SPDX document must describe exactly the bound image root")
    require(root["name"] == "sha256" and root["versionInfo"] == expected[7:] and root["checksums"] ==
            [{"algorithm": "SHA256", "checksumValue": representation_sha[7:]}], "SPDX root checksum mismatch")
    refs = [r for r in root["externalRefs"] if r["referenceType"] == "purl"]
    purl = f'pkg:oci/sha256@sha256%3A{representation_sha[7:]}?arch={architecture}&tag={expected[7:]}'
    require(len(refs) == 1 and refs[0]["referenceCategory"] == "PACKAGE-MANAGER" and
            refs[0]["referenceLocator"] == purl, "SPDX image PURL mismatch")
    return {**{k: v for k, v in identity.items() if k != "config_bytes"}, "schema_version": 1,
            "status": "passed", "scope": "saved image integrity and pinned SBOM source representations",
            "syft_docker_descriptor_sha256": representation_sha,
            "syft_descriptor_is_registry_manifest": False,
            "expected_decoded_manifest_values": {"cyclonedx": expected[7:], "spdx": representation_sha},
            "image_binding_qualified": True, "scanner_parity_qualified": False,
            "publisher_authenticity_verified": False, "native_installation_verified": False, "formal_rc_accepted": False}


def verify(archive, expected, raw_path, cdx_path, spdx_path, platform="linux/amd64"):
    paths = {"archive": archive, "syft": raw_path, "cyclonedx": cdx_path, "spdx": spdx_path}
    for name, path in paths.items():
        limit = ARCHIVE_LIMIT if name == "archive" else 64 * 1024 * 1024
        require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= limit,
                "bounded regular verification input required")
    hashes = {name: file_hash(path) for name, path in paths.items()}
    identity = inspect_archive(archive, expected, platform)
    result = bind(identity, *(decode(path.read_bytes()) for path in (raw_path, cdx_path, spdx_path)))
    require(hashes == {name: file_hash(path) for name, path in paths.items()}, "verification inputs changed")
    result["input_sha256"] = hashes
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expected-image-id", required=True)
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"), default="linux/amd64")
    parser.add_argument("--syft", type=Path, required=True)
    parser.add_argument("--cyclonedx", type=Path, required=True)
    parser.add_argument("--spdx", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.archive, args.expected_image_id, args.syft, args.cyclonedx, args.spdx, args.platform)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
