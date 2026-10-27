#!/usr/bin/env python3
"""Reject partial or unproven ELF pruning before a runtime SBOM can be scanned."""
import argparse
import hashlib
import json
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(items, key):
    values = {item[key]: item for item in items}
    require(len(values) == len(items), f"duplicate {key}")
    return values


def strict_pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def verify(diagnostic, standard, ownership):
    for document, excluded in [(diagnostic, False), (standard, True)]:
        require(document["descriptor"]["name"] == "syft" and
                document["descriptor"]["version"] == "1.44.0", "pinned Syft required")
        config = document["descriptor"]["configuration"]["relationships"]
        require(config["exclude-binary-packages-with-file-ownership-overlap"] is excluded and
                config["package-file-ownership"] is True and config["package-file-ownership-overlap"] is True,
                "effective overlap configuration mismatch")
        require(document["distro"]["id"] == "ubuntu" and document["distro"]["versionID"] == "24.04",
                "observed Ubuntu 24.04 identity required")
    require(diagnostic["source"] == standard["source"] and
            standard["source"]["type"] == "image" and standard["source"]["id"], "scan source mismatch")
    require(ownership["schema_version"] == 1 and ownership["packages"], "ownership manifest required")
    before = unique(diagnostic["artifacts"], "id")
    after = unique(standard["artifacts"], "id")
    require(after.keys() <= before.keys(), "unexpected added package")
    require(all(before[key] == value for key, value in after.items()), "surviving package changed")
    owned = {}
    covered_packages = set()
    for package in ownership["packages"].values():
        candidates = [p for p in after.values() if p["foundBy"] == "dpkg-db-cataloger" and
                      p["name"] == package["name"] and p["version"] == package["version"] and
                      p["metadata"]["architecture"] == package["architecture"]]
        require(len(candidates) == 1, "exactly one surviving dpkg package required")
        survivor = candidates[0]
        covered_packages.add(survivor["id"])
        require(survivor["metadata"]["source"] == package["source"] and
                survivor["metadata"]["sourceVersion"] == package["source_version"], "source package mismatch")
        files = unique(survivor["metadata"]["files"], "path")
        require(set(files) == {f["path"] for f in package["files"]}, "ownership path set mismatch")
        for file in package["files"]:
            location = file["path"]
            require(location not in owned, "ambiguous file ownership")
            require(files[location]["digest"] == {"algorithm": "md5", "value": file["package_md5"]},
                    "package file checksum mismatch")
            observed = [f for f in diagnostic["files"] if f["location"]["path"] == location]
            require(len(observed) == 1 and {"algorithm": "sha256", "value": file["sha256"]}
                    in observed[0].get("digests", []), "observed file SHA-256 mismatch")
            owned[location] = (package, survivor["id"], observed[0]["location"].get("layerID"))
    require(covered_packages == {p["id"] for p in after.values() if p["foundBy"] == "dpkg-db-cataloger"},
            "dpkg package inventory coverage mismatch")
    removed = []
    for key in sorted(before.keys() - after.keys()):
        note = before[key]
        require(note["foundBy"] == "elf-binary-package-cataloger" and note["type"] == "deb" and
                note["metadataType"] == "elf-binary-package-note-json-payload" and note["locations"],
                "unreviewed pruned package type")
        proof = []
        for location in note["locations"]:
            require(location["path"] in owned, "partially owned ELF aggregate")
            package, survivor, layer = owned[location["path"]]
            require(layer == location.get("layerID"), "ELF evidence layer mismatch")
            require(package["source"] == note["name"] and package["source_version"] == note["version"] and
                    package["architecture"] == note["metadata"]["architecture"] and
                    note["metadata"]["os"].lower() == standard["distro"]["id"], "ELF producer identity mismatch")
            proof.append({"path": location["path"], "surviving_package_id": survivor})
        removed.append({"id": key, "name": note["name"], "locations": proof})
    return {"schema_version": 1, "status": "passed", "scope": "package ownership and pruning only",
            "diagnostic_packages": len(before), "standard_packages": len(after), "removed": removed,
            "owned_files": len(owned), "image_binding_qualified": False, "scanner_parity_qualified": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("diagnostic", "standard", "ownership", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    paths = {name: getattr(args, name) for name in ("diagnostic", "standard", "ownership")}
    require(all(0 < path.stat().st_size <= 64 * 1024 * 1024 for path in paths.values()), "bounded input required")
    inputs = {name: path.read_bytes() for name, path in paths.items()}
    result = verify(*(json.loads(inputs[name], object_pairs_hook=strict_pairs) for name in inputs))
    result["input_sha256"] = {name: hashlib.sha256(data).hexdigest() for name, data in inputs.items()}
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
