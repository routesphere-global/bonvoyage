#!/usr/bin/env python3
"""Inventory glibc-sensitive imports in one exact BonVoyage runtime export.

This is a bounded static reachability inventory. It does not prove runtime
callability, safe function arguments, vulnerability absence, or VEX status.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import struct
import tarfile


ARCHIVE_LIMIT = 2 * 1024 * 1024 * 1024
MEMBER_LIMIT = 512 * 1024 * 1024
TOTAL_REGULAR_LIMIT = 1024 * 1024 * 1024
JSON_LIMIT = 4 * 1024 * 1024
MEMBER_COUNT_LIMIT = 4096
ELF_COUNT_LIMIT = 256
SYMBOL_COUNT_LIMIT = 1_000_000
COMMIT = re.compile(r"[a-f0-9]{40}\Z")
SHA256 = re.compile(r"(?:sha256:)?[a-f0-9]{64}\Z")

RESOLVER_SYMBOLS = {
    "getaddrinfo", "freeaddrinfo", "gai_strerror", "getnameinfo",
    "gethostbyaddr", "gethostbyaddr_r", "gethostbyname",
    "gethostbyname2", "gethostbyname2_r", "gethostbyname_r",
    "res_init", "res_mkquery", "res_query", "res_querydomain",
    "res_search", "res_send", "__res_init", "__res_mkquery",
    "__res_query", "__res_querydomain", "__res_search", "__res_send",
}
FILE_MODE_SYMBOLS = {"fopen", "fopen64", "freopen", "freopen64"}
DYNAMIC_LOADER_SYMBOLS = {"dlopen", "dlmopen", "dlsym", "dlvsym"}
OPENSSL_NETWORK_PREFIXES = (
    "BIO_lookup", "BIO_gethostbyname", "BIO_connect", "BIO_new_connect",
    "BIO_s_connect", "OSSL_HTTP_", "OCSP_sendreq", "OCSP_parse_url",
    "X509_load_http", "X509_CRL_load_http",
)
MODULE_PATH_MARKERS = ("/ossl-modules/", "/engines-", "/pkcs11/", "/modules/")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode_json(data):
    def reject_constant(value):
        raise ValueError(f"non-JSON constant: {value}")

    return json.loads(data, object_pairs_hook=unique_pairs,
                      parse_constant=reject_constant)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path, limit=ARCHIVE_LIMIT):
    require(path.is_file() and not path.is_symlink(),
            f"regular non-symlink file required: {path}")
    require(0 < path.stat().st_size <= limit, f"bounded nonempty file required: {path}")
    value, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            require(size <= limit, f"file exceeds byte budget: {path}")
            value.update(block)
    return value.hexdigest(), size


def read_json_file(path):
    require(path.is_file() and not path.is_symlink(),
            f"regular non-symlink JSON file required: {path}")
    size = path.stat().st_size
    require(0 < size <= JSON_LIMIT, "bounded nonempty JSON input required")
    data = path.read_bytes()
    require(len(data) == size, "JSON input changed while reading")
    return decode_json(data), {"sha256": digest(data), "bytes": len(data)}


def canonical_member(name):
    value = name.rstrip("/")
    parsed = PurePosixPath(value)
    require(value and not parsed.is_absolute() and ".." not in parsed.parts and
            str(parsed) == value and not value.startswith("./"),
            f"unsafe or noncanonical archive path: {name}")
    return value


def bounded_slice(data, offset, size, label):
    require(type(offset) is int and type(size) is int and offset >= 0 and size >= 0 and
            offset <= len(data) and size <= len(data) - offset,
            f"out-of-bounds ELF {label}")
    return data[offset:offset + size]


def parse_elf(data, path):
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01",
            f"64-bit little-endian ELF required: {path}")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    elf_type, machine = header[1], header[2]
    section_offset, header_size, section_size = header[6], header[8], header[11]
    section_count, section_names = header[12], header[13]
    require(elf_type in (2, 3) and machine == 62 and header_size == 64,
            f"Linux AMD64 executable/shared ELF required: {path}")
    require(section_size == 64 and 0 < section_count <= 4096 and
            section_names < section_count,
            f"reviewed ELF section table required: {path}")
    bounded_slice(data, section_offset, section_size * section_count,
                  "section table")
    sections = []
    for index in range(section_count):
        section = struct.unpack_from("<IIQQQQIIQQ", data,
                                     section_offset + index * section_size)
        record = {
            "name": section[0], "type": section[1], "flags": section[2],
            "address": section[3], "offset": section[4], "size": section[5],
            "link": section[6], "info": section[7], "alignment": section[8],
            "entry_size": section[9],
        }
        if record["type"] != 8:  # SHT_NOBITS occupies no file bytes.
            bounded_slice(data, record["offset"], record["size"],
                          f"section {index}")
        sections.append(record)

    dynsyms = [section for section in sections if section["type"] == 11]
    require(0 < len(dynsyms) <= 4, f"bounded dynamic symbol table required: {path}")
    undefined, total_symbols = set(), 0
    for section in dynsyms:
        require(section["entry_size"] == 24 and section["size"] % 24 == 0 and
                section["link"] < len(sections),
                f"valid ELF64 dynamic symbols required: {path}")
        strings = sections[section["link"]]
        require(strings["type"] == 3 and strings["size"] <= 64 * 1024 * 1024,
                f"linked dynamic string table required: {path}")
        names = bounded_slice(data, strings["offset"], strings["size"],
                              "dynamic string table")
        count = section["size"] // 24
        total_symbols += count
        require(total_symbols <= SYMBOL_COUNT_LIMIT,
                f"dynamic symbol budget exceeded: {path}")
        for index in range(count):
            entry = struct.unpack_from("<IBBHQQ", data,
                                       section["offset"] + index * 24)
            name_offset, section_index = entry[0], entry[3]
            require(name_offset < len(names), f"invalid dynamic symbol name: {path}")
            end = names.find(b"\0", name_offset)
            require(end >= name_offset, f"unterminated dynamic symbol name: {path}")
            if section_index == 0 and end > name_offset:
                try:
                    undefined.add(names[name_offset:end].decode("ascii"))
                except UnicodeDecodeError as error:
                    raise ValueError(f"non-ASCII dynamic symbol: {path}") from error
    return {
        "elf_type": "executable" if elf_type == 2 else "shared-object",
        "machine": "x86_64",
        "dynamic_symbol_count": total_symbols,
        "undefined_symbols": sorted(undefined),
    }


def selected(symbols):
    values = set(symbols)
    return {
        "glibc_resolver": sorted(values & RESOLVER_SYMBOLS),
        "file_mode": sorted(values & FILE_MODE_SYMBOLS),
        "dynamic_loader": sorted(values & DYNAMIC_LOADER_SYMBOLS),
        "openssl_network": sorted(name for name in values
                                   if name.startswith(OPENSSL_NETWORK_PREFIXES)),
    }


def verify_identity(image, container, expected_image_id, source_commit):
    require(isinstance(image, list) and len(image) == 1 and isinstance(image[0], dict),
            "one Docker image inspection record required")
    record = image[0]
    require(record.get("Id") == expected_image_id and record.get("Os") == "linux" and
            record.get("Architecture") == "amd64", "exact Linux AMD64 image required")
    config = record.get("Config")
    require(isinstance(config, dict) and config.get("User") == "65532:65532" and
            config.get("Entrypoint") == ["/usr/local/bin/bonvoyage-dataplane"],
            "reviewed non-root BonVoyage runtime profile required")
    labels = config.get("Labels")
    require(isinstance(labels, dict) and
            labels.get("io.routesphere.bonvoyage.upstream-http1-client") in
            ("seastar-reference", "llhttp-candidate"),
            "reviewed upstream client label required")
    require(labels.get("org.opencontainers.image.revision") == source_commit,
            "runtime source-revision label differs from the inspected source")
    require(isinstance(container, list) and len(container) == 1 and
            isinstance(container[0], dict) and container[0].get("Image") == expected_image_id,
            "container must be created from the exact image ID")
    container = container[0]
    state = container.get("State")
    host = container.get("HostConfig")
    require(isinstance(state, dict) and state.get("Status") == "created" and
            state.get("Running") is False and state.get("Pid") == 0 and
            state.get("StartedAt") == "0001-01-01T00:00:00Z" and
            container.get("Mounts") == [],
            "unstarted, unmounted evidence container required")
    require(isinstance(container.get("Config"), dict) and
            container["Config"].get("Image") == expected_image_id and
            isinstance(host, dict) and not host.get("Binds") and
            not host.get("Tmpfs") and not host.get("Mounts"),
            "evidence container must not add mounts or change image identity")
    return {
        "image_id": expected_image_id,
        "platform": "linux/amd64",
        "runtime_user": config["User"],
        "entrypoint": config["Entrypoint"],
        "upstream_http1_client": labels[
            "io.routesphere.bonvoyage.upstream-http1-client"],
        "source_revision": labels["org.opencontainers.image.revision"],
        "source_dirty_label": labels.get("io.routesphere.bonvoyage.source-dirty"),
    }


def validate_ownership(document, regular):
    require(isinstance(document, dict) and document.get("schema_version") == 1 and
            document.get("scope") == "copied runtime shared-library closure" and
            isinstance(document.get("packages"), dict) and document["packages"],
            "runtime package ownership schema required")
    packages, owned = [], {}
    for key, package in sorted(document["packages"].items()):
        require(isinstance(key, str) and isinstance(package, dict) and
                isinstance(package.get("files"), list) and package["files"],
                "complete package ownership entry required")
        for field in ("name", "architecture", "version", "source", "source_version"):
            require(isinstance(package.get(field), str) and package[field],
                    f"complete package field required: {key}.{field}")
        require(package["architecture"] == "amd64", "AMD64 package ownership required")
        require(key in (package["name"], f'{package["name"]}:{package["architecture"]}'),
                f"package ownership key mismatch: {key}")
        files = []
        for item in package["files"]:
            require(isinstance(item, dict) and isinstance(item.get("path"), str) and
                    isinstance(item.get("sha256"), str) and
                    re.fullmatch(r"[a-f0-9]{64}", item["sha256"]),
                    "owned file path and SHA-256 required")
            path = canonical_member(item["path"].lstrip("/"))
            require(path not in owned and path in regular,
                    f"unique regular owned runtime file required: /{path}")
            actual = digest(regular[path])
            require(actual == item["sha256"],
                    f"owned runtime file hash mismatch: /{path}")
            owned[path] = key
            files.append({"path": "/" + path, "sha256": actual})
        packages.append({
            "key": key, "name": package["name"],
            "architecture": package["architecture"], "version": package["version"],
            "source": package["source"], "source_version": package["source_version"],
            "files": files,
        })
    libc = [package for package in packages if package["name"] == "libc6"]
    require(len(libc) == 1 and libc[0]["source"] == "glibc",
            "one glibc-owned libc6 package required")
    return packages, owned, libc[0]


def inspect_archive(path, expected_gateway_sha256):
    archive_sha256, archive_bytes = file_digest(path)
    require(re.fullmatch(r"[a-f0-9]{64}", expected_gateway_sha256),
            "explicit gateway SHA-256 required")
    members, regular, total = {}, {}, 0
    with tarfile.open(path, "r:") as archive:
        for item in archive:
            require(len(members) < MEMBER_COUNT_LIMIT, "archive member budget exceeded")
            name = canonical_member(item.name)
            require(name not in members, f"duplicate archive path: {name}")
            require(item.isdir() or item.isfile() or item.issym() or item.islnk(),
                    f"special archive member rejected: {name}")
            members[name] = {
                "type": "directory" if item.isdir() else
                        "regular" if item.isfile() else
                        "symlink" if item.issym() else "hardlink",
                "linkname": item.linkname or None,
            }
            if item.isfile():
                require(0 <= item.size <= MEMBER_LIMIT, f"archive member too large: {name}")
                total += item.size
                require(total <= TOTAL_REGULAR_LIMIT, "archive regular-file budget exceeded")
                stream = archive.extractfile(item)
                require(stream is not None, f"unreadable archive member: {name}")
                data = stream.read(MEMBER_LIMIT + 1)
                require(len(data) == item.size and len(data) <= MEMBER_LIMIT,
                        f"archive member size changed: {name}")
                regular[name] = data

    gateway_path = "usr/local/bin/bonvoyage-dataplane"
    ownership_path = "usr/share/bonvoyage/runtime-package-ownership.json"
    require(gateway_path in regular and ownership_path in regular,
            "gateway and runtime ownership manifest required")
    gateway_sha256 = digest(regular[gateway_path])
    require(gateway_sha256 == expected_gateway_sha256,
            "gateway differs from the externally locked SHA-256")
    ownership = decode_json(regular[ownership_path])
    packages, owned, libc = validate_ownership(ownership, regular)

    elfs = []
    for name, data in sorted(regular.items()):
        if data[:4] != b"\x7fELF":
            continue
        require(len(elfs) < ELF_COUNT_LIMIT, "ELF object budget exceeded")
        parsed = parse_elf(data, name)
        imports = selected(parsed.pop("undefined_symbols"))
        elfs.append({
            "path": "/" + name, "bytes": len(data), "sha256": digest(data),
            "package": owned.get(name), **parsed, "selected_imports": imports,
        })

    by_path = {item["path"]: item for item in elfs}
    gateway = by_path.get("/" + gateway_path)
    require(gateway is not None, "gateway ELF inventory missing")
    expected_elfs = {"/" + name for name in owned} | {"/" + gateway_path}
    require(set(by_path) == expected_elfs,
            "runtime ELF closure differs from gateway plus owned libraries")
    module_paths = sorted("/" + name for name in members
                          if any(marker in "/" + name for marker in MODULE_PATH_MARKERS))
    importers = {}
    for category in ("glibc_resolver", "file_mode", "dynamic_loader", "openssl_network"):
        importers[category] = [
            {"path": item["path"], "symbols": item["selected_imports"][category]}
            for item in elfs if item["selected_imports"][category]
        ]
    require(archive_sha256 == file_digest(path)[0],
            "runtime export changed during inspection")
    return {
        "rootfs_export": {"sha256": archive_sha256, "bytes": archive_bytes,
                          "member_count": len(members), "regular_bytes": total},
        "gateway": gateway,
        "runtime_packages": packages,
        "glibc_package": libc,
        "elf_inventory": elfs,
        "selected_importers": importers,
        "dynamic_module_paths": module_paths,
    }


def analyze(rootfs, image_inspect, container_inspect, expected_image_id,
            source_commit, expected_gateway_sha256):
    require(COMMIT.fullmatch(source_commit or ""), "exact lowercase source commit required")
    require(SHA256.fullmatch(expected_image_id or "") and expected_image_id.startswith("sha256:"),
            "exact sha256 image ID required")
    image, image_receipt = read_json_file(image_inspect)
    container, container_receipt = read_json_file(container_inspect)
    identity = verify_identity(image, container, expected_image_id, source_commit)
    runtime = inspect_archive(rootfs, expected_gateway_sha256)
    gateway_imports = runtime["gateway"]["selected_imports"]
    return {
        "schema_version": 1,
        "classification": "exact-runtime-static-glibc-reachability-inventory",
        "source_commit": source_commit,
        "runtime_identity": identity,
        "inspection_receipts": {
            "image_inspect": image_receipt,
            "container_inspect": container_receipt,
        },
        **runtime,
        "observations": {
            "gateway_imports_glibc_resolver": bool(gateway_imports["glibc_resolver"]),
            "gateway_imports_openssl_network": bool(gateway_imports["openssl_network"]),
            "closure_contains_resolver_imports": bool(runtime["selected_importers"]["glibc_resolver"]),
            "closure_contains_file_mode_imports": bool(runtime["selected_importers"]["file_mode"]),
            "closure_contains_dynamic_loader_imports": bool(runtime["selected_importers"]["dynamic_loader"]),
            "runtime_contains_dynamic_module_paths": bool(runtime["dynamic_module_paths"]),
        },
        "finding_status": {
            "CVE-2026-8674": {
                "status": "under_review",
                "reason": "Static import inventory cannot prove that every transitive resolver path is unreachable at runtime.",
            },
            "CVE-2026-18374": {
                "status": "under_review",
                "reason": "An fopen-family import does not reveal the runtime mode argument; fixed-mode call-site evidence remains separate.",
            },
        },
        "evidence_qualified": True,
        "source_binding_verified": False,
        "reachability_closed": False,
        "vex_authorized": False,
        "scanner_suppression_authorized": False,
        "release_authorized": False,
        "limitations": [
            "Dynamic symbols establish import presence or absence, not whole-program call reachability.",
            "Static inspection does not prove runtime fopen mode arguments.",
            "The source commit is operator-supplied; this analyzer does not prove that it produced the image.",
            "A Docker export is bound to daemon inspection receipts, not independently reconstructed from OCI layers.",
            "Unexercised host services, bind mounts, future modules, and native-package files are outside this container scope.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--image-inspect", required=True, type=Path)
    parser.add_argument("--container-inspect", required=True, type=Path)
    parser.add_argument("--expected-image-id", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--expected-gateway-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.rootfs, args.image_inspect, args.container_inspect,
                         args.expected_image_id, args.source_commit,
                         args.expected_gateway_sha256)
        require(not args.output.exists() and not args.output.is_symlink(),
                "output must be new")
        os.umask(0o077)
        with args.output.open("x", encoding="utf-8") as output:
            json.dump(result, output, indent=2, sort_keys=True)
            output.write("\n")
        print("Verified exact runtime ELF inventory; both glibc findings remain under review.")
    except (ValueError, OSError, KeyError, TypeError, struct.error, tarfile.TarError) as error:
        print("Invalid runtime glibc reachability evidence: " + str(error))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
