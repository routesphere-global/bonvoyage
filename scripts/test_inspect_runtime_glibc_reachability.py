#!/usr/bin/env python3
"""Synthetic mutation tests; no Docker, scan, or vulnerability probe is run."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("inspect-runtime-glibc-reachability.py")
SPEC = importlib.util.spec_from_file_location("glibc_reachability", SCRIPT)
reachability = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reachability)
IMAGE_ID = "sha256:" + "1" * 64
COMMIT = "2" * 40


def elf(*symbols):
    strings = bytearray(b"\0")
    offsets = []
    for symbol in symbols:
        offsets.append(len(strings))
        strings.extend(symbol.encode("ascii") + b"\0")
    dynsym = bytearray(24)
    for offset in offsets:
        dynsym.extend(struct.pack("<IBBHQQ", offset, 0x12, 0, 0, 0, 0))
    string_offset = 64
    symbol_offset = string_offset + len(strings)
    section_offset = symbol_offset + len(dynsym)
    header = struct.pack("<16sHHIQQQIHHHHHH",
                         b"\x7fELF\x02\x01\x01" + bytes(9), 3, 62, 1, 0,
                         0, section_offset, 0, 64, 0, 0, 64, 3, 0)
    null = bytes(64)
    string_section = struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0,
                                 string_offset, len(strings), 0, 0, 1, 0)
    symbol_section = struct.pack("<IIQQQQIIQQ", 0, 11, 0, 0,
                                 symbol_offset, len(dynsym), 1, 1, 8, 24)
    return header + strings + dynsym + null + string_section + symbol_section


class RuntimeGlibcReachabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.gateway = elf("fopen", "dlsym", "EVP_sha256")
        self.libc = elf()
        self.crypto = elf("getaddrinfo", "gethostbyname", "fopen")
        self.files = {
            "usr/local/bin/bonvoyage-dataplane": self.gateway,
            "lib/x86_64-linux-gnu/libc.so.6": self.libc,
            "lib/x86_64-linux-gnu/libcrypto.so.3": self.crypto,
        }
        self.ownership = {
            "schema_version": 1,
            "scope": "copied runtime shared-library closure",
            "packages": {
                "libc6:amd64": self.package("libc6", "glibc", "2.39-0ubuntu8.9",
                                              "lib/x86_64-linux-gnu/libc.so.6"),
                "libssl3t64:amd64": self.package("libssl3t64", "openssl", "3.0.13",
                                                  "lib/x86_64-linux-gnu/libcrypto.so.3"),
            },
        }
        self.image = [{"Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64",
                       "Config": {"User": "65532:65532",
                                  "Entrypoint": ["/usr/local/bin/bonvoyage-dataplane"],
                                  "Labels": {"io.routesphere.bonvoyage.upstream-http1-client":
                                             "seastar-reference",
                                             "org.opencontainers.image.revision": COMMIT,
                                             "io.routesphere.bonvoyage.source-dirty": "false"}}}]
        self.container = [{"Image": IMAGE_ID,
                           "State": {"Status": "created", "Running": False, "Pid": 0,
                                     "StartedAt": "0001-01-01T00:00:00Z"},
                           "Mounts": [], "Config": {"Image": IMAGE_ID},
                           "HostConfig": {"Binds": None, "Tmpfs": None, "Mounts": None}}]
        self.write_inputs()

    def package(self, name, source, version, path):
        return {"name": name, "architecture": "amd64", "version": version,
                "source": source, "source_version": version,
                "files": [{"path": "/" + path, "build_path": "/usr/" + path,
                           "package_md5": "0" * 32,
                           "sha256": reachability.digest(self.files[path])}]}

    def write_inputs(self, extra=None):
        self.archive = self.root / "rootfs.tar"
        members = dict(self.files)
        members["usr/share/bonvoyage/runtime-package-ownership.json"] = json.dumps(
            self.ownership, separators=(",", ":")).encode()
        if extra:
            members.update(extra)
        with tarfile.open(self.archive, "w") as output:
            for name, data in members.items():
                item = tarfile.TarInfo(name)
                item.size = len(data)
                output.addfile(item, io.BytesIO(data))
        self.image_path = self.root / "image.json"
        self.container_path = self.root / "container.json"
        self.image_path.write_text(json.dumps(self.image))
        self.container_path.write_text(json.dumps(self.container))

    def inspect(self):
        return reachability.analyze(
            self.archive, self.image_path, self.container_path, IMAGE_ID, COMMIT,
            reachability.digest(self.gateway))

    def test_exact_inventory_is_evidence_not_vex(self):
        result = self.inspect()
        self.assertTrue(result["evidence_qualified"])
        self.assertFalse(result["source_binding_verified"])
        self.assertFalse(result["reachability_closed"])
        self.assertFalse(result["vex_authorized"])
        self.assertFalse(result["release_authorized"])
        self.assertEqual(result["finding_status"]["CVE-2026-8674"]["status"],
                         "under_review")
        self.assertFalse(result["observations"]["gateway_imports_glibc_resolver"])
        self.assertTrue(result["observations"]["closure_contains_resolver_imports"])
        self.assertEqual(result["glibc_package"]["version"], "2.39-0ubuntu8.9")
        self.assertEqual(len(result["elf_inventory"]), 3)

    def test_selected_imports_are_exact(self):
        parsed = reachability.parse_elf(
            elf("getaddrinfo", "fopen64", "dlopen", "OSSL_HTTP_open", "EVP_sha256"),
            "fixture")
        imports = reachability.selected(parsed["undefined_symbols"])
        self.assertEqual(imports["glibc_resolver"], ["getaddrinfo"])
        self.assertEqual(imports["file_mode"], ["fopen64"])
        self.assertEqual(imports["dynamic_loader"], ["dlopen"])
        self.assertEqual(imports["openssl_network"], ["OSSL_HTTP_open"])

    def test_identity_drift_is_rejected(self):
        cases = [
            ("image", lambda: self.image[0].update(Id="sha256:" + "0" * 64)),
            ("platform", lambda: self.image[0].update(Architecture="arm64")),
            ("user", lambda: self.image[0]["Config"].update(User="0:0")),
            ("entrypoint", lambda: self.image[0]["Config"].update(Entrypoint=["/bin/sh"])),
            ("revision", lambda: self.image[0]["Config"]["Labels"].update(
                {"org.opencontainers.image.revision": "0" * 40})),
            ("container", lambda: self.container[0].update(Image="sha256:" + "0" * 64)),
            ("started container", lambda: self.container[0]["State"].update(
                Status="exited", StartedAt="2026-09-30T00:00:00Z")),
            ("mounted container", lambda: self.container[0]["Mounts"].append(
                {"Source": "/tmp", "Destination": "/tmp"})),
        ]
        for label, mutation in cases:
            with self.subTest(label=label):
                self.setUp()
                mutation()
                self.write_inputs()
                with self.assertRaises(ValueError):
                    self.inspect()

    def test_binary_and_ownership_drift_are_rejected(self):
        original = copy.deepcopy(self.ownership)
        for label, mutation in [
            ("gateway hash", lambda: reachability.analyze(
                self.archive, self.image_path, self.container_path, IMAGE_ID,
                COMMIT, "0" * 64)),
            ("owned hash", lambda: self.ownership["packages"]["libc6:amd64"]
             ["files"][0].update(sha256="0" * 64)),
            ("missing glibc", lambda: self.ownership["packages"].pop("libc6:amd64")),
        ]:
            with self.subTest(label=label):
                self.ownership = copy.deepcopy(original)
                if label == "gateway hash":
                    with self.assertRaises(ValueError):
                        mutation()
                else:
                    mutation()
                    self.write_inputs()
                    with self.assertRaises(ValueError):
                        self.inspect()

    def test_unowned_elf_or_dynamic_module_is_not_silently_ignored(self):
        for name in ("usr/local/bin/helper", "usr/lib/x86_64-linux-gnu/ossl-modules/provider.so"):
            with self.subTest(name=name):
                self.setUp()
                self.write_inputs({name: elf("getaddrinfo")})
                with self.assertRaisesRegex(ValueError, "ELF closure differs"):
                    self.inspect()

    def test_malformed_elf_and_unsafe_archive_are_rejected(self):
        self.files["lib/x86_64-linux-gnu/libcrypto.so.3"] = b"\x7fELFbroken"
        self.ownership["packages"]["libssl3t64:amd64"]["files"][0]["sha256"] = \
            reachability.digest(self.files["lib/x86_64-linux-gnu/libcrypto.so.3"])
        self.write_inputs()
        with self.assertRaises(ValueError):
            self.inspect()

        self.setUp()
        with tarfile.open(self.archive, "a") as output:
            item = tarfile.TarInfo("../escape")
            item.size = 1
            output.addfile(item, io.BytesIO(b"x"))
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.inspect()

    def test_duplicate_and_special_archive_members_are_rejected(self):
        for label, name, kind in (
            ("duplicate", "usr/local/bin/bonvoyage-dataplane", tarfile.REGTYPE),
            ("device", "dev/synthetic", tarfile.CHRTYPE),
            ("fifo", "run/synthetic", tarfile.FIFOTYPE),
        ):
            with self.subTest(label=label):
                self.setUp()
                with tarfile.open(self.archive, "a") as output:
                    item = tarfile.TarInfo(name)
                    item.type = kind
                    if kind == tarfile.REGTYPE:
                        item.size = 1
                        output.addfile(item, io.BytesIO(b"x"))
                    else:
                        output.addfile(item)
                with self.assertRaises(ValueError):
                    self.inspect()

    def test_foreign_or_truncated_elf_is_rejected(self):
        original = self.files["lib/x86_64-linux-gnu/libcrypto.so.3"]
        for label, value in (
            ("arm64", original[:18] + struct.pack("<H", 183) + original[20:]),
            ("truncated", original[:-40]),
        ):
            with self.subTest(label=label):
                self.setUp()
                self.files["lib/x86_64-linux-gnu/libcrypto.so.3"] = value
                self.ownership["packages"]["libssl3t64:amd64"]["files"][0]["sha256"] = \
                    reachability.digest(value)
                self.write_inputs()
                with self.assertRaises(ValueError):
                    self.inspect()

    def test_package_identity_mismatch_is_rejected(self):
        package = self.ownership["packages"].pop("libc6:amd64")
        self.ownership["packages"]["unrelated:amd64"] = package
        self.write_inputs()
        with self.assertRaisesRegex(ValueError, "key mismatch"):
            self.inspect()

    def test_duplicate_json_keys_and_nonfinite_values_are_rejected(self):
        for value in ('[{"Id":"one","Id":"two"}]', '[NaN]'):
            with self.subTest(value=value):
                self.setUp()
                self.image_path.write_text(value)
                with self.assertRaises(ValueError):
                    self.inspect()

    def test_cli_preserves_existing_output_and_writes_private_new_output(self):
        output = self.root / "result.json"
        command = [sys.executable, "-B", str(SCRIPT), "--rootfs", str(self.archive),
                   "--image-inspect", str(self.image_path),
                   "--container-inspect", str(self.container_path),
                   "--expected-image-id", IMAGE_ID, "--source-commit", COMMIT,
                   "--expected-gateway-sha256", reachability.digest(self.gateway),
                   "--output", str(output)]
        result = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout.decode())
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        before = output.read_bytes()
        self.assertEqual(subprocess.run(command, capture_output=True, timeout=10).returncode, 2)
        self.assertEqual(output.read_bytes(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
