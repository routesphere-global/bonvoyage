"""Focused packaging input/payload tests; no install, Docker or systemd mutation."""

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("builder", Path(__file__).with_name("build-native-deb.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class NativePackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = self.root / "inputs.json"
        elf = bytearray(128)
        elf[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", elf, 16, 3, 62)
        struct.pack_into("<Q", elf, 24, 4096)
        (self.root / "gateway").write_bytes(elf)
        (self.root / "copyright").write_text("Private fixture; no distribution license granted.\n")
        self.document = {
            "schema_version": 1, "classification": "private-native-gateway-input",
            "distribution": "ubuntu-24.04", "architecture": "amd64", "version": "0.1.0~rehearsal-1",
            "maintainer": "Packaging Test <test@example.invalid>", "producer_source_commit": "1" * 40,
            "source_date_epoch": 1700000000,
            "files": {"dataplane": self.record("gateway"), "copyright": self.record("copyright")},
        }
        self.seal()

    def record(self, name):
        data = (self.root / name).read_bytes()
        return {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def seal(self):
        self.manifest.write_text(json.dumps(self.document))
        self.anchor = hashlib.sha256(self.manifest.read_bytes()).hexdigest()

    def load(self):
        return builder.load_inputs(self.manifest, self.anchor)

    def test_valid_explicit_input(self):
        spec, payload = self.load()
        self.assertEqual(spec["version"], "0.1.0~rehearsal-1")
        self.assertEqual(payload["dataplane"], (self.root / "gateway").read_bytes())

    def test_control_template_continuation_lines(self):
        control = (builder.ROOT / "packaging/debian/control").read_text()
        for line in control.splitlines():
            self.assertTrue(not line or line.startswith(" ") or ": " in line, line)
        self.assertIn(" C++/Seastar gateway", control)

    def test_manifest_digest(self):
        with self.assertRaisesRegex(ValueError, "manifest digest"):
            builder.load_inputs(self.manifest, "0" * 64)

    def test_duplicate_json_key(self):
        self.manifest.write_text(self.manifest.read_text().replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'))
        self.anchor = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            self.load()

    def test_symlink_manifest(self):
        link = self.root / "link.json"
        link.symlink_to(self.manifest)
        with self.assertRaisesRegex(ValueError, "regular manifest"):
            builder.load_inputs(link, self.anchor)

    def test_unsupported_or_injected_fields(self):
        mutations = [("schema_version", True), ("classification", "public-release"), ("architecture", "arm64"),
                     ("distribution", "ubuntu-26.04"), ("version", "1.0\nDepends: arbitrary"),
                     ("maintainer", "Name <test@example.invalid>\nField: injected"),
                     ("producer_source_commit", "g" * 40), ("source_date_epoch", True),
                     ("source_date_epoch", -1)]
        original = copy.deepcopy(self.document)
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                self.document = copy.deepcopy(original)
                self.document[field] = value
                self.seal()
                with self.assertRaises(ValueError):
                    self.load()

    def test_undeclared_field(self):
        self.document["publishable"] = True
        self.seal()
        with self.assertRaisesRegex(ValueError, "manifest fields"):
            self.load()

    def test_unsafe_paths(self):
        for path in ["/etc/passwd", "../gateway", "./gateway", "a/../gateway", "a//gateway"]:
            with self.subTest(path=path):
                self.document["files"]["dataplane"]["path"] = path
                self.seal()
                with self.assertRaises(ValueError):
                    self.load()

    def test_symlink_payload(self):
        (self.root / "link").symlink_to("gateway")
        self.document["files"]["dataplane"]["path"] = "link"
        self.seal()
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.load()

    def test_symlink_parent(self):
        (self.root / "link").symlink_to(self.root, target_is_directory=True)
        self.document["files"]["dataplane"]["path"] = "link/gateway"
        self.seal()
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.load()

    def test_wrong_size_and_digest(self):
        for field, value in [("bytes", 0), ("bytes", True), ("bytes", 4), ("sha256", "0" * 64)]:
            with self.subTest(field=field):
                record = self.record("gateway")
                record[field] = value
                self.document["files"]["dataplane"] = record
                self.seal()
                with self.assertRaises(ValueError):
                    self.load()

    def test_wrong_elf(self):
        original = (self.root / "gateway").read_bytes()
        for offset, value in [(4, 1), (5, 2), (18, 183), (25, 0)]:
            with self.subTest(offset=offset):
                bad = bytearray(original)
                bad[offset] = value
                (self.root / "gateway").write_bytes(bad)
                self.document["files"]["dataplane"] = self.record("gateway")
                self.seal()
                with self.assertRaisesRegex(ValueError, "ELF"):
                    self.load()

    def test_explicit_license_required(self):
        (self.root / "copyright").write_bytes(b" \n")
        self.document["files"]["copyright"] = self.record("copyright")
        self.seal()
        with self.assertRaisesRegex(ValueError, "copyright"):
            self.load()

    def test_prepare_preserves_bytes_and_source_contract(self):
        out = self.root / "out"
        unit = (builder.ROOT / "packaging/systemd/bonvoyage.service").read_bytes()
        _, binding = builder.prepare_tree(self.manifest, self.anchor, out)
        self.assertEqual((out / "work/input/bonvoyage-dataplane").read_bytes(), (self.root / "gateway").read_bytes())
        rendered = (out / "work/debian/bonvoyage-gateway.bonvoyage.service").read_bytes()
        self.assertIn(b"ExecStart=/usr/bin/bonvoyage-dataplane", rendered)
        self.assertEqual(rendered, unit.replace(b"/usr/local/bin/bonvoyage-dataplane", b"/usr/bin/bonvoyage-dataplane"))
        for directive in (b"StandardOutput=journal", b"StandardError=journal",
                          b"SyslogLevel=info", b"SyslogLevelPrefix=no"):
            self.assertEqual(rendered.splitlines().count(directive), 1)
        for flag in (b"--log-to-syslog 1", b"--log-to-stdout 0", b"--log-with-color 0"):
            self.assertEqual(rendered.count(flag), 1)
        self.assertEqual((builder.ROOT / "packaging/systemd/bonvoyage.service").read_bytes(), unit)
        self.assertEqual(binding["source_unit_sha256"], builder.digest(unit))
        self.assertIn("override_dh_strip override_dh_dwz:", (out / "work/debian/rules").read_text())
        self.assertIn("--no-enable --no-start --no-restart-after-upgrade", (out / "work/debian/rules").read_text())
        self.assertEqual((out / "work/debian/rules").stat().st_mode & 0o777, 0o755)

    def test_output_never_overwritten(self):
        out = self.root / "out"
        out.mkdir()
        (out / "sentinel").write_text("keep")
        with self.assertRaisesRegex(ValueError, "new output"):
            builder.prepare_tree(self.manifest, self.anchor, out)
        self.assertEqual((out / "sentinel").read_text(), "keep")

    def test_bad_input_creates_no_output(self):
        out = self.root / "out"
        with self.assertRaises(ValueError):
            builder.prepare_tree(self.manifest, "0" * 64, out)
        self.assertFalse(out.exists())

    def test_source_contract_drift_rejects(self):
        fake = self.root / "repo"
        shutil.copytree(builder.ROOT / "packaging", fake / "packaging")
        (fake / "packaging/systemd/bonvoyage.service").write_text("ExecStart=/unexpected\n")
        with self.assertRaisesRegex(ValueError, "contract drift"):
            builder.prepare_tree(self.manifest, self.anchor, self.root / "out", fake)
        self.assertFalse((self.root / "out").exists())

    def payload_tar(self, extra=None, mode=0o755, uid=0, duplicate=False):
        files = {
            "usr/bin/bonvoyage-dataplane": (self.root / "gateway").read_bytes(),
            "lib/systemd/system/bonvoyage.service": b"unit",
            "usr/share/doc/bonvoyage-gateway/copyright": (self.root / "copyright").read_bytes(),
            "usr/share/doc/bonvoyage-gateway/README.Debian": b"readme",
        }
        if extra:
            files[extra] = b"unexpected"
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w") as archive:
            for name, data in files.items():
                member = tarfile.TarInfo("./" + name)
                member.size = len(data)
                member.uid = uid
                member.mode = mode if name == "usr/bin/bonvoyage-dataplane" else 0o644
                archive.addfile(member, io.BytesIO(data))
                if duplicate:
                    archive.addfile(member, io.BytesIO(data))
        return out.getvalue()

    def test_payload_exact_and_root_owned(self):
        self.assertEqual(builder.verify_payload_tar(self.payload_tar(), self.document, b"unit", b"readme"), 4)

    def test_standard_tar_root_is_validated(self):
        for mode, uid, duplicate in [(0o755, 0, False), (0o777, 0, False), (0o755, 999, False), (0o755, 0, True)]:
            with self.subTest(mode=mode, uid=uid, duplicate=duplicate):
                out = io.BytesIO()
                with tarfile.open(fileobj=out, mode="w") as target:
                    root = tarfile.TarInfo(".")
                    root.type = tarfile.DIRTYPE
                    root.mode, root.uid = mode, uid
                    target.addfile(root)
                    if duplicate:
                        target.addfile(root)
                    with tarfile.open(fileobj=io.BytesIO(self.payload_tar())) as payload:
                        for member in payload:
                            target.addfile(member, payload.extractfile(member))
                if mode == 0o755 and uid == 0 and not duplicate:
                    self.assertEqual(builder.verify_payload_tar(out.getvalue(), self.document, b"unit", b"readme"), 4)
                else:
                    with self.assertRaisesRegex(ValueError, "archive root"):
                        builder.verify_payload_tar(out.getvalue(), self.document, b"unit", b"readme")

    def test_payload_rejects_unexpected_files(self):
        for name in ["usr/local/bin/gateway", "etc/bonvoyage/snapshot.pb", "../escape", "/absolute", "run/state"]:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    builder.verify_payload_tar(self.payload_tar(extra=name), self.document, b"unit", b"readme")

    def test_payload_rejects_modes_owner_duplicates_corruption(self):
        for kwargs in [{"mode": 0o4755}, {"uid": 999}, {"duplicate": True}]:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    builder.verify_payload_tar(self.payload_tar(**kwargs), self.document, b"unit", b"readme")
        with self.assertRaises(ValueError):
            builder.verify_payload_tar(self.payload_tar(), self.document, b"wrong-unit", b"readme")

    def test_payload_rejects_symlinks(self):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w") as archive:
            member = tarfile.TarInfo("usr/bin/bonvoyage-dataplane")
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
            member.mode = 0o755
            archive.addfile(member)
        with self.assertRaisesRegex(ValueError, "links"):
            builder.verify_payload_tar(out.getvalue(), self.document, b"unit", b"readme")

    def test_preinst_preserves_admin_unit(self):
        scripts = self.root / "systemd"
        scripts.mkdir()
        (scripts / "bonvoyage.service").write_text("administrator")
        source = (builder.ROOT / "packaging/debian/preinst").read_text()
        rendered = self.root / "preinst"
        rendered.write_text(source.replace("/etc/systemd/system", str(scripts)))
        result = subprocess.run(["sh", str(rendered), "install"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("shadows", result.stderr)
        self.assertEqual((scripts / "bonvoyage.service").read_text(), "administrator")

    def test_postinst_rejects_root_identity_before_mutation(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        shim = bin_dir / "getent"
        shim.write_text("#!/bin/sh\ncase \"$1\" in passwd) echo 'bonvoyage:x:0:0::/var/lib/bonvoyage:/usr/sbin/nologin';; group) echo 'bonvoyage:x:0:';; esac\n")
        shim.chmod(0o755)
        import os
        result = subprocess.run(["sh", str(builder.ROOT / "packaging/debian/postinst"), "configure"],
                                env={**os.environ, "PATH": str(bin_dir) + ":" + os.environ["PATH"]},
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("unsupported bonvoyage service identity", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
