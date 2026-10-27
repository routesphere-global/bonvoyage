"""Negative tests for private RC handoff verification; no Docker daemon required."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("verifier", Path(__file__).with_name("verify-native-rc-package.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.blobs = {}
        config = self.blob({"os": "linux", "architecture": "amd64"})
        manifest = self.blob({"config": config, "layers": []})
        manifest["platform"] = {"architecture": "amd64", "os": "linux"}
        self.index = self.blob({"manifests": [manifest]})
        self.write_archive()
        (self.root / "gateway").write_bytes(b"\x7fELF\x02\x01" + bytes(12) + b"\x3e\x00")
        self.document = {"schema_version": 1, "classification": "private-native-rc-handoff",
                         "formal_rc_accepted": False, "allocation_authorized": False,
                         "publishable": False, "source_commit": "1" * 40,
                         "runtime_image": self.index["digest"], "image_archive": "images.tar",
                         "images": verifier.inspect_oci_archive(self.root / "images.tar", [self.index["digest"]]),
                         "executables": ["gateway"]}
        self.seal()

    def blob(self, value):
        data = json.dumps(value).encode()
        digest = hashlib.sha256(data).hexdigest()
        self.blobs["blobs/sha256/" + digest] = data
        return {"digest": "sha256:" + digest, "size": len(data)}

    def write_archive(self):
        with tarfile.open(self.root / "images.tar", "w") as archive:
            values = {**self.blobs, "index.json": json.dumps({"manifests": [self.index]}).encode()}
            for name, data in values.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def seal(self):
        self.document["files"] = [{"path": name, "bytes": (self.root / name).stat().st_size,
                                   "sha256": verifier.digest_file(self.root / name)}
                                  for name in ["images.tar", "gateway"]]
        self.write_manifest()

    def write_manifest(self):
        (self.root / "rc-package.json").write_text(json.dumps(self.document))
        self.expected = verifier.digest_file(self.root / "rc-package.json")

    def test_valid_selected_amd64_package(self):
        self.assertEqual(verifier.verify(self.root, self.expected)["outcome"], "PASS")

    def test_manifest_corruption(self):
        with (self.root / "rc-package.json").open("a") as stream:
            stream.write(" ")
        with self.assertRaisesRegex(ValueError, "manifest digest"):
            verifier.verify(self.root, self.expected)

    def test_binary_corruption(self):
        (self.root / "gateway").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "size mismatch"):
            verifier.verify(self.root, self.expected)

    def test_unbound_file(self):
        (self.root / "extra").write_text("unbound")
        with self.assertRaisesRegex(ValueError, "unbound"):
            verifier.verify(self.root, self.expected)

    def test_symlink_and_traversal(self):
        (self.root / "linked").symlink_to(self.root / "gateway")
        for name in ["linked", "../gateway", "/tmp/gateway"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                verifier.contained_file(self.root, name)

    def test_corrupt_oci_blob_even_with_updated_package_hash(self):
        name = next(iter(self.blobs))
        self.blobs[name] += b" "
        self.write_archive()
        self.seal()
        with self.assertRaisesRegex(ValueError, "corrupt blob"):
            verifier.verify(self.root, self.expected)

    def test_platform_substitution(self):
        self.document["images"][0]["platform_manifest"] = "sha256:" + "f" * 64
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "selected image"):
            verifier.verify(self.root, self.expected)

    def test_wrong_elf_architecture(self):
        data = bytearray((self.root / "gateway").read_bytes())
        data[18:20] = b"\xb7\x00"
        (self.root / "gateway").write_bytes(data)
        self.seal()
        with self.assertRaisesRegex(ValueError, "AMD64 ELF"):
            verifier.verify(self.root, self.expected)

    def test_no_handoff_authorization_escalation(self):
        for field in ["formal_rc_accepted", "allocation_authorized", "publishable"]:
            with self.subTest(field=field):
                self.document[field] = True
                self.write_manifest()
                with self.assertRaisesRegex(ValueError, "cannot authorize"):
                    verifier.verify(self.root, self.expected)
                self.document[field] = False


if __name__ == "__main__":
    unittest.main()
