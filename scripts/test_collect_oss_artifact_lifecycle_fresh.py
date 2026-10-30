import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("collect-oss-artifact-lifecycle-fresh.py")
SPEC = importlib.util.spec_from_file_location("fresh_lane", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class FreshLifecycleLaneTest(unittest.TestCase):
    def intake(self, root, commit, tag, body):
        artifact_path = root / "artifacts/candidate.deb"
        artifact_path.parent.mkdir(parents=True)
        artifact_path.write_bytes(body)
        receipt_path = root / "evidence/debian/oss-deb-build-a/build-receipt.json"
        receipt_path.parent.mkdir(parents=True)
        receipt_path.write_text("{}\n", encoding="utf-8")
        receipt = {
            "schema_version": 1,
            "classification": MODULE.INTAKE_CLASSIFICATION,
            "source": {
                "repository": MODULE.REPOSITORY,
                "commit": commit,
                "tag": tag,
                "dirty": False,
            },
            "artifacts": [{
                "id": "gateway-deb-linux-amd64",
                "kind": "debian-package",
                "path": "artifacts/candidate.deb",
                "bytes": len(body),
                "sha256": sha256(body),
            }],
            "authority": MODULE.AUTHORITY,
        }
        (root / "candidate-intake-receipt.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        return receipt

    def test_wraps_only_a_verified_exact_native_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate_root = root / "candidate"
            baseline_root = root / "baseline"
            output = root / "output"
            candidate_root.mkdir()
            baseline_root.mkdir()
            candidate = self.intake(candidate_root, "a" * 40, "v1.0.0-rc.7", b"candidate")
            baseline = self.intake(baseline_root, "b" * 40, "v1.0.0-rc.6", b"baseline")

            def collector(**arguments):
                arguments["output"].mkdir()
                (arguments["output"] / "raw").mkdir()
                (arguments["output"] / "raw/traffic.txt").write_text("PASS\n")
                (arguments["output"] / "observation.json").write_text("{}\n")
                return {"verification": {
                    "fresh_install_qualified": True,
                    "source_commit": candidate["source"]["commit"],
                    "source_tag": candidate["source"]["tag"],
                    "package_sha256": candidate["artifacts"][0]["sha256"],
                    "release_admitted": False,
                    "publishable": False,
                }}

            lane = MODULE.collect(
                candidate_root=candidate_root,
                baseline_root=baseline_root,
                output=output,
                confirmed_hostname="fixture",
                retained_state_confirmation="RETAIN_BONVOYAGE_OPERATOR_STATE",
                collector=collector,
            )
            self.assertEqual(lane["job"], "debian-candidate-fresh")
            self.assertEqual(lane["phases"][0]["id"], "candidate-fresh-install")
            self.assertTrue(all(lane["phases"][0]["checks"].values()))
            self.assertEqual(lane["phases"][0]["evidence"],
                             ["observation.json", "raw/traffic.txt"])
            self.assertEqual(json.loads((output / "lane.json").read_text()), lane)

    def test_rejects_an_unverified_or_same_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate_root = root / "candidate"
            baseline_root = root / "baseline"
            candidate_root.mkdir()
            baseline_root.mkdir()
            self.intake(candidate_root, "a" * 40, "v1.0.0-rc.7", b"same")
            self.intake(baseline_root, "a" * 40, "v1.0.0-rc.6", b"same")
            with self.assertRaises(MODULE.Rejected):
                MODULE.collect(
                    candidate_root=candidate_root,
                    baseline_root=baseline_root,
                    output=root / "output",
                    confirmed_hostname="fixture",
                    retained_state_confirmation="RETAIN_BONVOYAGE_OPERATOR_STATE",
                    collector=lambda **_: {},
                )

    def test_json_reader_rejects_a_symlink_without_reopening_the_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            link = root / "receipt.json"
            link.symlink_to(target)
            with self.assertRaises((OSError, MODULE.Rejected)):
                MODULE.read_json(link, "linked receipt")

    def test_intake_rejects_a_symlinked_artifact_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            intake_root = root / "intake"
            external = root / "external"
            intake_root.mkdir()
            external.mkdir()
            body = b"candidate"
            (external / "candidate.deb").write_bytes(body)
            (intake_root / "artifacts").symlink_to(external, target_is_directory=True)
            receipt = {
                "schema_version": 1,
                "classification": MODULE.INTAKE_CLASSIFICATION,
                "source": {
                    "repository": MODULE.REPOSITORY,
                    "commit": "a" * 40,
                    "tag": "v1.0.0-rc.7",
                    "dirty": False,
                },
                "artifacts": [{
                    "id": "gateway-deb-linux-amd64",
                    "kind": "debian-package",
                    "path": "artifacts/candidate.deb",
                    "bytes": len(body),
                    "sha256": sha256(body),
                }],
                "authority": MODULE.AUTHORITY,
            }
            (intake_root / "candidate-intake-receipt.json").write_text(
                json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            with self.assertRaises(MODULE.Rejected):
                MODULE.intake(intake_root, "gateway-deb-linux-amd64")

    def test_stage_file_copies_only_the_expected_bytes_into_a_private_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "candidate.deb"
            body = b"exact-candidate-bytes"
            source.write_bytes(body)
            staging = root / "inputs"
            staging.mkdir(mode=0o700)
            destination = staging / "candidate.deb"
            result = MODULE.stage_file(source, destination, len(body), sha256(body))
            self.assertEqual(result, {
                "path": destination,
                "bytes": len(body),
                "sha256": sha256(body),
            })
            self.assertEqual(destination.read_bytes(), body)
            self.assertEqual(os.stat(destination).st_mode & 0o777, 0o600)

            tampered = staging / "tampered.deb"
            with self.assertRaises(MODULE.Rejected):
                MODULE.stage_file(source, tampered, len(body), "0" * 64)
            self.assertFalse(tampered.exists())


if __name__ == "__main__":
    unittest.main()
