#!/usr/bin/env python3

import hashlib
import json
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PATCH = ROOT / "deploy/docker/bonvoyage/patches/seastar-tls-certificate-policy.patch"
DOCKERFILE = ROOT / "deploy/docker/bonvoyage/Dockerfile"
LEDGER = ROOT / "security/dependencies/seastar-25.05.0.json"


class GnuTLSCertificatePolicyContractTest(unittest.TestCase):
    def test_patch_is_content_addressed_everywhere(self):
        digest = hashlib.sha256(PATCH.read_bytes()).hexdigest()
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        match = re.search(
            r"ARG SEASTAR_TLS_CERTIFICATE_POLICY_PATCH_SHA256=([0-9a-f]{64})",
            dockerfile,
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), digest)
        self.assertIn("/tmp/seastar-tls-certificate-policy.patch", dockerfile)

        ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
        records = {
            entry["file"]: entry
            for entry in ledger["build"]["local_patches"]
        }
        path = "deploy/docker/bonvoyage/patches/seastar-tls-certificate-policy.patch"
        self.assertIn(path, records)
        self.assertEqual(records[path]["sha256"], digest)

    def test_patch_contains_each_fail_closed_boundary(self):
        patch = PATCH.read_text(encoding="utf-8")
        for required in (
            "verify_key_usage(leaf)",
            "usage == 0",
            "has_dns_subject_alt_name(leaf)",
            "gnutls_x509_crt_check_hostname",
            "GNUTLS_SAN_DN || type == GNUTLS_SAN_URI",
            "verify_trust_bundle_policy(b, fmt)",
            "verify_peer_certificate_policy();",
        ):
            with self.subTest(required=required):
                self.assertIn(required, patch)

    def test_failed_certificate_list_import_uses_gnutls_owned_cleanup(self):
        patch = PATCH.read_text(encoding="utf-8")
        failure_branch = re.search(
            r"if \(result < 0\) \{(?P<body>.*?)\n\+        \}",
            patch,
            re.DOTALL,
        )
        self.assertIsNotNone(failure_branch)
        body = failure_branch.group("body")
        self.assertNotIn("release();", body)
        self.assertIn("_certificates = nullptr;", body)
        self.assertIn("_count = 0;", body)
        self.assertIn("gtls_chk(result);", body)

    def test_live_replay_covers_good_and_rejected_cases(self):
        harness = (
            ROOT / "scripts/phase6-gnutls-certificate-policy.sh"
        ).read_text(encoding="utf-8")
        for required in (
            "valid.client.example.test",
            "cn-only.client.example.test",
            "zero-key-usage.client.example.test",
            "malformed-key-usage.client.example.test",
            "unsupported directoryName or URI name constraints",
            "malformed trust bundle terminated through the exception path",
        ):
            with self.subTest(required=required):
                self.assertIn(required, harness)


if __name__ == "__main__":
    unittest.main()
