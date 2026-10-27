#!/usr/bin/env python3
"""Synthetic evidence mutations; not scans, advisory queries or native load tests."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

SCRIPT = Path(__file__).with_name("review-native-advisories.py")
SPEC = importlib.util.spec_from_file_location("advisories", SCRIPT)
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)
ROOT = SCRIPT.parent.parent


class AdvisoryEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "repository"
        self.deps = self.repo / "security/dependencies"
        self.deps.mkdir(parents=True)
        self.evidence = self.base / "evidence"
        (self.evidence / "sources").mkdir(parents=True)
        self.components, self.requests = [], []
        for path in sorted((ROOT / "security/dependencies").glob("*.json")):
            raw = path.read_bytes()
            (self.deps / path.name).write_bytes(raw)
            item = json.loads(raw)
            name, commit = item["name"], item["source"]["commit"]
            repo = "/".join(urlsplit(item["source"]["release_url"]).path.strip("/").split("/")[:2])
            prefix = "https://api.github.com/repos/" + repo
            self.components.append({"name": name, "version": item["version"], "source_commit": commit,
                "repository": repo, "record": {"path": "security/dependencies/" + path.name, **review.digest(raw)}, "github_advisory_count": 0})
            for suffix, url, payload, body in (
                ("github-advisories", prefix + "/security-advisories?per_page=100&state=published", None, []),
                ("osv-commit", "https://api.osv.dev/v1/query", {"commit": commit}, {}),
                ("pinned-commit", prefix + "/commits/" + commit, None,
                 {"sha": commit, "url": prefix + "/commits/" + commit, "html_url": "https://github.com/" + repo + "/commit/" + commit})):
                identity = name + "-" + suffix
                self.requests.append({"name": identity, "url": url, "payload": payload, "http_result": "200 " + url, "exit_code": 0,
                    "started_at": "2026-09-14T16:00:00+00:00", "completed_at": "2026-09-14T16:00:01+00:00"})
                self.body(identity, body)
                self.headers(identity, "HTTP/2 200\n\n")
        self.save()

    def request(self, name):
        return next(r for r in self.requests if r["name"] == name)

    def body(self, name, value):
        data = json.dumps(value).encode()
        (self.evidence / "sources" / (name + ".body")).write_bytes(data)
        self.request(name)["body"] = review.digest(data)

    def headers(self, name, value):
        data = value.encode()
        (self.evidence / "sources" / (name + ".headers")).write_bytes(data)
        self.request(name)["headers"] = review.digest(data)

    def save(self):
        (self.evidence / "components.json").write_text(json.dumps(self.components))
        (self.evidence / "requests.json").write_text(json.dumps(self.requests))

    def check(self):
        self.save()
        return review.verify(self.evidence, self.repo)

    def rejected(self):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.check()

    def test_empty_feeds_never_qualify_coverage_or_release(self):
        result = self.check()
        self.assertTrue(result["input_evidence_verified"])
        for name in ("coverage_qualified", "scan_qualified", "publishable"):
            self.assertIs(result[name], False)
        self.assertTrue(all(c["coverage_qualified"] is False and c["applicability_review_complete"] is False for c in result["components"]))
        self.assertEqual(len(result["components"]), 8)
        self.assertEqual(result["declaration_source"], {"kind": "checkout", "commit": None})

    def test_missing_cares_current_declaration_rejected(self):
        (self.deps / "c-ares-1.34.8.json").unlink()
        self.components = [c for c in self.components if c["name"] != "c-ares"]
        self.rejected()

    def test_missing_llhttp_current_declaration_rejected(self):
        (self.deps / "llhttp-9.4.3.json").unlink()
        self.components = [c for c in self.components if c["name"] != "llhttp"]
        self.rejected()

    def test_historical_observations_explicitly_bind_producer_records(self):
        records = {str(p.relative_to(self.repo)): p.read_bytes() for p in self.deps.glob("*.json") if p.name != "llhttp-9.4.3.json"}
        self.components = [c for c in self.components if c["name"] != "llhttp"]
        self.save()
        # Producer-history admission is tested with real disposable Git graphs in
        # test_collect_native_runtime.py; this fixture tests the advisory binding.
        with patch.object(review.runtime, "producer_records", return_value=records) as load:
            (self.deps / "seastar-25.05.0.json").write_text("checkout drift")
            result = review.verify(self.evidence, self.repo, "a" * 40)
            load.assert_called_once_with("a" * 40, self.repo)
            self.assertEqual(len(result["components"]), 7)
            self.assertEqual(result["declaration_source"], {"kind": "producer-commit", "commit": "a" * 40})
            self.assertIs(result["scan_qualified"], False)

    def test_seven_observations_cannot_hide_new_producer_llhttp(self):
        records = {str(p.relative_to(self.repo)): p.read_bytes() for p in self.deps.glob("*.json")}
        self.components = [c for c in self.components if c["name"] != "llhttp"]
        self.save()
        with patch.object(review.runtime, "producer_records", return_value=records), self.assertRaises(ValueError):
            review.verify(self.evidence, self.repo, "a" * 40)

    def test_historical_source_gate_failure_is_not_silently_retried_with_checkout(self):
        with patch.object(review.runtime, "producer_records", side_effect=ValueError("missing producer history")), self.assertRaises(ValueError):
            review.verify(self.evidence, self.repo, "a" * 40)

    def test_nonempty_advisory_is_retained_without_applicability_claim(self):
        component = next(c for c in self.components if c["name"] == "nghttp2")
        component["github_advisory_count"] = 1
        self.body("nghttp2-github-advisories", [{"ghsa_id": "GHSA-aaaa-bbbb-cccc", "state": "published", "summary": "Synthetic",
            "vulnerabilities": [{}], "html_url": "https://github.com/nghttp2/nghttp2/security/advisories/GHSA-aaaa-bbbb-cccc"}])
        self.assertEqual(next(c for c in self.check()["components"] if c["name"] == "nghttp2")["published_github_advisories"], ["GHSA-aaaa-bbbb-cccc"])

    def test_osv_match_is_retained_without_waiver(self):
        self.body("seastar-osv-commit", {"vulns": [{"id": "OSV-SYNTHETIC-1"}]})
        self.assertEqual(next(c for c in self.check()["components"] if c["name"] == "seastar")["osv_commit_observations"], ["OSV-SYNTHETIC-1"])

    def test_missing_duplicate_or_unknown_component_rejected(self):
        original = copy.deepcopy(self.components)
        for value in (original[:-1], original[:-1] + [original[0]], original + [original[0]]):
            self.components = value
            self.rejected()

    def test_unknown_current_dependency_rejected(self):
        (self.deps / "extra.json").write_text(json.dumps({"name": "extra", "source": {}}))
        self.rejected()

    def test_current_record_drift_rejected(self):
        path = next(self.deps.glob("*.json"))
        path.write_bytes(path.read_bytes() + b"\n")
        self.rejected()

    def test_component_commit_version_repository_and_path_drift_rejected(self):
        original = copy.deepcopy(self.components)
        for key, value in (("version", "old"), ("source_commit", "a" * 40), ("repository", "wrong/repo"), ("record", {})):
            self.components = copy.deepcopy(original)
            self.components[0][key] = value
            self.rejected()

    def test_missing_or_duplicate_request_rejected(self):
        original = copy.deepcopy(self.requests)
        self.requests.pop()
        self.rejected()
        self.requests = original + [original[0]]
        self.rejected()

    def test_failed_non200_or_redirected_request_rejected(self):
        record = self.request("seastar-osv-commit")
        original = copy.deepcopy(record)
        for key, value in (("exit_code", 28), ("exit_code", False), ("http_result", "404 " + record["url"]),
                           ("http_result", "200 https://wrong.example/"), ("url", "https://wrong.example/"), ("payload", {"commit": "a" * 40})):
            record.clear()
            record.update(original)
            record[key] = value
            self.rejected()

    def test_body_hash_or_size_drift_rejected(self):
        record = self.request("seastar-osv-commit")
        for value in ({"bytes": 2, "sha256": "a" * 64}, {"bytes": 3, "sha256": record["body"]["sha256"]}):
            record["body"] = value
            self.rejected()

    def test_header_drift_rejected(self):
        (self.evidence / "sources/seastar-osv-commit.headers").write_bytes(b"changed")
        self.rejected()

    def test_symlink_response_rejected(self):
        path = self.evidence / "sources/seastar-osv-commit.body"
        target = self.base / "target"
        path.rename(target)
        path.symlink_to(target)
        self.rejected()

    def test_oversized_response_rejected(self):
        path = self.evidence / "sources/seastar-osv-commit.body"
        with path.open("wb") as output:
            output.truncate(review.LIMIT + 1)
        self.rejected()

    def test_duplicate_json_keys_rejected(self):
        (self.evidence / "components.json").write_text('{"name":1,"name":2}')
        with self.assertRaises(ValueError):
            review.verify(self.evidence, self.repo)

    def test_non_finite_json_rejected(self):
        (self.evidence / "components.json").write_text('[NaN]')
        with self.assertRaises(ValueError):
            review.verify(self.evidence, self.repo)

    def test_invalid_or_negative_retrieval_time_rejected(self):
        record = self.request("seastar-osv-commit")
        for value in ("yesterday", "2026-09-14T16:00:01+08:00", "2026-09-14T15:59:59Z"):
            record["completed_at"] = value
            self.rejected()

    def test_uncollected_github_page_rejected(self):
        self.headers("nghttp2-github-advisories", 'HTTP/2 200\nLink: <https://api.github.com/next>; rel="next"\n\n')
        self.rejected()

    def test_uncollected_osv_page_or_error_rejected(self):
        for value in ({"next_page_token": "more"}, {"error": "unavailable"}, {"vulns": None}, {"vulns": [None]}, {"vulns": [{"id": "A"}, {"id": "A"}]}):
            self.body("seastar-osv-commit", value)
            self.rejected()

    def test_wrong_commit_object_rejected(self):
        record = self.request("seastar-pinned-commit")
        path = self.evidence / "sources/seastar-pinned-commit.body"
        original = json.loads(path.read_bytes())
        for key, value in (("sha", "a" * 40), ("url", "https://api.github.com/wrong"), ("html_url", "https://github.com/wrong")):
            body = dict(original, **{key: value})
            self.body(record["name"], body)
            self.rejected()

    def test_malformed_feed_or_count_drift_rejected(self):
        for body in ({}, [None], [{"ghsa_id": "bad"}]):
            self.body("nghttp2-github-advisories", body)
            self.rejected()
        self.body("nghttp2-github-advisories", [])
        self.components[0]["github_advisory_count"] = 10
        self.rejected()

    def cli(self, output):
        self.save()
        return subprocess.run(["python3", "-B", str(SCRIPT), "--repository", str(self.repo),
            "--evidence", str(self.evidence), "--output", str(output)], capture_output=True, timeout=10)

    def test_cli_writes_private_nonqualified_report(self):
        output = self.base / "summary.json"
        self.assertEqual(self.cli(output).returncode, 0)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertIs(json.loads(output.read_bytes())["publishable"], False)

    def test_cli_invalid_evidence_writes_nothing(self):
        self.request("seastar-osv-commit")["exit_code"] = 28
        output = self.base / "summary.json"
        self.assertEqual(self.cli(output).returncode, 2)
        self.assertFalse(output.exists())

    def test_cli_refuses_existing_output(self):
        output = self.base / "summary.json"
        output.write_bytes(b"preserve")
        self.assertEqual(self.cli(output).returncode, 2)
        self.assertEqual(output.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main(verbosity=2)
