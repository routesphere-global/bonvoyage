#!/usr/bin/env python3
"""Verify retained public observations, never infer vulnerability absence or VEX."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

MODULE = importlib.util.spec_from_file_location("native_inventory", Path(__file__).with_name("collect-native-runtime.py"))
runtime = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(runtime)
NAMES = {
    "seastar", "nghttp2", "libjwt", "abseil", "re2",
    "opentelemetry-proto", "c-ares", "llhttp",
}
LIMIT = 8 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def raw(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= LIMIT,
            "bounded regular evidence file required: " + str(path))
    return path.read_bytes()


def decode(data):
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda value: require(False, "non-finite JSON: " + value))


def digest(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def instant(value):
    require(isinstance(value, str) and re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)", value), "UTC retrieval time required")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def verify(evidence, repository, producer_commit=None):
    components = decode(raw(evidence / "components.json"))
    requests = decode(raw(evidence / "requests.json"))
    declared = {}
    records = runtime.producer_records(producer_commit, repository) if producer_commit is not None else {
        path.relative_to(repository).as_posix(): raw(path)
        for path in sorted((repository / "security/dependencies").glob("*.json"))}
    for relative, data in records.items():
        path = repository / relative
        item = runtime.validate_record(data)
        require(item.get("name") in NAMES and item["name"] not in declared, "unreviewed/duplicate dependency declaration")
        require(relative == "security/dependencies/" + item["name"] + "-" + item["version"] + ".json",
                "dependency filename identity mismatch")
        declared[item["name"]] = (path, data, item)
    require(producer_commit is not None or set(declared) == NAMES, "current dependency declarations incomplete")
    require(isinstance(components, list) and len(components) == len(declared), "complete source-bound component set required")
    require(isinstance(requests, list) and 3 * len(declared) <= len(requests) <= 128, "bounded request records required")
    require(all(isinstance(c, dict) and isinstance(c.get("name"), str) for c in components) and
            {c.get("name") for c in components} == set(declared), "missing/duplicate/unknown component")
    require(all(isinstance(r, dict) and isinstance(r.get("name"), str) for r in requests), "request identities required")
    by_name = {r["name"]: r for r in requests}
    require(len(by_name) == len(requests), "duplicate request identity")
    observations = []
    for component in components:
        name = component["name"]
        path, data, item = declared[name]
        reference = component.get("record")
        require(isinstance(reference, dict) and reference == {
            "path": path.relative_to(repository).as_posix(), **digest(data)}, "dependency record drift: " + name)
        commit = item.get("source", {}).get("commit")
        require(isinstance(commit, str) and re.fullmatch(r"[a-f0-9]{40}", commit), "pinned commit required")
        source = urlsplit(item["source"]["release_url"])
        parts = source.path.strip("/").split("/")
        require(source.scheme == "https" and source.netloc == "github.com" and not source.query and not source.fragment and
                len(parts) >= 5 and parts[2:4] == ["releases", "tag"] and all(re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in parts[:2]),
                "public upstream repository identity required")
        repo = "/".join(parts[:2])
        require(component.get("repository") == repo and component.get("source_commit") == commit and
                component.get("version") == item.get("version"), "component identity drift: " + name)
        prefix = "https://api.github.com/repos/" + repo
        expected = [("github-advisories", prefix + "/security-advisories?per_page=100&state=published", None),
                    ("osv-commit", "https://api.osv.dev/v1/query", {"commit": commit}),
                    ("pinned-commit", prefix + "/commits/" + commit, None)]
        responses = {}
        retrieved = {}
        for suffix, url, payload in expected:
            identity = name + "-" + suffix
            request = by_name.get(identity)
            require(request is not None, "missing request: " + identity)
            require(request.get("url") == url and request.get("payload") == payload and
                    type(request.get("exit_code")) is int and request["exit_code"] == 0 and
                    request.get("http_result") == "200 " + url, "failed/redirected/wrong-source request: " + identity)
            started, completed = instant(request.get("started_at")), instant(request.get("completed_at"))
            require(started <= completed, "negative retrieval interval")
            retrieved[suffix] = request["completed_at"]
            for kind in ("body", "headers"):
                value = raw(evidence / "sources" / (identity + "." + kind))
                require(request.get(kind) == digest(value), "response hash/size mismatch: " + identity + "." + kind)
                if kind == "body":
                    responses[suffix] = decode(value)
                else:
                    # A first page is not a complete published-feed observation.
                    require(not any(re.search(r'\brel\s*=\s*"?next\b', line, re.I)
                                    for line in value.decode("utf-8").splitlines() if line.lower().startswith("link:")),
                            "uncollected GitHub page: " + identity)
        pinned = responses["pinned-commit"]
        require(isinstance(pinned, dict) and pinned.get("sha") == commit and pinned.get("url") == prefix + "/commits/" + commit and
                pinned.get("html_url") == "https://github.com/" + repo + "/commit/" + commit, "wrong upstream commit object")
        advisories = responses["github-advisories"]
        require(isinstance(advisories, list), "GitHub advisory array required")
        ids = []
        for advisory in advisories:
            require(isinstance(advisory, dict) and re.fullmatch(r"GHSA-[a-z0-9]{4}(?:-[a-z0-9]{4}){2}", advisory.get("ghsa_id", "")) and
                    advisory.get("state") == "published" and isinstance(advisory.get("summary"), str) and advisory["summary"] and
                    isinstance(advisory.get("vulnerabilities"), list) and advisory["vulnerabilities"] and
                    advisory.get("html_url") == "https://github.com/" + repo + "/security/advisories/" + advisory["ghsa_id"],
                    "incomplete or wrong-repository advisory")
            ids.append(advisory["ghsa_id"])
        require(len(ids) == len(set(ids)), "duplicate advisory identity")
        osv = responses["osv-commit"]
        require(isinstance(osv, dict) and set(osv) <= {"vulns", "next_page_token"} and
                osv.get("next_page_token", "") == "" and isinstance(osv.get("vulns", []), list), "incomplete/error/paginated OSV response")
        osv_ids = [v.get("id") if isinstance(v, dict) else None for v in osv.get("vulns", [])]
        require(all(isinstance(v, str) and v.strip() for v in osv_ids) and len(osv_ids) == len(set(osv_ids)), "incomplete/duplicate OSV identities")
        require(component.get("github_advisory_count") == len(ids), "retained advisory count drift")
        observations.append({"name": name, "version": item["version"], "source_commit": commit, "record_sha256": reference["sha256"],
            "repository": repo, "retrieved_at": retrieved, "published_github_advisories": ids, "osv_commit_observations": osv_ids,
            "coverage_qualified": False, "applicability_review_complete": False})
    return {"schema_version": 1, "classification": "verified-public-observations-not-a-scan", "input_evidence_verified": True,
            "declaration_source": {"kind": "producer-commit" if producer_commit else "checkout", "commit": producer_commit},
            "components": observations, "coverage_qualified": False, "scan_qualified": False, "publishable": False,
            "limitations": ["Empty public feeds do not prove advisory coverage or vulnerability absence.",
                            "Response hashes bind retained bytes, not signed upstream attestations.",
                            "Commit existence is not fix ancestry or local-patch applicability.",
                            "This review does not suppress findings, generate VEX, or authorize releases."],
            "reviewed_at": datetime.now(timezone.utc).isoformat()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--producer-source-commit", help="Verify dated observations against this exact producing commit")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.evidence, args.repository, args.producer_source_commit)
        os.umask(0o077)
        with args.output.open("x", encoding="utf-8") as output:
            json.dump(result, output, indent=2, sort_keys=True)
            output.write("\n")
        print("Verified " + str(len(result["components"])) + " source-bound public observations; coverage and release acceptance remain false.")
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print("Invalid native advisory evidence: " + str(error))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
