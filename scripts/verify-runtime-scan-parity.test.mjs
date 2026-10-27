import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { compareScans, verifyDecoded } from "./verify-runtime-scan-parity.mjs";

// Synthetic contract tests, not evidence of real decoder execution or scans.
const now = Date.parse("2026-09-15T12:00:00Z");
const cpe = "cpe:2.3:a:c-ares_project:c-ares:1.34.8:*:*:*:*:*:*:*";
const clone = (value) => structuredClone(value);
function fixture() {
  const binding = {schema_version: 1, status: "passed", image_binding_qualified: true,
    syft_descriptor_is_registry_manifest: false, platform: "linux/amd64", locked_image_id: "sha256:" + "a".repeat(64),
    syft_docker_descriptor_sha256: "sha256:" + "b".repeat(64),
    expected_decoded_manifest_values: {cyclonedx: "a".repeat(64), spdx: "sha256:" + "b".repeat(64)}};
  const artifacts = [{id: "cdx-libc", name: "libc6", version: "2.39-0ubuntu8.9", type: "deb", cpes: [],
    purl: "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.9?arch=amd64&distro=ubuntu-24.04&upstream=glibc",
    metadata: {architecture: "", source: "glibc", sourceVersion: "2.39-0ubuntu8.9", files: ["representation-only"]}},
  {id: "cdx-cares", name: "c-ares", version: "1.34.8", type: "UnknownPackage",
    purl: "pkg:generic/c-ares@1.34.8", cpes: [{cpe, source: "declared"}]}];
  const decoded = (format) => ({descriptor: {name: "syft", version: "1.44.0"},
    distro: {id: "ubuntu", versionID: "24.04"},
    source: {type: "image", metadata: {manifestDigest: binding.expected_decoded_manifest_values[format]}}, artifacts: clone(artifacts)});
  const cdx = decoded("cyclonedx"), spdx = decoded("spdx");
  // Actual retained Syft 1.44.0 SPDX conversion omits producer identity.
  spdx.descriptor = {name: "", version: ""};
  spdx.artifacts[0].id = "spdx-libc";
  spdx.artifacts[1].id = "spdx-cares";
  spdx.artifacts[0].metadata.architecture = "amd64";
  spdx.artifacts[0].metadata.files = [];
  spdx.artifacts[1].cpes[0].source = "decoder-decoration";
  const scan = (format, id) => ({source: {type: "image", target: {manifestDigest: binding.expected_decoded_manifest_values[format]}},
    distro: {name: "ubuntu", version: "24.04"}, ignoredMatches: [], matches: [
      {vulnerability: {id: "CVE-synthetic", namespace: "ubuntu:distro:ubuntu:24.04", severity: "Medium",
        dataSource: "https://example.invalid/advisory", fix: {state: "fixed", versions: ["2.40", "2.41"]}},
      artifact: {id, name: artifacts[0].name, version: artifacts[0].version, type: "deb", purl: artifacts[0].purl,
        cpes: [], upstreams: [{name: "glibc", version: "2.39-0ubuntu8.9"}], locations: [{path: `/different/${format}`}],
        language: "", licenses: []}, relatedVulnerabilities: [{id: "CVE-related", namespace: "nvd:cpe", severity: "High"}],
      matchDetails: [{matcher: "dpkg-matcher", type: "exact-direct-match", searchedBy: {package: {name: "libc6", version: "2.39-0ubuntu8.9"}},
        found: {vulnerabilityID: "CVE-synthetic", versionConstraint: "< 2.40 (deb)"}}]}],
    descriptor: {name: "grype", version: "0.116.1", timestamp: "2026-09-15T11:00:00Z",
      db: {status: {valid: true, schemaVersion: "v6.1.9", built: "2026-09-15T06:00:00Z", path: "/cache/6/vulnerability.db",
        from: "https://grype.anchore.io/databases/v6/database.tar.zst?checksum=sha256%3A" + "c".repeat(64)},
        providers: {ubuntu: {captured: "2026-09-15T04:00:00Z", input: "xxh64:fixture"}}},
      configuration: {file: `/out/${format}.json`, output: ["json"], distro: "", platform: "", pretty: false,
        "only-fixed": false, "only-notfixed": false, "ignore-wontfix": "", exclude: [], "vex-documents": [], "vex-add": [], ignore: [],
        db: {"auto-update": false, "validate-by-hash-on-start": true, "validate-age": true, "max-allowed-built-age": 172800000000000},
        "add-cpes-if-none": false, externalSources: {enable: false},
        match: {dpkg: {"using-cpes": false, "missing-epoch-strategy": "zero", "use-cpes-for-eol": false}, stock: {"using-cpes": true}},
        search: {scope: "squashed", "indexed-archives": true, "unindexed-archives": false},
        "fix-channel": {"ubuntu-esm": {apply: "auto", versions: ""}}, "by-cve": false,
        "match-upstream-kernel-headers": false, exp: {}}}});
  return {binding, cdx, spdx, cdxScan: scan("cyclonedx", "grype-cdx-libc"), spdxScan: scan("spdx", "grype-spdx-libc")};
}
const verify = (f) => verifyDecoded(f.cdx, f.spdx, f.binding);
const compare = (f, time = now) => compareScans(f.cdxScan, f.spdxScan, f.cdx, f.spdx, f.binding, time);
function bothScans(f, change) { for (const scan of [f.cdxScan, f.spdxScan]) change(scan); }

test("exact image/index CDX and synthetic SPDX identities pass despite representation differences", () => {
  const f = fixture(), before = clone(f), receipt = verify(f), result = compare(f);
  assert.equal(receipt.package_count, 2);
  assert.equal(receipt.scanner_parity_qualified, false);
  assert.deepEqual(receipt.decoder_descriptors.spdx, {name: "", version: ""});
  assert.match(receipt.decoder_identity_basis, /external runner pinned Syft command receipts required/);
  assert.equal(result.scanner_parity_qualified, true);
  assert.equal(result.findings.length, 1);
  assert.equal(result.counts.Medium, 1);
  assert.equal(result.counts.High, 0);
  assert.equal(result.findings[0].relatedVulnerabilities[0].severity, "High");
  assert.equal(result.findings[0].artifact.id, undefined);
  assert.equal(result.findings[0].artifact.locations, undefined);
  assert.deepEqual(result.findings[0].matchDetails, f.cdxScan.matches[0].matchDetails);
  assert.deepEqual(f, before, "comparisons must not mutate caller inputs");
  for (const flags of [receipt, result, result.inventory]) {
    for (const name of ["coverage_qualified", "native_installation_verified", "native_scan_qualified",
      "formal_rc_accepted", "publisher_authenticity_verified", "database_integrity_verified"]) assert.equal(flags[name], false);
  }
});

test("order-only changes pass without collapsing finding multiplicity", () => {
  const f = fixture();
  bothScans(f, (s) => { const match = clone(s.matches[0]); match.vulnerability.id = "CVE-second"; s.matches.push(match); });
  f.spdx.artifacts.reverse();
  f.spdxScan.matches.reverse();
  f.spdxScan.matches[0].vulnerability.fix.versions.reverse();
  f.spdxScan.descriptor.timestamp = "2026-09-15T11:05:00Z";
  assert.equal(compare(f).findings.length, 2);
});

test("multiple CPEs are order-independent, CPE decoration is not identity", () => {
  const f = fixture(), second = cpe.replace("c-ares_project", "alternate");
  f.cdx.artifacts[1].cpes.push({cpe: second});
  f.spdx.artifacts[1].cpes.unshift({cpe: second, source: "different"});
  assert.equal(verify(f).packages.find((p) => p.name === "c-ares").cpes.length, 2);
});

test("SPDX also accepts the exact pinned producer pair without rewriting either representation", () => {
  const f = fixture(); f.spdx.descriptor = {name: "syft", version: "1.44.0"};
  const before = clone(f);
  assert.deepEqual(verify(f).decoder_descriptors.spdx, f.spdx.descriptor);
  assert.equal(compare(f).status, "passed");
  assert.deepEqual(f, before);
});

for (const [name, descriptor] of Object.entries({
  missing: undefined, null: null, "missing both fields": {}, "missing name": {version: ""},
  "missing version": {name: ""}, "name only": {name: "syft", version: ""},
  "version only": {name: "", version: "1.44.0"}, "wrong name": {name: "grype", version: "1.44.0"},
  "wrong version": {name: "syft", version: "1.45.0"}, "null fields": {name: null, version: null},
  whitespace: {name: " ", version: " "},
})) {
  test(`SPDX rejects contradictory/incomplete descriptor: ${name}`, () => {
    const f = fixture(); f.spdx.descriptor = descriptor;
    assert.throws(() => verify(f), /producer descriptor/);
    assert.throws(() => compare(f), /producer descriptor/);
  });
}

test("empty SPDX producer metadata exception never applies to CDX", () => {
  const f = fixture(); f.cdx.descriptor = {name: "", version: ""};
  assert.throws(() => verify(f), /producer descriptor/);
  assert.throws(() => compare(f), /producer descriptor/);
});

test("zero findings still require nonempty verified inventories and never qualify coverage", () => {
  const f = fixture(); bothScans(f, (s) => { s.matches = []; });
  assert.equal(compare(f).gate.passed, true);
  assert.equal(compare(f).coverage_qualified, false);
  f.spdx.artifacts = [];
  assert.throws(() => compare(f), /nonempty/);
});

for (const severity of ["Unknown", "Negligible", "Low", "Medium", "High", "Critical"]) {
  test(`matching ${severity} findings preserve the shared High gate`, () => {
    const f = fixture(); bothScans(f, (s) => { s.matches[0].vulnerability.severity = severity; });
    const result = compare(f);
    assert.equal(result.counts[severity], 1);
    assert.equal(result.gate.passed, !["High", "Critical"].includes(severity));
    assert.equal(result.scanner_parity_qualified, true, "parity is independent of vulnerability clearance");
  });
}

const decoderMutations = {
  "unqualified binding": (f) => { f.binding.image_binding_qualified = false; },
  "wrong binding schema": (f) => { f.binding.schema_version = 2; },
  "inconsistent CDX expectation": (f) => { f.binding.expected_decoded_manifest_values.cyclonedx = "d".repeat(64); },
  "inconsistent SPDX expectation": (f) => { f.binding.expected_decoded_manifest_values.spdx = f.binding.locked_image_id; },
  "synthetic descriptor called registry digest": (f) => { f.binding.syft_descriptor_is_registry_manifest = true; },
  "movable image tag": (f) => { f.binding.locked_image_id = "gateway:latest"; },
  "wrong platform": (f) => { f.binding.platform = "linux/arm64"; },
  "unknown decoder": (f) => { f.spdx.descriptor.version = "1.45.0"; },
  "missing decoder identity": (f) => { delete f.cdx.descriptor; },
  "directory source": (f) => { f.spdx.source.type = "directory"; },
  "CDX adds digest prefix": (f) => { f.cdx.source.metadata.manifestDigest = f.binding.locked_image_id; },
  "SPDX loses digest prefix": (f) => { f.spdx.source.metadata.manifestDigest = "b".repeat(64); },
  "SPDX substitutes locked image": (f) => { f.spdx.source.metadata.manifestDigest = f.binding.locked_image_id; },
  "swapped sources": (f) => { [f.cdx.source, f.spdx.source] = [f.spdx.source, f.cdx.source]; },
  "wrong decoded OS": (f) => { f.cdx.source.metadata.os = "windows"; },
  "wrong decoded architecture": (f) => { f.spdx.source.metadata.architecture = "arm64"; },
  "versionless Ubuntu": (f) => { delete f.spdx.distro.versionID; },
  "wrong Ubuntu": (f) => { f.cdx.distro.versionID = "22.04"; },
  "empty inventory": (f) => { f.cdx.artifacts = []; },
  "missing inventory": (f) => { delete f.spdx.artifacts; },
  "missing package": (f) => { f.spdx.artifacts.pop(); },
  "duplicate internal ID": (f) => { f.spdx.artifacts[1].id = f.spdx.artifacts[0].id; },
  "duplicate package new ID": (f) => { f.cdx.artifacts.push({...clone(f.cdx.artifacts[0]), id: "other"}); },
  "duplicate package changed CPE": (f) => { f.spdx.artifacts.push({...clone(f.spdx.artifacts[0]), id: "other", cpes: [{cpe}]}); },
  "package version drift": (f) => { f.spdx.artifacts[0].version = "2.40"; },
  "package type drift": (f) => { f.spdx.artifacts[0].type = "UnknownPackage"; },
  "empty PURL": (f) => { f.cdx.artifacts[0].purl = ""; },
  "wrong PURL name": (f) => { f.cdx.artifacts[0].purl = f.cdx.artifacts[0].purl.replace("libc6@", "wrong@"); },
  "missing arch despite metadata": (f) => { f.spdx.artifacts[0].purl = f.spdx.artifacts[0].purl.replace("arch=amd64&", ""); },
  "PURL contradicts metadata": (f) => { f.spdx.artifacts[0].metadata.architecture = "arm64"; },
  "duplicate qualifier": (f) => { f.cdx.artifacts[0].purl += "&arch=amd64"; },
  "encoded duplicate qualifier": (f) => { f.cdx.artifacts[0].purl += "&%61rch=amd64"; },
  "malformed PURL escape": (f) => { f.cdx.artifacts[0].purl += "&extra=%GG"; },
  "versionless PURL distro": (f) => { f.cdx.artifacts[0].purl = f.cdx.artifacts[0].purl.replace("ubuntu-24.04", "ubuntu"); },
  "CPE lost": (f) => { f.spdx.artifacts[1].cpes = []; },
  "CPE invented": (f) => { f.spdx.artifacts[0].cpes = [{cpe}]; },
  "duplicate CPE": (f) => { f.spdx.artifacts[1].cpes.push({cpe}); },
  "missing CPE array": (f) => { delete f.cdx.artifacts[0].cpes; },
  "invalid CPE": (f) => { f.cdx.artifacts[1].cpes[0].cpe = "not-a-cpe"; },
  "upstream source drift": (f) => { f.spdx.artifacts[0].metadata.source = "other"; },
  "upstream version drift": (f) => { f.spdx.artifacts[0].metadata.sourceVersion = "2.38"; },
  "lost upstream version": (f) => { delete f.spdx.artifacts[0].metadata.sourceVersion; },
  "source version without source": (f) => { delete f.spdx.artifacts[0].metadata.source; },
};
for (const [name, mutate] of Object.entries(decoderMutations)) {
  test(`decoder rejects ${name}`, () => {
    const f = fixture(); mutate(f);
    assert.throws(() => verify(f));
    assert.throws(() => compare(f));
  });
}

const scanMutations = {
  "wrong scan source": (s) => { s.source.type = "sbom-file"; },
  "CDX scan prefix substitution": (s) => { s.source.target.manifestDigest = "sha256:" + "a".repeat(64); },
  "wrong scanner": (s) => { s.descriptor.version = "0.117.0"; },
  "missing distro": (s) => { delete s.distro; },
  "invalid database": (s) => { s.descriptor.db.status.valid = false; },
  "stale database": (s) => { s.descriptor.db.status.built = "2026-09-01T00:00:00Z"; },
  "future scan": (s) => { s.descriptor.timestamp = "2026-09-16T00:00:00Z"; },
  "different DB schema": (s) => { s.descriptor.db.status.schemaVersion = "v6.1.10"; },
  "different fresh DB build": (s) => { s.descriptor.db.status.built = "2026-09-15T05:00:00Z"; },
  "different official DB checksum": (s) => { s.descriptor.db.status.from = s.descriptor.db.status.from.replace("c".repeat(64), "d".repeat(64)); },
  "different physical DB path": (s) => { s.descriptor.db.status.path = "/other/6/vulnerability.db"; },
  "provider drift": (s) => { s.descriptor.db.providers.ubuntu.input = "xxh64:other"; },
  "DB auto update": (s) => { s.descriptor.configuration.db["auto-update"] = true; },
  "missing DB auto update": (s) => { delete s.descriptor.configuration.db["auto-update"]; },
  "disabled DB hash validation": (s) => { s.descriptor.configuration.db["validate-by-hash-on-start"] = false; },
  "relaxed DB age": (s) => { s.descriptor.configuration.db["max-allowed-built-age"] *= 2; },
  "matcher drift": (s) => { s.descriptor.configuration.match.stock["using-cpes"] = false; },
  "dpkg CPE matching enabled": (s) => { s.descriptor.configuration.match.dpkg["using-cpes"] = true; },
  "dpkg EOL fallback enabled": (s) => { s.descriptor.configuration.match.dpkg["use-cpes-for-eol"] = true; },
  "missing matcher policy": (s) => { delete s.descriptor.configuration.match; },
  "epoch strategy drift": (s) => { s.descriptor.configuration.match.dpkg["missing-epoch-strategy"] = "auto"; },
  "archive search drift": (s) => { s.descriptor.configuration.search["indexed-archives"] = false; },
  "fix channel drift": (s) => { s.descriptor.configuration["fix-channel"]["ubuntu-esm"].apply = "never"; },
  "unknown policy drift": (s) => { s.descriptor.configuration["future-policy"] = true; },
  "external lookup": (s) => { s.descriptor.configuration.externalSources.enable = true; },
  "invented CPE generation": (s) => { s.descriptor.configuration["add-cpes-if-none"] = true; },
  "distro override": (s) => { s.descriptor.configuration.distro = "ubuntu:24.04"; },
  "experiment enabled": (s) => { s.descriptor.configuration.exp.future = true; },
  "only fixed filter": (s) => { s.descriptor.configuration["only-fixed"] = true; },
  "waiver": (s) => { s.descriptor.configuration.ignore = [{vulnerability: "CVE-synthetic"}]; },
  "VEX": (s) => { s.descriptor.configuration["vex-documents"] = ["vex.json"]; },
  "suppressed finding": (s) => { s.ignoredMatches.push(clone(s.matches[0])); },
  "missing matches": (s) => { delete s.matches; },
  "lost finding": (s) => { s.matches = []; },
  "different CVE same counts": (s) => { s.matches[0].vulnerability.id = "CVE-other"; },
  "different namespace same CVE": (s) => { s.matches[0].vulnerability.namespace = "nvd:cpe"; },
  "different severity": (s) => { s.matches[0].vulnerability.severity = "High"; },
  "different fix state": (s) => { s.matches[0].vulnerability.fix.state = "not-fixed"; },
  "different fix version": (s) => { s.matches[0].vulnerability.fix.versions = ["2.42"]; },
  "changed advisory data": (s) => { s.matches[0].vulnerability.dataSource = "https://example.invalid/other"; },
  "changed related rating": (s) => { s.matches[0].relatedVulnerabilities[0].severity = "Low"; },
  "missing matcher evidence": (s) => { s.matches[0].matchDetails = []; },
  "changed matcher": (s) => { s.matches[0].matchDetails[0].matcher = "stock-matcher"; },
  "changed searched package": (s) => { s.matches[0].matchDetails[0].searchedBy.package.version = "2.38"; },
  "changed found constraint": (s) => { s.matches[0].matchDetails[0].found.versionConstraint = "< 2.39 (deb)"; },
  "nested ID must not be stripped": (s) => { s.matches[0].matchDetails[0].found.id = "important-evidence"; },
  "nested location must not be stripped": (s) => { s.matches[0].matchDetails[0].searchedBy.location = "important-evidence"; },
  "artifact absent from inventory": (s) => { s.matches[0].artifact.name = "unknown"; },
  "matched PURL drift": (s) => { s.matches[0].artifact.purl += "&extra=other"; },
  "matched CPE drift": (s) => { s.matches[0].artifact.cpes = [cpe]; },
  "matched upstream version drift": (s) => { s.matches[0].artifact.upstreams[0].version = "2.38"; },
  "matched upstream missing": (s) => { s.matches[0].artifact.upstreams = []; },
  "duplicate finding": (s) => { s.matches.push(clone(s.matches[0])); },
  "duplicate semantic finding with new ID": (s) => { const m = clone(s.matches[0]); m.artifact.id = "different-id"; s.matches.push(m); },
  "unexpected non-JSON evidence": (s) => { s.matches[0].matchDetails[0].found.bad = NaN; },
};
for (const [name, mutate] of Object.entries(scanMutations)) {
  test(`scan rejects ${name}`, () => {
    const f = fixture(); mutate(f.cdxScan);
    assert.throws(() => compare(f));
  });
}

for (const name of ["DB auto update", "missing DB auto update", "only fixed filter", "waiver", "VEX",
  "suppressed finding", "missing matcher policy", "external lookup", "invented CPE generation", "distro override",
  "experiment enabled", "matched upstream version drift", "duplicate semantic finding with new ID",
  "matcher drift", "dpkg CPE matching enabled", "dpkg EOL fallback enabled", "epoch strategy drift"]) {
  test(`matching invalid inputs do not pass: ${name}`, () => {
    const f = fixture(); bothScans(f, scanMutations[name]);
    assert.throws(() => compare(f));
  });
}

test("both scans disabling stock CPE matching cannot manufacture a zero-match pass", () => {
  const f = fixture();
  bothScans(f, (s) => { s.matches = []; s.descriptor.configuration.match.stock["using-cpes"] = false; });
  assert.throws(() => compare(f), /pinned stock\/dpkg/);
});

test("equal reports cannot contain an invented package absent from both inventories", () => {
  const f = fixture();
  bothScans(f, (s) => { s.matches[0].artifact.name = "other"; s.matches[0].artifact.purl = s.matches[0].artifact.purl.replace("libc6@", "other@"); });
  assert.throws(() => compare(f), /absent from decoded/);
});

test("actual c-ares CPE findings retain CPE evidence", () => {
  const f = fixture();
  bothScans(f, (s) => {
    s.matches[0].artifact = {id: "scanner-cares", name: "c-ares", version: "1.34.8", type: "UnknownPackage",
      purl: "pkg:generic/c-ares@1.34.8", cpes: [cpe], upstreams: []};
    s.matches[0].matchDetails = [{matcher: "stock-matcher", type: "cpe-match", searchedBy: {cpes: [cpe]},
      found: {vulnerabilityID: "CVE-synthetic", cpes: [cpe]}}];
  });
  assert.deepEqual(compare(f).findings[0].artifact.cpes, [cpe]);
  f.spdxScan.matches[0].matchDetails[0].searchedBy.cpes = [];
  assert.throws(() => compare(f), /multisets differ/);
});

test("fresh-at-scan reports become invalid when database is stale now", () => {
  assert.throws(() => compare(fixture(), now + 48 * 3600000), /stale/);
  assert.throws(() => compare(fixture(), NaN));
});

test("ARM64 is explicit, PURL-bound, and not hardcoded to AMD64", () => {
  const f = fixture(); f.binding.platform = "linux/arm64";
  for (const d of [f.cdx, f.spdx]) {
    d.artifacts[0].purl = d.artifacts[0].purl.replace("amd64", "arm64");
    d.artifacts[0].metadata.architecture = "arm64";
  }
  bothScans(f, (s) => { s.matches[0].artifact.purl = s.matches[0].artifact.purl.replace("amd64", "arm64"); });
  assert.equal(compare(f).inventory.platform, "linux/arm64");
});

test("prototype-looking JSON keys stay evidence, not prototype assignments", () => {
  const f = fixture();
  bothScans(f, (s) => { s.matches[0].matchDetails[0].found = JSON.parse('{"__proto__":{"important":true}}'); });
  const result = compare(f);
  assert.equal(Object.hasOwn(result.findings[0].matchDetails[0].found, "__proto__"), true);
  assert.equal({}.important, undefined);
  f.spdxScan.matches[0].matchDetails[0].found = {};
  assert.throws(() => compare(f), /multisets differ/);
});

function cliFixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "bonvoyage-parity-cli-"));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const f = fixture();
  bothScans(f, (s) => {
    s.descriptor.timestamp = new Date().toISOString();
    s.descriptor.db.status.built = new Date(Date.now() - 3600000).toISOString();
  });
  // Avoid millisecond drift between the two synthetic database statuses.
  f.spdxScan.descriptor.db = clone(f.cdxScan.descriptor.db);
  const paths = ["binding", "cdx", "spdx", "cdxScan", "spdxScan"].map((name) => {
    const filename = path.join(directory, name + ".json");
    fs.writeFileSync(filename, JSON.stringify(f[name]), {mode: 0o600});
    return filename;
  });
  const cli = fileURLToPath(new URL("./verify-runtime-scan-parity.mjs", import.meta.url));
  const run = (args = paths) => spawnSync(process.execPath, [cli, ...args], {encoding: "utf8", timeout: 10000});
  return {f, paths, run};
}

test("CLI three/five argument stdout receipts and High exit code match runner contract", (t) => {
  const {f, paths, run} = cliFixture(t);
  for (const args of [paths.slice(0, 3), paths]) {
    const result = run(args);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, "");
    assert.equal(JSON.parse(result.stdout).status, "passed");
  }
  bothScans(f, (s) => { s.matches[0].vulnerability.severity = "High"; });
  fs.writeFileSync(paths[3], JSON.stringify(f.cdxScan));
  fs.writeFileSync(paths[4], JSON.stringify(f.spdxScan));
  const result = run();
  assert.equal(result.status, 1, result.stderr);
  const receipt = JSON.parse(result.stdout);
  assert.equal(receipt.status, "passed");
  assert.equal(receipt.gate.passed, false);
  assert.equal(receipt.coverage_qualified, false);
});

test("CLI invalid/malformed/duplicate-key inputs emit no passing stdout", (t) => {
  const {paths, run} = cliFixture(t);
  const original = fs.readFileSync(paths[0], "utf8");
  const valid = JSON.parse(original);
  const cases = ["{", "{}", "null", "[]", "", original.replace('"schema_version":1', '"schema_version":2,"schema_version":1'),
    original.replace('"schema_version":1', '"schema_version":2,"schema_\\u0076ersion":1'),
    JSON.stringify({...valid, extra: [{x: 1}]}).replace('"x":1', '"x":0,"x":1')];
  for (const input of cases) {
    fs.writeFileSync(paths[0], input);
    const result = run();
    assert.equal(result.status, 2, input);
    assert.equal(result.stdout, "");
  }
  fs.writeFileSync(paths[0], original);
  for (const args of [[], paths.slice(0, 2), paths.slice(0, 4), [...paths, "extra"]]) {
    const result = run(args);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, "");
  }
});

test("CLI refuses links, directories, invalid UTF-8 and oversized input", (t) => {
  const {paths, run} = cliFixture(t);
  const alias = paths[0] + ".alias";
  fs.symlinkSync(paths[0], alias);
  assert.equal(run([alias, ...paths.slice(1)]).status, 2);
  fs.unlinkSync(alias);
  fs.linkSync(paths[0], alias);
  assert.equal(run().status, 2);
  fs.unlinkSync(alias);
  assert.equal(run([path.dirname(paths[0]), ...paths.slice(1)]).status, 2);
  fs.writeFileSync(paths[0], Buffer.from([0xff]));
  assert.equal(run().status, 2);
  fs.truncateSync(paths[0], 64 * 1024 * 1024 + 1);
  const oversized = run();
  assert.equal(oversized.status, 2);
  assert.equal(oversized.stdout, "");
});

test("CLI nested distinct keys and escaped delimiters are valid JSON", (t) => {
  const {f, paths, run} = cliFixture(t);
  f.binding.extra = {one: {key: "value:[]{}\\\""}, two: {key: "other"}, three: ["name", {key: 3}]};
  fs.writeFileSync(paths[0], JSON.stringify(f.binding));
  const result = run(paths.slice(0, 3));
  assert.equal(result.status, 0, result.stderr);
});
