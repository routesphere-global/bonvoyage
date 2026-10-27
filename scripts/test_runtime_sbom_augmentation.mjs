#!/usr/bin/env node
// Synthetic SBOM/declaration tests; no scanner, Docker image, or VM is exercised.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { readDependencyRecords } from "./augment-runtime-sbom.mjs";

const scripts = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(scripts);
const cpe = "cpe:2.3:a:c-ares_project:c-ares:1.34.8:*:*:*:*:*:*:*";
const archiveSha = "c222b6d681096f9444d2c4863d2c1174019e27cacca0a4a5c114d36dd7d7bf78";

test("scanner writers retain caller ownership without restoring capabilities", () => {
  const source = fs.readFileSync(path.join(scripts, "qualify-runtime-dependencies.sh"), "utf8");
  const runs = source.split("docker run --rm").slice(1);
  assert.equal(runs.length, 2);
  for (const run of runs) {
    assert.ok(run.includes('--user "$scanner_uid:$scanner_gid"'));
    assert.ok(run.includes('--cap-drop ALL'));
    assert.ok(run.includes('--security-opt no-new-privileges'));
    assert.equal(run.split('mode=0700,uid=$scanner_uid,gid=$scanner_gid').length, 3,
      'both temporary storage and cache must be caller-owned');
    assert.ok(!run.includes('--cap-add'));
  }
  assert.ok(runs[0].includes('--group-add "$docker_socket_gid"'));
  assert.ok(runs[1].includes('--group-add "$docker_socket_gid"'));
  assert.ok(runs[1].includes('SYFT_PACKAGE_EXCLUDE_BINARY_OVERLAP_BY_OWNERSHIP=false'));
  assert.ok(source.includes('python3 -B scripts/scan-runtime-sbom-pair.py'));
  assert.ok(source.includes('dual-format/evidence-checksums.json'));
  assert.ok(source.includes('exit "$scan_status"'));
  const syntax = spawnSync("sh", ["-n", path.join(scripts, "qualify-runtime-dependencies.sh")]);
  assert.equal(syntax.status, 0, syntax.stderr.toString());
});

test("runtime qualification binds clean Git identity into the immutable image", () => {
  const build = fs.readFileSync(path.join(scripts, "build-dataplane-container.sh"), "utf8");
  const collector = fs.readFileSync(
    path.join(scripts, "qualify-runtime-dependencies.sh"), "utf8");
  assert.ok(build.includes('--label "org.opencontainers.image.revision=$source_commit"'));
  assert.ok(build.includes('--label "io.routesphere.bonvoyage.source-dirty=$source_dirty"'));
  assert.ok(collector.includes('[ "$runtime_source_revision" != "$source_commit" ]'));
  assert.ok(collector.includes('[ "$runtime_source_dirty" != false ]'));
  assert.ok(collector.includes("scripts/bind-runtime-glibc-reachability.py"));
});

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bonvoyage-sbom-fixture-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const deps = path.join(dir, "dependencies");
  fs.mkdirSync(deps);
  for (const file of fs.readdirSync(path.join(root, "security/dependencies"))) {
    if (file.endsWith(".json")) {
      fs.copyFileSync(path.join(root, "security/dependencies", file), path.join(deps, file));
    }
  }
  const purl = "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.9?arch=amd64&distro=ubuntu-24.04&upstream=glibc";
  const cdx = { bomFormat: "CycloneDX", specVersion: "1.6", metadata: { component: { "bom-ref": "root" } },
    components: [{ "bom-ref": "libc", type: "library", name: "libc6", version: "2.39-0ubuntu8.9", purl },
      { "bom-ref": "os", type: "operating-system", name: "ubuntu", version: "24.04" }],
    dependencies: [{ ref: "root", dependsOn: ["libc", "os"] }] };
  const spdx = { spdxVersion: "SPDX-2.3", creationInfo: { creators: ["Tool: fixture"] },
    packages: [{ SPDXID: "SPDXRef-Root", name: "fixture", primaryPackagePurpose: "CONTAINER" },
      { SPDXID: "SPDXRef-Libc", name: "libc6", versionInfo: "2.39-0ubuntu8.9", externalRefs: [
        { referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: purl }] }],
    relationships: [] };
  const cdxPath = path.join(dir, "runtime.cdx.json");
  const spdxPath = path.join(dir, "runtime.spdx.json");
  fs.writeFileSync(cdxPath, JSON.stringify(cdx));
  fs.writeFileSync(spdxPath, JSON.stringify(spdx));
  return { dir, deps, cdx, spdx, cdxPath, spdxPath };
}

function mutate(f, file, change) {
  const target = path.join(f.deps, file);
  const record = JSON.parse(fs.readFileSync(target, "utf8"));
  change(record);
  fs.writeFileSync(target, JSON.stringify(record));
}

function augment(f, script, input, client) {
  const result = spawnSync(process.execPath, [path.join(scripts, script), input, f.deps, client],
    { encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(fs.readFileSync(input, "utf8"));
}

test("current source declares exactly eight pinned runtime components", () => {
  const records = readDependencyRecords(path.join(root, "security/dependencies"));
  assert.equal(records.length, 8);
  assert.equal(records.find(({ record }) => record.name === "c-ares").record.matching.cpe, cpe);
});

test("augmentation preserves unproven ELF-note packages and graph edges", (t) => {
  const f = fixture(t);
  const note = { type: "library", name: "systemd", version: "255.4", "bom-ref": "elf-note",
    purl: "pkg:deb/Ubuntu/systemd@255.4?distro=Ubuntu",
    properties: [{ name: "syft:package:foundBy", value: "elf-binary-package-cataloger" }] };
  f.cdx.components.push(note);
  f.cdx.dependencies[0].dependsOn.push("elf-note");
  f.cdx.dependencies.push({ ref: "elf-note", dependsOn: ["libc"] });
  fs.writeFileSync(f.cdxPath, JSON.stringify(f.cdx));
  const result = augment(f, "augment-runtime-sbom.mjs", f.cdxPath, "seastar-reference");
  assert.deepEqual(result.components.find((c) => c["bom-ref"] === "elf-note"), note);
  assert.ok(result.dependencies.find((d) => d.ref === "root").dependsOn.includes("elf-note"));
  assert.deepEqual(result.dependencies.find((d) => d.ref === "elf-note"), f.cdx.dependencies[1]);
});

test("collector preserves all three raw formats before augmentation", () => {
  const source = fs.readFileSync(path.join(scripts, "qualify-runtime-dependencies.sh"), "utf8");
  for (const name of ["runtime.raw.syft.json", "runtime.raw.cdx.json", "runtime.raw.spdx.json"]) {
    assert.ok(source.includes(`=/out/${name}`));
    assert.ok(source.includes("raw-checksums.sha256"));
    assert.equal(source.match(new RegExp(`augment-runtime-[^\\n]+\\n[^\\n]*${name.replaceAll(".", "\\.")}`)), null);
  }
  assert.ok(source.indexOf('cp "$evidence_dir/runtime.raw.cdx.json"') < source.indexOf("node scripts/augment-runtime-sbom.mjs"));
  assert.ok(source.includes("scripts/build-runtime-package-index.py"));
});

test("both formats retain c-ares CPE, source identity, and Ubuntu PURLs", (t) => {
  const f = fixture(t);
  const cdx = augment(f, "augment-runtime-sbom.mjs", f.cdxPath, "seastar-reference");
  const spdx = augment(f, "augment-runtime-spdx.mjs", f.spdxPath, "seastar-reference");
  assert.deepEqual(cdx.components.find((c) => c.name === "libc6"), f.cdx.components[0]);
  assert.deepEqual(spdx.packages.find((p) => p.name === "libc6"), f.spdx.packages[1]);
  const cares = cdx.components.find((c) => c.name === "c-ares");
  assert.equal(cares.cpe, cpe);
  assert.equal(cares.version, "1.34.8");
  assert.deepEqual(cares.hashes, [{ alg: "SHA-256", content: archiveSha }]);
  assert.ok(cares.properties.some((p) => p.name === "bonvoyage:hash:subject" && p.value === "official source release archive"));
  const packageRecord = spdx.packages.find((p) => p.name === "c-ares");
  assert.ok(packageRecord.externalRefs.some((r) => r.referenceCategory === "SECURITY" && r.referenceType === "cpe23Type" && r.referenceLocator === cpe));
  assert.deepEqual(packageRecord.checksums, [{ algorithm: "SHA256", checksumValue: archiveSha }]);
  assert.equal(packageRecord.filesAnalyzed, false);
  assert.ok(cdx.dependencies.find((d) => d.ref === "root").dependsOn.includes(cares["bom-ref"]));
  assert.ok(spdx.relationships.some((r) => r.relatedSpdxElement === packageRecord.SPDXID));
});

test("both Seastar patch layouts are retained", (t) => {
  const f = fixture(t);
  mutate(f, "seastar-25.05.0.json", (r) => r.patches = [{ path: "fixture.patch", sha256: "a".repeat(64) }]);
  const record = JSON.parse(fs.readFileSync(path.join(f.deps, "seastar-25.05.0.json"), "utf8"));
  const expected = [...record.patches, ...record.build.local_patches];
  assert.deepEqual(record.build.local_patches.map((p) => p.file), [
    "deploy/docker/bonvoyage/patches/seastar-dns-disable-query-cache.patch",
    "deploy/docker/bonvoyage/patches/seastar-http-client-lazy-trace.patch",
    "deploy/docker/bonvoyage/patches/seastar-tls-server-metadata.patch",
    "deploy/docker/bonvoyage/patches/seastar-tls-certificate-policy.patch",
    "deploy/docker/bonvoyage/patches/seastar-http-client-bounded-chunks.patch",
    "deploy/docker/bonvoyage/patches/seastar-http-client-pool-wait-observer.patch",
    "deploy/docker/bonvoyage/patches/seastar-ascii-case-insensitive-headers.patch",
    "deploy/docker/bonvoyage/patches/seastar-bounded-log-hook.patch",
  ]);
  const cdx = augment(f, "augment-runtime-sbom.mjs", f.cdxPath, "seastar-reference");
  const spdx = augment(f, "augment-runtime-spdx.mjs", f.spdxPath, "seastar-reference");
  const component = cdx.components.find((c) => c.name === "seastar");
  const packageRecord = spdx.packages.find((p) => p.name === "seastar");
  for (const p of expected) {
    assert.ok(component.properties.some((v) => v.name === "bonvoyage:patch:path" && v.value === (p.path ?? p.file)));
    assert.ok(component.properties.some((v) => v.name === "bonvoyage:patch:sha256" && v.value === p.sha256));
    assert.ok(packageRecord.sourceInfo.includes(`${p.path ?? p.file} sha256=${p.sha256}`));
  }
});

test("nghttp2 CPE is identical in both formats and pinned to the producer source", (t) => {
  const f = fixture(t);
  const cdx = augment(f, "augment-runtime-sbom.mjs", f.cdxPath, "seastar-reference");
  const spdx = augment(f, "augment-runtime-spdx.mjs", f.spdxPath, "seastar-reference");
  const cpe = "cpe:2.3:a:nghttp2:nghttp2:1.70.0:*:*:*:*:*:*:*";
  assert.equal(cdx.components.find((c) => c.name === "nghttp2").cpe, cpe);
  assert.ok(spdx.packages.find((p) => p.name === "nghttp2").externalRefs.some((r) =>
    r.referenceCategory === "SECURITY" && r.referenceType === "cpe23Type" && r.referenceLocator === cpe));
});

test("llhttp is required for both supported upstream client selectors", (t) => {
  const f = fixture(t);
  assert.equal(readDependencyRecords(f.deps).length, 8);
  assert.equal(readDependencyRecords(f.deps, "llhttp-candidate").length, 8);
  assert.equal(augment(f, "augment-runtime-sbom.mjs", f.cdxPath,
    "seastar-reference").components.filter((c) => c.name === "llhttp").length, 1);
  assert.equal(augment(f, "augment-runtime-spdx.mjs", f.spdxPath,
    "llhttp-candidate").packages.filter((c) => c.name === "llhttp").length, 1);
  fs.unlinkSync(path.join(f.deps, "llhttp-9.4.3.json"));
  assert.throws(() => readDependencyRecords(f.deps), /missing\/unknown/);
  assert.throws(() => readDependencyRecords(f.deps, "llhttp-candidate"), /missing\/unknown/);
});

for (const [name, change] of [
  ["nghttp2 commit drift", (f) => mutate(f, "nghttp2-1.70.0.json", (r) => r.source.commit = "a".repeat(40))],
  ["nghttp2 archive drift", (f) => mutate(f, "nghttp2-1.70.0.json", (r) => r.source.archive_sha256 = "a".repeat(64))],
  ["nghttp2 license drift", (f) => mutate(f, "nghttp2-1.70.0.json", (r) => r.license.spdx = "BSD-3-Clause")],
  ["nghttp2 linkage drift", (f) => mutate(f, "nghttp2-1.70.0.json", (r) => r.build.linkage = "generated C++ messages linked into the dataplane")],
  ["missing c-ares", (f) => fs.unlinkSync(path.join(f.deps, "c-ares-1.34.8.json"))],
  ["unknown record", (f) => fs.writeFileSync(path.join(f.deps, "unknown.json"), "{}")],
  ["duplicate name", (f) => mutate(f, "c-ares-1.34.8.json", (r) => r.name = "seastar")],
  ["version drift", (f) => mutate(f, "c-ares-1.34.8.json", (r) => r.version = "1.34.7")],
  ["commit drift", (f) => mutate(f, "c-ares-1.34.8.json", (r) => r.source.commit = "a".repeat(40))],
  ["archive drift", (f) => mutate(f, "c-ares-1.34.8.json", (r) => r.source.archive_sha256 = "a".repeat(64))],
  ["license drift", (f) => mutate(f, "c-ares-1.34.8.json", (r) => r.license.spdx = "BSD-3-Clause")],
  ["dynamic linkage", (f) => mutate(f, "c-ares-1.34.8.json", (r) => r.build.linkage = "dynamic")],
  ["missing CPE", (f) => mutate(f, "c-ares-1.34.8.json", (r) => delete r.matching)],
  ["invented CPE vendor", (f) => mutate(f, "c-ares-1.34.8.json", (r) => r.matching.cpe = cpe.replace("c-ares_project", "c-ares"))],
  ["wildcard CPE version", (f) => mutate(f, "c-ares-1.34.8.json", (r) => r.matching.cpe = cpe.replace("1.34.8", "*"))],
  ["unreviewed other CPE", (f) => mutate(f, "seastar-25.05.0.json", (r) => r.matching = { cpe })],
  ["missing local patch hash", (f) => mutate(f, "seastar-25.05.0.json", (r) => delete r.build.local_patches[0].sha256)],
  ["symlink record", (f) => { fs.unlinkSync(path.join(f.deps, "c-ares-1.34.8.json"));
    fs.symlinkSync(path.join(root, "security/dependencies/c-ares-1.34.8.json"), path.join(f.deps, "c-ares-1.34.8.json")); }],
]) {
  test(`reject ${name} before writing either SBOM`, (t) => {
    const f = fixture(t);
    change(f);
    assert.throws(() => readDependencyRecords(f.deps));
    for (const [script, target] of [["augment-runtime-sbom.mjs", f.cdxPath], ["augment-runtime-spdx.mjs", f.spdxPath]]) {
      const before = fs.readFileSync(target);
      const result = spawnSync(process.execPath, [path.join(scripts, script), target, f.deps, "seastar-reference"],
        { encoding: "utf8", timeout: 10000 });
      assert.notEqual(result.status, 0);
      assert.deepEqual(fs.readFileSync(target), before);
    }
  });
}

test("unknown image client is not treated as a reference client", (t) => {
  const f = fixture(t);
  assert.throws(() => readDependencyRecords(f.deps, "auto"), /supported/);
});

for (const unknown of [true, false]) {
  test(`reject ${unknown ? "unknown" : "duplicate"} preexisting static SBOM entries`, (t) => {
    const f = fixture(t);
    f.cdx.components.push({ type: "library", name: unknown ? "unknown" : "c-ares", "bom-ref": "different",
      version: "1.0", properties: [{ name: "bonvoyage:source:commit", value: "a".repeat(40) }] });
    f.spdx.packages.push({ name: unknown ? "unknown" : "c-ares", versionInfo: "1.0",
      SPDXID: unknown ? "SPDXRef-Package-BonVoyage-unknown" : "SPDXRef-Duplicate" });
    fs.writeFileSync(f.cdxPath, JSON.stringify(f.cdx));
    fs.writeFileSync(f.spdxPath, JSON.stringify(f.spdx));
    for (const [script, target] of [["augment-runtime-sbom.mjs", f.cdxPath], ["augment-runtime-spdx.mjs", f.spdxPath]]) {
      const before = fs.readFileSync(target);
      const result = spawnSync(process.execPath, [path.join(scripts, script), target, f.deps, "seastar-reference"],
        { encoding: "utf8", timeout: 10000 });
      assert.notEqual(result.status, 0);
      assert.deepEqual(fs.readFileSync(target), before);
    }
  });
}
