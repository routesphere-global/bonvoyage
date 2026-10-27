#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { summarize } from "./summarize-vulnerability-scan.mjs";

const record = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const text = (v) => typeof v === "string" && v.length > 0 && v.trim() === v;
const digest = (v) => typeof v === "string" && /^sha256:[a-f0-9]{64}$/.test(v);
function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function canonical(value, depth = 0) {
  requireValue(depth <= 64, "JSON nesting budget exceeded");
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return Array.from(value, (v) => canonical(v, depth + 1));
  requireValue(record(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value)), "JSON value required");
  return Object.fromEntries(Object.keys(value).sort().map((k) => [k, canonical(value[k], depth + 1)]));
}
const key = (value) => JSON.stringify(canonical(value));
const ordered = (values) => values.map((v) => [key(v), canonical(v)])
  .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, v]) => v);
function equal(a, b, message) {
  requireValue(key(a) === key(b), message);
}

function scopeFlags() {
  return {coverage_qualified: false, native_installation_verified: false, native_scan_qualified: false,
    formal_rc_accepted: false, publisher_authenticity_verified: false, database_integrity_verified: false};
}

function checkedBinding(binding) {
  // The runner must freshly call verify-runtime-image-binding.py and bind the
  // actual decoder/scan inputs to that result. JSON alone cannot prove freshness.
  requireValue(record(binding) && binding.schema_version === 1 && binding.status === "passed" &&
    binding.image_binding_qualified === true && binding.syft_descriptor_is_registry_manifest === false &&
    digest(binding.locked_image_id) && digest(binding.syft_docker_descriptor_sha256) &&
    ["linux/amd64", "linux/arm64"].includes(binding.platform), "fresh image-binding result required");
  const expected = binding.expected_decoded_manifest_values;
  requireValue(record(expected) && expected.cyclonedx === binding.locked_image_id.slice(7) &&
    expected.spdx === binding.syft_docker_descriptor_sha256, "inconsistent per-format binding expectations");
  return {expected, architecture: binding.platform.split("/")[1]};
}

function sourceIdentity(source, expected, architecture, decoded) {
  const metadata = decoded ? source?.metadata : source?.target;
  requireValue(source?.type === "image" && record(metadata) && metadata.manifestDigest === expected,
    "exact format-specific image source required");
  requireValue((metadata.architecture ?? "") === "" || metadata.architecture === architecture,
    "contradictory image architecture");
  requireValue((metadata.os ?? "") === "" || metadata.os === "linux", "contradictory image OS");
}

function cpes(value, decoded) {
  requireValue(Array.isArray(value), "explicit CPE array required");
  const values = value.map((v) => {
    const cpe = decoded && record(v) ? v.cpe : v;
    requireValue(text(cpe) && /^(?:cpe:2\.3:|cpe:\/)/.test(cpe), "CPE identity required");
    return cpe;
  });
  requireValue(new Set(values).size === values.length, "duplicate CPE identity");
  return values.sort();
}

function packageIdentity(artifact, architecture, decoded) {
  requireValue(record(artifact) && [artifact.name, artifact.version, artifact.type, artifact.purl].every(text),
    "complete package name/version/type/PURL required");
  requireValue(!/%(?![a-f0-9]{2})/i.test(artifact.purl), "malformed PURL escape");
  const purl = new URL(artifact.purl);
  requireValue(purl.protocol === "pkg:" && !purl.host && !purl.hash && !/\s/.test(artifact.purl), "package PURL required");
  const qualifiers = [...purl.searchParams];
  requireValue(qualifiers.every(([k, v]) => text(k) && text(v)) &&
    new Set(qualifiers.map(([k]) => k)).size === qualifiers.length, "unique nonempty PURL qualifiers required");
  const at = purl.pathname.lastIndexOf("@");
  const packagePath = purl.pathname.slice(0, at).split("/");
  requireValue(at > 0 && packagePath.length >= 2 &&
    decodeURIComponent(packagePath.at(-1)) === artifact.name &&
    decodeURIComponent(purl.pathname.slice(at + 1)) === artifact.version, "PURL name/version mismatch");
  const arch = purl.searchParams.get("arch");
  requireValue(arch === null || [architecture, "all"].includes(arch), "PURL architecture mismatch");
  if (artifact.type === "deb") {
    requireValue(packagePath.join("/").startsWith("deb/ubuntu/") && packagePath.length === 3 &&
      arch !== null && purl.searchParams.get("distro") === "ubuntu-24.04", "Ubuntu package PURL identity required");
  } else {
    requireValue(packagePath[0] !== "deb", "Debian PURL decoded as non-Debian package");
  }
  if (decoded) {
    const metadata = artifact.metadata ?? {};
    requireValue(record(metadata), "package metadata object required");
    const reportedArch = metadata.architecture ?? "";
    // CDX can leave this field empty. Never fill a missing PURL arch from it.
    requireValue(reportedArch === "" || (text(reportedArch) && reportedArch === arch),
      "package metadata contradicts authoritative PURL architecture");
  }
  return {name: artifact.name, version: artifact.version, type: artifact.type,
    purl: artifact.purl, cpes: cpes(artifact.cpes, decoded)};
}

function sourcePackage(artifact) {
  const metadata = artifact.metadata ?? {};
  const source = metadata.source ?? "", version = metadata.sourceVersion ?? "";
  requireValue(typeof source === "string" && typeof version === "string" &&
    (!source || text(source)) && (!version || text(version)) && (!version || source), "invalid upstream source identity");
  return {source, source_version: version};
}

function decodedInventory(decoded, expected, architecture, format) {
  // Pinned Syft converts SPDX with empty producer descriptor fields. The
  // executing decoder's identity comes from the runner's pinned command receipt,
  // not this producer metadata. Never fill in or repair the retained report.
  const descriptor = decoded?.descriptor;
  const pinned = record(descriptor) && descriptor.name === "syft" && descriptor.version === "1.44.0";
  const emptySpdx = format === "spdx" && record(descriptor) && descriptor.name === "" && descriptor.version === "";
  requireValue(record(decoded) && (pinned || emptySpdx), "unexpected format-specific Syft producer descriptor");
  sourceIdentity(decoded.source, expected, architecture, true);
  requireValue(decoded.distro?.id === "ubuntu" && decoded.distro.versionID === "24.04", "decoded Ubuntu 24.04 required");
  requireValue(Array.isArray(decoded.artifacts) && decoded.artifacts.length > 0, "nonempty decoded inventory required");
  const ids = new Set(), identities = new Set();
  return ordered(decoded.artifacts.map((artifact) => {
    const identity = packageIdentity(artifact, architecture, true);
    requireValue(text(artifact.id) && !ids.has(artifact.id), "unique decoded internal ID required");
    ids.add(artifact.id);
    // CPE/upstream drift cannot turn a duplicate package into another package.
    const id = key([identity.name, identity.version, identity.type, identity.purl]);
    requireValue(!identities.has(id), "duplicate decoded package identity");
    identities.add(id);
    return {...identity, ...sourcePackage(artifact)};
  }));
}

export function verifyDecoded(cdxDecoded, spdxDecoded, binding) {
  // Mandatory caller precondition: fresh image binding and retained successful
  // decoder command receipts for the pinned Syft image. This pure API cannot
  // authenticate tool execution or a caller-supplied JSON receipt by itself.
  const {expected, architecture} = checkedBinding(binding);
  const cdx = decodedInventory(cdxDecoded, expected.cyclonedx, architecture, "cyclonedx");
  const spdx = decodedInventory(spdxDecoded, expected.spdx, architecture, "spdx");
  equal(cdx, spdx, "decoded package/CPE/upstream inventories differ");
  return {schema_version: 1, status: "passed", scope: "bound image decoder inventory parity only",
    locked_image_id: binding.locked_image_id, platform: binding.platform,
    expected_decoded_manifest_values: canonical(expected), distro: {id: "ubuntu", versionID: "24.04"},
    decoder_descriptors: {cyclonedx: canonical(cdxDecoded.descriptor), spdx: canonical(spdxDecoded.descriptor)},
    decoder_identity_basis: "external runner pinned Syft command receipts required",
    package_count: cdx.length, packages: cdx, decoder_parity_verified: true,
    scanner_parity_qualified: false, ...scopeFlags()};
}

function policy(scan, architecture) {
  const config = scan.descriptor.configuration;
  requireValue(config.db["auto-update"] === false, "offline database auto-update=false required");
  requireValue(config.distro === "" && ["", `linux/${architecture}`].includes(config.platform),
    "distro/platform override rejected");
  requireValue(config["add-cpes-if-none"] === false && config.externalSources?.enable === false,
    "invented CPEs/external lookup rejected");
  requireValue(record(config.match) && record(config.match.dpkg) && record(config.match.stock) &&
    Object.values(config.match).every((v) => record(v) && typeof v["using-cpes"] === "boolean") &&
    config.match.stock["using-cpes"] === true && config.match.dpkg["using-cpes"] === false &&
    config.match.dpkg["missing-epoch-strategy"] === "zero" && config.match.dpkg["use-cpes-for-eol"] === false,
    "pinned stock/dpkg matching policy required");
  requireValue(record(config.search) && text(config.search.scope) &&
    typeof config.search["indexed-archives"] === "boolean" && typeof config.search["unindexed-archives"] === "boolean" &&
    record(config["fix-channel"]) && record(config.exp) && Object.keys(config.exp).length === 0 &&
    typeof config["by-cve"] === "boolean" && typeof config["match-upstream-kernel-headers"] === "boolean",
    "complete non-experimental matching policy required");
  // Compare every remaining field, including unknown future policy fields.
  // Only explicit presentation/output differences are excluded.
  const {file, output, pretty, "output-template-file": template, SortBy, name, ...relevant} = config;
  return canonical(relevant);
}

function normalizedFindings(scan, packages, architecture) {
  const inventory = new Map(packages.map(({source, source_version, ...identity}) =>
    [key(identity), {source, source_version}]));
  const seen = new Set();
  return ordered(scan.matches.map((match) => {
    const identity = packageIdentity(match.artifact, architecture, false);
    const owner = inventory.get(key(identity));
    requireValue(owner !== undefined, "matched artifact absent from decoded inventory");
    const upstreams = match.artifact.upstreams ?? [];
    requireValue(Array.isArray(upstreams) && upstreams.every((v) => record(v) && text(v.name) &&
      typeof v.version === "string" && (v.version === "" || text(v.version))), "complete matched upstream identity required");
    // Preserve an unknown source version as unknown; do not infer a version.
    equal(ordered(upstreams.map(({name, version}) => ({name, version}))),
      owner.source ? [{name: owner.source, version: owner.source_version}] : [], "matched upstream differs from decoded inventory");
    const duplicate = key([match.vulnerability.id, match.vulnerability.namespace, identity]);
    requireValue(!seen.has(duplicate), "duplicate semantic finding identity");
    seen.add(duplicate);
    const {id, locations, ...artifact} = match.artifact;
    const result = canonical({...match, artifact});
    result.artifact.cpes = identity.cpes;
    if (Object.hasOwn(artifact, "upstreams")) result.artifact.upstreams = ordered(upstreams);
    result.vulnerability.fix.versions = ordered(result.vulnerability.fix.versions);
    result.matchDetails = ordered(result.matchDetails);
    if (Object.hasOwn(result, "relatedVulnerabilities")) {
      requireValue(Array.isArray(result.relatedVulnerabilities), "related advisory array required");
      result.relatedVulnerabilities = ordered(result.relatedVulnerabilities);
    }
    return result;
  }));
}

export function compareScans(cdxScan, spdxScan, cdxDecoded, spdxDecoded, binding, now = Date.now()) {
  const inventory = verifyDecoded(cdxDecoded, spdxDecoded, binding);
  const {expected, architecture} = checkedBinding(binding);
  const validated = [cdxScan, spdxScan].map((scan, index) => {
    const manifest = index === 0 ? expected.cyclonedx : expected.spdx;
    sourceIdentity(scan?.source, manifest, architecture, false);
    // Preserve the shared severity/source/policy/freshness contract unchanged.
    return summarize(scan, "docker:sha256:" + manifest.replace(/^sha256:/, ""), now);
  });
  const config = policy(cdxScan, architecture);
  equal(config, policy(spdxScan, architecture), "scanner matching/database policies differ");
  equal(cdxScan.descriptor.db, spdxScan.descriptor.db, "database status/providers differ (including physical path)");
  const findings = normalizedFindings(cdxScan, inventory.packages, architecture);
  equal(findings, normalizedFindings(spdxScan, inventory.packages, architecture), "normalized finding multisets differ");
  equal(validated[0].counts, validated[1].counts, "finding counts differ");
  equal(validated[0].gate, validated[1].gate, "severity gates differ");
  return canonical({schema_version: 1, status: "passed", scope: "decoder and same-status database finding parity only",
    inventory, scanner: validated[0].scanner, database: cdxScan.descriptor.db, matching_configuration: config,
    scanned_at: {cyclonedx: validated[0].scanned_at, spdx: validated[1].scanned_at},
    findings, counts: validated[0].counts, blocking: ordered(validated[0].blocking), gate: validated[0].gate,
    scanner_parity_qualified: true, ...scopeFlags()});
}

function readInput(filename) {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  let data;
  try {
    const before = fs.fstatSync(fd);
    requireValue(before.isFile() && before.nlink === 1 && before.size > 0 && before.size <= 64 * 1024 * 1024,
      "bounded regular single-link JSON input required");
    const buffer = Buffer.alloc(before.size + 1);
    let count = 0;
    while (count < buffer.length) {
      const read = fs.readSync(fd, buffer, count, buffer.length - count, null);
      if (read === 0) break;
      count += read;
    }
    const after = fs.fstatSync(fd);
    requireValue(count === before.size && ["dev", "ino", "size", "mtimeMs", "ctimeMs"].every((k) => before[k] === after[k]),
      "JSON input changed while reading");
    data = new TextDecoder("utf-8", {fatal: true}).decode(buffer.subarray(0, count));
  } finally { fs.closeSync(fd); }
  const value = JSON.parse(data);
  // JSON.parse validates syntax but silently overwrites duplicate keys. Audit
  // its string/delimiter tokens separately, including escaped-key aliases.
  const objects = [];
  let lastString;
  for (const token of data.matchAll(/"(?:[^"\\]|\\.)*"|[{}\[\]:]/g)) {
    const [part] = token;
    if (part === "{") objects.push(new Set());
    else if (part === "[") objects.push(null);
    else if (part === "}" || part === "]") objects.pop();
    else if (part === ":") {
      const names = objects.at(-1);
      requireValue(names instanceof Set && !names.has(lastString), "duplicate JSON key rejected");
      names.add(lastString);
    } else lastString = JSON.parse(part);
  }
  return value;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    requireValue(args.length === 3 || args.length === 5,
      "usage: verify-runtime-scan-parity.mjs <binding.json> <cdx-decoded.json> <spdx-decoded.json> [<cdx-grype.json> <spdx-grype.json>]");
    const [binding, cdx, spdx, cdxScan, spdxScan] = args.map(readInput);
    const result = args.length === 3 ? verifyDecoded(cdx, spdx, binding) : compareScans(cdxScan, spdxScan, cdx, spdx, binding);
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.gate?.passed === false ? 1 : 0;
  } catch (error) {
    console.error(`invalid runtime scan parity: ${error.message}`);
    process.exitCode = 2;
  }
}
