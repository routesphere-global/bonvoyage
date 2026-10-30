#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {TextDecoder} from 'node:util';
import {fileURLToPath} from 'node:url';

import {summarize} from './summarize-vulnerability-scan.mjs';

const SCRIPT_ROOT = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_ROOT, '..');
const DEFAULT_CONTRACT = path.join(
  REPOSITORY_ROOT, 'packaging/release/oss-supply-chain-evidence-contract.json');
const DEFAULT_INTAKE_CONTRACT = path.join(
  REPOSITORY_ROOT, 'packaging/release/oss-candidate-intake-contract.json');
const CONTRACT_CLASSIFICATION =
  'routesphere-bonvoyage-oss-supply-chain-evidence-contract';
const INTAKE_CLASSIFICATION =
  'routesphere-bonvoyage-oss-candidate-intake-receipt';
const DATABASE_CLASSIFICATION =
  'routesphere-bonvoyage-oss-vulnerability-database-evidence';
const VALIDATION_CLASSIFICATION =
  'routesphere-bonvoyage-oss-sbom-validation-evidence';
const DECODED_CLASSIFICATION =
  'routesphere-bonvoyage-oss-sbom-decoded-inventory';
const REVIEW_CLASSIFICATION =
  'routesphere-bonvoyage-oss-vulnerability-review-evidence';
const HANDOFF_CLASSIFICATION =
  'routesphere-bonvoyage-oss-supply-chain-evidence-handoff';
const PUBLIC_REPOSITORY = 'https://github.com/routesphere-global/bonvoyage';
const PINNED_SYFT_IMAGE =
  'anchore/syft:v1.44.0@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6';
const PINNED_CYCLONEDX_VALIDATOR_IMAGE =
  'cyclonedx/cyclonedx-cli:0.33.1@sha256:9a37575fb51fcaed3a4c62dddba091c46ffc867712e46bdb6cdf219a7e90a061';
const PINNED_SPDX_SCHEMA_SHA256 =
  '239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b';
const PINNED_SPDX_VALIDATOR_LOCK_SHA256 =
  'e2e52a0b047055d4d860b379b1c0e35931659d94069398c6bf0b68cb21d6e194';
const PINNED_GRYPE_IMAGE =
  'anchore/grype:v0.116.1@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db';
const COMMIT = /^[a-f0-9]{40}$/u;
const TAG =
  /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/u;
const RUN_ID = /^[1-9][0-9]*$/u;
const DECODER = new TextDecoder('utf-8', {fatal: true});
const BOOTSTRAP_CONTROL_LIMIT = 64 * 1024 * 1024;
const FINDING_SEVERITIES = Object.freeze([
  'Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical',
]);
const ARTIFACT_EVIDENCE_FILES = Object.freeze([
  'cyclonedx.json',
  'decoded-cyclonedx.json',
  'decoded-spdx.json',
  'review.json',
  'scan-cyclonedx.json',
  'scan-spdx.json',
  'spdx.json',
  'validation.json',
]);
const POWERLESS_FIELDS = Object.freeze([
  'product_artifact_signature_allowed',
  'product_provenance_allowed',
  'release_admitted',
  'publishable',
  'github_release_created',
  'package_uploaded',
  'container_uploaded',
]);

function fail(message) {
  throw new Error(message);
}

function requireCondition(condition, message) {
  if (!condition) fail(message);
}

function requireObject(value, label) {
  requireCondition(value !== null && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  return value;
}

function requireArray(value, label) {
  requireCondition(Array.isArray(value), `${label} must be an array`);
  return value;
}

function requireString(value, label) {
  requireCondition(typeof value === 'string' && value.length > 0 &&
    value === value.trim() && !/[\u0000-\u001f\u007f]/u.test(value),
  `${label} must be a nonempty trimmed single-line string`);
  return value;
}

function requireInteger(value, label) {
  requireCondition(Number.isSafeInteger(value) && value >= 0,
    `${label} must be a nonnegative safe integer`);
  return value;
}

function requireSha256(value, label) {
  requireCondition(typeof value === 'string' && SHA256.test(value),
    `${label} must be a lowercase SHA-256 digest`);
  return value;
}

function requireSha256Digest(value, label) {
  requireCondition(typeof value === 'string' && SHA256_DIGEST.test(value),
    `${label} must be a lowercase sha256: digest`);
  return value;
}

function exactKeys(value, expected, label) {
  const actual = Object.keys(requireObject(value, label)).sort();
  const wanted = [...expected].sort();
  requireCondition(actual.length === wanted.length &&
    actual.every((item, index) => item === wanted[index]),
  `${label} fields must be exactly [${wanted.join(', ')}]`);
}

function canonicalTimestamp(value, label) {
  requireString(value, label);
  requireCondition(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
    new Date(value).toISOString() === value, `${label} must be canonical UTC`);
  return Date.parse(value);
}

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sha256Bytes(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function assertStableFile(before, after, bytes, label) {
  requireCondition(
    before.dev === after.dev && before.ino === after.ino &&
    before.size === after.size && before.mtimeMs === after.mtimeMs &&
    before.ctimeMs === after.ctimeMs && before.nlink === after.nlink &&
    bytes === after.size,
    `${label} changed while it was read`);
}

function snapshotIdentity(filePath, label, maximum) {
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && before.nlink === 1 && before.size > 0,
      `${label} must be one nonempty regular non-hard-linked file`);
    requireCondition(before.size <= maximum, `${label} exceeds its size limit`);
    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    while (true) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      hash.update(buffer.subarray(0, count));
      bytes += count;
    }
    assertStableFile(before, fs.fstatSync(descriptor), bytes, label);
    return {bytes, sha256: hash.digest('hex')};
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.startsWith(label)) throw error;
    fail(`${label} could not be read safely: ${message}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function snapshotFile(filePath, label, maximum) {
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && before.nlink === 1 && before.size > 0,
      `${label} must be one nonempty regular non-hard-linked file`);
    requireCondition(before.size <= maximum, `${label} exceeds its size limit`);
    const content = Buffer.allocUnsafe(before.size);
    let bytes = 0;
    while (bytes < content.length) {
      const count = fs.readSync(
        descriptor, content, bytes, content.length - bytes, null);
      if (count === 0) break;
      bytes += count;
    }
    assertStableFile(before, fs.fstatSync(descriptor), bytes, label);
    return {bytes, sha256: sha256Bytes(content), content};
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.startsWith(label)) throw error;
    fail(`${label} could not be read safely: ${message}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function auditDuplicateJsonKeys(text, label) {
  const objects = [];
  let lastString;
  for (const token of text.matchAll(/"(?:[^"\\]|\\.)*"|[{}\[\]:]/gu)) {
    const [part] = token;
    if (part === '{') objects.push(new Set());
    else if (part === '[') objects.push(null);
    else if (part === '}' || part === ']') objects.pop();
    else if (part === ':') {
      const names = objects.at(-1);
      requireCondition(names instanceof Set && !names.has(lastString),
        `${label} contains a duplicate JSON key`);
      names.add(lastString);
    } else {
      lastString = JSON.parse(part);
    }
  }
  requireCondition(objects.length === 0, `${label} has unbalanced JSON delimiters`);
}

function readJson(filePath, label, maximum, {canonical = false} = {}) {
  const record = snapshotFile(filePath, label, maximum);
  let text;
  let value;
  try {
    text = DECODER.decode(record.content);
    value = JSON.parse(text);
  } catch (error) {
    fail(`${label} is not valid UTF-8 JSON: ${error.message}`);
  }
  auditDuplicateJsonKeys(text, label);
  requireObject(value, label);
  if (canonical) {
    requireCondition(text === canonicalJson(value),
      `${label} must use canonical JSON encoding`);
  }
  return {...record, text, value};
}

function safeRelative(value, label) {
  requireString(value, label);
  requireCondition(!value.includes('\\') && !path.posix.isAbsolute(value) &&
    path.posix.normalize(value) === value && value !== '.' && !value.startsWith('./') &&
    value.split('/').every((part) => part.length > 0 && part !== '..'),
  `${label} must be a safe normalized relative path`);
  return value;
}

function assertDirectory(directory, label) {
  const stat = fs.lstatSync(directory);
  requireCondition(stat.isDirectory() && !stat.isSymbolicLink(),
    `${label} must be a real directory`);
}

function inventory(root, excluded, maximum) {
  const records = [];
  function walk(directory, prefix = '') {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      safeRelative(relative, `tree path ${relative}`);
      const absolute = path.join(directory, entry.name);
      const stat = fs.lstatSync(absolute);
      requireCondition(!stat.isSymbolicLink(), `tree path ${relative} must not be a link`);
      if (stat.isDirectory()) {
        walk(absolute, relative);
      } else {
        requireCondition(stat.isFile() && stat.nlink === 1,
          `tree path ${relative} must be one regular non-hard-linked file`);
        if (!excluded.has(relative)) {
          records.push({
            path: relative,
            ...snapshotIdentity(absolute, `tree path ${relative}`, maximum),
          });
        }
      }
    }
  }
  walk(root);
  return records.sort((left, right) => left.path.localeCompare(right.path));
}

function exactInventory(actual, expected, label) {
  requireArray(expected, label);
  requireCondition(JSON.stringify(actual) === JSON.stringify(expected),
    `${label} does not match the retained tree`);
}

function validatePowerless(authority, label) {
  exactKeys(authority, POWERLESS_FIELDS, label);
  for (const field of POWERLESS_FIELDS) {
    requireCondition(authority[field] === false, `${label}.${field} must remain false`);
  }
}

function validateSource(source, commit, tag, label) {
  exactKeys(source, ['repository', 'commit', 'tag', 'dirty'], label);
  requireCondition(source.repository === PUBLIC_REPOSITORY && source.commit === commit &&
    source.tag === tag && source.dirty === false,
  `${label} is not the exact clean public source`);
}

function validateHostedEvidenceArtifacts(value, prefix, label) {
  const records = requireArray(value, label);
  requireCondition(records.length === 2, `${label} must contain exactly two records`);
  const expectedNames = ['a', 'b'].map((suffix) => `${prefix}-build-${suffix}`);
  records.forEach((record, index) => {
    exactKeys(record, ['name', 'sha256'], `${label}[${index}]`);
    requireString(record.name, `${label}[${index}].name`);
    requireSha256(record.sha256, `${label}[${index}].sha256`);
  });
  requireCondition(JSON.stringify(records.map((record) => record.name)) ===
    JSON.stringify(expectedNames), `${label} names or order changed`);
}

function validateOciObject(value, fields, label) {
  exactKeys(value, fields, label);
  requireInteger(value.bytes, `${label}.bytes`);
  requireSha256Digest(value.digest, `${label}.digest`);
  if (fields.includes('diff_id')) {
    requireSha256Digest(value.diff_id, `${label}.diff_id`);
  }
}

function validateHostedArtifactMetadata(artifact, id) {
  requireCondition(typeof artifact.hosted_run_id === 'string' &&
    RUN_ID.test(artifact.hosted_run_id),
  `candidate intake ${id}.hosted_run_id must be a positive decimal string`);
  const expectedBuilders = ['a', 'b'].map(
    (suffix) => `github-${artifact.hosted_run_id}-1-${suffix}`);
  requireCondition(JSON.stringify(requireArray(
    artifact.builders, `candidate intake ${id}.builders`)) ===
    JSON.stringify(expectedBuilders),
  `candidate intake ${id}.builders do not bind the hosted run`);
  const prefix = id === 'gateway-deb-linux-amd64' ? 'oss-deb' : 'oss-oci';
  validateHostedEvidenceArtifacts(
    artifact.hosted_evidence_artifacts, prefix,
    `candidate intake ${id}.hosted_evidence_artifacts`);
  if (id === 'gateway-oci-linux-amd64') {
    validateOciObject(
      artifact.manifest, ['bytes', 'digest'], `candidate intake ${id}.manifest`);
    validateOciObject(
      artifact.config, ['bytes', 'digest'], `candidate intake ${id}.config`);
    validateOciObject(
      artifact.layer, ['bytes', 'diff_id', 'digest'], `candidate intake ${id}.layer`);
  }
}

function validateContract(contract) {
  exactKeys(contract, [
    'schema_version', 'classification', 'product', 'source_repository', 'platform',
    'candidate_intake_contract_path', 'artifacts', 'limits', 'sbom',
    'vulnerability', 'review', 'authority',
  ], 'supply-chain contract');
  requireCondition(contract.schema_version === 1 &&
    contract.classification === CONTRACT_CLASSIFICATION &&
    contract.product === 'RouteSphere BonVoyage API Gateway' &&
    contract.source_repository === PUBLIC_REPOSITORY &&
    contract.platform === 'linux/amd64' &&
    contract.candidate_intake_contract_path ===
      'packaging/release/oss-candidate-intake-contract.json',
  'supply-chain contract identity changed');
  requireCondition(JSON.stringify(contract.artifacts) === JSON.stringify([
    {id: 'gateway-deb-linux-amd64', kind: 'debian-package',
      evidence_directory: 'gateway-deb-linux-amd64'},
    {id: 'gateway-oci-linux-amd64', kind: 'oci-image',
      evidence_directory: 'gateway-oci-linux-amd64'},
  ]), 'supply-chain artifact contract changed');
  exactKeys(contract.limits, [
    'maximum_artifact_bytes', 'maximum_control_bytes', 'maximum_database_bytes',
  ], 'supply-chain contract.limits');
  requireCondition(contract.limits.maximum_artifact_bytes === 2147483648 &&
    contract.limits.maximum_control_bytes === 67108864 &&
    contract.limits.maximum_database_bytes === 8589934592,
  'supply-chain size limits changed');
  exactKeys(contract.sbom, [
    'formats', 'syft_image', 'cyclonedx_validator_image', 'spdx_schema_sha256',
    'spdx_validator_lock_sha256', 'official_validation_required',
    'invalid_control_rejection_required', 'decoded_inventory_parity_required',
    'artifact_root_binding_required',
  ], 'supply-chain contract.sbom');
  requireCondition(JSON.stringify(contract.sbom.formats) === JSON.stringify([
    'cyclonedx-1.6-json', 'spdx-2.3-json',
  ]) && contract.sbom.syft_image === PINNED_SYFT_IMAGE &&
    contract.sbom.cyclonedx_validator_image === PINNED_CYCLONEDX_VALIDATOR_IMAGE &&
    contract.sbom.spdx_schema_sha256 === PINNED_SPDX_SCHEMA_SHA256 &&
    contract.sbom.spdx_validator_lock_sha256 ===
      PINNED_SPDX_VALIDATOR_LOCK_SHA256 &&
    contract.sbom.official_validation_required === true &&
    contract.sbom.invalid_control_rejection_required === true &&
    contract.sbom.decoded_inventory_parity_required === true &&
    contract.sbom.artifact_root_binding_required === true,
  'SBOM policy or pinned tool identity changed');
  exactKeys(contract.vulnerability, [
    'scanner_image', 'database_origin', 'maximum_database_age_hours',
    'blocking_severities', 'maximum_unreviewed_findings',
    'maximum_unresolved_blocking_findings', 'same_physical_database_required',
    'format_parity_required', 'suppression_allowed', 'vex_allowed',
  ], 'supply-chain contract.vulnerability');
  requireCondition(contract.vulnerability.scanner_image === PINNED_GRYPE_IMAGE &&
    contract.vulnerability.database_origin === 'grype.anchore.io' &&
    contract.vulnerability.maximum_database_age_hours === 48 &&
    JSON.stringify(contract.vulnerability.blocking_severities) ===
      JSON.stringify(['High', 'Critical']) &&
    contract.vulnerability.maximum_unreviewed_findings === 0 &&
    contract.vulnerability.maximum_unresolved_blocking_findings === 0 &&
    contract.vulnerability.same_physical_database_required === true &&
    contract.vulnerability.format_parity_required === true &&
    contract.vulnerability.suppression_allowed === false &&
    contract.vulnerability.vex_allowed === false,
  'vulnerability evidence policy or pinned scanner identity changed');
  exactKeys(contract.review, [
    'required_reviewer_identity', 'required_reviewer_role',
  ], 'supply-chain contract.review');
  requireCondition(contract.review.required_reviewer_identity ===
    'johnynixon@routesphere.global' &&
    contract.review.required_reviewer_role === 'release-security-reviewer',
  'supply-chain reviewer accountability changed');
  exactKeys(contract.authority, [
    'evidence_handoff_allowed', ...POWERLESS_FIELDS,
  ], 'supply-chain contract.authority');
  requireCondition(contract.authority.evidence_handoff_allowed === true,
    'supply-chain contract must allow only evidence handoff');
  validatePowerless(
    Object.fromEntries(POWERLESS_FIELDS.map((field) => [field, contract.authority[field]])),
    'supply-chain contract authority boundary');
}

function validateIntake(root, commit, tag, limits) {
  assertDirectory(root, 'candidate intake root');
  const receiptPath = path.join(root, 'candidate-intake-receipt.json');
  const receiptRecord = readJson(
    receiptPath, 'candidate intake receipt', limits.maximum_control_bytes,
    {canonical: true});
  const receipt = receiptRecord.value;
  exactKeys(receipt, [
    'schema_version', 'classification', 'product', 'created_at', 'contract',
    'source', 'artifacts', 'files', 'authority',
  ], 'candidate intake receipt');
  requireCondition(receipt.schema_version === 1 &&
    receipt.classification === INTAKE_CLASSIFICATION &&
    receipt.product === 'RouteSphere BonVoyage API Gateway',
  'candidate intake receipt identity changed');
  canonicalTimestamp(receipt.created_at, 'candidate intake receipt.created_at');
  validateSource(receipt.source, commit, tag, 'candidate intake receipt.source');
  exactKeys(receipt.contract, ['path', 'bytes', 'sha256'], 'candidate intake receipt.contract');
  const embeddedContract = readJson(
    path.join(root, safeRelative(receipt.contract.path, 'candidate intake contract path')),
    'embedded candidate intake contract', limits.maximum_control_bytes, {canonical: true});
  const canonicalContract = snapshotIdentity(
    DEFAULT_INTAKE_CONTRACT, 'canonical candidate intake contract',
    limits.maximum_control_bytes);
  requireCondition(receipt.contract.bytes === embeddedContract.bytes &&
    receipt.contract.sha256 === embeddedContract.sha256 &&
    embeddedContract.sha256 === canonicalContract.sha256,
  'candidate intake contract binding changed');
  const actualFiles = inventory(
    root, new Set(['candidate-intake-receipt.json']), limits.maximum_artifact_bytes);
  exactInventory(actualFiles, receipt.files, 'candidate intake receipt.files');
  const actualByPath = new Map(actualFiles.map((record) => [record.path, record]));
  const byId = new Map();
  for (const artifact of requireArray(receipt.artifacts, 'candidate intake artifacts')) {
    requireObject(artifact, 'candidate intake artifact');
    const id = requireString(artifact.id, 'candidate intake artifact.id');
    requireCondition([
      'gateway-deb-linux-amd64', 'gateway-oci-linux-amd64',
    ].includes(id), 'candidate intake artifact ID changed');
    const fields = [
      'id', 'kind', 'platform', 'path', 'bytes', 'sha256', 'hosted_run_id',
      'builders', 'hosted_evidence_artifacts',
    ];
    if (id === 'gateway-oci-linux-amd64') {
      fields.push('manifest', 'config', 'layer');
    }
    exactKeys(artifact, fields, `candidate intake artifact ${id}`);
    requireCondition(!byId.has(artifact.id), 'candidate intake artifact IDs must be unique');
    byId.set(artifact.id, artifact);
  }
  requireCondition(JSON.stringify([...byId.keys()].sort()) === JSON.stringify([
    'gateway-deb-linux-amd64', 'gateway-oci-linux-amd64',
  ]), 'candidate intake artifacts changed');
  for (const [id, kind] of [
    ['gateway-deb-linux-amd64', 'debian-package'],
    ['gateway-oci-linux-amd64', 'oci-image'],
  ]) {
    const artifact = byId.get(id);
    requireCondition(artifact.kind === kind && artifact.platform === 'linux/amd64',
      `candidate intake ${id} kind or platform changed`);
    requireInteger(artifact.bytes, `candidate intake ${id}.bytes`);
    requireSha256(artifact.sha256, `candidate intake ${id}.sha256`);
    validateHostedArtifactMetadata(artifact, id);
    const artifactPath = safeRelative(artifact.path, `${id} path`);
    const payload = actualByPath.get(artifactPath);
    requireCondition(payload !== undefined && payload.bytes === artifact.bytes &&
      payload.sha256 === artifact.sha256,
      `candidate intake ${id} payload does not match its receipt`);
  }
  exactKeys(receipt.authority, [
    'release_admitted', 'publishable', 'github_release_created', 'package_uploaded',
    'container_uploaded', 'signature_created', 'provenance_created',
  ], 'candidate intake authority');
  requireCondition(Object.values(receipt.authority).every((value) => value === false),
    'candidate intake must grant no release authority');
  return {receiptRecord, receipt, artifactsById: byId};
}

function validateArtifactBinding(value, artifact, label) {
  exactKeys(value, ['id', 'kind', 'platform', 'bytes', 'sha256'], label);
  requireCondition(value.id === artifact.id && value.kind === artifact.kind &&
    value.platform === artifact.platform && value.bytes === artifact.bytes &&
    value.sha256 === artifact.sha256,
  `${label} does not match the candidate artifact`);
}

function requiredProperty(properties, name, expected, label) {
  const matches = requireArray(properties, `${label}.properties`)
    .filter((property) => property?.name === name);
  requireCondition(matches.length === 1 && matches[0].value === expected,
    `${label} must contain one ${name} property bound to ${expected}`);
}

function validateSbomRoots(cdx, spdx, artifact, source) {
  requireCondition(cdx.bomFormat === 'CycloneDX' && cdx.specVersion === '1.6',
    `${artifact.id} requires CycloneDX 1.6`);
  const component = requireObject(cdx.metadata?.component,
    `${artifact.id} CycloneDX root component`);
  requireCondition(component.type === 'file' &&
    component['bom-ref'] === `artifact:${artifact.id}` &&
    component.name === artifact.id && component.version === source.tag &&
    JSON.stringify(component.hashes) === JSON.stringify([
      {alg: 'SHA-256', content: artifact.sha256},
    ]), `${artifact.id} CycloneDX root is not bound to the candidate bytes`);
  requiredProperty(component.properties, 'routesphere:artifact-kind', artifact.kind,
    `${artifact.id} CycloneDX root`);
  requiredProperty(component.properties, 'routesphere:platform', artifact.platform,
    `${artifact.id} CycloneDX root`);
  requiredProperty(component.properties, 'routesphere:source-commit', source.commit,
    `${artifact.id} CycloneDX root`);
  requireCondition(requireArray(cdx.components ?? [], `${artifact.id} CycloneDX components`)
    .every((value) => value?.['bom-ref'] !== component['bom-ref']),
  `${artifact.id} CycloneDX root reference is duplicated`);

  requireCondition(spdx.spdxVersion === 'SPDX-2.3' &&
    spdx.SPDXID === 'SPDXRef-DOCUMENT',
  `${artifact.id} requires an SPDX 2.3 document`);
  const packages = requireArray(spdx.packages, `${artifact.id} SPDX packages`);
  const roots = packages.filter((value) => value?.SPDXID === 'SPDXRef-ArtifactRoot');
  requireCondition(roots.length === 1, `${artifact.id} requires one SPDX artifact root`);
  const root = roots[0];
  requireCondition(root.name === artifact.id && root.versionInfo === source.tag &&
    root.primaryPackagePurpose === 'FILE' && root.filesAnalyzed === false &&
    JSON.stringify(root.checksums) === JSON.stringify([
      {algorithm: 'SHA256', checksumValue: artifact.sha256},
    ]), `${artifact.id} SPDX root is not bound to the candidate bytes`);
  const described = requireArray(spdx.relationships, `${artifact.id} SPDX relationships`)
    .filter((value) => value?.spdxElementId === 'SPDXRef-DOCUMENT' &&
      value?.relationshipType === 'DESCRIBES')
    .map((value) => value.relatedSpdxElement);
  requireCondition(JSON.stringify(described) === JSON.stringify(['SPDXRef-ArtifactRoot']),
    `${artifact.id} SPDX document must describe only its candidate root`);
}

function decodedPackage(value, label) {
  exactKeys(value, ['name', 'version', 'type', 'purl'], label);
  return {
    name: requireString(value.name, `${label}.name`),
    version: requireString(value.version, `${label}.version`),
    type: requireString(value.type, `${label}.type`),
    purl: requireString(value.purl, `${label}.purl`),
  };
}

function validateDecoded(record, format, artifact, source, label) {
  const value = record.value;
  exactKeys(value, [
    'schema_version', 'classification', 'source', 'artifact', 'format',
    'descriptor', 'packages',
  ], label);
  requireCondition(value.schema_version === 1 &&
    value.classification === DECODED_CLASSIFICATION && value.format === format,
  `${label} identity changed`);
  validateSource(value.source, source.commit, source.tag, `${label}.source`);
  validateArtifactBinding(value.artifact, artifact, `${label}.artifact`);
  exactKeys(value.descriptor, ['name', 'version'], `${label}.descriptor`);
  requireCondition(value.descriptor.name === 'syft' &&
    value.descriptor.version === '1.44.0',
  `${label} requires the pinned Syft decoder identity`);
  const packages = requireArray(value.packages, `${label}.packages`)
    .map((item, index) => decodedPackage(item, `${label}.packages[${index}]`))
    .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  requireCondition(packages.length > 0 &&
    new Set(packages.map((item) => JSON.stringify(item))).size === packages.length,
  `${label} requires a nonempty unique decoded package inventory`);
  return packages;
}

function commandTool(operation, format, contract) {
  if (operation === 'generate' || operation === 'decode') return contract.sbom.syft_image;
  if (format === 'cyclonedx-1.6-json') return contract.sbom.cyclonedx_validator_image;
  return `spdx-json-schema@sha256:${contract.sbom.spdx_schema_sha256}+` +
    `validator-lock@sha256:${contract.sbom.spdx_validator_lock_sha256}`;
}

function validateCommandReceipts(receipts, documents, artifact, contract, label) {
  const byKey = new Map();
  for (const [index, command] of requireArray(receipts, label).entries()) {
    const commandLabel = `${label}[${index}]`;
    exactKeys(command, [
      'operation', 'format', 'tool', 'argv', 'exit_code',
      'input_sha256', 'output_sha256',
    ], commandLabel);
    requireCondition(['generate', 'schema-validate', 'invalid-control', 'decode']
      .includes(command.operation), `${commandLabel}.operation is unsupported`);
    requireCondition(contract.sbom.formats.includes(command.format),
      `${commandLabel}.format is unsupported`);
    requireCondition(command.tool === commandTool(
      command.operation, command.format, contract),
    `${commandLabel}.tool is not the pinned command identity`);
    const argv = requireArray(command.argv, `${commandLabel}.argv`);
    requireCondition(argv.length >= 2 && argv.length <= 32 &&
      argv.every((value) => {
        try {
          return requireString(value, `${commandLabel}.argv value`) === value;
        } catch {
          return false;
        }
      }), `${commandLabel}.argv must be a bounded argument vector`);
    requireInteger(command.exit_code, `${commandLabel}.exit_code`);
    requireSha256(command.input_sha256, `${commandLabel}.input_sha256`);
    requireSha256(command.output_sha256, `${commandLabel}.output_sha256`);
    const key = `${command.format}:${command.operation}`;
    requireCondition(!byKey.has(key), `${label} contains duplicate operation ${key}`);
    byKey.set(key, command);
  }
  const expectedKeys = contract.sbom.formats.flatMap((format) =>
    ['generate', 'schema-validate', 'invalid-control', 'decode']
      .map((operation) => `${format}:${operation}`)).sort();
  requireCondition(JSON.stringify([...byKey.keys()].sort()) ===
    JSON.stringify(expectedKeys), `${label} is incomplete`);
  for (const document of documents) {
    const generated = byKey.get(`${document.format}:generate`);
    const validated = byKey.get(`${document.format}:schema-validate`);
    const invalid = byKey.get(`${document.format}:invalid-control`);
    const decoded = byKey.get(`${document.format}:decode`);
    requireCondition(generated.exit_code === 0 &&
      generated.input_sha256 === artifact.sha256 &&
      generated.output_sha256 === document.sha256,
    `${label} does not bind ${document.format} generation`);
    requireCondition(validated.exit_code === 0 &&
      validated.input_sha256 === document.sha256 &&
      validated.output_sha256 === document.sha256,
    `${label} does not bind ${document.format} official validation`);
    requireCondition(invalid.exit_code !== 0 &&
      invalid.input_sha256 !== document.sha256 &&
      invalid.output_sha256 === invalid.input_sha256,
    `${label} does not retain ${document.format} invalid-control rejection`);
    requireCondition(decoded.exit_code === 0 &&
      decoded.input_sha256 === document.sha256 &&
      decoded.output_sha256 === document.decoded_sha256,
    `${label} does not bind ${document.format} decoded inventory`);
  }
}

function normalizeFinding(match) {
  const vulnerability = requireObject(match?.vulnerability, 'scan vulnerability');
  const artifact = requireObject(match?.artifact, 'scan artifact');
  const fix = requireObject(vulnerability.fix, 'scan vulnerability.fix');
  for (const [value, label] of [
    [vulnerability.id, 'vulnerability id'],
    [vulnerability.namespace, 'vulnerability namespace'],
    [artifact.id, 'artifact package id'],
    [artifact.purl, 'artifact package URL'],
    [artifact.name, 'artifact name'],
    [artifact.version, 'artifact version'],
    [artifact.type, 'artifact type'],
  ]) requireString(value, label);
  requireCondition(FINDING_SEVERITIES.includes(vulnerability.severity),
    'unsupported vulnerability severity');
  requireCondition(['fixed', 'not-fixed', 'wont-fix', 'unknown'].includes(fix.state) &&
    Array.isArray(fix.versions) && fix.versions.every((value) =>
      typeof value === 'string' && value.length > 0), 'invalid fix identity');
  return {
    id: vulnerability.id,
    namespace: vulnerability.namespace,
    package_id: artifact.purl,
    package: artifact.name,
    version: artifact.version,
    type: artifact.type,
    severity: vulnerability.severity,
    fix_state: fix.state,
    fix_versions: [...fix.versions].sort(),
  };
}

function findingKey(value) {
  return JSON.stringify([
    value.id, value.namespace, value.package_id, value.package, value.version, value.type,
    value.severity, value.fix_state, value.fix_versions,
  ]);
}

function normalizedFindings(scan) {
  const result = requireArray(scan.matches, 'scan matches').map(normalizeFinding)
    .sort((left, right) => findingKey(left).localeCompare(findingKey(right)));
  requireCondition(new Set(result.map(findingKey)).size === result.length,
    'scan contains duplicate normalized findings');
  return result;
}

function validateRetainedDistro(distro, artifact, label) {
  exactKeys(distro, ['idLike', 'name', 'version'], label);
  if (artifact.kind === 'debian-package') {
    requireCondition(distro.name === '' && distro.version === '' && distro.idLike === null,
      `${label} must retain the standalone Debian-package identity`);
    return;
  }
  requireCondition(distro.name === 'ubuntu' && distro.version === '24.04' &&
    Array.isArray(distro.idLike) && distro.idLike.length === 1 &&
    ['debian', 'ubuntu'].includes(distro.idLike[0]),
  `${label} must retain the Ubuntu 24.04 image identity`);
}

function summarizeRetainedSbomScan(scan, target, verifiedAt, artifact, label) {
  const source = requireObject(scan.source, `${label}.source`);
  exactKeys(source, ['type', 'target'], `${label}.source`);
  requireCondition(['file', 'directory', 'sbom-file'].includes(source.type) &&
    source.target === target,
  `${label}.source is not bound to the retained SBOM target`);
  validateRetainedDistro(requireObject(scan.distro, `${label}.distro`), artifact,
    `${label}.distro`);
  const canonical = structuredClone(scan);
  canonical.source.type = 'sbom-file';
  canonical.distro = {name: 'ubuntu', version: '24.04'};
  return summarize(canonical, target, verifiedAt);
}

function databaseIdentity(summary) {
  const database = requireObject(summary.database, 'scan database');
  const origin = new URL(database.from);
  requireCondition(database.path === '/evidence/database/vulnerability.db',
    'all scans must name the retained physical vulnerability database');
  return {
    path: 'vulnerability.db',
    built_at: new Date(database.built).toISOString(),
    schema_version: database.schemaVersion,
    origin: `${origin.protocol}//${origin.host}${origin.pathname}`,
    archive_sha256: origin.searchParams.get('checksum')?.replace(/^sha256:/u, ''),
  };
}

function validateDatabase(reviewRoot, source, contract) {
  const directory = path.join(reviewRoot, 'database');
  assertDirectory(directory, 'vulnerability database evidence');
  const entries = fs.readdirSync(directory, {withFileTypes: true});
  requireCondition(entries.every((entry) => entry.isFile()) &&
    JSON.stringify(entries.map((entry) => entry.name).sort()) ===
      JSON.stringify(['receipt.json', 'vulnerability.db']),
  'vulnerability database evidence must contain exactly receipt.json and vulnerability.db');
  const payload = snapshotIdentity(
    path.join(directory, 'vulnerability.db'), 'vulnerability database payload',
    contract.limits.maximum_database_bytes);
  const record = readJson(
    path.join(directory, 'receipt.json'), 'vulnerability database receipt',
    contract.limits.maximum_control_bytes, {canonical: true});
  const value = record.value;
  exactKeys(value, [
    'schema_version', 'classification', 'source', 'scanner_image', 'database',
    'authority',
  ], 'vulnerability database receipt');
  requireCondition(value.schema_version === 1 &&
    value.classification === DATABASE_CLASSIFICATION &&
    value.scanner_image === contract.vulnerability.scanner_image,
  'vulnerability database receipt identity changed');
  validateSource(value.source, source.commit, source.tag,
    'vulnerability database receipt.source');
  exactKeys(value.database, [
    'path', 'bytes', 'sha256', 'built_at', 'schema_version', 'origin',
    'archive_sha256',
  ], 'vulnerability database receipt.database');
  requireCondition(value.database.path === 'vulnerability.db' &&
    value.database.bytes === payload.bytes && value.database.sha256 === payload.sha256 &&
    /^v6\.\d+\.\d+$/u.test(value.database.schema_version),
  'vulnerability database receipt does not bind the retained database');
  canonicalTimestamp(value.database.built_at,
    'vulnerability database receipt.database.built_at');
  const origin = new URL(value.database.origin);
  requireCondition(origin.protocol === 'https:' &&
    origin.hostname === contract.vulnerability.database_origin &&
    origin.pathname.startsWith('/databases/v6/') &&
    origin.search === '' && origin.hash === '',
  'vulnerability database origin changed');
  requireSha256(value.database.archive_sha256,
    'vulnerability database receipt.database.archive_sha256');
  validatePowerless(value.authority, 'vulnerability database receipt.authority');
  return {record, payload, database: value.database};
}

function validateReview({
  directory, artifact, source, contract, databaseEvidence, verifiedAt,
}) {
  assertDirectory(directory, `${artifact.id} evidence`);
  const entries = fs.readdirSync(directory, {withFileTypes: true});
  requireCondition(entries.every((entry) => entry.isFile()) &&
    JSON.stringify(entries.map((entry) => entry.name).sort()) ===
      JSON.stringify([...ARTIFACT_EVIDENCE_FILES]),
  `${artifact.id} evidence must contain exactly the fixed evidence files`);
  const read = (file, label, canonical = false) => readJson(
    path.join(directory, file), label, contract.limits.maximum_control_bytes,
    {canonical});
  const cdx = read('cyclonedx.json', `${artifact.id} CycloneDX`);
  const spdx = read('spdx.json', `${artifact.id} SPDX`);
  validateSbomRoots(cdx.value, spdx.value, artifact, source);
  const decodedCdx = read(
    'decoded-cyclonedx.json', `${artifact.id} decoded CycloneDX`, true);
  const decodedSpdx = read(
    'decoded-spdx.json', `${artifact.id} decoded SPDX`, true);
  const cdxPackages = validateDecoded(
    decodedCdx, 'cyclonedx-1.6-json', artifact, source,
    `${artifact.id} decoded CycloneDX`);
  const spdxPackages = validateDecoded(
    decodedSpdx, 'spdx-2.3-json', artifact, source,
    `${artifact.id} decoded SPDX`);
  requireCondition(JSON.stringify(cdxPackages) === JSON.stringify(spdxPackages),
    `${artifact.id} decoded package inventories differ between SBOM formats`);

  const validationRecord = read(
    'validation.json', `${artifact.id} validation`, true);
  const validation = validationRecord.value;
  exactKeys(validation, [
    'schema_version', 'classification', 'source', 'artifact', 'tools',
    'documents', 'command_receipts', 'decoder_parity', 'authority',
  ], `${artifact.id} validation`);
  requireCondition(validation.schema_version === 1 &&
    validation.classification === VALIDATION_CLASSIFICATION,
  `${artifact.id} validation identity changed`);
  validateSource(validation.source, source.commit, source.tag,
    `${artifact.id} validation.source`);
  validateArtifactBinding(
    validation.artifact, artifact, `${artifact.id} validation.artifact`);
  requireCondition(JSON.stringify(validation.tools) === JSON.stringify({
    syft_image: contract.sbom.syft_image,
    cyclonedx_validator_image: contract.sbom.cyclonedx_validator_image,
    spdx_schema_sha256: contract.sbom.spdx_schema_sha256,
    spdx_validator_lock_sha256: contract.sbom.spdx_validator_lock_sha256,
  }), `${artifact.id} validator tool identities changed`);
  const documentSpecs = [
    ['cyclonedx-1.6-json', 'cyclonedx.json', cdx,
      'decoded-cyclonedx.json', decodedCdx],
    ['spdx-2.3-json', 'spdx.json', spdx, 'decoded-spdx.json', decodedSpdx],
  ];
  const documents = requireArray(
    validation.documents, `${artifact.id} validation.documents`);
  requireCondition(documents.length === documentSpecs.length,
    `${artifact.id} validation documents changed`);
  for (let index = 0; index < documentSpecs.length; index += 1) {
    const [format, file, record, decodedFile, decodedRecord] = documentSpecs[index];
    const document = documents[index];
    exactKeys(document, [
      'format', 'path', 'bytes', 'sha256', 'decoded_path', 'decoded_bytes',
      'decoded_sha256',
    ], `${artifact.id} validation document[${index}]`);
    requireCondition(document.format === format && document.path === file &&
      document.bytes === record.bytes && document.sha256 === record.sha256 &&
      document.decoded_path === decodedFile &&
      document.decoded_bytes === decodedRecord.bytes &&
      document.decoded_sha256 === decodedRecord.sha256,
    `${artifact.id} ${format} validation is unbound`);
  }
  validateCommandReceipts(
    validation.command_receipts, documents, artifact, contract,
    `${artifact.id} validation.command_receipts`);
  requireCondition(validation.decoder_parity === true,
    `${artifact.id} decoder parity is required`);
  validatePowerless(validation.authority, `${artifact.id} validation.authority`);

  const scanRecords = [
    ['cyclonedx-1.6-json', 'scan-cyclonedx.json',
      `/input/${artifact.id}/cyclonedx.json`],
    ['spdx-2.3-json', 'scan-spdx.json', `/input/${artifact.id}/spdx.json`],
  ].map(([format, file, target]) => {
    const record = read(file, `${artifact.id} ${format} scan`);
    const summary = summarizeRetainedSbomScan(
      record.value, target, verifiedAt, artifact, `${artifact.id} ${format} scan`);
    return {
      format, file, target, record, summary,
      findings: normalizedFindings(record.value),
      database: databaseIdentity(summary),
    };
  });
  requireCondition(JSON.stringify(scanRecords[0].findings) ===
    JSON.stringify(scanRecords[1].findings),
  `${artifact.id} scan findings differ between SBOM formats`);
  requireCondition(JSON.stringify(scanRecords[0].database) ===
    JSON.stringify(scanRecords[1].database),
  `${artifact.id} scans did not use the same physical database identity`);
  const expectedDatabase = {
    path: databaseEvidence.database.path,
    built_at: databaseEvidence.database.built_at,
    schema_version: databaseEvidence.database.schema_version,
    origin: databaseEvidence.database.origin,
    archive_sha256: databaseEvidence.database.archive_sha256,
  };
  requireCondition(JSON.stringify(scanRecords[0].database) ===
    JSON.stringify(expectedDatabase),
  `${artifact.id} scans are not bound to the retained database receipt`);
  requireCondition(scanRecords.every(({summary}) => summary.gate.passed === true),
    `${artifact.id} has unresolved High or Critical findings`);

  const reviewRecord = read('review.json', `${artifact.id} review`, true);
  const review = reviewRecord.value;
  exactKeys(review, [
    'schema_version', 'classification', 'source', 'artifact', 'scanner_image',
    'database', 'scans', 'scan_commands', 'reviewer', 'findings',
    'format_parity', 'unreviewed_findings', 'unresolved_blocking_findings',
    'reviewed_at', 'authority',
  ], `${artifact.id} review`);
  requireCondition(review.schema_version === 1 &&
    review.classification === REVIEW_CLASSIFICATION &&
    review.scanner_image === contract.vulnerability.scanner_image,
  `${artifact.id} review identity changed`);
  validateSource(review.source, source.commit, source.tag,
    `${artifact.id} review.source`);
  validateArtifactBinding(review.artifact, artifact, `${artifact.id} review.artifact`);
  requireCondition(JSON.stringify(review.database) ===
    JSON.stringify(databaseEvidence.database),
  `${artifact.id} review does not bind the retained physical database`);
  requireCondition(JSON.stringify(review.scans) === JSON.stringify(
    scanRecords.map((value) => ({
      format: value.format,
      path: value.file,
      bytes: value.record.bytes,
      sha256: value.record.sha256,
      target: value.target,
    }))), `${artifact.id} review scan bindings changed`);
  const scanCommands = requireArray(
    review.scan_commands, `${artifact.id} review.scan_commands`);
  requireCondition(scanCommands.length === 2, `${artifact.id} requires two scan commands`);
  for (let index = 0; index < scanCommands.length; index += 1) {
    const command = scanCommands[index];
    const scan = scanRecords[index];
    exactKeys(command, [
      'format', 'tool', 'argv', 'exit_code', 'input_sha256',
      'database_sha256', 'output_sha256',
    ], `${artifact.id} scan command[${index}]`);
    requireCondition(command.format === scan.format &&
      command.tool === contract.vulnerability.scanner_image &&
      Array.isArray(command.argv) && command.argv.length >= 2 &&
      command.argv.length <= 32 && command.argv.every((value) =>
        typeof value === 'string' && value.length > 0 &&
        value === value.trim() && !/[\u0000-\u001f\u007f]/u.test(value)) &&
      command.exit_code === 0 &&
      command.input_sha256 ===
        (index === 0 ? cdx.sha256 : spdx.sha256) &&
      command.database_sha256 === databaseEvidence.database.sha256 &&
      command.output_sha256 === scan.record.sha256,
    `${artifact.id} scan command[${index}] is incomplete or unbound`);
  }
  exactKeys(review.reviewer, ['identity', 'role'], `${artifact.id} review.reviewer`);
  requireCondition(review.reviewer.identity ===
    contract.review.required_reviewer_identity &&
    review.reviewer.role === contract.review.required_reviewer_role,
  `${artifact.id} review lacks the accountable contracted reviewer`);
  const reviewedAt = canonicalTimestamp(
    review.reviewed_at, `${artifact.id} review.reviewed_at`);
  const latestScan = Math.max(...scanRecords.map(({summary}) =>
    Date.parse(summary.scanned_at)));
  requireCondition(reviewedAt >= latestScan && reviewedAt <= verifiedAt &&
    verifiedAt - reviewedAt <=
      contract.vulnerability.maximum_database_age_hours * 60 * 60 * 1000,
  `${artifact.id} review is stale or future-dated`);
  const expectedFindings = scanRecords[0].findings;
  const reviewFindings = requireArray(review.findings, `${artifact.id} review.findings`)
    .map((value) => {
      exactKeys(value, [
        'id', 'namespace', 'package_id', 'package', 'version', 'type', 'severity',
        'fix_state', 'fix_versions', 'disposition', 'rationale',
      ], `${artifact.id} reviewed finding`);
      requireCondition(value.disposition === 'observed-nonblocking' &&
        typeof value.rationale === 'string' && value.rationale.trim().length >= 8 &&
        value.rationale.length <= 1024 &&
        !/[\u0000-\u001f\u007f]/u.test(value.rationale),
      `${artifact.id} finding requires a bounded nonblocking review rationale`);
      return value;
    })
    .sort((left, right) => findingKey(left).localeCompare(findingKey(right)));
  requireCondition(JSON.stringify(reviewFindings.map((value) => {
    const {disposition, rationale, ...identity} = value;
    return identity;
  })) === JSON.stringify(expectedFindings),
  `${artifact.id} review does not cover every exact finding`);
  requireCondition(review.format_parity === true && review.unreviewed_findings === 0 &&
    review.unresolved_blocking_findings === 0,
  `${artifact.id} vulnerability review is incomplete`);
  validatePowerless(review.authority, `${artifact.id} review.authority`);
  return {
    database: databaseEvidence.database,
    findings: expectedFindings,
    reviewer: review.reviewer,
    evidenceRecords: new Map([
      ['cyclonedx.json', cdx],
      ['decoded-cyclonedx.json', decodedCdx],
      ['decoded-spdx.json', decodedSpdx],
      ['review.json', reviewRecord],
      ['scan-cyclonedx.json', scanRecords[0].record],
      ['scan-spdx.json', scanRecords[1].record],
      ['spdx.json', spdx],
      ['validation.json', validationRecord],
    ]),
  };
}

function writeExclusive(destination, content) {
  fs.mkdirSync(path.dirname(destination), {recursive: true, mode: 0o700});
  fs.writeFileSync(destination, content, {flag: 'wx', mode: 0o600});
}

function copyExclusive(source, destination, label, maximum) {
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  let input;
  let output;
  try {
    input = fs.openSync(source, fs.constants.O_RDONLY | noFollow);
    const before = fs.fstatSync(input);
    requireCondition(before.isFile() && before.nlink === 1 && before.size > 0 &&
      before.size <= maximum, `${label} is not a bounded regular source file`);
    fs.mkdirSync(path.dirname(destination), {recursive: true, mode: 0o700});
    output = fs.openSync(destination,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    const hash = crypto.createHash('sha256');
    let bytes = 0;
    while (true) {
      const count = fs.readSync(input, buffer, 0, buffer.length, null);
      if (count === 0) break;
      let written = 0;
      while (written < count) {
        written += fs.writeSync(output, buffer, written, count - written);
      }
      hash.update(buffer.subarray(0, count));
      bytes += count;
    }
    assertStableFile(before, fs.fstatSync(input), bytes, label);
    fs.fsyncSync(output);
    return {bytes, sha256: hash.digest('hex')};
  } finally {
    if (output !== undefined) fs.closeSync(output);
    if (input !== undefined) fs.closeSync(input);
  }
}

function writeCanonicalJson(destination, value) {
  writeExclusive(destination, canonicalJson(value));
}

function fileReference(root, relative, maximum) {
  return {
    path: relative,
    ...snapshotIdentity(path.join(root, relative), `output ${relative}`, maximum),
  };
}

export function intakeSupplyChainEvidence({
  candidateRoot,
  reviewRoot,
  output,
  sourceCommit,
  sourceTag,
  verifiedAt = Date.now(),
  contractPath = DEFAULT_CONTRACT,
}) {
  requireCondition(COMMIT.test(sourceCommit ?? ''),
    'source commit must be a lowercase Git SHA-1');
  requireCondition(TAG.test(sourceTag ?? ''), 'source tag must be strict v-prefixed SemVer');
  requireCondition(Number.isFinite(verifiedAt) && verifiedAt >= 0,
    'verifiedAt must be a finite timestamp');
  const contractRecord = readJson(
    path.resolve(contractPath), 'supply-chain contract', BOOTSTRAP_CONTROL_LIMIT,
    {canonical: true});
  validateContract(contractRecord.value);
  const limits = contractRecord.value.limits;
  const candidateDirectory = path.resolve(candidateRoot);
  const candidate = validateIntake(
    candidateDirectory, sourceCommit, sourceTag, limits);
  const reviewDirectory = path.resolve(reviewRoot);
  assertDirectory(reviewDirectory, 'review root');
  const expectedEntries = [
    'database',
    ...contractRecord.value.artifacts.map((artifact) => artifact.evidence_directory),
  ].sort();
  const actualEntries = fs.readdirSync(reviewDirectory, {withFileTypes: true});
  requireCondition(actualEntries.every((entry) => entry.isDirectory()) &&
    JSON.stringify(actualEntries.map((entry) => entry.name).sort()) ===
      JSON.stringify(expectedEntries),
  'review root must contain exactly the database and contracted artifact directories');
  const databaseEvidence = validateDatabase(
    reviewDirectory, candidate.receipt.source, contractRecord.value);
  const reviewedByArtifact = new Map();
  for (const contracted of contractRecord.value.artifacts) {
    const artifact = candidate.artifactsById.get(contracted.id);
    reviewedByArtifact.set(contracted.id, validateReview({
      directory: path.join(reviewDirectory, contracted.evidence_directory),
      artifact,
      source: candidate.receipt.source,
      contract: contractRecord.value,
      databaseEvidence,
      verifiedAt,
    }));
  }

  const destination = path.resolve(output);
  requireCondition(!fs.existsSync(destination), 'output directory must not already exist');
  fs.mkdirSync(destination, {mode: 0o700});
  try {
    const controlMaximum = limits.maximum_control_bytes;
    writeExclusive(
      path.join(destination, 'metadata/oss-supply-chain-evidence-contract.json'),
      contractRecord.content);
    writeExclusive(
      path.join(destination, 'evidence/candidate-intake-receipt.json'),
      candidate.receiptRecord.content);
    writeExclusive(
      path.join(destination, 'evidence/database/receipt.json'),
      databaseEvidence.record.content);
    const copiedDatabase = copyExclusive(
      path.join(reviewDirectory, 'database/vulnerability.db'),
      path.join(destination, 'evidence/database/vulnerability.db'),
      'vulnerability database handoff copy', limits.maximum_database_bytes);
    requireCondition(copiedDatabase.bytes === databaseEvidence.payload.bytes &&
      copiedDatabase.sha256 === databaseEvidence.payload.sha256,
    'vulnerability database handoff copy changed');

    const artifactResults = [];
    for (const contracted of contractRecord.value.artifacts) {
      const artifact = candidate.artifactsById.get(contracted.id);
      const reviewed = reviewedByArtifact.get(contracted.id);
      const evidencePrefix = `evidence/supply-chain/${contracted.id}`;
      for (const file of ARTIFACT_EVIDENCE_FILES) {
        writeExclusive(
          path.join(destination, evidencePrefix, file),
          reviewed.evidenceRecords.get(file).content);
      }
      artifactResults.push({
        id: artifact.id,
        kind: artifact.kind,
        platform: artifact.platform,
        artifact_bytes: artifact.bytes,
        artifact_sha256: artifact.sha256,
        status: 'EVIDENCE_RETAINED',
        reviewer: reviewed.reviewer,
        sboms: [
          {
            format: 'cyclonedx-1.6-json',
            ...fileReference(
              destination, `${evidencePrefix}/cyclonedx.json`, controlMaximum),
          },
          {
            format: 'spdx-2.3-json',
            ...fileReference(
              destination, `${evidencePrefix}/spdx.json`, controlMaximum),
          },
        ],
        vulnerability_evidence: {
          database_sha256: reviewed.database.sha256,
          finding_count: reviewed.findings.length,
          unreviewed_findings: 0,
          unresolved_blocking_findings: 0,
        },
      });
    }
    const handoff = {
      schema_version: 1,
      classification: HANDOFF_CLASSIFICATION,
      status: 'EVIDENCE_RETAINED',
      product: contractRecord.value.product,
      retained_at: new Date(verifiedAt).toISOString(),
      contract: fileReference(
        destination, 'metadata/oss-supply-chain-evidence-contract.json',
        controlMaximum),
      candidate_intake: {
        ...fileReference(
          destination, 'evidence/candidate-intake-receipt.json', controlMaximum),
        original_sha256: candidate.receiptRecord.sha256,
      },
      source: candidate.receipt.source,
      database: {
        receipt: fileReference(
          destination, 'evidence/database/receipt.json', controlMaximum),
        payload: fileReference(
          destination, 'evidence/database/vulnerability.db',
          limits.maximum_database_bytes),
      },
      artifacts: artifactResults,
      files: inventory(
        destination, new Set(['supply-chain-evidence-handoff.json']),
        limits.maximum_database_bytes),
      authority: contractRecord.value.authority,
    };
    const handoffPath = path.join(
      destination, 'supply-chain-evidence-handoff.json');
    writeCanonicalJson(handoffPath, handoff);
    exactInventory(inventory(
      destination, new Set(['supply-chain-evidence-handoff.json']),
      limits.maximum_database_bytes), handoff.files, 'supply-chain handoff.files');

    const finalCandidate = validateIntake(
      candidateDirectory, sourceCommit, sourceTag, limits);
    requireCondition(
      finalCandidate.receiptRecord.sha256 === candidate.receiptRecord.sha256,
      'candidate intake changed before handoff completion');
    const handoffIdentity = snapshotIdentity(
      handoffPath, 'supply-chain evidence handoff', controlMaximum);
    return {
      status: 'EVIDENCE_RETAINED',
      source_commit: sourceCommit,
      source_tag: sourceTag,
      handoff_path: handoffPath,
      handoff_bytes: handoffIdentity.bytes,
      handoff_sha256: handoffIdentity.sha256,
      artifacts: artifactResults,
      release_admitted: false,
      publishable: false,
    };
  } catch (error) {
    fs.rmSync(destination, {recursive: true, force: true});
    throw error;
  }
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    requireCondition(key?.startsWith('--') && value !== undefined,
      'arguments must be --name value pairs');
    requireCondition(options[key] === undefined, `duplicate argument ${key}`);
    options[key] = value;
  }
  const expected = [
    '--candidate-root', '--review-root', '--output', '--source-commit', '--source-tag',
  ];
  requireCondition(Object.keys(options).length === expected.length &&
    expected.every((key) => options[key] !== undefined),
  `required arguments: ${expected.join(' ')}`);
  return options;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const result = intakeSupplyChainEvidence({
      candidateRoot: options['--candidate-root'],
      reviewRoot: options['--review-root'],
      output: options['--output'],
      sourceCommit: options['--source-commit'],
      sourceTag: options['--source-tag'],
    });
    console.log(JSON.stringify(result));
  } catch (error) {
    console.error(`invalid supply-chain evidence: ${error.message}`);
    process.exitCode = 2;
  }
}
