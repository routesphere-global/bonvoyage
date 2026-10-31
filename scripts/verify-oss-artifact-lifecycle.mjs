#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {TextDecoder} from 'node:util';
import {fileURLToPath} from 'node:url';

const SCRIPT_ROOT = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_CONTRACT = path.resolve(
  SCRIPT_ROOT, '..', 'packaging', 'release', 'oss-artifact-lifecycle-contract.json');
const CONTRACT_CLASSIFICATION =
  'routesphere-bonvoyage-oss-artifact-lifecycle-contract';
const INTAKE_CLASSIFICATION =
  'routesphere-bonvoyage-oss-candidate-intake-receipt';
const OBSERVATION_CLASSIFICATION =
  'routesphere-bonvoyage-oss-artifact-lifecycle-observation';
const PUBLIC_REPOSITORY = 'https://github.com/routesphere-global/bonvoyage';
const LEGACY_RUNTIME_IDENTITY_CLASSIFICATION =
  'routesphere-bonvoyage-legacy-runtime-identity-absence';
const LEGACY_RUNTIME_IDENTITY_EVIDENCE =
  'evidence/legacy-runtime-identity-absence.json';
const LEGACY_RUNTIME_IDENTITY_BASELINE = Object.freeze({
  commit: '78e7cc798eab902a6cc87b7063b6bc2ef09284da',
  tag: 'v1.0.0-rc.6',
  debian_run_id: '40984886786',
  oci_run_id: '40984894383',
});
const POWERLESS_FIELDS = Object.freeze([
  'release_admitted',
  'publishable',
  'github_release_created',
  'package_uploaded',
  'container_uploaded',
  'signature_created',
  'provenance_created',
]);
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const RUN_ID = /^[1-9][0-9]*$/u;
const TAG = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*))?$/u;
const DECODER = new TextDecoder('utf-8', {fatal: true});
const MAX_CONTROL_BYTES = 8 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;
const MAX_EVIDENCE_BYTES = 64 * 1024 * 1024;

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

function exactKeys(value, expected, label) {
  const actual = Object.keys(requireObject(value, label)).sort();
  const wanted = [...expected].sort();
  requireCondition(actual.length === wanted.length &&
    actual.every((item, index) => item === wanted[index]),
  `${label} fields must be exactly [${wanted.join(', ')}]`);
}

function exactSet(actualValues, expectedValues, label) {
  const actual = [...actualValues].sort();
  const expected = [...expectedValues].sort();
  requireCondition(actual.length === expected.length &&
    actual.every((item, index) => item === expected[index]),
  `${label} must be exactly [${expected.join(', ')}], got [${actual.join(', ')}]`);
}

function canonicalTimestamp(value, label) {
  requireString(value, label);
  requireCondition(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
    new Date(value).toISOString() === value, `${label} must be canonical UTC`);
  return Date.parse(value);
}

function safeRelative(value, label) {
  requireString(value, label);
  requireCondition(!value.includes('\\') && !path.posix.isAbsolute(value) &&
    path.posix.normalize(value) === value && value !== '.' && !value.startsWith('./') &&
    value.split('/').every((part) => part.length > 0 && part !== '..'),
  `${label} must be a safe normalized relative path`);
  return value;
}

function snapshotFile(filePath, label, maximum, retain = false) {
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && before.nlink === 1 && before.size > 0,
      `${label} must be one nonempty regular non-hard-linked file`);
    requireCondition(before.size <= maximum, `${label} exceeds its size limit`);
    const hash = crypto.createHash('sha256');
    const chunks = retain ? [] : null;
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    while (true) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      const part = buffer.subarray(0, count);
      hash.update(part);
      if (chunks) chunks.push(Buffer.from(part));
      bytes += count;
    }
    const after = fs.fstatSync(descriptor);
    requireCondition(before.dev === after.dev && before.ino === after.ino &&
      before.size === after.size && before.mtimeMs === after.mtimeMs &&
      before.ctimeMs === after.ctimeMs && before.nlink === after.nlink &&
      bytes === after.size, `${label} changed while it was read`);
    return {
      bytes,
      sha256: hash.digest('hex'),
      ...(chunks ? {content: Buffer.concat(chunks, bytes)} : {}),
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.startsWith(label)) throw error;
    fail(`${label} could not be read safely: ${message}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readCanonicalJson(filePath, label) {
  const record = snapshotFile(filePath, label, MAX_CONTROL_BYTES, true);
  let text;
  let value;
  try {
    text = DECODER.decode(record.content);
    value = JSON.parse(text);
  } catch (error) {
    fail(`${label} is not valid UTF-8 JSON: ${error.message}`);
  }
  requireObject(value, label);
  requireCondition(text === `${JSON.stringify(value, null, 2)}\n`,
    `${label} must use canonical JSON encoding`);
  return {value, bytes: record.bytes, sha256: record.sha256};
}

function assertDirectory(directory, label) {
  const metadata = fs.lstatSync(directory);
  requireCondition(metadata.isDirectory() && !metadata.isSymbolicLink(),
    `${label} must be a real directory`);
}

function inventory(root, excluded = new Set(), maximum = MAX_ARTIFACT_BYTES) {
  assertDirectory(root, 'evidence tree');
  const records = [];
  function walk(directory, prefix = '') {
    const entries = fs.readdirSync(directory, {withFileTypes: true});
    requireCondition(entries.length > 0, `tree directory ${prefix || '.'} must not be empty`);
    for (const entry of entries) {
      const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      safeRelative(relative, `tree path ${relative}`);
      const absolute = path.join(directory, entry.name);
      const metadata = fs.lstatSync(absolute);
      requireCondition(!metadata.isSymbolicLink(), `tree path ${relative} must not be a link`);
      if (metadata.isDirectory()) {
        walk(absolute, relative);
      } else {
        requireCondition(metadata.isFile() && metadata.nlink === 1,
          `tree path ${relative} must be one regular non-hard-linked file`);
        if (!excluded.has(relative)) {
          records.push({path: relative, ...snapshotFile(
            absolute, `tree path ${relative}`, maximum)});
        }
      }
    }
  }
  walk(root);
  return records.sort((left, right) => left.path.localeCompare(right.path));
}

function validatePowerless(authority, label) {
  exactKeys(authority, POWERLESS_FIELDS, label);
  for (const field of POWERLESS_FIELDS) {
    requireCondition(authority[field] === false, `${label}.${field} must remain false`);
  }
}

function validateLegacyRuntimeIdentityAbsence(root, filesByPath, label) {
  const retained = filesByPath.get(LEGACY_RUNTIME_IDENTITY_EVIDENCE);
  if (retained === undefined) return null;
  const record = readCanonicalJson(
    path.join(root, LEGACY_RUNTIME_IDENTITY_EVIDENCE),
    `${label} legacy runtime identity evidence`);
  requireCondition(record.bytes === retained.bytes && record.sha256 === retained.sha256,
    `${label} legacy runtime identity evidence is not bound by the intake inventory`);
  const evidence = record.value;
  exactKeys(evidence, [
    'schema_version', 'classification', 'scope', 'source', 'hosted_runs',
    'runtime_identity', 'authority',
  ], `${label} legacy runtime identity evidence`);
  requireCondition(evidence.schema_version === 1 &&
    evidence.classification === LEGACY_RUNTIME_IDENTITY_CLASSIFICATION &&
    evidence.scope === 'historical-lifecycle-baseline-only',
  `${label} legacy runtime identity evidence identity changed`);
  exactKeys(evidence.source, ['repository', 'commit', 'tag', 'dirty'],
    `${label} legacy runtime identity source`);
  requireCondition(evidence.source.repository === PUBLIC_REPOSITORY &&
    COMMIT.test(evidence.source.commit) && TAG.test(evidence.source.tag) &&
    evidence.source.dirty === false,
  `${label} legacy runtime identity source is invalid`);
  exactKeys(evidence.hosted_runs, ['debian', 'oci'],
    `${label} legacy runtime identity hosted runs`);
  requireCondition(RUN_ID.test(evidence.hosted_runs.debian) &&
    RUN_ID.test(evidence.hosted_runs.oci) &&
    evidence.hosted_runs.debian !== evidence.hosted_runs.oci,
  `${label} legacy runtime identity hosted runs are invalid`);
  exactKeys(evidence.runtime_identity, ['debian', 'oci'],
    `${label} legacy runtime identity states`);
  requireCondition(JSON.stringify(evidence.runtime_identity) === JSON.stringify({
    debian: ['absent', 'absent'],
    oci: ['absent', 'absent'],
  }), `${label} legacy runtime identity states must record four absent builder fields`);
  exactKeys(evidence.authority, POWERLESS_FIELDS,
    `${label} legacy runtime identity authority`);
  validatePowerless(evidence.authority, `${label} legacy runtime identity authority`);
  return evidence;
}

function uniqueStrings(values, label) {
  const result = requireArray(values, label).map((value, index) =>
    requireString(value, `${label}[${index}]`));
  requireCondition(new Set(result).size === result.length,
    `${label} must not contain duplicates`);
  return result;
}

function validateArtifactSpecifications(values, label) {
  const ids = new Set();
  return requireArray(values, label).map((value, index) => {
    const itemLabel = `${label}[${index}]`;
    const artifact = requireObject(value, itemLabel);
    exactKeys(artifact, ['id', 'kind', 'transition', 'phases'], itemLabel);
    const id = requireString(artifact.id, `${itemLabel}.id`);
    requireCondition(!ids.has(id), `${label} contains duplicate artifact ${id}`);
    ids.add(id);
    const phases = requireArray(artifact.phases, `${itemLabel}.phases`).map(
      (phaseValue, phaseIndex) => {
        const phaseLabel = `${itemLabel}.phases[${phaseIndex}]`;
        const phase = requireObject(phaseValue, phaseLabel);
        exactKeys(phase, ['id', 'required_checks'], phaseLabel);
        return {
          id: requireString(phase.id, `${phaseLabel}.id`),
          requiredChecks: uniqueStrings(
            phase.required_checks, `${phaseLabel}.required_checks`),
        };
      });
    requireCondition(phases.length > 0 &&
      new Set(phases.map((phase) => phase.id)).size === phases.length,
    `${itemLabel}.phases must be nonempty and unique`);
    return {
      id,
      kind: requireString(artifact.kind, `${itemLabel}.kind`),
      transition: requireString(artifact.transition, `${itemLabel}.transition`),
      phases,
    };
  });
}

function validateContract(contract) {
  exactKeys(contract, [
    'schema_version', 'classification', 'product', 'source_repository', 'platform',
    'baseline', 'runner', 'artifacts', 'authority',
  ], 'lifecycle contract');
  requireCondition(contract.schema_version === 1 &&
    contract.classification === CONTRACT_CLASSIFICATION &&
    contract.product === 'RouteSphere BonVoyage API Gateway' &&
    contract.source_repository === PUBLIC_REPOSITORY &&
    contract.platform === 'linux/amd64', 'lifecycle contract identity changed');
  const artifacts = validateArtifactSpecifications(contract.artifacts, 'contract.artifacts');
  requireCondition(artifacts.length === 2, 'lifecycle contract must define two artifacts');

  const baseline = requireObject(contract.baseline, 'contract.baseline');
  exactKeys(baseline, ['source', 'hosted_runs', 'artifacts'], 'contract.baseline');
  exactKeys(baseline.source, ['commit', 'tag'], 'contract.baseline.source');
  requireCondition(COMMIT.test(baseline.source.commit) && TAG.test(baseline.source.tag),
    'contract baseline source identity is invalid');
  exactKeys(baseline.hosted_runs, ['debian', 'oci'], 'contract.baseline.hosted_runs');
  requireCondition(RUN_ID.test(baseline.hosted_runs.debian) &&
    RUN_ID.test(baseline.hosted_runs.oci) &&
    baseline.hosted_runs.debian !== baseline.hosted_runs.oci,
  'contract baseline hosted runs must be distinct positive IDs');
  const baselineArtifacts = requireArray(
    baseline.artifacts, 'contract.baseline.artifacts').map((value, index) => {
      const itemLabel = `contract.baseline.artifacts[${index}]`;
      const artifact = requireObject(value, itemLabel);
      exactKeys(artifact, ['id', 'kind', 'bytes', 'sha256'], itemLabel);
      return {
        id: requireString(artifact.id, `${itemLabel}.id`),
        kind: requireString(artifact.kind, `${itemLabel}.kind`),
        bytes: requireInteger(artifact.bytes, `${itemLabel}.bytes`),
        sha256: requireSha256(artifact.sha256, `${itemLabel}.sha256`),
      };
    });
  exactSet(baselineArtifacts.map((artifact) => artifact.id),
    artifacts.map((artifact) => artifact.id), 'contract baseline artifact IDs');

  const runner = requireObject(contract.runner, 'contract.runner');
  exactKeys(runner, [
    'provider', 'operating_system', 'architecture', 'required_run_attempt', 'jobs',
  ], 'contract.runner');
  requireCondition(runner.provider === 'github-actions' &&
    runner.operating_system === 'ubuntu-24.04' && runner.architecture === 'amd64' &&
    runner.required_run_attempt === '1', 'contract runner identity changed');
  const jobs = uniqueStrings(runner.jobs, 'contract.runner.jobs');
  requireCondition(jobs.length > 0, 'contract runner jobs must not be empty');
  validatePowerless(contract.authority, 'contract.authority');
  return {artifacts, baselineArtifacts, jobs};
}

function parseSemver(tag, label) {
  const match = TAG.exec(tag);
  requireCondition(match !== null, `${label} must be a strict v-prefixed semantic version`);
  const prerelease = match[4]?.split('.') ?? [];
  requireCondition(prerelease.every((part) =>
    !/^[0-9]+$/u.test(part) || part === '0' || !part.startsWith('0')),
  `${label} must not contain a zero-prefixed numeric prerelease identifier`);
  return {
    major: match[1],
    minor: match[2],
    patch: match[3],
    prerelease,
  };
}

function compareNumericText(left, right) {
  if (left.length !== right.length) return left.length > right.length ? 1 : -1;
  if (left === right) return 0;
  return left > right ? 1 : -1;
}

function compareSemver(left, right) {
  for (const field of ['major', 'minor', 'patch']) {
    const comparison = compareNumericText(left[field], right[field]);
    if (comparison !== 0) return comparison;
  }
  if (left.prerelease.length === 0 || right.prerelease.length === 0) {
    if (left.prerelease.length === right.prerelease.length) return 0;
    return left.prerelease.length === 0 ? 1 : -1;
  }
  const length = Math.max(left.prerelease.length, right.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = left.prerelease[index];
    const rightPart = right.prerelease[index];
    if (leftPart === undefined || rightPart === undefined) {
      return leftPart === rightPart ? 0 : leftPart === undefined ? -1 : 1;
    }
    if (leftPart === rightPart) continue;
    const leftNumeric = /^[0-9]+$/u.test(leftPart);
    const rightNumeric = /^[0-9]+$/u.test(rightPart);
    if (leftNumeric && rightNumeric) return compareNumericText(leftPart, rightPart);
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return leftPart > rightPart ? 1 : -1;
  }
  return 0;
}

function validateIntake(root, label) {
  assertDirectory(root, `${label} intake root`);
  const receiptPath = path.join(root, 'candidate-intake-receipt.json');
  const receiptRecord = readCanonicalJson(receiptPath, `${label} intake receipt`);
  const receipt = receiptRecord.value;
  exactKeys(receipt, [
    'schema_version', 'classification', 'product', 'created_at', 'contract',
    'source', 'artifacts', 'files', 'authority',
  ], `${label} intake receipt`);
  requireCondition(receipt.schema_version === 1 &&
    receipt.classification === INTAKE_CLASSIFICATION &&
    receipt.product === 'RouteSphere BonVoyage API Gateway',
  `${label} intake receipt identity changed`);
  canonicalTimestamp(receipt.created_at, `${label} intake created_at`);
  exactKeys(receipt.source, ['repository', 'commit', 'tag', 'dirty'],
    `${label} intake source`);
  requireCondition(receipt.source.repository === PUBLIC_REPOSITORY &&
    COMMIT.test(receipt.source.commit) && TAG.test(receipt.source.tag) &&
    receipt.source.dirty === false, `${label} intake source is not exact public source`);
  validatePowerless(receipt.authority, `${label} intake authority`);

  const files = requireArray(receipt.files, `${label} intake files`).map((value, index) => {
    const fileLabel = `${label} intake files[${index}]`;
    exactKeys(value, ['path', 'bytes', 'sha256'], fileLabel);
    return {
      path: safeRelative(value.path, `${fileLabel}.path`),
      bytes: requireInteger(value.bytes, `${fileLabel}.bytes`),
      sha256: requireSha256(value.sha256, `${fileLabel}.sha256`),
    };
  });
  requireCondition(new Set(files.map((file) => file.path)).size === files.length,
    `${label} intake files contain duplicates`);
  const actual = inventory(root, new Set(['candidate-intake-receipt.json']));
  requireCondition(JSON.stringify(actual) === JSON.stringify(files),
    `${label} intake tree does not match its retained inventory`);
  const filesByPath = new Map(files.map((file) => [file.path, file]));
  const legacyRuntimeIdentityAbsence = validateLegacyRuntimeIdentityAbsence(
    root, filesByPath, label);

  exactKeys(receipt.contract, ['path', 'bytes', 'sha256'], `${label} intake contract`);
  const intakeContractPath = safeRelative(
    receipt.contract.path, `${label} intake contract.path`);
  const retainedContract = filesByPath.get(intakeContractPath);
  requireCondition(retainedContract?.bytes === requireInteger(
    receipt.contract.bytes, `${label} intake contract.bytes`) &&
    retainedContract?.sha256 === requireSha256(
      receipt.contract.sha256, `${label} intake contract.sha256`),
  `${label} intake contract is missing or changed`);

  const artifacts = requireArray(receipt.artifacts, `${label} intake artifacts`).map(
    (value, index) => {
      const artifactLabel = `${label} intake artifacts[${index}]`;
      const artifact = requireObject(value, artifactLabel);
      const id = requireString(artifact.id, `${artifactLabel}.id`);
      const kind = requireString(artifact.kind, `${artifactLabel}.kind`);
      const artifactPath = safeRelative(artifact.path, `${artifactLabel}.path`);
      const bytes = requireInteger(artifact.bytes, `${artifactLabel}.bytes`);
      const sha256 = requireSha256(artifact.sha256, `${artifactLabel}.sha256`);
      requireCondition(artifact.platform === 'linux/amd64',
        `${artifactLabel}.platform must be linux/amd64`);
      requireCondition(RUN_ID.test(artifact.hosted_run_id ?? ''),
        `${artifactLabel}.hosted_run_id must be positive`);
      const retained = filesByPath.get(artifactPath);
      requireCondition(retained?.bytes === bytes && retained?.sha256 === sha256,
        `${artifactLabel} does not bind exact retained bytes`);
      return {id, kind, path: artifactPath, bytes, sha256,
        hostedRunId: artifact.hosted_run_id};
    });
  requireCondition(artifacts.length === 2 &&
    new Set(artifacts.map((artifact) => artifact.id)).size === artifacts.length,
  `${label} intake must contain two unique artifacts`);
  return {
    receiptSha256: receiptRecord.sha256,
    source: receipt.source,
    artifacts,
    legacyRuntimeIdentityAbsence,
  };
}

function artifactSummary(intake) {
  return intake.artifacts.map(({id, kind, bytes, sha256}) => ({id, kind, bytes, sha256}));
}

function expectedIntakeSummary(intake) {
  return {
    intake_receipt_sha256: intake.receiptSha256,
    source: intake.source,
    artifacts: artifactSummary(intake),
  };
}

function validateBaseline(contract, contractInfo, baseline) {
  requireCondition(baseline.source.commit === contract.baseline.source.commit &&
    baseline.source.tag === contract.baseline.source.tag,
  'baseline intake source does not match the pinned lifecycle baseline');
  const expectedRuns = new Map([
    ['gateway-deb-linux-amd64', contract.baseline.hosted_runs.debian],
    ['gateway-oci-linux-amd64', contract.baseline.hosted_runs.oci],
  ]);
  const expectedArtifacts = new Map(
    contractInfo.baselineArtifacts.map((artifact) => [artifact.id, artifact]));
  exactSet(baseline.artifacts.map((artifact) => artifact.id),
    expectedArtifacts.keys(), 'baseline intake artifact IDs');
  for (const artifact of baseline.artifacts) {
    const expected = expectedArtifacts.get(artifact.id);
    requireCondition(artifact.kind === expected.kind && artifact.bytes === expected.bytes &&
      artifact.sha256 === expected.sha256 &&
      artifact.hostedRunId === expectedRuns.get(artifact.id),
    `baseline artifact ${artifact.id} does not match the pinned hosted identity`);
  }
  const legacyBaseline = contract.baseline.source.commit ===
    LEGACY_RUNTIME_IDENTITY_BASELINE.commit &&
    contract.baseline.source.tag === LEGACY_RUNTIME_IDENTITY_BASELINE.tag &&
    contract.baseline.hosted_runs.debian ===
      LEGACY_RUNTIME_IDENTITY_BASELINE.debian_run_id &&
    contract.baseline.hosted_runs.oci === LEGACY_RUNTIME_IDENTITY_BASELINE.oci_run_id;
  if (legacyBaseline) {
    const evidence = requireObject(baseline.legacyRuntimeIdentityAbsence,
      'baseline legacy runtime identity evidence');
    requireCondition(JSON.stringify(evidence.source) === JSON.stringify(baseline.source) &&
      evidence.hosted_runs.debian === contract.baseline.hosted_runs.debian &&
      evidence.hosted_runs.oci === contract.baseline.hosted_runs.oci,
    'baseline legacy runtime identity evidence does not match the pinned lifecycle baseline');
  } else {
    requireCondition(baseline.legacyRuntimeIdentityAbsence === null,
      'legacy runtime identity evidence is only valid for the exact pinned lifecycle baseline');
  }
}

function validateCandidate(contractInfo, baseline, candidate) {
  requireCondition(candidate.legacyRuntimeIdentityAbsence === null,
    'candidate intake must not use the legacy runtime identity exception');
  exactSet(candidate.artifacts.map((artifact) => artifact.id),
    contractInfo.artifacts.map((artifact) => artifact.id), 'candidate artifact IDs');
  const specifications = new Map(
    contractInfo.artifacts.map((artifact) => [artifact.id, artifact]));
  const baselineArtifacts = new Map(
    baseline.artifacts.map((artifact) => [artifact.id, artifact]));
  for (const artifact of candidate.artifacts) {
    requireCondition(artifact.kind === specifications.get(artifact.id).kind,
      `candidate artifact ${artifact.id} kind changed`);
    requireCondition(artifact.sha256 !== baselineArtifacts.get(artifact.id).sha256,
      `candidate artifact ${artifact.id} must differ from the rollback baseline`);
  }
  requireCondition(candidate.source.commit !== baseline.source.commit,
    'candidate source commit must differ from the rollback baseline');
  requireCondition(compareSemver(
    parseSemver(candidate.source.tag, 'candidate tag'),
    parseSemver(baseline.source.tag, 'baseline tag')) > 0,
  'candidate tag must be newer than the rollback baseline tag');
}

function validateObservation({contract, contractRecord, contractInfo,
  candidate, baseline, evidenceRoot}) {
  const observationPath = path.join(evidenceRoot, 'observation.json');
  const observationRecord = readCanonicalJson(
    observationPath, 'lifecycle observation');
  const observation = observationRecord.value;
  exactKeys(observation, [
    'schema_version', 'classification', 'outcome', 'captured_at', 'contract',
    'candidate', 'baseline', 'runner', 'artifacts', 'authority',
  ], 'lifecycle observation');
  requireCondition(observation.schema_version === 1 &&
    observation.classification === OBSERVATION_CLASSIFICATION &&
    observation.outcome === 'passed', 'lifecycle observation did not pass');
  canonicalTimestamp(observation.captured_at, 'lifecycle observation captured_at');
  exactKeys(observation.contract, ['path', 'sha256'], 'observation.contract');
  requireCondition(observation.contract.path ===
    'packaging/release/oss-artifact-lifecycle-contract.json' &&
    observation.contract.sha256 === contractRecord.sha256,
  'lifecycle observation does not bind the exact contract');
  requireCondition(JSON.stringify(observation.candidate) ===
    JSON.stringify(expectedIntakeSummary(candidate)),
  'lifecycle observation candidate binding changed');
  requireCondition(JSON.stringify(observation.baseline) ===
    JSON.stringify(expectedIntakeSummary(baseline)),
  'lifecycle observation baseline binding changed');

  exactKeys(observation.runner, [
    'provider', 'operating_system', 'architecture', 'run_id', 'run_attempt', 'jobs',
  ], 'observation.runner');
  requireCondition(observation.runner.provider === contract.runner.provider &&
    observation.runner.operating_system === contract.runner.operating_system &&
    observation.runner.architecture === contract.runner.architecture &&
    RUN_ID.test(observation.runner.run_id ?? '') &&
    observation.runner.run_attempt === contract.runner.required_run_attempt &&
    JSON.stringify(observation.runner.jobs) === JSON.stringify(contractInfo.jobs),
  'lifecycle observation runner identity changed');
  validatePowerless(observation.authority, 'observation.authority');

  const actualEvidence = inventory(
    evidenceRoot, new Set(['observation.json']), MAX_EVIDENCE_BYTES);
  const evidenceByPath = new Map(actualEvidence.map((record) => [record.path, record]));
  const boundEvidence = new Set();
  const candidateArtifacts = new Map(
    candidate.artifacts.map((artifact) => [artifact.id, artifact]));
  const baselineArtifacts = new Map(
    baseline.artifacts.map((artifact) => [artifact.id, artifact]));
  const observations = requireArray(observation.artifacts, 'observation.artifacts');
  exactSet(observations.map((artifact) => artifact.id),
    contractInfo.artifacts.map((artifact) => artifact.id), 'observation artifact IDs');
  const observationsById = new Map(observations.map((artifact) => [artifact.id, artifact]));

  for (const specification of contractInfo.artifacts) {
    const artifact = requireObject(
      observationsById.get(specification.id), `observation artifact ${specification.id}`);
    exactKeys(artifact, [
      'id', 'kind', 'transition', 'candidate_sha256', 'baseline_sha256', 'phases',
    ], `observation artifact ${specification.id}`);
    requireCondition(artifact.kind === specification.kind &&
      artifact.transition === specification.transition &&
      artifact.candidate_sha256 === candidateArtifacts.get(specification.id).sha256 &&
      artifact.baseline_sha256 === baselineArtifacts.get(specification.id).sha256,
    `observation artifact ${specification.id} identity changed`);
    const phases = requireArray(
      artifact.phases, `observation artifact ${specification.id}.phases`);
    requireCondition(phases.length === specification.phases.length,
      `observation artifact ${specification.id} phase count changed`);
    for (let index = 0; index < specification.phases.length; index += 1) {
      const expected = specification.phases[index];
      const phaseLabel = `observation artifact ${specification.id}.phases[${index}]`;
      const phase = requireObject(phases[index], phaseLabel);
      exactKeys(phase, ['id', 'status', 'checks', 'evidence'], phaseLabel);
      requireCondition(phase.id === expected.id && phase.status === 'PASS',
        `${phaseLabel} did not record PASS for ${expected.id}`);
      exactKeys(phase.checks, expected.requiredChecks, `${phaseLabel}.checks`);
      for (const check of expected.requiredChecks) {
        requireCondition(phase.checks[check] === true,
          `${phaseLabel}.checks.${check} must be true`);
      }
      const evidence = requireArray(phase.evidence, `${phaseLabel}.evidence`);
      requireCondition(evidence.length > 0, `${phaseLabel} must bind evidence`);
      for (const [evidenceIndex, value] of evidence.entries()) {
        const evidenceLabel = `${phaseLabel}.evidence[${evidenceIndex}]`;
        const item = requireObject(value, evidenceLabel);
        exactKeys(item, ['path', 'bytes', 'sha256'], evidenceLabel);
        const evidencePath = safeRelative(item.path, `${evidenceLabel}.path`);
        requireCondition(evidencePath.startsWith('raw/'),
          `${evidenceLabel}.path must remain under raw/`);
        requireCondition(!boundEvidence.has(evidencePath),
          `lifecycle evidence path ${evidencePath} is bound more than once`);
        const retained = evidenceByPath.get(evidencePath);
        requireCondition(retained?.bytes === requireInteger(item.bytes, `${evidenceLabel}.bytes`) &&
          retained?.sha256 === requireSha256(item.sha256, `${evidenceLabel}.sha256`),
        `lifecycle evidence path ${evidencePath} is missing or changed`);
        boundEvidence.add(evidencePath);
      }
    }
  }
  exactSet(boundEvidence, evidenceByPath.keys(), 'bound lifecycle evidence paths');
  return {observation, observationSha256: observationRecord.sha256};
}

export function verifyArtifactLifecycle({
  contractPath = DEFAULT_CONTRACT,
  candidateRoot,
  baselineRoot,
  evidenceRoot,
  allowUnpinnedContractForTests = false,
}) {
  const resolvedContract = path.resolve(contractPath);
  requireCondition(allowUnpinnedContractForTests || resolvedContract === DEFAULT_CONTRACT,
    'production verification uses the canonical lifecycle contract');
  const contractRecord = readCanonicalJson(resolvedContract, 'lifecycle contract');
  const contract = contractRecord.value;
  const contractInfo = validateContract(contract);
  const baseline = validateIntake(path.resolve(baselineRoot), 'baseline');
  const candidate = validateIntake(path.resolve(candidateRoot), 'candidate');
  validateBaseline(contract, contractInfo, baseline);
  validateCandidate(contractInfo, baseline, candidate);
  const accepted = validateObservation({
    contract,
    contractRecord,
    contractInfo,
    candidate,
    baseline,
    evidenceRoot: path.resolve(evidenceRoot),
  });
  return {
    outcome: 'verified-artifact-lifecycle',
    source_commit: candidate.source.commit,
    source_tag: candidate.source.tag,
    baseline_commit: baseline.source.commit,
    baseline_tag: baseline.source.tag,
    artifacts: artifactSummary(candidate),
    contract_sha256: contractRecord.sha256,
    observation_sha256: accepted.observationSha256,
    lifecycle_qualified: true,
    release_admitted: false,
    publishable: false,
  };
}

function parseArguments(argv) {
  const options = {};
  const mapping = {
    '--contract': 'contractPath',
    '--candidate': 'candidateRoot',
    '--baseline': 'baselineRoot',
    '--evidence': 'evidenceRoot',
  };
  for (let index = 0; index < argv.length; index += 2) {
    const key = mapping[argv[index]];
    requireCondition(key !== undefined && options[key] === undefined &&
      argv[index + 1] !== undefined, `unsupported, duplicate or incomplete argument ${argv[index]}`);
    options[key] = argv[index + 1];
  }
  options.contractPath ??= DEFAULT_CONTRACT;
  requireCondition(options.candidateRoot && options.baselineRoot && options.evidenceRoot,
    '--candidate, --baseline and --evidence are required');
  return options;
}

if (fileURLToPath(import.meta.url) === path.resolve(process.argv[1] ?? '')) {
  try {
    const result = verifyArtifactLifecycle(parseArguments(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`OSS artifact lifecycle verification rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}
