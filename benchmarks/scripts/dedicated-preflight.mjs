#!/usr/bin/env node

import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath, pathToFileURL} from 'node:url';

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
export const REPOSITORY_ROOT = path.resolve(SCRIPT_DIRECTORY, '..', '..');
const require = createRequire(path.join(REPOSITORY_ROOT, 'package.json'));
const Ajv2020 = require('ajv/dist/2020').default;
const addFormats = require('ajv-formats');
const yaml = require('js-yaml');

export const CLAIM_BOUNDARY =
  'Pre-allocation engineering evidence only; no dedicated-host performance, ' +
  'production-readiness, competitive, capacity, or marketing claim is authorized.';

export const REQUIRED_ARTIFACT_IDS = [
  'bonvoyage',
  'controlled-upstream',
  'envoy',
  'haproxy',
  'load-generator',
  'metrics-store',
  'nginx',
  'sbom-generator',
  'telemetry-collector',
  'vulnerability-scanner',
];

export const REQUIRED_VALIDATION_CHECK_IDS = [
  'api-contracts',
  'asan-ubsan',
  'comparator-qualification',
  'control-plane-tests',
  'dataplane-release-tests',
  'host-tune-tests',
  'http2-fuzz',
  'phase3-integration',
  'project-validation',
  'retained-evidence',
  'runtime-sbom-scan',
  'static-analysis',
  'upstream-http1-fuzz',
];

export const VALIDATION_RUNTIME_ENVIRONMENT_NAMES = [
  'BONVOYAGE_BUILD_JOBS',
  'BONVOYAGE_BUILD_PLATFORM',
  'BONVOYAGE_DATAPLANE_IMAGE',
  'BONVOYAGE_DEDICATED_ARTIFACT_LOCK',
  'BONVOYAGE_DEDICATED_REMOTE_REF',
  'BONVOYAGE_LOCKED_DATAPLANE_IMAGE_ID',
  'BONVOYAGE_UPSTREAM_HTTP1_CLIENT',
];

const RUNTIME_CRITICAL_PATHS = [
  'CMakeLists.txt',
  'api',
  'config',
  'control-plane/cmd/bonvoyage-control-plane',
  'control-plane/go.mod',
  'control-plane/go.sum',
  'control-plane/internal/snapshot',
  'dataplane',
  'deploy/docker/bonvoyage',
  'deploy/docker/control-plane',
  'deploy/docker/upstream',
  'packaging/systemd/bonvoyage.service',
  'scripts/build-dataplane-container.sh',
  'scripts/phase3-multi-hour-hardening.sh',
  'tests/fixtures/grpc-unary',
  'tests/fixtures/phase3-composite-hardening.yaml',
  'third_party',
];

const SCHEMAS = {
  artifactLock: 'benchmarks/spec/dedicated-artifact-lock.schema.json',
  campaign: 'benchmarks/spec/dedicated-campaign.schema.json',
  environmentReport: 'benchmarks/spec/dedicated-environment-report.schema.json',
  environmentReview: 'benchmarks/spec/dedicated-environment-review.schema.json',
  environmentTopology: 'benchmarks/spec/dedicated-environment-topology.schema.json',
  preflight: 'benchmarks/spec/dedicated-preflight.schema.json',
  productLock: 'benchmarks/spec/product-lock.schema.json',
  productQualification: 'benchmarks/spec/product-qualification.schema.json',
  tuningPolicy: 'deploy/tuning/host-tuning-policy.schema.json',
  validationCheck: 'benchmarks/spec/dedicated-validation-check.schema.json',
  validationPlan: 'benchmarks/spec/dedicated-validation-plan.schema.json',
  validationReceipt: 'benchmarks/spec/dedicated-validation-receipt.schema.json',
};

const validatorCache = new Map();

function slashPath(value) {
  return value.split(path.sep).join('/');
}

export function digestBuffer(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function sha256File(absolutePath) {
  return digestBuffer(fs.readFileSync(absolutePath));
}

export function stableJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${stableJson(value[key])}`,
    );
    return `{${entries.join(',')}}`;
  }
  return JSON.stringify(value);
}

function readJson(absolutePath) {
  return JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
}

export function schemaErrors(schemaRelativePath, document) {
  let validator = validatorCache.get(schemaRelativePath);
  if (!validator) {
    const ajv = new Ajv2020({allErrors: true, strict: true});
    addFormats(ajv);
    validator = ajv.compile(
      readJson(path.join(REPOSITORY_ROOT, schemaRelativePath)),
    );
    validatorCache.set(schemaRelativePath, validator);
  }
  if (validator(document)) {
    return [];
  }
  return validator.errors.map(
    (error) => `${error.instancePath || '/'} ${error.message}`,
  );
}

function resolveRepositoryFile(value, label) {
  const absolutePath = path.isAbsolute(value)
    ? path.resolve(value)
    : path.resolve(REPOSITORY_ROOT, value);
  const relativePath = path.relative(REPOSITORY_ROOT, absolutePath);
  if (relativePath === '' || relativePath.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relativePath)) {
    throw new Error(`${label} must be a file below the repository root`);
  }
  if (!fs.existsSync(absolutePath) || !fs.statSync(absolutePath).isFile()) {
    throw new Error(`${label} does not exist: ${value}`);
  }
  return {absolutePath, path: slashPath(relativePath)};
}

export function repositoryFileReference(value, label) {
  const resolved = resolveRepositoryFile(value, label);
  return {...resolved, sha256: sha256File(resolved.absolutePath)};
}

function runGit(arguments_, {allowFailure = false} = {}) {
  try {
    return execFileSync('git', arguments_, {
      cwd: REPOSITORY_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', allowFailure ? 'ignore' : 'pipe'],
    }).trim();
  } catch (error) {
    if (allowFailure) {
      return null;
    }
    const detail = error.stderr?.toString().trim();
    throw new Error(detail || `git ${arguments_.join(' ')} failed`);
  }
}

function listFiles(relativeDirectory, predicate) {
  const root = path.join(REPOSITORY_ROOT, relativeDirectory);
  if (!fs.existsSync(root)) {
    return [];
  }
  const pending = [root];
  const files = [];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const absolutePath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        pending.push(absolutePath);
      } else if (entry.isFile() && predicate(absolutePath)) {
        files.push(slashPath(path.relative(REPOSITORY_ROOT, absolutePath)));
      }
    }
  }
  return files.sort();
}

function bindingId(prefix, relativePath) {
  return `${prefix}:${relativePath}`
    .toLowerCase()
    .replace(/\.ya?ml$/u, '')
    .replace(/[^a-z0-9._:-]+/gu, '.');
}

function uniqueIds(entries, label) {
  const seen = new Set();
  const duplicates = [];
  for (const entry of entries) {
    if (seen.has(entry.id)) {
      duplicates.push(entry.id);
    }
    seen.add(entry.id);
  }
  return duplicates.length === 0
    ? []
    : [`${label} repeats IDs: ${[...new Set(duplicates)].sort().join(', ')}`];
}

function sameIds(actual, expected) {
  return [...actual].sort().join('\0') === [...expected].sort().join('\0');
}

function sameBindings(actual, expected) {
  const normalized = (entries) => [...entries]
    .sort((left, right) => left.id.localeCompare(right.id))
    .map(({id, path: filePath, sha256}) => ({id, path: filePath, sha256}));
  return stableJson(normalized(actual)) === stableJson(normalized(expected));
}

function verifyEvidenceReference(reference) {
  const file = repositoryFileReference(reference.path, 'evidence path');
  return file.sha256 === reference.sha256
    ? []
    : [`${reference.path} does not match its retained SHA-256 digest`];
}

export function inspectArtifactLockDocument(document, {
  campaignId,
  sourceCommit,
  bindings,
  verifySboms = false,
} = {}) {
  const errors = schemaErrors(SCHEMAS.artifactLock, document);
  if (errors.length > 0) {
    return {valid: false, errors};
  }

  errors.push(...uniqueIds(document.input_bindings, 'artifact input bindings'));
  errors.push(...uniqueIds(document.artifacts, 'artifacts'));
  errors.push(...uniqueIds(document.evidence, 'artifact evidence'));
  const artifactIds = document.artifacts.map(({id}) => id);
  const missingArtifacts = REQUIRED_ARTIFACT_IDS.filter(
    (artifactId) => !artifactIds.includes(artifactId),
  );
  if (missingArtifacts.length > 0) {
    errors.push(`artifact scope is missing: ${missingArtifacts.join(', ')}`);
  }
  if (campaignId && document.campaign_id !== campaignId) {
    errors.push('artifact lock campaign does not match the selected campaign');
  }
  if (sourceCommit && document.source_commit !== sourceCommit) {
    errors.push('artifact lock source commit does not match HEAD');
  }
  if (bindings && !sameBindings(document.input_bindings, bindings)) {
    errors.push('artifact lock input bindings differ from the current campaign inputs');
  }

  const gatewayIds = ['bonvoyage', 'envoy', 'haproxy', 'nginx'];
  for (const gatewayId of gatewayIds) {
    const artifact = document.artifacts.find(({id}) => id === gatewayId);
    if (artifact && !artifact.files.some(({purpose}) => purpose === 'executable')) {
      errors.push(`${gatewayId} lacks an executable identity`);
    }
  }
  const bonvoyage = document.artifacts.find(({id}) => id === 'bonvoyage');
  if (!['seastar-reference', 'llhttp-candidate'].includes(
    bonvoyage?.metadata?.upstream_http1_client,
  )) {
    errors.push('BonVoyage artifact lacks a supported upstream HTTP/1 client identity');
  }
  const sbomFormats = document.sboms
    .filter(({artifact_id: artifactId}) => artifactId === 'bonvoyage')
    .map(({format}) => format);
  if (!sameIds(sbomFormats, ['CycloneDX JSON', 'SPDX JSON'])) {
    errors.push('BonVoyage must retain both CycloneDX JSON and SPDX JSON SBOMs');
  }
  const requiredEvidence = [
    'comparator-qualification',
    'runtime-dependency-environment',
    'runtime-evidence-checksums',
    'runtime-vulnerability-summary',
  ];
  const evidenceIds = document.evidence.map(({id}) => id);
  for (const requiredId of requiredEvidence) {
    if (!evidenceIds.includes(requiredId)) {
      errors.push(`artifact lock evidence is missing ${requiredId}`);
    }
  }
  if (verifySboms) {
    for (const sbom of document.sboms) {
      try {
        errors.push(...verifyEvidenceReference(sbom));
      } catch (error) {
        errors.push(error.message);
      }
    }
    for (const evidence of document.evidence) {
      try {
        errors.push(...verifyEvidenceReference(evidence));
      } catch (error) {
        errors.push(error.message);
      }
    }
    errors.push(...inspectLockedSecurityEvidence(document));
    errors.push(...inspectLockedComparatorEvidence(document));
  }
  return {valid: errors.length === 0, errors};
}

function parseKeyValueFile(absolutePath) {
  const values = {};
  for (const line of fs.readFileSync(absolutePath, 'utf8').split('\n')) {
    if (!line || !line.includes('=')) {
      continue;
    }
    const index = line.indexOf('=');
    values[line.slice(0, index)] = line.slice(index + 1);
  }
  return values;
}

function verifyNamedChecksumManifest(absolutePath) {
  const directory = path.dirname(absolutePath);
  const errors = [];
  const lines = fs.readFileSync(absolutePath, 'utf8')
    .split('\n')
    .filter(Boolean);
  if (lines.length === 0) {
    return ['runtime evidence checksum manifest is empty'];
  }
  for (const line of lines) {
    const match = /^([a-f0-9]{64})\s+\*?(.+)$/u.exec(line);
    if (!match) {
      errors.push(`invalid runtime evidence checksum line: ${line}`);
      continue;
    }
    const absoluteEvidencePath = path.resolve(directory, match[2].replace(/^\.\//u, ''));
    const relativePath = path.relative(directory, absoluteEvidencePath);
    if (relativePath.startsWith(`..${path.sep}`) || path.isAbsolute(relativePath) ||
        !fs.existsSync(absoluteEvidencePath)) {
      errors.push(`runtime evidence checksum path is missing or unsafe: ${match[2]}`);
    } else if (sha256File(absoluteEvidencePath) !== match[1]) {
      errors.push(`runtime evidence checksum mismatch: ${match[2]}`);
    }
  }
  return errors;
}

function verifyRepositoryChecksumManifest(absolutePath) {
  const errors = [];
  const lines = fs.readFileSync(absolutePath, 'utf8')
    .split('\n')
    .filter(Boolean);
  if (lines.length === 0) {
    return ['runtime source checksum manifest is empty'];
  }
  for (const line of lines) {
    const match = /^([a-f0-9]{64})\s+\*?(.+)$/u.exec(line);
    if (!match) {
      errors.push(`invalid runtime source checksum line: ${line}`);
      continue;
    }
    try {
      const source = resolveRepositoryFile(match[2], 'runtime source checksum');
      if (sha256File(source.absolutePath) !== match[1]) {
        errors.push(`runtime source checksum mismatch: ${match[2]}`);
      }
    } catch (error) {
      errors.push(error.message);
    }
  }
  return errors;
}

function evidenceById(document, id) {
  return document.evidence.find((entry) => entry.id === id);
}

export function inspectRuntimeSecurityIdentity(values, {sourceCommit, artifact}) {
  if (!artifact) return ['runtime dependency evidence has no locked BonVoyage artifact'];
  const fields = [
    ['source_commit', sourceCommit, 'source commit differs from the lock'],
    ['source_dirty', 'false', 'was not captured from a clean tree'],
    ['runtime_platform', 'linux/amd64', 'is not Linux AMD64'],
    ['runtime_image_id', artifact.image_digest, 'image differs from locked BonVoyage'],
    ['upstream_http1_client', artifact.metadata?.upstream_http1_client, 'build variant differs from locked BonVoyage'],
    ['runtime_scan_target', `docker:${artifact.image_digest}`, 'scan target is not the locked Docker image'],
  ];
  return fields.filter(([name, expected]) => !expected || values[name] !== expected)
    .map(([, , message]) => `runtime dependency evidence ${message}`);
}

function inspectLockedSecurityEvidence(document) {
  const errors = [];
  const environment = evidenceById(document, 'runtime-dependency-environment');
  const checksums = evidenceById(document, 'runtime-evidence-checksums');
  const vulnerability = evidenceById(document, 'runtime-vulnerability-summary');
  if (!environment || !checksums || !vulnerability) {
    return errors;
  }
  try {
    const environmentFile = resolveRepositoryFile(
      environment.path,
      'runtime dependency environment',
    );
    const values = parseKeyValueFile(environmentFile.absolutePath);
    const bonvoyage = document.artifacts.find(({id}) => id === 'bonvoyage');
    errors.push(...inspectRuntimeSecurityIdentity(values, {
      sourceCommit: document.source_commit, artifact: bonvoyage,
    }));

    const vulnerabilityFile = resolveRepositoryFile(
      vulnerability.path,
      'runtime vulnerability summary',
    );
    const summary = readJson(vulnerabilityFile.absolutePath);
    if (summary.gate?.passed !== true || (summary.blocking?.length ?? 0) !== 0) {
      errors.push('runtime vulnerability evidence does not pass its blocking policy');
    }

    const checksumFile = resolveRepositoryFile(
      checksums.path,
      'runtime evidence checksum manifest',
    );
    errors.push(...verifyNamedChecksumManifest(checksumFile.absolutePath));
    const sourceChecksums = path.join(
      path.dirname(checksumFile.absolutePath),
      'source-checksums.sha256',
    );
    if (!fs.existsSync(sourceChecksums)) {
      errors.push('runtime source checksum manifest is missing');
    } else {
      errors.push(...verifyRepositoryChecksumManifest(sourceChecksums));
    }
  } catch (error) {
    errors.push(error.message);
  }
  return errors;
}

function inspectLockedComparatorEvidence(document) {
  const evidence = evidenceById(document, 'comparator-qualification');
  if (!evidence) {
    return [];
  }
  const errors = [];
  try {
    const file = resolveRepositoryFile(evidence.path, 'comparator qualification');
    const qualification = readJson(file.absolutePath);
    errors.push(...schemaErrors(SCHEMAS.productQualification, qualification));
    if (qualification.architecture !== 'x86_64' || qualification.passed !== true) {
      errors.push('locked comparator qualification is not passing AMD64 evidence');
    }
    if (!sameIds(
      qualification.products?.map(({name}) => name) ?? [],
      ['envoy', 'haproxy', 'nginx'],
    )) {
      errors.push('locked comparator qualification does not contain the canonical set');
    }
    for (const product of qualification.products ?? []) {
      const artifact = document.artifacts.find(({id}) => id === product.name);
      const executable = artifact?.files.find(({purpose}) => purpose === 'executable');
      const configuration = artifact?.files.find(
        ({purpose}) => purpose === 'configuration',
      );
      if (!artifact || artifact.platform_digest !== product.image_manifest_digest ||
          executable?.sha256 !== product.executable_sha256 ||
          configuration?.sha256 !== product.config_sha256 || product.passed !== true) {
        errors.push(`${product.name} differs from its locked comparator qualification`);
      }
    }
  } catch (error) {
    errors.push(error.message);
  }
  return errors;
}

export function inspectValidationPlanDocument(document, {campaignId} = {}) {
  const errors = schemaErrors(SCHEMAS.validationPlan, document);
  if (errors.length > 0) {
    return {valid: false, errors};
  }
  errors.push(...uniqueIds(document.checks, 'validation plan checks'));
  const checkIds = document.checks.map(({id}) => id);
  for (const requiredId of REQUIRED_VALIDATION_CHECK_IDS) {
    if (!checkIds.includes(requiredId)) {
      errors.push(`validation plan is missing ${requiredId}`);
    }
  }
  if (campaignId && document.campaign_id !== campaignId) {
    errors.push('validation plan campaign does not match the selected campaign');
  }
  const shellExecutables = new Set(['sh', 'bash', 'zsh', '/bin/sh', '/bin/bash']);
  for (const check of document.checks) {
    if (check.id === 'phase3-integration' &&
        (check.fixed_environment.BONVOYAGE_RC_TEST_CLIENT_USER !== '65532:65532' ||
         !/^ghcr\.io\/hatoo\/oha@sha256:[a-f0-9]{64}$/u.test(
           check.fixed_environment.BONVOYAGE_OHA_IMAGE ?? ''))) {
      errors.push('phase3-integration requires the pinned stock client and explicit non-root executor policy');
    }
    const names = [
      ...check.required_environment,
      ...check.derived_environment,
      ...Object.keys(check.fixed_environment),
    ];
    if (new Set(names).size !== names.length) {
      errors.push(`${check.id} repeats an environment name across sources`);
    }
    const reservedNames = names.filter(
      (name) => VALIDATION_RUNTIME_ENVIRONMENT_NAMES.includes(name),
    );
    if (reservedNames.length > 0) {
      errors.push(
        `${check.id} attempts to override controlled runtime environment: ` +
        reservedNames.join(', '),
      );
    }
    if (shellExecutables.has(check.command.argv[0])) {
      errors.push(`${check.id} must use an argv command rather than a shell interpreter`);
    }
  }
  return {valid: errors.length === 0, errors};
}

function environmentNames(check) {
  return [
    ...check.required_environment,
    ...check.derived_environment,
    ...Object.keys(check.fixed_environment),
    ...VALIDATION_RUNTIME_ENVIRONMENT_NAMES,
  ].sort();
}

export function validationEvidencePath(name, checkDirectory) {
  return path.posix.join(
    checkDirectory,
    'evidence',
    name.toLowerCase().replace(/^bonvoyage_/u, '').replace(/_/gu, '-'),
  );
}

export function inspectValidationCheckDocument(document, {
  campaignId,
  sourceCommit,
  remoteRef,
  artifactLock,
  validationPlan,
  planCheck,
  recordPath,
  verifyEvidence = false,
} = {}) {
  const errors = schemaErrors(SCHEMAS.validationCheck, document);
  if (errors.length > 0) {
    return {valid: false, errors};
  }
  if (campaignId && document.campaign_id !== campaignId) {
    errors.push('validation check campaign does not match');
  }
  if (sourceCommit && document.source_commit !== sourceCommit) {
    errors.push('validation check source commit does not match');
  }
  if (remoteRef && document.remote_ref !== remoteRef) {
    errors.push('validation check remote ref does not match');
  }
  for (const [label, actual, expected] of [
    ['artifact lock path', document.artifact_lock.path, artifactLock?.path],
    ['artifact lock digest', document.artifact_lock.sha256, artifactLock?.sha256],
    ['validation plan path', document.validation_plan.path, validationPlan?.path],
    ['validation plan digest', document.validation_plan.sha256, validationPlan?.sha256],
  ]) {
    if (expected && actual !== expected) {
      errors.push(`validation check ${label} does not match`);
    }
  }
  const lockedRuntimeDigest = artifactLock?.document?.artifacts
    ?.find(({id}) => id === 'bonvoyage')?.image_digest;
  if (planCheck) {
    if (planCheck.id === 'phase3-integration' &&
        planCheck.fixed_environment.BONVOYAGE_OHA_IMAGE !==
          artifactLock?.document?.artifacts?.find(({id}) => id === 'load-generator')?.image_reference) {
      errors.push('phase3-integration test client differs from the artifact lock');
    }
    if (document.check_id !== planCheck.id) {
      errors.push('validation check ID does not match its plan entry');
    }
    if (stableJson(document.command) !== stableJson(planCheck.command)) {
      errors.push(`${document.check_id} command differs from the validation plan`);
    }
    const actualNames = document.environment.map(({name}) => name).sort();
    if (!sameIds(actualNames, environmentNames(planCheck))) {
      errors.push(`${document.check_id} environment differs from the validation plan`);
    }
    for (const [name, value] of Object.entries(planCheck.fixed_environment)) {
      const recorded = document.environment.find((entry) => entry.name === name);
      if (recorded?.value_sha256 !== digestBuffer(value)) {
        errors.push(`${document.check_id} fixed environment ${name} differs`);
      }
    }
    const automaticValues = {
      BONVOYAGE_BUILD_JOBS: '2',
      BONVOYAGE_BUILD_PLATFORM: 'linux/amd64',
      BONVOYAGE_DATAPLANE_IMAGE: document.runtime_image.reference,
      BONVOYAGE_DEDICATED_ARTIFACT_LOCK: document.artifact_lock.path,
      BONVOYAGE_DEDICATED_REMOTE_REF: document.remote_ref,
      BONVOYAGE_LOCKED_DATAPLANE_IMAGE_ID: lockedRuntimeDigest,
      BONVOYAGE_UPSTREAM_HTTP1_CLIENT:
        artifactLock?.document?.artifacts?.find(({id}) => id === 'bonvoyage')
          ?.metadata?.upstream_http1_client,
    };
    for (const [name, value] of Object.entries(automaticValues)) {
      const recorded = document.environment.find((entry) => entry.name === name);
      if (!value || recorded?.value_sha256 !== digestBuffer(value)) {
        errors.push(`${document.check_id} controlled runtime environment ${name} differs`);
      }
    }
    if (recordPath) {
      const checkDirectory = path.posix.dirname(recordPath);
      for (const name of planCheck.derived_environment) {
        const recorded = document.environment.find((entry) => entry.name === name);
        const expected = validationEvidencePath(name, checkDirectory);
        if (recorded?.value_sha256 !== digestBuffer(expected)) {
          errors.push(`${document.check_id} derived environment ${name} differs`);
        }
      }
    }
  }
  if (lockedRuntimeDigest &&
      (document.runtime_image.image_digest_before !== lockedRuntimeDigest ||
       document.runtime_image.image_digest_after !== lockedRuntimeDigest)) {
    errors.push('validation check did not preserve the locked runtime image');
  }
  if (Date.parse(document.completed_at) < Date.parse(document.started_at)) {
    errors.push('validation check completion precedes its start');
  }
  if (verifyEvidence) {
    for (const evidence of document.evidence) {
      try {
        errors.push(...verifyEvidenceReference(evidence));
      } catch (error) {
        errors.push(error.message);
      }
    }
    if (document.check_id === 'phase3-integration') {
      try {
        if (!recordPath) throw new Error('test-client evidence requires the check record path');
        const client = artifactLock?.document?.artifacts?.find(({id}) => id === 'load-generator');
        const observations = ['before', 'after'].map(stage => {
          const expected = path.posix.join(path.posix.dirname(recordPath), 'evidence', `test-client-${stage}.json`);
          const reference = document.evidence.find(entry => entry.path === expected);
          if (!reference) throw new Error(`missing test-client ${stage} evidence`);
          const observation = readJson(resolveRepositoryFile(expected, 'test-client observation').absolutePath);
          if (!client || observation.policy !== 'stock-image-explicit-caller-uid-v1' ||
              observation.executor_user !== '65532:65532' ||
              observation.reference !== client.image_reference ||
              observation.image_digest !== client.image_digest ||
              observation.platform_digest !== client.platform_digest) {
            throw new Error(`test-client ${stage} evidence differs from the locked policy`);
          }
          return observation;
        });
        if (stableJson(observations[0]) !== stableJson(observations[1])) {
          throw new Error('test-client identity changed during validation');
        }
      } catch (error) {
        errors.push(error.message);
      }
    }
  }
  return {valid: errors.length === 0, errors};
}

export function inspectValidationReceiptDocument(document, {
  campaignId,
  sourceCommit,
  artifactLockPath,
  artifactLockSha256,
  remoteRef,
  verifyEvidence = false,
} = {}) {
  const errors = schemaErrors(SCHEMAS.validationReceipt, document);
  if (errors.length > 0) {
    return {valid: false, errors};
  }

  errors.push(...uniqueIds(document.checks, 'validation checks'));
  const checkIds = document.checks.map(({id}) => id);
  for (const requiredId of REQUIRED_VALIDATION_CHECK_IDS) {
    if (!checkIds.includes(requiredId)) {
      errors.push(`validation receipt is missing ${requiredId}`);
    }
  }
  if (campaignId && document.campaign_id !== campaignId) {
    errors.push('validation receipt campaign does not match the selected campaign');
  }
  if (sourceCommit && document.source_commit !== sourceCommit) {
    errors.push('validation receipt source commit does not match HEAD');
  }
  if (artifactLockPath && document.artifact_lock.path !== artifactLockPath) {
    errors.push('validation receipt references a different artifact-lock path');
  }
  if (artifactLockSha256 &&
      document.artifact_lock.sha256 !== artifactLockSha256) {
    errors.push('validation receipt references a different artifact-lock digest');
  }
  if (Date.parse(document.completed_at) < Date.parse(document.started_at)) {
    errors.push('validation receipt completion precedes its start');
  }
  if (verifyEvidence) {
    try {
      errors.push(...verifyEvidenceReference(document.artifact_lock));
      errors.push(...verifyEvidenceReference(document.validation_plan));
      const planFile = resolveRepositoryFile(
        document.validation_plan.path,
        'validation plan',
      );
      const plan = yaml.load(fs.readFileSync(planFile.absolutePath, 'utf8'));
      const planInspection = inspectValidationPlanDocument(plan, {
        campaignId: document.campaign_id,
      });
      errors.push(...planInspection.errors);
      const lockFile = resolveRepositoryFile(
        document.artifact_lock.path,
        'artifact lock',
      );
      const lockDocument = readJson(lockFile.absolutePath);
      const validationPlanBinding = lockDocument.input_bindings?.find(
        ({id}) => id === 'validation-plan',
      );
      if (!validationPlanBinding ||
          validationPlanBinding.path !== document.validation_plan.path ||
          validationPlanBinding.sha256 !== document.validation_plan.sha256) {
        errors.push('validation receipt plan differs from the artifact-lock binding');
      }
      const artifactContext = {
        path: document.artifact_lock.path,
        sha256: document.artifact_lock.sha256,
        document: lockDocument,
      };
      const planContext = {
        path: document.validation_plan.path,
        sha256: document.validation_plan.sha256,
      };
      for (const check of document.checks) {
        errors.push(...verifyEvidenceReference(check.record));
        for (const evidence of check.evidence) {
          errors.push(...verifyEvidenceReference(evidence));
        }
        const recordFile = resolveRepositoryFile(
          check.record.path,
          `validation record ${check.id}`,
        );
        const record = readJson(recordFile.absolutePath);
        const recordInspection = inspectValidationCheckDocument(record, {
          campaignId: document.campaign_id,
          sourceCommit: document.source_commit,
          remoteRef,
          artifactLock: artifactContext,
          validationPlan: planContext,
          planCheck: plan.checks.find(({id}) => id === check.id),
          recordPath: check.record.path,
          verifyEvidence: true,
        });
        errors.push(...recordInspection.errors);
        if (stableJson(check.evidence) !== stableJson(record.evidence)) {
          errors.push(`${check.id} receipt evidence differs from its check record`);
        }
      }
    } catch (error) {
      errors.push(error.message);
    }
  }
  return {valid: errors.length === 0, errors};
}

export function verifyChecksumManifest(directory) {
  const manifestPath = path.join(directory, 'checksums.sha256');
  if (!fs.existsSync(manifestPath)) {
    return {valid: false, entries: 0, error: 'checksums.sha256 is missing'};
  }
  const lines = fs.readFileSync(manifestPath, 'utf8')
    .split('\n')
    .filter((line) => line.length > 0);
  let entries = 0;
  const seen = new Set();
  const realDirectory = fs.realpathSync(directory);
  for (const line of lines) {
    // Both sha256sum filename forms are valid; containment is checked separately.
    const match = /^([a-f0-9]{64}) [ *](.+)$/u.exec(line);
    if (!match) {
      return {valid: false, entries, error: `invalid checksum line: ${line}`};
    }
    const absolutePath = path.resolve(directory, match[2]);
    const relativePath = path.relative(directory, absolutePath);
    if (path.isAbsolute(match[2]) || relativePath === '' || relativePath === '..' ||
        relativePath.startsWith(`..${path.sep}`) || path.isAbsolute(relativePath) ||
        seen.has(absolutePath) || !fs.existsSync(absolutePath) ||
        !fs.lstatSync(absolutePath).isFile()) {
      return {valid: false, entries, error: `unsafe or duplicate checksum path: ${match[2]}`};
    }
    const realRelative = path.relative(realDirectory, fs.realpathSync(absolutePath));
    if (realRelative === '..' || realRelative.startsWith(`..${path.sep}`) ||
        path.isAbsolute(realRelative) || sha256File(absolutePath) !== match[1]) {
      return {
        valid: false,
        entries,
        error: `checksum mismatch or unsafe path: ${match[2]}`,
      };
    }
    seen.add(absolutePath);
    entries += 1;
  }
  return {valid: entries > 0, entries};
}

function findLatestComparatorQualification() {
  const candidates = listFiles(
    'benchmarks/results/qualification',
    (absolutePath) => absolutePath.endsWith('.qualification.json'),
  ).reverse();
  for (const candidate of candidates) {
    try {
      const document = readJson(path.join(REPOSITORY_ROOT, candidate));
      if (document.architecture === 'x86_64' && document.passed === true) {
        return candidate;
      }
    } catch {
      // Invalid candidates are reported by project validation, not selected here.
    }
  }
  throw new Error('no passing AMD64 comparator qualification was found');
}

function resolveHardeningSummary(explicitPath) {
  if (explicitPath) {
    return explicitPath;
  }
  const pointerPath = path.join(
    REPOSITORY_ROOT,
    'benchmarks/results/verification/current-multi-hour-hardening.txt',
  );
  const directoryName = fs.readFileSync(pointerPath, 'utf8').trim();
  if (!/^[A-Za-z0-9-]+$/u.test(directoryName)) {
    throw new Error('current hardening pointer contains an unsafe directory name');
  }
  return `benchmarks/results/verification/${directoryName}/qualification-summary.json`;
}

function collectHardening(summaryPath) {
  const file = repositoryFileReference(summaryPath, 'hardening summary');
  const summary = readJson(file.absolutePath);
  const manifest = verifyChecksumManifest(path.dirname(file.absolutePath));
  const valid = summary.outcome === 'PASS' &&
    summary.evidence_class === 'clean-tree-local-hardening' &&
    summary.source?.dirty_at_start === false &&
    summary.source?.dirty_at_end === false &&
    summary.duration?.configured_seconds >= 86400 &&
    summary.duration?.actual_seconds >= summary.duration.configured_seconds &&
    summary.process?.identity_unchanged === true &&
    summary.process?.restart_count === 0 &&
    summary.process?.graceful_exit_code === 0 &&
    summary.evidence?.raw_checksums_verified === true &&
    summary.evidence?.source_checksums_verified === true &&
    summary.publishable === false &&
    summary.marketing_use_authorized === false &&
    summary.performance_claim_authorized === false &&
    manifest.valid;
  return {
    valid,
    path: file.path,
    sha256: file.sha256,
    sourceCommit: summary.source?.commit,
    manifestEntries: manifest.entries,
    message: valid
      ? `Accepted 24-hour local hardening evidence (${manifest.entries} retained checksums); its nonpublication boundary remains in force.`
      : `Local hardening evidence failed semantic or checksum verification${manifest.error ? `: ${manifest.error}` : '.'}`,
  };
}

function collectComparator(qualificationPath, currentProductLock) {
  const file = repositoryFileReference(
    qualificationPath,
    'comparator qualification',
  );
  const qualification = readJson(file.absolutePath);
  const errors = schemaErrors(SCHEMAS.productQualification, qualification);
  const directory = path.dirname(file.absolutePath);
  const archivedLockPath = path.join(directory, 'product-lock.json');
  if (!fs.existsSync(archivedLockPath)) {
    errors.push('comparator qualification lacks its archived product lock');
  } else {
    const archivedLock = readJson(archivedLockPath);
    errors.push(...schemaErrors(SCHEMAS.productLock, archivedLock));
    const archivedSha256 = sha256File(archivedLockPath);
    if (qualification.product_lock_sha256 !== archivedSha256) {
      errors.push('comparator qualification does not match its archived product lock');
    }
    if (sha256File(currentProductLock.absolutePath) !== archivedSha256) {
      errors.push('comparator qualification product lock differs from the current lock');
    }
  }
  if (qualification.architecture !== 'x86_64' || qualification.passed !== true ||
      !sameIds(
        qualification.products?.filter(({passed}) => passed).map(({name}) => name) ?? [],
        ['envoy', 'haproxy', 'nginx'],
      )) {
    errors.push('comparator qualification is not a complete passing AMD64 identity set');
  }
  const currentLockDocument = readJson(currentProductLock.absolutePath);
  for (const qualifiedProduct of qualification.products ?? []) {
    const lockedProduct = currentLockDocument.products.find(
      ({name}) => name === qualifiedProduct.name,
    );
    if (!lockedProduct ||
        qualifiedProduct.version !== lockedProduct.version ||
        qualifiedProduct.image_manifest_digest !==
          lockedProduct.manifests.linux_amd64 ||
        qualifiedProduct.config_sha256 !== lockedProduct.config_sha256 ||
        qualifiedProduct.config_valid !== true ||
        qualifiedProduct.ready !== true ||
        qualifiedProduct.payload_valid !== true ||
        qualifiedProduct.passed !== true) {
      errors.push(
        `${qualifiedProduct.name} identity or qualification state differs from the current product lock`,
      );
      continue;
    }
    const retainedConfigPath = path.join(
      directory,
      `${qualifiedProduct.name}.config`,
    );
    if (!fs.existsSync(retainedConfigPath) ||
        sha256File(retainedConfigPath) !== qualifiedProduct.config_sha256) {
      errors.push(`${qualifiedProduct.name} retained configuration is missing or stale`);
    }
  }
  return {
    valid: errors.length === 0,
    path: file.path,
    sha256: file.sha256,
    message: errors.length === 0
      ? 'Exact AMD64 comparator identities match the current product lock; this is identity evidence, not dedicated performance evidence.'
      : errors.join('; '),
  };
}

export function runtimeChangesRequiringHardening(changedPaths) {
  // Scan tooling is bound by fresh security evidence, not by the gateway soak.
  return changedPaths.filter(file => RUNTIME_CRITICAL_PATHS.some(input =>
    file === input || file.startsWith(`${input}/`))).sort();
}

function collectSource(hardeningCommit, remoteRef) {
  const commit = runGit(['rev-parse', 'HEAD']);
  const clean = runGit(['status', '--porcelain=v1', '--untracked-files=all']) === '';
  const pushed = runGit(
    ['merge-base', '--is-ancestor', commit, remoteRef],
    {allowFailure: true},
  ) !== null;
  const hardeningIsAncestor = runGit(
    ['merge-base', '--is-ancestor', hardeningCommit, commit],
    {allowFailure: true},
  ) !== null;
  const runtimeChanges = hardeningIsAncestor
    ? runtimeChangesRequiringHardening(runGit([
      'diff',
      '--name-only',
      `${hardeningCommit}..${commit}`,
      '--',
      ...RUNTIME_CRITICAL_PATHS,
    ]).split('\n').filter(Boolean))
    : ['hardening-commit-is-not-an-ancestor'];
  return {
    commit,
    remote_ref: remoteRef,
    clean,
    pushed,
    hardening_commit: hardeningCommit,
    runtime_changes_since_hardening: runtimeChanges,
  };
}

function collectAuditorHost() {
  let operatingSystem = `${os.type()} ${os.release()}`;
  if (process.platform === 'linux' && fs.existsSync('/etc/os-release')) {
    const values = Object.fromEntries(
      fs.readFileSync('/etc/os-release', 'utf8')
        .split('\n')
        .filter((line) => line.includes('='))
        .map((line) => {
          const index = line.indexOf('=');
          return [
            line.slice(0, index),
            line.slice(index + 1).replace(/^"|"$/gu, ''),
          ];
        }),
    );
    operatingSystem = values.PRETTY_NAME ?? operatingSystem;
  }
  const architecture = process.arch === 'x64'
    ? 'x86_64'
    : process.arch === 'arm64' ? 'aarch64' : process.arch;
  return {
    operating_system: operatingSystem,
    architecture,
    target_compatible: process.platform === 'linux' &&
      architecture === 'x86_64' && /Ubuntu 24\.04/u.test(operatingSystem),
  };
}

export function collectBindings({campaignPath, productLock, tuningPolicyPath}) {
  const entries = [
    ['campaign-plan', campaignPath],
    ['campaign-schema', SCHEMAS.campaign],
    ['product-lock', productLock.path],
    ['product-lock-schema', SCHEMAS.productLock],
    ['host-tuning-policy', tuningPolicyPath],
    ['host-tuning-policy-schema', SCHEMAS.tuningPolicy],
    ['validation-plan', 'benchmarks/plans/dedicated-rc-validation-v1.yaml'],
    ['validation-plan-schema', SCHEMAS.validationPlan],
    ['validation-check-schema', SCHEMAS.validationCheck],
    ['environment-topology-template', 'benchmarks/plans/dedicated-environment-template.yaml'],
    ['environment-topology-schema', SCHEMAS.environmentTopology],
    ['environment-review-schema', SCHEMAS.environmentReview],
    ['environment-report-schema', SCHEMAS.environmentReport],
    ['environment-adapter', 'benchmarks/scripts/dedicated-environment.mjs'],
    ['environment-supervisor', 'benchmarks/scripts/dedicated-collection-supervisor.mjs'],
    ['phase1-runner', 'benchmarks/scripts/run-phase1-scaling.sh'],
    ['phase1-accounting', 'benchmarks/scripts/phase1-accounting.jq'],
    ['phase2-analyzer', 'benchmarks/scripts/summarize-phase2.mjs'],
    ['benchmark-fairness-contract', 'benchmarks/contracts/benchmark-fairness.md'],
    ['dedicated-security-plan', 'benchmarks/contracts/dedicated-security-test-plan.md'],
    ['workload-schema', 'benchmarks/spec/workload.schema.json'],
    ['benchmark-compose', 'benchmarks/docker-compose.yml'],
    ['controlled-upstream-image', 'benchmarks/products/upstream/Dockerfile'],
    ['controlled-upstream-config', 'benchmarks/products/upstream/nginx.conf'],
    ['phase3-upstream-image', 'deploy/docker/upstream/Dockerfile'],
    ['phase3-upstream-server', 'deploy/docker/upstream/server.py'],
  ];
  const productLockDocument = readJson(productLock.absolutePath);
  for (const product of productLockDocument.products) {
    entries.push([`comparator-config:${product.name}`, product.config]);
  }
  for (const workloadPath of listFiles(
    'benchmarks/workloads',
    (absolutePath) => /\.ya?ml$/u.test(absolutePath),
  )) {
    entries.push([bindingId('workload', workloadPath), workloadPath]);
  }

  const bindings = entries.map(([id, relativePath]) => {
    const file = repositoryFileReference(relativePath, `binding ${id}`);
    return {id, path: file.path, sha256: file.sha256};
  }).sort((left, right) => left.id.localeCompare(right.id));
  const duplicateErrors = uniqueIds(bindings, 'campaign bindings');
  if (duplicateErrors.length > 0) {
    throw new Error(duplicateErrors.join('; '));
  }
  return bindings;
}

function missingEvidence(id, message) {
  return {
    valid: false,
    status: 'missing',
    id,
    required_for_strict: true,
    message,
  };
}

function collectArtifactLock(lockPath, context) {
  if (!lockPath) {
    return missingEvidence(
      'artifact-lock',
      'The exact Linux AMD64 artifact lock has not been generated.',
    );
  }
  try {
    const file = repositoryFileReference(lockPath, 'artifact lock');
    const document = readJson(file.absolutePath);
    const inspection = inspectArtifactLockDocument(document, {
      campaignId: context.campaignId,
      sourceCommit: context.sourceCommit,
      bindings: context.bindings,
      verifySboms: true,
    });
    return {
      valid: inspection.valid,
      status: inspection.valid ? 'accepted' : 'stale',
      id: 'artifact-lock',
      required_for_strict: true,
      path: file.path,
      sha256: file.sha256,
      message: inspection.valid
        ? 'Exact release artifacts, tools, SBOMs, and campaign inputs are digest-locked.'
        : inspection.errors.join('; '),
      document,
    };
  } catch (error) {
    return {
      ...missingEvidence('artifact-lock', error.message),
      status: 'invalid',
    };
  }
}

function collectValidationReceipt(receiptPath, context) {
  if (!receiptPath) {
    return missingEvidence(
      'validation-receipt',
      'The exact-release validation receipt has not been generated.',
    );
  }
  try {
    const file = repositoryFileReference(receiptPath, 'validation receipt');
    const document = readJson(file.absolutePath);
    const inspection = inspectValidationReceiptDocument(document, {
      campaignId: context.campaignId,
      sourceCommit: context.sourceCommit,
      artifactLockPath: context.artifactLock.path,
      artifactLockSha256: context.artifactLock.sha256,
      remoteRef: context.remoteRef,
      verifyEvidence: true,
    });
    return {
      valid: inspection.valid && context.artifactLock.valid,
      status: inspection.valid && context.artifactLock.valid
        ? 'accepted'
        : 'stale',
      id: 'validation-receipt',
      required_for_strict: true,
      path: file.path,
      sha256: file.sha256,
      message: inspection.valid && context.artifactLock.valid
        ? 'All required exact-release checks passed with checksum-bound evidence.'
        : [
          ...inspection.errors,
          ...(context.artifactLock.valid ? [] : ['artifact lock is not accepted']),
        ].join('; '),
    };
  } catch (error) {
    return {
      ...missingEvidence('validation-receipt', error.message),
      status: 'invalid',
    };
  }
}

/**
 * Builds the fail-closed decision from already collected facts. Rehearsal may
 * precede campaign freeze, but still requires every source and evidence gate.
 * Only strict mode can authorize qualification infrastructure.
 */
export function evaluatePreflight({
  mode,
  generatedAt = new Date().toISOString(),
  campaign,
  source,
  auditorHost,
  bindings,
  bindingsValid = true,
  hardening,
  comparator,
  artifactLock,
  validationReceipt,
}) {
  if (!['candidate', 'rehearsal', 'strict'].includes(mode)) {
    throw new Error('preflight mode must be candidate, rehearsal or strict');
  }
  const checks = [];
  const check = (id, condition, passMessage, blockMessage) => {
    checks.push({
      id,
      status: condition ? 'pass' : 'block',
      message: condition ? passMessage : blockMessage,
    });
  };

  check(
    'campaign-contract',
    campaign.hasInfra001 === true,
    'The DQ-INFRA-001 campaign contract is valid.',
    'The selected campaign does not contain the required DQ-INFRA-001 gate.',
  );
  // Rehearsal validates the environment before freeze; never report freeze as passed.
  if (mode === 'rehearsal' && campaign.status === 'pre-execution') {
    checks.push({
      id: 'campaign-frozen',
      status: 'warn',
      message: 'The campaign remains pre-execution; bounded ordinary-instance rehearsal may precede freeze, but qualification may not.',
    });
  } else {
    check(
      'campaign-frozen',
      campaign.status === 'frozen',
      'The campaign is frozen.',
      `The campaign is ${campaign.status}; freeze it only after all harnesses and exact RC inputs are complete.`,
    );
  }
  check(
    'source-clean',
    source.clean,
    'The selected source tree is clean.',
    'The selected source tree contains uncommitted or untracked files.',
  );
  check(
    'source-pushed',
    source.pushed,
    `The selected source commit is present on ${source.remote_ref}.`,
    `The selected source commit is not present on ${source.remote_ref}.`,
  );
  checks.push({
    id: 'auditor-host',
    status: auditorHost.target_compatible ? 'pass' : 'warn',
    message: auditorHost.target_compatible
      ? 'The audit is running on Ubuntu 24.04 x86_64.'
      : 'The audit host is not the target platform; exact artifact and receipt platform fields remain authoritative.',
  });
  check(
    'runtime-equivalence',
    source.runtime_changes_since_hardening.length === 0,
    'No runtime-critical file changed after the accepted local hardening run.',
    `Runtime-critical files changed after local hardening: ${source.runtime_changes_since_hardening.join(', ')}`,
  );
  check(
    'binding-integrity',
    bindingsValid,
    `All ${bindings.length} campaign inputs have retained SHA-256 digests.`,
    'One or more campaign inputs could not be bound to an exact digest.',
  );
  check(
    'hardening-evidence',
    hardening.valid,
    'The accepted 24-hour local evidence remains checksum-valid and runtime-equivalent.',
    hardening.message,
  );
  check(
    'comparator-identity',
    comparator.valid,
    'The AMD64 comparator identities match the current product lock.',
    comparator.message,
  );
  check(
    'artifact-lock',
    artifactLock.valid,
    'The exact Linux AMD64 artifact lock matches this source and campaign.',
    artifactLock.message,
  );
  check(
    'validation-receipt',
    validationReceipt.valid,
    'The exact artifact validation receipt contains every required passing check.',
    validationReceipt.message,
  );
  if (mode === 'candidate') {
    checks.push({
      id: 'candidate-mode',
      status: 'warn',
      message: 'Candidate mode reports readiness but never authorizes paid allocation.',
    });
  }
  if (mode === 'rehearsal') {
    checks.push({
      id: 'rehearsal-mode',
      status: 'warn',
      message: 'Rehearsal readiness only; ordinary-instance spending needs operator approval, and this report never authorizes qualification allocation.',
    });
  }

  const blockers = checks
    .filter(({status}) => status === 'block')
    .map(({id}) => id);
  const warnings = checks
    .filter(({status}) => status === 'warn')
    .map(({id}) => id);
  const status = blockers.length === 0 ? 'ready' : 'blocked';
  const evidence = [hardening, comparator, artifactLock, validationReceipt]
    .map(({id, status: evidenceStatus, required_for_strict: required, path: evidencePath,
      sha256, message}) => ({
      id,
      status: evidenceStatus,
      required_for_strict: required,
      ...(evidencePath ? {path: evidencePath} : {}),
      ...(sha256 ? {sha256} : {}),
      message,
    }));
  const identity = {
    mode,
    campaign_id: campaign.id,
    source,
    bindings,
    evidence: evidence.map(({id, status: evidenceStatus, sha256}) => ({
      id,
      status: evidenceStatus,
      ...(sha256 ? {sha256} : {}),
    })),
    checks: checks.map(({id, status: checkStatus}) => ({id, status: checkStatus})),
  };
  const report = {
    schema_version: 1,
    preflight_id: `dq-infra-001-${digestBuffer(stableJson(identity)).slice(0, 16)}`,
    generated_at: generatedAt,
    mode,
    campaign_id: campaign.id,
    status,
    allocation_authorized: mode === 'strict' && status === 'ready',
    source,
    auditor_host: auditorHost,
    bindings,
    evidence,
    checks,
    blockers,
    warnings,
    claim_boundary: CLAIM_BOUNDARY,
  };
  const errors = schemaErrors(SCHEMAS.preflight, report);
  if (errors.length > 0) {
    throw new Error(`generated preflight report is invalid: ${errors.join('; ')}`);
  }
  return report;
}

function parseArguments(argv) {
  const options = {
    mode: 'candidate',
    campaign: 'benchmarks/plans/dedicated-qualification-v1.yaml',
    productLock: 'benchmarks/products/lock.json',
    tuningPolicy: 'deploy/tuning/policies/throughput-balanced.yaml',
    hardeningSummary: undefined,
    comparatorQualification: undefined,
    artifactLock: process.env.BONVOYAGE_DEDICATED_ARTIFACT_LOCK,
    validationReceipt: process.env.BONVOYAGE_DEDICATED_VALIDATION_RECEIPT,
    remoteRef: process.env.BONVOYAGE_DEDICATED_REMOTE_REF ?? 'origin/main',
    output: process.env.BONVOYAGE_DEDICATED_PREFLIGHT_OUTPUT ?? '-',
  };
  const valueOptions = new Map([
    ['--mode', 'mode'],
    ['--campaign', 'campaign'],
    ['--product-lock', 'productLock'],
    ['--tuning-policy', 'tuningPolicy'],
    ['--hardening-summary', 'hardeningSummary'],
    ['--comparator-qualification', 'comparatorQualification'],
    ['--artifact-lock', 'artifactLock'],
    ['--validation-receipt', 'validationReceipt'],
    ['--remote-ref', 'remoteRef'],
    ['--output', 'output'],
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const key = valueOptions.get(argv[index]);
    const value = argv[index + 1];
    if (!key || !value) {
      throw new Error(`unknown or incomplete argument: ${argv[index]}`);
    }
    options[key] = value;
    index += 1;
  }
  return options;
}

function collectContext(options) {
  const campaignFile = repositoryFileReference(options.campaign, 'campaign plan');
  const campaign = yaml.load(fs.readFileSync(campaignFile.absolutePath, 'utf8'));
  const campaignErrors = schemaErrors(SCHEMAS.campaign, campaign);
  if (campaignErrors.length > 0) {
    throw new Error(`campaign plan is invalid: ${campaignErrors.join('; ')}`);
  }
  const infraGroup = campaign.test_groups.find(({id}) => id === 'DQ-INFRA-001');

  const productLock = repositoryFileReference(options.productLock, 'product lock');
  const productLockDocument = readJson(productLock.absolutePath);
  const productLockErrors = schemaErrors(SCHEMAS.productLock, productLockDocument);
  if (productLockErrors.length > 0) {
    throw new Error(`product lock is invalid: ${productLockErrors.join('; ')}`);
  }
  const tuningPolicy = repositoryFileReference(options.tuningPolicy, 'tuning policy');
  const tuningDocument = yaml.load(fs.readFileSync(tuningPolicy.absolutePath, 'utf8'));
  const tuningErrors = schemaErrors(SCHEMAS.tuningPolicy, tuningDocument);
  if (tuningErrors.length > 0) {
    throw new Error(`tuning policy is invalid: ${tuningErrors.join('; ')}`);
  }

  const hardening = collectHardening(resolveHardeningSummary(options.hardeningSummary));
  const source = collectSource(hardening.sourceCommit, options.remoteRef);
  hardening.id = 'local-hardening';
  hardening.required_for_strict = true;
  hardening.status = hardening.valid &&
    source.runtime_changes_since_hardening.length === 0
    ? 'reusable-nonpublication'
    : hardening.valid ? 'stale' : 'invalid';
  hardening.valid = hardening.valid &&
    source.runtime_changes_since_hardening.length === 0;

  const bindings = collectBindings({
    campaignPath: campaignFile.path,
    productLock,
    tuningPolicyPath: tuningPolicy.path,
  });
  const comparator = collectComparator(
    options.comparatorQualification ?? findLatestComparatorQualification(),
    productLock,
  );
  comparator.id = 'comparator-identity';
  comparator.required_for_strict = true;
  comparator.status = comparator.valid ? 'accepted' : 'invalid';

  const artifactLock = collectArtifactLock(options.artifactLock, {
    campaignId: campaign.id,
    sourceCommit: source.commit,
    bindings,
  });
  const validationReceipt = collectValidationReceipt(options.validationReceipt, {
    campaignId: campaign.id,
    sourceCommit: source.commit,
    remoteRef: source.remote_ref,
    artifactLock,
  });
  return {
    mode: options.mode,
    campaign: {
      id: campaign.id,
      status: campaign.status,
      hasInfra001: infraGroup?.required === true && infraGroup.execution_order === 1,
    },
    source,
    auditorHost: collectAuditorHost(),
    bindings,
    hardening,
    comparator,
    artifactLock,
    validationReceipt,
  };
}

function writeReport(report, output) {
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  if (output === '-') {
    process.stdout.write(serialized);
    return;
  }
  const absolutePath = path.isAbsolute(output)
    ? path.resolve(output)
    : path.resolve(REPOSITORY_ROOT, output);
  fs.mkdirSync(path.dirname(absolutePath), {recursive: true});
  fs.writeFileSync(absolutePath, serialized, {flag: 'wx'});
  process.stdout.write(
    `${report.preflight_id}: ${report.status}; ` +
    `allocation_authorized=${report.allocation_authorized}; output=${output}\n`,
  );
}

function main() {
  const options = parseArguments(process.argv.slice(2));
  const report = evaluatePreflight(collectContext(options));
  writeReport(report, options.output);
  if (options.mode === 'strict' && !report.allocation_authorized) {
    process.exitCode = 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`dedicated-preflight: ${error.message}\n`);
    process.exitCode = 1;
  }
}
