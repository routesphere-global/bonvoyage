#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {TextDecoder} from 'node:util';
import {fileURLToPath} from 'node:url';

import {verifyArtifactLifecycle} from './verify-oss-artifact-lifecycle.mjs';

const SCRIPT_ROOT = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_CONTRACT = path.resolve(
  SCRIPT_ROOT, '..', 'packaging', 'release', 'oss-artifact-lifecycle-contract.json');
const INTAKE_CLASSIFICATION =
  'routesphere-bonvoyage-oss-candidate-intake-receipt';
const LANE_CLASSIFICATION =
  'routesphere-bonvoyage-oss-artifact-lifecycle-lane';
const OBSERVATION_CLASSIFICATION =
  'routesphere-bonvoyage-oss-artifact-lifecycle-observation';
const CONTRACT_PATH = 'packaging/release/oss-artifact-lifecycle-contract.json';
const AUTHORITY_FIELDS = [
  'release_admitted', 'publishable', 'github_release_created', 'package_uploaded',
  'container_uploaded', 'signature_created', 'provenance_created',
];
const JOBS = [
  {
    name: 'debian-candidate-fresh',
    artifact: 'gateway-deb-linux-amd64',
    phases: ['candidate-fresh-install'],
  },
  {
    name: 'debian-transition',
    artifact: 'gateway-deb-linux-amd64',
    phases: [
      'upgrade-from-baseline', 'rollback-to-baseline',
      'candidate-reactivation', 'shutdown-remove',
    ],
  },
  {
    name: 'oci-lifecycle',
    artifact: 'gateway-oci-linux-amd64',
    phases: [
      'candidate-fresh-start', 'replace-baseline-with-candidate',
      'rollback-to-baseline', 'candidate-reactivation', 'shutdown-remove',
    ],
  },
];
const DECODER = new TextDecoder('utf-8', {fatal: true});
const SHA256 = /^[a-f0-9]{64}$/u;
const RUN_ID = /^[1-9][0-9]*$/u;
const MAX_FILE_BYTES = 64 * 1024 * 1024;

function fail(message) {
  throw new Error(message);
}

function requireCondition(condition, message) {
  if (!condition) fail(message);
}

function object(value, label) {
  requireCondition(value !== null && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  return value;
}

function exactKeys(value, expected, label) {
  const actual = Object.keys(object(value, label)).sort();
  const wanted = [...expected].sort();
  requireCondition(actual.length === wanted.length &&
    actual.every((item, index) => item === wanted[index]),
  `${label} fields must be exactly [${wanted.join(', ')}]`);
}

function safeRelative(value, label) {
  requireCondition(typeof value === 'string' && value.length > 0 &&
    value === value.trim() && !value.includes('\\') && !path.posix.isAbsolute(value) &&
    path.posix.normalize(value) === value && value !== '.' &&
    value.split('/').every((part) => part && part !== '..'),
  `${label} must be a safe relative path`);
  return value;
}

function snapshot(filePath, label, maximum = MAX_FILE_BYTES, retain = false) {
  const descriptor = fs.openSync(filePath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && before.nlink === 1 &&
      before.size > 0 && before.size <= maximum,
    `${label} must be one bounded regular single-link file`);
    const digest = crypto.createHash('sha256');
    const chunks = retain ? [] : null;
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    while (true) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      const part = buffer.subarray(0, count);
      digest.update(part);
      if (chunks) chunks.push(Buffer.from(part));
      bytes += count;
    }
    const after = fs.fstatSync(descriptor);
    requireCondition(before.dev === after.dev && before.ino === after.ino &&
      before.size === after.size && before.mtimeMs === after.mtimeMs &&
      before.ctimeMs === after.ctimeMs && before.nlink === after.nlink &&
      bytes === after.size, `${label} changed while read`);
    return {
      bytes,
      sha256: digest.digest('hex'),
      ...(chunks ? {content: Buffer.concat(chunks, bytes)} : {}),
    };
  } finally {
    fs.closeSync(descriptor);
  }
}

function readJson(filePath, label) {
  const record = snapshot(filePath, label, 8 * 1024 * 1024, true);
  let text;
  let value;
  try {
    text = DECODER.decode(record.content);
    value = JSON.parse(text);
  } catch (error) {
    fail(`${label} is not valid UTF-8 JSON: ${error.message}`);
  }
  object(value, label);
  requireCondition(text === `${JSON.stringify(value, null, 2)}\n`,
    `${label} must use canonical JSON`);
  return {value, bytes: record.bytes, sha256: record.sha256};
}

function inventory(root, excluded = new Set()) {
  const metadata = fs.lstatSync(root);
  requireCondition(metadata.isDirectory() && !metadata.isSymbolicLink(),
    `${root} must be a real directory`);
  const records = [];
  function walk(directory, prefix = '') {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      safeRelative(relative, 'lane inventory path');
      const absolute = path.join(directory, entry.name);
      const item = fs.lstatSync(absolute);
      requireCondition(!item.isSymbolicLink(), `lane path ${relative} must not be a link`);
      if (item.isDirectory()) walk(absolute, relative);
      else {
        requireCondition(item.isFile() && item.nlink === 1,
          `lane path ${relative} must be one regular single-link file`);
        if (!excluded.has(relative)) records.push({path: relative, ...snapshot(
          absolute, `lane path ${relative}`)});
      }
    }
  }
  walk(root);
  return records.sort((left, right) => left.path.localeCompare(right.path));
}

function validateAuthority(authority, label) {
  exactKeys(authority, AUTHORITY_FIELDS, label);
  requireCondition(AUTHORITY_FIELDS.every((field) => authority[field] === false),
    `${label} must grant no release authority`);
}

function readIntake(root, label) {
  const receipt = readJson(path.join(root, 'candidate-intake-receipt.json'),
    `${label} intake receipt`);
  const value = receipt.value;
  requireCondition(value.classification === INTAKE_CLASSIFICATION,
    `${label} intake classification changed`);
  validateAuthority(value.authority, `${label} intake authority`);
  requireCondition(Array.isArray(value.artifacts) && value.artifacts.length === 2,
    `${label} intake must contain two artifacts`);
  return {
    receiptSha256: receipt.sha256,
    source: value.source,
    artifacts: value.artifacts.map((artifact) => ({
      id: artifact.id,
      kind: artifact.kind,
      bytes: artifact.bytes,
      sha256: artifact.sha256,
    })),
  };
}

function artifactSummary(intake) {
  return {
    intake_receipt_sha256: intake.receiptSha256,
    source: intake.source,
    artifacts: intake.artifacts,
  };
}

function copyExclusive(source, destination) {
  fs.mkdirSync(path.dirname(destination), {recursive: true, mode: 0o700});
  fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
  fs.chmodSync(destination, 0o600);
  const before = snapshot(source, `source ${source}`);
  const after = snapshot(destination, `copied ${destination}`);
  requireCondition(before.bytes === after.bytes && before.sha256 === after.sha256,
    `copy changed ${source}`);
  return after;
}

function phaseSpecification(contract) {
  const result = new Map();
  for (const artifact of contract.artifacts) {
    const phases = new Map(artifact.phases.map((phase) => [phase.id, phase.required_checks]));
    result.set(artifact.id, {artifact, phases});
  }
  return result;
}

export function validateLane({root, job, contract, candidate, baseline}) {
  const laneRecord = readJson(path.join(root, 'lane.json'), `${job.name} lane`);
  const lane = laneRecord.value;
  exactKeys(lane, [
    'schema_version', 'classification', 'outcome', 'job', 'candidate', 'baseline',
    'artifact', 'phases', 'authority',
  ], `${job.name} lane`);
  requireCondition(lane.schema_version === 1 && lane.classification === LANE_CLASSIFICATION &&
    lane.outcome === 'passed' && lane.job === job.name &&
    JSON.stringify(lane.candidate) === JSON.stringify(candidate.source) &&
    JSON.stringify(lane.baseline) === JSON.stringify(baseline.source),
  `${job.name} lane identity changed`);
  validateAuthority(lane.authority, `${job.name} lane authority`);
  const candidateArtifact = candidate.artifacts.find((item) => item.id === job.artifact);
  const baselineArtifact = baseline.artifacts.find((item) => item.id === job.artifact);
  const specification = phaseSpecification(contract).get(job.artifact);
  requireCondition(candidateArtifact && baselineArtifact && specification,
    `${job.name} artifact is unavailable`);
  exactKeys(lane.artifact, [
    'id', 'kind', 'candidate_sha256', 'baseline_sha256',
  ], `${job.name} lane artifact`);
  requireCondition(lane.artifact.id === job.artifact &&
    lane.artifact.kind === candidateArtifact.kind &&
    lane.artifact.candidate_sha256 === candidateArtifact.sha256 &&
    lane.artifact.baseline_sha256 === baselineArtifact.sha256,
  `${job.name} artifact binding changed`);
  requireCondition(Array.isArray(lane.phases) && lane.phases.length === job.phases.length,
    `${job.name} phase count changed`);
  const referenced = new Set();
  const phases = lane.phases.map((phase, index) => {
    const expectedId = job.phases[index];
    const requiredChecks = specification.phases.get(expectedId);
    exactKeys(phase, ['id', 'status', 'checks', 'evidence'],
      `${job.name} phase ${index}`);
    requireCondition(phase.id === expectedId && phase.status === 'PASS' && requiredChecks,
      `${job.name} phase order or status changed`);
    exactKeys(phase.checks, requiredChecks, `${job.name} phase ${expectedId} checks`);
    requireCondition(requiredChecks.every((check) => phase.checks[check] === true),
      `${job.name} phase ${expectedId} contains a failed check`);
    requireCondition(Array.isArray(phase.evidence) && phase.evidence.length > 0,
      `${job.name} phase ${expectedId} must bind evidence`);
    const evidence = phase.evidence.map((relative, evidenceIndex) => {
      safeRelative(relative, `${job.name} phase ${expectedId} evidence ${evidenceIndex}`);
      requireCondition(relative !== 'lane.json' && !referenced.has(relative),
        `${job.name} lane evidence is duplicated or reserved`);
      referenced.add(relative);
      return relative;
    });
    return {id: phase.id, status: phase.status, checks: phase.checks, evidence};
  });
  const files = inventory(root);
  const expectedFiles = new Set(['lane.json', ...referenced]);
  requireCondition(files.length === expectedFiles.size &&
    files.every((file) => expectedFiles.has(file.path)),
  `${job.name} lane contains unbound or missing files`);
  return {lane, laneRecord, phases, files};
}

export function assembleLifecycle({
  contractPath = DEFAULT_CONTRACT,
  candidateRoot,
  baselineRoot,
  laneRoots,
  output,
  runId,
  runAttempt,
  capturedAt,
  allowUnpinnedContractForTests = false,
}) {
  requireCondition(RUN_ID.test(runId ?? '') && runAttempt === '1',
    'exact first-attempt GitHub run identity required');
  requireCondition(typeof capturedAt === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(capturedAt) &&
    new Date(capturedAt).toISOString() === capturedAt,
  'captured-at must be canonical millisecond UTC');
  const contractRecord = readJson(path.resolve(contractPath), 'lifecycle contract');
  const contract = contractRecord.value;
  validateAuthority(contract.authority, 'lifecycle contract authority');
  requireCondition(JSON.stringify(contract.runner.jobs) ===
    JSON.stringify(JOBS.map((job) => job.name)), 'lifecycle job inventory changed');
  const candidate = readIntake(path.resolve(candidateRoot), 'candidate');
  const baseline = readIntake(path.resolve(baselineRoot), 'baseline');
  const roots = object(laneRoots, 'lane roots');
  exactKeys(roots, JOBS.map((job) => job.name), 'lane roots');
  const lanes = JOBS.map((job) => validateLane({
    root: path.resolve(roots[job.name]), job, contract, candidate, baseline,
  }));

  const destination = path.resolve(output);
  requireCondition(!fs.existsSync(destination), 'lifecycle output must not exist');
  const staging = `${destination}.tmp-${process.pid}`;
  requireCondition(!fs.existsSync(staging), 'lifecycle staging output already exists');
  fs.mkdirSync(path.join(staging, 'raw'), {recursive: true, mode: 0o700});
  try {
    const observations = new Map(contract.artifacts.map((artifact) => [artifact.id, {
      id: artifact.id,
      kind: artifact.kind,
      transition: artifact.transition,
      candidate_sha256: candidate.artifacts.find((item) => item.id === artifact.id).sha256,
      baseline_sha256: baseline.artifacts.find((item) => item.id === artifact.id).sha256,
      phases: [],
    }]));
    for (let laneIndex = 0; laneIndex < lanes.length; laneIndex += 1) {
      const job = JOBS[laneIndex];
      const lane = lanes[laneIndex];
      const sourceRoot = path.resolve(roots[job.name]);
      const phaseCopies = new Map();
      for (const phase of lane.phases) {
        phaseCopies.set(phase.id, phase.evidence.map((relative) => {
          const destinationRelative = `raw/${job.name}/${relative}`;
          return {path: destinationRelative, ...copyExclusive(
            path.join(sourceRoot, relative), path.join(staging, destinationRelative))};
        }));
      }
      const laneRelative = `raw/${job.name}/lane.json`;
      const laneIdentity = copyExclusive(
        path.join(sourceRoot, 'lane.json'), path.join(staging, laneRelative));
      phaseCopies.get(lane.phases[0].id).unshift({path: laneRelative, ...laneIdentity});
      const target = observations.get(job.artifact);
      for (const phase of lane.phases) {
        target.phases.push({
          id: phase.id,
          status: phase.status,
          checks: phase.checks,
          evidence: phaseCopies.get(phase.id),
        });
      }
    }
    const observation = {
      schema_version: 1,
      classification: OBSERVATION_CLASSIFICATION,
      outcome: 'passed',
      captured_at: capturedAt,
      contract: {path: CONTRACT_PATH, sha256: contractRecord.sha256},
      candidate: artifactSummary(candidate),
      baseline: artifactSummary(baseline),
      runner: {
        provider: contract.runner.provider,
        operating_system: contract.runner.operating_system,
        architecture: contract.runner.architecture,
        run_id: runId,
        run_attempt: runAttempt,
        jobs: contract.runner.jobs,
      },
      artifacts: contract.artifacts.map((artifact) => observations.get(artifact.id)),
      authority: contract.authority,
    };
    fs.writeFileSync(path.join(staging, 'observation.json'),
      `${JSON.stringify(observation, null, 2)}\n`, {flag: 'wx', mode: 0o600});
    const report = verifyArtifactLifecycle({
      contractPath: path.resolve(contractPath),
      candidateRoot: path.resolve(candidateRoot),
      baselineRoot: path.resolve(baselineRoot),
      evidenceRoot: staging,
      allowUnpinnedContractForTests,
    });
    requireCondition(report.lifecycle_qualified === true &&
      report.release_admitted === false && report.publishable === false,
    'accepted lifecycle verifier did not qualify the powerless observation');
    fs.renameSync(staging, destination);
    return report;
  } catch (error) {
    fs.rmSync(staging, {recursive: true, force: true});
    throw error;
  }
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    requireCondition(key?.startsWith('--') && value !== undefined && options[key] === undefined,
      `unsupported, duplicate or incomplete argument ${key}`);
    options[key] = value;
  }
  const required = [
    '--candidate', '--baseline', '--debian-candidate-fresh', '--debian-transition',
    '--oci-lifecycle', '--output', '--run-id', '--run-attempt', '--captured-at',
  ];
  requireCondition(required.every((name) => options[name]),
    `required arguments are ${required.join(', ')}`);
  return {
    candidateRoot: options['--candidate'],
    baselineRoot: options['--baseline'],
    laneRoots: {
      'debian-candidate-fresh': options['--debian-candidate-fresh'],
      'debian-transition': options['--debian-transition'],
      'oci-lifecycle': options['--oci-lifecycle'],
    },
    output: options['--output'],
    runId: options['--run-id'],
    runAttempt: options['--run-attempt'],
    capturedAt: options['--captured-at'],
    contractPath: options['--contract'] ?? DEFAULT_CONTRACT,
  };
}

if (fileURLToPath(import.meta.url) === path.resolve(process.argv[1] ?? '')) {
  try {
    const report = assembleLifecycle(parseArguments(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`OSS lifecycle assembly rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}
