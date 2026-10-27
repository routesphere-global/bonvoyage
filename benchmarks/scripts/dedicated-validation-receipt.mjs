#!/usr/bin/env node

import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';

import {
  REPOSITORY_ROOT,
  collectBindings,
  digestBuffer,
  inspectArtifactLockDocument,
  inspectValidationCheckDocument,
  inspectValidationPlanDocument,
  inspectValidationReceiptDocument,
  repositoryFileReference,
  stableJson,
} from './dedicated-preflight.mjs';

const require = createRequire(path.join(REPOSITORY_ROOT, 'package.json'));
const yaml = require('js-yaml');

const TARGET_PLATFORM = {
  operating_system: 'Ubuntu 24.04 LTS',
  architecture: 'x86_64',
  container_platform: 'linux/amd64',
};

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
    throw error;
  }
}

function readJson(absolutePath) {
  return JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
}

function cleanPushedSource(remoteRef) {
  const commit = runGit(['rev-parse', 'HEAD']);
  const clean = runGit(['status', '--porcelain=v1', '--untracked-files=all']) === '';
  const pushed = runGit(
    ['merge-base', '--is-ancestor', commit, remoteRef],
    {allowFailure: true},
  ) !== null;
  if (!clean || !pushed) {
    throw new Error('receipt assembly requires a clean source commit on the remote');
  }
  return commit;
}

function archivePath(value, label, {directory = false} = {}) {
  if (!value) {
    throw new Error(`${label} is required`);
  }
  const absolutePath = path.isAbsolute(value)
    ? path.resolve(value)
    : path.resolve(REPOSITORY_ROOT, value);
  const archiveRoot = path.join(REPOSITORY_ROOT, 'benchmarks/results/local-archives');
  const relative = path.relative(archiveRoot, absolutePath);
  if (relative === '' || relative.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relative)) {
    throw new Error(`${label} must be below benchmarks/results/local-archives`);
  }
  if (directory && (!fs.existsSync(absolutePath) ||
      !fs.statSync(absolutePath).isDirectory())) {
    throw new Error(`${label} does not exist: ${value}`);
  }
  return absolutePath;
}

export function buildValidationReceipt({
  campaignId,
  sourceCommit,
  artifactLock,
  validationPlan,
  records,
}) {
  const startedAt = records
    .map(({document}) => document.started_at)
    .sort()[0];
  const completedAt = records
    .map(({document}) => document.completed_at)
    .sort()
    .at(-1);
  const checks = records.map(({reference, document}) => ({
    id: document.check_id,
    status: 'pass',
    record: reference,
    evidence: document.evidence,
  }));
  const identity = {
    campaignId,
    sourceCommit,
    artifactLock,
    validationPlan,
    checkRecords: records.map(({reference}) => reference),
  };
  return {
    schema_version: 1,
    receipt_id: `dq-validation-${digestBuffer(stableJson(identity)).slice(0, 16)}`,
    campaign_id: campaignId,
    source_commit: sourceCommit,
    artifact_lock: artifactLock,
    validation_plan: validationPlan,
    started_at: startedAt,
    completed_at: completedAt,
    platform: TARGET_PLATFORM,
    checks,
    passed: true,
  };
}

function parseArguments(argv) {
  const options = {
    artifactLock: process.env.BONVOYAGE_DEDICATED_ARTIFACT_LOCK,
    checksRoot: process.env.BONVOYAGE_DEDICATED_CHECKS_ROOT,
    output: process.env.BONVOYAGE_DEDICATED_VALIDATION_RECEIPT_OUTPUT,
    validationPlan: process.env.BONVOYAGE_DEDICATED_VALIDATION_PLAN ??
      'benchmarks/plans/dedicated-rc-validation-v1.yaml',
    campaign: 'benchmarks/plans/dedicated-qualification-v1.yaml',
    productLock: 'benchmarks/products/lock.json',
    tuningPolicy: 'deploy/tuning/policies/throughput-balanced.yaml',
    remoteRef: process.env.BONVOYAGE_DEDICATED_REMOTE_REF ?? 'origin/main',
  };
  const valueOptions = new Map([
    ['--artifact-lock', 'artifactLock'],
    ['--checks-root', 'checksRoot'],
    ['--output', 'output'],
    ['--validation-plan', 'validationPlan'],
    ['--remote-ref', 'remoteRef'],
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

function assemble(options) {
  if (!options.artifactLock || !options.checksRoot || !options.output) {
    throw new Error('artifact lock, checks root, and receipt output are required');
  }
  const sourceCommit = cleanPushedSource(options.remoteRef);
  const planFile = repositoryFileReference(options.validationPlan, 'validation plan');
  const plan = yaml.load(fs.readFileSync(planFile.absolutePath, 'utf8'));
  const planInspection = inspectValidationPlanDocument(plan);
  if (!planInspection.valid) {
    throw new Error(`validation plan is invalid: ${planInspection.errors.join('; ')}`);
  }
  const lockFile = repositoryFileReference(options.artifactLock, 'artifact lock');
  const lock = readJson(lockFile.absolutePath);
  const campaignFile = repositoryFileReference(options.campaign, 'campaign plan');
  const productLock = repositoryFileReference(options.productLock, 'product lock');
  const tuningPolicy = repositoryFileReference(options.tuningPolicy, 'tuning policy');
  const bindings = collectBindings({
    campaignPath: campaignFile.path,
    productLock,
    tuningPolicyPath: tuningPolicy.path,
  });
  const lockInspection = inspectArtifactLockDocument(lock, {
    campaignId: plan.campaign_id,
    sourceCommit,
    bindings,
    verifySboms: true,
  });
  if (!lockInspection.valid) {
    throw new Error(`artifact lock is invalid: ${lockInspection.errors.join('; ')}`);
  }
  const checksRoot = archivePath(options.checksRoot, 'validation checks root', {
    directory: true,
  });
  const lockReference = {path: lockFile.path, sha256: lockFile.sha256};
  const planReference = {path: planFile.path, sha256: planFile.sha256};
  const records = [];
  for (const check of plan.checks) {
    const checkPath = path.join(checksRoot, check.id, 'check.json');
    if (!fs.existsSync(checkPath)) {
      throw new Error(`validation record is missing for ${check.id}`);
    }
    const reference = repositoryFileReference(checkPath, `${check.id} record`);
    const document = readJson(reference.absolutePath);
    const inspection = inspectValidationCheckDocument(document, {
      campaignId: plan.campaign_id,
      sourceCommit,
      remoteRef: options.remoteRef,
      artifactLock: {...lockReference, document: lock},
      validationPlan: planReference,
      planCheck: check,
      recordPath: reference.path,
      verifyEvidence: true,
    });
    if (!inspection.valid) {
      throw new Error(`${check.id} record is invalid: ${inspection.errors.join('; ')}`);
    }
    records.push({
      reference: {path: reference.path, sha256: reference.sha256},
      document,
    });
  }
  const receipt = buildValidationReceipt({
    campaignId: plan.campaign_id,
    sourceCommit,
    artifactLock: lockReference,
    validationPlan: planReference,
    records,
  });
  const receiptInspection = inspectValidationReceiptDocument(receipt, {
    campaignId: plan.campaign_id,
    sourceCommit,
    artifactLockPath: lockFile.path,
    artifactLockSha256: lockFile.sha256,
    remoteRef: options.remoteRef,
    verifyEvidence: true,
  });
  if (!receiptInspection.valid) {
    throw new Error(`generated receipt is invalid: ${receiptInspection.errors.join('; ')}`);
  }
  const output = archivePath(options.output, 'validation receipt output');
  if (fs.existsSync(output)) {
    throw new Error(`validation receipt output already exists: ${output}`);
  }
  fs.mkdirSync(path.dirname(output), {recursive: true});
  fs.writeFileSync(output, `${JSON.stringify(receipt, null, 2)}\n`, {flag: 'wx'});
  cleanPushedSource(options.remoteRef);
  process.stdout.write(
    `${receipt.receipt_id}: assembled ${receipt.checks.length} passing checks; ` +
    `output=${path.relative(REPOSITORY_ROOT, output)}\n`,
  );
}

function main() {
  assemble(parseArguments(process.argv.slice(2)));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`dedicated-validation-receipt: ${error.message}\n`);
    process.exitCode = 1;
  }
}
