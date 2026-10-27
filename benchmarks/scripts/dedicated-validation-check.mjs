#!/usr/bin/env node

import {spawn, execFileSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {normalizeImageInspection} from './dedicated-artifact-lock.mjs';

import {
  REPOSITORY_ROOT,
  collectBindings,
  digestBuffer,
  inspectArtifactLockDocument,
  inspectValidationCheckDocument,
  inspectValidationPlanDocument,
  repositoryFileReference,
  sha256File,
  validationEvidencePath,
} from './dedicated-preflight.mjs';

const require = createRequire(path.join(REPOSITORY_ROOT, 'package.json'));
const yaml = require('js-yaml');

const TARGET_PLATFORM = {
  operating_system: 'Ubuntu 24.04 LTS',
  architecture: 'x86_64',
  container_platform: 'linux/amd64',
};

function run(command, arguments_, {allowFailure = false} = {}) {
  try {
    return execFileSync(command, arguments_, {
      cwd: REPOSITORY_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', allowFailure ? 'ignore' : 'pipe'],
    }).trim();
  } catch (error) {
    if (allowFailure) {
      return null;
    }
    const detail = error.stderr?.toString().trim();
    throw new Error(detail || `${command} ${arguments_.join(' ')} failed`);
  }
}

function readJson(absolutePath) {
  return JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
}

function sourceFacts(remoteRef) {
  const commit = run('git', ['rev-parse', 'HEAD']);
  const clean = run('git', ['status', '--porcelain=v1', '--untracked-files=all']) === '';
  const pushed = run(
    'git',
    ['merge-base', '--is-ancestor', commit, remoteRef],
    {allowFailure: true},
  ) !== null;
  return {commit, clean, pushed};
}

function executorPlatform() {
  if (process.platform !== 'linux' || process.arch !== 'x64') {
    throw new Error('exact-release validation must run on Linux x86_64');
  }
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
  if (values.ID !== 'ubuntu' || values.VERSION_ID !== '24.04') {
    throw new Error(
      `exact-release validation requires Ubuntu 24.04; found ${values.PRETTY_NAME ?? 'unknown'}`,
    );
  }
  return TARGET_PLATFORM;
}

function archiveDirectory(value, label, {mustExist = false} = {}) {
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
  if (mustExist && (!fs.existsSync(absolutePath) ||
      !fs.statSync(absolutePath).isDirectory())) {
    throw new Error(`${label} does not exist: ${value}`);
  }
  return absolutePath;
}

function imageIdentity(reference) {
  const document = JSON.parse(run(
    'docker',
    ['image', 'inspect', reference, '--format', '{{json .}}'],
  ));
  const platform = `${document.Os}/${document.Architecture}`;
  if (platform !== 'linux/amd64') {
    throw new Error(`runtime image is ${platform}; linux/amd64 is required`);
  }
  return {
    id: document.Id,
    upstreamHttp1Client:
      document.Config?.Labels?.['io.routesphere.bonvoyage.upstream-http1-client'],
  };
}

function environmentRecord(values) {
  return Object.entries(values)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, value]) => ({name, value_sha256: digestBuffer(value)}));
}

export function validateTestClientPolicy(check, lock, productLock, inspection, user) {
  const client = productLock.load_generator;
  const digest = client.manifests.linux_amd64;
  const reference = `${client.repository}@${digest}`;
  const configured = check.fixed_environment;
  if (configured.BONVOYAGE_OHA_IMAGE !== reference ||
      configured.BONVOYAGE_RC_TEST_CLIENT_USER !== '65532:65532' ||
      user !== configured.BONVOYAGE_RC_TEST_CLIENT_USER) {
    throw new Error('RC test-client policy requires the stock pinned AMD64 client and executor UID/GID 65532:65532');
  }
  const artifact = lock.artifacts.find(({id}) => id === 'load-generator');
  const image = normalizeImageInspection(inspection, {
    id: 'load-generator', reference, expectedPlatformDigest: digest,
  });
  if (!artifact || artifact.image_reference !== reference ||
      artifact.platform_digest !== digest || artifact.image_digest !== image.id) {
    throw new Error('RC test client differs from the locked stock load-generator');
  }
  return {policy: 'stock-image-explicit-caller-uid-v1', reference,
    image_digest: image.id, platform_digest: image.platformDigest,
    image_default_user: inspection.Config?.User ?? '', executor_user: user};
}

function captureTestClientPolicy(check, lock, productLock) {
  if (check.id !== 'phase3-integration') return undefined;
  const reference = check.fixed_environment.BONVOYAGE_OHA_IMAGE;
  if (!reference) throw new Error('RC test-client image policy is missing');
  const inspection = JSON.parse(run('docker',
    ['image', 'inspect', reference, '--format', '{{json .}}']));
  return validateTestClientPolicy(check, lock, productLock, inspection,
    `${process.geteuid()}:${process.getegid()}`);
}

export function prepareCheckEnvironment(check, checkDirectory, baseEnvironment) {
  const selected = {};
  for (const name of check.required_environment) {
    const value = baseEnvironment[name];
    if (!value) {
      throw new Error(`${check.id} requires environment variable ${name}`);
    }
    selected[name] = value;
  }
  for (const name of check.derived_environment) {
    selected[name] = validationEvidencePath(name, checkDirectory);
  }
  Object.assign(selected, check.fixed_environment);
  return selected;
}

function evidenceFiles(root) {
  const files = [];
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, {withFileTypes: true})) {
      const absolutePath = path.join(current, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error(`validation evidence must not contain symlinks: ${absolutePath}`);
      }
      if (entry.isDirectory()) {
        pending.push(absolutePath);
      } else if (entry.isFile() && !['check.json', 'failure.json'].includes(entry.name)) {
        const relativePath = path.relative(REPOSITORY_ROOT, absolutePath)
          .split(path.sep).join('/');
        files.push({path: relativePath, sha256: sha256File(absolutePath)});
      }
    }
  }
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

export function buildValidationCheckRecord({
  check,
  campaignId,
  sourceCommit,
  artifactLock,
  validationPlan,
  startedAt,
  completedAt,
  environment,
  runtimeReference,
  runtimeDigestBefore,
  runtimeDigestAfter,
  remoteRef,
  evidence,
}) {
  return {
    schema_version: 1,
    check_id: check.id,
    campaign_id: campaignId,
    source_commit: sourceCommit,
    artifact_lock: artifactLock,
    validation_plan: validationPlan,
    started_at: startedAt,
    completed_at: completedAt,
    artifact_platform: TARGET_PLATFORM,
    executor: TARGET_PLATFORM,
    command: check.command,
    environment: environmentRecord(environment),
    runtime_image: {
      reference: runtimeReference,
      image_digest_before: runtimeDigestBefore,
      image_digest_after: runtimeDigestAfter,
    },
    remote_ref: remoteRef,
    exit_code: 0,
    source_clean_before: true,
    source_clean_after: true,
    evidence,
    status: 'pass',
  };
}

function runPlannedCommand(check, environment, logPath) {
  return new Promise((resolve, reject) => {
    const log = fs.createWriteStream(logPath, {flags: 'wx'});
    const argv = check.command.argv;
    log.write(`check_id=${check.id}\n`);
    log.write(`command_argv=${JSON.stringify(argv)}\n`);
    log.write(`environment_names=${JSON.stringify(Object.keys(environment).sort())}\n`);
    log.write('--- command output ---\n');
    const childEnvironment = {...process.env};
    for (const name of Object.keys(childEnvironment)) {
      if (name.startsWith('BONVOYAGE_') || [
        'ASAN_OPTIONS',
        'CFLAGS',
        'CPPFLAGS',
        'CXXFLAGS',
        'GODEBUG',
        'GOFLAGS',
        'LDFLAGS',
        'LD_LIBRARY_PATH',
        'LD_PRELOAD',
        'MAKEFLAGS',
        'MFLAGS',
        'NODE_OPTIONS',
        'UBSAN_OPTIONS',
      ].includes(name)) {
        delete childEnvironment[name];
      }
    }
    const child = spawn(argv[0], argv.slice(1), {
      cwd: REPOSITORY_ROOT,
      env: {...childEnvironment, ...environment},
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', (chunk) => {
      process.stdout.write(chunk);
      log.write(chunk);
    });
    child.stderr.on('data', (chunk) => {
      process.stderr.write(chunk);
      log.write(chunk);
    });
    let settled = false;
    child.on('error', (error) => {
      if (!settled) {
        settled = true;
        log.end(() => reject(error));
      }
    });
    child.on('close', (code, signal) => {
      if (settled) {
        return;
      }
      settled = true;
      log.write(`\n--- command result ---\nexit_code=${code ?? 'null'}\n`);
      log.write(`signal=${signal ?? 'none'}\n`);
      log.end(() => resolve({code, signal}));
    });
  });
}

function parseArguments(argv) {
  const options = {
    checkId: process.env.BONVOYAGE_DEDICATED_CHECK_ID,
    artifactLock: process.env.BONVOYAGE_DEDICATED_ARTIFACT_LOCK,
    runtimeImage: process.env.BONVOYAGE_DEDICATED_RUNTIME_IMAGE,
    checksRoot: process.env.BONVOYAGE_DEDICATED_CHECKS_ROOT,
    validationPlan: process.env.BONVOYAGE_DEDICATED_VALIDATION_PLAN ??
      'benchmarks/plans/dedicated-rc-validation-v1.yaml',
    campaign: 'benchmarks/plans/dedicated-qualification-v1.yaml',
    productLock: 'benchmarks/products/lock.json',
    tuningPolicy: 'deploy/tuning/policies/throughput-balanced.yaml',
    remoteRef: process.env.BONVOYAGE_DEDICATED_REMOTE_REF ?? 'origin/main',
  };
  const valueOptions = new Map([
    ['--check', 'checkId'],
    ['--artifact-lock', 'artifactLock'],
    ['--runtime-image', 'runtimeImage'],
    ['--checks-root', 'checksRoot'],
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

async function execute(options) {
  const executor = executorPlatform();
  const sourceBefore = sourceFacts(options.remoteRef);
  if (!sourceBefore.clean || !sourceBefore.pushed) {
    throw new Error('validation requires a clean source commit present on the remote');
  }
  if (!options.checkId || !options.runtimeImage || !options.artifactLock ||
      !options.checksRoot) {
    throw new Error(
      'check ID, artifact lock, runtime image, and checks root are required',
    );
  }

  const planFile = repositoryFileReference(options.validationPlan, 'validation plan');
  const plan = yaml.load(fs.readFileSync(planFile.absolutePath, 'utf8'));
  const planInspection = inspectValidationPlanDocument(plan);
  if (!planInspection.valid) {
    throw new Error(`validation plan is invalid: ${planInspection.errors.join('; ')}`);
  }
  const check = plan.checks.find(({id}) => id === options.checkId);
  if (!check) {
    throw new Error(`validation plan has no check ${options.checkId}`);
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
    sourceCommit: sourceBefore.commit,
    bindings,
    verifySboms: true,
  });
  if (!lockInspection.valid) {
    throw new Error(`artifact lock is invalid: ${lockInspection.errors.join('; ')}`);
  }
  const lockedRuntime = lock.artifacts.find(({id}) => id === 'bonvoyage');
  const testClientBefore = captureTestClientPolicy(check, lock, readJson(productLock.absolutePath));
  const runtimeBefore = imageIdentity(options.runtimeImage);
  if (runtimeBefore.id !== lockedRuntime.image_digest ||
      runtimeBefore.upstreamHttp1Client !==
        lockedRuntime.metadata.upstream_http1_client) {
    throw new Error('runtime image does not match the BonVoyage artifact lock');
  }

  const checksRoot = archiveDirectory(options.checksRoot, 'validation checks root');
  const checkDirectory = path.join(checksRoot, check.id);
  if (fs.existsSync(checkDirectory)) {
    throw new Error(`validation check output already exists: ${checkDirectory}`);
  }
  fs.mkdirSync(path.join(checkDirectory, 'evidence'), {recursive: true});
  if (testClientBefore) {
    fs.writeFileSync(path.join(checkDirectory, 'evidence', 'test-client-before.json'),
      `${JSON.stringify(testClientBefore, null, 2)}\n`, {flag: 'wx'});
  }
  const relativeCheckDirectory = path.relative(REPOSITORY_ROOT, checkDirectory)
    .split(path.sep).join('/');
  const selectedEnvironment = prepareCheckEnvironment(
    check,
    relativeCheckDirectory,
    process.env,
  );
  const commandEnvironment = {
    ...selectedEnvironment,
    BONVOYAGE_BUILD_JOBS: '2',
    BONVOYAGE_BUILD_PLATFORM: 'linux/amd64',
    BONVOYAGE_DATAPLANE_IMAGE: options.runtimeImage,
    BONVOYAGE_LOCKED_DATAPLANE_IMAGE_ID: lockedRuntime.image_digest,
    BONVOYAGE_DEDICATED_ARTIFACT_LOCK: lockFile.path,
    BONVOYAGE_DEDICATED_REMOTE_REF: options.remoteRef,
    BONVOYAGE_UPSTREAM_HTTP1_CLIENT:
      lockedRuntime.metadata.upstream_http1_client,
  };
  const startedAt = new Date().toISOString();
  const result = await runPlannedCommand(
    check,
    commandEnvironment,
    path.join(checkDirectory, 'command.log'),
  );
  const completedAt = new Date().toISOString();
  const sourceAfter = sourceFacts(options.remoteRef);
  const runtimeAfter = imageIdentity(options.runtimeImage);
  // A changed or missing client cannot produce a passing validation receipt.
  if (testClientBefore) {
    const testClientAfter = captureTestClientPolicy(check, lock, readJson(productLock.absolutePath));
    fs.writeFileSync(path.join(checkDirectory, 'evidence', 'test-client-after.json'),
      `${JSON.stringify(testClientAfter, null, 2)}\n`, {flag: 'wx'});
    if (JSON.stringify(testClientBefore) !== JSON.stringify(testClientAfter)) {
      throw new Error('RC test-client identity changed during validation');
    }
  }
  if (result.code !== 0 || result.signal || !sourceAfter.clean ||
      !sourceAfter.pushed || sourceAfter.commit !== sourceBefore.commit ||
      runtimeAfter.id !== lockedRuntime.image_digest ||
      runtimeAfter.upstreamHttp1Client !==
        lockedRuntime.metadata.upstream_http1_client) {
    const failure = {
      check_id: check.id,
      completed_at: completedAt,
      exit_code: result.code,
      signal: result.signal,
      source_clean_after: sourceAfter.clean,
      source_pushed_after: sourceAfter.pushed,
      source_commit_unchanged: sourceAfter.commit === sourceBefore.commit,
      runtime_image_unchanged: runtimeAfter.id === lockedRuntime.image_digest &&
        runtimeAfter.upstreamHttp1Client ===
          lockedRuntime.metadata.upstream_http1_client,
    };
    fs.writeFileSync(
      path.join(checkDirectory, 'failure.json'),
      `${JSON.stringify(failure, null, 2)}\n`,
      {flag: 'wx'},
    );
    throw new Error(`${check.id} failed; retained failure evidence in ${checkDirectory}`);
  }
  const artifactReference = {path: lockFile.path, sha256: lockFile.sha256};
  const planReference = {path: planFile.path, sha256: planFile.sha256};
  const record = buildValidationCheckRecord({
    check,
    campaignId: plan.campaign_id,
    sourceCommit: sourceBefore.commit,
    artifactLock: artifactReference,
    validationPlan: planReference,
    startedAt,
    completedAt,
    environment: commandEnvironment,
    runtimeReference: options.runtimeImage,
    runtimeDigestBefore: runtimeBefore.id,
    runtimeDigestAfter: runtimeAfter.id,
    remoteRef: options.remoteRef,
    evidence: evidenceFiles(checkDirectory),
  });
  const recordInspection = inspectValidationCheckDocument(record, {
    campaignId: plan.campaign_id,
    sourceCommit: sourceBefore.commit,
    remoteRef: options.remoteRef,
    artifactLock: {...artifactReference, document: lock},
    validationPlan: planReference,
    planCheck: check,
    recordPath: `${relativeCheckDirectory}/check.json`,
    verifyEvidence: true,
  });
  if (!recordInspection.valid) {
    throw new Error(`generated check record is invalid: ${recordInspection.errors.join('; ')}`);
  }
  fs.writeFileSync(
    path.join(checkDirectory, 'check.json'),
    `${JSON.stringify(record, null, 2)}\n`,
    {flag: 'wx'},
  );
  process.stdout.write(
    `${check.id}: pass; ${record.evidence.length} evidence files; executor=` +
    `${executor.operating_system}/${executor.architecture}\n`,
  );
}

async function main() {
  await execute(parseArguments(process.argv.slice(2)));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`dedicated-validation-check: ${error.message}\n`);
    process.exitCode = 1;
  });
}
