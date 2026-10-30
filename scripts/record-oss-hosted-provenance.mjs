#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const PUBLIC_REPOSITORY = 'https://github.com/routesphere-global/bonvoyage';
const PUBLIC_REPOSITORY_SLUG = 'routesphere-global/bonvoyage';
const CLASSIFICATION = 'routesphere-bonvoyage-oss-hosted-provenance';
const COMMIT = /^[a-f0-9]{40}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const RUN_ID = /^[1-9][0-9]*$/u;
const TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const ATTESTATION_ID = /^[A-Za-z0-9._:-]{1,256}$/u;
const MAX_CONTROL_BYTES = 8 * 1024 * 1024;
const MAX_BUNDLE_BYTES = 16 * 1024 * 1024;
const FORMATS = Object.freeze({
  debian: Object.freeze({
    receipt: 'build-receipt.json',
    classification: 'routesphere-bonvoyage-oss-deb-build',
    subjectField: 'package',
    workflow: '.github/workflows/oss-deb-reproducibility.yml',
    provenanceArtifact: 'oss-deb-provenance',
  }),
  oci: Object.freeze({
    receipt: 'oci-builder-execution.json',
    classification: 'routesphere-bonvoyage-oss-oci-builder-execution',
    subjectField: 'archive',
    workflow: '.github/workflows/oss-oci-reproducibility.yml',
    provenanceArtifact: 'oss-oci-provenance',
  }),
});

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

function requireString(value, label) {
  requireCondition(typeof value === 'string' && value.length > 0 && value === value.trim() &&
    !/[\r\n\0]/u.test(value), `${label} must be a nonempty single-line string`);
  return value;
}

function normalizePositiveInteger(value, label) {
  requireCondition(typeof value === 'string' && RUN_ID.test(value),
    `${label} must be a positive integer string`);
  return value;
}

function sha256File(filePath, maximumBytes = Number.MAX_SAFE_INTEGER) {
  const descriptor = fs.openSync(filePath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && before.nlink === 1 && before.size > 0 &&
      before.size <= maximumBytes, `${filePath} must be a bounded regular single-link file`);
    const digest = crypto.createHash('sha256');
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    while (true) {
      const count = fs.readSync(descriptor, chunk, 0, chunk.length, null);
      if (count === 0) break;
      digest.update(chunk.subarray(0, count));
      bytes += count;
    }
    const after = fs.fstatSync(descriptor);
    requireCondition(before.size === after.size && before.mtimeMs === after.mtimeMs &&
      before.ctimeMs === after.ctimeMs && bytes === after.size,
    `${filePath} changed while it was read`);
    return {bytes, sha256: digest.digest('hex')};
  } finally {
    fs.closeSync(descriptor);
  }
}

function readCanonicalJson(filePath, label) {
  const identity = sha256File(filePath, MAX_CONTROL_BYTES);
  let text;
  let value;
  try {
    text = fs.readFileSync(filePath, 'utf8');
    value = JSON.parse(text);
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
  requireObject(value, label);
  requireCondition(text === `${JSON.stringify(value, null, 2)}\n`,
    `${label} must use canonical JSON encoding`);
  return {value, ...identity};
}

function validateDirectory(directory, label) {
  const stat = fs.lstatSync(directory);
  requireCondition(stat.isDirectory() && !stat.isSymbolicLink(),
    `${label} must be a real directory`);
}

function validateFilename(value, label) {
  requireString(value, label);
  requireCondition(path.basename(value) === value && value !== '.' && value !== '..',
    `${label} must be one filename`);
  return value;
}

function validateSource(source, options, label) {
  requireObject(source, label);
  requireCondition(source.repository === PUBLIC_REPOSITORY &&
    source.commit === options.commit && source.tag === options.tag && source.dirty === false,
  `${label} must bind the exact clean public source`);
}

function validateContext(options, specification) {
  requireCondition(options.repository === PUBLIC_REPOSITORY_SLUG,
    'hosted provenance is public-repository-only');
  requireCondition(COMMIT.test(options.commit ?? ''),
    'hosted provenance requires a lowercase full Git commit');
  requireCondition(TAG.test(options.tag ?? ''),
    'hosted provenance requires a strict release tag');
  normalizePositiveInteger(options.runId, 'run ID');
  normalizePositiveInteger(options.runAttempt, 'run attempt');
  const expectedWorkflowRef =
    `${PUBLIC_REPOSITORY_SLUG}/${specification.workflow}@refs/tags/${options.tag}`;
  requireCondition(options.workflowRef === expectedWorkflowRef,
    'workflow ref does not bind the expected tagged producer workflow');
  requireCondition(options.workflowSha === options.commit,
    'workflow SHA must match the exact source commit');
}

export function resolveHostedProvenanceSubject(options) {
  const specification = FORMATS[options.format];
  requireCondition(specification !== undefined, 'format must be debian or oci');
  validateContext(options, specification);
  const inputRoot = path.resolve(requireString(options.input, 'input directory'));
  validateDirectory(inputRoot, 'input directory');
  const receiptPath = path.join(inputRoot, specification.receipt);
  const receipt = readCanonicalJson(receiptPath, `${options.format} build receipt`);
  requireCondition(receipt.value.classification === specification.classification,
    `${options.format} build receipt classification changed`);
  validateSource(receipt.value.source, options, `${options.format} build source`);
  requireCondition(receipt.value.release_admitted === false &&
    receipt.value.publishable === false &&
    receipt.value.technical_candidate_built === true,
  `${options.format} build receipt does not describe a bounded technical candidate`);

  const declared = requireObject(receipt.value[specification.subjectField],
    `${options.format} subject`);
  const filename = validateFilename(declared.path, `${options.format} subject path`);
  requireCondition(Number.isSafeInteger(declared.bytes) && declared.bytes > 0 &&
    typeof declared.sha256 === 'string' && SHA256.test(declared.sha256),
  `${options.format} subject identity is invalid`);
  const subjectPath = path.join(inputRoot, filename);
  const subject = sha256File(subjectPath);
  requireCondition(subject.bytes === declared.bytes && subject.sha256 === declared.sha256,
    `${options.format} subject bytes do not match the build receipt`);

  return {
    format: options.format,
    specification,
    subject: {path: filename, absolute_path: subjectPath, ...subject},
    receipt: {path: specification.receipt, absolute_path: receiptPath,
      bytes: receipt.bytes, sha256: receipt.sha256},
    source: {repository: PUBLIC_REPOSITORY, commit: options.commit,
      tag: options.tag, dirty: false},
  };
}

function writeGithubOutputs(filePath, resolved) {
  const outputPath = path.resolve(requireString(filePath, 'GitHub output path'));
  const descriptor = fs.openSync(outputPath,
    fs.constants.O_WRONLY | fs.constants.O_APPEND | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const metadata = fs.fstatSync(descriptor);
    requireCondition(metadata.isFile() && metadata.nlink === 1,
      'GitHub output must be a regular single-link file');
    fs.writeSync(descriptor, [
      `subject_path=${resolved.subject.absolute_path}`,
      `subject_sha256=${resolved.subject.sha256}`,
      `subject_name=${resolved.subject.path}`,
    ].join('\n') + '\n', null, 'utf8');
  } finally {
    fs.closeSync(descriptor);
  }
}

function validateAttestationUrl(value) {
  const text = requireString(value, 'attestation URL');
  let url;
  try {
    url = new URL(text);
  } catch (error) {
    fail(`attestation URL is invalid: ${error.message}`);
  }
  requireCondition(url.protocol === 'https:' && url.hostname === 'github.com' &&
    url.username === '' && url.password === '' && url.hash === '' &&
    url.pathname.startsWith(`/${PUBLIC_REPOSITORY_SLUG}/attestations/`),
  'attestation URL must identify this public repository');
  return url.toString();
}

export function recordHostedProvenance(options) {
  const resolved = resolveHostedProvenanceSubject(options);
  const bundlePath = path.resolve(requireString(options.bundle, 'attestation bundle path'));
  const bundle = sha256File(bundlePath, MAX_BUNDLE_BYTES);
  const attestationId = requireString(options.attestationId, 'attestation ID');
  requireCondition(ATTESTATION_ID.test(attestationId), 'attestation ID is invalid');
  const attestationUrl = validateAttestationUrl(options.attestationUrl);

  const outputRoot = path.resolve(requireString(options.output, 'output directory'));
  if (fs.existsSync(outputRoot)) {
    validateDirectory(outputRoot, 'output directory');
    requireCondition(fs.readdirSync(outputRoot).length === 0,
      'output directory must be empty');
  } else {
    fs.mkdirSync(outputRoot, {recursive: true, mode: 0o700});
  }
  const copiedBundleName = 'provenance.sigstore.jsonl';
  const copiedBundlePath = path.join(outputRoot, copiedBundleName);
  fs.copyFileSync(bundlePath, copiedBundlePath, fs.constants.COPYFILE_EXCL);
  const copiedBundle = sha256File(copiedBundlePath, MAX_BUNDLE_BYTES);
  requireCondition(copiedBundle.bytes === bundle.bytes && copiedBundle.sha256 === bundle.sha256,
    'copied attestation bundle identity changed');

  const receipt = {
    schema_version: 1,
    classification: CLASSIFICATION,
    format: resolved.format,
    subject: {
      path: resolved.subject.path,
      bytes: resolved.subject.bytes,
      sha256: resolved.subject.sha256,
    },
    build_receipt: {
      path: resolved.receipt.path,
      bytes: resolved.receipt.bytes,
      sha256: resolved.receipt.sha256,
    },
    source: resolved.source,
    producer: {
      workflow: resolved.specification.workflow,
      workflow_ref: options.workflowRef,
      workflow_sha: options.workflowSha,
      event: 'workflow_dispatch',
      runner: 'ubuntu-24.04',
      hosted: true,
      run_id: options.runId,
      run_attempt: options.runAttempt,
    },
    attestation: {
      id: attestationId,
      url: attestationUrl,
      bundle: {
        path: copiedBundleName,
        bytes: copiedBundle.bytes,
        sha256: copiedBundle.sha256,
      },
      predicate_type: 'https://slsa.dev/provenance/v1',
      slsa_build_level: 2,
    },
    authority: {
      provenance_created: true,
      signature_created: false,
      release_admitted: false,
      publishable: false,
      github_release_created: false,
      package_uploaded: false,
      container_uploaded: false,
    },
  };
  const receiptPath = path.join(outputRoot, 'provenance-receipt.json');
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`,
    {encoding: 'utf8', flag: 'wx', mode: 0o600});
  return {receipt, receiptPath, bundlePath: copiedBundlePath,
    artifactName: resolved.specification.provenanceArtifact};
}

function parseArguments(argv) {
  const mapping = {
    '--mode': 'mode',
    '--format': 'format',
    '--input': 'input',
    '--repository': 'repository',
    '--commit': 'commit',
    '--tag': 'tag',
    '--run-id': 'runId',
    '--run-attempt': 'runAttempt',
    '--workflow-ref': 'workflowRef',
    '--workflow-sha': 'workflowSha',
    '--github-output': 'githubOutput',
    '--bundle': 'bundle',
    '--attestation-id': 'attestationId',
    '--attestation-url': 'attestationUrl',
    '--output': 'output',
  };
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const key = mapping[argv[index]];
    requireCondition(key !== undefined && options[key] === undefined &&
      index + 1 < argv.length, `unsupported, duplicate or incomplete argument ${argv[index]}`);
    options[key] = argv[index + 1];
    index += 1;
  }
  const shared = [
    'mode', 'format', 'input', 'repository', 'commit', 'tag', 'runId',
    'runAttempt', 'workflowRef', 'workflowSha',
  ];
  requireCondition(shared.every((key) => options[key] !== undefined),
    'all hosted provenance context arguments are required');
  requireCondition(['prepare', 'record'].includes(options.mode),
    'mode must be prepare or record');
  if (options.mode === 'prepare') {
    requireCondition(options.githubOutput !== undefined &&
      ['bundle', 'attestationId', 'attestationUrl', 'output'].every((key) =>
        options[key] === undefined), 'prepare mode requires only --github-output');
  } else {
    requireCondition(['bundle', 'attestationId', 'attestationUrl', 'output'].every((key) =>
      options[key] !== undefined) && options.githubOutput === undefined,
    'record mode requires bundle, attestation identity and output arguments');
  }
  return options;
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  try {
    const options = parseArguments(process.argv.slice(2));
    if (options.mode === 'prepare') {
      const resolved = resolveHostedProvenanceSubject(options);
      writeGithubOutputs(options.githubOutput, resolved);
      process.stdout.write(`${JSON.stringify({
        format: resolved.format,
        subject: {path: resolved.subject.path, bytes: resolved.subject.bytes,
          sha256: resolved.subject.sha256},
      }, null, 2)}\n`);
    } else {
      const result = recordHostedProvenance(options);
      process.stdout.write(`${JSON.stringify(result.receipt, null, 2)}\n`);
    }
  } catch (error) {
    process.stderr.write(`Hosted provenance evidence rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}
