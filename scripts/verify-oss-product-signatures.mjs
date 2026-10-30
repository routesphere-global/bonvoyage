#!/usr/bin/env node

import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

import {
  fileIdentity,
  readCanonicalJson,
  validateProductSignatureReceipt,
} from './finalize-oss-product-signatures.mjs';

const CLASSIFICATION =
  'routesphere-bonvoyage-oss-product-signature-independent-verification';
const ARTIFACT_IDS = Object.freeze([
  'gateway-deb-linux-amd64', 'gateway-oci-linux-amd64',
]);
const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const SAFE_RELATIVE = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._+~@/-]+$/u;

function fail(message) { throw new Error(message); }
function requireCondition(condition, message) { if (!condition) fail(message); }
function object(value, label) {
  requireCondition(value !== null && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  return value;
}
function array(value, label) {
  requireCondition(Array.isArray(value), `${label} must be an array`);
  return value;
}
function string(value, label) {
  requireCondition(typeof value === 'string' && value.length > 0 && value === value.trim() &&
    !/[\r\n\0]/u.test(value), `${label} must be a nonempty single-line string`);
  return value;
}
function exactKeys(value, expected, label) {
  const actual = Object.keys(object(value, label)).sort();
  const wanted = [...expected].sort();
  requireCondition(actual.length === wanted.length &&
    actual.every((item, index) => item === wanted[index]),
  `${label} fields must be exactly [${wanted.join(', ')}]`);
}
function relative(value, label) {
  string(value, label);
  requireCondition(SAFE_RELATIVE.test(value) && path.posix.normalize(value) === value,
    `${label} must be a safe normalized relative path`);
  return value;
}
function integer(value, label) {
  requireCondition(Number.isSafeInteger(value) && value >= 0,
    `${label} must be a nonnegative safe integer`);
  return value;
}
function canonicalTime(value, label) {
  string(value, label);
  requireCondition(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
    new Date(value).toISOString() === value, `${label} must be canonical UTC time`);
  return value;
}

function sanitizedEnvironment() {
  const environment = {...process.env};
  for (const name of [
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL',
    'GITHUB_TOKEN', 'GH_TOKEN',
  ]) delete environment[name];
  return environment;
}

function runCosign(cosign, args, label) {
  string(cosign, 'Cosign executable');
  const result = spawnSync(cosign, args, {
    encoding: 'utf8',
    env: sanitizedEnvironment(),
    maxBuffer: MAX_OUTPUT_BYTES,
    timeout: 120_000,
  });
  requireCondition(!result.error, `${label}: unable to execute Cosign: ${result.error?.message}`);
  requireCondition(result.status === 0,
    `${label}: Cosign exited ${result.status}: ${(result.stderr || result.stdout || '').trim()}`);
  const transcript = [
    `stdout:\n${result.stdout ?? ''}`,
    `stderr:\n${result.stderr ?? ''}`,
  ].join('');
  requireCondition(Buffer.byteLength(transcript) <= MAX_OUTPUT_BYTES,
    `${label}: Cosign output is oversized`);
  return transcript;
}

function captureVersion(cosign, outputPath) {
  const result = runCosign(cosign, ['version', '--json'], 'Cosign version');
  const stdout = result.slice('stdout:\n'.length, result.indexOf('stderr:\n'));
  let version;
  try {
    version = JSON.parse(stdout);
  } catch (error) {
    fail(`Cosign version output is not JSON: ${error.message}`);
  }
  object(version, 'Cosign version output');
  fs.writeFileSync(outputPath, `${JSON.stringify(version, null, 2)}\n`, {
    flag: 'wx', mode: 0o600,
  });
  return version;
}

function walkOutput(outputRoot, evidenceRoot, receiptPath) {
  const files = [];
  function walk(directory) {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const absolute = path.join(directory, entry.name);
      const stat = fs.lstatSync(absolute);
      requireCondition(!stat.isSymbolicLink(),
        `independent verification contains link ${path.relative(outputRoot, absolute)}`);
      if (stat.isDirectory()) {
        walk(absolute);
      } else {
        requireCondition(stat.isFile() && stat.nlink === 1,
          `independent verification contains non-regular or linked file ${absolute}`);
        if (absolute !== receiptPath) {
          const relativePath = path.relative(evidenceRoot, absolute).split(path.sep).join('/');
          files.push({path: relativePath, ...fileIdentity(absolute, relativePath)});
        }
      }
    }
  }
  walk(outputRoot);
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

function verificationArguments(receipt, artifactPath, bundlePath, offline) {
  const args = [
    'verify-blob',
    '--bundle', bundlePath,
    '--certificate-identity', receipt.cosign.subject,
    '--certificate-oidc-issuer', receipt.cosign.issuer,
    '--certificate-github-workflow-repository', 'routesphere-global/bonvoyage',
    '--certificate-github-workflow-sha', receipt.source.commit,
    '--certificate-github-workflow-ref', `refs/tags/${receipt.source.tag}`,
    '--certificate-github-workflow-trigger', receipt.workflow.event,
  ];
  if (offline) args.push('--offline=true');
  args.push(artifactPath);
  return args;
}

export function validateIndependentProductVerification({intakeRoot, evidenceRoot}) {
  const root = path.resolve(evidenceRoot);
  const outputRoot = path.join(root, 'independent-verification');
  const receiptPath = path.join(outputRoot, 'independent-verification-receipt.json');
  const base = validateProductSignatureReceipt({
    intakeRoot,
    evidenceRoot: root,
    allowIndependentVerification: true,
  });
  const record = readCanonicalJson(receiptPath, 'independent verification receipt');
  const receipt = record.value;
  exactKeys(receipt, [
    'schema_version', 'classification', 'product', 'created_at',
    'product_signature_receipt', 'source', 'signing_workflow', 'cosign',
    'artifacts', 'files', 'authority',
  ], 'independent verification receipt');
  requireCondition(receipt.schema_version === 1 && receipt.classification === CLASSIFICATION &&
    receipt.product === base.receipt.product,
  'independent verification schema or product is unsupported');
  canonicalTime(receipt.created_at, 'independent verification created_at');
  exactKeys(receipt.product_signature_receipt, ['path', 'bytes', 'sha256'],
    'product signature receipt reference');
  requireCondition(receipt.product_signature_receipt.path === 'product-signature-receipt.json' &&
    receipt.product_signature_receipt.bytes === base.receiptRecord.bytes &&
    receipt.product_signature_receipt.sha256 === base.receiptRecord.sha256,
  'independent verification does not bind the exact product signature receipt');
  requireCondition(JSON.stringify(receipt.source) === JSON.stringify(base.receipt.source) &&
    JSON.stringify(receipt.signing_workflow) === JSON.stringify(base.receipt.workflow),
  'independent verification source or workflow binding changed');

  exactKeys(receipt.cosign, ['version', 'version_record'],
    'independent verification Cosign');
  const versionPath = relative(receipt.cosign.version_record.path,
    'independent verification Cosign version path');
  const versionRecord = readCanonicalJson(path.join(root, versionPath),
    'independent verification Cosign version');
  requireCondition(receipt.cosign.version === base.receipt.cosign.version &&
    versionRecord.value.gitVersion === receipt.cosign.version &&
    versionRecord.bytes === receipt.cosign.version_record.bytes &&
    versionRecord.sha256 === receipt.cosign.version_record.sha256,
  'independent verification Cosign version changed');

  const artifacts = array(receipt.artifacts, 'independent verification artifacts');
  requireCondition(artifacts.length === 2 &&
    JSON.stringify(artifacts.map(({id}) => id)) === JSON.stringify(ARTIFACT_IDS),
  'independent verification artifact set changed');
  for (const [index, artifact] of artifacts.entries()) {
    const baseArtifact = base.receipt.artifacts[index];
    exactKeys(artifact, [
      'id', 'artifact', 'bundle', 'online_verification', 'offline_verification',
    ], `independent verification artifacts[${index}]`);
    requireCondition(artifact.id === baseArtifact.id &&
      JSON.stringify(artifact.artifact) === JSON.stringify(baseArtifact.artifact) &&
      JSON.stringify(artifact.bundle) === JSON.stringify(baseArtifact.bundle),
    `independent verification artifact ${baseArtifact.id} binding changed`);
    for (const [mode, expectedPath] of [
      ['online_verification',
        `independent-verification/verification/${artifact.id}.online.txt`],
      ['offline_verification',
        `independent-verification/verification/${artifact.id}.offline.txt`],
    ]) {
      const reference = object(artifact[mode], `${artifact.id}.${mode}`);
      exactKeys(reference, ['path', 'bytes', 'sha256'], `${artifact.id}.${mode}`);
      requireCondition(reference.path === expectedPath, `${artifact.id}.${mode} path changed`);
      const identity = fileIdentity(path.join(root, reference.path), `${artifact.id}.${mode}`);
      requireCondition(identity.bytes === integer(reference.bytes, `${artifact.id}.${mode}.bytes`) &&
        identity.sha256 === reference.sha256,
      `${artifact.id}.${mode} does not match its receipt`);
    }
  }

  const expectedFiles = array(receipt.files, 'independent verification files').map(
    (value, index) => {
      exactKeys(value, ['path', 'bytes', 'sha256'], `independent files[${index}]`);
      return {
        path: relative(value.path, `independent files[${index}].path`),
        bytes: integer(value.bytes, `independent files[${index}].bytes`),
        sha256: string(value.sha256, `independent files[${index}].sha256`),
      };
    });
  const actualFiles = walkOutput(outputRoot, root, receiptPath);
  requireCondition(JSON.stringify(expectedFiles) === JSON.stringify(actualFiles),
    'independent verification evidence inventory changed');
  exactKeys(receipt.authority, [
    'signature_created', 'signing_job_verification_passed', 'independently_verified',
    'release_admitted', 'publishable', 'github_release_created', 'package_uploaded',
    'container_uploaded',
  ], 'independent verification authority');
  requireCondition(receipt.authority.signature_created === true &&
    receipt.authority.signing_job_verification_passed === true &&
    receipt.authority.independently_verified === true &&
    Object.entries(receipt.authority).every(([field, value]) => [
      'signature_created', 'signing_job_verification_passed', 'independently_verified',
    ].includes(field) ? value === true : value === false),
  'independent verification authority is invalid');
  return {receipt, receiptRecord: record, base};
}

export function verifyProductSignatures({
  intakeRoot, evidenceRoot, output, createdAt, cosign = 'cosign',
}) {
  canonicalTime(createdAt, 'created-at');
  const root = path.resolve(evidenceRoot);
  const destination = path.resolve(output);
  requireCondition(destination === path.join(root, 'independent-verification'),
    'independent verification output must use the fixed evidence subdirectory');
  requireCondition(!fs.existsSync(destination),
    'independent verification output directory must be new');
  const base = validateProductSignatureReceipt({intakeRoot, evidenceRoot: root});
  fs.mkdirSync(path.join(destination, 'verification'), {recursive: true, mode: 0o700});
  const versionPath = path.join(destination, 'cosign-version.json');
  const version = captureVersion(cosign, versionPath);
  requireCondition(version.gitVersion === base.receipt.cosign.version,
    'independent verifier Cosign version differs from the signing job');

  const verified = base.receipt.artifacts.map((artifact) => {
    const artifactPath = path.join(path.resolve(intakeRoot), artifact.artifact.path);
    const bundlePath = path.join(root, artifact.bundle.path);
    const references = {};
    for (const [mode, offline] of [['online', false], ['offline', true]]) {
      const relativePath = `independent-verification/verification/${artifact.id}.${mode}.txt`;
      const transcript = runCosign(cosign,
        verificationArguments(base.receipt, artifactPath, bundlePath, offline),
        `${artifact.id} ${mode} verification`);
      fs.writeFileSync(path.join(root, relativePath), transcript, {flag: 'wx', mode: 0o600});
      references[`${mode}_verification`] = {
        path: relativePath,
        ...fileIdentity(path.join(root, relativePath), `${artifact.id}.${mode}`),
      };
    }
    return {
      id: artifact.id,
      artifact: artifact.artifact,
      bundle: artifact.bundle,
      ...references,
    };
  });
  const receiptPath = path.join(destination, 'independent-verification-receipt.json');
  const versionIdentity = fileIdentity(versionPath, 'independent Cosign version');
  const files = walkOutput(destination, root, receiptPath);
  const receipt = {
    schema_version: 1,
    classification: CLASSIFICATION,
    product: base.receipt.product,
    created_at: createdAt,
    product_signature_receipt: {
      path: 'product-signature-receipt.json',
      bytes: base.receiptRecord.bytes,
      sha256: base.receiptRecord.sha256,
    },
    source: base.receipt.source,
    signing_workflow: base.receipt.workflow,
    cosign: {
      version: base.receipt.cosign.version,
      version_record: {
        path: 'independent-verification/cosign-version.json',
        ...versionIdentity,
      },
    },
    artifacts: verified,
    files,
    authority: {
      signature_created: true,
      signing_job_verification_passed: true,
      independently_verified: true,
      release_admitted: false,
      publishable: false,
      github_release_created: false,
      package_uploaded: false,
      container_uploaded: false,
    },
  };
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, {
    flag: 'wx', mode: 0o600,
  });
  const validation = validateIndependentProductVerification({intakeRoot, evidenceRoot: root});
  return {
    status: 'PASS',
    receipt_path: receiptPath,
    receipt_sha256: validation.receiptRecord.sha256,
    artifacts: verified.map(({id, online_verification, offline_verification}) => ({
      id, online_verification, offline_verification,
    })),
    independently_verified: true,
    release_admitted: false,
    publishable: false,
  };
}

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    requireCondition(argv[index]?.startsWith('--') && argv[index + 1] !== undefined,
      'arguments must be --name value pairs');
    requireCondition(!values.has(argv[index]), `duplicate argument ${argv[index]}`);
    values.set(argv[index], argv[index + 1]);
  }
  for (const required of [
    '--intake-root', '--evidence-root', '--output', '--created-at',
  ]) requireCondition(values.has(required), `${required} is required`);
  requireCondition([...values.keys()].every((name) => [
    '--intake-root', '--evidence-root', '--output', '--created-at', '--cosign',
  ].includes(name)), 'unknown arguments are not allowed');
  return {
    intakeRoot: values.get('--intake-root'),
    evidenceRoot: values.get('--evidence-root'),
    output: values.get('--output'),
    createdAt: values.get('--created-at'),
    cosign: values.get('--cosign') ?? 'cosign',
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(`${JSON.stringify(
      verifyProductSignatures(parseArguments(process.argv.slice(2))), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`independent product signature verification rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}
