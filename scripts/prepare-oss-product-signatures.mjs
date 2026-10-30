#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {TextDecoder} from 'node:util';
import {fileURLToPath} from 'node:url';

const SCRIPT_ROOT = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_ROOT, '..');
const DEFAULT_SIGNING_CONTRACT = path.join(
  REPOSITORY_ROOT, 'packaging/release/oss-product-signing-workflow-contract.json');
const PUBLIC_REPOSITORY = 'https://github.com/routesphere-global/bonvoyage';
const PLAN_CLASSIFICATION = 'routesphere-bonvoyage-oss-product-signing-plan';
const RECEIPT_CLASSIFICATION = 'routesphere-bonvoyage-oss-candidate-intake-receipt';
const CONTRACT_CLASSIFICATION =
  'routesphere-bonvoyage-oss-product-signing-workflow-contract';
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const RUN_ID = /^[1-9][0-9]*$/u;
const SAFE_RELATIVE = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._+~@/-]+$/u;
const MAX_CONTROL_BYTES = 8 * 1024 * 1024;
const DECODER = new TextDecoder('utf-8', {fatal: true});
const ARTIFACTS = Object.freeze([
  {id: 'gateway-deb-linux-amd64', kind: 'debian-package', platform: 'linux/amd64'},
  {id: 'gateway-oci-linux-amd64', kind: 'oci-image', platform: 'linux/amd64'},
]);
const FALSE_AUTHORITY = Object.freeze([
  'release_admitted', 'publishable', 'github_release_created', 'package_uploaded',
  'container_uploaded', 'signature_created', 'provenance_created',
]);

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
function sha(value, label) {
  requireCondition(typeof value === 'string' && SHA256.test(value),
    `${label} must be a lowercase SHA-256 digest`);
  return value;
}
function integer(value, label) {
  requireCondition(Number.isSafeInteger(value) && value >= 0,
    `${label} must be a nonnegative safe integer`);
  return value;
}
function runId(value, label) {
  requireCondition(typeof value === 'string' && RUN_ID.test(value),
    `${label} must be a positive run ID`);
  return value;
}
function relative(value, label) {
  string(value, label);
  requireCondition(SAFE_RELATIVE.test(value) && path.posix.normalize(value) === value,
    `${label} must be a safe normalized relative path`);
  return value;
}
function canonicalTime(value, label) {
  string(value, label);
  requireCondition(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
    new Date(value).toISOString() === value, `${label} must be canonical UTC time`);
  return value;
}

function fileIdentity(filePath, label) {
  const descriptor = fs.openSync(filePath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && before.nlink === 1,
      `${label} must be a regular single-link file`);
    const digest = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    while (true) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      digest.update(buffer.subarray(0, count));
      bytes += count;
    }
    const after = fs.fstatSync(descriptor);
    requireCondition(before.size === after.size && before.mtimeMs === after.mtimeMs &&
      before.ctimeMs === after.ctimeMs && bytes === after.size,
    `${label} changed while it was read`);
    return {bytes, sha256: digest.digest('hex')};
  } finally {
    fs.closeSync(descriptor);
  }
}

function readCanonicalJson(filePath, label) {
  const identity = fileIdentity(filePath, label);
  requireCondition(identity.bytes > 0 && identity.bytes <= MAX_CONTROL_BYTES,
    `${label} must be a bounded nonempty JSON file`);
  let text;
  let value;
  try {
    text = DECODER.decode(fs.readFileSync(filePath));
    value = JSON.parse(text);
  } catch (error) {
    fail(`${label} is not JSON: ${error.message}`);
  }
  object(value, label);
  requireCondition(text === `${JSON.stringify(value, null, 2)}\n`,
    `${label} must use canonical JSON encoding`);
  return {value, ...identity};
}

function walkFiles(root, excluded = new Set()) {
  const stat = fs.lstatSync(root);
  requireCondition(stat.isDirectory() && !stat.isSymbolicLink(),
    `${root} must be a real directory`);
  const files = [];
  function walk(directory, prefix = '') {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const relativePath = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      const absolute = path.join(directory, entry.name);
      const value = fs.lstatSync(absolute);
      requireCondition(!value.isSymbolicLink(), `candidate intake contains link ${relativePath}`);
      if (value.isDirectory()) {
        walk(absolute, relativePath);
      } else {
        requireCondition(value.isFile() && value.nlink === 1,
          `candidate intake contains non-regular or linked file ${relativePath}`);
        if (!excluded.has(relativePath)) {
          files.push({path: relativePath, ...fileIdentity(absolute, relativePath)});
        }
      }
    }
  }
  walk(root);
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

function validateSigningContract(record) {
  const contract = record.value;
  requireCondition(contract.schema_version === 1 &&
    contract.classification === CONTRACT_CLASSIFICATION,
  'product-signing contract schema or classification is unsupported');
  requireCondition(contract.source.repository === PUBLIC_REPOSITORY &&
    contract.candidate_intake.contract_path ===
      'packaging/release/oss-candidate-intake-contract.json' &&
    contract.signing.mode === 'sigstore-keyless' &&
    contract.signing.issuer === 'https://token.actions.githubusercontent.com' &&
    contract.authority.product_artifact_signature_allowed === true,
  'product-signing contract boundary is unsupported');
  for (const field of [
    'product_provenance_allowed', 'release_admitted', 'publishable',
    'github_release_created', 'package_uploaded', 'container_uploaded',
  ]) {
    requireCondition(contract.authority[field] === false,
      `product-signing contract ${field} must remain false`);
  }
  requireCondition(JSON.stringify(contract.signing.artifacts) ===
    JSON.stringify(ARTIFACTS.map(({id}) => id)),
  'product-signing artifact set changed');
  return contract;
}

function validateCandidateIntake(root, contract, expectedSource) {
  const receiptPath = path.join(root, 'candidate-intake-receipt.json');
  const receiptRecord = readCanonicalJson(receiptPath, 'candidate intake receipt');
  const receipt = receiptRecord.value;
  exactKeys(receipt, [
    'schema_version', 'classification', 'product', 'created_at', 'contract',
    'source', 'artifacts', 'files', 'authority',
  ], 'candidate intake receipt');
  requireCondition(receipt.schema_version === 1 &&
    receipt.classification === RECEIPT_CLASSIFICATION,
  'candidate intake receipt schema or classification is unsupported');
  requireCondition(receipt.product === 'RouteSphere BonVoyage API Gateway',
    'candidate intake product is unexpected');
  canonicalTime(receipt.created_at, 'candidate intake created_at');
  exactKeys(receipt.source, ['repository', 'commit', 'tag', 'dirty'],
    'candidate intake source');
  requireCondition(receipt.source.repository === PUBLIC_REPOSITORY &&
    receipt.source.commit === expectedSource.commit &&
    receipt.source.tag === expectedSource.tag && receipt.source.dirty === false,
  'candidate intake source does not match the protected signing source');

  const embeddedContractPath = relative(receipt.contract.path, 'candidate intake contract path');
  const embeddedContract = fileIdentity(path.join(root, embeddedContractPath),
    'embedded candidate intake contract');
  const repositoryContractPath = path.join(REPOSITORY_ROOT,
    contract.candidate_intake.contract_path);
  const repositoryContract = fileIdentity(repositoryContractPath,
    'repository candidate intake contract');
  requireCondition(integer(receipt.contract.bytes, 'candidate intake contract bytes') ===
    embeddedContract.bytes && sha(receipt.contract.sha256, 'candidate intake contract sha256') ===
    embeddedContract.sha256 && embeddedContract.sha256 === repositoryContract.sha256,
  'candidate intake contract does not match the reviewed repository contract');

  const fileRecords = array(receipt.files, 'candidate intake files').map((value, index) => {
    exactKeys(value, ['path', 'bytes', 'sha256'], `candidate intake files[${index}]`);
    return {
      path: relative(value.path, `candidate intake files[${index}].path`),
      bytes: integer(value.bytes, `candidate intake files[${index}].bytes`),
      sha256: sha(value.sha256, `candidate intake files[${index}].sha256`),
    };
  });
  const uniquePaths = new Set(fileRecords.map(({path: value}) => value));
  requireCondition(uniquePaths.size === fileRecords.length,
    'candidate intake file inventory contains duplicate paths');
  const actualFiles = walkFiles(root, new Set(['candidate-intake-receipt.json']));
  requireCondition(JSON.stringify(fileRecords) === JSON.stringify(actualFiles),
    'candidate intake file inventory does not match the downloaded tree');

  const artifacts = array(receipt.artifacts, 'candidate intake artifacts');
  requireCondition(artifacts.length === ARTIFACTS.length,
    'candidate intake must contain exactly two product artifacts');
  const byId = new Map(artifacts.map((value) => [value.id, value]));
  requireCondition(byId.size === ARTIFACTS.length,
    'candidate intake artifact IDs must be unique');
  const accepted = ARTIFACTS.map((expected) => {
    const artifact = object(byId.get(expected.id), `candidate artifact ${expected.id}`);
    requireCondition(artifact.kind === expected.kind && artifact.platform === expected.platform,
      `candidate artifact ${expected.id} kind or platform changed`);
    const sourcePath = relative(artifact.path, `candidate artifact ${expected.id}.path`);
    requireCondition(sourcePath.startsWith('artifacts/'),
      `candidate artifact ${expected.id} is outside artifacts/`);
    const identity = fileIdentity(path.join(root, sourcePath),
      `candidate artifact ${expected.id}`);
    requireCondition(identity.bytes === integer(artifact.bytes,
      `candidate artifact ${expected.id}.bytes`) && identity.sha256 === sha(artifact.sha256,
      `candidate artifact ${expected.id}.sha256`),
    `candidate artifact ${expected.id} bytes do not match the intake receipt`);
    const fileRecord = fileRecords.find(({path: value}) => value === sourcePath);
    requireCondition(fileRecord?.bytes === identity.bytes &&
      fileRecord?.sha256 === identity.sha256,
    `candidate artifact ${expected.id} is not bound by the intake inventory`);
    return {...expected, source_path: sourcePath, ...identity};
  });
  exactKeys(receipt.authority, FALSE_AUTHORITY, 'candidate intake authority');
  for (const field of FALSE_AUTHORITY) {
    requireCondition(receipt.authority[field] === false,
      `candidate intake authority.${field} must remain false`);
  }
  return {receipt: receiptRecord, artifacts: accepted};
}

function copyExclusive(source, destination) {
  const identity = fileIdentity(source, source);
  fs.mkdirSync(path.dirname(destination), {recursive: true, mode: 0o700});
  fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
  fs.chmodSync(destination, 0o600);
  const copied = fileIdentity(destination, destination);
  requireCondition(JSON.stringify(copied) === JSON.stringify(identity),
    `${destination} changed while it was copied`);
  return copied;
}

function appendGithubOutputs(filePath, values) {
  const descriptor = fs.openSync(path.resolve(filePath),
    fs.constants.O_WRONLY | fs.constants.O_APPEND | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const stat = fs.fstatSync(descriptor);
    requireCondition(stat.isFile() && stat.nlink === 1,
      'GitHub output must be a regular single-link file');
    for (const [key, value] of Object.entries(values)) {
      requireCondition(/^[a-z][a-z0-9_]*$/u.test(key) && typeof value === 'string' &&
        value.length > 0 && !/[\r\n\0]/u.test(value), 'invalid GitHub output');
      fs.writeSync(descriptor, `${key}=${value}\n`, null, 'utf8');
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

export function prepareProductSignatures({
  intakeRoot, output, sourceCommit, sourceTag, currentRunId, candidateRunId,
  createdAt, githubOutput, contractPath = DEFAULT_SIGNING_CONTRACT,
}) {
  requireCondition(COMMIT.test(sourceCommit ?? ''), 'source commit must be a full lowercase SHA');
  requireCondition(TAG.test(sourceTag ?? ''), 'source tag must be strict v-prefixed SemVer');
  runId(currentRunId, 'current signing run ID');
  runId(candidateRunId, 'candidate intake run ID');
  requireCondition(currentRunId !== candidateRunId, 'signing and candidate runs must be distinct');
  canonicalTime(createdAt, 'created-at');
  const contractRecord = readCanonicalJson(path.resolve(contractPath),
    'product-signing workflow contract');
  const contract = validateSigningContract(contractRecord);
  const intake = validateCandidateIntake(path.resolve(intakeRoot), contract,
    {commit: sourceCommit, tag: sourceTag});
  const destination = path.resolve(output);
  requireCondition(!fs.existsSync(destination), 'output directory must be new');
  fs.mkdirSync(destination, {mode: 0o700});
  const copiedContract = copyExclusive(path.resolve(contractPath), path.join(destination,
    'metadata/oss-product-signing-workflow-contract.json'));
  const subject = `${contract.signing.subject_prefix}${sourceTag}`;
  const artifacts = intake.artifacts.map((artifact) => ({
    ...artifact,
    bundle_path: `signatures/${artifact.id}.sigstore.json`,
  }));
  const plan = {
    schema_version: 1,
    classification: PLAN_CLASSIFICATION,
    product: 'RouteSphere BonVoyage API Gateway',
    created_at: createdAt,
    contract: {
      path: 'metadata/oss-product-signing-workflow-contract.json',
      bytes: copiedContract.bytes,
      sha256: copiedContract.sha256,
    },
    source: {
      repository: PUBLIC_REPOSITORY,
      commit: sourceCommit,
      tag: sourceTag,
      dirty: false,
    },
    workflow: {
      path: contract.signing.workflow_path,
      run_id: currentRunId,
      run_attempt: 1,
      event: contract.source.event,
      identity: subject,
      issuer: contract.signing.issuer,
    },
    candidate_intake: {
      run_id: candidateRunId,
      receipt_bytes: intake.receipt.bytes,
      receipt_sha256: intake.receipt.sha256,
    },
    artifacts,
    authority: {
      signature_created: false,
      signature_verified: false,
      release_admitted: false,
      publishable: false,
      github_release_created: false,
      package_uploaded: false,
      container_uploaded: false,
    },
  };
  const planPath = path.join(destination, 'product-signing-plan.json');
  fs.writeFileSync(planPath, `${JSON.stringify(plan, null, 2)}\n`, {flag: 'wx', mode: 0o600});
  fs.mkdirSync(path.join(destination, 'signatures'), {mode: 0o700});
  fs.mkdirSync(path.join(destination, 'signing-verification'), {mode: 0o700});

  const byId = new Map(artifacts.map((artifact) => [artifact.id, artifact]));
  const outputValues = {
    debian_artifact: path.join(path.resolve(intakeRoot),
      byId.get('gateway-deb-linux-amd64').source_path),
    debian_bundle: path.join(destination,
      byId.get('gateway-deb-linux-amd64').bundle_path),
    oci_artifact: path.join(path.resolve(intakeRoot),
      byId.get('gateway-oci-linux-amd64').source_path),
    oci_bundle: path.join(destination,
      byId.get('gateway-oci-linux-amd64').bundle_path),
    signing_plan: planPath,
  };
  if (githubOutput !== undefined) appendGithubOutputs(githubOutput, outputValues);
  return {
    status: 'PASS',
    plan_path: planPath,
    plan_sha256: fileIdentity(planPath, 'product signing plan').sha256,
    workflow_identity: subject,
    artifacts: artifacts.map(({id, bytes, sha256}) => ({id, bytes, sha256})),
    outputs: outputValues,
    signature_created: false,
    release_admitted: false,
    publishable: false,
  };
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
  const required = [
    '--intake-root', '--output', '--source-commit', '--source-tag', '--current-run-id',
    '--candidate-run-id', '--created-at', '--github-output',
  ];
  for (const name of required) requireCondition(options[name] !== undefined, `${name} is required`);
  const allowed = new Set([...required, '--contract']);
  for (const name of Object.keys(options)) {
    requireCondition(allowed.has(name), `unknown argument ${name}`);
  }
  return {
    intakeRoot: options['--intake-root'],
    output: options['--output'],
    sourceCommit: options['--source-commit'],
    sourceTag: options['--source-tag'],
    currentRunId: options['--current-run-id'],
    candidateRunId: options['--candidate-run-id'],
    createdAt: options['--created-at'],
    githubOutput: options['--github-output'],
    contractPath: options['--contract'] ?? DEFAULT_SIGNING_CONTRACT,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(`${JSON.stringify(
      prepareProductSignatures(parseArguments(process.argv.slice(2))), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`product signature preparation rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}
