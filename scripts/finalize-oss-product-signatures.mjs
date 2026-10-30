#!/usr/bin/env node

import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {TextDecoder} from 'node:util';
import {fileURLToPath} from 'node:url';

const PLAN_CLASSIFICATION = 'routesphere-bonvoyage-oss-product-signing-plan';
const RECEIPT_CLASSIFICATION = 'routesphere-bonvoyage-oss-product-signature-receipt';
const CONTRACT_CLASSIFICATION =
  'routesphere-bonvoyage-oss-product-signing-workflow-contract';
const PUBLIC_REPOSITORY = 'https://github.com/routesphere-global/bonvoyage';
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const RUN_ID = /^[1-9][0-9]*$/u;
const SAFE_RELATIVE = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._+~@/-]+$/u;
const MAX_CONTROL_BYTES = 16 * 1024 * 1024;
const DECODER = new TextDecoder('utf-8', {fatal: true});
const ARTIFACT_IDS = Object.freeze([
  'gateway-deb-linux-amd64', 'gateway-oci-linux-amd64',
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
function integer(value, label) {
  requireCondition(Number.isSafeInteger(value) && value >= 0,
    `${label} must be a nonnegative safe integer`);
  return value;
}
function digest(value, label) {
  requireCondition(typeof value === 'string' && SHA256.test(value),
    `${label} must be a lowercase SHA-256 digest`);
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

export function fileIdentity(filePath, label = filePath) {
  const descriptor = fs.openSync(filePath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && before.nlink === 1,
      `${label} must be a regular single-link file`);
    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    while (true) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      hash.update(buffer.subarray(0, count));
      bytes += count;
    }
    const after = fs.fstatSync(descriptor);
    requireCondition(before.size === after.size && before.mtimeMs === after.mtimeMs &&
      before.ctimeMs === after.ctimeMs && bytes === after.size,
    `${label} changed while it was read`);
    return {bytes, sha256: hash.digest('hex')};
  } finally {
    fs.closeSync(descriptor);
  }
}

export function readCanonicalJson(filePath, label) {
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

function walkFiles(root, excludedPrefixes = []) {
  const rootStat = fs.lstatSync(root);
  requireCondition(rootStat.isDirectory() && !rootStat.isSymbolicLink(),
    `${root} must be a real directory`);
  const files = [];
  function walk(directory, prefix = '') {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const relativePath = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (excludedPrefixes.some((excluded) => relativePath === excluded ||
        relativePath.startsWith(`${excluded}/`))) continue;
      const absolute = path.join(directory, entry.name);
      const stat = fs.lstatSync(absolute);
      requireCondition(!stat.isSymbolicLink(), `signature evidence contains link ${relativePath}`);
      if (stat.isDirectory()) {
        walk(absolute, relativePath);
      } else {
        requireCondition(stat.isFile() && stat.nlink === 1,
          `signature evidence contains non-regular or linked file ${relativePath}`);
        files.push({path: relativePath, ...fileIdentity(absolute, relativePath)});
      }
    }
  }
  walk(root);
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

function validatePlan(evidenceRoot, intakeRoot) {
  const planRecord = readCanonicalJson(path.join(evidenceRoot, 'product-signing-plan.json'),
    'product signing plan');
  const plan = planRecord.value;
  exactKeys(plan, [
    'schema_version', 'classification', 'product', 'created_at', 'contract', 'source',
    'workflow', 'candidate_intake', 'artifacts', 'authority',
  ], 'product signing plan');
  requireCondition(plan.schema_version === 1 && plan.classification === PLAN_CLASSIFICATION &&
    plan.product === 'RouteSphere BonVoyage API Gateway',
  'product signing plan schema or product is unsupported');
  canonicalTime(plan.created_at, 'product signing plan.created_at');
  exactKeys(plan.source, ['repository', 'commit', 'tag', 'dirty'], 'product signing source');
  requireCondition(plan.source.repository === PUBLIC_REPOSITORY && COMMIT.test(plan.source.commit) &&
    TAG.test(plan.source.tag) && plan.source.dirty === false,
  'product signing source is invalid');
  exactKeys(plan.workflow, ['path', 'run_id', 'run_attempt', 'event', 'identity', 'issuer'],
    'product signing workflow');
  requireCondition(plan.workflow.path === '.github/workflows/oss-product-signing.yml' &&
    RUN_ID.test(plan.workflow.run_id) && plan.workflow.run_attempt === 1 &&
    plan.workflow.event === 'workflow_dispatch' &&
    plan.workflow.identity ===
      `https://github.com/routesphere-global/bonvoyage/.github/workflows/oss-product-signing.yml@refs/tags/${plan.source.tag}` &&
    plan.workflow.issuer === 'https://token.actions.githubusercontent.com',
  'product signing workflow identity is invalid');
  exactKeys(plan.candidate_intake, ['run_id', 'receipt_bytes', 'receipt_sha256'],
    'product signing candidate intake');
  requireCondition(RUN_ID.test(plan.candidate_intake.run_id),
    'candidate intake run ID is invalid');
  const candidateReceipt = fileIdentity(path.join(intakeRoot, 'candidate-intake-receipt.json'),
    'candidate intake receipt');
  requireCondition(candidateReceipt.bytes === integer(plan.candidate_intake.receipt_bytes,
    'candidate intake receipt bytes') && candidateReceipt.sha256 ===
    digest(plan.candidate_intake.receipt_sha256, 'candidate intake receipt sha256'),
  'candidate intake receipt changed after signing preparation');

  const contractPath = relative(plan.contract.path, 'product signing contract path');
  const contractRecord = readCanonicalJson(path.join(evidenceRoot, contractPath),
    'embedded product-signing contract');
  requireCondition(contractRecord.bytes === integer(plan.contract.bytes,
    'product signing contract bytes') && contractRecord.sha256 ===
    digest(plan.contract.sha256, 'product signing contract sha256') &&
    contractRecord.value.classification === CONTRACT_CLASSIFICATION &&
    contractRecord.value.signing.cosign_version === 'v3.1.4',
  'embedded product-signing contract changed');

  const artifacts = array(plan.artifacts, 'product signing artifacts');
  requireCondition(artifacts.length === 2 &&
    JSON.stringify(artifacts.map(({id}) => id)) === JSON.stringify(ARTIFACT_IDS),
  'product signing artifact set changed');
  const checked = artifacts.map((artifact, index) => {
    exactKeys(artifact, [
      'id', 'kind', 'platform', 'source_path', 'bytes', 'sha256', 'bundle_path',
    ], `product signing artifacts[${index}]`);
    relative(artifact.source_path, `product signing artifacts[${index}].source_path`);
    relative(artifact.bundle_path, `product signing artifacts[${index}].bundle_path`);
    requireCondition(artifact.bundle_path === `signatures/${artifact.id}.sigstore.json`,
      `product signing artifact ${artifact.id} bundle path changed`);
    const payload = fileIdentity(path.join(intakeRoot, artifact.source_path),
      `product signing artifact ${artifact.id}`);
    requireCondition(payload.bytes === integer(artifact.bytes,
      `product signing artifact ${artifact.id}.bytes`) && payload.sha256 ===
      digest(artifact.sha256, `product signing artifact ${artifact.id}.sha256`),
    `product signing artifact ${artifact.id} changed`);
    return {...artifact, payload};
  });
  exactKeys(plan.authority, [
    'signature_created', 'signature_verified', 'release_admitted', 'publishable',
    'github_release_created', 'package_uploaded', 'container_uploaded',
  ], 'product signing plan authority');
  requireCondition(Object.values(plan.authority).every((value) => value === false),
    'product signing plan must grant no completed authority');
  return {plan, planRecord, contract: contractRecord, artifacts: checked};
}

function boundedFile(filePath, label, maximum = MAX_CONTROL_BYTES) {
  const identity = fileIdentity(filePath, label);
  requireCondition(identity.bytes <= maximum, `${label} is oversized`);
  return identity;
}

function sanitizedEnvironment() {
  const environment = {...process.env};
  for (const name of [
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL',
    'GITHUB_TOKEN', 'GH_TOKEN',
  ]) delete environment[name];
  return environment;
}

function captureCosignVersion(cosign, outputPath) {
  string(cosign, 'Cosign executable');
  requireCondition(!fs.existsSync(outputPath), 'Cosign version record must be new');
  const result = spawnSync(cosign, ['version', '--json'], {
    encoding: 'utf8',
    env: sanitizedEnvironment(),
    maxBuffer: 1024 * 1024,
    timeout: 30_000,
  });
  requireCondition(!result.error, `unable to execute Cosign: ${result.error?.message}`);
  requireCondition(result.status === 0,
    `Cosign version command failed with status ${result.status}: ${(result.stderr ?? '').trim()}`);
  let version;
  try {
    version = JSON.parse(result.stdout);
  } catch (error) {
    fail(`Cosign version output is not JSON: ${error.message}`);
  }
  object(version, 'Cosign version output');
  fs.writeFileSync(outputPath, `${JSON.stringify(version, null, 2)}\n`, {
    flag: 'wx', mode: 0o600,
  });
}

export function validateProductSignatureReceipt({
  intakeRoot, evidenceRoot, allowIndependentVerification = false,
}) {
  const root = path.resolve(evidenceRoot);
  const intake = path.resolve(intakeRoot);
  const {plan, planRecord, contract, artifacts} = validatePlan(root, intake);
  const receiptRecord = readCanonicalJson(path.join(root, 'product-signature-receipt.json'),
    'product signature receipt');
  const receipt = receiptRecord.value;
  exactKeys(receipt, [
    'schema_version', 'classification', 'product', 'created_at', 'plan', 'source',
    'workflow', 'candidate_intake', 'cosign', 'artifacts', 'files', 'authority',
  ], 'product signature receipt');
  requireCondition(receipt.schema_version === 1 &&
    receipt.classification === RECEIPT_CLASSIFICATION && receipt.product === plan.product,
  'product signature receipt schema or product is unsupported');
  canonicalTime(receipt.created_at, 'product signature receipt.created_at');
  requireCondition(JSON.stringify(receipt.source) === JSON.stringify(plan.source) &&
    JSON.stringify(receipt.workflow) === JSON.stringify(plan.workflow) &&
    JSON.stringify(receipt.candidate_intake) === JSON.stringify(plan.candidate_intake),
  'product signature receipt source or workflow binding changed');
  requireCondition(receipt.plan.path === 'product-signing-plan.json' &&
    receipt.plan.bytes === planRecord.bytes && receipt.plan.sha256 === planRecord.sha256,
  'product signature receipt does not bind the exact plan');
  exactKeys(receipt.cosign, ['version', 'mode', 'issuer', 'subject', 'version_record'],
    'product signature receipt.cosign');
  const cosignVersion = readCanonicalJson(path.join(root,
    relative(receipt.cosign.version_record.path, 'cosign version record path')),
  'cosign version record');
  requireCondition(receipt.cosign.version === contract.value.signing.cosign_version &&
    receipt.cosign.mode === contract.value.signing.mode &&
    receipt.cosign.issuer === plan.workflow.issuer &&
    receipt.cosign.subject === plan.workflow.identity &&
    cosignVersion.value.gitVersion === receipt.cosign.version &&
    cosignVersion.bytes === receipt.cosign.version_record.bytes &&
    cosignVersion.sha256 === receipt.cosign.version_record.sha256,
  'Cosign version or signing identity changed');

  const receiptArtifacts = array(receipt.artifacts, 'product signature receipt artifacts');
  requireCondition(receiptArtifacts.length === artifacts.length,
    'product signature receipt artifact count changed');
  for (const [index, expected] of artifacts.entries()) {
    const signed = receiptArtifacts[index];
    exactKeys(signed, [
      'id', 'kind', 'platform', 'artifact', 'bundle', 'online_verification',
      'offline_verification',
    ], `product signature receipt artifacts[${index}]`);
    requireCondition(signed.id === expected.id && signed.kind === expected.kind &&
      signed.platform === expected.platform &&
      JSON.stringify(signed.artifact) === JSON.stringify({
        path: expected.source_path, bytes: expected.bytes, sha256: expected.sha256,
      }), `product signature receipt artifact ${expected.id} binding changed`);
    for (const [field, expectedPath] of [
      ['bundle', expected.bundle_path],
      ['online_verification', `signing-verification/${expected.id}.online.txt`],
      ['offline_verification', `signing-verification/${expected.id}.offline.txt`],
    ]) {
      const reference = object(signed[field], `${expected.id}.${field}`);
      exactKeys(reference, ['path', 'bytes', 'sha256'], `${expected.id}.${field}`);
      requireCondition(reference.path === expectedPath,
        `${expected.id}.${field} path changed`);
      const identity = boundedFile(path.join(root, reference.path), `${expected.id}.${field}`);
      requireCondition(identity.bytes === reference.bytes && identity.sha256 === reference.sha256,
        `${expected.id}.${field} does not match its receipt`);
      if (field === 'bundle') {
        requireCondition(identity.bytes > 0, `${expected.id} signature bundle is empty`);
        object(JSON.parse(fs.readFileSync(path.join(root, reference.path), 'utf8')),
          `${expected.id} signature bundle`);
      }
    }
  }

  const expectedFiles = array(receipt.files, 'product signature receipt files').map(
    (value, index) => {
      exactKeys(value, ['path', 'bytes', 'sha256'], `receipt.files[${index}]`);
      return {
        path: relative(value.path, `receipt.files[${index}].path`),
        bytes: integer(value.bytes, `receipt.files[${index}].bytes`),
        sha256: digest(value.sha256, `receipt.files[${index}].sha256`),
      };
    });
  const actualFiles = walkFiles(root, [
    'product-signature-receipt.json',
    ...(allowIndependentVerification ? ['independent-verification'] : []),
  ]);
  requireCondition(JSON.stringify(expectedFiles) === JSON.stringify(actualFiles),
    'product signature evidence inventory changed');
  exactKeys(receipt.authority, [
    'signature_created', 'signing_job_verification_passed',
    'independently_verified', 'release_admitted', 'publishable',
    'github_release_created', 'package_uploaded', 'container_uploaded',
  ], 'product signature receipt authority');
  requireCondition(receipt.authority.signature_created === true &&
    receipt.authority.signing_job_verification_passed === true &&
    receipt.authority.independently_verified === false &&
    Object.entries(receipt.authority).every(([field, value]) =>
      ['signature_created', 'signing_job_verification_passed'].includes(field) || value === false),
  'product signature receipt authority is invalid');
  return {receipt, receiptRecord, plan, artifacts};
}

export function finalizeProductSignatures({intakeRoot, evidenceRoot, createdAt, cosign = 'cosign'}) {
  canonicalTime(createdAt, 'created-at');
  const root = path.resolve(evidenceRoot);
  requireCondition(!fs.existsSync(path.join(root, 'product-signature-receipt.json')),
    'product signature receipt must be new');
  const {plan, planRecord, contract, artifacts} = validatePlan(root, path.resolve(intakeRoot));
  captureCosignVersion(cosign, path.join(root, 'cosign-version.json'));
  const cosignVersion = readCanonicalJson(path.join(root, 'cosign-version.json'),
    'cosign version record');
  requireCondition(cosignVersion.value.gitVersion === contract.value.signing.cosign_version,
    'unexpected Cosign version');
  const signedArtifacts = artifacts.map((artifact) => {
    const references = {};
    for (const [field, relativePath] of [
      ['bundle', artifact.bundle_path],
      ['online_verification', `signing-verification/${artifact.id}.online.txt`],
      ['offline_verification', `signing-verification/${artifact.id}.offline.txt`],
    ]) {
      const identity = boundedFile(path.join(root, relativePath), `${artifact.id}.${field}`);
      if (field === 'bundle') {
        requireCondition(identity.bytes > 0, `${artifact.id} signature bundle is empty`);
        object(JSON.parse(fs.readFileSync(path.join(root, relativePath), 'utf8')),
          `${artifact.id} signature bundle`);
      }
      references[field] = {path: relativePath, ...identity};
    }
    return {
      id: artifact.id,
      kind: artifact.kind,
      platform: artifact.platform,
      artifact: {
        path: artifact.source_path,
        bytes: artifact.bytes,
        sha256: artifact.sha256,
      },
      ...references,
    };
  });
  const expectedBeforeReceipt = [
    'cosign-version.json',
    'metadata/oss-product-signing-workflow-contract.json',
    'product-signing-plan.json',
    ...artifacts.flatMap((artifact) => [
      artifact.bundle_path,
      `signing-verification/${artifact.id}.offline.txt`,
      `signing-verification/${artifact.id}.online.txt`,
    ]),
  ].sort();
  const actualBeforeReceipt = walkFiles(root);
  requireCondition(JSON.stringify(actualBeforeReceipt.map(({path: value}) => value)) ===
    JSON.stringify(expectedBeforeReceipt), 'product signature evidence contains unexpected files');
  const receipt = {
    schema_version: 1,
    classification: RECEIPT_CLASSIFICATION,
    product: plan.product,
    created_at: createdAt,
    plan: {path: 'product-signing-plan.json', bytes: planRecord.bytes, sha256: planRecord.sha256},
    source: plan.source,
    workflow: plan.workflow,
    candidate_intake: plan.candidate_intake,
    cosign: {
      version: contract.value.signing.cosign_version,
      mode: contract.value.signing.mode,
      issuer: plan.workflow.issuer,
      subject: plan.workflow.identity,
      version_record: {
        path: 'cosign-version.json', bytes: cosignVersion.bytes, sha256: cosignVersion.sha256,
      },
    },
    artifacts: signedArtifacts,
    files: actualBeforeReceipt,
    authority: {
      signature_created: true,
      signing_job_verification_passed: true,
      independently_verified: false,
      release_admitted: false,
      publishable: false,
      github_release_created: false,
      package_uploaded: false,
      container_uploaded: false,
    },
  };
  const receiptPath = path.join(root, 'product-signature-receipt.json');
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, {
    flag: 'wx', mode: 0o600,
  });
  const validation = validateProductSignatureReceipt({intakeRoot, evidenceRoot: root});
  return {
    status: 'PASS',
    receipt_path: receiptPath,
    receipt_sha256: validation.receiptRecord.sha256,
    artifacts: signedArtifacts.map(({id, artifact, bundle}) => ({id, artifact, bundle})),
    signature_created: true,
    independently_verified: false,
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
  for (const required of ['--intake-root', '--evidence-root', '--created-at']) {
    requireCondition(values.has(required), `${required} is required`);
  }
  requireCondition([...values.keys()].every((name) => [
    '--intake-root', '--evidence-root', '--created-at', '--cosign',
  ].includes(name)), 'unknown arguments are not allowed');
  return {
    intakeRoot: values.get('--intake-root'),
    evidenceRoot: values.get('--evidence-root'),
    createdAt: values.get('--created-at'),
    cosign: values.get('--cosign') ?? 'cosign',
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(`${JSON.stringify(
      finalizeProductSignatures(parseArguments(process.argv.slice(2))), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`product signature finalization rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}
