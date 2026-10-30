#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {TextDecoder} from 'node:util';
import {fileURLToPath} from 'node:url';

const SCRIPT_ROOT = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_CONTRACT = path.resolve(
  SCRIPT_ROOT, '..', 'packaging', 'release', 'oss-candidate-intake-contract.json');
const PUBLIC_REPOSITORY = 'https://github.com/routesphere-global/bonvoyage';
const RECEIPT_CLASSIFICATION =
  'routesphere-bonvoyage-oss-candidate-intake-receipt';
const CONTRACT_CLASSIFICATION =
  'routesphere-bonvoyage-oss-candidate-intake-contract';
const CONTRACT_ARTIFACTS = [
  {
    id: 'gateway-deb-linux-amd64',
    kind: 'debian-package',
    workflow: 'OSS Debian Reproducibility Candidate',
    input_prefix: 'oss-deb',
  },
  {
    id: 'gateway-oci-linux-amd64',
    kind: 'oci-image',
    workflow: 'OSS OCI Reproducibility Candidate',
    input_prefix: 'oss-oci',
  },
];
const CONTRACT_AUTHORITY_FIELDS = [
  'release_admitted',
  'publishable',
  'github_release_created',
  'package_uploaded',
  'container_uploaded',
  'signature_created',
  'provenance_created',
];
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const RUN_ID = /^[1-9][0-9]*$/u;
const MAX_CONTROL_BYTES = 8 * 1024 * 1024;
const DECODER = new TextDecoder('utf-8', {fatal: true});

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
  requireCondition(typeof value === 'string' && value.length > 0 && value === value.trim(),
    `${label} must be a nonempty trimmed string`);
  return value;
}

function exactKeys(value, expected, label) {
  const actual = Object.keys(requireObject(value, label)).sort();
  const wanted = [...expected].sort();
  requireCondition(actual.length === wanted.length &&
    actual.every((item, index) => item === wanted[index]),
  `${label} fields must be exactly [${wanted.join(', ')}]`);
}

function sha256File(filePath) {
  const descriptor = fs.openSync(filePath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && before.nlink === 1,
      `${filePath} must be a regular single-link file`);
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
  const identity = sha256File(filePath);
  requireCondition(identity.bytes > 0 && identity.bytes <= MAX_CONTROL_BYTES,
    `${label} must be a bounded nonempty JSON file`);
  let text;
  let value;
  try {
    text = DECODER.decode(fs.readFileSync(filePath));
    value = JSON.parse(text);
  } catch (error) {
    fail(`${label} is not canonical JSON: ${error.message}`);
  }
  requireObject(value, label);
  requireCondition(text === `${JSON.stringify(value, null, 2)}\n`,
    `${label} must use canonical JSON encoding`);
  return {value, ...identity};
}

function assertDirectory(directory, label) {
  const stat = fs.lstatSync(directory);
  requireCondition(stat.isDirectory() && !stat.isSymbolicLink(),
    `${label} must be a real directory`);
}

function assertExactFiles(root, expected, label) {
  assertDirectory(root, label);
  const actual = [];
  function walk(directory, prefix = '') {
    const entries = fs.readdirSync(directory, {withFileTypes: true});
    requireCondition(entries.length > 0, `${label} contains an empty directory`);
    for (const entry of entries) {
      const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      const absolute = path.join(directory, entry.name);
      const stat = fs.lstatSync(absolute);
      requireCondition(!stat.isSymbolicLink(), `${label} contains symbolic link ${relative}`);
      if (stat.isDirectory()) {
        walk(absolute, relative);
      } else {
        requireCondition(stat.isFile() && stat.nlink === 1,
          `${label} contains non-regular or linked file ${relative}`);
        actual.push(relative);
      }
    }
  }
  walk(root);
  actual.sort();
  const wanted = [...expected].sort();
  requireCondition(actual.length === wanted.length &&
    actual.every((item, index) => item === wanted[index]),
  `${label} files must be exactly [${wanted.join(', ')}], got [${actual.join(', ')}]`);
}

function checkSha(value, label) {
  requireCondition(typeof value === 'string' && SHA256.test(value),
    `${label} must be a lowercase SHA-256 digest`);
  return value;
}

function checkSource(source, expected, label) {
  requireObject(source, label);
  requireCondition(source.repository === PUBLIC_REPOSITORY &&
    source.commit === expected.commit && source.tag === expected.tag && source.dirty === false,
  `${label} does not match the exact clean public source`);
}

function checkAuthorityFalse(record, label) {
  for (const field of ['release_admitted', 'publishable']) {
    requireCondition(record[field] === false, `${label}.${field} must remain false`);
  }
}

function checkCandidate(actualPath, candidate, label) {
  requireObject(candidate, `${label} identity`);
  const filename = requireString(candidate.path, `${label}.path`);
  requireCondition(path.basename(filename) === filename && !filename.includes('..'),
    `${label}.path must be one filename`);
  const actual = sha256File(actualPath);
  requireCondition(actual.bytes === candidate.bytes && actual.sha256 === candidate.sha256,
    `${label} bytes do not match the retained identity`);
  return {path: filename, ...actual};
}

function checkEvidenceArtifacts(values, prefix, label) {
  const records = requireArray(values, label);
  requireCondition(records.length === 2, `${label} must contain two builder artifacts`);
  const expectedNames = [`${prefix}-build-a`, `${prefix}-build-b`];
  const names = records.map((record, index) => {
    requireObject(record, `${label}[${index}]`);
    checkSha(record.sha256, `${label}[${index}].sha256`);
    return record.name;
  });
  requireCondition(names.every((name, index) => name === expectedNames[index]),
    `${label} builder artifact order or names changed`);
  requireCondition(records[0].sha256 !== records[1].sha256,
    `${label} must bind distinct uploaded builder artifacts`);
  return records;
}

function checkBuildReceiptHashes(technical, files, label) {
  const references = requireArray(technical.build_receipts, `${label}.build_receipts`);
  requireCondition(references.length === 2,
    `${label}.build_receipts must contain two records`);
  for (let index = 0; index < references.length; index += 1) {
    const reference = requireObject(references[index], `${label}.build_receipts[${index}]`);
    const actual = sha256File(files[index]);
    requireCondition(reference.sha256 === actual.sha256,
      `${label} build receipt ${index} digest mismatch`);
  }
}

function validateDebian(root, identity, runId) {
  const technicalPath = path.join(root,
    'oss-deb-comparison/reproducibility-receipt.json');
  const hostedPath = path.join(root,
    'oss-deb-comparison/hosted-reproducibility-receipt.json');
  const technical = readCanonicalJson(technicalPath, 'Debian reproducibility receipt');
  const hosted = readCanonicalJson(hostedPath, 'Debian hosted receipt');
  const candidate = requireObject(technical.value.package, 'Debian package');
  const expectedFiles = [
    `oss-deb-build-a/${candidate.path}`,
    'oss-deb-build-a/build-receipt.json',
    'oss-deb-build-a/builder-execution.json',
    'oss-deb-build-a/builder-image-observation.json',
    `oss-deb-build-b/${candidate.path}`,
    'oss-deb-build-b/build-receipt.json',
    'oss-deb-build-b/builder-execution.json',
    'oss-deb-build-b/builder-image-observation.json',
    'oss-deb-comparison/hosted-reproducibility-receipt.json',
    'oss-deb-comparison/reproducibility-receipt.json',
  ];
  assertExactFiles(root, expectedFiles, 'Debian intake');

  requireCondition(technical.value.classification ===
    'routesphere-bonvoyage-oss-deb-reproducibility' &&
    technical.value.outcome === 'byte-identical-technical-candidates' &&
    technical.value.technical_reproducibility_observed === true &&
    technical.value.hosted_builder_independence_qualified === false,
  'Debian technical receipt is not an accepted pre-hosted comparison');
  requireCondition(hosted.value.classification ===
    'routesphere-bonvoyage-oss-deb-hosted-reproducibility' &&
    hosted.value.outcome === 'byte-identical-hosted-technical-candidates' &&
    hosted.value.technical_reproducibility_observed === true &&
    hosted.value.hosted_builder_independence_qualified === true,
  'Debian hosted reproducibility is not qualified');
  checkAuthorityFalse(technical.value, 'Debian technical receipt');
  checkAuthorityFalse(hosted.value, 'Debian hosted receipt');
  checkSource(technical.value.source, identity, 'Debian technical source');
  checkSource(hosted.value.source, identity, 'Debian hosted source');
  requireCondition(hosted.value.workflow?.name === 'OSS Debian Reproducibility Candidate' &&
    hosted.value.workflow?.run_id === runId && hosted.value.workflow?.run_attempt === '1' &&
    JSON.stringify(hosted.value.workflow?.jobs) === JSON.stringify(['build-a', 'build-b', 'compare']),
  'Debian hosted workflow identity changed');
  requireCondition(hosted.value.technical_receipt_sha256 === technical.sha256,
    'Debian hosted receipt does not bind the retained technical receipt');
  requireCondition(JSON.stringify(hosted.value.package) === JSON.stringify(candidate),
    'Debian hosted and technical package identities differ');
  const evidenceArtifacts = checkEvidenceArtifacts(
    hosted.value.evidence_artifacts, 'oss-deb', 'Debian hosted evidence artifacts');

  const buildReceiptPaths = ['a', 'b'].map((builder) =>
    path.join(root, `oss-deb-build-${builder}/build-receipt.json`));
  const executions = ['a', 'b'].map((builder) => readCanonicalJson(
    path.join(root, `oss-deb-build-${builder}/builder-execution.json`),
    `Debian builder ${builder} execution`).value);
  const builds = buildReceiptPaths.map((file, index) => readCanonicalJson(
    file, `Debian builder ${index === 0 ? 'a' : 'b'} receipt`).value);
  checkBuildReceiptHashes(technical.value, buildReceiptPaths, 'Debian technical receipt');
  const expectedBuilders = ['a', 'b'].map((builder) => `github-${runId}-1-${builder}`);
  requireCondition(JSON.stringify(technical.value.builders) === JSON.stringify(expectedBuilders),
    'Debian technical builder identities changed');
  for (let index = 0; index < 2; index += 1) {
    const label = `Debian builder ${index === 0 ? 'a' : 'b'}`;
    checkAuthorityFalse(builds[index], `${label} receipt`);
    checkAuthorityFalse(executions[index], `${label} execution`);
    checkSource(builds[index].source, identity, `${label} source`);
    checkSource(executions[index].source, identity, `${label} execution source`);
    requireCondition(builds[index].builder_id === expectedBuilders[index] &&
      executions[index].builder_id === expectedBuilders[index] &&
      builds[index].technical_candidate_built === true &&
      executions[index].technical_candidate_built === true &&
      executions[index].compiled_tests_passed === true &&
      JSON.stringify(builds[index].package) === JSON.stringify(candidate) &&
      JSON.stringify(executions[index].package) === JSON.stringify({
        bytes: candidate.bytes,
        path: candidate.path,
        sha256: candidate.sha256,
      }), `${label} identity or compiled test result changed`);
  }

  const first = checkCandidate(
    path.join(root, `oss-deb-build-a/${candidate.path}`), candidate, 'Debian builder a package');
  const second = checkCandidate(
    path.join(root, `oss-deb-build-b/${candidate.path}`), candidate, 'Debian builder b package');
  requireCondition(first.sha256 === second.sha256 && first.bytes === second.bytes,
    'Debian builder outputs are not byte-identical');
  return {
    artifact: {
      id: 'gateway-deb-linux-amd64',
      kind: 'debian-package',
      platform: 'linux/amd64',
      path: `artifacts/${candidate.path}`,
      bytes: first.bytes,
      sha256: first.sha256,
      hosted_run_id: runId,
      builders: expectedBuilders,
      hosted_evidence_artifacts: evidenceArtifacts,
    },
    payload: path.join(root, `oss-deb-build-a/${candidate.path}`),
    evidence: expectedFiles.filter((value) => !value.endsWith(`/${candidate.path}`)),
  };
}

function validateOci(root, identity, runId) {
  const technicalPath = path.join(root,
    'oss-oci-comparison/reproducibility-receipt.json');
  const hostedPath = path.join(root,
    'oss-oci-comparison/hosted-reproducibility-receipt.json');
  const technical = readCanonicalJson(technicalPath, 'OCI reproducibility receipt');
  const hosted = readCanonicalJson(hostedPath, 'OCI hosted receipt');
  const candidate = requireObject(technical.value.archive, 'OCI archive');
  const expectedFiles = [
    `oss-oci-build-a/${candidate.path}`,
    'oss-oci-build-a/builder-image-observation.json',
    'oss-oci-build-a/oci-builder-execution.json',
    `oss-oci-build-b/${candidate.path}`,
    'oss-oci-build-b/builder-image-observation.json',
    'oss-oci-build-b/oci-builder-execution.json',
    'oss-oci-comparison/hosted-reproducibility-receipt.json',
    'oss-oci-comparison/reproducibility-receipt.json',
  ];
  assertExactFiles(root, expectedFiles, 'OCI intake');

  requireCondition(technical.value.classification ===
    'routesphere-bonvoyage-oss-oci-reproducibility' &&
    technical.value.outcome === 'byte-identical-technical-candidates' &&
    technical.value.technical_reproducibility_observed === true &&
    technical.value.hosted_builder_independence_qualified === false,
  'OCI technical receipt is not an accepted pre-hosted comparison');
  requireCondition(hosted.value.classification ===
    'routesphere-bonvoyage-oss-oci-hosted-reproducibility' &&
    hosted.value.outcome === 'byte-identical-hosted-technical-candidates' &&
    hosted.value.technical_reproducibility_observed === true &&
    hosted.value.hosted_builder_independence_qualified === true,
  'OCI hosted reproducibility is not qualified');
  checkAuthorityFalse(technical.value, 'OCI technical receipt');
  checkAuthorityFalse(hosted.value, 'OCI hosted receipt');
  checkSource(technical.value.source, identity, 'OCI technical source');
  checkSource(hosted.value.source, identity, 'OCI hosted source');
  requireCondition(hosted.value.workflow?.name === 'OSS OCI Reproducibility Candidate' &&
    hosted.value.workflow?.run_id === runId && hosted.value.workflow?.run_attempt === '1' &&
    JSON.stringify(hosted.value.workflow?.jobs) === JSON.stringify(['build-a', 'build-b', 'compare']),
  'OCI hosted workflow identity changed');
  requireCondition(hosted.value.technical_receipt_sha256 === technical.sha256,
    'OCI hosted receipt does not bind the retained technical receipt');
  for (const field of ['archive', 'manifest', 'config', 'layer']) {
    requireCondition(JSON.stringify(hosted.value[field]) === JSON.stringify(technical.value[field]),
      `OCI hosted and technical ${field} identities differ`);
  }
  const evidenceArtifacts = checkEvidenceArtifacts(
    hosted.value.evidence_artifacts, 'oss-oci', 'OCI hosted evidence artifacts');

  const buildReceiptPaths = ['a', 'b'].map((builder) =>
    path.join(root, `oss-oci-build-${builder}/oci-builder-execution.json`));
  const builds = buildReceiptPaths.map((file, index) => readCanonicalJson(
    file, `OCI builder ${index === 0 ? 'a' : 'b'} execution`).value);
  checkBuildReceiptHashes(technical.value, buildReceiptPaths, 'OCI technical receipt');
  const expectedBuilders = ['a', 'b'].map((builder) => `github-${runId}-1-${builder}`);
  requireCondition(JSON.stringify(technical.value.builders) === JSON.stringify(expectedBuilders),
    'OCI technical builder identities changed');
  for (let index = 0; index < 2; index += 1) {
    const label = `OCI builder ${index === 0 ? 'a' : 'b'}`;
    checkAuthorityFalse(builds[index], `${label} execution`);
    checkSource(builds[index].source, identity, `${label} source`);
    requireCondition(builds[index].builder_id === expectedBuilders[index] &&
      builds[index].technical_candidate_built === true &&
      builds[index].compiled_tests_passed === true &&
      JSON.stringify(builds[index].archive) === JSON.stringify(candidate) &&
      JSON.stringify(builds[index].manifest) === JSON.stringify(technical.value.manifest) &&
      JSON.stringify(builds[index].config) === JSON.stringify(technical.value.config) &&
      JSON.stringify(builds[index].layer) === JSON.stringify(technical.value.layer),
    `${label} identity or compiled test result changed`);
  }

  const first = checkCandidate(
    path.join(root, `oss-oci-build-a/${candidate.path}`), candidate, 'OCI builder a archive');
  const second = checkCandidate(
    path.join(root, `oss-oci-build-b/${candidate.path}`), candidate, 'OCI builder b archive');
  requireCondition(first.sha256 === second.sha256 && first.bytes === second.bytes,
    'OCI builder outputs are not byte-identical');
  return {
    artifact: {
      id: 'gateway-oci-linux-amd64',
      kind: 'oci-image',
      platform: 'linux/amd64',
      path: `artifacts/${candidate.path}`,
      bytes: first.bytes,
      sha256: first.sha256,
      manifest: technical.value.manifest,
      config: technical.value.config,
      layer: technical.value.layer,
      hosted_run_id: runId,
      builders: expectedBuilders,
      hosted_evidence_artifacts: evidenceArtifacts,
    },
    payload: path.join(root, `oss-oci-build-a/${candidate.path}`),
    evidence: expectedFiles.filter((value) => !value.endsWith(`/${candidate.path}`)),
  };
}

function copyExclusive(source, destination) {
  fs.mkdirSync(path.dirname(destination), {recursive: true, mode: 0o700});
  fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
  fs.chmodSync(destination, 0o600);
  const sourceIdentity = sha256File(source);
  const destinationIdentity = sha256File(destination);
  requireCondition(JSON.stringify(sourceIdentity) === JSON.stringify(destinationIdentity),
    `copy changed ${source}`);
}

function inventory(root, excluded = new Set()) {
  const records = [];
  function walk(directory, prefix = '') {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        walk(absolute, relative);
      } else if (!excluded.has(relative)) {
        const identity = sha256File(absolute);
        records.push({path: relative, ...identity});
      }
    }
  }
  walk(root);
  return records.sort((left, right) => left.path.localeCompare(right.path));
}

function validateContract(contract) {
  exactKeys(contract, [
    'schema_version', 'classification', 'product', 'source_repository', 'platform',
    'artifacts', 'required_builders', 'required_run_attempt', 'authority',
  ], 'intake contract');
  requireCondition(contract.schema_version === 1 &&
    contract.classification === CONTRACT_CLASSIFICATION &&
    contract.product === 'RouteSphere BonVoyage API Gateway' &&
    contract.source_repository === PUBLIC_REPOSITORY &&
    contract.platform === 'linux/amd64' &&
    JSON.stringify(contract.required_builders) === JSON.stringify(['a', 'b']) &&
    contract.required_run_attempt === '1', 'intake contract identity changed');
  const artifacts = requireArray(contract.artifacts, 'intake contract.artifacts');
  requireCondition(JSON.stringify(artifacts) === JSON.stringify(CONTRACT_ARTIFACTS),
    'intake contract artifact identities changed');
  exactKeys(contract.authority, CONTRACT_AUTHORITY_FIELDS, 'intake contract.authority');
  requireCondition(CONTRACT_AUTHORITY_FIELDS.every((field) =>
    contract.authority[field] === false),
  'intake contract must grant no release authority');
}

export function intakeReleaseCandidate({
  debRoot,
  ociRoot,
  output,
  sourceCommit,
  sourceTag,
  debRunId,
  ociRunId,
  createdAt,
  contractPath = DEFAULT_CONTRACT,
}) {
  requireCondition(COMMIT.test(sourceCommit ?? ''), 'source commit must be lowercase Git SHA-1');
  requireCondition(TAG.test(sourceTag ?? ''), 'source tag must be strict v-prefixed SemVer');
  requireCondition(RUN_ID.test(debRunId ?? '') && RUN_ID.test(ociRunId ?? ''),
    'hosted run IDs must be positive integers');
  requireCondition(typeof createdAt === 'string' &&
    new Date(createdAt).toISOString() === createdAt &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(createdAt),
  'created-at must be a canonical millisecond UTC timestamp');
  requireCondition(debRunId !== ociRunId, 'Debian and OCI runs must be distinct');
  const contractRecord = readCanonicalJson(path.resolve(contractPath), 'intake contract');
  validateContract(contractRecord.value);
  const expectedSource = {commit: sourceCommit, tag: sourceTag};
  const debian = validateDebian(path.resolve(debRoot), expectedSource, debRunId);
  const oci = validateOci(path.resolve(ociRoot), expectedSource, ociRunId);

  const destination = path.resolve(output);
  requireCondition(!fs.existsSync(destination), 'output directory must not already exist');
  fs.mkdirSync(destination, {mode: 0o700});
  copyExclusive(path.resolve(contractPath),
    path.join(destination, 'metadata/oss-candidate-intake-contract.json'));
  for (const item of [debian, oci]) {
    copyExclusive(item.payload, path.join(destination, item.artifact.path));
  }
  for (const [scope, root, item] of [
    ['debian', path.resolve(debRoot), debian],
    ['oci', path.resolve(ociRoot), oci],
  ]) {
    for (const relative of item.evidence) {
      copyExclusive(path.join(root, relative),
        path.join(destination, 'evidence', scope, relative));
    }
  }

  const receipt = {
    schema_version: 1,
    classification: RECEIPT_CLASSIFICATION,
    product: contractRecord.value.product,
    created_at: createdAt,
    contract: {
      path: 'metadata/oss-candidate-intake-contract.json',
      bytes: contractRecord.bytes,
      sha256: contractRecord.sha256,
    },
    source: {
      repository: PUBLIC_REPOSITORY,
      commit: sourceCommit,
      tag: sourceTag,
      dirty: false,
    },
    artifacts: [debian.artifact, oci.artifact],
    files: inventory(destination),
    authority: contractRecord.value.authority,
  };
  const receiptPath = path.join(destination, 'candidate-intake-receipt.json');
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, {
    flag: 'wx', mode: 0o600,
  });
  const receiptIdentity = sha256File(receiptPath);
  const finalFiles = inventory(destination, new Set(['candidate-intake-receipt.json']));
  requireCondition(JSON.stringify(finalFiles) === JSON.stringify(receipt.files),
    'intake tree changed while the receipt was finalized');
  return {
    status: 'PASS',
    source_commit: sourceCommit,
    source_tag: sourceTag,
    artifacts: receipt.artifacts.map(({id, path: artifactPath, bytes, sha256}) => ({
      id, path: artifactPath, bytes, sha256,
    })),
    receipt_path: receiptPath,
    receipt_bytes: receiptIdentity.bytes,
    receipt_sha256: receiptIdentity.sha256,
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
    '--deb-root', '--oci-root', '--output', '--source-commit', '--source-tag',
    '--deb-run-id', '--oci-run-id', '--created-at',
  ];
  for (const name of required) {
    requireCondition(options[name] !== undefined, `${name} is required`);
  }
  const allowed = new Set([...required, '--contract']);
  for (const name of Object.keys(options)) {
    requireCondition(allowed.has(name), `unknown argument ${name}`);
  }
  return {
    debRoot: options['--deb-root'],
    ociRoot: options['--oci-root'],
    output: options['--output'],
    sourceCommit: options['--source-commit'],
    sourceTag: options['--source-tag'],
    debRunId: options['--deb-run-id'],
    ociRunId: options['--oci-run-id'],
    createdAt: options['--created-at'],
    contractPath: options['--contract'] ?? DEFAULT_CONTRACT,
  };
}

if (process.argv[1] &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    console.log(JSON.stringify(intakeReleaseCandidate(parseArguments(process.argv.slice(2))), null, 2));
  } catch (error) {
    console.error(`candidate intake rejected: ${error.message}`);
    process.exitCode = 1;
  }
}
