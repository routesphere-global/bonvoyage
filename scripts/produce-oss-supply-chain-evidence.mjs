#!/usr/bin/env node

import childProcess from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

const SCRIPT_ROOT = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_ROOT, '..');
const CONTRACT_PATH = path.join(
  REPOSITORY_ROOT, 'packaging/release/oss-supply-chain-evidence-contract.json');
const WORKFLOW_CONTRACT_PATH = path.join(
  REPOSITORY_ROOT, 'packaging/release/oss-supply-chain-producer-workflow-contract.json');
const VALIDATOR_SCRIPT = path.join(REPOSITORY_ROOT, 'scripts/validate-native-spdx.py');
const VALIDATOR_LOCK = path.join(REPOSITORY_ROOT, 'security/tools/native-sbom-python.lock');
const SPDX_SCHEMA_URL =
  'https://raw.githubusercontent.com/spdx/spdx-spec/aadf3b0b8dbbabdb4d880b0fc714255fea436ff7/schemas/spdx-schema.json';
const PUBLIC_REPOSITORY = 'https://github.com/routesphere-global/bonvoyage';
const SYFT =
  'anchore/syft:v1.44.0@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6';
const CYCLONEDX_VALIDATOR =
  'cyclonedx/cyclonedx-cli:0.33.1@sha256:9a37575fb51fcaed3a4c62dddba091c46ffc867712e46bdb6cdf219a7e90a061';
const GRYPE =
  'anchore/grype:v0.116.1@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db';
const PYTHON =
  'python:3.12-slim@sha256:1148dbb014615300fa7e713b2f94f550c0d1c69780c0805f84f093ceee34dd0b';
const SPDX_SCHEMA_SHA =
  '239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b';
const SPDX_LOCK_SHA =
  'e2e52a0b047055d4d860b379b1c0e35931659d94069398c6bf0b68cb21d6e194';
const COMMIT = /^[a-f0-9]{40}$/u;
const TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_OUTPUT = 128 * 1024 * 1024;
const POWERLESS = Object.freeze({
  product_artifact_signature_allowed: false,
  product_provenance_allowed: false,
  release_admitted: false,
  publishable: false,
  github_release_created: false,
  package_uploaded: false,
  container_uploaded: false,
});

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
    !/[\u0000-\u001f\u007f]/u.test(value), `${label} must be a nonempty single-line string`);
  return value;
}
function exactKeys(value, expected, label) {
  const actual = Object.keys(object(value, label)).sort();
  const wanted = [...expected].sort();
  requireCondition(JSON.stringify(actual) === JSON.stringify(wanted),
    `${label} fields must be exactly [${wanted.join(', ')}]`);
}
function sameJson(actual, expected, label) {
  requireCondition(JSON.stringify(actual) === JSON.stringify(expected), `${label} changed`);
}
function powerless(value, label) {
  exactKeys(value, Object.keys(POWERLESS), label);
  requireCondition(Object.values(value).every((item) => item === false),
    `${label} must grant no release or publication authority`);
}
function sha256Bytes(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}
export function fileIdentity(filePath) {
  const expected = fs.lstatSync(filePath);
  requireCondition(expected.isFile() && expected.size > 0 && expected.nlink === 1,
    `${filePath} must be a nonempty regular non-hard-linked file`);

  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  try {
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && before.size > 0 && before.nlink === 1 &&
      before.dev === expected.dev && before.ino === expected.ino,
    `${filePath} changed before hashing`);

    const hash = crypto.createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let bytes = 0;
    for (;;) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      hash.update(buffer.subarray(0, count));
      bytes += count;
    }

    const after = fs.fstatSync(descriptor);
    requireCondition(bytes === before.size &&
      before.dev === after.dev && before.ino === after.ino &&
      before.size === after.size && before.mtimeMs === after.mtimeMs &&
      before.ctimeMs === after.ctimeMs && after.nlink === 1,
    `${filePath} changed while hashing`);
    return {bytes, sha256: hash.digest('hex')};
  } finally {
    fs.closeSync(descriptor);
  }
}
export function copyBoundFile(sourcePath, destinationPath, expectedIdentity) {
  const before = fileIdentity(sourcePath);
  if (expectedIdentity) sameJson(before, expectedIdentity, `${sourcePath} expected identity`);
  fs.mkdirSync(path.dirname(destinationPath), {recursive: true, mode: 0o700});
  fs.copyFileSync(sourcePath, destinationPath, fs.constants.COPYFILE_EXCL);
  const after = fileIdentity(sourcePath);
  const copied = fileIdentity(destinationPath);
  sameJson(after, before, `${sourcePath} source identity during copy`);
  sameJson(copied, before, `${destinationPath} copied identity`);
  return copied;
}
function treeFiles(rootPath) {
  const root = path.resolve(rootPath);
  requireCondition(fs.lstatSync(root).isDirectory(), `${root} must be a directory`);
  const files = [];
  function visit(directory, relativeDirectory) {
    const entries = fs.readdirSync(directory).sort();
    for (const name of entries) {
      const absolute = path.join(directory, name);
      const relative = path.posix.join(relativeDirectory, name);
      const stat = fs.lstatSync(absolute);
      requireCondition(!stat.isSymbolicLink(), `${relative} must not be a symbolic link`);
      if (stat.isDirectory()) visit(absolute, relative);
      else {
        requireCondition(stat.isFile() && stat.size > 0 && stat.nlink === 1,
          `${relative} must be a nonempty regular non-hard-linked file`);
        files.push(relative);
      }
    }
  }
  visit(root, '');
  return files;
}
function canonicalJson(value) { return `${JSON.stringify(value, null, 2)}\n`; }
function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), {recursive: true, mode: 0o700});
  fs.writeFileSync(filePath, canonicalJson(value), {flag: 'wx', mode: 0o600});
}
function readJson(filePath, label) {
  const raw = fs.readFileSync(filePath);
  requireCondition(raw.length > 0 && raw.length <= MAX_OUTPUT, `${label} is empty or oversized`);
  try { return object(JSON.parse(raw.toString('utf8')), label); } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
}
function createOutput(directory, label) {
  const resolved = path.resolve(directory);
  requireCondition(!fs.existsSync(resolved), `${label} must be a new path`);
  fs.mkdirSync(resolved, {recursive: false, mode: 0o700});
  return resolved;
}
function source(commit, tag) {
  requireCondition(COMMIT.test(commit ?? ''), 'source commit must be a full lowercase digest');
  requireCondition(TAG.test(tag ?? ''), 'source tag must be a strict release tag');
  return {repository: PUBLIC_REPOSITORY, commit, tag, dirty: false};
}
function artifactBinding(artifact) {
  return {
    id: artifact.id,
    kind: artifact.kind,
    platform: artifact.platform,
    bytes: artifact.bytes,
    sha256: artifact.sha256,
  };
}

export function loadCandidate(candidateRoot, commit, tag) {
  const root = path.resolve(candidateRoot);
  const receipt = readJson(path.join(root, 'candidate-intake-receipt.json'),
    'candidate intake receipt');
  requireCondition(receipt.classification ===
    'routesphere-bonvoyage-oss-candidate-intake-receipt',
  'candidate intake receipt identity changed');
  requireCondition(JSON.stringify(receipt.source) === JSON.stringify(source(commit, tag)),
    'candidate intake source does not match this producer run');
  const artifacts = array(receipt.artifacts, 'candidate artifacts').map((value) => {
    const artifact = object(value, 'candidate artifact');
    requireCondition(['gateway-deb-linux-amd64', 'gateway-oci-linux-amd64']
      .includes(artifact.id), 'unexpected candidate artifact ID');
    requireCondition(artifact.platform === 'linux/amd64' &&
      ((artifact.id === 'gateway-deb-linux-amd64' && artifact.kind === 'debian-package') ||
      (artifact.id === 'gateway-oci-linux-amd64' && artifact.kind === 'oci-image')),
    `${artifact.id} identity changed`);
    requireCondition(Number.isSafeInteger(artifact.bytes) && artifact.bytes > 0 &&
      SHA256.test(artifact.sha256 ?? ''), `${artifact.id} has an invalid byte identity`);
    const filePath = path.resolve(root, string(artifact.path, `${artifact.id} path`));
    requireCondition(filePath.startsWith(`${root}${path.sep}`), `${artifact.id} escapes the intake root`);
    const actual = fileIdentity(filePath);
    requireCondition(actual.bytes === artifact.bytes && actual.sha256 === artifact.sha256,
      `${artifact.id} candidate bytes changed`);
    return {...artifactBinding(artifact), path: filePath};
  });
  requireCondition(artifacts.length === 2 && new Set(artifacts.map(({id}) => id)).size === 2,
    'exactly two candidate artifacts are required');
  return {root, receipt, artifacts: artifacts.sort((left, right) => left.id.localeCompare(right.id))};
}

function containerArgs({image, network = 'none', volumes = [], environment = [], entrypoint}) {
  const uid = process.getuid?.() ?? 1000;
  const gid = process.getgid?.() ?? 1000;
  const result = [
    'docker', 'run', '--rm', '--pull', 'never', '--platform', 'linux/amd64',
    '--network', network, '--read-only', '--user', `${uid}:${gid}`,
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '--cpus', '2', '--memory', '4g', '--pids-limit', '256',
    '--tmpfs', `/tmp:rw,noexec,nosuid,size=768m,mode=0700,uid=${uid},gid=${gid}`,
    '--tmpfs', `/.cache:rw,noexec,nosuid,size=64m,mode=0700,uid=${uid},gid=${gid}`,
  ];
  for (const value of volumes) result.push('--volume', value);
  for (const value of environment) result.push('--env', value);
  if (entrypoint) result.push('--entrypoint', entrypoint);
  result.push(image);
  return result;
}

function execute(argv, {allowed = [0], timeout = 900_000} = {}) {
  const result = childProcess.spawnSync(argv[0], argv.slice(1), {
    encoding: 'buffer', maxBuffer: MAX_OUTPUT, timeout,
    env: {...process.env, DOCKER_CLI_HINTS: 'false'},
  });
  requireCondition(result.error === undefined,
    `command could not run: ${result.error?.message ?? 'unknown error'}`);
  requireCondition(allowed.includes(result.status),
    `command failed (${result.status}): ${argv.slice(-8).join(' ')}\n${result.stderr?.toString('utf8') ?? ''}`);
  return {exitCode: result.status, stdout: result.stdout, stderr: result.stderr};
}

export async function prepareValidator({output, fetchImpl = globalThis.fetch, runner = execute}) {
  const root = createOutput(output, 'validator output');
  const schemaResponse = await fetchImpl(SPDX_SCHEMA_URL, {
    method: 'GET', redirect: 'error', signal: AbortSignal.timeout(30_000),
  });
  requireCondition(schemaResponse?.ok === true && schemaResponse.status === 200,
    `SPDX schema download failed with status ${schemaResponse?.status ?? 'unknown'}`);
  const schema = Buffer.from(await schemaResponse.arrayBuffer());
  requireCondition(schema.length > 0 && schema.length <= 16 * 1024 * 1024 &&
    sha256Bytes(schema) === SPDX_SCHEMA_SHA, 'official SPDX schema byte pin mismatch');
  fs.writeFileSync(path.join(root, 'spdx-schema.json'), schema, {flag: 'wx', mode: 0o600});

  const command = containerArgs({
    image: PYTHON, network: 'bridge', entrypoint: '/bin/sh',
    volumes: [`${root}:/validator:rw`, `${REPOSITORY_ROOT}:/repository:ro`],
  });
  command.push('-ec', validatorInstallScript());
  runner(command);
  const lock = fileIdentity(VALIDATOR_LOCK);
  requireCondition(lock.sha256 === SPDX_LOCK_SHA, 'SPDX validator lock byte pin mismatch');
  writeJson(path.join(root, 'validator-receipt.json'), {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-spdx-validator-preparation',
    python_image: PYTHON,
    schema: {url: SPDX_SCHEMA_URL, bytes: schema.length, sha256: SPDX_SCHEMA_SHA},
    lock: {path: 'security/tools/native-sbom-python.lock', ...lock},
    authority: POWERLESS,
  });
  return root;
}

export function validatorInstallScript() {
  return [
    'python -m venv /validator/venv',
    '/validator/venv/bin/python -m pip install --disable-pip-version-check ' +
      '--no-cache-dir --require-hashes ' +
      '-r /repository/security/tools/native-sbom-python.lock',
  ].join(' && ');
}

export function bindCycloneDx(raw, artifact, sourceIdentity) {
  const document = structuredClone(object(raw, 'raw CycloneDX'));
  requireCondition(document.bomFormat === 'CycloneDX' && document.specVersion === '1.6',
    'Syft did not emit CycloneDX 1.6');
  document.metadata = object(document.metadata ?? {}, 'CycloneDX metadata');
  document.metadata.component = {
    type: 'file',
    'bom-ref': `artifact:${artifact.id}`,
    name: artifact.id,
    version: sourceIdentity.tag,
    hashes: [{alg: 'SHA-256', content: artifact.sha256}],
    properties: [
      {name: 'routesphere:artifact-kind', value: artifact.kind},
      {name: 'routesphere:platform', value: artifact.platform},
      {name: 'routesphere:source-commit', value: sourceIdentity.commit},
    ],
  };
  document.components = array(document.components ?? [], 'CycloneDX components')
    .filter((value) => value?.['bom-ref'] !== `artifact:${artifact.id}`);
  return document;
}

export function bindSpdx(raw, artifact, sourceIdentity) {
  const document = structuredClone(object(raw, 'raw SPDX'));
  requireCondition(document.spdxVersion === 'SPDX-2.3' &&
    document.SPDXID === 'SPDXRef-DOCUMENT', 'Syft did not emit SPDX 2.3 JSON');
  const packages = array(document.packages ?? [], 'SPDX packages');
  const relationships = array(document.relationships ?? [], 'SPDX relationships');
  const described = relationships.filter((value) =>
    value?.spdxElementId === 'SPDXRef-DOCUMENT' && value?.relationshipType === 'DESCRIBES');
  requireCondition(described.length === 1,
    'Syft SPDX must contain exactly one native document root');
  const nativeRootId = described[0].relatedSpdxElement;
  const nativeRoots = packages.filter((value) => value?.SPDXID === nativeRootId);
  requireCondition(nativeRoots.length === 1 && packages.every((value) =>
    value?.SPDXID !== 'SPDXRef-ArtifactRoot'),
  'Syft SPDX native document root is missing or conflicts with the artifact root');
  const root = {
    ...nativeRoots[0],
    SPDXID: 'SPDXRef-ArtifactRoot',
    name: artifact.id,
    versionInfo: sourceIdentity.tag,
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: false,
    primaryPackagePurpose: 'FILE',
    checksums: [{algorithm: 'SHA256', checksumValue: artifact.sha256}],
    licenseConcluded: 'NOASSERTION',
    licenseDeclared: 'NOASSERTION',
    copyrightText: 'NOASSERTION',
  };
  delete root.externalRefs;
  document.packages = packages.map((value) =>
    value.SPDXID === nativeRootId ? root : value);
  document.relationships = relationships.map((value) => ({
    ...value,
    spdxElementId: value.spdxElementId === nativeRootId ? root.SPDXID : value.spdxElementId,
    relatedSpdxElement: value.relatedSpdxElement === nativeRootId ?
      root.SPDXID : value.relatedSpdxElement,
  }));
  return document;
}

export function decodedPackages(value) {
  const document = object(value, 'Syft decoded inventory');
  const packages = new Map();
  for (const [index, value] of array(document.artifacts, 'Syft decoded artifacts').entries()) {
    const artifact = object(value, `Syft decoded artifact ${index}`);
    const normalized = {
      name: string(artifact.name, `Syft decoded artifact ${index} name`),
      version: string(artifact.version, `Syft decoded artifact ${index} version`),
      type: string(artifact.type, `Syft decoded artifact ${index} type`),
      purl: string(artifact.purl, `Syft decoded artifact ${index} package URL`),
    };
    packages.set(JSON.stringify(normalized), normalized);
  }
  requireCondition(packages.size > 0, 'Syft decoded package inventory is empty');
  return [...packages.values()].sort((left, right) =>
    JSON.stringify(left).localeCompare(JSON.stringify(right)));
}

export function syftSourceDescriptor(artifact) {
  const sourceType = artifact.kind === 'debian-package' ? 'file' : 'oci-archive';
  const mountPath = artifact.kind === 'debian-package' ?
    '/input/candidate.deb' : '/input/candidate.oci.tar';
  return {mountPath, source: `${sourceType}:${mountPath}`};
}

function syftCommand(artifact, format) {
  const descriptor = syftSourceDescriptor(artifact);
  const output = format === 'cyclonedx-1.6-json' ? 'cyclonedx-json@1.6' : 'spdx-json@2.3';
  return {
    source: descriptor.source,
    output,
    argv: containerArgs({
      image: SYFT,
      volumes: [`${artifact.path}:${descriptor.mountPath}:ro`],
      environment: ['SYFT_CHECK_FOR_APP_UPDATE=false'],
    }),
  };
}

function validateCycloneDx(document, allowed, runner) {
  const argv = containerArgs({
    image: CYCLONEDX_VALIDATOR,
    volumes: [`${document}:/input.json:ro`],
  });
  argv.push('validate', '--input-file', '/input.json', '--input-format', 'json',
    '--input-version', 'v1_6', '--fail-on-errors');
  return runner(argv, {allowed});
}

function validateSpdx(document, validatorRoot, allowed, runner) {
  const argv = containerArgs({
    image: PYTHON,
    entrypoint: '/validator/venv/bin/python',
    volumes: [
      `${validatorRoot}:/validator:ro`, `${REPOSITORY_ROOT}:/repository:ro`,
      `${document}:/input.json:ro`,
    ],
  });
  argv.push('/repository/scripts/validate-native-spdx.py', '--input', '/input.json',
    '--schema', '/validator/spdx-schema.json');
  return runner(argv, {allowed});
}

function decodeDocument(document, runner) {
  const argv = containerArgs({
    image: SYFT,
    volumes: [`${document}:/input.json:ro`],
    environment: ['SYFT_CHECK_FOR_APP_UPDATE=false'],
  });
  argv.push('convert', '/input.json', '-o', 'syft-json');
  return runner(argv);
}

function commandReceipt(operation, format, tool, argv, exitCode, inputSha, outputSha) {
  return {
    operation, format, tool, argv, exit_code: exitCode,
    input_sha256: inputSha, output_sha256: outputSha,
  };
}

export function produceSbom({candidateRoot, validatorRoot, output, sourceCommit, sourceTag,
  runner = execute}) {
  const sourceIdentity = source(sourceCommit, sourceTag);
  const candidate = loadCandidate(candidateRoot, sourceCommit, sourceTag);
  const validator = path.resolve(validatorRoot);
  const validatorReceipt = readJson(path.join(validator, 'validator-receipt.json'),
    'validator preparation receipt');
  requireCondition(validatorReceipt.schema?.sha256 === SPDX_SCHEMA_SHA &&
    validatorReceipt.lock?.sha256 === SPDX_LOCK_SHA && validatorReceipt.python_image === PYTHON,
  'SPDX validator preparation does not match the producer contract');
  const root = createOutput(output, 'SBOM producer output');
  const evidence = path.join(root, 'evidence');
  const work = path.join(root, '.work');
  fs.mkdirSync(evidence, {mode: 0o700});
  fs.mkdirSync(work, {mode: 0o700});
  const boundedArtifacts = candidate.artifacts.map((artifact) => {
    const fileName = artifact.kind === 'debian-package' ? 'candidate.deb' : 'candidate.oci.tar';
    const destination = path.join(work, 'candidate', artifact.id, fileName);
    copyBoundFile(artifact.path, destination,
      {bytes: artifact.bytes, sha256: artifact.sha256});
    return {...artifact, path: destination};
  });
  const produced = [];

  for (const artifact of boundedArtifacts) {
    const directory = path.join(evidence, artifact.id);
    const temporary = path.join(work, artifact.id);
    fs.mkdirSync(directory, {mode: 0o700});
    fs.mkdirSync(temporary, {mode: 0o700});
    const receipts = [];
    const documents = [];
    const decodedByFormat = new Map();
    for (const specification of [
      ['cyclonedx-1.6-json', 'cyclonedx.json', bindCycloneDx],
      ['spdx-2.3-json', 'spdx.json', bindSpdx],
    ]) {
      const [format, fileName, binder] = specification;
      const command = syftCommand(artifact, format);
      command.argv.push('scan', command.source, '-o', command.output);
      const generated = runner(command.argv);
      const bound = binder(JSON.parse(generated.stdout.toString('utf8')), artifact, sourceIdentity);
      const documentPath = path.join(directory, fileName);
      writeJson(documentPath, bound);
      const documentIdentity = fileIdentity(documentPath);
      receipts.push(commandReceipt('generate', format, SYFT,
        ['syft', 'scan', command.source, '-o', command.output, 'bind-root', artifact.id],
        generated.exitCode, artifact.sha256, documentIdentity.sha256));

      const invalid = structuredClone(bound);
      if (format === 'cyclonedx-1.6-json') delete invalid.bomFormat;
      else delete invalid.SPDXID;
      const invalidPath = path.join(temporary, `invalid-${fileName}`);
      writeJson(invalidPath, invalid);
      const invalidIdentity = fileIdentity(invalidPath);
      const validatorTool = format === 'cyclonedx-1.6-json' ? CYCLONEDX_VALIDATOR :
        `spdx-json-schema@sha256:${SPDX_SCHEMA_SHA}+validator-lock@sha256:${SPDX_LOCK_SHA}`;
      const validResult = format === 'cyclonedx-1.6-json' ?
        validateCycloneDx(documentPath, [0], runner) :
        validateSpdx(documentPath, validator, [0], runner);
      const invalidResult = format === 'cyclonedx-1.6-json' ?
        validateCycloneDx(invalidPath, [1, 2, 255], runner) :
        validateSpdx(invalidPath, validator, [1], runner);
      requireCondition(invalidResult.exitCode !== 0,
        `${format} invalid control was not rejected`);
      receipts.push(
        commandReceipt('schema-validate', format, validatorTool,
          ['validate', fileName], validResult.exitCode,
          documentIdentity.sha256, documentIdentity.sha256),
        commandReceipt('invalid-control', format, validatorTool,
          ['validate', `invalid-${fileName}`], invalidResult.exitCode,
          invalidIdentity.sha256, invalidIdentity.sha256),
      );

      const decodedResult = decodeDocument(documentPath, runner);
      const packages = decodedPackages(JSON.parse(decodedResult.stdout.toString('utf8')));
      const decodedName = format === 'cyclonedx-1.6-json' ?
        'decoded-cyclonedx.json' : 'decoded-spdx.json';
      const decodedPath = path.join(directory, decodedName);
      writeJson(decodedPath, {
        schema_version: 1,
        classification: 'routesphere-bonvoyage-oss-sbom-decoded-inventory',
        source: sourceIdentity,
        artifact: artifactBinding(artifact),
        format,
        descriptor: {name: 'syft', version: '1.44.0'},
        packages,
      });
      const decodedIdentity = fileIdentity(decodedPath);
      receipts.push(commandReceipt('decode', format, SYFT,
        ['syft', 'convert', fileName, '-o', 'syft-json'], decodedResult.exitCode,
        documentIdentity.sha256, decodedIdentity.sha256));
      decodedByFormat.set(format, packages);
      documents.push({
        format, path: fileName, ...documentIdentity,
        decoded_path: decodedName, decoded_bytes: decodedIdentity.bytes,
        decoded_sha256: decodedIdentity.sha256,
      });
    }
    requireCondition(JSON.stringify(decodedByFormat.get('cyclonedx-1.6-json')) ===
      JSON.stringify(decodedByFormat.get('spdx-2.3-json')),
    `${artifact.id} decoded inventories differ`);
    receipts.sort((left, right) => {
      const formats = ['cyclonedx-1.6-json', 'spdx-2.3-json'];
      const operations = ['generate', 'schema-validate', 'invalid-control', 'decode'];
      return (formats.indexOf(left.format) - formats.indexOf(right.format)) ||
        (operations.indexOf(left.operation) - operations.indexOf(right.operation));
    });
    writeJson(path.join(directory, 'validation.json'), {
      schema_version: 1,
      classification: 'routesphere-bonvoyage-oss-sbom-validation-evidence',
      source: sourceIdentity,
      artifact: artifactBinding(artifact),
      tools: {
        syft_image: SYFT,
        cyclonedx_validator_image: CYCLONEDX_VALIDATOR,
        spdx_schema_sha256: SPDX_SCHEMA_SHA,
        spdx_validator_lock_sha256: SPDX_LOCK_SHA,
      },
      documents,
      command_receipts: receipts,
      decoder_parity: true,
      authority: POWERLESS,
    });
    produced.push({artifact: artifactBinding(artifact), documents});
  }
  fs.rmSync(work, {recursive: true});
  writeJson(path.join(root, 'producer-receipt.json'), {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-sbom-producer-evidence',
    status: 'SBOM_EVIDENCE_PRODUCED',
    source: sourceIdentity,
    artifacts: produced,
    human_review_required: true,
    review_generated: false,
    authority: POWERLESS,
  });
  return root;
}

function grypeEnvironment() {
  return [
    'GRYPE_CHECK_FOR_APP_UPDATE=false', 'GRYPE_TIMESTAMP=true',
    'GRYPE_DB_CACHE_DIR=/database', 'GRYPE_EXTERNAL_SOURCES_ENABLE=false',
    'GRYPE_ADD_CPES_IF_NONE=false', 'GRYPE_DB_AUTO_UPDATE=false',
    'GRYPE_DB_VALIDATE_BY_HASH_ON_START=true', 'GRYPE_DB_VALIDATE_AGE=true',
    'GRYPE_DB_MAX_ALLOWED_BUILT_AGE=48h',
  ];
}

function grypeCommand(database, {online = false, evidence} = {}) {
  const volumes = [`${database}:/database:${online ? 'rw' : 'ro'}`];
  if (evidence) volumes.push(`${evidence}:/input:ro`);
  return containerArgs({
    image: GRYPE, network: online ? 'bridge' : 'none', volumes,
    environment: grypeEnvironment(),
  });
}

export function normalizeGrypeScan(raw, target) {
  const scan = structuredClone(object(raw, 'Grype report'));
  const sourceReport = object(scan.source, 'Grype source');
  const expectedRoot = path.posix.basename(path.posix.dirname(target));
  requireCondition(['file', 'directory', 'sbom-file'].includes(sourceReport.type) &&
    sourceReport.target === expectedRoot,
  'Grype did not bind the scan to the expected SBOM artifact root');
  scan.source.target = target;
  const status = object(scan.descriptor?.db?.status, 'Grype database status');
  requireCondition(status.valid === true && /^v6\.\d+\.\d+$/u.test(status.schemaVersion ?? ''),
    'Grype did not use a valid v6 database');
  status.path = '/evidence/database/vulnerability.db';
  return scan;
}

export function normalizeFinding(match) {
  const vulnerability = object(match?.vulnerability, 'finding vulnerability');
  const artifact = object(match?.artifact, 'finding artifact');
  const fix = object(vulnerability.fix, 'finding fix');
  const packageName = string(artifact.name, 'finding package');
  const packageVersion = string(artifact.version, 'finding version');
  const packageType = string(artifact.type, 'finding type');
  const packageIdentity = string(artifact.purl, 'finding package URL');
  return {
    id: string(vulnerability.id, 'finding ID'),
    namespace: string(vulnerability.namespace, 'finding namespace'),
    package_id: packageIdentity,
    package: packageName,
    version: packageVersion,
    type: packageType,
    severity: string(vulnerability.severity, 'finding severity'),
    fix_state: string(fix.state, 'finding fix state'),
    fix_versions: array(fix.versions, 'finding fix versions').slice().sort(),
  };
}

function verifyCycloneDxRoot(document, artifact) {
  requireCondition(document.bomFormat === 'CycloneDX' && document.specVersion === '1.6',
    `${artifact.id} CycloneDX format changed`);
  const component = object(object(document.metadata, 'CycloneDX metadata').component,
    'CycloneDX root component');
  requireCondition(component.type === 'file' && component['bom-ref'] === `artifact:${artifact.id}` &&
    component.name === artifact.id && array(component.hashes, 'CycloneDX root hashes')
      .some((value) => value?.alg === 'SHA-256' && value?.content === artifact.sha256),
  `${artifact.id} CycloneDX root is not bound to the candidate bytes`);
}

function verifySpdxRoot(document, artifact) {
  requireCondition(document.spdxVersion === 'SPDX-2.3' && document.SPDXID === 'SPDXRef-DOCUMENT',
    `${artifact.id} SPDX format changed`);
  const roots = array(document.packages, 'SPDX packages')
    .filter((value) => value?.SPDXID === 'SPDXRef-ArtifactRoot');
  requireCondition(roots.length === 1 && roots[0].name === artifact.id &&
    array(roots[0].checksums, 'SPDX root checksums').some((value) =>
      value?.algorithm === 'SHA256' && value?.checksumValue === artifact.sha256),
  `${artifact.id} SPDX root is not bound to the candidate bytes`);
  const describes = array(document.relationships, 'SPDX relationships').filter((value) =>
    value?.spdxElementId === 'SPDXRef-DOCUMENT' && value?.relationshipType === 'DESCRIBES' &&
    value?.relatedSpdxElement === 'SPDXRef-ArtifactRoot');
  requireCondition(describes.length === 1,
    `${artifact.id} SPDX document does not describe the candidate root exactly once`);
}

function verifyDecodedInventory(document, sourceIdentity, artifact, format) {
  exactKeys(document, [
    'schema_version', 'classification', 'source', 'artifact', 'format', 'descriptor', 'packages',
  ], `${artifact.id} ${format} decoded inventory`);
  requireCondition(document.schema_version === 1 && document.classification ===
    'routesphere-bonvoyage-oss-sbom-decoded-inventory' && document.format === format,
  `${artifact.id} ${format} decoded inventory identity changed`);
  sameJson(document.source, sourceIdentity, `${artifact.id} ${format} decoded source`);
  sameJson(document.artifact, artifactBinding(artifact),
    `${artifact.id} ${format} decoded artifact`);
  sameJson(document.descriptor, {name: 'syft', version: '1.44.0'},
    `${artifact.id} ${format} decoder`);
  const normalized = decodedPackages({artifacts: document.packages});
  sameJson(document.packages, normalized, `${artifact.id} ${format} normalized packages`);
  return normalized;
}

function verifyValidationReceipt(document, sourceIdentity, artifact, documents) {
  exactKeys(document, [
    'schema_version', 'classification', 'source', 'artifact', 'tools', 'documents',
    'command_receipts', 'decoder_parity', 'authority',
  ], `${artifact.id} validation evidence`);
  requireCondition(document.schema_version === 1 && document.classification ===
    'routesphere-bonvoyage-oss-sbom-validation-evidence' && document.decoder_parity === true,
  `${artifact.id} validation evidence identity changed`);
  sameJson(document.source, sourceIdentity, `${artifact.id} validation source`);
  sameJson(document.artifact, artifactBinding(artifact), `${artifact.id} validation artifact`);
  sameJson(document.tools, {
    syft_image: SYFT,
    cyclonedx_validator_image: CYCLONEDX_VALIDATOR,
    spdx_schema_sha256: SPDX_SCHEMA_SHA,
    spdx_validator_lock_sha256: SPDX_LOCK_SHA,
  }, `${artifact.id} validation tools`);
  sameJson(document.documents, documents, `${artifact.id} validation documents`);
  powerless(document.authority, `${artifact.id} validation authority`);

  const receipts = array(document.command_receipts, `${artifact.id} command receipts`);
  requireCondition(receipts.length === 8, `${artifact.id} must retain eight command receipts`);
  for (const specification of [
    ['cyclonedx-1.6-json', documents[0], CYCLONEDX_VALIDATOR],
    ['spdx-2.3-json', documents[1],
      `spdx-json-schema@sha256:${SPDX_SCHEMA_SHA}+validator-lock@sha256:${SPDX_LOCK_SHA}`],
  ]) {
    const [format, sbom, validator] = specification;
    const byOperation = new Map(receipts.filter((value) => value?.format === format)
      .map((value) => [value.operation, value]));
    requireCondition(byOperation.size === 4 &&
      ['generate', 'schema-validate', 'invalid-control', 'decode']
        .every((operation) => byOperation.has(operation)),
    `${artifact.id} ${format} command receipt set changed`);
    for (const [operation, receipt] of byOperation) {
      exactKeys(receipt, [
        'operation', 'format', 'tool', 'argv', 'exit_code', 'input_sha256', 'output_sha256',
      ], `${artifact.id} ${format} ${operation} receipt`);
      requireCondition(Array.isArray(receipt.argv),
        `${artifact.id} ${format} ${operation} argv must be an array`);
    }
    const generated = byOperation.get('generate');
    const validated = byOperation.get('schema-validate');
    const invalid = byOperation.get('invalid-control');
    const decoded = byOperation.get('decode');
    requireCondition(generated.tool === SYFT && generated.exit_code === 0 &&
      generated.input_sha256 === artifact.sha256 && generated.output_sha256 === sbom.sha256 &&
      validated.tool === validator && validated.exit_code === 0 &&
      validated.input_sha256 === sbom.sha256 && validated.output_sha256 === sbom.sha256 &&
      invalid.tool === validator && Number.isInteger(invalid.exit_code) && invalid.exit_code !== 0 &&
      SHA256.test(invalid.input_sha256 ?? '') && invalid.output_sha256 === invalid.input_sha256 &&
      decoded.tool === SYFT && decoded.exit_code === 0 &&
      decoded.input_sha256 === sbom.sha256 && decoded.output_sha256 === sbom.decoded_sha256,
    `${artifact.id} ${format} command binding changed`);
  }
}

function verifySbomHandoff(candidate, sbomRoot, sourceIdentity) {
  const root = path.resolve(sbomRoot);
  const expectedFiles = ['producer-receipt.json'];
  for (const artifact of candidate.artifacts) {
    for (const fileName of [
      'cyclonedx.json', 'spdx.json', 'decoded-cyclonedx.json',
      'decoded-spdx.json', 'validation.json',
    ]) expectedFiles.push(path.posix.join('evidence', artifact.id, fileName));
  }
  sameJson(treeFiles(root), expectedFiles.sort(), 'SBOM evidence file inventory');

  const receipt = readJson(path.join(root, 'producer-receipt.json'), 'SBOM producer receipt');
  exactKeys(receipt, [
    'schema_version', 'classification', 'status', 'source', 'artifacts',
    'human_review_required', 'review_generated', 'authority',
  ], 'SBOM producer receipt');
  requireCondition(receipt.schema_version === 1 && receipt.classification ===
    'routesphere-bonvoyage-oss-sbom-producer-evidence' &&
    receipt.status === 'SBOM_EVIDENCE_PRODUCED' &&
    receipt.human_review_required === true && receipt.review_generated === false,
  'SBOM producer receipt is not eligible');
  sameJson(receipt.source, sourceIdentity, 'SBOM producer source');
  powerless(receipt.authority, 'SBOM producer authority');
  const artifacts = array(receipt.artifacts, 'SBOM producer artifacts');
  requireCondition(artifacts.length === candidate.artifacts.length,
    'SBOM producer artifact count changed');
  const byId = new Map(artifacts.map((value) => [value?.artifact?.id, value]));
  requireCondition(byId.size === candidate.artifacts.length,
    'SBOM producer artifacts are not unique');

  const verified = [];
  for (const artifact of candidate.artifacts) {
    const record = object(byId.get(artifact.id), `${artifact.id} SBOM producer artifact`);
    exactKeys(record, ['artifact', 'documents'], `${artifact.id} SBOM producer artifact`);
    sameJson(record.artifact, artifactBinding(artifact), `${artifact.id} SBOM binding`);
    const documents = array(record.documents, `${artifact.id} SBOM documents`);
    requireCondition(documents.length === 2, `${artifact.id} must have two SBOM documents`);
    const formats = [
      ['cyclonedx-1.6-json', 'cyclonedx.json', 'decoded-cyclonedx.json'],
      ['spdx-2.3-json', 'spdx.json', 'decoded-spdx.json'],
    ];
    const normalized = [];
    for (let index = 0; index < formats.length; index += 1) {
      const [format, fileName, decodedName] = formats[index];
      const document = object(documents[index], `${artifact.id} ${format} document receipt`);
      exactKeys(document, [
        'format', 'path', 'bytes', 'sha256', 'decoded_path', 'decoded_bytes', 'decoded_sha256',
      ], `${artifact.id} ${format} document receipt`);
      requireCondition(document.format === format && document.path === fileName &&
        document.decoded_path === decodedName && Number.isSafeInteger(document.bytes) &&
        document.bytes > 0 && SHA256.test(document.sha256 ?? '') &&
        Number.isSafeInteger(document.decoded_bytes) && document.decoded_bytes > 0 &&
        SHA256.test(document.decoded_sha256 ?? ''),
      `${artifact.id} ${format} document identity changed`);
      const directory = path.join(root, 'evidence', artifact.id);
      sameJson(fileIdentity(path.join(directory, fileName)),
        {bytes: document.bytes, sha256: document.sha256}, `${artifact.id} ${format} bytes`);
      sameJson(fileIdentity(path.join(directory, decodedName)),
        {bytes: document.decoded_bytes, sha256: document.decoded_sha256},
        `${artifact.id} ${format} decoded bytes`);
      const sbom = readJson(path.join(directory, fileName), `${artifact.id} ${format} SBOM`);
      if (format === 'cyclonedx-1.6-json') verifyCycloneDxRoot(sbom, artifact);
      else verifySpdxRoot(sbom, artifact);
      normalized.push(verifyDecodedInventory(
        readJson(path.join(directory, decodedName), `${artifact.id} ${format} decoded inventory`),
        sourceIdentity, artifact, format));
    }
    sameJson(normalized[0], normalized[1], `${artifact.id} decoded inventory parity`);
    verifyValidationReceipt(readJson(
      path.join(root, 'evidence', artifact.id, 'validation.json'),
      `${artifact.id} validation evidence`), sourceIdentity, artifact, documents);
    verified.push({artifact, documents});
  }
  return {root, artifacts: verified};
}

function databaseFromScan(scan, payload) {
  const status = object(scan.descriptor?.db?.status, 'Grype database status');
  const origin = new URL(status.from);
  const archiveSha = origin.searchParams.get('checksum')?.replace(/^sha256:/u, '');
  requireCondition(SHA256.test(archiveSha ?? ''), 'Grype database origin lacks a SHA-256');
  return {
    path: 'vulnerability.db', ...payload,
    built_at: new Date(status.built).toISOString(),
    schema_version: status.schemaVersion,
    origin: `${origin.protocol}//${origin.host}${origin.pathname}`,
    archive_sha256: archiveSha,
  };
}

export function produceVulnerability({candidateRoot, sbomRoot, output, sourceCommit,
  sourceTag, runner = execute}) {
  const sourceIdentity = source(sourceCommit, sourceTag);
  const candidate = loadCandidate(candidateRoot, sourceCommit, sourceTag);
  const sbom = verifySbomHandoff(candidate, sbomRoot, sourceIdentity);
  const root = createOutput(output, 'vulnerability producer output');
  const evidence = path.join(root, 'evidence');
  const reviewInput = path.join(root, 'review-input');
  const work = path.join(root, '.work');
  fs.mkdirSync(evidence, {mode: 0o700});
  for (const {artifact, documents} of sbom.artifacts) {
    const sourceDirectory = path.join(sbom.root, 'evidence', artifact.id);
    const destinationDirectory = path.join(evidence, artifact.id);
    for (const document of documents) {
      copyBoundFile(path.join(sourceDirectory, document.path),
        path.join(destinationDirectory, document.path),
        {bytes: document.bytes, sha256: document.sha256});
      copyBoundFile(path.join(sourceDirectory, document.decoded_path),
        path.join(destinationDirectory, document.decoded_path),
        {bytes: document.decoded_bytes, sha256: document.decoded_sha256});
    }
    const validation = path.join(sourceDirectory, 'validation.json');
    copyBoundFile(validation, path.join(destinationDirectory, 'validation.json'),
      fileIdentity(validation));
  }
  fs.mkdirSync(reviewInput, {mode: 0o700});
  fs.mkdirSync(work, {mode: 0o700});
  const databaseCache = path.join(work, 'database-cache');
  fs.mkdirSync(databaseCache, {mode: 0o700});
  const update = grypeCommand(databaseCache, {online: true});
  update.push('db', 'update');
  runner(update);
  const databasePayload = path.join(databaseCache, '6/vulnerability.db');
  requireCondition(fs.existsSync(databasePayload), 'Grype v6 database payload was not hydrated');
  const before = fileIdentity(databasePayload);
  const scansByArtifact = new Map();

  for (const artifact of candidate.artifacts) {
    const scans = [];
    for (const [format, fileName, scanName] of [
      ['cyclonedx-1.6-json', 'cyclonedx.json', 'scan-cyclonedx.json'],
      ['spdx-2.3-json', 'spdx.json', 'scan-spdx.json'],
    ]) {
      const target = `/input/${artifact.id}/${fileName}`;
      const inputPath = path.join(evidence, artifact.id, fileName);
      const inputIdentity = fileIdentity(inputPath);
      const argv = grypeCommand(databaseCache, {evidence});
      argv.push(`sbom:${target}`, '-o', 'json');
      const result = runner(argv);
      const report = normalizeGrypeScan(JSON.parse(result.stdout.toString('utf8')), target);
      const destination = path.join(evidence, artifact.id, scanName);
      writeJson(destination, report);
      requireCondition(JSON.stringify(fileIdentity(databasePayload)) === JSON.stringify(before),
        'vulnerability database changed between scans');
      sameJson(fileIdentity(inputPath), inputIdentity,
        `${artifact.id} ${format} SBOM changed during scan`);
      scans.push({
        format, path: scanName, ...fileIdentity(destination), target,
        input_sha256: inputIdentity.sha256,
        exit_code: result.exitCode,
        report,
      });
    }
    requireCondition(JSON.stringify(scans[0].report.matches.map(normalizeFinding)
      .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)))) ===
      JSON.stringify(scans[1].report.matches.map(normalizeFinding)
        .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)))),
    `${artifact.id} scan findings differ between formats`);
    scansByArtifact.set(artifact.id, scans);
  }

  const databaseDirectory = path.join(evidence, 'database');
  fs.mkdirSync(databaseDirectory, {mode: 0o700});
  copyBoundFile(databasePayload, path.join(databaseDirectory, 'vulnerability.db'), before);
  const firstScan = scansByArtifact.values().next().value[0].report;
  const database = databaseFromScan(firstScan, before);
  writeJson(path.join(databaseDirectory, 'receipt.json'), {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-vulnerability-database-evidence',
    source: sourceIdentity,
    scanner_image: GRYPE,
    database,
    authority: POWERLESS,
  });

  const summaries = [];
  for (const artifact of candidate.artifacts) {
    const scans = scansByArtifact.get(artifact.id);
    const findings = scans[0].report.matches.map(normalizeFinding)
      .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
    const blocking = findings.filter(({severity}) => ['High', 'Critical'].includes(severity));
    const review = {
      schema_version: 1,
      classification: 'routesphere-bonvoyage-oss-vulnerability-review-input',
      source: sourceIdentity,
      artifact: artifactBinding(artifact),
      scanner_image: GRYPE,
      database,
      scans: scans.map(({format, path: scanPath, bytes, sha256, target}) =>
        ({format, path: scanPath, bytes, sha256, target})),
      scan_commands: scans.map((scan) => ({
        format: scan.format,
        tool: GRYPE,
        argv: ['grype', `sbom:${scan.target}`, '-o', 'json'],
        exit_code: scan.exit_code,
        input_sha256: scan.input_sha256,
        database_sha256: database.sha256,
        output_sha256: scan.sha256,
      })),
      findings,
      blocking_findings: blocking,
      format_parity: true,
      required_reviewer: {
        identity: 'johnynixon@routesphere.global',
        role: 'release-security-reviewer',
      },
      human_review_required: true,
      review_generated: false,
      authority: POWERLESS,
    };
    writeJson(path.join(reviewInput, `${artifact.id}.json`), review);
    summaries.push({artifact: artifactBinding(artifact), findings: findings.length,
      blocking_findings: blocking.length});
  }
  fs.rmSync(work, {recursive: true});
  writeJson(path.join(root, 'producer-receipt.json'), {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-vulnerability-producer-evidence',
    status: 'VULNERABILITY_EVIDENCE_PRODUCED_REVIEW_REQUIRED',
    source: sourceIdentity,
    database,
    artifacts: summaries,
    human_review_required: true,
    review_generated: false,
    release_blocked_pending_review: true,
    authority: POWERLESS,
  });
  return root;
}

function parseArguments(argv) {
  const [operation, ...rest] = argv;
  const values = new Map();
  for (let index = 0; index < rest.length; index += 2) {
    requireCondition(rest[index]?.startsWith('--') && rest[index + 1] !== undefined,
      'arguments must be --name value pairs');
    values.set(rest[index].slice(2), rest[index + 1]);
  }
  return {operation, values};
}

async function main(argv) {
  const {operation, values} = parseArguments(argv);
  if (operation === 'prepare-validator') {
    await prepareValidator({output: values.get('output')});
  } else if (operation === 'sbom') {
    produceSbom({
      candidateRoot: values.get('candidate-root'),
      validatorRoot: values.get('validator-root'), output: values.get('output'),
      sourceCommit: values.get('source-commit'), sourceTag: values.get('source-tag'),
    });
  } else if (operation === 'vulnerability') {
    produceVulnerability({
      candidateRoot: values.get('candidate-root'), sbomRoot: values.get('sbom-root'),
      output: values.get('output'), sourceCommit: values.get('source-commit'),
      sourceTag: values.get('source-tag'),
    });
  } else fail('operation must be prepare-validator, sbom, or vulnerability');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`supply-chain producer failed: ${error.message}\n`);
    process.exitCode = 2;
  });
}
