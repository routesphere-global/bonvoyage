#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

import yaml from 'js-yaml';

const CLASSIFICATION = 'routesphere-bonvoyage-oss-oci-builder-image-contract';
const LOCAL_STATE = 'local-foundation-unpublished';
const PUBLIC_STATE = 'public-foundation-verified';
const REPOSITORY = 'ghcr.io/routesphere-global/bonvoyage-oci-builder';
const ENTRYPOINT = '/usr/local/bin/bonvoyage-oss-oci-builder';
const FOUNDATION_REFERENCE =
  `${REPOSITORY}@sha256:51d38192e3bdd43714b77b30b87908030a0424224aacd75747125186624ada9b`;
const PACKAGING_SNAPSHOT = '20261006T000000Z';
const ZLIB1G_VERSION = '1:1.3.dfsg-3.1ubuntu2.3';
const ZLIB1G_SHA256 =
  '376249c8de139568221dbb242318cc8cb8f02299e3a62b7432948e1754fbddf9';
const ZLIB1G_DEV_SHA256 =
  '419902a649e1078f24596cdf31ced9c839519828790f59888056fcdcd58e8a28';
const IMAGE_ID = /^sha256:[a-f0-9]{64}$/u;
const IMAGE_REFERENCE = /^(ghcr[.]io\/routesphere-global\/bonvoyage-oci-builder)@sha256:([a-f0-9]{64})$/u;
const RECEIPT_CLASSIFICATION =
  'routesphere-bonvoyage-oss-oci-builder-image-verification';

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

function readJson(filePath, label) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
}

function validateRelativePath(value, label) {
  requireCondition(typeof value === 'string' && value.length > 0 &&
    !value.includes('\\') && !value.includes('\0') && !path.posix.isAbsolute(value) &&
    path.posix.normalize(value) === value && !value.startsWith('./') &&
    !value.split('/').some((part) => part === '' || part === '..'),
  `${label} must be a normalized POSIX-relative path`);
}

function validateContract(contract) {
  exactKeys(contract, [
    'schema_version', 'classification', 'state', 'image', 'build', 'runtime',
    'remediation', 'registry', 'authority',
  ], 'contract');
  requireCondition(contract.schema_version === 1 &&
    contract.classification === CLASSIFICATION &&
    [LOCAL_STATE, PUBLIC_STATE].includes(contract.state),
  'unsupported OCI builder-image contract');
  const image = object(contract.image, 'contract.image');
  exactKeys(image, [
    'dockerfile', 'target', 'platform', 'ubuntu_base', 'foundation_reference',
    'packaging_snapshot',
    'entrypoint_source', 'entrypoint', 'default_user', 'working_directory',
  ], 'contract.image');
  requireCondition(image.dockerfile === 'deploy/docker/bonvoyage/Dockerfile' &&
    image.target === 'oss-oci-builder' && image.platform === 'linux/amd64' &&
    /^ubuntu:24[.]04@sha256:[a-f0-9]{64}$/u.test(image.ubuntu_base) &&
    image.foundation_reference === FOUNDATION_REFERENCE &&
    image.packaging_snapshot === PACKAGING_SNAPSHOT &&
    image.entrypoint_source === 'scripts/oss-oci-builder-entrypoint.py' &&
    image.entrypoint === ENTRYPOINT && image.default_user === '65532:65532' &&
    image.working_directory === '/workspace', 'unexpected OCI builder identity');
  const remediation = object(contract.remediation, 'contract.remediation');
  exactKeys(remediation, [
    'zlib1g_version', 'zlib1g_sha256', 'zlib1g_dev_sha256',
  ], 'contract.remediation');
  requireCondition(remediation.zlib1g_version === ZLIB1G_VERSION &&
    remediation.zlib1g_sha256 === ZLIB1G_SHA256 &&
    remediation.zlib1g_dev_sha256 === ZLIB1G_DEV_SHA256,
  'unexpected OCI builder remediation identity');
  const build = object(contract.build, 'contract.build');
  exactKeys(build, [
    'source_compiled_at_runtime', 'source_or_binary_embedded', 'build_type',
    'compiled_tests_required', 'output', 'manifest_count', 'layer_count',
    'dependency_prefixes',
  ], 'contract.build');
  requireCondition(build.source_compiled_at_runtime === true &&
    build.source_or_binary_embedded === false && build.build_type === 'RelWithDebInfo' &&
    build.compiled_tests_required === true &&
    build.output === 'deterministic-oci-image-layout-tar' &&
    build.manifest_count === 1 && build.layer_count === 1 &&
    JSON.stringify(build.dependency_prefixes) === JSON.stringify([
      '/opt/abseil', '/opt/c-ares', '/opt/libjwt', '/opt/llhttp', '/opt/nghttp2',
      '/opt/re2', '/opt/seastar',
    ]), 'unexpected OCI builder policy');
  const runtime = object(contract.runtime, 'contract.runtime');
  exactKeys(runtime, [
    'network', 'read_only_root', 'capabilities', 'no_new_privileges', 'run_as_caller',
    'source_mount', 'source_mount_read_only', 'work_mount', 'output_mount', 'tmp_mount',
    'tmp_noexec', 'required_environment',
  ], 'contract.runtime');
  requireCondition(runtime.network === 'none' && runtime.read_only_root === true &&
    JSON.stringify(runtime.capabilities) === '[]' && runtime.no_new_privileges === true &&
    runtime.run_as_caller === true && runtime.source_mount === '/workspace/source' &&
    runtime.source_mount_read_only === true && runtime.work_mount === '/workspace/work' &&
    runtime.output_mount === '/workspace/output' && runtime.tmp_mount === '/tmp' &&
    runtime.tmp_noexec === true && JSON.stringify(runtime.required_environment) ===
    JSON.stringify(['BONVOYAGE_BUILDER_ID', 'BONVOYAGE_BUILDER_IMAGE',
      'BONVOYAGE_SOURCE_COMMIT', 'BONVOYAGE_SOURCE_TAG']),
  'unexpected OCI builder runtime boundary');
  const registry = object(contract.registry, 'contract.registry');
  exactKeys(registry, [
    'repository', 'reference', 'external_verification_receipt', 'anonymous_pull_verified',
  ], 'contract.registry');
  requireCondition(registry.repository === REPOSITORY,
    'unexpected OCI builder registry repository');
  const publicVerified = contract.state === PUBLIC_STATE;
  if (publicVerified) {
    requireCondition(IMAGE_REFERENCE.test(registry.reference ?? '') &&
      registry.reference.startsWith(`${REPOSITORY}@sha256:`) &&
      registry.anonymous_pull_verified === true,
    'public OCI builder requires an immutable anonymously verified registry identity');
    validateRelativePath(registry.external_verification_receipt,
      'contract.registry.external_verification_receipt');
  } else {
    requireCondition(registry.reference === null &&
      registry.external_verification_receipt === null &&
      registry.anonymous_pull_verified === false,
    'unpublished OCI builder must not assert registry identity');
  }
  const authority = object(contract.authority, 'contract.authority');
  exactKeys(authority, [
    'release_admitted', 'publishable', 'package_uploaded', 'container_uploaded',
    'signature_created', 'provenance_created',
  ], 'contract.authority');
  requireCondition(Object.values(authority)
    .every((value) => value === false),
  'OCI builder must not grant release or publication authority');
  return {publicVerified};
}

function validateVerificationReceipt(contract, repositoryRoot) {
  if (contract.state !== PUBLIC_STATE) return null;
  const receiptPath = path.resolve(repositoryRoot,
    contract.registry.external_verification_receipt);
  const receipt = object(readJson(receiptPath, 'OCI builder-image verification receipt'),
    'OCI builder-image verification receipt');
  exactKeys(receipt, [
    'schema_version', 'classification', 'repository', 'reference', 'digest', 'platform',
    'registry', 'verified_at', 'verification_methods', 'release_admitted', 'publishable',
  ], 'OCI builder-image verification receipt');
  const match = IMAGE_REFERENCE.exec(contract.registry.reference);
  requireCondition(receipt.schema_version === 1 &&
    receipt.classification === RECEIPT_CLASSIFICATION &&
    receipt.repository === REPOSITORY && receipt.reference === contract.registry.reference &&
    receipt.digest === match[2] && receipt.platform === contract.image.platform &&
    receipt.registry === 'ghcr.io' && Number.isFinite(Date.parse(receipt.verified_at)) &&
    JSON.stringify(receipt.verification_methods) === JSON.stringify([
      'registry-manifest', 'anonymous-pull', 'local-image-inspect',
    ]) && receipt.release_admitted === false && receipt.publishable === false,
  'OCI builder-image verification receipt does not satisfy the public foundation contract');
  return {path: contract.registry.external_verification_receipt};
}

function validateDockerfile(contract, source) {
  requireCondition(source.includes(`ARG UBUNTU_IMAGE=${contract.image.ubuntu_base}`),
    'Dockerfile Ubuntu base does not match OCI builder contract');
  requireCondition(source.includes(
    `ARG OSS_OCI_BUILDER_FOUNDATION=${contract.image.foundation_reference}`),
  'Dockerfile OCI builder foundation does not match the contract');
  const startMarker = 'FROM ${OSS_OCI_BUILDER_FOUNDATION} AS oss-oci-builder';
  const endMarker = 'FROM scratch AS runtime';
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  requireCondition(start >= 0 && end > start, 'bounded oss-oci-builder stage required');
  const stage = source.slice(start, end);
  for (const marker of [
    `ADD --checksum=sha256:${contract.remediation.zlib1g_sha256}`,
    `ADD --checksum=sha256:${contract.remediation.zlib1g_dev_sha256}`,
    'zlib1g_1.3.dfsg-3.1ubuntu2.3_amd64.deb',
    'zlib1g-dev_1.3.dfsg-3.1ubuntu2.3_amd64.deb',
    'dpkg -i /tmp/zlib1g.deb /tmp/zlib1g-dev.deb',
    `"${contract.remediation.zlib1g_version}"`,
    'test -z "$(dpkg --audit)"',
    'scripts/build-oss-oci.py', 'scripts/build-runtime-package-index.py',
    contract.image.entrypoint_source, 'packaging/release/oci/oss-oci-image-contract.json',
    `USER ${contract.image.default_user}`, `WORKDIR ${contract.image.working_directory}`,
    `ENTRYPOINT ["${contract.image.entrypoint}"]`,
    'io.routesphere.bonvoyage.role="oss-oci-builder"',
    `io.routesphere.bonvoyage.ubuntu-snapshot="${contract.image.packaging_snapshot}"`,
    `io.routesphere.bonvoyage.zlib1g-version="${contract.remediation.zlib1g_version}"`,
    'io.routesphere.bonvoyage.release-authority="false"',
  ]) requireCondition(stage.includes(marker), `OCI builder stage is missing ${marker}`);
  requireCondition(!stage.includes('apt-get'),
    'OCI builder remediation must not depend on a live package index');
  for (const forbidden of [
    /COPY\s+(?:--[^\s]+\s+)*dataplane\//u,
    /COPY\s+(?:--[^\s]+\s+)*api\//u,
    /COPY\s+--from=bonvoyage-build/u,
    /\b(?:COPY|cp)\b[^\n]*bonvoyage-dataplane/u,
    /\b(?:curl|wget)\b/u,
  ]) requireCondition(!forbidden.test(stage),
    `OCI builder stage embeds forbidden input ${forbidden}`);
}

function validateEntrypoint(contract, source) {
  for (const marker of [
    'git", "-c", f"safe.directory={root}"', 'status", "--porcelain=v1"',
    'refs/tags/', 'substantive reviewed public LICENSE required', 'ctest',
    'compiled_tests_passed', 'build-runtime-package-index.py', 'build-oss-oci.py',
    'release_admitted": False', 'publishable": False',
  ]) requireCondition(source.includes(marker), `OCI entrypoint is missing ${marker}`);
  for (const name of contract.runtime.required_environment) {
    requireCondition(source.includes(`"${name}"`),
      `OCI entrypoint does not require ${name}`);
  }
  for (const forbidden of [
    /^import\s+(?:requests|socket|urllib)/mu,
    /\b(?:curl|wget|docker\s+push|gh\s+release|cosign\s+sign)\b/iu,
    /safe[.]directory=\*/u,
  ]) requireCondition(!forbidden.test(source),
    `OCI entrypoint contains forbidden network or authority path ${forbidden}`);
}

function validateWorkflow(contract, workflowSource) {
  let workflow;
  try {
    workflow = object(yaml.load(workflowSource), 'hosted OCI workflow');
  } catch (error) {
    fail(`hosted OCI workflow is not valid YAML: ${error.message}`);
  }
  for (const name of ['build-a', 'build-b']) {
    const job = object(workflow.jobs?.[name], `${name} job`);
    const runSource = job.steps.filter((step) => typeof step.run === 'string')
      .map((step) => step.run).join('\n');
    const suffix = name === 'build-a' ? 'a' : 'b';
    for (const marker of [
      'docker run --rm --network none --read-only', '--cap-drop ALL',
      '--security-opt no-new-privileges', '--tmpfs /tmp:rw,nosuid,nodev,noexec',
      `source=$RUNNER_TEMP/oss-oci-work-${suffix},target=/workspace/work`,
      'target=/workspace/source,readonly', 'target=/workspace/output',
      '--env BONVOYAGE_BUILDER_IMAGE=',
    ]) requireCondition(runSource.includes(marker),
      `${name} is missing OCI runtime boundary ${marker}`);
  }
  requireCondition(!workflowSource.includes('docker push') &&
    !workflowSource.includes('packages: write') && !workflowSource.includes('id-token: write'),
  'hosted OCI candidate must not publish or mint identity');
}

function localObservation(contract, inspection) {
  requireCondition(Array.isArray(inspection) && inspection.length === 1,
    'exactly one local Docker image inspection is required');
  const record = object(inspection[0], 'Docker image inspection');
  const config = object(record.Config, 'Docker image Config');
  const labels = object(config.Labels, 'Docker image labels');
  requireCondition(record.Os === 'linux' && record.Architecture === 'amd64' &&
    IMAGE_ID.test(record.Id) && JSON.stringify(config.Entrypoint) ===
    JSON.stringify([ENTRYPOINT]) && config.User === contract.image.default_user &&
    config.WorkingDir === contract.image.working_directory &&
    labels['io.routesphere.bonvoyage.role'] === 'oss-oci-builder' &&
    labels['io.routesphere.bonvoyage.ubuntu-snapshot'] ===
    contract.image.packaging_snapshot &&
    labels['io.routesphere.bonvoyage.zlib1g-version'] ===
      contract.remediation.zlib1g_version &&
    labels['io.routesphere.bonvoyage.release-authority'] === 'false',
  'local image inspection does not satisfy the OCI builder contract');
  return {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-oci-builder-image-local-observation',
    outcome: 'local-image-observed',
    image_id: record.Id,
    platform: contract.image.platform,
    target: contract.image.target,
    externally_resolved: false,
    registry_reference_verified: false,
    release_admitted: false,
    publishable: false,
  };
}

export function verifyOciBuilderImage(contractPath, dockerfilePath, entrypointPath,
  workflowPath, options = {}) {
  const contract = object(readJson(contractPath, 'OCI builder-image contract'),
    'OCI builder-image contract');
  const state = validateContract(contract);
  validateDockerfile(contract, fs.readFileSync(dockerfilePath, 'utf8'));
  validateEntrypoint(contract, fs.readFileSync(entrypointPath, 'utf8'));
  const workflowSource = fs.readFileSync(workflowPath, 'utf8');
  validateWorkflow(contract, workflowSource);
  const repositoryRoot = path.resolve(path.dirname(contractPath), '../../..');
  const activeWorkflowPath = path.join(repositoryRoot,
    '.github/workflows/oss-oci-reproducibility.yml');
  if (state.publicVerified) {
    requireCondition(fs.existsSync(activeWorkflowPath) &&
      fs.readFileSync(activeWorkflowPath, 'utf8') === workflowSource,
    'public OCI builder foundation requires the exact reviewed hosted workflow');
  } else {
    requireCondition(!fs.existsSync(activeWorkflowPath),
      'unpublished OCI builder foundation must not activate the hosted workflow');
  }
  const verificationReceipt = validateVerificationReceipt(contract, repositoryRoot);
  const result = {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-oci-builder-image-contract-result',
    outcome: state.publicVerified ? 'public-foundation-accepted' : 'local-foundation-accepted',
    state: contract.state,
    registry_reference_verified: state.publicVerified,
    verification_receipt: verificationReceipt,
    hosted_execution_qualified: false,
    release_admitted: false,
    publishable: false,
  };
  if (options.imageInspection !== undefined) {
    result.local_image = localObservation(contract,
      readJson(options.imageInspection, 'Docker image inspection'));
  }
  return {contract, result};
}

function parseArguments(argv) {
  const options = {};
  const names = {'--contract': 'contract', '--dockerfile': 'dockerfile',
    '--entrypoint': 'entrypoint', '--workflow': 'workflow',
    '--image-inspection': 'imageInspection'};
  for (let index = 0; index < argv.length; index += 1) {
    const name = names[argv[index]];
    requireCondition(name !== undefined && index + 1 < argv.length,
      `unknown or incomplete argument ${argv[index]}`);
    options[name] = argv[index + 1];
    index += 1;
  }
  for (const name of ['contract', 'dockerfile', 'entrypoint', 'workflow']) {
    requireCondition(typeof options[name] === 'string', `--${name} is required`);
  }
  return options;
}

if (process.argv[1] && path.resolve(process.argv[1]) ===
    path.resolve(fileURLToPath(import.meta.url))) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const {result} = verifyOciBuilderImage(
      options.contract, options.dockerfile, options.entrypoint, options.workflow, options,
    );
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`OSS OCI builder-image verification rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}

export {localObservation};
