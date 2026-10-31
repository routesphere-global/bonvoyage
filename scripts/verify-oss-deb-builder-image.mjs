#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

import yaml from 'js-yaml';

import {verifyHostedBuildContract} from './verify-oss-deb-hosted-build.mjs';

const CLASSIFICATION = 'routesphere-bonvoyage-oss-deb-builder-image-contract';
const OBSERVATION_CLASSIFICATION =
  'routesphere-bonvoyage-oss-deb-builder-image-local-observation';
const LOCAL_STATE = 'local-foundation-unpublished';
const PUBLIC_STATE = 'public-foundation-verified';
const REPOSITORY = 'ghcr.io/routesphere-global/bonvoyage-debian-builder';
const ENTRYPOINT = '/usr/local/bin/bonvoyage-oss-deb-builder';
const FOUNDATION_REFERENCE =
  `${REPOSITORY}@sha256:f32465ff914634bcb5bbb2ff9271dd1ba0cbb8838be0ab26c696e64d2a17a225`;
const PACKAGING_SNAPSHOT = '20261006T000000Z';
const ZLIB1G_VERSION = '1:1.3.dfsg-3.1ubuntu2.3';
const ZLIB1G_SHA256 =
  '376249c8de139568221dbb242318cc8cb8f02299e3a62b7432948e1754fbddf9';
const ZLIB1G_DEV_SHA256 =
  '419902a649e1078f24596cdf31ced9c839519828790f59888056fcdcd58e8a28';
const IMAGE_ID = /^sha256:[a-f0-9]{64}$/u;
const IMAGE_REFERENCE = /^(ghcr[.]io\/routesphere-global\/bonvoyage-debian-builder)@sha256:([a-f0-9]{64})$/u;
const RECEIPT_CLASSIFICATION =
  'routesphere-bonvoyage-oss-deb-builder-image-verification';

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

function exactKeys(value, expected, label) {
  const actual = Object.keys(requireObject(value, label)).sort();
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
  requireCondition(contract.schema_version === 1 && contract.classification === CLASSIFICATION &&
    [LOCAL_STATE, PUBLIC_STATE].includes(contract.state),
  'unsupported builder-image contract');

  exactKeys(contract.image, [
    'dockerfile', 'target', 'platform', 'ubuntu_base', 'foundation_reference',
    'packaging_snapshot',
    'entrypoint_source', 'entrypoint', 'default_user', 'working_directory',
  ], 'contract.image');
  validateRelativePath(contract.image.dockerfile, 'contract.image.dockerfile');
  validateRelativePath(contract.image.entrypoint_source, 'contract.image.entrypoint_source');
  requireCondition(contract.image.dockerfile === 'deploy/docker/bonvoyage/Dockerfile' &&
    contract.image.target === 'oss-deb-builder' && contract.image.platform === 'linux/amd64' &&
    /^ubuntu:24[.]04@sha256:[a-f0-9]{64}$/u.test(contract.image.ubuntu_base) &&
    contract.image.foundation_reference === FOUNDATION_REFERENCE &&
    contract.image.packaging_snapshot === PACKAGING_SNAPSHOT &&
    contract.image.entrypoint_source === 'scripts/oss-deb-builder-entrypoint.py' &&
    contract.image.entrypoint === ENTRYPOINT && contract.image.default_user === '65532:65532' &&
    contract.image.working_directory === '/workspace', 'unexpected builder image identity');

  exactKeys(contract.remediation, [
    'zlib1g_version', 'zlib1g_sha256', 'zlib1g_dev_sha256',
  ], 'contract.remediation');
  requireCondition(contract.remediation.zlib1g_version === ZLIB1G_VERSION &&
    contract.remediation.zlib1g_sha256 === ZLIB1G_SHA256 &&
    contract.remediation.zlib1g_dev_sha256 === ZLIB1G_DEV_SHA256,
  'unexpected builder remediation identity');

  exactKeys(contract.build, [
    'source_compiled_at_runtime', 'source_or_binary_embedded', 'build_type',
    'compiled_tests_required', 'package_revision', 'maintainer', 'dependency_prefixes',
  ], 'contract.build');
  requireCondition(contract.build.source_compiled_at_runtime === true &&
    contract.build.source_or_binary_embedded === false &&
    contract.build.build_type === 'RelWithDebInfo' &&
    contract.build.compiled_tests_required === true && contract.build.package_revision === 1 &&
    contract.build.maintainer === 'RouteSphere Release <release@routesphere.global>' &&
    JSON.stringify(contract.build.dependency_prefixes) === JSON.stringify([
      '/opt/abseil', '/opt/c-ares', '/opt/libjwt', '/opt/llhttp', '/opt/nghttp2',
      '/opt/re2', '/opt/seastar',
    ]), 'unexpected builder compilation policy');

  exactKeys(contract.runtime, [
    'network', 'read_only_root', 'capabilities', 'no_new_privileges', 'run_as_caller',
    'source_mount', 'source_mount_read_only', 'work_mount', 'output_mount', 'tmp_mount',
    'tmp_noexec', 'required_environment',
  ], 'contract.runtime');
  requireCondition(contract.runtime.network === 'none' &&
    contract.runtime.read_only_root === true &&
    JSON.stringify(contract.runtime.capabilities) === '[]' &&
    contract.runtime.no_new_privileges === true && contract.runtime.run_as_caller === true &&
    contract.runtime.source_mount === '/workspace/source' &&
    contract.runtime.source_mount_read_only === true &&
    contract.runtime.work_mount === '/workspace/work' &&
    contract.runtime.output_mount === '/workspace/output' &&
    contract.runtime.tmp_mount === '/tmp' && contract.runtime.tmp_noexec === true &&
    JSON.stringify(contract.runtime.required_environment) === JSON.stringify([
      'BONVOYAGE_BUILDER_ID', 'BONVOYAGE_BUILDER_IMAGE',
      'BONVOYAGE_SOURCE_COMMIT', 'BONVOYAGE_SOURCE_TAG',
    ]), 'unexpected builder runtime boundary');

  exactKeys(contract.registry, [
    'repository', 'reference', 'external_verification_receipt', 'anonymous_pull_verified',
  ], 'contract.registry');
  requireCondition(contract.registry.repository === REPOSITORY,
    'unexpected builder registry repository');
  const publicVerified = contract.state === PUBLIC_STATE;
  if (publicVerified) {
    requireCondition(IMAGE_REFERENCE.test(contract.registry.reference ?? '') &&
      contract.registry.reference.startsWith(`${REPOSITORY}@sha256:`) &&
      contract.registry.anonymous_pull_verified === true,
    'public builder contract requires an immutable anonymously verified registry identity');
    validateRelativePath(contract.registry.external_verification_receipt,
      'contract.registry.external_verification_receipt');
  } else {
    requireCondition(contract.registry.reference === null &&
      contract.registry.external_verification_receipt === null &&
      contract.registry.anonymous_pull_verified === false,
    'unpublished builder contract must not assert registry identity');
  }

  exactKeys(contract.authority, [
    'release_admitted', 'publishable', 'package_uploaded', 'container_uploaded',
    'signature_created', 'provenance_created',
  ], 'contract.authority');
  requireCondition(Object.values(contract.authority).every((value) => value === false),
    'builder image must not grant release or publication authority');
  return {publicVerified};
}

function validateVerificationReceipt(contract, repositoryRoot) {
  if (contract.state !== PUBLIC_STATE) return null;
  const receiptPath = path.resolve(repositoryRoot,
    contract.registry.external_verification_receipt);
  const receipt = requireObject(readJson(receiptPath,
    'builder-image verification receipt'), 'builder-image verification receipt');
  exactKeys(receipt, [
    'schema_version', 'classification', 'repository', 'reference', 'digest', 'platform',
    'registry', 'verified_at', 'verification_methods', 'release_admitted', 'publishable',
  ], 'builder-image verification receipt');
  const match = IMAGE_REFERENCE.exec(contract.registry.reference);
  requireCondition(receipt.schema_version === 1 &&
    receipt.classification === RECEIPT_CLASSIFICATION &&
    receipt.repository === REPOSITORY && receipt.reference === contract.registry.reference &&
    receipt.digest === match[2] && receipt.platform === contract.image.platform &&
    receipt.registry === 'ghcr.io' && Number.isFinite(Date.parse(receipt.verified_at)) &&
    JSON.stringify(receipt.verification_methods) === JSON.stringify([
      'registry-manifest', 'anonymous-pull', 'local-image-inspect',
    ]) && receipt.release_admitted === false && receipt.publishable === false,
  'builder-image verification receipt does not satisfy the public foundation contract');
  return {path: contract.registry.external_verification_receipt};
}

function validateDockerfile(contract, source) {
  requireCondition(source.includes(`ARG UBUNTU_IMAGE=${contract.image.ubuntu_base}`),
    'Dockerfile Ubuntu base does not match the builder contract');
  requireCondition(source.includes(
    `ARG OSS_DEB_BUILDER_FOUNDATION=${contract.image.foundation_reference}`),
  'Dockerfile Debian builder foundation does not match the contract');
  const startMarker = 'FROM ${OSS_DEB_BUILDER_FOUNDATION} AS oss-deb-builder';
  const start = source.indexOf(startMarker);
  requireCondition(start >= 0, 'bounded oss-deb-builder stage required');
  const remaining = source.slice(start + startMarker.length);
  const nextStage = remaining.search(/^FROM\s+/mu);
  requireCondition(nextStage >= 0, 'bounded oss-deb-builder stage required');
  const end = start + startMarker.length + nextStage;
  const stage = source.slice(start, end);
  for (const marker of [
    `ADD --checksum=sha256:${contract.remediation.zlib1g_sha256}`,
    `ADD --checksum=sha256:${contract.remediation.zlib1g_dev_sha256}`,
    'zlib1g_1.3.dfsg-3.1ubuntu2.3_amd64.deb',
    'zlib1g-dev_1.3.dfsg-3.1ubuntu2.3_amd64.deb',
    'dpkg-deb --field /tmp/zlib1g.deb Package',
    'dpkg-deb --field /tmp/zlib1g-dev.deb Package',
    'dpkg -i /tmp/zlib1g.deb /tmp/zlib1g-dev.deb',
    `"${contract.remediation.zlib1g_version}"`,
    'test -z "$(dpkg --audit)"',
    `io.routesphere.bonvoyage.ubuntu-snapshot="${contract.image.packaging_snapshot}"`,
    `io.routesphere.bonvoyage.zlib1g-version="${contract.remediation.zlib1g_version}"`,
  ]) requireCondition(stage.includes(marker), `builder remediation is missing ${marker}`);
  requireCondition(!stage.includes('apt-get') &&
    stage.includes(`COPY ${contract.image.entrypoint_source}`) &&
    stage.includes(contract.image.entrypoint) &&
    stage.includes(`USER ${contract.image.default_user}`) &&
    stage.includes(`WORKDIR ${contract.image.working_directory}`) &&
    stage.includes(`ENTRYPOINT ["${contract.image.entrypoint}"]`) &&
    stage.includes('io.routesphere.bonvoyage.release-authority="false"'),
  'builder image entrypoint, user, workdir or authority label changed');
  for (const forbidden of [
    /COPY\s+(?:--[^\s]+\s+)*dataplane\//u,
    /COPY\s+(?:--[^\s]+\s+)*api\//u,
    /COPY\s+(?:--[^\s]+\s+)*third_party\//u,
    /COPY\s+--from=/u,
    /COPY\s+--from=bonvoyage-build/u,
    /\/opt\/bonvoyage/u,
    /\b(?:curl|wget)\b/u,
  ]) requireCondition(!forbidden.test(stage), `builder stage embeds forbidden input ${forbidden}`);
}

function validateEntrypoint(contract, source) {
  for (const marker of [
    'git", "-c", f"safe.directory={root}"',
    '"GIT_CONFIG_KEY_0": "safe.directory"',
    '"GIT_CONFIG_VALUE_0": str(SOURCE_ROOT)',
    'status", "--porcelain=v1"', 'refs/tags/',
    'reviewed public LICENSE file required', 'ctest', 'compiled_tests_passed',
    'runtime_identity',
    'capture-oss-deb-toolchain.py', 'create-oss-deb-input.py', 'build-oss-deb.py',
    'release_admitted": False', 'publishable": False',
  ]) requireCondition(source.includes(marker), `builder entrypoint is missing ${marker}`);
  for (const name of contract.runtime.required_environment) {
    requireCondition(source.includes(`"${name}"`), `builder entrypoint does not require ${name}`);
  }
  for (const forbidden of [
    /^import\s+(?:requests|socket|urllib)/mu,
    /\b(?:curl|wget|docker\s+push|gh\s+release|cosign\s+sign)\b/iu,
    /safe[.]directory=\*/u,
  ]) requireCondition(!forbidden.test(source), `builder entrypoint contains forbidden network or authority path ${forbidden}`);
}

function validateWorkflow(contract, workflowSource) {
  let workflow;
  try {
    workflow = requireObject(yaml.load(workflowSource), 'hosted workflow');
  } catch (error) {
    fail(`hosted workflow is not valid YAML: ${error.message}`);
  }
  for (const name of ['build-a', 'build-b']) {
    const job = requireObject(workflow.jobs?.[name], `${name} job`);
    const runSource = job.steps.filter((step) => typeof step.run === 'string')
      .map((step) => step.run).join('\n');
    const suffix = name === 'build-a' ? 'a' : 'b';
    for (const marker of [
      'docker run --rm --network none --read-only', '--cap-drop ALL',
      '--security-opt no-new-privileges', '--tmpfs /tmp:rw,nosuid,nodev,noexec',
      `source=$RUNNER_TEMP/oss-deb-work-${suffix},target=/workspace/work`,
      'target=/workspace/source,readonly', 'target=/workspace/output',
      '--env BONVOYAGE_BUILDER_IMAGE=',
    ]) requireCondition(runSource.includes(marker), `${name} is missing runtime boundary ${marker}`);
  }
  requireCondition(!workflowSource.includes('docker push') &&
    !workflowSource.includes('packages: write') &&
    !workflowSource.includes('contents: write') &&
    !workflowSource.includes('pull-requests: write') &&
    !workflowSource.includes('gh release') &&
    !workflowSource.includes('cosign sign'),
  'hosted candidate must not publish, sign or grant release authority');
}

function localObservation(contract, inspection) {
  const records = inspection;
  requireCondition(Array.isArray(records) && records.length === 1,
    'exactly one local Docker image inspection is required');
  const record = requireObject(records[0], 'Docker image inspection');
  const config = requireObject(record.Config, 'Docker image Config');
  const labels = requireObject(config.Labels, 'Docker image labels');
  requireCondition(record.Os === 'linux' && record.Architecture === 'amd64' &&
    IMAGE_ID.test(record.Id) && JSON.stringify(config.Entrypoint) === JSON.stringify([ENTRYPOINT]) &&
    config.User === contract.image.default_user &&
    config.WorkingDir === contract.image.working_directory &&
    labels['io.routesphere.bonvoyage.role'] === 'oss-deb-builder' &&
    labels['io.routesphere.bonvoyage.ubuntu-snapshot'] === contract.image.packaging_snapshot &&
    labels['io.routesphere.bonvoyage.zlib1g-version'] ===
      contract.remediation.zlib1g_version &&
    labels['io.routesphere.bonvoyage.release-authority'] === 'false',
  'local image inspection does not satisfy the builder contract');
  return {
    schema_version: 1,
    classification: OBSERVATION_CLASSIFICATION,
    outcome: 'local-image-observed',
    image_id: record.Id,
    platform: contract.image.platform,
    target: contract.image.target,
    entrypoint: contract.image.entrypoint,
    externally_resolved: false,
    registry_reference_verified: false,
    release_admitted: false,
    publishable: false,
  };
}

export function verifyBuilderImageFoundation(contractPath, dockerfilePath, entrypointPath,
  workflowPath, options = {}) {
  const repositoryRoot = path.resolve(path.dirname(contractPath), '../../..');
  const contract = requireObject(readJson(contractPath, 'builder-image contract'),
    'builder-image contract');
  const state = validateContract(contract);
  validateDockerfile(contract, fs.readFileSync(dockerfilePath, 'utf8'));
  validateEntrypoint(contract, fs.readFileSync(entrypointPath, 'utf8'));
  const workflowSource = fs.readFileSync(workflowPath, 'utf8');
  verifyHostedBuildContract(path.join(repositoryRoot,
    'packaging/release/debian/oss-deb-hosted-build-contract.json'), workflowPath);
  validateWorkflow(contract, workflowSource);
  const activeWorkflowPath = path.join(repositoryRoot,
    '.github/workflows/oss-deb-reproducibility.yml');
  if (state.publicVerified) {
    requireCondition(fs.existsSync(activeWorkflowPath) &&
      fs.readFileSync(activeWorkflowPath, 'utf8') === workflowSource,
    'public builder foundation requires the exact reviewed hosted workflow');
  } else {
    requireCondition(!fs.existsSync(activeWorkflowPath),
      'unpublished builder foundation must not activate the hosted workflow');
  }
  const verificationReceipt = validateVerificationReceipt(contract, repositoryRoot);
  const result = {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-deb-builder-image-contract-result',
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
  const names = {
    '--contract': 'contract', '--dockerfile': 'dockerfile', '--entrypoint': 'entrypoint',
    '--workflow': 'workflow', '--image-inspection': 'imageInspection',
    '--image-observation': 'imageObservation',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const name = names[argv[index]];
    requireCondition(name !== undefined && index + 1 < argv.length, `unknown or incomplete argument ${argv[index]}`);
    options[name] = argv[index + 1];
    index += 1;
  }
  for (const name of ['contract', 'dockerfile', 'entrypoint', 'workflow']) {
    requireCondition(typeof options[name] === 'string', `--${name} is required`);
  }
  return options;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const {result} = verifyBuilderImageFoundation(
      options.contract, options.dockerfile, options.entrypoint, options.workflow, options,
    );
    if (options.imageObservation !== undefined) {
      requireCondition(!fs.existsSync(options.imageObservation), 'new image observation output required');
      fs.writeFileSync(options.imageObservation, `${JSON.stringify(result.local_image, null, 2)}\n`,
        {encoding: 'utf8', mode: 0o600, flag: 'wx'});
    }
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`OSS Debian builder-image verification rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}

export {localObservation};
