#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

const CLASSIFICATION = 'routesphere-bonvoyage-oss-oci-builder-image-contract';
const STATE = 'local-foundation-unpublished';
const ENTRYPOINT = '/usr/local/bin/bonvoyage-oss-oci-builder';
const IMAGE_ID = /^sha256:[a-f0-9]{64}$/u;

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

function validateContract(contract) {
  exactKeys(contract, [
    'schema_version', 'classification', 'state', 'image', 'build', 'runtime',
    'registry', 'authority',
  ], 'contract');
  requireCondition(contract.schema_version === 1 &&
    contract.classification === CLASSIFICATION && contract.state === STATE,
  'unsupported or activated OCI builder-image contract');
  const image = object(contract.image, 'contract.image');
  requireCondition(image.dockerfile === 'deploy/docker/bonvoyage/Dockerfile' &&
    image.target === 'oss-oci-builder' && image.platform === 'linux/amd64' &&
    /^ubuntu:24[.]04@sha256:[a-f0-9]{64}$/u.test(image.ubuntu_base) &&
    image.packaging_snapshot === '20261006T000000Z' &&
    image.entrypoint_source === 'scripts/oss-oci-builder-entrypoint.py' &&
    image.entrypoint === ENTRYPOINT && image.default_user === '65532:65532' &&
    image.working_directory === '/workspace', 'unexpected OCI builder identity');
  const build = object(contract.build, 'contract.build');
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
  requireCondition(registry.repository === 'ghcr.io/routesphere-global/bonvoyage-oci-builder' &&
    registry.reference === null && registry.external_verification_receipt === null &&
    registry.anonymous_pull_verified === false,
  'unpublished OCI builder must not assert registry identity');
  requireCondition(Object.values(object(contract.authority, 'contract.authority'))
    .every((value) => value === false),
  'OCI builder must not grant release or publication authority');
}

function validateDockerfile(contract, source) {
  requireCondition(source.includes(`ARG UBUNTU_IMAGE=${contract.image.ubuntu_base}`),
    'Dockerfile Ubuntu base does not match OCI builder contract');
  const startMarker = 'FROM oss-deb-builder AS oss-oci-builder';
  const endMarker = 'FROM scratch AS runtime';
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  requireCondition(start >= 0 && end > start, 'bounded oss-oci-builder stage required');
  const stage = source.slice(start, end);
  for (const marker of [
    'scripts/build-oss-oci.py', 'scripts/build-runtime-package-index.py',
    contract.image.entrypoint_source, 'packaging/release/oci/oss-oci-image-contract.json',
    `USER ${contract.image.default_user}`, `WORKDIR ${contract.image.working_directory}`,
    `ENTRYPOINT ["${contract.image.entrypoint}"]`,
    'io.routesphere.bonvoyage.role="oss-oci-builder"',
    'io.routesphere.bonvoyage.release-authority="false"',
  ]) requireCondition(stage.includes(marker), `OCI builder stage is missing ${marker}`);
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
  options = {}) {
  const contract = object(readJson(contractPath, 'OCI builder-image contract'),
    'OCI builder-image contract');
  validateContract(contract);
  validateDockerfile(contract, fs.readFileSync(dockerfilePath, 'utf8'));
  validateEntrypoint(contract, fs.readFileSync(entrypointPath, 'utf8'));
  const result = {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-oci-builder-image-contract-result',
    outcome: 'local-foundation-accepted',
    state: contract.state,
    registry_reference_verified: false,
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
    '--entrypoint': 'entrypoint', '--image-inspection': 'imageInspection'};
  for (let index = 0; index < argv.length; index += 1) {
    const name = names[argv[index]];
    requireCondition(name !== undefined && index + 1 < argv.length,
      `unknown or incomplete argument ${argv[index]}`);
    options[name] = argv[index + 1];
    index += 1;
  }
  for (const name of ['contract', 'dockerfile', 'entrypoint']) {
    requireCondition(typeof options[name] === 'string', `--${name} is required`);
  }
  return options;
}

if (process.argv[1] && path.resolve(process.argv[1]) ===
    path.resolve(fileURLToPath(import.meta.url))) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const {result} = verifyOciBuilderImage(
      options.contract, options.dockerfile, options.entrypoint, options,
    );
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`OSS OCI builder-image verification rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}

export {localObservation};
