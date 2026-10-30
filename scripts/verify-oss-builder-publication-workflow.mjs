#!/usr/bin/env node

import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

import yaml from 'js-yaml';

const CLASSIFICATION =
  'routesphere-bonvoyage-oss-builder-publication-workflow-contract';
const CHECKOUT = 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1';
const SETUP_NODE = 'actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1';
const COMMIT = '^[a-f0-9]{40}$';
const RUN_SHA256 = {
  install: '9b121a2c9dfda060ff1898be64ffb3252cdf0fbc8e0e121128b9688ce1f7ef4d',
  verify_workflow: '6bfd4d9176ccb0f5697ea4c40e575da6998cd5dbcb3ac8b93e7b19f898741349',
  verify_source: '47f3183cf8d40ad07187582a513c087b78d0e289e7f1de822b150447b293135e',
  build_and_verify: 'ed3791c9af3dbe04c0aefb83a6e3078a7b817acc1607f4b9d6d433367832cdab',
  authenticate: 'bcc146e2d20ee44938f89f122d290a0ecd8ea1bd6c73b8f5bc5c6d7331824977',
  upload: '71e0ae660bb281d93a08f184c7189e8fb31030cf62e5a235b8257a1d25dfc7df',
  record: 'a1027ae046502334bc166cb77fbf4653214f9999da539119d8be10b9b30366cd',
  logout: '9cfd7d985065da07510a57c133685a3be819f5e7e6df08aea9c7389509cc7f43',
};

function fail(message) { throw new Error(message); }
function requireCondition(condition, message) { if (!condition) fail(message); }
function object(value, label) {
  requireCondition(value !== null && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  return value;
}
function exactKeys(value, expected, label) {
  const actual = Object.keys(object(value, label)).sort();
  const wanted = [...expected].sort();
  requireCondition(JSON.stringify(actual) === JSON.stringify(wanted),
    `${label} fields must be exactly [${wanted.join(', ')}]`);
}
function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function validateContract(contract) {
  exactKeys(contract, [
    'schema_version', 'classification', 'state', 'source', 'execution', 'authority',
  ], 'contract');
  requireCondition(contract.schema_version === 1 &&
    contract.classification === CLASSIFICATION &&
    contract.state === 'manual-powerless-builder-publication',
  'unsupported builder publication contract');
  requireCondition(JSON.stringify(contract.source) === JSON.stringify({
    repository: 'https://github.com/routesphere-global/bonvoyage',
    event: 'workflow_dispatch', workflow_branch: 'main', input: 'source_commit',
    commit_pattern: COMMIT,
  }), 'builder publication source boundary changed');
  const execution = object(contract.execution, 'contract.execution');
  exactKeys(execution, [
    'environment', 'runner', 'timeout_minutes', 'workflow_permissions',
    'job_permissions', 'checkout_action', 'setup_node_action', 'node_version',
    'platform', 'dockerfile', 'tag_template', 'source_free_paths', 'targets',
    'packaging_snapshot', 'zlib1g_version', 'run_sha256',
  ], 'contract.execution');
  requireCondition(execution.environment === 'builder-publication' &&
    execution.runner === 'ubuntu-24.04' && execution.timeout_minutes === 180 &&
    JSON.stringify(execution.workflow_permissions) === JSON.stringify({contents: 'read'}) &&
    JSON.stringify(execution.job_permissions) ===
      JSON.stringify({contents: 'read', packages: 'write'}) &&
    execution.checkout_action === CHECKOUT && execution.setup_node_action === SETUP_NODE &&
    execution.node_version === '22.19.0' && execution.platform === 'linux/amd64' &&
    execution.dockerfile === 'deploy/docker/bonvoyage/Dockerfile' &&
    execution.tag_template ===
      'source-${SOURCE_COMMIT}-run-${GITHUB_RUN_ID}-attempt-${GITHUB_RUN_ATTEMPT}' &&
    JSON.stringify(execution.source_free_paths) === JSON.stringify([
      '/opt/bonvoyage', '/usr/src/bonvoyage', '/workspace',
    ]) &&
    execution.packaging_snapshot === '20261006T000000Z' &&
    execution.zlib1g_version === '1:1.3.dfsg-3.1ubuntu2.3' &&
    JSON.stringify(execution.targets) === JSON.stringify([
      {name: 'oss-deb-builder',
        repository: 'ghcr.io/routesphere-global/bonvoyage-debian-builder',
        role: 'oss-deb-builder', entrypoint: '/usr/local/bin/bonvoyage-oss-deb-builder'},
      {name: 'oss-oci-builder',
        repository: 'ghcr.io/routesphere-global/bonvoyage-oci-builder',
        role: 'oss-oci-builder', entrypoint: '/usr/local/bin/bonvoyage-oss-oci-builder'},
    ]) && JSON.stringify(execution.run_sha256) === JSON.stringify(RUN_SHA256),
  'builder publication execution boundary changed');
  requireCondition(JSON.stringify(contract.authority) === JSON.stringify({
    builder_container_upload_allowed: true,
    product_artifact_signature_allowed: false,
    product_provenance_allowed: false,
    release_admitted: false,
    publishable: false,
    github_release_created: false,
    product_package_uploaded: false,
    product_container_uploaded: false,
  }), 'builder publication authority changed');
}

function validateWorkflow(contract, workflow, source) {
  exactKeys(workflow, ['name', 'on', 'permissions', 'concurrency', 'jobs'], 'workflow');
  requireCondition(workflow.name === 'OSS Builder Image Publication' &&
    JSON.stringify(workflow.on) === JSON.stringify({workflow_dispatch: {inputs: {
      source_commit: {
        description: 'Exact reviewed BonVoyage source commit to build',
        required: true, type: 'string',
      },
    }}}) && JSON.stringify(workflow.permissions) === JSON.stringify({contents: 'read'}) &&
    JSON.stringify(workflow.concurrency) === JSON.stringify({
      group: 'oss-builder-image-publication', 'cancel-in-progress': false,
    }), 'workflow trigger or global authority changed');
  exactKeys(workflow.jobs, ['publish'], 'workflow.jobs');
  const job = object(workflow.jobs.publish, 'workflow.jobs.publish');
  exactKeys(job, [
    'name', 'if', 'runs-on', 'timeout-minutes', 'environment', 'permissions', 'env', 'steps',
  ], 'workflow.jobs.publish');
  requireCondition(job.name === 'Publish powerless builder images' &&
    job.if === "github.ref == 'refs/heads/main'" &&
    job['runs-on'] === contract.execution.runner &&
    job['timeout-minutes'] === contract.execution.timeout_minutes &&
    job.environment === contract.execution.environment &&
    JSON.stringify(job.permissions) === JSON.stringify(contract.execution.job_permissions) &&
    JSON.stringify(job.env) === JSON.stringify({
      SOURCE_COMMIT: '${{ inputs.source_commit }}',
      DEB_REPOSITORY: contract.execution.targets[0].repository,
      OCI_REPOSITORY: contract.execution.targets[1].repository,
      PACKAGING_SNAPSHOT: contract.execution.packaging_snapshot,
      ZLIB1G_VERSION: contract.execution.zlib1g_version,
    }), 'publication job boundary changed');

  const steps = job.steps;
  requireCondition(Array.isArray(steps) && steps.length === 11,
    'publication step count changed');
  const names = steps.map((step) => step.name);
  requireCondition(JSON.stringify(names) === JSON.stringify([
    'Check out protected workflow authority', 'Set up verifier Node.js',
    'Install pinned verifier dependencies', 'Verify the bounded publication workflow',
    'Check out the exact reviewed builder source', 'Verify exact clean source identity',
    'Build and verify source-free builder images',
    'Authenticate only for the bounded registry upload',
    'Upload the two powerless builder images', 'Record immutable registry identities',
    'Remove registry credentials',
  ]), 'publication step order changed');
  const stepKeys = [
    ['name', 'uses', 'with'], ['name', 'uses', 'with'], ['name', 'run'],
    ['name', 'run'], ['name', 'uses', 'with'], ['name', 'run'], ['name', 'run'],
    ['name', 'env', 'run'], ['name', 'run'], ['name', 'run'], ['name', 'if', 'run'],
  ];
  steps.forEach((step, index) => exactKeys(step, stepKeys[index], `step ${index}`));
  const checkouts = [steps[0], steps[4]];
  requireCondition(checkouts.length === 2 && checkouts.every((step) => step.uses === CHECKOUT),
    'publication workflow must use only the pinned checkout action for source access');
  requireCondition(JSON.stringify(checkouts[0].with) === JSON.stringify({
    'fetch-depth': 1, path: 'authority', 'persist-credentials': false,
    ref: '${{ github.sha }}',
  }) && JSON.stringify(checkouts[1].with) === JSON.stringify({
    'fetch-depth': 1, path: 'source', 'persist-credentials': false,
    ref: '${{ inputs.source_commit }}',
  }), 'publication checkout identity changed');
  requireCondition(steps[1].uses === SETUP_NODE &&
    JSON.stringify(steps[1].with) === JSON.stringify({'node-version': '22.19.0'}),
  'publication verifier runtime changed');
  const runSteps = {
    install: steps[2], verify_workflow: steps[3], verify_source: steps[5],
    build_and_verify: steps[6], authenticate: steps[7], upload: steps[8],
    record: steps[9], logout: steps[10],
  };
  for (const [name, step] of Object.entries(runSteps)) {
    requireCondition(sha256(step.run) === RUN_SHA256[name],
      `${name} publication command changed`);
  }
  const runText = steps.filter((step) => step.run).map((step) => step.run).join('\n');
  for (const required of [
    'npm --prefix authority ci --ignore-scripts --no-audit --no-fund',
    'verify-oss-builder-publication-workflow.mjs',
    'git -C source rev-parse HEAD', 'status --porcelain=v1 --untracked-files=all',
    'attempt-${GITHUB_RUN_ATTEMPT}',
    '--platform linux/amd64 --target oss-deb-builder',
    '--platform linux/amd64 --target oss-oci-builder', '--provenance=false',
    '-f="\\${Version}"', 'zlib1g-dev)" = "$1"',
    "'oss-deb-builder'", "'oss-oci-builder'", 'docker login ghcr.io',
    "'false'", '"$PACKAGING_SNAPSHOT"', '"$ZLIB1G_VERSION"', "'65532:65532'",
    "'[\"/usr/local/bin/bonvoyage-oss-deb-builder\"]'",
    "'[\"/usr/local/bin/bonvoyage-oss-oci-builder\"]'",
    'test ! -e /opt/bonvoyage', 'test ! -e /usr/src/bonvoyage',
    'find /workspace -mindepth 1 -print -quit',
    'docker push "$DEB_IMAGE"', 'docker push "$OCI_IMAGE"',
    'docker image inspect --format', 'Product release authority: `false`',
    'docker logout ghcr.io || true',
  ]) requireCondition(runText.includes(required), `publication workflow is missing ${required}`);
  requireCondition(JSON.stringify(steps[7].env) === JSON.stringify({
    REGISTRY_TOKEN: '${{ secrets.GITHUB_TOKEN }}',
  }) && steps[10].if === 'always()', 'registry credential lifetime changed');
  const tokenReferences = source.match(/\$\{\{\s*(?:secrets[.]GITHUB_TOKEN|github[.]token)\s*\}\}/gu) ?? [];
  requireCondition(tokenReferences.length === 1 &&
    tokenReferences[0].includes('secrets.GITHUB_TOKEN'),
  'registry token must appear only in the bounded login environment');
  requireCondition(!/\b(?:pull_request|push|schedule):/u.test(source) &&
    !/id-token\s*:\s*write/u.test(source) &&
    !/contents\s*:\s*write/u.test(source) &&
    !/\b(?:gh release|cosign|npm publish|dpkg-sig|gh attestation)\b/u.test(source) &&
    !/ghcr[.]io\/routesphere-global\/bonvoyage(?:[:@\s"'])/u.test(source),
  'workflow gained an automatic trigger, release identity, or product publication authority');
}

export function verifyBuilderPublicationWorkflow({contractPath, workflowPath}) {
  const contract = object(JSON.parse(fs.readFileSync(contractPath, 'utf8')), 'contract');
  const source = fs.readFileSync(workflowPath, 'utf8');
  const workflow = object(yaml.load(source), 'workflow');
  validateContract(contract);
  validateWorkflow(contract, workflow, source);
  return {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-builder-publication-workflow-result',
    status: 'POWERLESS_BUILDER_PUBLICATION_VERIFIED',
    authority: contract.authority,
  };
}

function parseArguments(argv) {
  const result = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    requireCondition(argv[index]?.startsWith('--') && argv[index + 1] !== undefined,
      'arguments must be --name value pairs');
    result.set(argv[index].slice(2), argv[index + 1]);
  }
  return result;
}

function main(argv) {
  const values = parseArguments(argv);
  const result = verifyBuilderPublicationWorkflow({
    contractPath: values.get('contract'), workflowPath: values.get('workflow'),
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); } catch (error) {
    process.stderr.write(`builder publication workflow rejected: ${error.message}\n`);
    process.exitCode = 2;
  }
}
