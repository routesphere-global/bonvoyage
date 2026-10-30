#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

import yaml from 'js-yaml';

const CLASSIFICATION =
  'routesphere-bonvoyage-oss-builder-publication-workflow-contract';
const CHECKOUT = 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1';
const COMMIT = '^[a-f0-9]{40}$';

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
  requireCondition(execution.environment === 'builder-publication' &&
    execution.runner === 'ubuntu-24.04' && execution.timeout_minutes === 180 &&
    JSON.stringify(execution.workflow_permissions) === JSON.stringify({contents: 'read'}) &&
    JSON.stringify(execution.job_permissions) ===
      JSON.stringify({contents: 'read', packages: 'write'}) &&
    execution.checkout_action === CHECKOUT && execution.platform === 'linux/amd64' &&
    execution.dockerfile === 'deploy/docker/bonvoyage/Dockerfile' &&
    execution.minimum_zlib1g === '1:1.3.dfsg-3.1ubuntu2.3' &&
    JSON.stringify(execution.targets) === JSON.stringify([
      {name: 'oss-deb-builder',
        repository: 'ghcr.io/routesphere-global/bonvoyage-debian-builder',
        role: 'oss-deb-builder'},
      {name: 'oss-oci-builder',
        repository: 'ghcr.io/routesphere-global/bonvoyage-oci-builder',
        role: 'oss-oci-builder'},
    ]), 'builder publication execution boundary changed');
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
      MINIMUM_ZLIB1G: contract.execution.minimum_zlib1g,
    }), 'publication job boundary changed');

  const steps = job.steps;
  requireCondition(Array.isArray(steps) && steps.length === 9,
    'publication step count changed');
  const names = steps.map((step) => step.name);
  requireCondition(JSON.stringify(names) === JSON.stringify([
    'Check out protected workflow authority', 'Verify the bounded publication workflow',
    'Check out the exact reviewed builder source', 'Verify exact clean source identity',
    'Build and verify source-free builder images',
    'Authenticate only for the bounded registry upload',
    'Upload the two powerless builder images', 'Record immutable registry identities',
    'Remove registry credentials',
  ]), 'publication step order changed');
  const checkouts = steps.filter((step) => step.uses);
  requireCondition(checkouts.length === 2 && checkouts.every((step) => step.uses === CHECKOUT),
    'publication workflow may use only the pinned checkout action');
  requireCondition(JSON.stringify(checkouts[0].with) === JSON.stringify({
    'fetch-depth': 1, path: 'authority', 'persist-credentials': false,
    ref: '${{ github.sha }}',
  }) && JSON.stringify(checkouts[1].with) === JSON.stringify({
    'fetch-depth': 1, path: 'source', 'persist-credentials': false,
    ref: '${{ inputs.source_commit }}',
  }), 'publication checkout identity changed');
  const runText = steps.filter((step) => step.run).map((step) => step.run).join('\n');
  for (const required of [
    'verify-oss-builder-publication-workflow.mjs',
    'git -C source rev-parse HEAD', 'status --porcelain=v1 --untracked-files=all',
    '--platform linux/amd64 --target oss-deb-builder',
    '--platform linux/amd64 --target oss-oci-builder', '--provenance=false',
    'dpkg --compare-versions "$version" ge "$1"',
    "'oss-deb-builder'", "'oss-oci-builder'", 'docker login ghcr.io',
    'docker push "$DEB_IMAGE"', 'docker push "$OCI_IMAGE"',
    'docker image inspect --format', 'Product release authority: `false`',
    'docker logout ghcr.io || true',
  ]) requireCondition(runText.includes(required), `publication workflow is missing ${required}`);
  requireCondition(steps[5].env?.REGISTRY_TOKEN === '${{ secrets.GITHUB_TOKEN }}' &&
    steps[8].if === 'always()', 'registry credential lifetime changed');
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
