#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

import yaml from 'js-yaml';

const CLASSIFICATION =
  'routesphere-bonvoyage-oss-supply-chain-producer-workflow-contract';
const REPOSITORY = 'https://github.com/routesphere-global/bonvoyage';
const REPOSITORY_SLUG = 'routesphere-global/bonvoyage';
const TAG = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const PINNED_ACTION = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[a-f0-9]{40}$/u;
const ACTIONS = Object.freeze({
  checkout: 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
  setup_node: 'actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1',
  download_artifact: 'actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333',
  upload_artifact: 'actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9',
});
const TOOLS = Object.freeze({
  syft_image:
    'anchore/syft:v1.44.0@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6',
  cyclonedx_validator_image:
    'cyclonedx/cyclonedx-cli:0.33.1@sha256:9a37575fb51fcaed3a4c62dddba091c46ffc867712e46bdb6cdf219a7e90a061',
  grype_image:
    'anchore/grype:v0.116.1@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db',
  python_image:
    'python:3.12-slim@sha256:1148dbb014615300fa7e713b2f94f550c0d1c69780c0805f84f093ceee34dd0b',
});
const VERIFY = [
  'node scripts/verify-oss-supply-chain-producer-workflow.mjs',
  '--contract packaging/release/oss-supply-chain-producer-workflow-contract.json',
  '--workflow .github/workflows/oss-supply-chain-producers.yml',
  '--github-repository "$GITHUB_REPOSITORY"',
  '--github-ref-type "$GITHUB_REF_TYPE"',
  '--github-ref-name "$GITHUB_REF_NAME"',
  '--github-ref-protected "$GITHUB_REF_PROTECTED"',
  '--github-sha "$GITHUB_SHA"',
].join(' ');
const DISCOVER = [
  'node scripts/discover-oss-release-intake-run.mjs',
  '--repository "$GITHUB_REPOSITORY"', '--tag "$GITHUB_REF_NAME"',
  '--commit "$GITHUB_SHA"', '--current-run-id "$GITHUB_RUN_ID"',
  '--github-output "$GITHUB_OUTPUT"',
].join(' ');
const PREPARE = [
  'node scripts/produce-oss-supply-chain-evidence.mjs prepare-validator',
  '--output "$RUNNER_TEMP/spdx-validator"',
].join(' ');
const PRODUCE_SBOM = [
  'node scripts/produce-oss-supply-chain-evidence.mjs sbom',
  '--candidate-root "$RUNNER_TEMP/candidate-intake"',
  '--validator-root "$RUNNER_TEMP/spdx-validator"',
  '--output "$RUNNER_TEMP/sbom-producer"', '--source-commit "$GITHUB_SHA"',
  '--source-tag "$GITHUB_REF_NAME"',
].join(' ');
const PRODUCE_VULNERABILITY = [
  'node scripts/produce-oss-supply-chain-evidence.mjs vulnerability',
  '--candidate-root "$RUNNER_TEMP/candidate-intake"',
  '--sbom-root "$RUNNER_TEMP/sbom-producer"',
  '--output "$RUNNER_TEMP/vulnerability-producer"', '--source-commit "$GITHUB_SHA"',
  '--source-tag "$GITHUB_REF_NAME"',
].join(' ');
const PULL_SBOM_IMAGES = [
  'docker pull "$SYFT_IMAGE"',
  'docker pull "$CYCLONEDX_VALIDATOR_IMAGE"',
  'docker pull "$PYTHON_IMAGE"',
  '',
].join('\n');

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
function exactKeys(value, expected, label) {
  const actual = Object.keys(object(value, label)).sort();
  const wanted = [...expected].sort();
  requireCondition(JSON.stringify(actual) === JSON.stringify(wanted),
    `${label} fields must be exactly [${wanted.join(', ')}]`);
}
function multiset(values) {
  const result = new Map();
  for (const value of values) result.set(value, (result.get(value) ?? 0) + 1);
  return [...result.entries()].sort((left, right) => left[0].localeCompare(right[0]));
}
function powerless(value, label) {
  exactKeys(value, [
    'product_artifact_signature_allowed', 'product_provenance_allowed',
    'release_admitted', 'publishable', 'github_release_created',
    'package_uploaded', 'container_uploaded',
  ], label);
  requireCondition(Object.values(value).every((item) => item === false),
    `${label} must grant no release or publication authority`);
}

function validateContract(contract) {
  exactKeys(contract, [
    'schema_version', 'classification', 'state', 'source', 'execution',
    'actions', 'tools', 'handoff', 'authority',
  ], 'contract');
  requireCondition(contract.schema_version === 1 && contract.classification === CLASSIFICATION &&
    contract.state === 'producer-foundation', 'unsupported producer contract');
  requireCondition(contract.source.repository === REPOSITORY &&
    contract.source.event === 'workflow_dispatch' && contract.source.ref_type === 'tag' &&
    contract.source.tag_pattern === TAG.source && contract.source.protected_tag_required === true &&
    contract.source.exact_commit_required === true, 'producer source boundary changed');
  requireCondition(contract.execution.environment === 'release' &&
    contract.execution.runner === 'ubuntu-24.04' &&
    JSON.stringify(contract.execution.workflow_permissions) === JSON.stringify({contents: 'read'}) &&
    JSON.stringify(contract.execution.job_permissions) === JSON.stringify({
      preflight: {contents: 'read', actions: 'read'},
      'sbom-producer': {contents: 'read', actions: 'read'},
      'vulnerability-producer': {contents: 'read', actions: 'read'},
    }) && JSON.stringify(contract.execution.jobs) === JSON.stringify({
      preflight: {timeout_minutes: 5},
      'sbom-producer': {timeout_minutes: 30},
      'vulnerability-producer': {timeout_minutes: 30},
    }) && contract.execution.artifact_retention_days === 3 &&
    contract.execution.maximum_billable_job_minutes === 65 &&
    contract.execution.manual_only === true && contract.execution.scheduled_runs === false &&
    contract.execution.self_hosted_runners === false &&
    contract.execution.cancel_in_progress === false, 'producer execution boundary changed');
  requireCondition(JSON.stringify(contract.actions) === JSON.stringify(ACTIONS) &&
    Object.values(contract.actions).every((value) => PINNED_ACTION.test(value)),
  'producer action pins changed');
  requireCondition(JSON.stringify(contract.tools) === JSON.stringify(TOOLS),
    'producer tool pins changed');
  requireCondition(JSON.stringify(contract.handoff) === JSON.stringify({
    release_workflow: '.github/workflows/release.yml',
    candidate_artifact: 'oss-release-candidate-intake',
    sbom_artifact: 'oss-release-sbom-producer-evidence',
    vulnerability_artifact: 'oss-release-vulnerability-producer-evidence',
    discovery_script: 'scripts/discover-oss-release-intake-run.mjs',
    producer_script: 'scripts/produce-oss-supply-chain-evidence.mjs',
    evidence_contract: 'packaging/release/oss-supply-chain-evidence-contract.json',
    human_review_required: true,
    review_generated_by_workflow: false,
  }), 'producer handoff boundary changed');
  powerless(contract.authority, 'contract.authority');
}

function stepsFor(job, label) {
  return array(object(job, label).steps, `${label}.steps`);
}
function usesSteps(jobs) {
  return Object.entries(jobs).flatMap(([name, job]) =>
    stepsFor(job, `jobs.${name}`).filter((step) => step.uses).map((step) => ({job: name, step})));
}
function runSteps(jobs) {
  return Object.entries(jobs).flatMap(([name, job]) =>
    stepsFor(job, `jobs.${name}`).filter((step) => step.run).map((step) =>
      ({job: name, step})));
}
function assertAction(step, action, label) {
  requireCondition(step.uses === action && PINNED_ACTION.test(step.uses),
    `${label} action identity changed`);
}

function validateWorkflow(contract, workflow, sourceText) {
  exactKeys(workflow, ['name', 'on', 'permissions', 'concurrency', 'jobs'], 'workflow');
  requireCondition(workflow.name === 'OSS Supply Chain Evidence Producers' &&
    JSON.stringify(workflow.on) === JSON.stringify({workflow_dispatch: null}) &&
    JSON.stringify(workflow.permissions) === JSON.stringify({contents: 'read'}) &&
    JSON.stringify(workflow.concurrency) === JSON.stringify({
      group: 'oss-supply-chain-producers-${{ github.ref }}',
      'cancel-in-progress': false,
    }), 'workflow trigger, permission, or concurrency boundary changed');
  const jobs = object(workflow.jobs, 'workflow.jobs');
  exactKeys(jobs, ['preflight', 'sbom-producer', 'vulnerability-producer'], 'workflow.jobs');
  for (const [name, job] of Object.entries(jobs)) {
    exactKeys(job, name === 'preflight' ?
      ['name', 'runs-on', 'timeout-minutes', 'environment', 'permissions', 'outputs', 'steps'] :
      ['name', 'needs', 'runs-on', 'timeout-minutes', 'environment', 'permissions', 'steps'],
    `jobs.${name}`);
    requireCondition(job['runs-on'] === 'ubuntu-24.04' && job.environment === 'release' &&
      job['timeout-minutes'] === contract.execution.jobs[name].timeout_minutes &&
      JSON.stringify(job.permissions) === JSON.stringify(contract.execution.job_permissions[name]),
    `${name} execution boundary changed`);
  }
  requireCondition(JSON.stringify(jobs.preflight.outputs) === JSON.stringify({
    candidate_run_id: '${{ steps.candidate-intake.outputs.candidate_run_id }}',
  }), 'preflight output changed');
  requireCondition(jobs['sbom-producer'].needs === 'preflight' &&
    JSON.stringify(jobs['vulnerability-producer'].needs) ===
      JSON.stringify(['preflight', 'sbom-producer']), 'producer dependency order changed');

  const actionSteps = usesSteps(jobs);
  requireCondition(actionSteps.length === 11, 'producer action count changed');
  for (const {step} of actionSteps) {
    exactKeys(step, ['name', 'uses', 'with'], `action step ${step.name}`);
    requireCondition(Object.values(ACTIONS).includes(step.uses),
      `unapproved action ${step.uses}`);
  }
  const checkouts = actionSteps.filter(({step}) => step.uses === ACTIONS.checkout);
  const setups = actionSteps.filter(({step}) => step.uses === ACTIONS.setup_node);
  const downloads = actionSteps.filter(({step}) => step.uses === ACTIONS.download_artifact);
  const uploads = actionSteps.filter(({step}) => step.uses === ACTIONS.upload_artifact);
  requireCondition(checkouts.length === 3 && setups.length === 3 &&
    downloads.length === 3 && uploads.length === 2, 'producer action use counts changed');
  for (const {step} of checkouts) {
    assertAction(step, ACTIONS.checkout, 'checkout');
    requireCondition(JSON.stringify(step.with) === JSON.stringify({
      'fetch-depth': 0, 'persist-credentials': false, ref: '${{ github.sha }}',
    }), 'checkout no longer selects the exact commit without credentials');
  }
  for (const {step} of setups) {
    requireCondition(JSON.stringify(step.with) === JSON.stringify({'node-version': '22.19.0'}),
      'Node.js runtime pin changed');
  }
  const candidateDownloads = downloads.filter(({step}) =>
    step.with?.name === 'oss-release-candidate-intake');
  requireCondition(candidateDownloads.length === 2 && candidateDownloads.every(({step}) =>
    JSON.stringify(step.with) === JSON.stringify({
      name: 'oss-release-candidate-intake',
      path: '${{ runner.temp }}/candidate-intake',
      'github-token': '${{ github.token }}', repository: '${{ github.repository }}',
      'run-id': '${{ needs.preflight.outputs.candidate_run_id }}',
    })), 'candidate intake downloads changed');
  const sbomDownload = downloads.find(({step}) =>
    step.with?.name === 'oss-release-sbom-producer-evidence');
  requireCondition(sbomDownload && JSON.stringify(sbomDownload.step.with) === JSON.stringify({
    name: 'oss-release-sbom-producer-evidence', path: '${{ runner.temp }}/sbom-producer',
  }), 'same-run SBOM evidence download changed');
  const expectedUploads = new Map([
    ['oss-release-sbom-producer-evidence', '${{ runner.temp }}/sbom-producer'],
    ['oss-release-vulnerability-producer-evidence', '${{ runner.temp }}/vulnerability-producer'],
  ]);
  for (const {step} of uploads) {
    requireCondition(expectedUploads.get(step.with?.name) === step.with?.path &&
      step.with['if-no-files-found'] === 'error' && step.with['compression-level'] === 0 &&
      step.with.overwrite === false && step.with['include-hidden-files'] === false &&
      step.with['retention-days'] === 3, 'producer upload boundary changed');
  }

  const runs = runSteps(jobs);
  for (const {step} of runs) {
    const keys = step.name === 'Discover the exact prior candidate intake' ?
      ['name', 'id', 'env', 'run'] :
      ['Pull pinned SBOM and validator images',
        'Pull the pinned vulnerability scanner image'].includes(step.name) ?
        ['name', 'env', 'run'] : ['name', 'run'];
    exactKeys(step, keys, `run step ${step.name}`);
  }
  const expectedRuns = [
    'npm ci --ignore-scripts', 'npm ci --ignore-scripts', 'npm ci --ignore-scripts',
    VERIFY, VERIFY, VERIFY, DISCOVER,
    PULL_SBOM_IMAGES,
    PREPARE, PRODUCE_SBOM, 'docker pull "$GRYPE_IMAGE"', PRODUCE_VULNERABILITY,
  ];
  requireCondition(JSON.stringify(multiset(runs.map(({step}) => step.run))) ===
    JSON.stringify(multiset(expectedRuns)), 'producer command set changed');
  const sbomPull = runs.find(({step}) => step.name === 'Pull pinned SBOM and validator images');
  const grypePull = runs.find(({step}) =>
    step.name === 'Pull the pinned vulnerability scanner image');
  const discovery = runs.find(({step}) => step.name === 'Discover the exact prior candidate intake');
  requireCondition(JSON.stringify(sbomPull?.step.env) === JSON.stringify({
    SYFT_IMAGE: TOOLS.syft_image,
    CYCLONEDX_VALIDATOR_IMAGE: TOOLS.cyclonedx_validator_image,
    PYTHON_IMAGE: TOOLS.python_image,
  }) && JSON.stringify(grypePull?.step.env) === JSON.stringify({GRYPE_IMAGE: TOOLS.grype_image}) &&
    discovery?.step.id === 'candidate-intake' &&
    JSON.stringify(discovery.step.env) === JSON.stringify({GITHUB_TOKEN: '${{ github.token }}'}),
  'producer pull environment changed');
  requireCondition(!/\b(?:push|schedule|pull_request):/u.test(sourceText) &&
    !/id-token\s*:\s*write/u.test(sourceText) &&
    !/(?:contents|packages|actions)\s*:\s*write/u.test(sourceText) &&
    !/\b(?:gh release|cosign sign|docker push|oras push|npm publish)\b/u.test(sourceText) &&
    !/review\.json/u.test(sourceText) && !/\$\{\{\s*secrets\./u.test(sourceText),
  'workflow gained an automatic, publishing, signing, review, or secret authority');
}

export function verifySupplyChainProducerWorkflow({
  contractPath, workflowPath, githubRepository, githubRefType, githubRefName,
  githubRefProtected, githubSha,
}) {
  requireCondition(githubRepository === REPOSITORY_SLUG && githubRefType === 'tag' &&
    githubRefProtected === 'true' && TAG.test(githubRefName ?? '') && COMMIT.test(githubSha ?? ''),
  'producer execution requires the exact public repository, protected strict tag, and full commit');
  const contract = object(JSON.parse(fs.readFileSync(contractPath, 'utf8')), 'contract');
  const sourceText = fs.readFileSync(workflowPath, 'utf8');
  const workflow = object(yaml.load(sourceText), 'workflow');
  validateContract(contract);
  validateWorkflow(contract, workflow, sourceText);
  return {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-supply-chain-producer-workflow-result',
    status: 'PRODUCER_FOUNDATION_VERIFIED',
    source: {repository: REPOSITORY, commit: githubSha, tag: githubRefName, dirty: false},
    human_review_required: true,
    review_generated: false,
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
  const result = verifySupplyChainProducerWorkflow({
    contractPath: values.get('contract'), workflowPath: values.get('workflow'),
    githubRepository: values.get('github-repository'),
    githubRefType: values.get('github-ref-type'), githubRefName: values.get('github-ref-name'),
    githubRefProtected: values.get('github-ref-protected'),
    githubSha: values.get('github-sha'),
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); } catch (error) {
    process.stderr.write(`supply-chain producer workflow rejected: ${error.message}\n`);
    process.exitCode = 2;
  }
}
