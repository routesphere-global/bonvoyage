#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

import yaml from 'js-yaml';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLASSIFICATION =
  'routesphere-bonvoyage-oss-artifact-lifecycle-workflow-contract';
const RESULT_CLASSIFICATION =
  'routesphere-bonvoyage-oss-artifact-lifecycle-workflow-result';
const LIFECYCLE_CLASSIFICATION =
  'routesphere-bonvoyage-oss-artifact-lifecycle-contract';
const REPOSITORY = 'routesphere-global/bonvoyage';
const REPOSITORY_URL = `https://github.com/${REPOSITORY}`;
const TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const TAG_PATTERN =
  '^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$';
const COMMIT = /^[a-f0-9]{40}$/u;
const PINNED_ACTION = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[a-f0-9]{40}$/u;
const ACTIONS = Object.freeze({
  checkout: 'actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803',
  setup_node: 'actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38',
  download_artifact:
    'actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53',
  upload_artifact:
    'actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4',
});
const RUNTIME_IMAGES = Object.freeze({
  skopeo:
    'quay.io/skopeo/stable@sha256:35bf578e3fa75a1f23bbec819fc1bd9745eacb4a0594dea203e426da66e95e5a',
  python:
    'python:3.12-slim@sha256:1148dbb014615300fa7e713b2f94f550c0d1c69780c0805f84f093ceee34dd0b',
});
const JOBS = Object.freeze({
  preflight: {name: 'Discover exact hosted candidates', timeout: 10},
  intakes: {name: 'Reconstruct exact baseline and candidate intakes', timeout: 20},
  'debian-candidate-fresh': {name: 'Candidate Debian fresh install', timeout: 30},
  'debian-transition': {name: 'Debian upgrade rollback and reactivation', timeout: 45},
  'oci-lifecycle': {name: 'OCI replacement rollback and reactivation', timeout: 35},
  aggregate: {name: 'Verify the complete lifecycle observation', timeout: 15},
});
const STEP_NAMES = Object.freeze({
  preflight: [
    'Check out the exact tagged commit without retained credentials',
    'Use the reviewed Node.js runtime',
    'Install locked workflow-verifier dependencies',
    'Verify the protected powerless workflow',
    'Discover exact unexpired baseline and candidate artifacts',
  ],
  intakes: [
    'Check out the exact tagged commit without retained credentials',
    'Use the reviewed Node.js runtime',
    'Download baseline Debian builder A',
    'Download baseline Debian builder B',
    'Download baseline Debian comparison',
    'Download baseline OCI builder A',
    'Download baseline OCI builder B',
    'Download baseline OCI comparison',
    'Download candidate Debian builder A',
    'Download candidate Debian builder B',
    'Download candidate Debian comparison',
    'Download candidate OCI builder A',
    'Download candidate OCI builder B',
    'Download candidate OCI comparison',
    'Build checksum-bound baseline and candidate intakes',
    'Upload exact lifecycle intakes',
  ],
  'debian-candidate-fresh': [
    'Check out the exact tagged commit without retained credentials',
    'Download same-run lifecycle intakes',
    'Exercise exact fresh install and removal',
    'Upload bounded fresh-install evidence',
  ],
  'debian-transition': [
    'Check out the exact tagged commit without retained credentials',
    'Download same-run lifecycle intakes',
    'Exercise upgrade rollback reactivation and removal',
    'Upload bounded Debian transition evidence',
  ],
  'oci-lifecycle': [
    'Check out the exact tagged commit without retained credentials',
    'Download same-run lifecycle intakes',
    'Exercise replacement rollback reactivation and cleanup',
    'Upload bounded OCI lifecycle evidence',
  ],
  aggregate: [
    'Check out the exact tagged commit without retained credentials',
    'Use the reviewed Node.js runtime',
    'Download same-run lifecycle intakes',
    'Download fresh-install lane',
    'Download Debian transition lane',
    'Download OCI lifecycle lane',
    'Assemble and independently verify the lifecycle observation',
    'Upload non-publishing lifecycle evidence',
  ],
});
const RUN_SHA256 = Object.freeze({
  'Install locked workflow-verifier dependencies':
    'e568f48e4564d1ada4a272f93f6e94a1db7c70212a765c414a6ec92d2a889e21',
  'Verify the protected powerless workflow':
    '751898f17be65c5cc246daa3af0a333984cb1f32776e28d9f1151771e46583bf',
  'Discover exact unexpired baseline and candidate artifacts':
    'c2ad5c3af57fe2ec9fd718382909f3f34ee64383f3f8d04f48d33b8a89e217fc',
  'Build checksum-bound baseline and candidate intakes':
    'da9d33a6f83e54b32e73d5a03e55f0cad7ad63e4c73dd49dc24500747032bdef',
  'Exercise exact fresh install and removal':
    'df1df4626cf08bb8d2786ecbdc8a964e4f971e4f8f899643833343252aa4fe34',
  'Exercise upgrade rollback reactivation and removal':
    '708eb52bd271954edf621b7d45b088f1aac0f3853cd752880a088138c6e6035c',
  'Exercise replacement rollback reactivation and cleanup':
    'e79af1ceb0180172d0d1d5d44ab108dd5563a54673d763382f004668211334a6',
  'Assemble and independently verify the lifecycle observation':
    '7f8459ac08a678292fa4f44feab58f72fe595d35f2dae7f0272dbb6e450959f6',
});
const AUTHORITY = Object.freeze({
  release_admitted: false,
  publishable: false,
  github_release_created: false,
  package_uploaded: false,
  container_uploaded: false,
  signature_created: false,
  provenance_created: false,
});

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
function exact(value, expected, message) {
  requireCondition(JSON.stringify(value) === JSON.stringify(expected), message);
}
function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}
function canonicalJson(filePath, label) {
  const raw = fs.readFileSync(filePath, 'utf8');
  const value = JSON.parse(raw);
  requireCondition(`${JSON.stringify(value, null, 2)}\n` === raw,
    `${label} must be canonical JSON`);
  return object(value, label);
}

function parseVersion(value, label) {
  requireCondition(TAG.test(value ?? ''), `${label} must be a strict version tag`);
  const dash = value.indexOf('-');
  const core = value.slice(1, dash === -1 ? undefined : dash).split('.');
  const prerelease = dash === -1 ? null : value.slice(dash + 1).split('.');
  requireCondition(prerelease === null || prerelease.every((part) =>
    !/^[0-9]+$/u.test(part) || part === '0' || !part.startsWith('0')),
  `${label} contains a numeric prerelease identifier with a leading zero`);
  return {core, prerelease};
}
function compareNumeric(left, right) {
  if (left.length !== right.length) return left.length > right.length ? 1 : -1;
  if (left === right) return 0;
  return left > right ? 1 : -1;
}
function compareVersions(leftValue, rightValue) {
  const left = parseVersion(leftValue, 'candidate tag');
  const right = parseVersion(rightValue, 'baseline tag');
  for (let index = 0; index < 3; index += 1) {
    const comparison = compareNumeric(left.core[index], right.core[index]);
    if (comparison !== 0) return comparison;
  }
  if (left.prerelease === null || right.prerelease === null) {
    if (left.prerelease === right.prerelease) return 0;
    return left.prerelease === null ? 1 : -1;
  }
  const length = Math.max(left.prerelease.length, right.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = left.prerelease[index];
    const rightPart = right.prerelease[index];
    if (leftPart === undefined || rightPart === undefined) {
      return leftPart === undefined ? -1 : 1;
    }
    if (leftPart === rightPart) continue;
    const leftNumeric = /^[0-9]+$/u.test(leftPart);
    const rightNumeric = /^[0-9]+$/u.test(rightPart);
    if (leftNumeric && rightNumeric) return compareNumeric(leftPart, rightPart);
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return leftPart > rightPart ? 1 : -1;
  }
  return 0;
}

function validateContract(contract) {
  exactKeys(contract, [
    'schema_version', 'classification', 'activation', 'source', 'execution',
    'actions', 'runtime_images', 'evidence', 'authority',
  ], 'workflow contract');
  requireCondition(contract.schema_version === 1 &&
    contract.classification === CLASSIFICATION,
  'unsupported lifecycle workflow contract');
  exact(contract.activation, {
    state: 'activatable',
    template_path: 'packaging/release/oss-artifact-lifecycle.workflow.yml',
    active_workflow_path: '.github/workflows/oss-artifact-lifecycle.yml',
    public_repository_created: true,
    repository_settings_verified: true,
    protected_release_tags_verified: true,
  }, 'lifecycle workflow activation boundary changed');
  exact(contract.source, {
    repository: REPOSITORY_URL,
    event: 'workflow_dispatch',
    ref_type: 'tag',
    tag_pattern: TAG_PATTERN,
    protected_tag_required: true,
    pushed_commit_required: true,
    clean_checkout_required: true,
    newer_than_baseline_required: true,
  }, 'lifecycle workflow source boundary changed');
  const execution = object(contract.execution, 'workflow contract execution');
  exactKeys(execution, [
    'environment', 'runner', 'platform', 'node_version', 'permissions', 'jobs',
    'artifact_retention_days', 'maximum_billable_job_minutes', 'manual_only',
    'scheduled_runs', 'self_hosted_runners', 'cancel_in_progress',
  ], 'workflow contract execution');
  exact(execution.permissions, {actions: 'read', contents: 'read'},
    'lifecycle workflow permissions changed');
  const expectedJobs = Object.fromEntries(Object.entries(JOBS).map(
    ([name, value]) => [name, {timeout_minutes: value.timeout}]));
  exact(execution.jobs, expectedJobs, 'lifecycle workflow job budget changed');
  requireCondition(execution.environment === 'release' &&
    execution.runner === 'ubuntu-24.04' && execution.platform === 'linux/amd64' &&
    execution.node_version === '24' && execution.artifact_retention_days === 3 &&
    execution.maximum_billable_job_minutes === 155 && execution.manual_only === true &&
    execution.scheduled_runs === false && execution.self_hosted_runners === false &&
    execution.cancel_in_progress === false,
  'lifecycle workflow execution boundary changed');
  exact(contract.actions, ACTIONS, 'lifecycle workflow action pins changed');
  requireCondition(Object.values(contract.actions).every((value) => PINNED_ACTION.test(value)),
    'every lifecycle action must use a full commit pin');
  exact(contract.runtime_images, RUNTIME_IMAGES,
    'lifecycle workflow runtime image pins changed');
  exact(contract.evidence, {
    intakes: 'oss-artifact-lifecycle-intakes',
    lanes: [
      'oss-artifact-lifecycle-debian-candidate-fresh',
      'oss-artifact-lifecycle-debian-transition',
      'oss-artifact-lifecycle-oci',
    ],
    final: 'oss-artifact-lifecycle-evidence',
  }, 'lifecycle workflow evidence identities changed');
  exact(contract.authority, AUTHORITY, 'lifecycle workflow authority changed');
}

function validateExecutionContext(options, lifecycleContract) {
  requireCondition(options.githubRepository === REPOSITORY &&
    options.githubRefType === 'tag' && options.githubRefProtected === 'true' &&
    COMMIT.test(options.githubSha ?? '') && TAG.test(options.githubRefName ?? ''),
  'lifecycle execution requires the public repository, protected tag, and full commit');
  requireCondition(lifecycleContract.schema_version === 1 &&
    lifecycleContract.classification === LIFECYCLE_CLASSIFICATION &&
    lifecycleContract.source_repository === REPOSITORY_URL,
  'lifecycle evidence contract identity changed');
  const baseline = object(lifecycleContract.baseline?.source, 'lifecycle baseline source');
  requireCondition(COMMIT.test(baseline.commit ?? '') && TAG.test(baseline.tag ?? '') &&
    options.githubSha !== baseline.commit &&
    compareVersions(options.githubRefName, baseline.tag) > 0,
  'lifecycle candidate must be newer than and differ from the rollback baseline');
}

function validateCheckout(step, label) {
  exactKeys(step, ['name', 'uses', 'with'], label);
  requireCondition(step.name ===
    'Check out the exact tagged commit without retained credentials' &&
    step.uses === ACTIONS.checkout,
  `${label} changed`);
  exact(step.with, {
    'fetch-depth': 0,
    'persist-credentials': false,
    ref: '${{ github.sha }}',
  }, `${label} source identity changed`);
}

function validateSetupNode(step, label) {
  exactKeys(step, ['name', 'uses', 'with'], label);
  requireCondition(step.name === 'Use the reviewed Node.js runtime' &&
    step.uses === ACTIONS.setup_node,
  `${label} changed`);
  exact(step.with, {'node-version': '24'}, `${label} runtime changed`);
}

function validateDownload(step, expected, label) {
  exactKeys(step, ['name', 'uses', 'with'], label);
  requireCondition(step.uses === ACTIONS.download_artifact, `${label} action changed`);
  exact(step.with, expected, `${label} source or destination changed`);
}

function validateUpload(step, expected, label) {
  exactKeys(step, ['name', 'uses', 'with'], label);
  requireCondition(step.uses === ACTIONS.upload_artifact, `${label} action changed`);
  exact(step.with, {
    ...expected,
    'if-no-files-found': 'error',
    'compression-level': 0,
    overwrite: false,
    'include-hidden-files': false,
    'retention-days': 3,
  }, `${label} evidence boundary changed`);
}

function validateRunSteps(workflow) {
  for (const [jobName, job] of Object.entries(workflow.jobs)) {
    for (const step of job.steps) {
      if (step.run === undefined) continue;
      exactKeys(step,
        step.name === 'Discover exact unexpired baseline and candidate artifacts'
          ? ['name', 'id', 'env', 'run'] : ['name', 'run'],
        `${jobName} run step ${step.name}`);
      requireCondition(RUN_SHA256[step.name] === sha256(step.run),
        `${step.name} command changed`);
    }
  }
  const discovery = workflow.jobs.preflight.steps[4];
  requireCondition(discovery.id === 'discovery', 'lifecycle discovery output identity changed');
  exact(discovery.env, {GITHUB_TOKEN: '${{ github.token }}'},
    'lifecycle discovery credential boundary changed');
}

function validateExternalDownloads(job) {
  const specifications = [];
  const artifacts = {
    deb: [
      ['builder A', 'oss-deb-build-a'],
      ['builder B', 'oss-deb-build-b'],
      ['comparison', 'oss-deb-comparison'],
    ],
    oci: [
      ['builder A', 'oss-oci-build-a'],
      ['builder B', 'oss-oci-build-b'],
      ['comparison', 'oss-oci-comparison'],
    ],
  };
  for (const source of ['baseline', 'candidate']) {
    for (const kind of ['deb', 'oci']) {
      const displayKind = kind === 'deb' ? 'Debian' : 'OCI';
      for (const [displayArtifact, artifact] of artifacts[kind]) {
        specifications.push({
          name: `Download ${source} ${displayKind} ${displayArtifact}`,
          with: {
            name: artifact,
            path: `\${{ runner.temp }}/${source}-${kind}/${artifact}`,
            repository: '${{ github.repository }}',
            'run-id': `\${{ needs.preflight.outputs.${source}_${kind}_run_id }}`,
            'github-token': '${{ github.token }}',
          },
        });
      }
    }
  }
  const steps = job.steps.slice(2, 14);
  requireCondition(steps.length === specifications.length,
    'external lifecycle artifact download count changed');
  steps.forEach((step, index) => {
    requireCondition(step.name === specifications[index].name,
      `external download ${index} name changed`);
    validateDownload(step, specifications[index].with, `external download ${index}`);
  });
}

function validateWorkflow(contract, workflow, sourceText) {
  exactKeys(workflow, ['name', 'on', 'permissions', 'concurrency', 'env', 'jobs'],
    'lifecycle workflow');
  requireCondition(workflow.name === 'OSS Artifact Lifecycle Evidence',
    'lifecycle workflow name changed');
  exact(workflow.on, {workflow_dispatch: null}, 'lifecycle workflow trigger changed');
  exact(workflow.permissions, contract.execution.permissions,
    'lifecycle workflow global permissions changed');
  exact(workflow.concurrency, {
    group: 'oss-artifact-lifecycle-${{ github.ref }}',
    'cancel-in-progress': false,
  }, 'lifecycle workflow concurrency changed');
  exact(workflow.env, {
    LIFECYCLE_CONTRACT: 'packaging/release/oss-artifact-lifecycle-contract.json',
    WORKFLOW_CONTRACT:
      'packaging/release/oss-artifact-lifecycle-workflow-contract.json',
    WORKFLOW_TEMPLATE: 'packaging/release/oss-artifact-lifecycle.workflow.yml',
  }, 'lifecycle workflow environment changed');
  requireCondition(JSON.stringify(Object.keys(workflow.jobs)) ===
    JSON.stringify(Object.keys(JOBS)), 'lifecycle workflow job order changed');

  for (const [jobName, specification] of Object.entries(JOBS)) {
    const job = object(workflow.jobs[jobName], `workflow job ${jobName}`);
    exactKeys(job,
      jobName === 'preflight'
        ? ['name', 'runs-on', 'timeout-minutes', 'environment', 'outputs', 'steps']
        : ['name', 'needs', 'runs-on', 'timeout-minutes', 'environment', 'steps'],
      `workflow job ${jobName}`);
    requireCondition(job.name === specification.name &&
      job['runs-on'] === contract.execution.runner &&
      job['timeout-minutes'] === specification.timeout &&
      job.environment === contract.execution.environment,
    `workflow job ${jobName} execution boundary changed`);
    requireCondition(JSON.stringify(job.steps.map((step) => step.name)) ===
      JSON.stringify(STEP_NAMES[jobName]), `workflow job ${jobName} steps changed`);
    validateCheckout(job.steps[0], `${jobName} checkout`);
  }
  requireCondition(workflow.jobs.intakes.needs === 'preflight' &&
    workflow.jobs['debian-candidate-fresh'].needs === 'intakes' &&
    workflow.jobs['debian-transition'].needs === 'intakes' &&
    workflow.jobs['oci-lifecycle'].needs === 'intakes',
  'lifecycle workflow dependency graph changed');
  exact(workflow.jobs.aggregate.needs, [
    'preflight', 'intakes', 'debian-candidate-fresh', 'debian-transition',
    'oci-lifecycle',
  ], 'lifecycle aggregate dependency graph changed');
  exact(workflow.jobs.preflight.outputs, {
    baseline_deb_run_id: '${{ steps.discovery.outputs.baseline_deb_run_id }}',
    baseline_oci_run_id: '${{ steps.discovery.outputs.baseline_oci_run_id }}',
    candidate_deb_run_id: '${{ steps.discovery.outputs.candidate_deb_run_id }}',
    candidate_oci_run_id: '${{ steps.discovery.outputs.candidate_oci_run_id }}',
    baseline_created_at: '${{ steps.discovery.outputs.baseline_created_at }}',
    candidate_created_at: '${{ steps.discovery.outputs.candidate_created_at }}',
    baseline_commit: '${{ steps.discovery.outputs.baseline_commit }}',
    baseline_tag: '${{ steps.discovery.outputs.baseline_tag }}',
    candidate_commit: '${{ steps.discovery.outputs.candidate_commit }}',
    candidate_tag: '${{ steps.discovery.outputs.candidate_tag }}',
  }, 'lifecycle discovery outputs changed');

  validateSetupNode(workflow.jobs.preflight.steps[1], 'preflight Node setup');
  validateSetupNode(workflow.jobs.intakes.steps[1], 'intakes Node setup');
  validateSetupNode(workflow.jobs.aggregate.steps[1], 'aggregate Node setup');
  validateRunSteps(workflow);
  validateExternalDownloads(workflow.jobs.intakes);

  validateUpload(workflow.jobs.intakes.steps[15], {
    name: contract.evidence.intakes,
    path: '${{ runner.temp }}/intakes',
  }, 'intake upload');
  const laneDownloads = [
    ['debian-candidate-fresh', '${{ runner.temp }}/intakes'],
    ['debian-transition', '${{ runner.temp }}/intakes'],
    ['oci-lifecycle', '${{ runner.temp }}/intakes'],
  ];
  for (const [jobName, destination] of laneDownloads) {
    validateDownload(workflow.jobs[jobName].steps[1], {
      name: contract.evidence.intakes, path: destination,
    }, `${jobName} same-run intake download`);
  }
  validateUpload(workflow.jobs['debian-candidate-fresh'].steps[3], {
    name: contract.evidence.lanes[0], path: '/var/tmp/bonvoyage-lifecycle-fresh',
  }, 'fresh lane upload');
  validateUpload(workflow.jobs['debian-transition'].steps[3], {
    name: contract.evidence.lanes[1], path: '/var/tmp/bonvoyage-debian-transition',
  }, 'Debian transition upload');
  validateUpload(workflow.jobs['oci-lifecycle'].steps[3], {
    name: contract.evidence.lanes[2], path: '/var/tmp/bonvoyage-oci-lifecycle',
  }, 'OCI lane upload');

  const aggregateDownloads = [
    [2, contract.evidence.intakes, '${{ runner.temp }}/intakes'],
    [3, contract.evidence.lanes[0],
      '${{ runner.temp }}/lanes/debian-candidate-fresh'],
    [4, contract.evidence.lanes[1], '${{ runner.temp }}/lanes/debian-transition'],
    [5, contract.evidence.lanes[2], '${{ runner.temp }}/lanes/oci-lifecycle'],
  ];
  for (const [index, name, destination] of aggregateDownloads) {
    validateDownload(workflow.jobs.aggregate.steps[index], {name, path: destination},
      `aggregate download ${name}`);
  }
  validateUpload(workflow.jobs.aggregate.steps[7], {
    name: contract.evidence.final,
    path: '${{ runner.temp }}/oss-artifact-lifecycle-evidence',
  }, 'final lifecycle evidence upload');

  const uses = Object.values(workflow.jobs).flatMap((job) =>
    job.steps.filter((step) => step.uses !== undefined).map((step) => step.uses));
  requireCondition(uses.every((value) => Object.values(ACTIONS).includes(value) &&
    PINNED_ACTION.test(value)), 'lifecycle workflow gained an unapproved action');
  requireCondition(uses.filter((value) => value === ACTIONS.checkout).length === 6 &&
    uses.filter((value) => value === ACTIONS.setup_node).length === 3 &&
    uses.filter((value) => value === ACTIONS.download_artifact).length === 19 &&
    uses.filter((value) => value === ACTIONS.upload_artifact).length === 5,
  'lifecycle workflow action count changed');
  const tokenReferences = sourceText.match(/\$\{\{\s*github[.]token\s*\}\}/gu) ?? [];
  requireCondition(tokenReferences.length === 13 &&
    !/\$\{\{\s*secrets[.]/u.test(sourceText),
  'lifecycle workflow credential boundary changed');
  requireCondition(!/\b(?:push|schedule|pull_request):/u.test(sourceText) &&
    !/id-token\s*:\s*write/u.test(sourceText) &&
    !/(?:actions|contents|packages)\s*:\s*write/u.test(sourceText) &&
    !/continue-on-error\s*:/u.test(sourceText) &&
    !/persist-credentials\s*:\s*true/u.test(sourceText) &&
    !/\b(?:gh release|cosign|docker push|oras push|npm publish|dpkg-sig|gh attestation)\b/u
      .test(sourceText),
  'workflow gained an automatic, permissive, publishing, or signing boundary');
}

export function verifyArtifactLifecycleWorkflow({
  contractPath,
  workflowPath,
  activeWorkflowPath,
  lifecycleContractPath = path.join(
    ROOT, 'packaging/release/oss-artifact-lifecycle-contract.json'),
  ociCollectorPath = path.join(ROOT, 'scripts/collect-oss-oci-lifecycle.py'),
  githubRepository,
  githubRefType,
  githubRefName,
  githubRefProtected,
  githubSha,
}) {
  const contract = canonicalJson(contractPath, 'lifecycle workflow contract');
  const lifecycleContract = canonicalJson(
    lifecycleContractPath, 'lifecycle evidence contract');
  const sourceText = fs.readFileSync(workflowPath, 'utf8');
  const activeText = fs.readFileSync(activeWorkflowPath, 'utf8');
  requireCondition(sourceText === activeText,
    'reviewed lifecycle template and active workflow must be byte-identical');
  const workflow = object(yaml.load(sourceText), 'lifecycle workflow');
  validateContract(contract);
  validateExecutionContext({
    githubRepository, githubRefType, githubRefName, githubRefProtected, githubSha,
  }, lifecycleContract);
  validateWorkflow(contract, workflow, sourceText);
  const collectorText = fs.readFileSync(ociCollectorPath, 'utf8');
  const normalizedCollectorText = collectorText.replace(/"\s*"/gu, '');
  for (const image of Object.values(RUNTIME_IMAGES)) {
    requireCondition(normalizedCollectorText.includes(image),
      `OCI collector is missing pinned runtime image ${image}`);
  }
  return {
    schema_version: 1,
    classification: RESULT_CLASSIFICATION,
    status: 'ARTIFACT_LIFECYCLE_WORKFLOW_VERIFIED',
    source: {
      repository: REPOSITORY_URL,
      commit: githubSha,
      tag: githubRefName,
      protected: true,
      dirty: false,
    },
    human_review_required: true,
    lifecycle_executed: false,
    authority: contract.authority,
  };
}

function parseArguments(argv) {
  const result = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    requireCondition(argv[index]?.startsWith('--') && argv[index + 1] !== undefined,
      'arguments must be --name value pairs');
    const name = argv[index].slice(2);
    requireCondition(!result.has(name), `duplicate argument --${name}`);
    result.set(name, argv[index + 1]);
  }
  return result;
}

function main(argv) {
  const values = parseArguments(argv);
  const result = verifyArtifactLifecycleWorkflow({
    contractPath: values.get('contract'),
    workflowPath: values.get('workflow'),
    activeWorkflowPath: values.get('active-workflow'),
    githubRepository: values.get('github-repository'),
    githubRefType: values.get('github-ref-type'),
    githubRefName: values.get('github-ref-name'),
    githubRefProtected: values.get('github-ref-protected'),
    githubSha: values.get('github-sha'),
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); } catch (error) {
    process.stderr.write(`artifact lifecycle workflow rejected: ${error.message}\n`);
    process.exitCode = 2;
  }
}
