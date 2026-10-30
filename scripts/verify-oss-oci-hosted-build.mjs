#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import yaml from 'js-yaml';

const CLASSIFICATION = 'routesphere-bonvoyage-oss-oci-hosted-build-contract';
const RESULT_CLASSIFICATION = 'routesphere-bonvoyage-oss-oci-hosted-build-contract-result';
const IMAGE_OBSERVATION_CLASSIFICATION =
  'routesphere-bonvoyage-oss-oci-builder-image-observation';
const HOSTED_RECEIPT_CLASSIFICATION =
  'routesphere-bonvoyage-oss-oci-hosted-reproducibility';
const PUBLIC_REPOSITORY = 'https://github.com/routesphere-global/bonvoyage';
const PUBLIC_REPOSITORY_SLUG = 'routesphere-global/bonvoyage';
const ACTIVATABLE = 'activatable';
const BLOCKED = 'blocked-pending-public-builder-image';
const SHA256 = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const IMAGE_REFERENCE = /^(ghcr\.io\/routesphere-global\/bonvoyage-oci-builder)@sha256:([a-f0-9]{64})$/u;
const ATTEST_ACTION = 'actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6';
const PROVENANCE_VERIFY_COMMAND = [
  'node scripts/verify-oss-oci-hosted-build.mjs',
  '--contract "$CONTRACT_PATH"',
  '--workflow "$WORKFLOW_TEMPLATE"',
  '--require-activatable',
  '--github-repository "$GITHUB_REPOSITORY"',
  '--github-ref-type "$GITHUB_REF_TYPE"',
  '--github-ref-name "$GITHUB_REF_NAME"',
  '--github-sha "$GITHUB_SHA"',
].join(' ');
const PROVENANCE_PREPARE_COMMAND = [
  'node scripts/record-oss-hosted-provenance.mjs',
  '--mode prepare',
  '--format oci',
  '--input "$RUNNER_TEMP/oss-oci-build-a"',
  '--repository "$GITHUB_REPOSITORY"',
  '--commit "$GITHUB_SHA"',
  '--tag "$GITHUB_REF_NAME"',
  '--run-id "$GITHUB_RUN_ID"',
  '--run-attempt "$GITHUB_RUN_ATTEMPT"',
  '--workflow-ref "$GITHUB_WORKFLOW_REF"',
  '--workflow-sha "$GITHUB_WORKFLOW_SHA"',
  '--github-output "$GITHUB_OUTPUT"',
].join(' ');
const PROVENANCE_RECORD_COMMAND = [
  'node scripts/record-oss-hosted-provenance.mjs',
  '--mode record',
  '--format oci',
  '--input "$RUNNER_TEMP/oss-oci-build-a"',
  '--repository "$GITHUB_REPOSITORY"',
  '--commit "$GITHUB_SHA"',
  '--tag "$GITHUB_REF_NAME"',
  '--run-id "$GITHUB_RUN_ID"',
  '--run-attempt "$GITHUB_RUN_ATTEMPT"',
  '--workflow-ref "$GITHUB_WORKFLOW_REF"',
  '--workflow-sha "$GITHUB_WORKFLOW_SHA"',
  '--bundle "${{ steps.attest.outputs.bundle-path }}"',
  '--attestation-id "${{ steps.attest.outputs.attestation-id }}"',
  '--attestation-url "${{ steps.attest.outputs.attestation-url }}"',
  '--output "$RUNNER_TEMP/oss-oci-provenance"',
].join(' ');

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

function exactKeys(value, expected, label) {
  const actual = Object.keys(requireObject(value, label)).sort();
  const wanted = [...expected].sort();
  requireCondition(actual.length === wanted.length &&
    actual.every((item, index) => item === wanted[index]),
  `${label} fields must be exactly [${wanted.join(', ')}]`);
}

function readJsonValue(filePath, label) {
  let value;
  try {
    value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
  return value;
}

function readJson(filePath, label) {
  return requireObject(readJsonValue(filePath, label), label);
}

function readYaml(filePath, label) {
  let value;
  try {
    value = yaml.load(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    fail(`${label} is not valid YAML: ${error.message}`);
  }
  return requireObject(value, label);
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function validateRelativePath(value, label) {
  requireCondition(typeof value === 'string' && value.length > 0, `${label} is required`);
  requireCondition(!value.includes('\\') && !value.includes('\0') &&
    !path.posix.isAbsolute(value) && path.posix.normalize(value) === value &&
    !value.startsWith('./') && !value.split('/').some((part) => part === '' || part === '..'),
  `${label} must be a normalized POSIX-relative path`);
  return value;
}

function validateContract(contract) {
  exactKeys(contract, [
    'schema_version', 'classification', 'activation', 'source', 'execution',
    'builder_image', 'actions', 'evidence', 'provenance', 'authority',
  ], 'contract');
  requireCondition(contract.schema_version === 1 && contract.classification === CLASSIFICATION,
    'unsupported hosted-build contract');

  const activation = contract.activation;
  exactKeys(activation, [
    'state', 'template_path', 'active_workflow_path', 'public_repository_created',
    'builder_image_identity_verified', 'repository_settings_verified',
  ], 'contract.activation');
  requireCondition([BLOCKED, ACTIVATABLE].includes(activation.state),
    'unsupported activation state');
  validateRelativePath(activation.template_path, 'contract.activation.template_path');
  validateRelativePath(activation.active_workflow_path,
    'contract.activation.active_workflow_path');
  requireCondition(activation.template_path ===
    'packaging/release/oci/oss-oci-reproducibility.workflow.yml',
  'unexpected workflow template path');
  requireCondition(activation.active_workflow_path ===
    '.github/workflows/oss-oci-reproducibility.yml',
  'unexpected active workflow path');

  exactKeys(contract.source, [
    'repository', 'event', 'ref_type', 'tag_pattern', 'protected_tag_required',
    'pushed_commit_required', 'clean_checkout_required',
  ], 'contract.source');
  requireCondition(contract.source.repository === PUBLIC_REPOSITORY,
    'unexpected public source repository');
  requireCondition(contract.source.event === 'workflow_dispatch' &&
    contract.source.ref_type === 'tag', 'hosted build must be manual and tag-only');
  requireCondition(contract.source.protected_tag_required === true &&
    contract.source.pushed_commit_required === true &&
    contract.source.clean_checkout_required === true,
  'source protections must remain enabled');
  let tagPattern;
  try {
    tagPattern = new RegExp(contract.source.tag_pattern, 'u');
  } catch (error) {
    fail(`invalid tag pattern: ${error.message}`);
  }
  requireCondition(tagPattern.test('v1.0.0') && tagPattern.test('v1.0.0-rc.1') &&
    !tagPattern.test('main') && !tagPattern.test('v01.0.0'), 'tag pattern is not strict SemVer');

  exactKeys(contract.execution, [
    'environment', 'runner', 'platform', 'permissions', 'provenance_permissions', 'jobs',
    'artifact_retention_days', 'maximum_billable_job_minutes', 'manual_only',
    'scheduled_runs', 'self_hosted_runners', 'cancel_in_progress',
  ], 'contract.execution');
  requireCondition(contract.execution.environment === 'release' &&
    contract.execution.runner === 'ubuntu-24.04' &&
    contract.execution.platform === 'linux/amd64', 'unexpected hosted execution target');
  requireCondition(JSON.stringify(contract.execution.permissions) ===
    JSON.stringify({contents: 'read'}), 'workflow permissions must be read-only contents');
  requireCondition(JSON.stringify(contract.execution.provenance_permissions) ===
    JSON.stringify({contents: 'read', 'id-token': 'write', attestations: 'write'}),
  'provenance permissions must be minimal and explicit');
  const expectedTimeouts = {
    preflight: 5, 'build-a': 90, 'build-b': 90, compare: 15, provenance: 10,
  };
  requireCondition(JSON.stringify(contract.execution.jobs) === JSON.stringify(
    Object.fromEntries(Object.entries(expectedTimeouts).map(([name, timeout]) =>
      [name, {timeout_minutes: timeout}]))), 'unexpected hosted job budget');
  requireCondition(contract.execution.artifact_retention_days === 3 &&
    contract.execution.maximum_billable_job_minutes === 210 &&
    contract.execution.manual_only === true && contract.execution.scheduled_runs === false &&
    contract.execution.self_hosted_runners === false &&
    contract.execution.cancel_in_progress === false, 'hosted cost or runner boundary changed');

  exactKeys(contract.builder_image, [
    'repository', 'reference', 'verification_receipt', 'entrypoint', 'network',
    'read_only_root',
  ], 'contract.builder_image');
  requireCondition(contract.builder_image.repository ===
    'ghcr.io/routesphere-global/bonvoyage-oci-builder' &&
    contract.builder_image.entrypoint === '/usr/local/bin/bonvoyage-oss-oci-builder' &&
    contract.builder_image.network === 'none' && contract.builder_image.read_only_root === true,
  'builder image isolation contract changed');

  exactKeys(contract.actions, ['checkout', 'upload_artifact', 'download_artifact', 'attest'],
    'contract.actions');
  for (const [name, value] of Object.entries(contract.actions)) {
    requireCondition(/^actions\/[a-z-]+@[a-f0-9]{40}$/u.test(value),
      `contract.actions.${name} must be a GitHub-owned action pinned to a full commit`);
  }
  requireCondition(contract.actions.attest === ATTEST_ACTION,
    'provenance action identity changed');

  exactKeys(contract.evidence, [
    'builder_artifacts', 'comparison_artifacts', 'builder_names', 'comparison_name',
    'provenance_artifacts', 'provenance_name',
  ], 'contract.evidence');
  requireCondition(JSON.stringify(contract.evidence.builder_names) ===
    JSON.stringify(['oss-oci-build-a', 'oss-oci-build-b']) &&
    contract.evidence.comparison_name === 'oss-oci-comparison' &&
    contract.evidence.provenance_name === 'oss-oci-provenance',
  'hosted evidence names changed');
  requireCondition(JSON.stringify(requireArray(contract.evidence.builder_artifacts,
    'contract.evidence.builder_artifacts')) === JSON.stringify([
      'oci-builder-execution.json', 'builder-image-observation.json',
      'bonvoyage-gateway-*-linux-amd64.oci.tar',
    ]) && JSON.stringify(requireArray(contract.evidence.comparison_artifacts,
    'contract.evidence.comparison_artifacts')) === JSON.stringify([
      'reproducibility-receipt.json', 'hosted-reproducibility-receipt.json',
    ]) && JSON.stringify(requireArray(contract.evidence.provenance_artifacts,
      'contract.evidence.provenance_artifacts')) === JSON.stringify([
      'provenance-receipt.json', 'provenance.sigstore.jsonl',
    ]),
  'hosted evidence inventory must remain exact');

  exactKeys(contract.provenance, [
    'recorder_script', 'predicate_type', 'slsa_build_level', 'subject_builder',
  ], 'contract.provenance');
  requireCondition(contract.provenance.recorder_script ===
    'scripts/record-oss-hosted-provenance.mjs' &&
    contract.provenance.predicate_type === 'https://slsa.dev/provenance/v1' &&
    contract.provenance.slsa_build_level === 2 &&
    contract.provenance.subject_builder === 'build-a',
  'hosted provenance contract changed');

  exactKeys(contract.authority, [
    'release_admitted', 'publishable', 'github_release_created', 'package_uploaded',
    'container_uploaded', 'signature_created', 'provenance_created',
  ], 'contract.authority');
  requireCondition(contract.authority.provenance_created === true &&
    Object.entries(contract.authority).every(([field, value]) =>
      field === 'provenance_created' ? value === true : value === false),
  'hosted build may create provenance but must not grant release authority');

  const active = activation.state === ACTIVATABLE;
  if (active) {
    requireCondition(activation.public_repository_created === true &&
      activation.builder_image_identity_verified === true &&
      activation.repository_settings_verified === true,
    'activatable state requires all external controls to be verified');
    const imageMatch = IMAGE_REFERENCE.exec(contract.builder_image.reference ?? '');
    requireCondition(imageMatch !== null && imageMatch[1] === contract.builder_image.repository,
      'activatable builder image must use the approved digest-pinned GHCR repository');
    validateRelativePath(contract.builder_image.verification_receipt,
      'contract.builder_image.verification_receipt');
  } else {
    requireCondition(activation.public_repository_created === false &&
      activation.builder_image_identity_verified === false &&
      activation.repository_settings_verified === false &&
      contract.builder_image.reference === null &&
      contract.builder_image.verification_receipt === null,
    'blocked contract must not carry unverified activation state');
  }
  return {active, tagPattern};
}

function actionName(value) {
  return typeof value === 'string' ? value.split('@', 1)[0] : '';
}

function validateProvenanceJob(contract, job) {
  requireCondition(job.name === 'Attest exact OCI candidate bytes' &&
    job.needs === 'compare' && job.steps.length === 8,
  'OCI provenance job boundary changed');
  const download = job.steps[3];
  requireCondition(download.name === 'Download the exact builder A candidate' &&
    download.uses === contract.actions.download_artifact &&
    JSON.stringify(download.with) === JSON.stringify({
      name: 'oss-oci-build-a', path: '${{ runner.temp }}/oss-oci-build-a',
    }), 'OCI provenance download changed');
  const prepare = job.steps[4];
  requireCondition(prepare.name === 'Resolve and verify the exact OCI subject' &&
    prepare.id === 'subject' && prepare.run.trimEnd() === PROVENANCE_PREPARE_COMMAND,
  'OCI provenance subject resolution changed');
  const attest = job.steps[5];
  requireCondition(attest.name ===
    'Create signed SLSA provenance for the exact OCI subject' &&
    attest.id === 'attest' && attest.uses === contract.actions.attest &&
    JSON.stringify(attest.with) === JSON.stringify({
      'subject-path': '${{ steps.subject.outputs.subject_path }}',
    }), 'OCI provenance action boundary changed');
  const record = job.steps[6];
  requireCondition(record.name ===
    'Record bounded non-publishing OCI provenance evidence' &&
    record.run.trimEnd() === PROVENANCE_RECORD_COMMAND,
  'OCI provenance evidence recorder changed');
  const upload = job.steps[7];
  requireCondition(upload.name === 'Upload bounded OCI provenance evidence' &&
    upload.uses === contract.actions.upload_artifact &&
    upload.with.name === contract.evidence.provenance_name &&
    upload.with.path === '${{ runner.temp }}/oss-oci-provenance',
  'OCI provenance upload changed');
  requireCondition(job.steps[1].name === 'Install locked contract-verifier dependencies' &&
    job.steps[1].run === 'npm ci --ignore-scripts' &&
    job.steps[2].name === 'Reverify the hosted-build contract before attestation' &&
    job.steps[2].run.trimEnd() === PROVENANCE_VERIFY_COMMAND,
  'OCI provenance preflight changed');
}

function validateWorkflow(contract, workflow, workflowSource) {
  requireCondition(workflow.name === 'OSS OCI Reproducibility Candidate',
    'unexpected hosted workflow name');
  requireCondition(JSON.stringify(workflow.on) === JSON.stringify({workflow_dispatch: null}),
    'hosted workflow must have only a parameterless manual trigger');
  requireCondition(JSON.stringify(workflow.permissions) === JSON.stringify({contents: 'read'}),
    'hosted workflow permissions must remain read-only');
  requireCondition(workflow.concurrency?.['cancel-in-progress'] === false,
    'hosted evidence runs must not be silently cancelled');
  requireCondition(workflow.env?.CONTRACT_PATH ===
    'packaging/release/oci/oss-oci-hosted-build-contract.json' &&
    workflow.env?.WORKFLOW_TEMPLATE === contract.activation.template_path,
  'workflow must use the reviewed contract and template paths');
  requireCondition(JSON.stringify(Object.keys(workflow.jobs)) ===
    JSON.stringify(['preflight', 'build-a', 'build-b', 'compare', 'provenance']),
  'workflow must contain the exact preflight, builders, comparison and provenance jobs');

  const allowedActions = new Set(Object.values(contract.actions));
  for (const [jobName, expected] of Object.entries(contract.execution.jobs)) {
    const job = requireObject(workflow.jobs[jobName], `workflow.jobs.${jobName}`);
    requireCondition(job['runs-on'] === contract.execution.runner &&
      job['timeout-minutes'] === expected.timeout_minutes &&
      job.environment === contract.execution.environment,
    `${jobName} execution policy changed`);
    requireCondition(job.container === undefined,
      `${jobName} must use the reviewed Docker boundary`);
    if (jobName === 'provenance') {
      requireCondition(JSON.stringify(job.permissions) ===
        JSON.stringify(contract.execution.provenance_permissions),
      'provenance job permissions changed');
    } else {
      requireCondition(job.permissions === undefined,
        `${jobName} must inherit read-only permissions`);
    }
    for (const step of requireArray(job.steps, `${jobName}.steps`)) {
      if (step.uses !== undefined) {
        requireCondition(allowedActions.has(step.uses), `${step.uses} is not an approved action`);
      }
    }
  }
  requireCondition(workflow.jobs['build-a'].needs === 'preflight' &&
    workflow.jobs['build-b'].needs === 'preflight', 'builders must depend on protected preflight');
  requireCondition(JSON.stringify(workflow.jobs.compare.needs) ===
    JSON.stringify(['preflight', 'build-a', 'build-b']),
  'comparison must depend on both independent builders');
  validateProvenanceJob(contract, workflow.jobs.provenance);

  for (const job of Object.values(workflow.jobs)) {
    const checkouts = job.steps.filter((step) => actionName(step.uses) === 'actions/checkout');
    requireCondition(checkouts.length === 1 && checkouts[0].with['fetch-depth'] === 0 &&
      checkouts[0].with['persist-credentials'] === false &&
      checkouts[0].with.ref === '${{ github.sha }}',
    'every job must check out the exact tagged commit without retained credentials');
    for (const step of job.steps.filter((item) =>
      actionName(item.uses) === 'actions/upload-artifact')) {
      requireCondition(step.with['retention-days'] ===
        contract.execution.artifact_retention_days &&
        step.with['if-no-files-found'] === 'error' && step.with.overwrite === false &&
        step.with['include-hidden-files'] === false,
      'artifact upload must be bounded and fail closed');
    }
  }
  const firstUpload = workflow.jobs['build-a'].steps.find((step) =>
    actionName(step.uses) === 'actions/upload-artifact');
  const secondUpload = workflow.jobs['build-b'].steps.find((step) =>
    actionName(step.uses) === 'actions/upload-artifact');
  requireCondition(firstUpload?.with?.name === 'oss-oci-build-a' &&
    secondUpload?.with?.name === 'oss-oci-build-b' && firstUpload?.if === 'always()' &&
    secondUpload?.if === 'always()',
  'builder evidence names must be distinct and failed attempts must be retained');
  requireCondition(workflow.jobs.compare.steps.filter((step) =>
    actionName(step.uses) === 'actions/download-artifact').length === 2,
  'comparison must download both builder artifacts');
  const comparisonStep = workflow.jobs.compare.steps.find((step) =>
    step.name === 'Compare exact OCI archive and receipt bytes');
  requireCondition(typeof comparisonStep?.run === 'string' && [
    '--github-repository "$GITHUB_REPOSITORY"',
    '--github-ref-type "$GITHUB_REF_TYPE"',
    '--github-ref-name "$GITHUB_REF_NAME"',
    '--github-sha "$GITHUB_SHA"',
  ].every((argument) => comparisonStep.run.includes(argument)),
  'hosted receipt must bind complete GitHub source context');

  for (const forbidden of [
    /pull_request_target/u, /self-hosted/u, /secrets\s*[.[]/u,
    /(?:packages|pull-requests|contents)\s*:\s*write/iu,
    /\bgh\s+release\b/iu, /\bdocker\s+push\b/iu, /\bnpm\s+publish\b/iu,
    /\bcosign\s+sign\b/iu,
  ]) {
    requireCondition(!forbidden.test(workflowSource),
      `workflow contains forbidden authority or execution pattern ${forbidden}`);
  }
  requireCondition((workflowSource.match(/^\s+id-token:\s*write\s*$/gmu) || []).length === 1 &&
    (workflowSource.match(/^\s+attestations:\s*write\s*$/gmu) || []).length === 1,
  'provenance OIDC and attestation write permissions must appear exactly once');
  requireCondition((workflowSource.match(/actions\/attest@[a-f0-9]{40}/gu) || []).length === 1,
    'exactly one pinned hosted provenance action is required');
  requireCondition(workflowSource.includes('docker run --rm --network none --read-only') &&
    workflowSource.includes('--cap-drop ALL') &&
    workflowSource.includes('--security-opt no-new-privileges'),
  'builder container isolation flags are incomplete');
}

function validateVerificationReceipt(contract, repositoryRoot) {
  if (contract.activation.state !== ACTIVATABLE) return null;
  const receiptPath = path.resolve(repositoryRoot, contract.builder_image.verification_receipt);
  const receipt = readJson(receiptPath, 'builder-image verification receipt');
  exactKeys(receipt, [
    'schema_version', 'classification', 'repository', 'reference', 'digest', 'platform',
    'registry', 'verified_at', 'verification_methods', 'release_admitted', 'publishable',
  ], 'builder-image verification receipt');
  const match = IMAGE_REFERENCE.exec(contract.builder_image.reference);
  requireCondition(receipt.schema_version === 1 &&
    receipt.classification === 'routesphere-bonvoyage-oss-oci-builder-image-verification' &&
    receipt.repository === contract.builder_image.repository &&
    receipt.reference === contract.builder_image.reference && receipt.digest === match[2] &&
    receipt.platform === contract.execution.platform && receipt.registry === 'ghcr.io' &&
    Number.isFinite(Date.parse(receipt.verified_at)) &&
    JSON.stringify(receipt.verification_methods) ===
      JSON.stringify(['registry-manifest', 'anonymous-pull', 'local-image-inspect']) &&
    receipt.release_admitted === false && receipt.publishable === false,
  'builder-image verification receipt does not satisfy the contract');
  return {path: contract.builder_image.verification_receipt, sha256: sha256File(receiptPath)};
}

function validateImageInspection(contract, inspection) {
  requireCondition(contract.activation.state === ACTIVATABLE,
    'builder image inspection requires an activatable contract');
  const records = requireArray(inspection, 'Docker image inspection');
  requireCondition(records.length === 1, 'exactly one Docker image inspection is required');
  const record = requireObject(records[0], 'Docker image inspection record');
  const match = IMAGE_REFERENCE.exec(contract.builder_image.reference);
  requireCondition(record.Os === 'linux' && record.Architecture === 'amd64',
    'builder image platform must be linux/amd64');
  requireCondition(Array.isArray(record.RepoDigests) &&
    record.RepoDigests.includes(contract.builder_image.reference),
  'pulled builder image does not expose the contracted repository digest');
  requireCondition(typeof record.Id === 'string' && /^sha256:[a-f0-9]{64}$/u.test(record.Id),
    'pulled builder image ID is invalid');
  return {
    schema_version: 1,
    classification: IMAGE_OBSERVATION_CLASSIFICATION,
    repository: contract.builder_image.repository,
    reference: contract.builder_image.reference,
    manifest_digest: match[2],
    image_id: record.Id,
    platform: contract.execution.platform,
    externally_resolved: true,
    release_admitted: false,
    publishable: false,
  };
}

function validateRuntimeSource(contract, options) {
  const supplied = [
    options.githubRepository, options.githubRefType, options.githubRefName, options.githubSha,
  ];
  if (supplied.every((value) => value === undefined)) return;
  requireCondition(supplied.every((value) => typeof value === 'string' && value.length > 0),
    'complete GitHub source context is required');
  requireCondition(options.githubRepository === PUBLIC_REPOSITORY_SLUG &&
    options.githubRefType === contract.source.ref_type &&
    new RegExp(contract.source.tag_pattern, 'u').test(options.githubRefName) &&
    COMMIT.test(options.githubSha), 'GitHub source context is not an approved tagged public commit');
}

function hostedReceipt(contract, technicalReceipt, options) {
  requireCondition(contract.activation.state === ACTIVATABLE,
    'hosted reproducibility requires an activatable contract');
  requireCondition(technicalReceipt.classification ===
    'routesphere-bonvoyage-oss-oci-reproducibility' &&
    technicalReceipt.outcome === 'byte-identical-technical-candidates' &&
    technicalReceipt.technical_reproducibility_observed === true &&
    technicalReceipt.hosted_builder_independence_qualified === false &&
    technicalReceipt.release_admitted === false && technicalReceipt.publishable === false,
  'technical reproducibility receipt is not an accepted powerless input');
  requireCondition(technicalReceipt.source?.repository === PUBLIC_REPOSITORY &&
    technicalReceipt.source?.commit === options.githubSha &&
    technicalReceipt.source?.tag === options.githubRefName &&
    technicalReceipt.source?.dirty === false,
  'technical receipt source does not match the hosted run');
  requireCondition(technicalReceipt.platform?.architecture === 'amd64' &&
    technicalReceipt.platform?.os === 'linux' &&
    typeof technicalReceipt.version === 'string' &&
    options.githubRefName === `v${technicalReceipt.version}`,
  'technical receipt platform or version does not match the hosted tag');
  requireCondition(technicalReceipt.builder_image === contract.builder_image.reference,
    'technical receipt builder image does not match the hosted contract');
  requireCondition(Array.isArray(technicalReceipt.builders) &&
    technicalReceipt.builders.length === 2 &&
    new Set(technicalReceipt.builders).size === 2,
  'two distinct technical builders are required');
  exactKeys(technicalReceipt.archive, ['path', 'bytes', 'sha256'],
    'technical receipt archive');
  requireCondition(typeof technicalReceipt.archive.path === 'string' &&
    /^bonvoyage-gateway-[0-9A-Za-z.-]+-linux-amd64[.]oci[.]tar$/u
      .test(technicalReceipt.archive.path) &&
    technicalReceipt.archive.path ===
      `bonvoyage-gateway-${technicalReceipt.version}-linux-amd64.oci.tar` &&
    Number.isSafeInteger(technicalReceipt.archive.bytes) &&
    technicalReceipt.archive.bytes > 0 && SHA256.test(technicalReceipt.archive.sha256),
  'technical receipt OCI archive identity is invalid');
  for (const name of ['manifest', 'config']) {
    exactKeys(technicalReceipt[name], ['bytes', 'digest'], `technical receipt ${name}`);
    requireCondition(Number.isSafeInteger(technicalReceipt[name].bytes) &&
      technicalReceipt[name].bytes > 0 &&
      /^sha256:[a-f0-9]{64}$/u.test(technicalReceipt[name].digest),
    `technical receipt ${name} identity is invalid`);
  }
  exactKeys(technicalReceipt.layer, ['bytes', 'digest', 'diff_id'],
    'technical receipt layer');
  requireCondition(Number.isSafeInteger(technicalReceipt.layer.bytes) &&
    technicalReceipt.layer.bytes > 0 &&
    /^sha256:[a-f0-9]{64}$/u.test(technicalReceipt.layer.digest) &&
    /^sha256:[a-f0-9]{64}$/u.test(technicalReceipt.layer.diff_id),
  'technical receipt layer identity is invalid');
  for (const [label, digest] of [
    ['first artifact digest', options.firstArtifactDigest],
    ['second artifact digest', options.secondArtifactDigest],
    ['technical receipt digest', options.technicalReceiptSha256],
  ]) requireCondition(SHA256.test(digest), `${label} must be a lowercase SHA-256 digest`);
  requireCondition(options.firstArtifactDigest !== options.secondArtifactDigest,
    'two distinct uploaded evidence artifacts are required');
  requireCondition(/^[1-9][0-9]*$/u.test(options.githubRunId) &&
    /^[1-9][0-9]*$/u.test(options.githubRunAttempt) && COMMIT.test(options.githubSha) &&
    new RegExp(contract.source.tag_pattern, 'u').test(options.githubRefName),
  'hosted run identity is invalid');
  return {
    schema_version: 1,
    classification: HOSTED_RECEIPT_CLASSIFICATION,
    outcome: 'byte-identical-hosted-technical-candidates',
    source: {
      repository: PUBLIC_REPOSITORY,
      commit: options.githubSha,
      tag: options.githubRefName,
      dirty: false,
    },
    workflow: {
      name: 'OSS OCI Reproducibility Candidate',
      run_id: options.githubRunId,
      run_attempt: options.githubRunAttempt,
      jobs: ['build-a', 'build-b', 'compare'],
    },
    builder_image: contract.builder_image.reference,
    evidence_artifacts: [
      {name: 'oss-oci-build-a', sha256: options.firstArtifactDigest},
      {name: 'oss-oci-build-b', sha256: options.secondArtifactDigest},
    ],
    technical_receipt_sha256: options.technicalReceiptSha256,
    archive: technicalReceipt.archive,
    manifest: technicalReceipt.manifest,
    config: technicalReceipt.config,
    layer: technicalReceipt.layer,
    technical_reproducibility_observed: true,
    hosted_builder_independence_qualified: true,
    release_admitted: false,
    publishable: false,
  };
}

function parseArguments(argv) {
  const options = {};
  const mapping = {
    '--contract': 'contract', '--workflow': 'workflow',
    '--github-repository': 'githubRepository', '--github-ref-type': 'githubRefType',
    '--github-ref-name': 'githubRefName', '--github-sha': 'githubSha',
    '--github-output': 'githubOutput', '--image-inspection': 'imageInspection',
    '--image-observation': 'imageObservation', '--technical-receipt': 'technicalReceipt',
    '--first-artifact-digest': 'firstArtifactDigest',
    '--second-artifact-digest': 'secondArtifactDigest', '--github-run-id': 'githubRunId',
    '--github-run-attempt': 'githubRunAttempt', '--hosted-receipt': 'hostedReceipt',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--require-activatable') {
      options.requireActivatable = true;
      continue;
    }
    requireCondition(mapping[argument] !== undefined && index + 1 < argv.length,
      `unsupported or incomplete argument ${argument}`);
    options[mapping[argument]] = argv[index + 1];
    index += 1;
  }
  return options;
}

export function verifyHostedBuildContract(contractPath, workflowPath, options = {}) {
  const repositoryRoot = path.resolve(path.dirname(contractPath), '..', '..', '..');
  const contract = readJson(contractPath, 'hosted-build contract');
  const workflowSource = fs.readFileSync(workflowPath, 'utf8');
  const workflow = readYaml(workflowPath, 'hosted-build workflow template');
  const state = validateContract(contract);
  validateWorkflow(contract, workflow, workflowSource);
  validateRuntimeSource(contract, options);
  const verificationReceipt = validateVerificationReceipt(contract, repositoryRoot);
  const activeWorkflowPath = path.resolve(repositoryRoot,
    contract.activation.active_workflow_path);
  if (!state.active) {
    requireCondition(!fs.existsSync(activeWorkflowPath),
      'blocked hosted-build contract must not have an active GitHub workflow');
  }
  if (options.githubRepository !== undefined) {
    requireCondition(fs.existsSync(activeWorkflowPath) &&
      fs.statSync(activeWorkflowPath).isFile() &&
      sha256File(activeWorkflowPath) === sha256File(workflowPath),
    'active hosted workflow must exactly match the reviewed template');
  }
  if (options.requireActivatable) {
    requireCondition(state.active, 'hosted-build contract is not activatable');
  }
  return {
    contract,
    result: {
      schema_version: 1,
      classification: RESULT_CLASSIFICATION,
      outcome: state.active ? 'activatable' : 'blocked',
      activation_state: contract.activation.state,
      activation_ready: state.active,
      blockers: state.active ? [] : [
        'public repository not created',
        'digest-pinned public builder image not externally verified',
        'protected release environment settings not verified',
      ],
      contract_sha256: sha256File(contractPath),
      workflow_template_sha256: sha256File(workflowPath),
      builder_image_verification: verificationReceipt,
      provenance_created: true,
      release_admitted: false,
      publishable: false,
    },
  };
}

function writeNewJson(filePath, value) {
  requireCondition(!fs.existsSync(filePath), `${filePath} must be a new output`);
  fs.mkdirSync(path.dirname(filePath), {recursive: true});
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, {flag: 'wx', mode: 0o600});
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  try {
    const options = parseArguments(process.argv.slice(2));
    requireCondition(options.contract && options.workflow,
      '--contract and --workflow are required');
    const {contract, result} = verifyHostedBuildContract(
      path.resolve(options.contract), path.resolve(options.workflow), options);
    if (options.githubOutput) {
      requireCondition(contract.builder_image.reference !== null,
        'activatable builder image is required for GitHub output');
      fs.appendFileSync(options.githubOutput,
        `builder_image=${contract.builder_image.reference}\n`, {encoding: 'utf8'});
    }
    if (options.imageInspection || options.imageObservation) {
      requireCondition(options.imageInspection && options.imageObservation,
        'both --image-inspection and --image-observation are required');
      const observation = validateImageInspection(contract,
        readJsonValue(path.resolve(options.imageInspection), 'Docker image inspection'));
      writeNewJson(path.resolve(options.imageObservation), observation);
    }
    if (options.technicalReceipt || options.hostedReceipt) {
      requireCondition(options.technicalReceipt && options.hostedReceipt,
        'both --technical-receipt and --hosted-receipt are required');
      const technicalPath = path.resolve(options.technicalReceipt);
      const receipt = hostedReceipt(contract,
        readJson(technicalPath, 'technical reproducibility receipt'), {
          ...options,
          technicalReceiptSha256: sha256File(technicalPath),
        });
      writeNewJson(path.resolve(options.hostedReceipt), receipt);
    }
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`OSS hosted OCI build contract rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}

export {hostedReceipt, validateImageInspection};
