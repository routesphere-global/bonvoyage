#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import yaml from 'js-yaml';

const CLASSIFICATION = 'routesphere-bonvoyage-oss-release-identity-workflow-contract';
const RESULT_CLASSIFICATION =
  'routesphere-bonvoyage-oss-release-identity-workflow-contract-result';
const REPOSITORY = 'https://github.com/routesphere-global/bonvoyage';
const REPOSITORY_SLUG = 'routesphere-global/bonvoyage';
const TAG = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const PINNED_ACTION = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[a-f0-9]{40}$/u;
const ACTIONS = Object.freeze({
  checkout: 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
  setup_node: 'actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1',
  download_artifact:
    'actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333',
  cosign_installer:
    'sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6',
  upload_artifact:
    'actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9',
});
const VERIFY_COMMAND = [
  'node scripts/verify-oss-release-workflow.mjs',
  '--contract packaging/release/oss-release-identity-workflow-contract.json',
  '--workflow .github/workflows/release.yml',
  '--github-repository "$GITHUB_REPOSITORY"',
  '--github-ref-type "$GITHUB_REF_TYPE"',
  '--github-ref-name "$GITHUB_REF_NAME"',
  '--github-sha "$GITHUB_SHA"',
].join(' ');
const DISCOVER_COMMAND = [
  'node scripts/discover-oss-release-candidate-runs.mjs',
  '--repository "$GITHUB_REPOSITORY"',
  '--tag "$GITHUB_REF_NAME"',
  '--commit "$GITHUB_SHA"',
  '--current-run-id "$GITHUB_RUN_ID"',
  '--github-output "$GITHUB_OUTPUT"',
].join(' ');
const INTAKE_COMMAND = [
  'node scripts/intake-oss-release-candidate.mjs',
  '--deb-root "$RUNNER_TEMP/release-candidate-input/debian"',
  '--oci-root "$RUNNER_TEMP/release-candidate-input/oci"',
  '--output "$RUNNER_TEMP/release-candidate-intake"',
  '--source-commit "$GITHUB_SHA"',
  '--source-tag "$GITHUB_REF_NAME"',
  '--deb-run-id "${{ steps.candidate-runs.outputs.deb_run_id }}"',
  '--oci-run-id "${{ steps.candidate-runs.outputs.oci_run_id }}"',
  '--created-at "${{ steps.candidate-runs.outputs.created_at }}"',
].join(' ');
const PROBE_COMMAND = [
  'node scripts/create-oss-release-identity-probe.mjs',
  '--output "$RUNNER_TEMP/release-identity-probe/identity-probe.json"',
  '--repository "$GITHUB_REPOSITORY"',
  '--ref-type "$GITHUB_REF_TYPE"',
  '--tag "$GITHUB_REF_NAME"',
  '--commit "$GITHUB_SHA"',
  '--run-id "$GITHUB_RUN_ID"',
  '--run-attempt "$GITHUB_RUN_ATTEMPT"',
].join(' ');
const SIGN_AND_VERIFY_COMMAND = [
  'cosign sign-blob --yes --oidc-provider github-actions --bundle \\',
  '  "$RUNNER_TEMP/release-identity-probe/identity-probe.sigstore.json" \\',
  '  "$RUNNER_TEMP/release-identity-probe/identity-probe.json"',
  'cosign verify-blob --bundle \\',
  '  "$RUNNER_TEMP/release-identity-probe/identity-probe.sigstore.json" \\',
  '  --certificate-identity "$EXPECTED_IDENTITY" \\',
  '  --certificate-oidc-issuer "$EXPECTED_ISSUER" \\',
  '  --certificate-github-workflow-repository "$GITHUB_REPOSITORY" \\',
  '  --certificate-github-workflow-sha "$GITHUB_SHA" \\',
  '  --certificate-github-workflow-ref "$GITHUB_REF" \\',
  '  --certificate-github-workflow-trigger "$GITHUB_EVENT_NAME" \\',
  '  "$RUNNER_TEMP/release-identity-probe/identity-probe.json" \\',
  '  > "$RUNNER_TEMP/release-identity-probe/verification.txt"',
  'cosign version --json \\',
  '  > "$RUNNER_TEMP/release-identity-probe/cosign-version.json"',
  'sha256sum \\',
  '  "$RUNNER_TEMP/release-identity-probe/identity-probe.json" \\',
  '  "$RUNNER_TEMP/release-identity-probe/identity-probe.sigstore.json" \\',
  '  "$RUNNER_TEMP/release-identity-probe/verification.txt" \\',
  '  "$RUNNER_TEMP/release-identity-probe/cosign-version.json" \\',
  '  > "$RUNNER_TEMP/release-identity-probe/sha256sums.txt"',
].join('\n');

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
    return requireObject(JSON.parse(fs.readFileSync(filePath, 'utf8')), label);
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
}

function readYaml(filePath, label) {
  try {
    return requireObject(yaml.load(fs.readFileSync(filePath, 'utf8')), label);
  } catch (error) {
    fail(`${label} is not valid YAML: ${error.message}`);
  }
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function validateContract(contract) {
  exactKeys(contract, [
    'schema_version', 'classification', 'state', 'source', 'execution',
    'actions', 'candidate_intake', 'identity', 'authority',
  ], 'contract');
  requireCondition(contract.schema_version === 1 &&
    contract.classification === CLASSIFICATION &&
    contract.state === 'candidate-intake-foundation',
  'unsupported release workflow contract');

  exactKeys(contract.source, [
    'repository', 'event', 'ref_type', 'tag_pattern', 'protected_tag_required',
    'pushed_commit_required', 'clean_checkout_required',
  ], 'contract.source');
  requireCondition(contract.source.repository === REPOSITORY &&
    contract.source.event === 'workflow_dispatch' &&
    contract.source.ref_type === 'tag', 'release identity source must be manual tag-only');
  requireCondition(contract.source.tag_pattern === TAG.source &&
    contract.source.protected_tag_required === true &&
    contract.source.pushed_commit_required === true &&
    contract.source.clean_checkout_required === true,
  'release identity source protections changed');

  exactKeys(contract.execution, [
    'environment', 'runner', 'workflow_permissions', 'job_permissions', 'jobs',
    'artifact_retention_days', 'maximum_billable_job_minutes', 'manual_only',
    'scheduled_runs', 'self_hosted_runners', 'cancel_in_progress',
  ], 'contract.execution');
  requireCondition(contract.execution.environment === 'release' &&
    contract.execution.runner === 'ubuntu-24.04', 'unexpected release execution target');
  requireCondition(JSON.stringify(contract.execution.workflow_permissions) ===
    JSON.stringify({contents: 'read'}), 'workflow permissions must remain read-only');
  requireCondition(JSON.stringify(contract.execution.job_permissions) === JSON.stringify({
    preflight: {contents: 'read'},
    'candidate-intake': {contents: 'read', actions: 'read'},
    'identity-probe': {contents: 'read', 'id-token': 'write'},
  }), 'job permissions exceed the candidate intake foundation');
  requireCondition(JSON.stringify(contract.execution.jobs) === JSON.stringify({
    preflight: {timeout_minutes: 5},
    'candidate-intake': {timeout_minutes: 20},
    'identity-probe': {timeout_minutes: 10},
  }), 'unexpected release job budget');
  requireCondition(contract.execution.artifact_retention_days === 3 &&
    contract.execution.maximum_billable_job_minutes === 35 &&
    contract.execution.manual_only === true &&
    contract.execution.scheduled_runs === false &&
    contract.execution.self_hosted_runners === false &&
    contract.execution.cancel_in_progress === false,
  'release cost or execution boundary changed');

  exactKeys(contract.actions, [
    'checkout', 'setup_node', 'download_artifact', 'cosign_installer',
    'upload_artifact',
  ], 'contract.actions');
  for (const [name, action] of Object.entries(contract.actions)) {
    requireCondition(typeof action === 'string' && PINNED_ACTION.test(action),
      `contract action ${name} must be pinned to a full commit`);
  }
  requireCondition(JSON.stringify(contract.actions) === JSON.stringify(ACTIONS),
    'release action identities changed');

  exactKeys(contract.candidate_intake, [
    'contract_path', 'discovery_script', 'intake_script', 'workflow_files',
    'workflow_names', 'artifact_names', 'download_root', 'output_path',
    'output_artifact', 'exact_source_required', 'required_run_attempt',
    'caller_selected_run_ids_allowed',
  ], 'contract.candidate_intake');
  exactKeys(contract.candidate_intake.workflow_files, ['debian', 'oci'],
    'contract.candidate_intake.workflow_files');
  exactKeys(contract.candidate_intake.workflow_names, ['debian', 'oci'],
    'contract.candidate_intake.workflow_names');
  exactKeys(contract.candidate_intake.artifact_names, ['debian', 'oci'],
    'contract.candidate_intake.artifact_names');
  requireCondition(contract.candidate_intake.contract_path ===
    'packaging/release/oss-candidate-intake-contract.json' &&
    contract.candidate_intake.discovery_script ===
      'scripts/discover-oss-release-candidate-runs.mjs' &&
    contract.candidate_intake.intake_script ===
      'scripts/intake-oss-release-candidate.mjs' &&
    JSON.stringify(contract.candidate_intake.workflow_files) === JSON.stringify({
      debian: '.github/workflows/oss-deb-reproducibility.yml',
      oci: '.github/workflows/oss-oci-reproducibility.yml',
    }) &&
    JSON.stringify(contract.candidate_intake.workflow_names) === JSON.stringify({
      debian: 'OSS Debian Reproducibility Candidate',
      oci: 'OSS OCI Reproducibility Candidate',
    }) &&
    JSON.stringify(contract.candidate_intake.artifact_names) === JSON.stringify({
      debian: ['oss-deb-build-a', 'oss-deb-build-b', 'oss-deb-comparison'],
      oci: ['oss-oci-build-a', 'oss-oci-build-b', 'oss-oci-comparison'],
    }) &&
    contract.candidate_intake.download_root ===
      '${{ runner.temp }}/release-candidate-input' &&
    contract.candidate_intake.output_path ===
      '${{ runner.temp }}/release-candidate-intake' &&
    contract.candidate_intake.output_artifact ===
      'oss-release-candidate-intake' &&
    contract.candidate_intake.exact_source_required === true &&
    contract.candidate_intake.required_run_attempt === 1 &&
    contract.candidate_intake.caller_selected_run_ids_allowed === false,
  'candidate intake boundary changed');

  exactKeys(contract.identity, [
    'issuer', 'subject_prefix', 'cosign_version', 'probe_classification',
    'probe_path', 'bundle_path', 'verification_required',
    'caller_selected_payload_allowed',
  ], 'contract.identity');
  requireCondition(contract.identity.issuer ===
    'https://token.actions.githubusercontent.com' &&
    contract.identity.subject_prefix ===
      `${REPOSITORY}/.github/workflows/release.yml@refs/tags/` &&
    contract.identity.cosign_version === 'v3.1.4' &&
    contract.identity.probe_classification ===
      'routesphere-bonvoyage-oss-release-identity-probe' &&
    contract.identity.probe_path ===
      'release-identity-probe/identity-probe.json' &&
    contract.identity.bundle_path ===
      'release-identity-probe/identity-probe.sigstore.json' &&
    contract.identity.verification_required === true &&
    contract.identity.caller_selected_payload_allowed === false,
  'release identity boundary changed');

  exactKeys(contract.authority, [
    'candidate_intake_allowed', 'identity_probe_signature_allowed',
    'product_artifact_signature_allowed', 'product_provenance_allowed',
    'release_admitted', 'publishable', 'github_release_created',
    'package_uploaded', 'container_uploaded',
  ], 'contract.authority');
  requireCondition(contract.authority.candidate_intake_allowed === true &&
    contract.authority.identity_probe_signature_allowed === true,
  'candidate intake and identity probe permissions must remain explicit');
  for (const [field, value] of Object.entries(contract.authority)) {
    if (!['candidate_intake_allowed', 'identity_probe_signature_allowed'].includes(field)) {
      requireCondition(value === false, `${field} must remain false`);
    }
  }
}

function collectUses(workflow) {
  const uses = [];
  for (const job of Object.values(requireObject(workflow.jobs, 'workflow.jobs'))) {
    for (const step of job.steps || []) {
      if (step.uses !== undefined) uses.push(step.uses);
    }
  }
  return uses;
}

function validateCheckoutStep(step, action) {
  exactKeys(step, ['name', 'uses', 'with'], 'checkout step');
  exactKeys(step.with, ['fetch-depth', 'persist-credentials', 'ref'],
    'checkout step inputs');
  requireCondition(step.name ===
    'Check out the exact tagged commit without retained credentials',
  'checkout step name changed');
  requireCondition(step.uses === action, 'checkout action identity changed');
  requireCondition(step.with?.['fetch-depth'] === 0 &&
    step.with?.['persist-credentials'] === false &&
    step.with?.ref === '${{ github.sha }}', 'checkout must bind the exact tag commit');
}

function validateSetupNodeStep(step, action) {
  exactKeys(step, ['name', 'uses', 'with'], 'Node setup step');
  exactKeys(step.with, ['node-version'], 'Node setup inputs');
  requireCondition(step.name === 'Set up Node.js' && step.uses === action &&
    step.with['node-version'] === '22.19.0', 'Node setup boundary changed');
}

function validateRunStep(step, name, command, label) {
  exactKeys(step, ['name', 'run'], label);
  requireCondition(step.name === name && step.run.trimEnd() === command,
    `${label} changed`);
}

function validateDiscoveryStep(step) {
  exactKeys(step, ['name', 'id', 'env', 'run'], 'candidate discovery step');
  exactKeys(step.env, ['GITHUB_TOKEN'], 'candidate discovery environment');
  requireCondition(step.name === 'Discover exact prior candidate workflow runs' &&
    step.id === 'candidate-runs' &&
    step.env.GITHUB_TOKEN === '${{ github.token }}' &&
    step.run.trimEnd() === DISCOVER_COMMAND,
  'candidate run discovery boundary changed');
}

function validateDownloadStep(step, contract, format, artifact, runOutput, label) {
  exactKeys(step, ['name', 'uses', 'with'], label);
  exactKeys(step.with, ['name', 'path', 'github-token', 'repository', 'run-id'],
    `${label} inputs`);
  const title = artifact.endsWith('build-a')
    ? `${format === 'debian' ? 'Debian' : 'OCI'} builder A evidence`
    : artifact.endsWith('build-b')
      ? `${format === 'debian' ? 'Debian' : 'OCI'} builder B evidence`
      : `${format === 'debian' ? 'Debian' : 'OCI'} comparison evidence`;
  requireCondition(step.name === `Download ${title}` &&
    step.uses === contract.actions.download_artifact &&
    step.with.name === artifact &&
    step.with.path === `${contract.candidate_intake.download_root}/${format}/${artifact}` &&
    step.with['github-token'] === '${{ github.token }}' &&
    step.with.repository === '${{ github.repository }}' &&
    step.with['run-id'] === `\${{ steps.candidate-runs.outputs.${runOutput} }}`,
  `${label} boundary changed`);
}

function validateCandidateUploadStep(step, contract) {
  exactKeys(step, ['name', 'uses', 'with'], 'candidate intake upload step');
  exactKeys(step.with, [
    'name', 'path', 'if-no-files-found', 'compression-level', 'overwrite',
    'include-hidden-files', 'retention-days',
  ], 'candidate intake upload inputs');
  requireCondition(step.name === 'Upload bounded non-publishing intake evidence' &&
    step.uses === contract.actions.upload_artifact &&
    step.with.name === contract.candidate_intake.output_artifact &&
    step.with.path === contract.candidate_intake.output_path &&
    step.with['retention-days'] === contract.execution.artifact_retention_days &&
    step.with['if-no-files-found'] === 'error' &&
    step.with['compression-level'] === 0 &&
    step.with.overwrite === false &&
    step.with['include-hidden-files'] === false,
  'candidate intake upload boundary changed');
}

function validateSigningStep(step, contract) {
  exactKeys(step, ['name', 'env', 'run'], 'identity signing step');
  exactKeys(step.env, ['EXPECTED_IDENTITY', 'EXPECTED_ISSUER'],
    'identity signing environment');
  requireCondition(step.name ===
    'Sign and independently verify only the identity probe' &&
    step.env.EXPECTED_IDENTITY ===
      `${contract.identity.subject_prefix}\${{ github.ref_name }}` &&
    step.env.EXPECTED_ISSUER === contract.identity.issuer &&
    step.run.trimEnd() === SIGN_AND_VERIFY_COMMAND,
  'identity signing step changed');
}

function validateUploadStep(step, contract) {
  exactKeys(step, ['name', 'uses', 'with'], 'identity evidence upload step');
  exactKeys(step.with, [
    'name', 'path', 'if-no-files-found', 'compression-level', 'overwrite',
    'include-hidden-files', 'retention-days',
  ], 'identity evidence upload inputs');
  requireCondition(step.name === 'Upload bounded non-publishing identity evidence' &&
    step.uses === contract.actions.upload_artifact &&
    step.with.name === 'oss-release-identity-probe' &&
    step.with.path === '${{ runner.temp }}/release-identity-probe' &&
    step.with['retention-days'] === contract.execution.artifact_retention_days &&
    step.with['if-no-files-found'] === 'error' &&
    step.with['compression-level'] === 0 &&
    step.with.overwrite === false &&
    step.with['include-hidden-files'] === false,
  'identity evidence upload boundary changed');
}

function validateWorkflow(contract, workflow, source) {
  exactKeys(workflow, ['name', 'on', 'permissions', 'concurrency', 'jobs'], 'workflow');
  requireCondition(workflow.name === 'OSS Release Candidate Intake Foundation',
    'unexpected release workflow name');
  requireCondition(JSON.stringify(workflow.on) ===
    JSON.stringify({workflow_dispatch: null}), 'release workflow must be manual only');
  requireCondition(JSON.stringify(workflow.permissions) ===
    JSON.stringify(contract.execution.workflow_permissions),
  'release workflow permissions changed');
  requireCondition(workflow.concurrency?.group ===
    'oss-release-candidate-intake-${{ github.ref }}' &&
    workflow.concurrency?.['cancel-in-progress'] === false,
  'release workflow concurrency changed');

  exactKeys(workflow.jobs, ['preflight', 'candidate-intake', 'identity-probe'],
    'workflow.jobs');
  const preflight = workflow.jobs.preflight;
  const candidate = workflow.jobs['candidate-intake'];
  const identity = workflow.jobs['identity-probe'];
  exactKeys(preflight, [
    'name', 'runs-on', 'timeout-minutes', 'environment', 'permissions', 'steps',
  ], 'preflight job');
  exactKeys(candidate, [
    'name', 'needs', 'runs-on', 'timeout-minutes', 'environment', 'permissions',
    'steps',
  ], 'candidate-intake job');
  exactKeys(identity, [
    'name', 'needs', 'runs-on', 'timeout-minutes', 'environment', 'permissions',
    'steps',
  ], 'identity-probe job');
  requireCondition(preflight.name === 'Protected candidate intake preflight' &&
    candidate.name === 'Replay exact hosted candidate intake' &&
    identity.name === 'Verify keyless workflow identity',
  'release workflow job names changed');
  for (const [name, job] of Object.entries(workflow.jobs)) {
    requireCondition(job['runs-on'] === contract.execution.runner &&
      job.environment === contract.execution.environment &&
      job['timeout-minutes'] === contract.execution.jobs[name].timeout_minutes,
    `workflow job ${name} execution boundary changed`);
    requireCondition(JSON.stringify(job.permissions) ===
      JSON.stringify(contract.execution.job_permissions[name]),
    `workflow job ${name} permissions changed`);
    requireCondition(Array.isArray(job.steps) && job.steps.length > 0,
      `workflow job ${name} requires steps`);
  }
  requireCondition(candidate.needs === 'preflight' &&
    identity.needs === 'candidate-intake',
  'candidate intake and identity probe dependency order changed');
  requireCondition(preflight.steps.length === 4 &&
    candidate.steps.length === 13 && identity.steps.length === 8,
    'release workflow step set changed');

  validateCheckoutStep(preflight.steps[0], contract.actions.checkout);
  validateSetupNodeStep(preflight.steps[1], contract.actions.setup_node);
  validateRunStep(preflight.steps[2],
    'Install locked release-verifier dependencies', 'npm ci --ignore-scripts',
    'preflight dependency step');
  validateRunStep(preflight.steps[3],
    'Verify the protected manual tag and powerless workflow contract',
    VERIFY_COMMAND, 'preflight verification step');

  validateCheckoutStep(candidate.steps[0], contract.actions.checkout);
  validateSetupNodeStep(candidate.steps[1], contract.actions.setup_node);
  validateRunStep(candidate.steps[2],
    'Install locked release-verifier dependencies', 'npm ci --ignore-scripts',
    'candidate intake dependency step');
  validateRunStep(candidate.steps[3],
    'Reverify the workflow before reading hosted evidence',
    VERIFY_COMMAND, 'candidate intake verification step');
  validateDiscoveryStep(candidate.steps[4]);
  let stepIndex = 5;
  for (const format of ['debian', 'oci']) {
    const runOutput = format === 'debian' ? 'deb_run_id' : 'oci_run_id';
    for (const artifact of contract.candidate_intake.artifact_names[format]) {
      validateDownloadStep(candidate.steps[stepIndex], contract, format, artifact,
        runOutput, `candidate download step ${stepIndex}`);
      stepIndex += 1;
    }
  }
  validateRunStep(candidate.steps[11],
    'Replay the fail-closed candidate intake', INTAKE_COMMAND,
    'candidate intake replay step');
  validateCandidateUploadStep(candidate.steps[12], contract);

  validateCheckoutStep(identity.steps[0], contract.actions.checkout);
  validateSetupNodeStep(identity.steps[1], contract.actions.setup_node);
  validateRunStep(identity.steps[2],
    'Install locked release-verifier dependencies', 'npm ci --ignore-scripts',
    'identity dependency step');
  validateRunStep(identity.steps[3],
    'Reverify the workflow before requesting an identity token',
    VERIFY_COMMAND, 'identity verification step');
  validateRunStep(identity.steps[4],
    'Create the fixed non-release identity probe', PROBE_COMMAND,
    'identity probe generation step');
  exactKeys(identity.steps[5], ['name', 'uses', 'with'],
    'Cosign installation step');
  exactKeys(identity.steps[5].with, ['cosign-release'],
    'Cosign installation inputs');
  requireCondition(identity.steps[5].name ===
    'Install the pinned keyless signing client' &&
    identity.steps[5].uses === contract.actions.cosign_installer &&
    identity.steps[5].with['cosign-release'] === contract.identity.cosign_version,
  'Cosign installation boundary changed');
  validateSigningStep(identity.steps[6], contract);
  validateUploadStep(identity.steps[7], contract);
  const uses = collectUses(workflow);
  const expectedUses = [
    contract.actions.checkout,
    contract.actions.setup_node,
    contract.actions.checkout,
    contract.actions.setup_node,
    contract.actions.download_artifact,
    contract.actions.download_artifact,
    contract.actions.download_artifact,
    contract.actions.download_artifact,
    contract.actions.download_artifact,
    contract.actions.download_artifact,
    contract.actions.upload_artifact,
    contract.actions.checkout,
    contract.actions.setup_node,
    contract.actions.cosign_installer,
    contract.actions.upload_artifact,
  ];
  requireCondition(JSON.stringify(uses) === JSON.stringify(expectedUses),
    'release workflow action set or order changed');
  requireCondition(uses.every((action) => PINNED_ACTION.test(action)),
    'release workflow contains an unpinned action');

  const normalized = source.toLowerCase();
  const forbidden = [
    '${{ secrets.', 'contents: write', 'packages: write', 'attestations: write',
    'pull-requests: write', 'deployments: write', 'actions: write',
    'gh release', 'docker push', 'npm publish', 'cosign sign ',
    'actions/attest', 'softprops/action-gh-release', 'create-release',
  ];
  for (const value of forbidden) {
    requireCondition(!normalized.includes(value),
      `release candidate foundation contains forbidden authority: ${value}`);
  }
  requireCondition((source.match(/^\s+actions:\s*read\s*$/gmu) || []).length === 1,
    'GitHub Actions read authority must appear exactly once');
  requireCondition((source.match(/id-token:\s*write/gu) || []).length === 1,
    'OIDC authority must appear exactly once');
  requireCondition((source.match(/\$\{\{ github\.token \}\}/gu) || []).length === 7,
    'ephemeral GitHub token use must remain limited to discovery and six downloads');
  requireCondition(source.includes(
    'cosign sign-blob --yes --oidc-provider github-actions --bundle') &&
    source.includes('cosign verify-blob --bundle') &&
    source.includes('--certificate-github-workflow-repository "$GITHUB_REPOSITORY"') &&
    source.includes('--certificate-github-workflow-sha "$GITHUB_SHA"') &&
    source.includes('--certificate-github-workflow-ref "$GITHUB_REF"') &&
    source.includes('--certificate-github-workflow-trigger "$GITHUB_EVENT_NAME"') &&
    source.includes(contract.identity.issuer) &&
    source.includes(contract.identity.subject_prefix) &&
    source.includes(contract.identity.probe_path) &&
    source.includes(contract.identity.bundle_path),
  'identity probe signing or verification command changed');
  requireCondition(!source.includes('${{ inputs.') &&
    !source.includes('workflow_dispatch:\n    inputs:'),
  'caller-selected release inputs are forbidden');

}

function validateRuntimeSource(contract, options) {
  const supplied = [
    options.githubRepository, options.githubRefType, options.githubRefName,
    options.githubSha,
  ];
  if (supplied.every((value) => value === undefined)) return;
  requireCondition(supplied.every((value) => value !== undefined),
    'complete GitHub source context is required');
  requireCondition(options.githubRepository === REPOSITORY_SLUG &&
    options.githubRefType === 'tag' && TAG.test(options.githubRefName) &&
    COMMIT.test(options.githubSha), 'release workflow requires a tagged public commit');
  requireCondition(new RegExp(contract.source.tag_pattern, 'u').test(options.githubRefName),
    'runtime tag does not match the release contract');
}

function parseArguments(argv) {
  const mapping = {
    '--contract': 'contract',
    '--workflow': 'workflow',
    '--github-repository': 'githubRepository',
    '--github-ref-type': 'githubRefType',
    '--github-ref-name': 'githubRefName',
    '--github-sha': 'githubSha',
  };
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const key = mapping[argv[index]];
    requireCondition(key !== undefined && index + 1 < argv.length,
      `unsupported or incomplete argument ${argv[index]}`);
    options[key] = argv[index + 1];
    index += 1;
  }
  return options;
}

export function verifyReleaseWorkflow(contractPath, workflowPath, options = {}) {
  const contract = readJson(contractPath, 'release workflow contract');
  const workflow = readYaml(workflowPath, 'release workflow');
  const source = fs.readFileSync(workflowPath, 'utf8');
  validateContract(contract);
  validateWorkflow(contract, workflow, source);
  validateRuntimeSource(contract, options);
  return {
    schema_version: 1,
    classification: RESULT_CLASSIFICATION,
    state: contract.state,
    contract_sha256: sha256File(contractPath),
    workflow_sha256: sha256File(workflowPath),
    identity_subject_prefix: contract.identity.subject_prefix,
    candidate_intake_allowed: true,
    identity_probe_signature_allowed: true,
    product_artifact_signature_allowed: false,
    product_provenance_allowed: false,
    release_admitted: false,
    publishable: false,
  };
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  try {
    const options = parseArguments(process.argv.slice(2));
    requireCondition(options.contract && options.workflow,
      '--contract and --workflow are required');
    const result = verifyReleaseWorkflow(
      path.resolve(options.contract), path.resolve(options.workflow), options);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`OSS release candidate workflow rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}
