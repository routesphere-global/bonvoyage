#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

import yaml from 'js-yaml';

const CLASSIFICATION =
  'routesphere-bonvoyage-oss-product-signing-workflow-contract';
const REPOSITORY = 'https://github.com/routesphere-global/bonvoyage';
const REPOSITORY_SLUG = 'routesphere-global/bonvoyage';
const TAG = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const PINNED_ACTION = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[a-f0-9]{40}$/u;
const ACTIONS = Object.freeze({
  checkout: 'actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803',
  setup_node: 'actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38',
  download_artifact:
    'actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53',
  cosign_installer:
    'sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6',
  upload_artifact: 'actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4',
});
const VERIFY_WORKFLOW = [
  'node scripts/verify-oss-product-signing-workflow.mjs',
  '--contract packaging/release/oss-product-signing-workflow-contract.json',
  '--workflow .github/workflows/oss-product-signing.yml',
  '--github-repository "$GITHUB_REPOSITORY"',
  '--github-ref-type "$GITHUB_REF_TYPE"',
  '--github-ref-name "$GITHUB_REF_NAME"',
  '--github-ref-protected "$GITHUB_REF_PROTECTED"',
  '--github-sha "$GITHUB_SHA"',
].join(' ');
const DISCOVER = [
  'node scripts/discover-oss-product-signing-input.mjs',
  '--repository "$GITHUB_REPOSITORY"', '--tag "$GITHUB_REF_NAME"',
  '--commit "$GITHUB_SHA"', '--current-run-id "$GITHUB_RUN_ID"',
  '--github-output "$GITHUB_OUTPUT"',
].join(' ');
const PREPARE = [
  'node scripts/prepare-oss-product-signatures.mjs',
  '--intake-root "$RUNNER_TEMP/product-signing-candidate"',
  '--output "$RUNNER_TEMP/product-signature-evidence"',
  '--source-commit "$GITHUB_SHA"', '--source-tag "$GITHUB_REF_NAME"',
  '--current-run-id "$GITHUB_RUN_ID"',
  '--candidate-run-id "${{ needs.preflight.outputs.candidate_run_id }}"',
  '--created-at "$(node -e \'process.stdout.write(new Date().toISOString())\')"',
  '--github-output "$GITHUB_OUTPUT"',
].join(' ');
const FINALIZE = [
  'node scripts/finalize-oss-product-signatures.mjs',
  '--intake-root "$RUNNER_TEMP/product-signing-candidate"',
  '--evidence-root "$RUNNER_TEMP/product-signature-evidence"',
  '--created-at "$(node -e \'process.stdout.write(new Date().toISOString())\')"',
  '--cosign cosign',
].join(' ');
const INDEPENDENT_VERIFY = [
  'node scripts/verify-oss-product-signatures.mjs',
  '--intake-root "$RUNNER_TEMP/product-signing-candidate"',
  '--evidence-root "$RUNNER_TEMP/product-signature-evidence"',
  '--output "$RUNNER_TEMP/product-signature-evidence/independent-verification"',
  '--created-at "$(node -e \'process.stdout.write(new Date().toISOString())\')"',
  '--cosign cosign',
].join(' ');
const SIGN = [
  'cosign sign-blob --yes --oidc-provider github-actions \\\n',
  '  --bundle "$DEBIAN_BUNDLE" "$DEBIAN_ARTIFACT"\n',
  'cosign sign-blob --yes --oidc-provider github-actions \\\n',
  '  --bundle "$OCI_BUNDLE" "$OCI_ARTIFACT"\n',
].join('');
const SIGNING_VERIFY = [
  'cosign verify-blob --bundle "$DEBIAN_BUNDLE" \\\n',
  '  --certificate-identity "$EXPECTED_IDENTITY" \\\n',
  '  --certificate-oidc-issuer "$EXPECTED_ISSUER" \\\n',
  '  --certificate-github-workflow-repository "$GITHUB_REPOSITORY" \\\n',
  '  --certificate-github-workflow-sha "$GITHUB_SHA" \\\n',
  '  --certificate-github-workflow-ref "$GITHUB_REF" \\\n',
  '  --certificate-github-workflow-trigger "$GITHUB_EVENT_NAME" \\\n',
  '  "$DEBIAN_ARTIFACT" \\\n',
  '  > "$RUNNER_TEMP/product-signature-evidence/signing-verification/gateway-deb-linux-amd64.online.txt"\n',
  'cosign verify-blob --offline=true --bundle "$DEBIAN_BUNDLE" \\\n',
  '  --certificate-identity "$EXPECTED_IDENTITY" \\\n',
  '  --certificate-oidc-issuer "$EXPECTED_ISSUER" \\\n',
  '  --certificate-github-workflow-repository "$GITHUB_REPOSITORY" \\\n',
  '  --certificate-github-workflow-sha "$GITHUB_SHA" \\\n',
  '  --certificate-github-workflow-ref "$GITHUB_REF" \\\n',
  '  --certificate-github-workflow-trigger "$GITHUB_EVENT_NAME" \\\n',
  '  "$DEBIAN_ARTIFACT" \\\n',
  '  > "$RUNNER_TEMP/product-signature-evidence/signing-verification/gateway-deb-linux-amd64.offline.txt"\n',
  'cosign verify-blob --bundle "$OCI_BUNDLE" \\\n',
  '  --certificate-identity "$EXPECTED_IDENTITY" \\\n',
  '  --certificate-oidc-issuer "$EXPECTED_ISSUER" \\\n',
  '  --certificate-github-workflow-repository "$GITHUB_REPOSITORY" \\\n',
  '  --certificate-github-workflow-sha "$GITHUB_SHA" \\\n',
  '  --certificate-github-workflow-ref "$GITHUB_REF" \\\n',
  '  --certificate-github-workflow-trigger "$GITHUB_EVENT_NAME" \\\n',
  '  "$OCI_ARTIFACT" \\\n',
  '  > "$RUNNER_TEMP/product-signature-evidence/signing-verification/gateway-oci-linux-amd64.online.txt"\n',
  'cosign verify-blob --offline=true --bundle "$OCI_BUNDLE" \\\n',
  '  --certificate-identity "$EXPECTED_IDENTITY" \\\n',
  '  --certificate-oidc-issuer "$EXPECTED_ISSUER" \\\n',
  '  --certificate-github-workflow-repository "$GITHUB_REPOSITORY" \\\n',
  '  --certificate-github-workflow-sha "$GITHUB_SHA" \\\n',
  '  --certificate-github-workflow-ref "$GITHUB_REF" \\\n',
  '  --certificate-github-workflow-trigger "$GITHUB_EVENT_NAME" \\\n',
  '  "$OCI_ARTIFACT" \\\n',
  '  > "$RUNNER_TEMP/product-signature-evidence/signing-verification/gateway-oci-linux-amd64.offline.txt"\n',
].join('');

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

function validateContract(contract) {
  exactKeys(contract, [
    'schema_version', 'classification', 'state', 'source', 'execution', 'actions',
    'candidate_intake', 'signing', 'authority',
  ], 'contract');
  requireCondition(contract.schema_version === 1 && contract.classification === CLASSIFICATION &&
    contract.state === 'product-signing-evidence-foundation',
  'unsupported product-signing contract');
  requireCondition(JSON.stringify(contract.source) === JSON.stringify({
    repository: REPOSITORY,
    event: 'workflow_dispatch',
    ref_type: 'tag',
    tag_pattern: TAG.source,
    protected_tag_required: true,
    exact_commit_required: true,
  }), 'product-signing source boundary changed');
  requireCondition(contract.execution.environment === 'release' &&
    contract.execution.runner === 'ubuntu-24.04' &&
    JSON.stringify(contract.execution.workflow_permissions) === JSON.stringify({contents: 'read'}) &&
    JSON.stringify(contract.execution.job_permissions) === JSON.stringify({
      preflight: {contents: 'read', actions: 'read'},
      sign: {contents: 'read', actions: 'read', 'id-token': 'write'},
      verify: {contents: 'read', actions: 'read'},
    }) && JSON.stringify(contract.execution.jobs) === JSON.stringify({
      preflight: {timeout_minutes: 5},
      sign: {timeout_minutes: 20},
      verify: {timeout_minutes: 15},
    }) && contract.execution.artifact_retention_days === 3 &&
    contract.execution.maximum_billable_job_minutes === 40 &&
    contract.execution.manual_only === true && contract.execution.scheduled_runs === false &&
    contract.execution.self_hosted_runners === false &&
    contract.execution.cancel_in_progress === false,
  'product-signing execution boundary changed');
  requireCondition(JSON.stringify(contract.actions) === JSON.stringify(ACTIONS) &&
    Object.values(contract.actions).every((value) => PINNED_ACTION.test(value)),
  'product-signing action pins changed');
  requireCondition(JSON.stringify(contract.candidate_intake) === JSON.stringify({
    workflow_name: 'OSS Release Candidate Intake Foundation',
    workflow_path: '.github/workflows/release.yml',
    artifact_name: 'oss-release-candidate-intake',
    contract_path: 'packaging/release/oss-candidate-intake-contract.json',
    discovery_script: 'scripts/discover-oss-product-signing-input.mjs',
    prepare_script: 'scripts/prepare-oss-product-signatures.mjs',
    download_root: '${{ runner.temp }}/product-signing-candidate',
    required_run_attempt: 1,
    caller_selected_run_id_allowed: false,
    caller_selected_payload_allowed: false,
  }), 'candidate-intake boundary changed');
  requireCondition(JSON.stringify(contract.signing) === JSON.stringify({
    workflow_path: '.github/workflows/oss-product-signing.yml',
    cosign_version: 'v3.1.4',
    mode: 'sigstore-keyless',
    issuer: 'https://token.actions.githubusercontent.com',
    subject_prefix:
      'https://github.com/routesphere-global/bonvoyage/.github/workflows/oss-product-signing.yml@refs/tags/',
    output_root: '${{ runner.temp }}/product-signature-evidence',
    intermediate_artifact: 'oss-product-signature-bundles',
    final_artifact: 'oss-product-signature-evidence',
    artifacts: ['gateway-deb-linux-amd64', 'gateway-oci-linux-amd64'],
    online_verification_required: true,
    offline_verification_required: true,
    independent_job_required: true,
  }), 'product-signing identity or evidence boundary changed');
  exactKeys(contract.authority, [
    'product_artifact_signature_allowed', 'product_provenance_allowed',
    'release_admitted', 'publishable', 'github_release_created',
    'package_uploaded', 'container_uploaded',
  ], 'contract.authority');
  requireCondition(contract.authority.product_artifact_signature_allowed === true &&
    Object.entries(contract.authority).every(([field, value]) =>
      field === 'product_artifact_signature_allowed' ? value === true : value === false),
  'product-signing contract gained release or publication authority');
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
    stepsFor(job, `jobs.${name}`).filter((step) => step.run).map((step) => ({job: name, step})));
}

function validateWorkflow(contract, workflow, sourceText) {
  exactKeys(workflow, ['name', 'on', 'permissions', 'concurrency', 'jobs'], 'workflow');
  requireCondition(workflow.name === 'OSS Product Signing Evidence' &&
    JSON.stringify(workflow.on) === JSON.stringify({workflow_dispatch: null}) &&
    JSON.stringify(workflow.permissions) === JSON.stringify({contents: 'read'}) &&
    JSON.stringify(workflow.concurrency) === JSON.stringify({
      group: 'oss-product-signing-${{ github.ref }}', 'cancel-in-progress': false,
    }), 'workflow trigger, permission, or concurrency boundary changed');
  const jobs = object(workflow.jobs, 'workflow.jobs');
  exactKeys(jobs, ['preflight', 'sign', 'verify'], 'workflow.jobs');
  for (const [name, job] of Object.entries(jobs)) {
    exactKeys(job, name === 'preflight' ?
      ['name', 'runs-on', 'timeout-minutes', 'environment', 'permissions', 'outputs', 'steps'] :
      ['name', 'needs', 'runs-on', 'timeout-minutes', 'environment', 'permissions', 'steps'],
    `jobs.${name}`);
    requireCondition(job['runs-on'] === contract.execution.runner &&
      job.environment === contract.execution.environment &&
      job['timeout-minutes'] === contract.execution.jobs[name].timeout_minutes &&
      JSON.stringify(job.permissions) === JSON.stringify(contract.execution.job_permissions[name]),
    `${name} execution boundary changed`);
  }
  requireCondition(JSON.stringify(jobs.preflight.outputs) === JSON.stringify({
    candidate_run_id: '${{ steps.candidate-intake.outputs.candidate_run_id }}',
  }) && jobs.sign.needs === 'preflight' &&
    JSON.stringify(jobs.verify.needs) === JSON.stringify(['preflight', 'sign']),
  'product-signing dependency order or output changed');

  const actionSteps = usesSteps(jobs);
  requireCondition(actionSteps.length === 13, 'product-signing action count changed');
  for (const {step} of actionSteps) {
    exactKeys(step, ['name', 'uses', 'with'], `action step ${step.name}`);
    requireCondition(Object.values(ACTIONS).includes(step.uses) && PINNED_ACTION.test(step.uses),
      `unapproved action ${step.uses}`);
  }
  const checkouts = actionSteps.filter(({step}) => step.uses === ACTIONS.checkout);
  const setups = actionSteps.filter(({step}) => step.uses === ACTIONS.setup_node);
  const downloads = actionSteps.filter(({step}) => step.uses === ACTIONS.download_artifact);
  const installers = actionSteps.filter(({step}) => step.uses === ACTIONS.cosign_installer);
  const uploads = actionSteps.filter(({step}) => step.uses === ACTIONS.upload_artifact);
  requireCondition(checkouts.length === 3 && setups.length === 3 && downloads.length === 3 &&
    installers.length === 2 && uploads.length === 2,
  'product-signing action use counts changed');
  for (const {step} of checkouts) {
    requireCondition(JSON.stringify(step.with) === JSON.stringify({
      'fetch-depth': 0, 'persist-credentials': false, ref: '${{ github.sha }}',
    }), 'checkout no longer selects the exact commit without credentials');
  }
  for (const {step} of setups) {
    requireCondition(JSON.stringify(step.with) === JSON.stringify({'node-version': '24'}),
      'Node.js runtime pin changed');
  }
  const candidateDownloads = downloads.filter(({step}) =>
    step.with?.name === 'oss-release-candidate-intake');
  requireCondition(candidateDownloads.length === 2 && candidateDownloads.every(({step}) =>
    JSON.stringify(step.with) === JSON.stringify({
      name: 'oss-release-candidate-intake',
      path: '${{ runner.temp }}/product-signing-candidate',
      'github-token': '${{ github.token }}',
      repository: '${{ github.repository }}',
      'run-id': '${{ needs.preflight.outputs.candidate_run_id }}',
    })), 'candidate intake downloads changed');
  const signatureDownload = downloads.find(({step}) =>
    step.with?.name === 'oss-product-signature-bundles');
  requireCondition(signatureDownload && JSON.stringify(signatureDownload.step.with) ===
    JSON.stringify({
      name: 'oss-product-signature-bundles',
      path: '${{ runner.temp }}/product-signature-evidence',
    }), 'same-run signature evidence download changed');
  for (const {step} of installers) {
    requireCondition(JSON.stringify(step.with) === JSON.stringify({'cosign-release': 'v3.1.4'}),
      'Cosign version pin changed');
  }
  const expectedUploads = new Map([
    ['oss-product-signature-bundles', '${{ runner.temp }}/product-signature-evidence'],
    ['oss-product-signature-evidence', '${{ runner.temp }}/product-signature-evidence'],
  ]);
  for (const {step} of uploads) {
    requireCondition(expectedUploads.get(step.with?.name) === step.with?.path &&
      step.with['if-no-files-found'] === 'error' && step.with['compression-level'] === 0 &&
      step.with.overwrite === false && step.with['include-hidden-files'] === false &&
      step.with['retention-days'] === contract.execution.artifact_retention_days,
    'product-signing upload boundary changed');
  }

  const runs = runSteps(jobs);
  const expectedRuns = [
    'npm ci --ignore-scripts', 'npm ci --ignore-scripts', 'npm ci --ignore-scripts',
    VERIFY_WORKFLOW, VERIFY_WORKFLOW, VERIFY_WORKFLOW,
    DISCOVER, PREPARE, SIGN, SIGNING_VERIFY, FINALIZE, INDEPENDENT_VERIFY,
  ];
  requireCondition(JSON.stringify(multiset(runs.map(({step}) => step.run))) ===
    JSON.stringify(multiset(expectedRuns)), 'product-signing command set changed');
  for (const {step} of runs) {
    const expected = step.name === 'Discover the exact prior candidate intake' ?
      ['name', 'id', 'env', 'run'] :
      step.name === 'Prepare checksum-bound signing targets' ? ['name', 'id', 'run'] :
      ['Sign the exact Debian and OCI candidate bytes',
        'Verify both signatures in the signing job'].includes(step.name) ?
        ['name', 'env', 'run'] : ['name', 'run'];
    exactKeys(step, expected, `run step ${step.name}`);
  }
  const discovery = runs.find(({step}) =>
    step.name === 'Discover the exact prior candidate intake')?.step;
  requireCondition(discovery?.id === 'candidate-intake' &&
    JSON.stringify(discovery.env) === JSON.stringify({GITHUB_TOKEN: '${{ github.token }}'}),
  'candidate intake discovery authority changed');
  const signingPlan = runs.find(({step}) => step.name ===
    'Prepare checksum-bound signing targets')?.step;
  requireCondition(signingPlan?.id === 'signing-plan', 'signing plan output identity changed');
  const sign = runs.find(({step}) => step.name ===
    'Sign the exact Debian and OCI candidate bytes')?.step;
  requireCondition(JSON.stringify(sign?.env) === JSON.stringify({
    DEBIAN_ARTIFACT: '${{ steps.signing-plan.outputs.debian_artifact }}',
    DEBIAN_BUNDLE: '${{ steps.signing-plan.outputs.debian_bundle }}',
    OCI_ARTIFACT: '${{ steps.signing-plan.outputs.oci_artifact }}',
    OCI_BUNDLE: '${{ steps.signing-plan.outputs.oci_bundle }}',
  }), 'signing target environment changed');
  const signingVerification = runs.find(({step}) => step.name ===
    'Verify both signatures in the signing job')?.step;
  requireCondition(JSON.stringify(signingVerification?.env) === JSON.stringify({
    DEBIAN_ARTIFACT: '${{ steps.signing-plan.outputs.debian_artifact }}',
    DEBIAN_BUNDLE: '${{ steps.signing-plan.outputs.debian_bundle }}',
    OCI_ARTIFACT: '${{ steps.signing-plan.outputs.oci_artifact }}',
    OCI_BUNDLE: '${{ steps.signing-plan.outputs.oci_bundle }}',
    EXPECTED_IDENTITY:
      'https://github.com/routesphere-global/bonvoyage/.github/workflows/oss-product-signing.yml@refs/tags/${{ github.ref_name }}',
    EXPECTED_ISSUER: 'https://token.actions.githubusercontent.com',
  }), 'signing-job verification identity changed');

  requireCondition((sourceText.match(/id-token\s*:\s*write/gu) ?? []).length === 1 &&
    (sourceText.match(/cosign sign-blob/gu) ?? []).length === 2 &&
    (sourceText.match(/cosign verify-blob/gu) ?? []).length === 4 &&
    !/\b(?:push|schedule|pull_request):/u.test(sourceText) &&
    !/(?:contents|packages|actions)\s*:\s*write/u.test(sourceText) &&
    !/\$\{\{\s*secrets\./u.test(sourceText) &&
    !/\b(?:gh release|docker push|oras push|npm publish|attest|provenance)\b/u.test(sourceText),
  'workflow gained an automatic, secret, provenance, publishing, or excess-write authority');
}

export function verifyProductSigningWorkflow({
  contractPath, workflowPath, githubRepository, githubRefType, githubRefName,
  githubRefProtected, githubSha,
}) {
  requireCondition(githubRepository === REPOSITORY_SLUG && githubRefType === 'tag' &&
    githubRefProtected === 'true' && TAG.test(githubRefName ?? '') && COMMIT.test(githubSha ?? ''),
  'product signing requires the exact public repository, protected strict tag, and full commit');
  const contract = object(JSON.parse(fs.readFileSync(contractPath, 'utf8')), 'contract');
  const sourceText = fs.readFileSync(workflowPath, 'utf8');
  const workflow = object(yaml.load(sourceText), 'workflow');
  validateContract(contract);
  validateWorkflow(contract, workflow, sourceText);
  return {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-product-signing-workflow-result',
    status: 'PRODUCT_SIGNING_FOUNDATION_VERIFIED',
    source: {repository: REPOSITORY, commit: githubSha, tag: githubRefName, dirty: false},
    authority: contract.authority,
  };
}

function parseArguments(argv) {
  const result = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    requireCondition(argv[index]?.startsWith('--') && argv[index + 1] !== undefined,
      'arguments must be --name value pairs');
    requireCondition(!result.has(argv[index].slice(2)), `duplicate argument ${argv[index]}`);
    result.set(argv[index].slice(2), argv[index + 1]);
  }
  return result;
}

function main(argv) {
  const values = parseArguments(argv);
  const result = verifyProductSigningWorkflow({
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
    process.stderr.write(`product-signing workflow rejected: ${error.message}\n`);
    process.exitCode = 2;
  }
}
