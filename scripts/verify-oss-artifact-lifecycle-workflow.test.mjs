import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {verifyArtifactLifecycleWorkflow} from
  './verify-oss-artifact-lifecycle-workflow.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACT = path.join(
  ROOT, 'packaging/release/oss-artifact-lifecycle-workflow-contract.json');
const WORKFLOW = path.join(
  ROOT, 'packaging/release/oss-artifact-lifecycle.workflow.yml');
const ACTIVE = path.join(ROOT, '.github/workflows/oss-artifact-lifecycle.yml');
const LIFECYCLE = path.join(
  ROOT, 'packaging/release/oss-artifact-lifecycle-contract.json');
const COLLECTOR = path.join(ROOT, 'scripts/collect-oss-oci-lifecycle.py');
const COMMIT = 'a'.repeat(40);

function verify(overrides = {}) {
  return verifyArtifactLifecycleWorkflow({
    contractPath: CONTRACT,
    workflowPath: WORKFLOW,
    activeWorkflowPath: ACTIVE,
    lifecycleContractPath: LIFECYCLE,
    ociCollectorPath: COLLECTOR,
    githubRepository: 'routesphere-global/bonvoyage',
    githubRefType: 'tag',
    githubRefName: 'v1.0.0-rc.7',
    githubRefProtected: 'true',
    githubSha: COMMIT,
    ...overrides,
  });
}

function changedWorkflows(t, mutate, activeMutate = mutate) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-lifecycle-workflow-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const workflowPath = path.join(root, 'workflow.yml');
  const activeWorkflowPath = path.join(root, 'active.yml');
  const source = fs.readFileSync(WORKFLOW, 'utf8');
  fs.writeFileSync(workflowPath, mutate(source));
  fs.writeFileSync(activeWorkflowPath, activeMutate(source));
  return {workflowPath, activeWorkflowPath};
}

function changedContract(t, mutate) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-lifecycle-contract-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const contractPath = path.join(root, 'contract.json');
  const value = JSON.parse(fs.readFileSync(CONTRACT, 'utf8'));
  mutate(value);
  fs.writeFileSync(contractPath, `${JSON.stringify(value, null, 2)}\n`);
  return contractPath;
}

test('accepts only the protected powerless lifecycle workflow', () => {
  const result = verify();
  assert.equal(result.status, 'ARTIFACT_LIFECYCLE_WORKFLOW_VERIFIED');
  assert.equal(result.lifecycle_executed, false);
  assert.equal(result.human_review_required, true);
  assert.ok(Object.values(result.authority).every((value) => value === false));
});

test('rejects unprotected, stale, forked, branch, and abbreviated sources', () => {
  assert.throws(() => verify({githubRefProtected: 'false'}));
  assert.throws(() => verify({githubRefType: 'branch'}));
  assert.throws(() => verify({githubRepository: 'personal/fork'}));
  assert.throws(() => verify({githubRefName: 'v1.0.0-rc.5'}));
  assert.throws(() => verify({githubRefName: 'v1.0.0-rc.06'}));
  assert.throws(() => verify({githubSha: COMMIT.slice(0, 12)}));
});

test('rejects template and active workflow byte drift', (t) => {
  const paths = changedWorkflows(t, (value) => value,
    (value) => `${value}\n`);
  assert.throws(() => verify(paths), /byte-identical/u);
});

test('rejects trigger permission runner action and timeout drift', (t) => {
  const mutations = [
    (value) => value.replace('  workflow_dispatch:\n', '  push:\n'),
    (value) => value.replace('  contents: read\n', '  contents: write\n'),
    (value) => value.replace('runs-on: ubuntu-24.04', 'runs-on: self-hosted'),
    (value) => value.replace('timeout-minutes: 45', 'timeout-minutes: 46'),
    (value) => value.replace(
      'actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803',
      'actions/checkout@v6'),
    (value) => value.replace('persist-credentials: false', 'persist-credentials: true'),
  ];
  for (const mutate of mutations) {
    const paths = changedWorkflows(t, mutate);
    assert.throws(() => verify(paths));
  }
});

test('rejects external artifact substitution and evidence drift', (t) => {
  const mutations = [
    (value) => value.replace('name: oss-deb-build-a', 'name: different-build'),
    (value) => value.replace(
      'run-id: ${{ needs.preflight.outputs.baseline_deb_run_id }}',
      'run-id: 1'),
    (value) => value.replace('retention-days: 3', 'retention-days: 30'),
    (value) => value.replace(
      'path: ${{ runner.temp }}/intakes', 'path: /tmp/unbound-intakes'),
    (value) => value.replace(
      'node scripts/assemble-oss-artifact-lifecycle.mjs', 'true'),
  ];
  for (const mutate of mutations) {
    const paths = changedWorkflows(t, mutate);
    assert.throws(() => verify(paths));
  }
});

test('rejects omission of the private intake parent directory', (t) => {
  const paths = changedWorkflows(t, (value) => value.replace(
    '          mkdir -p "$RUNNER_TEMP/intakes"\n', ''));
  assert.throws(() => verify(paths));
});

test('rejects publication signing secrets and error suppression', (t) => {
  for (const injected of [
    '      - run: gh release create v1.0.0\n',
    '      - run: cosign sign artifact\n',
    '      - run: echo "${{ secrets.RELEASE_TOKEN }}"\n',
    '      - continue-on-error: true\n        run: false\n',
  ]) {
    const paths = changedWorkflows(t, (value) =>
      value.replace('    steps:\n', `    steps:\n${injected}`));
    assert.throws(() => verify(paths));
  }
});

test('rejects contract authority action runtime and budget drift', (t) => {
  const mutations = [
    (value) => { value.authority.release_admitted = true; },
    (value) => { value.actions.checkout = 'actions/checkout@v6'; },
    (value) => { value.runtime_images.python = 'python:latest'; },
    (value) => { value.execution.maximum_billable_job_minutes = 156; },
    (value) => { value.execution.jobs.aggregate.timeout_minutes = 16; },
    (value) => { value.activation.protected_release_tags_verified = false; },
  ];
  for (const mutate of mutations) {
    assert.throws(() => verify({contractPath: changedContract(t, mutate)}));
  }
});

test('rejects duplicate YAML keys and OCI collector image drift', (t) => {
  const paths = changedWorkflows(t, (value) =>
    value.replace('permissions:\n', 'permissions:\n  contents: read\n'));
  assert.throws(() => verify(paths));

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-oci-collector-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const ociCollectorPath = path.join(root, 'collector.py');
  fs.writeFileSync(ociCollectorPath,
    fs.readFileSync(COLLECTOR, 'utf8').replace('quay.io/skopeo/stable@',
      'quay.io/skopeo/stable:latest'));
  assert.throws(() => verify({ociCollectorPath}));
});
