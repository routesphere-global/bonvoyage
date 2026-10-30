import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import yaml from 'js-yaml';

import {verifyProductSigningWorkflow} from './verify-oss-product-signing-workflow.mjs';

const COMMIT = 'a'.repeat(40);
const TAG = 'v1.0.0-rc.16';
const REPOSITORY_ROOT = path.resolve(import.meta.dirname, '..');
const CONTRACT_SOURCE = path.join(REPOSITORY_ROOT,
  'packaging/release/oss-product-signing-workflow-contract.json');
const WORKFLOW_SOURCE = path.join(REPOSITORY_ROOT,
  '.github/workflows/oss-product-signing.yml');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-signing-workflow-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const contract = path.join(root, 'contract.json');
  const workflow = path.join(root, 'workflow.yml');
  fs.copyFileSync(CONTRACT_SOURCE, contract);
  fs.copyFileSync(WORKFLOW_SOURCE, workflow);
  return {root, contract, workflow};
}

function verify(value, overrides = {}) {
  return verifyProductSigningWorkflow({
    contractPath: value.contract,
    workflowPath: value.workflow,
    githubRepository: 'routesphere-global/bonvoyage',
    githubRefType: 'tag',
    githubRefName: TAG,
    githubRefProtected: 'true',
    githubSha: COMMIT,
    ...overrides,
  });
}

function mutateWorkflow(value, callback) {
  const document = yaml.load(fs.readFileSync(value.workflow, 'utf8'));
  callback(document);
  fs.writeFileSync(value.workflow, yaml.dump(document, {lineWidth: -1, noRefs: true}));
}

test('accepts only the reviewed protected-tag signing workflow', (t) => {
  const value = fixture(t);
  const result = verify(value);
  assert.equal(result.status, 'PRODUCT_SIGNING_FOUNDATION_VERIFIED');
  assert.equal(result.authority.product_artifact_signature_allowed, true);
  assert.equal(result.authority.release_admitted, false);
  assert.equal(result.authority.publishable, false);
});

test('rejects an unprotected, branch, foreign, or abbreviated source', (t) => {
  const value = fixture(t);
  assert.throws(() => verify(value, {githubRefProtected: 'false'}), /protected strict tag/u);
  assert.throws(() => verify(value, {githubRefType: 'branch'}), /protected strict tag/u);
  assert.throws(() => verify(value, {githubRepository: 'someone/bonvoyage'}),
    /exact public repository/u);
  assert.throws(() => verify(value, {githubSha: 'a'.repeat(39)}), /full commit/u);
});

test('rejects trigger, permission, action, command and upload drift', (t) => {
  const value = fixture(t);
  const original = fs.readFileSync(value.workflow, 'utf8');
  const cases = [
    (workflow) => { workflow.on.push = null; },
    (workflow) => { workflow.jobs.verify.permissions['id-token'] = 'write'; },
    (workflow) => {
      workflow.jobs.sign.steps.find((step) => step.uses?.startsWith('actions/checkout@')).uses =
        'actions/checkout@main';
    },
    (workflow) => {
      const step = workflow.jobs.sign.steps.find((item) =>
        item.name === 'Verify both signatures in the signing job');
      step.run = step.run.replace('--offline=true ', '');
    },
    (workflow) => {
      workflow.jobs.verify.steps.push({name: 'Publish', run: 'gh release create v1.0.0'});
    },
    (workflow) => {
      const upload = workflow.jobs.verify.steps.find((step) =>
        step.uses?.startsWith('actions/upload-artifact@'));
      upload.with.path = '${{ runner.temp }}/product-signing-candidate';
    },
  ];
  for (const mutation of cases) {
    fs.writeFileSync(value.workflow, original);
    mutateWorkflow(value, mutation);
    assert.throws(() => verify(value));
  }
});

test('rejects contract authority, identity and action-pin escalation', (t) => {
  const value = fixture(t);
  const original = fs.readFileSync(value.contract, 'utf8');
  const cases = [
    (contract) => { contract.authority.release_admitted = true; },
    (contract) => { contract.signing.subject_prefix = 'https://example.test/'; },
    (contract) => { contract.actions.cosign_installer = 'sigstore/cosign-installer@main'; },
    (contract) => { contract.execution.job_permissions.verify['id-token'] = 'write'; },
  ];
  for (const mutation of cases) {
    const contract = JSON.parse(original);
    mutation(contract);
    fs.writeFileSync(value.contract, `${JSON.stringify(contract, null, 2)}\n`);
    assert.throws(() => verify(value));
  }
});
