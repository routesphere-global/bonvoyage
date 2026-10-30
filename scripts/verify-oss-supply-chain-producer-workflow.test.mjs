import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {verifySupplyChainProducerWorkflow} from
  './verify-oss-supply-chain-producer-workflow.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACT = path.join(
  ROOT, 'packaging/release/oss-supply-chain-producer-workflow-contract.json');
const WORKFLOW = path.join(ROOT, '.github/workflows/oss-supply-chain-producers.yml');
const COMMIT = 'a'.repeat(40);

function verify(overrides = {}) {
  return verifySupplyChainProducerWorkflow({
    contractPath: CONTRACT, workflowPath: WORKFLOW,
    githubRepository: 'routesphere-global/bonvoyage', githubRefType: 'tag',
    githubRefName: 'v1.0.0-rc.9', githubRefProtected: 'true',
    githubSha: COMMIT, ...overrides,
  });
}
function changedWorkflow(t, mutate) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-producer-workflow-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const destination = path.join(root, 'workflow.yml');
  fs.writeFileSync(destination, mutate(fs.readFileSync(WORKFLOW, 'utf8')));
  return destination;
}

test('accepts only the protected powerless producer workflow', () => {
  const result = verify();
  assert.equal(result.status, 'PRODUCER_FOUNDATION_VERIFIED');
  assert.equal(result.human_review_required, true);
  assert.equal(result.review_generated, false);
  assert.ok(Object.values(result.authority).every((value) => value === false));
});

test('rejects non-tag, fork, and abbreviated source identities', () => {
  assert.throws(() => verify({githubRefType: 'branch'}));
  assert.throws(() => verify({githubRefProtected: 'false'}));
  assert.throws(() => verify({githubRepository: 'personal/fork'}));
  assert.throws(() => verify({githubSha: COMMIT.slice(0, 12)}));
});

test('rejects permission, trigger, action, and timeout drift', (t) => {
  const mutations = [
    (value) => value.replace('contents: read\n\nconcurrency:', 'contents: write\n\nconcurrency:'),
    (value) => value.replace('workflow_dispatch:', 'push:'),
    (value) => value.replace('timeout-minutes: 30', 'timeout-minutes: 31'),
    (value) => value.replace(
      'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
      'actions/checkout@v4'),
  ];
  for (const mutate of mutations) {
    const workflowPath = changedWorkflow(t, mutate);
    assert.throws(() => verify({workflowPath}));
  }
});

test('rejects publication, signing, secrets, or generated human review', (t) => {
  for (const injected of [
    '      - run: gh release create v1.0.0\n',
    '      - run: cosign sign artifact\n',
    '      - run: echo "${{ secrets.RELEASE_TOKEN }}"\n',
    '      - run: touch review.json\n',
  ]) {
    const workflowPath = changedWorkflow(t, (value) =>
      value.replace('    steps:\n', `    steps:\n${injected}`));
    assert.throws(() => verify({workflowPath}));
  }
});

test('rejects candidate substitution and producer command changes', (t) => {
  const mutations = [
    (value) => value.replace('oss-release-candidate-intake', 'different-candidate'),
    (value) => value.replace('--source-tag "$GITHUB_REF_NAME"', '--source-tag v1.0.0'),
    (value) => value.replace('retention-days: 3', 'retention-days: 30'),
    (value) => value.replace('GRYPE_IMAGE: anchore/grype:', 'GRYPE_IMAGE: attacker/grype:'),
  ];
  for (const mutate of mutations) {
    const workflowPath = changedWorkflow(t, mutate);
    assert.throws(() => verify({workflowPath}));
  }
});

test('rejects skipped steps, error suppression, and folded command drift', (t) => {
  const mutations = [
    (value) => value.replace('        run: npm ci --ignore-scripts',
      '        if: false\n        run: npm ci --ignore-scripts'),
    (value) => value.replace('        run: npm ci --ignore-scripts',
      '        continue-on-error: true\n        run: npm ci --ignore-scripts'),
    (value) => value.replace('        run: |\n          docker pull "$SYFT_IMAGE"',
      '        run: >\n          docker pull "$SYFT_IMAGE"'),
    (value) => value.replace('    runs-on: ubuntu-24.04',
      '    if: false\n    runs-on: ubuntu-24.04'),
  ];
  for (const mutate of mutations) {
    const workflowPath = changedWorkflow(t, mutate);
    assert.throws(() => verify({workflowPath}));
  }
});
