import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {createIdentityProbe} from './create-oss-release-identity-probe.mjs';
import {verifyReleaseWorkflow} from './verify-oss-release-workflow.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACT = path.join(ROOT,
  'packaging/release/oss-release-identity-workflow-contract.json');
const WORKFLOW = path.join(ROOT, '.github/workflows/release.yml');
const GENERATOR = path.join(ROOT, 'scripts/create-oss-release-identity-probe.mjs');

const VALID_PROBE = {
  repository: 'routesphere-global/bonvoyage',
  refType: 'tag',
  tag: 'v1.0.0-rc.7',
  commit: 'a'.repeat(40),
  runId: '40999999999',
  runAttempt: '1',
};

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-release-identity-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const contract = path.join(root, 'contract.json');
  const workflow = path.join(root, 'release.yml');
  fs.copyFileSync(CONTRACT, contract);
  fs.copyFileSync(WORKFLOW, workflow);
  return {root, contract, workflow};
}

function mutateJson(filePath, callback) {
  const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  callback(value);
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function mutateWorkflow(filePath, from, to) {
  const source = fs.readFileSync(filePath, 'utf8');
  assert.ok(source.includes(from), `missing workflow fixture text: ${from}`);
  fs.writeFileSync(filePath, source.replace(from, to));
}

test('accepts the powerless candidate intake and identity workflow foundation', () => {
  const result = verifyReleaseWorkflow(CONTRACT, WORKFLOW);
  assert.equal(result.state, 'candidate-intake-foundation');
  assert.equal(result.candidate_intake_allowed, true);
  assert.equal(result.identity_probe_signature_allowed, true);
  assert.equal(result.product_artifact_signature_allowed, false);
  assert.equal(result.product_provenance_allowed, false);
  assert.equal(result.release_admitted, false);
  assert.equal(result.publishable, false);
});

test('creates a fixed identity probe with no release authority', () => {
  const probe = createIdentityProbe(VALID_PROBE);
  assert.equal(probe.repository, 'https://github.com/routesphere-global/bonvoyage');
  assert.equal(probe.workflow_identity,
    'https://github.com/routesphere-global/bonvoyage/.github/workflows/release.yml@refs/tags/v1.0.0-rc.7');
  assert.deepEqual(probe.source, {
    commit: 'a'.repeat(40),
    tag: 'v1.0.0-rc.7',
    ref_type: 'tag',
  });
  assert.equal(probe.authority.identity_probe_only, true);
  assert.equal(probe.authority.product_artifact_signed, false);
  assert.equal(probe.authority.product_provenance_created, false);
  assert.equal(probe.authority.release_admitted, false);
  assert.equal(probe.authority.publishable, false);
});

test('rejects non-public, non-tagged, malformed or incomplete probe contexts', () => {
  for (const mutation of [
    {repository: 'personal/fork'},
    {refType: 'branch'},
    {tag: 'main'},
    {tag: 'v01.0.0'},
    {commit: 'A'.repeat(40)},
    {runId: '0'},
    {runAttempt: 'not-a-number'},
  ]) {
    assert.throws(() => createIdentityProbe({...VALID_PROBE, ...mutation}));
  }
});

test('CLI writes one new private probe and refuses overwrite', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-probe-cli-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const output = path.join(root, 'probe.json');
  const args = [
    GENERATOR,
    '--output', output,
    '--repository', VALID_PROBE.repository,
    '--ref-type', VALID_PROBE.refType,
    '--tag', VALID_PROBE.tag,
    '--commit', VALID_PROBE.commit,
    '--run-id', VALID_PROBE.runId,
    '--run-attempt', VALID_PROBE.runAttempt,
  ];
  const first = spawnSync(process.execPath, args, {encoding: 'utf8'});
  assert.equal(first.status, 0, first.stderr);
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
  const second = spawnSync(process.execPath, args, {encoding: 'utf8'});
  assert.equal(second.status, 1);
  assert.match(second.stderr, /output must be new/u);
});

test('rejects automatic triggers, caller inputs, secrets and excessive permissions', (t) => {
  for (const [from, to] of [
    ['  workflow_dispatch:\n', '  push:\n    tags: ["v*"]\n'],
    ['  workflow_dispatch:\n', '  workflow_dispatch:\n    inputs:\n      payload:\n        required: true\n'],
    ['  contents: read\n', '  contents: write\n'],
    ['      actions: read\n', '      actions: write\n'],
    ['      id-token: write\n', '      id-token: write\n      packages: write\n'],
    ['npm ci --ignore-scripts', 'echo "${{ secrets.RELEASE_TOKEN }}"'],
  ]) {
    const value = fixture(t);
    mutateWorkflow(value.workflow, from, to);
    assert.throws(() => verifyReleaseWorkflow(value.contract, value.workflow));
  }
});

test('rejects unpinned or added actions and changed evidence retention', (t) => {
  for (const [from, to] of [
    ['actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
      'actions/checkout@v7'],
    ['      - name: Install the pinned keyless signing client\n',
      '      - uses: untrusted/example@0000000000000000000000000000000000000000\n' +
      '      - name: Install the pinned keyless signing client\n'],
    ['          retention-days: 3\n', '          retention-days: 30\n'],
  ]) {
    const value = fixture(t);
    mutateWorkflow(value.workflow, from, to);
    assert.throws(() => verifyReleaseWorkflow(value.contract, value.workflow));
  }
});

test('rejects an added run step even when its command is not deny-listed', (t) => {
  const value = fixture(t);
  mutateWorkflow(value.workflow,
    '      - name: Upload bounded non-publishing identity evidence\n',
    '      - name: Unreviewed command\n        run: echo harmless\n' +
    '      - name: Upload bounded non-publishing identity evidence\n');
  assert.throws(() => verifyReleaseWorkflow(value.contract, value.workflow));
});

test('rejects caller-selected, mixed or reordered candidate intake inputs', (t) => {
  for (const [from, to] of [
    ['--current-run-id "$GITHUB_RUN_ID"', '--current-run-id "${{ inputs.run_id }}"'],
    ['name: oss-deb-build-a', 'name: attacker-selected-artifact'],
    ['run-id: ${{ steps.candidate-runs.outputs.deb_run_id }}',
      'run-id: 40984886786'],
    ['path: ${{ runner.temp }}/release-candidate-input/oci/oss-oci-build-a',
      'path: ${{ runner.temp }}/release-candidate-input/debian/oss-oci-build-a'],
    ['GITHUB_TOKEN: ${{ github.token }}', 'GITHUB_TOKEN: ${{ secrets.RELEASE_TOKEN }}'],
    ['needs: candidate-intake\n', 'needs: preflight\n'],
  ]) {
    const value = fixture(t);
    mutateWorkflow(value.workflow, from, to);
    assert.throws(() => verifyReleaseWorkflow(value.contract, value.workflow));
  }
});

test('rejects product signing, provenance and publication commands', (t) => {
  for (const command of [
    'cosign sign product.deb',
    'gh release create v1.0.0',
    'docker push ghcr.io/routesphere-global/bonvoyage:v1.0.0',
    'npm publish',
    'uses: actions/attest-build-provenance@0000000000000000000000000000000000000000',
  ]) {
    const value = fixture(t);
    mutateWorkflow(value.workflow,
      '      - name: Upload bounded non-publishing identity evidence\n',
      `      - name: Forbidden command\n        run: ${command}\n` +
      '      - name: Upload bounded non-publishing identity evidence\n');
    assert.throws(() => verifyReleaseWorkflow(value.contract, value.workflow));
  }
});

test('rejects weakened OIDC provider or GitHub certificate claim verification', (t) => {
  for (const [from, to] of [
    ['--oidc-provider github-actions', '--oidc-provider filesystem'],
    ['--certificate-github-workflow-repository "$GITHUB_REPOSITORY"',
      '--certificate-github-workflow-repository personal/fork'],
    ['--certificate-github-workflow-sha "$GITHUB_SHA"',
      '--certificate-github-workflow-sha deadbeef'],
    ['--certificate-github-workflow-ref "$GITHUB_REF"',
      '--certificate-github-workflow-ref refs/heads/main'],
    ['--certificate-github-workflow-trigger "$GITHUB_EVENT_NAME"',
      '--certificate-github-workflow-trigger push'],
  ]) {
    const value = fixture(t);
    mutateWorkflow(value.workflow, from, to);
    assert.throws(() => verifyReleaseWorkflow(value.contract, value.workflow));
  }
});

test('rejects authority, identity, tool and contract drift', (t) => {
  const mutations = [
    (value) => { value.authority.publishable = true; },
    (value) => { value.authority.candidate_intake_allowed = false; },
    (value) => { value.authority.product_artifact_signature_allowed = true; },
    (value) => { value.candidate_intake.caller_selected_run_ids_allowed = true; },
    (value) => { value.candidate_intake.required_run_attempt = 2; },
    (value) => { value.candidate_intake.artifact_names.debian[0] = 'different'; },
    (value) => { value.identity.caller_selected_payload_allowed = true; },
    (value) => { value.identity.cosign_version = 'v3.1.3'; },
    (value) => { value.identity.subject_prefix = 'https://github.com/personal/fork/'; },
    (value) => { value.actions.cosign_installer = 'sigstore/cosign-installer@v4'; },
    (value) => { value.actions.checkout = `actions/checkout@${'0'.repeat(40)}`; },
  ];
  for (const mutation of mutations) {
    const value = fixture(t);
    mutateJson(value.contract, mutation);
    assert.throws(() => verifyReleaseWorkflow(value.contract, value.workflow));
  }
});

test('runtime context requires one complete strict public tag identity', () => {
  const valid = {
    githubRepository: 'routesphere-global/bonvoyage',
    githubRefType: 'tag',
    githubRefName: 'v1.0.0-rc.7',
    githubSha: 'b'.repeat(40),
  };
  assert.equal(verifyReleaseWorkflow(CONTRACT, WORKFLOW, valid).publishable, false);
  assert.throws(() => verifyReleaseWorkflow(CONTRACT, WORKFLOW,
    {...valid, githubRepository: 'personal/fork'}));
  assert.throws(() => verifyReleaseWorkflow(CONTRACT, WORKFLOW,
    {...valid, githubRefType: 'branch'}));
  assert.throws(() => verifyReleaseWorkflow(CONTRACT, WORKFLOW,
    {...valid, githubRefName: 'v01.0.0'}));
  assert.throws(() => verifyReleaseWorkflow(CONTRACT, WORKFLOW,
    {githubRepository: valid.githubRepository}));
});
