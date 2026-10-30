import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  discoverProductSigningInput,
  selectProductSigningInput,
  writeGithubOutput,
} from './discover-oss-product-signing-input.mjs';

const REPOSITORY = 'routesphere-global/bonvoyage';
const TAG = 'v1.0.0-rc.16';
const COMMIT = 'a'.repeat(40);
const CURRENT_RUN = '43000000000';
const CANDIDATE_RUN = '42999999999';
const TOKEN = 'github-token-fixture-value';

function run({id, name, workflowPath, createdAt, status = 'completed', conclusion = 'success'}) {
  return {
    id: Number(id), name, path: workflowPath, event: 'workflow_dispatch', status, conclusion,
    head_branch: TAG, head_sha: COMMIT, run_attempt: 1, created_at: createdAt,
    repository: {full_name: REPOSITORY},
  };
}

function fixture() {
  return {
    repository: REPOSITORY, tag: TAG, commit: COMMIT, currentRunId: CURRENT_RUN,
    currentRun: run({
      id: CURRENT_RUN, name: 'OSS Product Signing Evidence',
      workflowPath: '.github/workflows/oss-product-signing.yml',
      createdAt: '2026-10-31T08:00:00Z', status: 'in_progress', conclusion: null,
    }),
    releaseResponse: {
      total_count: 1,
      workflow_runs: [run({
        id: CANDIDATE_RUN, name: 'OSS Release Candidate Intake Foundation',
        workflowPath: '.github/workflows/release.yml',
        createdAt: '2026-10-31T07:00:00Z',
      })],
    },
  };
}

test('selects one exact prior candidate intake without release authority', () => {
  const result = selectProductSigningInput(fixture());
  assert.equal(result.candidate_run_id, CANDIDATE_RUN);
  assert.deepEqual(result.source, {commit: COMMIT, tag: TAG, dirty: false});
  assert.ok(Object.values(result.authority).every((value) => value === false));
});

test('rejects current-run, source and prior-run drift', () => {
  const mutations = [
    (value) => { value.repository = 'personal/fork'; },
    (value) => { value.tag = 'main'; },
    (value) => { value.currentRun.name = 'Different'; },
    (value) => { value.currentRun.path = '.github/workflows/release.yml'; },
    (value) => { value.currentRun.status = 'completed'; },
    (value) => { value.releaseResponse.workflow_runs[0].name = 'Different'; },
    (value) => { value.releaseResponse.workflow_runs[0].path = '.github/workflows/ci.yml'; },
    (value) => { value.releaseResponse.workflow_runs[0].head_sha = 'b'.repeat(40); },
    (value) => { value.releaseResponse.workflow_runs[0].conclusion = 'failure'; },
    (value) => { value.releaseResponse.workflow_runs[0].run_attempt = 2; },
    (value) => { value.releaseResponse.workflow_runs[0].created_at = '2026-10-31T09:00:00Z'; },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(fixture());
    mutate(value);
    assert.throws(() => selectProductSigningInput(value));
  }
});

test('rejects duplicate and incomplete candidate responses', () => {
  const duplicate = fixture();
  duplicate.releaseResponse.workflow_runs.push({...duplicate.releaseResponse.workflow_runs[0], id: 7});
  duplicate.releaseResponse.total_count = 2;
  assert.throws(() => selectProductSigningInput(duplicate), /exactly one/u);
  const incomplete = fixture();
  incomplete.releaseResponse.total_count = 2;
  assert.throws(() => selectProductSigningInput(incomplete), /incomplete or paginated/u);
});

test('writes only the selected run ID to an existing regular output file', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-signing-discovery-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const output = path.join(root, 'output');
  fs.writeFileSync(output, 'existing=value\n');
  writeGithubOutput(output, selectProductSigningInput(fixture()));
  assert.equal(fs.readFileSync(output, 'utf8'),
    `existing=value\ncandidate_run_id=${CANDIDATE_RUN}\n`);
  const link = path.join(root, 'link');
  fs.symlinkSync(output, link);
  assert.throws(() => writeGithubOutput(link, selectProductSigningInput(fixture())));
});

test('queries only fixed GitHub endpoints and does not expose the token', async () => {
  const value = fixture();
  const currentUrl = `https://api.github.com/repos/${REPOSITORY}/actions/runs/${CURRENT_RUN}`;
  const releaseUrl = `https://api.github.com/repos/${REPOSITORY}/actions/workflows/${encodeURIComponent('.github/workflows/release.yml')}/runs?event=workflow_dispatch&status=success&head_sha=${COMMIT}&per_page=100`;
  const responses = new Map([[currentUrl, value.currentRun], [releaseUrl, value.releaseResponse]]);
  const observed = [];
  const fetchImpl = async (url, options) => {
    observed.push(url);
    assert.equal(options.headers.Authorization, `Bearer ${TOKEN}`);
    return {ok: true, status: 200, text: async () => JSON.stringify(responses.get(url))};
  };
  const result = await discoverProductSigningInput({
    repository: REPOSITORY, tag: TAG, commit: COMMIT, currentRunId: CURRENT_RUN,
  }, {token: TOKEN, fetchImpl});
  assert.deepEqual(observed.sort(), [currentUrl, releaseUrl].sort());
  assert.equal(JSON.stringify(result).includes(TOKEN), false);
});
