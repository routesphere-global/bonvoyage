import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  discoverReleaseCandidateRuns,
  selectReleaseCandidateRuns,
  writeGithubOutputs,
} from './discover-oss-release-candidate-runs.mjs';

const REPOSITORY = 'routesphere-global/bonvoyage';
const TAG = 'v1.0.0-rc.7';
const COMMIT = 'a'.repeat(40);
const RELEASE_RUN = '41000000000';
const DEB_RUN = '41000000001';
const OCI_RUN = '41000000002';
const TOKEN = 'github-token-fixture-value';

function run({
  id,
  name,
  workflowPath,
  createdAt,
  status = 'completed',
  conclusion = 'success',
  headBranch = TAG,
  event = 'workflow_dispatch',
  attempt = 1,
  repository = REPOSITORY,
  headSha = COMMIT,
}) {
  return {
    id: Number(id),
    name,
    path: workflowPath,
    event,
    status,
    conclusion,
    head_branch: headBranch,
    head_sha: headSha,
    run_attempt: attempt,
    created_at: createdAt,
    repository: {full_name: repository},
  };
}

function fixture() {
  return {
    repository: REPOSITORY,
    tag: TAG,
    commit: COMMIT,
    currentRunId: RELEASE_RUN,
    currentRun: run({
      id: RELEASE_RUN,
      name: 'OSS Release Candidate Intake Foundation',
      workflowPath: '.github/workflows/release.yml',
      createdAt: '2026-10-30T05:00:00Z',
      status: 'in_progress',
      conclusion: null,
    }),
    debianResponse: {
      total_count: 1,
      workflow_runs: [run({
        id: DEB_RUN,
        name: 'OSS Debian Reproducibility Candidate',
        workflowPath: '.github/workflows/oss-deb-reproducibility.yml',
        createdAt: '2026-10-30T04:00:00Z',
      })],
    },
    ociResponse: {
      total_count: 1,
      workflow_runs: [run({
        id: OCI_RUN,
        name: 'OSS OCI Reproducibility Candidate',
        workflowPath: '.github/workflows/oss-oci-reproducibility.yml',
        createdAt: '2026-10-30T04:01:00Z',
      })],
    },
  };
}

test('selects one exact prior run per candidate workflow without granting authority', () => {
  const result = selectReleaseCandidateRuns(fixture());
  assert.equal(result.candidates.debian.id, DEB_RUN);
  assert.equal(result.candidates.oci.id, OCI_RUN);
  assert.equal(result.release_workflow_run.created_at, '2026-10-30T05:00:00.000Z');
  assert.deepEqual(result.source, {commit: COMMIT, tag: TAG, dirty: false});
  assert.ok(Object.values(result.authority).every((value) => value === false));
  assert.equal(JSON.stringify(result).includes(TOKEN), false);
});

test('rejects source, current-run and candidate identity drift', () => {
  const mutations = [
    (value) => { value.repository = 'personal/fork'; },
    (value) => { value.tag = 'main'; },
    (value) => { value.commit = 'A'.repeat(40); },
    (value) => { value.currentRun.name = 'Different workflow'; },
    (value) => { value.currentRun.path = '.github/workflows/ci.yml'; },
    (value) => { value.currentRun.status = 'completed'; },
    (value) => { value.currentRun.run_attempt = 2; },
    (value) => { value.debianResponse.workflow_runs[0].repository.full_name = 'personal/fork'; },
    (value) => { value.debianResponse.workflow_runs[0].name = 'Different workflow'; },
    (value) => { value.debianResponse.workflow_runs[0].path = '.github/workflows/ci.yml'; },
    (value) => { value.debianResponse.workflow_runs[0].event = 'push'; },
    (value) => { value.debianResponse.workflow_runs[0].status = 'in_progress'; },
    (value) => { value.debianResponse.workflow_runs[0].conclusion = 'failure'; },
    (value) => { value.debianResponse.workflow_runs[0].run_attempt = 2; },
    (value) => { value.debianResponse.workflow_runs[0].head_sha = 'b'.repeat(40); },
    (value) => { value.debianResponse.workflow_runs[0].head_branch = 'v1.0.0-rc.8'; },
    (value) => { value.debianResponse.workflow_runs[0].created_at = '2026-10-30T06:00:00Z'; },
  ];
  for (const mutation of mutations) {
    const value = structuredClone(fixture());
    mutation(value);
    assert.throws(() => selectReleaseCandidateRuns(value));
  }
});

test('rejects duplicate, paginated and reused workflow runs', () => {
  const duplicate = fixture();
  duplicate.debianResponse.workflow_runs.push(
    {...duplicate.debianResponse.workflow_runs[0], id: 41000000003});
  duplicate.debianResponse.total_count = 2;
  assert.throws(() => selectReleaseCandidateRuns(duplicate), /exactly one/u);

  const incomplete = fixture();
  incomplete.debianResponse.total_count = 2;
  assert.throws(() => selectReleaseCandidateRuns(incomplete), /incomplete or paginated/u);

  const reused = fixture();
  reused.ociResponse.workflow_runs[0].id = Number(DEB_RUN);
  assert.throws(() => selectReleaseCandidateRuns(reused), /must be distinct/u);
});

test('writes only bounded GitHub step outputs to an existing regular file', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-run-discovery-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const output = path.join(root, 'github-output');
  fs.writeFileSync(output, 'existing=value\n');
  writeGithubOutputs(output, selectReleaseCandidateRuns(fixture()));
  assert.equal(fs.readFileSync(output, 'utf8'), [
    'existing=value',
    `deb_run_id=${DEB_RUN}`,
    `oci_run_id=${OCI_RUN}`,
    'created_at=2026-10-30T05:00:00.000Z',
    '',
  ].join('\n'));

  const link = path.join(root, 'linked-output');
  fs.symlinkSync(output, link);
  assert.throws(() => writeGithubOutputs(link, selectReleaseCandidateRuns(fixture())));
});

test('uses only fixed GitHub API endpoints and keeps the bearer token out of results', async () => {
  const value = fixture();
  const responses = new Map([
    [`https://api.github.com/repos/${REPOSITORY}/actions/runs/${RELEASE_RUN}`,
      value.currentRun],
    [`https://api.github.com/repos/${REPOSITORY}/actions/workflows/${encodeURIComponent('.github/workflows/oss-deb-reproducibility.yml')}/runs?event=workflow_dispatch&status=success&head_sha=${COMMIT}&per_page=100`,
      value.debianResponse],
    [`https://api.github.com/repos/${REPOSITORY}/actions/workflows/${encodeURIComponent('.github/workflows/oss-oci-reproducibility.yml')}/runs?event=workflow_dispatch&status=success&head_sha=${COMMIT}&per_page=100`,
      value.ociResponse],
  ]);
  const observed = [];
  const fetchImpl = async (url, options) => {
    observed.push({url, options});
    assert.equal(options.headers.Authorization, `Bearer ${TOKEN}`);
    assert.equal(options.method, 'GET');
    const body = responses.get(url);
    assert.ok(body, `unexpected URL ${url}`);
    return {ok: true, status: 200, text: async () => JSON.stringify(body)};
  };
  const result = await discoverReleaseCandidateRuns({
    repository: REPOSITORY,
    tag: TAG,
    commit: COMMIT,
    currentRunId: RELEASE_RUN,
  }, {token: TOKEN, fetchImpl});
  assert.equal(observed.length, 3);
  assert.equal(JSON.stringify(result).includes(TOKEN), false);
});

test('rejects missing tokens and unsuccessful or malformed API responses', async () => {
  const options = {
    repository: REPOSITORY,
    tag: TAG,
    commit: COMMIT,
    currentRunId: RELEASE_RUN,
  };
  await assert.rejects(() => discoverReleaseCandidateRuns(options, {
    token: '',
    fetchImpl: async () => { throw new Error('must not run'); },
  }), /GITHUB_TOKEN/u);
  await assert.rejects(() => discoverReleaseCandidateRuns(options, {
    token: TOKEN,
    fetchImpl: async () => ({ok: false, status: 403, text: async () => '{}'}),
  }), /status 403/u);
});
