import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  discoverArtifactLifecycleRuns,
  selectArtifactLifecycleRuns,
  writeGithubOutputs,
} from './discover-oss-artifact-lifecycle-runs.mjs';

const REPOSITORY = 'routesphere-global/bonvoyage';
const REPOSITORY_URL = `https://github.com/${REPOSITORY}`;
const BASELINE_TAG = 'v1.0.0-rc.6';
const BASELINE_COMMIT = '7'.repeat(40);
const CANDIDATE_TAG = 'v1.0.0-rc.7';
const CANDIDATE_COMMIT = 'a'.repeat(40);
const CURRENT_RUN = '42000000000';
const BASELINE_DEB_RUN = '40984886786';
const BASELINE_OCI_RUN = '40984894383';
const CANDIDATE_DEB_RUN = '42000000001';
const CANDIDATE_OCI_RUN = '42000000002';
const TOKEN = 'github-token-fixture-value';
const CURRENT_CREATED = '2026-10-30T05:00:00Z';

const WORKFLOWS = {
  debian: {
    name: 'OSS Debian Reproducibility Candidate',
    path: '.github/workflows/oss-deb-reproducibility.yml',
    baselineArtifacts: [
      'oss-deb-build-a', 'oss-deb-build-b', 'oss-deb-comparison',
    ],
    candidateArtifacts: [
      'oss-deb-build-a', 'oss-deb-build-b', 'oss-deb-comparison',
      'oss-deb-provenance',
    ],
  },
  oci: {
    name: 'OSS OCI Reproducibility Candidate',
    path: '.github/workflows/oss-oci-reproducibility.yml',
    baselineArtifacts: [
      'oss-oci-build-a', 'oss-oci-build-b', 'oss-oci-comparison',
    ],
    candidateArtifacts: [
      'oss-oci-build-a', 'oss-oci-build-b', 'oss-oci-comparison',
      'oss-oci-provenance',
    ],
  },
};

function contract() {
  return {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-artifact-lifecycle-contract',
    source_repository: REPOSITORY_URL,
    platform: 'linux/amd64',
    baseline: {
      source: {commit: BASELINE_COMMIT, tag: BASELINE_TAG, dirty: false},
      hosted_runs: {debian: BASELINE_DEB_RUN, oci: BASELINE_OCI_RUN},
    },
  };
}

function run({
  id,
  kind,
  tag,
  commit,
  createdAt,
  name = WORKFLOWS[kind]?.name,
  workflowPath = WORKFLOWS[kind]?.path,
  status = 'completed',
  conclusion = 'success',
  event = 'workflow_dispatch',
  attempt = 1,
  repository = REPOSITORY,
}) {
  return {
    id: Number(id),
    name,
    path: workflowPath,
    event,
    status,
    conclusion,
    head_branch: tag,
    head_sha: commit,
    run_attempt: attempt,
    created_at: createdAt,
    repository: {full_name: repository},
  };
}

function currentRun() {
  return run({
    id: CURRENT_RUN,
    tag: CANDIDATE_TAG,
    commit: CANDIDATE_COMMIT,
    createdAt: CURRENT_CREATED,
    name: 'OSS Artifact Lifecycle Evidence',
    workflowPath: '.github/workflows/oss-artifact-lifecycle.yml',
    status: 'in_progress',
    conclusion: null,
  });
}

function buildRun(kind, baseline = false) {
  return run({
    id: baseline
      ? (kind === 'debian' ? BASELINE_DEB_RUN : BASELINE_OCI_RUN)
      : (kind === 'debian' ? CANDIDATE_DEB_RUN : CANDIDATE_OCI_RUN),
    kind,
    tag: baseline ? BASELINE_TAG : CANDIDATE_TAG,
    commit: baseline ? BASELINE_COMMIT : CANDIDATE_COMMIT,
    createdAt: baseline ? '2026-10-29T04:00:00Z' :
      (kind === 'debian' ? '2026-10-30T04:00:00Z' : '2026-10-30T04:01:00Z'),
  });
}

function artifactResponse(kind, baseline = false) {
  const selectedRun = buildRun(kind, baseline);
  const expectedArtifacts = baseline
    ? WORKFLOWS[kind].baselineArtifacts
    : WORKFLOWS[kind].candidateArtifacts;
  return {
    total_count: expectedArtifacts.length,
    artifacts: expectedArtifacts.map((name, index) => ({
      id: 50000000000 + index,
      name,
      expired: false,
      expires_at: '2026-11-02T00:00:00Z',
      workflow_run: {
        id: selectedRun.id,
        head_branch: selectedRun.head_branch,
        head_sha: selectedRun.head_sha,
      },
    })),
  };
}

function fixture() {
  return {
    repository: REPOSITORY,
    tag: CANDIDATE_TAG,
    commit: CANDIDATE_COMMIT,
    currentRunId: CURRENT_RUN,
    contract: contract(),
    currentRun: currentRun(),
    baselineRuns: {
      debian: buildRun('debian', true),
      oci: buildRun('oci', true),
    },
    candidateResponses: {
      debian: {total_count: 1, workflow_runs: [buildRun('debian')]},
      oci: {total_count: 1, workflow_runs: [buildRun('oci')]},
    },
    artifactResponses: {
      baseline_debian: artifactResponse('debian', true),
      baseline_oci: artifactResponse('oci', true),
      candidate_debian: artifactResponse('debian'),
      candidate_oci: artifactResponse('oci'),
    },
  };
}

test('selects exact baseline and candidate evidence without granting release authority', () => {
  const result = selectArtifactLifecycleRuns(fixture());
  assert.equal(result.baseline.runs.debian.id, BASELINE_DEB_RUN);
  assert.equal(result.baseline.runs.oci.id, BASELINE_OCI_RUN);
  assert.equal(result.candidate.runs.debian.id, CANDIDATE_DEB_RUN);
  assert.equal(result.candidate.runs.oci.id, CANDIDATE_OCI_RUN);
  assert.deepEqual(result.baseline.source,
    {commit: BASELINE_COMMIT, tag: BASELINE_TAG, dirty: false});
  assert.deepEqual(result.candidate.source,
    {commit: CANDIDATE_COMMIT, tag: CANDIDATE_TAG, dirty: false});
  assert.ok(Object.values(result.authority).every((value) => value === false));
  assert.equal(JSON.stringify(result).includes(TOKEN), false);
});

test('validates unrelated same-commit runs but selects only the exact candidate tag', () => {
  const value = fixture();
  value.candidateResponses.debian.workflow_runs.unshift({
    ...buildRun('debian'),
    id: 42000000003,
    head_branch: 'v1.0.0-rc.8',
  });
  value.candidateResponses.debian.total_count = 2;
  const result = selectArtifactLifecycleRuns(value);
  assert.equal(result.candidate.runs.debian.id, CANDIDATE_DEB_RUN);

  value.candidateResponses.debian.workflow_runs[0].event = 'push';
  assert.throws(() => selectArtifactLifecycleRuns(value), /protected identity/u);
});

test('rejects source, current-run, baseline and candidate identity drift', () => {
  const mutations = [
    (value) => { value.repository = 'personal/fork'; },
    (value) => { value.tag = 'main'; },
    (value) => { value.tag = 'v1.0.0-rc.5'; value.currentRun.head_branch = value.tag; },
    (value) => { value.tag = BASELINE_TAG; value.currentRun.head_branch = value.tag; },
    (value) => { value.commit = 'A'.repeat(40); },
    (value) => { value.currentRun.name = 'Different workflow'; },
    (value) => { value.currentRun.status = 'completed'; },
    (value) => { value.currentRun.run_attempt = 2; },
    (value) => { value.baselineRuns.debian.id = 1; },
    (value) => { value.baselineRuns.debian.head_sha = 'b'.repeat(40); },
    (value) => { value.baselineRuns.oci.head_branch = CANDIDATE_TAG; },
    (value) => { value.candidateResponses.debian.workflow_runs[0].repository.full_name = 'personal/fork'; },
    (value) => { value.candidateResponses.debian.workflow_runs[0].path = '.github/workflows/ci.yml'; },
    (value) => { value.candidateResponses.debian.workflow_runs[0].event = 'push'; },
    (value) => { value.candidateResponses.debian.workflow_runs[0].conclusion = 'failure'; },
    (value) => { value.candidateResponses.debian.workflow_runs[0].run_attempt = 2; },
    (value) => { value.candidateResponses.debian.workflow_runs[0].created_at = '2026-10-30T06:00:00Z'; },
  ];
  for (const mutation of mutations) {
    const value = structuredClone(fixture());
    mutation(value);
    assert.throws(() => selectArtifactLifecycleRuns(value));
  }
});

test('rejects duplicate, incomplete and reused workflow runs', () => {
  const duplicate = fixture();
  duplicate.candidateResponses.debian.workflow_runs.push({
    ...buildRun('debian'), id: 42000000003,
  });
  duplicate.candidateResponses.debian.total_count = 2;
  assert.throws(() => selectArtifactLifecycleRuns(duplicate), /exactly one/u);

  const incomplete = fixture();
  incomplete.candidateResponses.debian.total_count = 2;
  assert.throws(() => selectArtifactLifecycleRuns(incomplete), /incomplete or paginated/u);

  const reused = fixture();
  reused.candidateResponses.oci.workflow_runs[0].id = Number(CANDIDATE_DEB_RUN);
  reused.artifactResponses.candidate_oci.artifacts.forEach((artifact) => {
    artifact.workflow_run.id = Number(CANDIDATE_DEB_RUN);
  });
  assert.throws(() => selectArtifactLifecycleRuns(reused), /must be distinct/u);
});

test('rejects missing, extra, expired and incorrectly bound artifacts', () => {
  const mutations = [
    (value) => { value.artifactResponses.baseline_debian.total_count = 2; },
    (value) => { value.artifactResponses.baseline_debian.artifacts.pop(); },
    (value) => { value.artifactResponses.candidate_debian.artifacts[0].name = 'unexpected'; },
    (value) => { value.artifactResponses.candidate_debian.artifacts[0].expired = true; },
    (value) => { value.artifactResponses.candidate_debian.artifacts[0].expires_at = CURRENT_CREATED; },
    (value) => { value.artifactResponses.candidate_oci.artifacts[0].workflow_run.id = 1; },
    (value) => { value.artifactResponses.candidate_oci.artifacts[0].workflow_run.head_branch = BASELINE_TAG; },
    (value) => { value.artifactResponses.candidate_oci.artifacts[0].workflow_run.head_sha = BASELINE_COMMIT; },
  ];
  for (const mutation of mutations) {
    const value = structuredClone(fixture());
    mutation(value);
    assert.throws(() => selectArtifactLifecycleRuns(value));
  }
});

test('writes only bounded outputs to an existing regular single-link file', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-lifecycle-discovery-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const output = path.join(root, 'github-output');
  fs.writeFileSync(output, 'existing=value\n');
  writeGithubOutputs(output, selectArtifactLifecycleRuns(fixture()));
  assert.equal(fs.readFileSync(output, 'utf8'), [
    'existing=value',
    `baseline_deb_run_id=${BASELINE_DEB_RUN}`,
    `baseline_oci_run_id=${BASELINE_OCI_RUN}`,
    `candidate_deb_run_id=${CANDIDATE_DEB_RUN}`,
    `candidate_oci_run_id=${CANDIDATE_OCI_RUN}`,
    'baseline_created_at=2026-10-29T04:00:00.000Z',
    'candidate_created_at=2026-10-30T04:01:00.000Z',
    `baseline_commit=${BASELINE_COMMIT}`,
    `baseline_tag=${BASELINE_TAG}`,
    `candidate_commit=${CANDIDATE_COMMIT}`,
    `candidate_tag=${CANDIDATE_TAG}`,
    '',
  ].join('\n'));

  const link = path.join(root, 'linked-output');
  fs.symlinkSync(output, link);
  assert.throws(() => writeGithubOutputs(link, selectArtifactLifecycleRuns(fixture())));

  const hardLink = path.join(root, 'hard-linked-output');
  fs.linkSync(output, hardLink);
  assert.throws(() => writeGithubOutputs(output, selectArtifactLifecycleRuns(fixture())),
    /single-link/u);
});

test('uses fixed GitHub endpoints and keeps the bearer token out of results', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-lifecycle-contract-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const contractPath = path.join(root, 'contract.json');
  fs.writeFileSync(contractPath, `${JSON.stringify(contract(), null, 2)}\n`);
  const value = fixture();
  const api = `https://api.github.com/repos/${REPOSITORY}`;
  const query = `event=workflow_dispatch&status=success&head_sha=${CANDIDATE_COMMIT}&per_page=100`;
  const responses = new Map([
    [`${api}/actions/runs/${CURRENT_RUN}`, value.currentRun],
    [`${api}/actions/runs/${BASELINE_DEB_RUN}`, value.baselineRuns.debian],
    [`${api}/actions/runs/${BASELINE_OCI_RUN}`, value.baselineRuns.oci],
    [`${api}/actions/workflows/${encodeURIComponent(WORKFLOWS.debian.path)}/runs?${query}`,
      value.candidateResponses.debian],
    [`${api}/actions/workflows/${encodeURIComponent(WORKFLOWS.oci.path)}/runs?${query}`,
      value.candidateResponses.oci],
    [`${api}/actions/runs/${BASELINE_DEB_RUN}/artifacts`,
      value.artifactResponses.baseline_debian],
    [`${api}/actions/runs/${BASELINE_OCI_RUN}/artifacts`,
      value.artifactResponses.baseline_oci],
    [`${api}/actions/runs/${CANDIDATE_DEB_RUN}/artifacts`,
      value.artifactResponses.candidate_debian],
    [`${api}/actions/runs/${CANDIDATE_OCI_RUN}/artifacts`,
      value.artifactResponses.candidate_oci],
  ]);
  const observed = [];
  const fetchImpl = async (url, options) => {
    observed.push(url);
    assert.equal(options.headers.Authorization, `Bearer ${TOKEN}`);
    assert.equal(options.method, 'GET');
    const body = responses.get(url);
    assert.ok(body, `unexpected URL ${url}`);
    return {ok: true, status: 200, text: async () => JSON.stringify(body)};
  };
  const result = await discoverArtifactLifecycleRuns({
    repository: REPOSITORY,
    tag: CANDIDATE_TAG,
    commit: CANDIDATE_COMMIT,
    currentRunId: CURRENT_RUN,
    contractPath,
  }, {token: TOKEN, fetchImpl});
  assert.equal(observed.length, 9);
  assert.equal(new Set(observed).size, 9);
  assert.equal(JSON.stringify(result).includes(TOKEN), false);
});

test('rejects missing tokens and unsuccessful API responses', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-lifecycle-contract-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const contractPath = path.join(root, 'contract.json');
  fs.writeFileSync(contractPath, `${JSON.stringify(contract(), null, 2)}\n`);
  const options = {
    repository: REPOSITORY,
    tag: CANDIDATE_TAG,
    commit: CANDIDATE_COMMIT,
    currentRunId: CURRENT_RUN,
    contractPath,
  };
  await assert.rejects(() => discoverArtifactLifecycleRuns(options, {
    token: '', fetchImpl: async () => { throw new Error('must not run'); },
  }), /GITHUB_TOKEN/u);
  await assert.rejects(() => discoverArtifactLifecycleRuns(options, {
    token: TOKEN,
    fetchImpl: async () => ({ok: false, status: 403, text: async () => '{}'}),
  }), /status 403/u);
});
