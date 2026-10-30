#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

const REPOSITORY = 'routesphere-global/bonvoyage';
const REPOSITORY_URL = `https://github.com/${REPOSITORY}`;
const CURRENT = Object.freeze({
  name: 'OSS Supply Chain Evidence Producers',
  path: '.github/workflows/oss-supply-chain-producers.yml',
});
const PRIOR = Object.freeze({
  name: 'OSS Release Candidate Intake Foundation',
  path: '.github/workflows/release.yml',
});
const CLASSIFICATION = 'routesphere-bonvoyage-oss-release-intake-run-discovery';
const TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const RUN_ID = /^[1-9][0-9]*$/u;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

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
function string(value, label) {
  requireCondition(typeof value === 'string' && value.length > 0 && value === value.trim(),
    `${label} must be a nonempty trimmed string`);
  return value;
}
function runId(value, label) {
  const normalized = typeof value === 'number' && Number.isSafeInteger(value) ? String(value) : value;
  requireCondition(typeof normalized === 'string' && RUN_ID.test(normalized),
    `${label} must be a positive run ID`);
  return normalized;
}
function timestamp(value, label) {
  string(value, label);
  const parsed = new Date(value);
  requireCondition(Number.isFinite(parsed.valueOf()) &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value),
  `${label} must be a UTC GitHub timestamp`);
  return {milliseconds: parsed.valueOf(), canonical: parsed.toISOString()};
}
function repository(run, label) {
  return string(object(run.repository, `${label}.repository`).full_name,
    `${label}.repository.full_name`);
}
function context(options) {
  requireCondition(options.repository === REPOSITORY, 'discovery is public-repository-only');
  requireCondition(TAG.test(options.tag ?? ''), 'discovery requires a strict release tag');
  requireCondition(COMMIT.test(options.commit ?? ''), 'discovery requires a full lowercase commit');
  return {...options, currentRunId: runId(options.currentRunId, 'current run ID')};
}

export function selectReleaseIntakeRun(options) {
  const expected = context(options);
  const current = object(options.currentRun, 'current producer run');
  const currentCreated = timestamp(current.created_at, 'current producer run.created_at');
  requireCondition(runId(current.id, 'current producer run ID') === expected.currentRunId &&
    repository(current, 'current producer run') === REPOSITORY &&
    current.name === CURRENT.name && current.path === CURRENT.path &&
    current.event === 'workflow_dispatch' && current.head_branch === expected.tag &&
    current.head_sha === expected.commit && current.run_attempt === 1 &&
    current.status === 'in_progress' && current.conclusion === null,
  'current producer run does not match the protected tag execution');

  const response = object(options.releaseResponse, 'release workflow response');
  requireCondition(Number.isSafeInteger(response.total_count) && response.total_count <= 100,
    'release workflow response must fit one complete page');
  const runs = array(response.workflow_runs, 'release workflow runs');
  requireCondition(runs.length === response.total_count,
    'release workflow response is incomplete or paginated');
  const matches = runs.filter((value, index) => {
    const run = object(value, `release workflow run ${index}`);
    requireCondition(repository(run, `release workflow run ${index}`) === REPOSITORY &&
      run.name === PRIOR.name && run.path === PRIOR.path && run.event === 'workflow_dispatch' &&
      run.head_sha === expected.commit && run.run_attempt === 1 &&
      run.status === 'completed' && run.conclusion === 'success',
    `release workflow run ${index} has an unexpected identity`);
    const created = timestamp(run.created_at, `release workflow run ${index}.created_at`);
    requireCondition(created.milliseconds <= currentCreated.milliseconds,
      `release workflow run ${index} was created after the producer run`);
    return run.head_branch === expected.tag;
  });
  requireCondition(matches.length === 1,
    'exactly one successful prior candidate intake is required');
  const selected = matches[0];
  return {
    schema_version: 1,
    classification: CLASSIFICATION,
    repository: REPOSITORY_URL,
    source: {commit: expected.commit, tag: expected.tag, dirty: false},
    current_run_id: expected.currentRunId,
    candidate_run_id: runId(selected.id, 'candidate intake run ID'),
    authority: {
      release_admitted: false,
      publishable: false,
      github_release_created: false,
      package_uploaded: false,
      container_uploaded: false,
      signature_created: false,
      provenance_created: false,
    },
  };
}

async function githubJson(url, token, fetchImpl) {
  const response = await fetchImpl(url, {
    method: 'GET',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'routesphere-bonvoyage-release-intake-discovery',
    },
    redirect: 'error',
    signal: AbortSignal.timeout(15_000),
  });
  requireCondition(response?.ok === true && response.status === 200,
    `GitHub Actions API request failed with status ${response?.status ?? 'unknown'}`);
  const text = await response.text();
  requireCondition(Buffer.byteLength(text) > 0 && Buffer.byteLength(text) <= MAX_RESPONSE_BYTES,
    'GitHub Actions API returned an empty or oversized response');
  return object(JSON.parse(text), 'GitHub Actions API response');
}

export async function discoverReleaseIntakeRun(options, dependencies = {}) {
  const expected = context(options);
  const token = dependencies.token ?? process.env.GITHUB_TOKEN;
  requireCondition(typeof token === 'string' && token.length >= 16 && !/[\r\n]/u.test(token),
    'GITHUB_TOKEN is required');
  const fetchImpl = dependencies.fetchImpl ?? globalThis.fetch;
  const api = 'https://api.github.com';
  const query = `event=workflow_dispatch&status=success&head_sha=${expected.commit}&per_page=100`;
  const [currentRun, releaseResponse] = await Promise.all([
    githubJson(`${api}/repos/${REPOSITORY}/actions/runs/${expected.currentRunId}`,
      token, fetchImpl),
    githubJson(`${api}/repos/${REPOSITORY}/actions/workflows/${encodeURIComponent(PRIOR.path)}/runs?${query}`,
      token, fetchImpl),
  ]);
  return selectReleaseIntakeRun({...expected, currentRun, releaseResponse});
}

export function writeGithubOutput(filePath, discovery) {
  string(filePath, 'GitHub output path');
  const descriptor = fs.openSync(path.resolve(filePath),
    fs.constants.O_WRONLY | fs.constants.O_APPEND | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const stat = fs.fstatSync(descriptor);
    requireCondition(stat.isFile() && stat.nlink === 1,
      'GitHub output must be a regular single-link file');
    fs.writeSync(descriptor,
      `candidate_run_id=${runId(discovery?.candidate_run_id, 'candidate run ID')}\n`,
      null, 'utf8');
  } finally {
    fs.closeSync(descriptor);
  }
}

function argumentsFrom(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    requireCondition(argv[index]?.startsWith('--') && argv[index + 1] !== undefined,
      'arguments must be --name value pairs');
    values.set(argv[index].slice(2), argv[index + 1]);
  }
  return values;
}

async function main(argv) {
  const values = argumentsFrom(argv);
  const result = await discoverReleaseIntakeRun({
    repository: values.get('repository'), tag: values.get('tag'),
    commit: values.get('commit'), currentRunId: values.get('current-run-id'),
  });
  writeGithubOutput(values.get('github-output'), result);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`release intake discovery failed: ${error.message}\n`);
    process.exitCode = 2;
  });
}
