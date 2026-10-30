#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

const CLASSIFICATION =
  'routesphere-bonvoyage-oss-release-candidate-run-discovery';
const REPOSITORY = 'routesphere-global/bonvoyage';
const REPOSITORY_URL = `https://github.com/${REPOSITORY}`;
const RELEASE_WORKFLOW = Object.freeze({
  name: 'OSS Release Candidate Intake Foundation',
  path: '.github/workflows/release.yml',
});
const CANDIDATE_WORKFLOWS = Object.freeze({
  debian: Object.freeze({
    name: 'OSS Debian Reproducibility Candidate',
    path: '.github/workflows/oss-deb-reproducibility.yml',
  }),
  oci: Object.freeze({
    name: 'OSS OCI Reproducibility Candidate',
    path: '.github/workflows/oss-oci-reproducibility.yml',
  }),
});
const TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const RUN_ID = /^[1-9][0-9]*$/u;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

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

function requireArray(value, label) {
  requireCondition(Array.isArray(value), `${label} must be an array`);
  return value;
}

function requireString(value, label) {
  requireCondition(typeof value === 'string' && value.length > 0 && value === value.trim(),
    `${label} must be a nonempty trimmed string`);
  return value;
}

function normalizeRunId(value, label) {
  const normalized = typeof value === 'number' && Number.isSafeInteger(value)
    ? String(value)
    : value;
  requireCondition(typeof normalized === 'string' && RUN_ID.test(normalized),
    `${label} must be a positive GitHub run ID`);
  return normalized;
}

function normalizeTimestamp(value, label) {
  requireString(value, label);
  const parsed = new Date(value);
  requireCondition(Number.isFinite(parsed.valueOf()) &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value),
  `${label} must be a UTC GitHub timestamp`);
  return {milliseconds: parsed.valueOf(), canonical: parsed.toISOString()};
}

function repositoryName(run, label) {
  return requireString(requireObject(run.repository, `${label}.repository`).full_name,
    `${label}.repository.full_name`);
}

function validateSourceContext({repository, tag, commit, currentRunId}) {
  requireCondition(repository === REPOSITORY, 'candidate discovery is public-repository-only');
  requireCondition(TAG.test(tag ?? ''), 'candidate discovery requires a strict release tag');
  requireCondition(COMMIT.test(commit ?? ''),
    'candidate discovery requires a lowercase full Git commit');
  return {
    repository,
    tag,
    commit,
    currentRunId: normalizeRunId(currentRunId, 'current run ID'),
  };
}

function validateCurrentRun(value, context) {
  const run = requireObject(value, 'current release workflow run');
  const id = normalizeRunId(run.id, 'current release workflow run ID');
  requireCondition(id === context.currentRunId &&
    repositoryName(run, 'current release workflow run') === context.repository &&
    run.name === RELEASE_WORKFLOW.name &&
    run.path === RELEASE_WORKFLOW.path &&
    run.event === 'workflow_dispatch' &&
    run.head_branch === context.tag &&
    run.head_sha === context.commit &&
    run.run_attempt === 1 &&
    run.status === 'in_progress' &&
    run.conclusion === null,
  'current release workflow run does not match the protected tag execution');
  const created = normalizeTimestamp(run.created_at,
    'current release workflow run created_at');
  return {id, created};
}

function validateCandidateResponse(value, label, specification, context, current) {
  const response = requireObject(value, `${label} workflow response`);
  requireCondition(Number.isSafeInteger(response.total_count) &&
    response.total_count >= 0 && response.total_count <= 100,
  `${label} workflow response must fit one complete page`);
  const runs = requireArray(response.workflow_runs, `${label} workflow runs`);
  requireCondition(runs.length === response.total_count,
    `${label} workflow response is incomplete or paginated`);

  const matching = [];
  for (const [index, valueRun] of runs.entries()) {
    const runLabel = `${label} workflow run ${index}`;
    const run = requireObject(valueRun, runLabel);
    requireCondition(repositoryName(run, runLabel) === context.repository &&
      run.name === specification.name &&
      run.path === specification.path &&
      run.event === 'workflow_dispatch' &&
      run.head_sha === context.commit &&
      run.status === 'completed' &&
      run.conclusion === 'success' &&
      run.run_attempt === 1,
    `${runLabel} does not match the required successful workflow identity`);
    const created = normalizeTimestamp(run.created_at, `${runLabel}.created_at`);
    requireCondition(created.milliseconds <= current.created.milliseconds,
      `${runLabel} was created after the release intake run`);
    if (run.head_branch === context.tag) {
      matching.push({
        id: normalizeRunId(run.id, `${runLabel} ID`),
        created_at: created.canonical,
        workflow: specification.name,
        workflow_path: specification.path,
      });
    }
  }
  requireCondition(matching.length === 1,
    `${label} requires exactly one successful run for the exact tag and commit`);
  requireCondition(matching[0].id !== current.id,
    `${label} candidate run must differ from the release workflow run`);
  return matching[0];
}

export function selectReleaseCandidateRuns({
  repository,
  tag,
  commit,
  currentRunId,
  currentRun,
  debianResponse,
  ociResponse,
}) {
  const context = validateSourceContext({repository, tag, commit, currentRunId});
  const current = validateCurrentRun(currentRun, context);
  const debian = validateCandidateResponse(
    debianResponse, 'Debian', CANDIDATE_WORKFLOWS.debian, context, current);
  const oci = validateCandidateResponse(
    ociResponse, 'OCI', CANDIDATE_WORKFLOWS.oci, context, current);
  requireCondition(debian.id !== oci.id,
    'Debian and OCI candidate workflow runs must be distinct');
  return {
    schema_version: 1,
    classification: CLASSIFICATION,
    repository: REPOSITORY_URL,
    source: {commit, tag, dirty: false},
    release_workflow_run: {
      id: current.id,
      created_at: current.created.canonical,
    },
    candidates: {debian, oci},
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
      'User-Agent': 'routesphere-bonvoyage-release-candidate-discovery',
    },
    redirect: 'error',
    signal: AbortSignal.timeout(15_000),
  });
  requireCondition(response?.ok === true && response.status === 200,
    `GitHub Actions API request failed with status ${response?.status ?? 'unknown'}`);
  const text = await response.text();
  requireCondition(Buffer.byteLength(text, 'utf8') > 0 &&
    Buffer.byteLength(text, 'utf8') <= MAX_RESPONSE_BYTES,
  'GitHub Actions API returned an empty or oversized response');
  try {
    return requireObject(JSON.parse(text), 'GitHub Actions API response');
  } catch (error) {
    fail(`GitHub Actions API returned invalid JSON: ${error.message}`);
  }
}

export async function discoverReleaseCandidateRuns(options, dependencies = {}) {
  const context = validateSourceContext(options);
  const token = dependencies.token ?? process.env.GITHUB_TOKEN;
  requireCondition(typeof token === 'string' && token.length >= 16 &&
    !/[\r\n]/u.test(token), 'GITHUB_TOKEN is required');
  const fetchImpl = dependencies.fetchImpl ?? globalThis.fetch;
  requireCondition(typeof fetchImpl === 'function', 'Fetch implementation is required');
  const api = 'https://api.github.com';
  const query = `event=workflow_dispatch&status=success&head_sha=${context.commit}&per_page=100`;
  const [currentRun, debianResponse, ociResponse] = await Promise.all([
    githubJson(`${api}/repos/${REPOSITORY}/actions/runs/${context.currentRunId}`,
      token, fetchImpl),
    githubJson(`${api}/repos/${REPOSITORY}/actions/workflows/${encodeURIComponent(CANDIDATE_WORKFLOWS.debian.path)}/runs?${query}`,
      token, fetchImpl),
    githubJson(`${api}/repos/${REPOSITORY}/actions/workflows/${encodeURIComponent(CANDIDATE_WORKFLOWS.oci.path)}/runs?${query}`,
      token, fetchImpl),
  ]);
  return selectReleaseCandidateRuns({
    ...context,
    currentRun,
    debianResponse,
    ociResponse,
  });
}

export function writeGithubOutputs(filePath, discovery) {
  requireString(filePath, 'GitHub output path');
  const lines = [
    `deb_run_id=${normalizeRunId(discovery?.candidates?.debian?.id, 'Debian run ID')}`,
    `oci_run_id=${normalizeRunId(discovery?.candidates?.oci?.id, 'OCI run ID')}`,
    `created_at=${normalizeTimestamp(discovery?.release_workflow_run?.created_at,
      'release workflow created_at').canonical}`,
  ];
  const descriptor = fs.openSync(path.resolve(filePath),
    fs.constants.O_WRONLY | fs.constants.O_APPEND | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const metadata = fs.fstatSync(descriptor);
    requireCondition(metadata.isFile() && metadata.nlink === 1,
      'GitHub output must be a regular single-link file');
    fs.writeSync(descriptor, `${lines.join('\n')}\n`, null, 'utf8');
  } finally {
    fs.closeSync(descriptor);
  }
}

function parseArguments(argv) {
  const mapping = {
    '--repository': 'repository',
    '--tag': 'tag',
    '--commit': 'commit',
    '--current-run-id': 'currentRunId',
    '--github-output': 'githubOutput',
  };
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const key = mapping[argv[index]];
    requireCondition(key !== undefined && options[key] === undefined &&
      index + 1 < argv.length, `unsupported, duplicate or incomplete argument ${argv[index]}`);
    options[key] = argv[index + 1];
    index += 1;
  }
  requireCondition(Object.keys(mapping).every((argument) =>
    options[mapping[argument]] !== undefined), 'all candidate discovery arguments are required');
  return options;
}

if (fileURLToPath(import.meta.url) === path.resolve(process.argv[1] ?? '')) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const result = await discoverReleaseCandidateRuns(options);
    writeGithubOutputs(options.githubOutput, result);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`OSS release candidate discovery rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}
