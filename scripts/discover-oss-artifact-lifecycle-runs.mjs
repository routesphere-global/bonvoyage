#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_CONTRACT = path.join(
  ROOT, 'packaging/release/oss-artifact-lifecycle-contract.json');
const CLASSIFICATION =
  'routesphere-bonvoyage-oss-artifact-lifecycle-run-discovery';
const CONTRACT_CLASSIFICATION =
  'routesphere-bonvoyage-oss-artifact-lifecycle-contract';
const REPOSITORY = 'routesphere-global/bonvoyage';
const REPOSITORY_URL = `https://github.com/${REPOSITORY}`;
const CURRENT = Object.freeze({
  name: 'OSS Artifact Lifecycle Evidence',
  path: '.github/workflows/oss-artifact-lifecycle.yml',
});
const WORKFLOWS = Object.freeze({
  debian: Object.freeze({
    name: 'OSS Debian Reproducibility Candidate',
    path: '.github/workflows/oss-deb-reproducibility.yml',
    artifacts: Object.freeze([
      'oss-deb-build-a', 'oss-deb-build-b', 'oss-deb-comparison',
    ]),
  }),
  oci: Object.freeze({
    name: 'OSS OCI Reproducibility Candidate',
    path: '.github/workflows/oss-oci-reproducibility.yml',
    artifacts: Object.freeze([
      'oss-oci-build-a', 'oss-oci-build-b', 'oss-oci-comparison',
    ]),
  }),
});
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
  const normalized = typeof value === 'number' && Number.isSafeInteger(value)
    ? String(value) : value;
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
function canonicalJson(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  const value = JSON.parse(raw);
  requireCondition(`${JSON.stringify(value, null, 2)}\n` === raw,
    'lifecycle contract must be canonical JSON');
  return object(value, 'lifecycle contract');
}

function parseVersion(value, label) {
  const match = TAG.exec(value);
  requireCondition(match !== null, `${label} must be a strict version tag`);
  const dash = value.indexOf('-');
  const core = value.slice(1, dash === -1 ? undefined : dash);
  const prerelease = dash === -1 ? undefined : value.slice(dash + 1);
  const prereleaseParts = prerelease === undefined ? null : prerelease.split('.');
  requireCondition(prereleaseParts === null || prereleaseParts.every((part) =>
    !/^[0-9]+$/u.test(part) || part === '0' || !part.startsWith('0')),
  `${label} contains a numeric prerelease identifier with a leading zero`);
  return {
    core: core.split('.'),
    prerelease: prereleaseParts,
  };
}

function compareNumericStrings(left, right) {
  if (left.length !== right.length) return left.length > right.length ? 1 : -1;
  if (left === right) return 0;
  return left > right ? 1 : -1;
}

function compareVersions(leftValue, rightValue) {
  const left = parseVersion(leftValue, 'candidate tag');
  const right = parseVersion(rightValue, 'baseline tag');
  for (let index = 0; index < left.core.length; index += 1) {
    const comparison = compareNumericStrings(left.core[index], right.core[index]);
    if (comparison !== 0) return comparison;
  }
  if (left.prerelease === null || right.prerelease === null) {
    if (left.prerelease === right.prerelease) return 0;
    return left.prerelease === null ? 1 : -1;
  }
  const length = Math.max(left.prerelease.length, right.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = left.prerelease[index];
    const rightPart = right.prerelease[index];
    if (leftPart === undefined || rightPart === undefined) {
      return leftPart === undefined ? -1 : 1;
    }
    if (leftPart === rightPart) continue;
    const leftNumeric = /^[0-9]+$/u.test(leftPart);
    const rightNumeric = /^[0-9]+$/u.test(rightPart);
    if (leftNumeric && rightNumeric) return compareNumericStrings(leftPart, rightPart);
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return leftPart > rightPart ? 1 : -1;
  }
  return 0;
}

function validateContract(contract) {
  requireCondition(contract.schema_version === 1 &&
    contract.classification === CONTRACT_CLASSIFICATION &&
    contract.source_repository === REPOSITORY_URL &&
    contract.platform === 'linux/amd64', 'lifecycle contract identity changed');
  const source = object(contract.baseline?.source, 'baseline source');
  requireCondition(COMMIT.test(source.commit ?? '') && TAG.test(source.tag ?? ''),
    'baseline source identity changed');
  const runs = object(contract.baseline?.hosted_runs, 'baseline hosted runs');
  return {
    source: {commit: source.commit, tag: source.tag},
    runs: {
      debian: runId(runs.debian, 'baseline Debian run ID'),
      oci: runId(runs.oci, 'baseline OCI run ID'),
    },
  };
}

function context(options) {
  requireCondition(options.repository === REPOSITORY,
    'lifecycle discovery is public-repository-only');
  requireCondition(TAG.test(options.tag ?? ''),
    'lifecycle discovery requires a strict candidate tag');
  requireCondition(COMMIT.test(options.commit ?? ''),
    'lifecycle discovery requires a full lowercase candidate commit');
  const contract = validateContract(options.contract);
  requireCondition(compareVersions(options.tag, contract.source.tag) > 0 &&
    options.commit !== contract.source.commit,
  'candidate source must be newer than and differ from the rollback baseline');
  return {
    repository: options.repository,
    tag: options.tag,
    commit: options.commit,
    currentRunId: runId(options.currentRunId, 'current run ID'),
    contract,
  };
}

function validateRun(value, label, specification, expected, currentCreated,
  expectedId = undefined, requireExactTag = true) {
  const run = object(value, label);
  const id = runId(run.id, `${label}.id`);
  const created = timestamp(run.created_at, `${label}.created_at`);
  requireCondition((expectedId === undefined || id === expectedId) &&
    repository(run, label) === REPOSITORY &&
    run.name === specification.name && run.path === specification.path &&
    run.event === 'workflow_dispatch' &&
    (!requireExactTag || run.head_branch === expected.tag) &&
    run.head_sha === expected.commit && run.run_attempt === 1 &&
    run.status === 'completed' && run.conclusion === 'success' &&
    created.milliseconds <= currentCreated.milliseconds,
  `${label} does not match the required successful protected identity`);
  return {id, created_at: created.canonical, head_branch: run.head_branch};
}

function selectCandidate(responseValue, label, specification, expected, currentCreated) {
  const response = object(responseValue, `${label} workflow response`);
  requireCondition(Number.isSafeInteger(response.total_count) &&
    response.total_count >= 0 && response.total_count <= 100,
  `${label} workflow response must fit one complete page`);
  const runs = array(response.workflow_runs, `${label} workflow runs`);
  requireCondition(runs.length === response.total_count,
    `${label} workflow response is incomplete or paginated`);
  const matches = runs.map((run, index) => validateRun(
    run, `${label} workflow run ${index}`, specification, expected, currentCreated,
    undefined, false))
    .filter((run) => run.head_branch === expected.tag);
  requireCondition(matches.length === 1,
    `${label} requires exactly one successful run for the exact candidate`);
  return matches[0];
}

function validateArtifacts(value, label, run, expectedNames, now) {
  const response = object(value, `${label} artifact response`);
  requireCondition(response.total_count === expectedNames.length,
    `${label} artifact count changed`);
  const artifacts = array(response.artifacts, `${label} artifacts`);
  requireCondition(artifacts.length === response.total_count,
    `${label} artifact response is incomplete`);
  const names = [];
  for (const [index, valueArtifact] of artifacts.entries()) {
    const artifact = object(valueArtifact, `${label} artifact ${index}`);
    const workflow = object(artifact.workflow_run, `${label} artifact ${index}.workflow_run`);
    const expires = timestamp(artifact.expires_at, `${label} artifact ${index}.expires_at`);
    requireCondition(runId(workflow.id, `${label} artifact ${index} run ID`) === run.id &&
      workflow.head_branch === run.tag && workflow.head_sha === run.commit &&
      artifact.expired === false && expires.milliseconds > now,
    `${label} artifact ${index} is expired or bound to the wrong run`);
    names.push(string(artifact.name, `${label} artifact ${index}.name`));
  }
  requireCondition(JSON.stringify(names.sort()) === JSON.stringify([...expectedNames].sort()),
    `${label} artifact names changed`);
}

export function selectArtifactLifecycleRuns(options) {
  const expected = context(options);
  const current = object(options.currentRun, 'current lifecycle run');
  const currentCreated = timestamp(current.created_at, 'current lifecycle run.created_at');
  requireCondition(runId(current.id, 'current lifecycle run ID') === expected.currentRunId &&
    repository(current, 'current lifecycle run') === REPOSITORY &&
    current.name === CURRENT.name && current.path === CURRENT.path &&
    current.event === 'workflow_dispatch' && current.head_branch === expected.tag &&
    current.head_sha === expected.commit && current.run_attempt === 1 &&
    current.status === 'in_progress' && current.conclusion === null,
  'current lifecycle run does not match the protected candidate execution');

  const baseline = {};
  const candidate = {};
  for (const kind of ['debian', 'oci']) {
    baseline[kind] = validateRun(
      options.baselineRuns[kind], `baseline ${kind} run`, WORKFLOWS[kind],
      expected.contract.source, currentCreated, expected.contract.runs[kind]);
    candidate[kind] = selectCandidate(
      options.candidateResponses[kind], `candidate ${kind}`, WORKFLOWS[kind],
      {tag: expected.tag, commit: expected.commit}, currentCreated);
    baseline[kind].tag = expected.contract.source.tag;
    baseline[kind].commit = expected.contract.source.commit;
    candidate[kind].tag = expected.tag;
    candidate[kind].commit = expected.commit;
    requireCondition(candidate[kind].id !== baseline[kind].id,
      `${kind} candidate run must differ from the baseline run`);
    validateArtifacts(options.artifactResponses[`baseline_${kind}`],
      `baseline ${kind}`, baseline[kind], WORKFLOWS[kind].artifacts,
      currentCreated.milliseconds);
    validateArtifacts(options.artifactResponses[`candidate_${kind}`],
      `candidate ${kind}`, candidate[kind], WORKFLOWS[kind].artifacts,
      currentCreated.milliseconds);
  }
  requireCondition(new Set([
    baseline.debian.id, baseline.oci.id, candidate.debian.id, candidate.oci.id,
  ]).size === 4, 'all baseline and candidate runs must be distinct');
  const createdAt = (values) => new Date(Math.max(...values.map(
    (value) => timestamp(value.created_at, 'selected run created_at').milliseconds)))
    .toISOString();
  return {
    schema_version: 1,
    classification: CLASSIFICATION,
    repository: REPOSITORY_URL,
    current_run_id: expected.currentRunId,
    baseline: {
      source: {...expected.contract.source, dirty: false},
      runs: {debian: baseline.debian, oci: baseline.oci},
      created_at: createdAt(Object.values(baseline)),
    },
    candidate: {
      source: {commit: expected.commit, tag: expected.tag, dirty: false},
      runs: {debian: candidate.debian, oci: candidate.oci},
      created_at: createdAt(Object.values(candidate)),
    },
    authority: {
      release_admitted: false, publishable: false,
      github_release_created: false, package_uploaded: false,
      container_uploaded: false, signature_created: false,
      provenance_created: false,
    },
  };
}

async function githubJson(url, token, fetchImpl) {
  const response = await fetchImpl(url, {
    method: 'GET',
    headers: {
      Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'routesphere-bonvoyage-lifecycle-discovery',
    },
    redirect: 'error', signal: AbortSignal.timeout(15_000),
  });
  requireCondition(response?.ok === true && response.status === 200,
    `GitHub Actions API request failed with status ${response?.status ?? 'unknown'}`);
  const text = await response.text();
  requireCondition(Buffer.byteLength(text) > 0 &&
    Buffer.byteLength(text) <= MAX_RESPONSE_BYTES,
  'GitHub Actions API returned an empty or oversized response');
  return object(JSON.parse(text), 'GitHub Actions API response');
}

export async function discoverArtifactLifecycleRuns(options, dependencies = {}) {
  const contract = canonicalJson(path.resolve(options.contractPath ?? DEFAULT_CONTRACT));
  const expected = context({...options, contract});
  const token = dependencies.token ?? process.env.GITHUB_TOKEN;
  requireCondition(typeof token === 'string' && token.length >= 16 && !/[\r\n]/u.test(token),
    'GITHUB_TOKEN is required');
  const fetchImpl = dependencies.fetchImpl ?? globalThis.fetch;
  requireCondition(typeof fetchImpl === 'function', 'Fetch implementation is required');
  const api = `https://api.github.com/repos/${REPOSITORY}`;
  const query = `event=workflow_dispatch&status=success&head_sha=${expected.commit}&per_page=100`;
  const urls = {
    current: `${api}/actions/runs/${expected.currentRunId}`,
    baseline_debian: `${api}/actions/runs/${expected.contract.runs.debian}`,
    baseline_oci: `${api}/actions/runs/${expected.contract.runs.oci}`,
    candidate_debian: `${api}/actions/workflows/${encodeURIComponent(WORKFLOWS.debian.path)}/runs?${query}`,
    candidate_oci: `${api}/actions/workflows/${encodeURIComponent(WORKFLOWS.oci.path)}/runs?${query}`,
  };
  const values = Object.fromEntries(await Promise.all(Object.entries(urls).map(
    async ([name, url]) => [name, await githubJson(url, token, fetchImpl)])));
  const candidateRuns = {};
  for (const kind of ['debian', 'oci']) {
    const specification = WORKFLOWS[kind];
    const response = object(values[`candidate_${kind}`], `${kind} candidate response`);
    const matches = array(response.workflow_runs, `${kind} candidate workflow runs`)
      .filter((run) => object(run, `${kind} candidate run`).head_branch === expected.tag);
    requireCondition(matches.length === 1, `${kind} candidate run is not unique`);
    candidateRuns[kind] = runId(matches[0].id, `${kind} candidate run ID`);
  }
  const artifactUrls = {
    baseline_debian: `${api}/actions/runs/${expected.contract.runs.debian}/artifacts`,
    baseline_oci: `${api}/actions/runs/${expected.contract.runs.oci}/artifacts`,
    candidate_debian: `${api}/actions/runs/${candidateRuns.debian}/artifacts`,
    candidate_oci: `${api}/actions/runs/${candidateRuns.oci}/artifacts`,
  };
  const artifactResponses = Object.fromEntries(await Promise.all(
    Object.entries(artifactUrls).map(async ([name, url]) =>
      [name, await githubJson(url, token, fetchImpl)])));
  return selectArtifactLifecycleRuns({
    ...expected,
    contract,
    currentRun: values.current,
    baselineRuns: {debian: values.baseline_debian, oci: values.baseline_oci},
    candidateResponses: {
      debian: values.candidate_debian, oci: values.candidate_oci,
    },
    artifactResponses,
  });
}

export function writeGithubOutputs(filePath, discovery) {
  string(filePath, 'GitHub output path');
  const values = {
    baseline_deb_run_id: discovery?.baseline?.runs?.debian?.id,
    baseline_oci_run_id: discovery?.baseline?.runs?.oci?.id,
    candidate_deb_run_id: discovery?.candidate?.runs?.debian?.id,
    candidate_oci_run_id: discovery?.candidate?.runs?.oci?.id,
    baseline_created_at: discovery?.baseline?.created_at,
    candidate_created_at: discovery?.candidate?.created_at,
    baseline_commit: discovery?.baseline?.source?.commit,
    baseline_tag: discovery?.baseline?.source?.tag,
    candidate_commit: discovery?.candidate?.source?.commit,
    candidate_tag: discovery?.candidate?.source?.tag,
  };
  const lines = Object.entries(values).map(([name, value]) => {
    if (name.endsWith('_run_id')) return `${name}=${runId(value, name)}`;
    if (name.endsWith('_commit')) {
      requireCondition(typeof value === 'string' && COMMIT.test(value),
        `${name} must be a full lowercase commit`);
      return `${name}=${value}`;
    }
    if (name.endsWith('_tag')) {
      requireCondition(typeof value === 'string' && TAG.test(value),
        `${name} must be a strict tag`);
      return `${name}=${value}`;
    }
    return `${name}=${timestamp(value, name).canonical}`;
  });
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
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    requireCondition(argv[index]?.startsWith('--') && argv[index + 1] !== undefined &&
      !values.has(argv[index]), `unsupported, duplicate or incomplete argument ${argv[index]}`);
    values.set(argv[index], argv[index + 1]);
  }
  const required = [
    '--repository', '--tag', '--commit', '--current-run-id', '--github-output',
  ];
  requireCondition(required.every((key) => values.has(key)) &&
    [...values.keys()].every((key) => [...required, '--contract'].includes(key)),
  'all lifecycle discovery arguments are required');
  return {
    repository: values.get('--repository'), tag: values.get('--tag'),
    commit: values.get('--commit'), currentRunId: values.get('--current-run-id'),
    githubOutput: values.get('--github-output'),
    contractPath: values.get('--contract') ?? DEFAULT_CONTRACT,
  };
}

if (fileURLToPath(import.meta.url) === path.resolve(process.argv[1] ?? '')) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const result = await discoverArtifactLifecycleRuns(options);
    writeGithubOutputs(options.githubOutput, result);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`artifact lifecycle discovery rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}
