#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const defaultContractPath = path.join(root, 'packaging', 'release', 'benchmark',
  'oss-bounded-benchmark-contract.json');

export class Rejected extends Error {}

function requireValue(condition, message) {
  if (!condition) throw new Rejected(message);
}

function readJSON(file, label) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    throw new Rejected(`${label} is not valid JSON: ${error.message}`);
  }
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function safeInteger(value, label) {
  requireValue(Number.isSafeInteger(value) && value >= 0,
    `${label} must be a non-negative safe integer`);
  return value;
}

function finiteNumber(value, label, minimum = 0) {
  requireValue(typeof value === 'number' && Number.isFinite(value) && value >= minimum,
    `${label} must be a finite number greater than or equal to ${minimum}`);
  return value;
}

function exact(actual, expected, label) {
  requireValue(JSON.stringify(actual) === JSON.stringify(expected),
    `${label} differs from the contract`);
}

function exactKeys(value, expected, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  exact(Object.keys(value).sort(), [...expected].sort(), `${label} field inventory`);
}

function near(actual, expected, label) {
  finiteNumber(actual, label);
  finiteNumber(expected, `${label} expected value`);
  const tolerance = Math.max(1e-9, Math.abs(expected) * 1e-9);
  requireValue(Math.abs(actual - expected) <= tolerance,
    `${label} differs from independently derived evidence`);
}

function relativePath(value, label) {
  requireValue(typeof value === 'string' && value.length > 0 &&
    value === value.replaceAll('\\', '/') && !path.posix.isAbsolute(value) &&
    !value.split('/').includes('..') && !value.split('/').includes(''),
  `${label} is not a safe relative path`);
  return value;
}

function renderTemplate(template, repetition) {
  requireValue(typeof template === 'string' && template.includes('%02d'),
    'repetition evidence template is invalid');
  return template.replace('%02d', String(repetition).padStart(2, '0'));
}

function collectFiles(rootPath, current = '') {
  const result = [];
  for (const entry of fs.readdirSync(path.join(rootPath, current),
    {withFileTypes: true}).sort((left, right) => left.name.localeCompare(right.name))) {
    const relative = current ? `${current}/${entry.name}` : entry.name;
    const absolute = path.join(rootPath, relative);
    const stat = fs.lstatSync(absolute);
    requireValue(!stat.isSymbolicLink(), `evidence contains a symbolic link: ${relative}`);
    if (stat.isDirectory()) result.push(...collectFiles(rootPath, relative));
    else {
      requireValue(stat.isFile(), `evidence contains a non-regular file: ${relative}`);
      result.push(relative);
    }
  }
  return result;
}

function readChecksumManifest(evidencePath, relative) {
  const manifestPath = path.join(evidencePath, relative);
  requireValue(fs.existsSync(manifestPath), 'checksum manifest is absent');
  const entries = new Map();
  const text = fs.readFileSync(manifestPath, 'utf8');
  requireValue(text.endsWith('\n'), 'checksum manifest must end with a newline');
  for (const [index, line] of text.trimEnd().split('\n').entries()) {
    const match = line.match(/^([0-9a-f]{64})  ([^\r\n]+)$/);
    requireValue(match, `checksum manifest line ${index + 1} is malformed`);
    const file = relativePath(match[2], `checksum path on line ${index + 1}`);
    requireValue(file !== relative, 'checksum manifest must not list itself');
    requireValue(!entries.has(file), `checksum manifest repeats ${file}`);
    entries.set(file, match[1]);
  }
  const actualFiles = collectFiles(evidencePath)
    .filter(file => file !== relative).sort();
  exact([...entries.keys()].sort(), actualFiles,
    'checksum manifest inventory');
  for (const [file, expected] of entries) {
    requireValue(sha256File(path.join(evidencePath, file)) === expected,
      `checksum mismatch: ${file}`);
  }
  return entries;
}

function metricValue(document, metric) {
  let found = false;
  let sum = 0;
  for (const line of document.split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{[^}]*\})?\s+([^\s]+)(?:\s+\d+)?$/);
    if (!match || match[1] !== metric) continue;
    const value = Number(match[2]);
    finiteNumber(value, `${metric} sample`);
    found = true;
    sum += value;
  }
  requireValue(found, `required metric is absent: ${metric}`);
  return sum;
}

function countDistribution(value, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  const result = new Map();
  for (const [name, count] of Object.entries(value)) {
    safeInteger(count, `${label}.${name}`);
    result.set(name, count);
  }
  return result;
}

function deriveOha(raw, contract, minimumDuration, label) {
  const workload = contract.workload;
  const duration = finiteNumber(raw?.summary?.total, `${label} duration`);
  requireValue(duration >= minimumDuration,
    `${label} duration is shorter than the contract`);
  const statuses = countDistribution(raw.statusCodeDistribution,
    `${label} status distribution`);
  for (const status of statuses.keys()) {
    requireValue(/^[1-5][0-9][0-9]$/.test(status),
      `oha status is invalid: ${status}`);
  }
  const errors = countDistribution(raw.errorDistribution,
    `${label} error distribution`);
  const accepted = statuses.get(String(workload.accepted_status)) || 0;
  const completed = [...statuses.values()].reduce((sum, value) => sum + value, 0);
  const deadline = errors.get('aborted due to deadline') || 0;
  requireValue(deadline <= workload.concurrency,
    'deadline-end cancellations exceed contracted concurrency');
  let transport = 0;
  for (const [name, count] of errors) {
    if (name !== 'aborted due to deadline') transport += count;
  }
  const measured = completed + transport;
  requireValue(measured > 0 && accepted > 0,
    `${label} contains no accepted measured requests`);
  const failures = measured - accepted;
  requireValue(failures >= 0, 'accepted responses exceed measured requests');

  const percentiles = raw.latencyPercentiles;
  requireValue(percentiles && typeof percentiles === 'object' &&
    !Array.isArray(percentiles), `${label} latency percentiles are absent`);
  const latency = {
    p50: finiteNumber(percentiles.p50, `${label} p50`) * 1000,
    p95: finiteNumber(percentiles.p95, `${label} p95`) * 1000,
    p99: finiteNumber(percentiles.p99, `${label} p99`) * 1000,
    p999: finiteNumber(percentiles['p99.9'], `${label} p99.9`) * 1000,
    max: finiteNumber(raw.summary.slowest, `${label} maximum latency`) * 1000,
  };
  requireValue(latency.p50 <= latency.p95 && latency.p95 <= latency.p99 &&
    latency.p99 <= latency.p999 && latency.p999 <= latency.max,
  `${label} latency distribution is not monotonic`);
  return {
    duration_seconds: duration,
    accepted_http_responses: accepted,
    completed_http_responses: completed,
    http_failures: completed - accepted,
    transport_failures: transport,
    deadline_end_cancellations: deadline,
    measured_requests: measured,
    successful_rps: accepted / duration,
    error_rate: failures / measured,
    latency_ms: latency,
  };
}

function validateRawResponse(file, workload) {
  const raw = fs.readFileSync(file);
  const separator = raw.indexOf(Buffer.from('\r\n\r\n'));
  requireValue(separator > 0, 'response probe lacks an HTTP header boundary');
  const headerText = raw.subarray(0, separator).toString('latin1');
  const lines = headerText.split('\r\n');
  requireValue(/^HTTP\/1\.1 200(?:\s|$)/.test(lines.shift() || ''),
    'response probe status differs from HTTP/1.1 200');
  const headers = new Map();
  for (const line of lines) {
    const index = line.indexOf(':');
    requireValue(index > 0, 'response probe contains a malformed header');
    const name = line.slice(0, index).trim().toLowerCase();
    const value = line.slice(index + 1).trim();
    requireValue(!headers.has(name), `response probe repeats ${name}`);
    headers.set(name, value);
  }
  requireValue(!headers.has('transfer-encoding'),
    'response probe must use a fixed Content-Length');
  requireValue(headers.get('content-length') === String(workload.response_bytes),
    'response probe Content-Length differs from the contract');
  const body = raw.subarray(separator + 4);
  exact(body.length, workload.response_bytes, 'response probe body length');
  exact(crypto.createHash('sha256').update(body).digest('hex'),
    workload.response_sha256, 'response probe body digest');
}

function validateCommandJournal(file) {
  const document = fs.readFileSync(file, 'utf8');
  requireValue(document.endsWith('\n') && document.length > 1,
    'command journal is empty or lacks a final newline');
  const records = document.trimEnd().split('\n').map((line, index) => {
    let record;
    try {
      record = JSON.parse(line);
    } catch (error) {
      throw new Rejected(`command journal line ${index + 1} is invalid JSON: ${error.message}`);
    }
    requireValue(typeof record.program === 'string' && record.program.length > 0 &&
      Array.isArray(record.arguments) && record.arguments.every(value =>
        typeof value === 'string') && Number.isSafeInteger(record.status),
    `command journal line ${index + 1} is malformed`);
    return record;
  });
  requireValue(records.some(record => path.basename(record.program) === 'git'),
    'command journal lacks source identity checks');
  requireValue(records.some(record => path.basename(record.program) === 'docker'),
    'command journal lacks Docker observations');
}

function validateRuntime(runtime, roles, maximumRestarts, repetition) {
  exact(runtime.schema_version, 1, `repetition ${repetition} runtime schema`);
  for (const role of ['gateway', 'upstream']) {
    const value = runtime[role];
    requireValue(value && typeof value === 'object',
      `repetition ${repetition} ${role} runtime is absent`);
    exact(value.container_id, roles[role].container_id,
      `repetition ${repetition} ${role} container identity`);
    exact(value.image_id, roles[role].image_id,
      `repetition ${repetition} ${role} image identity`);
    exact(value.status_before, 'running',
      `repetition ${repetition} ${role} initial status`);
    exact(value.status_after, 'running',
      `repetition ${repetition} ${role} final status`);
    safeInteger(value.restart_count_before,
      `repetition ${repetition} ${role} initial restarts`);
    safeInteger(value.restart_count_after,
      `repetition ${repetition} ${role} final restarts`);
    requireValue(value.restart_count_before <= maximumRestarts &&
      value.restart_count_after <= maximumRestarts,
    `repetition ${repetition} ${role} restart bound was exceeded`);
  }
  const loadGenerator = runtime['load-generator'];
  requireValue(loadGenerator && typeof loadGenerator === 'object',
    `repetition ${repetition} load-generator runtime is absent`);
  exact(loadGenerator.image_id, roles['load-generator'].image_id,
    `repetition ${repetition} load-generator image identity`);
  exact(loadGenerator.exit_code, 0,
    `repetition ${repetition} load-generator exit code`);
  requireValue(/^[0-9a-f]{12,64}$/.test(loadGenerator.container_id || ''),
    `repetition ${repetition} load-generator container identity is invalid`);
}

function deriveResources(file, contract, repetition, identities) {
  const lines = fs.readFileSync(file, 'utf8').trimEnd().split('\n');
  requireValue(lines.length > 0 && lines[0] !== '',
    `repetition ${repetition} resource samples are empty`);
  const roles = new Map(contract.acceptance.required_resource_roles
    .map(role => [role, []]));
  for (const [index, line] of lines.entries()) {
    let sample;
    try {
      sample = JSON.parse(line);
    } catch (error) {
      throw new Rejected(`repetition ${repetition} resource sample ${index + 1} is invalid JSON: ${error.message}`);
    }
    requireValue(roles.has(sample.role),
      `repetition ${repetition} resource sample has unexpected role`);
    exact(sample.container_id, identities[sample.role],
      `repetition ${repetition} ${sample.role} resource identity`);
    requireValue(typeof sample.captured_at === 'string' &&
      !Number.isNaN(Date.parse(sample.captured_at)),
    `repetition ${repetition} resource timestamp is invalid`);
    finiteNumber(sample.cpu_percent,
      `repetition ${repetition} ${sample.role} CPU`);
    safeInteger(sample.memory_bytes,
      `repetition ${repetition} ${sample.role} memory`);
    roles.get(sample.role).push(sample);
  }
  const sampleCounts = {};
  const averageCPU = {};
  const peakMemory = {};
  for (const [role, samples] of roles) {
    requireValue(samples.length >= contract.acceptance.minimum_resource_samples_per_role,
      `repetition ${repetition} ${role} has too few resource samples`);
    sampleCounts[role] = samples.length;
    averageCPU[role] = samples.reduce((sum, sample) => sum + sample.cpu_percent, 0) /
      samples.length;
    peakMemory[role] = Math.max(...samples.map(sample => sample.memory_bytes));
  }
  return {
    sample_counts: sampleCounts,
    average_cpu_percent: averageCPU,
    peak_memory_bytes: peakMemory,
  };
}

function validateCounterEvidence(beforeDocument, afterDocument, contract, derived,
  repetition) {
  const requestMetric = 'bonvoyage_bonvoyage_gateway_requests_total';
  const responseMetric = 'bonvoyage_bonvoyage_gateway_responses_2xx_total';
  const upstreamMetric =
    'bonvoyage_bonvoyage_gateway_upstream_endpoint_selections_total';
  const deltas = {
    requests: metricValue(afterDocument, requestMetric) -
      metricValue(beforeDocument, requestMetric),
    responses_2xx: metricValue(afterDocument, responseMetric) -
      metricValue(beforeDocument, responseMetric),
    upstream_selections: metricValue(afterDocument, upstreamMetric) -
      metricValue(beforeDocument, upstreamMetric),
  };
  for (const [name, value] of Object.entries(deltas)) {
    requireValue(Number.isSafeInteger(value) && value >= 0,
      `repetition ${repetition} ${name} counter delta is invalid`);
  }
  exact(deltas.requests, derived.completed_http_responses,
    `repetition ${repetition} request counter delta`);
  exact(deltas.responses_2xx, derived.accepted_http_responses,
    `repetition ${repetition} 2xx counter delta`);
  exact(deltas.upstream_selections, derived.accepted_http_responses,
    `repetition ${repetition} upstream-selection counter delta`);
  for (const metric of contract.acceptance.zero_counters) {
    exact(metricValue(beforeDocument, metric), 0,
      `repetition ${repetition} initial ${metric}`);
    exact(metricValue(afterDocument, metric), 0,
      `repetition ${repetition} final ${metric}`);
  }
  return deltas;
}

function median(values) {
  const ordered = [...values].sort((left, right) => left - right);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2 ? ordered[middle] :
    (ordered[middle - 1] + ordered[middle]) / 2;
}

function expectedAggregate(repetitions) {
  const latency = key => median(repetitions.map(value => value.latency_ms[key]));
  const rates = repetitions.map(value => value.successful_rps);
  return {
    valid_repetitions: repetitions.length,
    minimum_successful_rps: Math.min(...rates),
    median_successful_rps: median(rates),
    maximum_successful_rps: Math.max(...rates),
    median_latency_ms: {
      p50: latency('p50'),
      p95: latency('p95'),
      p99: latency('p99'),
      p999: latency('p999'),
      max: latency('max'),
    },
  };
}

function validateContract(contract) {
  exact(contract.schema_version, 1, 'contract schema version');
  exact(contract.classification,
    'routesphere-bonvoyage-oss-bounded-benchmark-contract',
    'contract classification');
  exact(contract.evidence_class, 'single-host-local-engineering',
    'contract evidence class');
  requireValue(contract.workload?.repetitions ===
    contract.acceptance?.minimum_valid_repetitions,
  'contracted repetitions and minimum valid repetitions differ');
  for (const field of ['warmup_seconds', 'measurement_seconds', 'repetitions',
    'concurrency']) {
    requireValue(Number.isSafeInteger(contract.workload?.[field]) &&
      contract.workload[field] > 0, `contract workload ${field} is invalid`);
  }
  exact(contract.acceptance.maximum_error_rate, 0,
    'bounded benchmark maximum error rate');
  exact(contract.acceptance.maximum_container_restarts, 0,
    'bounded benchmark restart allowance');
  requireValue(/^ghcr\.io\/hatoo\/oha@sha256:[0-9a-f]{64}$/.test(
    contract.load_generator?.image || ''), 'load-generator image is not pinned');
  exact(contract.load_generator?.wait_ongoing_requests_after_deadline, true,
    'load-generator deadline behavior');
  requireValue(contract.runner?.compose_file === 'deploy/compose/local.yml' &&
    contract.runner?.compose_project === 'bonvoyage-local' &&
    contract.runner?.gateway_service === 'bonvoyage' &&
    contract.runner?.upstream_service === 'upstream',
  'runner Compose identity differs from the supported local topology');
  exact(contract.claim_boundary, {
    capacity_qualified: false,
    competitive_comparison_qualified: false,
    dedicated_hardware_qualified: false,
    publication_qualified: false,
  }, 'benchmark claim boundary');
  exact(contract.qualifications, {
    verifier_foundation_qualified: true,
    runner_foundation_qualified: true,
    benchmark_reproduction_qualified: true,
    release_admitted: false,
    publishable: false,
  }, 'benchmark qualifications');
  return contract;
}

export function verifyEvidence(contractPath, evidencePath) {
  const absoluteContract = path.resolve(contractPath || defaultContractPath);
  const absoluteEvidence = path.resolve(evidencePath);
  requireValue(fs.existsSync(absoluteEvidence) &&
    fs.statSync(absoluteEvidence).isDirectory(), 'evidence directory is absent');
  const contract = validateContract(readJSON(absoluteContract,
    'bounded benchmark contract'));
  const checksumEntries = readChecksumManifest(absoluteEvidence,
    contract.evidence.checksum_manifest);
  const required = [contract.evidence.summary, contract.evidence.environment,
    contract.evidence.roles, contract.evidence.command_journal,
    contract.evidence.response_probe];
  for (let repetition = 1; repetition <= contract.workload.repetitions;
    repetition += 1) {
    for (const template of Object.values(contract.evidence.repetition_files)) {
      required.push(renderTemplate(template, repetition));
    }
  }
  for (const file of required) {
    requireValue(checksumEntries.has(file), `required evidence is absent: ${file}`);
  }
  exact([...checksumEntries.keys()].sort(), [...required].sort(),
    'contracted evidence inventory');
  validateCommandJournal(path.join(absoluteEvidence,
    contract.evidence.command_journal));
  validateRawResponse(path.join(absoluteEvidence,
    contract.evidence.response_probe), contract.workload);

  const summary = readJSON(path.join(absoluteEvidence, contract.evidence.summary),
    'bounded benchmark summary');
  exactKeys(summary, ['schema_version', 'classification', 'status',
    'contract_sha256', 'evidence_class', 'source', 'environment_sha256',
    'roles_sha256', 'workload', 'repetitions', 'aggregate', 'claim_boundary',
    'qualifications'], 'summary');
  exact(summary.schema_version, 1, 'summary schema version');
  exact(summary.classification,
    'routesphere-bonvoyage-oss-bounded-benchmark-result',
    'summary classification');
  exact(summary.status, 'candidate', 'summary status');
  exact(summary.contract_sha256, sha256File(absoluteContract),
    'summary contract identity');
  exact(summary.evidence_class, contract.evidence_class,
    'summary evidence class');
  requireValue(/^[0-9a-f]{40}$/.test(summary.source?.commit || ''),
    'summary source commit is invalid');
  exactKeys(summary.source, ['commit', 'dirty'], 'summary source');
  exact(summary.source?.dirty, false, 'summary source cleanliness');
  exact(summary.workload, contract.workload, 'summary workload');
  exact(summary.claim_boundary, contract.claim_boundary,
    'summary claim boundary');
  exact(summary.qualifications, contract.qualifications,
    'summary qualifications');

  const environmentPath = path.join(absoluteEvidence, contract.evidence.environment);
  const environment = readJSON(environmentPath, 'bounded benchmark environment');
  exactKeys(environment, ['schema_version', 'evidence_class', 'source', 'host',
    'docker', 'topology'], 'environment');
  exact(summary.environment_sha256, sha256File(environmentPath),
    'summary environment identity');
  exact(environment.schema_version, 1, 'environment schema version');
  exact(environment.evidence_class, contract.evidence_class,
    'environment evidence class');
  exact(environment.source, summary.source, 'environment source identity');
  exact(environment.topology?.single_host, true, 'environment single-host boundary');
  exact(environment.topology?.roles,
    ['gateway', 'load-generator', 'upstream'], 'environment role inventory');

  const rolesPath = path.join(absoluteEvidence, contract.evidence.roles);
  const roles = readJSON(rolesPath, 'bounded benchmark roles');
  exactKeys(roles, ['schema_version', 'gateway', 'upstream', 'load-generator'],
    'role evidence');
  exact(summary.roles_sha256, sha256File(rolesPath), 'summary role identity');
  exact(roles.schema_version, 1, 'role schema version');
  for (const role of ['gateway', 'upstream']) {
    requireValue(/^[0-9a-f]{12,64}$/.test(roles[role]?.container_id || ''),
      `${role} container identity is invalid`);
    requireValue(/^sha256:[0-9a-f]{64}$/.test(roles[role]?.image_id || ''),
      `${role} image identity is invalid`);
  }
  exact(roles.gateway?.service, 'bonvoyage', 'gateway service identity');
  exact(roles.upstream?.service, 'upstream', 'upstream service identity');
  requireValue(/^sha256:[0-9a-f]{64}$/.test(
    roles['load-generator']?.image_id || ''),
  'load-generator image identity is invalid');
  exact(roles['load-generator']?.image_reference, contract.load_generator.image,
    'load-generator image reference');

  requireValue(Array.isArray(summary.repetitions) &&
    summary.repetitions.length === contract.workload.repetitions,
  'summary repetition count differs from the contract');
  const derivedRepetitions = [];
  for (let repetition = 1; repetition <= contract.workload.repetitions;
    repetition += 1) {
    const files = Object.fromEntries(Object.entries(contract.evidence.repetition_files)
      .map(([name, template]) => [name,
        path.join(absoluteEvidence, renderTemplate(template, repetition))]));
    const warmup = deriveOha(readJSON(files.warmup,
      `repetition ${repetition} warmup output`), contract,
    contract.workload.warmup_seconds, `repetition ${repetition} warmup`);
    requireValue(warmup.error_rate <= contract.acceptance.maximum_error_rate,
      `repetition ${repetition} warmup exceeds the error budget`);
    const raw = readJSON(files.oha, `repetition ${repetition} oha output`);
    const derived = deriveOha(raw, contract, contract.workload.measurement_seconds,
      `repetition ${repetition} measurement`);
    requireValue(derived.error_rate <= contract.acceptance.maximum_error_rate,
      `repetition ${repetition} exceeds the error budget`);
    const counters = validateCounterEvidence(
      fs.readFileSync(files.metrics_before, 'utf8'),
      fs.readFileSync(files.metrics_after, 'utf8'), contract, derived, repetition);
    const runtime = readJSON(files.runtime, `repetition ${repetition} runtime`);
    validateRuntime(runtime, roles, contract.acceptance.maximum_container_restarts,
      repetition);
    const resources = deriveResources(files.resources, contract, repetition, {
      gateway: roles.gateway.container_id,
      upstream: roles.upstream.container_id,
      'load-generator': runtime['load-generator'].container_id,
    });

    const recorded = summary.repetitions[repetition - 1];
    exactKeys(recorded, ['repetition', 'accepted_http_responses',
      'completed_http_responses', 'http_failures', 'transport_failures',
      'deadline_end_cancellations', 'measured_requests', 'duration_seconds',
      'successful_rps', 'error_rate', 'latency_ms', 'counters', 'resources'],
    `summary repetition ${repetition}`);
    exact(recorded.repetition, repetition, `summary repetition ${repetition} index`);
    for (const field of ['accepted_http_responses', 'completed_http_responses',
      'http_failures', 'transport_failures', 'deadline_end_cancellations',
      'measured_requests']) {
      exact(recorded[field], derived[field],
        `summary repetition ${repetition} ${field}`);
    }
    near(recorded.duration_seconds, derived.duration_seconds,
      `summary repetition ${repetition} duration`);
    near(recorded.successful_rps, derived.successful_rps,
      `summary repetition ${repetition} successful RPS`);
    near(recorded.error_rate, derived.error_rate,
      `summary repetition ${repetition} error rate`);
    for (const field of ['p50', 'p95', 'p99', 'p999', 'max']) {
      near(recorded.latency_ms?.[field], derived.latency_ms[field],
        `summary repetition ${repetition} latency ${field}`);
    }
    exact(recorded.counters, counters,
      `summary repetition ${repetition} counter evidence`);
    for (const role of contract.acceptance.required_resource_roles) {
      exact(recorded.resources?.sample_counts?.[role],
        resources.sample_counts[role],
        `summary repetition ${repetition} ${role} sample count`);
      near(recorded.resources?.average_cpu_percent?.[role],
        resources.average_cpu_percent[role],
        `summary repetition ${repetition} ${role} CPU`);
      exact(recorded.resources?.peak_memory_bytes?.[role],
        resources.peak_memory_bytes[role],
        `summary repetition ${repetition} ${role} peak memory`);
    }
    derivedRepetitions.push(derived);
  }

  const aggregate = expectedAggregate(derivedRepetitions);
  exact(summary.aggregate?.valid_repetitions, aggregate.valid_repetitions,
    'summary valid repetitions');
  for (const field of ['minimum_successful_rps', 'median_successful_rps',
    'maximum_successful_rps']) {
    near(summary.aggregate?.[field], aggregate[field], `summary ${field}`);
  }
  for (const field of ['p50', 'p95', 'p99', 'p999', 'max']) {
    near(summary.aggregate?.median_latency_ms?.[field],
      aggregate.median_latency_ms[field], `summary median latency ${field}`);
  }
  requireValue(summary.aggregate.valid_repetitions >=
    contract.acceptance.minimum_valid_repetitions,
  'summary has too few valid repetitions');
  return {
    status: 'accepted',
    source_commit: summary.source.commit,
    repetitions: aggregate.valid_repetitions,
    median_successful_rps: aggregate.median_successful_rps,
    median_latency_ms: aggregate.median_latency_ms,
    evidence_files: checksumEntries.size + 1,
  };
}

function parseArguments(argv) {
  const options = {contractPath: defaultContractPath, evidencePath: null};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--contract') options.contractPath = argv[++index];
    else if (argument === '--evidence') options.evidencePath = argv[++index];
    else throw new Rejected(`unknown argument: ${argument}`);
  }
  requireValue(options.evidencePath, '--evidence is required');
  return options;
}

if (process.argv[1] &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = parseArguments(process.argv.slice(2));
    console.log(JSON.stringify(verifyEvidence(options.contractPath,
      options.evidencePath), null, 2));
  } catch (error) {
    const message = error instanceof Rejected ? error.message :
      `unexpected verifier error: ${error.stack || error.message}`;
    console.error(`bounded benchmark evidence rejected: ${message}`);
    process.exit(1);
  }
}
