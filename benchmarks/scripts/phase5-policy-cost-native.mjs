#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';

import {parsePerfStat} from './phase5-baseline.mjs';
import {parseOhaReport} from './phase5-oha-lanes.mjs';
import {buildPolicyCostResult, POLICY_COST_CONTRACT,
  POLICY_COST_PROFILED_WARMUP_REPETITIONS, validatePolicyCostPlan} from
  './phase5-policy-cost.mjs';
import {descriptorAttribution, validateDescriptorObservation} from
  './phase5-protocol-p5-t01-executor.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/u;
const FORMAT = 'bonvoyage-perf06-policy-cost-raw-capture';
const METRIC_PREFIX = 'bonvoyage_';
export const POLICY_COST_RAW_FILES_V1 = Object.freeze([
  'binary-observation.json',
  'environment.json',
  'final-metrics.prom',
  'gateway-metrics-after.prom',
  'gateway-metrics-before.prom',
  'gateway-proc-after.txt',
  'gateway-proc-before.txt',
  'journal.log',
  'load-generator-proc-after.txt',
  'load-generator-proc-before.txt',
  'measurement.oha.json',
  'perf.csv',
  'protocol-body.bin',
  'protocol-headers.txt',
  'protocol-status.txt',
  'provenance-after.json',
  'provenance-before.json',
  'request-observation.json',
  'resource-after.json',
  'resource-before.json',
  'socket-output.json',
  'status.json',
  'tls-observation.json',
  'upstream-proc-after.txt',
  'upstream-proc-before.txt',
  'warmup.oha.json',
]);
export const POLICY_COST_RAW_FILES = Object.freeze([
  ...POLICY_COST_RAW_FILES_V1,
  'descriptors-after.json',
  'descriptors-before.json',
].sort());
export const POLICY_COST_RAW_FILES_V3 = Object.freeze([
  ...POLICY_COST_RAW_FILES,
  'warmup-admission.json',
].sort());
export const POLICY_COST_RAW_FILES_V4 = Object.freeze([
  ...POLICY_COST_RAW_FILES_V3,
  ...Array.from({length: POLICY_COST_PROFILED_WARMUP_REPETITIONS},
    (_, index) => `warmup-pass-${index + 1}-descriptors.json`),
  ...Array.from({length: POLICY_COST_PROFILED_WARMUP_REPETITIONS},
    (_, index) => `warmup-pass-${index + 1}-final-metrics.prom`),
].sort());

export function policyCostRawFiles(schemaVersion) {
  requireValue([1, 2, 3, 4].includes(schemaVersion),
    'policy-cost raw schema version is unsupported');
  if (schemaVersion === 1) return POLICY_COST_RAW_FILES_V1;
  if (schemaVersion === 2) return POLICY_COST_RAW_FILES;
  if (schemaVersion === 3) return POLICY_COST_RAW_FILES_V3;
  return POLICY_COST_RAW_FILES_V4;
}
const ACTIVE_METRICS = Object.freeze([
  'bonvoyage_bonvoyage_gateway_active_requests',
  'bonvoyage_bonvoyage_gateway_active_route_requests',
  'bonvoyage_bonvoyage_gateway_active_upstream_requests',
  'bonvoyage_bonvoyage_gateway_active_upstream_http1_requests',
  'bonvoyage_bonvoyage_gateway_active_http2_streams',
]);

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  requireValue(isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort()),
    `${label} has missing or unexpected keys`);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) =>
      [key, canonicalize(value[key])]));
  }
  return value;
}

function canonicalHash(value) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(canonicalize(value))).digest('hex');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function integer(value, label, minimum = 0) {
  requireValue(Number.isSafeInteger(value) && value >= minimum,
    `${label} must be an integer >= ${minimum}`);
  return value;
}

function finite(value, label, minimum = 0, maximum = Number.POSITIVE_INFINITY) {
  requireValue(Number.isFinite(value) && value >= minimum && value <= maximum,
    `${label} must be between ${minimum} and ${maximum}`);
  return value;
}

function json(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

function readRegular(filename, label, maximum = 256 * 1024 * 1024) {
  const absolute = path.resolve(filename);
  const stat = fs.lstatSync(absolute);
  requireValue(stat.isFile() && !stat.isSymbolicLink() && stat.size <= maximum,
    `${label} must be a bounded regular non-symlink file`);
  return fs.readFileSync(absolute);
}

function safeRawFile(root, relative, expectedFiles) {
  requireValue(expectedFiles.includes(relative) && SAFE_PATH.test(relative),
    `unexpected policy-cost raw capture file: ${relative}`);
  const absoluteRoot = path.resolve(root);
  const absolute = path.resolve(absoluteRoot, relative);
  requireValue(absolute.startsWith(`${absoluteRoot}${path.sep}`),
    `policy-cost raw capture file escapes root: ${relative}`);
  const stat = fs.lstatSync(absolute);
  requireValue(stat.isFile() && !stat.isSymbolicLink() &&
    stat.size <= 64 * 1024 * 1024,
  `policy-cost raw capture file is unsafe or oversized: ${relative}`);
  return absolute;
}

function verifyRawManifest(root, schemaVersion) {
  const expectedFiles = policyCostRawFiles(schemaVersion);
  const absoluteRoot = path.resolve(root);
  const stat = fs.lstatSync(absoluteRoot);
  requireValue(stat.isDirectory() && !stat.isSymbolicLink(),
    'policy-cost raw capture root must be a real directory');
  const manifest = readRegular(path.join(absoluteRoot, 'checksums.sha256'),
    'policy-cost raw capture checksum manifest', 1024 * 1024)
    .toString('utf8');
  const lines = manifest.trimEnd().split('\n');
  requireValue(lines.length === expectedFiles.length,
    'policy-cost raw capture checksum manifest has incomplete coverage');
  const records = lines.map((line, index) => {
    const match = /^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$/u.exec(line);
    requireValue(match, `policy-cost raw checksum line ${index + 1} is invalid`);
    return {sha256: match[1], path: match[2]};
  });
  requireValue(isDeepStrictEqual(records.map((item) => item.path),
    expectedFiles),
    'policy-cost raw checksum paths are not exact, unique, and sorted');
  for (const record of records) {
    const absolute = safeRawFile(absoluteRoot, record.path, expectedFiles);
    requireValue(sha256(fs.readFileSync(absolute)) === record.sha256,
      `policy-cost raw capture checksum mismatch: ${record.path}`);
  }
  const actual = fs.readdirSync(absoluteRoot).sort();
  requireValue(isDeepStrictEqual(actual,
    [...expectedFiles, 'checksums.sha256'].sort()),
  'policy-cost raw capture directory contains missing or unbound files');
  return records;
}

function packRawCapture(root, pointId, schemaVersion) {
  const records = verifyRawManifest(root, schemaVersion);
  return {schema_version: schemaVersion, format: FORMAT, point_id: pointId,
    files: records.map((record) => {
      const bytes = fs.readFileSync(path.join(root, record.path));
      return {...record, bytes: bytes.length,
        content_base64: bytes.toString('base64')};
    })};
}

function unpackRawCapture(archive) {
  exactKeys(archive, ['schema_version', 'format', 'point_id', 'files'],
    'policy-cost raw capture archive');
  requireValue([1, 2, 3, 4].includes(archive.schema_version) &&
    archive.format === FORMAT,
    'policy-cost raw capture archive header is invalid');
  const expectedFiles = policyCostRawFiles(archive.schema_version);
  requireValue(Array.isArray(archive.files) &&
    archive.files.length === expectedFiles.length,
  'policy-cost raw capture file set is incomplete');
  const files = new Map();
  for (const [index, file] of archive.files.entries()) {
    exactKeys(file, ['path', 'sha256', 'bytes', 'content_base64'],
      `policy-cost raw capture file ${index}`);
    requireValue(file.path === expectedFiles[index] &&
      SHA256.test(file.sha256),
      `policy-cost raw capture file ${index} identity is invalid`);
    integer(file.bytes, `policy-cost raw capture file ${file.path} bytes`);
    requireValue(typeof file.content_base64 === 'string' &&
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u
        .test(file.content_base64),
    `policy-cost raw capture file ${file.path} is not canonical base64`);
    const bytes = Buffer.from(file.content_base64, 'base64');
    requireValue(bytes.length === file.bytes && sha256(bytes) === file.sha256 &&
      bytes.toString('base64') === file.content_base64,
    `policy-cost raw capture file ${file.path} differs from its binding`);
    files.set(file.path, bytes);
  }
  return files;
}

function fileText(files, name) {
  const bytes = files.get(name);
  requireValue(bytes !== undefined, `policy-cost raw capture omits ${name}`);
  return bytes.toString('utf8');
}

function fileJson(files, name) {
  return json(files.get(name), name);
}

function pointFor(plan, pointId) {
  const point = plan.points.find((item) => item.point_id === pointId);
  requireValue(point, `policy-cost point is outside the plan: ${pointId}`);
  return point;
}

function validateProvenance(value, plan, point, label) {
  exactKeys(value, ['schema_version', 'plan_id', 'point_id', 'profile_id',
    'repetition', 'source', 'catalog_sha256', 'snapshot_sha256',
    'observed_harness_commit', 'source_status'], label);
  requireValue(value.schema_version === 1 && value.plan_id === plan.plan_id &&
    value.point_id === point.point_id && value.profile_id === point.profile_id &&
    value.repetition === point.repetition,
  `${label} point identity differs from plan`);
  requireValue(isDeepStrictEqual(value.source, plan.input.source) &&
    value.catalog_sha256 === plan.input.catalog_sha256 &&
    value.snapshot_sha256 === point.snapshot_sha256,
  `${label} source or artifact identity differs from plan`);
  requireValue(value.observed_harness_commit ===
    plan.input.source.harness_commit && value.source_status === '' &&
    COMMIT.test(value.observed_harness_commit),
  `${label} does not prove clean harness source`);
}

function validateEnvironment(value, plan, point, attempt) {
  exactKeys(value, ['schema_version', 'plan_id', 'point_id', 'profile_id',
    'repetition', 'attempt', 'roles', 'load_generator_cpu_set',
    'load_generator_lanes', 'gateway_cpu_set', 'housekeeping_cpu_set',
    'irq_policy', 'profiler_scope', 'reactor_tids_before',
    'reactor_tids_after', 'profiled_reactor_tids'],
  'policy-cost environment');
  requireValue(value.schema_version === 1 && value.plan_id === plan.plan_id &&
    value.point_id === point.point_id && value.profile_id === point.profile_id &&
    value.repetition === point.repetition && value.attempt === attempt,
  'policy-cost environment point identity differs from plan');
  requireValue(isDeepStrictEqual(value.roles, plan.input.topology.roles) &&
    isDeepStrictEqual(value.load_generator_cpu_set,
      plan.input.topology.load_generator_cpu_set) &&
    value.load_generator_lanes ===
      plan.input.topology.load_generator_lanes &&
    isDeepStrictEqual(value.gateway_cpu_set,
      plan.input.topology.gateway_cpu_set) &&
    isDeepStrictEqual(value.housekeeping_cpu_set,
      plan.input.topology.housekeeping_cpu_set) &&
    value.irq_policy === plan.input.topology.irq_policy &&
    value.profiler_scope === POLICY_COST_CONTRACT.profiler_scope,
  'policy-cost environment placement differs from plan');
  requireValue(Array.isArray(value.load_generator_cpu_set) &&
    value.load_generator_cpu_set.length >= value.load_generator_lanes &&
    new Set(value.load_generator_cpu_set).size ===
      value.load_generator_cpu_set.length &&
    value.load_generator_cpu_set.every((cpu) =>
      Number.isSafeInteger(cpu) && cpu >= 0),
  'policy-cost load-generator CPU set is invalid');
  for (const name of ['reactor_tids_before', 'reactor_tids_after',
    'profiled_reactor_tids']) {
    requireValue(Array.isArray(value[name]) &&
      value[name].length === point.core_count &&
      new Set(value[name]).size === point.core_count &&
      value[name].every((tid) => Number.isSafeInteger(tid) && tid > 1),
    `policy-cost environment ${name} is incomplete`);
  }
  requireValue(isDeepStrictEqual(value.reactor_tids_before,
    value.reactor_tids_after) && isDeepStrictEqual(value.reactor_tids_before,
    value.profiled_reactor_tids),
  'policy-cost reactor identity or profiler coverage changed');
  return value;
}

function validateBinaryObservation(value, plan) {
  exactKeys(value, ['schema_version', 'source'],
    'policy-cost binary observation');
  requireValue(value.schema_version === 1 &&
    isDeepStrictEqual(value.source, plan.input.source),
  'policy-cost binary or collector identity differs from plan');
}

function countMap(value, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  return Object.values(value).reduce((total, item) =>
    total + integer(item, label), 0);
}

function expectedRequestIdentity(point, request) {
  if (point.request.mode === 'none') {
    return {credential: null, headers: null, names: null};
  }
  if (point.request.mode === 'secret-file') {
    return {credential: point.request.planned_artifact_sha256,
      headers: null, names: null};
  }
  return {credential: null, headers: request.artifact_sha256,
    names: point.request.header_names};
}

function cpuList(spec, label) {
  requireValue(typeof spec === 'string' &&
    /^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$/u.test(spec),
  `${label} CPU set is invalid`);
  const cpus = [];
  for (const range of spec.split(',')) {
    const [first, last = first] = range.split('-').map(Number);
    requireValue(Number.isSafeInteger(first) && Number.isSafeInteger(last) &&
      first <= last && last - first < 4096,
    `${label} CPU range is invalid`);
    for (let cpu = first; cpu <= last; cpu += 1) cpus.push(cpu);
  }
  requireValue(new Set(cpus).size === cpus.length,
    `${label} CPU set overlaps`);
  return cpus;
}

function validateOha(raw, plan, point, request, expectedSeconds, label) {
  const report = parseOhaReport(raw);
  const duration = finite(report.active_measurement_seconds ??
    report.summary?.total, `${label} active duration`, 0.001);
  requireValue(report.offered_rps === point.offered_rps,
    `${label} offered rate differs from plan`);
  const successes = integer(report.statusCodeDistribution?.['200'] ?? 0,
    `${label} HTTP 200 count`, 1);
  const httpFailures = Object.entries(report.statusCodeDistribution ?? {})
    .reduce((total, [status, count]) => status === '200' ? total :
      total + integer(count, `${label} HTTP ${status}`), 0);
  const transportFailures = countMap(report.errorDistribution ?? {},
    `${label} transport failures`);
  for (const name of ['p50', 'p95', 'p99', 'p99.9']) {
    finite(report.latencyPercentiles?.[name], `${label} ${name}`);
  }
  requireValue(report.latencyPercentiles.p50 <= report.latencyPercentiles.p95 &&
    report.latencyPercentiles.p95 <= report.latencyPercentiles.p99 &&
    report.latencyPercentiles.p99 <= report.latencyPercentiles['p99.9'],
  `${label} latency percentiles are not monotonic`);
  const gateway = plan.input.topology.roles.find((item) =>
    item.role === 'gateway');
  const identity = expectedRequestIdentity(point, request);
  const workload = report.workload;
  requireValue(workload !== undefined &&
    report.client_lanes === plan.input.topology.load_generator_lanes &&
    workload.client_sha256 === plan.input.source.client_sha256 &&
    workload.protocol === 'http1' && workload.tls === true &&
    workload.authority === 'api.example.test' &&
    workload.listener_port === 8443 &&
    isDeepStrictEqual(workload.target_addresses,
      [gateway.private_address]) &&
    workload.path === point.request_path &&
    workload.connections_per_lane * report.client_lanes ===
      point.connections &&
    workload.streams_per_connection === 1 &&
    workload.requests_per_lane * report.client_lanes ===
      point.offered_rps * expectedSeconds &&
    SHA256.test(workload.ca_sha256) &&
    workload.credential_sha256 === identity.credential &&
    workload.request_timeout_seconds * 1000 ===
      plan.input.workload.request_timeout_ms,
  `${label} structured workload differs from plan`);
  if (identity.headers === null) {
    requireValue(workload.request_headers_sha256 === undefined &&
      workload.request_header_names === undefined,
    `${label} unexpectedly retained generic request headers`);
  } else {
    requireValue(workload.request_headers_sha256 === identity.headers &&
      isDeepStrictEqual(workload.request_header_names, identity.names),
    `${label} request-header identity differs from the bound request`);
  }
  requireValue(duration >= expectedSeconds * 0.95 &&
    duration <= expectedSeconds * 1.1 + 0.5,
  `${label} duration differs from plan`);
  return {report, duration, successes, httpFailures, transportFailures};
}

function labels(raw) {
  const result = {};
  const matcher = /([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\]|\\.)*)"/gu;
  for (const match of raw.matchAll(matcher)) {
    result[match[1]] = match[2].replaceAll('\\"', '"')
      .replaceAll('\\\\', '\\');
  }
  return result;
}

function prometheus(raw) {
  const result = [];
  for (const [index, source] of raw.split(/\r?\n/u).entries()) {
    const line = source.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{([^}]*)\})?\s+(\S+)(?:\s+\d+)?$/u
      .exec(line);
    if (!match || !match[1].startsWith(METRIC_PREFIX)) continue;
    const value = Number(match[3]);
    requireValue(Number.isFinite(value),
      `policy-cost Prometheus sample at line ${index + 1} is not finite`);
    result.push({name: match[1], labels: labels(match[2] ?? ''), value});
  }
  return result;
}

function shardMap(samples, name, coreCount, label) {
  const result = new Map();
  for (const sample of samples.filter((item) => item.name === name)) {
    const shard = Number(sample.labels.shard);
    requireValue(Number.isSafeInteger(shard) && shard >= 0 &&
      shard < coreCount && !result.has(shard),
    `${label} has invalid or duplicate shard series`);
    result.set(shard, sample.value);
  }
  requireValue(result.size === coreCount,
    `${label} does not cover every gateway shard`);
  return result;
}

function deltaMap(before, after, label) {
  requireValue(isDeepStrictEqual([...before.keys()], [...after.keys()]),
    `${label} shard identity changed`);
  return new Map([...before].map(([key, value]) => {
    const delta = after.get(key) - value;
    requireValue(Number.isFinite(delta) && delta >= 0,
      `${label} counter regressed`);
    return [key, delta];
  }));
}

function counterDeltaMap(before, after, label) {
  const result = deltaMap(before, after, label);
  requireValue([...result.values()].every((value) =>
    Number.isSafeInteger(value)), `${label} contains a non-integer counter`);
  return result;
}

function sumMetric(samples, name, label) {
  const matching = samples.filter((item) => item.name === name);
  requireValue(matching.length > 0, `${label} metric is missing`);
  return matching.reduce((total, item) => total + item.value, 0);
}

function parseProcStat(raw, label) {
  const fields = raw.split(/\r?\n/u)[0]?.trim().split(/\s+/u) ?? [];
  requireValue(fields[0] === 'cpu' && fields.length >= 9 &&
    fields.slice(1, 9).every((item) => /^[0-9]+$/u.test(item)),
  `${label} aggregate CPU row is invalid`);
  return fields.slice(1, 9).map(Number);
}

function cpuPercent(beforeRaw, afterRaw, label) {
  const before = parseProcStat(beforeRaw, `${label} before`);
  const after = parseProcStat(afterRaw, `${label} after`);
  const delta = after.map((value, index) => value - before[index]);
  requireValue(delta.every((value) => Number.isSafeInteger(value) && value >= 0),
    `${label} CPU counters regressed`);
  const total = delta.reduce((sum, value) => sum + value, 0);
  requireValue(total > 0, `${label} CPU interval is empty`);
  return {busy: (total - delta[3] - delta[4]) / total * 100,
    irq: (delta[5] + delta[6]) / total * 100};
}

function validateResource(value, label) {
  exactKeys(value, ['identity', 'pid', 'start_ticks', 'restart_count',
    'rss_bytes', 'file_descriptors'], label);
  requireValue(typeof value.identity === 'string' && value.identity.length > 0,
    `${label} identity is invalid`);
  integer(value.pid, `${label} pid`, 2);
  integer(value.start_ticks, `${label} start ticks`, 1);
  integer(value.restart_count, `${label} restart count`);
  integer(value.rss_bytes, `${label} RSS`, 1);
  integer(value.file_descriptors, `${label} descriptors`);
  return value;
}

function validateSocket(value, label) {
  exactKeys(value, ['interval_id', 'duration_nanoseconds', 'scope', 'pid',
    'start_ticks', 'calls', 'requested_bytes', 'completed_bytes',
    'partial_writes', 'would_block', 'fatal_errors', 'lost_events'], label);
  requireValue(value.scope === 'gateway-downstream-sockets',
    `${label} scope is invalid`);
  for (const name of ['duration_nanoseconds', 'pid', 'start_ticks', 'calls',
    'requested_bytes', 'completed_bytes', 'partial_writes', 'would_block',
    'fatal_errors', 'lost_events']) integer(value[name], `${label} ${name}`);
  requireValue(value.calls > 0 && value.completed_bytes > 0 &&
    value.completed_bytes <= value.requested_bytes &&
    value.partial_writes <= value.calls && value.fatal_errors === 0 &&
    value.lost_events === 0,
  `${label} contains incomplete or failed socket evidence`);
  return value;
}

function validateStatus(value) {
  exactKeys(value, ['warmup_command_exit_code',
    'measurement_command_exit_code', 'collector_exit_code',
    'protocol_probe_exit_code'], 'policy-cost status');
  for (const [name, code] of Object.entries(value)) {
    requireValue(code === 0, `policy-cost ${name} is nonzero`);
  }
}

function parseResponseHeaders(raw) {
  const blocks = raw.replaceAll('\r\n', '\n').trim().split(/\n\n+/u)
    .filter(Boolean);
  requireValue(blocks.length > 0, 'policy-cost response headers are empty');
  const lines = blocks.at(-1).split('\n');
  requireValue(/^HTTP\/1\.[01] 200(?: |$)/u.test(lines.shift() ?? ''),
    'policy-cost response status line is not HTTP 200');
  const headers = new Map();
  for (const line of lines) {
    if (line === '') continue;
    const separator = line.indexOf(':');
    requireValue(separator > 0, 'policy-cost response header is malformed');
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    requireValue(/^[!#$%&'*+.^_`|~0-9a-z-]+$/u.test(name),
      'policy-cost response header name is invalid');
    const values = headers.get(name) ?? [];
    values.push(value);
    headers.set(name, values);
  }
  return headers;
}

function singleHeader(headers, name) {
  const values = headers.get(name) ?? [];
  requireValue(values.length === 1,
    `policy-cost ${name} must occur exactly once`);
  return values[0];
}

function validateProtocol(files, point) {
  requireValue(fileText(files, 'protocol-status.txt').trim() === '200',
    'policy-cost protocol status is not 200');
  const body = files.get('protocol-body.bin');
  requireValue(body.equals(Buffer.alloc(point.response_payload_bytes, 'x')),
    'policy-cost response body differs from controlled payload');
  const headers = parseResponseHeaders(fileText(files, 'protocol-headers.txt'));
  requireValue(Number(singleHeader(headers, 'content-length')) ===
    point.response_payload_bytes &&
    singleHeader(headers, 'content-type') === 'application/octet-stream',
  'policy-cost response framing or content type differs from fixture');
  if (point.feature === 'bounded-header-transformations') {
    const expected = {
      'x-upstream-policy-set': 'gateway-set',
      'x-upstream-policy-append': 'upstream-append, gateway-append',
      'x-policy-response-added': 'gateway-added',
      'x-observed-request-set': 'gateway-set',
      'x-observed-request-append': 'client-append, gateway-append',
      'x-observed-request-added': 'gateway-added',
    };
    for (const [name, value] of Object.entries(expected)) {
      requireValue(singleHeader(headers, name) === value,
        `policy-cost ${name} semantics changed`);
    }
    for (const name of ['x-upstream-policy-remove',
      'x-observed-request-remove']) {
      requireValue(!headers.has(name), `policy-cost ${name} must be absent`);
    }
  }
  const tls = fileJson(files, 'tls-observation.json');
  exactKeys(tls, ['tls_version', 'cipher', 'alpn', 'ca_verified',
    'hostname_verified'], 'policy-cost TLS observation');
  requireValue(tls.tls_version === 'TLSv1.3' &&
    /^TLS_AES_[A-Z0-9_]+$/u.test(tls.cipher) &&
    !tls.cipher.includes('CHACHA') && tls.alpn === 'http/1.1' &&
    tls.ca_verified === true && tls.hostname_verified === true,
  'policy-cost TLS identity is incomplete or outside the contract');
  return {downstream_tls_version: tls.tls_version,
    downstream_tls_cipher: tls.cipher,
    peer_certificate_verified: tls.ca_verified,
    hostname_verified: tls.hostname_verified, alpn: tls.alpn,
    status_code: 200, semantic_validated: true,
    response_payload_bytes: body.length};
}

function average(values, label) {
  requireValue(values.length > 0, `${label} is empty`);
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

export function validatePolicyWarmupAdmission(value, plan, point,
  files = null, label = 'policy-cost warmup admission') {
  const boundedConvergence = plan.schema_version >= 4;
  exactKeys(value, ['schema_version', 'required_profiled_warmup_repetitions',
    'passes', boundedConvergence ? 'convergence' : 'plateau'], label);
  const required = plan?.input?.workload?.profiled_warmup_repetitions;
  requireValue(plan.schema_version >= 3 &&
    value.schema_version === (boundedConvergence ? 2 : 1) &&
    required === POLICY_COST_PROFILED_WARMUP_REPETITIONS &&
    value.required_profiled_warmup_repetitions === required &&
    Array.isArray(value.passes) && value.passes.length === required,
  `${label} repetition contract is invalid`);
  const expectedSuccesses = point.offered_rps *
    plan.input.workload.warmup_seconds;
  requireValue(Number.isSafeInteger(expectedSuccesses) &&
    expectedSuccesses > 0, `${label} expected request count is invalid`);

  let identity;
  const passEvidence = [];
  for (const [index, pass] of value.passes.entries()) {
    const passKeys = ['pass', 'settled', 'settlement_ms', 'identity',
      'restart_count', 'rss_bytes', 'file_descriptors',
      'successful_requests', 'http_failures', 'transport_failures'];
    if (boundedConvergence) passKeys.push('allocated_memory_bytes',
      'malloc_live_objects', 'controlled_upstream_connections',
      'non_controlled_descriptors');
    exactKeys(pass, passKeys, `${label} pass ${index + 1}`);
    requireValue(pass.pass === index + 1 && pass.settled === true &&
      typeof pass.identity === 'string' && pass.identity.length > 0,
    `${label} pass ${index + 1} identity or settlement is invalid`);
    integer(pass.settlement_ms, `${label} pass ${index + 1} settlement`);
    integer(pass.restart_count, `${label} pass ${index + 1} restart count`);
    integer(pass.rss_bytes, `${label} pass ${index + 1} RSS`, 1);
    integer(pass.file_descriptors,
      `${label} pass ${index + 1} descriptors`);
    integer(pass.successful_requests,
      `${label} pass ${index + 1} successful requests`, 1);
    integer(pass.http_failures,
      `${label} pass ${index + 1} HTTP failures`);
    integer(pass.transport_failures,
      `${label} pass ${index + 1} transport failures`);
    if (boundedConvergence) {
      integer(pass.allocated_memory_bytes,
        `${label} pass ${index + 1} allocated memory`);
      integer(pass.malloc_live_objects,
        `${label} pass ${index + 1} live objects`);
      integer(pass.controlled_upstream_connections,
        `${label} pass ${index + 1} controlled-upstream connections`);
      integer(pass.non_controlled_descriptors,
        `${label} pass ${index + 1} non-controlled descriptors`);
      requireValue(files instanceof Map,
        `${label} schema v4 requires retained warmup evidence`);
      const descriptors = validateDescriptorObservation(fileJson(files,
        `warmup-pass-${index + 1}-descriptors.json`),
      `${label} pass ${index + 1} descriptors`);
      const samples = prometheus(fileText(files,
        `warmup-pass-${index + 1}-final-metrics.prom`));
      const upstream = plan.input.topology.roles.find((item) =>
        item.role === 'controlled_upstream');
      const upstreamContract = plan.input.topology.controlled_upstream;
      const descriptorPolicy = {remote_address: upstream.private_address,
        remote_port: upstreamContract.port,
        maximum_connections: upstreamContract.max_connections_per_shard *
          point.core_count};
      const selfAttribution = descriptorAttribution(descriptors, descriptors,
        descriptorPolicy);
      const allocatedMemory = sumMetric(samples,
        'bonvoyage_memory_allocated_memory',
        `${label} pass ${index + 1} allocated memory`);
      const liveObjects = sumMetric(samples,
        'bonvoyage_memory_malloc_live_objects',
        `${label} pass ${index + 1} live objects`);
      requireValue(descriptors.identity === pass.identity &&
        descriptors.restart_count === pass.restart_count &&
        descriptors.total === pass.file_descriptors &&
        selfAttribution.controlled_upstream_connections_bounded &&
        pass.allocated_memory_bytes === allocatedMemory &&
        pass.malloc_live_objects === liveObjects &&
        pass.controlled_upstream_connections ===
          selfAttribution.controlled_upstream_connections_after &&
        pass.non_controlled_descriptors ===
          selfAttribution.non_controlled_descriptors_after,
      `${label} pass ${index + 1} differs from retained evidence`);
      passEvidence.push({descriptors, descriptorPolicy});
    }
    identity ??= pass.identity;
    requireValue(pass.identity === identity && pass.restart_count === 0 &&
      pass.successful_requests === expectedSuccesses &&
      pass.http_failures === 0 && pass.transport_failures === 0 &&
      pass.settlement_ms <= plan.input.workload.maximum_cleanup_ms,
    `${label} pass ${index + 1} failed its admission contract`);
  }

  const penultimate = value.passes.at(-2);
  const final = value.passes.at(-1);
  const rssDelta = final.rss_bytes - penultimate.rss_bytes;
  const fdDelta = final.file_descriptors - penultimate.file_descriptors;
  if (!boundedConvergence) {
    exactKeys(value.plateau, ['compared_passes', 'rss_delta_bytes', 'fd_delta',
      'stable'], `${label} plateau`);
    requireValue(isDeepStrictEqual(value.plateau.compared_passes,
      [required - 1, required]) &&
      value.plateau.rss_delta_bytes === rssDelta &&
      value.plateau.fd_delta === fdDelta && value.plateau.stable === true &&
      rssDelta === 0 && fdDelta === 0,
    `${label} final profiled passes do not establish an exact resource plateau`);
    return value;
  }

  exactKeys(value.convergence, ['compared_passes', 'rss_delta_bytes',
    'allocated_memory_delta_bytes', 'malloc_live_object_delta', 'fd_delta',
    'controlled_upstream_connection_delta', 'unaccounted_fd_delta',
    'maximum_memory_growth_bytes', 'maximum_unaccounted_fd_growth',
    'controlled_upstream_connection_limit', 'contained'],
  `${label} convergence`);
  const allocatedMemoryDelta = final.allocated_memory_bytes -
    penultimate.allocated_memory_bytes;
  const liveObjectDelta = final.malloc_live_objects -
    penultimate.malloc_live_objects;
  const descriptorDelta = descriptorAttribution(
    passEvidence.at(-2).descriptors, passEvidence.at(-1).descriptors,
    passEvidence.at(-1).descriptorPolicy);
  const maximumMemoryGrowth =
    plan.input.workload.maximum_retained_rss_growth_bytes;
  requireValue(isDeepStrictEqual(value.convergence.compared_passes,
    [required - 1, required]) &&
    value.convergence.rss_delta_bytes === rssDelta &&
    value.convergence.allocated_memory_delta_bytes === allocatedMemoryDelta &&
    value.convergence.malloc_live_object_delta === liveObjectDelta &&
    value.convergence.fd_delta === fdDelta &&
    value.convergence.controlled_upstream_connection_delta ===
      descriptorDelta.controlled_upstream_connection_growth &&
    value.convergence.unaccounted_fd_delta ===
      descriptorDelta.unaccounted_fd_growth &&
    value.convergence.maximum_memory_growth_bytes === maximumMemoryGrowth &&
    value.convergence.maximum_unaccounted_fd_growth === 0 &&
    value.convergence.controlled_upstream_connection_limit ===
      descriptorDelta.controlled_upstream_connection_limit &&
    value.convergence.contained === true &&
    rssDelta <= maximumMemoryGrowth &&
    allocatedMemoryDelta <= maximumMemoryGrowth &&
    descriptorDelta.controlled_upstream_connections_bounded &&
    descriptorDelta.unaccounted_fd_growth <= 0,
  `${label} final profiled passes do not establish bounded resource convergence`);
  return value;
}

export function describePolicyCostPoint(plan, catalogBytes, pointId) {
  validatePolicyCostPlan(plan, catalogBytes);
  const point = pointFor(plan, pointId);
  return {schema_version: plan.schema_version, checkpoint: 'PERF-06',
    plan_id: plan.plan_id,
    point, source: plan.input.source, topology: plan.input.topology,
    profiler_scope: POLICY_COST_CONTRACT.profiler_scope,
    publication_authorized: false};
}

export function derivePolicyCostInput(archive, environmentBytes, plan,
  catalogBytes, attempt) {
  validatePolicyCostPlan(plan, catalogBytes);
  integer(attempt, 'policy-cost attempt', 1);
  requireValue(archive.schema_version === plan.schema_version,
    'policy-cost raw capture schema differs from the plan');
  const files = unpackRawCapture(archive);
  const point = pointFor(plan, archive.point_id);
  const environment = validateEnvironment(json(environmentBytes,
    'policy-cost environment'), plan, point, attempt);
  requireValue(isDeepStrictEqual(environment,
    fileJson(files, 'environment.json')),
  'external policy-cost environment differs from raw capture');
  const provenanceBefore = fileJson(files, 'provenance-before.json');
  const provenanceAfter = fileJson(files, 'provenance-after.json');
  validateProvenance(provenanceBefore, plan, point,
    'policy-cost provenance before');
  validateProvenance(provenanceAfter, plan, point,
    'policy-cost provenance after');
  requireValue(isDeepStrictEqual(provenanceBefore, provenanceAfter),
    'policy-cost source or artifact identity changed during capture');
  validateBinaryObservation(fileJson(files, 'binary-observation.json'), plan);
  validateStatus(fileJson(files, 'status.json'));
  requireValue(!/(?:fatal|segmentation fault|addresssanitizer|undefinedbehaviorsanitizer)/iu
    .test(fileText(files, 'journal.log')),
  'policy-cost journal contains a fatal runtime diagnostic');

  const request = fileJson(files, 'request-observation.json');
  const warmupAdmission = plan.schema_version >= 3 ?
    validatePolicyWarmupAdmission(fileJson(files, 'warmup-admission.json'),
      plan, point, plan.schema_version >= 4 ? files : null) : null;
  const warmup = validateOha(fileText(files, 'warmup.oha.json'), plan, point,
    request, plan.input.workload.warmup_seconds, 'policy-cost warmup');
  requireValue(warmup.httpFailures === 0 && warmup.transportFailures === 0,
    'policy-cost warmup contains failures');
  const measurement = validateOha(fileText(files, 'measurement.oha.json'),
    plan, point, request, point.measurement_seconds,
    'policy-cost measurement');
  requireValue(warmup.report.workload.ca_sha256 ===
    measurement.report.workload.ca_sha256 &&
    isDeepStrictEqual(warmup.report.client_cpu_sets,
      measurement.report.client_cpu_sets),
  'policy-cost load-client identity or placement changed after warmup');
  const observedClientCpus = measurement.report.client_cpu_sets.flatMap(
    (spec, index) => cpuList(spec, `policy-cost client lane ${index}`));
  requireValue(isDeepStrictEqual(observedClientCpus,
    environment.load_generator_cpu_set),
  'policy-cost client lane placement differs from environment evidence');

  const beforeSamples = prometheus(fileText(files,
    'gateway-metrics-before.prom'));
  const afterSamples = prometheus(fileText(files,
    'gateway-metrics-after.prom'));
  const counterDeltas = (name, label) => counterDeltaMap(
    shardMap(beforeSamples, name, point.core_count, `${label} before`),
    shardMap(afterSamples, name, point.core_count, `${label} after`), label);
  const requests = counterDeltas('bonvoyage_bonvoyage_gateway_requests_total',
    'gateway requests');
  const successes = counterDeltas(
    'bonvoyage_bonvoyage_gateway_responses_2xx_total',
    'gateway successful responses');
  const allocations = counterDeltas('bonvoyage_memory_malloc_operations',
    'gateway allocations');
  const poolWaits = counterDeltas(
    'bonvoyage_bonvoyage_gateway_upstream_http1_pool_waits_total',
    'upstream HTTP/1 pool waits');
  const reactorBusy = deltaMap(shardMap(beforeSamples,
    'bonvoyage_reactor_cpu_busy_ms', point.core_count,
    'reactor busy time before'), shardMap(afterSamples,
    'bonvoyage_reactor_cpu_busy_ms', point.core_count,
    'reactor busy time after'), 'reactor busy time');
  const successfulOperations = [...successes.values()]
    .reduce((a, b) => a + b, 0);
  const requestOperations = [...requests.values()].reduce((a, b) => a + b, 0);
  const totalAttempts = measurement.successes + measurement.httpFailures +
    measurement.transportFailures;
  const completedClientAttempts = measurement.successes +
    measurement.httpFailures;
  requireValue(successfulOperations === measurement.successes &&
    requestOperations >= completedClientAttempts &&
    requestOperations <= totalAttempts,
  'policy-cost client and gateway request denominators differ');

  const perShardCpu = [...reactorBusy].map(([shard, busyMs]) => ({shard,
    cpu_percent: finite(busyMs / (measurement.duration * 1000) * 100,
      `policy-cost shard ${shard} CPU`, 0, 100)}));
  const gatewayCpu = cpuPercent(fileText(files, 'gateway-proc-before.txt'),
    fileText(files, 'gateway-proc-after.txt'), 'policy-cost gateway host');
  const loadCpu = cpuPercent(fileText(files,
    'load-generator-proc-before.txt'), fileText(files,
    'load-generator-proc-after.txt'), 'policy-cost load-generator host');
  const upstreamCpu = cpuPercent(fileText(files, 'upstream-proc-before.txt'),
    fileText(files, 'upstream-proc-after.txt'),
    'policy-cost controlled-upstream host');
  const performance = parsePerfStat(fileText(files, 'perf.csv'));
  const socket = validateSocket(fileJson(files, 'socket-output.json'),
    'policy-cost socket output');
  requireValue(socket.interval_id === point.point_id,
    'policy-cost socket interval differs from the planned point');
  const clientEnvelopeNanoseconds = finite(
    measurement.report.summary?.total,
    'policy-cost client process envelope', 0.001) * 1e9;
  const maximumCollectorOverhead = Math.max(1e9,
    clientEnvelopeNanoseconds * 0.01);
  requireValue(socket.duration_nanoseconds >= clientEnvelopeNanoseconds &&
    socket.duration_nanoseconds - clientEnvelopeNanoseconds <=
      maximumCollectorOverhead,
  'policy-cost socket interval does not contain the bounded client process envelope');
  const resourceBefore = validateResource(fileJson(files,
    'resource-before.json'), 'policy-cost resource before');
  const resourceAfter = validateResource(fileJson(files,
    'resource-after.json'), 'policy-cost resource after');
  if (warmupAdmission !== null) {
    const admitted = warmupAdmission.passes.at(-1);
    requireValue(admitted.identity === resourceBefore.identity &&
      admitted.rss_bytes === resourceBefore.rss_bytes &&
      admitted.file_descriptors === resourceBefore.file_descriptors,
    'policy-cost measured resource baseline differs from warmup admission');
  }
  requireValue(resourceBefore.identity === resourceAfter.identity &&
    resourceBefore.pid === resourceAfter.pid &&
    resourceBefore.start_ticks === resourceAfter.start_ticks &&
    resourceBefore.restart_count === resourceAfter.restart_count &&
    socket.pid === resourceBefore.pid &&
    socket.start_ticks === resourceBefore.start_ticks,
  'policy-cost gateway process identity changed or disagrees with socket evidence');
  let descriptorAttributionValue;
  if (plan.schema_version >= 2) {
    const descriptorsBefore = validateDescriptorObservation(fileJson(files,
      'descriptors-before.json'), 'policy-cost descriptors before');
    const descriptorsAfter = validateDescriptorObservation(fileJson(files,
      'descriptors-after.json'), 'policy-cost descriptors after');
    requireValue(descriptorsBefore.identity === resourceBefore.identity &&
      descriptorsBefore.pid === resourceBefore.pid &&
      descriptorsBefore.start_ticks === resourceBefore.start_ticks &&
      descriptorsBefore.restart_count === resourceBefore.restart_count &&
      descriptorsBefore.total === resourceBefore.file_descriptors &&
      descriptorsAfter.identity === resourceAfter.identity &&
      descriptorsAfter.pid === resourceAfter.pid &&
      descriptorsAfter.start_ticks === resourceAfter.start_ticks &&
      descriptorsAfter.restart_count === resourceAfter.restart_count &&
      descriptorsAfter.total === resourceAfter.file_descriptors,
    'policy-cost descriptor inventories disagree with resource evidence');
    const upstream = plan.input.topology.roles.find((item) =>
      item.role === 'controlled_upstream');
    const policy = plan.input.topology.controlled_upstream;
    descriptorAttributionValue = descriptorAttribution(descriptorsBefore,
      descriptorsAfter, {remote_address: upstream.private_address,
        remote_port: policy.port,
        maximum_connections: policy.max_connections_per_shard *
          point.core_count});
  }
  const finalSamples = prometheus(fileText(files, 'final-metrics.prom'));
  for (const name of ACTIVE_METRICS) {
    requireValue(sumMetric(finalSamples, name,
      `policy-cost final ${name}`) === 0,
    `policy-cost final active metric did not drain: ${name}`);
  }
  const protocol = validateProtocol(files, point);
  const successDenominator = measurement.successes;
  const metrics = {
    offered_rps: point.offered_rps,
    successful_rps: successDenominator / measurement.duration,
    successful_responses: successDenominator,
    active_measurement_seconds: measurement.duration,
    application_cpu_percent: average(perShardCpu.map((item) =>
      item.cpu_percent), 'policy-cost application CPU'),
    host_cpu_percent: gatewayCpu.busy,
    irq_cpu_percent: gatewayCpu.irq,
    p50_ms: measurement.report.latencyPercentiles.p50 * 1000,
    p95_ms: measurement.report.latencyPercentiles.p95 * 1000,
    p99_ms: measurement.report.latencyPercentiles.p99 * 1000,
    p999_reference_ms:
      measurement.report.latencyPercentiles['p99.9'] * 1000,
    cycles_per_success: performance.cycles / successDenominator,
    instructions_per_success: performance.instructions / successDenominator,
    ipc: performance.instructions / performance.cycles,
    allocations_per_success: [...allocations.values()]
      .reduce((a, b) => a + b, 0) / successDenominator,
    syscalls_per_success: performance.syscalls / successDenominator,
    socket_writes_per_success: socket.calls / successDenominator,
    socket_bytes_per_write: socket.completed_bytes / socket.calls,
    queue_waits_per_success: [...poolWaits.values()]
      .reduce((a, b) => a + b, 0) / successDenominator,
    per_shard_cpu_percent: perShardCpu.map((item) => item.cpu_percent),
  };
  const runtime = {
    gateway_process_identity_before: resourceBefore.identity,
    gateway_process_identity_after: resourceAfter.identity,
    gateway_restart_count: resourceAfter.restart_count,
    support_role_capacity_percent: {load_generator: loadCpu.busy,
      controlled_upstream: upstreamCpu.busy},
    rss_before_bytes: resourceBefore.rss_bytes,
    rss_after_bytes: resourceAfter.rss_bytes,
    fd_before: resourceBefore.file_descriptors,
    fd_after: resourceAfter.file_descriptors,
    unexpected_error_count: measurement.httpFailures,
    transport_failure_count: measurement.transportFailures,
  };
  if (plan.schema_version >= 2) {
    runtime.descriptor_attribution = descriptorAttributionValue;
  }
  return {schema_version: plan.schema_version, plan_id: plan.plan_id,
    point_id: point.point_id, profile_id: point.profile_id, attempt,
    evidence_status: 'complete', invalid_reason: null,
    source: plan.input.source, snapshot_sha256: point.snapshot_sha256,
    request, protocol, runtime, metrics};
}

function fileReference(filename, evidenceRoot) {
  const absolute = path.resolve(filename);
  const root = path.resolve(evidenceRoot);
  requireValue(absolute.startsWith(`${root}${path.sep}`),
    'policy-cost output file is outside the evidence root');
  const relative = path.relative(root, absolute).split(path.sep).join('/');
  requireValue(SAFE_PATH.test(relative), 'policy-cost output path is unsafe');
  const bytes = readRegular(absolute, relative);
  return {path: relative, sha256: sha256(bytes), bytes: bytes.length};
}

function writeNew(filename, bytes) {
  const absolute = path.resolve(filename);
  fs.mkdirSync(path.dirname(absolute), {recursive: true});
  fs.writeFileSync(absolute, bytes, {flag: 'wx', mode: 0o600});
}

export function derivePolicyCostEvidence(options) {
  const catalogBytes = readRegular(options.catalog, 'PERF-06 catalog');
  const plan = json(readRegular(options.plan, 'PERF-06 plan'),
    'PERF-06 plan');
  validatePolicyCostPlan(plan, catalogBytes);
  const point = pointFor(plan, options.pointId);
  const archive = packRawCapture(options.rawRoot, options.pointId,
    plan.schema_version);
  const archiveBytes = Buffer.from(`${JSON.stringify(archive, null, 2)}\n`);
  const environmentBytes = readRegular(path.join(options.rawRoot,
    'environment.json'), 'policy-cost environment');
  const input = derivePolicyCostInput(archive, environmentBytes, plan,
    catalogBytes, options.attempt);
  requireValue(point.point_id === input.point_id,
    'policy-cost derived point differs from requested point');

  writeNew(options.captureArchive, archiveBytes);
  writeNew(options.environment, environmentBytes);
  const adapterBytes = readRegular(fileURLToPath(import.meta.url),
    'policy-cost derivation adapter');
  const derivation = {schema_version: plan.schema_version,
    checkpoint: 'PERF-06',
    plan_id: plan.plan_id, point_id: input.point_id,
    profile_id: input.profile_id, attempt: input.attempt,
    adapter_sha256: sha256(adapterBytes),
    raw_manifest_sha256: canonicalHash(archive.files.map((item) => ({
      path: item.path, sha256: item.sha256, bytes: item.bytes}))),
    capture_archive_sha256: sha256(archiveBytes),
    environment_sha256: sha256(environmentBytes),
    normalized_input_sha256: canonicalHash(input),
    derivation_policy:
      'raw-count-duration-counter-socket-protocol-and-process-replay',
    publication_authorized: false};
  writeNew(options.derivationManifest,
    Buffer.from(`${JSON.stringify(derivation, null, 2)}\n`));
  const resultInput = {...input, files: {
    capture_archive: fileReference(options.captureArchive,
      options.evidenceRoot),
    derivation_manifest: fileReference(options.derivationManifest,
      options.evidenceRoot),
    environment: fileReference(options.environment, options.evidenceRoot),
  }};
  const result = buildPolicyCostResult(resultInput, plan, catalogBytes);
  writeNew(options.result,
    Buffer.from(`${JSON.stringify(result, null, 2)}\n`));
  return {archive, derivation, result};
}

function option(name, argv) {
  const index = argv.indexOf(name);
  requireValue(index >= 0 && index + 1 < argv.length, `${name} is required`);
  return argv[index + 1];
}

function main() {
  const [, , command, ...argv] = process.argv;
  requireValue(['describe', 'derive'].includes(command),
    'usage: phase5-policy-cost-native.mjs describe|derive ...');
  const catalog = option('--catalog', argv);
  const planFile = option('--plan', argv);
  const pointId = option('--point-id', argv);
  if (command === 'describe') {
    const catalogBytes = readRegular(catalog, 'PERF-06 catalog');
    const plan = json(readRegular(planFile, 'PERF-06 plan'), 'PERF-06 plan');
    writeNew(option('--output', argv), Buffer.from(`${JSON.stringify(
      describePolicyCostPoint(plan, catalogBytes, pointId), null, 2)}\n`));
    return;
  }
  derivePolicyCostEvidence({catalog, plan: planFile, pointId,
    attempt: Number(option('--attempt', argv)),
    rawRoot: option('--raw-root', argv),
    evidenceRoot: option('--evidence-root', argv),
    captureArchive: option('--capture-archive', argv),
    environment: option('--environment', argv),
    derivationManifest: option('--derivation-manifest', argv),
    result: option('--result', argv)});
}

if (process.argv[1] && import.meta.url ===
    pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-policy-cost-native: ${error.message}\n`);
    process.exitCode = 1;
  }
}
