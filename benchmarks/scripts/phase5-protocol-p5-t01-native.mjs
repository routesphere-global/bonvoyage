#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';

import {parsePerfStat} from './phase5-baseline.mjs';
import {parseOhaReport, partitionCpus} from './phase5-oha-lanes.mjs';
import {validateProtocolNativePlan} from './phase5-protocol-native-plan.mjs';
import {buildProtocolNativeResult} from './phase5-protocol-native-result.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/u;
const FORMAT = 'bonvoyage-perf05-p5-t01-raw-capture';
const METRIC_PREFIX = 'bonvoyage_';
const RAW_FILES = Object.freeze([
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
  'protocol-probe.json',
  'provenance-after.json',
  'provenance-before.json',
  'resource-after.json',
  'resource-before.json',
  'runtime-inventory.json',
  'socket-output.json',
  'status.json',
  'upstream-proc-after.txt',
  'upstream-proc-before.txt',
  'warmup-admission.json',
  'warmup.oha.json',
]);
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

function safeRawFile(root, relative) {
  requireValue(RAW_FILES.includes(relative) && SAFE_PATH.test(relative),
    `unexpected raw capture file: ${relative}`);
  const absoluteRoot = path.resolve(root);
  const absolute = path.resolve(absoluteRoot, relative);
  requireValue(absolute.startsWith(`${absoluteRoot}${path.sep}`),
    `raw capture file escapes root: ${relative}`);
  const stat = fs.lstatSync(absolute);
  requireValue(stat.isFile() && !stat.isSymbolicLink() &&
    stat.size <= 64 * 1024 * 1024,
  `raw capture file is unsafe or oversized: ${relative}`);
  return {absolute, stat};
}

function verifyRawManifest(root) {
  const absoluteRoot = path.resolve(root);
  const stat = fs.lstatSync(absoluteRoot);
  requireValue(stat.isDirectory() && !stat.isSymbolicLink(),
    'raw capture root must be a real directory');
  const manifest = readRegular(path.join(absoluteRoot, 'checksums.sha256'),
    'raw capture checksum manifest', 1024 * 1024).toString('utf8');
  const lines = manifest.trimEnd().split('\n');
  requireValue(lines.length === RAW_FILES.length,
    'raw capture checksum manifest has incomplete coverage');
  const records = lines.map((line, index) => {
    const match = /^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$/u.exec(line);
    requireValue(match, `raw checksum line ${index + 1} is invalid`);
    return {sha256: match[1], path: match[2]};
  });
  requireValue(isDeepStrictEqual(records.map((item) => item.path), RAW_FILES),
    'raw capture checksum paths are not exact, unique, and sorted');
  for (const record of records) {
    const {absolute} = safeRawFile(absoluteRoot, record.path);
    requireValue(sha256(fs.readFileSync(absolute)) === record.sha256,
      `raw capture checksum mismatch: ${record.path}`);
  }
  const actual = fs.readdirSync(absoluteRoot).sort();
  requireValue(isDeepStrictEqual(actual, [...RAW_FILES, 'checksums.sha256'].sort()),
    'raw capture directory contains missing or unbound files');
  return records;
}

function packRawCapture(root, pointId) {
  const records = verifyRawManifest(root);
  return {
    schema_version: 1,
    format: FORMAT,
    point_id: pointId,
    files: records.map((record) => {
      const bytes = fs.readFileSync(path.join(root, record.path));
      return {...record, bytes: bytes.length,
        content_base64: bytes.toString('base64')};
    }),
  };
}

function unpackRawCapture(archive) {
  exactKeys(archive, ['schema_version', 'format', 'point_id', 'files'],
    'P5-T01 raw capture archive');
  requireValue(archive.schema_version === 1 && archive.format === FORMAT,
    'P5-T01 raw capture archive header is invalid');
  requireValue(Array.isArray(archive.files) &&
    archive.files.length === RAW_FILES.length,
  'P5-T01 raw capture file set is incomplete');
  const files = new Map();
  for (const [index, file] of archive.files.entries()) {
    exactKeys(file, ['path', 'sha256', 'bytes', 'content_base64'],
      `P5-T01 raw capture file ${index}`);
    requireValue(file.path === RAW_FILES[index] && SHA256.test(file.sha256),
      `P5-T01 raw capture file ${index} identity is invalid`);
    integer(file.bytes, `P5-T01 raw capture file ${file.path} bytes`);
    requireValue(typeof file.content_base64 === 'string' &&
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u
        .test(file.content_base64),
    `P5-T01 raw capture file ${file.path} is not canonical base64`);
    const bytes = Buffer.from(file.content_base64, 'base64');
    requireValue(bytes.length === file.bytes && sha256(bytes) === file.sha256 &&
      bytes.toString('base64') === file.content_base64,
    `P5-T01 raw capture file ${file.path} differs from its binding`);
    files.set(file.path, bytes);
  }
  return files;
}

function fileText(files, name) {
  const bytes = files.get(name);
  requireValue(bytes !== undefined, `raw capture omits ${name}`);
  return bytes.toString('utf8');
}

function fileJson(files, name) {
  return json(files.get(name), name);
}

function variantFor(plan, pointId) {
  const point = plan.points.find((item) => item.point_id === pointId);
  requireValue(point, `P5-T01 point is outside the plan: ${pointId}`);
  const variant = plan.input.variants.find((item) => item.id === point.variant_id);
  requireValue(variant?.profile === 'P5-T01' &&
    variant.measurement_class === 'throughput-cost',
  `${pointId} is not a P5-T01 throughput-cost point`);
  return {point, variant};
}

function validateProvenance(value, plan, point, variant, label) {
  exactKeys(value, ['schema_version', 'plan_id', 'point_id', 'variant_id',
    'repetition', 'source', 'catalog_sha256', 'snapshot_sha256',
    'observed_harness_commit', 'source_status'], label);
  requireValue(value.schema_version === 1 && value.plan_id === plan.plan_id &&
    value.point_id === point.point_id && value.variant_id === variant.id &&
    value.repetition === point.repetition,
  `${label} point identity differs from plan`);
  requireValue(isDeepStrictEqual(value.source, plan.input.source) &&
    value.catalog_sha256 === plan.input.catalog_sha256 &&
    value.snapshot_sha256 === variant.snapshot_sha256,
  `${label} source or artifact identity differs from plan`);
  requireValue(value.observed_harness_commit ===
    plan.input.source.harness_commit && value.source_status === '' &&
    COMMIT.test(value.observed_harness_commit),
  `${label} does not prove clean harness source`);
}

function validateEnvironment(value, plan, point, variant, attempt) {
  exactKeys(value, ['schema_version', 'plan_id', 'point_id', 'variant_id',
    'repetition', 'attempt', 'roles', 'load_generator_cpu_set',
    'load_generator_lanes', 'gateway_cpu_set',
    'gateway_housekeeping_cpus', 'irq_policy', 'profiler_scope',
    'reactor_tids_before', 'reactor_tids_after', 'profiled_reactor_tids'],
  'P5-T01 environment');
  requireValue(value.schema_version === 1 && value.plan_id === plan.plan_id &&
    value.point_id === point.point_id && value.variant_id === variant.id &&
    value.repetition === point.repetition && value.attempt === attempt,
  'P5-T01 environment point identity differs from plan');
  requireValue(isDeepStrictEqual(value.roles, plan.input.topology.roles) &&
    isDeepStrictEqual(value.load_generator_cpu_set,
      plan.input.topology.load_generator_cpu_set) &&
    value.load_generator_lanes === plan.input.topology.load_generator_lanes &&
    isDeepStrictEqual(value.gateway_cpu_set,
      plan.input.topology.gateway_cpu_sets[String(variant.core_count)]) &&
    isDeepStrictEqual(value.gateway_housekeeping_cpus,
      plan.input.topology.gateway_housekeeping_cpus) &&
    isDeepStrictEqual(value.irq_policy, plan.input.topology.irq_policy) &&
    value.profiler_scope === plan.result_contract.profiler_scope,
  'P5-T01 environment placement differs from plan');
  const expected = variant.core_count;
  for (const name of ['reactor_tids_before', 'reactor_tids_after',
    'profiled_reactor_tids']) {
    requireValue(Array.isArray(value[name]) && value[name].length === expected &&
      new Set(value[name]).size === expected &&
      value[name].every((tid) => Number.isSafeInteger(tid) && tid > 1),
    `P5-T01 environment ${name} is incomplete`);
  }
  requireValue(isDeepStrictEqual(value.reactor_tids_before,
    value.reactor_tids_after) && isDeepStrictEqual(value.reactor_tids_before,
    value.profiled_reactor_tids),
  'P5-T01 reactor identity or profiler coverage changed');
  return value;
}

function validateRuntimeInventory(value, bytes, plan) {
  requireValue(sha256(bytes) === plan.input.source.runtime_inventory_sha256,
    'P5-T01 runtime inventory differs from the native plan');
  requireValue(value?.schema_version === 1 &&
    value.classification === 'private-native-runtime-inventory' &&
    value.outcome === 'collected-unqualified' &&
    value.runtime_profile === 'package-install' &&
    value.producer_source_commit ===
      plan.input.source.binary_source_commit &&
    value.files?.binary?.sha256 ===
      plan.input.source.gateway_binary_sha256 &&
    COMMIT.test(value.producer_source_commit),
  'P5-T01 runtime inventory does not bind the planned package binary');
}

function countMap(value, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  return Object.values(value).reduce((total, item) =>
    total + integer(item, label), 0);
}

function validateOha(raw, plan, variant, expectedSeconds, label) {
  const report = parseOhaReport(raw);
  const duration = finite(report.summary?.total, `${label} duration`, 0.001);
  requireValue(report.offered_rps === variant.workload.target_rps,
    `${label} offered rate differs from plan`);
  const successes = integer(report.statusCodeDistribution?.['200'] ?? 0,
    `${label} HTTP 200 count`, 1);
  const httpFailures = Object.entries(report.statusCodeDistribution ?? {})
    .reduce((total, [status, count]) => status === '200' ? total :
      total + integer(count, `${label} HTTP ${status}`), 0);
  const transportFailures = countMap(report.errorDistribution ?? {},
    `${label} transport failures`);
  for (const name of ['p50', 'p95', 'p99', 'p99.9']) {
    finite(report.latencyPercentiles?.[name], `${label} ${name}`, 0);
  }
  requireValue(report.latencyPercentiles.p50 <= report.latencyPercentiles.p95 &&
    report.latencyPercentiles.p95 <= report.latencyPercentiles.p99 &&
    report.latencyPercentiles.p99 <= report.latencyPercentiles['p99.9'],
  `${label} latency percentiles are not monotonic`);
  const expectedPath = `/perf05/${variant.scenario === 'fixed-response' ?
    'fixed' : 'proxied'}/${variant.payload_bytes}`;
  const gateway = plan.input.topology.roles.find((item) =>
    item.role === 'gateway');
  const expectedClientCpuSets = partitionCpus(
    plan.input.topology.load_generator_cpu_set.join(','),
    plan.input.topology.load_generator_lanes);
  requireValue(report.workload !== undefined &&
    report.client_lanes === plan.input.topology.load_generator_lanes &&
    isDeepStrictEqual(report.client_cpu_sets, expectedClientCpuSets) &&
    report.workload.client_sha256 === plan.input.source.load_client_sha256 &&
    report.workload.protocol === 'http1' && report.workload.tls === true &&
    report.workload.authority === 'api.example.test' &&
    report.workload.listener_port === 8443 &&
    isDeepStrictEqual(report.workload.target_addresses,
      [gateway.private_address]) && report.workload.path === expectedPath &&
    report.workload.connections_per_lane * report.client_lanes ===
      variant.workload.connections &&
    report.workload.streams_per_connection === 1 &&
    report.workload.requests_per_lane * report.client_lanes ===
      variant.workload.target_rps * expectedSeconds &&
    SHA256.test(report.workload.ca_sha256) &&
    report.workload.credential_sha256 === null,
  `${label} structured workload differs from plan`);
  requireValue(duration >= expectedSeconds * 0.95 &&
    duration <= expectedSeconds * 1.1 + 0.5,
  `${label} duration differs from plan`);
  return {report, duration, successes, httpFailures, transportFailures};
}

export function validateP5T01WarmupAdmission(value, plan, variant,
  label = 'P5-T01 warmup admission') {
  exactKeys(value, ['schema_version', 'required_profiled_warmup_repetitions',
    'passes', 'plateau'], label);
  const required = plan?.input?.schedule?.profiled_warmup_repetitions;
  requireValue(value.schema_version === 1 && required === 3 &&
    value.required_profiled_warmup_repetitions === required &&
    Array.isArray(value.passes) && value.passes.length === required,
  `${label} repetition contract is invalid`);
  const expectedSuccesses = variant.workload.target_rps *
    variant.workload.warmup_seconds;
  requireValue(Number.isSafeInteger(expectedSuccesses) && expectedSuccesses > 0,
    `${label} expected request count is invalid`);

  let identity;
  for (const [index, pass] of value.passes.entries()) {
    exactKeys(pass, ['pass', 'settled', 'settlement_ms', 'identity',
      'restart_count', 'rss_bytes', 'file_descriptors',
      'successful_requests', 'http_failures', 'transport_failures'],
    `${label} pass ${index + 1}`);
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
    integer(pass.http_failures, `${label} pass ${index + 1} HTTP failures`);
    integer(pass.transport_failures,
      `${label} pass ${index + 1} transport failures`);
    identity ??= pass.identity;
    requireValue(pass.identity === identity && pass.restart_count === 0 &&
      pass.successful_requests === expectedSuccesses &&
      pass.http_failures === 0 && pass.transport_failures === 0 &&
      pass.settlement_ms <= plan.input.acceptance.maximum_cleanup_ms,
    `${label} pass ${index + 1} failed its admission contract`);
  }

  exactKeys(value.plateau, ['compared_passes', 'rss_delta_bytes', 'fd_delta',
    'stable'], `${label} plateau`);
  const penultimate = value.passes.at(-2);
  const final = value.passes.at(-1);
  const rssDelta = final.rss_bytes - penultimate.rss_bytes;
  const fdDelta = final.file_descriptors - penultimate.file_descriptors;
  requireValue(isDeepStrictEqual(value.plateau.compared_passes,
    [required - 1, required]) &&
    value.plateau.rss_delta_bytes === rssDelta &&
    value.plateau.fd_delta === fdDelta &&
    value.plateau.stable === true && rssDelta === 0 && fdDelta === 0,
  `${label} final profiled passes do not establish an exact resource plateau`);
  return value;
}

function labels(raw) {
  const result = {};
  const matcher = /([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\]|\\.)*)"/gu;
  for (const match of raw.matchAll(matcher)) {
    result[match[1]] = match[2].replaceAll('\\"', '"').replaceAll('\\\\', '\\');
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
      `Prometheus sample at line ${index + 1} is not finite`);
    result.push({name: match[1], labels: labels(match[2] ?? ''), value});
  }
  return result;
}

function shardMap(samples, name, coreCount, label) {
  const result = new Map();
  for (const sample of samples.filter((item) => item.name === name)) {
    const shard = Number(sample.labels.shard);
    requireValue(Number.isSafeInteger(shard) && shard >= 0 && shard < coreCount &&
      !result.has(shard), `${label} has invalid or duplicate shard series`);
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
  return {
    busy: (total - delta[3] - delta[4]) / total * 100,
    irq: (delta[5] + delta[6]) / total * 100,
  };
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
  exactKeys(value, ['measurement_command_exit_code', 'collector_exit_code',
    'protocol_probe_exit_code'], 'P5-T01 status');
  for (const [name, code] of Object.entries(value)) {
    requireValue(code === 0, `P5-T01 ${name} is nonzero`);
  }
}

function selectProtocolCase(value, variant) {
  requireValue(value?.schema_version === 1 && value.profile === 'P5-T01' &&
    value.status === 'pass' && Array.isArray(value.cases),
  'P5-T01 protocol probe is invalid');
  const mode = variant.scenario === 'fixed-response' ? 'fixed' : 'proxied';
  const matching = value.cases.filter((item) => item.mode === mode &&
    item.payload_bytes === variant.payload_bytes);
  requireValue(matching.length === 1, 'P5-T01 protocol probe case is missing');
  const item = matching[0];
  requireValue(item.status === 200 && item.content_length === variant.payload_bytes &&
    item.content_type === 'application/octet-stream' &&
    item.payload_sha256 === sha256(Buffer.alloc(variant.payload_bytes, 'x')) &&
    item.upstream_marker_present === (mode === 'proxied'),
  'P5-T01 protocol payload or route semantics differ');
  requireValue(item.transport?.tls_version === 'TLSv1.3' &&
    /^TLS_AES_[A-Z0-9_]+$/u.test(item.transport.cipher) &&
    !item.transport.cipher.includes('CHACHA') &&
    item.transport.alpn === 'http/1.1' &&
    item.transport.ca_verified === true &&
    item.transport.hostname_verified === true,
  'P5-T01 TLS observation is incomplete or outside contract');
  requireValue(value.negative_probes?.wrong_hostname_rejected === true &&
    value.negative_probes?.untrusted_ca_rejected === true,
  'P5-T01 negative TLS probes did not reject');
  return item;
}

function average(values, label) {
  requireValue(values.length > 0, `${label} is empty`);
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

export function describeP5T01Point(plan, catalogBytes, pointId) {
  validateProtocolNativePlan(plan, catalogBytes);
  const {point, variant} = variantFor(plan, pointId);
  return {schema_version: 1, plan_id: plan.plan_id, point, variant,
    source: plan.input.source, topology: plan.input.topology,
    result_contract: plan.result_contract};
}

export function deriveP5T01Input(archive, environmentBytes, plan,
  catalogBytes, attempt) {
  validateProtocolNativePlan(plan, catalogBytes);
  integer(attempt, 'P5-T01 attempt', 1);
  const files = unpackRawCapture(archive);
  const {point, variant} = variantFor(plan, archive.point_id);
  const environment = validateEnvironment(json(environmentBytes,
    'P5-T01 environment'), plan, point, variant, attempt);
  requireValue(isDeepStrictEqual(environment, fileJson(files,
    'environment.json')), 'external environment differs from raw capture');
  const provenanceBefore = fileJson(files, 'provenance-before.json');
  const provenanceAfter = fileJson(files, 'provenance-after.json');
  validateProvenance(provenanceBefore, plan, point, variant,
    'P5-T01 provenance before');
  validateProvenance(provenanceAfter, plan, point, variant,
    'P5-T01 provenance after');
  validateRuntimeInventory(fileJson(files, 'runtime-inventory.json'),
    files.get('runtime-inventory.json'), plan);
  requireValue(isDeepStrictEqual(provenanceBefore, provenanceAfter),
    'P5-T01 source or artifact identity changed during capture');
  validateStatus(fileJson(files, 'status.json'));
  requireValue(!/(?:fatal|segmentation fault|addresssanitizer|undefinedbehaviorsanitizer)/iu
    .test(fileText(files, 'journal.log')),
  'P5-T01 journal contains a fatal runtime diagnostic');

  const warmupAdmission = validateP5T01WarmupAdmission(fileJson(files,
    'warmup-admission.json'), plan, variant);
  const warmup = validateOha(fileText(files, 'warmup.oha.json'), plan, variant,
    variant.workload.warmup_seconds, 'P5-T01 warmup');
  const measurement = validateOha(fileText(files, 'measurement.oha.json'),
    plan, variant, variant.workload.measurement_seconds,
    'P5-T01 measurement');
  requireValue(warmup.httpFailures === 0 && warmup.transportFailures === 0,
    'P5-T01 warmup contains failures');
  const finalWarmupPass = warmupAdmission.passes.at(-1);
  requireValue(finalWarmupPass.successful_requests === warmup.successes &&
    finalWarmupPass.http_failures === warmup.httpFailures &&
    finalWarmupPass.transport_failures === warmup.transportFailures,
  'P5-T01 final warmup differs from its admission record');
  requireValue(warmup.report.workload.ca_sha256 ===
    measurement.report.workload.ca_sha256 &&
    isDeepStrictEqual(warmup.report.client_cpu_sets,
      measurement.report.client_cpu_sets),
  'P5-T01 load-client identity or placement changed after warmup');
  const totalAttempts = measurement.successes + measurement.httpFailures +
    measurement.transportFailures;
  const errorRate = (measurement.httpFailures + measurement.transportFailures) /
    totalAttempts;

  const beforeSamples = prometheus(fileText(files,
    'gateway-metrics-before.prom'));
  const afterSamples = prometheus(fileText(files,
    'gateway-metrics-after.prom'));
  const coreCount = variant.core_count;
  const deltas = (name, label) => deltaMap(
    shardMap(beforeSamples, name, coreCount, `${label} before`),
    shardMap(afterSamples, name, coreCount, `${label} after`), label);
  const requests = deltas('bonvoyage_bonvoyage_gateway_requests_total',
    'gateway requests');
  const successes = deltas('bonvoyage_bonvoyage_gateway_responses_2xx_total',
    'gateway successful responses');
  const allocations = deltas('bonvoyage_memory_malloc_operations',
    'gateway allocations');
  const poolWaits = deltas(
    'bonvoyage_bonvoyage_gateway_upstream_http1_pool_waits_total',
    'upstream HTTP/1 pool waits');
  const poolWaitNanoseconds = deltas(
    'bonvoyage_bonvoyage_gateway_upstream_http1_pool_wait_nanoseconds_total',
    'upstream HTTP/1 pool wait nanoseconds');
  const poolWaitMaximumBefore = shardMap(beforeSamples,
    'bonvoyage_bonvoyage_gateway_upstream_http1_pool_wait_max_nanoseconds',
    coreCount, 'upstream HTTP/1 pool wait maximum before');
  const poolWaitMaximumAfter = shardMap(afterSamples,
    'bonvoyage_bonvoyage_gateway_upstream_http1_pool_wait_max_nanoseconds',
    coreCount, 'upstream HTTP/1 pool wait maximum after');
  const reactorBusy = deltas('bonvoyage_reactor_cpu_busy_ms',
    'reactor busy time');
  const successfulOperations = [...successes.values()].reduce((a, b) => a + b, 0);
  const requestOperations = [...requests.values()].reduce((a, b) => a + b, 0);
  requireValue(successfulOperations === measurement.successes &&
    requestOperations === totalAttempts,
  'P5-T01 client and gateway request denominators differ');
  const poolWaitCount = [...poolWaits.values()].reduce((a, b) => a + b, 0);
  let poolWaitMaximumNanoseconds = 0;
  for (const [shard, count] of poolWaits) {
    const total = poolWaitNanoseconds.get(shard);
    const beforeMaximum = poolWaitMaximumBefore.get(shard);
    const afterMaximum = poolWaitMaximumAfter.get(shard);
    requireValue(afterMaximum >= beforeMaximum,
      `P5-T01 shard ${shard} pool-wait maximum regressed`);
    if (count === 0) {
      requireValue(total === 0,
        `P5-T01 shard ${shard} pool-wait duration changed without a wait`);
      continue;
    }
    requireValue(total > 0 && afterMaximum > 0 && total / count <= afterMaximum,
      `P5-T01 shard ${shard} pool-wait duration is inconsistent`);
    poolWaitMaximumNanoseconds = Math.max(poolWaitMaximumNanoseconds,
      afterMaximum);
  }

  const intervalSeconds = measurement.duration;
  const perShardWork = [...successes].map(([shard, count]) => ({
    shard,
    successful_operations: integer(count,
      `P5-T01 shard ${shard} successful operations`),
    cpu_percent: finite(reactorBusy.get(shard) /
      (intervalSeconds * 1000) * 100, `P5-T01 shard ${shard} CPU`, 0, 100),
  }));
  const applicationCpu = average(perShardWork.map((item) => item.cpu_percent),
    'P5-T01 application CPU');
  const gatewayCpu = cpuPercent(fileText(files, 'gateway-proc-before.txt'),
    fileText(files, 'gateway-proc-after.txt'), 'gateway host');
  const loadCpu = cpuPercent(fileText(files, 'load-generator-proc-before.txt'),
    fileText(files, 'load-generator-proc-after.txt'), 'load-generator host');
  const upstreamCpu = cpuPercent(fileText(files, 'upstream-proc-before.txt'),
    fileText(files, 'upstream-proc-after.txt'), 'controlled-upstream host');
  const performance = parsePerfStat(fileText(files, 'perf.csv'));
  const socket = validateSocket(fileJson(files, 'socket-output.json'),
    'P5-T01 socket output');
  const resourceBefore = validateResource(fileJson(files,
    'resource-before.json'), 'P5-T01 resource before');
  const resourceAfter = validateResource(fileJson(files,
    'resource-after.json'), 'P5-T01 resource after');
  requireValue(finalWarmupPass.identity === resourceBefore.identity &&
    finalWarmupPass.restart_count === resourceBefore.restart_count &&
    finalWarmupPass.rss_bytes === resourceBefore.rss_bytes &&
    finalWarmupPass.file_descriptors === resourceBefore.file_descriptors,
  'P5-T01 formal baseline differs from the admitted warmup plateau');
  requireValue(resourceBefore.identity === resourceAfter.identity &&
    resourceBefore.pid === resourceAfter.pid &&
    resourceBefore.start_ticks === resourceAfter.start_ticks &&
    resourceBefore.restart_count === resourceAfter.restart_count &&
    resourceAfter.restart_count === 0 && socket.pid === resourceBefore.pid &&
    socket.start_ticks === resourceBefore.start_ticks,
  'P5-T01 gateway process identity changed or disagrees with socket evidence');

  const finalSamples = prometheus(fileText(files, 'final-metrics.prom'));
  for (const name of ACTIVE_METRICS) {
    requireValue(sumMetric(finalSamples, name, `P5-T01 final ${name}`) === 0,
      `P5-T01 final active metric did not drain: ${name}`);
  }
  const protocolCase = selectProtocolCase(fileJson(files,
    'protocol-probe.json'), variant);
  const successDenominator = measurement.successes;
  const metrics = {
    successful_rps: measurement.report.successful_rps,
    application_cpu_percent: applicationCpu,
    host_cpu_percent: gatewayCpu.busy,
    irq_cpu_percent: gatewayCpu.irq,
    cycles_per_success: performance.cycles / successDenominator,
    instructions_per_success: performance.instructions / successDenominator,
    ipc: performance.ipc,
    allocations_per_success: [...allocations.values()].reduce((a, b) => a + b, 0) /
      successDenominator,
    syscalls_per_success: performance.syscalls / successDenominator,
    writes_per_success: socket.calls / successDenominator,
    bytes_per_write: socket.completed_bytes / socket.calls,
    p50_ms: measurement.report.latencyPercentiles.p50 * 1000,
    p95_ms: measurement.report.latencyPercentiles.p95 * 1000,
    p99_ms: measurement.report.latencyPercentiles.p99 * 1000,
    p999_reference_ms: measurement.report.latencyPercentiles['p99.9'] * 1000,
    rss_bytes: resourceAfter.rss_bytes,
    file_descriptors: resourceAfter.file_descriptors,
    queue_waits: {count: poolWaitCount,
      maximum_ms: poolWaitMaximumNanoseconds / 1e6},
    per_shard_work: perShardWork,
  };
  return {
    schema_version: 1,
    plan_id: plan.plan_id,
    point_id: point.point_id,
    variant_id: variant.id,
    repetition: point.repetition,
    attempt,
    evidence_status: 'complete',
    invalid_reason: null,
    source: plan.input.source,
    catalog_sha256: plan.input.catalog_sha256,
    snapshot_sha256: variant.snapshot_sha256,
    execution: {
      roles: environment.roles,
      load_generator_cpu_set: environment.load_generator_cpu_set,
      load_generator_lanes: environment.load_generator_lanes,
      gateway_cpu_set: environment.gateway_cpu_set,
      gateway_housekeeping_cpus: environment.gateway_housekeeping_cpus,
      irq_policy: environment.irq_policy,
      profiler_scope: environment.profiler_scope,
      reactor_tids_before: environment.reactor_tids_before,
      reactor_tids_after: environment.reactor_tids_after,
      profiled_reactor_tids: environment.profiled_reactor_tids,
    },
    protocol: {
      downstream_tls_version: protocolCase.transport.tls_version,
      downstream_tls_cipher: protocolCase.transport.cipher,
      downstream_peer_certificate_verified: protocolCase.transport.ca_verified,
      downstream_hostname_verified: protocolCase.transport.hostname_verified,
      downstream_alpn: protocolCase.transport.alpn,
      upstream_protocol: variant.upstream_protocol,
      semantic_outcome: 'success',
      payload_or_event_order_exact: true,
    },
    runtime: {
      gateway_process_identity_before: resourceBefore.identity,
      gateway_process_identity_after: resourceAfter.identity,
      gateway_restart_count: resourceAfter.restart_count,
      same_process_recovery: true,
      support_role_capacity_percent: {
        load_generator: loadCpu.busy,
        controlled_upstream: upstreamCpu.busy,
      },
      final_active_streams: 0,
      maximum_cleanup_ms: null,
      retained_rss_growth_bytes: resourceAfter.rss_bytes - resourceBefore.rss_bytes,
      retained_fd_growth: resourceAfter.file_descriptors -
        resourceBefore.file_descriptors,
      unexpected_error_count: measurement.httpFailures,
      transport_failure_count: measurement.transportFailures,
      pre_overload_error_rate: errorRate,
    },
    metrics,
  };
}

function fileReference(filename, evidenceRoot) {
  const absolute = path.resolve(filename);
  const root = path.resolve(evidenceRoot);
  requireValue(absolute.startsWith(`${root}${path.sep}`),
    'P5-T01 output file is outside the evidence root');
  const relative = path.relative(root, absolute).split(path.sep).join('/');
  requireValue(SAFE_PATH.test(relative), 'P5-T01 output path is unsafe');
  const bytes = readRegular(absolute, relative);
  return {path: relative, sha256: sha256(bytes), bytes: bytes.length};
}

function writeNew(filename, bytes) {
  const absolute = path.resolve(filename);
  fs.mkdirSync(path.dirname(absolute), {recursive: true});
  fs.writeFileSync(absolute, bytes, {flag: 'wx', mode: 0o600});
}

export function deriveP5T01Evidence(options) {
  const catalogBytes = readRegular(options.catalog, 'PERF-05 catalog')
    .toString('utf8');
  const plan = json(readRegular(options.plan, 'PERF-05 plan'), 'PERF-05 plan');
  validateProtocolNativePlan(plan, catalogBytes);
  const {point} = variantFor(plan, options.pointId);
  const archive = packRawCapture(options.rawRoot, options.pointId);
  const archiveBytes = Buffer.from(`${JSON.stringify(archive, null, 2)}\n`);
  const environmentBytes = readRegular(path.join(options.rawRoot,
    'environment.json'), 'P5-T01 environment');
  const input = deriveP5T01Input(archive, environmentBytes, plan, catalogBytes,
    options.attempt);
  requireValue(point.point_id === input.point_id,
    'P5-T01 derived point differs from requested point');

  writeNew(options.captureArchive, archiveBytes);
  writeNew(options.environment, environmentBytes);
  const adapterBytes = readRegular(fileURLToPath(import.meta.url),
    'P5-T01 derivation adapter');
  const derivation = {
    schema_version: 1,
    profile: 'P5-T01',
    plan_id: plan.plan_id,
    point_id: input.point_id,
    attempt: input.attempt,
    adapter_sha256: sha256(adapterBytes),
    raw_manifest_sha256: canonicalHash(archive.files.map((item) => ({
      path: item.path, sha256: item.sha256, bytes: item.bytes,
    }))),
    capture_archive_sha256: sha256(archiveBytes),
    environment_sha256: sha256(environmentBytes),
    normalized_input_sha256: canonicalHash(input),
    queue_wait_duration_policy:
      'exact-total-with-conservative-process-lifetime-maximum',
    publication_authorized: false,
  };
  writeNew(options.derivationManifest,
    Buffer.from(`${JSON.stringify(derivation, null, 2)}\n`));
  const resultInput = {...input, files: {
    capture_archive: fileReference(options.captureArchive, options.evidenceRoot),
    derivation_manifest: fileReference(options.derivationManifest,
      options.evidenceRoot),
    environment: fileReference(options.environment, options.evidenceRoot),
  }};
  const result = buildProtocolNativeResult(resultInput, plan, catalogBytes);
  writeNew(options.result, Buffer.from(`${JSON.stringify(result, null, 2)}\n`));
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
    'usage: phase5-protocol-p5-t01-native.mjs describe|derive ...');
  const catalog = option('--catalog', argv);
  const planFile = option('--plan', argv);
  const pointId = option('--point-id', argv);
  if (command === 'describe') {
    const catalogBytes = readRegular(catalog, 'PERF-05 catalog').toString('utf8');
    const plan = json(readRegular(planFile, 'PERF-05 plan'), 'PERF-05 plan');
    const output = option('--output', argv);
    writeNew(output, Buffer.from(`${JSON.stringify(
      describeP5T01Point(plan, catalogBytes, pointId), null, 2)}\n`));
    return;
  }
  deriveP5T01Evidence({catalog, plan: planFile, pointId,
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
    process.stderr.write(`phase5-protocol-p5-t01-native: ${error.message}\n`);
    process.exitCode = 1;
  }
}
