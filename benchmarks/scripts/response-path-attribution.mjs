#!/usr/bin/env node

import {createHash} from 'node:crypto';
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
import path from 'node:path';

import {parsePerfStat} from './phase5-baseline.mjs';
import {parseOhaReport} from './phase5-oha-lanes.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const APPLICATION_COUNTERS = Object.freeze([
  'completed_responses',
  'write_operations',
  'write_bytes',
  'flush_operations',
  'flush_wait_operations',
  'flush_wait_nanoseconds',
  'handoff_observations',
  'handoff_nanoseconds',
]);
const METRIC_PREFIX = 'bonvoyage_bonvoyage_gateway_';
const RESPONSE_PATH_METRICS = Object.freeze({
  response_path_completed_responses_total: 'completed_responses',
  response_path_write_operations_total: 'write_operations',
  response_path_write_bytes_total: 'write_bytes',
  response_path_flush_operations_total: 'flush_operations',
  response_path_flush_wait_operations_total: 'flush_wait_operations',
  response_path_flush_wait_nanoseconds_total: 'flush_wait_nanoseconds',
  response_path_handoff_observations_total: 'handoff_observations',
  response_path_handoff_nanoseconds_total: 'handoff_nanoseconds',
});
const RUNTIME_IDENTITY_FIELDS = Object.freeze([
  'interval_id', 'pid', 'start_ticks', 'restart_count', 'boot_id',
  'executable_path', 'executable_sha256', 'snapshot_path',
  'snapshot_sha256', 'cmdline_sha256', 'response_path_diagnostics',
]);

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  requireValue(stable(Object.keys(value).sort()) === stable([...expected].sort()),
    `${label} has missing or unexpected keys`);
}

function nonnegativeInteger(value, label) {
  requireValue(Number.isSafeInteger(value) && value >= 0,
    `${label} must be a non-negative safe integer`);
  return value;
}

function positiveInteger(value, label) {
  requireValue(Number.isSafeInteger(value) && value > 0,
    `${label} must be a positive safe integer`);
  return value;
}

function digest(value, label) {
  requireValue(typeof value === 'string' && SHA256.test(value),
    `${label} must be a lowercase SHA-256 digest`);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function parseCountMap(value, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  let total = 0;
  for (const [name, count] of Object.entries(value)) {
    requireValue(typeof name === 'string' && name.length > 0,
      `${label} contains an invalid key`);
    total += nonnegativeInteger(count, `${label} ${name}`);
    requireValue(Number.isSafeInteger(total), `${label} total is unsafe`);
  }
  return total;
}

/**
 * Reduces the per-shard Prometheus exposition to the exact application
 * counters consumed by the PERF-03 analyzer. Every response-path metric must
 * expose the same shard-label set so a missing shard cannot silently lower a
 * delta.
 */
export function parseResponsePathMetrics(raw, intervalId,
  diagnosticsExpected = true) {
  requireValue(typeof raw === 'string' && raw.length > 0,
    'Prometheus exposition is required');
  requireValue(typeof intervalId === 'string' && intervalId.length > 0,
    'metrics interval id is required');
  const wanted = new Set([
    'response_path_diagnostics_enabled', ...Object.keys(RESPONSE_PATH_METRICS),
  ]);
  const samples = new Map([...wanted].map((name) => [name, new Map()]));
  for (const [index, sourceLine] of raw.split(/\r?\n/u).entries()) {
    const line = sourceLine.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^([a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^}]*\})?)\s+(\S+)(?:\s+\d+)?$/u
      .exec(line);
    if (!match) continue;
    const descriptor = match[1];
    const brace = descriptor.indexOf('{');
    const metric = (brace < 0 ? descriptor : descriptor.slice(0, brace));
    if (!metric.startsWith(METRIC_PREFIX)) continue;
    const suffix = metric.slice(METRIC_PREFIX.length);
    if (!wanted.has(suffix)) continue;
    const labels = brace < 0 ? '' : descriptor.slice(brace);
    const value = Number(match[2]);
    requireValue(Number.isSafeInteger(value) && value >= 0,
      `metric ${suffix} at line ${index + 1} is not a non-negative integer`);
    requireValue(!samples.get(suffix).has(labels),
      `metric ${suffix} contains a duplicate series`);
    samples.get(suffix).set(labels, value);
  }

  const enabled = samples.get('response_path_diagnostics_enabled');
  requireValue(enabled.size > 0,
    'response-path diagnostics gauge is missing');
  const labels = [...enabled.keys()].sort();
  for (const value of enabled.values()) {
    requireValue(value === (diagnosticsExpected ? 1 : 0),
      `response-path diagnostics gauge is not ${diagnosticsExpected ? 'enabled' : 'disabled'}`);
  }

  const snapshot = {interval_id: intervalId};
  for (const [metric, field] of Object.entries(RESPONSE_PATH_METRICS)) {
    const series = samples.get(metric);
    requireValue(series.size > 0, `metric ${metric} is missing`);
    requireValue(stable([...series.keys()].sort()) === stable(labels),
      `metric ${metric} shard series differ from diagnostics gauge`);
    let total = 0;
    for (const value of series.values()) {
      total += value;
      requireValue(Number.isSafeInteger(total), `metric ${metric} total is unsafe`);
    }
    snapshot[field] = total;
  }
  return {snapshot, series: labels};
}

export function workloadFromOha(raw, intervalId, durationNanoseconds) {
  const report = parseOhaReport(typeof raw === 'string' ? raw : stable(raw));
  requireValue(report && typeof report === 'object' &&
    Number.isFinite(report.summary?.total) && report.summary.total > 0,
  'OHA report duration is missing');
  const intervalSeconds = positiveInteger(durationNanoseconds,
    'workload interval duration') / 1e9;
  requireValue(intervalSeconds >= report.summary.total * 0.95 &&
    intervalSeconds <= report.summary.total + 2,
  'OHA duration differs from the collector interval');
  const statuses = report.statusCodeDistribution;
  parseCountMap(statuses, 'OHA status distribution');
  const successes = nonnegativeInteger(statuses['200'] ?? 0,
    'OHA successful responses');
  const httpFailures = Object.entries(statuses).reduce((sum, [status, count]) =>
    status === '200' ? sum : sum + count, 0);
  const transportFailures = parseCountMap(report.errorDistribution ?? {},
    'OHA error distribution');
  requireValue(successes + httpFailures + transportFailures > 0,
    'OHA report contains no completed attempts');
  return {
    interval_id: intervalId,
    duration_nanoseconds: durationNanoseconds,
    successful_responses: successes,
    http_failures: httpFailures,
    transport_failures: transportFailures,
  };
}

export function performanceFromPerfStat(raw, runtimeIdentity,
  durationNanoseconds) {
  const counters = parsePerfStat(raw);
  return {
    interval_id: runtimeIdentity.interval_id,
    duration_nanoseconds: durationNanoseconds,
    scope: 'gateway-process',
    pid: runtimeIdentity.pid,
    start_ticks: runtimeIdentity.start_ticks,
    cycles: counters.cycles,
    instructions: counters.instructions,
  };
}

function validateRuntimeIdentity(value, label, intervalId) {
  exactKeys(value, RUNTIME_IDENTITY_FIELDS, label);
  requireValue(value.interval_id === intervalId,
    `${label} interval differs from capture`);
  positiveInteger(value.pid, `${label} pid`);
  positiveInteger(value.start_ticks, `${label} start ticks`);
  nonnegativeInteger(value.restart_count, `${label} restart count`);
  digest(value.executable_sha256, `${label} executable`);
  digest(value.snapshot_sha256, `${label} snapshot`);
  digest(value.cmdline_sha256, `${label} command line`);
  requireValue(value.response_path_diagnostics === true,
    `${label} response-path diagnostics are disabled`);
}

function validateRuntimeManifest(raw, anchor, sourceCommit, binarySha256) {
  digest(anchor, 'runtime manifest');
  requireValue(sha256(raw) === anchor, 'runtime manifest digest mismatch');
  const manifest = JSON.parse(raw);
  exactKeys(manifest, ['schema_version', 'classification', 'distribution',
    'architecture', 'version', 'maintainer', 'producer_source_commit',
    'source_date_epoch', 'files'], 'runtime manifest');
  requireValue(manifest.schema_version === 1 &&
    manifest.classification === 'private-native-gateway-input' &&
    manifest.distribution === 'ubuntu-24.04' &&
    manifest.architecture === 'amd64',
  'runtime manifest platform or classification is invalid');
  requireValue(manifest.producer_source_commit === sourceCommit,
    'runtime manifest source commit differs from collector source');
  exactKeys(manifest.files, ['dataplane', 'copyright'], 'runtime manifest files');
  exactKeys(manifest.files.dataplane, ['path', 'sha256', 'bytes'],
    'runtime manifest dataplane');
  digest(manifest.files.dataplane.sha256, 'runtime manifest dataplane');
  requireValue(manifest.files.dataplane.sha256 === binarySha256,
    'running executable differs from source-bound runtime manifest');
  return manifest;
}

/** Builds the frozen schema from independently retained native raw inputs. */
export function buildNativeResponsePathCapture(input) {
  exactKeys(input, ['run_id', 'point_id', 'source_commit',
    'configuration_sha256', 'runtime_manifest', 'runtime_manifest_sha256',
    'tls', 'payload_bytes', 'interval_id', 'duration_nanoseconds',
    'runtime_before', 'runtime_after', 'application_before_prometheus',
    'application_after_prometheus', 'workload_oha', 'socket_output',
    'performance_csv'], 'native capture inputs');
  requireValue(COMMIT.test(input.source_commit),
    'native capture source commit is invalid');
  digest(input.configuration_sha256, 'native capture configuration');
  requireValue(typeof input.tls === 'boolean', 'native capture TLS is invalid');
  positiveInteger(input.payload_bytes, 'native capture payload bytes');
  positiveInteger(input.duration_nanoseconds, 'native capture duration');
  validateRuntimeIdentity(input.runtime_before, 'runtime_before',
    input.interval_id);
  validateRuntimeIdentity(input.runtime_after, 'runtime_after',
    input.interval_id);
  requireValue(stable(input.runtime_before) === stable(input.runtime_after),
    'runtime identity changed during native capture');
  validateRuntimeManifest(input.runtime_manifest,
    input.runtime_manifest_sha256, input.source_commit,
    input.runtime_before.executable_sha256);

  const before = parseResponsePathMetrics(
    input.application_before_prometheus, input.interval_id);
  const after = parseResponsePathMetrics(
    input.application_after_prometheus, input.interval_id);
  requireValue(stable(before.series) === stable(after.series),
    'application metric shard series changed during native capture');

  return {
    schema_version: 1,
    run_id: input.run_id,
    point_id: input.point_id,
    evidence_class: 'native-diagnostic-engineering',
    publication_authorized: false,
    source_commit: input.source_commit,
    source_dirty: false,
    binary_sha256: input.runtime_before.executable_sha256,
    snapshot_sha256: input.runtime_before.snapshot_sha256,
    configuration_sha256: input.configuration_sha256,
    protocol: 'http1',
    tls: input.tls,
    method: 'GET',
    payload_bytes: input.payload_bytes,
    interval: {
      interval_id: input.interval_id,
      duration_nanoseconds: input.duration_nanoseconds,
    },
    process_before: {
      interval_id: input.interval_id,
      pid: input.runtime_before.pid,
      start_ticks: input.runtime_before.start_ticks,
      restart_count: input.runtime_before.restart_count,
    },
    process_after: {
      interval_id: input.interval_id,
      pid: input.runtime_after.pid,
      start_ticks: input.runtime_after.start_ticks,
      restart_count: input.runtime_after.restart_count,
    },
    workload: workloadFromOha(input.workload_oha, input.interval_id,
      input.duration_nanoseconds),
    application_before: before.snapshot,
    application_after: after.snapshot,
    socket_output: input.socket_output,
    performance: performanceFromPerfStat(input.performance_csv,
      input.runtime_before, input.duration_nanoseconds),
  };
}

function validateProcess(value, label, intervalId) {
  exactKeys(value, ['interval_id', 'pid', 'start_ticks', 'restart_count'], label);
  requireValue(value.interval_id === intervalId,
    `${label} interval differs from capture`);
  positiveInteger(value.pid, `${label} pid`);
  positiveInteger(value.start_ticks, `${label} start_ticks`);
  nonnegativeInteger(value.restart_count, `${label} restart_count`);
}

function validateApplicationSnapshot(value, label, intervalId) {
  exactKeys(value, ['interval_id', ...APPLICATION_COUNTERS], label);
  requireValue(value.interval_id === intervalId,
    `${label} interval differs from capture`);
  for (const field of APPLICATION_COUNTERS) {
    nonnegativeInteger(value[field], `${label} ${field}`);
  }
}

function counterDeltas(before, after) {
  return Object.fromEntries(APPLICATION_COUNTERS.map((field) => {
    requireValue(after[field] >= before[field],
      `application counter reset: ${field}`);
    return [field, after[field] - before[field]];
  }));
}

function divide(numerator, denominator) {
  return denominator === 0 ? null : numerator / denominator;
}

/**
 * Validates one PERF-03 diagnostic interval and derives normalized metrics.
 * Application submissions and kernel socket operations deliberately remain
 * separate because a Seastar output write is not evidence of one syscall.
 */
export function analyzeResponsePathAttribution(capture) {
  exactKeys(capture, [
    'schema_version', 'run_id', 'point_id', 'evidence_class',
    'publication_authorized', 'source_commit', 'source_dirty',
    'binary_sha256', 'snapshot_sha256', 'configuration_sha256',
    'protocol', 'tls', 'method', 'payload_bytes', 'interval',
    'process_before', 'process_after', 'workload',
    'application_before', 'application_after', 'socket_output', 'performance',
  ], 'capture');
  requireValue(capture.schema_version === 1,
    'unsupported response-path attribution schema');
  for (const field of ['run_id', 'point_id', 'evidence_class']) {
    requireValue(typeof capture[field] === 'string' && capture[field].length > 0,
      `${field} is required`);
  }
  requireValue(capture.publication_authorized === false,
    'diagnostic attribution cannot authorize publication');
  requireValue(COMMIT.test(capture.source_commit),
    'source_commit must be a lowercase Git commit');
  requireValue(capture.source_dirty === false,
    'clean source is required for response-path attribution');
  for (const field of ['binary_sha256', 'snapshot_sha256',
    'configuration_sha256']) digest(capture[field], field);
  requireValue(capture.protocol === 'http1',
    'initial PERF-03 attribution supports HTTP/1.1 only');
  requireValue(typeof capture.tls === 'boolean', 'tls must be a boolean');
  requireValue(capture.method === 'GET', 'initial PERF-03 method must be GET');
  positiveInteger(capture.payload_bytes, 'payload_bytes');

  exactKeys(capture.interval, ['interval_id', 'duration_nanoseconds'], 'interval');
  requireValue(typeof capture.interval.interval_id === 'string' &&
    capture.interval.interval_id.length > 0, 'interval_id is required');
  positiveInteger(capture.interval.duration_nanoseconds,
    'interval duration_nanoseconds');

  const intervalId = capture.interval.interval_id;
  const intervalDuration = capture.interval.duration_nanoseconds;
  validateProcess(capture.process_before, 'process_before', intervalId);
  validateProcess(capture.process_after, 'process_after', intervalId);
  requireValue(capture.process_before.pid === capture.process_after.pid &&
    capture.process_before.start_ticks === capture.process_after.start_ticks &&
    capture.process_before.restart_count === capture.process_after.restart_count,
  'gateway process was replaced or restarted');

  exactKeys(capture.workload, [
    'interval_id', 'duration_nanoseconds', 'successful_responses',
    'http_failures', 'transport_failures',
  ], 'workload');
  requireValue(capture.workload.interval_id === intervalId &&
    capture.workload.duration_nanoseconds === intervalDuration,
  'workload interval differs from capture');
  const responses = positiveInteger(capture.workload.successful_responses,
    'workload successful_responses');
  nonnegativeInteger(capture.workload.http_failures, 'workload http_failures');
  nonnegativeInteger(capture.workload.transport_failures,
    'workload transport_failures');
  requireValue(capture.workload.http_failures === 0 &&
    capture.workload.transport_failures === 0,
  'diagnostic workload contains failed responses');

  validateApplicationSnapshot(capture.application_before,
    'application_before', intervalId);
  validateApplicationSnapshot(capture.application_after,
    'application_after', intervalId);
  const application = counterDeltas(capture.application_before,
    capture.application_after);
  requireValue(application.completed_responses === responses,
    'application completed-response denominator differs from workload');
  requireValue(application.handoff_observations === responses,
    'application handoff denominator differs from workload');
  requireValue(application.write_operations >= responses,
    'application write count is below completed responses');
  requireValue(application.write_bytes >= responses * capture.payload_bytes,
    'application write bytes are below response payload bytes');
  requireValue(application.flush_operations >= responses,
    'application flush count is below completed responses');
  requireValue(application.flush_wait_operations <= application.flush_operations,
    'flush waits exceed flush operations');

  exactKeys(capture.socket_output, [
    'interval_id', 'duration_nanoseconds', 'scope', 'pid', 'start_ticks',
    'calls', 'requested_bytes',
    'completed_bytes', 'partial_writes', 'would_block', 'fatal_errors',
    'lost_events',
  ], 'socket_output');
  requireValue(capture.socket_output.scope === 'gateway-downstream-sockets',
    'socket output is not scoped to gateway downstream sockets');
  requireValue(capture.socket_output.interval_id === intervalId &&
    capture.socket_output.duration_nanoseconds === intervalDuration,
  'socket output interval differs from capture');
  requireValue(capture.socket_output.pid === capture.process_before.pid &&
    capture.socket_output.start_ticks === capture.process_before.start_ticks,
  'socket output process identity differs from gateway');
  for (const field of ['calls', 'requested_bytes', 'completed_bytes',
    'partial_writes', 'would_block', 'fatal_errors', 'lost_events']) {
    nonnegativeInteger(capture.socket_output[field], `socket_output ${field}`);
  }
  requireValue(capture.socket_output.calls > 0,
    'socket output contains no calls');
  requireValue(capture.socket_output.completed_bytes > 0 &&
    capture.socket_output.completed_bytes <= capture.socket_output.requested_bytes,
  'socket output byte accounting is invalid');
  requireValue(capture.socket_output.partial_writes <= capture.socket_output.calls,
    'partial writes exceed socket calls');
  requireValue(capture.socket_output.partial_writes +
    capture.socket_output.would_block + capture.socket_output.fatal_errors <=
    capture.socket_output.calls,
  'socket output classifications exceed socket calls');
  requireValue(capture.socket_output.fatal_errors === 0,
    'socket output contains fatal errors');
  requireValue(capture.socket_output.lost_events === 0,
    'socket trace lost events');

  exactKeys(capture.performance,
    ['interval_id', 'duration_nanoseconds', 'scope', 'pid', 'start_ticks',
      'cycles', 'instructions'], 'performance');
  requireValue(capture.performance.scope === 'gateway-process',
    'performance counters are not process scoped');
  requireValue(capture.performance.interval_id === intervalId &&
    capture.performance.duration_nanoseconds === intervalDuration,
  'performance counter interval differs from capture');
  requireValue(capture.performance.pid === capture.process_before.pid &&
    capture.performance.start_ticks === capture.process_before.start_ticks,
  'performance counter process identity differs from gateway');
  positiveInteger(capture.performance.cycles, 'performance cycles');
  positiveInteger(capture.performance.instructions, 'performance instructions');

  return {
    schema_version: 1,
    run_id: capture.run_id,
    point_id: capture.point_id,
    evidence_class: capture.evidence_class,
    publication_authorized: false,
    source_commit: capture.source_commit,
    protocol: capture.protocol,
    tls: capture.tls,
    payload_bytes: capture.payload_bytes,
    successful_responses: responses,
    application,
    socket_output: capture.socket_output,
    derived: {
      application_writes_per_response:
        application.write_operations / responses,
      application_bytes_per_write:
        application.write_bytes / application.write_operations,
      application_flushes_per_response:
        application.flush_operations / responses,
      application_flush_wait_fraction:
        application.flush_wait_operations / application.flush_operations,
      mean_waited_flush_microseconds: divide(
        application.flush_wait_nanoseconds / 1000,
        application.flush_wait_operations),
      mean_handoff_microseconds:
        application.handoff_nanoseconds / application.handoff_observations / 1000,
      socket_calls_per_response: capture.socket_output.calls / responses,
      socket_bytes_per_call:
        capture.socket_output.completed_bytes / capture.socket_output.calls,
      socket_partial_write_fraction:
        capture.socket_output.partial_writes / capture.socket_output.calls,
      socket_would_block_per_response:
        capture.socket_output.would_block / responses,
      cycles_per_response: capture.performance.cycles / responses,
      instructions_per_response: capture.performance.instructions / responses,
      ipc: capture.performance.instructions / capture.performance.cycles,
    },
    decision: 'attribution-valid-not-capacity-qualification',
  };
}

function fixed(value, digits = 4) {
  return value === null ? 'n/a' : Number(value).toFixed(digits);
}

export function renderResponsePathAttribution(summary) {
  return `# PERF-03 response-path attribution: ${summary.point_id}\n\n` +
    `- Evidence class: \`${summary.evidence_class}\`.\n` +
    `- Publication authorized: \`${summary.publication_authorized}\`.\n` +
    `- Source: \`${summary.source_commit}\`.\n` +
    `- Decision: **${summary.decision}**.\n\n` +
    '| Metric | Value |\n| --- | ---: |\n' +
    `| Successful responses | ${summary.successful_responses} |\n` +
    `| Application writes / response | ${fixed(summary.derived.application_writes_per_response)} |\n` +
    `| Application bytes / write | ${fixed(summary.derived.application_bytes_per_write, 2)} |\n` +
    `| Application flushes / response | ${fixed(summary.derived.application_flushes_per_response)} |\n` +
    `| Waited flush fraction | ${fixed(summary.derived.application_flush_wait_fraction)} |\n` +
    `| Mean waited flush | ${fixed(summary.derived.mean_waited_flush_microseconds, 3)} us |\n` +
    `| Mean upstream handoff | ${fixed(summary.derived.mean_handoff_microseconds, 3)} us |\n` +
    `| Downstream socket calls / response | ${fixed(summary.derived.socket_calls_per_response)} |\n` +
    `| Downstream socket bytes / call | ${fixed(summary.derived.socket_bytes_per_call, 2)} |\n` +
    `| Partial-write fraction | ${fixed(summary.derived.socket_partial_write_fraction)} |\n` +
    `| Cycles / response | ${fixed(summary.derived.cycles_per_response, 2)} |\n` +
    `| Instructions / response | ${fixed(summary.derived.instructions_per_response, 2)} |\n` +
    `| IPC | ${fixed(summary.derived.ipc)} |\n`;
}

function readBoundFile(root, relative, maximum = 16 * 1024 * 1024) {
  requireValue(typeof relative === 'string' &&
    /^(?:[a-zA-Z0-9._-]+\/)*[a-zA-Z0-9._-]+$/u.test(relative) &&
    !relative.split('/').includes('..'), `unsafe evidence path: ${relative}`);
  const target = path.join(root, ...relative.split('/'));
  const stat = fs.lstatSync(target);
  requireValue(stat.isFile() && !stat.isSymbolicLink() &&
    stat.size <= maximum, `evidence file is unsafe or oversized: ${relative}`);
  const resolvedRoot = fs.realpathSync(root);
  const resolvedTarget = fs.realpathSync(target);
  requireValue(resolvedTarget.startsWith(`${resolvedRoot}${path.sep}`),
    `evidence file escapes root: ${relative}`);
  return fs.readFileSync(target);
}

function textFile(root, relative, maximum) {
  return readBoundFile(root, relative, maximum).toString('utf8');
}

function jsonFile(root, relative) {
  return JSON.parse(textFile(root, relative));
}

function singleLine(root, relative, pattern, label) {
  const value = textFile(root, relative, 1024).trim();
  requireValue(pattern.test(value), `${label} is invalid`);
  return value;
}

export function assembleNativeResponsePathRoot(root, options) {
  exactKeys(options, ['run_id', 'point_id', 'tls', 'payload_bytes'],
    'native assembly options');
  const resolvedRoot = path.resolve(root);
  const rootStat = fs.lstatSync(resolvedRoot);
  requireValue(rootStat.isDirectory() && !rootStat.isSymbolicLink(),
    'native evidence root must be a real directory');
  for (const status of ['source-status.txt', 'socket/source-status.txt',
    'socket/source-status-after.txt']) {
    requireValue(textFile(resolvedRoot, status, 1024).length === 0,
      `${status} records dirty source`);
  }
  const sourceCommit = singleLine(resolvedRoot, 'source-commit.txt', COMMIT,
    'source commit');
  requireValue(singleLine(resolvedRoot, 'socket/source-commit.txt', COMMIT,
    'socket source commit') === sourceCommit,
  'socket collector source commit differs from native assembly');
  const configurationBefore = singleLine(resolvedRoot,
    'configuration-sha256-before.txt', SHA256, 'configuration digest');
  requireValue(singleLine(resolvedRoot, 'configuration-sha256-after.txt', SHA256,
    'final configuration digest') === configurationBefore,
  'configuration changed during native capture');
  const runtimeManifestSha256 = singleLine(resolvedRoot,
    'runtime-manifest-sha256.txt', SHA256, 'runtime manifest digest');
  const runtimeBefore = jsonFile(resolvedRoot, 'runtime-before.json');
  const runtimeAfter = jsonFile(resolvedRoot, 'runtime-after.json');
  requireValue(stable(runtimeBefore) ===
    stable(jsonFile(resolvedRoot, 'socket/process-before.json')) &&
    stable(runtimeAfter) === stable(jsonFile(resolvedRoot,
      'socket/process-after.json')),
  'outer and socket collector runtime identities differ');
  const threadIdsBefore = singleLine(resolvedRoot, 'thread-ids-before.txt',
    /^[0-9]+(?:,[0-9]+)*$/u, 'gateway thread set');
  requireValue(singleLine(resolvedRoot, 'thread-ids-after.txt',
    /^[0-9]+(?:,[0-9]+)*$/u, 'final gateway thread set') === threadIdsBefore,
  'gateway thread set changed during native capture');
  const threadIds = threadIdsBefore.split(',').map(Number);
  requireValue(new Set(threadIds).size === threadIds.length &&
    threadIds.every((tid) => Number.isSafeInteger(tid) && tid > 1) &&
    threadIds.includes(runtimeBefore.pid),
  'gateway thread set is invalid or excludes its process leader');
  const socketOutput = jsonFile(resolvedRoot, 'socket/socket-output.json');
  const duration = positiveInteger(Number(singleLine(resolvedRoot,
    'socket/duration-nanoseconds.txt', /^[0-9]+$/u,
    'collector duration')), 'collector duration');
  requireValue(socketOutput.duration_nanoseconds === duration,
    'socket summary duration differs from raw interval');

  const capture = buildNativeResponsePathCapture({
    run_id: options.run_id,
    point_id: options.point_id,
    source_commit: sourceCommit,
    configuration_sha256: configurationBefore,
    runtime_manifest: textFile(resolvedRoot, 'runtime-manifest.json'),
    runtime_manifest_sha256: runtimeManifestSha256,
    tls: options.tls,
    payload_bytes: options.payload_bytes,
    interval_id: runtimeBefore.interval_id,
    duration_nanoseconds: duration,
    runtime_before: runtimeBefore,
    runtime_after: runtimeAfter,
    application_before_prometheus: textFile(resolvedRoot,
      'application-before.prom'),
    application_after_prometheus: textFile(resolvedRoot,
      'application-after.prom'),
    workload_oha: textFile(resolvedRoot, 'socket/client.stdout'),
    socket_output: socketOutput,
    performance_csv: textFile(resolvedRoot, 'perf.csv'),
  });
  const summary = analyzeResponsePathAttribution(capture);
  fs.writeFileSync(path.join(resolvedRoot, 'capture.json'),
    `${JSON.stringify(capture, null, 2)}\n`, {flag: 'wx'});
  fs.writeFileSync(path.join(resolvedRoot, 'summary.json'),
    `${JSON.stringify(summary, null, 2)}\n`, {flag: 'wx'});
  fs.writeFileSync(path.join(resolvedRoot, 'report.md'),
    renderResponsePathAttribution(summary), {flag: 'wx'});
  return summary;
}

function parseOptions(args, allowed) {
  requireValue(args.length % 2 === 0, 'options require name/value pairs');
  const values = new Map();
  for (let index = 0; index < args.length; index += 2) {
    requireValue(allowed.includes(args[index]) && args[index + 1] &&
      !values.has(args[index]), `invalid or repeated option: ${args[index]}`);
    values.set(args[index], args[index + 1]);
  }
  requireValue(values.size === allowed.length &&
    allowed.every((name) => values.has(name)), 'required option is missing');
  return values;
}

function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'analyze') {
    const [input, output, report] = args;
    requireValue(Boolean(input && output && report) && args.length === 3,
      'usage: response-path-attribution.mjs analyze CAPTURE SUMMARY REPORT');
    const summary = analyzeResponsePathAttribution(
      JSON.parse(fs.readFileSync(input, 'utf8')));
    fs.writeFileSync(output, `${JSON.stringify(summary, null, 2)}\n`);
    fs.writeFileSync(report, renderResponsePathAttribution(summary));
    return;
  }
  if (command === 'assemble-native') {
    const options = parseOptions(args, ['--root', '--run-id', '--point-id',
      '--tls', '--payload-bytes']);
    requireValue(['true', 'false'].includes(options.get('--tls')),
      'TLS option must be true or false');
    const payloadBytes = Number(options.get('--payload-bytes'));
    positiveInteger(payloadBytes, 'payload bytes');
    assembleNativeResponsePathRoot(options.get('--root'), {
      run_id: options.get('--run-id'),
      point_id: options.get('--point-id'),
      tls: options.get('--tls') === 'true',
      payload_bytes: payloadBytes,
    });
    return;
  }
  throw new Error('usage: response-path-attribution.mjs analyze CAPTURE SUMMARY REPORT | assemble-native --root DIR --run-id ID --point-id ID --tls true|false --payload-bytes N');
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
