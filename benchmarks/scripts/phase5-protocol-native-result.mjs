#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';

import {NATIVE_RESULT_CONTRACT,
  validateProtocolNativePlan} from './phase5-protocol-native-plan.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/u;
const INVALID_REASONS = Object.freeze([
  'interrupted',
  'collector-failure',
  'load-generator-saturated',
  'upstream-saturated',
  'environment-drift',
  'source-drift',
  'artifact-drift',
  'protocol-observation-incomplete',
]);
const COMPLETE_FILES = Object.freeze([
  'capture_archive', 'derivation_manifest', 'environment',
]);
const INVALID_FILES = Object.freeze([
  'partial_archive', 'attempt_log', 'environment',
]);

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  requireValue(JSON.stringify(Object.keys(value).sort()) ===
    JSON.stringify([...expected].sort()),
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

function finite(value, label, minimum = 0, maximum = Number.POSITIVE_INFINITY) {
  requireValue(Number.isFinite(value) && value >= minimum && value <= maximum,
    `${label} must be between ${minimum} and ${maximum}`);
  return value;
}

function integer(value, label, minimum = 0) {
  requireValue(Number.isSafeInteger(value) && value >= minimum,
    `${label} must be an integer >= ${minimum}`);
  return value;
}

function signedInteger(value, label) {
  requireValue(Number.isSafeInteger(value), `${label} must be an integer`);
  return value;
}

function expectedAlpn(protocol) {
  return protocol === 'https-http1' ? 'http/1.1' : 'h2';
}

function metricSetName(variant) {
  if (variant.measurement_class === 'throughput-cost') return 'throughput_cost';
  if (variant.measurement_class === 'stream-cost') return 'stream_cost';
  return variant.profile === 'P5-S01' ? 'lifecycle_sse' : 'lifecycle_h2_grpc';
}

function validateFileReference(value, label) {
  exactKeys(value, ['path', 'sha256', 'bytes'], label);
  requireValue(typeof value.path === 'string' && SAFE_PATH.test(value.path) &&
    !value.path.endsWith('.result.json') && value.path !== 'checksums.sha256',
  `${label} path is unsafe`);
  requireValue(typeof value.sha256 === 'string' && SHA256.test(value.sha256),
    `${label} digest is invalid`);
  integer(value.bytes, `${label}.bytes`);
}

function validateFiles(files, status, label) {
  const expected = status === 'complete' ? COMPLETE_FILES : INVALID_FILES;
  exactKeys(files, expected, `${label}.files`);
  const paths = [];
  for (const name of expected) {
    validateFileReference(files[name], `${label}.files.${name}`);
    paths.push(files[name].path);
  }
  requireValue(new Set(paths).size === paths.length,
    `${label} evidence file paths must be distinct`);
}

function validateReactorTids(value, count, label) {
  requireValue(Array.isArray(value) && value.length === count &&
    new Set(value).size === count,
  `${label} must contain ${count} distinct reactor thread IDs`);
  for (const tid of value) integer(tid, label, 1);
}

function validateExecution(value, plan, variant, label) {
  exactKeys(value, ['roles', 'load_generator_cpu_set',
    'load_generator_lanes', 'gateway_cpu_set', 'gateway_housekeeping_cpus',
    'irq_policy', 'profiler_scope', 'reactor_tids_before',
    'reactor_tids_after', 'profiled_reactor_tids'], label);
  requireValue(isDeepStrictEqual(value.roles, plan.input.topology.roles),
    `${label}.roles differ from the plan`);
  requireValue(isDeepStrictEqual(value.load_generator_cpu_set,
    plan.input.topology.load_generator_cpu_set),
  `${label}.load_generator_cpu_set differs from the plan`);
  requireValue(value.load_generator_lanes ===
    plan.input.topology.load_generator_lanes,
  `${label}.load_generator_lanes differs from the plan`);
  requireValue(isDeepStrictEqual(value.gateway_cpu_set,
    plan.input.topology.gateway_cpu_sets[String(variant.core_count)]),
  `${label}.gateway_cpu_set differs from the plan`);
  requireValue(isDeepStrictEqual(value.gateway_housekeeping_cpus,
    plan.input.topology.gateway_housekeeping_cpus),
  `${label}.gateway_housekeeping_cpus differ from the plan`);
  requireValue(isDeepStrictEqual(value.irq_policy,
    plan.input.topology.irq_policy), `${label}.irq_policy differs from the plan`);
  requireValue(value.profiler_scope === NATIVE_RESULT_CONTRACT.profiler_scope,
    `${label}.profiler_scope does not cover all reactor threads`);
  for (const name of ['reactor_tids_before', 'reactor_tids_after',
    'profiled_reactor_tids']) {
    validateReactorTids(value[name], variant.core_count, `${label}.${name}`);
  }
}

function validateProtocol(value, label) {
  exactKeys(value, ['downstream_tls_version', 'downstream_tls_cipher',
    'downstream_peer_certificate_verified', 'downstream_hostname_verified',
    'downstream_alpn', 'upstream_protocol', 'semantic_outcome',
    'payload_or_event_order_exact'], label);
  for (const name of ['downstream_tls_version', 'downstream_tls_cipher',
    'downstream_alpn', 'upstream_protocol', 'semantic_outcome']) {
    requireValue(typeof value[name] === 'string' && value[name].length > 0,
      `${label}.${name} is invalid`);
  }
  for (const name of ['downstream_peer_certificate_verified',
    'downstream_hostname_verified', 'payload_or_event_order_exact']) {
    requireValue(typeof value[name] === 'boolean', `${label}.${name} is invalid`);
  }
}

function validateRuntime(value, variant, label) {
  exactKeys(value, ['gateway_process_identity_before',
    'gateway_process_identity_after', 'gateway_restart_count',
    'same_process_recovery', 'support_role_capacity_percent',
    'final_active_streams', 'maximum_cleanup_ms',
    'retained_rss_growth_bytes', 'retained_fd_growth',
    'unexpected_error_count', 'transport_failure_count',
    'pre_overload_error_rate'], label);
  for (const name of ['gateway_process_identity_before',
    'gateway_process_identity_after']) {
    requireValue(typeof value[name] === 'string' && value[name].length > 0,
      `${label}.${name} is invalid`);
  }
  integer(value.gateway_restart_count, `${label}.gateway_restart_count`);
  requireValue(typeof value.same_process_recovery === 'boolean',
    `${label}.same_process_recovery is invalid`);
  exactKeys(value.support_role_capacity_percent,
    ['load_generator', 'controlled_upstream'],
    `${label}.support_role_capacity_percent`);
  for (const [name, percent] of Object.entries(
    value.support_role_capacity_percent)) {
    finite(percent, `${label}.support_role_capacity_percent.${name}`, 0, 100);
  }
  integer(value.final_active_streams, `${label}.final_active_streams`);
  if (variant.measurement_class === 'lifecycle') {
    finite(value.maximum_cleanup_ms, `${label}.maximum_cleanup_ms`);
  } else {
    requireValue(value.maximum_cleanup_ms === null,
      `${label}.maximum_cleanup_ms must be null outside lifecycle evidence`);
  }
  signedInteger(value.retained_rss_growth_bytes,
    `${label}.retained_rss_growth_bytes`);
  signedInteger(value.retained_fd_growth, `${label}.retained_fd_growth`);
  integer(value.unexpected_error_count, `${label}.unexpected_error_count`);
  integer(value.transport_failure_count, `${label}.transport_failure_count`);
  finite(value.pre_overload_error_rate, `${label}.pre_overload_error_rate`, 0, 1);
}

function validateQueueWaits(value, label) {
  exactKeys(value, ['count', 'maximum_ms'], label);
  integer(value.count, `${label}.count`);
  finite(value.maximum_ms, `${label}.maximum_ms`);
}

function validatePerShardWork(value, variant, label) {
  requireValue(Array.isArray(value) && value.length === variant.core_count,
    `${label} must cover every gateway shard`);
  const expected = Array.from({length: variant.core_count}, (_, index) => index);
  for (const [index, shard] of value.entries()) {
    exactKeys(shard, ['shard', 'successful_operations', 'cpu_percent'],
      `${label}[${index}]`);
    integer(shard.shard, `${label}[${index}].shard`);
    integer(shard.successful_operations,
      `${label}[${index}].successful_operations`);
    finite(shard.cpu_percent, `${label}[${index}].cpu_percent`, 0, 100);
  }
  requireValue(isDeepStrictEqual(value.map((item) => item.shard), expected),
    `${label} shard indexes are incomplete or out of order`);
}

function validateMetrics(value, variant, label) {
  const setName = metricSetName(variant);
  const expected = NATIVE_RESULT_CONTRACT.metric_sets[setName];
  exactKeys(value, expected, label);
  for (const metric of expected) {
    if (metric === 'queue_waits') {
      validateQueueWaits(value[metric], `${label}.${metric}`);
    } else if (metric === 'per_shard_work') {
      validatePerShardWork(value[metric], variant, `${label}.${metric}`);
    } else {
      finite(value[metric], `${label}.${metric}`);
    }
  }
  for (const metric of ['application_cpu_percent', 'host_cpu_percent',
    'irq_cpu_percent']) {
    if (Object.hasOwn(value, metric)) finite(value[metric],
      `${label}.${metric}`, 0, 100);
  }
  for (const metric of ['rss_bytes', 'file_descriptors', 'active_streams']) {
    if (Object.hasOwn(value, metric)) integer(value[metric],
      `${label}.${metric}`);
  }
  if (Object.hasOwn(value, 'p50_ms')) {
    requireValue(value.p50_ms <= value.p95_ms && value.p95_ms <= value.p99_ms &&
      value.p99_ms <= value.p999_reference_ms,
    `${label} latency percentiles are not monotonic`);
  }
  if (variant.measurement_class === 'lifecycle') {
    requireValue(value.cancellation_cleanup_ms === undefined ||
      value.cancellation_cleanup_ms >= 0,
    `${label}.cancellation_cleanup_ms is invalid`);
  }
}

function locate(plan, pointId, variantId, repetition) {
  const point = plan.points.find((item) => item.point_id === pointId);
  requireValue(point, `result point ${pointId} is outside the plan`);
  requireValue(point.variant_id === variantId && point.repetition === repetition,
    `result point ${pointId} identity differs from the plan`);
  const variant = plan.input.variants.find((item) => item.id === variantId);
  requireValue(variant, `result variant ${variantId} is outside the plan`);
  return {point, variant};
}

function buildAgainstValidatedPlan(input, plan) {
  exactKeys(input, ['schema_version', 'plan_id', 'point_id', 'variant_id',
    'repetition', 'attempt', 'evidence_status', 'invalid_reason', 'source',
    'catalog_sha256', 'snapshot_sha256', 'execution', 'protocol', 'runtime',
    'metrics', 'files'], 'native result input');
  requireValue(input.schema_version === 1 && input.plan_id === plan.plan_id,
    'native result plan identity is invalid');
  integer(input.repetition, 'native result repetition', 1);
  integer(input.attempt, 'native result attempt', 1);
  const {variant} = locate(plan, input.point_id, input.variant_id,
    input.repetition);
  requireValue(isDeepStrictEqual(input.source, plan.input.source),
    `${input.point_id} source or artifact bindings differ from the plan`);
  requireValue(input.catalog_sha256 === plan.input.catalog_sha256,
    `${input.point_id} catalog binding differs from the plan`);
  requireValue(input.snapshot_sha256 === variant.snapshot_sha256,
    `${input.point_id} snapshot binding differs from the plan`);
  requireValue(['complete', 'invalid'].includes(input.evidence_status),
    `${input.point_id} evidence status is invalid`);
  validateFiles(input.files, input.evidence_status, input.point_id);

  if (input.evidence_status === 'invalid') {
    requireValue(INVALID_REASONS.includes(input.invalid_reason),
      `${input.point_id} invalid attempt reason is unsupported`);
    for (const name of ['execution', 'protocol', 'runtime', 'metrics']) {
      requireValue(input[name] === null,
        `${input.point_id} invalid attempt ${name} must be null`);
    }
  } else {
    requireValue(input.invalid_reason === null,
      `${input.point_id} complete evidence cannot have an invalid reason`);
    validateExecution(input.execution, plan, variant,
      `${input.point_id}.execution`);
    validateProtocol(input.protocol, `${input.point_id}.protocol`);
    validateRuntime(input.runtime, variant, `${input.point_id}.runtime`);
    validateMetrics(input.metrics, variant, `${input.point_id}.metrics`);
    if (variant.measurement_class === 'lifecycle') {
      requireValue(input.metrics.cancellation_cleanup_ms ===
        input.runtime.maximum_cleanup_ms,
      `${input.point_id} cleanup metric differs from runtime evidence`);
    }
  }
  const contract = {...input};
  return {...contract, result_id: canonicalHash(contract)};
}

export function buildProtocolNativeResults(inputs, plan, catalogBytes) {
  validateProtocolNativePlan(plan, catalogBytes);
  requireValue(Array.isArray(inputs), 'native result inputs must be an array');
  return inputs.map((input) => buildAgainstValidatedPlan(input, plan));
}

export function buildProtocolNativeResult(input, plan, catalogBytes) {
  return buildProtocolNativeResults([input], plan, catalogBytes)[0];
}

function validateAgainstValidatedPlan(result, plan) {
  requireValue(result && typeof result === 'object' && !Array.isArray(result) &&
    typeof result.result_id === 'string' && SHA256.test(result.result_id),
  'native result header is invalid');
  const {result_id: ignored, ...input} = result;
  const rebuilt = buildAgainstValidatedPlan(input, plan);
  requireValue(isDeepStrictEqual(rebuilt, result),
    `${result.point_id ?? 'unknown'} result differs from its deterministic contract`);
  return result;
}

export function validateProtocolNativeResult(result, plan, catalogBytes) {
  validateProtocolNativePlan(plan, catalogBytes);
  return validateAgainstValidatedPlan(result, plan);
}

function pointGates(result, variant, plan) {
  const protocol = result.protocol;
  const runtime = result.runtime;
  const metrics = result.metrics;
  const acceptance = plan.input.acceptance;
  const reactorStable = isDeepStrictEqual(result.execution.reactor_tids_before,
    result.execution.reactor_tids_after) &&
    isDeepStrictEqual(result.execution.reactor_tids_before,
      result.execution.profiled_reactor_tids);
  const supportMaximum = Math.max(...Object.values(
    runtime.support_role_capacity_percent));
  const gates = {
    tls_version_pass: protocol.downstream_tls_version ===
      NATIVE_RESULT_CONTRACT.required_tls_version,
    tls_cipher_pass: /^TLS_AES_[A-Z0-9_]+$/u.test(
      protocol.downstream_tls_cipher) &&
      !protocol.downstream_tls_cipher.includes('CHACHA'),
    tls_identity_pass: protocol.downstream_peer_certificate_verified === true &&
      protocol.downstream_hostname_verified === true,
    alpn_pass: protocol.downstream_alpn ===
      expectedAlpn(variant.downstream_protocol),
    upstream_protocol_pass: protocol.upstream_protocol ===
      variant.upstream_protocol,
    semantic_outcome_pass: protocol.semantic_outcome ===
      variant.expected_outcome,
    payload_order_pass: protocol.payload_or_event_order_exact === true,
    all_reactor_profile_pass: reactorStable,
    same_process_recovery_pass: runtime.gateway_process_identity_before ===
      runtime.gateway_process_identity_after &&
      runtime.gateway_restart_count === 0 &&
      runtime.same_process_recovery ===
        acceptance.same_process_recovery_required,
    support_capacity_pass: supportMaximum <=
      acceptance.maximum_support_capacity_percent,
    errors_pass: runtime.unexpected_error_count === 0 &&
      runtime.transport_failure_count === 0 &&
      runtime.pre_overload_error_rate <=
        acceptance.maximum_pre_overload_error_rate,
    rss_containment_pass: runtime.retained_rss_growth_bytes <=
      acceptance.maximum_retained_rss_growth_bytes,
    descriptor_containment_pass: runtime.retained_fd_growth <=
      acceptance.maximum_retained_fd_growth,
    active_streams_drained_pass: runtime.final_active_streams ===
      acceptance.final_active_streams,
  };
  if (variant.measurement_class === 'lifecycle') {
    gates.cleanup_pass = runtime.maximum_cleanup_ms <=
      acceptance.maximum_cleanup_ms;
  } else {
    gates.latency_pass = metrics.p95_ms <= variant.workload.p95_ceiling_ms &&
      metrics.p99_ms <= variant.workload.p99_ceiling_ms;
    gates.cost_metrics_pass = metrics.cycles_per_success > 0 &&
      metrics.instructions_per_success > 0 && metrics.ipc > 0 &&
      metrics.syscalls_per_success > 0 && metrics.writes_per_success > 0 &&
      metrics.bytes_per_write > 0;
    if (variant.measurement_class === 'throughput-cost') {
      gates.delivery_pass = metrics.successful_rps > 0;
      gates.offered_rate_attainment_pass = metrics.successful_rps >=
        variant.workload.target_rps *
          (1 - acceptance.maximum_pre_overload_error_rate);
    } else {
      gates.delivery_pass = metrics.delivery_bytes_per_second > 0 &&
        metrics.active_streams >= variant.workload.target_active_streams;
      gates.ttfb_pass = metrics.ttfb_ms <= variant.workload.ttfb_ceiling_ms;
      gates.event_gap_pass = metrics.maximum_event_gap_ms <=
        variant.workload.event_gap_ceiling_ms;
    }
  }
  return {gates, pass: Object.values(gates).every(Boolean), supportMaximum};
}

export function evaluateProtocolNativePoint(result, plan, catalogBytes) {
  validateProtocolNativePlan(plan, catalogBytes);
  const validated = validateAgainstValidatedPlan(result, plan);
  const point = plan.points.find((item) => item.point_id === validated.point_id);
  requireValue(point !== undefined && point.variant_id === validated.variant_id,
    `${validated.point_id} is not a point in the native plan`);
  const variant = plan.input.variants.find((item) =>
    item.id === validated.variant_id);
  requireValue(variant !== undefined,
    `${validated.point_id} references an unknown native variant`);
  return pointGates(validated, variant, plan);
}

function median(values) {
  if (values.length === 0) return null;
  const ordered = [...values].sort((left, right) => left - right);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2 === 1 ? ordered[middle] :
    (ordered[middle - 1] + ordered[middle]) / 2;
}

function maximumDeviationPercent(values) {
  const center = median(values);
  if (center === null || center === 0) return null;
  return Math.max(...values.map((value) =>
    Math.abs(value - center) / center * 100));
}

export function summarizeProtocolNativeResults(plan, catalogBytes, results) {
  validateProtocolNativePlan(plan, catalogBytes);
  requireValue(Array.isArray(results), 'native results must be an array');
  const attempts = new Set();
  const complete = new Map();
  let invalidAttempts = 0;
  for (const result of results) {
    validateAgainstValidatedPlan(result, plan);
    const attemptKey = `${result.point_id}:${result.attempt}`;
    requireValue(!attempts.has(attemptKey),
      `duplicate native result attempt ${attemptKey}`);
    attempts.add(attemptKey);
    if (result.evidence_status === 'invalid') {
      invalidAttempts += 1;
      continue;
    }
    requireValue(!complete.has(result.point_id),
      `duplicate complete native result ${result.point_id}`);
    complete.set(result.point_id, result);
  }

  const rows = [];
  const missing = [];
  for (const point of plan.points) {
    const result = complete.get(point.point_id);
    if (!result) {
      missing.push(point.point_id);
      continue;
    }
    const variant = plan.input.variants.find((item) =>
      item.id === point.variant_id);
    const evaluation = pointGates(result, variant, plan);
    rows.push({
      point_id: point.point_id,
      variant_id: variant.id,
      profile: variant.profile,
      measurement_class: variant.measurement_class,
      repetition: point.repetition,
      pass: evaluation.pass,
      gates: evaluation.gates,
      maximum_support_role_capacity_percent: evaluation.supportMaximum,
      metrics: result.metrics,
    });
  }

  const repetitionGroups = [];
  for (const variant of plan.input.variants.filter((item) =>
    item.measurement_class !== 'lifecycle')) {
    const matching = rows.filter((row) => row.variant_id === variant.id);
    const metric = variant.measurement_class === 'throughput-cost' ?
      'successful_rps' : 'delivery_bytes_per_second';
    const values = matching.map((row) => row.metrics[metric]);
    const deviation = values.length === plan.input.schedule.throughput_repetitions ?
      maximumDeviationPercent(values) : null;
    repetitionGroups.push({
      variant_id: variant.id,
      metric,
      repetitions: values.length,
      median: median(values),
      maximum_deviation_percent: deviation,
      pass: deviation !== null && deviation <=
        plan.input.acceptance.maximum_repetition_variation_percent,
    });
  }

  const profileSummaries = {};
  for (const profile of plan.input.profile_scope) {
    const planned = plan.points.filter((point) => {
      const variant = plan.input.variants.find((item) =>
        item.id === point.variant_id);
      return variant.profile === profile;
    });
    const observed = rows.filter((row) => row.profile === profile);
    profileSummaries[profile] = {
      planned_points: planned.length,
      complete_points: observed.length,
      passing_points: observed.filter((row) => row.pass).length,
      pass: observed.length === planned.length && observed.every((row) => row.pass),
    };
  }

  const evidenceComplete = missing.length === 0;
  const pointsPass = evidenceComplete && rows.every((row) => row.pass);
  const repeatabilityPass = repetitionGroups.every((group) => group.pass);
  const decision = !evidenceComplete ? 'incomplete' :
    pointsPass && repeatabilityPass ? 'pass' : 'fail';
  return {
    schema_version: 1,
    checkpoint: 'PERF-05',
    plan_id: plan.plan_id,
    evidence_class: plan.input.evidence_class,
    publication_authorized: false,
    result_documents: results.length,
    complete_points: rows.length,
    invalid_attempts: invalidAttempts,
    missing_points: missing,
    profiles: profileSummaries,
    repetition_groups: repetitionGroups,
    rows,
    gates: {
      evidence_complete: evidenceComplete,
      all_points_pass: pointsPass,
      repeatability_pass: repeatabilityPass,
      decision,
    },
  };
}

function safeEvidencePath(root, relative, label) {
  requireValue(typeof relative === 'string' && SAFE_PATH.test(relative),
    `${label} path is unsafe`);
  const absoluteRoot = path.resolve(root);
  const absolute = path.resolve(absoluteRoot, relative);
  requireValue(absolute.startsWith(`${absoluteRoot}${path.sep}`),
    `${label} escapes the evidence directory`);
  const stat = fs.lstatSync(absolute);
  requireValue(stat.isFile() && !stat.isSymbolicLink(),
    `${label} must be a regular non-symlink file`);
  return {absolute, stat};
}

function sha256File(filename) {
  const hash = crypto.createHash('sha256');
  const descriptor = fs.openSync(filename, 'r');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    let bytes = 0;
    do {
      bytes = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytes > 0) hash.update(buffer.subarray(0, bytes));
    } while (bytes > 0);
  } finally {
    fs.closeSync(descriptor);
  }
  return hash.digest('hex');
}

function walkEvidence(root, relative = '') {
  const result = [];
  const directory = path.join(root, relative);
  for (const name of fs.readdirSync(directory).sort()) {
    const child = path.posix.join(relative.replaceAll(path.sep, '/'), name);
    const absolute = path.join(root, child);
    const stat = fs.lstatSync(absolute);
    requireValue(!stat.isSymbolicLink(), `evidence symlink forbidden: ${child}`);
    if (stat.isDirectory()) result.push(...walkEvidence(root, child));
    else if (stat.isFile() && child !== 'checksums.sha256') result.push(child);
    else if (!stat.isFile()) throw new Error(`unsupported evidence entry: ${child}`);
  }
  return result.sort();
}

function verifyManifest(root) {
  const manifestPath = path.join(root, 'checksums.sha256');
  const stat = fs.lstatSync(manifestPath);
  requireValue(stat.isFile() && !stat.isSymbolicLink(),
    'checksums.sha256 must be a regular non-symlink file');
  const lines = fs.readFileSync(manifestPath, 'utf8').trimEnd().split('\n');
  requireValue(lines.length > 0 && lines.every((line) => line.length > 0),
    'evidence checksum manifest is empty or malformed');
  const records = [];
  for (const [index, line] of lines.entries()) {
    const match = line.match(/^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$/u);
    requireValue(match && SAFE_PATH.test(match[2]),
      `checksum manifest line ${index + 1} is invalid`);
    records.push({sha256: match[1], path: match[2]});
  }
  const manifestFiles = records.map((record) => record.path);
  requireValue(new Set(manifestFiles).size === manifestFiles.length &&
    isDeepStrictEqual(manifestFiles, [...manifestFiles].sort()),
  'checksum manifest paths must be unique and sorted');
  const actualFiles = walkEvidence(root);
  requireValue(isDeepStrictEqual(manifestFiles, actualFiles),
    'checksum manifest does not exactly cover the evidence directory');
  for (const record of records) {
    const {absolute} = safeEvidencePath(root, record.path,
      `checksum ${record.path}`);
    requireValue(sha256File(absolute) === record.sha256,
      `checksum mismatch for ${record.path}`);
  }
  return new Set(manifestFiles);
}

function verifyReferencedFiles(result, root, manifestFiles) {
  for (const [name, reference] of Object.entries(result.files)) {
    requireValue(manifestFiles.has(reference.path),
      `${result.point_id}.${name} is absent from the checksum manifest`);
    const {absolute, stat} = safeEvidencePath(root, reference.path,
      `${result.point_id}.${name}`);
    requireValue(stat.size === reference.bytes,
      `${result.point_id}.${name} byte length differs`);
    requireValue(sha256File(absolute) === reference.sha256,
      `${result.point_id}.${name} checksum differs`);
  }
}

export function analyzeProtocolNativeEvidence(plan, catalogBytes, evidenceRoot) {
  validateProtocolNativePlan(plan, catalogBytes);
  const root = path.resolve(evidenceRoot);
  const stat = fs.lstatSync(root);
  requireValue(stat.isDirectory() && !stat.isSymbolicLink(),
    'native evidence root must be a non-symlink directory');
  const manifestFiles = verifyManifest(root);
  const resultFiles = [...manifestFiles].filter((name) =>
    name.endsWith('.result.json')).sort();
  const results = [];
  const referencedFiles = new Set();
  const ownedFiles = new Set();
  for (const filename of resultFiles) {
    const {absolute} = safeEvidencePath(root, filename,
      `result ${filename}`);
    const result = JSON.parse(fs.readFileSync(absolute, 'utf8'));
    validateAgainstValidatedPlan(result, plan);
    verifyReferencedFiles(result, root, manifestFiles);
    for (const [name, reference] of Object.entries(result.files)) {
      referencedFiles.add(reference.path);
      if (name !== 'environment') {
        requireValue(!ownedFiles.has(reference.path),
          `point-owned evidence file reused: ${reference.path}`);
        ownedFiles.add(reference.path);
      }
    }
    results.push(result);
  }
  const expectedFiles = [...new Set([...resultFiles, ...referencedFiles])].sort();
  requireValue(isDeepStrictEqual(expectedFiles, [...manifestFiles].sort()),
    'checksum-bound evidence contains unreferenced files');
  return summarizeProtocolNativeResults(plan, catalogBytes, results);
}

function readRegular(filename, label) {
  const absolute = path.resolve(filename);
  const stat = fs.lstatSync(absolute);
  requireValue(stat.isFile() && !stat.isSymbolicLink(),
    `${label} must be a regular non-symlink file`);
  return fs.readFileSync(absolute, 'utf8');
}

function option(name, argv) {
  const index = argv.indexOf(name);
  requireValue(index >= 0 && index + 1 < argv.length, `${name} is required`);
  return argv[index + 1];
}

function writeNew(filename, value) {
  const absolute = path.resolve(filename);
  fs.mkdirSync(path.dirname(absolute), {recursive: true});
  fs.writeFileSync(absolute, `${JSON.stringify(value, null, 2)}\n`,
    {encoding: 'utf8', flag: 'wx', mode: 0o600});
}

function main() {
  const [, , command, ...argv] = process.argv;
  requireValue(command === 'analyze',
    'usage: phase5-protocol-native-result.mjs analyze --catalog FILE ' +
    '--plan FILE --results DIR --output FILE');
  const catalogBytes = readRegular(option('--catalog', argv), 'catalog');
  const plan = JSON.parse(readRegular(option('--plan', argv), 'plan'));
  const results = path.resolve(option('--results', argv));
  const output = path.resolve(option('--output', argv));
  requireValue(!output.startsWith(`${results}${path.sep}`),
    'summary output must remain outside the checksum-bound evidence directory');
  writeNew(output, analyzeProtocolNativeEvidence(plan, catalogBytes, results));
}

if (process.argv[1] && import.meta.url ===
    pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-protocol-native-result: ${error.message}\n`);
    process.exitCode = 1;
  }
}
