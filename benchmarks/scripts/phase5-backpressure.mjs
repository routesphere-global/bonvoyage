#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

export const PHASES = Object.freeze([
  'steady',
  'near_knee',
  'intentional_overload',
  'recovery',
]);

export const COUNTER_METRICS = Object.freeze([
  'requests_total',
  'responses_2xx_total',
  'responses_3xx_total',
  'responses_4xx_total',
  'responses_5xx_total',
  'downstream_connections_accepted_total',
  'downstream_connection_rejections_total',
  'overload_rejections_total',
  'route_overload_rejections_total',
  'route_rate_limit_rejections_total',
  'jwt_verification_overload_rejections_total',
  'cluster_overload_rejections_total',
  'endpoint_overload_rejections_total',
  'endpoint_circuit_probe_rejections_total',
  'upstream_failures_total',
  'request_timeouts_total',
  'upstream_http1_pool_waits_total',
  'upstream_http2_pool_waits_total',
  'response_path_flush_wait_operations_total',
  'response_path_flush_wait_nanoseconds_total',
  'reactor_tasks_processed',
  'scheduler_waittime_ms',
]);

export const GAUGE_METRICS = Object.freeze([
  'active_requests',
  'active_route_requests',
  'active_upstream_requests',
  'active_upstream_http1_requests',
  'active_upstream_http2_streams',
  'active_connections',
  'configured_upstream_http1_connections',
  'reactor_tasks_pending',
  'scheduler_queue_length',
  'reactor_utilization',
  'response_path_diagnostics_enabled',
]);

export const FINAL_ZERO_GAUGES = Object.freeze([
  'active_requests',
  'active_route_requests',
  'active_upstream_requests',
  'active_upstream_http1_requests',
  'active_upstream_http2_streams',
  'active_connections',
]);

export const RECOVERY_BASELINE_GAUGES = Object.freeze([
  'reactor_tasks_pending',
  'scheduler_queue_length',
]);

export const HOST_COUNTERS = Object.freeze([
  'softnet_dropped',
  'softnet_time_squeeze',
  'ena_allowance_exceeded',
  'ena_queue_stops',
]);

export const OPTIONAL_RESOURCE_METRICS = Object.freeze([
  'host_cpu_percent',
  'irq_cpu_percent',
]);

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function requireString(value, label) {
  requireValue(typeof value === 'string' && value.length > 0, `${label} is required`);
  return value;
}

function requireInteger(value, label, minimum = 0) {
  requireValue(Number.isSafeInteger(value) && value >= minimum,
    `${label} must be an integer >= ${minimum}`);
  return value;
}

function requireFinite(value, label, minimum = 0) {
  requireValue(Number.isFinite(value) && value >= minimum,
    `${label} must be a finite number >= ${minimum}`);
  return value;
}

function requireExactKeys(value, expected, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  requireValue(JSON.stringify(actual) === JSON.stringify(wanted),
    `${label} keys must be exactly: ${wanted.join(', ')}`);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
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
  return sha256(JSON.stringify(canonicalize(value)));
}

function validateLatencyCeiling(value, label) {
  requireExactKeys(value, ['p95', 'p99'], label);
  const p95 = requireFinite(value.p95, `${label}.p95`);
  const p99 = requireFinite(value.p99, `${label}.p99`);
  requireValue(p99 >= p95, `${label}.p99 must be >= p95`);
  return {p95, p99};
}

export function buildBackpressurePlan({
  profile = 'P5-Q01',
  coreCount,
  rates,
  durations,
  latencyCeilings,
  acceptance = {},
} = {}) {
  requireString(profile, 'profile');
  requireInteger(coreCount, 'coreCount', 1);
  requireExactKeys(rates, PHASES, 'rates');
  requireExactKeys(durations, PHASES, 'durations');
  requireExactKeys(latencyCeilings, PHASES, 'latencyCeilings');

  const normalizedRates = Object.fromEntries(PHASES.map((phase) =>
    [phase, requireInteger(rates[phase], `rates.${phase}`, 1)]));
  requireValue(normalizedRates.steady < normalizedRates.near_knee &&
    normalizedRates.near_knee < normalizedRates.intentional_overload,
  'rates must increase from steady through intentional overload');
  requireValue(normalizedRates.recovery === normalizedRates.steady,
    'recovery rate must equal the steady rate');

  const normalizedDurations = Object.fromEntries(PHASES.map((phase) =>
    [phase, requireInteger(durations[phase], `durations.${phase}`, 1)]));
  const normalizedLatency = Object.fromEntries(PHASES.map((phase) =>
    [phase, validateLatencyCeiling(latencyCeilings[phase],
      `latencyCeilings.${phase}`)]));

  const normalizedAcceptance = {
    minimum_attempted_rate_ratio: acceptance.minimum_attempted_rate_ratio ?? 0.99,
    maximum_attempted_rate_ratio: acceptance.maximum_attempted_rate_ratio ?? 1.01,
    maximum_pre_overload_error_rate: acceptance.maximum_pre_overload_error_rate ?? 0.001,
    maximum_support_capacity_percent: acceptance.maximum_support_capacity_percent ?? 80,
    maximum_request_imbalance_ratio: acceptance.maximum_request_imbalance_ratio ?? 0.20,
    minimum_recovery_rps_ratio: acceptance.minimum_recovery_rps_ratio ?? 0.95,
    maximum_recovery_rss_growth_bytes:
      acceptance.maximum_recovery_rss_growth_bytes ?? 4 * 1024 * 1024,
    maximum_recovery_fd_growth: acceptance.maximum_recovery_fd_growth ?? 4,
    required_overload_counter:
      acceptance.required_overload_counter ?? 'route_overload_rejections_total',
  };
  for (const name of [
    'minimum_attempted_rate_ratio',
    'maximum_attempted_rate_ratio',
    'maximum_pre_overload_error_rate',
    'maximum_support_capacity_percent',
    'maximum_request_imbalance_ratio',
    'minimum_recovery_rps_ratio',
    'maximum_recovery_rss_growth_bytes',
    'maximum_recovery_fd_growth',
  ]) requireFinite(normalizedAcceptance[name], `acceptance.${name}`);
  requireValue(normalizedAcceptance.maximum_attempted_rate_ratio >=
    normalizedAcceptance.minimum_attempted_rate_ratio,
  'maximum attempted-rate ratio must be >= minimum');
  requireValue(normalizedAcceptance.minimum_attempted_rate_ratio <= 1 &&
    normalizedAcceptance.maximum_attempted_rate_ratio >= 1,
  'attempted-rate ratio range must include 1');
  requireValue(normalizedAcceptance.maximum_pre_overload_error_rate <= 1 &&
    normalizedAcceptance.maximum_support_capacity_percent <= 100 &&
    normalizedAcceptance.minimum_recovery_rps_ratio <= 1,
  'acceptance percentages and ratios exceed their valid range');
  requireValue(COUNTER_METRICS.includes(normalizedAcceptance.required_overload_counter),
    'required overload counter is not in the frozen counter set');

  const points = PHASES.map((phase, index) => ({
    order: index + 1,
    phase,
    target_rps: normalizedRates[phase],
    duration_seconds: normalizedDurations[phase],
    intentional_overload: phase === 'intentional_overload',
    latency_ceiling_ms: normalizedLatency[phase],
  }));
  const contract = {
    schema_version: 1,
    profile,
    core_count: coreCount,
    points,
    acceptance: normalizedAcceptance,
    required_counter_metrics: COUNTER_METRICS,
    required_gauge_metrics: GAUGE_METRICS,
    required_final_zero_gauges: FINAL_ZERO_GAUGES,
    required_recovery_baseline_gauges: RECOVERY_BASELINE_GAUGES,
  };
  return {...contract, plan_id: canonicalHash(contract)};
}

function validatePlan(plan) {
  requireValue(plan?.schema_version === 1, 'unsupported backpressure plan schema');
  requireString(plan.plan_id, 'plan_id');
  requireString(plan.profile, 'profile');
  requireInteger(plan.core_count, 'core_count', 1);
  requireValue(Array.isArray(plan.points) && plan.points.length === PHASES.length,
    `plan must contain exactly ${PHASES.length} points`);
  for (const [index, phase] of PHASES.entries()) {
    const point = plan.points[index];
    requireValue(point?.order === index + 1 && point.phase === phase,
      `plan point ${index + 1} must be ${phase}`);
    requireInteger(point.target_rps, `${phase} target_rps`, 1);
    requireInteger(point.duration_seconds, `${phase} duration_seconds`, 1);
    requireValue(point.intentional_overload === (phase === 'intentional_overload'),
      `${phase} intentional-overload flag is invalid`);
    validateLatencyCeiling(point.latency_ceiling_ms, `${phase} latency ceiling`);
  }
  requireValue(plan.points[0].target_rps < plan.points[1].target_rps &&
    plan.points[1].target_rps < plan.points[2].target_rps &&
    plan.points[3].target_rps === plan.points[0].target_rps,
  'plan rates violate the steady/knee/overload/recovery sequence');
  requireValue(JSON.stringify(plan.required_counter_metrics) === JSON.stringify(COUNTER_METRICS) &&
    JSON.stringify(plan.required_gauge_metrics) === JSON.stringify(GAUGE_METRICS) &&
    JSON.stringify(plan.required_final_zero_gauges) === JSON.stringify(FINAL_ZERO_GAUGES) &&
    JSON.stringify(plan.required_recovery_baseline_gauges) ===
      JSON.stringify(RECOVERY_BASELINE_GAUGES),
  'plan metric contract drifted');
  const copy = structuredClone(plan);
  delete copy.plan_id;
  requireValue(canonicalHash(copy) === plan.plan_id, 'plan_id does not bind the plan');
}

function validateEnvironment(environment, plan) {
  requireValue(environment?.schema_version === 1, 'unsupported environment schema');
  for (const name of ['run_id', 'evidence_class', 'source_commit', 'gateway_binary_sha256',
    'snapshot_sha256', 'configuration_sha256', 'collector_sha256', 'boot_id']) {
    requireString(environment[name], `environment.${name}`);
  }
  requireValue(environment.source_dirty === false,
    'PERF-04 requires source_dirty=false');
  requireValue(environment.publication_authorized === false,
    'PERF-04 engineering analysis cannot authorize publication');
  requireValue(environment.response_path_diagnostics_enabled === true,
    'response-path diagnostics must be explicitly enabled');
  requireValue(Array.isArray(environment.expected_shards) &&
    environment.expected_shards.length === plan.core_count,
  'expected_shards must match core_count');
  const expectedShards = Array.from({length: plan.core_count}, (_, index) => index);
  requireValue(JSON.stringify(environment.expected_shards) === JSON.stringify(expectedShards),
    'expected_shards must be the contiguous reactor set starting at shard zero');
  requireValue(Array.isArray(environment.support_roles) &&
    environment.support_roles.length >= 2 &&
    new Set(environment.support_roles).size === environment.support_roles.length,
  'at least two distinct support roles are required');
  for (const role of environment.support_roles) requireString(role, 'support role');
  requireValue(Array.isArray(environment.required_host_counters) &&
    Array.isArray(environment.required_zero_host_counters),
  'host counter requirements must be arrays');
  requireValue(new Set(environment.required_host_counters).size ===
    environment.required_host_counters.length &&
    new Set(environment.required_zero_host_counters).size ===
      environment.required_zero_host_counters.length,
  'host counter requirements contain duplicates');
  for (const name of [...environment.required_host_counters,
    ...environment.required_zero_host_counters]) {
    requireValue(HOST_COUNTERS.includes(name), `unknown required host counter: ${name}`);
  }
  requireValue(environment.required_zero_host_counters.every((name) =>
    environment.required_host_counters.includes(name)),
  'zero host counters must also be required');
  const unavailableResources = environment.unavailable_resource_metrics ?? [];
  requireValue(Array.isArray(unavailableResources) &&
    new Set(unavailableResources).size === unavailableResources.length,
  'unavailable resource metrics must be a duplicate-free array');
  for (const name of unavailableResources) {
    requireValue(OPTIONAL_RESOURCE_METRICS.includes(name),
      `resource metric cannot be unavailable: ${name}`);
  }
}

function validateShardMap(value, expectedShards, label, validate) {
  requireExactKeys(value, expectedShards.map(String), label);
  return Object.fromEntries(expectedShards.map((shard) => [String(shard),
    validate(value[String(shard)], `${label}.${shard}`)]));
}

function counterMap(value, expectedShards, label) {
  return validateShardMap(value, expectedShards, label,
    (entry, entryLabel) => requireInteger(entry, entryLabel));
}

function gaugeMap(value, expectedShards, label) {
  return validateShardMap(value, expectedShards, label, (entry, entryLabel) => {
    requireExactKeys(entry, ['mean', 'peak', 'final'], entryLabel);
    const normalized = {
      mean: requireFinite(entry.mean, `${entryLabel}.mean`),
      peak: requireFinite(entry.peak, `${entryLabel}.peak`),
      final: requireFinite(entry.final, `${entryLabel}.final`),
    };
    requireValue(normalized.peak >= normalized.mean && normalized.peak >= normalized.final,
      `${entryLabel}.peak must be >= mean and final`);
    return normalized;
  });
}

function sumValues(value) {
  return Object.values(value).reduce((sum, item) => sum + item, 0);
}

function requestImbalance(value) {
  const values = Object.values(value);
  const mean = sumValues(value) / values.length;
  return mean === 0 ? 0 : (Math.max(...values) - Math.min(...values)) / mean;
}

function normalizedRequestImbalance(requests, connections) {
  const normalized = {};
  for (const shard of Object.keys(requests)) {
    requireValue(connections[shard] > 0,
      `shard ${shard} accepted no downstream connection during the interval`);
    normalized[shard] = requests[shard] / connections[shard];
  }
  return requestImbalance(normalized);
}

function statusClassCounts(statusCounts) {
  const result = {responses_2xx_total: 0, responses_3xx_total: 0,
    responses_4xx_total: 0, responses_5xx_total: 0};
  for (const [status, count] of Object.entries(statusCounts)) {
    requireValue(/^[2-5][0-9][0-9]$/u.test(status), `invalid final HTTP status: ${status}`);
    requireInteger(count, `status ${status}`);
    result[`responses_${status[0]}xx_total`] += count;
  }
  return result;
}

function sameIdentity(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function validateResult(result, point, environment, plan, canonicalProcess) {
  requireValue(result?.schema_version === 1 && result.plan_id === plan.plan_id &&
    result.order === point.order && result.phase === point.phase,
  `result does not match planned phase ${point.phase}`);
  requireValue(result.target_rps === point.target_rps,
    `target RPS drift at ${point.phase}`);
  const duration = requireFinite(result.measurement_seconds,
    `${point.phase} measurement_seconds`, 0.001);
  const processEnvelopeDuration = result.client_process_envelope_seconds === undefined
    ? duration : requireFinite(result.client_process_envelope_seconds,
      `${point.phase} client_process_envelope_seconds`, 0.001);
  requireValue(processEnvelopeDuration >= duration &&
    duration >= processEnvelopeDuration * 0.95,
  `client process envelope disagrees with measurement at ${point.phase}`);
  const durationRatio = duration / point.duration_seconds;
  requireValue(durationRatio >= 0.95 && durationRatio <= 1.05,
    `measurement duration drift at ${point.phase}`);

  const expectedIdentity = {
    source_commit: environment.source_commit,
    gateway_binary_sha256: environment.gateway_binary_sha256,
    snapshot_sha256: environment.snapshot_sha256,
    configuration_sha256: environment.configuration_sha256,
    collector_sha256: environment.collector_sha256,
    boot_id: environment.boot_id,
  };
  requireValue(sameIdentity(result.identities, expectedIdentity),
    `artifact or source identity drift at ${point.phase}`);
  requireExactKeys(result.process, ['service', 'pid', 'start_ticks', 'restart_count'],
    `${point.phase} process`);
  requireString(result.process.service, `${point.phase} process.service`);
  requireInteger(result.process.pid, `${point.phase} process.pid`, 2);
  requireInteger(result.process.start_ticks, `${point.phase} process.start_ticks`, 1);
  requireInteger(result.process.restart_count, `${point.phase} process.restart_count`);
  requireValue(result.process.restart_count === 0,
    `gateway restart observed at ${point.phase}`);
  if (canonicalProcess !== null) {
    requireValue(sameIdentity(result.process, canonicalProcess),
      `gateway process identity changed at ${point.phase}`);
  }

  requireValue(result.status_counts && typeof result.status_counts === 'object' &&
    !Array.isArray(result.status_counts), `${point.phase} status_counts missing`);
  const statusCounts = Object.fromEntries(Object.entries(result.status_counts).map(
    ([status, count]) => [status, requireInteger(count, `${point.phase} status ${status}`)]));
  const transportFailures = requireInteger(result.transport_failures,
    `${point.phase} transport_failures`);
  const attemptedRequests = requireInteger(result.attempted_requests,
    `${point.phase} attempted_requests`, 1);
  const completedResponses = sumValues(statusCounts);
  requireValue(completedResponses + transportFailures === attemptedRequests,
    `client accounting mismatch at ${point.phase}`);
  const attemptedRps = attemptedRequests / duration;
  const attemptedRatio = attemptedRps / point.target_rps;
  requireValue(attemptedRatio >= plan.acceptance.minimum_attempted_rate_ratio &&
    attemptedRatio <= plan.acceptance.maximum_attempted_rate_ratio,
  `offered-rate contract missed at ${point.phase}`);

  requireExactKeys(result.counters_by_shard, COUNTER_METRICS,
    `${point.phase} counters_by_shard`);
  const counters = Object.fromEntries(COUNTER_METRICS.map((name) => [name,
    counterMap(result.counters_by_shard[name], environment.expected_shards,
      `${point.phase}.${name}`)]));
  const counterSums = Object.fromEntries(COUNTER_METRICS.map((name) =>
    [name, sumValues(counters[name])]));
  requireValue(counterSums.requests_total === completedResponses,
    `gateway request/client response mismatch at ${point.phase}`);
  const classes = statusClassCounts(statusCounts);
  for (const [name, count] of Object.entries(classes)) {
    requireValue(counterSums[name] === count,
      `${name} does not match client statuses at ${point.phase}`);
  }

  requireExactKeys(result.gauges_by_shard, GAUGE_METRICS,
    `${point.phase} gauges_by_shard`);
  const gauges = Object.fromEntries(GAUGE_METRICS.map((name) => [name,
    gaugeMap(result.gauges_by_shard[name], environment.expected_shards,
      `${point.phase}.${name}`)]));
  for (const value of Object.values(gauges.response_path_diagnostics_enabled)) {
    requireValue(value.mean === 1 && value.peak === 1 && value.final === 1,
      `response-path diagnostics were not continuously enabled at ${point.phase}`);
  }
  for (const value of Object.values(gauges.configured_upstream_http1_connections)) {
    requireValue(value.mean > 0 && value.peak > 0 && value.final > 0,
      `configured HTTP/1 pool capacity is absent at ${point.phase}`);
  }

  requireExactKeys(result.support_capacity_percent, environment.support_roles,
    `${point.phase} support_capacity_percent`);
  const supportCapacity = Object.fromEntries(environment.support_roles.map((role) => [role,
    requireFinite(result.support_capacity_percent[role],
      `${point.phase} support capacity ${role}`)]));
  requireValue(Object.values(supportCapacity).every((value) =>
    value <= plan.acceptance.maximum_support_capacity_percent),
  `support role saturated at ${point.phase}`);

  requireExactKeys(result.resources, ['gateway_application_cpu_percent',
    'gateway_capacity_percent', 'host_cpu_percent', 'irq_cpu_percent',
    'rss_bytes', 'file_descriptors'], `${point.phase} resources`);
  const resources = {
    gateway_application_cpu_percent: requireFinite(
      result.resources.gateway_application_cpu_percent,
      `${point.phase} gateway application CPU`),
    gateway_capacity_percent: requireFinite(result.resources.gateway_capacity_percent,
      `${point.phase} gateway capacity`, 0),
    host_cpu_percent: result.resources.host_cpu_percent,
    irq_cpu_percent: result.resources.irq_cpu_percent,
    rss_bytes: result.resources.rss_bytes,
    file_descriptors: result.resources.file_descriptors,
  };
  const unavailableResources = new Set(environment.unavailable_resource_metrics ?? []);
  for (const [name, label] of [
    ['host_cpu_percent', 'host CPU'],
    ['irq_cpu_percent', 'IRQ CPU'],
  ]) {
    if (unavailableResources.has(name)) {
      requireValue(resources[name] === null,
        `${point.phase} ${label} must be null when declared unavailable`);
    } else {
      resources[name] = requireFinite(resources[name], `${point.phase} ${label}`);
    }
  }
  requireValue(resources.gateway_capacity_percent <= 100 &&
    (resources.host_cpu_percent === null || resources.host_cpu_percent <= 100) &&
    (resources.irq_cpu_percent === null || resources.irq_cpu_percent <= 100),
  `capacity percentages exceed 100 at ${point.phase}`);
  for (const [name, value] of [['rss_bytes', resources.rss_bytes],
    ['file_descriptors', resources.file_descriptors]]) {
    requireExactKeys(value, ['before', 'peak', 'after'], `${point.phase} ${name}`);
    for (const field of ['before', 'peak', 'after']) {
      requireInteger(value[field], `${point.phase} ${name}.${field}`);
    }
    requireValue(value.peak >= value.before && value.peak >= value.after,
      `${point.phase} ${name}.peak must cover before and after`);
  }

  requireExactKeys(result.host_counters, HOST_COUNTERS,
    `${point.phase} host_counters`);
  const hostCounters = {};
  for (const name of HOST_COUNTERS) {
    const value = result.host_counters[name];
    hostCounters[name] = value === null ? null : requireInteger(value,
      `${point.phase} host counter ${name}`);
    if (environment.required_host_counters.includes(name)) {
      requireValue(hostCounters[name] !== null,
        `required host counter missing at ${point.phase}: ${name}`);
    }
  }

  requireExactKeys(result.latency_ms, ['p50', 'p95', 'p99', 'p999'],
    `${point.phase} latency_ms`);
  const latency = Object.fromEntries(Object.entries(result.latency_ms).map(
    ([name, value]) => [name, requireFinite(value, `${point.phase} latency ${name}`)]));
  requireValue(latency.p95 >= latency.p50 && latency.p99 >= latency.p95 &&
    latency.p999 >= latency.p99, `latency percentiles are unordered at ${point.phase}`);

  const successfulResponses = statusCounts['200'] ?? 0;
  const failedRequests = attemptedRequests - successfulResponses;
  return {
    order: point.order,
    phase: point.phase,
    target_rps: point.target_rps,
    measurement_seconds: duration,
    client_process_envelope_seconds: processEnvelopeDuration,
    attempted_requests: attemptedRequests,
    attempted_rps: attemptedRps,
    attempted_rate_ratio: attemptedRatio,
    successful_responses: successfulResponses,
    successful_rps: successfulResponses / duration,
    completed_responses: completedResponses,
    error_rate: failedRequests / attemptedRequests,
    status_counts: statusCounts,
    transport_failures: transportFailures,
    latency_ms: latency,
    counters_by_shard: counters,
    counter_sums: counterSums,
    gauges_by_shard: gauges,
    request_imbalance_ratio: requestImbalance(counters.requests_total),
    normalized_request_imbalance_ratio: normalizedRequestImbalance(
      counters.requests_total, counters.downstream_connections_accepted_total),
    support_capacity_percent: supportCapacity,
    resources,
    host_counters: hostCounters,
    process: result.process,
    identities: result.identities,
  };
}

function stageSloPass(point, planned) {
  return point.latency_ms.p95 <= planned.latency_ceiling_ms.p95 &&
    point.latency_ms.p99 <= planned.latency_ceiling_ms.p99;
}

export function summarizeBackpressure({plan, environment, results}) {
  validatePlan(plan);
  validateEnvironment(environment, plan);
  requireValue(Array.isArray(results) && results.length === PHASES.length,
    `expected ${PHASES.length} results, received ${results?.length ?? 0}`);
  const byPhase = new Map();
  for (const [index, result] of results.entries()) {
    requireString(result?.phase, 'result phase');
    requireValue(!byPhase.has(result.phase), `duplicate result phase: ${result.phase}`);
    requireValue(result.phase === PHASES[index],
      `result order ${index + 1} must be ${PHASES[index]}`);
    byPhase.set(result.phase, result);
  }
  const canonicalProcess = results[0]?.process ?? null;
  const points = plan.points.map((planned) => {
    const result = byPhase.get(planned.phase);
    requireValue(result, `missing result phase: ${planned.phase}`);
    return validateResult(result, planned, environment, plan, canonicalProcess);
  });
  const get = (phase) => points.find((point) => point.phase === phase);
  const steady = get('steady');
  const nearKnee = get('near_knee');
  const overload = get('intentional_overload');
  const recovery = get('recovery');
  const requiredOverload = plan.acceptance.required_overload_counter;
  const overloadStatuses = Object.entries(overload.status_counts)
    .filter(([status, count]) => status !== '200' && count > 0);
  const recoveryFinalGauges = Object.fromEntries(FINAL_ZERO_GAUGES.map((name) =>
    [name, sumValues(Object.fromEntries(Object.entries(recovery.gauges_by_shard[name])
      .map(([shard, value]) => [shard, value.final])))]));
  const recoveryBaselineGauges = Object.fromEntries(RECOVERY_BASELINE_GAUGES.map((name) => {
    const steadyValues = steady.gauges_by_shard[name];
    const recoveryValues = recovery.gauges_by_shard[name];
    const withinBaseline = Object.keys(steadyValues).every((shard) =>
      recoveryValues[shard].final <= steadyValues[shard].peak);
    return [name, {
      steady_peak: sumValues(Object.fromEntries(Object.entries(steadyValues)
        .map(([shard, value]) => [shard, value.peak]))),
      recovery_final: sumValues(Object.fromEntries(Object.entries(recoveryValues)
        .map(([shard, value]) => [shard, value.final]))),
      within_baseline: withinBaseline,
    }];
  }));
  const preOverload = [steady, nearKnee];
  const gates = {
    exact_matrix_pass: true,
    clean_source_pass: true,
    process_identity_pass: true,
    support_roles_unsaturated_pass: true,
    pre_overload_error_budget_pass: preOverload.every((point) =>
      point.error_rate <= plan.acceptance.maximum_pre_overload_error_rate),
    steady_and_knee_slo_pass: [steady, nearKnee].every((point, index) =>
      stageSloPass(point, plan.points[index])),
    overload_fail_fast_pass: overload.transport_failures === 0 &&
      overload.counter_sums[requiredOverload] > 0 &&
      overload.counter_sums.overload_rejections_total === (overload.status_counts['503'] ?? 0) &&
      overloadStatuses.every(([status]) => status === '503'),
    overload_tail_bounded_pass: stageSloPass(overload, plan.points[2]),
    shard_balance_pass: points.every((point) => point.normalized_request_imbalance_ratio <=
      plan.acceptance.maximum_request_imbalance_ratio),
    recovery_throughput_pass: recovery.successful_rps >= steady.successful_rps *
      plan.acceptance.minimum_recovery_rps_ratio,
    recovery_slo_pass: recovery.error_rate === 0 && recovery.transport_failures === 0 &&
      stageSloPass(recovery, plan.points[3]),
    recovery_gauges_drained_pass: Object.values(recoveryFinalGauges)
      .every((value) => value === 0) && Object.values(recoveryBaselineGauges)
      .every((value) => value.within_baseline),
    recovery_resources_pass:
      recovery.resources.rss_bytes.after - steady.resources.rss_bytes.before <=
        plan.acceptance.maximum_recovery_rss_growth_bytes &&
      recovery.resources.file_descriptors.after - steady.resources.file_descriptors.before <=
        plan.acceptance.maximum_recovery_fd_growth,
    host_integrity_pass: points.every((point) =>
      environment.required_zero_host_counters.every((name) => point.host_counters[name] === 0)),
  };
  const passed = Object.values(gates).every(Boolean);
  return {
    schema_version: 1,
    analyzer_sha256: sha256(fs.readFileSync(new URL(import.meta.url))),
    run_id: environment.run_id,
    plan_id: plan.plan_id,
    profile: plan.profile,
    evidence_class: environment.evidence_class,
    publication_authorized: false,
    source_commit: environment.source_commit,
    source_dirty: environment.source_dirty,
    points,
    recovery: {
      successful_rps_ratio: recovery.successful_rps / steady.successful_rps,
      rss_growth_bytes: recovery.resources.rss_bytes.after - steady.resources.rss_bytes.before,
      file_descriptor_growth: recovery.resources.file_descriptors.after -
        steady.resources.file_descriptors.before,
      final_gauge_totals: recoveryFinalGauges,
      baseline_gauge_totals: recoveryBaselineGauges,
    },
    gates,
    decision: passed ? 'queueing-backpressure-pass' : 'investigate',
    limitations: [
      'This engineering analyzer does not authorize publication or competitive claims.',
      'Point-sampled gauges can bound sustained buildup but may miss sub-second peaks.',
      'A short recovery interval does not replace the multi-hour resource-slope gate.',
    ],
  };
}

export function renderBackpressureMarkdown(summary) {
  const lines = [
    `# PERF-04 queueing and backpressure: ${summary.run_id}`,
    '',
    `- Evidence class: \`${summary.evidence_class}\`.`,
    `- Decision: **${summary.decision}**.`,
    `- Publication authorized: \`${summary.publication_authorized}\`.`,
    `- Source: \`${summary.source_commit}\`; dirty: \`${summary.source_dirty}\`.`,
    '',
    '| Stage | Target RPS | Successful RPS | Error rate | p50 | p95 | p99 | p99.9 ref | Request imbalance |',
    '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
  ];
  for (const point of summary.points) {
    lines.push(`| ${point.phase} | ${point.target_rps.toLocaleString('en-US')} | ` +
      `${point.successful_rps.toFixed(2)} | ${(point.error_rate * 100).toFixed(4)}% | ` +
      `${point.latency_ms.p50.toFixed(3)} ms | ${point.latency_ms.p95.toFixed(3)} ms | ` +
      `${point.latency_ms.p99.toFixed(3)} ms | ${point.latency_ms.p999.toFixed(3)} ms | ` +
      `${(point.normalized_request_imbalance_ratio * 100).toFixed(2)}% |`);
  }
  lines.push('', '## Gates', '');
  for (const [name, passed] of Object.entries(summary.gates)) {
    lines.push(`- ${name}: **${passed ? 'PASS' : 'FAIL'}**`);
  }
  lines.push('');
  return `${lines.join('\n')}\n`;
}

function writeNewJson(output, value) {
  const descriptor = fs.openSync(output, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`);
  } finally {
    fs.closeSync(descriptor);
  }
}

function argument(name, argv) {
  const index = argv.indexOf(name);
  requireValue(index >= 0 && index + 1 < argv.length, `${name} is required`);
  return path.resolve(argv[index + 1]);
}

function main() {
  const [, , action, ...argv] = process.argv;
  if (action === 'plan') {
    const input = JSON.parse(fs.readFileSync(argument('--input', argv), 'utf8'));
    writeNewJson(argument('--output', argv), buildBackpressurePlan(input));
    return;
  }
  requireValue(action === 'summarize',
    'usage: phase5-backpressure.mjs plan|summarize [options]');
  const planPath = argument('--plan', argv);
  const environmentPath = argument('--environment', argv);
  const resultsPath = argument('--results', argv);
  const outputPath = argument('--output', argv);
  const summary = summarizeBackpressure({
    plan: JSON.parse(fs.readFileSync(planPath, 'utf8')),
    environment: JSON.parse(fs.readFileSync(environmentPath, 'utf8')),
    results: JSON.parse(fs.readFileSync(resultsPath, 'utf8')),
  });
  summary.inputs = {
    plan_sha256: sha256(fs.readFileSync(planPath)),
    environment_sha256: sha256(fs.readFileSync(environmentPath)),
    results_sha256: sha256(fs.readFileSync(resultsPath)),
  };
  writeNewJson(outputPath, summary);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-backpressure: ${error.message}\n`);
    process.exitCode = 1;
  }
}
