#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import {isIP} from 'node:net';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

import {validateProtocolStreamingCatalog} from './phase5-protocol-streaming.mjs';

const PROFILE_IDS = Object.freeze([
  'P5-T01', 'P5-H01', 'P5-H02', 'P5-G01', 'P5-S01',
]);
const CORE_COUNTS = Object.freeze([8, 24]);
const ROLE_NAMES = Object.freeze([
  'load_generator', 'gateway', 'controlled_upstream',
]);
const MEASUREMENT_CLASSES = Object.freeze([
  'throughput-cost', 'stream-cost', 'lifecycle',
]);
const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const HOST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

const SOURCE_KEYS = Object.freeze([
  'binary_source_commit',
  'harness_commit',
  'source_dirty',
  'gateway_binary_sha256',
  'snapshot_compiler_sha256',
  'load_client_sha256',
  'controlled_upstream_sha256',
  'fixture_bundle_sha256',
  'collector_bundle_sha256',
  'tls_bundle_sha256',
  'runtime_inventory_sha256',
]);

export const NATIVE_ACCEPTANCE = Object.freeze({
  maximum_repetition_variation_percent: 5,
  maximum_pre_overload_error_rate: 0.001,
  maximum_support_capacity_percent: 80,
  maximum_cleanup_ms: 2000,
  maximum_retained_rss_growth_bytes: 16 * 1024 * 1024,
  maximum_retained_fd_growth: 4,
  final_active_streams: 0,
  same_process_recovery_required: true,
});

export const NATIVE_RESULT_CONTRACT = Object.freeze({
  profiler_scope: 'all-stable-seastar-reactor-tids',
  cpu_scopes: Object.freeze([
    'gateway-cpuset',
    'whole-gateway-host',
    'gateway-host-hardirq-and-softirq',
    'whole-support-role-hosts',
  ]),
  protocol_observations: Object.freeze([
    'downstream_tls_version',
    'downstream_tls_cipher',
    'downstream_peer_certificate_verified',
    'downstream_hostname_verified',
    'downstream_alpn',
    'upstream_protocol',
    'semantic_outcome',
    'payload_or_event_order_exact',
    'gateway_process_identity',
    'gateway_restart_count',
    'support_role_capacity_percent',
  ]),
  required_tls_version: 'TLSv1.3',
  required_tls_cipher_family: 'AES',
  metric_sets: Object.freeze({
    throughput_cost: Object.freeze([
      'successful_rps', 'application_cpu_percent', 'host_cpu_percent',
      'irq_cpu_percent', 'cycles_per_success', 'instructions_per_success',
      'ipc', 'allocations_per_success', 'syscalls_per_success',
      'writes_per_success', 'bytes_per_write', 'p50_ms', 'p95_ms', 'p99_ms',
      'p999_reference_ms', 'rss_bytes', 'file_descriptors', 'queue_waits',
      'per_shard_work',
    ]),
    stream_cost: Object.freeze([
      'application_cpu_percent', 'host_cpu_percent', 'irq_cpu_percent',
      'cycles_per_success', 'instructions_per_success', 'ipc',
      'allocations_per_success', 'syscalls_per_success', 'writes_per_success',
      'bytes_per_write', 'p50_ms', 'p95_ms', 'p99_ms', 'p999_reference_ms',
      'ttfb_ms', 'first_semantic_event_ms', 'maximum_event_gap_ms',
      'delivery_bytes_per_second', 'rss_bytes', 'file_descriptors',
      'memory_per_active_stream_bytes', 'active_streams', 'queue_waits',
      'per_shard_work',
    ]),
    lifecycle_h2_grpc: Object.freeze([
      'application_cpu_percent', 'host_cpu_percent', 'irq_cpu_percent',
      'rss_bytes', 'file_descriptors', 'active_streams',
      'cancellation_cleanup_ms', 'queue_waits', 'per_shard_work',
    ]),
    lifecycle_sse: Object.freeze([
      'application_cpu_percent', 'host_cpu_percent', 'irq_cpu_percent',
      'ttfb_ms', 'first_semantic_event_ms', 'maximum_event_gap_ms',
      'delivery_bytes_per_second', 'rss_bytes', 'file_descriptors',
      'memory_per_active_stream_bytes', 'active_streams',
      'cancellation_cleanup_ms', 'queue_waits', 'per_shard_work',
    ]),
  }),
});

const EXPECTED_OUTCOME = Object.freeze({
  'P5-H02': Object.freeze({
    healthy: 'success',
    'connection-reuse': 'success',
    'peer-cancel': 'peer-cancel',
    deadline: 'deadline',
  }),
  'P5-G01': Object.freeze({
    healthy: 'grpc-ok',
    deadline: 'grpc-deadline-exceeded',
    'peer-cancel': 'grpc-cancelled',
    'malformed-message': 'grpc-rejected-malformed-message',
    'invalid-trailers': 'grpc-rejected-invalid-trailers',
  }),
  'P5-S01': Object.freeze({
    'healthy-cadence': 'terminal-done',
    'slow-consumer': 'bounded-slow-consumer',
    'peer-cancel': 'peer-cancel',
    'upstream-stall': 'gateway-deadline',
    'terminal-error': 'terminal-error',
    'missing-terminal-event': 'logical-incomplete',
  }),
});

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  requireValue(JSON.stringify(actual) === JSON.stringify(wanted),
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

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function canonicalHash(value) {
  return sha256(JSON.stringify(canonicalize(value)));
}

function positiveInteger(value, label) {
  requireValue(Number.isSafeInteger(value) && value > 0,
    `${label} must be a positive integer`);
  return value;
}

function nonNegativeFinite(value, label) {
  requireValue(Number.isFinite(value) && value >= 0,
    `${label} must be a finite number >= 0`);
  return value;
}

function digest(value, label) {
  requireValue(typeof value === 'string' && SHA256.test(value),
    `${label} must be a SHA-256 digest`);
  return value;
}

function exactArray(value, expected, label) {
  requireValue(Array.isArray(value) &&
    JSON.stringify(value) === JSON.stringify(expected), `${label} changed`);
}

function isPrivateIpv4(value) {
  if (typeof value !== 'string' || isIP(value) !== 4) return false;
  const [first, second] = value.split('.').map(Number);
  return first === 10 || (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168);
}

function validateRoleBindings(value) {
  requireValue(Array.isArray(value) && value.length === ROLE_NAMES.length,
    'native plan requires exactly three role bindings');
  exactArray(value.map((role) => role.role), ROLE_NAMES,
    'native role ordering');
  const hostIds = new Set();
  const addresses = new Set();
  for (const [index, role] of value.entries()) {
    exactKeys(role, ['role', 'host_id', 'private_address'],
      `role binding ${index + 1}`);
    requireValue(typeof role.host_id === 'string' && HOST_ID.test(role.host_id),
      `${role.role} host identity is invalid`);
    requireValue(isPrivateIpv4(role.private_address),
      `${role.role} private address must be a private IPv4 address`);
    hostIds.add(role.host_id);
    addresses.add(role.private_address);
  }
  requireValue(hostIds.size === ROLE_NAMES.length &&
    addresses.size === ROLE_NAMES.length,
    'native roles must use distinct hosts and private addresses');
}

function validateProfileScope(value) {
  requireValue(Array.isArray(value) && value.length > 0 &&
    value.length <= PROFILE_IDS.length && new Set(value).size === value.length,
  'native profile scope must contain distinct profiles');
  requireValue(value.every((profile) => PROFILE_IDS.includes(profile)),
    'native profile scope contains an unsupported profile');
  requireValue(JSON.stringify(value) === JSON.stringify(
    PROFILE_IDS.filter((profile) => value.includes(profile))),
  'native profile scope must use canonical profile order');
}

function validateCpuList(value, count, label) {
  requireValue(Array.isArray(value) && value.length === count &&
    new Set(value).size === count &&
    value.every((cpu) => Number.isSafeInteger(cpu) && cpu >= 0),
  `${label} must contain ${count} distinct non-negative CPUs`);
}

function validateTopology(value) {
  exactKeys(value, ['roles', 'load_generator_cpu_set',
    'load_generator_lanes', 'gateway_cpu_sets', 'gateway_housekeeping_cpus',
    'irq_policy'], 'native topology');
  validateRoleBindings(value.roles);
  requireValue(Array.isArray(value.load_generator_cpu_set) &&
    value.load_generator_cpu_set.length >= 2 &&
    value.load_generator_cpu_set.length <= 256 &&
    new Set(value.load_generator_cpu_set).size ===
      value.load_generator_cpu_set.length &&
    value.load_generator_cpu_set.every((cpu) =>
      Number.isSafeInteger(cpu) && cpu >= 0),
  'load-generator CPU set is invalid');
  requireValue(Number.isSafeInteger(value.load_generator_lanes) &&
    value.load_generator_lanes >= 2 && value.load_generator_lanes <= 16 &&
    value.load_generator_lanes <= value.load_generator_cpu_set.length,
  'load-generator lane count is invalid');
  exactKeys(value.gateway_cpu_sets, ['8', '24'], 'gateway CPU sets');
  validateCpuList(value.gateway_cpu_sets['8'], 8, '8-core gateway CPU set');
  validateCpuList(value.gateway_cpu_sets['24'], 24, '24-core gateway CPU set');
  requireValue(value.gateway_cpu_sets['8'].every((cpu) =>
    value.gateway_cpu_sets['24'].includes(cpu)),
  '8-core gateway CPUs must be a subset of the 24-core set');
  requireValue(Array.isArray(value.gateway_housekeeping_cpus) &&
    value.gateway_housekeeping_cpus.length > 0 &&
    new Set(value.gateway_housekeeping_cpus).size ===
      value.gateway_housekeeping_cpus.length &&
    value.gateway_housekeeping_cpus.every((cpu) =>
      Number.isSafeInteger(cpu) && cpu >= 0),
  'gateway housekeeping CPUs are invalid');
  requireValue(value.gateway_housekeeping_cpus.every((cpu) =>
    !value.gateway_cpu_sets['24'].includes(cpu)),
  'gateway and housekeeping CPU sets must be disjoint');

  exactKeys(value.irq_policy, ['mode', 'gateway_banned_cpus', 'irq_target_cpus'],
    'IRQ policy');
  requireValue(['irqbalance-with-gateway-ban', 'static-housekeeping-only']
    .includes(value.irq_policy.mode), 'IRQ policy mode is unsupported');
  requireValue(JSON.stringify(value.irq_policy.gateway_banned_cpus) ===
    JSON.stringify(value.gateway_cpu_sets['24']),
  'IRQ gateway ban must match the 24-core gateway CPU set');
  requireValue(Array.isArray(value.irq_policy.irq_target_cpus) &&
    value.irq_policy.irq_target_cpus.length > 0 &&
    value.irq_policy.irq_target_cpus.every((cpu) =>
      value.gateway_housekeeping_cpus.includes(cpu)),
  'IRQ target CPUs must be drawn from housekeeping CPUs');
}

function validateAcceptance(value) {
  exactKeys(value, Object.keys(NATIVE_ACCEPTANCE), 'native acceptance gates');
  requireValue(JSON.stringify(canonicalize(value)) ===
    JSON.stringify(canonicalize(NATIVE_ACCEPTANCE)),
    'native acceptance gates changed');
}

function validateSchedule(value) {
  exactKeys(value, ['throughput_repetitions', 'lifecycle_repetitions',
    'profiled_warmup_repetitions', 'position_balance',
    'inter_point_cooldown_seconds'], 'native schedule');
  requireValue(value.throughput_repetitions === 5,
    'throughput and stream-cost points require five repetitions');
  requireValue(value.lifecycle_repetitions === 3,
    'lifecycle points require three repetitions');
  requireValue(value.profiled_warmup_repetitions === 3,
    'native points require exactly three profiled warmup repetitions');
  requireValue(value.position_balance === 'forward-reverse',
    'native schedule must remain forward/reverse position-balanced');
  positiveInteger(value.inter_point_cooldown_seconds,
    'inter-point cooldown seconds');
}

function validateCommonWorkload(value, label) {
  for (const key of ['warmup_seconds', 'measurement_seconds',
    'request_timeout_ms', 'p95_ceiling_ms', 'p99_ceiling_ms']) {
    nonNegativeFinite(value[key], `${label}.${key}`);
  }
  requireValue(value.warmup_seconds > 0 && value.measurement_seconds > 0 &&
    value.request_timeout_ms > 0 && value.p95_ceiling_ms > 0 &&
    value.p99_ceiling_ms >= value.p95_ceiling_ms,
  `${label} timing and latency bounds are invalid`);
}

function validateThroughputWorkload(value, label) {
  exactKeys(value, ['target_rps', 'warmup_seconds', 'measurement_seconds',
    'connections', 'streams_per_connection', 'request_timeout_ms',
    'p95_ceiling_ms', 'p99_ceiling_ms'], label);
  for (const key of ['target_rps', 'connections', 'streams_per_connection']) {
    positiveInteger(value[key], `${label}.${key}`);
  }
  validateCommonWorkload(value, label);
}

function validateStreamWorkload(value, label, payloadBytes) {
  exactKeys(value, ['target_active_streams', 'stream_start_rate_per_second',
    'warmup_seconds', 'measurement_seconds', 'event_count',
    'event_interval_ms', 'event_payload_bytes', 'upstream_chunk_bytes',
    'request_timeout_ms', 'ttfb_ceiling_ms', 'event_gap_ceiling_ms',
    'p95_ceiling_ms', 'p99_ceiling_ms'], label);
  for (const key of ['target_active_streams', 'stream_start_rate_per_second',
    'event_count', 'event_interval_ms', 'event_payload_bytes',
    'upstream_chunk_bytes',
    'ttfb_ceiling_ms', 'event_gap_ceiling_ms']) {
    positiveInteger(value[key], `${label}.${key}`);
  }
  requireValue(value.event_payload_bytes === payloadBytes,
    `${label}.event_payload_bytes differs from the catalog payload`);
  requireValue(value.upstream_chunk_bytes <= value.event_payload_bytes,
    `${label}.upstream_chunk_bytes exceeds the event payload`);
  validateCommonWorkload(value, label);
}

function validateLifecycleWorkload(value, label, profile, scenario,
  payloadBytes) {
  exactKeys(value, ['concurrent_cases', 'iterations', 'event_count',
    'event_interval_ms', 'event_payload_bytes', 'upstream_chunk_bytes',
    'slow_consumer_read_rate_bytes_per_second', 'request_timeout_ms',
    'idle_timeout_ms', 'cleanup_ceiling_ms'], label);
  for (const key of ['concurrent_cases', 'iterations', 'request_timeout_ms',
    'idle_timeout_ms', 'cleanup_ceiling_ms']) {
    positiveInteger(value[key], `${label}.${key}`);
  }
  requireValue(value.cleanup_ceiling_ms ===
    NATIVE_ACCEPTANCE.maximum_cleanup_ms,
    `${label}.cleanup_ceiling_ms must match the fixed gate`);
  const streamFields = ['event_count', 'event_interval_ms',
    'event_payload_bytes', 'upstream_chunk_bytes'];
  if (profile === 'P5-S01') {
    for (const key of streamFields) positiveInteger(value[key], `${label}.${key}`);
    requireValue(value.upstream_chunk_bytes <= value.event_payload_bytes,
      `${label}.upstream_chunk_bytes exceeds the event payload`);
    if (scenario === 'slow-consumer') {
      requireValue(value.event_payload_bytes >= 4096,
        `${label}.event_payload_bytes must exercise a large slow-consumer event`);
      positiveInteger(value.slow_consumer_read_rate_bytes_per_second,
        `${label}.slow_consumer_read_rate_bytes_per_second`);
    } else {
      requireValue(value.event_payload_bytes === payloadBytes,
        `${label}.event_payload_bytes differs from the catalog payload`);
      requireValue(value.slow_consumer_read_rate_bytes_per_second === null,
        `${label} slow-reader rate is only valid for slow-consumer`);
    }
  } else {
    for (const key of [...streamFields,
      'slow_consumer_read_rate_bytes_per_second']) {
      requireValue(value[key] === null,
        `${label}.${key} must be null outside SSE lifecycle testing`);
    }
  }
}

function expectedClass(profile, scenario) {
  if (profile === 'P5-T01' || profile === 'P5-H01') return 'throughput-cost';
  if (profile === 'P5-H02' || profile === 'P5-G01') {
    return ['healthy', 'connection-reuse'].includes(scenario) ?
      'throughput-cost' : 'lifecycle';
  }
  return scenario === 'healthy-cadence' ? 'stream-cost' : 'lifecycle';
}

function validateVariant(variant, catalog, index) {
  const label = `variant ${index + 1}`;
  exactKeys(variant, ['id', 'profile', 'measurement_class', 'scenario',
    'core_count', 'downstream_protocol', 'upstream_protocol', 'payload_bytes',
    'expected_outcome', 'snapshot_sha256', 'workload'], label);
  requireValue(typeof variant.id === 'string' &&
    /^[a-z0-9][a-z0-9-]{2,95}$/u.test(variant.id), `${label} ID is invalid`);
  requireValue(PROFILE_IDS.includes(variant.profile),
    `${variant.id} profile is invalid`);
  requireValue(MEASUREMENT_CLASSES.includes(variant.measurement_class),
    `${variant.id} measurement class is invalid`);
  requireValue(CORE_COUNTS.includes(variant.core_count),
    `${variant.id} core count is invalid`);
  digest(variant.snapshot_sha256, `${variant.id} snapshot`);

  const profile = catalog.profiles.find((item) => item.id === variant.profile);
  requireValue(profile.scenarios.includes(variant.scenario),
    `${variant.id} scenario is outside the catalog`);
  requireValue(profile.downstream_protocols.includes(variant.downstream_protocol),
    `${variant.id} downstream protocol is outside the catalog`);
  requireValue(profile.upstream_protocols.includes(variant.upstream_protocol),
    `${variant.id} upstream protocol is outside the catalog`);
  requireValue(profile.payload_bytes.includes(variant.payload_bytes),
    `${variant.id} payload is outside the catalog`);
  requireValue(variant.measurement_class ===
    expectedClass(variant.profile, variant.scenario),
  `${variant.id} measurement class does not match its scenario`);

  const expected = EXPECTED_OUTCOME[variant.profile]?.[variant.scenario] ??
    'success';
  requireValue(variant.expected_outcome === expected,
    `${variant.id} expected outcome changed`);
  if (variant.profile === 'P5-T01') {
    requireValue((variant.scenario === 'fixed-response' &&
      variant.upstream_protocol === 'none') ||
      (variant.scenario === 'proxied-response' &&
        variant.upstream_protocol === 'http1'),
    `${variant.id} fixed/proxied upstream contract is invalid`);
  }
  if (variant.measurement_class === 'throughput-cost') {
    validateThroughputWorkload(variant.workload, `${variant.id}.workload`);
  } else if (variant.measurement_class === 'stream-cost') {
    validateStreamWorkload(variant.workload, `${variant.id}.workload`,
      variant.payload_bytes);
  } else {
    validateLifecycleWorkload(variant.workload, `${variant.id}.workload`,
      variant.profile, variant.scenario, variant.payload_bytes);
  }
}

function validateResultContract(catalog) {
  const metricSets = Object.values(NATIVE_RESULT_CONTRACT.metric_sets);
  for (const [name, metrics] of Object.entries(
    NATIVE_RESULT_CONTRACT.metric_sets)) {
    requireValue(metrics.length > 0 && new Set(metrics).size === metrics.length,
      `${name} result metric set is invalid`);
  }
  const covered = new Set(metricSets.flat());
  requireValue(catalog.required_metrics.length === covered.size &&
    catalog.required_metrics.every((metric) => covered.has(metric)),
  'native result metric sets do not cover the frozen catalog');
}

function hasVariant(variants, predicate) {
  return variants.some(predicate);
}

function requireCoverage(variants, catalog, profileScope) {
  const profile = (id) => catalog.profiles.find((item) => item.id === id);
  const included = new Set(profileScope);
  if (included.has('P5-T01')) {
    for (const scenario of profile('P5-T01').scenarios) {
      for (const payload of profile('P5-T01').payload_bytes) {
        for (const cores of CORE_COUNTS) {
          requireValue(hasVariant(variants, (item) => item.profile === 'P5-T01' &&
            item.scenario === scenario && item.payload_bytes === payload &&
            item.core_count === cores),
          `P5-T01 coverage missing ${scenario}/${payload}/${cores}c`);
        }
      }
    }
  }

  if (included.has('P5-H01')) {
    for (const scenario of profile('P5-H01').scenarios) {
      for (const cores of CORE_COUNTS) {
        requireValue(hasVariant(variants, (item) => item.profile === 'P5-H01' &&
          item.scenario === scenario && item.core_count === cores),
        `P5-H01 coverage missing ${scenario}/${cores}c`);
      }
    }
    for (const payload of profile('P5-H01').payload_bytes) {
      for (const cores of CORE_COUNTS) {
        requireValue(hasVariant(variants, (item) => item.profile === 'P5-H01' &&
          item.scenario === 'stable-headers' && item.payload_bytes === payload &&
          item.core_count === cores),
        `P5-H01 stable-header payload coverage missing ${payload}/${cores}c`);
      }
    }
  }

  if (included.has('P5-H02')) {
    for (const payload of profile('P5-H02').payload_bytes) {
      for (const cores of CORE_COUNTS) {
        requireValue(hasVariant(variants, (item) => item.profile === 'P5-H02' &&
          item.scenario === 'healthy' && item.payload_bytes === payload &&
          item.core_count === cores),
        `P5-H02 healthy coverage missing ${payload}/${cores}c`);
      }
    }
    for (const scenario of ['connection-reuse', 'peer-cancel', 'deadline']) {
      requireValue(hasVariant(variants, (item) => item.profile === 'P5-H02' &&
        item.scenario === scenario),
      `P5-H02 scenario coverage missing ${scenario}`);
    }
  }

  if (included.has('P5-G01')) {
    for (const payload of profile('P5-G01').payload_bytes) {
      for (const cores of CORE_COUNTS) {
        requireValue(hasVariant(variants, (item) => item.profile === 'P5-G01' &&
          item.scenario === 'healthy' && item.payload_bytes === payload &&
          item.core_count === cores),
        `P5-G01 healthy coverage missing ${payload}/${cores}c`);
      }
    }
    for (const scenario of profile('P5-G01').scenarios.filter((item) =>
      item !== 'healthy')) {
      requireValue(hasVariant(variants, (item) => item.profile === 'P5-G01' &&
        item.scenario === scenario),
      `P5-G01 scenario coverage missing ${scenario}`);
    }
  }

  if (included.has('P5-S01')) {
    for (const protocol of profile('P5-S01').downstream_protocols) {
      for (const cores of CORE_COUNTS) {
        const cadence = variants.filter((item) => item.profile === 'P5-S01' &&
          item.scenario === 'healthy-cadence' &&
          item.downstream_protocol === protocol && item.core_count === cores);
        requireValue(cadence.some((item) =>
          item.workload.upstream_chunk_bytes === 1),
        `P5-S01 one-byte chunk coverage missing ${protocol}/${cores}c`);
        requireValue(cadence.some((item) =>
          item.workload.upstream_chunk_bytes === item.payload_bytes),
        `P5-S01 event-sized chunk coverage missing ${protocol}/${cores}c`);
      }
      for (const scenario of profile('P5-S01').scenarios.filter((item) =>
        item !== 'healthy-cadence')) {
        requireValue(hasVariant(variants, (item) => item.profile === 'P5-S01' &&
          item.scenario === scenario && item.downstream_protocol === protocol),
        `P5-S01 lifecycle coverage missing ${protocol}/${scenario}`);
      }
    }
  }
}

function schedulePoints(variants, schedule) {
  const result = [];
  let order = 1;
  for (const group of [
    {name: 'measured', classes: ['throughput-cost', 'stream-cost'],
      repetitions: schedule.throughput_repetitions},
    {name: 'lifecycle', classes: ['lifecycle'],
      repetitions: schedule.lifecycle_repetitions},
  ]) {
    const selected = variants.filter((item) =>
      group.classes.includes(item.measurement_class)).sort((left, right) =>
      left.id.localeCompare(right.id));
    for (let repetition = 1; repetition <= group.repetitions; repetition += 1) {
      const positioned = repetition % 2 === 1 ? selected : [...selected].reverse();
      for (const variant of positioned) {
        result.push({
          order,
          point_id: `${variant.id}-r${repetition}`,
          group: group.name,
          variant_id: variant.id,
          repetition,
        });
        order += 1;
      }
    }
  }
  return result;
}

export function buildProtocolNativePlan(input, catalogBytes) {
  const catalog = validateProtocolStreamingCatalog(JSON.parse(catalogBytes));
  exactKeys(input, ['schema_version', 'checkpoint', 'evidence_class',
    'publication_authorized', 'catalog_sha256', 'profile_scope', 'source',
    'topology', 'schedule', 'acceptance', 'variants'], 'native plan input');
  requireValue(input.schema_version === 1 && input.checkpoint === 'PERF-05',
    'native plan schema or checkpoint is invalid');
  requireValue(input.evidence_class === 'native-engineering' &&
    input.publication_authorized === false,
  'native engineering plan cannot authorize publication');
  requireValue(input.catalog_sha256 === sha256(catalogBytes),
    'catalog digest does not bind the exact catalog bytes');
  validateProfileScope(input.profile_scope);

  exactKeys(input.source, SOURCE_KEYS, 'native source bindings');
  requireValue(COMMIT.test(input.source.binary_source_commit) &&
    COMMIT.test(input.source.harness_commit),
  'source and harness commits must be full Git SHAs');
  requireValue(input.source.source_dirty === false,
    'native plan requires clean source');
  for (const key of SOURCE_KEYS.filter((item) => item.endsWith('_sha256'))) {
    digest(input.source[key], `source.${key}`);
  }
  validateTopology(input.topology);
  validateSchedule(input.schedule);
  validateAcceptance(input.acceptance);
  validateResultContract(catalog);

  requireValue(Array.isArray(input.variants) && input.variants.length > 0,
    'native plan requires variants');
  input.variants.forEach((variant, index) =>
    validateVariant(variant, catalog, index));
  requireValue(input.variants.every((variant) =>
    input.profile_scope.includes(variant.profile)),
  'native variants must remain inside the profile scope');
  requireValue(new Set(input.variants.map((variant) => variant.id)).size ===
    input.variants.length, 'native variant IDs must be unique');
  requireCoverage(input.variants, catalog, input.profile_scope);

  const contract = {
    schema_version: 1,
    input,
    result_contract: NATIVE_RESULT_CONTRACT,
    points: schedulePoints(input.variants, input.schedule),
  };
  return {...contract, plan_id: canonicalHash(contract)};
}

export function validateProtocolNativePlan(plan, catalogBytes) {
  requireValue(plan?.schema_version === 1 &&
    typeof plan.plan_id === 'string' && SHA256.test(plan.plan_id),
  'native plan header is invalid');
  const rebuilt = buildProtocolNativePlan(plan.input, catalogBytes);
  requireValue(JSON.stringify(canonicalize(rebuilt)) ===
    JSON.stringify(canonicalize(plan)),
  'native plan differs from its deterministic contract');
  return plan;
}

function argument(name, argv) {
  const index = argv.indexOf(name);
  requireValue(index >= 0 && index + 1 < argv.length,
    `${name} is required`);
  return argv[index + 1];
}

function readRegular(filename, label) {
  const absolute = path.resolve(filename);
  const stat = fs.lstatSync(absolute);
  requireValue(stat.isFile() && !stat.isSymbolicLink(),
    `${label} must be a regular file`);
  return fs.readFileSync(absolute, 'utf8');
}

function writeNew(filename, value) {
  const absolute = path.resolve(filename);
  fs.mkdirSync(path.dirname(absolute), {recursive: true});
  fs.writeFileSync(absolute, `${JSON.stringify(value, null, 2)}\n`,
    {encoding: 'utf8', flag: 'wx', mode: 0o600});
}

function main() {
  const [, , command, ...argv] = process.argv;
  requireValue(['build', 'validate'].includes(command),
    'usage: phase5-protocol-native-plan.mjs build|validate --catalog FILE ...');
  const catalog = readRegular(argument('--catalog', argv), 'catalog');
  if (command === 'build') {
    const input = JSON.parse(readRegular(argument('--input', argv), 'plan input'));
    writeNew(argument('--output', argv), buildProtocolNativePlan(input, catalog));
    return;
  }
  const plan = JSON.parse(readRegular(argument('--plan', argv), 'plan'));
  validateProtocolNativePlan(plan, catalog);
  process.stdout.write(`${plan.plan_id}\n`);
}

if (process.argv[1] && import.meta.url ===
    pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-protocol-native-plan: ${error.message}\n`);
    process.exitCode = 1;
  }
}
