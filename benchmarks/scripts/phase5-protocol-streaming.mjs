#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

const PROFILE_IDS = Object.freeze([
  'P5-T01', 'P5-H01', 'P5-H02', 'P5-G01', 'P5-S01',
]);
const QUESTIONS = Object.freeze([
  'tls-response-boundary-cost',
  'downstream-http2-framing-hpack-flow-control',
  'end-to-end-http2-cost-and-lifecycle',
  'grpc-unary-cost-and-lifecycle',
  'incremental-sse-delivery-and-lifecycle',
]);
const PROFILE_CONTRACTS = Object.freeze([
  Object.freeze({
    downstream_protocols: Object.freeze(['https-http1']),
    upstream_protocols: Object.freeze(['none', 'http1']),
    payload_bytes: Object.freeze([15360, 16384, 17408, 65536]),
    scenarios: Object.freeze(['fixed-response', 'proxied-response']),
  }),
  Object.freeze({
    downstream_protocols: Object.freeze(['https-http2']),
    upstream_protocols: Object.freeze(['http1']),
    payload_bytes: Object.freeze([256, 8192, 65536]),
    scenarios: Object.freeze(['stable-headers', 'bounded-rotating-headers',
      'flow-control-window', 'mixed-short-long-streams']),
  }),
  Object.freeze({
    downstream_protocols: Object.freeze(['https-http2']),
    upstream_protocols: Object.freeze(['http2']),
    payload_bytes: Object.freeze([256, 8192, 65536]),
    scenarios: Object.freeze(['healthy', 'peer-cancel', 'deadline',
      'connection-reuse']),
  }),
  Object.freeze({
    downstream_protocols: Object.freeze(['grpc-h2']),
    upstream_protocols: Object.freeze(['grpc-h2']),
    payload_bytes: Object.freeze([256, 8192]),
    scenarios: Object.freeze(['healthy', 'deadline', 'peer-cancel',
      'malformed-message', 'invalid-trailers']),
  }),
  Object.freeze({
    downstream_protocols: Object.freeze(['https-http1', 'https-http2']),
    upstream_protocols: Object.freeze(['http1-chunked']),
    payload_bytes: Object.freeze([128]),
    scenarios: Object.freeze(['healthy-cadence', 'slow-consumer',
      'peer-cancel', 'upstream-stall', 'terminal-error',
      'missing-terminal-event']),
  }),
]);
const REQUIRED_METRICS = Object.freeze([
  'successful_rps',
  'application_cpu_percent',
  'host_cpu_percent',
  'irq_cpu_percent',
  'cycles_per_success',
  'instructions_per_success',
  'ipc',
  'allocations_per_success',
  'syscalls_per_success',
  'writes_per_success',
  'bytes_per_write',
  'p50_ms',
  'p95_ms',
  'p99_ms',
  'p999_reference_ms',
  'ttfb_ms',
  'first_semantic_event_ms',
  'maximum_event_gap_ms',
  'delivery_bytes_per_second',
  'rss_bytes',
  'file_descriptors',
  'memory_per_active_stream_bytes',
  'active_streams',
  'cancellation_cleanup_ms',
  'queue_waits',
  'per_shard_work',
]);
const FROZEN_FIELDS = Object.freeze([
  'offered_rate',
  'duration_seconds',
  'concurrency',
  'connections',
  'stream_count',
  'event_count',
  'event_interval_ms',
  'slow_consumer_read_rate_bytes_per_second',
  'request_and_idle_deadlines_ms',
  'ttfb_ceiling_ms',
  'event_gap_ceiling_ms',
  'p95_ceiling_ms',
  'p99_ceiling_ms',
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

function exactArray(value, expected, label) {
  requireValue(Array.isArray(value) &&
    JSON.stringify(value) === JSON.stringify(expected), `${label} changed`);
}

function positiveInteger(value, label) {
  requireValue(Number.isSafeInteger(value) && value > 0,
    `${label} must be a positive integer`);
}

function validateProfile(profile, index) {
  exactKeys(profile, ['id', 'question', 'downstream_protocols',
    'upstream_protocols', 'payload_bytes', 'scenarios'],
  `profile ${index + 1}`);
  requireValue(profile.id === PROFILE_IDS[index],
    `profile ${index + 1} ID or ordering changed`);
  requireValue(profile.question === QUESTIONS[index],
    `${profile.id} question changed`);
  for (const [name, value] of [
    ['downstream_protocols', profile.downstream_protocols],
    ['upstream_protocols', profile.upstream_protocols],
    ['scenarios', profile.scenarios],
  ]) {
    requireValue(Array.isArray(value) && value.length > 0 &&
      new Set(value).size === value.length &&
      value.every((item) => typeof item === 'string' && item.length > 0),
    `${profile.id} ${name} is invalid`);
  }
  requireValue(Array.isArray(profile.payload_bytes) &&
    profile.payload_bytes.length > 0 &&
    new Set(profile.payload_bytes).size === profile.payload_bytes.length,
  `${profile.id} payload sizes are invalid`);
  for (const size of profile.payload_bytes) positiveInteger(size,
    `${profile.id} payload size`);
  const contract = PROFILE_CONTRACTS[index];
  for (const key of ['downstream_protocols', 'upstream_protocols',
    'payload_bytes', 'scenarios']) {
    exactArray(profile[key], contract[key], `${profile.id} ${key}`);
  }
}

export function validateProtocolStreamingCatalog(input) {
  exactKeys(input, ['schema_version', 'checkpoint', 'evidence_class',
    'publication_authorized', 'measurement_environments', 'protocol_contract',
    'profiles', 'required_metrics', 'fixed_correctness_gates',
    'calibration_rule', 'excluded_claims'], 'PERF-05 catalog');
  requireValue(input.schema_version === 1, 'PERF-05 schema version invalid');
  requireValue(input.checkpoint === 'PERF-05', 'checkpoint must remain PERF-05');
  requireValue(input.evidence_class === 'engineering-only' &&
    input.publication_authorized === false,
  'PERF-05 contract cannot authorize publication claims');

  exactKeys(input.measurement_environments,
    ['local_preflight_core_count', 'native_core_counts', 'native_roles'],
    'measurement environments');
  requireValue(input.measurement_environments.local_preflight_core_count === 1,
    'local preflight must remain one core');
  exactArray(input.measurement_environments.native_core_counts, [8, 24],
    'native core counts');
  exactArray(input.measurement_environments.native_roles,
    ['load_generator', 'gateway', 'controlled_upstream'], 'native roles');

  exactKeys(input.protocol_contract, ['tls_version', 'tls_cipher_family',
    'certificate_validation', 'http2_alpn', 'http2_engine', 'grpc_scope',
    'streaming_grpc_qualified', 'sse_media_type',
    'sse_success_requires_terminal_event'], 'protocol contract');
  const contract = input.protocol_contract;
  requireValue(contract.tls_version === '1.3' &&
    contract.tls_cipher_family === 'AES' &&
    contract.certificate_validation === 'ca-and-hostname',
  'TLS contract changed');
  requireValue(contract.http2_alpn === 'h2' && contract.http2_engine === 'nghttp2',
    'HTTP/2 contract changed');
  requireValue(contract.grpc_scope === 'unary-only' &&
    contract.streaming_grpc_qualified === false,
  'streaming gRPC must remain outside PERF-05');
  requireValue(contract.sse_media_type === 'text/event-stream' &&
    contract.sse_success_requires_terminal_event === true,
  'SSE success contract changed');

  requireValue(Array.isArray(input.profiles) &&
    input.profiles.length === PROFILE_IDS.length,
  'PERF-05 profile count invalid');
  input.profiles.forEach(validateProfile);

  exactArray(input.required_metrics, REQUIRED_METRICS, 'required metrics');
  exactKeys(input.fixed_correctness_gates, [
    'unexpected_error_count', 'process_restart_count',
    'transport_failure_count', 'payload_and_event_order_exact',
    'tls_peer_and_hostname_verified', 'alpn_exact', 'maximum_cleanup_ms',
    'maximum_retained_rss_growth_bytes', 'maximum_retained_fd_growth',
    'final_active_streams', 'same_process_recovery_required',
    'support_role_capacity_limit_percent',
  ], 'fixed correctness gates');
  const gates = input.fixed_correctness_gates;
  requireValue(gates.unexpected_error_count === 0 &&
    gates.process_restart_count === 0 && gates.transport_failure_count === 0 &&
    gates.payload_and_event_order_exact === true &&
    gates.tls_peer_and_hostname_verified === true && gates.alpn_exact === true &&
    gates.maximum_cleanup_ms === 2000 &&
    gates.maximum_retained_rss_growth_bytes === 16777216 &&
    gates.maximum_retained_fd_growth === 4 && gates.final_active_streams === 0 &&
    gates.same_process_recovery_required === true &&
    gates.support_role_capacity_limit_percent === 80,
  'fixed correctness gates changed');

  exactKeys(input.calibration_rule, ['required_before_native_measurement',
    'freeze_before_measured_traffic', 'primary_latency_percentiles',
    'diagnostic_latency_percentiles'], 'calibration rule');
  requireValue(input.calibration_rule.required_before_native_measurement === true,
    'native measurement must require frozen calibration');
  exactArray(input.calibration_rule.freeze_before_measured_traffic,
    FROZEN_FIELDS, 'calibration fields');
  exactArray(input.calibration_rule.primary_latency_percentiles,
    ['p50', 'p95', 'p99'], 'primary latency percentiles');
  exactArray(input.calibration_rule.diagnostic_latency_percentiles,
    ['p99.9'], 'diagnostic latency percentiles');

  requireValue(Array.isArray(input.excluded_claims) &&
    input.excluded_claims.length === 6 &&
    input.excluded_claims.every((claim) => typeof claim === 'string' &&
      claim.length > 0), 'excluded claims are invalid');
  return input;
}

function main() {
  const [, , filename] = process.argv;
  requireValue(filename && process.argv.length === 3,
    'usage: phase5-protocol-streaming.mjs CATALOG.json');
  const absolute = path.resolve(filename);
  const stat = fs.lstatSync(absolute);
  requireValue(stat.isFile() && !stat.isSymbolicLink(),
    'PERF-05 catalog must be a regular file');
  const catalog = validateProtocolStreamingCatalog(
    JSON.parse(fs.readFileSync(absolute, 'utf8')));
  process.stdout.write(`${JSON.stringify(catalog)}\n`);
}

if (process.argv[1] && import.meta.url ===
    pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-protocol-streaming: ${error.message}\n`);
    process.exitCode = 1;
  }
}
