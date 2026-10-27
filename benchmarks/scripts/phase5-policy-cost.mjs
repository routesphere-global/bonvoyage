#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import {isIP} from 'node:net';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';

import {validatePolicyCatalog} from './phase5-policy-workloads.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/u;
const CORE_COUNT = 24;
export const POLICY_COST_PROFILED_WARMUP_REPETITIONS = 3;
const PROFILE_ORDER = Object.freeze([
  'P5-B02', 'P5-C00', 'P5-C01', 'P5-C02', 'P5-C03', 'P5-C04', 'P5-C05',
]);
const CONTROL_BY_PROFILE = Object.freeze({
  'P5-C01': 'P5-B02',
  'P5-C02': 'P5-C00',
  'P5-C03': 'P5-C00',
  'P5-C04': 'P5-B02',
  'P5-C05': 'P5-C00',
});
const INVALID_REASONS = new Set([
  'interrupted', 'collector-failure', 'environment-drift', 'source-drift',
  'artifact-drift', 'load-generator-saturated', 'upstream-saturated',
  'semantic-observation-incomplete',
]);

export const POLICY_COST_CONTRACT = Object.freeze({
  latest_schema_version: 4,
  core_count: CORE_COUNT,
  repetitions: 1,
  evidence_class: 'shared-vm-directional',
  profiler_scope: 'all-stable-seastar-reactor-tids',
  publication_authorized: false,
  profile_order: PROFILE_ORDER,
});

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

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function digest(value, label) {
  requireValue(typeof value === 'string' && SHA256.test(value),
    `${label} must be a SHA-256 digest`);
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

function finite(value, label, minimum = 0, maximum = Number.POSITIVE_INFINITY) {
  requireValue(Number.isFinite(value) && value >= minimum && value <= maximum,
    `${label} must be between ${minimum} and ${maximum}`);
  return value;
}

function positive(value, label) {
  return finite(value, label, Number.MIN_VALUE);
}

function privateIpv4(value) {
  if (isIP(value) !== 4) return false;
  const octets = value.split('.').map(Number);
  return octets[0] === 10 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168);
}

function validateSource(value) {
  exactKeys(value, ['binary_source_commit', 'harness_commit', 'source_dirty',
    'gateway_binary_sha256', 'client_sha256', 'upstream_sha256',
    'collector_bundle_sha256', 'tls_bundle_sha256'], 'policy source');
  requireValue(COMMIT.test(value.binary_source_commit) &&
    COMMIT.test(value.harness_commit), 'policy source commits must be full SHAs');
  requireValue(value.source_dirty === false,
    'policy cost evidence requires clean source');
  for (const name of ['gateway_binary_sha256', 'client_sha256',
    'upstream_sha256', 'collector_bundle_sha256', 'tls_bundle_sha256']) {
    digest(value[name], `policy source ${name}`);
  }
}

function validateRoles(roles) {
  requireValue(Array.isArray(roles) && roles.length === 3,
    'policy topology requires three roles');
  const expected = ['load_generator', 'gateway', 'controlled_upstream'];
  requireValue(isDeepStrictEqual(roles.map((item) => item.role), expected),
    'policy topology role order changed');
  for (const [index, role] of roles.entries()) {
    exactKeys(role, ['role', 'host_id', 'private_address'],
      `policy topology role ${index}`);
    requireValue(typeof role.host_id === 'string' &&
      /^[A-Za-z0-9._-]{1,128}$/u.test(role.host_id),
    `policy topology role ${index} host ID invalid`);
    requireValue(privateIpv4(role.private_address),
      `policy topology role ${index} must use a private IPv4 address`);
  }
  requireValue(new Set(roles.map((item) => item.host_id)).size === roles.length &&
    new Set(roles.map((item) => item.private_address)).size === roles.length,
  'policy topology roles must be distinct');
}

function validateCpuSet(value, expectedLength, label) {
  requireValue(Array.isArray(value) && value.length === expectedLength &&
    new Set(value).size === value.length &&
    value.every((cpu) => Number.isSafeInteger(cpu) && cpu >= 0),
  `${label} must contain ${expectedLength} distinct CPUs`);
}

function validateTopology(value, schemaVersion) {
  const expected = ['roles', 'gateway_cpu_set', 'housekeeping_cpu_set',
    'load_generator_cpu_set', 'irq_policy', 'load_generator_lanes'];
  if (schemaVersion >= 2) expected.push('controlled_upstream');
  exactKeys(value, expected,
  'policy topology');
  validateRoles(value.roles);
  validateCpuSet(value.gateway_cpu_set, CORE_COUNT,
    'policy topology gateway_cpu_set');
  requireValue(Array.isArray(value.housekeeping_cpu_set) &&
    value.housekeeping_cpu_set.length > 0 &&
    new Set(value.housekeeping_cpu_set).size === value.housekeeping_cpu_set.length &&
    value.housekeeping_cpu_set.every((cpu) =>
      Number.isSafeInteger(cpu) && cpu >= 0),
  'policy topology housekeeping_cpu_set invalid');
  requireValue(value.gateway_cpu_set.every((cpu) =>
    !value.housekeeping_cpu_set.includes(cpu)),
  'policy gateway and housekeeping CPU sets overlap');
  requireValue(Array.isArray(value.load_generator_cpu_set) &&
    value.load_generator_cpu_set.length >= value.load_generator_lanes &&
    value.load_generator_cpu_set.length % value.load_generator_lanes === 0 &&
    new Set(value.load_generator_cpu_set).size ===
      value.load_generator_cpu_set.length &&
    value.load_generator_cpu_set.every((cpu) =>
      Number.isSafeInteger(cpu) && cpu >= 0),
  'policy load-generator CPU set is invalid for its lanes');
  requireValue(['irqbalance-with-gateway-ban', 'irqbalance-observed']
    .includes(value.irq_policy), 'policy IRQ profile is unsupported');
  integer(value.load_generator_lanes, 'policy load-generator lanes', 1);
  if (schemaVersion >= 2) {
    exactKeys(value.controlled_upstream,
      ['port', 'max_connections_per_shard'],
      'policy controlled-upstream descriptor contract');
    integer(value.controlled_upstream.port,
      'policy controlled-upstream port', 1);
    requireValue(value.controlled_upstream.port <= 65535,
      'policy controlled-upstream port exceeds TCP range');
    integer(value.controlled_upstream.max_connections_per_shard,
      'policy controlled-upstream connections per shard', 1);
    requireValue(value.controlled_upstream.max_connections_per_shard *
      CORE_COUNT <= 4096,
    'policy controlled-upstream descriptor bound exceeds collector capacity');
  }
}

function validateArtifacts(value) {
  exactKeys(value, ['p5_b02_snapshot_sha256', 'profile_snapshot_sha256',
    'header_transform_request_sha256', 'api_key_credential_sha256',
    'jwt_jwks_sha256'],
  'policy artifacts');
  digest(value.p5_b02_snapshot_sha256, 'P5-B02 snapshot');
  exactKeys(value.profile_snapshot_sha256,
    PROFILE_ORDER.filter((id) => id !== 'P5-B02'),
    'policy profile snapshots');
  for (const [id, valueDigest] of Object.entries(
    value.profile_snapshot_sha256)) {
    digest(valueDigest, `${id} snapshot`);
  }
  digest(value.header_transform_request_sha256,
    'header-transform request artifact');
  digest(value.api_key_credential_sha256, 'API-key credential artifact');
  digest(value.jwt_jwks_sha256, 'JWT JWKS artifact');
}

function validateWorkload(value, lanes, schemaVersion) {
  const expected = ['offered_rps_by_payload', 'connections', 'warmup_seconds',
    'measurement_seconds', 'request_timeout_ms', 'maximum_cleanup_ms',
    'minimum_delivery_ratio',
    'p95_ceiling_ms', 'p99_ceiling_ms',
    'maximum_support_capacity_percent',
    'maximum_retained_rss_growth_bytes', 'maximum_retained_fd_growth'];
  if (schemaVersion >= 3) expected.push('profiled_warmup_repetitions');
  exactKeys(value, expected, 'policy workload');
  exactKeys(value.offered_rps_by_payload, ['256', '8192'],
    'policy offered rates');
  for (const [payload, rate] of Object.entries(value.offered_rps_by_payload)) {
    integer(rate, `policy ${payload}-byte offered rate`, 1);
    requireValue(rate % lanes === 0,
      `policy ${payload}-byte offered rate must divide across client lanes`);
  }
  integer(value.connections, 'policy connections', lanes);
  requireValue(value.connections % lanes === 0,
    'policy connections must divide across client lanes');
  integer(value.warmup_seconds, 'policy warmup seconds', 1);
  if (schemaVersion >= 3) {
    requireValue(value.profiled_warmup_repetitions ===
      POLICY_COST_PROFILED_WARMUP_REPETITIONS,
    'policy profiled warmup repetitions must remain three');
  }
  integer(value.measurement_seconds, 'policy measurement seconds', 1);
  integer(value.request_timeout_ms, 'policy request timeout', 1);
  requireValue(value.request_timeout_ms === 5000,
    'policy request timeout must remain 5000 ms');
  integer(value.maximum_cleanup_ms, 'policy cleanup deadline', 1);
  finite(value.minimum_delivery_ratio, 'policy minimum delivery ratio', 0.9, 1);
  positive(value.p95_ceiling_ms, 'policy p95 ceiling');
  positive(value.p99_ceiling_ms, 'policy p99 ceiling');
  requireValue(value.p95_ceiling_ms < value.p99_ceiling_ms,
    'policy p95 ceiling must be below p99 ceiling');
  finite(value.maximum_support_capacity_percent,
    'policy support capacity ceiling', 1, 99);
  integer(value.maximum_retained_rss_growth_bytes,
    'policy retained RSS ceiling');
  integer(value.maximum_retained_fd_growth, 'policy retained FD ceiling');
}

function validateJwt(value, workload, schemaVersion) {
  exactKeys(value, ['algorithm', 'maximum_age_seconds_at_start',
    'minimum_remaining_lifetime_seconds_at_end'], 'policy JWT');
  requireValue(value.algorithm === 'RS256', 'policy JWT algorithm changed');
  integer(value.maximum_age_seconds_at_start,
    'policy JWT maximum age', 1);
  integer(value.minimum_remaining_lifetime_seconds_at_end,
    'policy JWT minimum remaining lifetime', 1);
  if (schemaVersion >= 3) {
    const warmupSeconds = workload.warmup_seconds *
      workload.profiled_warmup_repetitions;
    const safetySeconds = 10;
    requireValue(value.maximum_age_seconds_at_start <= 300 &&
      value.maximum_age_seconds_at_start >= warmupSeconds + safetySeconds,
    'policy JWT maximum age cannot cover profiled warmup admission');
    requireValue(warmupSeconds + workload.measurement_seconds +
      value.minimum_remaining_lifetime_seconds_at_end + safetySeconds <= 300,
    'policy JWT schedule cannot fit the 300-second token lifetime');
  }
}

function requestFor(profile, artifacts) {
  if (['P5-B02', 'P5-C00'].includes(profile.id)) {
    return {mode: 'none', header_names: [], planned_artifact_sha256: null};
  }
  if (['P5-C01', 'P5-C02'].includes(profile.id)) {
    return {mode: 'static-json', header_names: profile.request_header_names,
      planned_artifact_sha256: artifacts.header_transform_request_sha256};
  }
  if (profile.id === 'P5-C03') {
    return {mode: 'secret-file', header_names: profile.request_header_names,
      planned_artifact_sha256: artifacts.api_key_credential_sha256};
  }
  return {mode: 'ephemeral-jwt', header_names: profile.request_header_names,
    planned_artifact_sha256: null};
}

function pointProfile(catalog, id, input) {
  if (id === 'P5-B02') {
    return {id, feature: 'plain-proxy-control', response_payload_bytes: 256,
      bonvoyage_policy: 'none', request_header_names: [],
      snapshot_sha256: input.artifacts.p5_b02_snapshot_sha256};
  }
  const profile = catalog.profiles.find((item) => item.id === id);
  return {...profile,
    snapshot_sha256: input.artifacts.profile_snapshot_sha256[id]};
}

export function buildPolicyCostPlan(input, catalogBytes) {
  const schemaVersion = input?.schema_version ?? 1;
  requireValue([1, 2, 3, 4].includes(schemaVersion),
    'policy plan input schema version is unsupported');
  const inputKeys = ['evidence_class', 'catalog_sha256', 'source', 'topology',
    'artifacts', 'workload', 'jwt'];
  if (schemaVersion >= 2) inputKeys.push('schema_version');
  exactKeys(input, inputKeys, 'policy plan input');
  requireValue(input.evidence_class === POLICY_COST_CONTRACT.evidence_class,
    'policy plan is directional shared-VM evidence only');
  requireValue(Buffer.isBuffer(catalogBytes), 'policy catalog bytes required');
  requireValue(input.catalog_sha256 === sha256(catalogBytes),
    'policy catalog digest differs from input');
  const catalog = validatePolicyCatalog(JSON.parse(catalogBytes.toString('utf8')));
  validateSource(input.source);
  validateTopology(input.topology, schemaVersion);
  validateArtifacts(input.artifacts);
  validateWorkload(input.workload, input.topology.load_generator_lanes,
    schemaVersion);
  validateJwt(input.jwt, input.workload, schemaVersion);

  const points = PROFILE_ORDER.map((id, index) => {
    const profile = pointProfile(catalog, id, input);
    const payload = profile.response_payload_bytes;
    return {
      order: index + 1,
      point_id: `${id}-24c-directional-r1`,
      profile_id: id,
      control_profile_id: CONTROL_BY_PROFILE[id] ?? null,
      core_count: CORE_COUNT,
      repetition: 1,
      feature: profile.feature,
      bonvoyage_policy: profile.bonvoyage_policy,
      response_payload_bytes: payload,
      request_path: id === 'P5-B02' ? '/payload/256' :
        `/policy/payload/${payload}`,
      connections: input.workload.connections,
      request: requestFor(profile, input.artifacts),
      snapshot_sha256: profile.snapshot_sha256,
      offered_rps: input.workload.offered_rps_by_payload[String(payload)],
      measurement_seconds: input.workload.measurement_seconds,
    };
  });
  for (const point of points) {
    if (point.control_profile_id === null) continue;
    const control = points.find((item) =>
      item.profile_id === point.control_profile_id);
    requireValue(control && control.response_payload_bytes ===
      point.response_payload_bytes && control.offered_rps === point.offered_rps,
    `${point.profile_id} does not have a payload- and rate-matched control`);
  }
  const contract = {schema_version: schemaVersion, checkpoint: 'PERF-06', input,
    points,
    publication_authorized: false};
  return {...contract, plan_id: canonicalHash(contract)};
}

export function validatePolicyCostPlan(plan, catalogBytes) {
  exactKeys(plan, ['schema_version', 'checkpoint', 'input', 'points',
    'publication_authorized', 'plan_id'], 'policy plan');
  requireValue([1, 2, 3, 4].includes(plan.schema_version) &&
    plan.checkpoint === 'PERF-06' &&
    plan.publication_authorized === false && SHA256.test(plan.plan_id),
  'policy plan header invalid');
  requireValue(isDeepStrictEqual(plan,
    buildPolicyCostPlan(plan.input, catalogBytes)),
  'policy plan differs from its deterministic contract');
  return plan;
}

function fileReference(value, label) {
  exactKeys(value, ['path', 'sha256', 'bytes'], label);
  requireValue(typeof value.path === 'string' && SAFE_PATH.test(value.path) &&
    !value.path.endsWith('.result.json') && value.path !== 'checksums.sha256',
  `${label} path is unsafe`);
  digest(value.sha256, `${label} digest`);
  integer(value.bytes, `${label} bytes`, 1);
}

function validateFiles(value, status, label) {
  const expected = status === 'complete' ?
    ['capture_archive', 'derivation_manifest', 'environment'] :
    ['partial_archive', 'attempt_log', 'environment'];
  exactKeys(value, expected, `${label}.files`);
  const paths = [];
  for (const name of expected) {
    fileReference(value[name], `${label}.files.${name}`);
    paths.push(value[name].path);
  }
  requireValue(new Set(paths).size === paths.length,
    `${label} file references must be distinct`);
}

function locatePoint(plan, pointId, profileId) {
  const point = plan.points.find((item) => item.point_id === pointId);
  requireValue(point && point.profile_id === profileId,
    `policy result ${pointId} is outside the plan`);
  return point;
}

function validateRequest(value, point, plan, label) {
  exactKeys(value, ['mode', 'header_names', 'artifact_sha256',
    'values_retained', 'jwt_window'], label);
  requireValue(value.mode === point.request.mode &&
    isDeepStrictEqual(value.header_names, point.request.header_names),
  `${label} differs from the planned request shape`);
  requireValue(value.values_retained === false,
    `${label} must not retain credential or header values`);
  if (point.request.mode === 'none') {
    requireValue(value.artifact_sha256 === null && value.jwt_window === null,
      `${label} plain control must not bind a request artifact`);
    return;
  }
  digest(value.artifact_sha256, `${label}.artifact_sha256`);
  if (point.request.mode !== 'ephemeral-jwt') {
    requireValue(value.artifact_sha256 === point.request.planned_artifact_sha256 &&
      value.jwt_window === null, `${label} artifact differs from the plan`);
    return;
  }
  exactKeys(value.jwt_window, ['issued_at_epoch_ms', 'expires_at_epoch_ms',
    'measurement_started_at_epoch_ms', 'measurement_ended_at_epoch_ms'],
  `${label}.jwt_window`);
  const window = value.jwt_window;
  for (const [name, timestamp] of Object.entries(window)) {
    integer(timestamp, `${label}.jwt_window.${name}`, 1);
  }
  requireValue(window.issued_at_epoch_ms <= window.measurement_started_at_epoch_ms &&
    window.measurement_started_at_epoch_ms <= window.measurement_ended_at_epoch_ms &&
    window.measurement_ended_at_epoch_ms <= window.expires_at_epoch_ms,
  `${label} JWT lifetime does not cover measurement`);
  requireValue(window.measurement_started_at_epoch_ms - window.issued_at_epoch_ms <=
    plan.input.jwt.maximum_age_seconds_at_start * 1000,
  `${label} JWT was not fresh at measurement start`);
  requireValue(window.expires_at_epoch_ms - window.measurement_ended_at_epoch_ms >=
    plan.input.jwt.minimum_remaining_lifetime_seconds_at_end * 1000,
  `${label} JWT remaining lifetime is insufficient`);
}

function validateProtocol(value, point, label) {
  exactKeys(value, ['downstream_tls_version', 'downstream_tls_cipher',
    'peer_certificate_verified', 'hostname_verified', 'alpn', 'status_code',
    'semantic_validated', 'response_payload_bytes'], label);
  for (const name of ['downstream_tls_version', 'downstream_tls_cipher', 'alpn']) {
    requireValue(typeof value[name] === 'string' && value[name].length > 0,
      `${label}.${name} invalid`);
  }
  requireValue(typeof value.peer_certificate_verified === 'boolean' &&
    typeof value.hostname_verified === 'boolean' &&
    typeof value.semantic_validated === 'boolean',
  `${label} verification flags invalid`);
  integer(value.status_code, `${label}.status_code`, 100);
  requireValue(value.status_code <= 599, `${label}.status_code exceeds HTTP range`);
  integer(value.response_payload_bytes, `${label}.response_payload_bytes`);
  requireValue(value.response_payload_bytes === point.response_payload_bytes,
    `${label} response payload differs from plan`);
}

function validateDescriptorAttribution(value, runtime, plan, point, label) {
  exactKeys(value, ['total_fd_growth',
    'controlled_upstream_connections_before',
    'controlled_upstream_connections_after',
    'controlled_upstream_connection_growth',
    'controlled_upstream_connection_limit',
    'controlled_upstream_connections_bounded',
    'non_controlled_descriptors_before',
    'non_controlled_descriptors_after', 'unaccounted_fd_growth'], label);
  for (const name of ['total_fd_growth',
    'controlled_upstream_connection_growth', 'unaccounted_fd_growth']) {
    signedInteger(value[name], `${label}.${name}`);
  }
  for (const name of ['controlled_upstream_connections_before',
    'controlled_upstream_connections_after',
    'controlled_upstream_connection_limit',
    'non_controlled_descriptors_before',
    'non_controlled_descriptors_after']) {
    integer(value[name], `${label}.${name}`);
  }
  requireValue(typeof value.controlled_upstream_connections_bounded ===
    'boolean', `${label}.controlled_upstream_connections_bounded invalid`);
  const expectedLimit = plan.input.topology.controlled_upstream
    .max_connections_per_shard * point.core_count;
  requireValue(value.total_fd_growth === runtime.fd_after - runtime.fd_before &&
    value.controlled_upstream_connection_growth ===
      value.controlled_upstream_connections_after -
        value.controlled_upstream_connections_before &&
    value.non_controlled_descriptors_before === runtime.fd_before -
      value.controlled_upstream_connections_before &&
    value.non_controlled_descriptors_after === runtime.fd_after -
      value.controlled_upstream_connections_after &&
    value.unaccounted_fd_growth ===
      value.non_controlled_descriptors_after -
        value.non_controlled_descriptors_before,
  `${label} arithmetic disagrees with runtime descriptors`);
  requireValue(value.controlled_upstream_connection_limit === expectedLimit &&
    value.controlled_upstream_connections_bounded ===
      (value.controlled_upstream_connections_before <= expectedLimit &&
       value.controlled_upstream_connections_after <= expectedLimit),
  `${label} controlled-upstream bound differs from the plan`);
}

function validateRuntime(value, plan, point, label) {
  const expected = ['gateway_process_identity_before',
    'gateway_process_identity_after', 'gateway_restart_count',
    'support_role_capacity_percent', 'rss_before_bytes', 'rss_after_bytes',
    'fd_before', 'fd_after', 'unexpected_error_count',
    'transport_failure_count'];
  if (plan.schema_version >= 2) expected.push('descriptor_attribution');
  exactKeys(value, expected, label);
  for (const name of ['gateway_process_identity_before',
    'gateway_process_identity_after']) {
    requireValue(typeof value[name] === 'string' && value[name].length > 0,
      `${label}.${name} invalid`);
  }
  for (const name of ['gateway_restart_count', 'rss_before_bytes',
    'rss_after_bytes', 'fd_before', 'fd_after', 'unexpected_error_count',
    'transport_failure_count']) {
    integer(value[name], `${label}.${name}`);
  }
  exactKeys(value.support_role_capacity_percent,
    ['load_generator', 'controlled_upstream'],
    `${label}.support_role_capacity_percent`);
  for (const [name, percent] of Object.entries(
    value.support_role_capacity_percent)) {
    finite(percent, `${label}.support_role_capacity_percent.${name}`, 0, 100);
  }
  if (plan.schema_version >= 2) {
    validateDescriptorAttribution(value.descriptor_attribution, value, plan,
      point, `${label}.descriptor_attribution`);
  }
}

function validateMetrics(value, point, label) {
  exactKeys(value, ['offered_rps', 'successful_rps', 'successful_responses',
    'active_measurement_seconds', 'application_cpu_percent',
    'host_cpu_percent', 'irq_cpu_percent',
    'p50_ms', 'p95_ms', 'p99_ms', 'p999_reference_ms',
    'cycles_per_success', 'instructions_per_success', 'ipc',
    'allocations_per_success', 'syscalls_per_success',
    'socket_writes_per_success', 'socket_bytes_per_write',
    'queue_waits_per_success', 'per_shard_cpu_percent'], label);
  requireValue(value.offered_rps === point.offered_rps,
    `${label}.offered_rps differs from plan`);
  positive(value.successful_rps, `${label}.successful_rps`);
  integer(value.successful_responses, `${label}.successful_responses`, 1);
  positive(value.active_measurement_seconds,
    `${label}.active_measurement_seconds`);
  const durationTolerance = Math.max(1, point.measurement_seconds * 0.01);
  requireValue(Math.abs(value.active_measurement_seconds -
    point.measurement_seconds) <= durationTolerance,
  `${label}.active_measurement_seconds differs from plan`);
  const derivedSuccessfulRps = value.successful_responses /
    value.active_measurement_seconds;
  const rpsTolerance = Math.max(0.01, derivedSuccessfulRps * 1e-6);
  requireValue(Math.abs(value.successful_rps - derivedSuccessfulRps) <=
    rpsTolerance, `${label}.successful_rps disagrees with response count`);
  finite(value.application_cpu_percent,
    `${label}.application_cpu_percent`, Number.MIN_VALUE, 100);
  finite(value.host_cpu_percent, `${label}.host_cpu_percent`,
    Number.MIN_VALUE, 100);
  finite(value.irq_cpu_percent, `${label}.irq_cpu_percent`, 0, 100);
  for (const name of ['p50_ms', 'p95_ms', 'p99_ms', 'p999_reference_ms',
    'allocations_per_success', 'syscalls_per_success',
    'socket_writes_per_success', 'socket_bytes_per_write',
    'queue_waits_per_success']) {
    finite(value[name], `${label}.${name}`);
  }
  positive(value.cycles_per_success, `${label}.cycles_per_success`);
  positive(value.instructions_per_success, `${label}.instructions_per_success`);
  positive(value.ipc, `${label}.ipc`);
  positive(value.syscalls_per_success, `${label}.syscalls_per_success`);
  positive(value.socket_writes_per_success,
    `${label}.socket_writes_per_success`);
  positive(value.socket_bytes_per_write, `${label}.socket_bytes_per_write`);
  const derivedIpc = value.instructions_per_success / value.cycles_per_success;
  requireValue(Math.abs(value.ipc - derivedIpc) <= 0.001,
    `${label}.ipc disagrees with instructions and cycles`);
  requireValue(value.p50_ms <= value.p95_ms && value.p95_ms <= value.p99_ms &&
    value.p99_ms <= value.p999_reference_ms,
  `${label} latency percentiles are not monotonic`);
  requireValue(Array.isArray(value.per_shard_cpu_percent) &&
    value.per_shard_cpu_percent.length === point.core_count &&
    value.per_shard_cpu_percent.every((percent) =>
      Number.isFinite(percent) && percent >= 0 && percent <= 100),
  `${label}.per_shard_cpu_percent must cover every shard`);
}

export function buildPolicyCostResult(input, plan, catalogBytes) {
  validatePolicyCostPlan(plan, catalogBytes);
  exactKeys(input, ['schema_version', 'plan_id', 'point_id', 'profile_id',
    'attempt', 'evidence_status', 'invalid_reason', 'source',
    'snapshot_sha256', 'request', 'protocol', 'runtime', 'metrics', 'files'],
  'policy result input');
  requireValue(input.schema_version === plan.schema_version &&
    input.plan_id === plan.plan_id,
    'policy result header differs from plan');
  integer(input.attempt, 'policy result attempt', 1);
  const point = locatePoint(plan, input.point_id, input.profile_id);
  requireValue(isDeepStrictEqual(input.source, plan.input.source),
    'policy result source or artifact identity differs from plan');
  requireValue(input.snapshot_sha256 === point.snapshot_sha256,
    'policy result snapshot differs from plan');
  requireValue(['complete', 'invalid'].includes(input.evidence_status),
    'policy result evidence status invalid');
  validateFiles(input.files, input.evidence_status, 'policy result');
  if (input.evidence_status === 'invalid') {
    requireValue(INVALID_REASONS.has(input.invalid_reason),
      'policy result invalid reason is unsupported');
    requireValue(input.request === null && input.protocol === null &&
      input.runtime === null && input.metrics === null,
    'invalid policy result must not contain completed observations');
  } else {
    requireValue(input.invalid_reason === null,
      'complete policy result cannot have an invalid reason');
    validateRequest(input.request, point, plan, 'policy result request');
    validateProtocol(input.protocol, point, 'policy result protocol');
    validateRuntime(input.runtime, plan, point, 'policy result runtime');
    validateMetrics(input.metrics, point, 'policy result metrics');
  }
  const contract = {...input};
  return {...contract, result_id: canonicalHash(contract),
    publication_authorized: false};
}

export function validatePolicyCostResult(result, plan, catalogBytes) {
  exactKeys(result, ['schema_version', 'plan_id', 'point_id', 'profile_id',
    'attempt', 'evidence_status', 'invalid_reason', 'source',
    'snapshot_sha256', 'request', 'protocol', 'runtime', 'metrics', 'files',
    'result_id', 'publication_authorized'], 'policy result');
  requireValue(result.publication_authorized === false &&
    SHA256.test(result.result_id), 'policy result authority or ID invalid');
  const {result_id: ignoredId, publication_authorized: ignoredAuthority,
    ...input} = result;
  void ignoredId;
  void ignoredAuthority;
  requireValue(isDeepStrictEqual(result,
    buildPolicyCostResult(input, plan, catalogBytes)),
  'policy result differs from its deterministic contract');
  return result;
}

function pointPass(point, result, plan) {
  const protocol = result.protocol;
  const runtime = result.runtime;
  const metrics = result.metrics;
  const workload = plan.input.workload;
  const rssRetained = runtime.rss_after_bytes - runtime.rss_before_bytes <=
    workload.maximum_retained_rss_growth_bytes;
  const descriptorGates = plan.schema_version === 1 ? {
    resources: rssRetained && runtime.fd_after - runtime.fd_before <=
      workload.maximum_retained_fd_growth,
  } : {
    controlled_upstream_descriptors:
      runtime.descriptor_attribution.controlled_upstream_connections_bounded,
    unaccounted_descriptors:
      runtime.descriptor_attribution.unaccounted_fd_growth <=
        workload.maximum_retained_fd_growth,
    resources: rssRetained &&
      runtime.descriptor_attribution.controlled_upstream_connections_bounded &&
      runtime.descriptor_attribution.unaccounted_fd_growth <=
        workload.maximum_retained_fd_growth,
  };
  const gates = {
    tls: protocol.downstream_tls_version === 'TLSv1.3' &&
      protocol.downstream_tls_cipher.includes('AES') &&
      protocol.peer_certificate_verified && protocol.hostname_verified &&
      protocol.alpn === 'http/1.1',
    semantics: protocol.status_code === 200 && protocol.semantic_validated,
    delivery: metrics.successful_rps >=
      point.offered_rps * workload.minimum_delivery_ratio,
    latency: metrics.p95_ms <= workload.p95_ceiling_ms &&
      metrics.p99_ms <= workload.p99_ceiling_ms,
    support_headroom: Object.values(runtime.support_role_capacity_percent)
      .every((percent) => percent <= workload.maximum_support_capacity_percent),
    process_stable: runtime.gateway_restart_count === 0 &&
      runtime.gateway_process_identity_before ===
        runtime.gateway_process_identity_after,
    errors: runtime.unexpected_error_count === 0 &&
      runtime.transport_failure_count === 0,
    ...descriptorGates,
  };
  return {...gates, pass: Object.values(gates).every(Boolean)};
}

function percentDelta(candidate, control) {
  return (candidate - control) / control * 100;
}

function deltaFor(point, result, control) {
  const metrics = result.metrics;
  const baseline = control.metrics;
  return {
    profile_id: point.profile_id,
    control_profile_id: point.control_profile_id,
    response_payload_bytes: point.response_payload_bytes,
    offered_rps: point.offered_rps,
    application_cpu_delta_points: metrics.application_cpu_percent -
      baseline.application_cpu_percent,
    application_cpu_delta_percent: percentDelta(
      metrics.application_cpu_percent, baseline.application_cpu_percent),
    cycles_per_success_delta_percent: percentDelta(metrics.cycles_per_success,
      baseline.cycles_per_success),
    instructions_per_success_delta_percent: percentDelta(
      metrics.instructions_per_success, baseline.instructions_per_success),
    ipc_delta_percent: percentDelta(metrics.ipc, baseline.ipc),
    allocations_per_success_delta: metrics.allocations_per_success -
      baseline.allocations_per_success,
    syscalls_per_success_delta: metrics.syscalls_per_success -
      baseline.syscalls_per_success,
    socket_writes_per_success_delta: metrics.socket_writes_per_success -
      baseline.socket_writes_per_success,
    p95_delta_ms: metrics.p95_ms - baseline.p95_ms,
    p99_delta_ms: metrics.p99_ms - baseline.p99_ms,
  };
}

export function summarizePolicyCostResults(plan, catalogBytes, results) {
  validatePolicyCostPlan(plan, catalogBytes);
  requireValue(Array.isArray(results), 'policy results must be an array');
  const validated = results.map((result) =>
    validatePolicyCostResult(result, plan, catalogBytes));
  const attempts = new Set();
  const complete = new Map();
  let invalidAttempts = 0;
  for (const result of validated) {
    const attemptKey = `${result.point_id}:${result.attempt}`;
    requireValue(!attempts.has(attemptKey),
      `duplicate policy attempt: ${attemptKey}`);
    attempts.add(attemptKey);
    if (result.evidence_status === 'invalid') {
      invalidAttempts += 1;
      continue;
    }
    requireValue(!complete.has(result.point_id),
      `duplicate complete policy result: ${result.point_id}`);
    complete.set(result.point_id, result);
  }
  const missingPoints = plan.points.filter((point) =>
    !complete.has(point.point_id)).map((point) => point.point_id);
  const pointGates = [];
  for (const point of plan.points) {
    const result = complete.get(point.point_id);
    if (!result) continue;
    pointGates.push({point_id: point.point_id, profile_id: point.profile_id,
      ...pointPass(point, result, plan)});
  }
  const environmentInvalidPoints = pointGates.filter((gate) =>
    !gate.support_headroom).map((gate) => gate.point_id);
  const productGateNames = ['tls', 'semantics', 'delivery', 'latency',
    'process_stable', 'errors', 'resources'];
  const productFailure = pointGates.some((gate) =>
    productGateNames.some((name) => !gate[name]));
  const deltas = [];
  for (const point of plan.points) {
    if (point.control_profile_id === null) continue;
    const result = complete.get(point.point_id);
    const controlPoint = plan.points.find((item) =>
      item.profile_id === point.control_profile_id);
    const control = complete.get(controlPoint.point_id);
    if (result && control) deltas.push(deltaFor(point, result, control));
  }
  const decision = productFailure ? 'product-failure' :
    (missingPoints.length > 0 || environmentInvalidPoints.length > 0 ?
      'incomplete' : 'directional-complete');
  return {
    schema_version: plan.schema_version,
    checkpoint: 'PERF-06',
    plan_id: plan.plan_id,
    expected_points: plan.points.length,
    complete_points: complete.size,
    invalid_attempts: invalidAttempts,
    missing_points: missingPoints,
    environment_invalid_points: environmentInvalidPoints,
    point_gates: pointGates,
    policy_deltas: deltas,
    decision,
    evidence_class: POLICY_COST_CONTRACT.evidence_class,
    publication_authorized: false,
  };
}

function readRegular(filename, label, maximum = 64 * 1024 * 1024) {
  const stat = fs.lstatSync(filename);
  requireValue(stat.isFile() && !stat.isSymbolicLink() && stat.size <= maximum,
    `${label} must be a bounded regular non-symlink file`);
  return fs.readFileSync(filename);
}

function verifyReferencedFile(root, reference, label) {
  let absolute = path.resolve(root);
  for (const part of reference.path.split('/')) {
    absolute = path.join(absolute, part);
    const stat = fs.lstatSync(absolute);
    requireValue(!stat.isSymbolicLink(), `${label} cannot traverse a symlink`);
  }
  const bytes = readRegular(absolute, label, 1024 * 1024 * 1024);
  requireValue(bytes.length === reference.bytes &&
    sha256(bytes) === reference.sha256, `${label} identity mismatch`);
}

export function analyzePolicyCostEvidence(plan, catalogBytes, resultsRoot) {
  const root = path.resolve(resultsRoot);
  const stat = fs.lstatSync(root);
  requireValue(stat.isDirectory() && !stat.isSymbolicLink(),
    'policy results root must be a directory');
  const names = fs.readdirSync(root).filter((name) =>
    name.endsWith('.result.json')).sort();
  const results = names.map((name) => JSON.parse(readRegular(
    path.join(root, name), `policy result ${name}`).toString('utf8')));
  const referenced = new Set();
  for (const result of results) {
    validatePolicyCostResult(result, plan, catalogBytes);
    for (const [name, reference] of Object.entries(result.files)) {
      requireValue(!referenced.has(reference.path),
        `policy evidence file reused: ${reference.path}`);
      referenced.add(reference.path);
      verifyReferencedFile(root, reference,
        `${result.point_id} ${name}`);
    }
  }
  return summarizePolicyCostResults(plan, catalogBytes, results);
}

function options(argv, expected) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    requireValue(expected.includes(name) && index + 1 < argv.length &&
      !argv[index + 1].startsWith('--'), `invalid option: ${name ?? ''}`);
    requireValue(result[name] === undefined, `duplicate option: ${name}`);
    result[name] = argv[index + 1];
  }
  requireValue(isDeepStrictEqual(Object.keys(result).sort(), [...expected].sort()),
    'policy command options are incomplete');
  return result;
}

function writeExclusive(filename, value) {
  fs.writeFileSync(path.resolve(filename), `${JSON.stringify(value, null, 2)}\n`,
    {encoding: 'utf8', mode: 0o600, flag: 'wx'});
}

function main() {
  const [, , command, ...argv] = process.argv;
  if (command === 'build-plan') {
    const args = options(argv, ['--catalog', '--input', '--output']);
    const catalog = readRegular(path.resolve(args['--catalog']), 'policy catalog');
    const input = JSON.parse(readRegular(path.resolve(args['--input']),
      'policy plan input').toString('utf8'));
    writeExclusive(args['--output'], buildPolicyCostPlan(input, catalog));
    return;
  }
  if (command === 'analyze') {
    const args = options(argv,
      ['--catalog', '--plan', '--results', '--output']);
    const catalog = readRegular(path.resolve(args['--catalog']), 'policy catalog');
    const plan = JSON.parse(readRegular(path.resolve(args['--plan']),
      'policy plan').toString('utf8'));
    validatePolicyCostPlan(plan, catalog);
    writeExclusive(args['--output'], analyzePolicyCostEvidence(
      plan, catalog, args['--results']));
    return;
  }
  throw new Error('usage: phase5-policy-cost.mjs build-plan|analyze [options]');
}

if (process.argv[1] &&
    import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-policy-cost: ${error.message}\n`);
    process.exitCode = 1;
  }
}
