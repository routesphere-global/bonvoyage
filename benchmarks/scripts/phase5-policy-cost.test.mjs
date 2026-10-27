import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {analyzePolicyCostEvidence, buildPolicyCostPlan,
  buildPolicyCostResult, summarizePolicyCostResults,
  validatePolicyCostPlan} from './phase5-policy-cost.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const catalogBytes = fs.readFileSync(path.join(root,
  'benchmarks/workloads/policy-cost/phase5-policy-cost.json'));

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function planInput() {
  return {
    schema_version: 2,
    evidence_class: 'shared-vm-directional',
    catalog_sha256: digest(catalogBytes),
    source: {
      binary_source_commit: '1'.repeat(40),
      harness_commit: '2'.repeat(40),
      source_dirty: false,
      gateway_binary_sha256: digest('gateway'),
      client_sha256: digest('client'),
      upstream_sha256: digest('upstream'),
      collector_bundle_sha256: digest('collectors'),
      tls_bundle_sha256: digest('tls'),
    },
    topology: {
      roles: [
        {role: 'load_generator', host_id: 'load-1',
          private_address: '10.0.0.10'},
        {role: 'gateway', host_id: 'gateway-1',
          private_address: '10.0.0.20'},
        {role: 'controlled_upstream', host_id: 'upstream-1',
          private_address: '10.0.0.30'},
      ],
      gateway_cpu_set: Array.from({length: 24}, (_, index) => index + 8),
      housekeeping_cpu_set: Array.from({length: 8}, (_, index) => index),
      load_generator_cpu_set: Array.from({length: 16}, (_, index) => index),
      irq_policy: 'irqbalance-with-gateway-ban',
      load_generator_lanes: 8,
      controlled_upstream: {port: 8081, max_connections_per_shard: 128},
    },
    artifacts: {
      p5_b02_snapshot_sha256: digest('b02-snapshot'),
      profile_snapshot_sha256: Object.fromEntries(
        ['P5-C00', 'P5-C01', 'P5-C02', 'P5-C03', 'P5-C04', 'P5-C05']
          .map((id) => [id, digest(`${id}-snapshot`)])),
      header_transform_request_sha256: digest('header-input'),
      api_key_credential_sha256: digest('api-key-file'),
      jwt_jwks_sha256: digest('jwt-jwks'),
    },
    workload: {
      offered_rps_by_payload: {'256': 24000, '8192': 12000},
      connections: 256,
      warmup_seconds: 60,
      measurement_seconds: 60,
      request_timeout_ms: 5000,
      maximum_cleanup_ms: 5000,
      minimum_delivery_ratio: 0.95,
      p95_ceiling_ms: 50,
      p99_ceiling_ms: 500,
      maximum_support_capacity_percent: 80,
      maximum_retained_rss_growth_bytes: 16 * 1024 * 1024,
      maximum_retained_fd_growth: 4,
    },
    jwt: {
      algorithm: 'RS256',
      maximum_age_seconds_at_start: 60,
      minimum_remaining_lifetime_seconds_at_end: 30,
    },
  };
}

function planInputV3() {
  const value = planInput();
  value.schema_version = 3;
  value.workload.profiled_warmup_repetitions = 3;
  value.jwt.maximum_age_seconds_at_start = 210;
  return value;
}

function plan() {
  return buildPolicyCostPlan(planInput(), catalogBytes);
}

function fileReference(pointId, name, content = `${pointId}:${name}`) {
  const bytes = Buffer.from(content);
  return {path: `evidence/${pointId}/${name}.json`,
    sha256: digest(bytes), bytes: bytes.length};
}

function completeInput(value, point, attempt = 1) {
  const jwt = point.request.mode === 'ephemeral-jwt';
  const artifact = point.request.mode === 'none' ? null :
    (jwt ? digest(`${point.profile_id}-jwt`) :
      point.request.planned_artifact_sha256);
  const factor = point.profile_id === 'P5-B02' || point.profile_id === 'P5-C00' ?
    1 : 1.1;
  const successfulRps = point.offered_rps * 0.99;
  const runtime = {
    gateway_process_identity_before: 'pid:42:start:100',
    gateway_process_identity_after: 'pid:42:start:100',
    gateway_restart_count: 0,
    support_role_capacity_percent: {
      load_generator: 40,
      controlled_upstream: 45,
    },
    rss_before_bytes: 100 * 1024 * 1024,
    rss_after_bytes: 100 * 1024 * 1024 + 1024,
    fd_before: 100,
    fd_after: 100,
    unexpected_error_count: 0,
    transport_failure_count: 0,
  };
  if (value.schema_version >= 2) {
    runtime.descriptor_attribution = {
      total_fd_growth: 0,
      controlled_upstream_connections_before: 10,
      controlled_upstream_connections_after: 10,
      controlled_upstream_connection_growth: 0,
      controlled_upstream_connection_limit: 3072,
      controlled_upstream_connections_bounded: true,
      non_controlled_descriptors_before: 90,
      non_controlled_descriptors_after: 90,
      unaccounted_fd_growth: 0,
    };
  }
  return {
    schema_version: value.schema_version,
    plan_id: value.plan_id,
    point_id: point.point_id,
    profile_id: point.profile_id,
    attempt,
    evidence_status: 'complete',
    invalid_reason: null,
    source: structuredClone(value.input.source),
    snapshot_sha256: point.snapshot_sha256,
    request: {
      mode: point.request.mode,
      header_names: structuredClone(point.request.header_names),
      artifact_sha256: artifact,
      values_retained: false,
      jwt_window: jwt ? {
        issued_at_epoch_ms: 100000,
        expires_at_epoch_ms: 400000,
        measurement_started_at_epoch_ms: 120000,
        measurement_ended_at_epoch_ms: 180000,
      } : null,
    },
    protocol: {
      downstream_tls_version: 'TLSv1.3',
      downstream_tls_cipher: 'TLS_AES_256_GCM_SHA384',
      peer_certificate_verified: true,
      hostname_verified: true,
      alpn: 'http/1.1',
      status_code: 200,
      semantic_validated: true,
      response_payload_bytes: point.response_payload_bytes,
    },
    runtime,
    metrics: {
      offered_rps: point.offered_rps,
      successful_rps: successfulRps,
      successful_responses: successfulRps *
        value.input.workload.measurement_seconds,
      active_measurement_seconds: value.input.workload.measurement_seconds,
      application_cpu_percent: 50 * factor,
      host_cpu_percent: 45 * factor,
      irq_cpu_percent: 2,
      p50_ms: 1 * factor,
      p95_ms: 2 * factor,
      p99_ms: 3 * factor,
      p999_reference_ms: 4 * factor,
      cycles_per_success: 100000 * factor,
      instructions_per_success: 120000 * factor,
      ipc: 1.2,
      allocations_per_success: 2 * factor,
      syscalls_per_success: 4 * factor,
      socket_writes_per_success: 1 * factor,
      socket_bytes_per_write: point.response_payload_bytes,
      queue_waits_per_success: 0,
      per_shard_cpu_percent: Array(24).fill(50 * factor),
    },
    files: {
      capture_archive: fileReference(point.point_id, 'capture'),
      derivation_manifest: fileReference(point.point_id, 'derivation'),
      environment: fileReference(point.point_id, 'environment'),
    },
  };
}

function completeResults(value = plan()) {
  return value.points.map((point) =>
    buildPolicyCostResult(completeInput(value, point), value, catalogBytes));
}

function setDescriptorCounts(input, beforePool, afterPool, beforeOther,
  afterOther) {
  input.runtime.fd_before = beforePool + beforeOther;
  input.runtime.fd_after = afterPool + afterOther;
  input.runtime.descriptor_attribution = {
    total_fd_growth: input.runtime.fd_after - input.runtime.fd_before,
    controlled_upstream_connections_before: beforePool,
    controlled_upstream_connections_after: afterPool,
    controlled_upstream_connection_growth: afterPool - beforePool,
    controlled_upstream_connection_limit: 3072,
    controlled_upstream_connections_bounded:
      beforePool <= 3072 && afterPool <= 3072,
    non_controlled_descriptors_before: beforeOther,
    non_controlled_descriptors_after: afterOther,
    unaccounted_fd_growth: afterOther - beforeOther,
  };
}

function invalidInput(value, point) {
  return {
    schema_version: value.schema_version,
    plan_id: value.plan_id,
    point_id: point.point_id,
    profile_id: point.profile_id,
    attempt: 1,
    evidence_status: 'invalid',
    invalid_reason: 'collector-failure',
    source: structuredClone(value.input.source),
    snapshot_sha256: point.snapshot_sha256,
    request: null,
    protocol: null,
    runtime: null,
    metrics: null,
    files: {
      partial_archive: fileReference(point.point_id, 'partial'),
      attempt_log: fileReference(point.point_id, 'attempt'),
      environment: fileReference(point.point_id, 'invalid-environment'),
    },
  };
}

test('policy plan is deterministic, 24-core, directional, and payload matched', () => {
  const value = plan();
  assert.deepEqual(value, buildPolicyCostPlan(planInput(), catalogBytes));
  assert.equal(validatePolicyCostPlan(value, catalogBytes), value);
  assert.equal(value.points.length, 7);
  assert.deepEqual(value.points.map((point) => point.profile_id),
    ['P5-B02', 'P5-C00', 'P5-C01', 'P5-C02', 'P5-C03', 'P5-C04', 'P5-C05']);
  assert.equal(value.points.every((point) => point.core_count === 24), true);
  assert.equal(value.points.every((point) => point.repetition === 1), true);
  assert.equal(value.schema_version, 2);
  assert.deepEqual(value.input.topology.controlled_upstream,
    {port: 8081, max_connections_per_shard: 128});
  assert.equal(value.publication_authorized, false);
  assert.equal(value.points[0].request_path, '/payload/256');
  for (const point of value.points.slice(1)) {
    assert.equal(point.request_path,
      `/policy/payload/${point.response_payload_bytes}`);
  }
  for (const point of value.points.filter((item) => item.control_profile_id)) {
    const control = value.points.find((item) =>
      item.profile_id === point.control_profile_id);
    assert.equal(control.response_payload_bytes, point.response_payload_bytes);
    assert.equal(control.offered_rps, point.offered_rps);
  }
});

test('legacy v1 policy plans and results remain replayable', () => {
  const input = planInput();
  delete input.schema_version;
  delete input.topology.controlled_upstream;
  const value = buildPolicyCostPlan(input, catalogBytes);
  assert.equal(value.schema_version, 1);
  assert.equal(validatePolicyCostPlan(value, catalogBytes), value);
  const result = buildPolicyCostResult(completeInput(value, value.points[0]),
    value, catalogBytes);
  assert.equal(result.schema_version, 1);
  assert.equal(result.runtime.descriptor_attribution, undefined);
});

test('policy v3 binds three profiled warmups to a 300-second JWT window', () => {
  const value = buildPolicyCostPlan(planInputV3(), catalogBytes);
  assert.equal(value.schema_version, 3);
  assert.equal(value.input.workload.profiled_warmup_repetitions, 3);
  assert.equal(validatePolicyCostPlan(value, catalogBytes), value);
  const result = buildPolicyCostResult(completeInput(value, value.points[0]),
    value, catalogBytes);
  assert.equal(result.schema_version, 3);
  assert.equal(result.runtime.descriptor_attribution.unaccounted_fd_growth, 0);

  const repetitions = planInputV3();
  repetitions.workload.profiled_warmup_repetitions = 2;
  assert.throws(() => buildPolicyCostPlan(repetitions, catalogBytes),
    /must remain three/u);

  const freshness = planInputV3();
  freshness.jwt.maximum_age_seconds_at_start = 180;
  assert.throws(() => buildPolicyCostPlan(freshness, catalogBytes),
    /cannot cover profiled warmup/u);

  const schedule = planInputV3();
  schedule.jwt.minimum_remaining_lifetime_seconds_at_end = 60;
  assert.throws(() => buildPolicyCostPlan(schedule, catalogBytes),
    /cannot fit the 300-second token lifetime/u);
});

test('policy v4 preserves the frozen workload while changing evidence shape',
  () => {
    const input = planInputV3();
    input.schema_version = 4;
    const value = buildPolicyCostPlan(input, catalogBytes);
    assert.equal(value.schema_version, 4);
    assert.equal(value.input.workload.profiled_warmup_repetitions, 3);
    assert.equal(validatePolicyCostPlan(value, catalogBytes), value);
    const result = buildPolicyCostResult(completeInput(value, value.points[0]),
      value, catalogBytes);
    assert.equal(result.schema_version, 4);
  });

test('policy plan rejects dirty source, placement, and workload drift', () => {
  const dirty = planInput();
  dirty.source.source_dirty = true;
  assert.throws(() => buildPolicyCostPlan(dirty, catalogBytes), /clean source/u);

  const overlap = planInput();
  overlap.topology.housekeeping_cpu_set[0] = 8;
  assert.throws(() => buildPolicyCostPlan(overlap, catalogBytes), /overlap/u);

  const rate = planInput();
  rate.workload.offered_rps_by_payload['256'] = 24001;
  assert.throws(() => buildPolicyCostPlan(rate, catalogBytes), /divide/u);

  const connections = planInput();
  connections.workload.connections = 255;
  assert.throws(() => buildPolicyCostPlan(connections, catalogBytes),
    /connections must divide/u);

  const clientCpus = planInput();
  clientCpus.topology.load_generator_cpu_set.pop();
  assert.throws(() => buildPolicyCostPlan(clientCpus, catalogBytes),
    /load-generator CPU set/u);

  const timeout = planInput();
  timeout.workload.request_timeout_ms = 10000;
  assert.throws(() => buildPolicyCostPlan(timeout, catalogBytes),
    /timeout must remain 5000 ms/u);

  const missingJwks = planInput();
  delete missingJwks.artifacts.jwt_jwks_sha256;
  assert.throws(() => buildPolicyCostPlan(missingJwks, catalogBytes),
    /missing or unexpected keys/u);

  const tamperedCatalog = Buffer.from(catalogBytes);
  tamperedCatalog[0] = 0x20;
  assert.throws(() => buildPolicyCostPlan(planInput(), tamperedCatalog),
    /catalog digest/u);
});

test('complete policy results produce five control-relative directional deltas', () => {
  const value = plan();
  const summary = summarizePolicyCostResults(value, catalogBytes,
    completeResults(value));
  assert.equal(summary.expected_points, 7);
  assert.equal(summary.complete_points, 7);
  assert.equal(summary.invalid_attempts, 0);
  assert.deepEqual(summary.missing_points, []);
  assert.equal(summary.point_gates.every((gate) => gate.pass), true);
  assert.equal(summary.policy_deltas.length, 5);
  assert.equal(summary.decision, 'directional-complete');
  assert.equal(summary.publication_authorized, false);
  assert.deepEqual(summary.policy_deltas.map((item) =>
    [item.profile_id, item.control_profile_id]), [
    ['P5-C01', 'P5-B02'], ['P5-C02', 'P5-C00'],
    ['P5-C03', 'P5-C00'], ['P5-C04', 'P5-B02'],
    ['P5-C05', 'P5-C00'],
  ]);
  assert.equal(summary.policy_deltas.every((item) =>
    Math.abs(item.instructions_per_success_delta_percent - 10) < 1e-9), true);
});

test('descriptor gates allow bounded pool retention but reject unexplained growth',
  () => {
    const value = plan();
    const poolGrowth = value.points.map((point) => completeInput(value, point));
    setDescriptorCounts(poolGrowth[0], 10, 30, 90, 90);
    let summary = summarizePolicyCostResults(value, catalogBytes,
      poolGrowth.map((input) => buildPolicyCostResult(input, value,
        catalogBytes)));
    assert.equal(summary.point_gates[0].controlled_upstream_descriptors, true);
    assert.equal(summary.point_gates[0].unaccounted_descriptors, true);
    assert.equal(summary.point_gates[0].resources, true);
    assert.equal(summary.decision, 'directional-complete');

    const unrelated = value.points.map((point) => completeInput(value, point));
    setDescriptorCounts(unrelated[0], 10, 10, 90, 95);
    summary = summarizePolicyCostResults(value, catalogBytes,
      unrelated.map((input) => buildPolicyCostResult(input, value,
        catalogBytes)));
    assert.equal(summary.point_gates[0].unaccounted_descriptors, false);
    assert.equal(summary.point_gates[0].resources, false);
    assert.equal(summary.decision, 'product-failure');
  });

test('descriptor gates reject pool overflow and shrinking-pool concealment', () => {
  const value = plan();
  const overflow = value.points.map((point) => completeInput(value, point));
  setDescriptorCounts(overflow[0], 10, 3073, 90, 90);
  let summary = summarizePolicyCostResults(value, catalogBytes,
    overflow.map((input) => buildPolicyCostResult(input, value, catalogBytes)));
  assert.equal(summary.point_gates[0].controlled_upstream_descriptors, false);
  assert.equal(summary.decision, 'product-failure');

  const shrinking = value.points.map((point) => completeInput(value, point));
  setDescriptorCounts(shrinking[0], 30, 10, 90, 95);
  summary = summarizePolicyCostResults(value, catalogBytes,
    shrinking.map((input) => buildPolicyCostResult(input, value, catalogBytes)));
  assert.equal(shrinking[0].runtime.descriptor_attribution.total_fd_growth, -15);
  assert.equal(shrinking[0].runtime.descriptor_attribution.unaccounted_fd_growth,
    5);
  assert.equal(summary.point_gates[0].unaccounted_descriptors, false);
  assert.equal(summary.decision, 'product-failure');
});

test('missing and invalid points remain incomplete without result selection', () => {
  const value = plan();
  const inputs = completeResults(value);
  inputs.shift();
  inputs.push(buildPolicyCostResult(invalidInput(value, value.points[0]),
    value, catalogBytes));
  const summary = summarizePolicyCostResults(value, catalogBytes, inputs);
  assert.equal(summary.decision, 'incomplete');
  assert.equal(summary.invalid_attempts, 1);
  assert.deepEqual(summary.missing_points, [value.points[0].point_id]);

  const duplicate = completeResults(value);
  duplicate.push(buildPolicyCostResult(completeInput(value, value.points[0], 2),
    value, catalogBytes));
  assert.throws(() => summarizePolicyCostResults(value, catalogBytes, duplicate),
    /duplicate complete/u);
});

test('observed semantic, latency, and runtime failures remain product failures', () => {
  const value = plan();
  const inputs = value.points.map((point) => completeInput(value, point));
  inputs[2].protocol.semantic_validated = false;
  inputs[3].metrics.p95_ms = 60;
  inputs[3].metrics.p99_ms = 70;
  inputs[3].metrics.p999_reference_ms = 80;
  inputs[4].runtime.gateway_restart_count = 1;
  const results = inputs.map((input) =>
    buildPolicyCostResult(input, value, catalogBytes));
  const summary = summarizePolicyCostResults(value, catalogBytes, results);
  assert.equal(summary.decision, 'product-failure');
  assert.equal(summary.point_gates.filter((gate) => !gate.pass).length, 3);
});

test('support saturation invalidates evidence without blaming the product', () => {
  const value = plan();
  const inputs = value.points.map((point) => completeInput(value, point));
  inputs[0].runtime.support_role_capacity_percent.load_generator = 81;
  const results = inputs.map((input) =>
    buildPolicyCostResult(input, value, catalogBytes));
  const summary = summarizePolicyCostResults(value, catalogBytes, results);
  assert.equal(summary.decision, 'incomplete');
  assert.deepEqual(summary.environment_invalid_points,
    [value.points[0].point_id]);
});

test('result contract rejects retained values, stale JWTs, and source drift', () => {
  const value = plan();
  const header = completeInput(value, value.points[2]);
  header.request.values_retained = true;
  assert.throws(() => buildPolicyCostResult(header, value, catalogBytes),
    /must not retain/u);

  const jwt = completeInput(value, value.points[5]);
  jwt.request.jwt_window.issued_at_epoch_ms = 1;
  assert.throws(() => buildPolicyCostResult(jwt, value, catalogBytes),
    /not fresh/u);

  const source = completeInput(value, value.points[0]);
  source.source.gateway_binary_sha256 = digest('substitute');
  assert.throws(() => buildPolicyCostResult(source, value, catalogBytes),
    /identity differs/u);

  const unexpected = completeInput(value, value.points[0]);
  unexpected.request.secret_value = 'must-never-exist';
  assert.throws(() => buildPolicyCostResult(unexpected, value, catalogBytes),
    /unexpected keys/u);

  const rate = completeInput(value, value.points[0]);
  rate.metrics.successful_responses -= 60;
  assert.throws(() => buildPolicyCostResult(rate, value, catalogBytes),
    /disagrees with response count/u);

  const duration = completeInput(value, value.points[0]);
  duration.metrics.active_measurement_seconds = 55;
  assert.throws(() => buildPolicyCostResult(duration, value, catalogBytes),
    /differs from plan/u);

  const ipc = completeInput(value, value.points[0]);
  ipc.metrics.ipc = 1.5;
  assert.throws(() => buildPolicyCostResult(ipc, value, catalogBytes),
    /ipc disagrees/u);
});

test('filesystem analyzer verifies every referenced evidence file', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'p5-policy-cost-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const value = plan();
  for (const point of value.points) {
    const input = completeInput(value, point);
    for (const [name, reference] of Object.entries(input.files)) {
      const absolute = path.join(directory, reference.path);
      fs.mkdirSync(path.dirname(absolute), {recursive: true});
      const contentName = name === 'capture_archive' ? 'capture' :
        (name === 'derivation_manifest' ? 'derivation' : name);
      fs.writeFileSync(absolute, `${point.point_id}:${contentName}`);
    }
    const result = buildPolicyCostResult(input, value, catalogBytes);
    fs.writeFileSync(path.join(directory, `${point.point_id}.result.json`),
      `${JSON.stringify(result, null, 2)}\n`);
  }
  const summary = analyzePolicyCostEvidence(value, catalogBytes, directory);
  assert.equal(summary.decision, 'directional-complete');

  fs.appendFileSync(path.join(directory,
    `evidence/${value.points[0].point_id}/capture.json`), 'tamper');
  assert.throws(() => analyzePolicyCostEvidence(value, catalogBytes, directory),
    /identity mismatch/u);
});
