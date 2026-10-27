import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {buildProtocolNativePlan,
  NATIVE_RESULT_CONTRACT} from './phase5-protocol-native-plan.mjs';
import {analyzeProtocolNativeEvidence, buildProtocolNativeResults,
  evaluateProtocolNativePoint, summarizeProtocolNativeResults,
  validateProtocolNativeResult} from './phase5-protocol-native-result.mjs';
import {catalogBytes, digest,
  nativePlanInput} from './phase5-protocol-native-test-fixture.mjs';

function planFixture() {
  const bytes = catalogBytes();
  return {bytes, plan: buildProtocolNativePlan(nativePlanInput(bytes), bytes)};
}

function variantFor(plan, point) {
  return plan.input.variants.find((item) => item.id === point.variant_id);
}

function metricSetName(variant) {
  if (variant.measurement_class === 'throughput-cost') return 'throughput_cost';
  if (variant.measurement_class === 'stream-cost') return 'stream_cost';
  return variant.profile === 'P5-S01' ? 'lifecycle_sse' : 'lifecycle_h2_grpc';
}

function metricsFor(variant, repetition) {
  const metrics = Object.fromEntries(
    NATIVE_RESULT_CONTRACT.metric_sets[metricSetName(variant)]
      .map((name) => [name, 1]));
  const factor = 1 + (repetition - 3) * 0.0002;
  if (Object.hasOwn(metrics, 'successful_rps')) {
    metrics.successful_rps = variant.workload.target_rps * factor;
  }
  if (Object.hasOwn(metrics, 'delivery_bytes_per_second')) {
    metrics.delivery_bytes_per_second = 1000000 * factor;
  }
  Object.assign(metrics, {
    application_cpu_percent: 70,
    host_cpu_percent: 60,
    irq_cpu_percent: 2,
    rss_bytes: 48 * 1024 * 1024,
    file_descriptors: 32,
    active_streams: Object.hasOwn(metrics, 'active_streams') ?
      (variant.measurement_class === 'stream-cost' ?
        variant.workload.target_active_streams : 0) : undefined,
    p50_ms: Object.hasOwn(metrics, 'p50_ms') ? 1 : undefined,
    p95_ms: Object.hasOwn(metrics, 'p95_ms') ? 2 : undefined,
    p99_ms: Object.hasOwn(metrics, 'p99_ms') ? 3 : undefined,
    p999_reference_ms: Object.hasOwn(metrics, 'p999_reference_ms') ? 4 :
      undefined,
    ttfb_ms: Object.hasOwn(metrics, 'ttfb_ms') ? 1 : undefined,
    first_semantic_event_ms: Object.hasOwn(metrics,
      'first_semantic_event_ms') ? 2 : undefined,
    maximum_event_gap_ms: Object.hasOwn(metrics, 'maximum_event_gap_ms') ?
      40 : undefined,
    memory_per_active_stream_bytes: Object.hasOwn(metrics,
      'memory_per_active_stream_bytes') ? 4096 : undefined,
    cancellation_cleanup_ms: Object.hasOwn(metrics,
      'cancellation_cleanup_ms') ? 100 : undefined,
  });
  for (const key of Object.keys(metrics)) {
    if (metrics[key] === undefined) delete metrics[key];
  }
  metrics.queue_waits = {count: 0, maximum_ms: 0};
  metrics.per_shard_work = Array.from({length: variant.core_count},
    (_, shard) => ({shard, successful_operations: 1000, cpu_percent: 70}));
  return metrics;
}

function fileReference(pointId, name) {
  return {path: `${pointId}/${name}.json`, sha256: digest(`${pointId}:${name}`),
    bytes: 10};
}

function completeInput(plan, point, attempt = 1) {
  const variant = variantFor(plan, point);
  const tids = Array.from({length: variant.core_count},
    (_, index) => 1000 + index);
  const metrics = metricsFor(variant, point.repetition);
  return {
    schema_version: 1,
    plan_id: plan.plan_id,
    point_id: point.point_id,
    variant_id: variant.id,
    repetition: point.repetition,
    attempt,
    evidence_status: 'complete',
    invalid_reason: null,
    source: structuredClone(plan.input.source),
    catalog_sha256: plan.input.catalog_sha256,
    snapshot_sha256: variant.snapshot_sha256,
    execution: {
      roles: structuredClone(plan.input.topology.roles),
      load_generator_cpu_set: structuredClone(
        plan.input.topology.load_generator_cpu_set),
      load_generator_lanes: plan.input.topology.load_generator_lanes,
      gateway_cpu_set: structuredClone(
        plan.input.topology.gateway_cpu_sets[String(variant.core_count)]),
      gateway_housekeeping_cpus: structuredClone(
        plan.input.topology.gateway_housekeeping_cpus),
      irq_policy: structuredClone(plan.input.topology.irq_policy),
      profiler_scope: NATIVE_RESULT_CONTRACT.profiler_scope,
      reactor_tids_before: [...tids],
      reactor_tids_after: [...tids],
      profiled_reactor_tids: [...tids],
    },
    protocol: {
      downstream_tls_version: 'TLSv1.3',
      downstream_tls_cipher: 'TLS_AES_256_GCM_SHA384',
      downstream_peer_certificate_verified: true,
      downstream_hostname_verified: true,
      downstream_alpn: variant.downstream_protocol === 'https-http1' ?
        'http/1.1' : 'h2',
      upstream_protocol: variant.upstream_protocol,
      semantic_outcome: variant.expected_outcome,
      payload_or_event_order_exact: true,
    },
    runtime: {
      gateway_process_identity_before: 'pid:42:start:100',
      gateway_process_identity_after: 'pid:42:start:100',
      gateway_restart_count: 0,
      same_process_recovery: true,
      support_role_capacity_percent: {
        load_generator: 40,
        controlled_upstream: 45,
      },
      final_active_streams: 0,
      maximum_cleanup_ms: variant.measurement_class === 'lifecycle' ? 100 : null,
      retained_rss_growth_bytes: 1024,
      retained_fd_growth: 0,
      unexpected_error_count: 0,
      transport_failure_count: 0,
      pre_overload_error_rate: 0,
    },
    metrics,
    files: {
      capture_archive: fileReference(point.point_id, 'capture'),
      derivation_manifest: fileReference(point.point_id, 'derivation'),
      environment: fileReference(point.point_id, 'environment'),
    },
  };
}

function invalidInput(plan, point, attempt = 1) {
  const variant = variantFor(plan, point);
  return {
    schema_version: 1,
    plan_id: plan.plan_id,
    point_id: point.point_id,
    variant_id: variant.id,
    repetition: point.repetition,
    attempt,
    evidence_status: 'invalid',
    invalid_reason: 'collector-failure',
    source: structuredClone(plan.input.source),
    catalog_sha256: plan.input.catalog_sha256,
    snapshot_sha256: variant.snapshot_sha256,
    execution: null,
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

function campaignInputs(plan) {
  return plan.points.map((point) => completeInput(plan, point));
}

test('complete normalized PERF-05 campaign passes without publication authority', () => {
  const {bytes, plan} = planFixture();
  const results = buildProtocolNativeResults(campaignInputs(plan), plan, bytes);
  const summary = summarizeProtocolNativeResults(plan, bytes, results);
  assert.equal(summary.result_documents, 283);
  assert.equal(summary.complete_points, 283);
  assert.equal(summary.repetition_groups.length, 47);
  assert.equal(summary.gates.evidence_complete, true);
  assert.equal(summary.gates.all_points_pass, true);
  assert.equal(summary.gates.repeatability_pass, true);
  assert.equal(summary.gates.decision, 'pass');
  assert.equal(summary.publication_authorized, false);
  assert.equal(Object.values(summary.profiles).every((profile) => profile.pass),
    true);
});

test('P5-T01-only campaign summarizes only its explicit plan scope', () => {
  const bytes = catalogBytes();
  const input = nativePlanInput(bytes);
  input.profile_scope = ['P5-T01'];
  input.variants = input.variants.filter((item) => item.profile === 'P5-T01');
  const plan = buildProtocolNativePlan(input, bytes);
  const results = buildProtocolNativeResults(campaignInputs(plan), plan, bytes);
  const summary = summarizeProtocolNativeResults(plan, bytes, results);
  assert.equal(summary.result_documents, 80);
  assert.equal(summary.complete_points, 80);
  assert.deepEqual(Object.keys(summary.profiles), ['P5-T01']);
  assert.equal(summary.profiles['P5-T01'].pass, true);
  assert.equal(summary.gates.decision, 'pass');
});

test('missing point remains incomplete and invalid attempt stays visible', () => {
  const {bytes, plan} = planFixture();
  const inputs = campaignInputs(plan);
  const first = plan.points[0];
  inputs.shift();
  const incomplete = summarizeProtocolNativeResults(plan, bytes,
    buildProtocolNativeResults(inputs, plan, bytes));
  assert.equal(incomplete.gates.decision, 'incomplete');
  assert.deepEqual(incomplete.missing_points, [first.point_id]);

  const retried = campaignInputs(plan);
  retried[0].attempt = 2;
  retried.push(invalidInput(plan, first, 1));
  const accepted = summarizeProtocolNativeResults(plan, bytes,
    buildProtocolNativeResults(retried, plan, bytes));
  assert.equal(accepted.gates.decision, 'pass');
  assert.equal(accepted.invalid_attempts, 1);
});

test('duplicate complete attempts cannot enable result selection', () => {
  const {bytes, plan} = planFixture();
  const inputs = campaignInputs(plan);
  inputs.push(completeInput(plan, plan.points[0], 2));
  const results = buildProtocolNativeResults(inputs, plan, bytes);
  assert.throws(() => summarizeProtocolNativeResults(plan, bytes, results),
    /duplicate complete native result/u);
});

test('source, topology, profiler, metric, and result identity drift fail closed', () => {
  const {bytes, plan} = planFixture();
  const source = completeInput(plan, plan.points[0]);
  source.source.gateway_binary_sha256 = digest('substitute');
  assert.throws(() => buildProtocolNativeResults([source], plan, bytes),
    /source or artifact bindings differ/u);

  const cpu = completeInput(plan, plan.points[0]);
  cpu.execution.gateway_cpu_set[0] = 0;
  assert.throws(() => buildProtocolNativeResults([cpu], plan, bytes),
    /gateway_cpu_set differs/u);

  const loadgen = completeInput(plan, plan.points[0]);
  loadgen.execution.load_generator_lanes = 4;
  assert.throws(() => buildProtocolNativeResults([loadgen], plan, bytes),
    /load_generator_lanes differs/u);

  const profiler = completeInput(plan, plan.points[0]);
  profiler.execution.profiler_scope = 'process-leader-only';
  assert.throws(() => buildProtocolNativeResults([profiler], plan, bytes),
    /does not cover all reactor threads/u);

  const metric = completeInput(plan, plan.points[0]);
  delete metric.metrics.instructions_per_success;
  assert.throws(() => buildProtocolNativeResults([metric], plan, bytes),
    /missing or unexpected keys/u);

  const result = buildProtocolNativeResults([
    completeInput(plan, plan.points[0])], plan, bytes)[0];
  result.protocol.semantic_outcome = 'forged';
  assert.throws(() => validateProtocolNativeResult(result, plan, bytes),
    /deterministic contract/u);
});

test('observed product, protocol, resource, and latency failures are retained', () => {
  const {bytes, plan} = planFixture();
  const inputs = campaignInputs(plan);
  inputs[0].protocol.downstream_tls_cipher = 'TLS_CHACHA20_POLY1305_SHA256';
  inputs[1].protocol.semantic_outcome = 'wrong-result';
  inputs[2].runtime.gateway_restart_count = 1;
  inputs[3].runtime.gateway_process_identity_after = 'pid:43:start:200';
  inputs[4].runtime.support_role_capacity_percent.load_generator = 90;
  inputs[5].runtime.retained_rss_growth_bytes = 32 * 1024 * 1024;
  inputs[6].metrics.p95_ms = 100;
  inputs[6].metrics.p99_ms = 200;
  inputs[6].metrics.p999_reference_ms = 300;
  const lifecycleIndex = inputs.findIndex((input) =>
    variantFor(plan, plan.points.find((point) =>
      point.point_id === input.point_id)).measurement_class === 'lifecycle');
  inputs[lifecycleIndex].runtime.maximum_cleanup_ms = 3000;
  inputs[lifecycleIndex].metrics.cancellation_cleanup_ms = 3000;
  const summary = summarizeProtocolNativeResults(plan, bytes,
    buildProtocolNativeResults(inputs, plan, bytes));
  assert.equal(summary.gates.evidence_complete, true);
  assert.equal(summary.gates.all_points_pass, false);
  assert.equal(summary.gates.decision, 'fail');
  assert.equal(summary.complete_points, 283);
});

test('more than five-percent repetition variation fails the campaign', () => {
  const {bytes, plan} = planFixture();
  const inputs = campaignInputs(plan);
  const variantId = plan.input.variants.find((item) =>
    item.measurement_class === 'throughput-cost').id;
  const changed = inputs.find((input) => input.variant_id === variantId &&
    input.repetition === 5);
  changed.metrics.successful_rps *= 1.2;
  const summary = summarizeProtocolNativeResults(plan, bytes,
    buildProtocolNativeResults(inputs, plan, bytes));
  assert.equal(summary.gates.repeatability_pass, false);
  assert.equal(summary.gates.decision, 'fail');
  assert.ok(summary.repetition_groups.find((group) =>
    group.variant_id === variantId).maximum_deviation_percent > 5);
});

test('throughput below the frozen offered rate fails every affected point', () => {
  const {bytes, plan} = planFixture();
  const inputs = campaignInputs(plan);
  const variant = plan.input.variants.find((item) =>
    item.measurement_class === 'throughput-cost');
  for (const input of inputs.filter((item) => item.variant_id === variant.id)) {
    input.metrics.successful_rps = variant.workload.target_rps * 0.99;
  }
  const summary = summarizeProtocolNativeResults(plan, bytes,
    buildProtocolNativeResults(inputs, plan, bytes));
  const affected = summary.rows.filter((row) => row.variant_id === variant.id);
  assert.equal(affected.length, plan.input.schedule.throughput_repetitions);
  assert.equal(affected.every((row) =>
    row.gates.offered_rate_attainment_pass === false), true);
  assert.equal(summary.repetition_groups.find((group) =>
    group.variant_id === variant.id).pass, true);
  assert.equal(summary.gates.decision, 'fail');
});

test('single-point evaluation uses the same formal gates as campaign analysis', () => {
  const {bytes, plan} = planFixture();
  const point = plan.points.find((item) =>
    variantFor(plan, item).measurement_class === 'throughput-cost');
  const passing = buildProtocolNativeResults([
    completeInput(plan, point)], plan, bytes)[0];
  assert.equal(evaluateProtocolNativePoint(passing, plan, bytes).pass, true);

  const failingInput = completeInput(plan, point);
  failingInput.runtime.retained_fd_growth =
    plan.input.acceptance.maximum_retained_fd_growth + 1;
  const failing = buildProtocolNativeResults([failingInput], plan, bytes)[0];
  const evaluation = evaluateProtocolNativePoint(failing, plan, bytes);
  assert.equal(evaluation.pass, false);
  assert.equal(evaluation.gates.descriptor_containment_pass, false);
});

function writeBound(root, relative, contents) {
  const filename = path.join(root, relative);
  fs.mkdirSync(path.dirname(filename), {recursive: true});
  fs.writeFileSync(filename, contents);
  return {path: relative,
    sha256: crypto.createHash('sha256').update(contents).digest('hex'),
    bytes: Buffer.byteLength(contents)};
}

function writeManifest(root) {
  const files = [];
  const walk = (directory, relative = '') => {
    for (const name of fs.readdirSync(directory)) {
      const child = path.posix.join(relative, name);
      if (child === 'checksums.sha256') continue;
      const absolute = path.join(root, child);
      const stat = fs.lstatSync(absolute);
      if (stat.isDirectory()) walk(absolute, child);
      else files.push(child);
    }
  };
  walk(root);
  files.sort();
  fs.writeFileSync(path.join(root, 'checksums.sha256'), files.map((name) =>
    `${crypto.createHash('sha256').update(
      fs.readFileSync(path.join(root, name))).digest('hex')}  ${name}`).join('\n') +
    '\n');
}

test('evidence loader verifies manifest, result, and referenced bytes', (t) => {
  const {bytes, plan} = planFixture();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'perf05-result-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const input = completeInput(plan, plan.points[0]);
  input.files = {
    capture_archive: writeBound(root, 'point/capture.bin', 'capture'),
    derivation_manifest: writeBound(root, 'point/derivation.json', '{}'),
    environment: writeBound(root, 'point/environment.json', '{}'),
  };
  const result = buildProtocolNativeResults([input], plan, bytes)[0];
  fs.writeFileSync(path.join(root, 'point.result.json'), JSON.stringify(result));
  writeManifest(root);
  const summary = analyzeProtocolNativeEvidence(plan, bytes, root);
  assert.equal(summary.gates.decision, 'incomplete');
  assert.equal(summary.complete_points, 1);

  fs.writeFileSync(path.join(root, 'point/capture.bin'), 'tampered');
  assert.throws(() => analyzeProtocolNativeEvidence(plan, bytes, root),
    /checksum mismatch/u);
});

test('evidence loader rejects checksum-bound but unreferenced files', (t) => {
  const {bytes, plan} = planFixture();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'perf05-unreferenced-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const input = completeInput(plan, plan.points[0]);
  input.files = {
    capture_archive: writeBound(root, 'point/capture.bin', 'capture'),
    derivation_manifest: writeBound(root, 'point/derivation.json', '{}'),
    environment: writeBound(root, 'environment.json', '{}'),
  };
  const result = buildProtocolNativeResults([input], plan, bytes)[0];
  fs.writeFileSync(path.join(root, 'point.result.json'), JSON.stringify(result));
  fs.writeFileSync(path.join(root, 'orphan.log'), 'not owned by any result');
  writeManifest(root);
  assert.throws(() => analyzeProtocolNativeEvidence(plan, bytes, root),
    /unreferenced files/u);
});

test('evidence loader rejects point-owned archive reuse', (t) => {
  const {bytes, plan} = planFixture();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'perf05-reuse-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const sharedCapture = writeBound(root, 'shared/capture.bin', 'capture');
  const environment = writeBound(root, 'environment.json', '{}');
  const inputs = plan.points.slice(0, 2).map((point, index) => {
    const input = completeInput(plan, point);
    input.files = {
      capture_archive: sharedCapture,
      derivation_manifest: writeBound(root,
        `point-${index}/derivation.json`, JSON.stringify({index})),
      environment,
    };
    return input;
  });
  const results = buildProtocolNativeResults(inputs, plan, bytes);
  for (const [index, result] of results.entries()) {
    fs.writeFileSync(path.join(root, `point-${index}.result.json`),
      JSON.stringify(result));
  }
  writeManifest(root);
  assert.throws(() => analyzeProtocolNativeEvidence(plan, bytes, root),
    /point-owned evidence file reused/u);
});
