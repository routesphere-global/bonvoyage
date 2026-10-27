import assert from 'node:assert/strict';
import test from 'node:test';

import {buildProtocolNativePlan, NATIVE_RESULT_CONTRACT,
  validateProtocolNativePlan} from './phase5-protocol-native-plan.mjs';
import {catalogBytes, digest,
  nativePlanInput as input} from './phase5-protocol-native-test-fixture.mjs';

test('native PERF-05 plan is deterministic and self-validating', () => {
  const bytes = catalogBytes();
  const first = buildProtocolNativePlan(input(bytes), bytes);
  const second = buildProtocolNativePlan(input(bytes), bytes);
  assert.deepEqual(first, second);
  assert.equal(first.input.variants.length, 63);
  assert.equal(first.points.length, 283);
  assert.equal(validateProtocolNativePlan(first, bytes), first);
  assert.match(first.plan_id, /^[0-9a-f]{64}$/u);
  assert.deepEqual(first.result_contract, NATIVE_RESULT_CONTRACT);
  assert.equal(first.result_contract.profiler_scope,
    'all-stable-seastar-reactor-tids');
  assert.equal(first.result_contract.required_tls_version, 'TLSv1.3');
  assert.equal(first.result_contract.required_tls_cipher_family, 'AES');
  assert.equal(first.result_contract.metric_sets.throughput_cost
    .includes('first_semantic_event_ms'), false);
  assert.equal(first.result_contract.metric_sets.stream_cost
    .includes('first_semantic_event_ms'), true);
  assert.equal(first.result_contract.metric_sets.lifecycle_h2_grpc
    .includes('first_semantic_event_ms'), false);
  assert.equal(first.result_contract.metric_sets.lifecycle_sse
    .includes('first_semantic_event_ms'), true);
});

test('native schedule has distinct five-run cost and three-run lifecycle IDs', () => {
  const plan = buildProtocolNativePlan(input(), catalogBytes());
  const measured = plan.input.variants.filter((item) =>
    item.measurement_class !== 'lifecycle');
  const lifecycle = plan.input.variants.filter((item) =>
    item.measurement_class === 'lifecycle');
  assert.equal(plan.points.length, measured.length * 5 + lifecycle.length * 3);
  assert.equal(new Set(plan.points.map((point) => point.point_id)).size,
    plan.points.length);
  for (const item of measured) {
    assert.deepEqual(plan.points.filter((point) => point.variant_id === item.id)
      .map((point) => point.repetition), [1, 2, 3, 4, 5]);
  }
  for (const item of lifecycle) {
    assert.deepEqual(plan.points.filter((point) => point.variant_id === item.id)
      .map((point) => point.repetition), [1, 2, 3]);
  }
  const firstMeasured = plan.points.filter((point) =>
    point.group === 'measured' && point.repetition === 1);
  const secondMeasured = plan.points.filter((point) =>
    point.group === 'measured' && point.repetition === 2);
  assert.deepEqual(secondMeasured.map((point) => point.variant_id),
    firstMeasured.map((point) => point.variant_id).reverse());
});

test('native plan supports an exact P5-T01-only campaign scope', () => {
  const bytes = catalogBytes();
  const scoped = input(bytes);
  scoped.profile_scope = ['P5-T01'];
  scoped.variants = scoped.variants.filter((item) => item.profile === 'P5-T01');
  const plan = buildProtocolNativePlan(scoped, bytes);
  assert.equal(plan.input.variants.length, 16);
  assert.equal(plan.points.length, 80);
  assert.equal(plan.points.every((point) =>
    point.variant_id.startsWith('t01-')), true);
  assert.equal(validateProtocolNativePlan(plan, bytes), plan);
});

test('native plan rejects dirty, unbound, or publication-authorized evidence', () => {
  const bytes = catalogBytes();
  const dirty = input(bytes);
  dirty.source.source_dirty = true;
  assert.throws(() => buildProtocolNativePlan(dirty, bytes), /clean source/u);

  const catalogDrift = input(bytes);
  catalogDrift.catalog_sha256 = digest('different catalog');
  assert.throws(() => buildProtocolNativePlan(catalogDrift, bytes),
    /exact catalog bytes/u);

  const publication = input(bytes);
  publication.publication_authorized = true;
  assert.throws(() => buildProtocolNativePlan(publication, bytes),
    /cannot authorize publication/u);

  const artifact = input(bytes);
  artifact.source.gateway_binary_sha256 = 'not-a-digest';
  assert.throws(() => buildProtocolNativePlan(artifact, bytes), /SHA-256/u);
});

test('native plan rejects incomplete profile, payload, core, and SSE coverage', () => {
  const bytes = catalogBytes();
  const missingTls = input(bytes);
  missingTls.variants = missingTls.variants.filter((item) =>
    item.id !== 't01-fixed-response-15360-8c');
  assert.throws(() => buildProtocolNativePlan(missingTls, bytes),
    /P5-T01 coverage missing/u);

  const missingH2 = input(bytes);
  missingH2.variants = missingH2.variants.filter((item) =>
    item.id !== 'h01-stable-65536-24c');
  assert.throws(() => buildProtocolNativePlan(missingH2, bytes),
    /stable-header payload coverage missing/u);

  const missingChunk = input(bytes);
  missingChunk.variants = missingChunk.variants.filter((item) =>
    item.id !== 's01-cadence-h2-24c-1b');
  assert.throws(() => buildProtocolNativePlan(missingChunk, bytes),
    /one-byte chunk coverage missing/u);
});

test('native plan rejects invalid scope ordering and out-of-scope variants', () => {
  const bytes = catalogBytes();
  const order = input(bytes);
  order.profile_scope = ['P5-H01', 'P5-T01'];
  assert.throws(() => buildProtocolNativePlan(order, bytes),
    /canonical profile order/u);

  const outside = input(bytes);
  outside.profile_scope = ['P5-T01'];
  assert.throws(() => buildProtocolNativePlan(outside, bytes),
    /inside the profile scope/u);
});

test('native plan rejects role, CPU, private-address, and IRQ overlap', () => {
  const bytes = catalogBytes();
  const duplicateHost = input(bytes);
  duplicateHost.topology.roles[2].host_id = 'gateway-01';
  assert.throws(() => buildProtocolNativePlan(duplicateHost, bytes),
    /distinct hosts/u);

  const publicAddress = input(bytes);
  publicAddress.topology.roles[0].private_address = '203.0.113.10';
  assert.throws(() => buildProtocolNativePlan(publicAddress, bytes),
    /private IPv4/u);

  const overlap = input(bytes);
  overlap.topology.gateway_housekeeping_cpus[7] = 8;
  assert.throws(() => buildProtocolNativePlan(overlap, bytes), /disjoint/u);

  const loadLanes = input(bytes);
  loadLanes.topology.load_generator_lanes = 33;
  assert.throws(() => buildProtocolNativePlan(loadLanes, bytes),
    /load-generator lane count/u);

  const loadCpu = input(bytes);
  loadCpu.topology.load_generator_cpu_set[31] = 0;
  assert.throws(() => buildProtocolNativePlan(loadCpu, bytes),
    /load-generator CPU set/u);

  const irq = input(bytes);
  irq.topology.irq_policy.irq_target_cpus = [8];
  assert.throws(() => buildProtocolNativePlan(irq, bytes),
    /housekeeping CPUs/u);
});

test('native plan rejects weaker gates, repetitions, and scenario semantics', () => {
  const bytes = catalogBytes();
  const gate = input(bytes);
  gate.acceptance.maximum_cleanup_ms = 5000;
  assert.throws(() => buildProtocolNativePlan(gate, bytes),
    /acceptance gates changed/u);

  const repetitions = input(bytes);
  repetitions.schedule.throughput_repetitions = 4;
  assert.throws(() => buildProtocolNativePlan(repetitions, bytes),
    /five repetitions/u);

  const warmups = input(bytes);
  warmups.schedule.profiled_warmup_repetitions = 2;
  assert.throws(() => buildProtocolNativePlan(warmups, bytes),
    /exactly three profiled warmup repetitions/u);

  const fixedUpstream = input(bytes);
  fixedUpstream.variants.find((item) =>
    item.id === 't01-fixed-response-15360-8c').upstream_protocol = 'http1';
  assert.throws(() => buildProtocolNativePlan(fixedUpstream, bytes),
    /fixed\/proxied upstream contract/u);

  const lifecycleClass = input(bytes);
  lifecycleClass.variants.find((item) =>
    item.id === 'h02-peer-cancel-256-8c').measurement_class = 'throughput-cost';
  assert.throws(() => buildProtocolNativePlan(lifecycleClass, bytes),
    /measurement class/u);

  const weakSlowConsumer = input(bytes);
  weakSlowConsumer.variants.find((item) =>
    item.id === 's01-slow-consumer-h1-8c').workload.event_payload_bytes = 128;
  weakSlowConsumer.variants.find((item) =>
    item.id === 's01-slow-consumer-h1-8c').workload.upstream_chunk_bytes = 128;
  assert.throws(() => buildProtocolNativePlan(weakSlowConsumer, bytes),
    /large slow-consumer event/u);
});

test('native plan validation detects point and identity tampering', () => {
  const bytes = catalogBytes();
  const plan = buildProtocolNativePlan(input(bytes), bytes);
  const point = structuredClone(plan);
  point.points[0].order = 2;
  assert.throws(() => validateProtocolNativePlan(point, bytes),
    /deterministic contract/u);

  const identity = structuredClone(plan);
  identity.plan_id = digest('tampered plan');
  assert.throws(() => validateProtocolNativePlan(identity, bytes),
    /deterministic contract/u);
});
