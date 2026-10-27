import assert from 'node:assert/strict';
import test from 'node:test';

import {buildBoundaryPlan, PAYLOAD_BYTES, PROTOCOLS, summarizeBoundary} from './response-boundary.mjs';

function fixture(repetitions = 5) {
  const plan = buildBoundaryPlan({repetitions, seed: 'test-seed'});
  const environment = {schema_version: 1, run_id: 'response-boundary-test',
    evidence_class: 'local-virtualized-engineering', publication_authorized: false,
    publication_reason: 'test fixture', source_commit: 'a'.repeat(40), source_dirty: false,
    gateway_image_id: 'sha256:' + '1'.repeat(64), compiler_image_id: 'sha256:' + '2'.repeat(64),
    upstream_image_id: 'sha256:' + '3'.repeat(64),
    load_generator_image_id: 'sha256:' + '4'.repeat(64),
    http_snapshot_sha256: '5'.repeat(64), https_snapshot_sha256: '6'.repeat(64),
    maximum_support_capacity_percent: 80, minimum_upstream_headroom_ratio: 1.2};
  const results = plan.points.map((point) => ({schema_version: 1, plan_id: plan.plan_id, ...point,
    successful_responses: 10000, successful_rps: 100000 * 8192 / point.payload_bytes,
    direct_upstream_rps: 200000 * 8192 / point.payload_bytes, upstream_headroom_ratio: 2,
    http_failures: 0, transport_failures: 0, error_rate: 0,
    latency_ms: {p50: 0.5, p95: 1, p99: 1.5, p999: 2},
    cpu_percent: {gateway: {mean: 180, maximum: 195}, upstream: {mean: 90, maximum: 110},
      load_generator: {mean: 100, maximum: 140}},
    capacity_percent: {gateway: {maximum: 97.5}, upstream: {maximum: 18.34},
      load_generator: {maximum: 35}},
    identities: {source_commit: environment.source_commit,
      gateway_image_id: environment.gateway_image_id,
      snapshot_sha256: point.protocol === 'http'
        ? environment.http_snapshot_sha256 : environment.https_snapshot_sha256},
    process: {restart_count: 0, oom_killed: false, exit_code: 0},
    diagnostic: {cycles_per_request: null, instructions_per_request: null,
      writes_per_request: null, bytes_per_write: null, downstream_flush_wait_ms: null}}));
  return {plan, environment, results};
}

test('plan contains every protocol, payload and repetition exactly once', () => {
  const plan = buildBoundaryPlan({repetitions: 5, seed: 'stable'});
  assert.equal(plan.points.length, 5 * PAYLOAD_BYTES.length * PROTOCOLS.length);
  assert.deepEqual(plan, buildBoundaryPlan({repetitions: 5, seed: 'stable'}));
  assert.equal(new Set(plan.points.map((point) =>
    `${point.protocol}:${point.payload_bytes}:${point.repetition}`)).size, plan.points.length);
});

test('complete five-repetition evidence is retained for native qualification', () => {
  const input = fixture();
  const summary = summarizeBoundary(input);
  assert.equal(summary.decision, 'retain-for-native-qualification');
  assert.equal(summary.groups.length, PAYLOAD_BYTES.length * PROTOCOLS.length);
  assert.equal(summary.gates.repeatability_pass, true);
  assert.equal(summary.groups[0].diagnostic.instructions_per_request, null);
  assert.equal(summary.boundary.http.byte_throughput_ratio_at_vs_below, 1);
});

test('single-repetition evidence is classified only as a preflight', () => {
  const summary = summarizeBoundary(fixture(1));
  assert.equal(summary.decision, 'preflight-pass');
  assert.equal(summary.gates.repeatability_evaluable, false);
  assert.equal(summary.gates.repeatability_pass, false);
});

test('missing and duplicate results fail closed', () => {
  const missing = fixture();
  missing.results.pop();
  assert.throws(() => summarizeBoundary(missing), /expected 60 results/);
  const duplicate = fixture();
  duplicate.results[1] = structuredClone(duplicate.results[0]);
  assert.throws(() => summarizeBoundary(duplicate), /duplicate result identity/);
});

test('errors, support saturation and process replacement fail closed', () => {
  for (const mutate of [
    (value) => { value.results[0].http_failures = 1; value.results[0].error_rate = 0.001; },
    (value) => { value.results[0].capacity_percent.upstream.maximum = 81; },
    (value) => { value.results[0].process.restart_count = 1; },
    (value) => { value.results[0].process.oom_killed = true; },
    (value) => { value.results[0].direct_upstream_rps = value.results[0].successful_rps;
      value.results[0].upstream_headroom_ratio = 1; },
  ]) {
    const input = fixture();
    mutate(input);
    assert.throws(() => summarizeBoundary(input),
      /measurement errors|support role saturated|process failure|insufficient direct-upstream headroom/);
  }
});

test('artifact identity drift and dirty full evidence cannot qualify', () => {
  const drift = fixture();
  drift.results[0].identities.snapshot_sha256 = 'f'.repeat(64);
  assert.throws(() => summarizeBoundary(drift), /snapshot_sha256 drift/);
  const dirty = fixture();
  dirty.environment.source_dirty = true;
  assert.equal(summarizeBoundary(dirty).decision, 'investigate');
});

test('more than five percent variation cannot qualify', () => {
  const input = fixture();
  const group = input.results.filter((result) =>
    result.protocol === 'https' && result.payload_bytes === 16384);
  group[0].successful_rps *= 1.2;
  group[0].upstream_headroom_ratio = group[0].direct_upstream_rps / group[0].successful_rps;
  const summary = summarizeBoundary(input);
  assert.equal(summary.gates.repeatability_pass, false);
  assert.equal(summary.decision, 'investigate');
});

test('optional diagnostics are numbers or explicit null, never fabricated zeroes', () => {
  const input = fixture();
  for (const result of input.results.filter((value) => value.protocol === 'http' &&
      value.payload_bytes === 65536)) result.diagnostic.instructions_per_request = 1234;
  const summary = summarizeBoundary(input);
  assert.equal(summary.groups.find((group) => group.protocol === 'http' &&
    group.payload_bytes === 65536).diagnostic.instructions_per_request, 1234);
  input.results[0].diagnostic.bytes_per_write = -1;
  assert.throws(() => summarizeBoundary(input), /bytes_per_write/);
});
