import assert from 'node:assert/strict';
import test from 'node:test';
import {summarizeBundle} from './phase5-discovery-summary.mjs';

function report(total = 10) {
  return JSON.stringify({
    summary: {total, requestsPerSec: 50},
    statusCodeDistribution: {200: 500},
    errorDistribution: {},
    latencyPercentiles: {p50: 0.001, p95: 0.002, p99: 0.003, 'p99.9': 0.004},
  });
}

function bundle(first = ['0', '10000000000'], second = ['0', '10000000000']) {
  return {kind: 'phase5-oha-lanes', schema_version: 1, rate_per_lane: 50,
    cpu_sets: ['0', '1'], lanes: [
      {index: 0, start_ns: first[0], end_ns: first[1], exit_code: 0,
        raw_json: report(), stderr: ''},
      {index: 1, start_ns: second[0], end_ns: second[1], exit_code: 0,
        raw_json: report(), stderr: ''},
    ]};
}

test('aligned discovery bundles replay the formal lane contract', () => {
  const summary = summarizeBundle(bundle());
  assert.equal(summary.contract_replay, true);
  assert.equal(summary.successful_rps_envelope, 100);
  assert.deepEqual(summary.latency_ms, {p50: 1, p95: 2, p99: 3, 'p99.9': 4});
});

test('misaligned discovery bundles retain diagnostics without becoming valid evidence', () => {
  const summary = summarizeBundle(bundle(['0', '10000000000'],
    ['600000000', '10600000000']));
  assert.equal(summary.contract_replay, false);
  assert.match(summary.contract_error, /windows insufficiently aligned/u);
  assert.equal(summary.successful_responses, 1000);
  assert.equal(summary.overlap_seconds, 9.4);
});

test('malformed lane output fails closed', () => {
  const input = bundle();
  input.lanes[1].raw_json = 'not-json';
  assert.throws(() => summarizeBundle(input), SyntaxError);
});
