import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {validateProtocolStreamingCatalog} from './phase5-protocol-streaming.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const catalogPath = path.join(root,
  'benchmarks/workloads/protocol-streaming/phase5-protocol-streaming.json');

function catalog() {
  return JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
}

test('committed PERF-05 protocol and streaming catalog is valid', () => {
  const value = validateProtocolStreamingCatalog(catalog());
  assert.deepEqual(value.profiles.map((profile) => profile.id),
    ['P5-T01', 'P5-H01', 'P5-H02', 'P5-G01', 'P5-S01']);
  assert.equal(value.protocol_contract.streaming_grpc_qualified, false);
  assert.equal(value.calibration_rule.primary_latency_percentiles[1], 'p95');
});

test('catalog rejects publication and protocol scope drift', () => {
  const publication = catalog();
  publication.publication_authorized = true;
  assert.throws(() => validateProtocolStreamingCatalog(publication),
    /cannot authorize publication/u);

  const grpc = catalog();
  grpc.protocol_contract.grpc_scope = 'streaming';
  grpc.protocol_contract.streaming_grpc_qualified = true;
  assert.throws(() => validateProtocolStreamingCatalog(grpc),
    /streaming gRPC/u);

  const tls = catalog();
  tls.protocol_contract.tls_cipher_family = 'any';
  assert.throws(() => validateProtocolStreamingCatalog(tls), /TLS contract/u);
});

test('catalog rejects weakened correctness and latency semantics', () => {
  const errors = catalog();
  errors.fixed_correctness_gates.unexpected_error_count = 1;
  assert.throws(() => validateProtocolStreamingCatalog(errors),
    /correctness gates changed/u);

  const latency = catalog();
  latency.calibration_rule.primary_latency_percentiles = ['p50', 'p99'];
  assert.throws(() => validateProtocolStreamingCatalog(latency),
    /primary latency percentiles changed/u);

  const cleanup = catalog();
  cleanup.fixed_correctness_gates.maximum_cleanup_ms = 5000;
  assert.throws(() => validateProtocolStreamingCatalog(cleanup),
    /correctness gates changed/u);

  const retainedMemory = catalog();
  retainedMemory.fixed_correctness_gates.maximum_retained_rss_growth_bytes =
    32 * 1024 * 1024;
  assert.throws(() => validateProtocolStreamingCatalog(retainedMemory),
    /correctness gates changed/u);
});

test('catalog rejects profile, payload, and SSE scenario drift', () => {
  const reordered = catalog();
  [reordered.profiles[0], reordered.profiles[1]] =
    [reordered.profiles[1], reordered.profiles[0]];
  assert.throws(() => validateProtocolStreamingCatalog(reordered),
    /ID or ordering changed/u);

  const payload = catalog();
  payload.profiles[0].payload_bytes[1] = 16000;
  assert.throws(() => validateProtocolStreamingCatalog(payload),
    /P5-T01 payload_bytes changed/u);

  const h2Protocol = catalog();
  h2Protocol.profiles[2].upstream_protocols = ['http1'];
  assert.throws(() => validateProtocolStreamingCatalog(h2Protocol),
    /P5-H02 upstream_protocols changed/u);

  const grpcPayload = catalog();
  grpcPayload.profiles[3].payload_bytes.push(65536);
  assert.throws(() => validateProtocolStreamingCatalog(grpcPayload),
    /P5-G01 payload_bytes changed/u);

  const sse = catalog();
  sse.profiles[4].scenarios.pop();
  assert.throws(() => validateProtocolStreamingCatalog(sse),
    /P5-S01 scenarios changed/u);
});

test('catalog rejects missing metrics and uncalibrated native field removal', () => {
  const metric = catalog();
  metric.required_metrics.splice(metric.required_metrics.indexOf('ttfb_ms'), 1);
  assert.throws(() => validateProtocolStreamingCatalog(metric),
    /required metrics changed/u);

  const field = catalog();
  field.calibration_rule.freeze_before_measured_traffic.pop();
  assert.throws(() => validateProtocolStreamingCatalog(field),
    /calibration fields changed/u);
});
