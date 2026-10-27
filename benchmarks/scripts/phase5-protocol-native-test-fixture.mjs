import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

import {NATIVE_ACCEPTANCE} from './phase5-protocol-native-plan.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const catalogPath = path.join(root,
  'benchmarks/workloads/protocol-streaming/phase5-protocol-streaming.json');

export function catalogBytes() {
  return fs.readFileSync(catalogPath, 'utf8');
}

export function digest(label) {
  return crypto.createHash('sha256').update(label).digest('hex');
}

export function runtimeInventoryBytes() {
  return `${JSON.stringify({schema_version: 1,
    classification: 'private-native-runtime-inventory',
    outcome: 'collected-unqualified', runtime_profile: 'package-install',
    producer_source_commit: 'a'.repeat(40),
    files: {binary: {path: '/usr/bin/bonvoyage-dataplane', bytes: 1234,
      sha256: digest('gateway')}},
    process: {executable: '/usr/bin/bonvoyage-dataplane'}})}\n`;
}

function throughputWorkload(cores) {
  return {
    target_rps: cores === 8 ? 200000 : 600000,
    warmup_seconds: 15,
    measurement_seconds: 60,
    connections: 512,
    streams_per_connection: 100,
    request_timeout_ms: 5000,
    p95_ceiling_ms: 50,
    p99_ceiling_ms: 500,
  };
}

function streamWorkload(chunkBytes) {
  return {
    target_active_streams: 1000,
    stream_start_rate_per_second: 100,
    warmup_seconds: 15,
    measurement_seconds: 60,
    event_count: 100,
    event_interval_ms: 40,
    event_payload_bytes: 128,
    upstream_chunk_bytes: chunkBytes,
    request_timeout_ms: 10000,
    ttfb_ceiling_ms: 100,
    event_gap_ceiling_ms: 100,
    p95_ceiling_ms: 50,
    p99_ceiling_ms: 500,
  };
}

function lifecycleWorkload(profile, scenario) {
  const isSse = profile === 'P5-S01';
  const slow = isSse && scenario === 'slow-consumer';
  return {
    concurrent_cases: 100,
    iterations: 3,
    event_count: isSse ? (slow ? 16384 : 100) : null,
    event_interval_ms: isSse ? (slow ? 1 : 40) : null,
    event_payload_bytes: isSse ? (slow ? 4096 : 128) : null,
    upstream_chunk_bytes: isSse ? (slow ? 4096 : 128) : null,
    slow_consumer_read_rate_bytes_per_second: slow ? 1024 : null,
    request_timeout_ms: 10000,
    idle_timeout_ms: 1000,
    cleanup_ceiling_ms: NATIVE_ACCEPTANCE.maximum_cleanup_ms,
  };
}

function variant({id, profile, measurementClass, scenario, cores,
  downstream, upstream, payload, expected = 'success', workload}) {
  return {
    id,
    profile,
    measurement_class: measurementClass,
    scenario,
    core_count: cores,
    downstream_protocol: downstream,
    upstream_protocol: upstream,
    payload_bytes: payload,
    expected_outcome: expected,
    snapshot_sha256: digest(`snapshot:${id}`),
    workload,
  };
}

function variants() {
  const result = [];
  for (const scenario of ['fixed-response', 'proxied-response']) {
    for (const payload of [15360, 16384, 17408, 65536]) {
      for (const cores of [8, 24]) {
        const id = `t01-${scenario}-${payload}-${cores}c`;
        result.push(variant({id, profile: 'P5-T01',
          measurementClass: 'throughput-cost', scenario, cores,
          downstream: 'https-http1',
          upstream: scenario === 'fixed-response' ? 'none' : 'http1',
          payload, workload: throughputWorkload(cores)}));
      }
    }
  }

  for (const payload of [256, 8192, 65536]) {
    for (const cores of [8, 24]) {
      const id = `h01-stable-${payload}-${cores}c`;
      result.push(variant({id, profile: 'P5-H01',
        measurementClass: 'throughput-cost', scenario: 'stable-headers',
        cores, downstream: 'https-http2', upstream: 'http1', payload,
        workload: throughputWorkload(cores)}));
    }
  }
  for (const scenario of ['bounded-rotating-headers', 'flow-control-window',
    'mixed-short-long-streams']) {
    for (const cores of [8, 24]) {
      const id = `h01-${scenario}-${cores}c`;
      result.push(variant({id, profile: 'P5-H01',
        measurementClass: 'throughput-cost', scenario, cores,
        downstream: 'https-http2', upstream: 'http1', payload: 256,
        workload: throughputWorkload(cores)}));
    }
  }

  for (const payload of [256, 8192, 65536]) {
    for (const cores of [8, 24]) {
      const id = `h02-healthy-${payload}-${cores}c`;
      result.push(variant({id, profile: 'P5-H02',
        measurementClass: 'throughput-cost', scenario: 'healthy', cores,
        downstream: 'https-http2', upstream: 'http2', payload,
        workload: throughputWorkload(cores)}));
    }
  }
  result.push(variant({id: 'h02-connection-reuse-256-8c', profile: 'P5-H02',
    measurementClass: 'throughput-cost', scenario: 'connection-reuse',
    cores: 8, downstream: 'https-http2', upstream: 'http2', payload: 256,
    workload: throughputWorkload(8)}));
  for (const [scenario, expected] of [
    ['peer-cancel', 'peer-cancel'], ['deadline', 'deadline'],
  ]) {
    result.push(variant({id: `h02-${scenario}-256-8c`, profile: 'P5-H02',
      measurementClass: 'lifecycle', scenario, cores: 8,
      downstream: 'https-http2', upstream: 'http2', payload: 256, expected,
      workload: lifecycleWorkload('P5-H02', scenario)}));
  }

  for (const payload of [256, 8192]) {
    for (const cores of [8, 24]) {
      const id = `g01-healthy-${payload}-${cores}c`;
      result.push(variant({id, profile: 'P5-G01',
        measurementClass: 'throughput-cost', scenario: 'healthy', cores,
        downstream: 'grpc-h2', upstream: 'grpc-h2', payload,
        expected: 'grpc-ok', workload: throughputWorkload(cores)}));
    }
  }
  for (const [scenario, expected] of [
    ['deadline', 'grpc-deadline-exceeded'],
    ['peer-cancel', 'grpc-cancelled'],
    ['malformed-message', 'grpc-rejected-malformed-message'],
    ['invalid-trailers', 'grpc-rejected-invalid-trailers'],
  ]) {
    result.push(variant({id: `g01-${scenario}-256-8c`, profile: 'P5-G01',
      measurementClass: 'lifecycle', scenario, cores: 8,
      downstream: 'grpc-h2', upstream: 'grpc-h2', payload: 256, expected,
      workload: lifecycleWorkload('P5-G01', scenario)}));
  }

  for (const downstream of ['https-http1', 'https-http2']) {
    const protocol = downstream === 'https-http1' ? 'h1' : 'h2';
    for (const cores of [8, 24]) {
      for (const chunkBytes of [1, 128]) {
        const id = `s01-cadence-${protocol}-${cores}c-${chunkBytes}b`;
        result.push(variant({id, profile: 'P5-S01',
          measurementClass: 'stream-cost', scenario: 'healthy-cadence',
          cores, downstream, upstream: 'http1-chunked', payload: 128,
          expected: 'terminal-done', workload: streamWorkload(chunkBytes)}));
      }
    }
    for (const [scenario, expected] of [
      ['slow-consumer', 'bounded-slow-consumer'],
      ['peer-cancel', 'peer-cancel'],
      ['upstream-stall', 'gateway-deadline'],
      ['terminal-error', 'terminal-error'],
      ['missing-terminal-event', 'logical-incomplete'],
    ]) {
      result.push(variant({id: `s01-${scenario}-${protocol}-8c`,
        profile: 'P5-S01', measurementClass: 'lifecycle', scenario, cores: 8,
        downstream, upstream: 'http1-chunked', payload: 128, expected,
        workload: lifecycleWorkload('P5-S01', scenario)}));
    }
  }
  return result;
}

export function nativePlanInput(bytes = catalogBytes()) {
  return {
    schema_version: 1,
    checkpoint: 'PERF-05',
    evidence_class: 'native-engineering',
    publication_authorized: false,
    catalog_sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    profile_scope: ['P5-T01', 'P5-H01', 'P5-H02', 'P5-G01', 'P5-S01'],
    source: {
      binary_source_commit: 'a'.repeat(40),
      harness_commit: 'b'.repeat(40),
      source_dirty: false,
      gateway_binary_sha256: digest('gateway'),
      snapshot_compiler_sha256: digest('compiler'),
      load_client_sha256: digest('client'),
      controlled_upstream_sha256: digest('upstream'),
      fixture_bundle_sha256: digest('fixtures'),
      collector_bundle_sha256: digest('collectors'),
      tls_bundle_sha256: digest('tls'),
      runtime_inventory_sha256: crypto.createHash('sha256')
        .update(runtimeInventoryBytes()).digest('hex'),
    },
    topology: {
      roles: [
        {role: 'load_generator', host_id: 'loadgen-01',
          private_address: '10.0.0.10'},
        {role: 'gateway', host_id: 'gateway-01',
          private_address: '10.0.0.20'},
        {role: 'controlled_upstream', host_id: 'upstream-01',
          private_address: '10.0.0.30'},
      ],
      load_generator_cpu_set: Array.from({length: 32}, (_, index) => index),
      load_generator_lanes: 8,
      gateway_cpu_sets: {
        '8': Array.from({length: 8}, (_, index) => index + 8),
        '24': Array.from({length: 24}, (_, index) => index + 8),
      },
      gateway_housekeeping_cpus: Array.from({length: 8}, (_, index) => index),
      irq_policy: {
        mode: 'irqbalance-with-gateway-ban',
        gateway_banned_cpus: Array.from({length: 24}, (_, index) => index + 8),
        irq_target_cpus: Array.from({length: 8}, (_, index) => index),
      },
    },
    schedule: {
      throughput_repetitions: 5,
      lifecycle_repetitions: 3,
      profiled_warmup_repetitions: 3,
      position_balance: 'forward-reverse',
      inter_point_cooldown_seconds: 10,
    },
    acceptance: {...NATIVE_ACCEPTANCE},
    variants: variants(),
  };
}
