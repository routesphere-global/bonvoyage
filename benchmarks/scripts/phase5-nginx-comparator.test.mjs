import assert from 'node:assert/strict';
import test from 'node:test';
import {OHA_LANE_MEMORY_BYTES} from './phase5-oha-lanes.mjs';
import {buildComparatorContract, renderNginxConfig,
  summarizeOha, validateIrqObservation} from './phase5-nginx-comparator.mjs';

const digest = 'a'.repeat(64);
const commit = 'b'.repeat(40);
const plan = {
  schema_version: 7,
  plan_id: digest,
  input: {
    profiles: {'P5-B01': {protocol: 'http1', tls: false,
      authority: 'api.example.test', listener_port: 8080,
      path: '/payload/256', connections: 256, streams: 1}},
    direct_upstream: {listener_port: 8081, minimum_headroom_ratio: 1.2,
      targets: [{address: '10.0.0.2', hostname: 'up-a'},
        {address: '10.0.0.3', hostname: 'up-b'}]},
    client_lanes: 16,
    client_cpus: Array.from({length: 32}, (_, index) => index),
    warmup_seconds: 60,
    measurement_seconds: 90,
    p999_ceiling_ms: 100,
    client_sha256: digest,
  },
  points: [{id: 'P5-B01-8c-steady-r1', profile: 'P5-B01', cores: 8,
    load: 'steady', repetition: 1, offered_rps: 280000}],
};
const lock = {products: [{name: 'nginx', version: '1.30.4',
  repository: 'docker.io/library/nginx',
  manifests: {linux_amd64: `sha256:${digest}`}}]};

function contract() {
  return buildComparatorContract(plan, lock, {
    pointId: 'P5-B01-8c-steady-r1', attempt: 1,
    gatewayAddress: '10.0.0.1', upstreamA: '10.0.0.2',
    upstreamB: '10.0.0.3', cpus: '8,10,12,13,14,15,17,19',
  }, {commit, dirty: false});
}

function activeContract() {
  return buildComparatorContract(plan, lock, {
    pointId: 'P5-B01-8c-steady-r1', attempt: 1,
    gatewayAddress: '10.0.0.1', upstreamA: '10.0.0.2',
    upstreamB: '10.0.0.3', cpus: '8,10,12,13,14,15,17,19',
    irqbalanceState: 'active',
  }, {commit, dirty: false});
}

function workload(requestsPerLane) {
  return {request_mode: 'fixed-count', client_sha256: digest,
    protocol: 'http1', tls: false, authority: 'api.example.test',
    listener_port: 8080, target_addresses: ['10.0.0.1'],
    path: '/payload/256', connections_per_lane: 256,
    streams_per_connection: 1, requests_per_lane: requestsPerLane,
    memory_limit_bytes: OHA_LANE_MEMORY_BYTES, ca_sha256: null,
    credential_sha256: null, method: 'GET', keepalive: true,
    compression: false, latency_correction: true,
    request_timeout_seconds: 5, connect_timeout_seconds: 5,
    redirect_limit: 0};
}

function bundle(seconds, requestsPerLane) {
  const start = 1000000000n;
  const end = start + BigInt(seconds) * 1000000000n;
  return {kind: 'phase5-oha-lanes', schema_version: 2,
    rate_per_lane: 17500,
    cpu_sets: Array.from({length: 16}, (_, index) => `${index * 2},${index * 2 + 1}`),
    workload: workload(requestsPerLane),
    lanes: Array.from({length: 16}, (_, index) => ({index,
      start_ns: String(start), end_ns: String(end), exit_code: 0,
      target_address: '10.0.0.1', stderr: '',
      raw_json: JSON.stringify({summary: {total: seconds},
        statusCodeDistribution: {'200': requestsPerLane}, errorDistribution: {},
        latencyPercentiles: {p50: 0.001, p95: 0.002, p99: 0.003,
          'p99.9': 0.050}})}))};
}

function sequence() {
  return {kind: 'phase5-oha-sequence', schema_version: 2,
    warmup: bundle(60, 1050000), measurement: bundle(90, 1575000)};
}

test('contract freezes the matched eight-core P5-B01 comparison', () => {
  const value = contract();
  assert.equal(value.runtime.worker_count, 8);
  assert.equal(value.runtime.upstream_keepalive_per_worker, 128);
  assert.equal(value.runtime.upstream_idle_connection_budget, 1024);
  assert.equal(value.runtime.worker_placement, 'os-managed-within-container-cpuset');
  assert.equal(value.runtime.irq_policy, 'kernel-observed-disjoint-no-static-write');
  assert.equal(value.runtime.irqbalance_measurement_state, 'inactive');
  assert.equal(value.workload.connections_per_lane * value.workload.client_lanes, 4096);
});

test('active IRQ contract binds service state and disjoint observed placement', () => {
  const value = activeContract();
  assert.equal(value.runtime.irqbalance_measurement_state, 'active');
  assert.equal(value.runtime.irq_policy,
    'irqbalance-active-observed-disjoint-no-static-write');
  const result = validateIrqObservation(value,
    '70 7\n71 16\n72 28\n', '70 11\n71 16\n72 28\n');
  assert.equal(result.irq_count, 3);
  assert.equal(result.moved_irq_count, 1);
  assert.equal(result.disjoint_before_and_after, true);
});

test('IRQ replay rejects overlap, identity drift, and unsupported service state', () => {
  const value = activeContract();
  assert.throws(() => validateIrqObservation(value,
    '70 7\n71 16\n', '70 8\n71 16\n'), /overlapped comparator CPUs/u);
  assert.throws(() => validateIrqObservation(value,
    '70 7\n71 16\n', '70 7\n72 16\n'), /identity changed/u);
  assert.throws(() => buildComparatorContract(plan, lock, {
    pointId: 'P5-B01-8c-steady-r1', attempt: 1,
    gatewayAddress: '10.0.0.1', upstreamA: '10.0.0.2',
    upstreamB: '10.0.0.3', cpus: '8,10,12,13,14,15,17,19',
    irqbalanceState: 'unknown',
  }, {commit, dirty: false}), /irqbalance state/u);
});

test('rendered NGINX config has two upstreams, no cache, and no worker affinity', () => {
  const rendered = renderNginxConfig(contract());
  assert.match(rendered, /worker_processes 8;/u);
  assert.match(rendered, /server 10\.0\.0\.2:8081;/u);
  assert.match(rendered, /server 10\.0\.0\.3:8081;/u);
  assert.match(rendered, /keepalive 128;/u);
  assert.match(rendered, /proxy_buffering off;/u);
  assert.doesNotMatch(rendered, /proxy_cache/u);
  assert.doesNotMatch(rendered, /worker_cpu_affinity/u);
});

test('dirty source and duplicated CPU sets fail closed', () => {
  assert.throws(() => buildComparatorContract(plan, lock, {
    pointId: 'P5-B01-8c-steady-r1', attempt: 1,
    gatewayAddress: '10.0.0.1', upstreamA: '10.0.0.2',
    upstreamB: '10.0.0.3', cpus: '8,8,10,11,12,13,14,15',
  }, {commit, dirty: false}), /eight distinct CPUs/u);
  assert.throws(() => buildComparatorContract(plan, lock, {
    pointId: 'P5-B01-8c-steady-r1', attempt: 1,
    gatewayAddress: '10.0.0.1', upstreamA: '10.0.0.2',
    upstreamB: '10.0.0.3', cpus: '8,9,10,11,12,13,14,15',
  }, {commit, dirty: true}), /clean comparator harness/u);
});

test('replay rejects contracts with changed support identity', () => {
  const altered = contract();
  altered.support.targets[0].address = '10.0.0.9';
  assert.throws(() => renderNginxConfig(altered),
    /digest mismatch|support targets differ/u);
});

test('summary reports conservative tails and rejects non-200 responses', () => {
  const accepted = summarizeOha(contract(), sequence());
  assert.equal(accepted.successful_rps, 280000);
  assert.equal(accepted.p999_ms, 50);

  const rejected = sequence();
  const lane = JSON.parse(rejected.measurement.lanes[0].raw_json);
  lane.statusCodeDistribution = {'200': 1574999, '503': 1};
  rejected.measurement.lanes[0].raw_json = JSON.stringify(lane);
  assert.throws(() => summarizeOha(contract(), rejected), /non-200/u);
});
