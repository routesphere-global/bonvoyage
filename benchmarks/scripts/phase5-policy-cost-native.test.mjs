import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {partitionCpus} from './phase5-oha-lanes.mjs';
import {buildPolicyCostPlan, validatePolicyCostResult} from
  './phase5-policy-cost.mjs';
import {derivePolicyCostEvidence, derivePolicyCostInput,
  describePolicyCostPoint, POLICY_COST_RAW_FILES,
  POLICY_COST_RAW_FILES_V1, POLICY_COST_RAW_FILES_V3,
  POLICY_COST_RAW_FILES_V4,
  validatePolicyWarmupAdmission} from './phase5-policy-cost-native.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const catalogBytes = fs.readFileSync(path.join(root,
  'benchmarks/workloads/policy-cost/phase5-policy-cost.json'));
const RAW_FILES = [...POLICY_COST_RAW_FILES];

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function planInput() {
  return {schema_version: 2, evidence_class: 'shared-vm-directional',
    catalog_sha256: sha256(catalogBytes),
    source: {binary_source_commit: '1'.repeat(40),
      harness_commit: '2'.repeat(40), source_dirty: false,
      gateway_binary_sha256: sha256('gateway'),
      client_sha256: sha256('client'), upstream_sha256: sha256('upstream'),
      collector_bundle_sha256: sha256('collectors'),
      tls_bundle_sha256: sha256('tls')},
    topology: {roles: [
      {role: 'load_generator', host_id: 'load-1',
        private_address: '10.0.0.10'},
      {role: 'gateway', host_id: 'gateway-1',
        private_address: '10.0.0.20'},
      {role: 'controlled_upstream', host_id: 'upstream-1',
        private_address: '10.0.0.30'},
    ], gateway_cpu_set: Array.from({length: 24}, (_, index) => index + 8),
    housekeeping_cpu_set: Array.from({length: 8}, (_, index) => index),
    load_generator_cpu_set: Array.from({length: 16}, (_, index) => index),
    irq_policy: 'irqbalance-with-gateway-ban', load_generator_lanes: 8,
    controlled_upstream: {port: 8081, max_connections_per_shard: 128}},
    artifacts: {p5_b02_snapshot_sha256: sha256('b02-snapshot'),
      profile_snapshot_sha256: Object.fromEntries(
        ['P5-C00', 'P5-C01', 'P5-C02', 'P5-C03', 'P5-C04', 'P5-C05']
          .map((id) => [id, sha256(`${id}-snapshot`)])),
      header_transform_request_sha256: sha256('header-input'),
      api_key_credential_sha256: sha256('api-key-file'),
      jwt_jwks_sha256: sha256('jwt-jwks')},
    workload: {offered_rps_by_payload: {'256': 24000, '8192': 12000},
      connections: 256, warmup_seconds: 60, measurement_seconds: 60,
      request_timeout_ms: 5000, maximum_cleanup_ms: 5000,
      minimum_delivery_ratio: 0.95, p95_ceiling_ms: 50,
      p99_ceiling_ms: 500, maximum_support_capacity_percent: 80,
      maximum_retained_rss_growth_bytes: 16 * 1024 * 1024,
      maximum_retained_fd_growth: 4},
    jwt: {algorithm: 'RS256', maximum_age_seconds_at_start: 60,
      minimum_remaining_lifetime_seconds_at_end: 30}};
}

function fixture(profileId = 'P5-C01', schemaVersion = 2) {
  const input = planInput();
  if (schemaVersion === 1) {
    delete input.schema_version;
    delete input.topology.controlled_upstream;
  } else if (schemaVersion >= 3) {
    input.schema_version = schemaVersion;
    input.workload.profiled_warmup_repetitions = 3;
    input.jwt.maximum_age_seconds_at_start = 210;
  }
  const plan = buildPolicyCostPlan(input, catalogBytes);
  const point = plan.points.find((item) => item.profile_id === profileId);
  return {plan, point};
}

function requestObservation(point) {
  const jwt = point.request.mode === 'ephemeral-jwt';
  const artifact = point.request.mode === 'none' ? null :
    (jwt ? sha256(`${point.profile_id}-ephemeral-jwt`) :
      point.request.planned_artifact_sha256);
  return {mode: point.request.mode, header_names: point.request.header_names,
    artifact_sha256: artifact, values_retained: false,
    jwt_window: jwt ? {issued_at_epoch_ms: 100000,
      expires_at_epoch_ms: 400000,
      measurement_started_at_epoch_ms: 120000,
      measurement_ended_at_epoch_ms: 180000} : null};
}

function oha(plan, point, request, duration) {
  const lanes = plan.input.topology.load_generator_lanes;
  const rate = point.offered_rps / lanes;
  const requests = rate * duration;
  const gateway = plan.input.topology.roles.find((item) =>
    item.role === 'gateway');
  const workload = {request_mode: 'fixed-count',
    client_sha256: plan.input.source.client_sha256, protocol: 'http1',
    tls: true, authority: 'api.example.test', listener_port: 8443,
    target_addresses: [gateway.private_address],
    path: point.request_path,
    connections_per_lane: 32, streams_per_connection: 1,
    requests_per_lane: requests, memory_limit_bytes: 4 * 1024 ** 3,
    ca_sha256: sha256('ca'),
    credential_sha256: point.request.mode === 'secret-file' ?
      request.artifact_sha256 : null,
    method: 'GET', keepalive: true, compression: false,
    latency_correction: true, request_timeout_seconds: 5,
    connect_timeout_seconds: 5, redirect_limit: 0};
  if (['static-json', 'ephemeral-jwt'].includes(point.request.mode)) {
    workload.request_headers_sha256 = request.artifact_sha256;
    workload.request_header_names = point.request.header_names;
  }
  const schema = workload.request_headers_sha256 === undefined ? 2 : 4;
  const raw = JSON.stringify({summary: {total: duration},
    statusCodeDistribution: {'200': requests}, errorDistribution: {},
    latencyPercentiles: {p50: 0.001, p95: 0.003, p99: 0.005,
      'p99.9': 0.009}});
  return {kind: 'phase5-oha-lanes', schema_version: schema,
    rate_per_lane: rate, cpu_sets: partitionCpus('0-15', lanes), workload,
    lanes: Array.from({length: lanes}, (_, index) => ({index,
      start_ns: '0', end_ns: String(duration * 1e9), exit_code: 0,
      raw_json: raw, stderr: '', target_address: gateway.private_address}))};
}

function metrics(coreCount, successfulPerShard, busyMs, allocations = 0,
  waits = 0, requestedPerShard = successfulPerShard) {
  const lines = [];
  for (let shard = 0; shard < coreCount; shard += 1) {
    const label = `{shard="${shard}"}`;
    lines.push(`bonvoyage_bonvoyage_gateway_requests_total${label} ${requestedPerShard}`);
    lines.push(`bonvoyage_bonvoyage_gateway_responses_2xx_total${label} ${successfulPerShard}`);
    lines.push(`bonvoyage_bonvoyage_gateway_upstream_http1_pool_waits_total${label} ${waits}`);
    lines.push(`bonvoyage_memory_malloc_operations${label} ${allocations}`);
    lines.push(`bonvoyage_reactor_cpu_busy_ms${label} ${busyMs}`);
  }
  return `${lines.join('\n')}\n`;
}

function finalMetrics() {
  return `${[
    'bonvoyage_bonvoyage_gateway_active_requests 0',
    'bonvoyage_bonvoyage_gateway_active_route_requests 0',
    'bonvoyage_bonvoyage_gateway_active_upstream_requests 0',
    'bonvoyage_bonvoyage_gateway_active_upstream_http1_requests 0',
    'bonvoyage_bonvoyage_gateway_active_http2_streams 0',
  ].join('\n')}\n`;
}

function warmupFinalMetrics(allocatedMemoryBytes, liveObjects) {
  return `${finalMetrics()}bonvoyage_memory_allocated_memory ${allocatedMemoryBytes}\n` +
    `bonvoyage_memory_malloc_live_objects ${liveObjects}\n`;
}

function proc(before, busy = 40) {
  if (before) return 'cpu 100 0 100 700 0 10 10 0\n';
  const active = busy * 10;
  const idle = (100 - busy) * 10;
  return `cpu ${100 + active - 20} 0 100 ${700 + idle} 0 20 20 0\n`;
}

function provenance(plan, point) {
  return {schema_version: 1, plan_id: plan.plan_id,
    point_id: point.point_id, profile_id: point.profile_id,
    repetition: point.repetition, source: plan.input.source,
    catalog_sha256: plan.input.catalog_sha256,
    snapshot_sha256: point.snapshot_sha256,
    observed_harness_commit: plan.input.source.harness_commit,
    source_status: ''};
}

function environment(plan, point, attempt = 1) {
  const tids = Array.from({length: point.core_count}, (_, index) => 100 + index);
  return {schema_version: 1, plan_id: plan.plan_id,
    point_id: point.point_id, profile_id: point.profile_id,
    repetition: point.repetition, attempt, roles: plan.input.topology.roles,
    load_generator_cpu_set: Array.from({length: 16}, (_, index) => index),
    load_generator_lanes: plan.input.topology.load_generator_lanes,
    gateway_cpu_set: plan.input.topology.gateway_cpu_set,
    housekeeping_cpu_set: plan.input.topology.housekeeping_cpu_set,
    irq_policy: plan.input.topology.irq_policy,
    profiler_scope: 'all-stable-seastar-reactor-tids',
    reactor_tids_before: [...tids], reactor_tids_after: [...tids],
    profiled_reactor_tids: [...tids]};
}

function responseHeaders(point) {
  const lines = ['HTTP/1.1 200 OK',
    `Content-Length: ${point.response_payload_bytes}`,
    'Content-Type: application/octet-stream'];
  if (point.feature === 'bounded-header-transformations') {
    lines.push('X-Upstream-Policy-Set: gateway-set',
      'X-Upstream-Policy-Append: upstream-append, gateway-append',
      'X-Policy-Response-Added: gateway-added',
      'X-Observed-Request-Set: gateway-set',
      'X-Observed-Request-Append: client-append, gateway-append',
      'X-Observed-Request-Added: gateway-added');
  }
  return `${lines.join('\r\n')}\r\n\r\n`;
}

function descriptorObservation(poolConnections = 2, otherDescriptors = 15) {
  const entries = [];
  let fd = 0;
  for (let index = 0; index < otherDescriptors; index += 1) {
    entries.push({fd, target: `/tmp/fixture-fd-${fd}`, kind: 'file',
      socket_inode: null, tcp: null});
    fd += 1;
  }
  for (let index = 0; index < poolConnections; index += 1) {
    entries.push({fd, target: `socket:[${1000 + fd}]`, kind: 'tcp-socket',
      socket_inode: 1000 + fd,
      tcp: {family: 'ipv4', local_address: '10.0.0.20',
        local_port: 40000 + index, remote_address: '10.0.0.30',
        remote_port: 8081, state: 'ESTABLISHED', tx_queue_bytes: 0,
        rx_queue_bytes: 0}});
    fd += 1;
  }
  return {identity: 'pid:42:start:99', pid: 42, start_ticks: 99,
    restart_count: 0, total: entries.length, entries};
}

function warmupAdmission(plan, point, finalRss = 44 * 1024 * 1024,
  finalDescriptors = 17) {
  const successfulRequests = point.offered_rps *
    plan.input.workload.warmup_seconds;
  const pass = (number, rssBytes, descriptors) => ({pass: number,
    settled: true, settlement_ms: 250, identity: 'pid:42:start:99',
    restart_count: 0, rss_bytes: rssBytes, file_descriptors: descriptors,
    successful_requests: successfulRequests, http_failures: 0,
    transport_failures: 0});
  if (plan.schema_version === 3) return {schema_version: 1,
    required_profiled_warmup_repetitions: 3,
    passes: [pass(1, 42 * 1024 * 1024, 16),
      pass(2, finalRss, finalDescriptors),
      pass(3, finalRss, finalDescriptors)],
    plateau: {compared_passes: [2, 3], rss_delta_bytes: 0, fd_delta: 0,
      stable: true}};

  const boundedPass = (number, rssBytes, descriptors, allocatedMemoryBytes,
    liveObjects, controlledConnections, nonControlledDescriptors) => ({
    ...pass(number, rssBytes, descriptors), allocated_memory_bytes:
      allocatedMemoryBytes, malloc_live_objects: liveObjects,
    controlled_upstream_connections: controlledConnections,
    non_controlled_descriptors: nonControlledDescriptors,
  });
  const penultimateRss = finalRss - 8 * 1024 * 1024;
  const penultimateAllocated = 31 * 1024 * 1024;
  const finalAllocated = penultimateAllocated + 196608;
  return {schema_version: 2, required_profiled_warmup_repetitions: 3,
    passes: [boundedPass(1, penultimateRss - 2 * 1024 * 1024, 16,
      30 * 1024 * 1024, 900, 1, 15),
    boundedPass(2, penultimateRss, finalDescriptors, penultimateAllocated,
      1000, 2, 15),
    boundedPass(3, finalRss, finalDescriptors, finalAllocated,
      1035, 2, 15)],
    convergence: {compared_passes: [2, 3],
      rss_delta_bytes: 8 * 1024 * 1024,
      allocated_memory_delta_bytes: 196608,
      malloc_live_object_delta: 35, fd_delta: 0,
      controlled_upstream_connection_delta: 0,
      unaccounted_fd_delta: 0,
      maximum_memory_growth_bytes: 16 * 1024 * 1024,
      maximum_unaccounted_fd_growth: 0,
      controlled_upstream_connection_limit: 3072, contained: true}};
}

function writeRaw(rawRoot, plan, point, changes = {}) {
  const request = requestObservation(point);
  const duration = point.measurement_seconds;
  const count = point.offered_rps * duration;
  const perShard = count / point.core_count;
  const values = {
    'binary-observation.json': JSON.stringify({schema_version: 1,
      source: plan.input.source}),
    'environment.json': JSON.stringify(environment(plan, point)),
    'final-metrics.prom': finalMetrics(),
    'gateway-metrics-after.prom': metrics(point.core_count, perShard,
      duration * 500, 100 + perShard * 2),
    'gateway-metrics-before.prom': metrics(point.core_count, 0, 0, 100),
    'gateway-proc-after.txt': proc(false, 60),
    'gateway-proc-before.txt': proc(true), 'journal.log': '',
    'load-generator-proc-after.txt': proc(false, 40),
    'load-generator-proc-before.txt': proc(true),
    'measurement.oha.json': JSON.stringify(oha(plan, point, request, duration)),
    'perf.csv': `${count * 100000},,cycles\n${count * 120000},,instructions\n1200,,cache-misses\n${count * 4},,raw_syscalls:sys_enter\n`,
    'protocol-body.bin': Buffer.alloc(point.response_payload_bytes, 'x'),
    'protocol-headers.txt': responseHeaders(point),
    'protocol-status.txt': '200\n',
    'provenance-after.json': JSON.stringify(provenance(plan, point)),
    'provenance-before.json': JSON.stringify(provenance(plan, point)),
    'request-observation.json': JSON.stringify(request),
    'descriptors-after.json': JSON.stringify(descriptorObservation()),
    'descriptors-before.json': JSON.stringify(descriptorObservation()),
    'resource-after.json': JSON.stringify({identity: 'pid:42:start:99',
      pid: 42, start_ticks: 99, restart_count: 0,
      rss_bytes: 44 * 1024 * 1024 + 1024, file_descriptors: 17}),
    'resource-before.json': JSON.stringify({identity: 'pid:42:start:99',
      pid: 42, start_ticks: 99, restart_count: 0,
      rss_bytes: 44 * 1024 * 1024, file_descriptors: 17}),
    'socket-output.json': JSON.stringify({interval_id: point.point_id,
      duration_nanoseconds: duration * 1e9,
      scope: 'gateway-downstream-sockets', pid: 42, start_ticks: 99,
      calls: count * 2,
      requested_bytes: count * point.response_payload_bytes,
      completed_bytes: count * point.response_payload_bytes,
      partial_writes: 0, would_block: 0, fatal_errors: 0, lost_events: 0}),
    'status.json': JSON.stringify({warmup_command_exit_code: 0,
      measurement_command_exit_code: 0, collector_exit_code: 0,
      protocol_probe_exit_code: 0}),
    'tls-observation.json': JSON.stringify({tls_version: 'TLSv1.3',
      cipher: 'TLS_AES_256_GCM_SHA384', alpn: 'http/1.1',
      ca_verified: true, hostname_verified: true}),
    'upstream-proc-after.txt': proc(false, 30),
    'upstream-proc-before.txt': proc(true),
    'warmup.oha.json': JSON.stringify(oha(plan, point, request,
      plan.input.workload.warmup_seconds)), ...changes};
  if (plan.schema_version >= 3 &&
      changes['warmup-admission.json'] === undefined) {
    values['warmup-admission.json'] = JSON.stringify(
      warmupAdmission(plan, point));
  }
  if (plan.schema_version >= 4) {
    const descriptors = [descriptorObservation(1, 15),
      descriptorObservation(2, 15), descriptorObservation(2, 15)];
    const warmupMetrics = [warmupFinalMetrics(30 * 1024 * 1024, 900),
      warmupFinalMetrics(31 * 1024 * 1024, 1000),
      warmupFinalMetrics(31 * 1024 * 1024 + 196608, 1035)];
    for (let pass = 1; pass <= 3; pass += 1) {
      const descriptorName = `warmup-pass-${pass}-descriptors.json`;
      const metricsName = `warmup-pass-${pass}-final-metrics.prom`;
      if (changes[descriptorName] === undefined) {
        values[descriptorName] = JSON.stringify(descriptors[pass - 1]);
      }
      if (changes[metricsName] === undefined) {
        values[metricsName] = warmupMetrics[pass - 1];
      }
    }
  }
  fs.mkdirSync(rawRoot, {recursive: true});
  const rawFiles = plan.schema_version === 1 ? POLICY_COST_RAW_FILES_V1 :
    (plan.schema_version === 2 ? RAW_FILES :
      (plan.schema_version === 3 ? POLICY_COST_RAW_FILES_V3 :
        POLICY_COST_RAW_FILES_V4));
  for (const name of rawFiles) {
    fs.writeFileSync(path.join(rawRoot, name), values[name]);
  }
  const manifest = rawFiles.map((name) =>
    `${sha256(fs.readFileSync(path.join(rawRoot, name)))}  ${name}`)
    .join('\n');
  fs.writeFileSync(path.join(rawRoot, 'checksums.sha256'), `${manifest}\n`);
}

function outputPaths(base, pointId) {
  const evidence = path.join(base, 'evidence');
  return {evidence, archive: path.join(evidence,
    `${pointId}.capture.raw.json`), environment: path.join(evidence,
    `${pointId}.environment.json`), derivation: path.join(evidence,
    `${pointId}.derivation.json`), result: path.join(evidence,
    `${pointId}.result.json`)};
}

function derive(profileId = 'P5-C01', changes = {}, schemaVersion = 2) {
  const {plan, point} = fixture(profileId, schemaVersion);
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'perf06-policy-native-'));
  const raw = path.join(base, 'raw');
  writeRaw(raw, plan, point, changes);
  const catalog = path.join(base, 'catalog.json');
  const planFile = path.join(base, 'plan.json');
  fs.writeFileSync(catalog, catalogBytes);
  fs.writeFileSync(planFile, JSON.stringify(plan));
  const output = outputPaths(base, point.point_id);
  const value = derivePolicyCostEvidence({catalog, plan: planFile,
    pointId: point.point_id, attempt: 1, rawRoot: raw,
    evidenceRoot: output.evidence, captureArchive: output.archive,
    environment: output.environment, derivationManifest: output.derivation,
    result: output.result});
  return {base, raw, plan, point, output, value};
}

test('policy-cost adapter derives one checksum-bound result from raw evidence', (t) => {
  const value = derive();
  t.after(() => fs.rmSync(value.base, {recursive: true, force: true}));
  const {result} = value.value;
  assert.equal(validatePolicyCostResult(result, value.plan, catalogBytes),
    result);
  assert.equal(result.profile_id, 'P5-C01');
  assert.equal(result.metrics.successful_rps, value.point.offered_rps);
  assert.equal(result.metrics.instructions_per_success, 120000);
  assert.equal(result.metrics.cycles_per_success, 100000);
  assert.equal(result.metrics.ipc, 1.2);
  assert.equal(result.metrics.allocations_per_success, 2);
  assert.equal(result.metrics.syscalls_per_success, 4);
  assert.equal(result.metrics.socket_writes_per_success, 2);
  assert.equal(result.metrics.per_shard_cpu_percent.length, 24);
  assert.equal(result.protocol.semantic_validated, true);
  assert.equal(result.schema_version, 2);
  assert.deepEqual(result.runtime.descriptor_attribution, {
    total_fd_growth: 0,
    controlled_upstream_connections_before: 2,
    controlled_upstream_connections_after: 2,
    controlled_upstream_connection_growth: 0,
    controlled_upstream_connection_limit: 3072,
    controlled_upstream_connections_bounded: true,
    non_controlled_descriptors_before: 15,
    non_controlled_descriptors_after: 15,
    unaccounted_fd_growth: 0,
  });
  assert.equal(result.publication_authorized, false);
  assert.equal(fs.existsSync(value.output.archive), true);
  assert.equal(fs.existsSync(value.output.derivation), true);
  assert.equal(fs.existsSync(value.output.environment), true);
  assert.equal(fs.existsSync(value.output.result), true);
});

test('policy-cost v2 attributes retained pool sockets without hiding other FDs',
  (t) => {
    const retained = derive('P5-B02', {
      'descriptors-after.json': JSON.stringify(descriptorObservation(22, 15)),
      'resource-after.json': JSON.stringify({identity: 'pid:42:start:99',
        pid: 42, start_ticks: 99, restart_count: 0,
        rss_bytes: 44 * 1024 * 1024 + 1024, file_descriptors: 37}),
    });
    t.after(() => fs.rmSync(retained.base, {recursive: true, force: true}));
    assert.equal(retained.value.result.runtime.descriptor_attribution
      .total_fd_growth, 20);
    assert.equal(retained.value.result.runtime.descriptor_attribution
      .controlled_upstream_connection_growth, 20);
    assert.equal(retained.value.result.runtime.descriptor_attribution
      .unaccounted_fd_growth, 0);

    const unrelated = derive('P5-B02', {
      'descriptors-after.json': JSON.stringify(descriptorObservation(2, 20)),
      'resource-after.json': JSON.stringify({identity: 'pid:42:start:99',
        pid: 42, start_ticks: 99, restart_count: 0,
        rss_bytes: 44 * 1024 * 1024 + 1024, file_descriptors: 22}),
    });
    t.after(() => fs.rmSync(unrelated.base, {recursive: true, force: true}));
    assert.equal(unrelated.value.result.runtime.descriptor_attribution
      .unaccounted_fd_growth, 5);
  });

test('policy-cost adapter replays legacy v1 raw evidence unchanged', (t) => {
  const value = derive('P5-B02', {}, 1);
  t.after(() => fs.rmSync(value.base, {recursive: true, force: true}));
  assert.equal(value.plan.schema_version, 1);
  assert.equal(value.value.archive.schema_version, 1);
  assert.equal(value.value.archive.files.length, POLICY_COST_RAW_FILES_V1.length);
  assert.equal(value.value.result.schema_version, 1);
  assert.equal(value.value.result.runtime.descriptor_attribution, undefined);
  assert.equal(validatePolicyCostResult(value.value.result, value.plan,
    catalogBytes), value.value.result);
});

test('policy-cost v3 binds the warmup plateau to the measured baseline', (t) => {
  const value = derive('P5-C00', {}, 3);
  t.after(() => fs.rmSync(value.base, {recursive: true, force: true}));
  assert.equal(value.plan.schema_version, 3);
  assert.equal(value.value.archive.schema_version, 3);
  assert.equal(value.value.archive.files.length,
    POLICY_COST_RAW_FILES_V3.length);
  assert.equal(validatePolicyCostResult(value.value.result, value.plan,
    catalogBytes), value.value.result);

  const admission = warmupAdmission(value.plan, value.point);
  assert.equal(validatePolicyWarmupAdmission(admission, value.plan,
    value.point), admission);
});

test('policy-cost v3 rejects warmup drift and a substituted baseline', () => {
  const {plan, point} = fixture('P5-C00', 3);
  const drifting = warmupAdmission(plan, point);
  drifting.passes[2].rss_bytes += 4096;
  drifting.plateau.rss_delta_bytes = 4096;
  assert.throws(() => derive('P5-C00', {
    'warmup-admission.json': JSON.stringify(drifting)}, 3),
  /resource plateau/u);

  const substituted = warmupAdmission(plan, point, 43 * 1024 * 1024, 17);
  assert.throws(() => derive('P5-C00', {
    'warmup-admission.json': JSON.stringify(substituted)}, 3),
  /baseline differs from warmup admission/u);
});

test('policy-cost v4 binds bounded convergence to retained warmup evidence',
  (t) => {
    const value = derive('P5-C00', {}, 4);
    t.after(() => fs.rmSync(value.base, {recursive: true, force: true}));
    assert.equal(value.plan.schema_version, 4);
    assert.equal(value.value.archive.schema_version, 4);
    assert.equal(value.value.archive.files.length,
      POLICY_COST_RAW_FILES_V4.length);
    assert.equal(validatePolicyCostResult(value.value.result, value.plan,
      catalogBytes), value.value.result);
  });

test('policy-cost v4 rejects metric substitution and unaccounted FD growth',
  () => {
    assert.throws(() => derive('P5-C00', {
      'warmup-pass-3-final-metrics.prom': warmupFinalMetrics(
        32 * 1024 * 1024, 1035)}, 4), /differs from retained evidence/u);

    const {plan, point} = fixture('P5-C00', 4);
    const admission = warmupAdmission(plan, point);
    admission.passes[2].file_descriptors += 1;
    admission.passes[2].non_controlled_descriptors += 1;
    admission.convergence.fd_delta = 1;
    admission.convergence.unaccounted_fd_delta = 1;
    assert.throws(() => derive('P5-C00', {
      'warmup-admission.json': JSON.stringify(admission),
      'warmup-pass-3-descriptors.json': JSON.stringify(
        descriptorObservation(2, 16))}, 4), /bounded resource convergence/u);
  });

test('policy-cost adapter replays all seven planned request identity modes', (t) => {
  const values = ['P5-B02', 'P5-C00', 'P5-C01', 'P5-C02', 'P5-C03',
    'P5-C04', 'P5-C05'].map((profile) => derive(profile));
  t.after(() => values.forEach((value) => fs.rmSync(value.base,
    {recursive: true, force: true})));
  assert.deepEqual(values.map((value) => value.value.result.request.mode),
    ['none', 'none', 'static-json', 'static-json', 'secret-file',
      'ephemeral-jwt', 'ephemeral-jwt']);
  assert.equal(values.every((value) =>
    value.value.result.protocol.semantic_validated), true);
});

test('policy-cost adapter rejects the policy path for the baseline point', () => {
  const {plan, point} = fixture('P5-B02');
  const request = requestObservation(point);
  const measurement = oha(plan, point, request, point.measurement_seconds);
  measurement.workload.path = '/policy/payload/256';
  assert.throws(() => derive('P5-B02', {
    'measurement.oha.json': JSON.stringify(measurement)}),
  /structured workload differs from plan/u);
});

test('policy-cost point description is immutable and non-publishing', () => {
  const {plan, point} = fixture('P5-C05');
  const description = describePolicyCostPoint(plan, catalogBytes,
    point.point_id);
  assert.equal(description.checkpoint, 'PERF-06');
  assert.equal(description.point.profile_id, 'P5-C05');
  assert.equal(description.profiler_scope,
    'all-stable-seastar-reactor-tids');
  assert.equal(description.publication_authorized, false);
});

test('policy-cost raw archive is independently self-binding', (t) => {
  const value = derive();
  t.after(() => fs.rmSync(value.base, {recursive: true, force: true}));
  const archive = structuredClone(value.value.archive);
  archive.files[0].content_base64 = Buffer.from('substitute').toString('base64');
  const environmentBytes = fs.readFileSync(value.output.environment);
  assert.throws(() => derivePolicyCostInput(archive, environmentBytes,
    value.plan, catalogBytes, 1), /differs from its binding/u);
});

test('policy-cost adapter rejects unbound files and manifest tampering', (t) => {
  const {plan, point} = fixture();
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'perf06-policy-files-'));
  t.after(() => fs.rmSync(base, {recursive: true, force: true}));
  const raw = path.join(base, 'raw');
  writeRaw(raw, plan, point);
  fs.writeFileSync(path.join(raw, 'unbound-secret.txt'), 'forbidden');
  const catalog = path.join(base, 'catalog.json');
  const planFile = path.join(base, 'plan.json');
  fs.writeFileSync(catalog, catalogBytes);
  fs.writeFileSync(planFile, JSON.stringify(plan));
  const output = outputPaths(base, point.point_id);
  assert.throws(() => derivePolicyCostEvidence({catalog, plan: planFile,
    pointId: point.point_id, attempt: 1, rawRoot: raw,
    evidenceRoot: output.evidence, captureArchive: output.archive,
    environment: output.environment, derivationManifest: output.derivation,
    result: output.result}), /missing or unbound files/u);
});

test('policy-cost adapter rejects semantic and TLS substitutions', () => {
  assert.throws(() => derive('P5-C01', {
    'protocol-body.bin': Buffer.alloc(256, 'y')}),
  /response body differs/u);
  assert.throws(() => derive('P5-C01', {
    'protocol-headers.txt': 'HTTP/1.1 200 OK\r\nContent-Length: 256\r\nContent-Type: application/octet-stream\r\n\r\n'}),
  /must occur exactly once/u);
  assert.throws(() => derive('P5-C01', {
    'tls-observation.json': JSON.stringify({tls_version: 'TLSv1.3',
      cipher: 'TLS_CHACHA20_POLY1305_SHA256', alpn: 'http/1.1',
      ca_verified: true, hostname_verified: true})}),
  /TLS identity/u);
});

test('policy-cost adapter rejects stale JWT metadata without retaining token', (t) => {
  const {plan, point} = fixture('P5-C04');
  const request = requestObservation(point);
  request.jwt_window.issued_at_epoch_ms = 1;
  assert.throws(() => derive('P5-C04', {
    'request-observation.json': JSON.stringify(request)}), /not fresh/u);

  const value = derive('P5-C04');
  t.after(() => fs.rmSync(value.base, {recursive: true, force: true}));
  const serialized = JSON.stringify(value.value.result);
  assert.equal(serialized.includes('Bearer '), false);
  assert.equal(value.value.result.request.values_retained, false);
  assert.equal(value.value.result.request.artifact_sha256,
    sha256('P5-C04-ephemeral-jwt'));
});

test('policy-cost adapter rejects source, denominator, and process drift', () => {
  const {plan, point} = fixture();
  const drift = provenance(plan, point);
  drift.source_status = ' M gateway.cc';
  assert.throws(() => derive('P5-C01', {
    'provenance-after.json': JSON.stringify(drift)}), /clean harness source/u);

  const count = point.offered_rps * point.measurement_seconds;
  assert.throws(() => derive('P5-C01', {
    'gateway-metrics-after.prom': metrics(point.core_count,
      count / point.core_count - 1, point.measurement_seconds * 500,
      100 + (count / point.core_count) * 2)}), /denominators differ/u);

  assert.throws(() => derive('P5-C01', {
    'resource-after.json': JSON.stringify({identity: 'pid:43:start:100',
      pid: 43, start_ticks: 100, restart_count: 1,
      rss_bytes: 44 * 1024 * 1024, file_descriptors: 17})}),
  /process identity changed/u);

  const placement = environment(plan, point);
  placement.load_generator_cpu_set.reverse();
  assert.throws(() => derive('P5-C01', {
    'environment.json': JSON.stringify(placement)}),
  /(?:environment placement|lane placement) differs/u);

  assert.throws(() => derive('P5-C01', {
    'socket-output.json': JSON.stringify({interval_id: 'foreign-point',
      duration_nanoseconds: point.measurement_seconds * 1e9,
      scope: 'gateway-downstream-sockets', pid: 42, start_ticks: 99,
      calls: count * 2,
      requested_bytes: count * point.response_payload_bytes,
      completed_bytes: count * point.response_payload_bytes,
      partial_writes: 0, would_block: 0, fatal_errors: 0, lost_events: 0})}),
  /socket interval differs/u);
});

test('policy-cost adapter binds socket capture to the client process envelope', (t) => {
  const {plan, point} = fixture();
  const request = requestObservation(point);
  const measurement = oha(plan, point, request, point.measurement_seconds);
  const processEnvelopeSeconds = point.measurement_seconds + 0.6;
  for (const lane of measurement.lanes) {
    lane.end_ns = String(processEnvelopeSeconds * 1e9);
  }

  const accepted = derive('P5-C01', {
    'measurement.oha.json': JSON.stringify(measurement),
    'socket-output.json': JSON.stringify({interval_id: point.point_id,
      duration_nanoseconds: (processEnvelopeSeconds + 0.5) * 1e9,
      scope: 'gateway-downstream-sockets', pid: 42, start_ticks: 99,
      calls: point.offered_rps * point.measurement_seconds * 2,
      requested_bytes: point.offered_rps * point.measurement_seconds *
        point.response_payload_bytes,
      completed_bytes: point.offered_rps * point.measurement_seconds *
        point.response_payload_bytes,
      partial_writes: 0, would_block: 0, fatal_errors: 0, lost_events: 0})});
  t.after(() => fs.rmSync(accepted.base, {recursive: true, force: true}));
  assert.equal(accepted.value.result.evidence_status, 'complete');

  assert.throws(() => derive('P5-C01', {
    'measurement.oha.json': JSON.stringify(measurement),
    'socket-output.json': JSON.stringify({interval_id: point.point_id,
      duration_nanoseconds: (processEnvelopeSeconds - 0.001) * 1e9,
      scope: 'gateway-downstream-sockets', pid: 42, start_ticks: 99,
      calls: point.offered_rps * point.measurement_seconds * 2,
      requested_bytes: point.offered_rps * point.measurement_seconds *
        point.response_payload_bytes,
      completed_bytes: point.offered_rps * point.measurement_seconds *
        point.response_payload_bytes,
      partial_writes: 0, would_block: 0, fatal_errors: 0, lost_events: 0})}),
  /bounded client process envelope/u);

  assert.throws(() => derive('P5-C01', {
    'measurement.oha.json': JSON.stringify(measurement),
    'socket-output.json': JSON.stringify({interval_id: point.point_id,
      duration_nanoseconds: (processEnvelopeSeconds + 1.001) * 1e9,
      scope: 'gateway-downstream-sockets', pid: 42, start_ticks: 99,
      calls: point.offered_rps * point.measurement_seconds * 2,
      requested_bytes: point.offered_rps * point.measurement_seconds *
        point.response_payload_bytes,
      completed_bytes: point.offered_rps * point.measurement_seconds *
        point.response_payload_bytes,
      partial_writes: 0, would_block: 0, fatal_errors: 0, lost_events: 0})}),
  /bounded client process envelope/u);
});

test('policy-cost adapter retains transport failures that precede gateway admission', (t) => {
  const {plan, point} = fixture('P5-C00');
  const request = requestObservation(point);
  const measurement = oha(plan, point, request, point.measurement_seconds);
  for (const lane of measurement.lanes) {
    const report = JSON.parse(lane.raw_json);
    report.statusCodeDistribution['200'] -= 3;
    report.errorDistribution = {timeout: 3};
    lane.raw_json = JSON.stringify(report);
  }
  const total = point.offered_rps * point.measurement_seconds;
  const successful = total - 3 * measurement.lanes.length;
  const value = derive('P5-C00', {
    'measurement.oha.json': JSON.stringify(measurement),
    'gateway-metrics-after.prom': metrics(point.core_count,
      successful / point.core_count, point.measurement_seconds * 500,
      100 + successful / point.core_count * 2),
  });
  t.after(() => fs.rmSync(value.base, {recursive: true, force: true}));
  assert.equal(value.value.result.runtime.transport_failure_count, 24);
  assert.equal(value.value.result.metrics.successful_responses, successful);
  assert.equal(value.value.result.runtime.unexpected_error_count, 0);
});
