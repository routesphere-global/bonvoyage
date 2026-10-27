import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {partitionCpus} from './phase5-oha-lanes.mjs';
import {buildProtocolNativePlan} from './phase5-protocol-native-plan.mjs';
import {validateProtocolNativeResult} from './phase5-protocol-native-result.mjs';
import {catalogBytes, nativePlanInput, runtimeInventoryBytes} from
  './phase5-protocol-native-test-fixture.mjs';
import {deriveP5T01Evidence, deriveP5T01Input,
  validateP5T01WarmupAdmission} from
  './phase5-protocol-p5-t01-native.mjs';

const RAW_FILES = [
  'environment.json', 'final-metrics.prom', 'gateway-metrics-after.prom',
  'gateway-metrics-before.prom', 'gateway-proc-after.txt',
  'gateway-proc-before.txt', 'journal.log',
  'load-generator-proc-after.txt', 'load-generator-proc-before.txt',
  'measurement.oha.json', 'perf.csv', 'protocol-probe.json',
  'provenance-after.json', 'provenance-before.json', 'resource-after.json',
  'resource-before.json', 'runtime-inventory.json', 'socket-output.json', 'status.json',
  'upstream-proc-after.txt', 'upstream-proc-before.txt',
  'warmup-admission.json', 'warmup.oha.json',
];

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function fixture() {
  const bytes = catalogBytes();
  const plan = buildProtocolNativePlan(nativePlanInput(bytes), bytes);
  const point = plan.points.find((item) =>
    item.variant_id === 't01-fixed-response-15360-8c');
  const variant = plan.input.variants.find((item) => item.id === point.variant_id);
  return {bytes, plan, point, variant};
}

function oha(plan, variant, duration = 60,
  lanes = plan.input.topology.load_generator_lanes) {
  const targetRps = variant.workload.target_rps;
  const rate = targetRps / lanes;
  const requests = rate * duration;
  const gateway = plan.input.topology.roles.find((item) => item.role === 'gateway');
  const mode = variant.scenario === 'fixed-response' ? 'fixed' : 'proxied';
  const workload = {request_mode: 'fixed-count',
    client_sha256: plan.input.source.load_client_sha256,
    protocol: 'http1', tls: true, authority: 'api.example.test',
    listener_port: 8443, target_addresses: [gateway.private_address],
    path: `/perf05/${mode}/${variant.payload_bytes}`,
    connections_per_lane: variant.workload.connections / lanes,
    streams_per_connection: 1, requests_per_lane: requests,
    memory_limit_bytes: 4 * 1024 ** 3, ca_sha256: sha256('ca'),
    credential_sha256: null, method: 'GET', keepalive: true,
    compression: false, latency_correction: true,
    request_timeout_seconds: 5, connect_timeout_seconds: 5,
    redirect_limit: 0};
  const raw = JSON.stringify({summary: {total: duration},
    statusCodeDistribution: {'200': requests}, errorDistribution: {},
    latencyPercentiles: {p50: 0.001, p95: 0.003, p99: 0.005,
      'p99.9': 0.009}});
  return {kind: 'phase5-oha-lanes', schema_version: 2,
    rate_per_lane: rate,
    cpu_sets: partitionCpus(
      plan.input.topology.load_generator_cpu_set.join(','), lanes),
    workload,
    lanes: Array.from({length: lanes}, (_, index) => ({index,
      start_ns: '0', end_ns: String(duration * 1e9), exit_code: 0,
      raw_json: raw, stderr: '', target_address: gateway.private_address}))};
}

function metrics(coreCount, successfulPerShard, busyMs, waits = 0,
  waitNanoseconds = 0, waitMaximumNanoseconds = 0, allocations = 0) {
  const lines = [];
  for (let shard = 0; shard < coreCount; shard += 1) {
    const label = `{shard="${shard}"}`;
    lines.push(`bonvoyage_bonvoyage_gateway_requests_total${label} ${successfulPerShard}`);
    lines.push(`bonvoyage_bonvoyage_gateway_responses_2xx_total${label} ${successfulPerShard}`);
    lines.push(`bonvoyage_bonvoyage_gateway_upstream_http1_pool_waits_total${label} ${waits}`);
    lines.push(`bonvoyage_bonvoyage_gateway_upstream_http1_pool_wait_nanoseconds_total${label} ${waitNanoseconds}`);
    lines.push(`bonvoyage_bonvoyage_gateway_upstream_http1_pool_wait_max_nanoseconds${label} ${waitMaximumNanoseconds}`);
    lines.push(`bonvoyage_memory_malloc_operations${label} ${allocations}`);
    lines.push(`bonvoyage_reactor_cpu_busy_ms${label} ${busyMs}`);
  }
  return `${lines.join('\n')}\n`;
}

function finalMetrics() {
  return [
    'bonvoyage_bonvoyage_gateway_active_requests 0',
    'bonvoyage_bonvoyage_gateway_active_route_requests 0',
    'bonvoyage_bonvoyage_gateway_active_upstream_requests 0',
    'bonvoyage_bonvoyage_gateway_active_upstream_http1_requests 0',
    'bonvoyage_bonvoyage_gateway_active_http2_streams 0',
    '',
  ].join('\n');
}

function proc(before, busy = 40) {
  if (before) return 'cpu 100 0 100 700 0 10 10 0\n';
  const active = busy * 10;
  const idle = (100 - busy) * 10;
  return `cpu ${100 + active - 20} 0 100 ${700 + idle} 0 20 20 0\n`;
}

function provenance(plan, point, variant) {
  return {schema_version: 1, plan_id: plan.plan_id,
    point_id: point.point_id, variant_id: variant.id,
    repetition: point.repetition, source: plan.input.source,
    catalog_sha256: plan.input.catalog_sha256,
    snapshot_sha256: variant.snapshot_sha256,
    observed_harness_commit: plan.input.source.harness_commit,
    source_status: ''};
}

function environment(plan, point, variant, attempt = 1) {
  const tids = Array.from({length: variant.core_count}, (_, index) => 100 + index);
  return {schema_version: 1, plan_id: plan.plan_id,
    point_id: point.point_id, variant_id: variant.id,
    repetition: point.repetition, attempt,
    roles: plan.input.topology.roles,
    load_generator_cpu_set: plan.input.topology.load_generator_cpu_set,
    load_generator_lanes: plan.input.topology.load_generator_lanes,
    gateway_cpu_set: plan.input.topology.gateway_cpu_sets[String(variant.core_count)],
    gateway_housekeeping_cpus: plan.input.topology.gateway_housekeeping_cpus,
    irq_policy: plan.input.topology.irq_policy,
    profiler_scope: plan.result_contract.profiler_scope,
    reactor_tids_before: [...tids], reactor_tids_after: [...tids],
    profiled_reactor_tids: [...tids]};
}

function protocolProbe(variant) {
  const mode = variant.scenario === 'fixed-response' ? 'fixed' : 'proxied';
  return {schema_version: 1, profile: 'P5-T01', status: 'pass', cases: [{
    mode, payload_bytes: variant.payload_bytes, status: 200,
    content_length: variant.payload_bytes,
    content_type: 'application/octet-stream',
    payload_sha256: sha256(Buffer.alloc(variant.payload_bytes, 'x')),
    upstream_marker_present: mode === 'proxied',
    transport: {tls_version: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384',
      alpn: 'http/1.1', ca_verified: true, hostname_verified: true},
  }], negative_probes: {wrong_hostname_rejected: true,
    untrusted_ca_rejected: true}};
}

function warmupAdmission(plan, variant) {
  const required = plan.input.schedule.profiled_warmup_repetitions;
  const successfulRequests = variant.workload.target_rps *
    variant.workload.warmup_seconds;
  const passes = Array.from({length: required}, (_, index) => ({
    pass: index + 1, settled: true, settlement_ms: 150,
    identity: 'pid:42:start:99', restart_count: 0,
    rss_bytes: 44 * 1024 * 1024, file_descriptors: 17,
    successful_requests: successfulRequests, http_failures: 0,
    transport_failures: 0,
  }));
  return {schema_version: 1,
    required_profiled_warmup_repetitions: required, passes,
    plateau: {compared_passes: [required - 1, required],
      rss_delta_bytes: 0, fd_delta: 0, stable: true}};
}

function writeRaw(root, plan, point, variant, changes = {}) {
  const count = variant.workload.target_rps * variant.workload.measurement_seconds;
  const perShard = count / variant.core_count;
  const values = {
    'environment.json': JSON.stringify(environment(plan, point, variant)),
    'final-metrics.prom': finalMetrics(),
    'gateway-metrics-before.prom': metrics(variant.core_count, 0, 0, 0, 0, 0,
      100),
    'gateway-metrics-after.prom': metrics(variant.core_count, perShard,
      variant.workload.measurement_seconds * 500, 0, 0, 0,
      100 + perShard * 2),
    'gateway-proc-before.txt': proc(true),
    'gateway-proc-after.txt': proc(false, 60),
    'journal.log': '',
    'load-generator-proc-before.txt': proc(true),
    'load-generator-proc-after.txt': proc(false, 40),
    'measurement.oha.json': JSON.stringify(oha(plan, variant,
      variant.workload.measurement_seconds)),
    'perf.csv': '24000000000,,cycles\n12000000000,,instructions\n1200,,cache-misses\n36000000,,raw_syscalls:sys_enter\n',
    'protocol-probe.json': JSON.stringify(protocolProbe(variant)),
    'provenance-after.json': JSON.stringify(provenance(plan, point, variant)),
    'provenance-before.json': JSON.stringify(provenance(plan, point, variant)),
    'resource-after.json': JSON.stringify({identity: 'pid:42:start:99', pid: 42,
      start_ticks: 99, restart_count: 0, rss_bytes: 48 * 1024 * 1024,
      file_descriptors: 18}),
    'resource-before.json': JSON.stringify({identity: 'pid:42:start:99', pid: 42,
      start_ticks: 99, restart_count: 0, rss_bytes: 44 * 1024 * 1024,
      file_descriptors: 17}),
    'runtime-inventory.json': runtimeInventoryBytes(),
    'socket-output.json': JSON.stringify({interval_id: point.point_id,
      duration_nanoseconds: variant.workload.measurement_seconds * 1e9,
      scope: 'gateway-downstream-sockets', pid: 42, start_ticks: 99,
      calls: count * 2, requested_bytes: count * variant.payload_bytes,
      completed_bytes: count * variant.payload_bytes, partial_writes: 0,
      would_block: 0, fatal_errors: 0, lost_events: 0}),
    'status.json': JSON.stringify({measurement_command_exit_code: 0,
      collector_exit_code: 0, protocol_probe_exit_code: 0}),
    'upstream-proc-after.txt': proc(false, 30),
    'upstream-proc-before.txt': proc(true),
    'warmup-admission.json': JSON.stringify(warmupAdmission(plan, variant)),
    'warmup.oha.json': JSON.stringify(oha(plan, variant,
      variant.workload.warmup_seconds)),
    ...changes,
  };
  fs.mkdirSync(root, {recursive: true});
  for (const name of RAW_FILES) fs.writeFileSync(path.join(root, name),
    values[name]);
  const manifest = RAW_FILES.map((name) =>
    `${sha256(fs.readFileSync(path.join(root, name)))}  ${name}`).join('\n');
  fs.writeFileSync(path.join(root, 'checksums.sha256'), `${manifest}\n`);
}

function paths(root, pointId) {
  const evidence = path.join(root, 'evidence');
  return {evidence,
    archive: path.join(evidence, `${pointId}.capture.raw.json`),
    environment: path.join(evidence, `${pointId}.environment.json`),
    derivation: path.join(evidence, `${pointId}.derivation.json`),
    result: path.join(evidence, `${pointId}.result.json`)};
}

function derive(changes = {}) {
  const {bytes, plan, point, variant} = fixture();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'perf05-p5-t01-'));
  const raw = path.join(root, 'raw');
  writeRaw(raw, plan, point, variant, changes);
  const catalog = path.join(root, 'catalog.json');
  const planFile = path.join(root, 'plan.json');
  fs.writeFileSync(catalog, bytes);
  fs.writeFileSync(planFile, JSON.stringify(plan));
  const output = paths(root, point.point_id);
  const value = deriveP5T01Evidence({catalog, plan: planFile,
    pointId: point.point_id, attempt: 1, rawRoot: raw,
    evidenceRoot: output.evidence, captureArchive: output.archive,
    environment: output.environment, derivationManifest: output.derivation,
    result: output.result});
  return {root, raw, bytes, plan, point, variant, output, value};
}

test('P5-T01 warmup admission requires three clean passes and an exact plateau', () => {
  const {plan, variant} = fixture();
  const admission = warmupAdmission(plan, variant);
  assert.equal(validateP5T01WarmupAdmission(admission, plan, variant),
    admission);

  const incomplete = structuredClone(admission);
  incomplete.passes.pop();
  assert.throws(() => validateP5T01WarmupAdmission(incomplete, plan, variant),
    /repetition contract/u);

  const rssDrift = structuredClone(admission);
  rssDrift.passes[2].rss_bytes += 4096;
  rssDrift.plateau.rss_delta_bytes = 4096;
  rssDrift.plateau.stable = false;
  assert.throws(() => validateP5T01WarmupAdmission(rssDrift, plan, variant),
    /exact resource plateau/u);

  const fdDrift = structuredClone(admission);
  fdDrift.passes[2].file_descriptors += 1;
  fdDrift.plateau.fd_delta = 1;
  fdDrift.plateau.stable = false;
  assert.throws(() => validateP5T01WarmupAdmission(fdDrift, plan, variant),
    /exact resource plateau/u);

  const replacement = structuredClone(admission);
  replacement.passes[2].identity = 'pid:43:start:100';
  assert.throws(() => validateP5T01WarmupAdmission(replacement, plan, variant),
    /failed its admission contract/u);

  const failedTraffic = structuredClone(admission);
  failedTraffic.passes[1].successful_requests -= 1;
  failedTraffic.passes[1].http_failures = 1;
  assert.throws(() => validateP5T01WarmupAdmission(failedTraffic, plan,
    variant), /failed its admission contract/u);
});

test('P5-T01 adapter derives one complete normalized result from raw evidence', (t) => {
  const value = derive();
  t.after(() => fs.rmSync(value.root, {recursive: true, force: true}));
  validateProtocolNativeResult(value.value.result, value.plan, value.bytes);
  assert.equal(value.value.result.evidence_status, 'complete');
  assert.equal(value.value.result.metrics.successful_rps, 200000);
  assert.equal(value.value.result.metrics.application_cpu_percent, 50);
  assert.equal(value.value.result.metrics.queue_waits.count, 0);
  assert.equal(value.value.result.runtime.retained_rss_growth_bytes,
    4 * 1024 * 1024);
  assert.equal(value.value.result.protocol.downstream_tls_cipher,
    'TLS_AES_256_GCM_SHA384');
  assert.equal(value.value.derivation.publication_authorized, false);
});

test('P5-T01 adapter binds the formal baseline to the admitted plateau', () => {
  const {plan, variant} = fixture();
  const admission = warmupAdmission(plan, variant);
  admission.passes[1].rss_bytes -= 4096;
  admission.passes[2].rss_bytes -= 4096;
  assert.throws(() => derive({'warmup-admission.json':
    JSON.stringify(admission)}), /baseline differs from the admitted/u);
});

test('P5-T01 raw archive is independently self-binding', (t) => {
  const value = derive();
  t.after(() => fs.rmSync(value.root, {recursive: true, force: true}));
  const archive = JSON.parse(fs.readFileSync(value.output.archive, 'utf8'));
  const environmentBytes = fs.readFileSync(value.output.environment);
  archive.files[0].content_base64 = Buffer.from('changed').toString('base64');
  assert.throws(() => deriveP5T01Input(archive, environmentBytes, value.plan,
    value.bytes, 1), /differs from its binding/u);
});

test('P5-T01 adapter derives observed pool-wait duration', (t) => {
  const {plan, point, variant} = fixture();
  const count = variant.workload.target_rps * variant.workload.measurement_seconds;
  const perShard = count / variant.core_count;
  const value = derive({'gateway-metrics-after.prom':
    metrics(variant.core_count, perShard,
      variant.workload.measurement_seconds * 500, 2, 4_000_000, 3_000_000,
      100 + perShard * 2)});
  t.after(() => fs.rmSync(value.root, {recursive: true, force: true}));
  assert.equal(value.value.result.metrics.queue_waits.count,
    variant.core_count * 2);
  assert.equal(value.value.result.metrics.queue_waits.maximum_ms, 3);
});

test('P5-T01 adapter rejects pool waits without duration telemetry', () => {
  const {plan, variant} = fixture();
  const count = variant.workload.target_rps * variant.workload.measurement_seconds;
  const perShard = count / variant.core_count;
  assert.throws(() => derive({'gateway-metrics-after.prom':
    metrics(variant.core_count, perShard,
      variant.workload.measurement_seconds * 500, 1, 0, 0,
      100 + perShard * 2)}), /pool-wait duration is inconsistent/u);
});

test('P5-T01 adapter rejects a pool-wait mean above the observed maximum', () => {
  const {variant} = fixture();
  const count = variant.workload.target_rps * variant.workload.measurement_seconds;
  const perShard = count / variant.core_count;
  assert.throws(() => derive({'gateway-metrics-after.prom':
    metrics(variant.core_count, perShard,
      variant.workload.measurement_seconds * 500, 2, 7_000_000, 3_000_000,
      100 + perShard * 2)}), /pool-wait duration is inconsistent/u);
});

test('P5-T01 adapter rejects incomplete all-reactor profiler coverage', () => {
  const {plan, point, variant} = fixture();
  const changed = environment(plan, point, variant);
  changed.profiled_reactor_tids.pop();
  assert.throws(() => derive({'environment.json': JSON.stringify(changed)}),
    /profiled_reactor_tids is incomplete/u);
});

test('P5-T01 adapter rejects TLS identity observation drift', () => {
  const {variant} = fixture();
  const probe = protocolProbe(variant);
  probe.cases[0].transport.hostname_verified = false;
  assert.throws(() => derive({'protocol-probe.json': JSON.stringify(probe)}),
    /TLS observation is incomplete/u);
});

test('P5-T01 adapter rejects source drift during capture', () => {
  const {plan, point, variant} = fixture();
  const changed = provenance(plan, point, variant);
  changed.source_status = ' M dataplane/src/gateway.cc';
  assert.throws(() => derive({'provenance-after.json': JSON.stringify(changed)}),
    /does not prove clean harness source/u);
});

test('P5-T01 adapter rejects runtime inventory substitution', () => {
  const inventory = JSON.parse(runtimeInventoryBytes());
  inventory.producer_source_commit = 'c'.repeat(40);
  assert.throws(() => derive({'runtime-inventory.json':
    `${JSON.stringify(inventory)}\n`}), /differs from the native plan/u);
});

test('P5-T01 adapter rejects client and gateway denominator disagreement', () => {
  const {variant} = fixture();
  assert.throws(() => derive({'gateway-metrics-after.prom':
    metrics(variant.core_count, 1, 1, 0, 0, 0, 101)}),
  /client and gateway request denominators differ/u);
});

test('P5-T01 adapter rejects legacy summaries without structured load identity', () => {
  const {variant} = fixture();
  const legacy = {summary: {total: variant.workload.measurement_seconds},
    statusCodeDistribution: {'200': variant.workload.target_rps *
      variant.workload.measurement_seconds}, errorDistribution: {},
    latencyPercentiles: {p50: 0.001, p95: 0.003, p99: 0.005,
      'p99.9': 0.009}, offered_rps: variant.workload.target_rps};
  assert.throws(() => derive({'measurement.oha.json': JSON.stringify(legacy)}),
    /structured workload differs from plan/u);
});

test('P5-T01 adapter rejects files outside the bound raw manifest', (t) => {
  const {plan, point, variant} = fixture();
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'perf05-p5-t01-extra-'));
  const root = path.join(parent, 'raw');
  t.after(() => fs.rmSync(parent, {recursive: true, force: true}));
  writeRaw(root, plan, point, variant);
  fs.writeFileSync(path.join(root, 'orphan.log'), 'unbound');
  const catalog = path.join(parent, 'catalog.json');
  const planFile = path.join(parent, 'plan.json');
  fs.writeFileSync(catalog, catalogBytes());
  fs.writeFileSync(planFile, JSON.stringify(plan));
  const output = paths(parent, point.point_id);
  assert.throws(() => deriveP5T01Evidence({catalog, plan: planFile,
    pointId: point.point_id, attempt: 1, rawRoot: root,
    evidenceRoot: output.evidence, captureArchive: output.archive,
    environment: output.environment, derivationManifest: output.derivation,
    result: output.result}), /unbound files/u);
});
