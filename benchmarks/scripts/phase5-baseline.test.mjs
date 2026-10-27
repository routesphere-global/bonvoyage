import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {analyze, buildLegacyPlanV7, buildPlan, packPoint, parsePerfStat,
  validatePlan} from './phase5-baseline.mjs';
import {OHA_DIRECT_LANE_MEMORY_BYTES, OHA_LANE_MEMORY_BYTES,
  partitionCpus} from './phase5-oha-lanes.mjs';

const digest = (value) => createHash('sha256').update(value).digest('hex');

function input() {
  const ids = ['P5-B01', 'P5-B02', 'P5-B03', 'P5-B04'];
  const profiles = {};
  const rates = {};
  ids.forEach((id, index) => {
    const tls = index !== 0;
    profiles[id] = {snapshot_sha256: digest(id),
      protocol: index === 2 ? 'http2' : 'http1', tls,
      connections: 64, streams: index === 2 ? 8 : 1,
      authority: 'api.example.test',
      listener_port: index === 2 ? 8444 : tls ? 8443 : 8080,
      path: '/payload/256', ca_sha256: tls ? digest('ca') : null,
      credential_sha256: index === 3 ? digest('key-file') : null};
    rates[id] = {8: {steady: 80}, 24: {steady: 80}};
  });
  return {binary_source_commit: 'a'.repeat(40),
    harness_commit: 'b'.repeat(40), source_dirty: false,
    binary_sha256: digest('gateway'), harness_runner_sha256: digest('runner'),
    client_sha256: digest('client'),
    upstream_sha256: digest('upstream'), profiles, rates,
    direct_upstream: {protocol: 'http1', tls: false, connections: 64,
      streams: 1, authority: 'upstream.example.test', listener_port: 8081,
      path: '/payload/256', targets: [
        {address: '10.0.0.43', hostname: 'upstream-a'},
        {address: '10.0.0.44', hostname: 'upstream-b'}], ca_sha256: null,
      offered_rps: 256, minimum_headroom_ratio: 1.2,
      client_lanes: 32,
      client_cpus: Array.from({length: 32}, (_, index) => index),
      memory_limit_bytes: OHA_DIRECT_LANE_MEMORY_BYTES,
      memory_swap_limit_bytes: OHA_DIRECT_LANE_MEMORY_BYTES,
      warmup_seconds: 15, measurement_seconds: 30},
    cpus: {8: [8, 9, 10, 11, 12, 13, 14, 15],
      24: Array.from({length: 24}, (_, index) => index + 8)},
    client_lanes: 16, client_cpus: Array.from({length: 32}, (_, index) => index),
    gateway_address: '10.0.0.42',
    load_points: ['steady'], repetitions: 5,
    measurement_seconds: 10, warmup_seconds: 5,
    p999_ceiling_ms: 100, evidence_class: 'shared-vm-engineering'};
}

function legacyInput() {
  const value = input();
  delete value.load_points;
  for (const profile of Object.values(value.rates)) {
    profile[8].near_knee = 96;
    profile[24].near_knee = 96;
  }
  return value;
}

function topology(plan, scope) {
  if (scope === 'direct-support') return {schemaVersion: 3,
    lanes: plan.input.direct_upstream.client_lanes,
    cpus: plan.input.direct_upstream.client_cpus,
    memoryLimitBytes: plan.input.direct_upstream.memory_limit_bytes,
    memorySwapLimitBytes: plan.input.direct_upstream.memory_swap_limit_bytes};
  return {schemaVersion: 2, lanes: plan.input.client_lanes,
    cpus: plan.input.client_cpus, memoryLimitBytes: OHA_LANE_MEMORY_BYTES};
}

function workload(plan, profile, targetAddresses, offeredRps, seconds,
  scope = 'gateway') {
  const client = topology(plan, scope);
  return {...(scope === 'direct-support' ? {evidence_scope: scope,
    memory_swap_limit_bytes: client.memorySwapLimitBytes} : {}),
    request_mode: 'fixed-count', client_sha256: plan.input.client_sha256,
    protocol: profile.protocol, tls: profile.tls, authority: profile.authority,
    listener_port: profile.listener_port,
    target_addresses: targetAddresses, path: profile.path,
    connections_per_lane: profile.connections,
    streams_per_connection: profile.streams,
    requests_per_lane: offeredRps / client.lanes * seconds,
    memory_limit_bytes: client.memoryLimitBytes,
    ca_sha256: profile.ca_sha256,
    credential_sha256: profile.credential_sha256 ?? null, method: 'GET',
    keepalive: true, compression: false, latency_correction: true,
    request_timeout_seconds: 5, connect_timeout_seconds: 5,
    redirect_limit: 0};
}

function structuredBundle(plan, profile, targetAddresses, offeredRps, seconds,
  scope = 'gateway') {
  const client = topology(plan, scope);
  const clientWorkload = workload(plan, profile, targetAddresses, offeredRps,
    seconds, scope);
  const lane = (index) => ({index, start_ns: '1000000000',
    end_ns: String(1000000000 + seconds * 1000000000), exit_code: 0, stderr: '',
    target_address: targetAddresses[index % targetAddresses.length],
    raw_json: JSON.stringify({summary: {total: seconds},
      statusCodeDistribution: {'200': clientWorkload.requests_per_lane},
      errorDistribution: {}, latencyPercentiles: {p50: 0.001, p95: 0.002,
        p99: 0.003, 'p99.9': 0.004}})});
  return {kind: 'phase5-oha-lanes', schema_version: client.schemaVersion,
    rate_per_lane: offeredRps / client.lanes,
    cpu_sets: partitionCpus(client.cpus.join(','), client.lanes,
      client.lanes === 32 ? 32 : 16),
    workload: clientWorkload,
    lanes: Array.from({length: client.lanes}, (_, index) => lane(index))};
}

function sequenceBundle(plan, profile, targetAddresses, offeredRps,
  scope = 'gateway') {
  const durations = scope === 'direct-support' ? plan.input.direct_upstream : plan.input;
  return sequenceBundleWithDurations(plan, profile, targetAddresses, offeredRps,
    durations.warmup_seconds, durations.measurement_seconds, scope);
}

function sequenceBundleWithDurations(plan, profile, targetAddresses, offeredRps,
  warmupSeconds, measurementSeconds, scope = 'gateway') {
  return {kind: 'phase5-oha-sequence', schema_version: topology(plan, scope).schemaVersion,
    warmup: structuredBundle(plan, profile, targetAddresses, offeredRps,
      warmupSeconds, scope),
    measurement: structuredBundle(plan, profile, targetAddresses, offeredRps,
      measurementSeconds, scope)};
}

function clientBundle(plan, point) {
  return sequenceBundle(plan, plan.input.profiles[point.profile],
    [plan.input.gateway_address], point.offered_rps);
}

function directBundle(plan) {
  const profile = plan.input.direct_upstream;
  return sequenceBundle(plan, profile, profile.targets.map((target) => target.address),
    profile.offered_rps, 'direct-support');
}

function writeBound(root, name, value) {
  const contents = typeof value === 'string' ? value : JSON.stringify(value);
  fs.writeFileSync(path.join(root, name), contents);
  return {path: name, sha256: digest(contents)};
}

function createFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-perf01-test-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const plan = buildPlan(input());
  const evidence = new Map();
  for (const point of plan.points) {
    const prefix = point.id;
    const response = clientBundle(plan, point);
    const perf = '100000,,cycles,\n80000,,instructions,\n100,,cache-misses,\n' +
      '1000,,raw_syscalls:sys_enter,\n';
    const shards = Object.fromEntries(Array.from({length: point.cores},
      (_, index) => [index, 6000]));
    const allocations = Object.fromEntries(Array.from({length: point.cores},
      (_, index) => [index, index === 0 ? 20 : 0]));
    const waits = Object.fromEntries(Array.from({length: point.cores},
      (_, index) => [index, 0]));
    const attribution = {schema_version: 1, hostname: 'gateway',
      process_identity_stable: true,
      source_unchanged: true, duration_seconds: 10,
      source: {commit: plan.input.harness_commit, dirty: false},
      process: {pid: 42, start_ticks: 100, restarts: 0,
        executable_sha256: plan.input.binary_sha256},
      gateway: {memory_malloc_operations_by_shard: allocations,
        upstream_http1_pool_waits_by_shard: waits,
        reactor_cpu_busy_ms_by_shard: shards},
      host: {cpu_busy_ratio: {cpu0: 0.5}, irq_cpu_busy_ratio: {cpu0: 0.02}}};
    const support = {direct: {load_generator_capacity_percent: 30,
      upstream_capacity_percent: [40, 40], direct_upstream_rps: 256},
    gateway: {load_generator_capacity_percent: 30,
      upstream_capacity_percent: [40, 40]}, load_generator_host: 'loadgen',
    upstream_hosts: ['upstream-a', 'upstream-b']};
    const result = {plan_id: plan.plan_id, point_id: point.id, attempt: 1,
      accepted: true, binary_source_commit: plan.input.binary_source_commit,
      harness_commit: plan.input.harness_commit, source_dirty: false,
      binary_sha256: plan.input.binary_sha256,
      client_sha256: plan.input.client_sha256,
      upstream_sha256: plan.input.upstream_sha256,
      snapshot_sha256: plan.input.profiles[point.profile].snapshot_sha256,
      files: {oha: writeBound(root, `${prefix}.oha.json`, response),
        diagnostic_oha: writeBound(root, `${prefix}.diagnostic.oha.json`, response),
        diagnostic_after: writeBound(root, `${prefix}.diagnostic-after.json`,
          {process: {pid: 42, start_ticks: 100, restarts: 0,
            executable_sha256: plan.input.binary_sha256},
          source: {commit: plan.input.harness_commit, dirty: false}}),
        snapshot_digest: writeBound(root, `${prefix}.snapshot-sha256.txt`,
          `${plan.input.profiles[point.profile].snapshot_sha256}\n`),
        credential_digest: writeBound(root, `${prefix}.credential-sha256.txt`,
          `${plan.input.profiles[point.profile].credential_sha256 ?? 'null'}\n`),
        perf: writeBound(root, `${prefix}.perf.csv`, perf),
        attribution: writeBound(root, `${prefix}.attribution.json`, attribution),
        support: writeBound(root, `${prefix}.support.json`, support),
        resource_before: writeBound(root, `${prefix}.before-resource.json`,
          {restart_count: 0, pid: 42, start_ticks: 100, rss_bytes: 4000000, fd: 12}),
        resource_after: writeBound(root, `${prefix}.after-resource.json`,
          {restart_count: 0, pid: 42, start_ticks: 100, rss_bytes: 4000200, fd: 12}),
        direct_loadgen_before: writeBound(root, `${prefix}.direct-loadgen-before.txt`,
          'cpu 50 0 0 50 0 0 0 0\n'),
        direct_loadgen_after: writeBound(root, `${prefix}.direct-loadgen-after.txt`,
          'cpu 80 0 0 120 0 0 0 0\n'),
        direct_upstream_a_before: writeBound(root, `${prefix}.direct-upstream-a-before.txt`,
          'cpu 50 0 0 50 0 0 0 0\n'),
        direct_upstream_a_after: writeBound(root, `${prefix}.direct-upstream-a-after.txt`,
          'cpu 90 0 0 110 0 0 0 0\n'),
        direct_upstream_b_before: writeBound(root, `${prefix}.direct-upstream-b-before.txt`,
          'cpu 50 0 0 50 0 0 0 0\n'),
        direct_upstream_b_after: writeBound(root, `${prefix}.direct-upstream-b-after.txt`,
          'cpu 90 0 0 110 0 0 0 0\n'),
        gateway_loadgen_before: writeBound(root, `${prefix}.gateway-loadgen-before.txt`,
          'cpu 50 0 0 50 0 0 0 0\n'),
        gateway_loadgen_after: writeBound(root, `${prefix}.gateway-loadgen-after.txt`,
          'cpu 80 0 0 120 0 0 0 0\n'),
        gateway_upstream_a_before: writeBound(root,
          `${prefix}.gateway-upstream-a-before.txt`, 'cpu 50 0 0 50 0 0 0 0\n'),
        gateway_upstream_a_after: writeBound(root,
          `${prefix}.gateway-upstream-a-after.txt`, 'cpu 90 0 0 110 0 0 0 0\n'),
        gateway_upstream_b_before: writeBound(root,
          `${prefix}.gateway-upstream-b-before.txt`, 'cpu 50 0 0 50 0 0 0 0\n'),
        gateway_upstream_b_after: writeBound(root,
          `${prefix}.gateway-upstream-b-after.txt`, 'cpu 90 0 0 110 0 0 0 0\n'),
        direct_upstream: writeBound(root, `${prefix}.direct.oha.json`,
          directBundle(plan)),
        direct_loadgen_host: writeBound(root, `${prefix}.direct-loadgen-host.txt`,
          'loadgen\n'),
        direct_upstream_a_host: writeBound(root, `${prefix}.direct-upstream-a-host.txt`,
          'upstream-a\n'),
        direct_upstream_b_host: writeBound(root, `${prefix}.direct-upstream-b-host.txt`,
          'upstream-b\n'),
        gateway_loadgen_host: writeBound(root, `${prefix}.gateway-loadgen-host.txt`,
          'loadgen\n'),
        gateway_upstream_a_host: writeBound(root,
          `${prefix}.gateway-upstream-a-host.txt`, 'upstream-a\n'),
        gateway_upstream_b_host: writeBound(root,
          `${prefix}.gateway-upstream-b-host.txt`, 'upstream-b\n'),
        direct_source_commit: writeBound(root, `${prefix}.direct-source-commit.txt`,
          `${plan.input.harness_commit}\n`),
        direct_expected_runner: writeBound(root, `${prefix}.direct-expected-runner.txt`,
          `${plan.input.harness_runner_sha256}\n`),
        gateway_expected_runner: writeBound(root, `${prefix}.gateway-expected-runner.txt`,
          `${plan.input.harness_runner_sha256}\n`),
        ...Object.fromEntries(['direct', 'gateway'].flatMap((scope) => [
          [`${scope}_loadgen_source_before`, writeBound(root,
            `${prefix}.${scope}-source-before.txt`, `${plan.input.harness_commit}\n`)],
          [`${scope}_loadgen_source_after`, writeBound(root,
            `${prefix}.${scope}-source-after.txt`, `${plan.input.harness_commit}\n`)],
          [`${scope}_loadgen_status_before`, writeBound(root,
            `${prefix}.${scope}-status-before.txt`, '')],
          [`${scope}_loadgen_status_after`, writeBound(root,
            `${prefix}.${scope}-status-after.txt`, '')],
          [`${scope}_loadgen_runner_before`, writeBound(root,
            `${prefix}.${scope}-runner-before.txt`, `${plan.input.harness_runner_sha256}\n`)],
          [`${scope}_loadgen_runner_after`, writeBound(root,
            `${prefix}.${scope}-runner-after.txt`, `${plan.input.harness_runner_sha256}\n`)],
        ]))},
      support,
      resource: {restart_count: 0, pid_before: 42, pid_after: 42,
        start_ticks_before: 100, start_ticks_after: 100,
        rss_before_bytes: 4000000, rss_after_bytes: 4000200,
        fd_before: 12, fd_after: 12},
      counters: {allocations: 20, queue_waits: 0, application_cpu_percent: 60,
        host_cpu_percent: 50, irq_cpu_percent: 2,
        shard_cpu_percent: Array(point.cores).fill(60)}};
    const filename = `${prefix}.result.json`;
    fs.writeFileSync(path.join(root, filename), JSON.stringify(result));
    evidence.set(point.id, {filename, result});
  }
  function modify(pointId, update) {
    const item = evidence.get(pointId);
    update(item.result);
    fs.writeFileSync(path.join(root, item.filename), JSON.stringify(item.result));
  }
  return {root, plan, evidence, modify, first: plan.points[0].id};
}

test('plan is deterministic and schedules five distinct repetitions at every point', () => {
  const plan = buildPlan(input());
  assert.equal(plan.schema_version, 8);
  assert.equal(plan.points.length, 40);
  assert.deepEqual(buildPlan(input()), plan);
  assert.equal(new Set(plan.points.map((point) => point.id)).size, 40);
  assert.deepEqual(new Set(plan.points.map((point) => point.repetition)),
    new Set([1, 2, 3, 4, 5]));
  assert.deepEqual(new Set(plan.points.map((point) => point.load)),
    new Set(['steady']));
});

test('schema-version-7 plans remain deterministic and replayable', () => {
  const legacy = buildLegacyPlanV7(legacyInput());
  assert.equal(legacy.schema_version, 7);
  assert.equal(legacy.points.length, 80);
  assert.deepEqual(validatePlan(legacy), legacy);
});

test('plan rejects dirty source, profile drift, invalid CPU placement, and missing rates', () => {
  const dirty = input(); dirty.source_dirty = true;
  assert.throws(() => buildPlan(dirty), /clean source/u);
  const protocol = input(); protocol.profiles['P5-B03'].protocol = 'http1';
  protocol.profiles['P5-B03'].streams = 1;
  assert.throws(() => buildPlan(protocol), /profile protocol\/TLS/u);
  const cpus = input(); cpus.cpus[24][23] = 8;
  assert.throws(() => buildPlan(cpus), /CPU set invalid/u);
  const lanes = input(); lanes.client_lanes = 8;
  assert.throws(() => buildPlan(lanes), /sixteen client lanes/u);
  const rates = input(); delete rates.rates['P5-B04'][24].steady;
  assert.throws(() => buildPlan(rates), /missing or unexpected/u);
  const expanded = input(); expanded.load_points.push('near_knee');
  assert.throws(() => buildPlan(expanded), /steady-only contract/u);
  const directTarget = input(); directTarget.direct_upstream.targets[0].address = 'bad target';
  assert.throws(() => buildPlan(directTarget), /target 0 address invalid/u);
  const duplicateTarget = input(); duplicateTarget.direct_upstream.targets[1].address =
    duplicateTarget.direct_upstream.targets[0].address;
  assert.throws(() => buildPlan(duplicateTarget), /identities must be distinct/u);
  const directRatio = input(); directRatio.direct_upstream.minimum_headroom_ratio = 1.1;
  assert.throws(() => buildPlan(directRatio), /remain 1.2/u);
  const directTls = input(); directTls.direct_upstream.tls = true;
  assert.throws(() => buildPlan(directTls), /cleartext HTTP\/1.1/u);
  const directLanes = input(); directLanes.direct_upstream.client_lanes = 16;
  assert.throws(() => buildPlan(directLanes), /32 distinct one-core/u);
  const directCpus = input(); directCpus.direct_upstream.client_cpus[31] = 0;
  assert.throws(() => buildPlan(directCpus), /32 distinct one-core/u);
  const directMemory = input(); directMemory.direct_upstream.memory_limit_bytes += 1;
  assert.throws(() => buildPlan(directMemory), /memory limit changed/u);
  const directSwap = input(); directSwap.direct_upstream.memory_swap_limit_bytes += 1;
  assert.throws(() => buildPlan(directSwap), /memory\/swap limit changed/u);
  const missingDirectDuration = input();
  delete missingDirectDuration.direct_upstream.warmup_seconds;
  assert.throws(() => buildPlan(missingDirectDuration), /missing or unexpected/u);
  const directDurationOrder = input();
  directDurationOrder.direct_upstream.warmup_seconds =
    directDurationOrder.direct_upstream.measurement_seconds;
  assert.throws(() => buildPlan(directDurationOrder), /must exceed warmup/u);
  const legacy = buildPlan(input()); legacy.schema_version = 6;
  assert.throws(() => validatePlan(legacy), /invalid PERF-01 plan header/u);
});

test('perf parser rejects missing and unsupported required counters', () => {
  assert.deepEqual(parsePerfStat('100,,cycles,\n80,,instructions,\n' +
    '1,,cache-misses,\n5,,raw_syscalls:sys_enter,\n'),
  {cycles: 100, instructions: 80, cache_misses: 1, syscalls: 5, ipc: 0.8});
  assert.throws(() => parsePerfStat('100,,cycles,\n'), /missing or unexpected/u);
  assert.throws(() => parsePerfStat('0,,cycles,\n80,,instructions,\n' +
    '1,,cache-misses,\n<not counted>,,raw_syscalls:sys_enter,\n'),
  /unavailable/u);
});

test('complete synthetic matrix passes contract, without claiming a measurement', (t) => {
  const fixture = createFixture(t);
  const summary = analyze(fixture.plan, fixture.root);
  assert.equal(summary.accepted_points, 40);
  assert.equal(summary.attempts, 40);
  assert.equal(summary.evidence_class, 'shared-vm-engineering');
  const steady = summary.rows.find((row) => row.point_id === fixture.first);
  assert.equal(steady.successful_rps, 80);
  assert.equal(steady.diagnostic_profiled_warmup_responses, 400);
  assert.equal(steady.diagnostic_profiled_measurement_responses, 800);
  assert.equal(steady.diagnostic_profiled_successful_responses, 1200);
  assert.equal(steady.diagnostic_cycles_per_request, 100000 / 1200);
  assert.equal(steady.diagnostic_instructions_per_request, 80000 / 1200);
  assert.equal(steady.diagnostic_syscalls_per_request, 1000 / 1200);
});

test('formal analyzer replays multi-lane raw responses and rejects a forged tail', (t) => {
  const fixture = createFixture(t);
  const first = fixture.evidence.get(fixture.first).result;
  const bundle = JSON.parse(fs.readFileSync(path.join(fixture.root,
    first.files.oha.path), 'utf8'));
  const secondLane = JSON.parse(bundle.measurement.lanes[1].raw_json);
  secondLane.latencyPercentiles['p99.9'] = 0.005;
  bundle.measurement.lanes[1].raw_json = JSON.stringify(secondLane);
  first.files.oha = writeBound(fixture.root, first.files.oha.path, bundle);
  fixture.modify(fixture.first, () => {});
  const summary = analyze(fixture.plan, fixture.root);
  assert.equal(summary.rows.find((row) => row.point_id === fixture.first).p999_ms, 5);
  bundle.measurement.rate_per_lane += 1;
  first.files.oha = writeBound(fixture.root, first.files.oha.path, bundle);
  fixture.modify(fixture.first, () => {});
  assert.throws(() => analyze(fixture.plan, fixture.root),
    /lane placement or rate differs from plan|warmup and measurement workload shapes differ/u);
  bundle.measurement.rate_per_lane -= 1;
  secondLane.statusCodeDistribution = {
    '503': bundle.measurement.workload.requests_per_lane};
  bundle.measurement.lanes[1].raw_json = JSON.stringify(secondLane);
  first.files.oha = writeBound(fixture.root, first.files.oha.path, bundle);
  fixture.modify(fixture.first, () => {});
  assert.throws(() => analyze(fixture.plan, fixture.root), /non-200/u);
});

function createCapture(fixture) {
  const capture = path.join(fixture.root, 'capture');
  fs.mkdirSync(capture);
  fs.mkdirSync(path.join(capture, 'before'));
  fs.mkdirSync(path.join(capture, 'after'));
  fs.mkdirSync(path.join(capture, 'diagnostic-after'));
  const point = fixture.evidence.get(fixture.first).result;
  const copied = [
    ['oha.json', point.files.oha],
    ['diagnostic.oha.json', point.files.diagnostic_oha],
    ['diagnostic-after/snapshot.json', point.files.diagnostic_after],
    ['perf.csv', point.files.perf],
    ['attribution.json', point.files.attribution],
    ['before-resource.json', point.files.resource_before],
    ['after-resource.json', point.files.resource_after],
    ['direct-loadgen-proc-before.txt', point.files.direct_loadgen_before],
    ['direct-loadgen-proc-after.txt', point.files.direct_loadgen_after],
    ['direct-upstream-a-proc-before.txt', point.files.direct_upstream_a_before],
    ['direct-upstream-a-proc-after.txt', point.files.direct_upstream_a_after],
    ['direct-upstream-b-proc-before.txt', point.files.direct_upstream_b_before],
    ['direct-upstream-b-proc-after.txt', point.files.direct_upstream_b_after],
    ['gateway-loadgen-proc-before.txt', point.files.gateway_loadgen_before],
    ['gateway-loadgen-proc-after.txt', point.files.gateway_loadgen_after],
    ['gateway-upstream-a-proc-before.txt', point.files.gateway_upstream_a_before],
    ['gateway-upstream-a-proc-after.txt', point.files.gateway_upstream_a_after],
    ['gateway-upstream-b-proc-before.txt', point.files.gateway_upstream_b_before],
    ['gateway-upstream-b-proc-after.txt', point.files.gateway_upstream_b_after],
    ['direct-upstream.oha.json', point.files.direct_upstream],
    ['direct-loadgen-host.txt', point.files.direct_loadgen_host],
    ['direct-upstream-a-host.txt', point.files.direct_upstream_a_host],
    ['direct-upstream-b-host.txt', point.files.direct_upstream_b_host],
    ['gateway-loadgen-host.txt', point.files.gateway_loadgen_host],
    ['gateway-upstream-a-host.txt', point.files.gateway_upstream_a_host],
    ['gateway-upstream-b-host.txt', point.files.gateway_upstream_b_host],
    ['direct-source-commit.txt', point.files.direct_source_commit],
    ['direct-expected-runner-sha256.txt', point.files.direct_expected_runner],
    ['expected-runner-sha256.txt', point.files.gateway_expected_runner],
    ['direct-loadgen-source-commit-before.txt', point.files.direct_loadgen_source_before],
    ['direct-loadgen-source-commit-after.txt', point.files.direct_loadgen_source_after],
    ['direct-loadgen-source-status-before.txt', point.files.direct_loadgen_status_before],
    ['direct-loadgen-source-status-after.txt', point.files.direct_loadgen_status_after],
    ['direct-loadgen-runner-sha256-before.txt', point.files.direct_loadgen_runner_before],
    ['direct-loadgen-runner-sha256-after.txt', point.files.direct_loadgen_runner_after],
    ['gateway-loadgen-source-commit-before.txt', point.files.gateway_loadgen_source_before],
    ['gateway-loadgen-source-commit-after.txt', point.files.gateway_loadgen_source_after],
    ['gateway-loadgen-source-status-before.txt', point.files.gateway_loadgen_status_before],
    ['gateway-loadgen-source-status-after.txt', point.files.gateway_loadgen_status_after],
    ['gateway-loadgen-runner-sha256-before.txt', point.files.gateway_loadgen_runner_before],
    ['gateway-loadgen-runner-sha256-after.txt', point.files.gateway_loadgen_runner_after],
    ['snapshot-sha256.txt', point.files.snapshot_digest],
    ['credential-sha256.txt', point.files.credential_digest],
  ];
  for (const [name, reference] of copied) {
    fs.copyFileSync(path.join(fixture.root, reference.path), path.join(capture, name));
  }
  fs.writeFileSync(path.join(capture, 'before/snapshot.json'), '{}');
  fs.writeFileSync(path.join(capture, 'after/snapshot.json'), '{}');
  fs.writeFileSync(path.join(capture, 'source-commit.txt'),
    `${fixture.plan.input.harness_commit}\n`);
  fs.writeFileSync(path.join(capture, 'client-exit-code.txt'), '0\n');
  fs.writeFileSync(path.join(capture, 'diagnostic-exit-code.txt'), '0\n');
  const names = ['source-commit.txt', 'before/snapshot.json', 'after/snapshot.json',
    'client-exit-code.txt', 'diagnostic-exit-code.txt',
    ...copied.map(([name]) => name)];
  fs.writeFileSync(path.join(capture, 'checksums.sha256'), names.map((name) =>
    `${digest(fs.readFileSync(path.join(capture, name)))}  ./${name}`).join('\n') + '\n');
  return capture;
}

function rewriteManifest(capture) {
  const names = fs.readFileSync(path.join(capture, 'checksums.sha256'), 'utf8')
    .trim().split('\n').map((line) => line.split('  ./')[1]);
  fs.writeFileSync(path.join(capture, 'checksums.sha256'), names.map((name) =>
    `${digest(fs.readFileSync(path.join(capture, name)))}  ./${name}`).join('\n') + '\n');
}

test('single-point pack binds the native capture and rejects changed raw bytes', (t) => {
  const fixture = createFixture(t);
  const capture = createCapture(fixture);
  const packed = packPoint(fixture.plan, fixture.first, capture, fixture.root);
  assert.equal(packed.point_id, fixture.first);
  assert.equal(packed.files.oha.path, 'capture/oha.json');
  fs.appendFileSync(path.join(capture, 'oha.json'), '\n');
  assert.throws(() => packPoint(fixture.plan, fixture.first, capture, fixture.root),
    /checksum mismatch/u);
});

test('pack binds warmup count and rejects warmup failures', (t) => {
  const fixture = createFixture(t);
  const capture = createCapture(fixture);
  for (const name of ['oha.json', 'diagnostic.oha.json']) {
    const filename = path.join(capture, name);
    const sequence = JSON.parse(fs.readFileSync(filename, 'utf8'));
    sequence.warmup.workload.requests_per_lane += 1;
    fs.writeFileSync(filename, JSON.stringify(sequence));
  }
  rewriteManifest(capture);
  assert.throws(() => packPoint(fixture.plan, fixture.first, capture, fixture.root),
    /fixed request count differs|warmup workload differs from plan/u);

  const failureFixture = createFixture(t);
  const failed = createCapture(failureFixture);
  const filename = path.join(failed, 'oha.json');
  const sequence = JSON.parse(fs.readFileSync(filename, 'utf8'));
  const lane = JSON.parse(sequence.warmup.lanes[0].raw_json);
  lane.statusCodeDistribution = {
    '200': sequence.warmup.workload.requests_per_lane - 1, '503': 1};
  sequence.warmup.lanes[0].raw_json = JSON.stringify(lane);
  fs.writeFileSync(filename, JSON.stringify(sequence));
  rewriteManifest(failed);
  assert.throws(() => packPoint(failureFixture.plan, failureFixture.first,
    failed, failureFixture.root),
    /warmup includes non-200/u);
});

test('pack binds the direct-upstream target and workload', (t) => {
  const fixture = createFixture(t);
  const capture = createCapture(fixture);
  const filename = path.join(capture, 'direct-upstream.oha.json');
  const sequence = JSON.parse(fs.readFileSync(filename, 'utf8'));
  for (const stage of ['warmup', 'measurement']) {
    sequence[stage].workload.target_addresses[1] = '10.0.0.99';
  }
  fs.writeFileSync(filename, JSON.stringify(sequence));
  rewriteManifest(capture);
  assert.throws(() => packPoint(fixture.plan, fixture.first, capture, fixture.root),
    /target differs from workload|direct upstream .* workload differs from plan/u);
});

test('pack rejects direct and gateway evidence scope substitution', (t) => {
  const fixture = createFixture(t);
  const capture = createCapture(fixture);
  fs.copyFileSync(path.join(capture, 'oha.json'),
    path.join(capture, 'direct-upstream.oha.json'));
  rewriteManifest(capture);
  assert.throws(() => packPoint(fixture.plan, fixture.first, capture, fixture.root),
    /direct upstream client schema differs from its evidence scope/u);

  const reverseFixture = createFixture(t);
  const reverseCapture = createCapture(reverseFixture);
  fs.copyFileSync(path.join(reverseCapture, 'direct-upstream.oha.json'),
    path.join(reverseCapture, 'oha.json'));
  fs.copyFileSync(path.join(reverseCapture, 'direct-upstream.oha.json'),
    path.join(reverseCapture, 'diagnostic.oha.json'));
  rewriteManifest(reverseCapture);
  assert.throws(() => packPoint(reverseFixture.plan, reverseFixture.first,
    reverseCapture, reverseFixture.root),
  /client schema differs from its evidence scope/u);
});

test('pack keeps direct-support and gateway durations independent', (t) => {
  const directFixture = createFixture(t);
  const directCapture = createCapture(directFixture);
  const directProfile = directFixture.plan.input.direct_upstream;
  fs.writeFileSync(path.join(directCapture, 'direct-upstream.oha.json'),
    JSON.stringify(sequenceBundleWithDurations(directFixture.plan, directProfile,
      directProfile.targets.map((target) => target.address),
      directProfile.offered_rps, directFixture.plan.input.warmup_seconds,
      directFixture.plan.input.measurement_seconds, 'direct-support')));
  rewriteManifest(directCapture);
  assert.throws(() => packPoint(directFixture.plan, directFixture.first,
    directCapture, directFixture.root),
  /direct upstream warmup workload differs from plan/u);

  const gatewayFixture = createFixture(t);
  const gatewayCapture = createCapture(gatewayFixture);
  const point = gatewayFixture.plan.points.find((item) =>
    item.id === gatewayFixture.first);
  const profile = gatewayFixture.plan.input.profiles[point.profile];
  const substituted = sequenceBundleWithDurations(gatewayFixture.plan, profile,
    [gatewayFixture.plan.input.gateway_address], point.offered_rps,
    gatewayFixture.plan.input.direct_upstream.warmup_seconds,
    gatewayFixture.plan.input.direct_upstream.measurement_seconds);
  fs.writeFileSync(path.join(gatewayCapture, 'oha.json'), JSON.stringify(substituted));
  fs.writeFileSync(path.join(gatewayCapture, 'diagnostic.oha.json'),
    JSON.stringify(substituted));
  rewriteManifest(gatewayCapture);
  assert.throws(() => packPoint(gatewayFixture.plan, gatewayFixture.first,
    gatewayCapture, gatewayFixture.root),
  /capacity warmup workload differs from plan/u);
});

for (const [field, mutate] of [
  ['request_mode', () => 'duration'],
  ['protocol', (value) => value === 'http1' ? 'http2' : 'http1'],
  ['tls', (value) => !value],
  ['connections_per_lane', (value) => value + 1],
  ['streams_per_connection', (value) => value + 1],
  ['requests_per_lane', (value) => value + 1],
  ['memory_limit_bytes', (value) => value / 2],
  ['authority', () => 'forged.example.test'],
  ['listener_port', (value) => value + 1],
  ['target_addresses', () => ['10.0.0.99']],
  ['path', () => '/payload/1024'],
  ['client_sha256', () => digest('forged-client')],
  ['ca_sha256', () => digest('forged-ca')],
  ['credential_sha256', () => digest('forged-credential')],
  ['method', () => 'POST'],
  ['keepalive', () => false],
  ['compression', () => true],
  ['latency_correction', () => false],
  ['request_timeout_seconds', (value) => value + 1],
  ['connect_timeout_seconds', (value) => value + 1],
  ['redirect_limit', (value) => value + 1],
]) {
  test(`pack rejects changed client workload ${field}`, (t) => {
    const fixture = createFixture(t);
    const capture = createCapture(fixture);
    for (const name of ['oha.json', 'diagnostic.oha.json']) {
      const filename = path.join(capture, name);
      const bundle = JSON.parse(fs.readFileSync(filename, 'utf8'));
      bundle.measurement.workload[field] =
        mutate(bundle.measurement.workload[field]);
      fs.writeFileSync(filename, JSON.stringify(bundle));
    }
    rewriteManifest(capture);
    assert.throws(() => packPoint(fixture.plan, fixture.first, capture, fixture.root),
    /workload|protocol|streams|fixed request|request mode|CA identity|cleartext CA|fixed client behavior|memory limit|target addresses/u);
  });
}

test('pack rejects changed client CPU placement and lane count', (t) => {
  const fixture = createFixture(t);
  const capture = createCapture(fixture);
  for (const name of ['oha.json', 'diagnostic.oha.json']) {
    const filename = path.join(capture, name);
    const bundle = JSON.parse(fs.readFileSync(filename, 'utf8'));
    bundle.measurement.cpu_sets[15] = '30,32';
    fs.writeFileSync(filename, JSON.stringify(bundle));
  }
  rewriteManifest(capture);
  assert.throws(() => packPoint(fixture.plan, fixture.first, capture, fixture.root),
    /lane placement or rate differs from plan|warmup and measurement workload shapes differ/u);
});

test('missing repetition and duplicate accepted attempt cannot pass', (t) => {
  const fixture = createFixture(t);
  fs.unlinkSync(path.join(fixture.root, fixture.evidence.get(fixture.first).filename));
  assert.throws(() => analyze(fixture.plan, fixture.root), /missing accepted/u);
  const second = fixture.plan.points[1].id;
  const cloned = {...fixture.evidence.get(second).result, attempt: 2};
  fs.writeFileSync(path.join(fixture.root, 'extra.result.json'), JSON.stringify(cloned));
  assert.throws(() => analyze(fixture.plan, fixture.root), /duplicate accepted point/u);
});

test('an attempt cannot impersonate a new scheduled repetition', (t) => {
  const fixture = createFixture(t);
  const removed = fixture.evidence.get(fixture.first);
  fs.unlinkSync(path.join(fixture.root, removed.filename));
  const second = fixture.plan.points[1].id;
  fixture.modify(second, (result) => { result.attempt = 5; });
  assert.throws(() => analyze(fixture.plan, fixture.root), /missing accepted/u);
});

for (const [label, mutate, expected] of [
  ['artifact drift', (result) => { result.binary_sha256 = digest('other'); }, /artifact drift/u],
  ['missing allocation counter', (result) => { result.counters.allocations = null; },
    /allocations unavailable/u],
  ['support saturation', (result) => {
    result.support.gateway.upstream_capacity_percent[1] = 80;
  },
    /support evidence mismatch/u],
  ['forged resource summary', (result) => { result.resource.pid_after = 43; },
    /resource evidence mismatch/u],
  ['invalid perf checksum', (result) => { result.files.perf.sha256 = digest('other'); },
    /checksum mismatch/u],
]) {
  test(`rejects ${label}`, (t) => {
    const fixture = createFixture(t);
    fixture.modify(fixture.first, mutate);
    assert.throws(() => analyze(fixture.plan, fixture.root), expected);
  });
}

test('rejects an actual native process replacement', (t) => {
  const fixture = createFixture(t);
  fixture.modify(fixture.first, (result) => {
    result.resource.pid_after = 43;
    result.files.resource_after = writeBound(fixture.root,
      result.files.resource_after.path,
      {restart_count: 0, pid: 43, start_ticks: 100, rss_bytes: 4000200, fd: 12});
  });
  assert.throws(() => analyze(fixture.plan, fixture.root), /process replaced/u);
});

test('rejects an actually saturated direct-support host from raw CPU ticks', (t) => {
  const fixture = createFixture(t);
  fixture.modify(fixture.first, (result) => {
    result.files.direct_loadgen_after = writeBound(fixture.root,
      result.files.direct_loadgen_after.path, 'cpu 130 0 0 70 0 0 0 0\n');
    result.support.direct.load_generator_capacity_percent = 80;
    result.files.support = writeBound(fixture.root, result.files.support.path,
      result.support);
  });
  assert.throws(() => analyze(fixture.plan, fixture.root),
    /direct load generator saturated/u);
});

test('rejects an actually saturated gateway-interval second upstream', (t) => {
  const fixture = createFixture(t);
  fixture.modify(fixture.first, (result) => {
    result.files.gateway_upstream_b_after = writeBound(fixture.root,
      result.files.gateway_upstream_b_after.path, 'cpu 130 0 0 70 0 0 0 0\n');
    result.support.gateway.upstream_capacity_percent[1] = 80;
    result.files.support = writeBound(fixture.root, result.files.support.path,
      result.support);
  });
  assert.throws(() => analyze(fixture.plan, fixture.root),
    /gateway upstream saturated/u);
});

test('rejects an upstream hostname that differs from the frozen target', (t) => {
  const fixture = createFixture(t);
  fixture.modify(fixture.first, (result) => {
    result.files.direct_upstream_b_host = writeBound(fixture.root,
      result.files.direct_upstream_b_host.path, 'different-upstream\n');
  });
  assert.throws(() => analyze(fixture.plan, fixture.root),
    /upstream host identities differ from plan/u);
});

test('rejects dirty or substituted remote client source', (t) => {
  const dirty = createFixture(t);
  dirty.modify(dirty.first, (result) => {
    result.files.gateway_loadgen_status_after = writeBound(dirty.root,
      result.files.gateway_loadgen_status_after.path, ' M changed\n');
  });
  assert.throws(() => analyze(dirty.plan, dirty.root), /source was dirty/u);

  const runner = createFixture(t);
  runner.modify(runner.first, (result) => {
    result.files.direct_loadgen_runner_before = writeBound(runner.root,
      result.files.direct_loadgen_runner_before.path, `${digest('substitute')}\n`);
  });
  assert.throws(() => analyze(runner.plan, runner.root), /runner differs from plan/u);
});

test('rejects an installed snapshot that differs from the frozen plan', (t) => {
  const fixture = createFixture(t);
  fixture.modify(fixture.first, (result) => {
    result.files.snapshot_digest = writeBound(fixture.root,
      result.files.snapshot_digest.path, `${digest('different-snapshot')}\n`);
  });
  assert.throws(() => analyze(fixture.plan, fixture.root),
    /installed snapshot differs/u);
});

test('rejects non-200 responses even when the raw checksum is updated', (t) => {
  const fixture = createFixture(t);
  fixture.modify(fixture.first, (result) => {
    const bundle = JSON.parse(fs.readFileSync(path.join(fixture.root,
      result.files.oha.path), 'utf8'));
    const lane = JSON.parse(bundle.measurement.lanes[0].raw_json);
    lane.statusCodeDistribution = {
      '200': bundle.measurement.workload.requests_per_lane - 1,
      '503': 1};
    bundle.measurement.lanes[0].raw_json = JSON.stringify(lane);
    result.files.oha = writeBound(fixture.root, result.files.oha.path, bundle);
  });
  assert.throws(() => analyze(fixture.plan, fixture.root), /non-200/u);
});

test('diagnostic responses cannot replace clean capacity responses', (t) => {
  const fixture = createFixture(t);
  fixture.modify(fixture.first, (result) => {
    const bundle = JSON.parse(fs.readFileSync(path.join(fixture.root,
      result.files.diagnostic_oha.path), 'utf8'));
    const lane = JSON.parse(bundle.measurement.lanes[0].raw_json);
    lane.statusCodeDistribution = {
      '200': bundle.measurement.workload.requests_per_lane - 1,
      '503': 1};
    bundle.measurement.lanes[0].raw_json = JSON.stringify(lane);
    result.files.diagnostic_oha = writeBound(fixture.root,
      result.files.diagnostic_oha.path, bundle);
  });
  assert.throws(() => analyze(fixture.plan, fixture.root),
    /diagnostic measurement includes non-200 responses or transport errors/u);
});

test('rejects evidence file symlinks', (t) => {
  const fixture = createFixture(t);
  fixture.modify(fixture.first, (result) => {
    const original = path.join(fixture.root, result.files.perf.path);
    const alias = path.join(fixture.root, 'alias.perf.csv');
    fs.symlinkSync(original, alias);
    result.files.perf.path = 'alias.perf.csv';
  });
  assert.throws(() => analyze(fixture.plan, fixture.root), /symlink forbidden/u);
});

test('rejects results outside a five-percent repetition envelope', (t) => {
  const fixture = createFixture(t);
  const point = fixture.plan.points.find((item) => item.repetition === 5 &&
    item.profile === 'P5-B01' && item.cores === 8 && item.load === 'steady');
  fixture.modify(point.id, (result) => {
    const bundle = JSON.parse(fs.readFileSync(path.join(fixture.root,
      result.files.oha.path), 'utf8'));
    for (const lane of bundle.measurement.lanes) {
      lane.end_ns = '9000000000';
      const raw = JSON.parse(lane.raw_json);
      raw.summary.total = 8;
      lane.raw_json = JSON.stringify(raw);
    }
    result.files.oha = writeBound(fixture.root, result.files.oha.path, bundle);
  });
  assert.throws(() => analyze(fixture.plan, fixture.root), /variation exceeds 5%/u);
});
