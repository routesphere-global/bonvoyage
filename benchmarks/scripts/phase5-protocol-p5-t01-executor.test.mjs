import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {buildP5T01WarmupAdmission, buildProfiledStageArgs,
  buildRemoteClientArgs, collectorBundleIdentity, controlledUpstreamDescriptorPolicy,
  descriptorAttribution, P5_T01_COLLECTOR_FILES, requireNativeCaptureRoot,
  validateDescriptorObservation, validateIrqPolicyObservation,
  settlePostRunState, settleWarmupState, validateIrqPolicyTransition,
  validateReactorObservation, validateRuntimeInventory, validateTlsBundle} from
  './phase5-protocol-p5-t01-executor.mjs';

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

function descriptors(resource, peerConnections = 0) {
  const entries = Array.from({length: resource.file_descriptors}, (_, fd) => ({
    fd, target: `/fixture/fd-${fd}`, kind: 'file', socket_inode: null, tcp: null,
  }));
  for (let index = 0; index < peerConnections; index += 1) {
    const fd = resource.file_descriptors - peerConnections + index;
    entries[fd] = {fd, target: `socket:[${1000 + fd}]`, kind: 'tcp-socket',
      socket_inode: 1000 + fd, tcp: {family: 'ipv4',
        local_address: '192.0.2.20', local_port: 40000 + index,
        remote_address: '192.0.2.30', remote_port: 8081,
        state: 'ESTABLISHED', tx_queue_bytes: 0, rx_queue_bytes: 0}};
  }
  return {identity: resource.identity, pid: resource.pid,
    start_ticks: resource.start_ticks, restart_count: resource.restart_count,
    total: resource.file_descriptors, entries};
}

function runtimeState(resource, peerConnections = 0) {
  return {resource, descriptors: descriptors(resource, peerConnections)};
}

test('P5-T01 collector identity binds every runtime collector file', () => {
  const identity = collectorBundleIdentity();
  assert.match(identity.sha256, /^[0-9a-f]{64}$/u);
  assert.equal(identity.manifest.trimEnd().split('\n').length,
    P5_T01_COLLECTOR_FILES.length);
  for (const name of P5_T01_COLLECTOR_FILES) assert.match(identity.manifest,
    new RegExp(`  ${name.replaceAll('.', '\\.')}\\n`, 'u'));
});

test('P5-T01 TLS bundle verifies exact membership, content, and CA binding', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'perf05-p5-t01-tls-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const files = [['ca.pem', 'ca'], ['server-chain.pem', 'chain'],
    ['server-key.pem', 'key']];
  for (const [name, contents] of files) fs.writeFileSync(path.join(root, name), contents);
  const manifest = files.map(([name, contents]) =>
    `${sha256(contents)}  ${name}\n`).join('');
  const manifestFile = path.join(root, 'checksums.sha256');
  fs.writeFileSync(manifestFile, manifest);
  const identity = validateTlsBundle(manifestFile, path.join(root, 'ca.pem'));
  assert.equal(identity.sha256, sha256(manifest));
  assert.equal(identity.ca_sha256, sha256('ca'));
  fs.writeFileSync(path.join(root, 'server-chain.pem'), 'changed');
  assert.throws(() => validateTlsBundle(manifestFile, path.join(root, 'ca.pem')),
    /digest mismatch/u);
});

test('P5-T01 runtime inventory binds package source and installed binary', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'perf05-p5-t01-runtime-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const binary = path.join(root, 'bonvoyage-dataplane');
  fs.writeFileSync(binary, 'gateway-binary');
  const inventory = {schema_version: 1,
    classification: 'private-native-runtime-inventory',
    outcome: 'collected-unqualified', runtime_profile: 'package-install',
    producer_source_commit: 'a'.repeat(40),
    files: {binary: {path: binary, bytes: 14,
      sha256: sha256('gateway-binary')}},
    process: {executable: binary}};
  const inventoryFile = path.join(root, 'inventory.json');
  const bytes = `${JSON.stringify(inventory)}\n`;
  fs.writeFileSync(inventoryFile, bytes);
  const identity = validateRuntimeInventory(inventoryFile, binary);
  assert.equal(identity.producerSourceCommit, 'a'.repeat(40));
  assert.equal(identity.sha256, sha256(bytes));
  fs.writeFileSync(binary, 'changed');
  assert.throws(() => validateRuntimeInventory(inventoryFile, binary),
    /differs from the native runtime inventory/u);
});

test('P5-T01 remote client command is data-only and stage bounded', () => {
  const base = {repository: '/home/ubuntu/RouteSphere-BonVoyage',
    catalog: '/home/ubuntu/campaign/catalog.json',
    plan: '/home/ubuntu/campaign/plan.json',
    caFile: '/home/ubuntu/campaign/ca.pem', pointId: 'point-r1',
    image: `example.test/oha@sha256:${'a'.repeat(64)}`,
    cpuSet: '0-31', lanes: 8};
  const args = buildRemoteClientArgs(base, 'measurement');
  assert.deepEqual(args.slice(0, 3), ['node',
    '/home/ubuntu/RouteSphere-BonVoyage/benchmarks/scripts/phase5-protocol-p5-t01-client.mjs',
    'run']);
  assert.equal(args[args.indexOf('--stage') + 1], 'measurement');
  assert.throws(() => buildRemoteClientArgs({...base, cpuSet: '0-7;id'},
    'measurement'), /CPU set/u);
  assert.throws(() => buildRemoteClientArgs(base, 'other'), /stage/u);
});

test('P5-T01 warmup and measurement use the same profiler stack', () => {
  const client = {repository: '/home/ubuntu/RouteSphere-BonVoyage',
    catalog: '/var/tmp/catalog.json', plan: '/var/tmp/plan.json',
    caFile: '/var/tmp/ca.pem', pointId: 'point-r1',
    image: `example.test/oha@sha256:${'a'.repeat(64)}`,
    cpuSet: '0-31', lanes: 8};
  const base = {output: '/var/tmp/output', service: 'bonvoyage.service',
    snapshotFile: '/etc/bonvoyage/snapshot.pb', downstreamPort: 8443,
    intervalId: 'point-r1-a1', perfOutput: '/var/tmp/perf.csv',
    perfTids: [100, 101], loadHost: '192.0.2.10', client};
  const warmup = buildProfiledStageArgs({...base, stage: 'warmup'});
  const measurement = buildProfiledStageArgs({...base, stage: 'measurement'});
  assert.equal(warmup[warmup.indexOf('-t') + 1], '100,101');
  assert.equal(warmup[warmup.indexOf('--stage') + 1], 'warmup');
  assert.equal(measurement[measurement.indexOf('--stage') + 1], 'measurement');
  assert.deepEqual(warmup.slice(0, warmup.indexOf('--stage')),
    measurement.slice(0, measurement.indexOf('--stage')));
  assert.throws(() => buildProfiledStageArgs({...base, perfTids: [100, 100],
    stage: 'warmup'}), /reactor TIDs/u);
});

test('P5-T01 descriptor policy is derived from the bound fixture', () => {
  const config = {clusters: [{name: 'controlled-upstream',
    max_connections_per_shard: 8,
    endpoints: [{name: 'upstream', address: 'upstream', port: 8081}]}]};
  assert.deepEqual(controlledUpstreamDescriptorPolicy(config,
    '192.0.2.30', 8), {remote_address: '192.0.2.30', remote_port: 8081,
    maximum_connections: 64});
  assert.throws(() => controlledUpstreamDescriptorPolicy({...config,
    clusters: [...config.clusters, config.clusters[0]]}, '192.0.2.30', 8),
  /differs from the bound fixture/u);
});

test('descriptor attribution cannot hide growth behind a shrinking pool', () => {
  const beforeResource = {identity: 'pid:42:start:1', pid: 42,
    start_ticks: 1, restart_count: 0, rss_bytes: 1000,
    file_descriptors: 120};
  const afterResource = {...beforeResource, file_descriptors: 105};
  const before = descriptors(beforeResource, 30);
  const after = descriptors(afterResource, 10);
  validateDescriptorObservation(before, 'before descriptors');
  validateDescriptorObservation(after, 'after descriptors');
  assert.deepEqual(descriptorAttribution(before, after,
    {remote_address: '192.0.2.30', remote_port: 8081,
      maximum_connections: 64}), {
    total_fd_growth: -15,
    controlled_upstream_connections_before: 30,
    controlled_upstream_connections_after: 10,
    controlled_upstream_connection_growth: -20,
    controlled_upstream_connection_limit: 64,
    controlled_upstream_connections_bounded: true,
    non_controlled_descriptors_before: 90,
    non_controlled_descriptors_after: 95,
    unaccounted_fd_growth: 5,
  });
});

test('P5-T01 native capture requires the system evidence privilege boundary', () => {
  assert.doesNotThrow(() => requireNativeCaptureRoot(0));
  assert.throws(() => requireNativeCaptureRoot(1000),
    /must run as root/u);
  assert.throws(() => requireNativeCaptureRoot(undefined),
    /must run as root/u);
});

test('P5-T01 reactor evidence proves exact live CPU pinning', () => {
  const observation = {reactor_tids: [100, 101], reactor_bindings: [
    {shard: 0, tid: 100, allowed_cpus: [8], current_cpu: 8},
    {shard: 1, tid: 101, allowed_cpus: [9], current_cpu: 9},
  ]};
  assert.deepEqual(validateReactorObservation(observation, [8, 9],
    'reactors'), [100, 101]);
  const broad = structuredClone(observation);
  broad.reactor_bindings[1].allowed_cpus = [9, 10];
  assert.throws(() => validateReactorObservation(broad, [8, 9], 'reactors'),
    /not pinned/u);
  assert.throws(() => validateReactorObservation(observation, [8, 10],
    'reactors'), /differ from the native plan/u);
});

test('P5-T01 IRQ evidence proves active exclusion and effective NIC affinity', () => {
  const expected = {mode: 'irqbalance-with-gateway-ban',
    gateway_banned_cpus: [8, 9], irq_target_cpus: [0, 1]};
  const observation = {mode: expected.mode, irqbalance_active: true,
    aws_nitro_irqbalance_active: false, banned_cpus: [8, 9],
    target_interface: 'ens5', msi_irqs: [
      {irq: 70, effective_cpus: [0]},
      {irq: 71, effective_cpus: [1]},
    ]};
  assert.equal(validateIrqPolicyObservation(observation, expected, 'IRQ'),
    observation);
  const overlap = structuredClone(observation);
  overlap.msi_irqs[1].effective_cpus = [8];
  assert.throws(() => validateIrqPolicyObservation(overlap, expected, 'IRQ'),
    /outside the IRQ CPU set/u);
  const incomplete = structuredClone(observation);
  incomplete.msi_irqs[1].effective_cpus = [0];
  assert.throws(() => validateIrqPolicyObservation(incomplete, expected,
    'IRQ'), /do not cover/u);
});

test('P5-T01 active irqbalance permits movement only inside the planned set', () => {
  const expected = {mode: 'irqbalance-with-gateway-ban',
    gateway_banned_cpus: [8, 9], irq_target_cpus: [0, 1]};
  const before = {mode: expected.mode, irqbalance_active: true,
    aws_nitro_irqbalance_active: false, banned_cpus: [8, 9],
    target_interface: 'ens5', msi_irqs: [
      {irq: 70, effective_cpus: [0]},
      {irq: 71, effective_cpus: [1]},
    ]};
  const after = structuredClone(before);
  after.msi_irqs[0].effective_cpus = [1];
  after.msi_irqs[1].effective_cpus = [0];
  assert.deepEqual(validateIrqPolicyTransition(before, after, expected,
    'IRQ transition'), {mode: expected.mode, target_interface: 'ens5',
    irq_ids: [70, 71], affinity_changed: true});

  const changedIdentity = structuredClone(after);
  changedIdentity.msi_irqs[1].irq = 72;
  assert.throws(() => validateIrqPolicyTransition(before, changedIdentity,
    expected, 'IRQ transition'), /identity changed/u);

  const escaped = structuredClone(after);
  escaped.msi_irqs[1].effective_cpus = [8];
  assert.throws(() => validateIrqPolicyTransition(before, escaped, expected,
    'IRQ transition'), /outside the IRQ CPU set/u);
});

test('P5-T01 observed irqbalance records Nitro overlap without claiming isolation', () => {
  const expected = {mode: 'irqbalance-observed',
    gateway_banned_cpus: [8, 9], irq_target_cpus: [0, 1]};
  const before = {mode: expected.mode, irqbalance_active: true,
    aws_nitro_irqbalance_active: false, banned_cpus: [],
    target_interface: 'ens5', msi_irqs: [
      {irq: 70, effective_cpus: [9]},
      {irq: 71, effective_cpus: [0]},
    ]};
  const after = structuredClone(before);
  after.msi_irqs[0].effective_cpus = [1];
  after.msi_irqs[1].effective_cpus = [8];
  assert.equal(validateIrqPolicyObservation(before, expected,
    'observed IRQ'), before);
  assert.deepEqual(validateIrqPolicyTransition(before, after, expected,
    'observed IRQ transition'), {mode: expected.mode, target_interface: 'ens5',
    irq_ids: [70, 71], affinity_changed: true, banned_cpus: [],
    gateway_overlap_irqs_before: [70], gateway_overlap_irqs_after: [71]});

  const outsideHost = structuredClone(before);
  outsideHost.msi_irqs[0].effective_cpus = [10];
  assert.throws(() => validateIrqPolicyObservation(outsideHost, expected,
    'observed IRQ'), /outside the planned host CPUs/u);

  const duplicateIdentity = structuredClone(before);
  duplicateIdentity.msi_irqs[1].irq = 70;
  assert.throws(() => validateIrqPolicyObservation(duplicateIdentity, expected,
    'observed IRQ'), /duplicate IRQ identity 70/u);
});

test('P5-T01 warmup settlement requires a drained stable resource plateau', () => {
  const base = {identity: 'boot:42:100', pid: 42, start_ticks: 100,
    restart_count: 0, rss_bytes: 1000, file_descriptors: 10};
  const samples = [base, {...base, rss_bytes: 2000},
    {...base, rss_bytes: 2000}, {...base, rss_bytes: 2000}];
  const busy = 'bonvoyage_bonvoyage_gateway_active_requests 1\n' +
    'bonvoyage_bonvoyage_gateway_active_route_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_upstream_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_upstream_http1_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_http2_streams 0\n';
  const drained = busy.replace('active_requests 1', 'active_requests 0');
  let elapsed = 0;
  let index = 0;
  const result = settleWarmupState({maximumCleanupMs: 2000,
    expectedIdentity: base.identity,
    captureState: () => runtimeState(samples[Math.min(index,
      samples.length - 1)]),
    captureMetrics: () => index++ === 0 ? busy : drained,
    now: () => elapsed,
    wait: (milliseconds) => { elapsed += milliseconds; },
    pollIntervalMs: 50, stableObservations: 3});
  assert.equal(result.settled, true);
  assert.equal(result.elapsed_ms, 150);
  assert.equal(result.observations.length, 4);
  assert.equal(result.state.resource.rss_bytes, 2000);
  assert.equal(result.observations.at(-1).consecutive_stable_observations, 3);
});

test('P5-T01 warmup settlement fails closed at its deadline', () => {
  const resource = {identity: 'boot:42:100', pid: 42, start_ticks: 100,
    restart_count: 0, rss_bytes: 1000, file_descriptors: 10};
  const drained = 'bonvoyage_bonvoyage_gateway_active_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_route_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_upstream_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_upstream_http1_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_http2_streams 0\n';
  let elapsed = 0;
  let rss = 1000;
  const result = settleWarmupState({maximumCleanupMs: 100,
    expectedIdentity: resource.identity,
    captureState: () => runtimeState({...resource, rss_bytes: rss++}),
    captureMetrics: () => drained, now: () => elapsed,
    wait: (milliseconds) => { elapsed += milliseconds; }, pollIntervalMs: 50,
    stableObservations: 3});
  assert.equal(result.settled, false);
  assert.equal(result.elapsed_ms, 100);
  assert.equal(result.observations.length, 3);
});

test('P5-T01 warmup settlement rejects process replacement', () => {
  const resource = {identity: 'boot:42:100', pid: 42, start_ticks: 100,
    restart_count: 0, rss_bytes: 1000, file_descriptors: 10};
  const drained = 'bonvoyage_bonvoyage_gateway_active_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_route_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_upstream_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_upstream_http1_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_http2_streams 0\n';
  assert.throws(() => settleWarmupState({maximumCleanupMs: 100,
    expectedIdentity: resource.identity,
    captureState: () => runtimeState({...resource,
      identity: 'boot:43:101', pid: 43, start_ticks: 101}),
    captureMetrics: () => drained}), /process identity changed/u);
});

test('P5-T01 executor admits only the final two identical profiled warmups', () => {
  const plan = {input: {schedule: {profiled_warmup_repetitions: 3},
    acceptance: {maximum_cleanup_ms: 2000}}};
  const variant = {workload: {target_rps: 10, warmup_seconds: 60}};
  const passes = Array.from({length: 3}, (_, index) => ({pass: index + 1,
    settled: true, settlement_ms: 100, identity: 'boot:42:100',
    restart_count: 0, rss_bytes: index === 0 ? 1000 : 2000,
    file_descriptors: 10, successful_requests: 600, http_failures: 0,
    transport_failures: 0}));
  const admission = buildP5T01WarmupAdmission(plan, variant, passes);
  assert.deepEqual(admission.plateau, {compared_passes: [2, 3],
    rss_delta_bytes: 0, fd_delta: 0, stable: true});

  const moving = structuredClone(passes);
  moving[2].rss_bytes += 1;
  assert.throws(() => buildP5T01WarmupAdmission(plan, variant, moving),
    /exact resource plateau/u);
});

test('P5-T01 post-run settlement waits within the frozen cleanup budget', () => {
  const before = {identity: 'boot:42:100', pid: 42, start_ticks: 100,
    restart_count: 0, rss_bytes: 1000, file_descriptors: 10};
  const samples = [
    {...before, rss_bytes: 2000, file_descriptors: 19},
    {...before, rss_bytes: 1800, file_descriptors: 13},
  ];
  const metricSamples = [
    'bonvoyage_bonvoyage_gateway_active_requests 1\n' +
      'bonvoyage_bonvoyage_gateway_active_route_requests 0\n' +
      'bonvoyage_bonvoyage_gateway_active_upstream_requests 0\n' +
      'bonvoyage_bonvoyage_gateway_active_upstream_http1_requests 0\n' +
      'bonvoyage_bonvoyage_gateway_active_http2_streams 0\n',
    'bonvoyage_bonvoyage_gateway_active_requests 0\n' +
      'bonvoyage_bonvoyage_gateway_active_route_requests 0\n' +
      'bonvoyage_bonvoyage_gateway_active_upstream_requests 0\n' +
      'bonvoyage_bonvoyage_gateway_active_upstream_http1_requests 0\n' +
      'bonvoyage_bonvoyage_gateway_active_http2_streams 0\n',
  ];
  let elapsed = 0;
  let index = 0;
  const result = settlePostRunState({before, acceptance: {
    maximum_cleanup_ms: 2000,
    maximum_retained_rss_growth_bytes: 1600,
    maximum_retained_fd_growth: 4,
  }, beforeDescriptors: descriptors(before), descriptorPolicy: {
    remote_address: '192.0.2.30', remote_port: 8081,
    maximum_connections: 16,
  }, captureState: () => runtimeState(
    samples[Math.min(index, samples.length - 1)]),
  captureMetrics: () => metricSamples[Math.min(index++, metricSamples.length - 1)],
  now: () => elapsed, wait: (milliseconds) => { elapsed += milliseconds; },
  pollIntervalMs: 50});
  assert.equal(result.settled, true);
  assert.equal(result.elapsed_ms, 50);
  assert.equal(result.observations.length, 2);
  assert.equal(result.resource.file_descriptors, 13);
});

test('P5-T01 post-run settlement fails closed at the cleanup deadline', () => {
  const before = {identity: 'boot:42:100', pid: 42, start_ticks: 100,
    restart_count: 0, rss_bytes: 1000, file_descriptors: 10};
  const busy = 'bonvoyage_bonvoyage_gateway_active_requests 1\n' +
    'bonvoyage_bonvoyage_gateway_active_route_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_upstream_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_upstream_http1_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_http2_streams 0\n';
  let elapsed = 0;
  const result = settlePostRunState({before, acceptance: {
    maximum_cleanup_ms: 100,
    maximum_retained_rss_growth_bytes: 100,
    maximum_retained_fd_growth: 1,
  }, beforeDescriptors: descriptors(before), descriptorPolicy: {
    remote_address: '192.0.2.30', remote_port: 8081,
    maximum_connections: 16,
  }, captureState: () => runtimeState({...before, rss_bytes: 1200,
    file_descriptors: 12}), captureMetrics: () => busy,
  now: () => elapsed, wait: (milliseconds) => { elapsed += milliseconds; },
  pollIntervalMs: 50});
  assert.equal(result.settled, false);
  assert.equal(result.elapsed_ms, 100);
  assert.equal(result.observations.length, 3);
});

test('P5-T01 descriptor attribution cannot weaken the retained FD gate', () => {
  const before = {identity: 'boot:42:100', pid: 42, start_ticks: 100,
    restart_count: 0, rss_bytes: 1000, file_descriptors: 10};
  const after = {...before, file_descriptors: 15};
  const drained = 'bonvoyage_bonvoyage_gateway_active_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_route_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_upstream_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_upstream_http1_requests 0\n' +
    'bonvoyage_bonvoyage_gateway_active_http2_streams 0\n';
  let elapsed = 0;
  const result = settlePostRunState({before,
    beforeDescriptors: descriptors(before), descriptorPolicy: {
      remote_address: '192.0.2.30', remote_port: 8081,
      maximum_connections: 64,
    }, acceptance: {maximum_cleanup_ms: 100,
      maximum_retained_rss_growth_bytes: 100,
      maximum_retained_fd_growth: 4},
    captureState: () => runtimeState(after, 5),
    captureMetrics: () => drained, now: () => elapsed,
    wait: (milliseconds) => { elapsed += milliseconds; }, pollIntervalMs: 50});
  assert.equal(result.settled, false);
  assert.equal(result.observations.at(-1).descriptor_attribution
    .controlled_upstream_connection_growth, 5);
  assert.equal(result.observations.at(-1).descriptor_attribution
    .unaccounted_fd_growth, 0);
  assert.equal(result.observations.at(-1).resource_contained, false);
});
