import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {buildPolicyCostPlan, validatePolicyCostResult} from
  './phase5-policy-cost.mjs';
import {buildPolicyAttemptLayout, buildPolicyProfiledStageArgs,
  buildPolicyCaptureStatus, buildPolicyProbeArgs, buildPolicyRemoteClientArgs,
  buildPolicyWarmupAdmission,
  classifyPolicyCostFailure, evaluatePolicyRecovery,
  POLICY_COST_COLLECTOR_FILES, policyCostCollectorIdentity,
  preflightPolicyCost, retainInvalidPolicyAttempt, validateJwtRunway,
  validatePolicyRuntimeSecrets} from
  './phase5-policy-cost-executor.mjs';
import {describePolicyCostPoint, POLICY_COST_RAW_FILES,
  POLICY_COST_RAW_FILES_V3, POLICY_COST_RAW_FILES_V4} from
  './phase5-policy-cost-native.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const catalogFile = path.join(root,
  'benchmarks/workloads/policy-cost/phase5-policy-cost.json');
const catalog = fs.readFileSync(catalogFile);
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

function input(collectorSha256, schemaVersion = 2) {
  const value = {schema_version: schemaVersion,
    evidence_class: 'shared-vm-directional',
    catalog_sha256: sha256(catalog),
    source: {binary_source_commit: '1'.repeat(40),
      harness_commit: '2'.repeat(40), source_dirty: false,
      gateway_binary_sha256: sha256('gateway'),
      client_sha256: 'a'.repeat(64), upstream_sha256: sha256('upstream'),
      collector_bundle_sha256: collectorSha256,
      tls_bundle_sha256: sha256('tls')},
    topology: {roles: [
      {role: 'load_generator', host_id: 'load', private_address: '10.0.0.10'},
      {role: 'gateway', host_id: 'gateway', private_address: '10.0.0.20'},
      {role: 'controlled_upstream', host_id: 'upstream',
        private_address: '10.0.0.30'},
    ], gateway_cpu_set: Array.from({length: 24}, (_, index) => index + 8),
    housekeeping_cpu_set: Array.from({length: 8}, (_, index) => index),
    load_generator_cpu_set: Array.from({length: 16}, (_, index) => index),
    irq_policy: 'irqbalance-with-gateway-ban', load_generator_lanes: 8,
    controlled_upstream: {port: 8081, max_connections_per_shard: 128}},
    artifacts: {p5_b02_snapshot_sha256: sha256('b02'),
      profile_snapshot_sha256: Object.fromEntries(
        ['P5-C00', 'P5-C01', 'P5-C02', 'P5-C03', 'P5-C04', 'P5-C05']
          .map((id) => [id, sha256(id)])),
      header_transform_request_sha256: sha256('headers'),
      api_key_credential_sha256: sha256('credential'),
      jwt_jwks_sha256: sha256('jwt-jwks')},
    workload: {offered_rps_by_payload: {'256': 24000, '8192': 12000},
      connections: 256, warmup_seconds: 60, measurement_seconds: 60,
      request_timeout_ms: 5000, maximum_cleanup_ms: 5000,
      minimum_delivery_ratio: 0.95, p95_ceiling_ms: 50,
      p99_ceiling_ms: 500, maximum_support_capacity_percent: 80,
      maximum_retained_rss_growth_bytes: 16 * 1024 * 1024,
      maximum_retained_fd_growth: 4},
    jwt: {algorithm: 'RS256', maximum_age_seconds_at_start: 90,
      minimum_remaining_lifetime_seconds_at_end: 30}};
  if (schemaVersion >= 3) {
    value.workload.profiled_warmup_repetitions = 3;
    value.jwt.maximum_age_seconds_at_start = 210;
  }
  return value;
}

function fixture(t, schemaVersion = 2) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'perf06-executor-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const collector = policyCostCollectorIdentity();
  const plan = buildPolicyCostPlan(input(collector.sha256, schemaVersion),
    catalog);
  const planFile = path.join(directory, 'plan.json');
  fs.writeFileSync(planFile, JSON.stringify(plan));
  return {directory, collector, plan, planFile};
}

function remoteClient(pointId = 'P5-B02-24c-directional-r1') {
  return {repository: '/home/ubuntu/RouteSphere-BonVoyage',
    catalog: '/var/tmp/perf06/catalog.json',
    plan: '/var/tmp/perf06/plan.json', caFile: '/var/tmp/perf06/ca.pem',
    pointId, image: `example.test/oha@sha256:${'a'.repeat(64)}`,
    cpuSet: '0-15', lanes: 8, requestArtifact: null};
}

test('PERF-06 collector identity binds the complete executable stack', () => {
  const identity = policyCostCollectorIdentity();
  assert.match(identity.sha256, /^[0-9a-f]{64}$/u);
  assert.equal(identity.manifest.trimEnd().split('\n').length,
    POLICY_COST_COLLECTOR_FILES.length);
  for (const name of POLICY_COST_COLLECTOR_FILES) {
    assert.match(identity.manifest,
      new RegExp(`  ${name.replaceAll('.', '\\.')}\\n`, 'u'));
  }
});

test('PERF-06 remote commands contain paths and identities but no values', () => {
  const client = remoteClient('P5-C04-24c-directional-r1');
  client.requestArtifact = '/var/tmp/perf06/jwt-headers.json';
  const warmup = buildPolicyRemoteClientArgs(client, 'warmup');
  const measurement = buildPolicyRemoteClientArgs(client, 'measurement');
  assert.equal(warmup[warmup.indexOf('--stage') + 1], 'warmup');
  assert.equal(measurement[measurement.indexOf('--stage') + 1], 'measurement');
  assert.equal(JSON.stringify(measurement).includes('Bearer '), false);
  const probe = buildPolicyProbeArgs({...client,
    targetAddress: '10.0.0.20', output: '/var/tmp/perf06/probe'});
  assert.equal(probe.includes('/var/tmp/perf06/jwt-headers.json'), true);
  assert.throws(() => buildPolicyRemoteClientArgs({...client,
    requestArtifact: '/tmp/a;id'}, 'measurement'), /path is unsafe/u);
});

test('PERF-06 measurement profiles every stable reactor TID', () => {
  const args = buildPolicyProfiledStageArgs({output: '/tmp/socket',
    service: 'bonvoyage.service', snapshotFile: '/etc/bonvoyage/snapshot.pb',
    downstreamPort: 8443, intervalId: 'P5-C01-24c-directional-r1',
    perfOutput: '/tmp/perf.csv', perfTids: [101, 102],
    loadHost: 'bonvoyage-loadgen', client: remoteClient(
      'P5-C01-24c-directional-r1')});
  assert.equal(args[args.indexOf('-t') + 1], '101,102');
  assert.equal(args.includes('phase5-policy-cost-client.mjs'), false);
  assert.match(args.join(' '), /phase5-policy-cost-client\.mjs run/u);

  const warmup = buildPolicyProfiledStageArgs({output: '/tmp/socket',
    service: 'bonvoyage.service', snapshotFile: '/etc/bonvoyage/snapshot.pb',
    downstreamPort: 8443, intervalId: 'P5-C01-warmup-1',
    perfOutput: '/tmp/perf.csv', perfTids: [101, 102],
    loadHost: 'bonvoyage-loadgen', stage: 'warmup',
    client: remoteClient('P5-C01-24c-directional-r1')});
  assert.equal(warmup[warmup.indexOf('--stage') + 1], 'warmup');
});

test('PERF-06 JWT runway covers warmup, measurement, and remaining life', (t) => {
  const value = fixture(t);
  const observation = {mode: 'ephemeral-jwt', header_names: ['authorization'],
    artifact_sha256: sha256('jwt'), values_retained: false,
    jwt_window: {issued_at_epoch_ms: 100000, expires_at_epoch_ms: 400000,
      measurement_started_at_epoch_ms: null,
      measurement_ended_at_epoch_ms: null}};
  assert.equal(validateJwtRunway(observation, value.plan, 120000), observation);
  const short = structuredClone(observation);
  short.jwt_window.expires_at_epoch_ms = 200000;
  assert.throws(() => validateJwtRunway(short, value.plan, 120000),
    /does not cover/u);
  const impossible = structuredClone(value.plan);
  impossible.input.jwt.maximum_age_seconds_at_start = 60;
  assert.throws(() => validateJwtRunway(observation, impossible, 120000),
    /freshness budget/u);
});

test('PERF-06 v3 JWT runway covers all profiled warmups exactly', (t) => {
  const value = fixture(t, 3);
  const observation = {mode: 'ephemeral-jwt', header_names: ['authorization'],
    artifact_sha256: sha256('jwt'), values_retained: false,
    jwt_window: {issued_at_epoch_ms: 100000, expires_at_epoch_ms: 400000,
      measurement_started_at_epoch_ms: null,
      measurement_ended_at_epoch_ms: null}};
  assert.equal(validateJwtRunway(observation, value.plan, 110000), observation);

  const short = structuredClone(observation);
  short.jwt_window.expires_at_epoch_ms = 380000;
  assert.throws(() => validateJwtRunway(short, value.plan, 110000),
    /does not cover/u);

  const insufficientFreshness = structuredClone(value.plan);
  insufficientFreshness.input.jwt.maximum_age_seconds_at_start = 180;
  assert.throws(() => validateJwtRunway(observation, insufficientFreshness,
    110000), /profiled warmups/u);
});

test('PERF-06 v3 admits only three successful warmups with a final plateau',
  (t) => {
    const value = fixture(t, 3);
    const point = value.plan.points[0];
    const successfulRequests = point.offered_rps *
      value.plan.input.workload.warmup_seconds;
    const pass = (number, rssBytes, fileDescriptors = 17) => ({pass: number,
      settled: true, settlement_ms: 250, identity: 'pid:42:start:99',
      restart_count: 0, rss_bytes: rssBytes,
      file_descriptors: fileDescriptors, successful_requests: successfulRequests,
      http_failures: 0, transport_failures: 0});
    const passes = [pass(1, 42 * 1024 * 1024),
      pass(2, 44 * 1024 * 1024), pass(3, 44 * 1024 * 1024)];
    const admission = buildPolicyWarmupAdmission(value.plan, point, passes);
    assert.equal(admission.plateau.stable, true);
    assert.deepEqual(admission.plateau.compared_passes, [2, 3]);

    const drifting = structuredClone(passes);
    drifting[2].rss_bytes += 4096;
    assert.throws(() => buildPolicyWarmupAdmission(value.plan, point,
      drifting), /resource plateau/u);

    const failed = structuredClone(passes);
    failed[0].successful_requests -= 1;
    assert.throws(() => buildPolicyWarmupAdmission(value.plan, point, failed),
      /pass 1 failed/u);
  });

test('PERF-06 v4 admits only evidence-attributed bounded convergence', (t) => {
  const value = fixture(t, 4);
  const point = value.plan.points[0];
  const successfulRequests = point.offered_rps *
    value.plan.input.workload.warmup_seconds;
  const pass = (number, rssBytes, allocatedMemoryBytes,
    controlledConnections, nonControlledDescriptors, liveObjects) => ({
    pass: number, settled: true, settlement_ms: 250,
    identity: 'pid:42:start:99', restart_count: 0, rss_bytes: rssBytes,
    file_descriptors: controlledConnections + nonControlledDescriptors,
    allocated_memory_bytes: allocatedMemoryBytes,
    malloc_live_objects: liveObjects,
    controlled_upstream_connections: controlledConnections,
    non_controlled_descriptors: nonControlledDescriptors,
    successful_requests: successfulRequests, http_failures: 0,
    transport_failures: 0,
  });
  const passes = [pass(1, 42 * 1024 * 1024, 30 * 1024 * 1024,
    96, 17, 900), pass(2, 44 * 1024 * 1024, 31 * 1024 * 1024,
    100, 17, 1000), pass(3, 52 * 1024 * 1024,
    31 * 1024 * 1024 + 196608, 105, 17, 1035)];
  const admission = buildPolicyWarmupAdmission(value.plan, point, passes);
  assert.equal(admission.schema_version, 2);
  assert.equal(admission.convergence.contained, true);
  assert.equal(admission.convergence.rss_delta_bytes, 8 * 1024 * 1024);
  assert.equal(admission.convergence.unaccounted_fd_delta, 0);

  const unaccounted = structuredClone(passes);
  unaccounted[2].non_controlled_descriptors += 1;
  unaccounted[2].file_descriptors += 1;
  assert.throws(() => buildPolicyWarmupAdmission(value.plan, point,
    unaccounted), /bounded resource convergence/u);

  const allocationDrift = structuredClone(passes);
  allocationDrift[2].allocated_memory_bytes =
    allocationDrift[1].allocated_memory_bytes + 17 * 1024 * 1024;
  assert.throws(() => buildPolicyWarmupAdmission(value.plan, point,
    allocationDrift), /bounded resource convergence/u);
});

test('PERF-06 capture status accepts profiled warmup completion', () => {
  assert.deepEqual(buildPolicyCaptureStatus(0, 0, 0, 0), {
    warmup_command_exit_code: 0,
    measurement_command_exit_code: 0,
    collector_exit_code: 0,
    protocol_probe_exit_code: 0,
  });
  assert.deepEqual(buildPolicyCaptureStatus(null, null, null, null), {
    warmup_command_exit_code: 1,
    measurement_command_exit_code: 1,
    collector_exit_code: 1,
    protocol_probe_exit_code: 1,
  });
});

test('PERF-06 executor binds active JWKS bytes for JWT points', (t) => {
  const value = fixture(t);
  const jwks = path.join(value.directory, 'jwks.json');
  fs.writeFileSync(jwks, 'jwt-jwks');
  const description = describePolicyCostPoint(value.plan, catalog,
    'P5-C04-24c-directional-r1');
  assert.doesNotThrow(() => validatePolicyRuntimeSecrets(description,
    {jwtJwksFile: jwks}, value.plan));
  fs.writeFileSync(jwks, 'substituted');
  assert.throws(() => validatePolicyRuntimeSecrets(description,
    {jwtJwksFile: jwks}, value.plan), /JWKS differs/u);
});

test('PERF-06 JWT generator accepts only a bounded explicit lifetime', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'perf06-jwt-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const script = path.join(root, 'scripts/generate-jwt-smoke-material.py');
  const generated = spawnSync('python3', ['-B', script, directory,
    '--lifetime-seconds', '180'], {encoding: 'utf8'});
  assert.equal(generated.status, 0, generated.stderr);
  const tokens = JSON.parse(fs.readFileSync(path.join(directory,
    'jwt-tokens.json'), 'utf8'));
  const [, claims] = tokens.valid.split('.');
  const decoded = JSON.parse(Buffer.from(claims, 'base64url').toString('utf8'));
  assert.equal(decoded.exp - decoded.iat, 180);
  assert.equal(fs.statSync(path.join(directory, 'phase3-jwks.json')).mode & 0o777,
    0o600);

  const rejected = spawnSync('python3', ['-B', script,
    path.join(directory, 'invalid'), '--lifetime-seconds', '301'],
  {encoding: 'utf8'});
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /between 60 and 300 seconds/u);

  const maximum = path.join(directory, 'maximum');
  const maximumGenerated = spawnSync('python3', ['-B', script, maximum,
    '--lifetime-seconds', '300'], {encoding: 'utf8'});
  assert.equal(maximumGenerated.status, 0, maximumGenerated.stderr);
  const maximumTokens = JSON.parse(fs.readFileSync(path.join(maximum,
    'jwt-tokens.json'), 'utf8'));
  const [, maximumClaims] = maximumTokens.valid.split('.');
  const maximumDecoded = JSON.parse(Buffer.from(maximumClaims,
    'base64url').toString('utf8'));
  assert.equal(maximumDecoded.exp - maximumDecoded.iat, 300);
});

test('PERF-06 JWT generator reuses one frozen key and JWKS safely', (t) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'perf06-jwt-reuse-'));
  t.after(() => fs.rmSync(base, {recursive: true, force: true}));
  const source = path.join(base, 'source');
  const refreshed = path.join(base, 'refreshed');
  const script = path.join(root, 'scripts/generate-jwt-smoke-material.py');
  const generated = spawnSync('python3', ['-B', script, source,
    '--lifetime-seconds', '180'], {encoding: 'utf8'});
  assert.equal(generated.status, 0, generated.stderr);
  const frozenJwks = fs.readFileSync(path.join(source, 'phase3-jwks.json'));
  const reused = spawnSync('python3', ['-B', script, refreshed,
    '--lifetime-seconds', '120', '--reuse-key-directory', source],
  {encoding: 'utf8'});
  assert.equal(reused.status, 0, reused.stderr);
  assert.deepEqual(fs.readFileSync(path.join(refreshed, 'phase3-jwks.json')),
    frozenJwks);
  assert.equal(fs.existsSync(path.join(refreshed, 'jwt-private.pem')), false);
  const jwks = JSON.parse(frozenJwks);
  const tokens = JSON.parse(fs.readFileSync(path.join(refreshed,
    'jwt-tokens.json'), 'utf8'));
  const [header, claims] = tokens.valid.split('.');
  const decodedHeader = JSON.parse(Buffer.from(header,
    'base64url').toString('utf8'));
  const decodedClaims = JSON.parse(Buffer.from(claims,
    'base64url').toString('utf8'));
  assert.equal(decodedHeader.kid, jwks.keys[0].kid);
  assert.equal(decodedClaims.exp - decodedClaims.iat, 120);

  const tampered = structuredClone(jwks);
  tampered.keys[0].kid = 'substituted';
  fs.writeFileSync(path.join(source, 'phase3-jwks.json'),
    `${JSON.stringify(tampered)}\n`, {mode: 0o600});
  const rejected = spawnSync('python3', ['-B', script,
    path.join(base, 'rejected'), '--reuse-key-directory', source],
  {encoding: 'utf8'});
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /differs from its frozen JWKS/u);
});

test('PERF-06 offline preflight is deterministic and non-publishing', (t) => {
  const value = fixture(t);
  const execution = preflightPolicyCost({catalog: catalogFile,
    plan: value.planFile, pointId: 'P5-B02-24c-directional-r1', attempt: 1,
    requestArtifact: null, loadRepository: remoteClient().repository,
    remoteCatalog: remoteClient().catalog, remotePlan: remoteClient().plan,
    remoteCaFile: remoteClient().caFile, remoteRequestArtifact: null,
    ohaImage: remoteClient().image, loadCpuSet: '0-15', loadLanes: 8,
    remoteProbeRoot: '/var/tmp/perf06/probe'});
  assert.equal(execution.publication_authorized, false);
  assert.deepEqual(execution.expected_raw_files, [...POLICY_COST_RAW_FILES]);
  assert.equal(execution.commands.warmup.includes('ssh'), false);
  assert.equal(execution.commands.measurement.includes('measurement'), true);
});

test('PERF-06 v3 preflight binds profiled warmups and admission evidence',
  (t) => {
    const value = fixture(t, 3);
    const execution = preflightPolicyCost({catalog: catalogFile,
      plan: value.planFile, pointId: 'P5-B02-24c-directional-r1', attempt: 1,
      requestArtifact: null, loadRepository: remoteClient().repository,
      remoteCatalog: remoteClient().catalog, remotePlan: remoteClient().plan,
      remoteCaFile: remoteClient().caFile, remoteRequestArtifact: null,
      ohaImage: remoteClient().image, loadCpuSet: '0-15', loadLanes: 8,
      remoteProbeRoot: '/var/tmp/perf06/probe'});
    assert.equal(execution.profiled_warmup_repetitions, 3);
    assert.deepEqual(execution.expected_raw_files,
      [...POLICY_COST_RAW_FILES_V3]);
  });

test('PERF-06 v4 preflight binds per-pass convergence evidence', (t) => {
  const value = fixture(t, 4);
  const execution = preflightPolicyCost({catalog: catalogFile,
    plan: value.planFile, pointId: 'P5-B02-24c-directional-r1', attempt: 1,
    requestArtifact: null, loadRepository: remoteClient().repository,
    remoteCatalog: remoteClient().catalog, remotePlan: remoteClient().plan,
    remoteCaFile: remoteClient().caFile, remoteRequestArtifact: null,
    ohaImage: remoteClient().image, loadCpuSet: '0-15', loadLanes: 8,
    remoteProbeRoot: '/var/tmp/perf06/probe'});
  assert.deepEqual(execution.expected_raw_files,
    [...POLICY_COST_RAW_FILES_V4]);
});

test('PERF-06 failures classify, retain, and remain invalid attempts', (t) => {
  const value = fixture(t);
  const pointId = 'P5-C01-24c-directional-r1';
  const layout = buildPolicyAttemptLayout(path.join(value.directory, 'attempt'),
    pointId, 2);
  fs.mkdirSync(layout.raw, {recursive: true});
  fs.mkdirSync(layout.diagnostics, {recursive: true});
  fs.writeFileSync(path.join(layout.raw, 'warmup.oha.json'), '{}\n');
  fs.writeFileSync(path.join(layout.diagnostics, 'collector.stderr'),
    'collector stopped\n');
  const error = new Error('collector exited 1');
  error.invalidReason = 'collector-failure';
  const description = describePolicyCostPoint(value.plan, catalog, pointId);
  const retained = retainInvalidPolicyAttempt({layout, description,
    plan: value.plan, catalogBytes: catalog, attempt: 2, error,
  });
  assert.equal(retained.reason, 'collector-failure');
  assert.equal(retained.result.evidence_status, 'invalid');
  assert.equal(retained.result.publication_authorized, false);
  validatePolicyCostResult(retained.result, value.plan, catalog);
  assert.equal(fs.readFileSync(retained.resultFile, 'utf8')
    .includes('collector stopped'), false);
  assert.equal(classifyPolicyCostFailure(new Error('source commit changed')),
    'source-drift');
  assert.equal(classifyPolicyCostFailure(new Error(
    'final warmups did not establish a resource plateau')),
  'environment-drift');
  assert.equal(classifyPolicyCostFailure(new Error('SIGTERM')), 'interrupted');
});

test('PERF-06 recovery requires one process and drained active metrics', () => {
  const before = {identity: 'boot:42:100', pid: 42, start_ticks: 100,
    restart_count: 0};
  assert.deepEqual(evaluatePolicyRecovery(before, {...before},
    [0, 0, 0, 0, 0]), {process_stable: true,
    active_metrics_drained: true, recovered: true});
  assert.equal(evaluatePolicyRecovery(before, {...before, pid: 43},
    [0, 0, 0, 0, 0]).recovered, false);
  assert.equal(evaluatePolicyRecovery(before, {...before},
    [0, 0, 1, 0, 0]).recovered, false);
});
