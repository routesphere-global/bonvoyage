import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {buildPolicyCostClientRun, completePolicyRequestObservation,
  observePolicyRequest, parsePolicyCostClientOptions,
  parsePolicyProbeResponse} from
  './phase5-policy-cost-client.mjs';
import {buildPolicyCostPlan} from './phase5-policy-cost.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const catalogFile = path.join(root,
  'benchmarks/workloads/policy-cost/phase5-policy-cost.json');
const catalog = fs.readFileSync(catalogFile);
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

function input(headerDigest, credentialDigest) {
  return {schema_version: 2, evidence_class: 'shared-vm-directional',
    catalog_sha256: sha256(catalog),
    source: {binary_source_commit: '1'.repeat(40),
      harness_commit: '2'.repeat(40), source_dirty: false,
      gateway_binary_sha256: sha256('gateway'),
      client_sha256: 'a'.repeat(64), upstream_sha256: sha256('upstream'),
      collector_bundle_sha256: sha256('collectors'),
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
      header_transform_request_sha256: headerDigest,
      api_key_credential_sha256: credentialDigest,
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
}

function base64url(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function jwtHeaders() {
  const header = base64url({alg: 'RS256', kid: 'fixture', typ: 'at+jwt'});
  const claims = base64url({aud: 'payments-api', exp: 400, iat: 100,
    iss: 'https://issuer.example.test', scope: 'payments:read',
    tenant: 'tenant-a'});
  return Buffer.from(`${JSON.stringify({authorization:
    `Bearer ${header}.${claims}.signature`})}\n`);
}

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'perf06-client-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const header = fs.readFileSync(path.join(root,
    'benchmarks/workloads/policy-cost/header-transform-request.json'));
  const credential = Buffer.from('0123456789abcdef0123456789abcdef\n');
  const plan = buildPolicyCostPlan(input(sha256(header), sha256(credential)),
    catalog);
  const planFile = path.join(directory, 'plan.json');
  const caFile = path.join(directory, 'ca.pem');
  const headerFile = path.join(directory, 'headers.json');
  const credentialFile = path.join(directory, 'api-key.txt');
  const jwtFile = path.join(directory, 'jwt.json');
  fs.writeFileSync(planFile, JSON.stringify(plan));
  fs.writeFileSync(caFile, 'ca');
  fs.chmodSync(caFile, 0o644);
  fs.writeFileSync(headerFile, header);
  fs.writeFileSync(credentialFile, credential, {mode: 0o600});
  fs.writeFileSync(jwtFile, jwtHeaders(), {mode: 0o600});
  return {directory, plan, planFile, caFile, headerFile, credentialFile,
    jwtFile};
}

function options(value, pointId, requestArtifact = null, stage = 'measurement') {
  return {catalog: catalogFile, plan: value.planFile, pointId, stage,
    image: `example.test/oha@sha256:${'a'.repeat(64)}`, cpuSet: '0-15',
    lanes: 8, caFile: value.caFile, requestArtifact,
    runner: path.join(root, 'benchmarks/scripts/phase5-oha-lanes.mjs')};
}

test('PERF-06 client freezes rate, duration, connection shape, and placement', (t) => {
  const value = fixture(t);
  const run = buildPolicyCostClientRun(options(value,
    'P5-C01-24c-directional-r1', value.headerFile));
  assert.equal(run.offeredRps, 24000);
  assert.equal(run.workload.connections_per_lane, 32);
  assert.equal(run.workload.requests_per_lane, 180000);
  assert.deepEqual(run.clientCpuSets,
    ['0,1', '2,3', '4,5', '6,7', '8,9', '10,11', '12,13', '14,15']);
  assert.equal(run.workload.request_headers_sha256,
    value.plan.input.artifacts.header_transform_request_sha256);
});

test('PERF-06 client uses each plan-bound baseline and policy path', (t) => {
  const value = fixture(t);
  const baseline = buildPolicyCostClientRun(options(value,
    'P5-B02-24c-directional-r1'));
  const policy = buildPolicyCostClientRun(options(value,
    'P5-C00-24c-directional-r1'));
  const baselineUrl = baseline.args[baseline.args.indexOf('--url') + 1];
  const policyUrl = policy.args[policy.args.indexOf('--url') + 1];
  assert.equal(baseline.workload.path, '/payload/256');
  assert.equal(baselineUrl,
    'https://api.example.test:8443/payload/256');
  assert.equal(policy.workload.path, '/policy/payload/8192');
  assert.equal(policyUrl,
    'https://api.example.test:8443/policy/payload/8192');
});

test('PERF-06 client maps API keys to the secret-file path only', (t) => {
  const value = fixture(t);
  const run = buildPolicyCostClientRun(options(value,
    'P5-C03-24c-directional-r1', value.credentialFile));
  assert.equal(run.workload.credential_sha256,
    value.plan.input.artifacts.api_key_credential_sha256);
  assert.equal(run.workload.request_headers_sha256, undefined);
  assert.equal(run.args.includes('--credential-file'), true);
  assert.equal(run.args.includes('--request-headers-file'), false);
});

test('PERF-06 JWT observation retains identity and timing but no token', (t) => {
  const value = fixture(t);
  const point = value.plan.points.find((item) => item.profile_id === 'P5-C04');
  const observed = observePolicyRequest(point, value.jwtFile);
  const complete = completePolicyRequestObservation(observed, 120000, 180000);
  assert.equal(complete.jwt_window.issued_at_epoch_ms, 100000);
  assert.equal(complete.jwt_window.expires_at_epoch_ms, 400000);
  assert.equal(complete.jwt_window.measurement_started_at_epoch_ms, 120000);
  assert.equal(JSON.stringify(complete).includes('Bearer '), false);
  assert.match(complete.artifact_sha256, /^[0-9a-f]{64}$/u);
});

test('PERF-06 client rejects substituted and malformed request artifacts', (t) => {
  const value = fixture(t);
  fs.writeFileSync(value.headerFile, '{"x-policy-set":"changed"}\n');
  assert.throws(() => buildPolicyCostClientRun(options(value,
    'P5-C01-24c-directional-r1', value.headerFile)), /differs from the plan/u);
  fs.writeFileSync(value.jwtFile,
    `${JSON.stringify({authorization: 'Bearer not-a-jwt'})}\n`);
  assert.throws(() => buildPolicyCostClientRun(options(value,
    'P5-C04-24c-directional-r1', value.jwtFile)), /compact signed token/u);
  assert.throws(() => buildPolicyCostClientRun(options(value,
    'P5-B02-24c-directional-r1', value.headerFile)),
  /must not have a request artifact/u);
});

test('PERF-06 client option parser is exact and does not invent artifacts', () => {
  const argv = ['--catalog', '/tmp/catalog', '--plan', '/tmp/plan',
    '--point-id', 'P5-B02-24c-directional-r1', '--stage', 'warmup',
    '--image', `example.test/oha@sha256:${'a'.repeat(64)}`,
    '--cpu-set', '0-15', '--lanes', '8', '--ca-file', '/tmp/ca'];
  const parsed = parsePolicyCostClientOptions(argv, '/tmp/runner');
  assert.equal(parsed.requestArtifact, null);
  assert.equal(parsed.runner, '/tmp/runner');
  assert.throws(() => parsePolicyCostClientOptions([...argv,
    '--unknown', 'x'], '/tmp/runner'), /unknown or valueless/u);
});

test('PERF-06 protocol probe parser retains exact HTTP bytes', () => {
  const raw = Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc');
  const parsed = parsePolicyProbeResponse(raw);
  assert.equal(parsed.statusCode, 200);
  assert.equal(parsed.headers.toString('latin1'),
    'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n');
  assert.equal(parsed.body.toString(), 'abc');
  assert.throws(() => parsePolicyProbeResponse(Buffer.from('bad')),
    /header boundary/u);
});
