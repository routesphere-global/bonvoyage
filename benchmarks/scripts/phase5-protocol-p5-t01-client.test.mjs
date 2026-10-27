import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {buildProtocolNativePlan} from './phase5-protocol-native-plan.mjs';
import {catalogBytes, nativePlanInput} from
  './phase5-protocol-native-test-fixture.mjs';
import {buildP5T01ClientRun, parseP5T01ClientOptions,
  failedRunnerDiagnostics, validateP5T01ClientOutput} from
  './phase5-protocol-p5-t01-client.mjs';

function fixture(t, pointId = 't01-fixed-response-15360-8c-r1') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'perf05-p5-t01-client-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const bytes = catalogBytes();
  const plan = buildProtocolNativePlan(nativePlanInput(bytes), bytes);
  const catalog = path.join(root, 'catalog.json');
  const planFile = path.join(root, 'plan.json');
  const ca = path.join(root, 'ca.pem');
  fs.writeFileSync(catalog, bytes);
  fs.writeFileSync(planFile, JSON.stringify(plan));
  fs.writeFileSync(ca, 'test-ca');
  return {root, plan, catalog, planFile, ca, pointId};
}

function build(item, overrides = {}) {
  return buildP5T01ClientRun({catalog: item.catalog, plan: item.planFile,
    pointId: item.pointId, stage: 'measurement',
    image: `example.test/oha@sha256:${item.plan.input.source.load_client_sha256}`,
    cpuSet: '0-31', lanes: 8, caFile: item.ca,
    runner: '/opt/bonvoyage/phase5-oha-lanes.mjs', ...overrides});
}

function clientOutput(run, duration = 60) {
  const requests = run.workload.requests_per_lane;
  const lane = JSON.stringify({summary: {total: duration},
    statusCodeDistribution: {'200': requests}, errorDistribution: {},
    latencyPercentiles: {p50: 0.001, p95: 0.002, p99: 0.003,
      'p99.9': 0.004}});
  return JSON.stringify({kind: 'phase5-oha-lanes', schema_version: 2,
    rate_per_lane: run.offeredRps / run.clientLanes,
    cpu_sets: run.clientCpuSets, workload: run.workload,
    lanes: Array.from({length: run.clientLanes}, (_, index) => ({index,
      start_ns: '0', end_ns: String(duration * 1e9), exit_code: 0,
      raw_json: lane, stderr: '',
      target_address: run.workload.target_addresses[0]}))});
}

test('P5-T01 client derives exact fixed-response measurement from the plan', (t) => {
  const item = fixture(t);
  const run = build(item);
  assert.equal(run.workload.requests_per_lane, 1500000);
  assert.equal(run.workload.connections_per_lane, 64);
  assert.deepEqual(run.workload.target_addresses, ['10.0.0.20']);
  assert.equal(run.workload.path, '/perf05/fixed/15360');
  assert.equal(run.workload.tls, true);
  assert.equal(run.args.includes('--warmup-requests-per-lane'), false);
});

test('P5-T01 client derives warmup duration and proxied path independently', (t) => {
  const item = fixture(t, 't01-proxied-response-65536-24c-r1');
  const run = build(item, {stage: 'warmup', cpuSet: '0-31'});
  assert.equal(run.workload.requests_per_lane, 1125000);
  assert.equal(run.workload.connections_per_lane, 64);
  assert.equal(run.workload.path, '/perf05/proxied/65536');
});

test('P5-T01 client rejects image, stage, and placement drift', (t) => {
  const item = fixture(t);
  assert.throws(() => build(item, {image:
    `example.test/oha@sha256:${'0'.repeat(64)}`}), /differs from the native plan/u);
  assert.throws(() => build(item, {stage: 'other'}), /stage must be/u);
  assert.throws(() => build(item, {lanes: 3}), /divide evenly/u);
  assert.throws(() => build(item, {cpuSet: '0-15'}),
    /placement differs/u);
});

test('P5-T01 client retains bounded failed-lane diagnostics', () => {
  const value = failedRunnerDiagnostics(JSON.stringify({
    kind: 'phase5-oha-lanes', schema_version: 2,
    lanes: [{index: 0, exit_code: 1, stderr: 'Permission denied'},
      {index: 1, exit_code: 0, stderr: ''}],
  }));
  assert.deepEqual(JSON.parse(value), {kind: 'phase5-oha-lanes', schema_version: 2,
    lanes: [{index: 0, exit_code: 1, stderr: 'Permission denied'},
      {index: 1, exit_code: 0, stderr: ''}]});
  assert.match(failedRunnerDiagnostics('not-json'), /unparseable/u);
});

test('P5-T01 client CLI rejects unknown, duplicate, and valueless options', () => {
  const required = ['--catalog', 'catalog.json', '--plan', 'plan.json',
    '--point-id', 'point-r1', '--stage', 'measurement', '--image',
    `example.test/oha@sha256:${'a'.repeat(64)}`, '--cpu-set', '0-31',
    '--lanes', '8', '--ca-file', 'ca.pem'];
  assert.equal(parseP5T01ClientOptions(required, '/runner').runner, '/runner');
  assert.throws(() => parseP5T01ClientOptions([...required, '--unknown', 'x'],
    '/runner'), /unknown or valueless/u);
  assert.throws(() => parseP5T01ClientOptions([...required,
    '--lanes', '8'], '/runner'), /may appear only once/u);
  assert.throws(() => parseP5T01ClientOptions(required.slice(0, -1), '/runner'),
    /name\/value pairs/u);
});

test('P5-T01 client accepts only the exact emitted workload and placement', (t) => {
  const item = fixture(t);
  const run = build(item);
  assert.equal(validateP5T01ClientOutput(clientOutput(run), run).offered_rps,
    run.offeredRps);
  const changed = JSON.parse(clientOutput(run));
  changed.workload.path = '/different';
  assert.throws(() => validateP5T01ClientOutput(JSON.stringify(changed), run),
    /differs from the planned workload/u);
  const moved = JSON.parse(clientOutput(run));
  moved.cpu_sets[0] = '31';
  assert.throws(() => validateP5T01ClientOutput(JSON.stringify(moved), run),
    /CPU sets overlap|planned workload/u);
});
