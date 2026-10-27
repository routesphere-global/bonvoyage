import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import {buildOhaRun, OHA_DIRECT_LANE_MEMORY_BYTES, OHA_LANE_MEMORY_BYTES,
  parseOhaReport, parseOhaSequence,
  partitionCpus} from './phase5-oha-lanes.mjs';

const digest = (value) => createHash('sha256').update(value).digest('hex');

function lane(index, start, end, responses, p999 = 0.004) {
  return {index, start_ns: String(start), end_ns: String(end), exit_code: 0,
    raw_json: JSON.stringify({summary: {total: 10},
      statusCodeDistribution: {'200': responses}, errorDistribution: {},
      latencyPercentiles: {p50: 0.001, p95: 0.002, p99: 0.003,
        'p99.9': p999}}), stderr: ''};
}

function bundle() {
  return {kind: 'phase5-oha-lanes', schema_version: 1,
    rate_per_lane: 150, cpu_sets: ['0-1', '2-3'],
    lanes: [lane(0, 1000000000, 11200000000, 1000),
      lane(1, 1100000000, 11300000000, 2000, 0.006)]};
}

function clockIdentity(current = 'tsc') {
  return {current_clocksource: current,
    available_clocksources: ['tsc', 'kvm-clock', 'hpet', 'acpi_pm'],
    tsc_capabilities: {tsc: true, rdtscp: true, constant_tsc: true,
      nonstop_tsc: true, tsc_known_freq: true}};
}

function clockWindow() {
  return {before: clockIdentity(), after: clockIdentity()};
}

function structuredBundle() {
  const targets = ['10.0.0.43', '10.0.0.44'];
  const workload = {request_mode: 'fixed-count', client_sha256: '5'.repeat(64),
    protocol: 'http1', tls: false, authority: 'upstream.example.test',
    listener_port: 8081, target_addresses: targets, path: '/payload/256',
    connections_per_lane: 8, streams_per_connection: 1, requests_per_lane: 100,
    memory_limit_bytes: OHA_LANE_MEMORY_BYTES, ca_sha256: null,
    credential_sha256: null, method: 'GET', keepalive: true, compression: false,
    latency_correction: true, request_timeout_seconds: 5,
    connect_timeout_seconds: 5, redirect_limit: 0};
  return {kind: 'phase5-oha-lanes', schema_version: 2, rate_per_lane: 10,
    cpu_sets: ['0', '1'], workload,
    lanes: [
      {...lane(0, 1000000000, 11000000000, 100), target_address: targets[0]},
      {...lane(1, 1000000000, 11000000000, 100), target_address: targets[1]},
    ]};
}

function policyStructuredBundle() {
  const value = structuredBundle();
  value.schema_version = 4;
  value.workload = {...value.workload,
    request_headers_sha256: digest('{"authorization":"Bearer secret"}\n'),
    request_header_names: ['authorization']};
  return value;
}

function directStructuredBundle() {
  const value = structuredBundle();
  value.schema_version = 3;
  value.rate_per_lane = 10;
  value.cpu_sets = Array.from({length: 32}, (_, index) => String(index));
  value.workload = {...value.workload, evidence_scope: 'direct-support',
    memory_limit_bytes: OHA_DIRECT_LANE_MEMORY_BYTES,
    memory_swap_limit_bytes: OHA_DIRECT_LANE_MEMORY_BYTES};
  value.lanes = Array.from({length: 32}, (_, index) => ({
    ...lane(index, 1000000000, 11000000000, 100),
    target_address: value.workload.target_addresses[index % 2]}));
  return value;
}

test('CPU partitions are disjoint and reject overlapping placement', () => {
  assert.deepEqual(partitionCpus('0-7', 4), ['0,1', '2,3', '4,5', '6,7']);
  assert.deepEqual(partitionCpus('0-31', 32, 32),
    Array.from({length: 32}, (_, index) => String(index)));
  assert.throws(() => partitionCpus('0-31', 32), /exceeds/u);
  assert.throws(() => partitionCpus('0-3,3-7', 4), /overlaps/u);
  assert.throws(() => partitionCpus('0-1', 4), /exceeds/u);
  assert.throws(() => partitionCpus('0-31', 32, 64), /limit is invalid/u);
});

test('generic diagnostics may use 32 lanes without widening structured evidence', () => {
  const diagnostic = bundle();
  diagnostic.cpu_sets = Array.from({length: 32}, (_, index) => String(index));
  diagnostic.lanes = Array.from({length: 32}, (_, index) =>
    lane(index, 1000000000, 11000000000, 100));
  assert.equal(parseOhaReport(diagnostic).client_lanes, 32);

  const structured = structuredBundle();
  structured.cpu_sets = diagnostic.cpu_sets;
  structured.lanes = diagnostic.lanes.map((item, index) => ({...item,
    target_address: structured.workload.target_addresses[index % 2]}));
  assert.throws(() => parseOhaReport(structured), /bundle is invalid/u);

  assert.throws(() => buildOhaRun(['--lanes', '32', '--rate-per-lane', '1000',
    '--requests-per-lane', '10000', '--connections-per-lane', '8',
    '--streams-per-connection', '1', '--cpu-set', '0-31', '--image',
    `example.test/oha@sha256:${'5'.repeat(64)}`, '--protocol', 'http1',
    '--url', 'http://api.example.test:8080/payload/256', '--target-addresses',
    '10.0.0.42']), /exceeds/u);
});

test('direct-support evidence requires its distinct 32-lane resource contract', () => {
  const valid = directStructuredBundle();
  const summary = parseOhaReport(valid);
  assert.equal(summary.client_lanes, 32);
  assert.equal(summary.workload.evidence_scope, 'direct-support');
  assert.equal(summary.workload.memory_limit_bytes,
    OHA_DIRECT_LANE_MEMORY_BYTES);

  const memory = structuredClone(valid);
  memory.workload.memory_limit_bytes = OHA_LANE_MEMORY_BYTES;
  assert.throws(() => parseOhaReport(memory), /memory limit changed/u);
  const swap = structuredClone(valid);
  swap.workload.memory_swap_limit_bytes = OHA_LANE_MEMORY_BYTES;
  assert.throws(() => parseOhaReport(swap), /memory\/swap limit changed/u);
  const groupedCpu = structuredClone(valid);
  groupedCpu.cpu_sets[0] = '0,32';
  assert.throws(() => parseOhaReport(groupedCpu), /one-core lanes/u);
  const missingLane = structuredClone(valid);
  missingLane.cpu_sets.pop();
  missingLane.lanes.pop();
  assert.throws(() => parseOhaReport(missingLane),
    /target topology|32 one-core lanes/u);
});

test('direct-support runner freezes cleartext two-target topology and memory', () => {
  const args = ['--lanes', '32', '--rate-per-lane', '25500',
    '--requests-per-lane', '2295000', '--warmup-requests-per-lane', '765000',
    '--connections-per-lane', '64', '--streams-per-connection', '1',
    '--cpu-set', '0-31', '--image',
    `example.test/oha@sha256:${'5'.repeat(64)}`, '--protocol', 'http1',
    '--url', 'http://upstream.example.test:8081/payload/256',
    '--target-addresses', '10.0.0.43,10.0.0.44'];
  const run = buildOhaRun(args, 'direct-support');
  assert.equal(run.schemaVersion, 3);
  assert.equal(run.sets.length, 32);
  assert.ok(run.sets.every((set, index) => set === String(index)));
  assert.equal(run.workload.evidence_scope, 'direct-support');
  assert.equal(run.workload.memory_limit_bytes, OHA_DIRECT_LANE_MEMORY_BYTES);
  assert.equal(run.workload.memory_swap_limit_bytes,
    OHA_DIRECT_LANE_MEMORY_BYTES);
  assert.ok(run.invocations.every((invocation) =>
    invocation.args.includes(`${OHA_DIRECT_LANE_MEMORY_BYTES}b`) &&
    invocation.args.includes('--memory-swap')));
  assert.deepEqual(run.invocations.slice(0, 4).map((item) => item.targetAddress),
    ['10.0.0.43', '10.0.0.44', '10.0.0.43', '10.0.0.44']);

  const tooFew = [...args];
  tooFew[tooFew.indexOf('--lanes') + 1] = '16';
  assert.throws(() => buildOhaRun(tooFew, 'direct-support'), /requires 32 lanes/u);
  const oneTarget = [...args];
  oneTarget[oneTarget.indexOf('--target-addresses') + 1] = '10.0.0.43';
  assert.throws(() => buildOhaRun(oneTarget, 'direct-support'), /two targets/u);
});

test('replay retains the process envelope and active measurement duration', () => {
  const summary = parseOhaReport(JSON.stringify(bundle()));
  assert.equal(summary.summary.total, 10.3);
  assert.equal(summary.active_measurement_seconds, 10);
  assert.equal(summary.statusCodeDistribution['200'], 3000);
  assert.equal(summary.latencyPercentiles['p99.9'], 0.006);
  assert.equal(summary.offered_rps, 300);
  assert.equal(summary.successful_rps, 300);
  assert.ok(3000 / summary.summary.total < 300);
});

test('structured replay binds a stable load-generator clock identity', () => {
  const valid = structuredBundle();
  valid.clock = clockWindow();
  assert.equal(parseOhaReport(valid).clock.current_clocksource, 'tsc');

  const changed = structuredBundle();
  changed.clock = clockWindow();
  changed.clock.after.current_clocksource = 'kvm-clock';
  assert.throws(() => parseOhaReport(changed), /clock changed during measurement/u);

  const unavailable = structuredBundle();
  unavailable.clock = clockWindow();
  unavailable.clock.before.available_clocksources = ['kvm-clock', 'hpet'];
  assert.throws(() => parseOhaReport(unavailable), /current clocksource is invalid/u);
});

test('failed, missing, and skewed lanes fail closed', () => {
  const failed = bundle(); failed.lanes[1].exit_code = 1;
  assert.throws(() => parseOhaReport(failed), /failed or is missing/u);
  const missing = bundle(); missing.lanes.pop();
  assert.throws(() => parseOhaReport(missing), /bundle is invalid|placement is invalid/u);
  const skewed = bundle();
  skewed.lanes[1].start_ns = '3000000000';
  skewed.lanes[1].end_ns = '13000000000';
  assert.throws(() => parseOhaReport(skewed), /windows insufficiently aligned/u);
});

test('non-200 and transport errors remain visible to the gate', () => {
  const invalid = bundle();
  const raw = JSON.parse(invalid.lanes[1].raw_json);
  raw.statusCodeDistribution = {'200': 1999, '503': 1};
  raw.errorDistribution = {timeout: 2};
  invalid.lanes[1].raw_json = JSON.stringify(raw);
  const summary = parseOhaReport(invalid);
  assert.equal(summary.statusCodeDistribution['503'], 1);
  assert.equal(summary.errorDistribution.timeout, 2);
  assert.equal(summary.successful_rps, 299.9);
});

test('altered timing, invalid counts, and nested bundles are rejected', () => {
  const wrongClock = bundle(); wrongClock.lanes[0].end_ns = '1000000001';
  assert.throws(() => parseOhaReport(wrongClock), /wall duration disagrees/u);
  const wrongCount = bundle();
  const raw = JSON.parse(wrongCount.lanes[0].raw_json);
  raw.statusCodeDistribution['200'] = 100.5;
  wrongCount.lanes[0].raw_json = JSON.stringify(raw);
  assert.throws(() => parseOhaReport(wrongCount), /must be a count/u);
  const nested = bundle(); nested.lanes[0].raw_json = JSON.stringify(bundle());
  assert.throws(() => parseOhaReport(nested), /nested/u);
});

test('invalid rate and overlapping CPU claims fail closed', () => {
  const rate = bundle(); rate.rate_per_lane = 0;
  assert.throws(() => parseOhaReport(rate), /placement is invalid/u);
  const overlap = bundle(); overlap.cpu_sets[1] = '1-3';
  assert.throws(() => parseOhaReport(overlap), /overlap/u);
});

test('ordinary single-lane oha reports remain unchanged', () => {
  const report = JSON.parse(bundle().lanes[0].raw_json);
  assert.equal(parseOhaReport(report), report);
});

test('structured replay binds deterministic lane-to-target placement', () => {
  const valid = structuredBundle();
  const summary = parseOhaReport(valid);
  assert.deepEqual(summary.workload.target_addresses,
    ['10.0.0.43', '10.0.0.44']);
  const changed = structuredBundle();
  changed.lanes[1].target_address = '10.0.0.43';
  assert.throws(() => parseOhaReport(changed), /target differs from workload/u);
  const duplicate = structuredBundle();
  duplicate.workload.target_addresses[1] = duplicate.workload.target_addresses[0];
  assert.throws(() => parseOhaReport(duplicate), /target addresses invalid/u);
});

test('policy replay binds request-header identity without retaining values', () => {
  const valid = policyStructuredBundle();
  const summary = parseOhaReport(valid);
  assert.equal(summary.workload.request_headers_sha256,
    digest('{"authorization":"Bearer secret"}\n'));
  assert.deepEqual(summary.workload.request_header_names, ['authorization']);
  assert.equal(JSON.stringify(summary.workload).includes('Bearer secret'), false);

  const unsorted = policyStructuredBundle();
  unsorted.workload.request_header_names = ['x-request-remove', 'authorization'];
  assert.throws(() => parseOhaReport(unsorted), /unique, sorted, lowercase/u);
  const protectedHeader = policyStructuredBundle();
  protectedHeader.workload.request_header_names = ['content-length'];
  assert.throws(() => parseOhaReport(protectedHeader), /unique, sorted, lowercase/u);
  const credential = policyStructuredBundle();
  credential.workload.credential_sha256 = digest('api-key');
  assert.throws(() => parseOhaReport(credential), /cannot combine/u);
});

test('legacy structured evidence remains readable but keeps its schema identity', () => {
  const legacy = structuredBundle();
  legacy.schema_version = 1;
  legacy.workload.gateway_address = legacy.workload.target_addresses[0];
  delete legacy.workload.target_addresses;
  for (const item of legacy.lanes) delete item.target_address;
  const summary = parseOhaReport(legacy);
  assert.deepEqual(summary.workload.target_addresses, ['10.0.0.43']);
  const warmup = structuredClone(legacy);
  warmup.workload.requests_per_lane = 50;
  for (const item of warmup.lanes) {
    const report = JSON.parse(item.raw_json);
    report.statusCodeDistribution['200'] = 50;
    item.raw_json = JSON.stringify(report);
  }
  const sequence = parseOhaSequence({kind: 'phase5-oha-sequence',
    schema_version: 1, warmup, measurement: legacy});
  assert.equal(sequence.schema_version, 1);
});

test('runner launches disjoint lanes and emits replayable raw reports', () => {
  const script = path.join(path.dirname(fileURLToPath(import.meta.url)),
    'phase5-oha-lanes.mjs');
  const fakeClient = `setTimeout(() => {
    process.stdout.write(JSON.stringify({summary: {total: 2},
      statusCodeDistribution: {'200': 100}, errorDistribution: {},
      latencyPercentiles: {p50: 0.001, p95: 0.002, p99: 0.003,
        'p99.9': 0.004}}));
  }, 2000);`;
  const output = execFileSync(process.execPath, [script, 'run', '--lanes', '2',
    '--rate-per-lane', '50', '--cpu-set', '0-3', '--', process.execPath,
    '-e', fakeClient, '{rate}', '{cpus}'], {encoding: 'utf8'});
  const bundle = JSON.parse(output);
  assert.equal(bundle.lanes.length, 2);
  assert.ok(bundle.lanes.every((lane) => lane.exit_code === 0));
  assert.equal(parseOhaReport(bundle).statusCodeDistribution['200'], 200);
});

test('structured runner builds a fixed, digest-bound client without retaining secrets', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-oha-run-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const ca = path.join(directory, 'ca.pem');
  const credential = path.join(directory, 'api-key.txt');
  const secret = '0123456789abcdef0123456789abcdef';
  fs.writeFileSync(ca, 'test-ca');
  fs.writeFileSync(credential, `${secret}\n`, {mode: 0o600});
  const imageDigest = '5'.repeat(64);
  const run = buildOhaRun(['--lanes', '4', '--rate-per-lane', '50000',
    '--requests-per-lane', '3000000', '--warmup-requests-per-lane', '750000',
    '--connections-per-lane', '128',
    '--streams-per-connection', '4', '--cpu-set', '0-31', '--image',
    `example.test/oha@sha256:${imageDigest}`, '--protocol', 'http2', '--url',
    'https://api.example.test:8444/payload/256', '--target-addresses',
    '10.0.0.42,10.0.0.43',
    '--ca-file', ca, '--credential-file', credential]);
  assert.deepEqual(run.sets, ['0,1,2,3,4,5,6,7', '8,9,10,11,12,13,14,15',
    '16,17,18,19,20,21,22,23', '24,25,26,27,28,29,30,31']);
  assert.equal(run.workload.client_sha256, imageDigest);
  assert.equal(run.workload.ca_sha256, digest('test-ca'));
  assert.equal(run.workload.credential_sha256, digest(`${secret}\n`));
  assert.equal(run.workload.requests_per_lane, 3000000);
  assert.equal(run.workload.memory_limit_bytes, OHA_LANE_MEMORY_BYTES);
  assert.deepEqual(run.workload.target_addresses, ['10.0.0.42', '10.0.0.43']);
  assert.equal(run.warmupWorkload.requests_per_lane, 750000);
  assert.equal(JSON.stringify(run.workload).includes(secret), false);
  assert.ok(run.invocations.every((invocation) =>
    invocation.command === 'sudo' && invocation.args.includes('--latency-correction') &&
    invocation.args.includes('--connect-to') && invocation.args.includes('-p') &&
    invocation.args.includes(`${OHA_LANE_MEMORY_BYTES}b`)));
  assert.ok(run.invocations.every((invocation) => invocation.args.includes(
    `X-API-Key: ${secret}`)));
  assert.deepEqual(run.invocations.map((invocation) => invocation.targetAddress),
    ['10.0.0.42', '10.0.0.43', '10.0.0.42', '10.0.0.43']);
  assert.ok(run.warmupInvocations.every((invocation) =>
    invocation.args.includes('750000')));
  assert.deepEqual(run.redactions, [secret]);
});

test('structured policy runner binds and redacts generic request headers', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-oha-policy-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const ca = path.join(directory, 'ca.pem');
  const headers = path.join(directory, 'headers.json');
  const token = 'Bearer eyJhbGciOiJSUzI1NiJ9.test.signature';
  const removed = 'remove-this-client-value';
  const headerBytes = `${JSON.stringify({authorization: token,
    'x-request-remove': removed})}\n`;
  fs.writeFileSync(ca, 'test-ca');
  fs.writeFileSync(headers, headerBytes, {mode: 0o600});
  const run = buildOhaRun(['--lanes', '4', '--rate-per-lane', '50000',
    '--requests-per-lane', '3000000', '--warmup-requests-per-lane', '750000',
    '--connections-per-lane', '128', '--streams-per-connection', '1',
    '--cpu-set', '0-31', '--image',
    `example.test/oha@sha256:${'5'.repeat(64)}`, '--protocol', 'http1', '--url',
    'https://api.example.test:8443/payload/8192', '--target-addresses',
    '10.0.0.42', '--ca-file', ca, '--request-headers-file', headers]);
  assert.equal(run.schemaVersion, 4);
  assert.equal(run.workload.request_headers_sha256, digest(headerBytes));
  assert.deepEqual(run.workload.request_header_names,
    ['authorization', 'x-request-remove']);
  assert.equal(JSON.stringify(run.workload).includes(token), false);
  assert.ok(run.invocations.every((invocation) =>
    invocation.args.includes(`authorization: ${token}`) &&
    invocation.args.includes(`x-request-remove: ${removed}`)));
  assert.deepEqual(run.redactions, [token, removed]);

  assert.throws(() => buildOhaRun([
    '--lanes', '4', '--rate-per-lane', '50000',
    '--requests-per-lane', '3000000', '--connections-per-lane', '128',
    '--streams-per-connection', '1', '--cpu-set', '0-31', '--image',
    `example.test/oha@sha256:${'5'.repeat(64)}`, '--protocol', 'http1', '--url',
    'https://api.example.test:8443/payload/8192', '--target-addresses',
    '10.0.0.42', '--ca-file', ca, '--credential-file', headers,
    '--request-headers-file', headers]), /mutually exclusive/u);
});

test('structured policy runner rejects unsafe or malformed headers', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-oha-policy-bad-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const base = ['--lanes', '4', '--rate-per-lane', '20',
    '--requests-per-lane', '200', '--connections-per-lane', '8',
    '--streams-per-connection', '1', '--cpu-set', '0-7', '--image',
    `example.test/oha@sha256:${'5'.repeat(64)}`, '--protocol', 'http1', '--url',
    'http://api.example.test:8080/payload/256', '--target-addresses', '10.0.0.42'];
  const filename = path.join(directory, 'headers.json');
  const reject = (contents, pattern) => {
    fs.writeFileSync(filename, contents);
    assert.throws(() => buildOhaRun([...base, '--request-headers-file', filename]),
      pattern);
  };
  reject('{', /one JSON object/u);
  reject(JSON.stringify({Host: 'api.example.test'}), /not lowercase/u);
  reject(JSON.stringify({'content-length': '1'}), /unsafe/u);
  reject(JSON.stringify({'x-test': 'value\r\ninjected: true'}), /value is invalid/u);
  reject(JSON.stringify({}), /between one and sixteen/u);
});

test('structured CLI emits replayable evidence and scrubs the API key', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-oha-cli-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const secret = 'abcdef0123456789abcdef0123456789';
  const ca = path.join(directory, 'ca.pem');
  const credential = path.join(directory, 'api-key.txt');
  const sudo = path.join(directory, 'sudo');
  fs.writeFileSync(ca, 'test-ca');
  fs.writeFileSync(credential, `${secret}\n`, {mode: 0o600});
  fs.writeFileSync(sudo, `#!/usr/bin/env node
const started = process.hrtime.bigint();
let requests = 0;
let header = '';
for (let index = 2; index < process.argv.length; index += 1) {
  if (process.argv[index] === '-n') requests = Number(process.argv[++index]);
  else if (process.argv[index] === '-H') header = process.argv[++index];
}
process.stderr.write(header);
setTimeout(() => {
  // Keep the fixture clear of the production alignment boundary under loaded CI.
  const total = Number(process.hrtime.bigint() - started) / 1e9 + 0.4;
  process.stdout.write(JSON.stringify({summary: {total},
    statusCodeDistribution: {'200': requests}, errorDistribution: {},
    latencyPercentiles: {p50: 0.001, p95: 0.002, p99: 0.003, 'p99.9': 0.004}}));
}, 8000);
`, {mode: 0o700});
  const script = path.join(path.dirname(fileURLToPath(import.meta.url)),
    'phase5-oha-lanes.mjs');
  const output = execFileSync(process.execPath, [script, 'run-oha', '--lanes', '2',
    '--rate-per-lane', '20', '--requests-per-lane', '10',
    '--warmup-requests-per-lane', '5',
    '--connections-per-lane', '2', '--streams-per-connection', '1',
    '--cpu-set', '0-3', '--image', `example.test/oha@sha256:${'5'.repeat(64)}`,
    '--protocol', 'http1', '--url', 'https://api.example.test:8443/payload/256',
    '--target-addresses', '10.0.0.42', '--ca-file', ca,
    '--credential-file', credential], {encoding: 'utf8',
    env: {...process.env, PATH: `${directory}:${process.env.PATH}`}});
  assert.equal(output.includes(secret), false);
  const bundle = JSON.parse(output);
  assert.ok(bundle.warmup.lanes.every((lane) =>
    lane.stderr === 'X-API-Key: [REDACTED]'));
  assert.ok(bundle.measurement.lanes.every((lane) =>
    lane.stderr === 'X-API-Key: [REDACTED]'));
  const sequence = parseOhaSequence(bundle);
  assert.equal(sequence.warmup.statusCodeDistribution['200'], 10);
  assert.equal(sequence.measurement.statusCodeDistribution['200'], 20);
  assert.equal(sequence.schema_version, 2);
});

test('structured CLI retains a scrubbed failed warmup and skips measurement', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-oha-failed-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const secret = 'fedcba9876543210fedcba9876543210';
  const ca = path.join(directory, 'ca.pem');
  const credential = path.join(directory, 'api-key.txt');
  const invocations = path.join(directory, 'invocations.txt');
  const sudo = path.join(directory, 'sudo');
  fs.writeFileSync(ca, 'test-ca');
  fs.writeFileSync(credential, `${secret}\n`, {mode: 0o600});
  fs.writeFileSync(sudo, `#!/bin/sh
requests=''
cpus=''
header=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -n) requests="$2"; shift 2 ;;
    --cpuset-cpus) cpus="$2"; shift 2 ;;
    -H) header="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '%s\n' "$cpus" >> '${invocations}'
printf '%s' "$header" >&2
if [ "$cpus" = '2,3' ]; then exit 7; fi
sleep 1
printf '{"summary":{"total":1},"statusCodeDistribution":{"200":%s},"errorDistribution":{},"latencyPercentiles":{"p50":0.001,"p95":0.002,"p99":0.003,"p99.9":0.004}}' "$requests"
`, {mode: 0o700});
  const script = path.join(path.dirname(fileURLToPath(import.meta.url)),
    'phase5-oha-lanes.mjs');
  const result = spawnSync(process.execPath, [script, 'run-oha', '--lanes', '2',
    '--rate-per-lane', '20', '--requests-per-lane', '10',
    '--warmup-requests-per-lane', '5', '--connections-per-lane', '2',
    '--streams-per-connection', '1', '--cpu-set', '0-3', '--image',
    `example.test/oha@sha256:${'5'.repeat(64)}`, '--protocol', 'http1', '--url',
    'https://api.example.test:8443/payload/256', '--target-addresses', '10.0.0.42',
    '--ca-file', ca, '--credential-file', credential], {encoding: 'utf8',
    env: {...process.env, PATH: `${directory}:${process.env.PATH}`}});
  assert.equal(result.status, 1);
  assert.match(result.stderr, /lane 1 failed or is missing/u);
  assert.equal(result.stdout.includes(secret), false);
  const failed = JSON.parse(result.stdout);
  assert.equal(failed.kind, 'phase5-oha-lanes');
  assert.deepEqual(failed.lanes.map((lane) => lane.exit_code), [0, 7]);
  assert.ok(failed.lanes.every((lane) => !lane.stderr.includes(secret)));
  assert.equal(fs.readFileSync(invocations, 'utf8').trim().split('\n').length, 2);
});

test('structured runner rejects mutable images, duration-like URLs, and TLS drift', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-oha-reject-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const ca = path.join(directory, 'ca.pem');
  fs.writeFileSync(ca, 'test-ca');
  const base = ['--lanes', '4', '--rate-per-lane', '20',
    '--requests-per-lane', '200', '--connections-per-lane', '8',
    '--streams-per-connection', '1', '--cpu-set', '0-7', '--image',
    `example.test/oha@sha256:${'5'.repeat(64)}`, '--protocol', 'http1', '--url',
    'http://api.example.test:8080/payload/256', '--target-addresses', '10.0.0.42'];
  const mutable = [...base];
  mutable[mutable.indexOf('--image') + 1] = 'example.test/oha:latest';
  assert.throws(() => buildOhaRun(mutable), /pinned/u);
  const query = [...base];
  query[query.indexOf('--url') + 1] += '?duration=60s';
  assert.throws(() => buildOhaRun(query), /no credentials, query, or fragment/u);
  assert.throws(() => buildOhaRun([...base, '--ca-file', ca]), /cleartext forbids/u);
  const unreadableCa = [...base];
  unreadableCa[unreadableCa.indexOf('--url') + 1] =
    'https://api.example.test:8443/payload/256';
  unreadableCa.push('--ca-file', ca);
  fs.chmodSync(ca, 0o600);
  assert.throws(() => buildOhaRun(unreadableCa), /CA file must be world-readable/u);
  assert.throws(() => buildOhaRun([...base,
    '--warmup-requests-per-lane', '200']), /fewer/u);
  const unevenTargets = [...base];
  unevenTargets[unevenTargets.indexOf('--lanes') + 1] = '3';
  unevenTargets[unevenTargets.indexOf('--target-addresses') + 1] =
    '10.0.0.42,10.0.0.43';
  assert.throws(() => buildOhaRun(unevenTargets), /target addresses invalid/u);
});
