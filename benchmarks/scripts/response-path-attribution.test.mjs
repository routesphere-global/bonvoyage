import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {analyzeResponsePathAttribution, assembleNativeResponsePathRoot,
  buildNativeResponsePathCapture,
  parseResponsePathMetrics, performanceFromPerfStat,
  renderResponsePathAttribution,
  workloadFromOha} from './response-path-attribution.mjs';

const APPLICATION_FIELDS = {
  completed_responses: 'response_path_completed_responses_total',
  write_operations: 'response_path_write_operations_total',
  write_bytes: 'response_path_write_bytes_total',
  flush_operations: 'response_path_flush_operations_total',
  flush_wait_operations: 'response_path_flush_wait_operations_total',
  flush_wait_nanoseconds: 'response_path_flush_wait_nanoseconds_total',
  handoff_observations: 'response_path_handoff_observations_total',
  handoff_nanoseconds: 'response_path_handoff_nanoseconds_total',
};

function prometheus(values, labels = '') {
  const prefix = 'bonvoyage_bonvoyage_gateway_';
  return [
    `${prefix}response_path_diagnostics_enabled${labels} 1`,
    ...Object.entries(APPLICATION_FIELDS).map(([field, metric]) =>
      `${prefix}${metric}${labels} ${values[field]}`),
    '',
  ].join('\n');
}

function runtimeIdentity() {
  return {
    interval_id: 'interval-1', pid: 100, start_ticks: 200, restart_count: 0,
    boot_id: '01234567-89ab-cdef-0123-456789abcdef',
    executable_path: '/usr/bin/bonvoyage-dataplane',
    executable_sha256: 'b'.repeat(64),
    snapshot_path: '/etc/bonvoyage/snapshot.pb',
    snapshot_sha256: 'c'.repeat(64), cmdline_sha256: 'e'.repeat(64),
    response_path_diagnostics: true,
  };
}

function runtimeManifest() {
  return JSON.stringify({
    schema_version: 1,
    classification: 'private-native-gateway-input',
    distribution: 'ubuntu-24.04',
    architecture: 'amd64',
    version: '0.3.0-1',
    maintainer: 'Test <test@example.invalid>',
    producer_source_commit: 'a'.repeat(40),
    source_date_epoch: 1,
    files: {
      dataplane: {path: 'bonvoyage-dataplane', sha256: 'b'.repeat(64), bytes: 1},
      copyright: {path: 'copyright', sha256: 'f'.repeat(64), bytes: 1},
    },
  });
}

function perfStat() {
  return '100000000,,cycles,\n120000000,,instructions,\n' +
    '1000,,cache-misses,\n5000,,raw_syscalls:sys_enter,\n';
}

function fixture() {
  return {
    schema_version: 1,
    run_id: 'perf03-test',
    point_id: 'https-16384-r1',
    evidence_class: 'native-diagnostic-engineering',
    publication_authorized: false,
    source_commit: 'a'.repeat(40),
    source_dirty: false,
    binary_sha256: 'b'.repeat(64),
    snapshot_sha256: 'c'.repeat(64),
    configuration_sha256: 'd'.repeat(64),
    protocol: 'http1',
    tls: true,
    method: 'GET',
    payload_bytes: 16384,
    interval: {interval_id: 'interval-1', duration_nanoseconds: 10_000_000_000},
    process_before: {
      interval_id: 'interval-1', pid: 100, start_ticks: 200, restart_count: 0,
    },
    process_after: {
      interval_id: 'interval-1', pid: 100, start_ticks: 200, restart_count: 0,
    },
    workload: {
      interval_id: 'interval-1', duration_nanoseconds: 10_000_000_000,
      successful_responses: 1000, http_failures: 0, transport_failures: 0,
    },
    application_before: {
      interval_id: 'interval-1',
      completed_responses: 10, write_operations: 20, write_bytes: 100,
      flush_operations: 10, flush_wait_operations: 1,
      flush_wait_nanoseconds: 1000, handoff_observations: 10,
      handoff_nanoseconds: 2000,
    },
    application_after: {
      interval_id: 'interval-1',
      completed_responses: 1010, write_operations: 3020,
      write_bytes: 16_500_100, flush_operations: 1010,
      flush_wait_operations: 101, flush_wait_nanoseconds: 501000,
      handoff_observations: 1010, handoff_nanoseconds: 2_002_000,
    },
    socket_output: {
      interval_id: 'interval-1', duration_nanoseconds: 10_000_000_000,
      scope: 'gateway-downstream-sockets', pid: 100, start_ticks: 200,
      calls: 2000, requested_bytes: 17_000_000, completed_bytes: 16_800_000,
      partial_writes: 20, would_block: 40, fatal_errors: 0, lost_events: 0,
    },
    performance: {
      interval_id: 'interval-1', duration_nanoseconds: 10_000_000_000,
      scope: 'gateway-process', pid: 100, start_ticks: 200,
      cycles: 100_000_000, instructions: 120_000_000,
    },
  };
}

test('valid capture keeps application and socket operations distinct', () => {
  const summary = analyzeResponsePathAttribution(fixture());
  assert.equal(summary.decision, 'attribution-valid-not-capacity-qualification');
  assert.equal(summary.application.write_operations, 3000);
  assert.equal(summary.derived.application_writes_per_response, 3);
  assert.equal(summary.derived.application_bytes_per_write, 5500);
  assert.equal(summary.derived.application_flush_wait_fraction, 0.1);
  assert.equal(summary.derived.mean_waited_flush_microseconds, 5);
  assert.equal(summary.derived.mean_handoff_microseconds, 2);
  assert.equal(summary.derived.socket_calls_per_response, 2);
  assert.equal(summary.derived.socket_partial_write_fraction, 0.01);
  assert.equal(summary.derived.cycles_per_response, 100000);
  assert.equal(summary.derived.instructions_per_response, 120000);
  assert.equal(summary.derived.ipc, 1.2);
  assert.match(renderResponsePathAttribution(summary),
    /Application writes \/ response \| 3\.0000/u);
});

test('capture schema rejects missing and unexpected fields', () => {
  const missing = fixture();
  delete missing.socket_output;
  assert.throws(() => analyzeResponsePathAttribution(missing),
    /missing or unexpected/u);
  const extra = fixture();
  extra.estimate = true;
  assert.throws(() => analyzeResponsePathAttribution(extra),
    /missing or unexpected/u);
});

test('source, process and response-denominator drift fail closed', () => {
  const dirty = fixture(); dirty.source_dirty = true;
  assert.throws(() => analyzeResponsePathAttribution(dirty), /clean source/u);
  const replaced = fixture(); replaced.process_after.pid += 1;
  assert.throws(() => analyzeResponsePathAttribution(replaced), /replaced or restarted/u);
  const denominator = fixture(); denominator.application_after.completed_responses -= 1;
  assert.throws(() => analyzeResponsePathAttribution(denominator),
    /denominator differs/u);
});

test('counter reset, failed traffic and incomplete socket traces fail closed', () => {
  const reset = fixture(); reset.application_after.write_operations = 1;
  assert.throws(() => analyzeResponsePathAttribution(reset), /counter reset/u);
  const failed = fixture(); failed.workload.http_failures = 1;
  assert.throws(() => analyzeResponsePathAttribution(failed), /failed responses/u);
  const fatal = fixture(); fatal.socket_output.fatal_errors = 1;
  assert.throws(() => analyzeResponsePathAttribution(fatal), /fatal errors/u);
  const lost = fixture(); lost.socket_output.lost_events = 1;
  assert.throws(() => analyzeResponsePathAttribution(lost), /lost events/u);
});

test('socket and performance evidence must belong to the gateway process', () => {
  const socket = fixture(); socket.socket_output.start_ticks += 1;
  assert.throws(() => analyzeResponsePathAttribution(socket),
    /socket output process identity/u);
  const perf = fixture(); perf.performance.pid += 1;
  assert.throws(() => analyzeResponsePathAttribution(perf),
    /performance counter process identity/u);
});

test('every producer must cover the same diagnostic interval', () => {
  for (const mutate of [
    (value) => { value.workload.interval_id = 'other'; },
    (value) => { value.application_after.interval_id = 'other'; },
    (value) => { value.socket_output.duration_nanoseconds -= 1; },
    (value) => { value.performance.interval_id = 'other'; },
  ]) {
    const value = fixture(); mutate(value);
    assert.throws(() => analyzeResponsePathAttribution(value),
      /interval differs from capture/u);
  }
});

test('a stable pre-existing service restart count is accepted', () => {
  const capture = fixture();
  capture.process_before.restart_count = 3;
  capture.process_after.restart_count = 3;
  assert.equal(analyzeResponsePathAttribution(capture).successful_responses,
    1000);

  capture.process_after.restart_count = 4;
  assert.throws(() => analyzeResponsePathAttribution(capture),
    /replaced or restarted/u);
});

test('native inputs reconcile Prometheus, OHA, perf and runtime identity', () => {
  const expected = fixture();
  const manifest = runtimeManifest();
  const capture = buildNativeResponsePathCapture({
    run_id: 'perf03-native-test',
    point_id: 'http-16384-r1',
    source_commit: 'a'.repeat(40),
    configuration_sha256: 'd'.repeat(64),
    runtime_manifest: manifest,
    runtime_manifest_sha256: createHash('sha256').update(manifest).digest('hex'),
    tls: false,
    payload_bytes: 16384,
    interval_id: 'interval-1',
    duration_nanoseconds: 10_000_000_000,
    runtime_before: runtimeIdentity(),
    runtime_after: runtimeIdentity(),
    application_before_prometheus: prometheus(expected.application_before),
    application_after_prometheus: prometheus(expected.application_after),
    workload_oha: JSON.stringify({summary: {total: 10},
      statusCodeDistribution: {'200': 1000}, errorDistribution: {}}),
    socket_output: expected.socket_output,
    performance_csv: perfStat(),
  });
  const summary = analyzeResponsePathAttribution(capture);
  assert.equal(summary.successful_responses, 1000);
  assert.equal(summary.derived.application_writes_per_response, 3);
  assert.equal(summary.derived.socket_calls_per_response, 2);
  assert.equal(summary.derived.instructions_per_response, 120000);
});

test('Prometheus parser requires complete stable enabled shard series', () => {
  const expected = fixture().application_before;
  const valid = parseResponsePathMetrics(prometheus(expected, '{shard="0"}'),
    'interval-1');
  assert.equal(valid.snapshot.completed_responses, 10);
  assert.deepEqual(valid.series, ['{shard="0"}']);

  assert.throws(() => parseResponsePathMetrics(
    prometheus(expected).replace('response_path_diagnostics_enabled 1',
      'response_path_diagnostics_enabled 0'), 'interval-1'), /not enabled/u);
  assert.throws(() => parseResponsePathMetrics(
    prometheus(expected).replace(/^.*response_path_write_bytes_total.*\n/mu, ''),
    'interval-1'), /write_bytes_total is missing/u);
});

test('native workload and perf parsing reject failed or unsynchronized input', () => {
  const workload = workloadFromOha(JSON.stringify({summary: {total: 10},
    statusCodeDistribution: {'200': 100, '503': 1},
    errorDistribution: {Timeout: 2}}), 'interval-1', 10_000_000_000);
  assert.equal(workload.successful_responses, 100);
  assert.equal(workload.http_failures, 1);
  assert.equal(workload.transport_failures, 2);
  assert.throws(() => workloadFromOha(JSON.stringify({summary: {total: 20},
    statusCodeDistribution: {'200': 1}, errorDistribution: {}}),
  'interval-1', 10_000_000_000), /duration differs/u);

  const performance = performanceFromPerfStat(perfStat(), runtimeIdentity(),
    10_000_000_000);
  assert.equal(performance.cycles, 100_000_000);
  assert.equal(performance.instructions, 120_000_000);
  assert.throws(() => performanceFromPerfStat(
    '100,,cycles,\n80,,instructions,\n', runtimeIdentity(), 1),
  /missing or unexpected/u);
});

test('native capture rejects source-bound runtime and process drift', () => {
  const expected = fixture();
  const manifest = runtimeManifest();
  const input = {
    run_id: 'perf03-native-test', point_id: 'http-16384-r1',
    source_commit: 'a'.repeat(40), configuration_sha256: 'd'.repeat(64),
    runtime_manifest: manifest,
    runtime_manifest_sha256: createHash('sha256').update(manifest).digest('hex'),
    tls: false, payload_bytes: 16384, interval_id: 'interval-1',
    duration_nanoseconds: 10_000_000_000,
    runtime_before: runtimeIdentity(), runtime_after: runtimeIdentity(),
    application_before_prometheus: prometheus(expected.application_before),
    application_after_prometheus: prometheus(expected.application_after),
    workload_oha: JSON.stringify({summary: {total: 10},
      statusCodeDistribution: {'200': 1000}, errorDistribution: {}}),
    socket_output: expected.socket_output, performance_csv: perfStat(),
  };
  const wrongBinary = JSON.parse(JSON.stringify(input));
  wrongBinary.runtime_after.executable_sha256 = '9'.repeat(64);
  assert.throws(() => buildNativeResponsePathCapture(wrongBinary),
    /runtime identity changed/u);
  const wrongManifest = {...input, runtime_manifest_sha256: '0'.repeat(64)};
  assert.throws(() => buildNativeResponsePathCapture(wrongManifest),
    /manifest digest mismatch/u);
});

test('native evidence root assembles and replays from retained raw files', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-perf03-test-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  fs.mkdirSync(path.join(root, 'socket'));
  const expected = fixture();
  const identity = runtimeIdentity();
  const manifest = runtimeManifest();
  const files = {
    'source-commit.txt': `${'a'.repeat(40)}\n`,
    'source-status.txt': '',
    'configuration-sha256-before.txt': `${'d'.repeat(64)}\n`,
    'configuration-sha256-after.txt': `${'d'.repeat(64)}\n`,
    'runtime-manifest.json': manifest,
    'runtime-manifest-sha256.txt':
      `${createHash('sha256').update(manifest).digest('hex')}\n`,
    'runtime-before.json': `${JSON.stringify(identity)}\n`,
    'runtime-after.json': `${JSON.stringify(identity)}\n`,
    'thread-ids-before.txt': '100,101,102\n',
    'thread-ids-after.txt': '100,101,102\n',
    'application-before.prom': prometheus(expected.application_before),
    'application-after.prom': prometheus(expected.application_after),
    'perf.csv': perfStat(),
    'socket/source-commit.txt': `${'a'.repeat(40)}\n`,
    'socket/source-status.txt': '',
    'socket/source-status-after.txt': '',
    'socket/process-before.json': `${JSON.stringify(identity)}\n`,
    'socket/process-after.json': `${JSON.stringify(identity)}\n`,
    'socket/socket-output.json': `${JSON.stringify(expected.socket_output)}\n`,
    'socket/duration-nanoseconds.txt': '10000000000\n',
    'socket/client.stdout': JSON.stringify({summary: {total: 10},
      statusCodeDistribution: {'200': 1000}, errorDistribution: {}}),
  };
  for (const [relative, body] of Object.entries(files)) {
    fs.writeFileSync(path.join(root, relative), body);
  }
  const summary = assembleNativeResponsePathRoot(root, {
    run_id: 'perf03-native-root-test', point_id: 'http-16384-r1',
    tls: false, payload_bytes: 16384,
  });
  assert.equal(summary.decision, 'attribution-valid-not-capacity-qualification');
  assert.equal(JSON.parse(fs.readFileSync(path.join(root, 'capture.json')))
    .binary_sha256, 'b'.repeat(64));
  assert.match(fs.readFileSync(path.join(root, 'report.md'), 'utf8'),
    /Successful responses \| 1000/u);
});
