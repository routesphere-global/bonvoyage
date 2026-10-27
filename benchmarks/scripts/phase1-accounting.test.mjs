import assert from 'node:assert/strict';
import {execFileSync, spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const accountingFilter = path.join(scriptDirectory, 'phase1-accounting.jq');
const runner = fs.readFileSync(path.join(scriptDirectory, 'run-phase1-scaling.sh'), 'utf8');
const readJson = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const retained = {
  summary: {successRate: 1, total: 30, requestsPerSec: 30},
  statusCodeDistribution: {200: 900},
  errorDistribution: {'aborted due to deadline': 64},
};
const syntheticUpstreamRps = 4000;

function account(raw, concurrency = 64, expectedDuration = 30) {
  return JSON.parse(execFileSync('jq', ['--argjson', 'concurrency', String(concurrency),
    '--argjson', 'expected_duration', String(expectedDuration), '-f', accountingFilter],
  {input: JSON.stringify(raw), encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe']}));
}

function temporaryDirectory(run) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'phase1-accounting-'));
  try { return run(directory); } finally { fs.rmSync(directory, {recursive: true, force: true}); }
}

function rawWith(statuses, errors = {}, duration = 30) {
  return {...structuredClone(retained), summary: {...retained.summary, total: duration},
    statusCodeDistribution: statuses, errorDistribution: errors};
}

// Run the production shell's accounting/metric wiring and aggregation, without
// Docker or resource sampling. All generated files live in a disposable directory.
function runnerMetrics(raw, concurrency = 64) {
  return temporaryDirectory((directory) => {
    const rawPath = path.join(directory, 'measurement.oha.json');
    const accountingPath = path.join(directory, 'measurement.accounting.json');
    fs.writeFileSync(rawPath, JSON.stringify(raw));
    const accountingStart = runner.indexOf('  jq --argjson concurrency "$measurement_concurrency"');
    const accountingEnd = runner.indexOf('\n\n', accountingStart);
    const metricsStart = runner.indexOf('  successful_rps="');
    const metricsEnd = runner.indexOf('\n  p50_ms=', metricsStart);
    assert.ok(accountingStart > 0 && accountingEnd > accountingStart && metricsEnd > metricsStart);
    const code = `${runner.slice(accountingStart, accountingEnd)}\n` +
      `${runner.slice(metricsStart, metricsEnd)}\n` +
      'jq -n --argjson rps "$successful_rps" --argjson errors "$error_rate" ' +
      "'{successful_rps: $rps, error_rate: $errors}'";
    return JSON.parse(execFileSync('sh', ['-eu', '-c', code], {encoding: 'utf8',
      env: {...process.env, script_dir: scriptDirectory, measurement_raw: rawPath,
        measurement_accounting: accountingPath, measurement_seconds: '30',
        measurement_concurrency: String(concurrency)}}));
  });
}

function upstreamPreflight(raw) {
  return temporaryDirectory((directory) => {
    fs.writeFileSync(path.join(directory, 'upstream-capacity.oha.json'), JSON.stringify(raw));
    const start = runner.indexOf('jq --argjson concurrency "$two_concurrency"');
    const end = runner.indexOf('\ndocker_os=', start);
    assert.ok(start > 0 && end > start);
    const code = 'fail() { echo "$*" >&2; exit 1; }\n' + runner.slice(start, end) +
      '\nprintf "%s" "$upstream_capacity_rps"';
    return Number(execFileSync('sh', ['-eu', '-c', code], {encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'], env: {...process.env, raw_dir: directory,
        script_dir: scriptDirectory, two_concurrency: '64', upstream_capacity_seconds: '30'}}));
  });
}

function runnerSummary(metrics, upstreamRps = syntheticUpstreamRps) {
  return temporaryDirectory((directory) => {
    const roles = [];
    for (let index = 0; index < 10; index += 1) {
      const cores = index < 5 ? 1 : 2;
      const repetition = index % 5 + 1;
      const name = `bonvoyage-${cores}core-rep${repetition}.result.json`;
      const result = {
        schema_version: 1,
        fixture: true,
        run_id: 'accounting-regression',
        workload_id: 'http1-keepalive-phase1-scaling',
        environment_sha256: '0'.repeat(64),
        product: {name: 'bonvoyage'},
        execution: {gateway_cores: cores, repetition},
        metrics: {
          successful_rps: cores * 100,
          error_rate: 0,
          latency_ms: {p50: 0.5, p95: 1, p99: 1.5, p999: 2},
          gateway_cpu_percent: cores * 45,
          gateway_rss_bytes: 16 * 1024 * 1024,
          connections: cores * 64,
        },
      };
      result.metrics = {...result.metrics, ...metrics[index % metrics.length]};
      fs.writeFileSync(path.join(directory, name), JSON.stringify(result));
      roles.push({gateway_cores: cores, repetition,
        upstream_cpu_percent: 25, upstream_capacity_percent: 25,
        load_generator_cpu_percent: 25, load_generator_capacity_percent: 25});
    }
    fs.writeFileSync(path.join(directory, 'role-utilization.json'), JSON.stringify(roles));
    const start = runner.indexOf('summary_path="$raw_dir/summary.json"');
    const end = runner.indexOf('\none_rps=', start);
    assert.ok(start > 0 && end > start);
    const env = {...process.env, raw_dir: directory, run_id: 'accounting-regression',
      workload_id: 'http1-keepalive-phase1-scaling', evidence_class: 'local-functional',
      publication_reason: 'test', environment_sha256: '0'.repeat(64),
      dataplane_executable_sha256: '0'.repeat(64), publication_authorized: 'false',
      latency_ceiling_ms: '4', minimum_scaling_ratio: '1.8', maximum_error_rate: '0.001',
      maximum_variation_percent: '5', minimum_headroom_ratio: '1.2',
      maximum_support_role_capacity_percent: '80', upstream_capacity_rps: String(upstreamRps)};
    execFileSync('sh', ['-eu', '-c', runner.slice(start, end)], {env});
    return readJson(path.join(directory, 'summary.json'));
  });
}

test('review trigger: correct payload preflight cannot mask all-503 measurement traffic', () => {
  assert.ok(account(retained).successful_rps > 0);
  const failed = structuredClone(retained);
  failed.statusCodeDistribution = {503: retained.statusCodeDistribution['200']};
  assert.ok(failed.summary.requestsPerSec * failed.summary.successRate > 0);
  const counts = account(failed);
  assert.equal(counts.http_failures, 900);
  assert.equal(counts.transport_failures, 0);
  assert.equal(counts.deadline_end_cancellations, 64);
  const metrics = runnerMetrics(failed);
  assert.deepEqual(metrics, {successful_rps: 0, error_rate: 1});
  const summary = runnerSummary([metrics]);
  assert.equal(summary.one_core.median_successful_rps, 0);
  assert.equal(summary.two_core.median_successful_rps, 0);
  for (const gate of ['errors_pass', 'scaling_pass', 'repeatability_pass',
    'upstream_headroom_pass', 'local_qualification_pass', 'phase1_exit_pass']) {
    assert.equal(summary.gates[gate], false, gate);
  }
});

test('a partial deployment without the accounting helper fails before starting containers', () => {
  temporaryDirectory((directory) => {
    const scripts = path.join(directory, 'benchmarks', 'scripts');
    fs.mkdirSync(scripts, {recursive: true});
    const script = path.join(scripts, 'run-phase1-scaling.sh');
    fs.writeFileSync(script, runner);
    const response = spawnSync('sh', [script], {encoding: 'utf8'});
    assert.notEqual(response.status, 0);
    assert.match(response.stderr, /missing phase1-accounting.jq; deploy the complete/);
  });
});

test('mixed responses separate accepted HTTP 200, HTTP failures, transport failures and cutoff', () => {
  const raw = rawWith({200: 800, 201: 40, 302: 30, 503: 30}, {
    'connection reset': 40, 'request timeout': 60, 'aborted due to deadline': 64,
  });
  const counts = account(raw);
  assert.equal(counts.successful_rps, 800 / 30);
  assert.equal(counts.completed_http_responses, 900);
  assert.equal(counts.accepted_http_responses, 800);
  assert.equal(counts.http_failures, 100);
  assert.equal(counts.transport_failures, 100);
  assert.equal(counts.deadline_end_cancellations, 64);
  assert.equal(counts.measured_requests, 1000);
  assert.equal(counts.total_attempts, 1064);
  assert.equal(counts.error_rate, 0.2);
  const metrics = runnerMetrics(raw);
  assert.equal(metrics.error_rate, 0.2);
  assert.equal(runnerSummary([metrics]).gates.errors_pass, false);
});

test('direct-upstream preflight uses the same accepted-count accounting', () => {
  assert.equal(upstreamPreflight(retained), account(retained).successful_rps);
  for (const raw of [rawWith({503: 1000}), rawWith({200: 999, 503: 1}),
    rawWith({200: 1000}, {timeout: 1})]) {
    assert.throws(() => upstreamPreflight(raw), /direct upstream capacity preflight failed/);
  }
});

test('only exact bounded deadline-end cancellations are excluded from the error denominator', () => {
  const raw = rawWith({200: 300}, {'aborted due to deadline': 64, 'deadline exceeded': 5});
  const counts = account(raw);
  assert.equal(counts.error_rate, 5 / 305);
  assert.equal(counts.transport_failures, 5);
  assert.equal(counts.deadline_end_cancellations, 64);
  assert.throws(() => account(rawWith({200: 300}, {'aborted due to deadline': 65})),
    /deadline-end cancellations exceed/);
});

test('empty, all-transport-failure and cutoff-only runs cannot pass measured errors', () => {
  for (const errors of [{}, {'connection refused': 100}, {'aborted due to deadline': 64}]) {
    const metrics = runnerMetrics(rawWith({}, errors));
    assert.deepEqual(metrics, {successful_rps: 0, error_rate: 1});
    assert.equal(runnerSummary([metrics]).gates.local_qualification_pass, false);
  }
});

test('an outage in only one core profile fails without division by zero', () => {
  const metrics = Array.from({length: 10}, (_, index) => index < 5
    ? {successful_rps: 0, error_rate: 1} : {successful_rps: 50000, error_rate: 0});
  for (const inputs of [metrics, [...metrics].reverse()]) {
    const summary = runnerSummary(inputs);
    assert.equal(summary.gates.scaling_pass, false);
    assert.equal(summary.gates.repeatability_pass, false);
    assert.equal(summary.gates.local_qualification_pass, false);
  }
});

test('summary uses measured elapsed time, not requested duration or aggregate oha RPS', () => {
  const raw = rawWith({200: 600}, {}, 31);
  raw.summary.requestsPerSec = 1e9;
  raw.summary.successRate = 0;
  assert.equal(account(raw).successful_rps, 600 / 31);
  assert.equal(account(raw).error_rate, 0);
});

const invalidInputs = {
  'missing duration': (raw) => { delete raw.summary.total; },
  'zero duration': (raw) => { raw.summary.total = 0; },
  'negative duration': (raw) => { raw.summary.total = -1; },
  'truncated measurement': (raw) => { raw.summary.total = 29; },
  'string duration': (raw) => { raw.summary.total = '30'; },
  'missing statuses': (raw) => { delete raw.statusCodeDistribution; },
  'missing errors': (raw) => { delete raw.errorDistribution; },
  'array statuses': (raw) => { raw.statusCodeDistribution = [300]; },
  'negative count': (raw) => { raw.statusCodeDistribution['200'] = -1; },
  'fractional count': (raw) => { raw.statusCodeDistribution['200'] = 1.5; },
  'string count': (raw) => { raw.statusCodeDistribution['200'] = '300'; },
  'negative error': (raw) => { raw.errorDistribution.timeout = -1; },
  'null cancellation': (raw) => { raw.errorDistribution['aborted due to deadline'] = null; },
  'bad status': (raw) => { raw.statusCodeDistribution.OK = 300; },
  'unsafe total': (raw) => { raw.statusCodeDistribution = {200: 9007199254740991, 503: 1}; },
};
for (const [name, mutate] of Object.entries(invalidInputs)) {
  test(`invalid counters fail closed: ${name}`, () => {
    const raw = structuredClone(retained);
    mutate(raw);
    assert.throws(() => account(raw), /invalid|exact integer range/);
  });
}

test('non-finite duration and invalid run bounds fail closed', () => {
  const response = spawnSync('jq', ['--argjson', 'concurrency', '64', '--argjson',
    'expected_duration', '30', '-f', accountingFilter], {encoding: 'utf8',
    input: JSON.stringify(retained).replace(String(retained.summary.total), '1e999')});
  assert.notEqual(response.status, 0);
  for (const concurrency of [0, -1, 1.5]) assert.throws(() => account(retained, concurrency));
  for (const duration of [0, -1]) assert.throws(() => account(retained, 64, duration));
});
