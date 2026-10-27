import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  assembleBackpressureStage,
  loadStageCapture,
  parsePrometheusSnapshot,
  supportCpuPercent,
} from './phase5-backpressure-assemble.mjs';
import {
  buildBackpressurePlan,
  COUNTER_METRICS,
  GAUGE_METRICS,
  HOST_COUNTERS,
  summarizeBackpressure,
} from './phase5-backpressure.mjs';

function fullName(name) {
  return name.startsWith('reactor_') || name.startsWith('scheduler_')
    ? `bonvoyage_${name}`
    : `bonvoyage_bonvoyage_gateway_${name}`;
}

function prometheus({counters = {}, gauges = {}} = {}) {
  const lines = [];
  for (const name of COUNTER_METRICS) {
    const group = name.startsWith('scheduler_') ? 'group="main",' : '';
    lines.push(`${fullName(name)}{${group}shard="0"} ${counters[name] ?? 0}`);
    if (group) lines.push(`${fullName(name)}{group="atexit",shard="0"} 0`);
  }
  for (const name of GAUGE_METRICS) {
    const group = name.startsWith('reactor_') || name.startsWith('scheduler_')
      ? 'group="main",' : '';
    const fallback = name === 'configured_upstream_http1_connections' ? 8
      : name === 'response_path_diagnostics_enabled' ? 1 : 0;
    lines.push(`${fullName(name)}{${group}shard="0"} ${gauges[name] ?? fallback}`);
    if (group) lines.push(`${fullName(name)}{group="atexit",shard="0"} 0`);
  }
  return `${lines.join('\n')}\n`;
}

function tscClock() {
  return {
    current_clocksource: 'tsc',
    available_clocksources: ['tsc', 'kvm-clock', 'hpet', 'acpi_pm'],
    tsc_capabilities: {tsc: true, rdtscp: true, constant_tsc: true,
      nonstop_tsc: true, tsc_known_freq: true},
  };
}

function fixture() {
  const plan = buildBackpressurePlan({
    coreCount: 1,
    rates: {steady: 10, near_knee: 20, intentional_overload: 40, recovery: 10},
    durations: {steady: 10, near_knee: 10, intentional_overload: 10, recovery: 10},
    latencyCeilings: {
      steady: {p95: 100, p99: 500},
      near_knee: {p95: 100, p99: 500},
      intentional_overload: {p95: 500, p99: 1000},
      recovery: {p95: 100, p99: 500},
    },
  });
  const environment = {
    schema_version: 1,
    run_id: 'perf04-assembler-test',
    evidence_class: 'local-virtualized-engineering',
    publication_authorized: false,
    source_commit: 'a'.repeat(40),
    source_dirty: false,
    gateway_binary_sha256: 'b'.repeat(64),
    snapshot_sha256: 'c'.repeat(64),
    configuration_sha256: 'd'.repeat(64),
    collector_sha256: 'e'.repeat(64),
    boot_id: 'boot-id',
    expected_shards: [0],
    support_roles: ['load_generator', 'controlled_upstream'],
    required_host_counters: [],
    required_zero_host_counters: [],
    unavailable_resource_metrics: ['host_cpu_percent', 'irq_cpu_percent'],
    response_path_diagnostics_enabled: true,
  };
  const process = {
    service: 'bonvoyage-perf04-gateway',
    pid: 123,
    start_ticks: 456,
    restart_count: 0,
    boot_id: environment.boot_id,
    rss_bytes: 40 * 1024 * 1024,
    file_descriptors: 20,
  };
  const captures = plan.points.map((point) => {
    const attempted = point.target_rps * point.duration_seconds;
    const overload = point.phase === 'intentional_overload';
    const rejected = overload ? 100 : 0;
    const successful = attempted - rejected;
    const counterDeltas = Object.fromEntries(COUNTER_METRICS.map((name) => [name, 0]));
    Object.assign(counterDeltas, {
      requests_total: attempted,
      responses_2xx_total: successful,
      responses_5xx_total: rejected,
      downstream_connections_accepted_total: 4,
      overload_rejections_total: rejected,
      route_overload_rejections_total: rejected,
      reactor_tasks_processed: attempted * 2,
      scheduler_waittime_ms: overload ? 100 : 10,
    });
    const traceGauges = {
      active_requests: overload ? 1 : 0,
      active_route_requests: overload ? 1 : 0,
      active_upstream_requests: overload ? 1 : 0,
      active_upstream_http1_requests: overload ? 1 : 0,
      reactor_tasks_pending: overload ? 3 : 1,
      scheduler_queue_length: overload ? 2 : 0,
      reactor_utilization: overload ? 0.98 : 0.60,
    };
    return {
      metadata: {
        schema_version: 1,
        plan_id: plan.plan_id,
        phase: point.phase,
        gateway_container: {name: 'gateway', capacity_cores: 1},
        support_containers: {
          load_generator: {name: 'loadgen', capacity_cores: 2},
          controlled_upstream: {name: 'upstream', capacity_cores: 2},
        },
        host_cpu_percent: null,
        irq_cpu_percent: null,
        host_counters: Object.fromEntries(HOST_COUNTERS.map((name) => [name, null])),
      },
      client: {
        summary: {total: point.duration_seconds},
        statusCodeDistribution: overload
          ? {'200': successful, '503': rejected} : {'200': successful},
        errorDistribution: {},
        latencyPercentiles: overload
          ? {p50: 0.01, p95: 0.2, p99: 0.4, 'p99.9': 0.6}
          : {p50: 0.001, p95: 0.005, p99: 0.01, 'p99.9': 0.02},
      },
      beforeMetrics: prometheus(),
      metricSamples: [prometheus({gauges: traceGauges})],
      afterMetrics: prometheus({counters: counterDeltas}),
      processBefore: process,
      processAfter: {...process, rss_bytes: process.rss_bytes + 1024,
        file_descriptors: 21},
      resourceSamples: [{rss_bytes: process.rss_bytes + 2048, file_descriptors: 22}],
      dockerStatsSamples: [
        {Name: 'gateway', CPUPerc: overload ? '98.00%' : '60.00%'},
        {Name: 'loadgen', CPUPerc: '40.00%'},
        {Name: 'upstream', CPUPerc: '50.00%'},
      ],
    };
  });
  return {plan, environment, captures};
}

function nativeFixture() {
  const input = fixture();
  input.environment.evidence_class = 'shared-aws-native-engineering';
  input.environment.required_host_counters = [...HOST_COUNTERS];
  input.environment.required_zero_host_counters = [...HOST_COUNTERS];
  input.environment.unavailable_resource_metrics = [];
  const queueCollector = 'f'.repeat(64);
  for (const [index, point] of input.plan.points.entries()) {
    const capture = input.captures[index];
    const workload = {
      request_mode: 'fixed-count',
      client_sha256: '1'.repeat(64),
      protocol: 'http1',
      tls: false,
      authority: 'api.example.test',
      listener_port: 8080,
      target_addresses: ['10.0.0.10'],
      path: '/circuit-http1/slow/20',
      connections_per_lane: point.phase === 'intentional_overload' ? 8 : 2,
      streams_per_connection: 1,
      requests_per_lane: point.target_rps * point.duration_seconds / 2,
      memory_limit_bytes: 4 * 1024 ** 3,
      ca_sha256: null,
      credential_sha256: null,
      method: 'GET',
      keepalive: true,
      compression: false,
      latency_correction: true,
      request_timeout_seconds: 5,
      connect_timeout_seconds: 5,
      redirect_limit: 0,
    };
    const workloadShape = {...workload};
    delete workloadShape.requests_per_lane;
    capture.metadata = {
      schema_version: 1,
      plan_id: input.plan.plan_id,
      phase: point.phase,
      resource_mode: 'native-linux',
      gateway_capacity_cores: 1,
      gateway_hostname: 'gateway-host',
      queue_collector_sha256: queueCollector,
      support_hosts: {
        load_generator: 'load-host',
        controlled_upstream: 'upstream-host',
      },
      client: {
        lanes: 2,
        rate_per_lane: point.target_rps / 2,
        requests_per_lane: workload.requests_per_lane,
        workload_shape: workloadShape,
      },
    };
    capture.client = {...capture.client, offered_rps: point.target_rps,
      rate_per_lane: point.target_rps / 2, client_lanes: 2,
      client_cpu_sets: ['0', '1'], active_measurement_seconds: point.duration_seconds,
      workload, clock: tscClock()};
    capture.dockerStatsSamples = [];
    capture.nativeSupport = {
      load_generator: {hostname: 'load-host',
        before: 'cpu 100 0 100 800 0 0 0 0\n',
        after: 'cpu 120 0 120 860 0 0 0 0\n'},
      controlled_upstream: {hostname: 'upstream-host',
        before: 'cpu 200 0 100 700 0 0 0 0\n',
        after: 'cpu 225 0 125 750 0 0 0 0\n'},
    };
    capture.nativeAttribution = {
      schema_version: 1,
      analyzer_sha256: queueCollector,
      capture_collector_sha256: queueCollector,
      hostname: 'gateway-host',
      duration_seconds: point.duration_seconds,
      process_identity_stable: true,
      source_unchanged: true,
      clock: tscClock(),
      process: {executable_sha256: input.environment.gateway_binary_sha256,
        boot_id: input.environment.boot_id},
      source: {commit: input.environment.source_commit, dirty: false},
      gateway: {reactor_cpu_busy_ms_by_shard: {'0': 6000}},
      host: {
        cpu_busy_ratio: {cpu0: 0.5, cpu1: 0.3},
        irq_cpu_busy_ratio: {cpu0: 0.02, cpu1: 0.01},
        softnet_deltas: [
          {cpu: 0, dropped: 0, time_squeeze: 0},
          {cpu: 1, dropped: 0, time_squeeze: 0},
        ],
        ethtool_deltas: {
          bw_in_allowance_exceeded: 0,
          bw_out_allowance_exceeded: 0,
          queue_0_tx_queue_stop: 0,
        },
      },
    };
  }
  return input;
}

test('Prometheus parser selects the main scheduler group', () => {
  const parsed = parsePrometheusSnapshot(prometheus({
    counters: {scheduler_waittime_ms: 42},
  }));
  assert.deepEqual(parsed.scheduler_waittime_ms, {'0': 42});
  assert.deepEqual(parsed.requests_total, {'0': 0});
});

test('assembler converts live-format captures into a passing four-stage result', () => {
  const input = fixture();
  const results = input.plan.points.map((point, index) => assembleBackpressureStage({
    plan: input.plan,
    environment: input.environment,
    point,
    capture: input.captures[index],
  }));
  const summary = summarizeBackpressure({...input, results});
  assert.equal(summary.decision, 'queueing-backpressure-pass');
  assert.equal(summary.points[2].status_counts['503'], 100);
  assert.equal(summary.points[0].resources.host_cpu_percent, null);
  assert.equal(summary.points[0].support_capacity_percent.load_generator, 20);
});

test('missing metric and process drift fail closed during assembly', () => {
  const missing = fixture();
  missing.captures[0].beforeMetrics = missing.captures[0].beforeMetrics
    .replace(/^bonvoyage_bonvoyage_gateway_requests_total.*\n/mu, '');
  assert.throws(() => assembleBackpressureStage({
    plan: missing.plan,
    environment: missing.environment,
    point: missing.plan.points[0],
    capture: missing.captures[0],
  }), /missing requests_total/u);

  const drift = fixture();
  drift.captures[0].processAfter.pid += 1;
  assert.throws(() => assembleBackpressureStage({
    plan: drift.plan,
    environment: drift.environment,
    point: drift.plan.points[0],
    capture: drift.captures[0],
  }), /process identity changed: pid/u);
});

test('support-role CPU evidence cannot be omitted', () => {
  const input = fixture();
  input.captures[0].dockerStatsSamples = input.captures[0].dockerStatsSamples
    .filter((sample) => sample.Name !== 'loadgen');
  assert.throws(() => assembleBackpressureStage({
    plan: input.plan,
    environment: input.environment,
    point: input.plan.points[0],
    capture: input.captures[0],
  }), /no Docker CPU samples for load_generator/u);
});

test('stage loader accepts one pretty-printed resource document per file', (context) => {
  const input = fixture();
  const capture = input.captures[0];
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'perf04-stage-loader-'));
  context.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  fs.mkdirSync(path.join(directory, 'metrics'));
  fs.mkdirSync(path.join(directory, 'resources'));
  fs.mkdirSync(path.join(directory, 'docker-stats'));
  fs.writeFileSync(path.join(directory, 'metadata.json'),
    `${JSON.stringify(capture.metadata, null, 2)}\n`);
  fs.writeFileSync(path.join(directory, 'client.oha.json'),
    `${JSON.stringify(capture.client, null, 2)}\n`);
  fs.writeFileSync(path.join(directory, 'before.metrics.prom'), capture.beforeMetrics);
  fs.writeFileSync(path.join(directory, 'metrics', '0001.prom'), capture.metricSamples[0]);
  fs.writeFileSync(path.join(directory, 'after.metrics.prom'), capture.afterMetrics);
  fs.writeFileSync(path.join(directory, 'process-before.json'),
    `${JSON.stringify(capture.processBefore, null, 2)}\n`);
  fs.writeFileSync(path.join(directory, 'process-after.json'),
    `${JSON.stringify(capture.processAfter, null, 2)}\n`);
  fs.writeFileSync(path.join(directory, 'resources', '0001.json'),
    `${JSON.stringify(capture.resourceSamples[0], null, 2)}\n`);
  fs.writeFileSync(path.join(directory, 'docker-stats', '0001.jsonl'),
    `${capture.dockerStatsSamples.map((value) => JSON.stringify(value)).join('\n')}\n`);

  const loaded = loadStageCapture(directory);
  assert.deepEqual(loaded.resourceSamples, capture.resourceSamples);
  assert.deepEqual(loaded.dockerStatsSamples, capture.dockerStatsSamples);
});

test('native Linux assembly derives host, IRQ, support and per-shard CPU from raw evidence', () => {
  const input = nativeFixture();
  const results = input.plan.points.map((point, index) => assembleBackpressureStage({
    plan: input.plan,
    environment: input.environment,
    point,
    capture: input.captures[index],
  }));
  const summary = summarizeBackpressure({...input, results});
  assert.equal(summary.decision, 'queueing-backpressure-pass');
  assert.equal(summary.points[0].resources.gateway_application_cpu_percent, 60);
  assert.equal(summary.points[0].resources.gateway_capacity_percent, 60);
  assert.equal(summary.points[0].resources.host_cpu_percent, 40);
  assert.equal(summary.points[0].resources.irq_cpu_percent, 1.5);
  assert.equal(summary.points[0].support_capacity_percent.load_generator, 40);
  assert.equal(summary.points[0].measurement_seconds, 10);
  assert.equal(summary.points[0].client_process_envelope_seconds, 10);
  assert.deepEqual(summary.points[0].host_counters,
    Object.fromEntries(HOST_COUNTERS.map((name) => [name, 0])));
});

test('native Linux assembly requires bounded active client timing', () => {
  const missing = nativeFixture();
  delete missing.captures[0].client.active_measurement_seconds;
  assert.throws(() => assembleBackpressureStage({
    plan: missing.plan,
    environment: missing.environment,
    point: missing.plan.points[0],
    capture: missing.captures[0],
  }), /active client duration/u);

  const drift = nativeFixture();
  drift.captures[0].client.summary.total = 11;
  drift.captures[0].nativeAttribution.duration_seconds = 11;
  assert.throws(() => assembleBackpressureStage({
    plan: drift.plan,
    environment: drift.environment,
    point: drift.plan.points[0],
    capture: drift.captures[0],
  }), /active client duration disagrees/u);
});

test('native Linux assembly requires invariant TSC kernel timing', () => {
  const source = nativeFixture();
  source.captures[0].nativeAttribution.clock.current_clocksource = 'kvm-clock';
  assert.throws(() => assembleBackpressureStage({
    plan: source.plan,
    environment: source.environment,
    point: source.plan.points[0],
    capture: source.captures[0],
  }), /kernel clocksource is not TSC/u);

  const capability = nativeFixture();
  capability.captures[0].nativeAttribution.clock.tsc_capabilities.nonstop_tsc = false;
  assert.throws(() => assembleBackpressureStage({
    plan: capability.plan,
    environment: capability.environment,
    point: capability.plan.points[0],
    capture: capability.captures[0],
  }), /TSC capability is missing: nonstop_tsc/u);
});

test('native Linux assembly rejects client-shape and support-host drift', () => {
  const client = nativeFixture();
  client.captures[0].client.workload.path = '/different';
  assert.throws(() => assembleBackpressureStage({
    plan: client.plan,
    environment: client.environment,
    point: client.plan.points[0],
    capture: client.captures[0],
  }), /client workload drifted/u);

  const support = nativeFixture();
  support.captures[0].nativeSupport.load_generator.hostname = 'other-host';
  assert.throws(() => assembleBackpressureStage({
    plan: support.plan,
    environment: support.environment,
    point: support.plan.points[0],
    capture: support.captures[0],
  }), /host identity drifted/u);
});

test('support CPU calculation fails closed on regressed or empty counters', () => {
  assert.equal(supportCpuPercent(
    'cpu 100 0 100 800 0 0 0 0\n',
    'cpu 120 0 120 860 0 0 0 0\n'), 40);
  assert.throws(() => supportCpuPercent(
    'cpu 100 0 100 800 0 0 0 0\n',
    'cpu 99 0 120 860 0 0 0 0\n'), /regressed/u);
  assert.throws(() => supportCpuPercent(
    'cpu 100 0 100 800 0 0 0 0\n',
    'cpu 100 0 100 800 0 0 0 0\n'), /interval is empty/u);
});

test('native stage loader verifies queue-capture checksums', (context) => {
  const input = nativeFixture();
  const capture = input.captures[0];
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'perf04-native-loader-'));
  context.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  for (const name of ['before', 'after', 'metrics', 'resources',
    'support/load_generator', 'support/controlled_upstream']) {
    fs.mkdirSync(path.join(directory, name), {recursive: true});
  }
  const writeQueue = (name, process) => {
    const root = path.join(directory, name);
    const files = {
      'metrics.prom': name === 'before' ? capture.beforeMetrics : capture.afterMetrics,
      'snapshot.json': `${JSON.stringify({process: {
        service: process.service,
        pid: process.pid,
        start_ticks: process.start_ticks,
        restarts: process.restart_count,
        boot_id: process.boot_id,
        executable_sha256: input.environment.gateway_binary_sha256,
        rss_kib: process.rss_bytes / 1024,
        fd_count: process.file_descriptors,
      }}, null, 2)}\n`,
    };
    const records = [];
    for (const [filename, contents] of Object.entries(files)) {
      const bytes = Buffer.from(contents);
      fs.writeFileSync(path.join(root, filename), bytes);
      records.push({path: filename, bytes: bytes.length,
        sha256: crypto.createHash('sha256').update(bytes).digest('hex')});
    }
    fs.writeFileSync(path.join(root, 'checksums.json'),
      `${JSON.stringify({schema_version: 1, files: records}, null, 2)}\n`);
  };
  writeQueue('before', capture.processBefore);
  writeQueue('after', capture.processAfter);
  fs.writeFileSync(path.join(directory, 'metadata.json'),
    `${JSON.stringify(capture.metadata, null, 2)}\n`);
  const laneReport = (responses) => JSON.stringify({
    summary: {total: 10},
    statusCodeDistribution: {'200': responses},
    errorDistribution: {},
    latencyPercentiles: {p50: 0.001, p95: 0.005, p99: 0.01, 'p99.9': 0.02},
  });
  fs.writeFileSync(path.join(directory, 'client.oha.json'), JSON.stringify({
    kind: 'phase5-oha-lanes',
    schema_version: 2,
    rate_per_lane: capture.metadata.client.rate_per_lane,
    cpu_sets: ['0', '1'],
    workload: capture.client.workload,
    lanes: [0, 1].map((index) => ({index, start_ns: '0',
      end_ns: '10000000000', exit_code: 0,
      raw_json: laneReport(capture.metadata.client.requests_per_lane), stderr: '',
      target_address: '10.0.0.10'})),
  }));
  fs.writeFileSync(path.join(directory, 'metrics', '0001.prom'),
    capture.metricSamples[0]);
  fs.writeFileSync(path.join(directory, 'resources', '0001.json'),
    `${JSON.stringify(capture.resourceSamples[0])}\n`);
  fs.writeFileSync(path.join(directory, 'attribution.json'),
    `${JSON.stringify(capture.nativeAttribution, null, 2)}\n`);
  for (const [role, item] of Object.entries(capture.nativeSupport)) {
    const root = path.join(directory, 'support', role);
    fs.writeFileSync(path.join(root, 'hostname.txt'), `${item.hostname}\n`);
    fs.writeFileSync(path.join(root, 'before.proc-stat'), item.before);
    fs.writeFileSync(path.join(root, 'after.proc-stat'), item.after);
  }

  const loaded = loadStageCapture(directory);
  assert.equal(loaded.client.offered_rps, 10);
  assert.equal(loaded.processBefore.rss_bytes, capture.processBefore.rss_bytes);
  fs.appendFileSync(path.join(directory, 'before', 'metrics.prom'), '# changed\n');
  assert.throws(() => loadStageCapture(directory), /queue capture changed/u);
});
