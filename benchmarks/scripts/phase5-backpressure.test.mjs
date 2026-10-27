import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildBackpressurePlan,
  COUNTER_METRICS,
  GAUGE_METRICS,
  HOST_COUNTERS,
  RECOVERY_BASELINE_GAUGES,
  summarizeBackpressure,
} from './phase5-backpressure.mjs';

function split(total) {
  return {'0': Math.floor(total / 2), '1': total - Math.floor(total / 2)};
}

function gauge(mean = 0, peak = 0, final = 0) {
  return {
    '0': {mean, peak, final},
    '1': {mean, peak, final},
  };
}

function fixture() {
  const plan = buildBackpressurePlan({
    coreCount: 2,
    rates: {steady: 100, near_knee: 180, intentional_overload: 250, recovery: 100},
    durations: {steady: 10, near_knee: 10, intentional_overload: 10, recovery: 10},
    latencyCeilings: {
      steady: {p95: 50, p99: 500},
      near_knee: {p95: 50, p99: 500},
      intentional_overload: {p95: 500, p99: 1000},
      recovery: {p95: 50, p99: 500},
    },
  });
  const environment = {
    schema_version: 1,
    run_id: 'perf04-test',
    evidence_class: 'local-contract-fixture',
    publication_authorized: false,
    source_commit: 'a'.repeat(40),
    source_dirty: false,
    gateway_binary_sha256: 'b'.repeat(64),
    snapshot_sha256: 'c'.repeat(64),
    configuration_sha256: 'd'.repeat(64),
    collector_sha256: 'e'.repeat(64),
    boot_id: 'boot-id',
    expected_shards: [0, 1],
    support_roles: ['load_generator', 'upstream_a'],
    required_host_counters: [
      'softnet_dropped',
      'ena_allowance_exceeded',
      'ena_queue_stops',
    ],
    required_zero_host_counters: [
      'softnet_dropped',
      'ena_allowance_exceeded',
      'ena_queue_stops',
    ],
    response_path_diagnostics_enabled: true,
  };
  const identity = {
    source_commit: environment.source_commit,
    gateway_binary_sha256: environment.gateway_binary_sha256,
    snapshot_sha256: environment.snapshot_sha256,
    configuration_sha256: environment.configuration_sha256,
    collector_sha256: environment.collector_sha256,
    boot_id: environment.boot_id,
  };
  const process = {service: 'bonvoyage.service', pid: 123, start_ticks: 456,
    restart_count: 0};
  const results = plan.points.map((point) => {
    const attempted = point.target_rps * point.duration_seconds;
    const overload = point.phase === 'intentional_overload';
    const rejected = overload ? 1000 : 0;
    const successful = attempted - rejected;
    const counters = Object.fromEntries(COUNTER_METRICS.map((name) => [name, split(0)]));
    counters.requests_total = split(attempted);
    counters.downstream_connections_accepted_total = split(100);
    counters.responses_2xx_total = split(successful);
    counters.responses_5xx_total = split(rejected);
    counters.overload_rejections_total = split(rejected);
    counters.route_overload_rejections_total = split(rejected);
    counters.reactor_tasks_processed = split(attempted * 2);
    counters.scheduler_waittime_ms = split(overload ? 100 : 10);
    const gauges = Object.fromEntries(GAUGE_METRICS.map((name) => [name, gauge()]));
    gauges.active_requests = gauge(overload ? 12 : 3, overload ? 20 : 5, 0);
    gauges.active_route_requests = gauge(overload ? 8 : 2, overload ? 16 : 4, 0);
    gauges.active_upstream_requests = gauge(overload ? 8 : 2, overload ? 16 : 4, 0);
    gauges.active_upstream_http1_requests = gauge(overload ? 8 : 2,
      overload ? 16 : 4, 0);
    gauges.reactor_tasks_pending = gauge(overload ? 4 : 1, overload ? 8 : 2, 0);
    gauges.scheduler_queue_length = gauge(overload ? 4 : 1, overload ? 8 : 2, 0);
    gauges.reactor_utilization = gauge(overload ? 0.98 : 0.70,
      overload ? 1 : 0.80, 0.50);
    gauges.configured_upstream_http1_connections = gauge(4096, 4096, 4096);
    gauges.response_path_diagnostics_enabled = gauge(1, 1, 1);
    const rssBefore = 100 * 1024 * 1024;
    const rssAfter = point.phase === 'recovery' ? rssBefore + 1024 * 1024 : rssBefore;
    const fdAfter = point.phase === 'recovery' ? 101 : 100;
    return {
      schema_version: 1,
      plan_id: plan.plan_id,
      order: point.order,
      phase: point.phase,
      target_rps: point.target_rps,
      measurement_seconds: point.duration_seconds,
      attempted_requests: attempted,
      status_counts: overload ? {'200': successful, '503': rejected} : {'200': successful},
      transport_failures: 0,
      latency_ms: overload
        ? {p50: 20, p95: 200, p99: 400, p999: 600}
        : {p50: 1, p95: 5, p99: 10, p999: 20},
      identities: identity,
      process,
      counters_by_shard: counters,
      gauges_by_shard: gauges,
      support_capacity_percent: {load_generator: 40, upstream_a: 45},
      resources: {
        gateway_application_cpu_percent: overload ? 195 : 140,
        gateway_capacity_percent: overload ? 97.5 : 70,
        host_cpu_percent: overload ? 80 : 60,
        irq_cpu_percent: 5,
        rss_bytes: {before: rssBefore, peak: rssAfter + 1024, after: rssAfter},
        file_descriptors: {before: 100, peak: fdAfter + 1, after: fdAfter},
      },
      host_counters: Object.fromEntries(HOST_COUNTERS.map((name) =>
        [name, name === 'softnet_time_squeeze' ? null : 0])),
    };
  });
  return {plan, environment, results};
}

test('plan is deterministic and freezes the four semantic phases', () => {
  const first = fixture().plan;
  const second = fixture().plan;
  assert.deepEqual(first, second);
  assert.deepEqual(first.points.map((point) => point.phase),
    ['steady', 'near_knee', 'intentional_overload', 'recovery']);
});

test('complete bounded overload and recovery evidence passes', () => {
  const summary = summarizeBackpressure(fixture());
  assert.equal(summary.decision, 'queueing-backpressure-pass');
  assert.equal(summary.publication_authorized, false);
  assert.equal(summary.points[2].successful_rps, 150);
  assert.equal(summary.points[2].error_rate, 0.4);
  assert.equal(summary.recovery.successful_rps_ratio, 1);
  assert.ok(Object.values(summary.gates).every(Boolean));
});

test('missing and duplicate phases fail closed', () => {
  const missing = fixture();
  missing.results.pop();
  assert.throws(() => summarizeBackpressure(missing), /expected 4 results/u);
  const duplicate = fixture();
  duplicate.results[3].phase = 'steady';
  assert.throws(() => summarizeBackpressure(duplicate), /duplicate result phase/u);
  const reordered = fixture();
  [reordered.results[0], reordered.results[1]] = [reordered.results[1], reordered.results[0]];
  assert.throws(() => summarizeBackpressure(reordered), /result order 1/u);
});

test('source, artifact and process drift fail closed', () => {
  const source = fixture();
  source.results[1].identities = {...source.results[1].identities,
    source_commit: 'f'.repeat(40)};
  assert.throws(() => summarizeBackpressure(source), /artifact or source identity drift/u);

  const process = fixture();
  process.results[2].process = {...process.results[2].process, pid: 124};
  assert.throws(() => summarizeBackpressure(process), /process identity changed/u);

  const restart = fixture();
  restart.results[2].process = {...restart.results[2].process, restart_count: 1};
  assert.throws(() => summarizeBackpressure(restart), /gateway restart observed/u);
});

test('client, response-class and gateway request accounting fail closed', () => {
  const client = fixture();
  client.results[0].attempted_requests += 1;
  assert.throws(() => summarizeBackpressure(client), /client accounting mismatch/u);

  const response = fixture();
  response.results[0].counters_by_shard.responses_2xx_total['0'] -= 1;
  assert.throws(() => summarizeBackpressure(response), /responses_2xx_total/u);

  const gateway = fixture();
  gateway.results[0].counters_by_shard.requests_total['0'] -= 1;
  assert.throws(() => summarizeBackpressure(gateway), /request\/client response mismatch/u);
});

test('support saturation and missing required host counters fail closed', () => {
  const support = fixture();
  support.results[0].support_capacity_percent.upstream_a = 81;
  assert.throws(() => summarizeBackpressure(support), /support role saturated/u);

  const host = fixture();
  host.results[0].host_counters.ena_queue_stops = null;
  assert.throws(() => summarizeBackpressure(host), /required host counter missing/u);
});

test('explicitly unavailable local host CPU signals remain null', () => {
  const local = fixture();
  local.environment.unavailable_resource_metrics = [
    'host_cpu_percent',
    'irq_cpu_percent',
  ];
  for (const result of local.results) {
    result.resources.host_cpu_percent = null;
    result.resources.irq_cpu_percent = null;
  }
  const summary = summarizeBackpressure(local);
  assert.equal(summary.decision, 'queueing-backpressure-pass');
  assert.equal(summary.points[0].resources.host_cpu_percent, null);

  const undeclared = fixture();
  undeclared.results[0].resources.host_cpu_percent = null;
  assert.throws(() => summarizeBackpressure(undeclared), /host CPU/u);

  const falselyMeasured = fixture();
  falselyMeasured.environment.unavailable_resource_metrics = ['host_cpu_percent'];
  assert.throws(() => summarizeBackpressure(falselyMeasured),
    /host CPU must be null/u);
});

test('pre-overload errors remain visible as a failed gate', () => {
  const input = fixture();
  const point = input.results[1];
  point.status_counts = {'200': 1790, '503': 10};
  point.counters_by_shard.responses_2xx_total = split(1790);
  point.counters_by_shard.responses_5xx_total = split(10);
  point.counters_by_shard.overload_rejections_total = split(10);
  point.counters_by_shard.route_overload_rejections_total = split(10);
  const summary = summarizeBackpressure(input);
  assert.equal(summary.gates.pre_overload_error_budget_pass, false);
  assert.equal(summary.decision, 'investigate');
});

test('overload must be fail-fast and remain inside its tail ceiling', () => {
  const noSignal = fixture();
  noSignal.results[2].status_counts = {'200': 2500};
  noSignal.results[2].counters_by_shard.responses_2xx_total = split(2500);
  noSignal.results[2].counters_by_shard.responses_5xx_total = split(0);
  noSignal.results[2].counters_by_shard.overload_rejections_total = split(0);
  noSignal.results[2].counters_by_shard.route_overload_rejections_total = split(0);
  let summary = summarizeBackpressure(noSignal);
  assert.equal(summary.gates.overload_fail_fast_pass, false);
  assert.equal(summary.decision, 'investigate');

  const tail = fixture();
  tail.results[2].latency_ms = {p50: 20, p95: 600, p99: 1200, p999: 1500};
  summary = summarizeBackpressure(tail);
  assert.equal(summary.gates.overload_tail_bounded_pass, false);
  assert.equal(summary.decision, 'investigate');
});

test('recovery requires throughput, SLO, drained gauges and bounded resources', () => {
  const gauges = fixture();
  gauges.results[3].gauges_by_shard.active_requests['0'].final = 1;
  gauges.results[3].gauges_by_shard.active_requests['0'].peak = 5;
  let summary = summarizeBackpressure(gauges);
  assert.equal(summary.gates.recovery_gauges_drained_pass, false);

  const resources = fixture();
  resources.results[3].resources.rss_bytes.after += 8 * 1024 * 1024;
  resources.results[3].resources.rss_bytes.peak =
    resources.results[3].resources.rss_bytes.after;
  summary = summarizeBackpressure(resources);
  assert.equal(summary.gates.recovery_resources_pass, false);

  const latency = fixture();
  latency.results[3].latency_ms = {p50: 20, p95: 60, p99: 200, p999: 300};
  summary = summarizeBackpressure(latency);
  assert.equal(summary.gates.recovery_slo_pass, false);

  const scheduler = fixture();
  for (const name of RECOVERY_BASELINE_GAUGES) {
    scheduler.results[3].gauges_by_shard[name]['0'].final = 3;
    scheduler.results[3].gauges_by_shard[name]['0'].peak = 3;
  }
  summary = summarizeBackpressure(scheduler);
  assert.equal(summary.gates.recovery_gauges_drained_pass, false);
});

test('missing metric and shard evidence fail closed', () => {
  const metric = fixture();
  delete metric.results[0].counters_by_shard.scheduler_waittime_ms;
  assert.throws(() => summarizeBackpressure(metric), /counters_by_shard keys/u);

  const shard = fixture();
  delete shard.results[0].gauges_by_shard.active_requests['1'];
  assert.throws(() => summarizeBackpressure(shard), /active_requests keys/u);

  const capacity = fixture();
  capacity.results[0].gauges_by_shard.configured_upstream_http1_connections = gauge();
  assert.throws(() => summarizeBackpressure(capacity), /pool capacity is absent/u);
});

test('request imbalance and required host integrity remain explicit gates', () => {
  const normalized = fixture();
  normalized.results[0].counters_by_shard.requests_total = {'0': 600, '1': 400};
  normalized.results[0].counters_by_shard.downstream_connections_accepted_total =
    {'0': 60, '1': 40};
  let summary = summarizeBackpressure(normalized);
  assert.equal(summary.gates.shard_balance_pass, true);
  assert.equal(summary.points[0].request_imbalance_ratio, 0.4);
  assert.equal(summary.points[0].normalized_request_imbalance_ratio, 0);

  const imbalance = fixture();
  imbalance.results[0].counters_by_shard.requests_total = {'0': 700, '1': 300};
  summary = summarizeBackpressure(imbalance);
  assert.equal(summary.gates.shard_balance_pass, false);
  assert.equal(summary.decision, 'investigate');

  const host = fixture();
  host.results[2].host_counters.softnet_dropped = 1;
  const hostSummary = summarizeBackpressure(host);
  assert.equal(hostSummary.gates.host_integrity_pass, false);
  assert.equal(hostSummary.decision, 'investigate');
});

test('tampered plan identity and dirty source cannot enter analysis', () => {
  const plan = fixture();
  plan.plan.points[0].latency_ceiling_ms.p95 += 1;
  assert.throws(() => summarizeBackpressure(plan), /plan_id does not bind/u);

  const dirty = fixture();
  dirty.environment.source_dirty = true;
  assert.throws(() => summarizeBackpressure(dirty), /source_dirty=false/u);
});
