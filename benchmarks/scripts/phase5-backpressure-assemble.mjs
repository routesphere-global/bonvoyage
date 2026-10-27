#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

import {
  COUNTER_METRICS,
  GAUGE_METRICS,
  HOST_COUNTERS,
  PHASES,
} from './phase5-backpressure.mjs';
import {parseOhaReport} from './phase5-oha-lanes.mjs';

const SAMPLE = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?|NaN|[+-]Inf)$/u;
const LABEL = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"/gu;

const FULL_METRIC_NAMES = new Map([
  ...COUNTER_METRICS,
  ...GAUGE_METRICS,
].map((name) => [
  name.startsWith('reactor_') || name.startsWith('scheduler_')
    ? `bonvoyage_${name}`
    : `bonvoyage_bonvoyage_gateway_${name}`,
  name,
]));

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function requireObject(value, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  return value;
}

function requireFinite(value, label, minimum = 0) {
  requireValue(Number.isFinite(value) && value >= minimum,
    `${label} must be a finite number >= ${minimum}`);
  return value;
}

function requireInteger(value, label, minimum = 0) {
  requireValue(Number.isSafeInteger(value) && value >= minimum,
    `${label} must be an integer >= ${minimum}`);
  return value;
}

function exactKeys(value, expected, label) {
  requireObject(value, label);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  requireValue(JSON.stringify(actual) === JSON.stringify(wanted),
    `${label} keys must be exactly: ${wanted.join(', ')}`);
}

function parseLabels(raw) {
  const labels = {};
  for (const match of (raw ?? '').matchAll(LABEL)) {
    requireValue(!(match[1] in labels), `duplicate metric label: ${match[1]}`);
    labels[match[1]] = JSON.parse(`"${match[2]}"`);
  }
  return labels;
}

export function parsePrometheusSnapshot(text, label = 'Prometheus snapshot') {
  const result = Object.fromEntries([...COUNTER_METRICS, ...GAUGE_METRICS]
    .map((name) => [name, {}]));
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const match = SAMPLE.exec(line);
    if (!match || !FULL_METRIC_NAMES.has(match[1])) continue;
    const labels = parseLabels(match[2]);
    if ('group' in labels && labels.group !== 'main') continue;
    requireValue(/^\d+$/u.test(labels.shard ?? ''),
      `${label} metric lacks an integer shard: ${match[1]}`);
    const value = Number(match[3]);
    requireValue(Number.isFinite(value), `${label} has a non-finite metric: ${match[1]}`);
    const shortName = FULL_METRIC_NAMES.get(match[1]);
    requireValue(!(labels.shard in result[shortName]),
      `${label} contains duplicate ${shortName} shard ${labels.shard}`);
    result[shortName][labels.shard] = value;
  }
  for (const [name, values] of Object.entries(result)) {
    requireValue(Object.keys(values).length > 0, `${label} is missing ${name}`);
  }
  return result;
}

function requireShards(values, expectedShards, label) {
  exactKeys(values, expectedShards.map(String), label);
  return values;
}

function counterDelta(before, after, expectedShards, name) {
  requireShards(before[name], expectedShards, `before ${name}`);
  requireShards(after[name], expectedShards, `after ${name}`);
  return Object.fromEntries(expectedShards.map((shard) => {
    const value = after[name][shard] - before[name][shard];
    requireInteger(value, `${name} shard ${shard} delta`);
    return [String(shard), value];
  }));
}

function gaugeSummary(snapshots, expectedShards, name) {
  for (const [index, snapshot] of snapshots.entries()) {
    requireShards(snapshot[name], expectedShards, `${name} sample ${index}`);
  }
  return Object.fromEntries(expectedShards.map((shard) => {
    const values = snapshots.map((snapshot) => snapshot[name][shard]);
    return [String(shard), {
      mean: values.reduce((sum, value) => sum + value, 0) / values.length,
      peak: Math.max(...values),
      final: values.at(-1),
    }];
  }));
}

function countDistribution(value, label) {
  requireObject(value, label);
  return Object.fromEntries(Object.entries(value).map(([name, count]) =>
    [name, requireInteger(count, `${label}.${name}`)]));
}

function sumValues(value) {
  return Object.values(value).reduce((sum, item) => sum + item, 0);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) =>
      [key, canonicalize(value[key])]));
  }
  return value;
}

function mean(values, label) {
  requireValue(Array.isArray(values) && values.length > 0,
    `${label} must not be empty`);
  return values.reduce((sum, value) => sum +
    requireFinite(value, label), 0) / values.length;
}

function parsePercent(value, label) {
  requireValue(typeof value === 'string' && /^\d+(?:\.\d+)?%$/u.test(value),
    `${label} must be a Docker percentage`);
  return Number(value.slice(0, -1));
}

function processIdentity(value, label) {
  requireObject(value, label);
  const result = {
    service: value.service,
    pid: requireInteger(value.pid, `${label}.pid`, 2),
    start_ticks: requireInteger(value.start_ticks, `${label}.start_ticks`, 1),
    restart_count: requireInteger(value.restart_count, `${label}.restart_count`),
  };
  requireValue(typeof result.service === 'string' && result.service.length > 0,
    `${label}.service is required`);
  requireValue(typeof value.boot_id === 'string' && value.boot_id.length > 0,
    `${label}.boot_id is required`);
  requireInteger(value.rss_bytes, `${label}.rss_bytes`, 1);
  requireInteger(value.file_descriptors, `${label}.file_descriptors`, 1);
  return {...result, boot_id: value.boot_id, rss_bytes: value.rss_bytes,
    file_descriptors: value.file_descriptors};
}

function sameProcess(before, after, environment, phase) {
  const fields = ['service', 'pid', 'start_ticks', 'restart_count', 'boot_id'];
  for (const field of fields) {
    requireValue(before[field] === after[field],
      `${phase} process identity changed: ${field}`);
  }
  requireValue(before.boot_id === environment.boot_id,
    `${phase} boot identity does not match the environment`);
  return Object.fromEntries(fields.slice(0, 4).map((field) => [field, before[field]]));
}

function dockerCpuSamples(lines, metadata, environment, phase) {
  const containers = {
    [metadata.gateway_container.name]: {
      role: 'gateway',
      cores: requireFinite(metadata.gateway_container.capacity_cores,
        `${phase} gateway capacity cores`, 0.001),
    },
  };
  exactKeys(metadata.support_containers, environment.support_roles,
    `${phase} support containers`);
  for (const role of environment.support_roles) {
    const item = requireObject(metadata.support_containers[role], `${phase} ${role}`);
    requireValue(typeof item.name === 'string' && item.name.length > 0,
      `${phase} ${role} container name is required`);
    requireValue(!(item.name in containers), `${phase} duplicate container name: ${item.name}`);
    containers[item.name] = {role, cores: requireFinite(item.capacity_cores,
      `${phase} ${role} capacity cores`, 0.001)};
  }
  const samples = Object.fromEntries(Object.values(containers).map(({role}) => [role, []]));
  for (const [index, line] of lines.entries()) {
    const sample = requireObject(line, `${phase} Docker sample ${index}`);
    const container = containers[sample.Name];
    if (!container) continue;
    const cpu = parsePercent(sample.CPUPerc, `${phase} ${sample.Name} CPU`);
    samples[container.role].push({raw: cpu, capacity: cpu / container.cores});
  }
  for (const [role, values] of Object.entries(samples)) {
    requireValue(values.length > 0, `${phase} has no Docker CPU samples for ${role}`);
  }
  const gateway = samples.gateway;
  return {
    gateway_application_cpu_percent:
      gateway.reduce((sum, value) => sum + value.raw, 0) / gateway.length,
    gateway_capacity_percent:
      gateway.reduce((sum, value) => sum + value.capacity, 0) / gateway.length,
    support_capacity_percent: Object.fromEntries(environment.support_roles.map((role) =>
      [role, Math.max(...samples[role].map((value) => value.capacity))])),
  };
}

function procCpu(raw, label) {
  const first = raw.split(/\r?\n/u)[0].trim().split(/\s+/u);
  requireValue(first[0] === 'cpu' && first.length >= 9 &&
    first.slice(1, 9).every((value) => /^[0-9]+$/u.test(value)),
  `${label} has no valid aggregate CPU row`);
  return first.slice(1, 9).map(Number);
}

export function supportCpuPercent(before, after, label = 'support host') {
  const first = procCpu(before, `${label} before`);
  const last = procCpu(after, `${label} after`);
  const delta = last.map((value, index) => value - first[index]);
  requireValue(delta.every((value) => Number.isSafeInteger(value) && value >= 0),
    `${label} CPU counters regressed`);
  const total = sumValues(delta);
  requireValue(total > 0, `${label} CPU interval is empty`);
  return (total - delta[3] - delta[4]) / total * 100;
}

function sumMatching(value, pattern) {
  const matches = Object.entries(value ?? {}).filter(([name]) => pattern.test(name));
  return matches.length === 0 ? null : matches.reduce((sum, [name, item]) =>
    sum + requireInteger(item, `host counter ${name}`), 0);
}

function nativeHostCounters(attribution) {
  requireObject(attribution.host, 'native host attribution');
  requireValue(Array.isArray(attribution.host.softnet_deltas) &&
    attribution.host.softnet_deltas.length > 0,
  'native softnet attribution is missing');
  return {
    softnet_dropped: attribution.host.softnet_deltas.reduce((sum, item, index) =>
      sum + requireInteger(item.dropped, `softnet CPU ${index} dropped`), 0),
    softnet_time_squeeze: attribution.host.softnet_deltas.reduce((sum, item, index) =>
      sum + requireInteger(item.time_squeeze, `softnet CPU ${index} time_squeeze`), 0),
    ena_allowance_exceeded: sumMatching(attribution.host.ethtool_deltas,
      /(?:^|_)allowance_exceeded$/u),
    ena_queue_stops: sumMatching(attribution.host.ethtool_deltas,
      /_queue_stop$/u),
  };
}

function validateNativeClock(value, label) {
  const clock = requireObject(value, `${label} clock identity`);
  exactKeys(clock, ['current_clocksource', 'available_clocksources',
    'tsc_capabilities'], `${label} clock identity`);
  requireValue(clock.current_clocksource === 'tsc' &&
    Array.isArray(clock.available_clocksources) &&
    clock.available_clocksources.includes('tsc') &&
    new Set(clock.available_clocksources).size ===
      clock.available_clocksources.length &&
    clock.available_clocksources.every((name) =>
      typeof name === 'string' && name.length > 0),
  `${label} kernel clocksource is not TSC`);
  const capabilities = requireObject(clock.tsc_capabilities,
    `${label} TSC capabilities`);
  exactKeys(capabilities, ['tsc', 'rdtscp', 'constant_tsc', 'nonstop_tsc',
    'tsc_known_freq'], `${label} TSC capabilities`);
  for (const name of ['tsc', 'constant_tsc', 'nonstop_tsc', 'tsc_known_freq']) {
    requireValue(capabilities[name] === true,
      `${label} TSC capability is missing: ${name}`);
  }
}

function validateNativeClient(client, metadata, point) {
  exactKeys(metadata.client, ['lanes', 'rate_per_lane', 'requests_per_lane',
    'workload_shape'], `${point.phase} native client contract`);
  const lanes = requireInteger(metadata.client.lanes,
    `${point.phase} native client lanes`, 2);
  const rate = requireInteger(metadata.client.rate_per_lane,
    `${point.phase} native client rate`, 1);
  const requests = requireInteger(metadata.client.requests_per_lane,
    `${point.phase} native client requests`, 1);
  requireValue(client.client_lanes === lanes && client.rate_per_lane === rate &&
    client.offered_rps === point.target_rps && rate * lanes === point.target_rps,
  `${point.phase} native client rate or lane placement drifted`);
  requireValue(client.workload && typeof client.workload === 'object',
    `${point.phase} native client requires a structured workload`);
  requireValue(client.workload.requests_per_lane === requests &&
    requests * lanes === point.target_rps * point.duration_seconds,
  `${point.phase} native fixed request count drifted`);
  const shape = {...client.workload};
  delete shape.requests_per_lane;
  requireValue(JSON.stringify(canonicalize(shape)) ===
    JSON.stringify(canonicalize(metadata.client.workload_shape)),
    `${point.phase} native client workload drifted`);
}

function nativeCpuSamples(capture, metadata, environment, point) {
  const attribution = requireObject(capture.nativeAttribution,
    `${point.phase} native attribution`);
  requireValue(attribution.schema_version === 1 &&
    attribution.process_identity_stable === true &&
    attribution.source_unchanged === true,
  `${point.phase} native attribution identity is invalid`);
  requireValue(attribution.hostname === metadata.gateway_hostname &&
    attribution.hostname !== '' && attribution.process?.executable_sha256 ===
      environment.gateway_binary_sha256 &&
    attribution.process?.boot_id === environment.boot_id &&
    attribution.source?.commit === environment.source_commit &&
    attribution.source?.dirty === false &&
    attribution.capture_collector_sha256 === metadata.queue_collector_sha256 &&
    attribution.analyzer_sha256 === metadata.queue_collector_sha256,
  `${point.phase} native source, binary, host, boot, or collector drifted`);
  requireValue(attribution.duration_seconds >= capture.client.summary.total * 0.95 &&
    attribution.duration_seconds <= capture.client.summary.total * 1.15,
  `${point.phase} native attribution window does not cover the client interval`);
  validateNativeClock(attribution.clock, `${point.phase} gateway`);
  validateNativeClock(capture.client.clock, `${point.phase} load generator`);
  requireValue(capture.resourceSamples.length > 0,
    `${point.phase} native resource sampling is missing`);
  validateNativeClient(capture.client, metadata, point);

  const expectedShards = environment.expected_shards.map(String);
  const reactor = attribution.gateway?.reactor_cpu_busy_ms_by_shard;
  exactKeys(reactor, expectedShards, `${point.phase} native reactor CPU`);
  const applicationCpu = sumValues(Object.fromEntries(expectedShards.map((shard) =>
    [shard, requireFinite(reactor[shard], `${point.phase} shard ${shard} CPU`)]))) /
    (attribution.duration_seconds * 1000) * 100;
  requireValue(metadata.gateway_capacity_cores === environment.expected_shards.length,
    `${point.phase} native gateway capacity differs from expected shards`);

  exactKeys(metadata.support_hosts, environment.support_roles,
    `${point.phase} native support hosts`);
  exactKeys(capture.nativeSupport, environment.support_roles,
    `${point.phase} native support captures`);
  const hostnames = [];
  const support = {};
  for (const role of environment.support_roles) {
    const item = capture.nativeSupport[role];
    requireValue(item.hostname === metadata.support_hosts[role] && item.hostname.length > 0,
      `${point.phase} ${role} host identity drifted`);
    hostnames.push(item.hostname);
    support[role] = supportCpuPercent(item.before, item.after,
      `${point.phase} ${role}`);
  }
  requireValue(new Set([metadata.gateway_hostname, ...hostnames]).size ===
    hostnames.length + 1, `${point.phase} native roles are not separate hosts`);

  const hostCpu = Object.values(attribution.host?.cpu_busy_ratio ?? {});
  const irqCpu = Object.values(attribution.host?.irq_cpu_busy_ratio ?? {});
  requireValue(hostCpu.length > 0 && irqCpu.length === hostCpu.length,
    `${point.phase} native host or IRQ CPU attribution is missing`);
  return {
    gateway_application_cpu_percent: applicationCpu,
    gateway_capacity_percent: applicationCpu / metadata.gateway_capacity_cores,
    support_capacity_percent: support,
    host_cpu_percent: mean(hostCpu, `${point.phase} host CPU`) * 100,
    irq_cpu_percent: mean(irqCpu, `${point.phase} IRQ CPU`) * 100,
    host_counters: nativeHostCounters(attribution),
  };
}

function validateMetadata(metadata, environment, point) {
  requireValue(metadata?.schema_version === 1, `${point.phase} metadata schema is invalid`);
  requireValue(typeof metadata.plan_id === 'string' && metadata.plan_id.length > 0,
    `${point.phase} metadata plan_id is missing`);
  requireValue(metadata.phase === point.phase, `${point.phase} metadata phase drifted`);
  const mode = metadata.resource_mode ?? 'docker';
  requireValue(['docker', 'native-linux'].includes(mode),
    `${point.phase} resource mode is invalid`);
  if (mode === 'native-linux') {
    requireInteger(metadata.gateway_capacity_cores,
      `${point.phase} gateway capacity cores`, 1);
    requireValue(typeof metadata.gateway_hostname === 'string' &&
      metadata.gateway_hostname.length > 0 &&
      typeof metadata.queue_collector_sha256 === 'string' &&
      /^[0-9a-f]{64}$/u.test(metadata.queue_collector_sha256),
    `${point.phase} native gateway or collector identity is invalid`);
    requireObject(metadata.support_hosts, `${point.phase} native support hosts`);
    requireObject(metadata.client, `${point.phase} native client contract`);
    return;
  }
  exactKeys(metadata.host_counters, HOST_COUNTERS, `${point.phase} host counters`);
  for (const name of HOST_COUNTERS) {
    const value = metadata.host_counters[name];
    requireValue(value === null || (Number.isSafeInteger(value) && value >= 0),
      `${point.phase} invalid host counter: ${name}`);
  }
  for (const name of ['host_cpu_percent', 'irq_cpu_percent']) {
    const value = metadata[name];
    requireValue(value === null || (Number.isFinite(value) && value >= 0 && value <= 100),
      `${point.phase} invalid ${name}`);
  }
}

export function assembleBackpressureStage({plan, environment, point, capture}) {
  requireValue(plan.plan_id === capture.metadata.plan_id,
    `${point.phase} capture does not match the plan`);
  validateMetadata(capture.metadata, environment, {...point, plan_id: plan.plan_id});
  const native = capture.metadata.resource_mode === 'native-linux';
  const cpu = native ? nativeCpuSamples(capture, capture.metadata, environment, point) :
    dockerCpuSamples(capture.dockerStatsSamples, capture.metadata,
      environment, point.phase);
  const hostCpuPercent = native ? cpu.host_cpu_percent :
    capture.metadata.host_cpu_percent;
  const irqCpuPercent = native ? cpu.irq_cpu_percent :
    capture.metadata.irq_cpu_percent;
  const hostCounters = native ? cpu.host_counters : capture.metadata.host_counters;
  const before = parsePrometheusSnapshot(capture.beforeMetrics,
    `${point.phase} before metrics`);
  const trace = capture.metricSamples.map((text, index) =>
    parsePrometheusSnapshot(text, `${point.phase} metric sample ${index}`));
  requireValue(trace.length >= 1, `${point.phase} requires at least one in-stage metric sample`);
  const after = parsePrometheusSnapshot(capture.afterMetrics,
    `${point.phase} after metrics`);
  const counters = Object.fromEntries(COUNTER_METRICS.map((name) =>
    [name, counterDelta(before, after, environment.expected_shards, name)]));
  const gauges = Object.fromEntries(GAUGE_METRICS.map((name) =>
    [name, gaugeSummary([before, ...trace, after], environment.expected_shards, name)]));

  const statuses = countDistribution(capture.client.statusCodeDistribution,
    `${point.phase} status distribution`);
  const errors = countDistribution(capture.client.errorDistribution,
    `${point.phase} error distribution`);
  const processEnvelopeDuration = requireFinite(capture.client.summary?.total,
    `${point.phase} client process envelope`, 0.001);
  const duration = native ? requireFinite(capture.client.active_measurement_seconds,
    `${point.phase} active client duration`, 0.001) : processEnvelopeDuration;
  requireValue(processEnvelopeDuration >= duration &&
    duration >= processEnvelopeDuration * 0.95,
  `${point.phase} active client duration disagrees with process envelope`);
  const latency = capture.client.latencyPercentiles;
  requireObject(latency, `${point.phase} latency percentiles`);
  const beforeProcess = processIdentity(capture.processBefore,
    `${point.phase} process before`);
  const afterProcess = processIdentity(capture.processAfter,
    `${point.phase} process after`);
  const process = sameProcess(beforeProcess, afterProcess, environment, point.phase);
  const resourceSamples = [beforeProcess, ...capture.resourceSamples.map((value, index) =>
    processIdentity({...beforeProcess, ...value}, `${point.phase} resource sample ${index}`)),
  afterProcess];

  return {
    schema_version: 1,
    plan_id: plan.plan_id,
    order: point.order,
    phase: point.phase,
    target_rps: point.target_rps,
    measurement_seconds: duration,
    client_process_envelope_seconds: processEnvelopeDuration,
    attempted_requests: sumValues(statuses) + sumValues(errors),
    status_counts: statuses,
    transport_failures: sumValues(errors),
    latency_ms: {
      p50: requireFinite(latency.p50, `${point.phase} p50`) * 1000,
      p95: requireFinite(latency.p95, `${point.phase} p95`) * 1000,
      p99: requireFinite(latency.p99, `${point.phase} p99`) * 1000,
      p999: requireFinite(latency['p99.9'], `${point.phase} p99.9`) * 1000,
    },
    identities: {
      source_commit: environment.source_commit,
      gateway_binary_sha256: environment.gateway_binary_sha256,
      snapshot_sha256: environment.snapshot_sha256,
      configuration_sha256: environment.configuration_sha256,
      collector_sha256: environment.collector_sha256,
      boot_id: environment.boot_id,
    },
    process,
    counters_by_shard: counters,
    gauges_by_shard: gauges,
    support_capacity_percent: cpu.support_capacity_percent,
    resources: {
      gateway_application_cpu_percent: cpu.gateway_application_cpu_percent,
      gateway_capacity_percent: cpu.gateway_capacity_percent,
      host_cpu_percent: hostCpuPercent,
      irq_cpu_percent: irqCpuPercent,
      rss_bytes: {
        before: beforeProcess.rss_bytes,
        peak: Math.max(...resourceSamples.map((value) => value.rss_bytes)),
        after: afterProcess.rss_bytes,
      },
      file_descriptors: {
        before: beforeProcess.file_descriptors,
        peak: Math.max(...resourceSamples.map((value) => value.file_descriptors)),
        after: afterProcess.file_descriptors,
      },
    },
    host_counters: hostCounters,
  };
}

function readJson(filename) {
  return JSON.parse(fs.readFileSync(filename, 'utf8'));
}

function readJsonLines(directory) {
  return fs.readdirSync(directory).sort().flatMap((name) => {
    const text = fs.readFileSync(path.join(directory, name), 'utf8').trim();
    if (!text) return [];
    return text.split(/\r?\n/u).map((line) => JSON.parse(line));
  });
}

function readJsonFiles(directory) {
  return fs.readdirSync(directory).filter((name) => name.endsWith('.json')).sort()
    .map((name) => readJson(path.join(directory, name)));
}

function readTexts(directory, suffix) {
  return fs.readdirSync(directory).filter((name) => name.endsWith(suffix)).sort()
    .map((name) => fs.readFileSync(path.join(directory, name), 'utf8'));
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function verifyQueueCapture(directory, label) {
  const manifest = readJson(path.join(directory, 'checksums.json'));
  requireValue(manifest?.schema_version === 1 && Array.isArray(manifest.files),
    `${label} queue checksum manifest is invalid`);
  const expected = new Set();
  for (const [index, record] of manifest.files.entries()) {
    exactKeys(record, ['bytes', 'path', 'sha256'], `${label} checksum ${index}`);
    requireValue(typeof record.path === 'string' &&
      /^[a-zA-Z0-9][a-zA-Z0-9.-]*$/u.test(record.path) &&
      /^[0-9a-f]{64}$/u.test(record.sha256) && !expected.has(record.path),
    `${label} checksum path or digest is invalid`);
    const filename = path.join(directory, record.path);
    const stat = fs.lstatSync(filename);
    requireValue(stat.isFile() && !stat.isSymbolicLink() &&
      stat.size === requireInteger(record.bytes, `${label} ${record.path} bytes`) &&
      sha256(fs.readFileSync(filename)) === record.sha256,
    `${label} queue capture changed: ${record.path}`);
    expected.add(record.path);
  }
  const actual = fs.readdirSync(directory).filter((name) => name !== 'checksums.json')
    .sort();
  requireValue(JSON.stringify(actual) === JSON.stringify([...expected].sort()),
    `${label} queue capture has unbound files`);
  requireValue(expected.has('snapshot.json') && expected.has('metrics.prom'),
    `${label} queue capture omits snapshot or metrics`);
  return readJson(path.join(directory, 'snapshot.json'));
}

function nativeProcess(snapshot, label) {
  const value = requireObject(snapshot.process, `${label} process`);
  requireValue(typeof value.service === 'string' && value.service.length > 0 &&
    typeof value.boot_id === 'string' && value.boot_id.length > 0,
  `${label} process service or boot identity is missing`);
  return {
    service: value.service,
    pid: requireInteger(value.pid, `${label} pid`, 2),
    start_ticks: requireInteger(value.start_ticks, `${label} start ticks`, 1),
    restart_count: requireInteger(value.restarts, `${label} restart count`),
    boot_id: value.boot_id,
    rss_bytes: requireInteger(value.rss_kib, `${label} RSS`, 1) * 1024,
    file_descriptors: requireInteger(value.fd_count, `${label} descriptors`, 1),
  };
}

function loadNativeSupport(directory, metadata) {
  const result = {};
  for (const role of Object.keys(metadata.support_hosts ?? {})) {
    requireValue(/^[a-z][a-z0-9_]*$/u.test(role),
      `native support role is unsafe: ${role}`);
    const root = path.join(directory, 'support', role);
    result[role] = {
      hostname: fs.readFileSync(path.join(root, 'hostname.txt'), 'utf8').trim(),
      before: fs.readFileSync(path.join(root, 'before.proc-stat'), 'utf8'),
      after: fs.readFileSync(path.join(root, 'after.proc-stat'), 'utf8'),
    };
  }
  return result;
}

export function loadStageCapture(directory) {
  const metadata = readJson(path.join(directory, 'metadata.json'));
  if (metadata.resource_mode === 'native-linux') {
    const beforeRoot = path.join(directory, 'before');
    const afterRoot = path.join(directory, 'after');
    const before = verifyQueueCapture(beforeRoot, `${metadata.phase} before`);
    const after = verifyQueueCapture(afterRoot, `${metadata.phase} after`);
    return {
      metadata,
      client: parseOhaReport(fs.readFileSync(path.join(directory,
        'client.oha.json'), 'utf8')),
      beforeMetrics: fs.readFileSync(path.join(beforeRoot, 'metrics.prom'), 'utf8'),
      metricSamples: readTexts(path.join(directory, 'metrics'), '.prom'),
      afterMetrics: fs.readFileSync(path.join(afterRoot, 'metrics.prom'), 'utf8'),
      processBefore: nativeProcess(before, `${metadata.phase} before`),
      processAfter: nativeProcess(after, `${metadata.phase} after`),
      resourceSamples: readJsonFiles(path.join(directory, 'resources')),
      dockerStatsSamples: [],
      nativeAttribution: readJson(path.join(directory, 'attribution.json')),
      nativeSupport: loadNativeSupport(directory, metadata),
    };
  }
  return {
    metadata,
    client: readJson(path.join(directory, 'client.oha.json')),
    beforeMetrics: fs.readFileSync(path.join(directory, 'before.metrics.prom'), 'utf8'),
    metricSamples: readTexts(path.join(directory, 'metrics'), '.prom'),
    afterMetrics: fs.readFileSync(path.join(directory, 'after.metrics.prom'), 'utf8'),
    processBefore: readJson(path.join(directory, 'process-before.json')),
    processAfter: readJson(path.join(directory, 'process-after.json')),
    resourceSamples: readJsonFiles(path.join(directory, 'resources')),
    dockerStatsSamples: readJsonLines(path.join(directory, 'docker-stats')),
  };
}

export function assembleBackpressureResults({plan, environment, capturesDirectory}) {
  requireValue(Array.isArray(plan.points) && plan.points.length === PHASES.length,
    'plan must contain the four PERF-04 points');
  return plan.points.map((point) => assembleBackpressureStage({
    plan,
    environment,
    point,
    capture: loadStageCapture(path.join(capturesDirectory, point.phase)),
  }));
}

function argument(name, argv) {
  const index = argv.indexOf(name);
  requireValue(index >= 0 && index + 1 < argv.length, `${name} is required`);
  return path.resolve(argv[index + 1]);
}

function writeNewJson(filename, value) {
  const descriptor = fs.openSync(filename, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`);
  } finally {
    fs.closeSync(descriptor);
  }
}

function main() {
  const argv = process.argv.slice(2);
  const plan = readJson(argument('--plan', argv));
  const environment = readJson(argument('--environment', argv));
  writeNewJson(argument('--output', argv), assembleBackpressureResults({
    plan,
    environment,
    capturesDirectory: argument('--captures', argv),
  }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-backpressure-assemble: ${error.message}\n`);
    process.exitCode = 1;
  }
}
