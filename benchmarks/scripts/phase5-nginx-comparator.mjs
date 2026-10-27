#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseOhaSequence} from './phase5-oha-lanes.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/u;

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function exactKeys(value, expected, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  requireValue(stable(Object.keys(value).sort()) === stable([...expected].sort()),
    `${label} has missing or unexpected keys`);
}

function validIpv4(value, label) {
  requireValue(typeof value === 'string' && IPV4.test(value) &&
    value.split('.').every((part) => Number(part) <= 255), `${label} invalid`);
}

function productFromLock(lock) {
  requireValue(Array.isArray(lock?.products), 'product lock invalid');
  const nginx = lock.products.find((product) => product.name === 'nginx');
  requireValue(nginx?.version === '1.30.4' &&
    nginx.repository === 'docker.io/library/nginx' &&
    /^sha256:[0-9a-f]{64}$/u.test(nginx.manifests?.linux_amd64),
  'locked NGINX AMD64 identity unavailable');
  return {name: nginx.name, version: nginx.version, repository: nginx.repository,
    manifest: nginx.manifests.linux_amd64,
    image: `${nginx.repository}@${nginx.manifests.linux_amd64}`};
}

function sourceIdentity() {
  const commit = execFileSync('git', ['-C', ROOT, 'rev-parse', 'HEAD'],
    {encoding: 'utf8'}).trim();
  const dirty = execFileSync('git', ['-C', ROOT, 'status', '--porcelain'],
    {encoding: 'utf8'}).trim() !== '';
  return {commit, dirty};
}

export function buildComparatorContract(plan, productLock, options, source) {
  requireValue(plan?.schema_version === 7 && SHA256.test(plan.plan_id),
    'schema-7 PERF-01 plan required');
  requireValue(COMMIT.test(source.commit) && source.dirty === false,
    'clean comparator harness source required');
  const point = plan.points?.find((entry) => entry.id === options.pointId);
  requireValue(point?.profile === 'P5-B01' && point.cores === 8 &&
    point.load === 'steady', 'first comparator checkpoint is P5-B01/8c/steady only');
  requireValue(Number.isSafeInteger(options.attempt) && options.attempt > 0,
    'attempt invalid');
  const cpus = options.cpus.split(',').map((value) => Number(value));
  requireValue(cpus.length === 8 && new Set(cpus).size === 8 &&
    cpus.every((cpu) => Number.isSafeInteger(cpu) && cpu >= 0),
  'comparator requires eight distinct CPUs');
  validIpv4(options.gatewayAddress, 'gateway address');
  validIpv4(options.upstreamA, 'upstream A');
  validIpv4(options.upstreamB, 'upstream B');
  requireValue(options.upstreamA !== options.upstreamB,
    'upstream addresses must be distinct');
  const irqbalanceState = options.irqbalanceState ?? 'inactive';
  requireValue(['active', 'inactive'].includes(irqbalanceState),
    'irqbalance state must be active or inactive');
  const profile = plan.input.profiles['P5-B01'];
  const contract = {
    schema_version: 1,
    evidence_class: 'shared-vm-engineering',
    plan_id: plan.plan_id,
    point_id: point.id,
    attempt: options.attempt,
    harness_commit: source.commit,
    source_dirty: false,
    product: productFromLock(productLock),
    runtime: {
      gateway_address: options.gatewayAddress,
      listener_port: profile.listener_port,
      readiness_port: 9901,
      worker_count: 8,
      cpus,
      worker_placement: 'os-managed-within-container-cpuset',
      irq_policy: irqbalanceState === 'active'
        ? 'irqbalance-active-observed-disjoint-no-static-write'
        : 'kernel-observed-disjoint-no-static-write',
      irqbalance_measurement_state: irqbalanceState,
      upstream_addresses: [options.upstreamA, options.upstreamB],
      upstream_port: plan.input.direct_upstream.listener_port,
      upstream_keepalive_per_worker: 128,
      upstream_idle_connection_budget: 1024,
      response_cache: false,
    },
    workload: {
      protocol: profile.protocol,
      tls: profile.tls,
      authority: profile.authority,
      path: profile.path,
      client_lanes: plan.input.client_lanes,
      client_cpus: [...plan.input.client_cpus],
      connections_per_lane: profile.connections,
      streams_per_connection: profile.streams,
      offered_rps: point.offered_rps,
      warmup_seconds: plan.input.warmup_seconds,
      measurement_seconds: plan.input.measurement_seconds,
      p999_ceiling_ms: plan.input.p999_ceiling_ms,
      client_sha256: plan.input.client_sha256,
    },
    support: {
      targets: plan.input.direct_upstream.targets.map((target) => ({...target})),
      minimum_headroom_ratio: plan.input.direct_upstream.minimum_headroom_ratio,
      maximum_cpu_percent: 80,
    },
  };
  return {...contract, contract_id: sha256(stable(contract))};
}

export function validateComparatorContract(contract) {
  exactKeys(contract, ['schema_version', 'evidence_class', 'plan_id', 'point_id',
    'attempt', 'harness_commit', 'source_dirty', 'product', 'runtime', 'workload',
    'support', 'contract_id'], 'comparator contract');
  requireValue(contract.schema_version === 1 &&
    contract.evidence_class === 'shared-vm-engineering' &&
    SHA256.test(contract.plan_id) && COMMIT.test(contract.harness_commit) &&
    contract.source_dirty === false && SHA256.test(contract.contract_id),
  'comparator contract identity invalid');
  const unsigned = Object.fromEntries(Object.entries(contract)
    .filter(([key]) => key !== 'contract_id'));
  requireValue(contract.contract_id === sha256(stable(unsigned)),
    'comparator contract digest mismatch');
  requireValue(contract.point_id.startsWith('P5-B01-8c-steady-r') &&
    Number.isSafeInteger(contract.attempt) && contract.attempt > 0,
  'comparator point invalid');
  exactKeys(contract.product, ['name', 'version', 'repository', 'manifest', 'image'],
    'comparator product');
  requireValue(contract.product.name === 'nginx' &&
    contract.product.version === '1.30.4' &&
    contract.product.image === `${contract.product.repository}@${contract.product.manifest}` &&
    /^sha256:[0-9a-f]{64}$/u.test(contract.product.manifest),
  'comparator product identity invalid');
  exactKeys(contract.runtime, ['gateway_address', 'listener_port', 'readiness_port',
    'worker_count', 'cpus', 'worker_placement', 'irq_policy',
    'irqbalance_measurement_state', 'upstream_addresses', 'upstream_port',
    'upstream_keepalive_per_worker', 'upstream_idle_connection_budget',
    'response_cache'], 'comparator runtime');
  validIpv4(contract.runtime.gateway_address, 'gateway address');
  requireValue(contract.runtime.worker_count === 8 &&
    contract.runtime.cpus.length === 8 && new Set(contract.runtime.cpus).size === 8 &&
    contract.runtime.cpus.every((cpu) => Number.isSafeInteger(cpu) && cpu >= 0) &&
    contract.runtime.listener_port === 8080 &&
    contract.runtime.readiness_port === 9901 &&
    contract.runtime.upstream_port === 8081 &&
    contract.runtime.worker_placement === 'os-managed-within-container-cpuset' &&
    ['active', 'inactive'].includes(contract.runtime.irqbalance_measurement_state) &&
    contract.runtime.irq_policy ===
      (contract.runtime.irqbalance_measurement_state === 'active'
        ? 'irqbalance-active-observed-disjoint-no-static-write'
        : 'kernel-observed-disjoint-no-static-write') &&
    contract.runtime.upstream_keepalive_per_worker === 128 &&
    contract.runtime.upstream_idle_connection_budget === 1024 &&
    contract.runtime.response_cache === false,
  'comparator runtime policy changed');
  requireValue(contract.runtime.upstream_addresses.length === 2 &&
    new Set(contract.runtime.upstream_addresses).size === 2,
  'comparator requires two upstreams');
  contract.runtime.upstream_addresses.forEach((address, index) =>
    validIpv4(address, `upstream ${index}`));
  exactKeys(contract.workload, ['protocol', 'tls', 'authority', 'path',
    'client_lanes', 'client_cpus', 'connections_per_lane',
    'streams_per_connection', 'offered_rps', 'warmup_seconds',
    'measurement_seconds', 'p999_ceiling_ms', 'client_sha256'],
  'comparator workload');
  requireValue(contract.workload.protocol === 'http1' &&
    contract.workload.tls === false &&
    contract.workload.authority === 'api.example.test' &&
    contract.workload.path === '/payload/256' &&
    contract.workload.client_lanes === 16 &&
    contract.workload.client_cpus.length === 32 &&
    new Set(contract.workload.client_cpus).size === 32 &&
    contract.workload.client_cpus.every((cpu) =>
      Number.isSafeInteger(cpu) && cpu >= 0) &&
    contract.workload.connections_per_lane === 256 &&
    contract.workload.streams_per_connection === 1 &&
    contract.workload.offered_rps === 280000 &&
    contract.workload.warmup_seconds === 60 &&
    contract.workload.measurement_seconds === 90 &&
    contract.workload.p999_ceiling_ms === 100 &&
    SHA256.test(contract.workload.client_sha256),
  'comparator workload differs from accepted BonVoyage point');
  exactKeys(contract.support, ['targets', 'minimum_headroom_ratio',
    'maximum_cpu_percent'], 'comparator support');
  requireValue(Array.isArray(contract.support.targets) &&
    contract.support.targets.length === 2 &&
    contract.support.minimum_headroom_ratio === 1.2 &&
    contract.support.maximum_cpu_percent === 80,
  'comparator support policy changed');
  const supportAddresses = contract.support.targets.map((target, index) => {
    exactKeys(target, ['address', 'hostname'], `support target ${index}`);
    validIpv4(target.address, `support target ${index} address`);
    requireValue(typeof target.hostname === 'string' &&
      /^[a-zA-Z0-9.-]+$/u.test(target.hostname),
    `support target ${index} hostname invalid`);
    return target.address;
  });
  requireValue(stable(supportAddresses) ===
    stable(contract.runtime.upstream_addresses),
  'support targets differ from comparator upstreams');
  return contract;
}

function cpuSet(spec, label) {
  requireValue(typeof spec === 'string' && /^[0-9,-]+$/u.test(spec),
    `${label} CPU list invalid`);
  const result = new Set();
  for (const part of spec.split(',')) {
    const bounds = part.split('-').map(Number);
    requireValue(bounds.length <= 2 && bounds.every((value) =>
      Number.isSafeInteger(value) && value >= 0), `${label} CPU list invalid`);
    const [start, end = start] = bounds;
    requireValue(start <= end, `${label} CPU range invalid`);
    for (let cpu = start; cpu <= end; cpu += 1) result.add(cpu);
  }
  requireValue(result.size > 0, `${label} CPU list empty`);
  return result;
}

function parseIrqObservation(raw, label) {
  requireValue(typeof raw === 'string', `${label} IRQ observation invalid`);
  const result = new Map();
  for (const line of raw.trim().split(/\n/u).filter(Boolean)) {
    const match = /^(\d+)\s+([0-9,-]+)$/u.exec(line.trim());
    requireValue(match && !result.has(match[1]), `${label} IRQ row invalid`);
    result.set(match[1], cpuSet(match[2], `${label} IRQ ${match[1]}`));
  }
  requireValue(result.size > 0, `${label} IRQ observation empty`);
  return result;
}

export function validateIrqObservation(contract, beforeRaw, afterRaw) {
  validateComparatorContract(contract);
  const before = parseIrqObservation(beforeRaw, 'before');
  const after = parseIrqObservation(afterRaw, 'after');
  requireValue(stable([...before.keys()].sort()) === stable([...after.keys()].sort()),
    'IRQ identity changed during comparator interval');
  const application = new Set(contract.runtime.cpus);
  const overlaps = [];
  let moved = 0;
  for (const [irq, beforeCpus] of before) {
    const afterCpus = after.get(irq);
    if (stable([...beforeCpus].sort((a, b) => a - b)) !==
        stable([...afterCpus].sort((a, b) => a - b))) moved += 1;
    for (const [stage, cpus] of [['before', beforeCpus], ['after', afterCpus]]) {
      for (const cpu of cpus) if (application.has(cpu)) overlaps.push({irq, stage, cpu});
    }
  }
  requireValue(overlaps.length === 0,
    `NIC IRQ overlapped comparator CPUs: ${JSON.stringify(overlaps)}`);
  return {irqbalance_measurement_state: contract.runtime.irqbalance_measurement_state,
    irq_count: before.size, moved_irq_count: moved, application_cpus: [...application],
    disjoint_before_and_after: true};
}

export function renderNginxConfig(contract) {
  validateComparatorContract(contract);
  const runtime = contract.runtime;
  return `worker_processes ${runtime.worker_count};
worker_rlimit_nofile 1048576;
error_log /dev/stderr crit;
pid /tmp/nginx.pid;

events {
  worker_connections 32768;
  multi_accept on;
}

http {
  access_log off;
  client_body_temp_path /tmp/client-body;
  proxy_temp_path /tmp/proxy;
  fastcgi_temp_path /tmp/fastcgi;
  uwsgi_temp_path /tmp/uwsgi;
  scgi_temp_path /tmp/scgi;
  client_max_body_size 10m;
  client_header_buffer_size 8k;
  large_client_header_buffers 4 8k;
  keepalive_timeout 60s;
  keepalive_requests 1000000;
  tcp_nodelay on;

  upstream controlled_upstream {
    server ${runtime.upstream_addresses[0]}:${runtime.upstream_port};
    server ${runtime.upstream_addresses[1]}:${runtime.upstream_port};
    keepalive ${runtime.upstream_keepalive_per_worker};
    keepalive_requests 1000000;
  }

  server {
    listen ${runtime.listener_port} reuseport;
    server_name _;

    location / {
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_set_header Host $http_host;
      proxy_request_buffering off;
      proxy_buffering off;
      proxy_connect_timeout 1s;
      proxy_send_timeout 15s;
      proxy_read_timeout 15s;
      proxy_pass http://controlled_upstream;
    }
  }

  server {
    listen 127.0.0.1:${runtime.readiness_port};
    server_name _;
    location = /health/ready { default_type text/plain; return 200 "ready\\n"; }
    location = /status { stub_status; }
    location / { return 404; }
  }
}
`;
}

export function summarizeOha(contract, raw) {
  validateComparatorContract(contract);
  const sequence = parseOhaSequence(raw);
  requireValue(sequence.schema_version === 2, 'comparator client schema invalid');
  const measurement = sequence.measurement;
  requireValue(measurement.client_lanes === contract.workload.client_lanes &&
    measurement.rate_per_lane * measurement.client_lanes ===
      contract.workload.offered_rps,
  'comparator client rate or lane count changed');
  requireValue(measurement.workload.connections_per_lane ===
    contract.workload.connections_per_lane &&
    measurement.workload.streams_per_connection === 1 &&
    measurement.workload.protocol === 'http1' &&
    measurement.workload.target_addresses.length === 1 &&
    measurement.workload.target_addresses[0] === contract.runtime.gateway_address,
  'comparator connection shape or target changed');
  const success = measurement.statusCodeDistribution?.['200'] ?? 0;
  const errors = Object.values(measurement.errorDistribution ?? {})
    .reduce((sum, count) => sum + count, 0);
  requireValue(success > 0 &&
    Object.keys(measurement.statusCodeDistribution ?? {}).length === 1 &&
    errors === 0, 'comparator returned non-200 responses or transport errors');
  const successfulRps = success / measurement.summary.total;
  const latency = measurement.latencyPercentiles;
  requireValue(successfulRps >= contract.workload.offered_rps * 0.95,
    'comparator missed 95% offered-rate alignment');
  requireValue(latency['p99.9'] * 1000 <= contract.workload.p999_ceiling_ms,
    'comparator exceeded the p99.9 ceiling');
  return {successful_rps: successfulRps, responses: success, errors,
    p50_ms: latency.p50 * 1000, p95_ms: latency.p95 * 1000,
    p99_ms: latency.p99 * 1000, p999_ms: latency['p99.9'] * 1000};
}

function option(args, name) {
  const index = args.indexOf(name);
  requireValue(index >= 0 && args[index + 1], `missing ${name}`);
  return args[index + 1];
}

function optional(args, name, fallback) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
}

function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'contract') {
    const plan = JSON.parse(fs.readFileSync(option(args, '--plan'), 'utf8'));
    const lock = JSON.parse(fs.readFileSync(option(args, '--product-lock'), 'utf8'));
    const contract = buildComparatorContract(plan, lock, {
      pointId: option(args, '--point'),
      attempt: Number(option(args, '--attempt')),
      gatewayAddress: option(args, '--gateway-address'),
      upstreamA: option(args, '--upstream-a'),
      upstreamB: option(args, '--upstream-b'),
      cpus: option(args, '--cpus'),
      irqbalanceState: optional(args, '--irqbalance-state', 'inactive'),
    }, sourceIdentity());
    process.stdout.write(`${JSON.stringify(contract, null, 2)}\n`);
  } else if (command === 'config') {
    const contract = JSON.parse(fs.readFileSync(option(args, '--contract'), 'utf8'));
    process.stdout.write(renderNginxConfig(contract));
  } else if (command === 'summarize') {
    const contract = JSON.parse(fs.readFileSync(option(args, '--contract'), 'utf8'));
    const raw = fs.readFileSync(option(args, '--oha'), 'utf8');
    process.stdout.write(`${JSON.stringify(summarizeOha(contract, raw), null, 2)}\n`);
  } else if (command === 'validate-irq') {
    const contract = JSON.parse(fs.readFileSync(option(args, '--contract'), 'utf8'));
    const before = fs.readFileSync(option(args, '--before'), 'utf8');
    const after = fs.readFileSync(option(args, '--after'), 'utf8');
    process.stdout.write(`${JSON.stringify(validateIrqObservation(
      contract, before, after), null, 2)}\n`);
  } else {
    throw new Error('usage: phase5-nginx-comparator.mjs contract|config|summarize|validate-irq ...');
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  try { main(); } catch (error) {
    process.stderr.write(`phase5-nginx-comparator: ${error.message}\n`);
    process.exitCode = 1;
  }
}
