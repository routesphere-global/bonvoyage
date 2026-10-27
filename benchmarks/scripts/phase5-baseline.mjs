#!/usr/bin/env node

import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {OHA_DIRECT_LANES, OHA_DIRECT_LANE_MEMORY_BYTES,
  OHA_LANE_MEMORY_BYTES, parseOhaSequence,
  partitionCpus} from './phase5-oha-lanes.mjs';

const PROFILE_IDS = ['P5-B01', 'P5-B02', 'P5-B03', 'P5-B04'];
const CORE_COUNTS = [8, 24];
const LEGACY_LOAD_POINTS = ['steady', 'near_knee'];
const STEADY_LOAD_POINTS = ['steady'];
const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function positive(value, name) {
  requireValue(Number.isFinite(value) && value > 0, `${name} must be positive`);
  return value;
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

function digest(value, label) {
  requireValue(SHA256.test(value), `${label} must be a SHA-256 digest`);
}

function exactKeys(object, expected, label) {
  requireValue(object && typeof object === 'object' && !Array.isArray(object),
    `${label} must be an object`);
  requireValue(stable(Object.keys(object).sort()) === stable([...expected].sort()),
    `${label} has missing or unexpected keys`);
}

function validateProfile(profile, id) {
  exactKeys(profile, ['snapshot_sha256', 'protocol', 'tls', 'connections',
    'streams', 'authority', 'listener_port', 'path', 'ca_sha256',
    'credential_sha256'], id);
  digest(profile.snapshot_sha256, `${id} snapshot`);
  requireValue(['http1', 'http2'].includes(profile.protocol), `${id} protocol invalid`);
  requireValue(typeof profile.tls === 'boolean', `${id} TLS must be boolean`);
  requireValue(Number.isSafeInteger(profile.connections) && profile.connections > 0,
    `${id} connections invalid`);
  requireValue(Number.isSafeInteger(profile.streams) && profile.streams > 0,
    `${id} streams invalid`);
  requireValue(typeof profile.authority === 'string' &&
    /^[a-zA-Z0-9.-]+$/u.test(profile.authority), `${id} authority invalid`);
  requireValue(Number.isSafeInteger(profile.listener_port) &&
    profile.listener_port > 0 && profile.listener_port <= 65535,
  `${id} listener port invalid`);
  requireValue(typeof profile.path === 'string' && profile.path.startsWith('/') &&
    !profile.path.includes('?'), `${id} path invalid`);
  if (profile.tls) digest(profile.ca_sha256, `${id} CA`);
  else requireValue(profile.ca_sha256 === null, `${id} cleartext CA must be null`);
  if (id === 'P5-B04') digest(profile.credential_sha256, `${id} credential`);
  else requireValue(profile.credential_sha256 === null,
    `${id} credential must be null`);
  requireValue(profile.protocol === 'http2' || profile.streams === 1,
    `${id} HTTP/1 streams must equal one`);
}

function validateDirectUpstream(profile) {
  exactKeys(profile, ['protocol', 'tls', 'connections', 'streams', 'authority',
    'listener_port', 'path', 'targets', 'ca_sha256', 'offered_rps',
    'minimum_headroom_ratio', 'client_lanes', 'client_cpus',
    'memory_limit_bytes', 'memory_swap_limit_bytes', 'warmup_seconds',
    'measurement_seconds'], 'direct upstream');
  requireValue(profile.protocol === 'http1' && profile.tls === false,
    'direct upstream must use cleartext HTTP/1.1');
  requireValue(Number.isSafeInteger(profile.connections) && profile.connections > 0 &&
    profile.streams === 1, 'direct upstream connection shape invalid');
  requireValue(typeof profile.authority === 'string' &&
    /^[a-zA-Z0-9.-]+$/u.test(profile.authority),
  'direct upstream authority invalid');
  requireValue(Array.isArray(profile.targets) && profile.targets.length === 2,
    'direct upstream requires two targets');
  for (const [index, target] of profile.targets.entries()) {
    exactKeys(target, ['address', 'hostname'], `direct upstream target ${index}`);
    for (const field of ['address', 'hostname']) {
      requireValue(typeof target[field] === 'string' &&
        /^[a-zA-Z0-9.-]+$/u.test(target[field]),
      `direct upstream target ${index} ${field} invalid`);
    }
  }
  requireValue(new Set(profile.targets.map((target) => target.address)).size === 2 &&
    new Set(profile.targets.map((target) => target.hostname)).size === 2,
  'direct upstream target identities must be distinct');
  requireValue(Number.isSafeInteger(profile.listener_port) &&
    profile.listener_port > 0 && profile.listener_port <= 65535,
  'direct upstream listener port invalid');
  requireValue(typeof profile.path === 'string' && profile.path.startsWith('/') &&
    !profile.path.includes('?') && !profile.path.includes('#'),
  'direct upstream path invalid');
  requireValue(profile.ca_sha256 === null,
    'cleartext direct upstream CA identity must be null');
  requireValue(Number.isSafeInteger(profile.offered_rps) && profile.offered_rps > 0,
    'direct upstream offered rate invalid');
  requireValue(profile.minimum_headroom_ratio === 1.2,
    'direct upstream headroom ratio must remain 1.2');
  requireValue(Number.isSafeInteger(profile.warmup_seconds) &&
    profile.warmup_seconds > 0,
  'direct upstream warmup seconds must be a positive integer');
  requireValue(Number.isSafeInteger(profile.measurement_seconds) &&
    profile.measurement_seconds > profile.warmup_seconds,
  'direct upstream measurement seconds must exceed warmup seconds');
  requireValue(profile.client_lanes === OHA_DIRECT_LANES &&
    Array.isArray(profile.client_cpus) &&
    profile.client_cpus.length === OHA_DIRECT_LANES &&
    new Set(profile.client_cpus).size === OHA_DIRECT_LANES &&
    profile.client_cpus.every((cpu) => Number.isSafeInteger(cpu) && cpu >= 0),
  'direct upstream requires 32 distinct one-core client lanes');
  requireValue(profile.memory_limit_bytes === OHA_DIRECT_LANE_MEMORY_BYTES,
    'direct upstream lane memory limit changed');
  requireValue(profile.memory_swap_limit_bytes === OHA_DIRECT_LANE_MEMORY_BYTES,
    'direct upstream lane memory/swap limit changed');
}

function buildPlanForSchema(input, schemaVersion, loadPoints, declaresLoadPoints) {
  exactKeys(input, ['binary_source_commit', 'harness_commit', 'source_dirty',
    'binary_sha256', 'harness_runner_sha256',
    'client_sha256', 'upstream_sha256', 'profiles', 'direct_upstream',
    'rates', 'cpus',
    'client_lanes', 'client_cpus', 'gateway_address',
    'repetitions', 'measurement_seconds', 'warmup_seconds',
    'p999_ceiling_ms', 'evidence_class',
    ...(declaresLoadPoints ? ['load_points'] : [])], 'PERF-01 input');
  if (declaresLoadPoints) {
    requireValue(stable(input.load_points) === stable(loadPoints),
      'PERF-01 load points differ from the steady-only contract');
  }
  requireValue(COMMIT.test(input.binary_source_commit),
    'binary source commit must be a full SHA');
  requireValue(COMMIT.test(input.harness_commit),
    'harness commit must be a full SHA');
  requireValue(input.source_dirty === false, 'PERF-01 needs clean source');
  for (const name of ['binary_sha256', 'harness_runner_sha256', 'client_sha256',
    'upstream_sha256']) {
    digest(input[name], name);
  }
  requireValue(input.evidence_class === 'shared-vm-engineering',
    'PERF-01 preparation cannot authorize dedicated or publication claims');
  requireValue(input.repetitions === 5, 'PERF-01 requires five distinct repetitions');
  requireValue(Number.isSafeInteger(input.measurement_seconds) &&
    input.measurement_seconds > 0, 'measurement seconds must be a positive integer');
  requireValue(Number.isSafeInteger(input.warmup_seconds) &&
    input.warmup_seconds > 0, 'warmup seconds must be a positive integer');
  positive(input.p999_ceiling_ms, 'p99.9 ceiling');
  requireValue(input.client_lanes === 16, 'PERF-01 requires sixteen client lanes');
  requireValue(Array.isArray(input.client_cpus) && input.client_cpus.length >= 16 &&
    new Set(input.client_cpus).size === input.client_cpus.length &&
    input.client_cpus.every((cpu) => Number.isSafeInteger(cpu) && cpu >= 0),
  'client CPU set invalid');
  requireValue(typeof input.gateway_address === 'string' &&
    /^[a-zA-Z0-9.-]+$/u.test(input.gateway_address), 'gateway address invalid');
  validateDirectUpstream(input.direct_upstream);
  requireValue(input.direct_upstream.offered_rps %
    input.direct_upstream.client_lanes === 0,
    'direct upstream rate must divide evenly across client lanes');
  exactKeys(input.profiles, PROFILE_IDS, 'profiles');
  exactKeys(input.rates, PROFILE_IDS, 'rates');
  exactKeys(input.cpus, CORE_COUNTS.map(String), 'CPU sets');
  for (const id of PROFILE_IDS) {
    validateProfile(input.profiles[id], id);
    exactKeys(input.rates[id], CORE_COUNTS.map(String), `${id} rates`);
    for (const cores of CORE_COUNTS) {
      exactKeys(input.rates[id][cores], loadPoints, `${id}/${cores} rates`);
      for (const load of loadPoints) {
        requireValue(Number.isSafeInteger(input.rates[id][cores][load]) &&
          input.rates[id][cores][load] > 0, `${id}/${cores}/${load} rate invalid`);
        requireValue(input.rates[id][cores][load] % input.client_lanes === 0,
          `${id}/${cores}/${load} rate must divide evenly across client lanes`);
      }
      if (loadPoints.includes('near_knee')) {
        requireValue(input.rates[id][cores].near_knee > input.rates[id][cores].steady,
          `${id}/${cores} near-knee rate must exceed steady rate`);
      }
    }
  }
  for (const cores of CORE_COUNTS) {
    const cpus = input.cpus[cores];
    requireValue(Array.isArray(cpus) && cpus.length === cores &&
      new Set(cpus).size === cores &&
      cpus.every((cpu) => Number.isSafeInteger(cpu) && cpu >= 0),
    `${cores}-core CPU set invalid`);
  }
  requireValue(input.profiles['P5-B01'].protocol === 'http1' &&
    !input.profiles['P5-B01'].tls &&
    input.profiles['P5-B02'].protocol === 'http1' &&
    input.profiles['P5-B02'].tls &&
    input.profiles['P5-B03'].protocol === 'http2' &&
    input.profiles['P5-B03'].tls &&
    input.profiles['P5-B04'].protocol === 'http1' &&
    input.profiles['P5-B04'].tls,
  'profile protocol/TLS matrix changed');
  const points = [];
  for (let repetition = 1; repetition <= input.repetitions; repetition += 1) {
    const profiles = repetition % 2 ? PROFILE_IDS : [...PROFILE_IDS].reverse();
    const coresOrder = repetition % 2 ? CORE_COUNTS : [...CORE_COUNTS].reverse();
    for (const profile of profiles) {
      for (const cores of coresOrder) {
        for (const load of loadPoints) {
          points.push({id: `${profile}-${cores}c-${load}-r${repetition}`,
            profile, cores, load, repetition,
            offered_rps: input.rates[profile][cores][load]});
        }
      }
    }
  }
  const contract = {schema_version: schemaVersion, input, points};
  return {...contract, plan_id: sha256(stable(contract))};
}

export function buildPlan(input) {
  return buildPlanForSchema(input, 8, STEADY_LOAD_POINTS, true);
}

export function buildLegacyPlanV7(input) {
  return buildPlanForSchema(input, 7, LEGACY_LOAD_POINTS, false);
}

export function validatePlan(plan) {
  requireValue([7, 8].includes(plan?.schema_version) && SHA256.test(plan.plan_id),
    'invalid PERF-01 plan header');
  const rebuilt = plan.schema_version === 7 ?
    buildLegacyPlanV7(plan.input) : buildPlan(plan.input);
  requireValue(stable(rebuilt) === stable(plan),
    'PERF-01 plan differs from its deterministic contract');
  return plan;
}

function clientTopology(plan, scope) {
  if (scope === 'direct-support') {
    return {schemaVersion: 3, lanes: plan.input.direct_upstream.client_lanes,
      cpus: plan.input.direct_upstream.client_cpus,
      memoryLimitBytes: plan.input.direct_upstream.memory_limit_bytes,
      memorySwapLimitBytes: plan.input.direct_upstream.memory_swap_limit_bytes,
      evidenceScope: scope};
  }
  return {schemaVersion: 2, lanes: plan.input.client_lanes,
    cpus: plan.input.client_cpus, memoryLimitBytes: OHA_LANE_MEMORY_BYTES,
    evidenceScope: null};
}

function expectedWorkload(plan, profile, targetAddresses, offeredRps, seconds,
  topology) {
  return {...(topology.evidenceScope ?
    {evidence_scope: topology.evidenceScope,
      memory_swap_limit_bytes: topology.memorySwapLimitBytes} : {}),
    request_mode: 'fixed-count', client_sha256: plan.input.client_sha256,
    protocol: profile.protocol, tls: profile.tls, authority: profile.authority,
    listener_port: profile.listener_port,
    target_addresses: targetAddresses, path: profile.path,
    connections_per_lane: profile.connections,
    streams_per_connection: profile.streams,
    requests_per_lane: offeredRps / topology.lanes * seconds,
    memory_limit_bytes: topology.memoryLimitBytes,
    ca_sha256: profile.ca_sha256,
    credential_sha256: profile.credential_sha256 ?? null, method: 'GET',
    keepalive: true, compression: false, latency_correction: true,
    request_timeout_seconds: 5, connect_timeout_seconds: 5,
    redirect_limit: 0};
}

function verifySequence(plan, sequence, profile, address, offeredRps, label,
  scope = 'gateway') {
  const topology = clientTopology(plan, scope);
  const durations = scope === 'direct-support' ? plan.input.direct_upstream : plan.input;
  requireValue(sequence.schema_version === topology.schemaVersion,
    `${label} client schema differs from its evidence scope`);
  const expectedSets = partitionCpus(topology.cpus.join(','), topology.lanes,
    topology.lanes === OHA_DIRECT_LANES ? OHA_DIRECT_LANES : 16);
  for (const [stage, report, seconds] of [
    ['warmup', sequence.warmup, durations.warmup_seconds],
    ['measurement', sequence.measurement, durations.measurement_seconds],
  ]) {
    requireValue(report.client_lanes === topology.lanes &&
      stable(report.client_cpu_sets) === stable(expectedSets) &&
      report.rate_per_lane * report.client_lanes === offeredRps,
    `${label} ${stage} client lane placement or rate differs from plan`);
    requireValue(stable(report.workload) === stable(expectedWorkload(
      plan, profile, address, offeredRps, seconds, topology)),
    `${label} ${stage} workload differs from plan`);
  }
  return sequence.measurement;
}

function successfulResponseCount(report, label) {
  const statuses = report.statusCodeDistribution;
  const errors = Object.values(report.errorDistribution ?? {}).reduce(
    (sum, count) => sum + count, 0);
  requireValue(statuses && Object.keys(statuses).length === 1 &&
    Number.isSafeInteger(statuses['200']) && statuses['200'] > 0 && errors === 0,
  `${label} includes non-200 responses or transport errors`);
  return statuses['200'];
}

export function parsePerfStat(raw) {
  const wanted = new Map([
    ['cycles', 'cycles'], ['instructions', 'instructions'],
    ['cache-misses', 'cache_misses'], ['raw_syscalls:sys_enter', 'syscalls'],
  ]);
  const values = {};
  for (const line of raw.split(/\r?\n/u)) {
    if (!line.trim() || line.startsWith('#')) continue;
    const columns = line.split(',');
    if (columns.length < 3) continue;
    const name = columns[2].trim();
    if (!wanted.has(name)) continue;
    const numeric = columns[0].trim();
    requireValue(/^[0-9]+$/u.test(numeric), `${name} counter unavailable`);
    const key = wanted.get(name);
    requireValue(values[key] === undefined, `duplicate perf counter: ${name}`);
    values[key] = Number(numeric);
    requireValue(Number.isSafeInteger(values[key]), `${name} counter unsafe`);
  }
  exactKeys(values, [...wanted.values()], 'perf counters');
  requireValue(values.cycles > 0 && values.instructions > 0 && values.syscalls >= 0,
    'perf counters invalid');
  return {...values, ipc: values.instructions / values.cycles};
}

function readBoundFile(root, reference, label) {
  exactKeys(reference, ['path', 'sha256'], label);
  digest(reference.sha256, label);
  requireValue(typeof reference.path === 'string' &&
    /^(?:[a-zA-Z0-9._-]+\/)*[a-zA-Z0-9._-]+$/u.test(reference.path) &&
    !reference.path.split('/').includes('..'), `${label} path invalid`);
  let absolute = path.resolve(root);
  for (const part of reference.path.split('/')) {
    absolute = path.join(absolute, part);
    requireValue(!fs.lstatSync(absolute).isSymbolicLink(), `${label} symlink forbidden`);
  }
  requireValue(fs.lstatSync(absolute).isFile(), `${label} must be a regular file`);
  const bytes = fs.readFileSync(absolute);
  requireValue(sha256(bytes) === reference.sha256, `${label} checksum mismatch`);
  return bytes.toString('utf8');
}

function fileReference(root, absolute) {
  const relative = path.relative(root, absolute).split(path.sep).join('/');
  const reference = {path: relative, sha256: sha256(fs.readFileSync(absolute))};
  readBoundFile(root, reference, relative);
  return reference;
}

function verifyCaptureManifest(captureRoot) {
  const manifest = fs.readFileSync(path.join(captureRoot, 'checksums.sha256'), 'utf8');
  const verified = new Set();
  for (const line of manifest.trimEnd().split('\n')) {
    const match = /^([0-9a-f]{64})  \.\/([a-zA-Z0-9._/-]+)$/u.exec(line);
    requireValue(match && !verified.has(match[2]), 'capture checksum manifest invalid');
    readBoundFile(captureRoot, {path: match[2], sha256: match[1]},
      'capture checksum');
    verified.add(match[2]);
  }
  for (const name of ['source-commit.txt', 'snapshot-sha256.txt',
    'credential-sha256.txt',
    'before/snapshot.json',
    'after/snapshot.json', 'before-resource.json', 'after-resource.json',
    'attribution.json', 'perf.csv', 'oha.json', 'client-exit-code.txt',
    'diagnostic.oha.json', 'diagnostic-after/snapshot.json',
    'diagnostic-exit-code.txt', 'expected-runner-sha256.txt',
    'direct-upstream.oha.json', 'direct-source-commit.txt',
    'direct-expected-runner-sha256.txt',
    'direct-loadgen-proc-before.txt', 'direct-loadgen-proc-after.txt',
    'direct-upstream-a-proc-before.txt', 'direct-upstream-a-proc-after.txt',
    'direct-upstream-b-proc-before.txt', 'direct-upstream-b-proc-after.txt',
    'gateway-loadgen-proc-before.txt', 'gateway-loadgen-proc-after.txt',
    'gateway-upstream-a-proc-before.txt', 'gateway-upstream-a-proc-after.txt',
    'gateway-upstream-b-proc-before.txt', 'gateway-upstream-b-proc-after.txt',
    'direct-loadgen-host.txt', 'direct-upstream-a-host.txt',
    'direct-upstream-b-host.txt', 'gateway-loadgen-host.txt',
    'gateway-upstream-a-host.txt', 'gateway-upstream-b-host.txt',
    'direct-loadgen-source-commit-before.txt',
    'direct-loadgen-source-commit-after.txt',
    'direct-loadgen-source-status-before.txt',
    'direct-loadgen-source-status-after.txt',
    'direct-loadgen-runner-sha256-before.txt',
    'direct-loadgen-runner-sha256-after.txt',
    'gateway-loadgen-source-commit-before.txt',
    'gateway-loadgen-source-commit-after.txt',
    'gateway-loadgen-source-status-before.txt',
    'gateway-loadgen-source-status-after.txt',
    'gateway-loadgen-runner-sha256-before.txt',
    'gateway-loadgen-runner-sha256-after.txt']) {
    requireValue(verified.has(name), `capture manifest omits ${name}`);
  }
}

function procCpu(raw, label) {
  const first = raw.split(/\r?\n/u)[0].trim().split(/\s+/u);
  requireValue(first[0] === 'cpu' && first.length >= 9 &&
    first.slice(1, 9).every((value) => /^[0-9]+$/u.test(value)),
  `${label} has no valid aggregate CPU row`);
  return first.slice(1, 9).map(Number);
}

function supportCpu(before, after, label) {
  const first = procCpu(before, `${label} before`);
  const last = procCpu(after, `${label} after`);
  const delta = last.map((value, index) => value - first[index]);
  requireValue(delta.every((value) => Number.isSafeInteger(value) && value >= 0),
    `${label} CPU counters regressed`);
  const total = delta.reduce((sum, value) => sum + value, 0);
  requireValue(total > 0, `${label} CPU interval empty`);
  return (total - delta[3] - delta[4]) / total * 100;
}

function directRps(plan, raw) {
  const profile = plan.input.direct_upstream;
  const result = verifySequence(plan, parseOhaSequence(raw), profile,
    profile.targets.map((target) => target.address), profile.offered_rps,
    'direct upstream', 'direct-support');
  const seconds = positive(result.summary?.total, 'direct upstream duration');
  const statuses = result.statusCodeDistribution;
  requireValue(statuses && Object.keys(statuses).length === 1 &&
    Number.isSafeInteger(statuses['200']) && statuses['200'] > 0 &&
    Object.values(result.errorDistribution ?? {}).reduce((a, b) => a + b, 0) === 0,
  'direct upstream probe has errors');
  return statuses['200'] / seconds;
}

function supportFromRaw(plan, read) {
  const directLoadHost = read('direct_loadgen_host').trim();
  const directUpstreamHosts = ['direct_upstream_a_host', 'direct_upstream_b_host']
    .map((name) => read(name).trim());
  const gatewayLoadHost = read('gateway_loadgen_host').trim();
  const gatewayUpstreamHosts = ['gateway_upstream_a_host', 'gateway_upstream_b_host']
    .map((name) => read(name).trim());
  const expectedHosts = plan.input.direct_upstream.targets
    .map((target) => target.hostname);
  requireValue(directLoadHost && directUpstreamHosts.every(Boolean) &&
    new Set([directLoadHost, ...directUpstreamHosts]).size === 3,
  'support hosts are not separate');
  requireValue(stable(directUpstreamHosts) === stable(expectedHosts),
    'upstream host identities differ from plan');
  requireValue(gatewayLoadHost === directLoadHost &&
    stable(gatewayUpstreamHosts) === stable(directUpstreamHosts),
  'gateway interval support hosts differ from direct interval');
  const cpu = (prefix) => ({load_generator_capacity_percent: supportCpu(
    read(`${prefix}_loadgen_before`), read(`${prefix}_loadgen_after`),
    `${prefix} load generator`), upstream_capacity_percent: [supportCpu(
    read(`${prefix}_upstream_a_before`), read(`${prefix}_upstream_a_after`),
    `${prefix} upstream A`), supportCpu(read(`${prefix}_upstream_b_before`),
    read(`${prefix}_upstream_b_after`), `${prefix} upstream B`)]});
  return {direct: {...cpu('direct'),
    direct_upstream_rps: directRps(plan, read('direct_upstream'))},
  gateway: cpu('gateway'), load_generator_host: directLoadHost,
  upstream_hosts: directUpstreamHosts};
}

function verifyRunnerProvenance(plan, read) {
  for (const scope of ['direct', 'gateway']) {
    requireValue(read(`${scope}_expected_runner`).trim() ===
      plan.input.harness_runner_sha256,
    `${scope} expected runner differs from plan`);
    if (scope === 'direct') {
      requireValue(read('direct_source_commit').trim() === plan.input.harness_commit,
        'direct-support harness commit differs from plan');
    }
    for (const stage of ['before', 'after']) {
      requireValue(read(`${scope}_loadgen_source_${stage}`).trim() ===
        plan.input.harness_commit,
      `${scope} load-generator source differs from plan`);
      requireValue(read(`${scope}_loadgen_status_${stage}`).trim() === '',
        `${scope} load-generator source was dirty`);
      requireValue(read(`${scope}_loadgen_runner_${stage}`).trim() ===
        plan.input.harness_runner_sha256,
      `${scope} load-generator runner differs from plan`);
    }
  }
}

function readJsonBound(root, reference, label) {
  return JSON.parse(readBoundFile(root, reference, label));
}

function evaluatePoint(plan, point, evidence, root) {
  requireValue(evidence.plan_id === plan.plan_id && evidence.point_id === point.id,
    `${point.id} identity mismatch`);
  requireValue(Number.isSafeInteger(evidence.attempt) && evidence.attempt > 0,
    `${point.id} attempt invalid`);
  requireValue(evidence.accepted === true, `${point.id} was not accepted`);
  requireValue(evidence.binary_source_commit === plan.input.binary_source_commit &&
    evidence.harness_commit === plan.input.harness_commit &&
    evidence.source_dirty === false &&
    evidence.binary_sha256 === plan.input.binary_sha256 &&
    evidence.client_sha256 === plan.input.client_sha256 &&
    evidence.upstream_sha256 === plan.input.upstream_sha256 &&
    evidence.snapshot_sha256 === plan.input.profiles[point.profile].snapshot_sha256,
  `${point.id} source or artifact drift`);
  exactKeys(evidence.files, ['oha', 'diagnostic_oha', 'diagnostic_after',
    'perf', 'attribution', 'support', 'snapshot_digest',
    'credential_digest',
    'resource_before', 'resource_after',
    'direct_loadgen_before', 'direct_loadgen_after',
    'direct_upstream_a_before', 'direct_upstream_a_after',
    'direct_upstream_b_before', 'direct_upstream_b_after',
    'gateway_loadgen_before', 'gateway_loadgen_after',
    'gateway_upstream_a_before', 'gateway_upstream_a_after',
    'gateway_upstream_b_before', 'gateway_upstream_b_after',
    'direct_upstream', 'direct_loadgen_host', 'direct_upstream_a_host',
    'direct_upstream_b_host', 'gateway_loadgen_host', 'gateway_upstream_a_host',
    'gateway_upstream_b_host', 'direct_source_commit',
    'direct_expected_runner', 'gateway_expected_runner',
    'direct_loadgen_source_before', 'direct_loadgen_source_after',
    'direct_loadgen_status_before', 'direct_loadgen_status_after',
    'direct_loadgen_runner_before', 'direct_loadgen_runner_after',
    'gateway_loadgen_source_before', 'gateway_loadgen_source_after',
    'gateway_loadgen_status_before', 'gateway_loadgen_status_after',
    'gateway_loadgen_runner_before', 'gateway_loadgen_runner_after'],
  `${point.id} files`);
  requireValue(readBoundFile(root, evidence.files.snapshot_digest,
    `${point.id} snapshot digest`).trim() ===
    plan.input.profiles[point.profile].snapshot_sha256,
  `${point.id} installed snapshot differs from plan`);
  requireValue(readBoundFile(root, evidence.files.credential_digest,
    `${point.id} credential digest`).trim() ===
    (plan.input.profiles[point.profile].credential_sha256 ?? 'null'),
  `${point.id} installed credential differs from plan`);
  const profile = plan.input.profiles[point.profile];
  const oha = verifySequence(plan, parseOhaSequence(readBoundFile(root,
    evidence.files.oha, `${point.id} oha`)), profile,
  [plan.input.gateway_address], point.offered_rps, `${point.id} capacity`);
  const diagnosticSequence = parseOhaSequence(readBoundFile(root,
    evidence.files.diagnostic_oha, `${point.id} diagnostic oha`));
  const diagnosticOha = verifySequence(plan, diagnosticSequence, profile,
  [plan.input.gateway_address], point.offered_rps, `${point.id} diagnostic`);
  const diagnosticWarmupResponses = successfulResponseCount(
    diagnosticSequence.warmup, `${point.id} diagnostic warmup`);
  const diagnosticMeasurementResponses = successfulResponseCount(
    diagnosticSequence.measurement, `${point.id} diagnostic measurement`);
  // perf wraps the complete client sequence, so its denominator must do the same.
  const diagnosticProfiledResponses = diagnosticWarmupResponses +
    diagnosticMeasurementResponses;
  requireValue(Number.isSafeInteger(diagnosticProfiledResponses),
    `${point.id} diagnostic profiled response count unsafe`);
  const diagnosticAfter = readJsonBound(root, evidence.files.diagnostic_after,
    `${point.id} diagnostic after`);
  const perf = parsePerfStat(readBoundFile(root, evidence.files.perf, `${point.id} perf`));
  const attribution = readJsonBound(root, evidence.files.attribution,
    `${point.id} attribution`);
  const seconds = positive(oha.summary?.total, `${point.id} duration`);
  const statuses = oha.statusCodeDistribution;
  requireValue(statuses && typeof statuses === 'object' &&
    Object.keys(statuses).length === 1 &&
    Number.isSafeInteger(statuses['200']) && statuses['200'] > 0,
  `${point.id} includes non-200 or lacks successful responses`);
  const errors = Object.values(oha.errorDistribution ?? {}).reduce(
    (sum, count) => sum + count, 0);
  requireValue(errors === 0, `${point.id} transport errors`);
  const rps = statuses['200'] / seconds;
  requireValue(oha.offered_rps === point.offered_rps,
    `${point.id} multi-lane offered rate differs from plan`);
  requireValue(rps >= point.offered_rps * 0.95,
    `${point.id} did not sustain its offered rate`);
  const latency = oha.latencyPercentiles;
  for (const name of ['p50', 'p95', 'p99', 'p99.9']) {
    positive(latency?.[name], `${point.id} ${name}`);
  }
  requireValue(latency.p50 <= latency.p95 && latency.p95 <= latency.p99 &&
    latency.p99 <= latency['p99.9'], `${point.id} percentile order invalid`);
  requireValue(latency['p99.9'] * 1000 <= plan.input.p999_ceiling_ms,
    `${point.id} exceeds p99.9 ceiling`);
  requireValue(attribution.schema_version === 1 &&
    attribution.process_identity_stable === true &&
    attribution.source_unchanged === true &&
    attribution.duration_seconds > 0,
  `${point.id} attribution invalid`);
  requireValue(attribution.source?.commit === plan.input.harness_commit &&
    attribution.source?.dirty === false &&
    attribution.process?.executable_sha256 === plan.input.binary_sha256,
  `${point.id} native process or source provenance mismatch`);
  requireValue(diagnosticAfter.process?.pid === attribution.process.pid &&
    diagnosticAfter.process?.start_ticks === attribution.process.start_ticks &&
    diagnosticAfter.process?.restarts === 0 &&
    diagnosticAfter.process?.executable_sha256 === plan.input.binary_sha256 &&
    diagnosticAfter.source?.commit === plan.input.harness_commit &&
    diagnosticAfter.source?.dirty === false,
  `${point.id} diagnostic process or source changed`);
  requireValue(positive(diagnosticOha.summary?.total,
    `${point.id} diagnostic duration`) > 0 &&
    Object.keys(diagnosticOha.statusCodeDistribution ?? {}).length === 1 &&
    Number.isSafeInteger(diagnosticOha.statusCodeDistribution['200']) &&
    diagnosticOha.statusCodeDistribution['200'] > 0 &&
    Object.values(diagnosticOha.errorDistribution ?? {}).reduce(
      (sum, count) => sum + count, 0) === 0,
  `${point.id} diagnostic client errors`);
  requireValue(diagnosticOha.statusCodeDistribution['200'] /
    diagnosticOha.summary.total >= point.offered_rps * 0.95,
  `${point.id} diagnostic offered rate not sustained`);
  requireValue(diagnosticOha.offered_rps === point.offered_rps,
    `${point.id} diagnostic multi-lane offered rate differs from plan`);
  const support = evidence.support;
  requireValue(stable(support) === stable(readJsonBound(root, evidence.files.support,
    `${point.id} support`)), `${point.id} support evidence mismatch`);
  const readRaw = (name) => readBoundFile(root, evidence.files[name],
    `${point.id} ${name}`);
  verifyRunnerProvenance(plan, readRaw);
  const rawSupport = supportFromRaw(plan, readRaw);
  requireValue(stable(support) === stable(rawSupport),
    `${point.id} support values disagree with raw role evidence`);
  requireValue(attribution.hostname &&
    attribution.hostname !== support.load_generator_host &&
    !support.upstream_hosts.includes(attribution.hostname),
  `${point.id} roles are not four separate hosts`);
  for (const interval of ['direct', 'gateway']) {
    requireValue(Number.isFinite(support[interval]?.load_generator_capacity_percent) &&
      support[interval].load_generator_capacity_percent < 80,
    `${point.id} ${interval} load generator saturated or unmeasured`);
    requireValue(Array.isArray(support[interval]?.upstream_capacity_percent) &&
      support[interval].upstream_capacity_percent.length === 2 &&
      support[interval].upstream_capacity_percent.every((value) =>
        Number.isFinite(value) && value < 80),
    `${point.id} ${interval} upstream saturated or unmeasured`);
  }
  requireValue(positive(support.direct.direct_upstream_rps,
    `${point.id} direct upstream RPS`) >=
    rps * plan.input.direct_upstream.minimum_headroom_ratio,
  `${point.id} upstream lacks planned headroom`);
  const resource = evidence.resource;
  const resourceBefore = readJsonBound(root, evidence.files.resource_before,
    `${point.id} resource before`);
  const resourceAfter = readJsonBound(root, evidence.files.resource_after,
    `${point.id} resource after`);
  requireValue(stable(resource) === stable({restart_count: resourceAfter.restart_count,
    pid_before: resourceBefore.pid, pid_after: resourceAfter.pid,
    start_ticks_before: resourceBefore.start_ticks,
    start_ticks_after: resourceAfter.start_ticks,
    rss_before_bytes: resourceBefore.rss_bytes,
    rss_after_bytes: resourceAfter.rss_bytes,
    fd_before: resourceBefore.fd, fd_after: resourceAfter.fd}),
  `${point.id} resource evidence mismatch`);
  requireValue(resource?.restart_count === 0 && resource?.pid_before > 0 &&
    resource.pid_before === resource.pid_after &&
    resource.start_ticks_before === resource.start_ticks_after &&
    resource.rss_before_bytes > 0 && resource.rss_after_bytes > 0 &&
    resource.fd_before >= 0 && resource.fd_after >= 0,
  `${point.id} process replaced or resource sample missing`);
  requireValue(attribution.process.pid === resource.pid_before &&
    attribution.process.start_ticks === resource.start_ticks_before &&
    attribution.process.restarts === 0,
  `${point.id} process evidence disagrees with attribution`);
  const counters = evidence.counters;
  for (const field of ['allocations', 'queue_waits', 'application_cpu_percent',
    'host_cpu_percent', 'irq_cpu_percent']) {
    requireValue(Number.isFinite(counters?.[field]) && counters[field] >= 0,
      `${point.id} ${field} unavailable`);
  }
  requireValue(Array.isArray(counters.shard_cpu_percent) &&
    counters.shard_cpu_percent.length === point.cores &&
    counters.shard_cpu_percent.every((value) => Number.isFinite(value) && value >= 0),
  `${point.id} per-shard CPU unavailable`);
  const shard = attribution.gateway;
  const expectedShards = Array.from({length: point.cores}, (_, index) => String(index));
  const requireShardMap = (value, label) => {
    exactKeys(value, expectedShards, `${point.id} ${label}`);
    return Object.values(value).map((item) => positiveOrZero(item, `${point.id} ${label}`));
  };
  const allocationDelta = requireShardMap(shard?.memory_malloc_operations_by_shard,
    'malloc operations').reduce((sum, value) => sum + value, 0);
  const poolWaitDelta = requireShardMap(shard?.upstream_http1_pool_waits_by_shard,
    'pool waits').reduce((sum, value) => sum + value, 0);
  const busy = requireShardMap(shard?.reactor_cpu_busy_ms_by_shard,
    'reactor CPU').map((milliseconds) =>
    milliseconds / (attribution.duration_seconds * 1000) * 100);
  const host = attribution.host;
  const hostValues = Object.values(host?.cpu_busy_ratio ?? {});
  const irqValues = Object.values(host?.irq_cpu_busy_ratio ?? {});
  requireValue(hostValues.length > 0 && hostValues.length === irqValues.length,
    `${point.id} host or IRQ CPU missing`);
  const average = (values) => values.reduce((sum, value) => sum + value, 0) / values.length;
  const close = (a, b) => Math.abs(a - b) <= 0.1;
  requireValue(counters.allocations === allocationDelta &&
    counters.queue_waits === poolWaitDelta &&
    counters.shard_cpu_percent.every((value, index) => close(value, busy[index])) &&
    close(counters.application_cpu_percent, average(busy)) &&
    close(counters.host_cpu_percent, average(hostValues) * 100) &&
    close(counters.irq_cpu_percent, average(irqValues) * 100),
  `${point.id} counters disagree with native attribution`);
  return {point_id: point.id, successful_rps: rps,
    p50_ms: latency.p50 * 1000, p95_ms: latency.p95 * 1000,
    p99_ms: latency.p99 * 1000, p999_ms: latency['p99.9'] * 1000,
    diagnostic_profiled_warmup_responses: diagnosticWarmupResponses,
    diagnostic_profiled_measurement_responses: diagnosticMeasurementResponses,
    diagnostic_profiled_successful_responses: diagnosticProfiledResponses,
    diagnostic_cycles_per_request: perf.cycles /
      diagnosticProfiledResponses,
    diagnostic_instructions_per_request: perf.instructions /
      diagnosticProfiledResponses,
    diagnostic_syscalls_per_request: perf.syscalls /
      diagnosticProfiledResponses, ipc: perf.ipc};
}

export function packPoint(plan, pointId, captureRoot, resultsRoot, attempt = 1) {
  validatePlan(plan);
  requireValue(Number.isSafeInteger(attempt) && attempt > 0, 'attempt invalid');
  const point = plan.points.find((item) => item.id === pointId);
  requireValue(point, 'point is not in plan');
  verifyCaptureManifest(captureRoot);
  requireValue(fs.readFileSync(path.join(captureRoot, 'source-commit.txt'), 'utf8').trim() ===
    plan.input.harness_commit, 'capture harness commit differs from plan');
  requireValue(fs.readFileSync(path.join(captureRoot, 'snapshot-sha256.txt'),
    'utf8').trim() === plan.input.profiles[point.profile].snapshot_sha256,
  'installed snapshot differs from plan');
  requireValue(fs.readFileSync(path.join(captureRoot, 'credential-sha256.txt'),
    'utf8').trim() === (plan.input.profiles[point.profile].credential_sha256 ?? 'null'),
  'installed credential differs from plan');
  requireValue(fs.readFileSync(path.join(captureRoot, 'client-exit-code.txt'),
    'utf8').trim() === '0', 'capture client failed');
  requireValue(fs.readFileSync(path.join(captureRoot, 'diagnostic-exit-code.txt'),
    'utf8').trim() === '0', 'diagnostic client failed');
  const file = (name) => fileReference(resultsRoot, path.join(captureRoot, name));
  const attribution = JSON.parse(fs.readFileSync(path.join(captureRoot,
    'attribution.json'), 'utf8'));
  const resourceBefore = JSON.parse(fs.readFileSync(path.join(captureRoot,
    'before-resource.json'), 'utf8'));
  const resourceAfter = JSON.parse(fs.readFileSync(path.join(captureRoot,
    'after-resource.json'), 'utf8'));
  const rawNames = {direct_loadgen_before: 'direct-loadgen-proc-before.txt',
    direct_loadgen_after: 'direct-loadgen-proc-after.txt',
    direct_upstream_a_before: 'direct-upstream-a-proc-before.txt',
    direct_upstream_a_after: 'direct-upstream-a-proc-after.txt',
    direct_upstream_b_before: 'direct-upstream-b-proc-before.txt',
    direct_upstream_b_after: 'direct-upstream-b-proc-after.txt',
    gateway_loadgen_before: 'gateway-loadgen-proc-before.txt',
    gateway_loadgen_after: 'gateway-loadgen-proc-after.txt',
    gateway_upstream_a_before: 'gateway-upstream-a-proc-before.txt',
    gateway_upstream_a_after: 'gateway-upstream-a-proc-after.txt',
    gateway_upstream_b_before: 'gateway-upstream-b-proc-before.txt',
    gateway_upstream_b_after: 'gateway-upstream-b-proc-after.txt',
    direct_upstream: 'direct-upstream.oha.json',
    direct_loadgen_host: 'direct-loadgen-host.txt',
    direct_upstream_a_host: 'direct-upstream-a-host.txt',
    direct_upstream_b_host: 'direct-upstream-b-host.txt',
    gateway_loadgen_host: 'gateway-loadgen-host.txt',
    gateway_upstream_a_host: 'gateway-upstream-a-host.txt',
    gateway_upstream_b_host: 'gateway-upstream-b-host.txt',
    direct_source_commit: 'direct-source-commit.txt',
    direct_expected_runner: 'direct-expected-runner-sha256.txt',
    gateway_expected_runner: 'expected-runner-sha256.txt',
    direct_loadgen_source_before: 'direct-loadgen-source-commit-before.txt',
    direct_loadgen_source_after: 'direct-loadgen-source-commit-after.txt',
    direct_loadgen_status_before: 'direct-loadgen-source-status-before.txt',
    direct_loadgen_status_after: 'direct-loadgen-source-status-after.txt',
    direct_loadgen_runner_before: 'direct-loadgen-runner-sha256-before.txt',
    direct_loadgen_runner_after: 'direct-loadgen-runner-sha256-after.txt',
    gateway_loadgen_source_before: 'gateway-loadgen-source-commit-before.txt',
    gateway_loadgen_source_after: 'gateway-loadgen-source-commit-after.txt',
    gateway_loadgen_status_before: 'gateway-loadgen-source-status-before.txt',
    gateway_loadgen_status_after: 'gateway-loadgen-source-status-after.txt',
    gateway_loadgen_runner_before: 'gateway-loadgen-runner-sha256-before.txt',
    gateway_loadgen_runner_after: 'gateway-loadgen-runner-sha256-after.txt'};
  const support = supportFromRaw(plan, (name) =>
    fs.readFileSync(path.join(captureRoot, rawNames[name]), 'utf8'));
  const supportPath = path.join(captureRoot, 'support.json');
  requireValue(!fs.existsSync(supportPath), 'support summary already exists');
  fs.writeFileSync(supportPath, `${JSON.stringify(support, null, 2)}\n`, {mode: 0o600});
  const perShard = Object.entries(attribution.gateway.reactor_cpu_busy_ms_by_shard)
    .sort(([left], [right]) => Number(left) - Number(right))
    .map(([, value]) => value / (attribution.duration_seconds * 1000) * 100);
  const average = (values) => values.reduce((sum, value) => sum + value, 0) / values.length;
  const counters = {
    allocations: Object.values(attribution.gateway.memory_malloc_operations_by_shard)
      .reduce((sum, value) => sum + value, 0),
    queue_waits: Object.values(attribution.gateway.upstream_http1_pool_waits_by_shard)
      .reduce((sum, value) => sum + value, 0),
    application_cpu_percent: average(perShard),
    host_cpu_percent: average(Object.values(attribution.host.cpu_busy_ratio)) * 100,
    irq_cpu_percent: average(Object.values(attribution.host.irq_cpu_busy_ratio)) * 100,
    shard_cpu_percent: perShard,
  };
  const resource = {restart_count: resourceAfter.restart_count,
    pid_before: resourceBefore.pid, pid_after: resourceAfter.pid,
    start_ticks_before: resourceBefore.start_ticks,
    start_ticks_after: resourceAfter.start_ticks,
    rss_before_bytes: resourceBefore.rss_bytes,
    rss_after_bytes: resourceAfter.rss_bytes,
    fd_before: resourceBefore.fd, fd_after: resourceAfter.fd};
  const result = {plan_id: plan.plan_id, point_id: point.id, attempt,
    accepted: true, binary_source_commit: plan.input.binary_source_commit,
    harness_commit: plan.input.harness_commit,
    source_dirty: false, binary_sha256: plan.input.binary_sha256,
    client_sha256: plan.input.client_sha256,
    upstream_sha256: plan.input.upstream_sha256,
    snapshot_sha256: plan.input.profiles[point.profile].snapshot_sha256,
    files: {oha: file('oha.json'),
      diagnostic_oha: file('diagnostic.oha.json'),
      diagnostic_after: file('diagnostic-after/snapshot.json'),
      perf: file('perf.csv'),
      attribution: file('attribution.json'), support: file('support.json'),
      snapshot_digest: file('snapshot-sha256.txt'),
      credential_digest: file('credential-sha256.txt'),
      resource_before: file('before-resource.json'),
      resource_after: file('after-resource.json'),
      ...Object.fromEntries(Object.entries(rawNames).map(([key, name]) =>
        [key, file(name)]))},
    support, resource, counters};
  evaluatePoint(plan, point, result, resultsRoot);
  return result;
}

function positiveOrZero(value, label) {
  requireValue(Number.isFinite(value) && value >= 0, `${label} must be nonnegative`);
  return value;
}

export function analyze(plan, evidenceRoot) {
  validatePlan(plan);
  const files = fs.readdirSync(evidenceRoot).filter((name) => name.endsWith('.result.json'));
  const expected = new Map(plan.points.map((point) => [point.id, point]));
  const accepted = new Map();
  const attempts = [];
  for (const name of files) {
    const file = path.join(evidenceRoot, name);
    requireValue(fs.lstatSync(file).isFile(), `${name} is not a regular file`);
    const result = JSON.parse(fs.readFileSync(file, 'utf8'));
    const point = expected.get(result.point_id);
    requireValue(point, `${name} is outside the plan`);
    requireValue(result.plan_id === plan.plan_id, `${name} plan mismatch`);
    requireValue(Number.isSafeInteger(result.attempt) && result.attempt > 0,
      `${name} attempt invalid`);
    const attemptKey = `${result.point_id}:${result.attempt}`;
    requireValue(!attempts.includes(attemptKey), `${name} duplicate attempt`);
    attempts.push(attemptKey);
    if (result.accepted === false) continue;
    requireValue(!accepted.has(result.point_id), `${name} duplicate accepted point`);
    accepted.set(result.point_id, evaluatePoint(plan, point, result, evidenceRoot));
  }
  requireValue(accepted.size === expected.size,
    `missing accepted PERF-01 points: ${expected.size - accepted.size}`);
  const rows = [...accepted.values()];
  const loadPoints = plan.schema_version === 7 ?
    LEGACY_LOAD_POINTS : STEADY_LOAD_POINTS;
  for (const profile of PROFILE_IDS) for (const cores of CORE_COUNTS) {
    for (const load of loadPoints) {
      const points = plan.points.filter((point) => point.profile === profile &&
        point.cores === cores && point.load === load);
      const rates = points.map((point) => accepted.get(point.id).successful_rps);
      const mean = rates.reduce((sum, rate) => sum + rate, 0) / rates.length;
      requireValue((Math.max(...rates) - Math.min(...rates)) / mean <= 0.05,
        `${profile}/${cores}/${load} variation exceeds 5%`);
    }
  }
  return {schema_version: 1, evidence_class: plan.input.evidence_class,
    plan_id: plan.plan_id,
    binary_source_commit: plan.input.binary_source_commit,
    harness_commit: plan.input.harness_commit,
    accepted_points: rows.length, attempts: attempts.length, rows};
}

function option(args, name) {
  const index = args.indexOf(name);
  requireValue(index >= 0 && args[index + 1], `missing ${name}`);
  return args[index + 1];
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const [, , command, ...args] = process.argv;
    if (command === 'plan') {
      const input = JSON.parse(fs.readFileSync(option(args, '--input'), 'utf8'));
      process.stdout.write(`${JSON.stringify(buildPlan(input), null, 2)}\n`);
    } else if (command === 'analyze') {
      const plan = JSON.parse(fs.readFileSync(option(args, '--plan'), 'utf8'));
      const result = analyze(plan, option(args, '--results'));
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else if (command === 'pack') {
      const plan = JSON.parse(fs.readFileSync(option(args, '--plan'), 'utf8'));
      const result = packPoint(plan, option(args, '--point'),
        option(args, '--capture'), option(args, '--results'),
        Number(option(args, '--attempt')));
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      throw new Error('usage: phase5-baseline.mjs plan --input FILE | analyze --plan FILE --results DIR');
    }
  } catch (error) {
    process.stderr.write(`phase5-baseline: ${error.message}\n`);
    process.exitCode = 1;
  }
}
