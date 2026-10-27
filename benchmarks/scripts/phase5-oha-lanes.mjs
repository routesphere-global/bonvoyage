#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
import path from 'node:path';

const KIND = 'phase5-oha-lanes';
const SEQUENCE_KIND = 'phase5-oha-sequence';
const PERCENTILES = ['p50', 'p95', 'p99', 'p99.9'];
const SHA256 = /^[0-9a-f]{64}$/u;
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9a-z-]+$/u;
const FORBIDDEN_REQUEST_HEADERS = new Set([
  'connection', 'content-length', 'expect', 'host', 'keep-alive',
  'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade',
]);
const CLOCKSOURCE_ROOT = '/sys/devices/system/clocksource/clocksource0';
const TSC_CAPABILITY_FLAGS = ['tsc', 'rdtscp', 'constant_tsc',
  'nonstop_tsc', 'tsc_known_freq'];
export const OHA_LANE_MEMORY_BYTES = 4 * 1024 ** 3;
export const OHA_DIRECT_LANES = 32;
export const OHA_DIRECT_LANE_MEMORY_BYTES = 1536 * 1024 ** 2;

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function positive(value, label) {
  requireValue(Number.isFinite(value) && value > 0, `${label} must be positive`);
  return value;
}

function count(value, label) {
  requireValue(Number.isSafeInteger(value) && value >= 0, `${label} must be a count`);
  return value;
}

function exactKeys(object, expected, label) {
  requireValue(object && typeof object === 'object' && !Array.isArray(object),
    `${label} must be an object`);
  requireValue(JSON.stringify(Object.keys(object).sort()) ===
    JSON.stringify([...expected].sort()), `${label} has missing or unexpected keys`);
}

function validateClockIdentity(value, label) {
  exactKeys(value, ['current_clocksource', 'available_clocksources',
    'tsc_capabilities'], label);
  requireValue(typeof value.current_clocksource === 'string' &&
    value.current_clocksource.length > 0 &&
    Array.isArray(value.available_clocksources) &&
    value.available_clocksources.includes(value.current_clocksource),
  `${label} current clocksource is invalid`);
  exactKeys(value.tsc_capabilities, TSC_CAPABILITY_FLAGS,
    `${label} TSC capabilities`);
  requireValue(TSC_CAPABILITY_FLAGS.every((name) =>
    typeof value.tsc_capabilities[name] === 'boolean'),
  `${label} TSC capabilities are invalid`);
  return value;
}

function validateClockWindow(value, label) {
  exactKeys(value, ['before', 'after'], label);
  const before = validateClockIdentity(value.before, `${label} before`);
  const after = validateClockIdentity(value.after, `${label} after`);
  requireValue(JSON.stringify(before) === JSON.stringify(after),
    `${label} changed during measurement`);
  return before;
}

function capturePlatformClockIdentity() {
  if (process.platform !== 'linux') {
    const name = `${process.platform}-monotonic`;
    return validateClockIdentity({current_clocksource: name,
      available_clocksources: [name],
      tsc_capabilities: Object.fromEntries(TSC_CAPABILITY_FLAGS.map((flag) =>
        [flag, false]))}, 'captured load-generator clock');
  }
  const current = fs.readFileSync(path.join(CLOCKSOURCE_ROOT,
    'current_clocksource'), 'utf8').trim();
  const available = fs.readFileSync(path.join(CLOCKSOURCE_ROOT,
    'available_clocksource'), 'utf8').trim().split(/\s+/u);
  const cpuinfo = fs.readFileSync('/proc/cpuinfo', 'utf8');
  const flagsLine = cpuinfo.split(/\r?\n/u).find((line) =>
    /^\s*(?:flags|Features)\s*:/u.test(line));
  requireValue(flagsLine !== undefined, 'CPU capability flags are unavailable');
  const flags = new Set(flagsLine.split(':', 2)[1].trim().split(/\s+/u));
  return validateClockIdentity({current_clocksource: current,
    available_clocksources: available,
    tsc_capabilities: Object.fromEntries(TSC_CAPABILITY_FLAGS.map((name) =>
      [name, flags.has(name)]))}, 'captured load-generator clock');
}

function addCounts(target, source, label) {
  requireValue(source && typeof source === 'object' && !Array.isArray(source),
    `${label} is missing`);
  for (const [key, value] of Object.entries(source)) {
    const sum = (target[key] ?? 0) + count(value, `${label} ${key}`);
    target[key] = count(sum, `${label} ${key} sum`);
  }
}

function cpuList(spec) {
  requireValue(typeof spec === 'string' && /^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$/u.test(spec),
    'CPU set must be a comma-separated list or ranges');
  const cpus = [];
  for (const range of spec.split(',')) {
    const [first, last = first] = range.split('-').map(Number);
    requireValue(Number.isSafeInteger(first) && Number.isSafeInteger(last) &&
      first <= last && last - first < 4096, 'CPU range invalid');
    for (let cpu = first; cpu <= last; cpu += 1) cpus.push(cpu);
  }
  requireValue(new Set(cpus).size === cpus.length, 'CPU set overlaps');
  return cpus;
}

export function partitionCpus(spec, lanes, maxLanes = 16) {
  const cpus = cpuList(spec);
  requireValue([16, 32].includes(maxLanes), 'lane limit is invalid');
  requireValue(Number.isSafeInteger(lanes) && lanes >= 2 && lanes <= maxLanes &&
    cpus.length >= lanes, 'lane count exceeds available CPUs');
  return Array.from({length: lanes}, (_, index) => {
    const first = Math.floor(index * cpus.length / lanes);
    const last = Math.floor((index + 1) * cpus.length / lanes);
    return cpus.slice(first, last).join(',');
  });
}

export function validateWorkload(workload) {
  exactKeys(workload, ['request_mode', 'client_sha256', 'protocol', 'tls',
    'authority', 'listener_port', 'target_addresses', 'path',
    'connections_per_lane', 'streams_per_connection', 'requests_per_lane',
    'memory_limit_bytes',
    'ca_sha256', 'credential_sha256', 'method', 'keepalive', 'compression',
    'latency_correction', 'request_timeout_seconds', 'connect_timeout_seconds',
    'redirect_limit'], 'workload');
  requireValue(workload.request_mode === 'fixed-count', 'request mode must be fixed-count');
  requireValue(SHA256.test(workload.client_sha256), 'client identity must be a SHA-256 digest');
  requireValue(['http1', 'http2'].includes(workload.protocol), 'protocol invalid');
  requireValue(typeof workload.tls === 'boolean', 'TLS flag invalid');
  requireValue(typeof workload.authority === 'string' &&
    /^[a-zA-Z0-9.-]+$/u.test(workload.authority), 'authority invalid');
  requireValue(Number.isSafeInteger(workload.listener_port) &&
    workload.listener_port > 0 && workload.listener_port <= 65535,
  'listener port invalid');
  requireValue(Array.isArray(workload.target_addresses) &&
    [1, 2].includes(workload.target_addresses.length) &&
    new Set(workload.target_addresses).size === workload.target_addresses.length &&
    workload.target_addresses.every((address) => typeof address === 'string' &&
      /^[a-zA-Z0-9.-]+$/u.test(address)), 'target addresses invalid');
  requireValue(typeof workload.path === 'string' && workload.path.startsWith('/') &&
    !workload.path.includes('?') && !workload.path.includes('#'), 'path invalid');
  for (const name of ['connections_per_lane', 'streams_per_connection',
    'requests_per_lane']) {
    requireValue(Number.isSafeInteger(workload[name]) && workload[name] > 0,
      `${name} invalid`);
  }
  requireValue(workload.memory_limit_bytes === OHA_LANE_MEMORY_BYTES,
    'client memory limit changed');
  requireValue(workload.protocol === 'http2' || workload.streams_per_connection === 1,
    'HTTP/1 streams must equal one');
  if (workload.tls) requireValue(SHA256.test(workload.ca_sha256), 'CA identity invalid');
  else requireValue(workload.ca_sha256 === null, 'cleartext CA identity must be null');
  requireValue(workload.credential_sha256 === null ||
    SHA256.test(workload.credential_sha256), 'credential identity invalid');
  requireValue(workload.method === 'GET' && workload.keepalive === true &&
    workload.compression === false && workload.latency_correction === true &&
    workload.request_timeout_seconds === 5 &&
    workload.connect_timeout_seconds === 5 && workload.redirect_limit === 0,
  'fixed client behavior changed');
  return workload;
}

function validatePolicyWorkload(workload) {
  exactKeys(workload, ['request_mode', 'client_sha256', 'protocol', 'tls',
    'authority', 'listener_port', 'target_addresses', 'path',
    'connections_per_lane', 'streams_per_connection', 'requests_per_lane',
    'memory_limit_bytes', 'ca_sha256', 'credential_sha256', 'method',
    'keepalive', 'compression', 'latency_correction',
    'request_timeout_seconds', 'connect_timeout_seconds', 'redirect_limit',
    'request_headers_sha256', 'request_header_names'], 'policy workload');
  const base = {...workload};
  delete base.request_headers_sha256;
  delete base.request_header_names;
  validateWorkload(base);
  requireValue(SHA256.test(workload.request_headers_sha256),
    'request header identity must be a SHA-256 digest');
  requireValue(Array.isArray(workload.request_header_names) &&
    workload.request_header_names.length > 0 &&
    workload.request_header_names.length <= 16 &&
    new Set(workload.request_header_names).size ===
      workload.request_header_names.length &&
    JSON.stringify(workload.request_header_names) ===
      JSON.stringify([...workload.request_header_names].sort()) &&
    workload.request_header_names.every((name) => HEADER_NAME.test(name) &&
      !FORBIDDEN_REQUEST_HEADERS.has(name)),
  'request header names must be unique, sorted, lowercase, bounded, and safe');
  requireValue(workload.credential_sha256 === null,
    'policy workload cannot combine generic headers with an API-key file');
  return workload;
}

function validateWorkloadForSchema(workload, schemaVersion) {
  if (schemaVersion === 2) return validateWorkload(workload);
  if (schemaVersion === 4) return validatePolicyWorkload(workload);
  if (schemaVersion === 3) {
    exactKeys(workload, ['evidence_scope', 'request_mode', 'client_sha256',
      'protocol', 'tls', 'authority', 'listener_port', 'target_addresses', 'path',
      'connections_per_lane', 'streams_per_connection', 'requests_per_lane',
      'memory_limit_bytes', 'memory_swap_limit_bytes', 'ca_sha256',
      'credential_sha256', 'method', 'keepalive', 'compression', 'latency_correction',
      'request_timeout_seconds', 'connect_timeout_seconds', 'redirect_limit'],
    'direct-support workload');
    requireValue(workload.evidence_scope === 'direct-support',
      'direct-support evidence scope invalid');
    const rest = {...workload};
    delete rest.evidence_scope;
    delete rest.memory_swap_limit_bytes;
    const validated = validateWorkload({...rest,
      memory_limit_bytes: OHA_LANE_MEMORY_BYTES});
    requireValue(workload.memory_limit_bytes === OHA_DIRECT_LANE_MEMORY_BYTES,
      'direct-support client memory limit changed');
    requireValue(workload.memory_swap_limit_bytes === OHA_DIRECT_LANE_MEMORY_BYTES,
      'direct-support client memory/swap limit changed');
    requireValue(workload.protocol === 'http1' && workload.tls === false &&
      workload.target_addresses.length === 2 &&
      workload.credential_sha256 === null,
    'direct-support workload shape changed');
    return {...validated, evidence_scope: workload.evidence_scope,
      memory_limit_bytes: workload.memory_limit_bytes,
      memory_swap_limit_bytes: workload.memory_swap_limit_bytes};
  }
  exactKeys(workload, ['request_mode', 'client_sha256', 'protocol', 'tls',
    'authority', 'listener_port', 'gateway_address', 'path',
    'connections_per_lane', 'streams_per_connection', 'requests_per_lane',
    'memory_limit_bytes', 'ca_sha256', 'credential_sha256', 'method',
    'keepalive', 'compression', 'latency_correction',
    'request_timeout_seconds', 'connect_timeout_seconds', 'redirect_limit'],
  'legacy workload');
  const {gateway_address: gatewayAddress, ...rest} = workload;
  return validateWorkload({...rest, target_addresses: [gatewayAddress]});
}

export function parseOhaReport(raw) {
  const input = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (input?.kind !== KIND) return input;
  const maxLanes = [1, 3].includes(input.schema_version) ? 32 : 16;
  requireValue([1, 2, 3, 4].includes(input.schema_version) &&
    Array.isArray(input.lanes) &&
    input.lanes.length >= 2 && input.lanes.length <= maxLanes,
  'multi-lane bundle is invalid');
  const rate = count(input.rate_per_lane, 'rate per lane');
  requireValue(rate > 0 && Array.isArray(input.cpu_sets) &&
    input.cpu_sets.length === input.lanes.length, 'multi-lane placement is invalid');
  const allCpus = input.cpu_sets.flatMap((set) => cpuList(set));
  requireValue(new Set(allCpus).size === allCpus.length &&
    input.cpu_sets.every((set) => cpuList(set).length > 0),
  'multi-lane CPU sets overlap or are empty');
  const workload = input.workload === undefined ? undefined :
    validateWorkloadForSchema(input.workload, input.schema_version);
  const clock = input.clock === undefined ? undefined :
    validateClockWindow(input.clock, 'load-generator clock');
  if (workload !== undefined) {
    if ([2, 3, 4].includes(input.schema_version)) {
      requireValue(input.lanes.length % workload.target_addresses.length === 0,
        'structured multi-lane target topology is invalid');
    }
    if (input.schema_version === 3) {
      requireValue(input.lanes.length === OHA_DIRECT_LANES &&
        input.cpu_sets.every((set) => cpuList(set).length === 1),
      'direct-support evidence requires 32 one-core lanes');
    }
    const keys = ['kind', 'schema_version', 'rate_per_lane', 'cpu_sets',
      'workload', 'lanes'];
    if (clock !== undefined) keys.push('clock');
    exactKeys(input, keys, 'structured multi-lane bundle');
  }
  const offeredRps = count(rate * input.lanes.length, 'aggregate offered RPS');
  const starts = [];
  const ends = [];
  const statuses = {};
  const errors = {};
  const latency = Object.fromEntries(PERCENTILES.map((name) => [name, 0]));
  let totalRequests = 0;
  let successfulRps = 0;
  const durations = [];
  for (const [index, lane] of input.lanes.entries()) {
    if (workload !== undefined) {
      const laneKeys = ['index', 'start_ns', 'end_ns', 'exit_code', 'raw_json',
        'stderr'];
      if ([2, 3, 4].includes(input.schema_version)) laneKeys.push('target_address');
      exactKeys(lane, laneKeys, `lane ${index}`);
      if ([2, 3, 4].includes(input.schema_version)) {
        requireValue(lane.target_address ===
          workload.target_addresses[index % workload.target_addresses.length],
        `lane ${index} target differs from workload`);
      }
    }
    requireValue(lane.index === index && lane.exit_code === 0 &&
      typeof lane.raw_json === 'string', `lane ${index} failed or is missing`);
  }
  for (const [index, lane] of input.lanes.entries()) {
    const start = BigInt(lane.start_ns);
    const end = BigInt(lane.end_ns);
    requireValue(start >= 0n && end > start, `lane ${index} clock invalid`);
    starts.push(start);
    ends.push(end);
    const report = JSON.parse(lane.raw_json);
    requireValue(![KIND, SEQUENCE_KIND].includes(report?.kind),
      'nested multi-lane bundle forbidden');
    const duration = positive(report.summary?.total, `lane ${index} duration`);
    const wall = Number(end - start) / 1e9;
    requireValue(wall >= duration * 0.95 && wall <= duration * 1.1 + 0.5,
      `lane ${index} wall duration disagrees with client`);
    durations.push(duration);
    addCounts(statuses, report.statusCodeDistribution, `lane ${index} status`);
    addCounts(errors, report.errorDistribution ?? {}, `lane ${index} error`);
    const laneResponses = Object.values(report.statusCodeDistribution).reduce(
      (sum, value) => sum + value, 0);
    const laneErrors = Object.values(report.errorDistribution ?? {}).reduce(
      (sum, value) => sum + value, 0);
    const laneSuccesses = count(report.statusCodeDistribution?.['200'] ?? 0,
      `lane ${index} HTTP 200 count`);
    successfulRps += laneSuccesses / duration;
    if (workload !== undefined) {
      requireValue(laneResponses + laneErrors === workload.requests_per_lane,
        `lane ${index} fixed request count differs from workload`);
    }
    for (const name of PERCENTILES) {
      latency[name] = Math.max(latency[name],
        positive(report.latencyPercentiles?.[name], `lane ${index} ${name}`));
    }
    totalRequests += laneResponses;
    count(totalRequests, 'total requests');
  }
  requireValue(totalRequests > 0, 'multi-lane bundle has no responses');
  const earliest = starts.reduce((a, b) => a < b ? a : b);
  const latest = ends.reduce((a, b) => a > b ? a : b);
  const overlapStart = starts.reduce((a, b) => a > b ? a : b);
  const overlapEnd = ends.reduce((a, b) => a < b ? a : b);
  const envelope = Number(latest - earliest) / 1e9;
  const overlap = Number(overlapEnd - overlapStart) / 1e9;
  requireValue(overlapEnd > overlapStart && overlap >= envelope * 0.95 &&
    durations.every((duration) => duration >= envelope * 0.95),
  `multi-lane windows insufficiently aligned: overlap=${overlap}, ` +
    `envelope=${envelope}, durations=${durations.join(',')}`);
  return {summary: {total: envelope},
    active_measurement_seconds: Math.max(...durations),
    successful_rps: successfulRps,
    statusCodeDistribution: statuses,
    errorDistribution: errors, latencyPercentiles: latency,
    offered_rps: offeredRps, rate_per_lane: rate,
    client_lanes: input.lanes.length, client_cpu_sets: input.cpu_sets,
    ...(workload === undefined ? {} : {workload}),
    ...(clock === undefined ? {} : {clock})};
}

function successful(report, label) {
  requireValue(Object.keys(report.statusCodeDistribution ?? {}).length === 1 &&
    Number.isSafeInteger(report.statusCodeDistribution?.['200']) &&
    report.statusCodeDistribution['200'] > 0 &&
    Object.values(report.errorDistribution ?? {}).reduce((sum, value) => sum + value, 0) === 0,
  `${label} includes non-200 responses or transport errors`);
}

export function parseOhaSequence(raw) {
  const input = typeof raw === 'string' ? JSON.parse(raw) : raw;
  exactKeys(input, ['kind', 'schema_version', 'warmup', 'measurement'],
    'client sequence');
  requireValue(input.kind === SEQUENCE_KIND &&
    [1, 2, 3, 4].includes(input.schema_version),
    'client sequence is invalid');
  const warmup = parseOhaReport(input.warmup);
  const measurement = parseOhaReport(input.measurement);
  requireValue(input.warmup.schema_version === input.schema_version &&
    input.measurement.schema_version === input.schema_version,
  'client sequence schema differs between stages');
  requireValue(warmup.workload && measurement.workload,
    'client sequence requires structured workloads');
  requireValue((warmup.clock === undefined) === (measurement.clock === undefined),
    'client sequence clock evidence availability changed');
  if (warmup.clock !== undefined) {
    requireValue(JSON.stringify(warmup.clock) === JSON.stringify(measurement.clock),
      'client sequence clock identity changed');
  }
  const warmupShape = {...warmup.workload};
  const measurementShape = {...measurement.workload};
  delete warmupShape.requests_per_lane;
  delete measurementShape.requests_per_lane;
  requireValue(JSON.stringify(warmupShape) === JSON.stringify(measurementShape) &&
    warmup.rate_per_lane === measurement.rate_per_lane &&
    JSON.stringify(warmup.client_cpu_sets) === JSON.stringify(measurement.client_cpu_sets) &&
    warmup.client_lanes === measurement.client_lanes,
  'warmup and measurement workload shapes differ');
  requireValue(warmup.workload.requests_per_lane <
    measurement.workload.requests_per_lane,
  'warmup request count must be smaller than measurement');
  successful(warmup, 'warmup');
  return {schema_version: input.schema_version, warmup, measurement};
}

function scrub(value, redactions) {
  return redactions.reduce((result, secret) => result.replaceAll(secret, '[REDACTED]'), value);
}

function runLane(index, command, args, redactions = []) {
  return new Promise((resolve) => {
    const start = process.hrtime.bigint();
    const child = spawn(command, args, {stdio: ['ignore', 'pipe', 'pipe']});
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; if (stdout.length > 1048576) child.kill(); });
    child.stderr.on('data', (chunk) => { stderr += chunk; if (stderr.length > 1048576) child.kill(); });
    child.on('error', (error) => { stderr += error.message; });
    child.on('close', (code) => resolve({index, start_ns: start.toString(),
      end_ns: process.hrtime.bigint().toString(), exit_code: code,
      raw_json: scrub(stdout, redactions), stderr: scrub(stderr, redactions)}));
  });
}

function optionMap(args, allowed, required) {
  requireValue(args.length % 2 === 0, 'options require name/value pairs');
  const result = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    requireValue(allowed.includes(name) && !result.has(name) && args[index + 1],
      `invalid or repeated option: ${name}`);
    result.set(name, args[index + 1]);
  }
  for (const name of required) requireValue(result.has(name), `missing ${name}`);
  return result;
}

function integerOption(options, name) {
  const value = Number(options.get(name));
  requireValue(Number.isSafeInteger(value) && value > 0, `${name} invalid`);
  return value;
}

function boundFile(filename, label) {
  const absolute = path.resolve(filename);
  const stat = fs.lstatSync(absolute);
  requireValue(stat.isFile() && !stat.isSymbolicLink(), `${label} must be a regular file`);
  const bytes = fs.readFileSync(absolute);
  return {absolute, bytes, sha256: createHash('sha256').update(bytes).digest('hex')};
}

export function buildOhaRun(args, evidenceScope = 'gateway') {
  requireValue(['gateway', 'direct-support'].includes(evidenceScope),
    'evidence scope invalid');
  const allowed = ['--lanes', '--rate-per-lane', '--requests-per-lane',
    '--warmup-requests-per-lane',
    '--connections-per-lane', '--streams-per-connection', '--cpu-set', '--image',
    '--protocol', '--url', '--target-addresses', '--ca-file', '--credential-file',
    '--request-headers-file'];
  const required = allowed.filter((name) =>
    !['--warmup-requests-per-lane', '--ca-file', '--credential-file',
      '--request-headers-file'].includes(name));
  const options = optionMap(args, allowed, required);
  const lanes = integerOption(options, '--lanes');
  const rate = integerOption(options, '--rate-per-lane');
  const requests = integerOption(options, '--requests-per-lane');
  const warmupRequests = options.has('--warmup-requests-per-lane') ?
    integerOption(options, '--warmup-requests-per-lane') : null;
  requireValue(warmupRequests === null || warmupRequests < requests,
    'warmup requests must be fewer than measurement requests');
  const connections = integerOption(options, '--connections-per-lane');
  const streams = integerOption(options, '--streams-per-connection');
  const directSupport = evidenceScope === 'direct-support';
  if (directSupport) requireValue(lanes === OHA_DIRECT_LANES,
    'direct-support evidence requires 32 lanes');
  const sets = partitionCpus(options.get('--cpu-set'), lanes,
    directSupport ? OHA_DIRECT_LANES : 16);
  if (directSupport) requireValue(sets.every((set) => cpuList(set).length === 1),
    'direct-support evidence requires one CPU per lane');
  const image = options.get('--image');
  const imageMatch = /^\S+@sha256:([0-9a-f]{64})$/u.exec(image);
  requireValue(imageMatch, 'client image must be pinned by SHA-256 digest');
  const protocol = options.get('--protocol');
  requireValue(['http1', 'http2'].includes(protocol), 'protocol invalid');
  requireValue(protocol === 'http2' || streams === 1, 'HTTP/1 streams must equal one');
  const target = new URL(options.get('--url'));
  requireValue(['http:', 'https:'].includes(target.protocol) && !target.username &&
    !target.password && !target.search && !target.hash && target.port,
  'URL must use HTTP(S), an explicit port, and no credentials, query, or fragment');
  const tls = target.protocol === 'https:';
  const authority = target.hostname;
  const listenerPort = Number(target.port);
  const targetAddresses = options.get('--target-addresses').split(',');
  requireValue([1, 2].includes(targetAddresses.length) &&
    new Set(targetAddresses).size === targetAddresses.length &&
    targetAddresses.every((address) => /^[a-zA-Z0-9.-]+$/u.test(address)) &&
    lanes % targetAddresses.length === 0, 'target addresses invalid for lane count');
  const ca = options.has('--ca-file') ? boundFile(options.get('--ca-file'), 'CA file') : null;
  requireValue(tls === Boolean(ca), 'TLS workloads require one CA file; cleartext forbids it');
  if (ca) requireValue((fs.statSync(ca.absolute).mode & 0o004) !== 0,
    'CA file must be world-readable by the pinned load-client container');
  const credential = options.has('--credential-file') ?
    boundFile(options.get('--credential-file'), 'credential file') : null;
  const requestHeadersFile = options.has('--request-headers-file') ?
    boundFile(options.get('--request-headers-file'), 'request headers file') : null;
  requireValue(!(credential && requestHeadersFile),
    'API-key and generic request-header files are mutually exclusive');
  let secret = null;
  if (credential) {
    const lines = credential.bytes.toString('utf8').split(/\r?\n/u).filter(Boolean);
    requireValue(lines.length === 1 && lines[0].trim() === lines[0] &&
      lines[0].length >= 16 && lines[0].length <= 4096,
    'credential file must contain exactly one bounded API key');
    [secret] = lines;
  }
  let requestHeaders = [];
  if (requestHeadersFile) {
    let parsed;
    try {
      parsed = JSON.parse(requestHeadersFile.bytes.toString('utf8'));
    } catch {
      throw new Error('request headers file must contain one JSON object');
    }
    requireValue(parsed && typeof parsed === 'object' && !Array.isArray(parsed),
      'request headers file must contain one JSON object');
    const entries = Object.entries(parsed);
    requireValue(entries.length > 0 && entries.length <= 16,
      'request headers file must contain between one and sixteen headers');
    requestHeaders = entries.map(([name, value]) => {
      requireValue(HEADER_NAME.test(name) && !FORBIDDEN_REQUEST_HEADERS.has(name),
        `request header name is unsafe or not lowercase: ${name}`);
      requireValue(typeof value === 'string' && value.length > 0 &&
        Buffer.byteLength(value) <= 4096 && !/[\u0000-\u001f\u007f]/u.test(value),
      `request header value is invalid: ${name}`);
      return [name, value];
    }).sort(([left], [right]) => left.localeCompare(right));
    requireValue(requestHeaders.reduce((sum, [name, value]) =>
      sum + Buffer.byteLength(name) + Buffer.byteLength(value), 0) <= 16384,
    'request headers exceed the 16 KiB client bound');
  }
  if (directSupport) requireValue(protocol === 'http1' && !tls &&
    targetAddresses.length === 2 && !credential && !requestHeadersFile,
  'direct-support evidence requires cleartext HTTP/1.1, two targets, and no credentials');
  const memoryLimitBytes = directSupport ? OHA_DIRECT_LANE_MEMORY_BYTES :
    OHA_LANE_MEMORY_BYTES;
  const workloadInput = {request_mode: 'fixed-count',
    client_sha256: imageMatch[1], protocol, tls, authority,
    listener_port: listenerPort, target_addresses: targetAddresses,
    path: target.pathname, connections_per_lane: connections,
    streams_per_connection: streams, requests_per_lane: requests,
    memory_limit_bytes: memoryLimitBytes,
    ca_sha256: ca?.sha256 ?? null, credential_sha256: credential?.sha256 ?? null,
    method: 'GET', keepalive: true, compression: false,
    latency_correction: true, request_timeout_seconds: 5,
    connect_timeout_seconds: 5, redirect_limit: 0};
  const policyInput = requestHeadersFile ? {...workloadInput,
    request_headers_sha256: requestHeadersFile.sha256,
    request_header_names: requestHeaders.map(([name]) => name)} : null;
  const workload = directSupport ? validateWorkloadForSchema(
    {evidence_scope: evidenceScope, ...workloadInput,
      memory_swap_limit_bytes: memoryLimitBytes}, 3) :
    policyInput ? validatePolicyWorkload(policyInput) : validateWorkload(workloadInput);
  const invocationsFor = (requestCount) => sets.map((cpus, index) => {
    const targetAddress = targetAddresses[index % targetAddresses.length];
    const docker = ['docker', 'run', '--rm', '--network', 'host',
      '--cpuset-cpus', cpus, '--memory', `${memoryLimitBytes}b`,
      '--pids-limit', '1024'];
    if (directSupport) docker.push('--memory-swap', `${memoryLimitBytes}b`);
    if (ca) docker.push('--volume', `${ca.absolute}:/bonvoyage/ca.pem:ro`);
    docker.push(image, '-n', String(requestCount), '-c', String(connections),
      '-q', String(rate), '--latency-correction', '--http-version',
      protocol === 'http2' ? '2' : '1.1', '--disable-compression',
      '--no-tui', '--no-color', '--output-format', 'json', '--redirect', '0',
      '--connect-timeout', '5s', '-t', '5s', '--connect-to',
      `${authority}:${listenerPort}:${targetAddress}:${listenerPort}`);
    if (protocol === 'http2') docker.push('-p', String(streams));
    if (ca) docker.push('--cacert', '/bonvoyage/ca.pem');
    if (secret) docker.push('-H', `X-API-Key: ${secret}`);
    for (const [name, value] of requestHeaders) docker.push('-H', `${name}: ${value}`);
    docker.push(target.toString());
    return {command: 'sudo', args: docker, targetAddress};
  });
  const warmupWorkload = warmupRequests === null ? null :
    {...workload, requests_per_lane: warmupRequests};
  return {schemaVersion: directSupport ? 3 : requestHeadersFile ? 4 : 2,
    rate, sets, workload,
    invocations: invocationsFor(requests),
    warmupWorkload,
    warmupInvocations: warmupRequests === null ? null : invocationsFor(warmupRequests),
    redactions: [...new Set([
      ...(secret ? [secret] : []), ...requestHeaders.map(([, value]) => value),
    ])].sort((left, right) => right.length - left.length)};
}

async function runGeneric(args) {
  const separator = args.indexOf('--');
  requireValue(separator >= 0 && args.length > separator + 1,
    'client command is required after --');
  const options = optionMap(args.slice(0, separator),
    ['--lanes', '--rate-per-lane', '--cpu-set'],
    ['--lanes', '--rate-per-lane', '--cpu-set']);
  const lanes = integerOption(options, '--lanes');
  const rate = integerOption(options, '--rate-per-lane');
  const sets = partitionCpus(options.get('--cpu-set'), lanes, 32);
  const [command, ...template] = args.slice(separator + 1);
  requireValue(template.filter((arg) => arg === '{rate}').length === 1 &&
    template.filter((arg) => arg === '{cpus}').length === 1,
  'client command needs one {rate} and one {cpus} argument');
  const results = await Promise.all(sets.map((cpus, index) => runLane(index,
    command, template.map((arg) => arg === '{rate}' ? String(rate) :
      arg === '{cpus}' ? cpus : arg === '{lane}' ? String(index) : arg))));
  return {kind: KIND, schema_version: 1, rate_per_lane: rate,
    cpu_sets: sets, lanes: results};
}

async function runStructuredLanes(invocations, redactions) {
  const before = capturePlatformClockIdentity();
  const lanes = await Promise.all(invocations.map((invocation, index) =>
    runLane(index, invocation.command, invocation.args, redactions).then((lane) =>
      ({...lane, target_address: invocation.targetAddress}))));
  const after = capturePlatformClockIdentity();
  return {lanes, clock: {before, after}};
}

async function main() {
  const [, , mode, ...args] = process.argv;
  let bundle;
  try {
    if (mode === 'run') {
      bundle = await runGeneric(args);
    } else if (mode === 'run-oha' || mode === 'run-oha-direct') {
      const run = buildOhaRun(args,
        mode === 'run-oha-direct' ? 'direct-support' : 'gateway');
      let warmup = null;
      if (run.warmupInvocations) {
        const result = await runStructuredLanes(run.warmupInvocations, run.redactions);
        warmup = {kind: KIND, schema_version: run.schemaVersion, rate_per_lane: run.rate,
          cpu_sets: run.sets, workload: run.warmupWorkload,
          lanes: result.lanes, clock: result.clock};
        bundle = warmup;
        successful(parseOhaReport(warmup), 'warmup');
      }
      const result = await runStructuredLanes(run.invocations, run.redactions);
      const measurement = {kind: KIND, schema_version: run.schemaVersion,
        rate_per_lane: run.rate,
        cpu_sets: run.sets, workload: run.workload,
        lanes: result.lanes, clock: result.clock};
      bundle = warmup ? {kind: SEQUENCE_KIND, schema_version: run.schemaVersion, warmup,
        measurement} : measurement;
    } else {
      throw new Error('usage: phase5-oha-lanes.mjs run ... | run-oha|run-oha-direct --lanes N --rate-per-lane R --requests-per-lane N [--warmup-requests-per-lane N] --connections-per-lane C --streams-per-connection S --cpu-set SET --image IMAGE@sha256:DIGEST --protocol http1|http2 --url URL --target-addresses ADDRESS[,ADDRESS] [--ca-file FILE] [--credential-file FILE | --request-headers-file FILE]');
    }
    if (bundle.kind === SEQUENCE_KIND) parseOhaSequence(bundle);
    else parseOhaReport(bundle);
  } catch (error) {
    if (bundle) process.stdout.write(`${JSON.stringify(bundle)}\n`);
    throw error;
  }
  process.stdout.write(`${JSON.stringify(bundle)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`phase5-oha-lanes: ${error.message}\n`);
    process.exitCode = 1;
  });
}
