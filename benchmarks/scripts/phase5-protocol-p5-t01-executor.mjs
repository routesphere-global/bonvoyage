#!/usr/bin/env node

import {spawnSync} from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {isIP} from 'node:net';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';

import {describeP5T01Point, deriveP5T01Evidence,
  validateP5T01WarmupAdmission} from
  './phase5-protocol-p5-t01-native.mjs';
import {parseOhaReport, partitionCpus} from './phase5-oha-lanes.mjs';
import {evaluateProtocolNativePoint} from
  './phase5-protocol-native-result.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SCRIPTS = path.join(ROOT, 'benchmarks/scripts');
const AUTHORITY = 'api.example.test';
const LISTENER_PORT = 8443;
const SAFE_HOST = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SAFE_REMOTE_PATH = /^\/[A-Za-z0-9._/-]+$/u;
const CPU_SET = /^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$/u;
const IMAGE = /^\S+@sha256:([0-9a-f]{64})$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const SAFE_SERVICE = /^[A-Za-z0-9@_.-]+$/u;
const SAFE_INTERVAL = /^[A-Za-z0-9._:-]+$/u;
const PERF_EVENTS = 'cycles,instructions,cache-misses,raw_syscalls:sys_enter';
const DESCRIPTOR_KINDS = Object.freeze([
  'tcp-socket', 'socket', 'pipe', 'anon-inode', 'file', 'other',
]);
const TCP_STATES = Object.freeze([
  'ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'FIN_WAIT1', 'FIN_WAIT2',
  'TIME_WAIT', 'CLOSE', 'CLOSE_WAIT', 'LAST_ACK', 'CLOSING',
  'NEW_SYN_RECV', 'LISTEN',
]);
const CAPTURE_OPTIONS = Object.freeze([
  '--catalog', '--plan', '--point-id', '--attempt', '--output', '--load-host',
  '--upstream-host', '--load-repository', '--remote-catalog', '--remote-plan',
  '--remote-ca-file', '--upstream-artifact', '--oha-image',
  '--loadgen-cpu-set', '--loadgen-lanes', '--tls-bundle-manifest', '--ca-file',
  '--runtime-inventory', '--gateway-binary', '--snapshot-compiler', '--fixture',
  '--service', '--snapshot-file', '--metrics-url',
]);
const RAW_FILES = Object.freeze([
  'environment.json', 'final-metrics.prom', 'gateway-metrics-after.prom',
  'gateway-metrics-before.prom', 'gateway-proc-after.txt',
  'gateway-proc-before.txt', 'journal.log',
  'load-generator-proc-after.txt', 'load-generator-proc-before.txt',
  'measurement.oha.json', 'perf.csv', 'protocol-probe.json',
  'provenance-after.json', 'provenance-before.json', 'resource-after.json',
  'resource-before.json', 'runtime-inventory.json', 'socket-output.json',
  'status.json', 'upstream-proc-after.txt', 'upstream-proc-before.txt',
  'warmup-admission.json',
  'warmup.oha.json',
]);
export const P5_T01_COLLECTOR_FILES = Object.freeze([
  'benchmarks/scripts/linux_socket_output.py',
  'benchmarks/scripts/phase5-oha-lanes.mjs',
  'benchmarks/scripts/phase5-protocol-native-plan.mjs',
  'benchmarks/scripts/phase5-protocol-native-result.mjs',
  'benchmarks/scripts/phase5-protocol-p5-t01-client.mjs',
  'benchmarks/scripts/phase5-protocol-p5-t01-executor.mjs',
  'benchmarks/scripts/phase5-protocol-p5-t01-native.mjs',
  'benchmarks/scripts/phase5-protocol-streaming.mjs',
  'benchmarks/scripts/phase5-socket-output-collector.sh',
  'benchmarks/scripts/response-path-socket-output.bt',
]);

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function readRegular(filename, label, maximum = 256 * 1024 * 1024) {
  const absolute = path.resolve(filename);
  const stat = fs.lstatSync(absolute);
  requireValue(stat.isFile() && !stat.isSymbolicLink() && stat.size <= maximum,
    `${label} must be a bounded regular non-symlink file`);
  return fs.readFileSync(absolute);
}

function write(filename, value) {
  fs.mkdirSync(path.dirname(filename), {recursive: true, mode: 0o700});
  fs.writeFileSync(filename, value, {mode: 0o600});
}

function writeJson(filename, value) {
  write(filename, `${JSON.stringify(value, null, 2)}\n`);
}

function exactOption(name, argv, fallback = undefined) {
  const matches = argv.flatMap((value, index) => value === name ? [index] : []);
  requireValue(matches.length <= 1, `${name} may appear only once`);
  if (matches.length === 0) {
    requireValue(fallback !== undefined, `${name} is required`);
    return fallback;
  }
  const index = matches[0];
  requireValue(index + 1 < argv.length && !argv[index + 1].startsWith('--'),
    `${name} requires a value`);
  return argv[index + 1];
}

function integer(value, label, minimum = 1, maximum = Number.MAX_SAFE_INTEGER) {
  const parsed = Number(value);
  requireValue(Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum,
    `${label} must be an integer between ${minimum} and ${maximum}`);
  return parsed;
}

function exactKeys(value, expected, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  requireValue(JSON.stringify(Object.keys(value).sort()) ===
    JSON.stringify([...expected].sort()),
  `${label} has missing or unexpected keys`);
}

function cpuList(value, label) {
  requireValue(typeof value === 'string' && CPU_SET.test(value),
    `${label} syntax is invalid`);
  const result = [];
  for (const item of value.split(',')) {
    const [first, last = first] = item.split('-').map(Number);
    requireValue(Number.isSafeInteger(first) && Number.isSafeInteger(last) &&
      first >= 0 && first <= last && last - first < 4096,
    `${label} range is invalid`);
    for (let cpu = first; cpu <= last; cpu += 1) result.push(cpu);
  }
  requireValue(result.length > 0 && new Set(result).size === result.length,
    `${label} is empty or duplicated`);
  return result;
}

export function validateReactorObservation(value, expectedCpus, label) {
  exactKeys(value, ['reactor_tids', 'reactor_bindings'], label);
  requireValue(Array.isArray(expectedCpus) && expectedCpus.length > 0 &&
    new Set(expectedCpus).size === expectedCpus.length,
  `${label} expected CPU set is invalid`);
  requireValue(Array.isArray(value.reactor_tids) &&
    Array.isArray(value.reactor_bindings) &&
    value.reactor_tids.length === expectedCpus.length &&
    value.reactor_bindings.length === expectedCpus.length,
  `${label} reactor set is incomplete`);
  const observedCpus = [];
  value.reactor_bindings.forEach((binding, shard) => {
    exactKeys(binding, ['shard', 'tid', 'allowed_cpus', 'current_cpu'],
      `${label} shard ${shard}`);
    requireValue(binding.shard === shard &&
      binding.tid === value.reactor_tids[shard] &&
      Number.isSafeInteger(binding.tid) && binding.tid > 1 &&
      Array.isArray(binding.allowed_cpus) &&
      binding.allowed_cpus.length === 1 &&
      Number.isSafeInteger(binding.allowed_cpus[0]) &&
      binding.current_cpu === binding.allowed_cpus[0],
    `${label} shard ${shard} is not pinned to its observed CPU`);
    observedCpus.push(binding.allowed_cpus[0]);
  });
  requireValue(isDeepStrictEqual([...observedCpus].sort((a, b) => a - b),
    [...expectedCpus].sort((a, b) => a - b)),
  `${label} reactor CPUs differ from the native plan`);
  return value.reactor_tids;
}

export function validateIrqPolicyObservation(value, expected, label) {
  exactKeys(value, ['mode', 'irqbalance_active',
    'aws_nitro_irqbalance_active', 'banned_cpus', 'target_interface',
    'msi_irqs'], label);
  requireValue(value.mode === expected.mode && value.irqbalance_active === true &&
    value.aws_nitro_irqbalance_active === false &&
    Array.isArray(value.banned_cpus) &&
    new Set(value.banned_cpus).size === value.banned_cpus.length &&
    value.banned_cpus.every((cpu) => Number.isSafeInteger(cpu) && cpu >= 0) &&
    typeof value.target_interface === 'string' &&
    /^[A-Za-z0-9_.:-]+$/u.test(value.target_interface) &&
    Array.isArray(value.msi_irqs) && value.msi_irqs.length >= 2,
  `${label} service or policy identity differs from the native plan`);
  const target = new Set(expected.irq_target_cpus);
  const banned = new Set(expected.gateway_banned_cpus);
  const host = new Set([...target, ...banned]);
  const irqIds = new Set();
  const used = new Set();
  for (const record of value.msi_irqs) {
    exactKeys(record, ['irq', 'effective_cpus'], `${label} IRQ`);
    requireValue(Number.isSafeInteger(record.irq) && record.irq > 0 &&
      Array.isArray(record.effective_cpus) &&
      record.effective_cpus.length > 0,
    `${label} has an invalid IRQ record`);
    requireValue(!irqIds.has(record.irq),
      `${label} contains duplicate IRQ identity ${record.irq}`);
    irqIds.add(record.irq);
    for (const cpu of record.effective_cpus) {
      requireValue(host.has(cpu),
        `${label} NIC IRQ ${record.irq} can run outside the planned host CPUs`);
      if (expected.mode === 'irqbalance-with-gateway-ban') {
        requireValue(target.has(cpu) && !banned.has(cpu),
          `${label} NIC IRQ ${record.irq} can run outside the IRQ CPU set`);
      }
      used.add(cpu);
    }
  }
  if (expected.mode === 'irqbalance-with-gateway-ban') {
    requireValue(isDeepStrictEqual(value.banned_cpus,
      expected.gateway_banned_cpus),
    `${label} gateway CPU exclusion differs from the native plan`);
    requireValue(isDeepStrictEqual([...used].sort((a, b) => a - b),
      [...target].sort((a, b) => a - b)),
    `${label} NIC IRQs do not cover the planned IRQ CPU set`);
  } else {
    requireValue(expected.mode === 'irqbalance-observed',
      `${label} IRQ policy mode is unsupported`);
  }
  return value;
}

export function validateIrqPolicyTransition(before, after, expected, label) {
  validateIrqPolicyObservation(before, expected, `${label} before`);
  validateIrqPolicyObservation(after, expected, `${label} after`);
  const beforeIds = before.msi_irqs.map((record) => record.irq);
  const afterIds = after.msi_irqs.map((record) => record.irq);
  requireValue(before.target_interface === after.target_interface &&
    isDeepStrictEqual(beforeIds, afterIds) &&
    isDeepStrictEqual(before.banned_cpus, after.banned_cpus),
  `${label} NIC or IRQ identity changed during measurement`);
  if (expected.mode === 'irqbalance-observed') {
    const gateway = new Set(expected.gateway_banned_cpus);
    const overlaps = (value) => value.msi_irqs
      .filter((record) => record.effective_cpus.some((cpu) => gateway.has(cpu)))
      .map((record) => record.irq);
    return {mode: expected.mode, target_interface: before.target_interface,
      irq_ids: beforeIds,
      affinity_changed: !isDeepStrictEqual(before.msi_irqs, after.msi_irqs),
      banned_cpus: before.banned_cpus,
      gateway_overlap_irqs_before: overlaps(before),
      gateway_overlap_irqs_after: overlaps(after)};
  }
  return {mode: expected.mode, target_interface: before.target_interface,
    irq_ids: beforeIds,
    affinity_changed: !isDeepStrictEqual(before.msi_irqs, after.msi_irqs)};
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8', maxBuffer: 128 * 1024 * 1024,
    input: options.input, cwd: options.cwd,
  });
  requireValue(result.error === undefined,
    `${options.label ?? command} failed to start: ${result.error?.message}`);
  if (!options.allowFailure) {
    requireValue(result.status === 0,
      `${options.label ?? command} exited ${result.status}: ${result.stderr.trim()}`);
  }
  return result;
}

function privileged(command, args, options = {}) {
  return process.getuid?.() === 0 ? run(command, args, options) :
    run('sudo', ['-n', command, ...args], options);
}

function ssh(host, args, options = {}) {
  requireValue(SAFE_HOST.test(host), 'SSH host is unsafe');
  requireValue(args.every((item) => typeof item === 'string' && item.length > 0 &&
    !/[\s'"`$;&|<>\\]/u.test(item)), 'remote command contains unsafe characters');
  return run('ssh', ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
    '-o', 'ConnectTimeout=8', host, ...args], options);
}

function role(description, name) {
  const value = description.topology.roles.find((item) => item.role === name);
  requireValue(value, `P5-T01 plan omits ${name}`);
  return value;
}

export function verifyHostIdentity(expected, remoteHost = null) {
  const capture = (args) => remoteHost === null ? run(args[0], args.slice(1)) :
    ssh(remoteHost, args);
  const names = new Set([
    capture(['hostname']).stdout.trim(),
    capture(['hostname', '-s']).stdout.trim(),
  ]);
  requireValue(names.has(expected.host_id),
    `${expected.role} hostname differs from the native plan`);
  const addresses = capture(['hostname', '-I']).stdout.trim().split(/\s+/u);
  requireValue(addresses.includes(expected.private_address),
    `${expected.role} private address differs from the native plan`);
  return {host_id: expected.host_id, private_address: expected.private_address};
}

export function observeIrqPolicy(expected, routeAddress, label) {
  const irqbalance = run('systemctl', ['is-active', 'irqbalance.service'],
    {allowFailure: true, label: `${label} irqbalance state`});
  const nitro = run('systemctl', ['is-active', 'aws-nitro-irqbalance.service'],
    {allowFailure: true, label: `${label} Nitro irqbalance state`});
  const environment = run('systemctl', ['show', 'irqbalance.service',
    '--property', 'Environment', '--value'],
  {label: `${label} irqbalance environment`}).stdout.trim();
  const banned = /(?:^|[\s"]+)IRQBALANCE_BANNED_CPULIST=([0-9,-]+)(?=[\s"]|$)/u
    .exec(environment);
  requireValue(expected.mode === 'irqbalance-observed' || banned,
    `${label} irqbalance CPU exclusion is absent`);

  const route = JSON.parse(run('ip', ['-json', 'route', 'get', routeAddress],
    {label: `${label} private route`}).stdout);
  requireValue(Array.isArray(route) && route.length === 1 &&
    typeof route[0].dev === 'string' && /^[A-Za-z0-9_.:-]+$/u.test(route[0].dev),
  `${label} private route interface is invalid`);
  const device = route[0].dev;
  const irqRoot = `/sys/class/net/${device}/device/msi_irqs`;
  const irqs = fs.readdirSync(irqRoot).filter((item) => /^\d+$/u.test(item))
    .map(Number).sort((left, right) => left - right);
  requireValue(irqs.length >= 2, `${label} NIC MSI IRQ set is incomplete`);
  const value = {
    mode: expected.mode,
    irqbalance_active: irqbalance.status === 0 &&
      irqbalance.stdout.trim() === 'active',
    aws_nitro_irqbalance_active: nitro.status === 0 &&
      nitro.stdout.trim() === 'active',
    banned_cpus: banned ? cpuList(banned[1], `${label} banned CPUs`) : [],
    target_interface: device,
    msi_irqs: irqs.map((irq) => ({irq, effective_cpus: cpuList(
      fs.readFileSync(`/proc/irq/${irq}/effective_affinity_list`, 'utf8').trim(),
      `${label} IRQ ${irq} effective CPUs`)})),
  };
  return validateIrqPolicyObservation(value, expected, label);
}

export function fileSha(filename, label) {
  return sha256(readRegular(filename, label));
}

export function collectorBundleIdentity(root = ROOT) {
  const manifest = P5_T01_COLLECTOR_FILES.map((relative) => {
    const bytes = readRegular(path.join(root, relative), relative);
    return `${sha256(bytes)}  ${relative}\n`;
  }).join('');
  return {sha256: sha256(manifest), manifest};
}

export function validateTlsBundle(manifestFile, caFile) {
  const manifestPath = path.resolve(manifestFile);
  const root = path.dirname(manifestPath);
  const bytes = readRegular(manifestPath, 'TLS bundle manifest', 1024 * 1024);
  const lines = bytes.toString('utf8').trimEnd().split('\n');
  requireValue(lines.length === 3, 'TLS bundle must contain exactly three files');
  const expected = ['ca.pem', 'server-chain.pem', 'server-key.pem'];
  const records = lines.map((line, index) => {
    const match = /^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$/u.exec(line);
    requireValue(match && match[2] === expected[index],
      'TLS bundle manifest is not exact and sorted');
    const filename = path.join(root, match[2]);
    requireValue(fileSha(filename, `TLS bundle ${match[2]}`) === match[1],
      `TLS bundle digest mismatch: ${match[2]}`);
    return {sha256: match[1], name: match[2]};
  });
  requireValue(path.resolve(caFile) === path.join(root, 'ca.pem'),
    'P5-T01 CA file is outside the bound TLS bundle');
  return {sha256: sha256(bytes), ca_sha256: records[0].sha256};
}

export function validateRuntimeInventory(filename, gatewayBinary) {
  const bytes = readRegular(filename, 'native runtime inventory', 16 * 1024 * 1024);
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error('native runtime inventory is not valid JSON');
  }
  const binaryPath = path.resolve(gatewayBinary);
  const binary = value?.files?.binary;
  requireValue(value?.schema_version === 1 &&
    value.classification === 'private-native-runtime-inventory' &&
    value.outcome === 'collected-unqualified' &&
    value.runtime_profile === 'package-install' &&
    typeof value.producer_source_commit === 'string' &&
    COMMIT.test(value.producer_source_commit),
  'native runtime inventory header is invalid or not package-based');
  requireValue(binary && binary.path === binaryPath &&
    Number.isSafeInteger(binary.bytes) && binary.bytes > 0 &&
    SHA256.test(binary.sha256) && value.process?.executable === binaryPath,
  'native runtime inventory does not identify the installed gateway binary');
  const actual = readRegular(binaryPath, 'gateway binary');
  requireValue(binary.bytes === actual.length && binary.sha256 === sha256(actual),
    'installed gateway binary differs from the native runtime inventory');
  return {producerSourceCommit: value.producer_source_commit,
    sha256: sha256(bytes), bytes};
}

export function remoteSha(host, filename, label) {
  requireValue(SAFE_REMOTE_PATH.test(filename), `${label} path is unsafe`);
  const output = ssh(host, ['sha256sum', filename], {label}).stdout.trim();
  const match = /^([0-9a-f]{64})  (\/[A-Za-z0-9._/-]+)$/u.exec(output);
  requireValue(match && match[2] === filename, `${label} digest output is invalid`);
  return match[1];
}

export function currentSource() {
  const commit = run('git', ['-C', ROOT, 'rev-parse', 'HEAD']).stdout.trim();
  const status = run('git', ['-C', ROOT, 'status', '--porcelain=v1',
    '--untracked-files=all']).stdout;
  return {commit, status};
}

export function buildRemoteClientArgs(options, stage) {
  for (const name of ['repository', 'catalog', 'plan', 'caFile']) {
    requireValue(SAFE_REMOTE_PATH.test(options[name]),
      `remote ${name} path is unsafe`);
  }
  requireValue(CPU_SET.test(options.cpuSet), 'load-generator CPU set is invalid');
  requireValue(IMAGE.test(options.image), 'OHA image is not digest pinned');
  integer(options.lanes, 'load-generator lanes', 2, 16);
  requireValue(['warmup', 'measurement'].includes(stage),
    'remote P5-T01 stage is invalid');
  return ['node', `${options.repository}/benchmarks/scripts/phase5-protocol-p5-t01-client.mjs`,
    'run', '--catalog', options.catalog, '--plan', options.plan,
    '--point-id', options.pointId, '--stage', stage, '--image', options.image,
    '--cpu-set', options.cpuSet, '--lanes', String(options.lanes),
    '--ca-file', options.caFile];
}

export function buildProfiledRemoteArgs(options) {
  requireValue(path.isAbsolute(options.output) &&
    path.isAbsolute(options.perfOutput) &&
    path.isAbsolute(options.snapshotFile),
  'profiled stage paths must be absolute');
  requireValue(SAFE_SERVICE.test(options.service) &&
    SAFE_INTERVAL.test(options.intervalId) &&
    Number.isSafeInteger(options.downstreamPort) &&
    options.downstreamPort > 0 && options.downstreamPort <= 65535 &&
    SAFE_HOST.test(options.loadHost),
  'profiled stage service, interval, port, or host is invalid');
  requireValue(Array.isArray(options.perfTids) && options.perfTids.length > 0 &&
    options.perfTids.every((tid) => Number.isSafeInteger(tid) && tid > 1) &&
    new Set(options.perfTids).size === options.perfTids.length,
  'profiled stage reactor TIDs are invalid');
  requireValue(Array.isArray(options.remoteCommand) &&
    options.remoteCommand.length > 0 &&
    options.remoteCommand.every((item) => typeof item === 'string' &&
      item.length > 0 && !item.includes('\u0000')),
  'profiled stage remote command is invalid');
  return ['--output', options.output, '--service', options.service,
    '--snapshot-file', options.snapshotFile, '--downstream-port',
    String(options.downstreamPort), '--interval-id', options.intervalId, '--',
    'perf', 'stat', '-x', ',', '-e', PERF_EVENTS, '-t',
    options.perfTids.join(','), '-o', options.perfOutput, '--',
    'ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
    '-o', 'ConnectTimeout=8', options.loadHost,
    ...options.remoteCommand];
}

export function buildProfiledStageArgs(options) {
  return buildProfiledRemoteArgs({...options,
    remoteCommand: buildRemoteClientArgs(options.client, options.stage)});
}

function observeSource(options, planSource) {
  const local = currentSource();
  const image = IMAGE.exec(options.ohaImage);
  const tls = validateTlsBundle(options.tlsManifest, options.caFile);
  const inventory = validateRuntimeInventory(options.runtimeInventory,
    options.gatewayBinary);
  const observed = {
    binary_source_commit: inventory.producerSourceCommit,
    harness_commit: local.commit,
    source_dirty: local.status !== '',
    gateway_binary_sha256: fileSha(options.gatewayBinary, 'gateway binary'),
    snapshot_compiler_sha256: fileSha(options.snapshotCompiler,
      'snapshot compiler'),
    load_client_sha256: image[1],
    controlled_upstream_sha256: remoteSha(options.upstreamHost,
      options.upstreamArtifact, 'controlled upstream'),
    fixture_bundle_sha256: fileSha(options.fixture, 'P5-T01 fixture'),
    collector_bundle_sha256: collectorBundleIdentity().sha256,
    tls_bundle_sha256: tls.sha256,
    runtime_inventory_sha256: inventory.sha256,
  };
  requireValue(isDeepStrictEqual(observed, planSource),
    'observed source or artifact identity differs from the native plan');
  return {observed, sourceStatus: local.status, caSha256: tls.ca_sha256,
    inventoryBytes: inventory.bytes};
}

export function remoteSource(host, repository) {
  requireValue(SAFE_REMOTE_PATH.test(repository), 'remote repository path is unsafe');
  return {
    commit: ssh(host, ['git', '-C', repository, 'rev-parse', 'HEAD']).stdout.trim(),
    status: ssh(host, ['git', '-C', repository, 'status', '--porcelain=v1',
      '--untracked-files=all']).stdout,
  };
}

export function captureHelper(command, options, extra = []) {
  const helper = path.join(SCRIPTS, 'linux_socket_output.py');
  const result = privileged('python3', ['-B', helper, command,
    '--service', options.service, '--interval-id', options.intervalId,
    '--snapshot-file', options.snapshotFile, ...extra, '--output', '-'],
  {label: `gateway ${command} capture`});
  return JSON.parse(result.stdout);
}

export function metrics(url) {
  return run('curl', ['--fail', '--silent', '--show-error', '--max-time', '5',
    url], {label: 'gateway metrics'}).stdout;
}

function activeMetricValues(value) {
  return [...value.matchAll(/^bonvoyage_bonvoyage_gateway_active_(?:requests|route_requests|upstream_requests|upstream_http1_requests|http2_streams)(?:\{[^}]*\})?\s+(\S+)/gmu)]
    .map((match) => Number(match[1]));
}

function waitMilliseconds(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function validateSettlementResource(value, label) {
  exactKeys(value, ['identity', 'pid', 'start_ticks', 'restart_count',
    'rss_bytes', 'file_descriptors'], label);
  requireValue(typeof value.identity === 'string' && value.identity.length > 0 &&
    Number.isSafeInteger(value.pid) && value.pid > 1 &&
    Number.isSafeInteger(value.start_ticks) && value.start_ticks > 0 &&
    Number.isSafeInteger(value.restart_count) && value.restart_count >= 0 &&
    Number.isSafeInteger(value.rss_bytes) && value.rss_bytes >= 0 &&
    Number.isSafeInteger(value.file_descriptors) && value.file_descriptors >= 0,
  `${label} values are invalid`);
  return value;
}

export function validateDescriptorObservation(value, label) {
  exactKeys(value, ['identity', 'pid', 'start_ticks', 'restart_count',
    'total', 'entries'], label);
  requireValue(typeof value.identity === 'string' && value.identity.length > 0 &&
    Number.isSafeInteger(value.pid) && value.pid > 1 &&
    Number.isSafeInteger(value.start_ticks) && value.start_ticks > 0 &&
    Number.isSafeInteger(value.restart_count) && value.restart_count >= 0 &&
    Number.isSafeInteger(value.total) && value.total >= 0 && value.total <= 4096 &&
    Array.isArray(value.entries) && value.entries.length === value.total,
  `${label} header is invalid`);
  const fileDescriptors = [];
  for (const [index, entry] of value.entries.entries()) {
    exactKeys(entry, ['fd', 'target', 'kind', 'socket_inode', 'tcp'],
      `${label} entry ${index}`);
    requireValue(Number.isSafeInteger(entry.fd) && entry.fd >= 0 &&
      typeof entry.target === 'string' && entry.target.length > 0 &&
      entry.target.length <= 4096 && DESCRIPTOR_KINDS.includes(entry.kind) &&
      (entry.socket_inode === null ||
        (Number.isSafeInteger(entry.socket_inode) && entry.socket_inode >= 0)),
    `${label} entry ${index} is invalid`);
    if (entry.tcp === null) {
      requireValue(entry.kind !== 'tcp-socket',
        `${label} entry ${index} omits TCP identity`);
    } else {
      exactKeys(entry.tcp, ['family', 'local_address', 'local_port',
        'remote_address', 'remote_port', 'state', 'tx_queue_bytes',
        'rx_queue_bytes'], `${label} entry ${index} TCP identity`);
      const expectedIpVersion = entry.tcp.family === 'ipv4' ? 4 : 6;
      requireValue(entry.kind === 'tcp-socket' && entry.socket_inode !== null &&
        ['ipv4', 'ipv6'].includes(entry.tcp.family) &&
        isIP(entry.tcp.local_address) === expectedIpVersion &&
        isIP(entry.tcp.remote_address) === expectedIpVersion &&
        Number.isSafeInteger(entry.tcp.local_port) &&
        entry.tcp.local_port >= 0 && entry.tcp.local_port <= 65535 &&
        Number.isSafeInteger(entry.tcp.remote_port) &&
        entry.tcp.remote_port >= 0 && entry.tcp.remote_port <= 65535 &&
        TCP_STATES.includes(entry.tcp.state) &&
        Number.isSafeInteger(entry.tcp.tx_queue_bytes) &&
        entry.tcp.tx_queue_bytes >= 0 &&
        Number.isSafeInteger(entry.tcp.rx_queue_bytes) &&
        entry.tcp.rx_queue_bytes >= 0,
      `${label} entry ${index} TCP identity is invalid`);
    }
    fileDescriptors.push(entry.fd);
  }
  requireValue(fileDescriptors.every((descriptor, index) =>
    index === 0 || descriptor > fileDescriptors[index - 1]),
  `${label} descriptor numbers are duplicated or unordered`);
  return value;
}

function validateRuntimeState(value, label) {
  exactKeys(value, ['resource', 'descriptors'], label);
  const resource = validateSettlementResource(value.resource,
    `${label} resource`);
  const descriptors = validateDescriptorObservation(value.descriptors,
    `${label} descriptors`);
  requireValue(resource.identity === descriptors.identity &&
    resource.pid === descriptors.pid &&
    resource.start_ticks === descriptors.start_ticks &&
    resource.restart_count === descriptors.restart_count &&
    resource.file_descriptors === descriptors.total,
  `${label} resource and descriptor identities disagree`);
  return {resource, descriptors};
}

export function controlledUpstreamDescriptorPolicy(config, remoteAddress,
  coreCount) {
  requireValue(config && typeof config === 'object' && !Array.isArray(config) &&
    Array.isArray(config.clusters) && isIP(remoteAddress) === 4 &&
    Number.isSafeInteger(coreCount) && coreCount > 0,
  'controlled-upstream descriptor policy input is invalid');
  const clusters = config.clusters.filter((cluster) =>
    cluster?.name === 'controlled-upstream');
  requireValue(clusters.length === 1 &&
    Number.isSafeInteger(clusters[0].max_connections_per_shard) &&
    clusters[0].max_connections_per_shard > 0 &&
    Array.isArray(clusters[0].endpoints) && clusters[0].endpoints.length === 1 &&
    Number.isSafeInteger(clusters[0].endpoints[0]?.port) &&
    clusters[0].endpoints[0].port > 0 && clusters[0].endpoints[0].port <= 65535,
  'controlled-upstream descriptor policy differs from the bound fixture');
  const maximumConnections = clusters[0].max_connections_per_shard * coreCount;
  requireValue(Number.isSafeInteger(maximumConnections) &&
    maximumConnections <= 4096,
  'controlled-upstream descriptor bound is invalid');
  return {remote_address: remoteAddress,
    remote_port: clusters[0].endpoints[0].port,
    maximum_connections: maximumConnections};
}

export function descriptorAttribution(before, after, policy) {
  const matchesPool = (entry) => entry.kind === 'tcp-socket' &&
    entry.tcp?.state === 'ESTABLISHED' &&
    entry.tcp.remote_address === policy.remote_address &&
    entry.tcp.remote_port === policy.remote_port;
  const beforePool = before.entries.filter(matchesPool).length;
  const afterPool = after.entries.filter(matchesPool).length;
  const poolGrowth = afterPool - beforePool;
  const nonPoolBefore = before.total - beforePool;
  const nonPoolAfter = after.total - afterPool;
  return {
    total_fd_growth: after.total - before.total,
    controlled_upstream_connections_before: beforePool,
    controlled_upstream_connections_after: afterPool,
    controlled_upstream_connection_growth: poolGrowth,
    controlled_upstream_connection_limit: policy.maximum_connections,
    controlled_upstream_connections_bounded:
      beforePool <= policy.maximum_connections &&
      afterPool <= policy.maximum_connections,
    non_controlled_descriptors_before: nonPoolBefore,
    non_controlled_descriptors_after: nonPoolAfter,
    unaccounted_fd_growth: nonPoolAfter - nonPoolBefore,
  };
}

export function settleWarmupState(options) {
  const {captureState, captureMetrics} = options;
  const now = options.now ?? Date.now;
  const wait = options.wait ?? waitMilliseconds;
  const pollIntervalMs = options.pollIntervalMs ?? 50;
  const stableObservations = options.stableObservations ?? 3;
  requireValue(typeof captureState === 'function' &&
    typeof captureMetrics === 'function' && typeof now === 'function' &&
    typeof wait === 'function' && typeof options.expectedIdentity === 'string' &&
    options.expectedIdentity.length > 0,
  'warmup settlement callbacks or process identity are invalid');
  requireValue(Number.isSafeInteger(options.maximumCleanupMs) &&
    options.maximumCleanupMs > 0 &&
    Number.isSafeInteger(pollIntervalMs) && pollIntervalMs > 0 &&
    Number.isSafeInteger(stableObservations) && stableObservations >= 2,
  'warmup settlement limits are invalid');

  const startedAt = now();
  requireValue(Number.isFinite(startedAt), 'warmup settlement clock is invalid');
  const observations = [];
  let previous = null;
  let consecutiveStable = 0;
  while (true) {
    const state = validateRuntimeState(captureState(),
      'warmup runtime observation');
    const {resource} = state;
    const metricText = captureMetrics();
    requireValue(resource.identity === options.expectedIdentity &&
      resource.restart_count === 0,
      'gateway process identity changed during warmup settlement');
    const observedAt = now();
    requireValue(Number.isFinite(observedAt) && observedAt >= startedAt,
      'warmup settlement clock moved backwards');
    const elapsedMs = observedAt - startedAt;
    const active = activeMetricValues(metricText);
    const activeDrained = active.length >= 5 &&
      active.every((value) => Number.isFinite(value) && value === 0);
    const resourceStable = previous !== null &&
      resource.rss_bytes === previous.rss_bytes &&
      resource.file_descriptors === previous.file_descriptors;
    consecutiveStable = activeDrained ?
      (resourceStable ? consecutiveStable + 1 : 1) : 0;
    observations.push({elapsed_ms: elapsedMs, active_metrics: active,
      active_streams_drained: activeDrained,
      rss_bytes: resource.rss_bytes,
      file_descriptors: resource.file_descriptors,
      resource_stable: resourceStable,
      consecutive_stable_observations: consecutiveStable});
    const withinDeadline = elapsedMs <= options.maximumCleanupMs;
    if (consecutiveStable >= stableObservations && withinDeadline) {
      return {settled: true, elapsed_ms: elapsedMs, state,
        metrics: metricText, observations};
    }
    if (!withinDeadline || elapsedMs === options.maximumCleanupMs) {
      return {settled: false, elapsed_ms: elapsedMs, state,
        metrics: metricText, observations};
    }
    previous = resource;
    wait(Math.min(pollIntervalMs, options.maximumCleanupMs - elapsedMs));
  }
}

function warmupPassRecord(pass, report, settlement) {
  const successfulRequests = report.statusCodeDistribution?.['200'] ?? 0;
  const httpFailures = Object.entries(report.statusCodeDistribution ?? {})
    .reduce((total, [status, count]) => status === '200' ? total : total + count,
      0);
  const transportFailures = Object.values(report.errorDistribution ?? {})
    .reduce((total, count) => total + count, 0);
  return {pass, settled: settlement.settled,
    settlement_ms: settlement.elapsed_ms,
    identity: settlement.state.resource.identity,
    restart_count: settlement.state.resource.restart_count,
    rss_bytes: settlement.state.resource.rss_bytes,
    file_descriptors: settlement.state.resource.file_descriptors,
    successful_requests: successfulRequests, http_failures: httpFailures,
    transport_failures: transportFailures};
}

export function buildP5T01WarmupAdmission(plan, variant, passes) {
  requireValue(Array.isArray(passes) && passes.length >= 2,
    'P5-T01 profiled warmup passes are incomplete');
  const penultimate = passes.at(-2);
  const final = passes.at(-1);
  const value = {schema_version: 1,
    required_profiled_warmup_repetitions:
      plan.input.schedule.profiled_warmup_repetitions,
    passes,
    plateau: {compared_passes: [penultimate.pass, final.pass],
      rss_delta_bytes: final.rss_bytes - penultimate.rss_bytes,
      fd_delta: final.file_descriptors - penultimate.file_descriptors,
      stable: final.rss_bytes === penultimate.rss_bytes &&
        final.file_descriptors === penultimate.file_descriptors}};
  return validateP5T01WarmupAdmission(value, plan, variant);
}

export function settlePostRunState(options) {
  const {before, beforeDescriptors, descriptorPolicy, acceptance,
    captureState, captureMetrics} = options;
  const now = options.now ?? Date.now;
  const wait = options.wait ?? waitMilliseconds;
  const pollIntervalMs = options.pollIntervalMs ?? 50;
  requireValue(typeof captureState === 'function' &&
    typeof captureMetrics === 'function' && typeof now === 'function' &&
    typeof wait === 'function', 'post-run settlement callbacks are invalid');
  requireValue(Number.isSafeInteger(pollIntervalMs) && pollIntervalMs > 0 &&
    Number.isSafeInteger(acceptance?.maximum_cleanup_ms) &&
    acceptance.maximum_cleanup_ms > 0 &&
    Number.isSafeInteger(acceptance.maximum_retained_rss_growth_bytes) &&
    acceptance.maximum_retained_rss_growth_bytes >= 0 &&
    Number.isSafeInteger(acceptance.maximum_retained_fd_growth) &&
    acceptance.maximum_retained_fd_growth >= 0,
  'post-run settlement limits are invalid');
  validateSettlementResource(before, 'resource baseline');
  validateDescriptorObservation(beforeDescriptors, 'descriptor baseline');
  requireValue(before.identity === beforeDescriptors.identity &&
    before.file_descriptors === beforeDescriptors.total &&
    descriptorPolicy && isIP(descriptorPolicy.remote_address) === 4 &&
    Number.isSafeInteger(descriptorPolicy.remote_port) &&
    descriptorPolicy.remote_port > 0 && descriptorPolicy.remote_port <= 65535 &&
    Number.isSafeInteger(descriptorPolicy.maximum_connections) &&
    descriptorPolicy.maximum_connections > 0,
  'descriptor baseline or controlled-upstream policy is invalid');
  const startedAt = now();
  requireValue(Number.isFinite(startedAt), 'post-run settlement clock is invalid');
  const observations = [];
  while (true) {
    const state = validateRuntimeState(captureState(),
      'post-run runtime observation');
    const {resource, descriptors} = state;
    const metricText = captureMetrics();
    requireValue(resource.identity === before.identity &&
      resource.pid === before.pid && resource.start_ticks === before.start_ticks &&
      resource.restart_count === before.restart_count &&
      resource.restart_count === 0,
    'gateway process identity changed during post-run settlement');
    const observedAt = now();
    requireValue(Number.isFinite(observedAt) && observedAt >= startedAt,
      'post-run settlement clock moved backwards');
    const elapsedMs = observedAt - startedAt;
    const active = activeMetricValues(metricText);
    const activeDrained = active.length >= 5 &&
      active.every((value) => Number.isFinite(value) && value === 0);
    const rssGrowthBytes = resource.rss_bytes - before.rss_bytes;
    const fdGrowth = resource.file_descriptors - before.file_descriptors;
    const descriptorAttributionValue = descriptorAttribution(
      beforeDescriptors, descriptors, descriptorPolicy);
    const resourceContained = rssGrowthBytes <=
      acceptance.maximum_retained_rss_growth_bytes &&
      fdGrowth <= acceptance.maximum_retained_fd_growth;
    const withinDeadline = elapsedMs <= acceptance.maximum_cleanup_ms;
    observations.push({elapsed_ms: elapsedMs, active_metrics: active,
      active_streams_drained: activeDrained, rss_growth_bytes: rssGrowthBytes,
      fd_growth: fdGrowth, resource_contained: resourceContained,
      descriptor_attribution: descriptorAttributionValue,
      descriptors});
    if (activeDrained && resourceContained && withinDeadline) {
      return {settled: true, elapsed_ms: elapsedMs, resource,
        metrics: metricText, observations};
    }
    if (!withinDeadline || elapsedMs === acceptance.maximum_cleanup_ms) {
      return {settled: false, elapsed_ms: elapsedMs, resource,
        metrics: metricText, observations};
    }
    wait(Math.min(pollIntervalMs,
      acceptance.maximum_cleanup_ms - elapsedMs));
  }
}

function fixedProvenance(description, source, catalogSha256, sourceStatus) {
  return {schema_version: 1, plan_id: description.plan_id,
    point_id: description.point.point_id,
    variant_id: description.variant.id,
    repetition: description.point.repetition, source,
    catalog_sha256: catalogSha256,
    snapshot_sha256: description.variant.snapshot_sha256,
    observed_harness_commit: source.harness_commit,
    source_status: sourceStatus};
}

function exactRawManifest(rawRoot) {
  const lines = RAW_FILES.map((name) => {
    const bytes = readRegular(path.join(rawRoot, name), `raw ${name}`);
    return `${sha256(bytes)}  ${name}\n`;
  }).join('');
  write(path.join(rawRoot, 'checksums.sha256'), lines);
}

function sealTree(root, manifestName = 'checksums.sha256') {
  const files = [];
  const visit = (directory) => {
    for (const name of fs.readdirSync(directory).sort()) {
      const absolute = path.join(directory, name);
      const relative = path.relative(root, absolute).split(path.sep).join('/');
      if (relative === manifestName) continue;
      const stat = fs.lstatSync(absolute);
      requireValue(!stat.isSymbolicLink(), 'evidence tree contains a symlink');
      if (stat.isDirectory()) visit(absolute);
      else if (stat.isFile()) files.push(relative);
      else throw new Error('evidence tree contains a non-regular member');
    }
  };
  visit(root);
  write(path.join(root, manifestName), files.map((relative) =>
    `${fileSha(path.join(root, relative), relative)}  ${relative}\n`).join(''));
}

function parseOptions(argv) {
  requireValue(argv.length % 2 === 0, 'capture options require name/value pairs');
  for (let index = 0; index < argv.length; index += 2) {
    requireValue(CAPTURE_OPTIONS.includes(argv[index]) &&
      typeof argv[index + 1] === 'string' && argv[index + 1].length > 0,
    `unknown or valueless capture option: ${argv[index]}`);
  }
  const options = {
    catalog: exactOption('--catalog', argv), plan: exactOption('--plan', argv),
    pointId: exactOption('--point-id', argv),
    attempt: integer(exactOption('--attempt', argv), 'attempt'),
    output: path.resolve(exactOption('--output', argv)),
    loadHost: exactOption('--load-host', argv),
    upstreamHost: exactOption('--upstream-host', argv),
    loadRepository: exactOption('--load-repository', argv),
    remoteCatalog: exactOption('--remote-catalog', argv),
    remotePlan: exactOption('--remote-plan', argv),
    remoteCaFile: exactOption('--remote-ca-file', argv),
    upstreamArtifact: exactOption('--upstream-artifact', argv),
    ohaImage: exactOption('--oha-image', argv),
    loadCpuSet: exactOption('--loadgen-cpu-set', argv),
    loadLanes: integer(exactOption('--loadgen-lanes', argv),
      'load-generator lanes', 2, 16),
    tlsManifest: path.resolve(exactOption('--tls-bundle-manifest', argv)),
    caFile: path.resolve(exactOption('--ca-file', argv)),
    runtimeInventory: path.resolve(exactOption('--runtime-inventory', argv)),
    gatewayBinary: path.resolve(exactOption('--gateway-binary', argv,
      '/usr/bin/bonvoyage-dataplane')),
    snapshotCompiler: path.resolve(exactOption('--snapshot-compiler', argv,
      '/usr/bin/bonvoyage-snapshot-compiler')),
    fixture: path.resolve(exactOption('--fixture', argv,
      path.join(ROOT, 'tests/fixtures/perf05-tls-boundary/fixture.py'))),
    service: exactOption('--service', argv, 'bonvoyage.service'),
    snapshotFile: path.resolve(exactOption('--snapshot-file', argv,
      '/etc/bonvoyage/snapshot.pb')),
    metricsUrl: exactOption('--metrics-url', argv,
      'http://127.0.0.1:9090/metrics'),
  };
  requireValue(SAFE_HOST.test(options.loadHost) &&
    SAFE_HOST.test(options.upstreamHost) && options.loadHost !== options.upstreamHost,
  'native support host targets are invalid or duplicated');
  requireValue(CPU_SET.test(options.loadCpuSet),
    'load-generator CPU set is invalid');
  requireValue(IMAGE.test(options.ohaImage), 'OHA image is not digest pinned');
  requireValue(/^http:\/\/127\.0\.0\.1:\d+\/metrics$/u.test(options.metricsUrl),
    'metrics URL must be an explicit IPv4 loopback endpoint');
  requireValue(options.output !== ROOT &&
    !options.output.startsWith(`${ROOT}${path.sep}`),
  'native evidence output must be outside the source checkout');
  return options;
}

export function requireNativeCaptureRoot(uid = process.getuid?.()) {
  requireValue(uid === 0,
    'native capture must run as root to read protected runtime artifacts and collect perf evidence');
}

function runCapture(options) {
  requireNativeCaptureRoot();
  requireValue(!fs.existsSync(options.output), 'native evidence output already exists');
  const catalogBytes = readRegular(options.catalog, 'PERF-05 catalog').toString('utf8');
  const plan = JSON.parse(readRegular(options.plan, 'PERF-05 plan').toString('utf8'));
  const description = describeP5T01Point(plan, catalogBytes, options.pointId);
  const gatewayRole = role(description, 'gateway');
  const loadRole = role(description, 'load_generator');
  const upstreamRole = role(description, 'controlled_upstream');
  const intervalId = `${options.pointId}-a${options.attempt}`;
    const runtime = {...options, intervalId};
    const plannedClientCpuSets = partitionCpus(
      description.topology.load_generator_cpu_set.join(','),
      description.topology.load_generator_lanes);
    const observedClientCpuSets = partitionCpus(options.loadCpuSet,
      options.loadLanes);
    requireValue(options.loadLanes ===
      description.topology.load_generator_lanes &&
      isDeepStrictEqual(observedClientCpuSets, plannedClientCpuSets),
    'executor load-generator placement differs from the native plan');
  fs.mkdirSync(options.output, {recursive: false, mode: 0o700});
  const raw = path.join(options.output, 'raw');
  const diagnostics = path.join(options.output, 'diagnostics');
  const evidence = path.join(options.output, 'evidence');
  fs.mkdirSync(raw, {mode: 0o700});
  fs.mkdirSync(diagnostics, {mode: 0o700});
  let succeeded = false;
  try {
    verifyHostIdentity(gatewayRole);
    verifyHostIdentity(loadRole, options.loadHost);
    verifyHostIdentity(upstreamRole, options.upstreamHost);
    const irqBefore = observeIrqPolicy(description.topology.irq_policy,
      loadRole.private_address, 'P5-T01 IRQ policy before');
    writeJson(path.join(diagnostics, 'irq-policy-before.json'), irqBefore);
    const observedBefore = observeSource(options, description.source);
    write(path.join(raw, 'runtime-inventory.json'),
      observedBefore.inventoryBytes);
    requireValue(fileSha(options.snapshotFile, 'active gateway snapshot') ===
      description.variant.snapshot_sha256,
    'active gateway snapshot differs from the native plan');
    const remoteBefore = remoteSource(options.loadHost, options.loadRepository);
    requireValue(remoteBefore.commit === description.source.harness_commit &&
      remoteBefore.status === '', 'load-generator source is not the clean plan commit');
    requireValue(remoteSha(options.loadHost, options.remoteCatalog,
      'remote PERF-05 catalog') === sha256(catalogBytes) &&
      remoteSha(options.loadHost, options.remotePlan, 'remote PERF-05 plan') ===
        fileSha(options.plan, 'PERF-05 plan') &&
      remoteSha(options.loadHost, options.remoteCaFile, 'remote PERF-05 CA') ===
        observedBefore.caSha256,
    'load-generator control artifact differs from the gateway host');

    const client = {repository: options.loadRepository,
      catalog: options.remoteCatalog, plan: options.remotePlan,
      caFile: options.remoteCaFile, pointId: options.pointId,
      image: options.ohaImage, cpuSet: options.loadCpuSet,
      lanes: options.loadLanes};
    const plannedGatewayCpus = description.topology.gateway_cpu_sets[
      String(description.variant.core_count)];
    const mode = description.variant.scenario === 'fixed-response' ?
      'fixed' : 'proxied';
    const probe = run('python3', ['-B', options.fixture, 'native-probe',
      '--connect-address', gatewayRole.private_address, '--host', AUTHORITY,
      '--port', String(LISTENER_PORT), '--ca', options.caFile,
      '--case-mode', mode, '--payload-bytes',
      String(description.variant.payload_bytes)],
    {allowFailure: true, label: 'P5-T01 protocol probe'});
    write(path.join(raw, 'protocol-probe.json'), probe.stdout);
    write(path.join(diagnostics, 'protocol-probe.stderr'), probe.stderr);
    requireValue(probe.status === 0, `P5-T01 protocol probe exited ${probe.status}`);

    const fixtureConfig = JSON.parse(run('python3', ['-B', options.fixture,
      'render-config'], {label: 'P5-T01 bound fixture configuration'}).stdout);
    const descriptorPolicy = controlledUpstreamDescriptorPolicy(fixtureConfig,
      upstreamRole.private_address, description.variant.core_count);
    writeJson(path.join(diagnostics, 'descriptor-policy.json'),
      descriptorPolicy);

    const initialWarmupState = validateRuntimeState(
      captureHelper('state', runtime), 'P5-T01 runtime state before warmup');
    requireValue(initialWarmupState.resource.restart_count === 0,
      'gateway restart count is nonzero before P5-T01 warmup');
    writeJson(path.join(diagnostics, 'warmup-state-before.json'),
      initialWarmupState);
    const requiredWarmups = plan.input.schedule.profiled_warmup_repetitions;
    const warmupPasses = [];
    let stateBefore = initialWarmupState;
    for (let pass = 1; pass <= requiredWarmups; pass += 1) {
      const passLabel = `warmup-pass-${pass}`;
      const passStateBefore = validateRuntimeState(captureHelper('state', runtime),
        `P5-T01 runtime state before warmup pass ${pass}`);
      requireValue(passStateBefore.resource.identity ===
        initialWarmupState.resource.identity &&
        passStateBefore.resource.restart_count === 0,
      `gateway process identity changed before P5-T01 warmup pass ${pass}`);
      writeJson(path.join(diagnostics, `${passLabel}-state-before.json`),
        passStateBefore);
      const reactorObservation = captureHelper('reactors', runtime,
        ['--expected-count', String(description.variant.core_count)]);
      const reactorTids = validateReactorObservation(reactorObservation,
        plannedGatewayCpus, `P5-T01 warmup pass ${pass} reactor placement`);
      writeJson(path.join(diagnostics, `${passLabel}-reactors.json`),
        reactorObservation);

      const socketRoot = path.join(diagnostics, `${passLabel}-socket`);
      const collector = run(
        path.join(SCRIPTS, 'phase5-socket-output-collector.sh'),
        buildProfiledStageArgs({output: socketRoot,
          service: options.service, snapshotFile: options.snapshotFile,
          downstreamPort: LISTENER_PORT,
          intervalId: `${intervalId}-${passLabel}`,
          perfOutput: path.join(diagnostics, `${passLabel}-perf.csv`),
          perfTids: reactorTids, loadHost: options.loadHost,
          client, stage: 'warmup'}),
        {allowFailure: true,
          label: `P5-T01 profiled warmup pass ${pass}`});
      write(path.join(diagnostics, `${passLabel}-collector.stdout`),
        collector.stdout);
      write(path.join(diagnostics, `${passLabel}-collector.stderr`),
        collector.stderr);
      const statusFile = path.join(socketRoot, 'client-exit-code.txt');
      const status = fs.existsSync(statusFile) ?
        Number(fs.readFileSync(statusFile, 'utf8').trim()) : collector.status;
      const output = path.join(socketRoot, 'client.stdout');
      const error = path.join(socketRoot, 'client.stderr');
      const retainedOutput = path.join(diagnostics, `${passLabel}.oha.json`);
      if (fs.existsSync(output)) fs.copyFileSync(output, retainedOutput);
      write(path.join(diagnostics, `${passLabel}.stderr`),
        fs.existsSync(error) ? fs.readFileSync(error) : '');
      requireValue(collector.status === 0 && status === 0 &&
        fs.existsSync(retainedOutput),
      `P5-T01 profiled warmup pass ${pass} collector or client failed`);
      if (pass === requiredWarmups) {
        fs.copyFileSync(retainedOutput, path.join(raw, 'warmup.oha.json'));
      }
      const report = parseOhaReport(fs.readFileSync(retainedOutput, 'utf8'));
      const settlement = settleWarmupState({
        maximumCleanupMs: plan.input.acceptance.maximum_cleanup_ms,
        expectedIdentity: initialWarmupState.resource.identity,
        captureState: () => captureHelper('state', runtime),
        captureMetrics: () => metrics(options.metricsUrl),
      });
      const {metrics: finalMetricText, state, ...settlementDiagnostic} =
        settlement;
      writeJson(path.join(diagnostics, `${passLabel}-settlement.json`),
        settlementDiagnostic);
      write(path.join(diagnostics, `${passLabel}-final-metrics.prom`),
        finalMetricText);
      requireValue(settlement.settled,
        `P5-T01 warmup pass ${pass} did not settle within ${plan.input.acceptance.maximum_cleanup_ms} ms`);
      warmupPasses.push(warmupPassRecord(pass, report, settlement));
      stateBefore = state;
    }
    const warmupAdmission = buildP5T01WarmupAdmission(plan,
      description.variant, warmupPasses);
    writeJson(path.join(raw, 'warmup-admission.json'), warmupAdmission);
    const resourceBefore = stateBefore.resource;
    const reactorObservationBefore = captureHelper('reactors', runtime,
      ['--expected-count', String(description.variant.core_count)]);
    const reactorsBefore = validateReactorObservation(
      reactorObservationBefore, plannedGatewayCpus,
      'P5-T01 reactor placement before');
    writeJson(path.join(diagnostics, 'reactors-before.json'),
      reactorObservationBefore);
    writeJson(path.join(diagnostics, 'descriptors-before.json'),
      stateBefore.descriptors);
    writeJson(path.join(raw, 'resource-before.json'), resourceBefore);
    write(path.join(raw, 'gateway-metrics-before.prom'), metrics(options.metricsUrl));
    write(path.join(raw, 'gateway-proc-before.txt'),
      fs.readFileSync('/proc/stat', 'utf8'));
    write(path.join(raw, 'load-generator-proc-before.txt'),
      ssh(options.loadHost, ['cat', '/proc/stat']).stdout);
    write(path.join(raw, 'upstream-proc-before.txt'),
      ssh(options.upstreamHost, ['cat', '/proc/stat']).stdout);
    const provenanceBefore = fixedProvenance(description, observedBefore.observed,
      plan.input.catalog_sha256, observedBefore.sourceStatus);
    writeJson(path.join(raw, 'provenance-before.json'), provenanceBefore);

    const started = new Date().toISOString();
    const socketRoot = path.join(diagnostics, 'socket');
    const collector = run(path.join(SCRIPTS, 'phase5-socket-output-collector.sh'),
      buildProfiledStageArgs({output: socketRoot,
        service: options.service, snapshotFile: options.snapshotFile,
        downstreamPort: LISTENER_PORT, intervalId,
        perfOutput: path.join(raw, 'perf.csv'),
        perfTids: reactorsBefore, loadHost: options.loadHost,
        client, stage: 'measurement'}),
      {allowFailure: true, label: 'P5-T01 socket/perf measurement'});
    write(path.join(diagnostics, 'collector.stdout'), collector.stdout);
    write(path.join(diagnostics, 'collector.stderr'), collector.stderr);
    const perfStatus = fs.existsSync(path.join(socketRoot, 'client-exit-code.txt')) ?
      Number(fs.readFileSync(path.join(socketRoot, 'client-exit-code.txt'), 'utf8').trim()) :
      collector.status;
    if (fs.existsSync(path.join(socketRoot, 'client.stdout'))) {
      fs.copyFileSync(path.join(socketRoot, 'client.stdout'),
        path.join(raw, 'measurement.oha.json'));
    }
    if (fs.existsSync(path.join(socketRoot, 'socket-output.json'))) {
      fs.copyFileSync(path.join(socketRoot, 'socket-output.json'),
        path.join(raw, 'socket-output.json'));
    }

    write(path.join(raw, 'gateway-proc-after.txt'),
      fs.readFileSync('/proc/stat', 'utf8'));
    write(path.join(raw, 'load-generator-proc-after.txt'),
      ssh(options.loadHost, ['cat', '/proc/stat']).stdout);
    write(path.join(raw, 'upstream-proc-after.txt'),
      ssh(options.upstreamHost, ['cat', '/proc/stat']).stdout);
    write(path.join(raw, 'gateway-metrics-after.prom'), metrics(options.metricsUrl));
    const reactorObservationAfter = captureHelper('reactors', runtime,
      ['--expected-count', String(description.variant.core_count)]);
    const reactorsAfter = validateReactorObservation(reactorObservationAfter,
      plannedGatewayCpus, 'P5-T01 reactor placement after');
    writeJson(path.join(diagnostics, 'reactors-after.json'),
      reactorObservationAfter);
    const irqAfter = observeIrqPolicy(description.topology.irq_policy,
      loadRole.private_address, 'P5-T01 IRQ policy after');
    writeJson(path.join(diagnostics, 'irq-policy-after.json'), irqAfter);
    requireValue(irqBefore.target_interface === irqAfter.target_interface &&
      isDeepStrictEqual(irqBefore.msi_irqs.map((item) => item.irq),
        irqAfter.msi_irqs.map((item) => item.irq)),
    'P5-T01 NIC interface or IRQ identity changed during measurement');
    const settlement = settlePostRunState({before: resourceBefore,
      beforeDescriptors: stateBefore.descriptors, descriptorPolicy,
      acceptance: plan.input.acceptance,
      captureState: () => captureHelper('state', runtime),
      captureMetrics: () => metrics(options.metricsUrl)});
    const {metrics: finalMetricText, ...settlementDiagnostic} = settlement;
    writeJson(path.join(diagnostics, 'post-run-settlement.json'),
      settlementDiagnostic);
    writeJson(path.join(raw, 'resource-after.json'), settlement.resource);
    write(path.join(raw, 'final-metrics.prom'), finalMetricText);
    requireValue(settlement.settled,
      `P5-T01 post-run state did not settle within ${plan.input.acceptance.maximum_cleanup_ms} ms`);
    const journal = privileged('journalctl', ['-u', options.service, '--since',
      started, '--no-pager', '--output=short-iso-precise'],
    {allowFailure: true, label: 'gateway journal'});
    write(path.join(raw, 'journal.log'), journal.stdout + journal.stderr);

    const observedAfter = observeSource(options, description.source);
    const remoteAfter = remoteSource(options.loadHost, options.loadRepository);
    requireValue(remoteAfter.commit === remoteBefore.commit &&
      remoteAfter.status === remoteBefore.status,
    'load-generator source changed during P5-T01 capture');
    writeJson(path.join(raw, 'provenance-after.json'),
      fixedProvenance(description, observedAfter.observed,
        plan.input.catalog_sha256, observedAfter.sourceStatus));
    writeJson(path.join(raw, 'environment.json'), {schema_version: 1,
      plan_id: description.plan_id, point_id: description.point.point_id,
      variant_id: description.variant.id,
      repetition: description.point.repetition, attempt: options.attempt,
      roles: description.topology.roles,
      load_generator_cpu_set: description.topology.load_generator_cpu_set,
      load_generator_lanes: description.topology.load_generator_lanes,
      gateway_cpu_set: plannedGatewayCpus,
      gateway_housekeeping_cpus: description.topology.gateway_housekeeping_cpus,
      irq_policy: description.topology.irq_policy,
      profiler_scope: description.result_contract.profiler_scope,
      reactor_tids_before: reactorsBefore,
      reactor_tids_after: reactorsAfter,
      profiled_reactor_tids: reactorsBefore});
    writeJson(path.join(raw, 'status.json'), {
      measurement_command_exit_code: perfStatus,
      collector_exit_code: collector.status ?? 1,
      protocol_probe_exit_code: probe.status ?? 1});
    requireValue(collector.status === 0 && perfStatus === 0,
      'P5-T01 measurement collector or client failed');
    exactRawManifest(raw);

    const point = options.pointId;
    const derived = deriveP5T01Evidence({catalog: options.catalog,
      plan: options.plan,
      pointId: point, attempt: options.attempt, rawRoot: raw,
      evidenceRoot: evidence,
      captureArchive: path.join(evidence, `${point}.capture.raw.json`),
      environment: path.join(evidence, `${point}.environment.json`),
      derivationManifest: path.join(evidence, `${point}.derivation.json`),
      result: path.join(evidence, `${point}.result.json`)});
    const evaluation = evaluateProtocolNativePoint(derived.result, plan,
      catalogBytes);
    const failedGates = Object.entries(evaluation.gates)
      .filter(([, passed]) => !passed).map(([name]) => name);
    requireValue(evaluation.pass,
      `P5-T01 formal point gates failed: ${failedGates.join(', ')}`);
    write(path.join(options.output, 'decision.txt'), 'point-pass\n');
    succeeded = true;
    return options.output;
  } finally {
    writeJson(path.join(options.output, 'attempt-status.json'), {
      schema_version: 1, point_id: options.pointId, attempt: options.attempt,
      outcome: succeeded ? 'complete' : 'investigate',
      publication_authorized: false,
    });
    sealTree(options.output);
  }
}

function main() {
  const [, , command, ...argv] = process.argv;
  requireValue(['capture', 'collector-identity'].includes(command),
    'usage: phase5-protocol-p5-t01-executor.mjs capture|collector-identity ...');
  if (command === 'collector-identity') {
    process.stdout.write(`${JSON.stringify(collectorBundleIdentity(), null, 2)}\n`);
    return;
  }
  const output = runCapture(parseOptions(argv));
  process.stdout.write(`P5_T01_EVIDENCE_DIR=${output}\n`);
}

if (process.argv[1] && import.meta.url ===
    pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-protocol-p5-t01-executor: ${error.message}\n`);
    process.exitCode = 1;
  }
}
