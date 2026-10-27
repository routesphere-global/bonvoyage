#!/usr/bin/env node

import {spawnSync} from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';

import {buildPolicyCostResult, POLICY_COST_PROFILED_WARMUP_REPETITIONS,
  validatePolicyCostPlan} from './phase5-policy-cost.mjs';
import {completePolicyRequestObservation, observePolicyRequest} from
  './phase5-policy-cost-client.mjs';
import {derivePolicyCostEvidence, describePolicyCostPoint,
  policyCostRawFiles} from './phase5-policy-cost-native.mjs';
import {parseOhaReport, partitionCpus} from './phase5-oha-lanes.mjs';
import {buildProfiledRemoteArgs, captureHelper, currentSource, fileSha,
  metrics, observeIrqPolicy, remoteSha, remoteSource,
  requireNativeCaptureRoot, settleWarmupState, validateReactorObservation,
  validateIrqPolicyTransition, validateRuntimeInventory, validateTlsBundle,
  verifyHostIdentity} from
  './phase5-protocol-p5-t01-executor.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SCRIPTS = path.join(ROOT, 'benchmarks/scripts');
const SAFE_HOST = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SAFE_REMOTE_PATH = /^\/[A-Za-z0-9._/-]+$/u;
const SAFE_SERVICE = /^[A-Za-z0-9@_.-]+$/u;
const CPU_SET = /^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$/u;
const IMAGE = /^\S+@sha256:([0-9a-f]{64})$/u;
const LISTENER_PORT = 8443;
const OPTIONS = Object.freeze([
  '--catalog', '--plan', '--point-id', '--attempt', '--output', '--load-host',
  '--upstream-host', '--load-repository', '--remote-catalog', '--remote-plan',
  '--remote-ca-file', '--request-artifact', '--remote-request-artifact',
  '--upstream-artifact', '--oha-image', '--loadgen-cpu-set', '--loadgen-lanes',
  '--tls-bundle-manifest', '--ca-file', '--runtime-inventory',
  '--gateway-binary', '--jwt-jwks-file', '--service', '--snapshot-file',
  '--metrics-url', '--remote-probe-root',
]);
const OPTIONAL_OPTIONS = new Set([
  '--request-artifact', '--remote-request-artifact', '--jwt-jwks-file',
  '--remote-probe-root',
]);
const INVALID_REASONS = new Set([
  'interrupted', 'collector-failure', 'environment-drift', 'source-drift',
  'artifact-drift', 'load-generator-saturated', 'upstream-saturated',
  'semantic-observation-incomplete',
]);
export const POLICY_COST_COLLECTOR_FILES = Object.freeze([
  'benchmarks/scripts/linux_socket_output.py',
  'benchmarks/scripts/phase5-baseline.mjs',
  'benchmarks/scripts/phase5-oha-lanes.mjs',
  'benchmarks/scripts/phase5-policy-cost-client.mjs',
  'benchmarks/scripts/phase5-policy-campaign.mjs',
  'benchmarks/scripts/phase5-policy-cost-executor.mjs',
  'benchmarks/scripts/phase5-policy-cost-native.mjs',
  'benchmarks/scripts/phase5-policy-cost.mjs',
  'benchmarks/scripts/phase5-protocol-p5-t01-client.mjs',
  'benchmarks/scripts/phase5-protocol-p5-t01-executor.mjs',
  'benchmarks/scripts/phase5-socket-output-collector.sh',
  'benchmarks/scripts/response-path-socket-output.bt',
  'scripts/generate-jwt-smoke-material.py',
]);

function requireValue(condition, message, invalidReason = null) {
  if (!condition) {
    const error = new Error(message);
    if (invalidReason !== null) error.invalidReason = invalidReason;
    throw error;
  }
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function readRegular(filename, label, maximum = 256 * 1024 * 1024) {
  const absolute = path.resolve(filename);
  const stat = fs.lstatSync(absolute);
  requireValue(stat.isFile() && !stat.isSymbolicLink() && stat.size <= maximum,
    `${label} must be a bounded regular non-symlink file`, 'artifact-drift');
  return fs.readFileSync(absolute);
}

function write(filename, value) {
  fs.mkdirSync(path.dirname(filename), {recursive: true, mode: 0o700});
  fs.writeFileSync(filename, value, {mode: 0o600});
}

function writeJson(filename, value) {
  write(filename, `${JSON.stringify(value, null, 2)}\n`);
}

function writeNew(filename, value) {
  fs.mkdirSync(path.dirname(filename), {recursive: true, mode: 0o700});
  fs.writeFileSync(filename, value, {flag: 'wx', mode: 0o600});
}

function integer(value, label, minimum = 1, maximum = Number.MAX_SAFE_INTEGER) {
  const parsed = Number(value);
  requireValue(Number.isSafeInteger(parsed) && parsed >= minimum &&
    parsed <= maximum, `${label} must be between ${minimum} and ${maximum}`);
  return parsed;
}

function expectedRemoteProbeRoot(pointId, attempt) {
  return `/var/tmp/bonvoyage-perf06-${pointId}-a${attempt}-probe`;
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024, input: options.input, cwd: options.cwd});
  requireValue(result.error === undefined,
    `${options.label ?? command} failed to start: ${result.error?.message}`,
    options.invalidReason ?? 'environment-drift');
  if (!options.allowFailure) {
    requireValue(result.status === 0,
      `${options.label ?? command} exited ${result.status}: ${result.stderr.trim()}`,
      options.invalidReason ?? 'environment-drift');
  }
  return result;
}

function ssh(host, args, options = {}) {
  requireValue(SAFE_HOST.test(host), 'SSH host is unsafe');
  requireValue(args.every((item) => typeof item === 'string' &&
    item.length > 0 && !/[\s'"`$;&|<>\\]/u.test(item)),
  'remote command contains unsafe characters');
  return run('ssh', ['-o', 'BatchMode=yes', '-o',
    'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=8', host, ...args],
  options);
}

function scpFrom(host, remoteFile, localFile, label) {
  requireValue(SAFE_HOST.test(host) && SAFE_REMOTE_PATH.test(remoteFile),
    `${label} source is unsafe`);
  return run('scp', ['-q', '-o', 'BatchMode=yes', '-o',
    'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=8',
    `${host}:${remoteFile}`, localFile], {label, invalidReason:
      'semantic-observation-incomplete'});
}

function cpuList(spec, label) {
  requireValue(typeof spec === 'string' && CPU_SET.test(spec),
    `${label} is invalid`);
  const values = [];
  for (const range of spec.split(',')) {
    const [first, last = first] = range.split('-').map(Number);
    requireValue(Number.isSafeInteger(first) && Number.isSafeInteger(last) &&
      first <= last && last - first < 4096, `${label} range is invalid`);
    for (let cpu = first; cpu <= last; cpu += 1) values.push(cpu);
  }
  requireValue(values.length > 0 && new Set(values).size === values.length,
    `${label} is empty or overlaps`);
  return values;
}

function role(description, name) {
  const value = description.topology.roles.find((item) => item.role === name);
  requireValue(value, `PERF-06 plan omits ${name}`);
  return value;
}

export function policyCostCollectorIdentity(root = ROOT) {
  const manifest = POLICY_COST_COLLECTOR_FILES.map((relative) => {
    const bytes = readRegular(path.join(root, relative), relative);
    return `${sha256(bytes)}  ${relative}\n`;
  }).join('');
  return {sha256: sha256(manifest), manifest};
}

export function buildPolicyRemoteClientArgs(options, stage) {
  for (const name of ['repository', 'catalog', 'plan', 'caFile']) {
    requireValue(SAFE_REMOTE_PATH.test(options[name]),
      `remote ${name} path is unsafe`);
  }
  requireValue(['warmup', 'measurement'].includes(stage),
    'PERF-06 remote stage is invalid');
  requireValue(CPU_SET.test(options.cpuSet),
    'PERF-06 load-generator CPU set is invalid');
  requireValue(IMAGE.test(options.image),
    'PERF-06 OHA image is not digest pinned');
  integer(options.lanes, 'PERF-06 load-generator lanes', 2, 16);
  const args = ['node',
    `${options.repository}/benchmarks/scripts/phase5-policy-cost-client.mjs`,
    'run', '--catalog', options.catalog, '--plan', options.plan,
    '--point-id', options.pointId, '--stage', stage, '--image', options.image,
    '--cpu-set', options.cpuSet, '--lanes', String(options.lanes),
    '--ca-file', options.caFile];
  if (options.requestArtifact !== null) {
    requireValue(SAFE_REMOTE_PATH.test(options.requestArtifact),
      'remote PERF-06 request artifact path is unsafe');
    args.push('--request-artifact', options.requestArtifact);
  }
  return args;
}

export function buildPolicyProbeArgs(options) {
  for (const name of ['repository', 'catalog', 'plan', 'caFile', 'output']) {
    requireValue(SAFE_REMOTE_PATH.test(options[name]),
      `remote probe ${name} path is unsafe`);
  }
  requireValue(/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(options.targetAddress),
    'remote probe target address is invalid');
  const args = ['node',
    `${options.repository}/benchmarks/scripts/phase5-policy-cost-client.mjs`,
    'probe', '--catalog', options.catalog, '--plan', options.plan,
    '--point-id', options.pointId, '--ca-file', options.caFile,
    '--target-address', options.targetAddress, '--output', options.output];
  if (options.requestArtifact !== null) {
    requireValue(SAFE_REMOTE_PATH.test(options.requestArtifact),
      'remote probe request artifact path is unsafe');
    args.push('--request-artifact', options.requestArtifact);
  }
  return args;
}

export function buildPolicyProfiledStageArgs(options) {
  return buildProfiledRemoteArgs({...options,
    remoteCommand: buildPolicyRemoteClientArgs(options.client,
      options.stage ?? 'measurement')});
}

export function classifyPolicyCostFailure(error) {
  if (INVALID_REASONS.has(error?.invalidReason)) return error.invalidReason;
  const message = String(error?.message ?? error).toLowerCase();
  if (/interrupt|signal|sigint|sigterm/u.test(message)) return 'interrupted';
  if (/\bsource\b|\bcommit\b|\bclean tree\b|\bworking tree\b/u.test(message)) {
    return 'source-drift';
  }
  if (/snapshot|digest|binary|artifact|image|bundle/u.test(message)) {
    return 'artifact-drift';
  }
  if (/protocol|semantic|tls|response|probe/u.test(message)) {
    return 'semantic-observation-incomplete';
  }
  if (/load.generator.*saturat/u.test(message)) return 'load-generator-saturated';
  if (/upstream.*saturat/u.test(message)) return 'upstream-saturated';
  if (/collector|perf|bpftrace|client/u.test(message)) return 'collector-failure';
  return 'environment-drift';
}

function safeMessage(error) {
  return String(error?.message ?? error)
    .replace(/Bearer\s+[^\s"']+/giu, 'Bearer [REDACTED]')
    .replace(/(x-api-key\s*[:=]\s*)[^\s"']+/giu, '$1[REDACTED]')
    .slice(0, 8192);
}

function fileReference(filename, evidenceRoot) {
  const absolute = path.resolve(filename);
  const root = path.resolve(evidenceRoot);
  requireValue(absolute.startsWith(`${root}${path.sep}`),
    'PERF-06 evidence reference escapes its root');
  const bytes = readRegular(absolute, 'PERF-06 evidence reference');
  return {path: path.relative(root, absolute).split(path.sep).join('/'),
    sha256: sha256(bytes), bytes: bytes.length};
}

function treeRecords(root) {
  if (!fs.existsSync(root)) return [];
  const records = [];
  const visit = (directory) => {
    for (const name of fs.readdirSync(directory).sort()) {
      const absolute = path.join(directory, name);
      const stat = fs.lstatSync(absolute);
      requireValue(!stat.isSymbolicLink(),
        'PERF-06 partial attempt contains a symlink');
      if (stat.isDirectory()) visit(absolute);
      else if (stat.isFile()) {
        const bytes = fs.readFileSync(absolute);
        records.push({path: path.relative(root, absolute).split(path.sep).join('/'),
          sha256: sha256(bytes), bytes: bytes.length});
      } else {
        throw new Error('PERF-06 partial attempt contains a non-regular member');
      }
    }
  };
  visit(root);
  return records;
}

export function buildPolicyAttemptLayout(output, pointId, attempt) {
  const root = path.resolve(output);
  requireValue(/^P5-(?:B02|C0[0-5])-24c-directional-r1$/u.test(pointId),
    'PERF-06 point ID is invalid');
  integer(attempt, 'PERF-06 attempt');
  const stem = `${pointId}-a${attempt}`;
  return {root, raw: path.join(root, 'raw'),
    diagnostics: path.join(root, 'diagnostics'),
    evidence: path.join(root, 'evidence'),
    failure: path.join(root, 'evidence', 'attempts', stem), stem};
}

export function validateJwtRunway(observation, plan, nowEpochMs) {
  if (observation.mode !== 'ephemeral-jwt') return observation;
  requireValue(Number.isSafeInteger(nowEpochMs) && nowEpochMs > 0,
    'PERF-06 JWT preflight clock is invalid');
  const window = observation.jwt_window;
  const workload = plan.input.workload;
  const jwt = plan.input.jwt;
  const safetyMs = 10000;
  const profiledWarmups = workload.profiled_warmup_repetitions ?? 1;
  const totalWarmupSeconds = workload.warmup_seconds * profiledWarmups;
  requireValue(jwt.maximum_age_seconds_at_start * 1000 >=
    totalWarmupSeconds * 1000 + safetyMs,
  'PERF-06 JWT freshness budget cannot cover profiled warmups plus safety margin',
  'artifact-drift');
  requireValue(window.issued_at_epoch_ms <= nowEpochMs + 5000 &&
    nowEpochMs - window.issued_at_epoch_ms <=
      jwt.maximum_age_seconds_at_start * 1000 &&
    window.expires_at_epoch_ms - nowEpochMs >=
      (totalWarmupSeconds + workload.measurement_seconds +
        jwt.minimum_remaining_lifetime_seconds_at_end) * 1000 + safetyMs,
  'PERF-06 JWT does not cover profiled warmups, measurement, and remaining-life gates',
  'artifact-drift');
  requireValue(window.expires_at_epoch_ms - window.issued_at_epoch_ms <= 300000,
    'PERF-06 JWT exceeds the configured 300-second token lifetime',
    'artifact-drift');
  return observation;
}

function prometheusMetricTotal(raw, name, label) {
  let total = 0;
  let samples = 0;
  for (const source of raw.split(/\r?\n/u)) {
    const line = source.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{[^}]*\})?\s+(\S+)(?:\s+\d+)?$/u
      .exec(line);
    if (match?.[1] !== name) continue;
    const value = Number(match[2]);
    requireValue(Number.isSafeInteger(value) && value >= 0,
      `${label} contains an invalid sample`, 'collector-failure');
    total += value;
    samples += 1;
  }
  requireValue(samples > 0 && Number.isSafeInteger(total),
    `${label} is missing or exceeds the safe integer range`,
    'collector-failure');
  return total;
}

function warmupDescriptorCounts(descriptors, policy) {
  const controlled = descriptors.entries.filter((entry) =>
    entry.kind === 'tcp-socket' && entry.tcp?.state === 'ESTABLISHED' &&
    entry.tcp.remote_address === policy.remote_address &&
    entry.tcp.remote_port === policy.remote_port).length;
  requireValue(controlled <= policy.maximum_connections,
    'PERF-06 warmup exceeded the controlled-upstream descriptor bound',
    'environment-drift');
  return {controlled_upstream_connections: controlled,
    non_controlled_descriptors: descriptors.total - controlled};
}

function policyWarmupPassRecord(pass, report, settlement, schemaVersion,
  descriptorPolicy) {
  const successfulRequests = report.statusCodeDistribution?.['200'] ?? 0;
  const httpFailures = Object.entries(report.statusCodeDistribution ?? {})
    .reduce((total, [status, count]) => status === '200' ? total : total + count,
      0);
  const transportFailures = Object.values(report.errorDistribution ?? {})
    .reduce((total, count) => total + count, 0);
  const record = {pass, settled: settlement.settled,
    settlement_ms: settlement.elapsed_ms,
    identity: settlement.state.resource.identity,
    restart_count: settlement.state.resource.restart_count,
    rss_bytes: settlement.state.resource.rss_bytes,
    file_descriptors: settlement.state.resource.file_descriptors,
    successful_requests: successfulRequests, http_failures: httpFailures,
    transport_failures: transportFailures};
  if (schemaVersion >= 4) {
    Object.assign(record, warmupDescriptorCounts(
      settlement.state.descriptors, descriptorPolicy), {
      allocated_memory_bytes: prometheusMetricTotal(settlement.metrics,
        'bonvoyage_memory_allocated_memory',
        `PERF-06 warmup pass ${pass} allocated-memory metric`),
      malloc_live_objects: prometheusMetricTotal(settlement.metrics,
        'bonvoyage_memory_malloc_live_objects',
        `PERF-06 warmup pass ${pass} live-object metric`),
    });
  }
  return record;
}

export function buildPolicyWarmupAdmission(plan, point, passes) {
  const required = plan.input.workload.profiled_warmup_repetitions;
  requireValue(plan.schema_version >= 3 &&
    required === POLICY_COST_PROFILED_WARMUP_REPETITIONS &&
    Array.isArray(passes) && passes.length === required,
  'PERF-06 profiled warmup passes are incomplete');
  const expectedSuccesses = point.offered_rps *
    plan.input.workload.warmup_seconds;
  const controlledUpstreamLimit = plan.schema_version >= 4 ?
    plan.input.topology.controlled_upstream.max_connections_per_shard *
      point.core_count : null;
  let identity;
  for (const [index, pass] of passes.entries()) {
    identity ??= pass.identity;
    const boundedFieldsValid = plan.schema_version < 4 ||
      [pass.allocated_memory_bytes, pass.malloc_live_objects,
        pass.controlled_upstream_connections,
        pass.non_controlled_descriptors].every((value) =>
        Number.isSafeInteger(value) && value >= 0) &&
      pass.file_descriptors === pass.controlled_upstream_connections +
        pass.non_controlled_descriptors &&
      pass.controlled_upstream_connections <= controlledUpstreamLimit;
    requireValue(pass.pass === index + 1 && pass.settled === true &&
      pass.identity === identity && pass.restart_count === 0 &&
      pass.successful_requests === expectedSuccesses &&
      pass.http_failures === 0 && pass.transport_failures === 0 &&
      pass.settlement_ms <= plan.input.workload.maximum_cleanup_ms &&
      boundedFieldsValid,
    `PERF-06 profiled warmup pass ${index + 1} failed admission`);
  }
  const penultimate = passes.at(-2);
  const final = passes.at(-1);
  const rssDelta = final.rss_bytes - penultimate.rss_bytes;
  const fdDelta = final.file_descriptors - penultimate.file_descriptors;
  if (plan.schema_version === 3) {
    requireValue(rssDelta === 0 && fdDelta === 0,
      'PERF-06 final profiled warmups did not establish an exact resource plateau');
    return {schema_version: 1,
      required_profiled_warmup_repetitions: required, passes,
      plateau: {compared_passes: [required - 1, required],
        rss_delta_bytes: rssDelta, fd_delta: fdDelta, stable: true}};
  }

  requireValue(plan.schema_version >= 4,
    'PERF-06 bounded warmup convergence requires schema v4');
  const allocatedMemoryDelta = final.allocated_memory_bytes -
    penultimate.allocated_memory_bytes;
  const liveObjectDelta = final.malloc_live_objects -
    penultimate.malloc_live_objects;
  const controlledUpstreamDelta = final.controlled_upstream_connections -
    penultimate.controlled_upstream_connections;
  const unaccountedFdDelta = final.non_controlled_descriptors -
    penultimate.non_controlled_descriptors;
  const maximumMemoryGrowth =
    plan.input.workload.maximum_retained_rss_growth_bytes;
  requireValue(Number.isSafeInteger(allocatedMemoryDelta) &&
    Number.isSafeInteger(liveObjectDelta) &&
    Number.isSafeInteger(controlledUpstreamDelta) &&
    Number.isSafeInteger(unaccountedFdDelta) &&
    rssDelta <= maximumMemoryGrowth &&
    allocatedMemoryDelta <= maximumMemoryGrowth &&
    unaccountedFdDelta <= 0 &&
    penultimate.controlled_upstream_connections <= controlledUpstreamLimit &&
    final.controlled_upstream_connections <= controlledUpstreamLimit,
  'PERF-06 final profiled warmups did not establish bounded resource convergence');
  return {schema_version: 2,
    required_profiled_warmup_repetitions: required, passes,
    convergence: {compared_passes: [required - 1, required],
      rss_delta_bytes: rssDelta,
      allocated_memory_delta_bytes: allocatedMemoryDelta,
      malloc_live_object_delta: liveObjectDelta,
      fd_delta: fdDelta,
      controlled_upstream_connection_delta: controlledUpstreamDelta,
      unaccounted_fd_delta: unaccountedFdDelta,
      maximum_memory_growth_bytes: maximumMemoryGrowth,
      maximum_unaccounted_fd_growth: 0,
      controlled_upstream_connection_limit: controlledUpstreamLimit,
      contained: true}};
}

export function buildPolicyCaptureStatus(warmupExitCode,
    measurementExitCode, collectorExitCode, protocolProbeExitCode) {
  return {warmup_command_exit_code: warmupExitCode ?? 1,
    measurement_command_exit_code: measurementExitCode ?? 1,
    collector_exit_code: collectorExitCode ?? 1,
    protocol_probe_exit_code: protocolProbeExitCode ?? 1};
}

export function validatePolicyRuntimeSecrets(description, options, plan) {
  if (description.point.request.mode !== 'ephemeral-jwt') return;
  requireValue(typeof options.jwtJwksFile === 'string' &&
    fileSha(options.jwtJwksFile, 'PERF-06 active JWT JWKS') ===
      plan.input.artifacts.jwt_jwks_sha256,
  'PERF-06 active JWT JWKS differs from the plan', 'artifact-drift');
}

export function evaluatePolicyRecovery(before, after, activeValues) {
  requireValue(before && after && Array.isArray(activeValues),
    'PERF-06 recovery observation is incomplete');
  const processStable = before.identity === after.identity &&
    before.pid === after.pid && before.start_ticks === after.start_ticks &&
    before.restart_count === after.restart_count && after.restart_count === 0;
  const drained = activeValues.length >= 5 && activeValues.every((value) =>
    Number.isFinite(value) && value === 0);
  return {process_stable: processStable, active_metrics_drained: drained,
    recovered: processStable && drained};
}

function activeMetricValues(value) {
  return [...value.matchAll(/^bonvoyage_bonvoyage_gateway_active_(?:requests|route_requests|upstream_requests|upstream_http1_requests|http2_streams)(?:\{[^}]*\})?\s+(\S+)/gmu)]
    .map((match) => Number(match[1]));
}

function fixedProvenance(description, source, catalogSha256, sourceStatus) {
  return {schema_version: 1, plan_id: description.plan_id,
    point_id: description.point.point_id,
    profile_id: description.point.profile_id,
    repetition: description.point.repetition, source,
    catalog_sha256: catalogSha256,
    snapshot_sha256: description.point.snapshot_sha256,
    observed_harness_commit: source.harness_commit,
    source_status: sourceStatus};
}

function exactRawManifest(rawRoot, schemaVersion) {
  const expectedFiles = policyCostRawFiles(schemaVersion);
  const actual = fs.readdirSync(rawRoot).sort();
  requireValue(isDeepStrictEqual(actual, [...expectedFiles].sort()),
    'PERF-06 raw collector output is incomplete or contains unbound files',
    'collector-failure');
  const lines = expectedFiles.map((name) => {
    const bytes = readRegular(path.join(rawRoot, name), `PERF-06 raw ${name}`);
    return `${sha256(bytes)}  ${name}\n`;
  }).join('');
  write(path.join(rawRoot, 'checksums.sha256'), lines);
}

function sealTree(root) {
  const records = treeRecords(root).filter((record) =>
    record.path !== 'checksums.sha256');
  write(path.join(root, 'checksums.sha256'), records.map((record) =>
    `${record.sha256}  ${record.path}\n`).join(''));
}

function attemptEnvironment(description, attempt, reactors = null) {
  return {schema_version: 1, plan_id: description.plan_id,
    point_id: description.point.point_id,
    profile_id: description.point.profile_id,
    repetition: description.point.repetition, attempt,
    roles: description.topology.roles,
    load_generator_cpu_set: description.topology.load_generator_cpu_set,
    load_generator_lanes: description.topology.load_generator_lanes,
    gateway_cpu_set: description.topology.gateway_cpu_set,
    housekeeping_cpu_set: description.topology.housekeeping_cpu_set,
    irq_policy: description.topology.irq_policy,
    profiler_scope: description.profiler_scope,
    reactor_tids_before: reactors?.before ?? [],
    reactor_tids_after: reactors?.after ?? [],
    profiled_reactor_tids: reactors?.profiled ?? []};
}

export function retainInvalidPolicyAttempt(options) {
  const {layout, description, plan, catalogBytes, attempt, error} = options;
  fs.mkdirSync(layout.failure, {recursive: true, mode: 0o700});
  const partial = path.join(layout.failure, 'partial-archive.json');
  const log = path.join(layout.failure, 'attempt-log.json');
  const environment = path.join(layout.failure, 'environment.json');
  writeNew(partial, `${JSON.stringify({schema_version: 1,
    point_id: description.point.point_id, attempt,
    raw: treeRecords(layout.raw), diagnostics: treeRecords(layout.diagnostics),
    publication_authorized: false}, null, 2)}\n`);
  const reason = classifyPolicyCostFailure(error);
  writeNew(log, `${JSON.stringify({schema_version: 1,
    point_id: description.point.point_id, attempt, invalid_reason: reason,
    message: safeMessage(error), values_retained: false,
    publication_authorized: false}, null, 2)}\n`);
  writeNew(environment, `${JSON.stringify(attemptEnvironment(description,
    attempt), null, 2)}\n`);
  const input = {schema_version: plan.schema_version, plan_id: plan.plan_id,
    point_id: description.point.point_id,
    profile_id: description.point.profile_id, attempt,
    evidence_status: 'invalid', invalid_reason: reason,
    source: plan.input.source,
    snapshot_sha256: description.point.snapshot_sha256,
    request: null, protocol: null, runtime: null, metrics: null,
    files: {partial_archive: fileReference(partial, layout.evidence),
      attempt_log: fileReference(log, layout.evidence),
      environment: fileReference(environment, layout.evidence)}};
  const result = buildPolicyCostResult(input, plan, catalogBytes);
  const resultFile = path.join(layout.evidence,
    `${description.point.point_id}.attempt-${attempt}.result.json`);
  writeNew(resultFile, `${JSON.stringify(result, null, 2)}\n`);
  return {reason, result, resultFile};
}

function parseOptions(argv) {
  requireValue(argv.length % 2 === 0,
    'PERF-06 capture options require name/value pairs');
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    requireValue(OPTIONS.includes(name) && value && !value.startsWith('--'),
      `unknown or valueless PERF-06 capture option: ${name}`);
    requireValue(!values.has(name), `${name} may appear only once`);
    values.set(name, value);
  }
  for (const name of OPTIONS.filter((item) => !OPTIONAL_OPTIONS.has(item))) {
    requireValue(values.has(name), `${name} is required`);
  }
  const pointId = values.get('--point-id');
  const attempt = integer(values.get('--attempt'), 'PERF-06 attempt');
  const output = path.resolve(values.get('--output'));
  const options = {catalog: path.resolve(values.get('--catalog')),
    plan: path.resolve(values.get('--plan')), pointId, attempt, output,
    loadHost: values.get('--load-host'),
    upstreamHost: values.get('--upstream-host'),
    loadRepository: values.get('--load-repository'),
    remoteCatalog: values.get('--remote-catalog'),
    remotePlan: values.get('--remote-plan'),
    remoteCaFile: values.get('--remote-ca-file'),
    requestArtifact: values.has('--request-artifact') ?
      path.resolve(values.get('--request-artifact')) : null,
    remoteRequestArtifact: values.get('--remote-request-artifact') ?? null,
    upstreamArtifact: values.get('--upstream-artifact'),
    ohaImage: values.get('--oha-image'),
    loadCpuSet: values.get('--loadgen-cpu-set'),
    loadLanes: integer(values.get('--loadgen-lanes'),
      'PERF-06 load-generator lanes', 2, 16),
    tlsManifest: path.resolve(values.get('--tls-bundle-manifest')),
    caFile: path.resolve(values.get('--ca-file')),
    runtimeInventory: path.resolve(values.get('--runtime-inventory')),
    gatewayBinary: path.resolve(values.get('--gateway-binary')),
    jwtJwksFile: values.has('--jwt-jwks-file') ?
      path.resolve(values.get('--jwt-jwks-file')) : null,
    service: values.get('--service'),
    snapshotFile: path.resolve(values.get('--snapshot-file')),
    metricsUrl: values.get('--metrics-url'),
    remoteProbeRoot: values.get('--remote-probe-root') ??
      expectedRemoteProbeRoot(pointId, attempt)};
  requireValue(SAFE_HOST.test(options.loadHost) &&
    SAFE_HOST.test(options.upstreamHost) &&
    options.loadHost !== options.upstreamHost,
  'PERF-06 support hosts are invalid or duplicated');
  for (const name of ['loadRepository', 'remoteCatalog', 'remotePlan',
    'remoteCaFile', 'upstreamArtifact', 'remoteProbeRoot']) {
    requireValue(SAFE_REMOTE_PATH.test(options[name]),
      `PERF-06 ${name} path is unsafe`);
  }
  requireValue(options.remoteRequestArtifact === null ||
    SAFE_REMOTE_PATH.test(options.remoteRequestArtifact),
  'PERF-06 remote request artifact path is unsafe');
  requireValue(options.remoteProbeRoot ===
    expectedRemoteProbeRoot(pointId, attempt),
  'PERF-06 remote probe root must use its attempt-scoped /var/tmp path');
  requireValue(CPU_SET.test(options.loadCpuSet) && IMAGE.test(options.ohaImage) &&
    SAFE_SERVICE.test(options.service),
  'PERF-06 CPU set, image, or service is invalid');
  requireValue(/^http:\/\/127\.0\.0\.1:\d+\/metrics$/u.test(options.metricsUrl),
    'PERF-06 metrics URL must be an IPv4 loopback endpoint');
  requireValue(output !== ROOT && !output.startsWith(`${ROOT}${path.sep}`),
    'PERF-06 native output must be outside the source checkout');
  return options;
}

function observeSource(options) {
  const local = currentSource();
  const image = IMAGE.exec(options.ohaImage);
  const tls = validateTlsBundle(options.tlsManifest, options.caFile);
  const inventory = validateRuntimeInventory(options.runtimeInventory,
    options.gatewayBinary);
  return {source: {binary_source_commit: inventory.producerSourceCommit,
    harness_commit: local.commit, source_dirty: local.status !== '',
    gateway_binary_sha256: fileSha(options.gatewayBinary, 'gateway binary'),
    client_sha256: image[1],
    upstream_sha256: remoteSha(options.upstreamHost,
      options.upstreamArtifact, 'controlled upstream'),
    collector_bundle_sha256: policyCostCollectorIdentity().sha256,
    tls_bundle_sha256: tls.sha256}, sourceStatus: local.status,
  caSha256: tls.ca_sha256};
}

function remoteClient(options) {
  return {repository: options.loadRepository, catalog: options.remoteCatalog,
    plan: options.remotePlan, caFile: options.remoteCaFile,
    pointId: options.pointId, image: options.ohaImage,
    cpuSet: options.loadCpuSet, lanes: options.loadLanes,
    requestArtifact: options.remoteRequestArtifact};
}

function collectProbe(options, description, diagnostics, raw) {
  const gateway = role(description, 'gateway');
  const command = buildPolicyProbeArgs({...remoteClient(options),
    targetAddress: gateway.private_address, output: options.remoteProbeRoot});
  const result = ssh(options.loadHost, command, {allowFailure: true,
    label: 'PERF-06 protocol probe',
    invalidReason: 'semantic-observation-incomplete'});
  write(path.join(diagnostics, 'protocol-probe.stdout'), result.stdout);
  write(path.join(diagnostics, 'protocol-probe.stderr'), result.stderr);
  requireValue(result.status === 0,
    `PERF-06 protocol probe exited ${result.status}`,
    'semantic-observation-incomplete');
  for (const name of ['protocol-status.txt', 'protocol-headers.txt',
    'protocol-body.bin', 'tls-observation.json']) {
    scpFrom(options.loadHost, `${options.remoteProbeRoot}/${name}`,
      path.join(raw, name), `PERF-06 protocol ${name}`);
  }
  return result.status;
}

function cleanupRemoteProbe(options, diagnostics, required) {
  try {
    const cleanup = ssh(options.loadHost,
      ['rm', '-rf', options.remoteProbeRoot], {allowFailure: true,
        label: 'PERF-06 remote probe cleanup'});
    writeJson(path.join(diagnostics, 'remote-probe-cleanup.json'),
      {exit_code: cleanup.status ?? 1,
        stderr: cleanup.stderr.slice(0, 4096)});
    if (required) {
      requireValue(cleanup.status === 0,
        `PERF-06 remote probe cleanup exited ${cleanup.status}`,
        'collector-failure');
    }
    return cleanup.status === 0;
  } catch (error) {
    writeJson(path.join(diagnostics, 'remote-probe-cleanup.json'),
      {exit_code: 1, error: safeMessage(error)});
    if (required) throw error;
    return false;
  }
}

function verifyRemoteArtifacts(options, description, catalogBytes,
  requestObservation) {
  const remote = remoteSource(options.loadHost, options.loadRepository);
  requireValue(remote.commit === description.source.harness_commit &&
    remote.status === '', 'load-generator source differs from the clean plan',
  'source-drift');
  requireValue(remoteSha(options.loadHost, options.remoteCatalog,
    'remote PERF-06 catalog') === sha256(catalogBytes) &&
    remoteSha(options.loadHost, options.remotePlan,
      'remote PERF-06 plan') === fileSha(options.plan, 'PERF-06 plan') &&
    remoteSha(options.loadHost, options.remoteCaFile,
      'remote PERF-06 CA') === fileSha(options.caFile, 'PERF-06 CA'),
  'load-generator control artifacts differ from the gateway host',
  'artifact-drift');
  if (requestObservation.mode === 'none') {
    requireValue(options.requestArtifact === null &&
      options.remoteRequestArtifact === null,
    'plain PERF-06 point unexpectedly has request artifacts', 'artifact-drift');
  } else {
    requireValue(options.requestArtifact !== null &&
      options.remoteRequestArtifact !== null &&
      remoteSha(options.loadHost, options.remoteRequestArtifact,
        'remote PERF-06 request artifact') ===
        requestObservation.artifact_sha256,
    'remote PERF-06 request artifact differs from the local identity',
    'artifact-drift');
  }
  return remote;
}

function captureRecovery(runtime, before, maximumCleanupMs) {
  try {
    const settled = settleWarmupState({maximumCleanupMs,
      expectedIdentity: before.identity,
      captureState: () => captureHelper('state', runtime),
      captureMetrics: () => metrics(runtime.metricsUrl)});
    return {...evaluatePolicyRecovery(before, settled.state.resource,
      activeMetricValues(settled.metrics)), settlement_ms: settled.elapsed_ms,
    observations: settled.observations};
  } catch (error) {
    return {process_stable: false, active_metrics_drained: false,
      recovered: false, error: safeMessage(error)};
  }
}

function runCapture(options) {
  requireNativeCaptureRoot();
  requireValue(!fs.existsSync(options.output),
    'PERF-06 native output already exists');
  const catalogBytes = readRegular(options.catalog, 'PERF-06 catalog');
  const plan = JSON.parse(readRegular(options.plan, 'PERF-06 plan'));
  validatePolicyCostPlan(plan, catalogBytes);
  const description = describePolicyCostPoint(plan, catalogBytes,
    options.pointId);
  const layout = buildPolicyAttemptLayout(options.output, options.pointId,
    options.attempt);
  fs.mkdirSync(layout.root, {mode: 0o700});
  fs.mkdirSync(layout.raw, {mode: 0o700});
  fs.mkdirSync(layout.diagnostics, {mode: 0o700});
  let succeeded = false;
  let failure = null;
  let baselineResource = null;
  let remoteProbeTouched = false;
  const runtime = {...options,
    intervalId: `${options.pointId}-a${options.attempt}`};
  try {
    const request = validateJwtRunway(observePolicyRequest(description.point,
      options.requestArtifact), plan, Date.now());
    validatePolicyRuntimeSecrets(description, options, plan);
    const plannedClientSets = partitionCpus(
      description.topology.load_generator_cpu_set.join(','), options.loadLanes);
    const observedClientSets = partitionCpus(options.loadCpuSet,
      options.loadLanes);
    requireValue(options.loadLanes ===
      description.topology.load_generator_lanes &&
      isDeepStrictEqual(observedClientSets, plannedClientSets),
    'PERF-06 executor load-generator placement differs from the plan',
    'environment-drift');
    const gateway = role(description, 'gateway');
    const load = role(description, 'load_generator');
    const upstream = role(description, 'controlled_upstream');
    const descriptorPolicy = plan.schema_version >= 2 ? {
      remote_address: upstream.private_address,
      remote_port: description.topology.controlled_upstream.port,
      maximum_connections:
        description.topology.controlled_upstream.max_connections_per_shard *
        description.point.core_count,
    } : null;
    verifyHostIdentity(gateway);
    verifyHostIdentity(load, options.loadHost);
    verifyHostIdentity(upstream, options.upstreamHost);
    const irqExpected = {mode: description.topology.irq_policy,
      gateway_banned_cpus: description.topology.gateway_cpu_set,
      irq_target_cpus: description.topology.housekeeping_cpu_set};
    const irqBefore = observeIrqPolicy(irqExpected,
      load.private_address, 'PERF-06 IRQ policy before');
    writeJson(path.join(layout.diagnostics, 'irq-before.json'), irqBefore);
    const observedBefore = observeSource(options);
    requireValue(isDeepStrictEqual(observedBefore.source,
      description.source) && observedBefore.sourceStatus === '',
    'observed PERF-06 source differs from the clean plan', 'source-drift');
    requireValue(fileSha(options.snapshotFile, 'active PERF-06 snapshot') ===
      description.point.snapshot_sha256,
    'active PERF-06 snapshot differs from the plan', 'artifact-drift');
    const remoteBefore = verifyRemoteArtifacts(options, description,
      catalogBytes, request);
    writeJson(path.join(layout.raw, 'binary-observation.json'),
      {schema_version: 1, source: observedBefore.source});
    writeJson(path.join(layout.raw, 'provenance-before.json'),
      fixedProvenance(description, observedBefore.source,
        plan.input.catalog_sha256, observedBefore.sourceStatus));

    const initial = captureHelper('state', runtime);
    requireValue(initial.resource.restart_count === 0,
      'gateway restart count is nonzero before PERF-06', 'environment-drift');
    baselineResource = initial.resource;
    remoteProbeTouched = true;
    const probeStatus = collectProbe(options, description,
      layout.diagnostics, layout.raw);
    cleanupRemoteProbe(options, layout.diagnostics, true);
    remoteProbeTouched = false;
    const client = remoteClient(options);
    let warmupState;
    let warmupCommandExitCode = 1;
    if (plan.schema_version >= 3) {
      const warmupPasses = [];
      warmupState = initial;
      for (let pass = 1;
        pass <= plan.input.workload.profiled_warmup_repetitions; pass += 1) {
        const label = `warmup-pass-${pass}`;
        const reactorObservation = captureHelper('reactors', runtime,
          ['--expected-count', String(description.point.core_count)]);
        const reactorTids = validateReactorObservation(reactorObservation,
          description.topology.gateway_cpu_set,
          `PERF-06 ${label} reactor placement`);
        writeJson(path.join(layout.diagnostics, `${label}-reactors.json`),
          reactorObservation);
        const socketRoot = path.join(layout.diagnostics, `${label}-socket`);
        const retainedOutput = path.join(layout.diagnostics,
          `${label}.oha.json`);
        const collector = run(path.join(SCRIPTS,
          'phase5-socket-output-collector.sh'), buildPolicyProfiledStageArgs({
          output: socketRoot, service: options.service,
          snapshotFile: options.snapshotFile, downstreamPort: LISTENER_PORT,
          intervalId: `${options.pointId}-${label}`,
          perfOutput: path.join(layout.diagnostics, `${label}-perf.csv`),
          perfTids: reactorTids, loadHost: options.loadHost, client,
          stage: 'warmup'}), {allowFailure: true,
          label: `PERF-06 profiled warmup pass ${pass}`,
          invalidReason: 'collector-failure'});
        write(path.join(layout.diagnostics, `${label}-collector.stdout`),
          collector.stdout);
        write(path.join(layout.diagnostics, `${label}-collector.stderr`),
          collector.stderr);
        const clientExit = path.join(socketRoot, 'client-exit-code.txt');
        const clientStatus = fs.existsSync(clientExit) ?
          Number(fs.readFileSync(clientExit, 'utf8').trim()) :
          (collector.status ?? 1);
        const clientOutput = path.join(socketRoot, 'client.stdout');
        const clientError = path.join(socketRoot, 'client.stderr');
        if (fs.existsSync(clientOutput)) {
          fs.copyFileSync(clientOutput, retainedOutput);
        }
        write(path.join(layout.diagnostics, `${label}.stderr`),
          fs.existsSync(clientError) ? fs.readFileSync(clientError) : '');
        requireValue(collector.status === 0 && clientStatus === 0 &&
          fs.existsSync(retainedOutput),
        `PERF-06 profiled warmup pass ${pass} failed`,
        'collector-failure');
        const report = parseOhaReport(fs.readFileSync(retainedOutput, 'utf8'));
        const settlement = settleWarmupState({
          maximumCleanupMs: plan.input.workload.maximum_cleanup_ms,
          expectedIdentity: initial.resource.identity,
          captureState: () => captureHelper('state', runtime),
          captureMetrics: () => metrics(options.metricsUrl)});
        const {metrics: finalMetrics, state, ...diagnostic} = settlement;
        writeJson(path.join(layout.diagnostics, `${label}-settlement.json`),
          diagnostic);
        write(path.join(layout.diagnostics,
          `${label}-final-metrics.prom`), finalMetrics);
        if (plan.schema_version >= 4) {
          writeJson(path.join(layout.raw, `${label}-descriptors.json`),
            state.descriptors);
          write(path.join(layout.raw, `${label}-final-metrics.prom`),
            finalMetrics);
        }
        requireValue(settlement.settled,
          `PERF-06 profiled warmup pass ${pass} did not settle`,
          'environment-drift');
        warmupPasses.push(policyWarmupPassRecord(pass, report, settlement,
          plan.schema_version, descriptorPolicy));
        warmupState = state;
        if (pass === plan.input.workload.profiled_warmup_repetitions) {
          fs.copyFileSync(retainedOutput,
            path.join(layout.raw, 'warmup.oha.json'));
        }
      }
      writeJson(path.join(layout.raw, 'warmup-admission.json'),
        buildPolicyWarmupAdmission(plan, description.point, warmupPasses));
      warmupCommandExitCode = 0;
    } else {
      const warmup = ssh(options.loadHost,
        buildPolicyRemoteClientArgs(client, 'warmup'), {allowFailure: true,
          label: 'PERF-06 warmup', invalidReason: 'collector-failure'});
      write(path.join(layout.raw, 'warmup.oha.json'), warmup.stdout);
      write(path.join(layout.diagnostics, 'warmup.stderr'), warmup.stderr);
      requireValue(warmup.status === 0,
        `PERF-06 warmup exited ${warmup.status}`, 'collector-failure');
      warmupCommandExitCode = warmup.status ?? 1;
      const settlement = settleWarmupState({
        maximumCleanupMs: plan.input.workload.maximum_cleanup_ms,
        expectedIdentity: initial.resource.identity,
        captureState: () => captureHelper('state', runtime),
        captureMetrics: () => metrics(options.metricsUrl)});
      writeJson(path.join(layout.diagnostics, 'warmup-settlement.json'),
        {settled: settlement.settled, elapsed_ms: settlement.elapsed_ms,
          observations: settlement.observations});
      requireValue(settlement.settled,
        'PERF-06 warmup did not settle before measurement',
        'environment-drift');
      warmupState = settlement.state;
    }
    baselineResource = warmupState.resource;
    writeJson(path.join(layout.diagnostics, 'descriptors-before.json'),
      warmupState.descriptors);
    if (plan.schema_version >= 2) {
      writeJson(path.join(layout.raw, 'descriptors-before.json'),
        warmupState.descriptors);
    }
    const reactorBeforeObservation = captureHelper('reactors', runtime,
      ['--expected-count', String(description.point.core_count)]);
    const reactorsBefore = validateReactorObservation(
      reactorBeforeObservation, description.topology.gateway_cpu_set,
      'PERF-06 reactor placement before');
    writeJson(path.join(layout.diagnostics, 'reactors-before.json'),
      reactorBeforeObservation);
    writeJson(path.join(layout.raw, 'resource-before.json'), baselineResource);
    write(path.join(layout.raw, 'gateway-metrics-before.prom'),
      metrics(options.metricsUrl));
    write(path.join(layout.raw, 'gateway-proc-before.txt'),
      fs.readFileSync('/proc/stat'));
    write(path.join(layout.raw, 'load-generator-proc-before.txt'),
      ssh(options.loadHost, ['cat', '/proc/stat']).stdout);
    write(path.join(layout.raw, 'upstream-proc-before.txt'),
      ssh(options.upstreamHost, ['cat', '/proc/stat']).stdout);

    const socketRoot = path.join(layout.diagnostics, 'socket-output');
    const startedAt = Date.now();
    const collector = run(path.join(SCRIPTS,
      'phase5-socket-output-collector.sh'), buildPolicyProfiledStageArgs({
      output: socketRoot, service: options.service,
      snapshotFile: options.snapshotFile, downstreamPort: LISTENER_PORT,
      intervalId: options.pointId, perfOutput: path.join(layout.raw, 'perf.csv'),
      perfTids: reactorsBefore, loadHost: options.loadHost, client}),
    {allowFailure: true, label: 'PERF-06 socket/perf collector',
      invalidReason: 'collector-failure'});
    const endedAt = Date.now();
    write(path.join(layout.diagnostics, 'collector.stdout'), collector.stdout);
    write(path.join(layout.diagnostics, 'collector.stderr'), collector.stderr);
    const clientExitFile = path.join(socketRoot, 'client-exit-code.txt');
    const clientStatus = fs.existsSync(clientExitFile) ?
      Number(fs.readFileSync(clientExitFile, 'utf8').trim()) :
      (collector.status ?? 1);
    for (const [source, target] of [
      ['client.stdout', 'measurement.oha.json'],
      ['socket-output.json', 'socket-output.json'],
    ]) {
      const filename = path.join(socketRoot, source);
      if (fs.existsSync(filename)) fs.copyFileSync(filename,
        path.join(layout.raw, target));
    }
    write(path.join(layout.raw, 'gateway-proc-after.txt'),
      fs.readFileSync('/proc/stat'));
    write(path.join(layout.raw, 'load-generator-proc-after.txt'),
      ssh(options.loadHost, ['cat', '/proc/stat']).stdout);
    write(path.join(layout.raw, 'upstream-proc-after.txt'),
      ssh(options.upstreamHost, ['cat', '/proc/stat']).stdout);
    write(path.join(layout.raw, 'gateway-metrics-after.prom'),
      metrics(options.metricsUrl));
    const reactorAfterObservation = captureHelper('reactors', runtime,
      ['--expected-count', String(description.point.core_count)]);
    const reactorsAfter = validateReactorObservation(reactorAfterObservation,
      description.topology.gateway_cpu_set,
      'PERF-06 reactor placement after');
    writeJson(path.join(layout.diagnostics, 'reactors-after.json'),
      reactorAfterObservation);
    const irqAfter = observeIrqPolicy(irqExpected,
      load.private_address, 'PERF-06 IRQ policy after');
    writeJson(path.join(layout.diagnostics, 'irq-after.json'), irqAfter);
    const irqTransition = validateIrqPolicyTransition(irqBefore, irqAfter,
      irqExpected, 'PERF-06 IRQ policy');
    writeJson(path.join(layout.diagnostics, 'irq-transition.json'),
      irqTransition);
    const post = settleWarmupState({
      maximumCleanupMs: plan.input.workload.maximum_cleanup_ms,
      expectedIdentity: baselineResource.identity,
      captureState: () => captureHelper('state', runtime),
      captureMetrics: () => metrics(options.metricsUrl)});
    writeJson(path.join(layout.diagnostics, 'post-run-settlement.json'),
      {settled: post.settled, elapsed_ms: post.elapsed_ms,
        observations: post.observations});
    writeJson(path.join(layout.diagnostics, 'descriptors-after.json'),
      post.state.descriptors);
    if (plan.schema_version >= 2) {
      writeJson(path.join(layout.raw, 'descriptors-after.json'),
        post.state.descriptors);
    }
    requireValue(post.settled, 'PERF-06 post-run state did not settle',
      'environment-drift');
    writeJson(path.join(layout.raw, 'resource-after.json'),
      post.state.resource);
    write(path.join(layout.raw, 'final-metrics.prom'), post.metrics);
    const journal = run('journalctl', ['-u', options.service, '--since',
      new Date(startedAt).toISOString(), '--no-pager',
      '--output=short-iso-precise'], {allowFailure: true,
      label: 'PERF-06 gateway journal'});
    write(path.join(layout.raw, 'journal.log'),
      journal.stdout + journal.stderr);
    requireValue(journal.status === 0,
      `PERF-06 journal capture exited ${journal.status}`,
      'collector-failure');

    const observedAfter = observeSource(options);
    const remoteAfter = remoteSource(options.loadHost,
      options.loadRepository);
    requireValue(isDeepStrictEqual(observedAfter.source,
      observedBefore.source) && observedAfter.sourceStatus === '' &&
      isDeepStrictEqual(remoteAfter, remoteBefore),
    'PERF-06 source or artifact identity changed during capture',
    'source-drift');
    const requestAfter = completePolicyRequestObservation(request,
      startedAt, endedAt);
    writeJson(path.join(layout.raw, 'request-observation.json'), requestAfter);
    writeJson(path.join(layout.raw, 'provenance-after.json'),
      fixedProvenance(description, observedAfter.source,
        plan.input.catalog_sha256, observedAfter.sourceStatus));
    writeJson(path.join(layout.raw, 'environment.json'),
      attemptEnvironment(description, options.attempt,
        {before: reactorsBefore, after: reactorsAfter,
          profiled: reactorsBefore}));
    writeJson(path.join(layout.raw, 'status.json'), buildPolicyCaptureStatus(
      warmupCommandExitCode, clientStatus, collector.status, probeStatus));
    requireValue(collector.status === 0 && clientStatus === 0,
      'PERF-06 measurement collector or client failed',
      'collector-failure');
    exactRawManifest(layout.raw, plan.schema_version);
    const point = options.pointId;
    derivePolicyCostEvidence({catalog: options.catalog, plan: options.plan,
      pointId: point, attempt: options.attempt, rawRoot: layout.raw,
      evidenceRoot: layout.evidence,
      captureArchive: path.join(layout.evidence, `${point}.capture.raw.json`),
      environment: path.join(layout.evidence, `${point}.environment.json`),
      derivationManifest: path.join(layout.evidence,
        `${point}.derivation.json`),
      result: path.join(layout.evidence, `${point}.result.json`)});
    write(path.join(layout.root, 'decision.txt'), 'point-complete\n');
    succeeded = true;
    return layout.root;
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    if (remoteProbeTouched) {
      cleanupRemoteProbe(options, layout.diagnostics, false);
    }
    if (!succeeded && baselineResource !== null) {
      writeJson(path.join(layout.diagnostics, 'recovery.json'),
        captureRecovery(runtime, baselineResource,
          plan.input.workload.maximum_cleanup_ms));
    }
    if (!succeeded && failure !== null) {
      retainInvalidPolicyAttempt({layout, description, plan, catalogBytes,
        attempt: options.attempt, error: failure});
    }
    writeJson(path.join(layout.root, 'attempt-status.json'), {
      schema_version: 1, point_id: options.pointId, attempt: options.attempt,
      outcome: succeeded ? 'complete' : 'investigate',
      publication_authorized: false});
    sealTree(layout.root);
  }
}

export function preflightPolicyCost(options) {
  const catalogBytes = readRegular(options.catalog, 'PERF-06 catalog');
  const plan = JSON.parse(readRegular(options.plan, 'PERF-06 plan'));
  validatePolicyCostPlan(plan, catalogBytes);
  const description = describePolicyCostPoint(plan, catalogBytes,
    options.pointId);
  const request = validateJwtRunway(observePolicyRequest(description.point,
    options.requestArtifact), plan, Date.now());
  validatePolicyRuntimeSecrets(description, options, plan);
  const collector = policyCostCollectorIdentity();
  requireValue(collector.sha256 ===
    plan.input.source.collector_bundle_sha256,
  'PERF-06 collector bundle differs from the plan', 'artifact-drift');
  const image = IMAGE.exec(options.ohaImage);
  requireValue(image && image[1] === plan.input.source.client_sha256,
    'PERF-06 load-client image differs from the plan', 'artifact-drift');
  const plannedClientSets = partitionCpus(
    plan.input.topology.load_generator_cpu_set.join(','), options.loadLanes);
  const observedClientSets = partitionCpus(options.loadCpuSet,
    options.loadLanes);
  requireValue(options.loadLanes === plan.input.topology.load_generator_lanes &&
    isDeepStrictEqual(observedClientSets, plannedClientSets),
  'PERF-06 preflight load-generator placement differs from the plan',
  'environment-drift');
  requireValue((request.mode === 'none' &&
    options.remoteRequestArtifact === null) ||
    (request.mode !== 'none' &&
      SAFE_REMOTE_PATH.test(options.remoteRequestArtifact)),
  'PERF-06 preflight request-artifact staging differs from the plan',
  'artifact-drift');
  const client = remoteClient(options);
  const execution = {schema_version: 1, checkpoint: 'PERF-06',
    plan_id: plan.plan_id, point_id: options.pointId, attempt: options.attempt,
    evidence_class: plan.input.evidence_class,
    profiled_warmup_repetitions:
      plan.input.workload.profiled_warmup_repetitions ?? 1,
    collector_bundle: collector,
    request: {mode: request.mode, header_names: request.header_names,
      artifact_sha256: request.artifact_sha256, values_retained: false,
      jwt_window: request.jwt_window},
    commands: {probe: buildPolicyProbeArgs({...client,
      targetAddress: role(description, 'gateway').private_address,
      output: options.remoteProbeRoot}),
    warmup: buildPolicyRemoteClientArgs(client, 'warmup'),
    measurement: buildPolicyRemoteClientArgs(client, 'measurement')},
    expected_raw_files: [...policyCostRawFiles(plan.schema_version)],
    failure_reasons: [...INVALID_REASONS].sort(),
    publication_authorized: false};
  return execution;
}

function main() {
  const [, , command, ...argv] = process.argv;
  requireValue(['preflight', 'capture', 'collector-identity'].includes(command),
    'usage: phase5-policy-cost-executor.mjs preflight|capture|collector-identity [options]');
  if (command === 'collector-identity') {
    process.stdout.write(`${JSON.stringify(policyCostCollectorIdentity(), null, 2)}\n`);
    return;
  }
  const options = parseOptions(argv);
  if (command === 'preflight') {
    process.stdout.write(`${JSON.stringify(preflightPolicyCost(options), null, 2)}\n`);
    return;
  }
  process.stdout.write(`PERF06_EVIDENCE_DIR=${runCapture(options)}\n`);
}

if (process.argv[1] && import.meta.url ===
    pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-policy-cost-executor: ${error.message}\n`);
    process.exitCode = 1;
  }
}
