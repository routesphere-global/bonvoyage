#!/usr/bin/env node

import {spawnSync} from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {isIP} from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';

import {buildOhaRun, parseOhaReport, partitionCpus} from
  './phase5-oha-lanes.mjs';
import {describePolicyCostPoint} from './phase5-policy-cost-native.mjs';
import {failedRunnerDiagnostics} from './phase5-protocol-p5-t01-client.mjs';

const AUTHORITY = 'api.example.test';
const LISTENER_PORT = 8443;
const IMAGE = /^\S+@sha256:([0-9a-f]{64})$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const OPTIONS = Object.freeze([
  '--catalog', '--plan', '--point-id', '--stage', '--image', '--cpu-set',
  '--lanes', '--ca-file', '--request-artifact', '--runner',
]);
const PROBE_OPTIONS = Object.freeze([
  '--catalog', '--plan', '--point-id', '--ca-file', '--target-address',
  '--output', '--request-artifact',
]);

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function readRegular(filename, label, maximum = 1024 * 1024) {
  const absolute = path.resolve(filename);
  const stat = fs.lstatSync(absolute);
  requireValue(stat.isFile() && !stat.isSymbolicLink() && stat.size <= maximum,
    `${label} must be a bounded regular non-symlink file`);
  return {absolute, bytes: fs.readFileSync(absolute)};
}

function integer(value, label, minimum = 1, maximum = Number.MAX_SAFE_INTEGER) {
  const parsed = Number(value);
  requireValue(Number.isSafeInteger(parsed) && parsed >= minimum &&
    parsed <= maximum, `${label} must be between ${minimum} and ${maximum}`);
  return parsed;
}

function exactOptions(argv) {
  requireValue(argv.length % 2 === 0,
    'PERF-06 client options require name/value pairs');
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    requireValue(OPTIONS.includes(name) && value && !value.startsWith('--'),
      `unknown or valueless PERF-06 client option: ${name}`);
    requireValue(!values.has(name), `${name} may appear only once`);
    values.set(name, value);
  }
  for (const name of OPTIONS.filter((item) =>
    !['--request-artifact', '--runner'].includes(item))) {
    requireValue(values.has(name), `${name} is required`);
  }
  return values;
}

export function parsePolicyCostClientOptions(argv, defaultRunner) {
  const values = exactOptions(argv);
  return {
    catalog: values.get('--catalog'), plan: values.get('--plan'),
    pointId: values.get('--point-id'), stage: values.get('--stage'),
    image: values.get('--image'), cpuSet: values.get('--cpu-set'),
    lanes: Number(values.get('--lanes')), caFile: values.get('--ca-file'),
    requestArtifact: values.get('--request-artifact') ?? null,
    runner: values.get('--runner') ?? defaultRunner,
  };
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

function writeExclusive(filename, value) {
  fs.writeFileSync(filename, value, {flag: 'wx', mode: 0o600});
}

function base64urlJson(value, label) {
  requireValue(typeof value === 'string' && /^[A-Za-z0-9_-]+$/u.test(value),
    `${label} is not canonical base64url`);
  const bytes = Buffer.from(value, 'base64url');
  requireValue(bytes.length > 0 && bytes.toString('base64url') === value,
    `${label} is not canonical base64url`);
  return parseJson(bytes, label);
}

function jwtIdentity(value) {
  requireValue(typeof value === 'string' && value.startsWith('Bearer '),
    'JWT request artifact must contain one Bearer authorization value');
  const token = value.slice('Bearer '.length);
  const parts = token.split('.');
  requireValue(parts.length === 3 && parts.every((item) => item.length > 0),
    'JWT request artifact is not a compact signed token');
  const header = base64urlJson(parts[0], 'JWT protected header');
  const claims = base64urlJson(parts[1], 'JWT claims');
  requireValue(header?.alg === 'RS256' && header.typ === 'at+jwt' &&
    typeof header.kid === 'string' && header.kid.length > 0,
  'JWT protected header differs from the PERF-06 contract');
  requireValue(claims?.iss === 'https://issuer.example.test' &&
    claims.aud === 'payments-api' && claims.tenant === 'tenant-a' &&
    typeof claims.scope === 'string' &&
    claims.scope.split(/\s+/u).includes('payments:read') &&
    Number.isSafeInteger(claims.iat) && Number.isSafeInteger(claims.exp) &&
    claims.iat > 0 && claims.exp > claims.iat,
  'JWT claims differ from the PERF-06 contract');
  return {issued_at_epoch_ms: claims.iat * 1000,
    expires_at_epoch_ms: claims.exp * 1000};
}

export function observePolicyRequest(point, artifactFile) {
  if (point.request.mode === 'none') {
    requireValue(artifactFile === null,
      'plain PERF-06 point must not have a request artifact');
    return {mode: 'none', header_names: [], artifact_sha256: null,
      values_retained: false, jwt_window: null};
  }
  requireValue(typeof artifactFile === 'string' && artifactFile.length > 0,
    `${point.request.mode} PERF-06 point requires a request artifact`);
  const artifact = readRegular(artifactFile, 'PERF-06 request artifact');
  const artifactSha256 = sha256(artifact.bytes);
  if (point.request.mode !== 'ephemeral-jwt') {
    requireValue(artifactSha256 === point.request.planned_artifact_sha256,
      'PERF-06 request artifact differs from the plan');
  }
  let jwtWindow = null;
  if (point.request.mode === 'static-json' ||
      point.request.mode === 'ephemeral-jwt') {
    const headers = parseJson(artifact.bytes, 'PERF-06 request headers');
    requireValue(headers && typeof headers === 'object' &&
      !Array.isArray(headers) && isDeepStrictEqual(
        Object.keys(headers).sort(), point.request.header_names),
    'PERF-06 request-header names differ from the plan');
    if (point.request.mode === 'ephemeral-jwt') {
      const identity = jwtIdentity(headers.authorization);
      jwtWindow = {...identity, measurement_started_at_epoch_ms: null,
        measurement_ended_at_epoch_ms: null};
    }
  }
  return {mode: point.request.mode,
    header_names: [...point.request.header_names],
    artifact_sha256: artifactSha256, values_retained: false,
    jwt_window: jwtWindow};
}

function policyRequestHeaders(point, artifactFile) {
  if (point.request.mode === 'none') return [];
  const artifact = readRegular(artifactFile, 'PERF-06 request artifact');
  if (point.request.mode === 'secret-file') {
    const lines = artifact.bytes.toString('utf8').split(/\r?\n/u)
      .filter((line) => line.length > 0);
    requireValue(lines.length === 1 && lines[0].trim() === lines[0],
      'PERF-06 API-key artifact must contain exactly one key');
    return [['x-api-key', lines[0]]];
  }
  const headers = parseJson(artifact.bytes, 'PERF-06 request headers');
  return Object.entries(headers).sort(([left], [right]) =>
    left.localeCompare(right));
}

export function completePolicyRequestObservation(observation, startedAt,
  endedAt) {
  if (observation.mode !== 'ephemeral-jwt') return observation;
  requireValue(Number.isSafeInteger(startedAt) && Number.isSafeInteger(endedAt) &&
    startedAt > 0 && endedAt >= startedAt,
  'PERF-06 JWT measurement window is invalid');
  return {...observation, jwt_window: {...observation.jwt_window,
    measurement_started_at_epoch_ms: startedAt,
    measurement_ended_at_epoch_ms: endedAt}};
}

function gatewayAddress(description) {
  const gateway = description.topology.roles.find((item) =>
    item.role === 'gateway');
  requireValue(gateway, 'PERF-06 plan omits the gateway role');
  return gateway.private_address;
}

export function buildPolicyCostClientRun(options) {
  const catalog = readRegular(options.catalog, 'PERF-06 catalog').bytes;
  const plan = parseJson(readRegular(options.plan, 'PERF-06 plan').bytes,
    'PERF-06 plan');
  const description = describePolicyCostPoint(plan, catalog, options.pointId);
  const point = description.point;
  requireValue(['warmup', 'measurement'].includes(options.stage),
    'PERF-06 client stage must be warmup or measurement');
  const lanes = integer(options.lanes, 'PERF-06 client lanes', 2, 16);
  const image = IMAGE.exec(options.image);
  requireValue(image && image[1] === description.source.client_sha256,
    'PERF-06 load-client image differs from the plan');
  requireValue(point.offered_rps % lanes === 0 &&
    point.connections % lanes === 0,
  'PERF-06 rate and connection placement must divide across lanes');
  const seconds = options.stage === 'warmup' ?
    plan.input.workload.warmup_seconds : point.measurement_seconds;
  const ratePerLane = point.offered_rps / lanes;
  const requestsPerLane = integer(ratePerLane * seconds,
    'PERF-06 requests per lane');
  const request = observePolicyRequest(point, options.requestArtifact);
  const runnerArgs = ['--lanes', String(lanes), '--rate-per-lane',
    String(ratePerLane), '--requests-per-lane', String(requestsPerLane),
    '--connections-per-lane', String(point.connections / lanes),
    '--streams-per-connection', '1', '--cpu-set', options.cpuSet,
    '--image', options.image, '--protocol', 'http1', '--url',
    `https://${AUTHORITY}:${LISTENER_PORT}${point.request_path}`,
    '--target-addresses', gatewayAddress(description), '--ca-file',
    path.resolve(options.caFile)];
  if (point.request.mode === 'secret-file') {
    runnerArgs.push('--credential-file', path.resolve(options.requestArtifact));
  } else if (['static-json', 'ephemeral-jwt'].includes(point.request.mode)) {
    runnerArgs.push('--request-headers-file',
      path.resolve(options.requestArtifact));
  }
  const built = buildOhaRun(runnerArgs);
  const plannedCpuSets = partitionCpus(
    description.topology.load_generator_cpu_set.join(','), lanes);
  requireValue(lanes === description.topology.load_generator_lanes &&
    isDeepStrictEqual(built.sets, plannedCpuSets),
  'PERF-06 load-generator placement differs from the plan');
  requireValue(built.workload.requests_per_lane === requestsPerLane &&
    built.workload.connections_per_lane * lanes === point.connections &&
    built.workload.client_sha256 === image[1],
  'PERF-06 structured load-client contract differs from the plan');
  return {description, request, runner: path.resolve(options.runner),
    args: ['run-oha', ...runnerArgs], workload: built.workload,
    clientLanes: lanes, clientCpuSets: built.sets,
    offeredRps: point.offered_rps};
}

export function validatePolicyCostClientOutput(raw, run) {
  const report = parseOhaReport(raw);
  requireValue(report.offered_rps === run.offeredRps &&
    report.client_lanes === run.clientLanes &&
    isDeepStrictEqual(report.client_cpu_sets, run.clientCpuSets) &&
    isDeepStrictEqual(report.workload, run.workload),
  'PERF-06 load-client output differs from the planned workload');
  return report;
}

export function parsePolicyProbeResponse(bytes, maximumBytes = 1024 * 1024) {
  requireValue(Buffer.isBuffer(bytes) && bytes.length > 0 &&
    bytes.length <= maximumBytes, 'PERF-06 probe response is empty or oversized');
  const boundary = bytes.indexOf('\r\n\r\n');
  requireValue(boundary > 0, 'PERF-06 probe response has no header boundary');
  const head = bytes.subarray(0, boundary + 4);
  const body = bytes.subarray(boundary + 4);
  const statusLine = head.toString('latin1').split('\r\n', 1)[0];
  const match = /^HTTP\/1\.[01] (\d{3})(?: |$)/u.exec(statusLine);
  requireValue(match, 'PERF-06 probe response status line is invalid');
  return {statusCode: Number(match[1]), headers: head, body};
}

function parseProbeOptions(argv) {
  requireValue(argv.length % 2 === 0,
    'PERF-06 probe options require name/value pairs');
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    requireValue(PROBE_OPTIONS.includes(name) && value &&
      !value.startsWith('--'), `unknown or valueless PERF-06 probe option: ${name}`);
    requireValue(!values.has(name), `${name} may appear only once`);
    values.set(name, value);
  }
  for (const name of PROBE_OPTIONS.filter((item) =>
    item !== '--request-artifact')) {
    requireValue(values.has(name), `${name} is required`);
  }
  return {catalog: values.get('--catalog'), plan: values.get('--plan'),
    pointId: values.get('--point-id'), caFile: values.get('--ca-file'),
    targetAddress: values.get('--target-address'),
    output: values.get('--output'),
    requestArtifact: values.get('--request-artifact') ?? null};
}

export async function runPolicyProbe(options) {
  requireValue(isIP(options.targetAddress) === 4,
    'PERF-06 probe target must be an IPv4 address');
  const catalog = readRegular(options.catalog, 'PERF-06 catalog').bytes;
  const plan = parseJson(readRegular(options.plan, 'PERF-06 plan').bytes,
    'PERF-06 plan');
  const description = describePolicyCostPoint(plan, catalog, options.pointId);
  const point = description.point;
  observePolicyRequest(point, options.requestArtifact);
  const requestHeaders = policyRequestHeaders(point, options.requestArtifact);
  const ca = readRegular(options.caFile, 'PERF-06 CA', 16 * 1024 * 1024).bytes;
  const output = path.resolve(options.output);
  requireValue(!fs.existsSync(output), 'PERF-06 probe output already exists');
  fs.mkdirSync(output, {mode: 0o700});
  const lines = [
    `GET ${point.request_path} HTTP/1.1`,
    `Host: ${AUTHORITY}:${LISTENER_PORT}`,
    'Accept: */*',
    'Connection: close',
    ...requestHeaders.map(([name, value]) => `${name}: ${value}`), '', '',
  ];
  const socket = tls.connect({host: options.targetAddress, port: LISTENER_PORT,
    servername: AUTHORITY, ca, rejectUnauthorized: true,
    minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
    ALPNProtocols: ['http/1.1']});
  const chunks = [];
  let total = 0;
  let tlsObservation = null;
  await new Promise((resolve, reject) => {
    socket.setTimeout(5000, () => socket.destroy(
      new Error('PERF-06 probe timed out')));
    socket.once('secureConnect', () => {
      const cipher = socket.getCipher()?.standardName ?? socket.getCipher()?.name;
      tlsObservation = {tls_version: socket.getProtocol(), cipher,
        alpn: socket.alpnProtocol, ca_verified: socket.authorized === true,
        hostname_verified: socket.authorized === true};
      socket.end(lines.join('\r\n'));
    });
    socket.on('data', (chunk) => {
      total += chunk.length;
      if (total > 1024 * 1024) {
        socket.destroy(new Error('PERF-06 probe response exceeded 1 MiB'));
        return;
      }
      chunks.push(chunk);
    });
    socket.once('end', resolve);
    socket.once('error', reject);
  });
  const cipher = tlsObservation?.cipher;
  requireValue(tlsObservation.tls_version === 'TLSv1.3' &&
    typeof cipher === 'string' && cipher.startsWith('TLS_AES_') &&
    !cipher.includes('CHACHA') && tlsObservation.alpn === 'http/1.1' &&
    tlsObservation.ca_verified && tlsObservation.hostname_verified,
  'PERF-06 probe TLS identity differs from the contract');
  const response = parsePolicyProbeResponse(Buffer.concat(chunks));
  requireValue(response.statusCode === 200,
    `PERF-06 protocol probe returned HTTP ${response.statusCode}`);
  writeExclusive(path.join(output, 'protocol-status.txt'),
    `${response.statusCode}\n`);
  writeExclusive(path.join(output, 'protocol-headers.txt'), response.headers);
  writeExclusive(path.join(output, 'protocol-body.bin'), response.body);
  writeExclusive(path.join(output, 'tls-observation.json'),
    `${JSON.stringify(tlsObservation, null, 2)}\n`);
  return {status_code: response.statusCode, response_bytes: response.body.length,
    tls: tlsObservation, values_retained: false};
}

export function runPolicyCostClient(options) {
  const run = buildPolicyCostClientRun(options);
  const result = spawnSync(process.execPath, [run.runner, ...run.args], {
    encoding: 'utf8', maxBuffer: 128 * 1024 * 1024,
  });
  if (result.stderr) process.stderr.write(result.stderr);
  requireValue(result.error === undefined,
    `PERF-06 load-client failed to start: ${result.error?.message}`);
  if (result.status !== 0) {
    const diagnostics = failedRunnerDiagnostics(result.stdout);
    if (diagnostics) process.stderr.write(
      `PERF-06 load-client diagnostics: ${diagnostics}\n`);
  }
  requireValue(result.status === 0,
    `PERF-06 load-client exited ${result.status ?? 'without a status'}`);
  validatePolicyCostClientOutput(result.stdout, run);
  return result.stdout;
}

async function main() {
  const [, , command, ...argv] = process.argv;
  requireValue(['run', 'probe'].includes(command),
    'usage: phase5-policy-cost-client.mjs run|probe [options]');
  if (command === 'probe') {
    process.stdout.write(`${JSON.stringify(await runPolicyProbe(
      parseProbeOptions(argv)))}\n`);
    return;
  }
  const runner = path.join(path.dirname(fileURLToPath(import.meta.url)),
    'phase5-oha-lanes.mjs');
  process.stdout.write(runPolicyCostClient(
    parsePolicyCostClientOptions(argv, runner)));
}

if (process.argv[1] && import.meta.url ===
    pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main().catch((error) => {
      process.stderr.write(`phase5-policy-cost-client: ${error.message}\n`);
      process.exitCode = 1;
    });
  } catch (error) {
    process.stderr.write(`phase5-policy-cost-client: ${error.message}\n`);
    process.exitCode = 1;
  }
}
