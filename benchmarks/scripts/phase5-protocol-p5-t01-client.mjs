#!/usr/bin/env node

import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';

import {buildOhaRun, parseOhaReport,
  partitionCpus} from './phase5-oha-lanes.mjs';
import {describeP5T01Point} from './phase5-protocol-p5-t01-native.mjs';

const AUTHORITY = 'api.example.test';
const LISTENER_PORT = 8443;
const IMAGE = /^\S+@sha256:([0-9a-f]{64})$/u;
const CLIENT_OPTIONS = Object.freeze([
  '--catalog', '--plan', '--point-id', '--stage', '--image', '--cpu-set',
  '--lanes', '--ca-file', '--runner',
]);

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function integer(value, label, minimum = 1) {
  requireValue(Number.isSafeInteger(value) && value >= minimum,
    `${label} must be an integer >= ${minimum}`);
  return value;
}

function readRegular(filename, label) {
  const absolute = path.resolve(filename);
  const stat = fs.lstatSync(absolute);
  requireValue(stat.isFile() && !stat.isSymbolicLink(),
    `${label} must be a regular non-symlink file`);
  return fs.readFileSync(absolute, 'utf8');
}

function exactOptions(argv) {
  requireValue(argv.length % 2 === 0,
    'P5-T01 client options require name/value pairs');
  const result = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    requireValue(CLIENT_OPTIONS.includes(name) && value &&
      !value.startsWith('--'), `unknown or valueless P5-T01 client option: ${name}`);
    requireValue(!result.has(name), `${name} may appear only once`);
    result.set(name, value);
  }
  return result;
}

export function parseP5T01ClientOptions(argv, defaultRunner) {
  const options = exactOptions(argv);
  for (const name of CLIENT_OPTIONS.filter((item) => item !== '--runner')) {
    requireValue(options.has(name), `${name} is required`);
  }
  return {
    catalog: options.get('--catalog'), plan: options.get('--plan'),
    pointId: options.get('--point-id'), stage: options.get('--stage'),
    image: options.get('--image'), cpuSet: options.get('--cpu-set'),
    lanes: Number(options.get('--lanes')), caFile: options.get('--ca-file'),
    runner: options.get('--runner') ?? defaultRunner,
  };
}

function gatewayAddress(description) {
  const gateway = description.topology.roles.find((item) => item.role === 'gateway');
  requireValue(gateway, 'P5-T01 plan omits the gateway role');
  return gateway.private_address;
}

export function buildP5T01ClientRun(options) {
  const catalogBytes = readRegular(options.catalog, 'PERF-05 catalog');
  const plan = JSON.parse(readRegular(options.plan, 'PERF-05 plan'));
  const description = describeP5T01Point(plan, catalogBytes, options.pointId);
  const variant = description.variant;
  requireValue(['warmup', 'measurement'].includes(options.stage),
    'P5-T01 client stage must be warmup or measurement');
  const lanes = integer(options.lanes, 'P5-T01 client lanes', 2);
  requireValue(lanes <= 16, 'P5-T01 client lanes exceed the evidence limit');
  const image = IMAGE.exec(options.image);
  requireValue(image && image[1] === description.source.load_client_sha256,
    'P5-T01 load-client image differs from the native plan');
  const seconds = options.stage === 'warmup' ?
    variant.workload.warmup_seconds : variant.workload.measurement_seconds;
  const targetRps = variant.workload.target_rps;
  requireValue(targetRps % lanes === 0 &&
    variant.workload.connections % lanes === 0,
  'P5-T01 rate and connection placement must divide evenly across lanes');
  const ratePerLane = targetRps / lanes;
  const requestsPerLane = ratePerLane * seconds;
  integer(requestsPerLane, 'P5-T01 requests per lane');
  const mode = variant.scenario === 'fixed-response' ? 'fixed' : 'proxied';
  const runnerArgs = ['--lanes', String(lanes), '--rate-per-lane',
    String(ratePerLane), '--requests-per-lane', String(requestsPerLane),
    '--connections-per-lane', String(variant.workload.connections / lanes),
    '--streams-per-connection', '1', '--cpu-set', options.cpuSet,
    '--image', options.image, '--protocol', 'http1', '--url',
    `https://${AUTHORITY}:${LISTENER_PORT}/perf05/${mode}/${variant.payload_bytes}`,
    '--target-addresses', gatewayAddress(description), '--ca-file',
    path.resolve(options.caFile)];
  const built = buildOhaRun(runnerArgs);
  const plannedCpuSets = partitionCpus(
    description.topology.load_generator_cpu_set.join(','), lanes);
  requireValue(lanes === description.topology.load_generator_lanes &&
    isDeepStrictEqual(built.sets, plannedCpuSets),
  'P5-T01 load-generator placement differs from the native plan');
  requireValue(built.workload.requests_per_lane === requestsPerLane &&
    built.workload.connections_per_lane * lanes ===
      variant.workload.connections && built.workload.client_sha256 === image[1],
  'P5-T01 structured load-client contract differs from the plan');
  return {description, runner: path.resolve(options.runner),
    args: ['run-oha', ...runnerArgs],
    workload: built.workload, clientLanes: lanes, clientCpuSets: built.sets,
    offeredRps: targetRps};
}

export function failedRunnerDiagnostics(raw) {
  if (typeof raw !== 'string' || raw.length === 0) return '';
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    return `unparseable runner output (${Buffer.byteLength(raw)} bytes)`;
  }
  if (value?.kind !== 'phase5-oha-lanes' || !Array.isArray(value.lanes)) {
    return `unexpected runner output (${Buffer.byteLength(raw)} bytes)`;
  }
  const lanes = value.lanes.slice(0, 16).map((lane) => ({
    index: Number.isSafeInteger(lane?.index) ? lane.index : null,
    exit_code: Number.isSafeInteger(lane?.exit_code) ? lane.exit_code : null,
    stderr: typeof lane.stderr === 'string' ? lane.stderr.slice(0, 4096) : '',
  }));
  return JSON.stringify({kind: value.kind,
    schema_version: Number.isSafeInteger(value.schema_version) ?
      value.schema_version : null,
    lanes});
}

export function runP5T01Client(options) {
  const run = buildP5T01ClientRun(options);
  const result = spawnSync(process.execPath, [run.runner, ...run.args], {
    encoding: 'utf8', maxBuffer: 128 * 1024 * 1024,
  });
  if (result.stderr) process.stderr.write(result.stderr);
  requireValue(result.error === undefined,
    `P5-T01 load-client process failed to start: ${result.error?.message}`);
  if (result.status !== 0) {
    const diagnostics = failedRunnerDiagnostics(result.stdout);
    if (diagnostics) process.stderr.write(
      `P5-T01 load-client runner diagnostics: ${diagnostics}\n`);
  }
  requireValue(result.status === 0,
    `P5-T01 load-client exited ${result.status ?? 'without a status'}`);
  validateP5T01ClientOutput(result.stdout, run);
  return result.stdout;
}

export function validateP5T01ClientOutput(raw, run) {
  const report = parseOhaReport(raw);
  requireValue(report.offered_rps === run.offeredRps &&
    report.client_lanes === run.clientLanes &&
    isDeepStrictEqual(report.client_cpu_sets, run.clientCpuSets) &&
    isDeepStrictEqual(report.workload, run.workload),
  'P5-T01 load-client output differs from the planned workload');
  return report;
}

function main() {
  const [, , command, ...argv] = process.argv;
  requireValue(command === 'run',
    'usage: phase5-protocol-p5-t01-client.mjs run ...');
  const defaultRunner = path.join(path.dirname(fileURLToPath(import.meta.url)),
    'phase5-oha-lanes.mjs');
  const value = runP5T01Client(parseP5T01ClientOptions(argv, defaultRunner));
  process.stdout.write(value);
}

if (process.argv[1] && import.meta.url ===
    pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-protocol-p5-t01-client: ${error.message}\n`);
    process.exitCode = 1;
  }
}
