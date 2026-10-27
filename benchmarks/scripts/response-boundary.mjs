#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const PAYLOAD_BYTES = Object.freeze([8192, 15360, 16384, 17408, 32768, 65536]);
export const PROTOCOLS = Object.freeze(['http', 'https']);

function requireInteger(value, name, minimum = 1) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${name} must be an integer >= ${minimum}`);
  }
  return value;
}

function requireFinite(value, name, minimum = 0) {
  if (!Number.isFinite(value) || value < minimum) {
    throw new Error(`${name} must be a finite number >= ${minimum}`);
  }
  return value;
}

function requireString(value, name) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

function median(values) {
  if (values.length === 0) throw new Error('median requires at least one value');
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? sorted[middle]
    : (sorted[middle - 1] + sorted[middle]) / 2;
}

function maximumDeviationPercent(values) {
  const center = median(values);
  if (center === 0) return values.every((value) => value === 0) ? 0 : Number.POSITIVE_INFINITY;
  return Math.max(...values.map((value) => Math.abs(value - center) / center * 100));
}

function rotate(values, offset) {
  const normalized = offset % values.length;
  return [...values.slice(normalized), ...values.slice(0, normalized)];
}

export function buildBoundaryPlan({repetitions = 5, seed = 'bonvoyage-response-boundary-v1'} = {}) {
  requireInteger(repetitions, 'repetitions');
  requireString(seed, 'seed');
  const seedOffset = crypto.createHash('sha256').update(seed).digest()[0] % PAYLOAD_BYTES.length;
  const points = [];
  let order = 0;
  for (let repetition = 1; repetition <= repetitions; repetition += 1) {
    let payloads = rotate(PAYLOAD_BYTES, seedOffset + repetition - 1);
    if (repetition % 2 === 0) payloads = payloads.reverse();
    const protocols = repetition % 2 === 1 ? PROTOCOLS : [...PROTOCOLS].reverse();
    for (const protocol of protocols) {
      for (const payloadBytes of payloads) {
        order += 1;
        points.push({order, protocol, payload_bytes: payloadBytes, repetition});
      }
    }
  }
  const contract = {schema_version: 1, seed, repetitions, payload_bytes: PAYLOAD_BYTES,
    protocols: PROTOCOLS, points};
  return {...contract, plan_id: crypto.createHash('sha256')
    .update(JSON.stringify(contract)).digest('hex')};
}

function pointKey(point) {
  return `${point.protocol}:${point.payload_bytes}:${point.repetition}`;
}

function validatePlan(plan) {
  if (plan?.schema_version !== 1) throw new Error('unsupported response-boundary plan schema');
  requireString(plan.plan_id, 'plan_id');
  requireInteger(plan.repetitions, 'repetitions');
  if (JSON.stringify(plan.payload_bytes) !== JSON.stringify(PAYLOAD_BYTES) ||
      JSON.stringify(plan.protocols) !== JSON.stringify(PROTOCOLS)) {
    throw new Error('plan matrix does not match the response-boundary contract');
  }
  const expected = plan.repetitions * PAYLOAD_BYTES.length * PROTOCOLS.length;
  if (!Array.isArray(plan.points) || plan.points.length !== expected) {
    throw new Error(`plan must contain exactly ${expected} points`);
  }
  const keys = new Set();
  for (const [index, point] of plan.points.entries()) {
    if (point.order !== index + 1 || !PROTOCOLS.includes(point.protocol) ||
        !PAYLOAD_BYTES.includes(point.payload_bytes)) throw new Error('invalid plan point');
    requireInteger(point.repetition, 'point repetition');
    const key = pointKey(point);
    if (keys.has(key)) throw new Error(`duplicate plan point: ${key}`);
    keys.add(key);
  }
}

function validateEnvironment(environment) {
  if (environment?.schema_version !== 1) throw new Error('unsupported environment schema');
  for (const field of ['run_id', 'evidence_class', 'source_commit', 'gateway_image_id',
    'compiler_image_id', 'upstream_image_id', 'load_generator_image_id',
    'http_snapshot_sha256', 'https_snapshot_sha256']) requireString(environment[field], field);
  if (typeof environment.source_dirty !== 'boolean' ||
      typeof environment.publication_authorized !== 'boolean') {
    throw new Error('environment source/publication flags are required booleans');
  }
  requireFinite(environment.maximum_support_capacity_percent,
    'maximum_support_capacity_percent');
  requireFinite(environment.minimum_upstream_headroom_ratio,
    'minimum_upstream_headroom_ratio');
}

function optionalMetric(value, name) {
  if (value === null || value === undefined) return null;
  return requireFinite(value, name);
}

function validateResult(result, planned, environment, plan) {
  if (result?.schema_version !== 1 || result.plan_id !== plan.plan_id ||
      result.order !== planned.order || pointKey(result) !== pointKey(planned)) {
    throw new Error(`result does not match planned point ${pointKey(planned)}`);
  }
  const expectedSnapshot = result.protocol === 'http'
    ? environment.http_snapshot_sha256 : environment.https_snapshot_sha256;
  const identities = {source_commit: environment.source_commit,
    gateway_image_id: environment.gateway_image_id, snapshot_sha256: expectedSnapshot};
  for (const [field, expected] of Object.entries(identities)) {
    if (result.identities?.[field] !== expected) throw new Error(`${field} drift at ${pointKey(result)}`);
  }
  requireInteger(result.successful_responses, 'successful_responses', 0);
  requireFinite(result.successful_rps, 'successful_rps');
  requireFinite(result.error_rate, 'error_rate');
  if (result.successful_responses === 0 || result.successful_rps === 0 || result.error_rate !== 0 ||
      result.http_failures !== 0 || result.transport_failures !== 0) {
    throw new Error(`measurement errors at ${pointKey(result)}`);
  }
  for (const percentile of ['p50', 'p95', 'p99', 'p999']) {
    requireFinite(result.latency_ms?.[percentile], `latency ${percentile}`);
  }
  for (const role of ['gateway', 'upstream', 'load_generator']) {
    requireFinite(result.cpu_percent?.[role]?.mean, `${role} mean CPU`);
    requireFinite(result.cpu_percent?.[role]?.maximum, `${role} maximum CPU`);
    requireFinite(result.capacity_percent?.[role]?.maximum, `${role} maximum capacity`);
  }
  if (result.capacity_percent.upstream.maximum > environment.maximum_support_capacity_percent ||
      result.capacity_percent.load_generator.maximum > environment.maximum_support_capacity_percent) {
    throw new Error(`support role saturated at ${pointKey(result)}`);
  }
  requireFinite(result.direct_upstream_rps, 'direct_upstream_rps');
  requireFinite(result.upstream_headroom_ratio, 'upstream_headroom_ratio');
  const computedHeadroom = result.direct_upstream_rps / result.successful_rps;
  if (Math.abs(computedHeadroom - result.upstream_headroom_ratio) > 1e-6) {
    throw new Error(`upstream headroom arithmetic mismatch at ${pointKey(result)}`);
  }
  if (computedHeadroom < environment.minimum_upstream_headroom_ratio) {
    throw new Error(`insufficient direct-upstream headroom at ${pointKey(result)}`);
  }
  if (result.process?.restart_count !== 0 || result.process?.oom_killed !== false ||
      result.process?.exit_code !== 0) throw new Error(`gateway process failure at ${pointKey(result)}`);
  return {
    ...result,
    diagnostic: {
      cycles_per_request: optionalMetric(result.diagnostic?.cycles_per_request,
        'cycles_per_request'),
      instructions_per_request: optionalMetric(result.diagnostic?.instructions_per_request,
        'instructions_per_request'),
      writes_per_request: optionalMetric(result.diagnostic?.writes_per_request,
        'writes_per_request'),
      bytes_per_write: optionalMetric(result.diagnostic?.bytes_per_write, 'bytes_per_write'),
      downstream_flush_wait_ms: optionalMetric(result.diagnostic?.downstream_flush_wait_ms,
        'downstream_flush_wait_ms'),
    },
  };
}

function groupSummary(results) {
  const rates = results.map((result) => result.successful_rps);
  const gatewayCpuPerK = results.map((result) =>
    result.cpu_percent.gateway.mean / result.successful_rps * 1000);
  const bytesPerSecond = results.map((result) => result.successful_rps * result.payload_bytes);
  const cpuPerGiBps = results.map((result, index) =>
    result.cpu_percent.gateway.mean / (bytesPerSecond[index] / (1024 ** 3)));
  const diagnostic = {};
  for (const field of ['cycles_per_request', 'instructions_per_request', 'writes_per_request',
    'bytes_per_write', 'downstream_flush_wait_ms']) {
    const values = results.map((result) => result.diagnostic[field]);
    diagnostic[field] = values.every((value) => value !== null) ? median(values) : null;
  }
  return {
    protocol: results[0].protocol,
    payload_bytes: results[0].payload_bytes,
    repetitions: results.length,
    median_successful_rps: median(rates),
    maximum_rps_deviation_percent: maximumDeviationPercent(rates),
    median_latency_ms: Object.fromEntries(['p50', 'p95', 'p99', 'p999'].map((field) =>
      [field, median(results.map((result) => result.latency_ms[field]))])),
    mean_gateway_cpu_percent: results.reduce((sum, result) =>
      sum + result.cpu_percent.gateway.mean, 0) / results.length,
    median_gateway_cpu_percent_per_1000_rps: median(gatewayCpuPerK),
    median_bytes_per_second: median(bytesPerSecond),
    median_gateway_cpu_percent_per_gib_per_second: median(cpuPerGiBps),
    maximum_upstream_capacity_percent: Math.max(...results.map((result) =>
      result.capacity_percent.upstream.maximum)),
    maximum_load_generator_capacity_percent: Math.max(...results.map((result) =>
      result.capacity_percent.load_generator.maximum)),
    minimum_upstream_headroom_ratio: Math.min(...results.map((result) =>
      result.upstream_headroom_ratio)),
    diagnostic,
  };
}

function ratio(current, prior) {
  return prior === 0 ? null : current / prior;
}

export function summarizeBoundary({plan, environment, results}) {
  validatePlan(plan);
  validateEnvironment(environment);
  if (!Array.isArray(results) || results.length !== plan.points.length) {
    throw new Error(`expected ${plan.points.length} results, received ${results?.length ?? 0}`);
  }
  const byKey = new Map();
  for (const result of results) {
    const key = pointKey(result);
    if (byKey.has(key)) throw new Error(`duplicate result identity: ${key}`);
    byKey.set(key, result);
  }
  const validated = plan.points.map((point) => {
    const result = byKey.get(pointKey(point));
    if (!result) throw new Error(`missing result: ${pointKey(point)}`);
    return validateResult(result, point, environment, plan);
  });
  const groups = [];
  for (const protocol of PROTOCOLS) {
    for (const payloadBytes of PAYLOAD_BYTES) {
      groups.push(groupSummary(validated.filter((result) =>
        result.protocol === protocol && result.payload_bytes === payloadBytes)));
    }
  }
  const boundary = {};
  for (const protocol of PROTOCOLS) {
    const get = (bytes) => groups.find((group) =>
      group.protocol === protocol && group.payload_bytes === bytes);
    const below = get(15360);
    const at = get(16384);
    const above = get(17408);
    boundary[protocol] = {
      rps_ratio_at_vs_below: ratio(at.median_successful_rps, below.median_successful_rps),
      byte_throughput_ratio_at_vs_below: ratio(at.median_bytes_per_second,
        below.median_bytes_per_second),
      cpu_per_gib_ratio_at_vs_below: ratio(at.median_gateway_cpu_percent_per_gib_per_second,
        below.median_gateway_cpu_percent_per_gib_per_second),
      rps_ratio_above_vs_at: ratio(above.median_successful_rps, at.median_successful_rps),
      byte_throughput_ratio_above_vs_at: ratio(above.median_bytes_per_second,
        at.median_bytes_per_second),
      cpu_per_gib_ratio_above_vs_at: ratio(above.median_gateway_cpu_percent_per_gib_per_second,
        at.median_gateway_cpu_percent_per_gib_per_second),
    };
  }
  const repeatabilityEvaluable = plan.repetitions >= 5;
  const repeatabilityPass = repeatabilityEvaluable && groups.every((group) =>
    group.maximum_rps_deviation_percent <= 5);
  const gates = {
    exact_matrix_pass: true,
    all_responses_successful_pass: true,
    support_roles_unsaturated_pass: true,
    process_stability_pass: true,
    repeatability_evaluable: repeatabilityEvaluable,
    repeatability_pass: repeatabilityPass,
    clean_source_pass: environment.source_dirty === false,
  };
  const preflightPass = gates.exact_matrix_pass && gates.all_responses_successful_pass &&
    gates.support_roles_unsaturated_pass && gates.process_stability_pass;
  return {schema_version: 1, run_id: environment.run_id, plan_id: plan.plan_id,
    evidence_class: environment.evidence_class,
    publication_authorized: false,
    publication_reason: environment.publication_reason,
    source_commit: environment.source_commit, source_dirty: environment.source_dirty,
    repetitions: plan.repetitions, points: validated, groups, boundary, gates,
    decision: !preflightPass ? 'investigate' : repeatabilityEvaluable
      ? repeatabilityPass && !environment.source_dirty
        ? 'retain-for-native-qualification' : 'investigate'
      : 'preflight-pass'};
}

function fixed(value, digits = 2) {
  return Number(value).toFixed(digits);
}

export function renderMarkdown(summary) {
  const lines = [
    `# Response payload boundary: ${summary.run_id}`,
    '',
    `- Evidence class: \`${summary.evidence_class}\`.`,
    `- Publication authorized: \`${summary.publication_authorized}\`.`,
    `- Source: \`${summary.source_commit}\`; dirty: \`${summary.source_dirty}\`.`,
    `- Decision: **${summary.decision}**.`,
    '',
    '| Protocol | Payload | Median successful RPS | Gateway CPU | CPU / 1K RPS | p95 | p99 | p99.9 | Upstream headroom | Max variation |',
    '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
  ];
  for (const group of summary.groups) {
    lines.push(`| ${group.protocol.toUpperCase()} | ${group.payload_bytes} B | ` +
      `${fixed(group.median_successful_rps, 0)} | ${fixed(group.mean_gateway_cpu_percent)}% | ` +
      `${fixed(group.median_gateway_cpu_percent_per_1000_rps, 4)}% | ` +
      `${fixed(group.median_latency_ms.p95, 3)} ms | ${fixed(group.median_latency_ms.p99, 3)} ms | ` +
      `${fixed(group.median_latency_ms.p999, 3)} ms | ${fixed(group.minimum_upstream_headroom_ratio, 2)}x | ` +
      `${fixed(group.maximum_rps_deviation_percent)}% |`);
  }
  lines.push('', 'Boundary ratios are descriptive, not an automatic optimization verdict. ' +
    'Dedicated native profiling must attribute cycles, instructions, writes, and flush waits.', '');
  return `${lines.join('\n')}\n`;
}

function parseArguments(values) {
  const options = {};
  for (let index = 0; index < values.length; index += 2) {
    if (!values[index]?.startsWith('--') || values[index + 1] === undefined) {
      throw new Error(`invalid argument: ${values[index] ?? ''}`);
    }
    options[values[index].slice(2)] = values[index + 1];
  }
  return options;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function main() {
  const [command, ...rest] = process.argv.slice(2);
  const options = parseArguments(rest);
  if (command === 'plan') {
    process.stdout.write(`${JSON.stringify(buildBoundaryPlan({
      repetitions: Number(options.repetitions ?? 5), seed: options.seed,
    }), null, 2)}\n`);
    return;
  }
  if (command === 'summarize') {
    for (const required of ['plan', 'environment', 'results-dir', 'output', 'report']) {
      if (!options[required]) throw new Error(`--${required} is required`);
    }
    const resultFiles = fs.readdirSync(options['results-dir'])
      .filter((name) => name.endsWith('.result.json')).sort();
    const summary = summarizeBoundary({plan: readJson(options.plan),
      environment: readJson(options.environment),
      results: resultFiles.map((name) => readJson(path.join(options['results-dir'], name)))});
    fs.writeFileSync(options.output, `${JSON.stringify(summary, null, 2)}\n`);
    fs.writeFileSync(options.report, renderMarkdown(summary));
    return;
  }
  throw new Error('usage: response-boundary.mjs plan|summarize [options]');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
