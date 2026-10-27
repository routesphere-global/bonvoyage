#!/usr/bin/env node

import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseOhaReport} from './phase5-oha-lanes.mjs';

const FILE = /^p5-(b0[1-4])-(8c|24c)-(\d+|200k)(-20s|-counted)?\.json$/u;
const PERCENTILES = ['p50', 'p95', 'p99', 'p99.9'];

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function count(value, label) {
  requireValue(Number.isSafeInteger(value) && value >= 0, `${label} must be a count`);
  return value;
}

function addCounts(target, source, label) {
  requireValue(source && typeof source === 'object' && !Array.isArray(source),
    `${label} missing`);
  for (const [name, value] of Object.entries(source)) {
    target[name] = count((target[name] ?? 0) + count(value, `${label} ${name}`),
      `${label} ${name} aggregate`);
  }
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function summarizeBundle(bundle, label = 'bundle') {
  requireValue(bundle?.kind === 'phase5-oha-lanes' && bundle.schema_version === 1 &&
    Array.isArray(bundle.lanes) && bundle.lanes.length >= 2,
  `${label} is not a Phase 5 lane bundle`);
  requireValue(Number.isSafeInteger(bundle.rate_per_lane) && bundle.rate_per_lane > 0 &&
    Array.isArray(bundle.cpu_sets) && bundle.cpu_sets.length === bundle.lanes.length,
  `${label} lane placement invalid`);
  const starts = [];
  const ends = [];
  const durations = [];
  const statuses = {};
  const errors = {};
  const percentiles = Object.fromEntries(PERCENTILES.map((name) => [name, 0]));
  let laneRps = 0;
  for (const [index, lane] of bundle.lanes.entries()) {
    requireValue(lane.index === index && lane.exit_code === 0 &&
      typeof lane.raw_json === 'string', `${label} lane ${index} failed`);
    const start = BigInt(lane.start_ns);
    const end = BigInt(lane.end_ns);
    requireValue(start >= 0n && end > start, `${label} lane ${index} clock invalid`);
    const report = JSON.parse(lane.raw_json);
    requireValue(Number.isFinite(report.summary?.total) && report.summary.total > 0 &&
      Number.isFinite(report.summary?.requestsPerSec) && report.summary.requestsPerSec > 0,
    `${label} lane ${index} summary invalid`);
    starts.push(start);
    ends.push(end);
    durations.push(report.summary.total);
    laneRps += report.summary.requestsPerSec;
    addCounts(statuses, report.statusCodeDistribution, `${label} lane ${index} status`);
    addCounts(errors, report.errorDistribution ?? {}, `${label} lane ${index} error`);
    for (const name of PERCENTILES) {
      const value = report.latencyPercentiles?.[name];
      requireValue(Number.isFinite(value) && value > 0,
        `${label} lane ${index} ${name} invalid`);
      percentiles[name] = Math.max(percentiles[name], value);
    }
  }
  const earliest = starts.reduce((a, b) => a < b ? a : b);
  const latest = ends.reduce((a, b) => a > b ? a : b);
  const overlapStart = starts.reduce((a, b) => a > b ? a : b);
  const overlapEnd = ends.reduce((a, b) => a < b ? a : b);
  const envelope = Number(latest - earliest) / 1e9;
  const overlap = overlapEnd > overlapStart ? Number(overlapEnd - overlapStart) / 1e9 : 0;
  const successes = statuses['200'] ?? 0;
  const offered = count(bundle.rate_per_lane * bundle.lanes.length,
    `${label} offered RPS`);
  let contractReplay = true;
  let contractError = null;
  try {
    parseOhaReport(bundle);
  } catch (error) {
    contractReplay = false;
    contractError = error.message;
  }
  return {
    lanes: bundle.lanes.length,
    offered_rps: offered,
    envelope_seconds: envelope,
    overlap_seconds: overlap,
    overlap_fraction: overlap / envelope,
    minimum_lane_seconds: Math.min(...durations),
    successful_responses: successes,
    successful_rps_envelope: successes / envelope,
    delivered_percent_envelope: successes / envelope / offered * 100,
    lane_reported_rps_sum: laneRps,
    status_counts: statuses,
    error_counts: errors,
    latency_ms: Object.fromEntries(PERCENTILES.map((name) =>
      [name, percentiles[name] * 1000])),
    contract_replay: contractReplay,
    contract_error: contractError,
  };
}

export function summarizeDirectory(directory) {
  const rows = [];
  for (const name of fs.readdirSync(directory).sort()) {
    const match = FILE.exec(name);
    if (!match) continue;
    const bytes = fs.readFileSync(path.join(directory, name));
    const bundle = JSON.parse(bytes);
    const offered = match[3] === '200k' ? 200000 : Number(match[3]);
    const mode = match[4] === '-counted' ? 'fixed-count' : 'duration';
    rows.push({file: name, sha256: digest(bytes), profile: `P5-${match[1].toUpperCase()}`,
      cores: Number(match[2].slice(0, -1)), offered_rps: offered, mode,
      ...summarizeBundle(bundle, name)});
  }
  requireValue(rows.length > 0, 'no discovery bundles found');
  return {schema_version: 1, evidence_class: 'shared-vm-engineering-diagnostic', rows};
}

function main() {
  const [, , action, option, directory, ...extra] = process.argv;
  requireValue(action === 'summarize' && option === '--input' && directory &&
    extra.length === 0,
  'usage: phase5-discovery-summary.mjs summarize --input DIR');
  process.stdout.write(`${JSON.stringify(summarizeDirectory(path.resolve(directory)), null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-discovery-summary: ${error.message}\n`);
    process.exitCode = 1;
  }
}
