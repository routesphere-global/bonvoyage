#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const evidence = path.join(root, 'benchmarks/results/verification',
  'phase5-schema7-native-first-point-20260926');
const output = path.join(root, 'website/static/img/performance');
const summary = JSON.parse(fs.readFileSync(path.join(evidence, 'summary.json')));
const attribution = JSON.parse(fs.readFileSync(
  path.join(evidence, 'capture/attribution.json')));

if (summary.schema_version !== 1 || summary.attempts?.[1]?.attempt !== 3 ||
    attribution.schema_version !== 1 || attribution.duration_seconds <= 0) {
  throw new Error('native first-point evidence contract changed');
}

const attempt = summary.attempts[1];
const escape = (value) => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;');
const text = (x, y, value, size = 16, weight = 400, fill = '#273142', anchor = 'start') =>
  `<text x="${x}" y="${y}" font-family="Inter,Arial,sans-serif" font-size="${size}" ` +
  `font-weight="${weight}" fill="${fill}" text-anchor="${anchor}" ` +
  `letter-spacing="0">${escape(value)}</text>`;
const rect = (x, y, width, height, fill, radius = 4) =>
  `<rect x="${x}" y="${y}" width="${width}" height="${height}" rx="${radius}" fill="${fill}"/>`;
const line = (x1, y1, x2, y2, stroke, width = 1, dash = '') =>
  `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${stroke}" ` +
  `stroke-width="${width}"${dash ? ` stroke-dasharray="${dash}"` : ''}/>`;
const shell = (body) => `<svg xmlns="http://www.w3.org/2000/svg" width="1280" ` +
  `height="720" viewBox="0 0 1280 720" role="img">${rect(0, 0, 1280, 720, '#ffffff', 0)}` +
  `${body}</svg>\n`;

function tailChart() {
  const series = [
    {label: 'Capacity', values: [attempt.p95_ms, attempt.p99_ms, attempt.p999_ms],
      color: '#d45d4c'},
    {label: 'Diagnostic', values: [7.059965, attempt.diagnostic_p99_ms,
      attempt.diagnostic_p999_ms], color: '#147d76'},
  ];
  const labels = ['p95', 'p99', 'p99.9'];
  const max = 450;
  const plot = {x: 130, y: 170, width: 1050, height: 420};
  const parts = [
    text(64, 60, 'P5-B01 first-point tail result', 28, 700, '#172033'),
    text(64, 94, 'Exact-plan capacity was rejected; the separate perf interval remained below the ceiling.',
      16, 400, '#5d6678'),
  ];
  for (let tick = 0; tick <= 450; tick += 50) {
    const y = plot.y + plot.height - tick / max * plot.height;
    parts.push(line(plot.x, y, plot.x + plot.width, y, '#dfe4ea'));
    parts.push(text(plot.x - 14, y + 5, `${tick} ms`, 13, 400, '#687386', 'end'));
  }
  const ceilingY = plot.y + plot.height - 100 / max * plot.height;
  parts.push(line(plot.x, ceilingY, plot.x + plot.width, ceilingY, '#8b5c00', 2, '8 6'));
  parts.push(text(plot.x + plot.width, ceilingY - 10, '100 ms acceptance ceiling', 14,
    700, '#8b5c00', 'end'));
  labels.forEach((label, index) => {
    const center = plot.x + 190 + index * 320;
    parts.push(text(center, plot.y + plot.height + 42, label, 16, 700, '#273142', 'middle'));
    series.forEach((item, seriesIndex) => {
      const value = item.values[index];
      const height = value / max * plot.height;
      const x = center - 82 + seriesIndex * 92;
      parts.push(rect(x, plot.y + plot.height - height, 72, height, item.color));
      parts.push(text(x + 36, plot.y + plot.height - height - 10, value.toFixed(1), 13,
        700, item.color, 'middle'));
    });
  });
  parts.push(rect(820, 42, 18, 18, series[0].color, 2), text(848, 57, 'Capacity', 14));
  parts.push(rect(930, 42, 18, 18, series[1].color, 2), text(958, 57, 'Diagnostic', 14));
  parts.push(text(64, 685, 'Shared-VM engineering evidence. Not a publication or Dedicated Host claim.',
    13, 400, '#687386'));
  return shell(parts.join(''));
}

function shardChart() {
  const busy = Object.entries(attribution.gateway.reactor_cpu_busy_ms_by_shard)
    .sort(([left], [right]) => Number(left) - Number(right))
    .map(([shard, value]) => ({shard, cpu: value / (attribution.duration_seconds * 10),
      requests: attribution.gateway.requests_by_shard[shard]}));
  const maximumRequests = Math.max(...busy.map((item) => item.requests));
  const parts = [
    text(64, 60, 'Reactor and request distribution under diagnostic load', 28, 700, '#172033'),
    text(64, 94, 'Shard 3 shared CPU 11 with an ENA queue IRQ and reached the highest reactor utilization.',
      16, 400, '#5d6678'),
  ];
  const plot = {x: 130, y: 160, width: 1050, height: 430};
  for (let tick = 0; tick <= 100; tick += 20) {
    const y = plot.y + plot.height - tick / 100 * plot.height;
    parts.push(line(plot.x, y, plot.x + plot.width, y, '#dfe4ea'));
    parts.push(text(plot.x - 14, y + 5, `${tick}%`, 13, 400, '#687386', 'end'));
  }
  busy.forEach((item, index) => {
    const center = plot.x + 85 + index * 125;
    const requestRatio = item.requests / maximumRequests * 100;
    const cpuHeight = item.cpu / 100 * plot.height;
    const requestHeight = requestRatio / 100 * plot.height;
    const cpuColor = index === 3 ? '#d45d4c' : '#147d76';
    parts.push(rect(center - 34, plot.y + plot.height - cpuHeight, 30, cpuHeight, cpuColor));
    parts.push(rect(center + 4, plot.y + plot.height - requestHeight, 30, requestHeight,
      '#4b76b8'));
    parts.push(text(center, plot.y + plot.height + 38, `Shard ${item.shard}`, 14, 700,
      '#273142', 'middle'));
    parts.push(text(center - 19, plot.y + plot.height - cpuHeight - 8, item.cpu.toFixed(1),
      12, 700, cpuColor, 'middle'));
  });
  parts.push(rect(780, 42, 18, 18, '#147d76', 2), text(808, 57, 'Reactor CPU', 14));
  parts.push(rect(925, 42, 18, 18, '#4b76b8', 2),
    text(953, 57, 'Requests vs busiest shard', 14));
  parts.push(text(64, 685, `Observed request imbalance: ${(attribution.gateway.request_imbalance_ratio * 100).toFixed(2)}%. ` +
    'The static-ENA profile must be measured, not assumed beneficial.', 13, 400, '#687386'));
  return shell(parts.join(''));
}

fs.mkdirSync(output, {recursive: true});
fs.writeFileSync(path.join(output, 'phase5-native-first-point-tail.svg'), tailChart());
fs.writeFileSync(path.join(output, 'phase5-native-first-point-shards.svg'), shardChart());
