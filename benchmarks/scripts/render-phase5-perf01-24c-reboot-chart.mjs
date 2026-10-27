#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const evidence = path.join(root, 'benchmarks/results/verification',
  'phase5-perf01-24c-reboot-diagnostic-20260926');
const output = path.join(root, 'website/static/img/performance',
  'phase5-perf01-24c-reboot-diagnostic-20260926.svg');
const summary = JSON.parse(fs.readFileSync(path.join(evidence, 'summary.json')));

if (summary.schema_version !== 1 || summary.accepted !== false ||
    summary.point_id !== 'P5-B01-24c-steady-r1') {
  throw new Error('24-core diagnostic evidence contract changed');
}

const formal = summary.attempts.find((attempt) => attempt.attempt === 4);
const disjoint = summary.client_placement_diagnostics.find(
  (item) => item.name === 'non_irq_client_cpus');
const single = summary.client_placement_diagnostics.find(
  (item) => item.name === 'single_core_non_irq_client_lanes');
if (!formal || !disjoint || !single) throw new Error('diagnostic rows missing');

const escape = (value) => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;');
const text = (x, y, value, size = 16, weight = 400, fill = '#273142', anchor = 'start') =>
  `<text x="${x}" y="${y}" font-family="Inter,Arial,sans-serif" font-size="${size}" ` +
  `font-weight="${weight}" fill="${fill}" text-anchor="${anchor}" ` +
  `letter-spacing="0">${escape(value)}</text>`;
const rect = (x, y, width, height, fill, radius = 4, stroke = '') =>
  `<rect x="${x}" y="${y}" width="${width}" height="${height}" rx="${radius}" ` +
  `fill="${fill}"${stroke ? ` stroke="${stroke}"` : ''}/>`;
const line = (x1, y1, x2, y2, stroke, width = 1, dash = '') =>
  `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${stroke}" ` +
  `stroke-width="${width}"${dash ? ` stroke-dasharray="${dash}"` : ''}/>`;

const rows = [
  {label: 'Formal capture', p95: formal.p95_ms, full: formal.p999_ms,
    first: formal.first_byte_p999_ms,
    rps: formal.successful_rps, errors: 0, color: '#b42318'},
  {label: 'Non-IRQ CPUs', p95: disjoint.p95_ms, full: disjoint.p999_ms,
    first: disjoint.first_byte_p999_ms,
    rps: disjoint.successful_rps, errors: 0, color: '#b26a00'},
  {label: 'One CPU / lane', p95: single.p95_ms, full: single.p999_ms,
    first: single.first_byte_p999_ms,
    rps: single.successful_rps, errors: single.http_504, color: '#147d76'},
];
const max = 700;
const plot = {x: 100, y: 175, width: 700, height: 390};
const parts = [
  rect(0, 0, 1280, 720, '#f8fafc', 0),
  text(60, 58, 'P5-B01 24-core shared-VM diagnostic', 28, 700, '#172033'),
  text(60, 91, 'p95 is the operating signal; p99.9 remains the frozen tail guard',
    16, 400, '#5d6678'),
];

for (let tick = 0; tick <= max; tick += 100) {
  const y = plot.y + plot.height - tick / max * plot.height;
  parts.push(line(plot.x, y, plot.x + plot.width, y, '#d9e0e7'));
  parts.push(text(plot.x - 12, y + 5, `${tick} ms`, 13, 400, '#687386', 'end'));
}
const ceilingY = plot.y + plot.height - 100 / max * plot.height;
parts.push(line(plot.x, ceilingY, plot.x + plot.width, ceilingY, '#8b5c00', 2, '8 6'));
parts.push(text(plot.x + plot.width, ceilingY - 9, '100 ms gate', 13, 700,
  '#8b5c00', 'end'));

rows.forEach((row, index) => {
  const center = 220 + index * 225;
  const fullHeight = row.full / max * plot.height;
  const firstHeight = Math.max(3, row.first / max * plot.height);
  parts.push(rect(center - 54, plot.y + plot.height - fullHeight, 72, fullHeight,
    row.color));
  parts.push(rect(center + 28, plot.y + plot.height - firstHeight, 34, firstHeight,
    '#4b76b8'));
  parts.push(text(center - 18, plot.y + plot.height - fullHeight - 10,
    row.full.toFixed(1), 13, 700, row.color, 'middle'));
  parts.push(text(center + 45, plot.y + plot.height - firstHeight - 10,
    row.first.toFixed(1), 12, 700, '#4b76b8', 'middle'));
  parts.push(text(center, plot.y + plot.height + 34, row.label, 14, 700,
    '#273142', 'middle'));
});

parts.push(rect(842, 148, 378, 405, '#ffffff', 6, '#cbd5e1'));
parts.push(text(870, 185, 'What the evidence says', 20, 700, '#172033'));
parts.push(text(870, 224, 'Primary operating envelope', 15, 700, '#147d76'));
parts.push(text(870, 249, `${formal.successful_rps.toFixed(0)} successful RPS`, 15));
parts.push(text(870, 274, `p95 ${formal.p95_ms.toFixed(3)} ms; 54.0M HTTP 200`, 15));
parts.push(text(870, 313, 'Tail diagnosis', 15, 700, '#b42318'));
parts.push(text(870, 338, `p99 ${formal.p99_ms.toFixed(1)} ms; p99.9 ${formal.p999_ms.toFixed(1)} ms`, 15));
parts.push(text(870, 363, `first-byte p99.9 ${formal.first_byte_p999_ms.toFixed(3)} ms`, 15));
parts.push(text(870, 402, 'Gateway health', 15, 700, '#4b76b8'));
parts.push(text(870, 427, '0 restarts; 0.81% imbalance; 0 pool waits', 15));
parts.push(text(870, 452, 'No synchronized sampled flamegraph captured', 15));
parts.push(text(870, 491, 'Frozen-gate decision', 15, 700, '#8b5c00'));
parts.push(text(870, 516, 'Point rejected; p95 result remains informative', 15));

parts.push(rect(850, 590, 18, 18, '#b42318', 2));
parts.push(text(878, 605, 'Full-response p99.9', 13));
parts.push(rect(1025, 590, 18, 18, '#4b76b8', 2));
parts.push(text(1053, 605, 'First-byte p99.9', 13));
parts.push(text(60, 680,
  'Failed shared-VM engineering evidence, 26 September 2026. Not publication or Dedicated Host proof.',
  13, 400, '#687386'));

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="720" ` +
  `viewBox="0 0 1280 720" role="img" aria-labelledby="title desc">` +
  `<title id="title">Rejected Phase 5 24-core steady point</title>` +
  `<desc id="desc">The formal run sustained a 2.5 millisecond p95 while the ` +
  `full-response p99.9 failed its frozen tail gate. Bars compare full-response and ` +
  `first-byte p99.9 for the formal run and two client-placement diagnostics.</desc>` +
  `${parts.join('')}</svg>\n`;

fs.mkdirSync(path.dirname(output), {recursive: true});
fs.writeFileSync(output, svg);
