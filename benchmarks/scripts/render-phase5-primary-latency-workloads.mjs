#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sourcePath = path.join(
  root,
  'benchmarks/results/exploratory/phase5-capacity-discovery-20260925/summary.json',
);
const outputDirectory = path.join(root, 'website/static/img/performance');

const evidence = JSON.parse(fs.readFileSync(sourcePath, 'utf8'));
const profileNames = new Map([
  ['P5-B01', 'HTTP/1.1'],
  ['P5-B02', 'HTTPS/1.1'],
  ['P5-B03', 'HTTPS/2'],
  ['P5-B04', 'HTTPS + API key'],
]);
const selections = new Map([
  [8, [
    'p5-b01-8c-200k.json',
    'p5-b02-8c-220000.json',
    'p5-b03-8c-200000-counted.json',
    'p5-b04-8c-240000-counted.json',
  ]],
  [24, [
    'p5-b01-24c-500000-counted.json',
    'p5-b02-24c-500000-counted.json',
    'p5-b03-24c-450000-counted.json',
    'p5-b04-24c-500000-counted.json',
  ]],
]);

const escape = (value) => String(value)
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;');
const text = (x, y, value, size = 16, weight = 400, fill = '#273142', anchor = 'start') =>
  `<text x="${x}" y="${y}" font-family="Inter,Arial,sans-serif" font-size="${size}" ` +
  `font-weight="${weight}" fill="${fill}" text-anchor="${anchor}" ` +
  `letter-spacing="0">${escape(value)}</text>`;
const line = (x1, y1, x2, y2, stroke, strokeWidth = 1, dash = '') =>
  `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${stroke}" ` +
  `stroke-width="${strokeWidth}"${dash ? ` stroke-dasharray="${dash}"` : ''}/>`;
const rect = (x, y, width, height, fill, radius = 0, stroke = '') =>
  `<rect x="${x}" y="${y}" width="${width}" height="${height}" rx="${radius}" ` +
  `fill="${fill}"${stroke ? ` stroke="${stroke}"` : ''}/>`;

function selectedRows(coreCount) {
  return selections.get(coreCount).map((file) => {
    const row = evidence.rows.find((candidate) => candidate.file === file);
    if (!row) {
      throw new Error(`missing evidence row: ${file}`);
    }
    if (row.cores !== coreCount || !profileNames.has(row.profile)) {
      throw new Error(`unexpected profile identity: ${file}`);
    }
    const values = [row.latency_ms.p50, row.latency_ms.p95, row.latency_ms.p99];
    if (!values.every(Number.isFinite) || values[0] > values[1] || values[1] > values[2]) {
      throw new Error(`invalid primary latency percentiles: ${file}`);
    }
    if (Object.keys(row.error_counts).length !== 0 ||
        Object.keys(row.status_counts).some((status) => status !== '200')) {
      throw new Error(`non-success response present: ${file}`);
    }
    return {...row, displayName: profileNames.get(row.profile)};
  });
}

function render(coreCount) {
  const rows = selectedRows(coreCount);
  const directional = rows.some((row) => !row.contract_replay);
  const width = 1400;
  const height = 820;
  const plot = {x: 120, y: 170, width: 1160, height: 440};
  const maxValue = Math.ceil(Math.max(...rows.flatMap((row) => [
    row.latency_ms.p50,
    row.latency_ms.p95,
    row.latency_ms.p99,
  ])) + 1);
  const yScale = (value) => plot.y + plot.height - value / maxValue * plot.height;
  const groupWidth = plot.width / rows.length;
  const colors = {
    p50: '#2563eb',
    p95: '#0f766e',
    p99: '#b45309',
  };
  const parts = [
    rect(0, 0, width, height, '#f8fafc'),
    text(56, 58, `BonVoyage ${coreCount}-core workload latency`, 29, 700, '#172033'),
    text(
      56,
      92,
      'Primary operator percentiles from retained Phase 5 shared-VM capacity discovery',
      16,
      400,
      '#5d6678',
    ),
  ];

  for (let tick = 0; tick <= maxValue; tick += 1) {
    const y = yScale(tick);
    parts.push(line(plot.x, y, plot.x + plot.width, y, '#d7dee7'));
    parts.push(text(plot.x - 18, y + 5, `${tick} ms`, 13, 500, '#687386', 'end'));
  }

  rows.forEach((row, rowIndex) => {
    const center = plot.x + groupWidth * (rowIndex + 0.5);
    const barWidth = 56;
    const gap = 18;
    const series = [
      ['p50', row.latency_ms.p50],
      ['p95', row.latency_ms.p95],
      ['p99', row.latency_ms.p99],
    ];

    series.forEach(([name, value], seriesIndex) => {
      const x = center + (seriesIndex - 1) * (barWidth + gap) - barWidth / 2;
      const y = yScale(value);
      parts.push(rect(x, y, barWidth, plot.y + plot.height - y, colors[name], 3));
      parts.push(text(x + barWidth / 2, y - 9, value.toFixed(3), 12, 700,
        colors[name], 'middle'));
    });

    parts.push(text(center, 648, row.displayName, 15, 700, '#273142', 'middle'));
    parts.push(text(center, 673, `${Math.round(row.offered_rps / 1000)}k offered RPS`,
      13, 500, '#687386', 'middle'));
    parts.push(text(center, 695,
      `${Math.round(row.successful_rps_envelope).toLocaleString('en-US')} conservative RPS`,
      12, 400, '#687386', 'middle'));
  });

  const legendY = 742;
  [['p50', 'p50 typical'], ['p95', 'p95 primary SLO'], ['p99', 'p99 boundary']]
    .forEach(([name, label], index) => {
      const x = 70 + index * 230;
      parts.push(rect(x, legendY - 12, 20, 20, colors[name], 3));
      parts.push(text(x + 30, legendY + 4, label, 14, 600));
    });
  parts.push(text(56, 790,
    directional
      ? 'Directional only: the 24-core short discovery windows failed the 95% alignment contract.'
      : 'All selected eight-core rows passed the retained client-contract replay with zero errors.',
    13,
    500,
    directional ? '#9f1239' : '#166534',
  ));

  const description = `Grouped bar chart of p50, p95 and p99 latency for four ${coreCount}-core ` +
    `BonVoyage workloads: HTTP/1.1, HTTPS/1.1, HTTPS/2 and HTTPS with API-key validation.`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" ` +
    `viewBox="0 0 ${width} ${height}" role="img" aria-labelledby="title desc">` +
    `<title id="title">BonVoyage ${coreCount}-core primary workload latency</title>` +
    `<desc id="desc">${escape(description)}</desc>${parts.join('')}</svg>\n`;
}

fs.mkdirSync(outputDirectory, {recursive: true});
for (const coreCount of selections.keys()) {
  const outputPath = path.join(
    outputDirectory,
    `phase5-primary-latency-workloads-${coreCount}core-20260927.svg`,
  );
  fs.writeFileSync(outputPath, render(coreCount));
}
