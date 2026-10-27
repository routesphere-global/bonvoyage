#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const evidenceRoot = path.join(repository, 'benchmarks', 'results', 'verification');
const outputRoot = path.join(repository, 'website', 'static', 'img', 'performance');
const runs = [
  {
    key: '550k',
    title: 'Rate-achieving diagnostic point',
    color: '#0f766e',
    root: path.join(evidenceRoot, 'aws-queue-attribution-20260918T052803Z'),
    cpusetBusy: 96.62,
    hostBusy: 87.72,
    loadgenBusy: 40.81,
    upstreamBusy: 46.30,
  },
  {
    key: '700k',
    title: 'Intentional overload point',
    color: '#b45309',
    root: path.join(evidenceRoot, 'aws-queue-attribution-20260918T053806Z'),
    cpusetBusy: 98.28,
    hostBusy: 93.49,
    loadgenBusy: 55.52,
    upstreamBusy: 49.37,
  },
].map((run) => ({
  ...run,
  load: readJson(path.join(run.root, 'loadgen', 'summary.json')),
  attribution: readJson(path.join(run.root, 'target', 'analysis.json')),
  trace: readJson(path.join(run.root, 'target', 'trace-analysis.json')),
}));

function readJson(filename) {
  return JSON.parse(fs.readFileSync(filename, 'utf8'));
}

function escape(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function text(x, y, value, size = 14, weight = 400, fill = '#172033', anchor = 'start') {
  return `<text x="${x}" y="${y}" text-anchor="${anchor}" font-family="Inter,Arial,sans-serif" font-size="${size}" font-weight="${weight}" fill="${fill}">${escape(value)}</text>`;
}

function rect(x, y, width, height, fill, radius = 6, stroke = 'none') {
  return `<rect x="${x}" y="${y}" width="${width}" height="${height}" rx="${radius}" fill="${fill}" stroke="${stroke}"/>`;
}

function line(x1, y1, x2, y2, stroke = '#d9dee8', width = 1, dash = '') {
  const pattern = dash ? ` stroke-dasharray="${dash}"` : '';
  return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${stroke}" stroke-width="${width}"${pattern}/>`;
}

function base(title, description) {
  return [
    '<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="720" viewBox="0 0 1280 720" role="img">',
    `<title>${escape(title)}</title>`,
    `<desc>${escape(description)}</desc>`,
    '<rect width="100%" height="100%" fill="#ffffff"/>',
    text(64, 62, title, 30, 700),
    text(64, 91, description, 15, 400, '#5d6678'),
  ];
}

function close(parts, filename) {
  parts.push('</svg>');
  fs.writeFileSync(path.join(outputRoot, filename), `${parts.join('\n')}\n`);
}

function worst(range) {
  return Math.max(...range);
}

function renderOperatingPoints() {
  const parts = base(
    'Three-node queue attribution replay',
    'Same 24-shard native package; 60-second open-loop HTTP/1.1 runs with four client lanes',
  );
  parts.push(rect(54, 122, 572, 530, '#f7f9fc', 8));
  parts.push(rect(654, 122, 572, 530, '#f7f9fc', 8));
  parts.push(text(82, 164, 'Operating points', 20, 700));
  parts.push(text(682, 164, 'Attribution verdict', 20, 700));

  runs.forEach((run, index) => {
    const y = 200 + index * 205;
    const achieved = run.load.successful_rps;
    const barWidth = achieved / 700000 * 470;
    parts.push(text(82, y, run.title, 17, 700));
    parts.push(text(544, y, `${(run.load.target_achievement_percent).toFixed(2)}% of target`, 13, 700, run.color, 'end'));
    parts.push(rect(82, y + 18, 470, 42, '#e4e8ef', 6));
    parts.push(rect(82, y + 18, barWidth.toFixed(1), 42, run.color, 6));
    parts.push(text(96, y + 46, `${(achieved / 1000).toFixed(1)}k successful RPS`, 17, 700, '#ffffff'));
    parts.push(text(82, y + 88, `Gateway CPU set ${run.cpusetBusy.toFixed(2)}% busy · host ${run.hostBusy.toFixed(2)}%`, 14, 400, '#5d6678'));
    parts.push(text(82, y + 112, `Client ${run.loadgenBusy.toFixed(2)}% busy · upstream ${run.upstreamBusy.toFixed(2)}%`, 14, 400, '#5d6678'));
    parts.push(text(82, y + 140, `Worst lane p95 ${worst(run.load.p95_ms_range).toFixed(1)} ms`, 14, 700, run.color));
    parts.push(text(274, y + 140, `p99 ${worst(run.load.p99_ms_range).toFixed(1)} ms`, 14, 700, run.color));
    parts.push(text(430, y + 140, `p99.9 ${worst(run.load.p999_ms_range).toFixed(1)} ms`, 14, 700, run.color));
  });

  const verdicts = [
    ['Process identity', 'Stable · zero restarts'],
    ['HTTP outcomes', '74.09M responses · zero errors'],
    ['Connection placement', '22 on 8 shards · 21 on 16 shards'],
    ['Requests per connection', '2.62% / 2.74% spread over mean'],
    ['HTTP/1 pool waits', 'Zero at both operating points'],
    ['Scheduler queue peak', '5 / 6 tasks on any shard'],
    ['Linux / ENA loss', 'Zero drops · two time-squeezes at 700k'],
    ['Support-role guard', 'Client and upstream below 80%'],
  ];
  verdicts.forEach(([label, value], index) => {
    const y = 205 + index * 50;
    parts.push(`<circle cx="694" cy="${y - 5}" r="7" fill="#0f766e"/>`);
    parts.push(text(714, y, label, 14, 700));
    parts.push(text(1194, y, value, 14, 400, '#5d6678', 'end'));
    if (index < verdicts.length - 1) parts.push(line(682, y + 20, 1198, y + 20));
  });
  parts.push(rect(682, 580, 516, 48, '#e8f5f2', 6));
  parts.push(text(700, 610, 'No gross shard skew or HTTP/1 pool pressure was observed.', 15, 700, '#0f766e'));
  close(parts, 'queue-attribution-operating-points.svg');
}

function normalizedRequestsPerConnection(run) {
  const requests = run.attribution.gateway.requests_by_shard;
  const connections = run.attribution.gateway.accepted_connections_by_shard;
  const values = Array.from({length: 24}, (_, shard) => requests[shard] / connections[shard]);
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  return values.map((value) => value / mean * 100);
}

function renderShardBalance() {
  const parts = base(
    'Shard work follows connection placement',
    'Requests per accepted connection, normalized to the 24-shard mean; 100% is perfectly even',
  );
  const plot = {x: 86, y: 144, width: 1110, height: 360};
  const minY = 97.5;
  const maxY = 102.5;
  for (let value = 98; value <= 102; value += 1) {
    const y = plot.y + (maxY - value) / (maxY - minY) * plot.height;
    parts.push(line(plot.x, y, plot.x + plot.width, y, value === 100 ? '#8a94a6' : '#e4e8ef', value === 100 ? 2 : 1, value === 100 ? '7 5' : ''));
    parts.push(text(plot.x - 12, y + 5, `${value}%`, 12, value === 100 ? 700 : 400, '#5d6678', 'end'));
  }
  runs.forEach((run) => {
    const values = normalizedRequestsPerConnection(run);
    const points = values.map((value, shard) => {
      const x = plot.x + shard / 23 * plot.width;
      const y = plot.y + (maxY - value) / (maxY - minY) * plot.height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    });
    parts.push(`<polyline points="${points.join(' ')}" fill="none" stroke="${run.color}" stroke-width="4" stroke-linejoin="round"/>`);
    values.forEach((value, shard) => {
      const x = plot.x + shard / 23 * plot.width;
      const y = plot.y + (maxY - value) / (maxY - minY) * plot.height;
      parts.push(`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="5" fill="${run.color}"/>`);
    });
  });
  for (let shard = 0; shard < 24; shard += 1) {
    const x = plot.x + shard / 23 * plot.width;
    parts.push(text(x, 532, shard, 11, 400, '#5d6678', 'middle'));
    parts.push(rect(x - 13, 550, 26, shard < 8 ? 35 : 28, shard < 8 ? '#bfded8' : '#dce4ea', 3));
    parts.push(text(x, shard < 8 ? 574 : 570, shard < 8 ? '22' : '21', 11, 700, '#172033', 'middle'));
  }
  parts.push(text(86, 610, 'Accepted connections per shard', 13, 700));
  parts.push(line(330, 606, 370, 606, runs[0].color, 4));
  parts.push(text(382, 611, '550k: 2.62% spread', 13, 700, runs[0].color));
  parts.push(line(570, 606, 610, 606, runs[1].color, 4));
  parts.push(text(622, 611, '700k: 2.74% spread', 13, 700, runs[1].color));
  parts.push(rect(865, 588, 331, 48, '#e8f5f2', 6));
  parts.push(text(884, 617, 'The 5–7% raw spread is explained by 22 vs 21 flows.', 13, 700, '#0f766e'));
  close(parts, 'queue-attribution-shard-balance.svg');
}

function renderEvidencePath() {
  const parts = base(
    'Where primary pressure was not observed',
    'Correlated evidence across the three private-VPC roles; shared AWS VM, not Dedicated Host qualification',
  );
  const boxes = [
    {x: 54, width: 255, title: 'Load generator', color: '#e8f5f2', lines: ['4 pinned lanes × 128 connections', '40.81% / 55.52% host busy', 'Zero transport errors']},
    {x: 349, width: 255, title: 'ENA + Linux', color: '#eef2f7', lines: ['8 NIC IRQ queues on CPUs 0–7', '100% target NIC IRQ placement', 'Zero drops; 2 time-squeezes at 700k']},
    {x: 644, width: 255, title: 'BonVoyage', color: '#e8f5f2', lines: ['24 shards on CPUs 8–31', '96.62% / 98.28% CPU-set busy', 'Queue peak 5 / 6 tasks per shard']},
    {x: 939, width: 287, title: 'Controlled upstream', color: '#fff4e5', lines: ['4 containers across 32 CPUs', '46.30% / 49.37% host busy', 'Zero pool waits; all targets healthy']},
  ];
  boxes.forEach((box, index) => {
    parts.push(rect(box.x, 166, box.width, 250, box.color, 8, '#d9dee8'));
    parts.push(text(box.x + 22, 205, box.title, 19, 700));
    box.lines.forEach((value, lineIndex) => parts.push(text(box.x + 22, 254 + lineIndex * 43, value, 14, lineIndex === 2 ? 700 : 400, lineIndex === 2 ? '#0f766e' : '#5d6678')));
    if (index < boxes.length - 1) {
      const x1 = box.x + box.width + 8;
      const x2 = boxes[index + 1].x - 8;
      parts.push(line(x1, 291, x2, 291, '#657084', 3));
      parts.push(`<path d="M ${x2 - 10} 284 L ${x2} 291 L ${x2 - 10} 298" fill="none" stroke="#657084" stroke-width="3"/>`);
    }
  });
  parts.push(rect(54, 458, 1172, 80, '#f7f9fc', 8));
  parts.push(text(78, 491, 'Not supported as primary causes in these intervals', 15, 700));
  parts.push(text(78, 520, 'gross shard skew · HTTP/1 pool pressure · generator saturation · upstream saturation · packet loss · process restart', 16, 700, '#0f766e'));
  parts.push(rect(54, 566, 1172, 72, '#fff4e5', 8));
  parts.push(text(78, 598, 'Next attribution boundary', 15, 700, '#8a3c05'));
  parts.push(text(78, 625, 'Per-flow client/NIC queue correlation on Dedicated Host hardware before changing Seastar scheduling or pool policy.', 15, 700, '#8a3c05'));
  close(parts, 'queue-attribution-evidence-path.svg');
}

fs.mkdirSync(outputRoot, {recursive: true});
renderOperatingPoints();
renderShardBalance();
renderEvidencePath();
