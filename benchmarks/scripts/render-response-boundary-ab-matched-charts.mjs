#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const evidenceRoot = path.join(
  repository,
  'benchmarks',
  'results',
  'verification',
  'aws-response-boundary-ab-matched-20260918',
);
const outputRoot = path.join(repository, 'website', 'static', 'img', 'performance');
const analysis = JSON.parse(fs.readFileSync(path.join(evidenceRoot, 'analysis.json'), 'utf8'));
const groups = analysis.groups;

const colors = {
  bonvoyage: '#0f766e',
  nginx: '#2563a6',
  caution: '#b45309',
  danger: '#b42318',
  ink: '#172033',
  muted: '#5d6678',
  grid: '#d9dee8',
  panel: '#f7f9fc',
};

function escape(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function text(x, y, value, size = 14, weight = 400, fill = colors.ink, anchor = 'start') {
  return `<text x="${x}" y="${y}" text-anchor="${anchor}" font-family="Inter,Arial,sans-serif" font-size="${size}" font-weight="${weight}" fill="${fill}">${escape(value)}</text>`;
}

function rect(x, y, width, height, fill, radius = 6, stroke = 'none') {
  return `<rect x="${x}" y="${y}" width="${width}" height="${height}" rx="${radius}" fill="${fill}" stroke="${stroke}"/>`;
}

function line(x1, y1, x2, y2, stroke = colors.grid, width = 1, dash = '') {
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
    text(64, 91, description, 15, 400, colors.muted),
  ];
}

function close(parts, filename) {
  parts.push('</svg>');
  fs.writeFileSync(path.join(outputRoot, filename), `${parts.join('\n')}\n`);
}

function renderEqualRate() {
  const bonvoyage = groups.bonvoyage_current_500k;
  const nginx = groups.nginx_os_managed_500k;
  const parts = base(
    'Equal throughput, different operating profiles',
    'Five-run medians at 500k successful RPS; zero errors; worst client-lane percentiles',
  );

  parts.push(rect(54, 124, 430, 520, colors.panel, 8));
  parts.push(rect(510, 124, 716, 520, colors.panel, 8));
  parts.push(text(82, 166, 'Application CPU', 20, 700));
  parts.push(text(538, 166, 'Corrected tail latency', 20, 700));

  const cpuRows = [
    ['BonVoyage tuned', bonvoyage.application_active_cores_median, colors.bonvoyage],
    ['NGINX OS-managed', nginx.application_active_cores_median, colors.nginx],
  ];
  cpuRows.forEach(([label, value, color], index) => {
    const y = 218 + index * 122;
    parts.push(text(82, y, label, 16, 700));
    parts.push(rect(82, y + 18, 338, 40, '#e4e8ef', 5));
    parts.push(rect(82, y + 18, value / 24 * 338, 40, color, 5));
    parts.push(text(98, y + 45, `${value.toFixed(2)} active cores`, 16, 700, '#ffffff'));
  });
  parts.push(text(82, 498, 'CPU interpretation', 15, 700));
  parts.push(text(82, 527, 'NGINX performs less application CPU work', 14, 400, colors.muted));
  parts.push(text(82, 550, 'at this equal-rate point. BonVoyage keeps', 14, 400, colors.muted));
  parts.push(text(82, 573, 'its reactor allocation busy and produces', 14, 400, colors.muted));
  parts.push(text(82, 596, 'the tighter observed tail.', 14, 700, colors.bonvoyage));

  const metrics = [
    ['p95', bonvoyage.worst_lane_p95_median_ms, nginx.worst_lane_p95_median_ms],
    ['p99', bonvoyage.worst_lane_p99_median_ms, nginx.worst_lane_p99_median_ms],
    ['p99.9', bonvoyage.worst_lane_p999_median_ms, nginx.worst_lane_p999_median_ms],
  ];
  const maxLatency = 250;
  metrics.forEach(([label, bv, ng], index) => {
    const y = 220 + index * 118;
    parts.push(text(538, y, label, 16, 700));
    parts.push(rect(610, y - 18, 520, 26, '#e4e8ef', 4));
    parts.push(rect(610, y - 18, bv / maxLatency * 520, 26, colors.bonvoyage, 4));
    parts.push(text(1148, y + 2, `${bv.toFixed(1)} ms`, 14, 700, colors.bonvoyage));
    parts.push(rect(610, y + 22, 520, 26, '#e4e8ef', 4));
    parts.push(rect(610, y + 22, ng / maxLatency * 520, 26, colors.nginx, 4));
    parts.push(text(1148, y + 42, `${ng.toFixed(1)} ms`, 14, 700, colors.nginx));
  });
  parts.push(rect(538, 582, 660, 42, '#e8f5f2', 6));
  parts.push(text(556, 608, 'BonVoyage: lower median p95, p99 and p99.9 at the same successful rate.', 14, 700, colors.bonvoyage));
  close(parts, 'response-boundary-equal-rate-cpu-tail.svg');
}

function renderMatchedEnvelope() {
  const nginx = groups.nginx_os_managed_500k;
  const stable = groups.bonvoyage_current_575k;
  const edge = groups.bonvoyage_current_600k;
  const rows = [
    {label: 'NGINX OS-managed', detail: 'accepted control', group: nginx, color: colors.nginx},
    {label: 'BonVoyage tuned', detail: 'stable envelope', group: stable, color: colors.bonvoyage},
    {label: 'BonVoyage tuned', detail: 'unstable edge', group: edge, color: colors.caution},
  ];
  const parts = base(
    'Matched p99.9 envelope: stable at +15%, unstable at +20%',
    'Five-run medians; all attempts retained; shared AWS VMs, not Dedicated Host qualification',
  );
  parts.push(text(72, 142, 'Successful RPS', 16, 700));
  parts.push(text(710, 142, 'Worst client-lane latency', 16, 700));

  rows.forEach((row, index) => {
    const y = 184 + index * 142;
    const rpsWidth = row.group.successful_rps_median / 650000 * 510;
    parts.push(text(72, y, row.label, 16, 700));
    parts.push(text(260, y, row.detail, 13, 400, colors.muted));
    parts.push(rect(72, y + 18, 510, 38, '#e4e8ef', 5));
    parts.push(rect(72, y + 18, rpsWidth, 38, row.color, 5));
    parts.push(text(88, y + 44, `${Math.round(row.group.successful_rps_median).toLocaleString('en-US')} RPS`, 15, 700, '#ffffff'));

    const latency = [
      ['p95', row.group.worst_lane_p95_median_ms],
      ['p99', row.group.worst_lane_p99_median_ms],
      ['p99.9', row.group.worst_lane_p999_median_ms],
    ];
    latency.forEach(([label, value], metricIndex) => {
      const x = 710 + metricIndex * 160;
      parts.push(text(x, y + 8, label, 13, 700, colors.muted));
      parts.push(text(x, y + 38, `${value.toFixed(1)} ms`, 18, 700, row.color));
    });
    if (row.group.worst_lane_p999_max_ms) {
      parts.push(text(710, y + 70, `Retained p99.9 outlier: ${row.group.worst_lane_p999_max_ms.toFixed(1)} ms`, 13, 700, colors.danger));
    }
    parts.push(line(72, y + 94, 1200, y + 94));
  });

  parts.push(rect(72, 612, 1128, 44, '#fff4e5', 6));
  parts.push(text(92, 639, 'Decision: retain +15% as the repeatable engineering envelope; keep the formal +20% gate open.', 15, 700, colors.caution));
  close(parts, 'response-boundary-matched-envelope.svg');
}

fs.mkdirSync(outputRoot, {recursive: true});
renderEqualRate();
renderMatchedEnvelope();
