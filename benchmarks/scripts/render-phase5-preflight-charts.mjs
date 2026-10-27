#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const evidence = path.join(repository, 'benchmarks', 'results', 'verification',
  'phase5-duration-placement-preflight-20260926', 'summary.json');
const schema7Evidence = path.join(repository, 'benchmarks', 'results', 'verification',
  'phase5-schema7-plan-freeze-20260926', 'summary.json');
const staticEnaEvidence = path.join(repository, 'benchmarks', 'results', 'verification',
  'phase5-static-ena-nitro-preflight-20260926', 'direct-support-summary.json');
const nitroDisjointEvidence = path.join(repository, 'benchmarks', 'results', 'verification',
  'phase5-p5b01-nitro-disjoint-20260926', 'summary.json');
const output = path.join(repository, 'website', 'static', 'img', 'performance');
const preflightSummary = JSON.parse(fs.readFileSync(evidence, 'utf8'));
const schema7Summary = JSON.parse(fs.readFileSync(schema7Evidence, 'utf8'));
const staticEnaSummary = JSON.parse(fs.readFileSync(staticEnaEvidence, 'utf8'));
const nitroDisjointSummary = JSON.parse(fs.readFileSync(nitroDisjointEvidence, 'utf8'));

if (preflightSummary.schema_version !== 1 ||
    preflightSummary.gateway_measured !== false ||
    preflightSummary.evidence_class !== 'shared-vm-engineering' ||
    preflightSummary.direct_support?.accepted_attempt !== 4 ||
    preflightSummary.direct_support?.errors !== 0) {
  throw new Error('Phase 5 preflight summary is not the reviewed evidence contract');
}
if (schema7Summary.schema_version !== 1 ||
    schema7Summary.gateway_measured !== false ||
    schema7Summary.source_dirty !== false ||
    schema7Summary.plan?.schema_version !== 7 ||
    schema7Summary.plan?.scheduled_points !== 80 ||
    schema7Summary.direct_support?.errors !== 0) {
  throw new Error('Phase 5 schema-7 summary is not the reviewed evidence contract');
}
if (staticEnaSummary.harness_commit !==
      'c9931c2727c0a7afa525f7170c003b4bfa038402' ||
    staticEnaSummary.static_ena?.accepted !== false ||
    staticEnaSummary.direct_support?.transport_errors !== 0 ||
    staticEnaSummary.restoration?.status !== 'restored') {
  throw new Error('Phase 5 static-ENA summary is not the reviewed evidence contract');
}
if (nitroDisjointSummary.schema_version !== 1 ||
    nitroDisjointSummary.evidence_class !== 'shared-vm-engineering' ||
    nitroDisjointSummary.gateway_measured !== true ||
    nitroDisjointSummary.source_dirty !== false ||
    nitroDisjointSummary.plan_id !==
      '234828f43ee8b89434b374b9ac858fcf2b99e2a910a83c98bc501244b6514b00' ||
    nitroDisjointSummary.accepted_points !== 1 ||
    nitroDisjointSummary.accepted?.attempt !== 2 ||
    nitroDisjointSummary.accepted?.transport_errors !== 0 ||
    nitroDisjointSummary.accepted?.non_200 !== 0 ||
    nitroDisjointSummary.placement?.overlap_count !== 0 ||
    nitroDisjointSummary.restoration?.status !== 'restored') {
  throw new Error('Phase 5 Nitro-disjoint summary is not the reviewed evidence contract');
}

function escape(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function fixedWithGrouping(value, digits = 2) {
  return Number(value).toFixed(digits).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

function text(x, y, value, size = 14, weight = 400, fill = '#172033',
  anchor = 'start') {
  return `<text x="${x}" y="${y}" text-anchor="${anchor}" ` +
    `font-family="Inter,Arial,sans-serif" font-size="${size}" ` +
    `font-weight="${weight}" fill="${fill}">${escape(value)}</text>`;
}

function rect(x, y, width, height, fill, radius = 6, stroke = 'none') {
  return `<rect x="${x}" y="${y}" width="${width}" height="${height}" ` +
    `rx="${radius}" fill="${fill}" stroke="${stroke}"/>`;
}

function line(x1, y1, x2, y2, stroke = '#d9dee8', width = 1, dash = '') {
  const pattern = dash ? ` stroke-dasharray="${dash}"` : '';
  return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" ` +
    `stroke="${stroke}" stroke-width="${width}"${pattern}/>`;
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
  fs.writeFileSync(path.join(output, filename), `${parts.join('\n')}\n`);
}

function renderCapacity(summary, title, description, filename) {
  const direct = summary.direct_support;
  const maximum = 850000;
  const plot = {x: 280, y: 150, width: 880};
  const rows = [
    ['Planned gateway ceiling', 650000, '#657084'],
    ['Required direct support (1.2x)', 780000, '#b45309'],
    ['Observed successful RPS', direct.successful_rps, '#0f766e'],
    ['Offered direct traffic', direct.offered_rps, '#2563a6'],
  ];
  const parts = base(title, description);
  for (let tick = 0; tick <= 800000; tick += 100000) {
    const x = plot.x + tick / maximum * plot.width;
    parts.push(line(x, 132, x, 520, '#e4e8ef'));
    parts.push(text(x, 548, `${tick / 1000}k`, 12, 400, '#5d6678', 'middle'));
  }
  rows.forEach(([label, value, color], index) => {
    const y = plot.y + index * 88;
    const width = value / maximum * plot.width;
    parts.push(text(plot.x - 18, y + 31, label, 14, 700, '#172033', 'end'));
    parts.push(rect(plot.x, y, plot.width, 44, '#eef2f7', 6));
    parts.push(rect(plot.x, y, width.toFixed(1), 44, color, 6));
    parts.push(text(plot.x + 14, y + 29,
      `${(value / 1000).toFixed(value % 1000 === 0 ? 0 : 1)}k RPS`,
      15, 700, '#ffffff'));
  });
  parts.push(rect(64, 586, 1152, 72, '#e8f5f2', 8));
  parts.push(text(88, 617,
    `${(direct.successful_rps / 650000).toFixed(3)}x observed support headroom over the planned 650k gateway point`,
    17, 700, '#0f766e'));
  parts.push(text(88, 644,
    'Support/client qualification only. This chart does not report BonVoyage throughput or latency.',
    14, 400, '#35625d'));
  close(parts, filename);
}

function renderCpu(summary, title, description, filename) {
  const direct = summary.direct_support;
  const roles = [
    ['Load generator', direct.load_generator_cpu_percent],
    ['Upstream A', direct.upstream_cpu_percent[0]],
    ['Upstream B', direct.upstream_cpu_percent[1]],
  ];
  const plot = {x: 250, y: 166, width: 930};
  const parts = base(title, description);
  for (let tick = 0; tick <= 100; tick += 10) {
    const x = plot.x + tick / 100 * plot.width;
    parts.push(line(x, 140, x, 490, tick === 80 ? '#b45309' : '#e4e8ef',
      tick === 80 ? 3 : 1, tick === 80 ? '8 6' : ''));
    parts.push(text(x, 520, `${tick}%`, 12, tick === 80 ? 700 : 400,
      tick === 80 ? '#8a3c05' : '#5d6678', 'middle'));
  }
  parts.push(text(plot.x + 0.8 * plot.width, 126, '80% saturation guard', 13, 700,
    '#8a3c05', 'middle'));
  roles.forEach(([label, value], index) => {
    const y = plot.y + index * 104;
    parts.push(text(plot.x - 20, y + 32, label, 16, 700, '#172033', 'end'));
    parts.push(rect(plot.x, y, plot.width, 48, '#eef2f7', 6));
    parts.push(rect(plot.x, y, (value / 100 * plot.width).toFixed(1), 48,
      '#0f766e', 6));
    parts.push(text(plot.x + 14, y + 32, `${value.toFixed(2)}%`, 16, 700,
      '#ffffff'));
  });
  parts.push(rect(64, 574, 1152, 84, '#f7f9fc', 8));
  parts.push(text(88, 608,
    `${(direct.measurement_http_200 / 1000000).toFixed(2)} million HTTP 200 responses | ` +
      `zero errors | ${fixedWithGrouping(direct.successful_rps)} conservative successful RPS`,
    17, 700, '#172033'));
  parts.push(text(88, 638,
    'Shared-VM engineering evidence; physical NIC, NUMA and Dedicated Host qualification remain separate.',
    14, 400, '#5d6678'));
  close(parts, filename);
}

function renderIrqPlacement(summary, filename) {
  const requested = summary.static_ena.requested;
  const observed = summary.static_ena.observed;
  const rows = Object.keys(requested).sort((a, b) => Number(a) - Number(b));
  const labels = ['Management', ...Array.from({length: 8}, (_, index) => `Queue ${index}`)];
  const plot = {x: 248, y: 158, width: 900, row: 48};
  const cpuX = (cpu) => plot.x + Number(cpu) / 31 * plot.width;
  const parts = base('AWS Nitro rejected direct static ENA placement',
    'Requested CPUs 0-7 versus effective affinity after procfs writes | no gateway load collected');
  parts.push(rect(plot.x, 128, cpuX(7) - plot.x, 464, '#e8f5f2', 0));
  parts.push(rect(cpuX(8), 128, cpuX(15) - cpuX(8), 464, '#fff0ed', 0));
  for (const cpu of [0, 7, 8, 15, 16, 23, 31]) {
    const x = cpuX(cpu);
    parts.push(line(x, 128, x, 592, cpu === 8 || cpu === 16 ? '#b45309' : '#d9dee8',
      cpu === 8 || cpu === 16 ? 2 : 1, cpu === 8 || cpu === 16 ? '7 5' : ''));
    parts.push(text(x, 620, `CPU ${cpu}`, 12, 600, '#5d6678', 'middle'));
  }
  parts.push(text((plot.x + cpuX(7)) / 2, 118, 'Reserved IRQ CPUs', 13, 700,
    '#0f766e', 'middle'));
  parts.push(text((cpuX(8) + cpuX(15)) / 2, 118, 'Gateway CPUs 8-15', 13, 700,
    '#a33f32', 'middle'));
  rows.forEach((irq, index) => {
    const y = plot.y + index * plot.row;
    const requestedCpu = requested[irq];
    const observedCpu = observed[irq];
    parts.push(text(plot.x - 22, y + 6, `IRQ ${irq}  ${labels[index]}`, 13, 700,
      '#172033', 'end'));
    parts.push(line(cpuX(requestedCpu), y, cpuX(observedCpu), y, '#aab2c0', 2));
    parts.push(rect(cpuX(requestedCpu) - 6, y - 6, 12, 12, '#0f766e', 2));
    parts.push(rect(cpuX(observedCpu) - 6, y - 6, 12, 12, '#d45d4c', 2));
  });
  parts.push(rect(64, 650, 14, 14, '#0f766e', 2));
  parts.push(text(88, 662, 'Requested', 13, 600));
  parts.push(rect(190, 650, 14, 14, '#d45d4c', 2));
  parts.push(text(214, 662, 'Effective', 13, 600));
  parts.push(text(1180, 662,
    'Activation rejected; package baseline restored', 14, 700, '#a33f32', 'end'));
  close(parts, filename);
}

function renderNitroDisjoint(summary, filename) {
  const prior = summary.prior_overlapping_irq_attempt;
  const accepted = summary.accepted;
  const parts = base('IRQ-disjoint placement stabilized the first PERF-01 point',
    'AWS shared VM | HTTP/1.1 | 8 cores | 280k offered RPS | one accepted repetition');
  const columns = [
    {x: 280, title: 'Overlapping IRQ attempt', color: '#d45d4c'},
    {x: 730, title: 'Disjoint accepted attempt', color: '#0f766e'},
  ];
  columns.forEach((column) => {
    parts.push(rect(column.x, 132, 360, 390, '#f7f9fc', 8, '#d9dee8'));
    parts.push(text(column.x + 180, 171, column.title, 18, 700, '#172033', 'middle'));
  });
  const rows = [
    ['Successful RPS', fixedWithGrouping(prior.successful_rps),
      fixedWithGrouping(accepted.successful_rps)],
    ['p99.9 latency', `${prior.p999_ms.toFixed(1)} ms`,
      `${accepted.p999_ms.toFixed(1)} ms`],
    ['Request imbalance', `${(prior.request_imbalance_ratio * 100).toFixed(2)}%`,
      `${(accepted.request_imbalance_ratio * 100).toFixed(2)}%`],
  ];
  rows.forEach(([label, left, right], index) => {
    const y = 230 + index * 96;
    parts.push(text(220, y, label, 15, 700, '#5d6678', 'end'));
    parts.push(text(columns[0].x + 180, y, left, 26, 700, columns[0].color, 'middle'));
    parts.push(text(columns[1].x + 180, y, right, 26, 700, columns[1].color, 'middle'));
  });
  parts.push(rect(64, 566, 1152, 88, '#e8f5f2', 8));
  parts.push(text(88, 602,
    `${summary.comparison.p999_reduction_percent.toFixed(2)}% lower p99.9 at effectively unchanged throughput`,
    20, 700, '#0f766e'));
  parts.push(text(88, 632,
    'Placement is a measured variable, not a universal Nitro guarantee. Repetitions 2-5 remain required.',
    14, 400, '#35625d'));
  close(parts, filename);
}

fs.mkdirSync(output, {recursive: true});
renderCapacity(preflightSummary,
  'Direct-support capacity before PERF-01 gateway measurement',
  'Clean source | 32 one-core client lanes | two upstream hosts | gateway bypassed',
  'phase5-preflight-support-capacity.svg');
renderCpu(preflightSummary,
  'Support roles remained outside saturation',
  'Whole-host CPU during the accepted 90-second direct-support interval',
  'phase5-preflight-support-cpu.svg');
renderCapacity(schema7Summary,
  'Schema-7 support capacity clears the frozen plan gate',
  'Clean harness 30ac9df7 | 32 one-core client lanes | gateway bypassed',
  'phase5-schema7-support-capacity.svg');
renderCpu(schema7Summary,
  'Schema-7 support roles remain below the 80% guard',
  'Whole-host CPU during the accepted clean 90-second support measurement',
  'phase5-schema7-support-cpu.svg');
renderIrqPlacement(staticEnaSummary, 'phase5-static-ena-nitro-preflight.svg');
renderNitroDisjoint(nitroDisjointSummary, 'phase5-p5b01-nitro-disjoint.svg');
