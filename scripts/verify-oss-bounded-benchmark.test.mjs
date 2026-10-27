import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {Rejected, verifyEvidence} from './verify-oss-bounded-benchmark.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const contractPath = path.join(root, 'packaging', 'release', 'benchmark',
  'oss-bounded-benchmark-contract.json');
const contract = JSON.parse(fs.readFileSync(contractPath, 'utf8'));
const commit = 'a'.repeat(40);
const gatewayID = '1'.repeat(64);
const upstreamID = '2'.repeat(64);
const loadGeneratorID = '3'.repeat(64);
const gatewayImage = `sha256:${'4'.repeat(64)}`;
const upstreamImage = `sha256:${'5'.repeat(64)}`;
const loadGeneratorImage = `sha256:${'6'.repeat(64)}`;

function stableJSON(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function write(directory, relative, value) {
  const file = path.join(directory, relative);
  fs.mkdirSync(path.dirname(file), {recursive: true});
  fs.writeFileSync(file, value);
}

function metricDocument(base, accepted) {
  const values = {
    bonvoyage_bonvoyage_gateway_requests_total: base + accepted,
    bonvoyage_bonvoyage_gateway_responses_2xx_total: base + accepted,
    bonvoyage_bonvoyage_gateway_upstream_endpoint_selections_total: base + accepted,
  };
  for (const metric of contract.acceptance.zero_counters) values[metric] = 0;
  return `${Object.entries(values).map(([name, value]) => `${name}{shard="0"} ${value}`)
    .join('\n')}\n`;
}

function resources() {
  const records = [];
  for (const role of contract.acceptance.required_resource_roles) {
    const containerID = role === 'gateway' ? gatewayID :
      role === 'upstream' ? upstreamID : loadGeneratorID;
    for (let index = 0; index < 3; index += 1) {
      records.push({
        captured_at: `2026-10-20T00:00:0${index}Z`,
        role,
        container_id: containerID,
        cpu_percent: 10 + index,
        memory_bytes: 1024 + index,
      });
    }
  }
  return `${records.map(value => JSON.stringify(value)).join('\n')}\n`;
}

function derivedRepetition(repetition) {
  const accepted = 1000 + (repetition * 100);
  const duration = 10;
  return {
    repetition,
    accepted_http_responses: accepted,
    completed_http_responses: accepted,
    http_failures: 0,
    transport_failures: 0,
    deadline_end_cancellations: 32,
    measured_requests: accepted,
    duration_seconds: duration,
    successful_rps: accepted / duration,
    error_rate: 0,
    latency_ms: {p50: 1, p95: 2, p99: 3, p999: 4, max: 5},
    counters: {
      requests: accepted,
      responses_2xx: accepted,
      upstream_selections: accepted,
    },
    resources: {
      sample_counts: {'gateway': 3, 'load-generator': 3, 'upstream': 3},
      average_cpu_percent: {'gateway': 11, 'load-generator': 11, 'upstream': 11},
      peak_memory_bytes: {'gateway': 1026, 'load-generator': 1026, 'upstream': 1026},
    },
  };
}

function seal(directory) {
  const files = [];
  function walk(current = '') {
    for (const entry of fs.readdirSync(path.join(directory, current),
      {withFileTypes: true})) {
      const relative = current ? `${current}/${entry.name}` : entry.name;
      if (relative === 'checksums.sha256') continue;
      if (entry.isDirectory()) walk(relative);
      else files.push(relative);
    }
  }
  walk();
  files.sort();
  fs.writeFileSync(path.join(directory, 'checksums.sha256'),
    `${files.map(file => `${sha256(fs.readFileSync(path.join(directory, file)))}  ${file}`)
      .join('\n')}\n`);
}

function createEvidence(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(),
    'bonvoyage-bounded-benchmark-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const source = {commit, dirty: false};
  const environment = {
    schema_version: 1,
    evidence_class: contract.evidence_class,
    source,
    host: {os: 'linux', architecture: 'amd64'},
    docker: {server_version: '29.0.0', server_architecture: 'amd64',
      logical_cpus: 8, total_memory_bytes: 17179869184},
    topology: {single_host: true, shared_kernel: true,
      roles: ['gateway', 'load-generator', 'upstream']},
  };
  const roles = {
    schema_version: 1,
    gateway: {service: 'bonvoyage', container_id: gatewayID,
      image_id: gatewayImage},
    upstream: {service: 'upstream', container_id: upstreamID,
      image_id: upstreamImage},
    'load-generator': {image_reference: contract.load_generator.image,
      image_id: loadGeneratorImage},
  };
  write(directory, 'environment.json', stableJSON(environment));
  write(directory, 'roles.json', stableJSON(roles));
  write(directory, 'raw/commands.jsonl', [
    {program: 'git', arguments: ['rev-parse', 'HEAD'], status: 0},
    {program: 'docker', arguments: ['info'], status: 0},
  ].map(value => JSON.stringify(value)).join('\n') + '\n');
  write(directory, 'raw/response-probe.http', Buffer.concat([
    Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 256\r\nContent-Type: application/octet-stream\r\n\r\n'),
    Buffer.from('x'.repeat(256)),
  ]));

  const repetitions = [];
  for (let repetition = 1; repetition <= 3; repetition += 1) {
    const recorded = derivedRepetition(repetition);
    repetitions.push(recorded);
    const prefix = `raw/repetition-${String(repetition).padStart(2, '0')}`;
    const oha = {
      summary: {successRate: 1, total: 10, slowest: 0.005,
        fastest: 0.0005, average: 0.0015,
        requestsPerSec: recorded.successful_rps},
      latencyPercentiles: {p50: 0.001, p95: 0.002, p99: 0.003,
        'p99.9': 0.004},
      statusCodeDistribution: {'200': recorded.accepted_http_responses},
      errorDistribution: {'aborted due to deadline': 32},
    };
    write(directory, `${prefix}.oha.json`, stableJSON(oha));
    write(directory, `${prefix}.warmup.oha.json`, stableJSON({
      ...oha,
      summary: {...oha.summary, total: 5},
      statusCodeDistribution: {'200': 500},
      errorDistribution: {},
    }));
    write(directory, `${prefix}.metrics-before.prom`, metricDocument(10, 0));
    write(directory, `${prefix}.metrics-after.prom`,
      metricDocument(10, recorded.accepted_http_responses));
    write(directory, `${prefix}.resources.jsonl`, resources());
    write(directory, `${prefix}.runtime.json`, stableJSON({
      schema_version: 1,
      gateway: {container_id: gatewayID, image_id: gatewayImage,
        status_before: 'running', status_after: 'running',
        restart_count_before: 0, restart_count_after: 0},
      upstream: {container_id: upstreamID, image_id: upstreamImage,
        status_before: 'running', status_after: 'running',
        restart_count_before: 0, restart_count_after: 0},
      'load-generator': {container_id: loadGeneratorID,
        image_id: loadGeneratorImage, exit_code: 0},
    }));
  }
  const rates = repetitions.map(value => value.successful_rps);
  const summary = {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-bounded-benchmark-result',
    status: 'candidate',
    contract_sha256: sha256(fs.readFileSync(contractPath)),
    evidence_class: contract.evidence_class,
    source,
    environment_sha256: sha256(fs.readFileSync(path.join(directory,
      'environment.json'))),
    roles_sha256: sha256(fs.readFileSync(path.join(directory, 'roles.json'))),
    workload: contract.workload,
    repetitions,
    aggregate: {
      valid_repetitions: 3,
      minimum_successful_rps: Math.min(...rates),
      median_successful_rps: rates[1],
      maximum_successful_rps: Math.max(...rates),
      median_latency_ms: {p50: 1, p95: 2, p99: 3, p999: 4, max: 5},
    },
    claim_boundary: contract.claim_boundary,
    qualifications: contract.qualifications,
  };
  write(directory, 'summary.json', stableJSON(summary));
  seal(directory);
  return directory;
}

function mutateJSON(file, mutate) {
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  mutate(value);
  fs.writeFileSync(file, stableJSON(value));
}

function rejects(directory, pattern) {
  assert.throws(() => verifyEvidence(contractPath, directory),
    error => error instanceof Rejected && pattern.test(error.message),
  );
}

test('accepts complete checksum-bound bounded benchmark evidence', t => {
  const directory = createEvidence(t);
  const result = verifyEvidence(contractPath, directory);
  assert.equal(result.status, 'accepted');
  assert.equal(result.source_commit, commit);
  assert.equal(result.repetitions, 3);
  assert.equal(result.median_successful_rps, 120);
  assert.deepEqual(result.median_latency_ms,
    {p50: 1, p95: 2, p99: 3, p999: 4, max: 5});
});

test('rejects evidence bytes changed after checksum sealing', t => {
  const directory = createEvidence(t);
  fs.appendFileSync(path.join(directory, 'raw/repetition-01.oha.json'), ' ');
  rejects(directory, /checksum mismatch/);
});

test('rejects unbound extra evidence files', t => {
  const directory = createEvidence(t);
  write(directory, 'raw/unbound.txt', 'unexpected\n');
  rejects(directory, /checksum manifest inventory/);
});

test('rejects extra evidence even when it is added to the checksum manifest', t => {
  const directory = createEvidence(t);
  write(directory, 'raw/sealed-but-unexpected.txt', 'unexpected\n');
  seal(directory);
  rejects(directory, /contracted evidence inventory/);
});

test('rejects unrecognized summary fields', t => {
  const directory = createEvidence(t);
  mutateJSON(path.join(directory, 'summary.json'), value => {
    value.marketing_claim = 'publication ready';
  });
  seal(directory);
  rejects(directory, /summary field inventory/);
});

test('rejects a response probe whose payload differs from the contract', t => {
  const directory = createEvidence(t);
  const file = path.join(directory, 'raw/response-probe.http');
  const value = fs.readFileSync(file);
  value[value.length - 1] = 'y'.charCodeAt(0);
  fs.writeFileSync(file, value);
  seal(directory);
  rejects(directory, /response probe body digest/);
});

test('rejects a malformed command journal', t => {
  const directory = createEvidence(t);
  fs.writeFileSync(path.join(directory, 'raw/commands.jsonl'), '{bad json}\n');
  seal(directory);
  rejects(directory, /command journal line 1 is invalid JSON/);
});

test('rejects dirty source identity', t => {
  const directory = createEvidence(t);
  mutateJSON(path.join(directory, 'summary.json'), value => { value.source.dirty = true; });
  seal(directory);
  rejects(directory, /source cleanliness/);
});

test('rejects all-503 traffic instead of counting transport completion as success', t => {
  const directory = createEvidence(t);
  mutateJSON(path.join(directory, 'raw/repetition-01.oha.json'), value => {
    value.statusCodeDistribution = {'503': 1100};
  });
  seal(directory);
  rejects(directory, /no accepted measured requests/);
});

test('rejects deadline-end cancellations above concurrency', t => {
  const directory = createEvidence(t);
  mutateJSON(path.join(directory, 'raw/repetition-01.oha.json'), value => {
    value.errorDistribution['aborted due to deadline'] = 33;
  });
  seal(directory);
  rejects(directory, /exceed contracted concurrency/);
});

test('rejects warmup traffic with an HTTP failure', t => {
  const directory = createEvidence(t);
  mutateJSON(path.join(directory, 'raw/repetition-01.warmup.oha.json'), value => {
    value.statusCodeDistribution = {'200': 499, '503': 1};
  });
  seal(directory);
  rejects(directory, /warmup exceeds the error budget/);
});

test('rejects summary latency not derived from raw output', t => {
  const directory = createEvidence(t);
  mutateJSON(path.join(directory, 'summary.json'), value => {
    value.repetitions[0].latency_ms.p95 = 200;
  });
  seal(directory);
  rejects(directory, /latency p95 differs/);
});

test('rejects gateway counter drift', t => {
  const directory = createEvidence(t);
  const file = path.join(directory, 'raw/repetition-01.metrics-after.prom');
  fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace(
    /bonvoyage_bonvoyage_gateway_requests_total\{shard="0"\} 1110/,
    'bonvoyage_bonvoyage_gateway_requests_total{shard="0"} 1111'));
  seal(directory);
  rejects(directory, /request counter delta/);
});

test('rejects a gateway restart', t => {
  const directory = createEvidence(t);
  mutateJSON(path.join(directory, 'raw/repetition-01.runtime.json'), value => {
    value.gateway.restart_count_after = 1;
  });
  seal(directory);
  rejects(directory, /restart bound was exceeded/);
});

test('rejects insufficient support-role resource samples', t => {
  const directory = createEvidence(t);
  const file = path.join(directory, 'raw/repetition-01.resources.jsonl');
  const records = fs.readFileSync(file, 'utf8').trimEnd().split('\n')
    .map(line => JSON.parse(line)).filter(value => value.role !== 'upstream' ||
      value.captured_at.endsWith('00Z'));
  fs.writeFileSync(file, `${records.map(value => JSON.stringify(value)).join('\n')}\n`);
  seal(directory);
  rejects(directory, /upstream has too few resource samples/);
});

test('rejects resource samples not bound to the measured container', t => {
  const directory = createEvidence(t);
  const file = path.join(directory, 'raw/repetition-01.resources.jsonl');
  const records = fs.readFileSync(file, 'utf8').trimEnd().split('\n')
    .map(line => JSON.parse(line));
  records[0].container_id = '9'.repeat(64);
  fs.writeFileSync(file, `${records.map(value => JSON.stringify(value)).join('\n')}\n`);
  seal(directory);
  rejects(directory, /gateway resource identity/);
});

test('rejects any attempt to promote the local run into a publication claim', t => {
  const directory = createEvidence(t);
  mutateJSON(path.join(directory, 'summary.json'), value => {
    value.claim_boundary.publication_qualified = true;
  });
  seal(directory);
  rejects(directory, /claim boundary differs/);
});

test('rejects a measurement shorter than the contract', t => {
  const directory = createEvidence(t);
  mutateJSON(path.join(directory, 'raw/repetition-01.oha.json'), value => {
    value.summary.total = 9.9;
  });
  seal(directory);
  rejects(directory, /measurement duration is shorter than the contract/);
});
