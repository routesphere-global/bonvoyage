import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {BoundedBenchmarkRunner, Rejected} from './run-oss-bounded-benchmark.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const contractPath = path.join(root, 'packaging', 'release', 'benchmark',
  'oss-bounded-benchmark-contract.json');
const contract = JSON.parse(fs.readFileSync(contractPath, 'utf8'));
const commit = 'a'.repeat(40);
const gatewayID = '1'.repeat(64);
const upstreamID = '2'.repeat(64);
const gatewayImage = `sha256:${'3'.repeat(64)}`;
const upstreamImage = `sha256:${'4'.repeat(64)}`;
const loadImage = `sha256:${'5'.repeat(64)}`;
const network = 'bonvoyage-local_default';

function result(status = 0, stdout = '', stderr = '') {
  return {status, stdout, stderr, signal: null, timedOut: false};
}

function roleDocument(role, options = {}) {
  const gateway = role === 'bonvoyage';
  return {
    Id: gateway ? gatewayID : upstreamID,
    Image: gateway ? gatewayImage : upstreamImage,
    Name: `/bonvoyage-local-${role}-1`,
    RestartCount: options.restartCount || 0,
    Config: {Labels: {
      'com.docker.compose.project': 'bonvoyage-local',
      'com.docker.compose.service': role,
    }},
    State: {Status: 'running', Running: true,
      Health: gateway ? undefined : {Status: 'healthy'}},
    NetworkSettings: {Networks: {[network]: {}}},
  };
}

function loadReport(repetition, warmup = false, options = {}) {
  const accepted = warmup ? 500 : 1000 + (repetition * 100);
  return {
    summary: {successRate: 1, total: warmup ? 5 : 10, slowest: 0.005,
      fastest: 0.0005, average: 0.0015, requestsPerSec: accepted / 10},
    latencyPercentiles: {p50: 0.001, p95: 0.002, p99: 0.003,
      'p99.9': 0.004},
    statusCodeDistribution: options.failed ? {'200': accepted - 1, '503': 1} :
      {'200': accepted},
    errorDistribution: {},
  };
}

function metrics(base, accepted = 0) {
  const values = {
    bonvoyage_bonvoyage_gateway_requests_total: base + accepted,
    bonvoyage_bonvoyage_gateway_responses_2xx_total: base + accepted,
    bonvoyage_bonvoyage_gateway_upstream_endpoint_selections_total: base + accepted,
  };
  for (const metric of contract.acceptance.zero_counters) values[metric] = 0;
  return `${Object.entries(values).map(([name, value]) =>
    `${name}{shard="0"} ${value}`).join('\n')}\n`;
}

function responseProbe(valid = true) {
  return Buffer.concat([
    Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 256\r\nContent-Type: application/octet-stream\r\n\r\n'),
    Buffer.from((valid ? 'x' : 'y').repeat(256)),
  ]);
}

class FakeExecutor {
  constructor(journalPath, options = {}) {
    this.journalPath = journalPath;
    this.options = options;
    this.calls = [];
    this.loads = new Map();
    this.statusQueries = 0;
    this.removed = [];
  }

  interrupt() {}

  record(program, args, response) {
    fs.appendFileSync(this.journalPath, `${JSON.stringify({
      program, arguments: args, status: response.status,
    })}\n`);
    return response;
  }

  async run(program, args) {
    this.calls.push({program, args: [...args]});
    const name = path.basename(program);
    let response;
    if (name === 'git' && args[0] === 'rev-parse') {
      response = result(0, `${commit}\n`);
    } else if (name === 'git' && args[0] === 'status') {
      this.statusQueries += 1;
      const dirty = this.options.dirtySource ||
        (this.options.dirtyAfterRun && this.statusQueries >= 3);
      response = result(0, dirty ? ' M changed\n' : '');
    } else if (name === 'docker') {
      response = this.docker(args);
    } else {
      throw new Error(`unhandled fake command: ${program} ${args.join(' ')}`);
    }
    return this.record(program, args, response);
  }

  docker(args) {
    if (args[0] === 'info') {
      return result(0, `${JSON.stringify({OSType: 'linux',
        Architecture: this.options.dockerArchitecture || 'amd64',
        ServerVersion: '29.0.0', NCPU: 8, MemTotal: 17179869184,
        OperatingSystem: 'Docker Engine', KernelVersion: '6.8.0'})}\n`);
    }
    if (args[0] === 'compose') {
      const service = args.at(-1);
      if (this.options.ambiguousRole && service === 'bonvoyage') {
        return result(0, `${gatewayID}\n${'9'.repeat(64)}\n`);
      }
      return result(0, `${service === 'bonvoyage' ? gatewayID : upstreamID}\n`);
    }
    if (args[0] === 'image' && args[1] === 'inspect') {
      return result(0, `${JSON.stringify([{Id: loadImage}])}\n`);
    }
    if (args[0] === 'pull') return result(0, 'pulled\n');
    if (args[0] === 'run') {
      const containerName = args[args.indexOf('--name') + 1];
      const identity = crypto.createHash('sha256').update(containerName).digest('hex');
      const warmup = containerName.endsWith('-warmup');
      this.loads.set(containerName, {identity, warmup,
        remaining: warmup ? 2 : 7, removed: false});
      return result(0, `${identity}\n`);
    }
    if (args[0] === 'inspect') return this.inspect(args[1]);
    if (args[0] === 'logs') {
      const load = this.loads.get(args[1]);
      const match = args[1].match(/-r([1-3])-/);
      return result(0, `${JSON.stringify(loadReport(Number(match[1]), load.warmup,
        {failed: this.options.failedMeasurement && !load.warmup}))}\n`);
    }
    if (args[0] === 'stats') return this.stats(args);
    if (args[0] === 'rm') {
      const containerName = args.at(-1);
      const load = this.loads.get(containerName);
      if (load) load.removed = true;
      this.removed.push(containerName);
      return result(0, `${containerName}\n`);
    }
    throw new Error(`unhandled fake docker command: ${args.join(' ')}`);
  }

  inspect(reference) {
    if (reference === gatewayID) {
      return result(0, `${JSON.stringify([roleDocument('bonvoyage', {
        restartCount: this.options.gatewayRestart ? 1 : 0,
      })])}\n`);
    }
    if (reference === upstreamID) {
      return result(0, `${JSON.stringify([roleDocument('upstream')])}\n`);
    }
    const load = this.loads.get(reference);
    if (!load) {
      if (this.options.collision && reference.includes('bonvoyage-oss-benchmark')) {
        return result(0, `${JSON.stringify([{
          Id: '8'.repeat(64), Image: loadImage, Name: `/${reference}`,
          Config: {Labels: {'owner': 'someone-else'}},
          State: {Status: 'running', Running: true, ExitCode: 0},
        }])}\n`);
      }
      return result(1, '', 'not found\n');
    }
    if (load.removed) return result(1, '', 'not found\n');
    const running = load.remaining > 0;
    if (load.remaining > 0) load.remaining -= 1;
    const failed = this.options.loadExitFailure && !load.warmup;
    return result(0, `${JSON.stringify([{
      Id: load.identity,
      Image: loadImage,
      Name: `/${reference}`,
      Config: {Labels: {'io.routesphere.bonvoyage.benchmark-run': 'testrun'}},
      State: {Status: running ? 'running' : 'exited', Running: running,
        ExitCode: running ? 0 : failed ? 1 : 0},
    }])}\n`);
  }

  stats(args) {
    const identity = args.at(-1);
    const load = [...this.loads.values()].find(value => value.identity === identity);
    assert.ok(load);
    const entries = [
      {Name: 'bonvoyage-local-bonvoyage-1', CPUPerc: '22.50%',
        MemUsage: '40MiB / 256MiB'},
      {Name: 'bonvoyage-local-upstream-1', CPUPerc: '11.25%',
        MemUsage: '20MiB / 256MiB'},
    ];
    if (!this.options.incompleteStats) {
      const loadName = [...this.loads.entries()].find(([, value]) => value === load)[0];
      entries.push({Name: loadName, CPUPerc: '15.00%',
        MemUsage: '10MiB / 256MiB'});
    }
    return result(0, `${entries.map(value => JSON.stringify(value)).join('\n')}\n`);
  }
}

function setup(t, options = {}, dependencyOverrides = {}) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-benchmark-run-'));
  t.after(() => fs.rmSync(temporary, {recursive: true, force: true}));
  const evidencePath = path.join(temporary, 'evidence');
  const journal = path.join(evidencePath, 'raw', 'commands.jsonl');
  const executor = new FakeExecutor(journal, options);
  const bases = [100, 2000, 4000];
  const accepted = [1100, 1200, 1300];
  const metricSequence = bases.flatMap((base, index) =>
    [metrics(base), metrics(base, accepted[index])]);
  let metricIndex = 0;
  const runner = new BoundedBenchmarkRunner({contractPath, evidencePath}, {
    executor,
    runId: 'testrun',
    sleep: async () => {},
    probe: async () => responseProbe(!options.badProbe),
    fetchText: async () => metricSequence[metricIndex++],
    ...dependencyOverrides,
  });
  return {runner, executor, evidencePath};
}

test('contract fixes a digest-bound, local-only benchmark reproduction', () => {
  assert.match(contract.load_generator.image, /@sha256:[0-9a-f]{64}$/);
  assert.equal(contract.load_generator.wait_ongoing_requests_after_deadline, true);
  assert.equal(contract.runner.compose_project, 'bonvoyage-local');
  assert.equal(contract.qualifications.benchmark_reproduction_qualified, true);
  assert.equal(contract.qualifications.release_admitted, false);
  assert.equal(contract.claim_boundary.publication_qualified, false);
});

test('full runner emits verifier-accepted evidence and removes only owned loads',
  async t => {
    const {runner, executor, evidencePath} = setup(t);
    const result = await runner.run();
    assert.equal(result.verification.status, 'accepted');
    assert.equal(result.verification.repetitions, 3);
    assert.equal(result.summary.status, 'candidate');
    assert.equal(runner.ownedContainers.size, 0);
    assert.equal(executor.removed.length, 6);
    assert.ok(executor.removed.every(value =>
      value.startsWith('bonvoyage-oss-benchmark-testrun-')));
    assert.equal(fs.existsSync(path.join(evidencePath, 'checksums.sha256')), true);
    assert.equal(fs.existsSync(path.join(evidencePath, 'failure.json')), false);
  });

test('aarch64 Docker identity is normalized to arm64 evidence', async t => {
  const {runner, evidencePath} = setup(t, {dockerArchitecture: 'aarch64'});
  const result = await runner.run();
  assert.equal(result.verification.status, 'accepted');
  const environment = JSON.parse(fs.readFileSync(path.join(evidencePath,
    contract.evidence.environment), 'utf8'));
  assert.equal(environment.docker.server_architecture, 'arm64');
});

test('dirty source is rejected before Docker is observed', async t => {
  const {runner, executor, evidencePath} = setup(t, {dirtySource: true});
  await assert.rejects(runner.run(), /clean source/);
  assert.equal(executor.calls.some(call => path.basename(call.program) === 'docker'),
    false);
  assert.equal(fs.existsSync(path.join(evidencePath, 'failure.json')), true);
});

test('ambiguous Compose role discovery blocks every load container', async t => {
  const {runner, executor} = setup(t, {ambiguousRole: true});
  await assert.rejects(runner.run(), /absent or ambiguous/);
  assert.equal(executor.calls.some(call => call.args[0] === 'run'), false);
});

test('a restarted gateway is rejected during preflight', async t => {
  const {runner, executor} = setup(t, {gatewayRestart: true});
  await assert.rejects(runner.run(), /not running without restarts/);
  assert.equal(executor.calls.some(call => call.args[0] === 'run'), false);
});

test('a colliding runner name is never removed', async t => {
  const {runner, executor} = setup(t, {collision: true});
  await assert.rejects(runner.run(), /runner container already exists/);
  assert.deepEqual(executor.removed, []);
});

test('wrong response bytes block load generation', async t => {
  const {runner, executor} = setup(t, {badProbe: true});
  await assert.rejects(runner.run(), /body digest differs/);
  assert.equal(executor.calls.some(call => call.args[0] === 'run'), false);
});

test('a failed load generator is removed and the evidence remains unsealed',
  async t => {
    const {runner, executor, evidencePath} = setup(t, {loadExitFailure: true});
    await assert.rejects(runner.run(), /did not exit successfully/);
    assert.ok(executor.removed.length >= 2);
    assert.equal(executor.removed.includes('bonvoyage-local-bonvoyage-1'), false);
    assert.equal(fs.existsSync(path.join(evidencePath, 'checksums.sha256')), false);
    assert.equal(fs.existsSync(path.join(evidencePath, 'failure.json')), true);
  });

test('incomplete resource sampling is a hard rejection', async t => {
  const {runner, evidencePath} = setup(t, {incompleteStats: true});
  await assert.rejects(runner.run(), /too few resource samples/);
  assert.equal(fs.existsSync(path.join(evidencePath, 'checksums.sha256')), false);
});

test('source drift after measurement rejects an otherwise valid run', async t => {
  const {runner, evidencePath} = setup(t, {dirtyAfterRun: true});
  await assert.rejects(runner.run(), /source became dirty/);
  assert.equal(fs.existsSync(path.join(evidencePath, 'checksums.sha256')), false);
});

test('an interrupt during measurement removes the active owned container', async t => {
  let runner;
  const state = setup(t, {}, {sleep: async () => {
    if ([...runner.ownedContainers].some(value => value.endsWith('-measurement'))) {
      runner.interrupt('SIGINT');
    }
  }});
  runner = state.runner;
  await assert.rejects(runner.run(), /interrupted by SIGINT/);
  assert.equal(runner.ownedContainers.size, 0);
  assert.ok(state.executor.removed.every(value =>
    value.startsWith('bonvoyage-oss-benchmark-testrun-')));
});

test('evidence inside the source worktree is refused before creation', () => {
  const evidencePath = path.join(root, 'temporary-benchmark-evidence');
  assert.throws(() => new BoundedBenchmarkRunner({contractPath, evidencePath}),
    error => error instanceof Rejected && /outside the source worktree/.test(
      error.message));
  assert.equal(fs.existsSync(evidencePath), false);
});

test('a symlinked evidence parent cannot disguise the source worktree', t => {
  const sourceParent = fs.mkdtempSync(path.join(root,
    '.temporary-benchmark-evidence-parent-'));
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(),
    'bonvoyage-benchmark-symlink-'));
  const linkedParent = path.join(temporary, 'linked-parent');
  t.after(() => fs.rmSync(sourceParent, {recursive: true, force: true}));
  t.after(() => fs.rmSync(temporary, {recursive: true, force: true}));
  try {
    fs.symlinkSync(sourceParent, linkedParent, 'dir');
  } catch (error) {
    t.skip(`directory symlink unavailable: ${error.message}`);
    return;
  }
  const evidencePath = path.join(linkedParent, 'evidence');
  assert.throws(() => new BoundedBenchmarkRunner({contractPath, evidencePath}),
    error => error instanceof Rejected && /outside the source worktree/.test(
      error.message));
  assert.equal(fs.existsSync(path.join(sourceParent, 'evidence')), false);
});
