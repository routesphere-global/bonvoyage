import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import yaml from 'js-yaml';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const verifier = path.join(root, 'scripts', 'verify-local-deployment.sh');

function writeExecutable(file, source) {
  fs.writeFileSync(file, source, {mode: 0o755});
}

function createFixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-local-verify-'));
  const bin = path.join(directory, 'bin');
  const state = path.join(directory, 'state.json');
  fs.mkdirSync(bin);
  fs.writeFileSync(state, JSON.stringify({fixed: 0, proxied: 0}));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));

  writeExecutable(path.join(bin, 'docker'), `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === 'compose' && args.includes('ps')) {
  const service = args.at(-1);
  const ids = {
    bonvoyage: 'gateway-id',
    upstream: 'upstream-id',
    'snapshot-compiler': 'compiler-id',
  };
  if (ids[service]) process.stdout.write(ids[service] + '\\n');
  process.exit(0);
}
if (args[0] === 'inspect' && args[1] === '--format') {
  const format = args[2];
  const id = args[3];
  if (format.includes('.RestartCount')) process.stdout.write('0\\n');
  else if (format.includes('.State.Health')) process.stdout.write('healthy\\n');
  else if (format.includes('.State.ExitCode')) process.stdout.write('0\\n');
  else if (format.includes('.State.Status')) {
    process.stdout.write(id === 'compiler-id' ? 'exited\\n' : 'running\\n');
  } else process.exit(2);
  process.exit(0);
}
process.exit(2);
`);

  writeExecutable(path.join(bin, 'curl'), `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
const url = args.at(-1);
const file = process.env.BONVOYAGE_FAKE_STATE;
const mode = process.env.BONVOYAGE_FAKE_MODE || '';
const state = JSON.parse(fs.readFileSync(file, 'utf8'));

if (url.endsWith('/metrics')) {
  const requests = state.fixed + state.proxied;
  let upstream = state.proxied;
  if (mode === 'bad-accounting' && state.proxied > 1) upstream -= 1;
  const runtimeFailure = mode === 'runtime-error' ? 1 : 0;
  process.stdout.write([
    'bonvoyage_bonvoyage_gateway_ready{shard="0"} 1',
    'bonvoyage_bonvoyage_gateway_configured_clusters{shard="0"} 1',
    'bonvoyage_bonvoyage_gateway_configured_endpoints{shard="0"} 1',
    'bonvoyage_bonvoyage_gateway_configured_listeners{shard="0"} 1',
    'bonvoyage_bonvoyage_gateway_configured_routes{shard="0"} 2',
    'bonvoyage_bonvoyage_gateway_requests_total{shard="0"} ' + requests,
    'bonvoyage_bonvoyage_gateway_responses_2xx_total{shard="0"} ' + requests,
    'bonvoyage_bonvoyage_gateway_upstream_endpoint_selections_total{shard="0"} ' + upstream,
    'bonvoyage_bonvoyage_gateway_responses_4xx_total{shard="0"} 0',
    'bonvoyage_bonvoyage_gateway_responses_5xx_total{shard="0"} 0',
    'bonvoyage_bonvoyage_gateway_route_misses_total{shard="0"} 0',
    'bonvoyage_bonvoyage_gateway_request_timeouts_total{shard="0"} 0',
    'bonvoyage_bonvoyage_gateway_overload_rejections_total{shard="0"} 0',
    'bonvoyage_bonvoyage_gateway_upstream_failures_total{shard="0"} 0',
    'bonvoyage_memory_malloc_failed{shard="0"} ' + runtimeFailure,
    'bonvoyage_reactor_abandoned_failed_futures{shard="0"} 0',
    'bonvoyage_stall_detector_reported{shard="0"} 0',
  ].join('\\n') + '\\n');
  process.exit(0);
}

if (url.endsWith('/bonvoyage/ready')) {
  state.fixed += 1;
  fs.writeFileSync(file, JSON.stringify(state));
  process.stdout.write('ready\\n');
  process.exit(0);
}
if (url.endsWith('/healthz')) {
  state.proxied += 1;
  fs.writeFileSync(file, JSON.stringify(state));
  process.stdout.write(mode === 'bad-proxy-body' ? 'unexpected\\n' : 'ok\\n');
  process.exit(0);
}
if (url.endsWith('/health/ready')) {
  process.stdout.write('{"status":"ok"}\\n');
  process.exit(0);
}
process.exit(22);
`);

  return {bin, state};
}

function runVerifier(t, overrides = {}) {
  const fixture = createFixture(t);
  const result = spawnSync('sh', [verifier], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${fixture.bin}:${process.env.PATH}`,
      TMPDIR: path.dirname(fixture.state),
      BONVOYAGE_FAKE_STATE: fixture.state,
      BONVOYAGE_VERIFY_REQUESTS_PER_ROUTE: '3',
      ...overrides,
    },
  });
  return {...fixture, result};
}

test('the local profile exposes only loopback host ports', () => {
  const compose = yaml.load(fs.readFileSync(
    path.join(root, 'deploy', 'compose', 'local.yml'), 'utf8'));
  assert.deepEqual(compose.services.bonvoyage.ports, [
    '127.0.0.1:8080:8080',
    '127.0.0.1:9090:9090',
    '127.0.0.1:9901:9901',
  ]);
});

test('the public verifier remains an executable POSIX-shell entry point', () => {
  const source = fs.readFileSync(verifier, 'utf8');
  assert.ok((fs.statSync(verifier).mode & 0o111) !== 0);
  assert.match(source, /^#!\/bin\/sh\nset -eu\n/);
  const overlayMakefile = path.join(root, 'tools', 'oss-export', 'public-root', 'Makefile');
  const publicMakefile = fs.readFileSync(
    fs.existsSync(overlayMakefile) ? overlayMakefile : path.join(root, 'Makefile'),
    'utf8');
  assert.match(publicMakefile,
    /^verify-local-deployment:\n\t@\.\/scripts\/verify-local-deployment\.sh$/m);
});

test('the verifier checks role state, traffic, accounting, and runtime health', t => {
  const {result, state} = runVerifier(t);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^status=pass$/m);
  assert.match(result.stdout, /^request_delta=6$/m);
  assert.match(result.stdout, /^upstream_selection_delta=3$/m);
  assert.match(result.stdout, /^container_restarts=0$/m);
  assert.deepEqual(JSON.parse(fs.readFileSync(state, 'utf8')), {
    fixed: 4,
    proxied: 4,
  });
});

test('the verifier rejects an invalid bounded request count', t => {
  const {result} = runVerifier(t, {
    BONVOYAGE_VERIFY_REQUESTS_PER_ROUTE: 'many',
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /must be a positive integer/);
});

test('the verifier rejects an unexpected proxied response body', t => {
  const {result} = runVerifier(t, {BONVOYAGE_FAKE_MODE: 'bad-proxy-body'});
  assert.equal(result.status, 1);
  assert.match(result.stderr, /proxied route body/);
});

test('the verifier rejects inconsistent upstream accounting', t => {
  const {result} = runVerifier(t, {BONVOYAGE_FAKE_MODE: 'bad-accounting'});
  assert.equal(result.status, 1);
  assert.match(result.stderr, /upstream selection counter delta/);
});

test('the verifier rejects a nonzero runtime failure counter', t => {
  const {result} = runVerifier(t, {BONVOYAGE_FAKE_MODE: 'runtime-error'});
  assert.equal(result.status, 1);
  assert.match(result.stderr, /bonvoyage_memory_malloc_failed/);
});
