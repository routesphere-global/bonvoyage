import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const helper = fileURLToPath(new URL('./test-fixture-secrets.sh', import.meta.url));
const label = 'com.bonvoyage.test-fixture-secrets';

// Every external action is intercepted; these tests never contact Docker.
const mock = String.raw`#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const tool = path.basename(process.argv[1]);
const args = process.argv.slice(2);
const state = JSON.parse(fs.readFileSync(process.env.MOCK_STATE));
const input = tool === 'docker' && ['run', 'exec'].includes(args[0])
  ? fs.readFileSync(0, 'utf8') : '';
state.calls.push({tool, args, input});
let status = 0, output = '';
const name = args.at(-1);
if (tool === 'date') output = String(state.now);
else if (tool === 'sleep') state.now += Number(args[0]);
else if (tool !== 'docker') status = 90;
else if (args[0] === 'volume') {
  if (args[1] === 'inspect') {
    if (!(name in state.volumes) || state.inspectFails) status = 1;
    else output = args.includes('--format') ? state.volumes[name] : '{}';
  } else if (args[1] === 'create') {
    status = state.createStatus || 0;
    if (!status) {
      state.volumes[name] = state.raceLabel ?? args[args.indexOf('--label') + 1].split('=').slice(1).join('=');
      output = name;
    }
  } else if (args[1] === 'rm') delete state.volumes[name];
  else status = 91;
} else if (args[0] === 'run') status = state.runStatus || 0;
else if (args[0] === 'inspect') {
  const next = state.gatewayStates.length > 1 ? state.gatewayStates.shift() : state.gatewayStates[0];
  status = next === 'error' ? 1 : 0;
  output = String(next);
} else if (args[0] === 'exec') {
  status = state.probeStatuses.length > 1 ? state.probeStatuses.shift() : state.probeStatuses[0];
  state.now += state.probeSeconds || 0;
} else if (args[0] === 'logs') {
  output = 'mock gateway logs';
  status = state.logsStatus || 0;
} else status = 92;
fs.writeFileSync(process.env.MOCK_STATE, JSON.stringify(state));
if (output) process.stdout.write(output + '\n');
process.exit(status);
`;

function fixture(t, overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bv-fixture-test-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const bin = path.join(dir, 'bin');
  const source = path.join(dir, 'source with spaces');
  fs.mkdirSync(bin);
  fs.mkdirSync(source);
  fs.writeFileSync(path.join(source, 'server-chain.pem'), 'certificate');
  fs.writeFileSync(path.join(source, 'server-key.pem'), 'private key', {mode: 0o600});
  fs.writeFileSync(path.join(source, 'ca-key.pem'), 'must not be copied', {mode: 0o600});
  for (const name of ['docker', 'date', 'sleep', 'sudo', 'chown', 'chmod']) {
    fs.writeFileSync(path.join(bin, name), mock, {mode: 0o700});
  }
  const stateFile = path.join(dir, 'state.json');
  fs.writeFileSync(stateFile, JSON.stringify({calls: [], volumes: {}, now: 1000,
    gatewayStates: [true], probeStatuses: [0], ...overrides}));
  const args = ['fixture-volume', source, 'existing-upstream:test', 'linux/amd64',
    'server-chain.pem', 'server-key.pem'];
  return {
    source, args,
    state: () => JSON.parse(fs.readFileSync(stateFile, 'utf8')),
    run: (script = 'bv_stage_fixture_secrets "$@"', argv = args) => spawnSync('sh',
      ['-eu', '-c', '. "$HELPER"\n' + script, 'fixture-test', ...argv], {
        encoding: 'utf8', timeout: 15000,
        env: {...process.env, HELPER: helper, MOCK_STATE: stateFile,
          PATH: `${bin}:${process.env.PATH}`},
      }),
  };
}

const dockerCalls = f => f.state().calls.filter(c => c.tool === 'docker');
const stages = f => dockerCalls(f).filter(c => c.args[0] === 'run');
const probes = f => dockerCalls(f).filter(c => c.args[0] === 'exec');
const assertOk = r => assert.equal(r.status, 0, r.stderr || String(r.error));

test('POSIX syntax; sourcing leaves caller options and traps intact', t => {
  assertOk(spawnSync('sh', ['-n', helper], {encoding: 'utf8'}));
  const f = fixture(t);
  assertOk(f.run('trap \'echo caller-trap\' EXIT\nbefore=$-\n. "$HELPER"\ntest "$before" = "$-"'));
  assert.deepEqual(f.state().calls, []);
});

test('explicit allowlist, confined staging argv, ownership check and caller cleanup', t => {
  const f = fixture(t);
  const before = fs.statSync(path.join(f.source, 'server-key.pem'));
  const result = f.run(`
trap 'status=$?; bv_remove_fixture_secrets "$1" "$2" || :; exit "$status"' EXIT
volume=caller directory=caller image=caller platform=caller
bv_stage_fixture_secrets "$@"
test "$volume:$directory:$image:$platform" = caller:caller:caller:caller
`);
  assertOk(result);
  const calls = dockerCalls(f);
  assert.deepEqual(calls.map(c => c.args.slice(0, 2)), [
    ['volume', 'inspect'], ['volume', 'create'], ['volume', 'inspect'],
    ['run', '--rm'], ['volume', 'inspect'], ['volume', 'rm'],
  ]);
  assert.match(calls[1].args[3], new RegExp(`^${label}=v1:[0-9]+:`));
  assert.deepEqual(stages(f)[0].args, [
    'run', '--rm', '--interactive', '--pull', 'never', '--platform', 'linux/amd64',
    '--network', 'none', '--read-only', '--user', '0:0', '--cap-drop', 'ALL',
    '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE', '--cap-add', 'FOWNER',
    '--security-opt', 'no-new-privileges:true',
    '--mount', `type=bind,src=${f.source},dst=/fixture-source,readonly`,
    '--mount', 'type=volume,src=fixture-volume,dst=/fixture-secrets,volume-nocopy',
    '--entrypoint', 'python', 'existing-upstream:test', '-', '/fixture-source',
    '/fixture-secrets', 'server-chain.pem', 'server-key.pem',
  ]);
  assert.match(stages(f)[0].input, /os\.fchown\(dst, 65532, 65532\)/);
  assert.deepEqual(f.state().volumes, {});
  assert.equal(fs.statSync(path.join(f.source, 'server-key.pem')).mode, before.mode);
  assert.equal(fs.statSync(path.join(f.source, 'server-key.pem')).uid, before.uid);
  assert.ok(f.state().calls.every(c => c.tool === 'docker'));
});

test('explicit refresh reuses the created volume without changing traps', t => {
  const f = fixture(t);
  assertOk(f.run('bv_stage_fixture_secrets "$@"\nbv_stage_fixture_secrets --refresh "$@"'));
  assert.equal(stages(f).length, 2);
  assert.equal(dockerCalls(f).filter(c => c.args[1] === 'create').length, 1);
  assert.deepEqual(stages(f)[0], stages(f)[1]);
  assert.ok('fixture-volume' in f.state().volumes, 'caller still owns volume cleanup');
});

for (const refresh of [false, true]) {
  test(`reject existing unrelated volume (refresh=${refresh}) without deleting it`, t => {
    const f = fixture(t, {volumes: {'fixture-volume': 'unrelated'}});
    assert.notEqual(f.run(undefined, [...(refresh ? ['--refresh'] : []), ...f.args]).status, 0);
    assert.equal(stages(f).length, 0);
    assert.equal(f.state().volumes['fixture-volume'], 'unrelated');
    assert.equal(dockerCalls(f).length, 1);
  });
}

test('refresh cannot create a volume, or reuse a different caller/source label', t => {
  const f = fixture(t);
  assert.notEqual(f.run(undefined, ['--refresh', ...f.args]).status, 0);
  assert.equal(stages(f).length, 0);
  assertOk(f.run());
  assert.notEqual(f.run(undefined, ['--refresh', ...f.args]).status, 0);
  assert.equal(stages(f).length, 1);
});

test('implicit refresh is rejected even in the creating shell', t => {
  const f = fixture(t);
  assertOk(f.run('bv_stage_fixture_secrets "$@"\nif bv_stage_fixture_secrets "$@"; then exit 99; fi'));
  assert.equal(stages(f).length, 1);
});

for (const overrides of [{createStatus: 7}, {raceLabel: 'unrelated'}, {inspectFails: true}]) {
  test(`creation/label failure is safe even when errexit is suppressed: ${JSON.stringify(overrides)}`, t => {
    const f = fixture(t, overrides);
    assertOk(f.run('if bv_stage_fixture_secrets "$@"; then exit 99; fi'));
    assert.equal(stages(f).length, 0);
    assert.ok(!dockerCalls(f).some(c => c.args[1] === 'rm'));
  });
}

test('failed copy propagates through set -e and invokes caller cleanup', t => {
  const f = fixture(t, {runStatus: 23});
  const result = f.run(`
trap 'status=$?; bv_remove_fixture_secrets "$1" "$2" || :; exit "$status"' EXIT
bv_stage_fixture_secrets "$@"
echo unreachable
`);
  assert.equal(result.status, 23);
  assert.doesNotMatch(result.stdout, /unreachable/);
  assert.deepEqual(f.state().volumes, {});
  assert.equal(dockerCalls(f).at(-1).args[1], 'rm');
});

test('failed copy returns failure in an if condition too', t => {
  const f = fixture(t, {runStatus: 23});
  assertOk(f.run('if bv_stage_fixture_secrets "$@"; then exit 99; fi'));
  assert.equal(stages(f).length, 1);
});

test('cleanup trap refuses to remove a colliding unrelated volume', t => {
  const f = fixture(t, {volumes: {'fixture-volume': 'unrelated'}});
  const result = f.run(`
trap 'status=$?; bv_remove_fixture_secrets "$1" "$2" || :; exit "$status"' EXIT
bv_stage_fixture_secrets "$@"
`);
  assert.equal(result.status, 1);
  assert.equal(f.state().volumes['fixture-volume'], 'unrelated');
  assert.match(result.stderr, /refusing to remove unowned/);
  assert.ok(!dockerCalls(f).some(c => c.args[1] === 'rm'));
});

test('cleanup rejects a different caller or source and a missing volume', t => {
  const f = fixture(t);
  assertOk(f.run(`
if bv_remove_fixture_secrets "$1" "$2"; then exit 99; fi
bv_stage_fixture_secrets "$@"
if bv_remove_fixture_secrets "$1" "$2/other"; then exit 99; fi
`));
  assert.notEqual(f.run('bv_remove_fixture_secrets "$1" "$2"').status, 0);
  assert.ok('fixture-volume' in f.state().volumes);
  assert.ok(!dockerCalls(f).some(c => c.args[1] === 'rm'));
});

for (const name of ['../server-key.pem', '/server-key.pem', '.', '..', '-key.pem',
  'bad,ro', 'bad name', 'bad\nname', 'missing.pem', '']) {
  test(`reject invalid/missing basename ${JSON.stringify(name)} before Docker`, t => {
    const f = fixture(t);
    assert.notEqual(f.run(undefined, [...f.args.slice(0, 4), name]).status, 0);
    assert.deepEqual(f.state().calls, []);
  });
}

test('reject duplicate, symlink, directory, missing arguments and bad mount paths', t => {
  const f = fixture(t);
  fs.symlinkSync(path.join(f.source, 'server-key.pem'), path.join(f.source, 'link.pem'));
  fs.mkdirSync(path.join(f.source, 'directory.pem'));
  for (const tail of [[], ['server-key.pem', 'server-key.pem'], ['link.pem'], ['directory.pem']]) {
    assert.notEqual(f.run(undefined, [...f.args.slice(0, 4), ...tail]).status, 0);
  }
  for (const directory of ['relative', '/missing-fixture-directory', `${f.source},readonly`, `${f.source}\n`]) {
    assert.notEqual(f.run(undefined, [f.args[0], directory, ...f.args.slice(2)]).status, 0);
  }
  fs.symlinkSync(f.source, `${f.source}-link`);
  assert.notEqual(f.run(undefined, [f.args[0], `${f.source}-link`, ...f.args.slice(2)]).status, 0);
  assert.deepEqual(f.state().calls, []);
});

const ready = 'bv_wait_gateway_ready "$@"';
const readinessArgs = ['gateway-test', 'probe-test', 'http://gateway-test:9901/health/ready?marker="quoted"'];

test('readiness retries then checks gateway before and after success; URL stays in argv', t => {
  const f = fixture(t, {probeStatuses: [1, 0]});
  assertOk(f.run(ready, readinessArgs));
  assert.deepEqual(dockerCalls(f).map(c => c.args[0]), ['inspect', 'exec', 'inspect', 'inspect', 'exec', 'inspect']);
  for (const probe of probes(f)) {
    assert.deepEqual(probe.args, ['exec', '--interactive', 'probe-test', 'python', '-', readinessArgs[2]]);
    assert.ok(!probe.input.includes(readinessArgs[2]));
    assert.match(probe.input, /signal\.alarm\(1\)/);
    assert.match(probe.input, /urlopen\(sys\.argv\[1\], timeout=1\)/);
  }
});

for (const [states, statuses, expected] of [
  [[false], [0], 0], [['error'], [0], 0], [[true, false], [0], 1], [[true, false], [1], 1],
]) {
  test(`gateway exit is prompt with states=${states} and probe=${statuses}`, t => {
    const f = fixture(t, {gatewayStates: states, probeStatuses: statuses});
    const result = f.run(ready, readinessArgs);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /not running/);
    assert.match(result.stderr, /mock gateway logs/);
    assert.equal(probes(f).length, expected);
    assert.ok(!f.state().calls.some(c => c.tool === 'sleep'));
  });
}

for (const probeSeconds of [0, 1]) {
  test(`readiness exhaustion is bounded with ${probeSeconds}s probes, including failed logs`, t => {
    const f = fixture(t, {probeStatuses: [1], probeSeconds, logsStatus: 4});
    const result = f.run(ready, readinessArgs);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /did not become ready within 30s/);
    assert.ok(probes(f).length <= 30);
    assert.ok(f.state().now <= 1030);
    assert.equal(dockerCalls(f).filter(c => c.args[0] === 'inspect').length, probes(f).length * 2);
    assert.equal(dockerCalls(f).at(-1).args[0], 'logs');
  });
}

test('custom-readiness guard reports inspect failure, including in an if condition', t => {
  const f = fixture(t, {gatewayStates: ['error']});
  assertOk(f.run('if bv_gateway_running gateway-test; then exit 99; fi'));
  assert.deepEqual(dockerCalls(f).map(c => c.args[0]), ['inspect', 'logs']);
});
