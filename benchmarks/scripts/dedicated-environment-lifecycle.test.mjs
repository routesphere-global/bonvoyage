import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  remoteStage,
  runCaptured,
  runRolePhase,
  writeRawManifest,
  verifyRawManifest,
} from './dedicated-environment.mjs';
import {REPOSITORY_ROOT} from './dedicated-preflight.mjs';

const require = createRequire(path.join(REPOSITORY_ROOT, 'package.json'));
const yaml = require('js-yaml');

function temporaryRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-collection-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  return root;
}

function commandRecord(base) {
  return JSON.parse(fs.readFileSync(`${base}.command.json`, 'utf8'));
}

test('each collection attempt has separate deterministic remote staging', () => {
  const topology = {source_commit: 'a'.repeat(40), campaign_id: 'phase1-phase3-dedicated-qualification-v1'};
  const role = {role: 'gateway-target', instance_id: 'i-11111111111111111'};
  const first = remoteStage(topology, role, '1'.repeat(32));
  const retry = remoteStage(topology, role, '2'.repeat(32));
  assert.notEqual(first, retry);
  assert.equal(first, remoteStage(topology, role, '1'.repeat(32)));
  assert.match(first, /^\/var\/tmp\/[A-Za-z0-9-]+$/u);
  assert.ok(path.basename(first).length < 255);
  assert.notEqual(first, remoteStage(topology, {...role, role: 'load-generator'}, '1'.repeat(32)));
  for (const invalid of ['', '../escape', 'a;id', '0'.repeat(31), 'A'.repeat(32), undefined]) {
    assert.throws(() => remoteStage(topology, role, invalid), /attempt/i);
  }
});

test('transport success and nonzero exit retain private immutable evidence', async (t) => {
  const root = temporaryRoot(t);
  for (const code of [0, 7]) {
    const base = path.join(root, `exit-${code}`);
    const call = runCaptured(process.execPath, ['-e',
      `process.stdout.write('out'); process.stderr.write('err'); process.exitCode=${code};`], base);
    if (code) await assert.rejects(call, /failed/);
    else assert.equal(await call, 'out');
    assert.equal(commandRecord(base).exit_code, code);
    assert.equal(fs.readFileSync(`${base}.stdout`, 'utf8'), 'out');
    assert.equal(fs.readFileSync(`${base}.stderr`, 'utf8'), 'err');
    for (const suffix of ['stdout', 'stderr', 'command.json']) {
      assert.equal(fs.statSync(`${base}.${suffix}`).mode & 0o777, 0o600);
    }
  }
});

test('timeout retains partial output and termination metadata', async (t) => {
  const base = path.join(temporaryRoot(t), 'timeout');
  await assert.rejects(runCaptured(process.execPath, ['-e',
    "process.stdout.write('started'); process.stderr.write('waiting'); setInterval(()=>{},100);"],
  base, {timeout: 1000}), /timed out/);
  const record = commandRecord(base);
  assert.equal(record.exit_code, null);
  assert.equal(record.failure_kind, 'timeout');
  assert.equal(record.timeout_ms, 1000);
  assert.equal(record.signal, 'SIGKILL');
  assert.equal(fs.readFileSync(`${base}.stdout`, 'utf8'), 'started');
  assert.equal(fs.readFileSync(`${base}.stderr`, 'utf8'), 'waiting');
});

test('missing executable retains a spawn failure record', async (t) => {
  const root = temporaryRoot(t);
  const base = path.join(root, 'missing');
  await assert.rejects(runCaptured(path.join(root, 'no-such-executable'), [], base));
  const record = commandRecord(base);
  assert.equal(record.exit_code, null);
  assert.equal(record.failure_kind, 'spawn-error');
  assert.equal(record.error_code, 'ENOENT');
  assert.equal(fs.readFileSync(`${base}.stdout`, 'utf8'), '');
});

test('output limit retains bounded diagnostics without becoming a pass', async (t) => {
  const base = path.join(temporaryRoot(t), 'overflow');
  await assert.rejects(runCaptured(process.execPath, ['-e',
    "process.stdout.write('x'.repeat(8192));"], base, {maxBuffer: 1024}), /output-limit/);
  const record = commandRecord(base);
  assert.equal(record.failure_kind, 'output-limit');
  assert.equal(record.exit_code, null);
  assert.ok(fs.statSync(`${base}.stdout`).size <= 1024);
});

test('existing evidence is rejected before executing another command', async (t) => {
  const root = temporaryRoot(t);
  const base = path.join(root, 'once');
  await runCaptured(process.execPath, ['-e', "process.stdout.write('original');"], base);
  const marker = path.join(root, 'must-not-exist');
  await assert.rejects(runCaptured(process.execPath, ['-e',
    `require('node:fs').writeFileSync(${JSON.stringify(marker)},'executed');`], base));
  assert.equal(fs.existsSync(marker), false);
  assert.equal(fs.readFileSync(`${base}.stdout`, 'utf8'), 'original');
});

test('role failure waits for active evidence writers before returning', async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let writerFinished = false;
  let returned = false;
  const result = runRolePhase(['failed', 'writing'], async (role) => {
    if (role === 'failed') throw new Error('failed role');
    await gate;
    writerFinished = true;
    return role;
  }).then(() => { returned = true; return null; }, (error) => { returned = true; return error; });
  try {
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(returned, false, 'must not return while a role can still write');
  } finally {
    release();
    await result;
  }
  assert.equal(writerFinished, true);
  const error = await result;
  assert.ok(error instanceof AggregateError);
  assert.match(error.message, /failed role/);
});

test('successful role phase preserves topology order', async () => {
  const result = await runRolePhase(['load', 'gateway', 'upstream'], async (role) => role);
  assert.deepEqual(result, ['load', 'gateway', 'upstream']);
});

test('synchronous role failure still settles all started operations', async () => {
  const visited = [];
  await assert.rejects(runRolePhase(['one', 'two', 'three'], (role) => {
    visited.push(role);
    if (role !== 'two') throw new Error(role);
    return role;
  }), (error) => error instanceof AggregateError && error.errors.length === 2);
  assert.deepEqual(visited, ['one', 'two', 'three']);
});

test('timeout bounds a local child that ignores SIGTERM', async (t) => {
  const base = path.join(temporaryRoot(t), 'ignores-term');
  const start = Date.now();
  await assert.rejects(runCaptured(process.execPath, ['-e',
    "process.on('SIGTERM',()=>{}); setTimeout(()=>process.exit(0),4000);"],
  base, {timeout: 1000}), /timed out/);
  assert.ok(Date.now() - start < 3500);
  assert.equal(commandRecord(base).signal, 'SIGKILL');
});

test('signal termination is retained separately from timeout', async (t) => {
  const base = path.join(temporaryRoot(t), 'signal');
  await assert.rejects(runCaptured(process.execPath, ['-e',
    "process.kill(process.pid,'SIGTERM');"], base), /signal/);
  assert.equal(commandRecord(base).failure_kind, 'signal');
  assert.equal(commandRecord(base).signal, 'SIGTERM');
});

test('invalid transport budgets cannot start a command', async (t) => {
  const root = temporaryRoot(t);
  for (const options of [{timeout: 0}, {timeout: Infinity}, {maxBuffer: 0}, {maxBuffer: 67108865}]) {
    await assert.rejects(runCaptured(process.execPath, ['-e', 'process.exit(0)'],
      path.join(root, 'invalid'), options), /bounded/);
  }
  assert.deepEqual(fs.readdirSync(root), []);
});

test('concurrent use of one output base executes only one attempt', async (t) => {
  const root = temporaryRoot(t);
  const marker = path.join(root, 'executions');
  const argv = ['-e', `require('node:fs').appendFileSync(${JSON.stringify(marker)},'one');`];
  const results = await Promise.allSettled([
    runCaptured(process.execPath, argv, path.join(root, 'same')),
    runCaptured(process.execPath, argv, path.join(root, 'same')),
  ]);
  assert.deepEqual(results.map(({status}) => status), ['fulfilled', 'rejected']);
  assert.equal(fs.readFileSync(marker, 'utf8'), 'one');
});

test('cancelled transport cannot start a queued command', async (t) => {
  const root = temporaryRoot(t);
  const controller = new AbortController();
  controller.abort(new Error('collection cancelled'));
  await assert.rejects(runCaptured(process.execPath, ['-e', 'process.exit(0)'],
    path.join(root, 'queued'), {signal: controller.signal}), /cancelled/);
  assert.deepEqual(fs.readdirSync(root), []);
});

test('cancellation stops an active transport and preserves its diagnostics', async (t) => {
  const base = path.join(temporaryRoot(t), 'active');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('operator cancellation')), 300);
  try {
    await assert.rejects(runCaptured(process.execPath, ['-e',
      "process.stdout.write('active');setTimeout(()=>process.exit(0),1800);"], base,
    {signal: controller.signal}), /cancelled/);
  } finally {
    clearTimeout(timer);
  }
  assert.equal(commandRecord(base).failure_kind, 'cancelled');
  assert.equal(fs.readFileSync(`${base}.stdout`, 'utf8'), 'active');
});

test('real CLI failure retains all three transports and allows isolated retry offline', (t) => {
  const parent = fs.mkdtempSync(path.join(REPOSITORY_ROOT,
    'benchmarks/results/local-archives/environment-lifecycle-test-'));
  t.after(() => fs.rmSync(parent, {recursive: true, force: true}));
  const bin = path.join(parent, 'bin');
  fs.mkdirSync(bin, {mode: 0o700});
  const calls = path.join(parent, 'fake-calls.jsonl');
  const commit = 'a'.repeat(40);
  const topology = yaml.load(fs.readFileSync(path.join(REPOSITORY_ROOT,
    'benchmarks/plans/dedicated-environment-template.yaml'), 'utf8'));
  topology.source_commit = commit;
  const preflight = JSON.parse(fs.readFileSync(path.join(REPOSITORY_ROOT,
    'benchmarks/spec/fixtures/dedicated-preflight.valid.json'), 'utf8'));
  preflight.source.commit = commit;
  preflight.mode = 'rehearsal';
  preflight.allocation_authorized = false;
  fs.writeFileSync(path.join(parent, 'topology.yaml'), yaml.dump(topology));
  fs.writeFileSync(path.join(parent, 'preflight.json'), JSON.stringify(preflight));
  // Synthetic ELF header is inspection input only; the fake SSH never executes it.
  const elf = Buffer.alloc(64);
  elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1]);
  elf.writeUInt16LE(62, 18);
  fs.writeFileSync(path.join(parent, 'host-tune'), elf);
  for (const name of ['git', 'ssh', 'scp', 'aws']) {
    const program = `#!${process.execPath}\n` +
      `const fs=require('node:fs'); const args=process.argv.slice(2);\n` +
      `const name=${JSON.stringify(name)};\n` +
      `fs.appendFileSync(${JSON.stringify(calls)},JSON.stringify({name,args})+'\\n');\n` +
      `if(name==='git'){ if(args[0]==='rev-parse')process.stdout.write(${JSON.stringify(commit)}); ` +
      `else if(args[0]!=='status')process.exitCode=99; }\n` +
      `else if(name==='ssh'){ process.stdout.write('simulated start'); ` +
      `setTimeout(()=>{process.stderr.write('simulated failure');process.exit(7);},` +
      `args.includes('bonvoyage-load-generator')?5:80); }\n` +
      `else {process.stderr.write('unexpected transport');process.exitCode=99;}\n`;
    fs.writeFileSync(path.join(bin, name), program, {mode: 0o700});
  }
  const stages = [];
  for (const attempt of ['first', 'retry']) {
    const output = path.join(parent, attempt);
    assert.throws(() => execFileSync(process.execPath, [
      path.join(REPOSITORY_ROOT, 'benchmarks/scripts/dedicated-environment.mjs'),
      'collect', '--topology', path.join(parent, 'topology.yaml'),
      '--preflight', path.join(parent, 'preflight.json'),
      '--host-tune-binary', path.join(parent, 'host-tune'), '--output', output,
    ], {env: {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`},
      stdio: 'pipe', timeout: 15000}), (error) => {
      assert.equal(error.status, 1);
      assert.match(error.stderr.toString(), /role phase failed/);
      return true;
    });
    const initial = JSON.parse(fs.readFileSync(path.join(output, 'collection-attempt.json')));
    const failure = JSON.parse(fs.readFileSync(path.join(output, 'failure.json')));
    assert.equal(failure.attempt_id, initial.attempt_id);
    assert.deepEqual(failure.remote_staging, initial.remote_staging);
    assert.equal(failure.remote_cleanup_performed, false);
    assert.equal(fs.existsSync(path.join(output, 'reports/environment-candidate.json')), false);
    assert.equal(fs.statSync(output).mode & 0o777, 0o700);
    stages.push(initial.remote_staging.map(({path: stage}) => stage));
    for (const role of topology.roles) {
      const base = path.join(output, 'environment', role.role, 'transport/01-create-stage');
      assert.equal(commandRecord(base).exit_code, 7);
      assert.equal(fs.readFileSync(`${base}.stderr`, 'utf8'), 'simulated failure');
    }
    assert.equal(writeRawManifest(output).valid, true);
  }
  assert.equal(new Set(stages.flat()).size, 6);
  assert.equal(verifyRawManifest(path.join(parent, 'first')).valid, true);
  const commands = fs.readFileSync(calls, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
  assert.equal(commands.filter(({name}) => name === 'ssh').length, 6);
  assert.equal(commands.some(({name}) => name === 'aws' || name === 'scp'), false);
  for (const {args} of commands.filter(({name}) => name === 'ssh')) {
    assert.ok(args.includes('StrictHostKeyChecking=yes'));
    assert.ok(args.includes('ForwardAgent=no'));
    assert.ok(args.includes('mkdir'));
    assert.ok(stages.flat().includes(args.at(-1)));
  }
});
