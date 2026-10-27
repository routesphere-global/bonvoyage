import assert from 'node:assert/strict';
import {spawn, execFileSync} from 'node:child_process';
import {EventEmitter} from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createRequire} from 'node:module';
import {setTimeout as delay} from 'node:timers/promises';
import test from 'node:test';
import {collectionTimeout, createCollectionSupervisor} from './dedicated-collection-supervisor.mjs';
import {recoveryObservation, remoteStage, runCaptured, verifyRawManifest} from './dedicated-environment.mjs';
import {REPOSITORY_ROOT, sha256File} from './dedicated-preflight.mjs';

const require = createRequire(path.join(REPOSITORY_ROOT, 'package.json'));
const yaml = require('js-yaml');
const cli = path.join(REPOSITORY_ROOT, 'benchmarks/scripts/dedicated-environment.mjs');
const boot = '12345678-1234-1234-1234-123456789abc';

test('collection budget rejects ambiguous or impossible values', () => {
  assert.equal(collectionTimeout(), 3600000);
  assert.equal(collectionTimeout('14400', 60), 14400000);
  for (const value of ['0', '-1', '1.2', '1e3', '01', ' 10', 'Infinity', '14401', ''])
    assert.throws(() => collectionTimeout(value));
  assert.throws(() => collectionTimeout('60', 60));
  assert.throws(() => createCollectionSupervisor({timeoutMs: Infinity}));
});
for (const signal of ['SIGINT', 'SIGTERM']) {
  test(signal + ' cancels waits and disposal restores signal listeners', async () => {
    const emitter = new EventEmitter();
    const supervisor = createCollectionSupervisor({timeoutMs: 1000, emitter});
    try {
      const wait = supervisor.wait(500);
      emitter.emit(signal);
      await assert.rejects(wait, new RegExp(signal));
      supervisor.cancel('later');
      assert.equal(supervisor.snapshot().cancellation_reason, signal);
      assert.throws(supervisor.check, new RegExp(signal));
    } finally { supervisor.dispose(); }
    assert.equal(emitter.listenerCount('SIGINT'), 0);
    assert.equal(emitter.listenerCount('SIGTERM'), 0);
  });
}
test('deadline cancels idle observation and disposal prevents later cancellation', async () => {
  const supervisor = createCollectionSupervisor({timeoutMs: 25, emitter: new EventEmitter()});
  try {
    await assert.rejects(supervisor.wait(500), /deadline/);
    assert.equal(supervisor.snapshot().cancellation_reason, 'deadline');
  } finally { supervisor.dispose(); }
  const disposed = createCollectionSupervisor({timeoutMs: 25, emitter: new EventEmitter()});
  disposed.dispose();
  await delay(50);
  assert.equal(disposed.signal.aborted, false);
});
test('timeout terminates an inherited-pipe local descendant', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bv-process-group-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const marker = path.join(root, 'ticks');
  const descendant = 'const fs=require("node:fs");setInterval(()=>fs.appendFileSync(' +
    JSON.stringify(marker) + ',"x"),20);setTimeout(()=>process.exit(0),4000);';
  const parent = 'require("node:child_process").spawn(process.execPath,["-e",' +
    JSON.stringify(descendant) + '],{stdio:"inherit"});setInterval(()=>{},100);';
  const started = Date.now();
  await assert.rejects(runCaptured(process.execPath, ['-e', parent], path.join(root, 'capture'),
    {timeout: 500}), /timed out/);
  assert.ok(Date.now() - started < 3000);
  const size = fs.statSync(marker).size;
  await delay(150);
  assert.equal(fs.statSync(marker).size, size, 'owned descendant must no longer write');
});
test('multibyte overflow preserves exact bounded transcript bytes', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bv-output-bytes-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const base = path.join(root, 'overflow');
  await assert.rejects(runCaptured(process.execPath, ['-e',
    'process.stdout.write(Buffer.from([0xe2,0x82,0xac,0xe2,0x82,0xac]));'],
  base, {maxBuffer: 4}), /output-limit/);
  assert.deepEqual(fs.readFileSync(base + '.stdout'), Buffer.from([0xe2, 0x82, 0xac, 0xe2]));
});
const baseObservation = {
  expectedBoot: boot, beforeBoot: boot, afterBoot: boot,
  processList: '1 /sbin/init\n22 ps -ww -eo pid=,args=', stage: '/var/tmp/bonvoyage-attempt',
};
for (const [name, changes, expected] of [
  ['no process match', {}, 'no-matching-process-observed'],
  ['attempt process', {processList: '34 /var/tmp/bonvoyage-attempt/bonvoyage-host-tune inspect'}, 'activity-observed'],
  ['missing identity', {expectedBoot: undefined}, 'unknown'],
  ['reboot', {afterBoot: '22345678-1234-1234-1234-123456789abc'}, 'unknown'],
  ['wrong machine', {beforeBoot: '22345678-1234-1234-1234-123456789abc'}, 'unknown'],
  ['empty process snapshot', {processList: ''}, 'unknown'],
  ['malformed snapshot', {processList: 'not process data'}, 'unknown'],
]) {
  test('recovery classification: ' + name + ' never authorizes cleanup', () => {
    const report = recoveryObservation({...baseObservation, ...changes});
    assert.equal(report.status, expected);
    assert.equal(report.cleanup_authorized, false);
    assert.equal(report.remote_quiescence_confirmed, false);
  });
}
function fixture(t) {
  const archives = path.join(REPOSITORY_ROOT, 'benchmarks/results/local-archives');
  fs.mkdirSync(archives, {recursive: true, mode: 0o700});
  const root = fs.mkdtempSync(path.join(archives, 'environment-supervisor-test-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin, {mode: 0o700});
  const calls = path.join(root, 'calls.jsonl');
  const commit = 'a'.repeat(40);
  const topology = yaml.load(fs.readFileSync(path.join(REPOSITORY_ROOT,
    'benchmarks/plans/dedicated-environment-template.yaml'), 'utf8'));
  topology.source_commit = commit;
  topology.observation.idle_seconds = 1;
  const preflight = JSON.parse(fs.readFileSync(path.join(REPOSITORY_ROOT,
    'benchmarks/spec/fixtures/dedicated-preflight.valid.json')));
  preflight.source.commit = commit;
  preflight.mode = 'rehearsal';
  preflight.allocation_authorized = false;
  fs.writeFileSync(path.join(root, 'topology.yaml'), yaml.dump(topology));
  fs.writeFileSync(path.join(root, 'preflight.json'), JSON.stringify(preflight));
  const elf = Buffer.alloc(64);
  elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1]);
  elf.writeUInt16LE(62, 18);
  fs.writeFileSync(path.join(root, 'host-tune'), elf);
  for (const name of ['git', 'ssh', 'scp', 'aws']) {
    const script = '#!' + process.execPath + '\n' +
      'const fs=require("node:fs"),args=process.argv.slice(2),name=' + JSON.stringify(name) + ';\n' +
      'fs.appendFileSync(' + JSON.stringify(calls) + ',JSON.stringify({name,args})+"\\n");\n' +
      'if(name==="git"){if(args[0]==="rev-parse")process.stdout.write(' + JSON.stringify(commit) +
      ');else if(args[0]!=="status")process.exitCode=99;}\n' +
      'else if(name!=="ssh"){process.exitCode=99;}\n' +
      'else if(process.env.FAKE_RECOVERY==="1"){\n' +
      'if(process.env.FAKE_SSH_FAIL==="1"){process.stderr.write("unreachable");process.exitCode=7;}\n' +
      'else if(args.includes("cat"))process.stdout.write(' + JSON.stringify(boot) + ');\n' +
      'else if(args.includes("ps"))process.stdout.write(process.env.FAKE_PS||"1 /sbin/init");\n' +
      'else process.exitCode=99;\n' +
      '}else{process.stdout.write("transport started");setTimeout(()=>process.exit(99),10000);}\n';
    fs.writeFileSync(path.join(bin, name), script, {mode: 0o700});
  }
  const env = {...process.env, PATH: bin + path.delimiter + process.env.PATH};
  const commands = () => fs.existsSync(calls)
    ? fs.readFileSync(calls, 'utf8').trim().split('\n').map(JSON.parse) : [];
  const collect = (output, seconds = '2') => [cli, 'collect',
    '--topology', path.join(root, 'topology.yaml'), '--preflight', path.join(root, 'preflight.json'),
    '--host-tune-binary', path.join(root, 'host-tune'), '--output', output, '--timeout-seconds', seconds];
  return {root, env, commands, collect, topology};
}
for (const reason of ['deadline', 'SIGINT', 'SIGTERM']) {
  test('offline CLI ' + reason + ' settles transports without starting later operations', async (t) => {
    const f = fixture(t);
    const output = path.join(f.root, 'collection');
    const child = spawn(process.execPath, f.collect(output, reason === 'deadline' ? '2' : '10'),
      {env: f.env, stdio: ['ignore', 'pipe', 'pipe']});
    let stderr = '';
    child.stdout.resume();
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const closed = new Promise((resolve, reject) => {
      child.once('error', reject); child.once('close', resolve);
    });
    const guard = setTimeout(() => child.kill('SIGKILL'), 15000);
    try {
      if (reason !== 'deadline') {
        const start = Date.now();
        while (f.commands().filter(({name}) => name === 'ssh').length < 3 && Date.now() - start < 5000)
          await delay(20);
        assert.equal(f.commands().filter(({name}) => name === 'ssh').length, 3);
        child.kill(reason);
      }
      assert.equal(await closed, 1, stderr);
    } finally {
      clearTimeout(guard);
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await closed;
    }
    const failure = JSON.parse(fs.readFileSync(path.join(output, 'failure.json')));
    assert.equal(failure.supervision.cancellation_reason, reason);
    assert.equal(failure.remote_cleanup_performed, false);
    assert.equal(fs.existsSync(path.join(output, 'reports/environment-candidate.json')), false);
    for (const role of f.topology.roles) {
      const base = path.join(output, 'environment', role.role, 'transport/01-create-stage');
      const record = JSON.parse(fs.readFileSync(base + '.command.json'));
      assert.equal(record.failure_kind, 'cancelled');
      assert.equal(record.cancellation_reason, reason);
      assert.equal(fs.statSync(base + '.stdout').mode & 0o777, 0o600);
    }
    assert.equal(f.commands().filter(({name}) => name === 'ssh').length, 3);
    assert.equal(f.commands().some(({name}) => ['aws', 'scp'].includes(name)), false);
  });
}
function recoveryFixture(t) {
  const f = fixture(t);
  const original = path.join(f.root, 'original');
  fs.mkdirSync(path.join(original, 'inputs'), {recursive: true});
  fs.copyFileSync(path.join(f.root, 'topology.yaml'), path.join(original, 'inputs/topology.yaml'));
  const attempt = {schema_version: 1, source_commit: f.topology.source_commit,
    attempt_id: '1'.repeat(32)};
  attempt.remote_staging = f.topology.roles.map((role) => ({
    role: role.role, path: remoteStage(f.topology, role, attempt.attempt_id),
  }));
  fs.writeFileSync(path.join(original, 'collection-attempt.json'), JSON.stringify(attempt));
  for (const role of f.topology.roles) {
    const dir = path.join(original, 'environment', role.role, 'host-inventory');
    fs.mkdirSync(dir, {recursive: true});
    const inventory = path.join(dir, 'inventory.json');
    fs.writeFileSync(inventory, JSON.stringify({host: {boot_id: boot}}));
    fs.writeFileSync(path.join(dir, 'checksums.sha256'), sha256File(inventory) + '  ./inventory.json\n');
  }
  return {...f, original, attempt};
}
for (const mode of ['no-match', 'activity', 'missing-baseline', 'unbound-inventory', 'transport-failure', 'deadline']) {
  test('offline recovery ' + mode + ' preserves evidence and never authorizes cleanup', (t) => {
    const f = recoveryFixture(t);
    const inventoryRoot = path.join(f.original, 'environment', f.topology.roles[0].role, 'host-inventory');
    if (mode === 'missing-baseline') fs.rmSync(inventoryRoot, {recursive: true});
    if (mode === 'unbound-inventory') fs.writeFileSync(path.join(inventoryRoot, 'checksums.sha256'), '');
    const originalAttempt = sha256File(path.join(f.original, 'collection-attempt.json'));
    const output = path.join(f.root, 'recovery');
    const env = {...f.env, FAKE_RECOVERY: mode === 'deadline' ? '0' : '1',
      FAKE_PS: mode === 'activity' ? '123 ' + f.attempt.remote_staging[0].path + '/bonvoyage-host-tune inspect' : '',
      FAKE_SSH_FAIL: mode === 'transport-failure' ? '1' : '0'};
    const args = [cli, 'recover', '--evidence-root', f.original, '--output', output,
      '--timeout-seconds', mode === 'deadline' ? '1' : '30'];
    if (['missing-baseline', 'unbound-inventory', 'transport-failure', 'deadline'].includes(mode)) {
      assert.throws(() => execFileSync(process.execPath, args, {env, timeout: 10000, stdio: 'pipe'}),
        (error) => error.status === 1);
    } else execFileSync(process.execPath, args, {env, timeout: 10000, stdio: 'pipe'});
    const report = JSON.parse(fs.readFileSync(path.join(output, 'recovery.json')));
    assert.equal(report.observations.length, 3);
    for (const key of ['cleanup_authorized', 'measurement_authorized', 'remote_quiescence_confirmed',
      'remote_cleanup_performed']) assert.equal(report[key], false);
    assert.equal(report.requires_operator_review, true);
    assert.equal(report.status, ['no-match', 'activity'].includes(mode) ? 'review-required' : 'blocked');
    if (mode === 'activity') assert.equal(report.observations[0].status, 'activity-observed');
    if (mode === 'deadline') assert.equal(report.supervision.cancellation_reason, 'deadline');
    assert.equal(verifyRawManifest(output).valid, true);
    assert.equal(fs.statSync(path.join(output, 'recovery.json')).mode & 0o777, 0o600);
    assert.equal(sha256File(path.join(f.original, 'collection-attempt.json')), originalAttempt);
    assert.equal(fs.existsSync(path.join(f.original, 'recovery.json')), false);
    for (const {name, args: argv} of f.commands()) {
      assert.equal(name, 'ssh');
      assert.ok(argv.includes('cat') || argv.includes('ps'));
      assert.ok(argv.includes('ForwardAgent=no'));
    }
  });
}
test('invalid recovery paths, altered staging and unknown flags fail before transport', (t) => {
  const f = recoveryFixture(t);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'bv-outside-archive-'));
  t.after(() => fs.rmSync(outside, {recursive: true, force: true}));
  fs.symlinkSync(outside, path.join(f.root, 'outside'));
  fs.symlinkSync(f.original, path.join(f.root, 'original-alias'));
  for (const args of [
    [cli, 'recover', '--evidence-root', f.original, '--output', path.join(f.original, 'nested')],
    [cli, 'recover', '--evidence-root', f.original, '--output', path.join(f.root, 'outside/recovery')],
    [cli, 'recover', '--evidence-root', f.original, '--output', path.join(f.root, 'original-alias/recovery')],
    [...f.collect(path.join(f.root, 'bad')), '--timeout-second', '3'],
    [cli, 'recover', '--evidence-root', f.original, '--output', path.join(f.root, 'bad'), '--timeout-seconds', '0'],
  ]) {
    assert.throws(() => execFileSync(process.execPath, args, {env: f.env, timeout: 5000, stdio: 'pipe'}));
    assert.equal(f.commands().length, 0);
  }
  f.attempt.remote_staging[0].path = '/var/tmp/unrelated';
  fs.writeFileSync(path.join(f.original, 'collection-attempt.json'), JSON.stringify(f.attempt));
  assert.throws(() => execFileSync(process.execPath,
    [cli, 'recover', '--evidence-root', f.original, '--output', path.join(f.root, 'bad')],
    {env: f.env, timeout: 5000, stdio: 'pipe'}));
  assert.equal(f.commands().length, 0);
});
