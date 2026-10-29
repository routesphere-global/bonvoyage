import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import {buildPackagePlacement} from './phase5-package-placement.mjs';
import {cleanGitIdentityEnvironment} from './test-git-identity.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sourceUnit = fs.readFileSync(path.join(root,
  'packaging/systemd/bonvoyage.service'), 'utf8');
const installedUnit = sourceUnit.replace('/usr/local/bin/bonvoyage-dataplane',
  '/usr/bin/bonvoyage-dataplane');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function fixture(overrides = {}) {
  return {sourceUnit, installedUnit, onlineCpus: '0-31',
    gatewayCpus: '8-15', irqCpus: '0-7', binarySha256: 'a'.repeat(64),
    seastarMemoryMiB: 4096, memoryHighMiB: 6144, memoryMaxMiB: 8192,
    networkIOCbsPerShard: 10000, currentAioMaxNr: 65536, currentAioNr: 11026,
    ...overrides};
}

test('8-core package plan is identity-bound and separates the eight IRQ CPUs', () => {
  const {plan, files} = buildPackagePlacement(fixture());
  assert.equal(plan.package_unit_sha256,
    '5f46acf80375a023ea06fac38f3b8d75774a41ea1361ed1a2518c880dd7aa6e7');
  assert.equal(plan.expected_fragment_path,
    '/usr/lib/systemd/system/bonvoyage.service');
  assert.equal(plan.install_targets['bonvoyage-runtime.conf'],
    '/etc/systemd/system/bonvoyage.service.d/30-perf01-runtime.conf');
  assert.equal(plan.measurement_authorized, false);
  assert.equal(plan.gateway_cpus, '8-15');
  assert.equal(plan.irq_cpus, '0-7');
  assert.equal(plan.irqbalance_banned_cpus, '8-31');
  assert.equal(plan.network_iocbs_per_shard, 10000);
  assert.equal(plan.response_path_diagnostics_enabled, false);
  assert.equal(plan.minimum_aio_capacity, 96384);
  assert.equal(plan.proposed_aio_max_nr, 131072);
  assert.equal(files['aio-capacity.conf'], 'fs.aio-max-nr = 131072\n');
  assert.equal(plan.install_targets['aio-capacity.conf'],
    '/etc/sysctl.d/99-bonvoyage-perf01-aio.conf');
  assert.match(files['bonvoyage-runtime.conf'],
    /--smp 8 --cpuset 8-15 --memory 4096M\n$/u);
  assert.match(files['bonvoyage-runtime.conf'],
    /--runtime-log-transport unix --runtime-log-socket \/dev\/log/u);
  assert.match(files['bonvoyage-resources.conf'],
    /CPUAffinity=8 9 10 11 12 13 14 15\nAllowedCPUs=8-15/u);
  assert.equal(plan.file_sha256['bonvoyage-runtime.conf'],
    sha256(files['bonvoyage-runtime.conf']));
});

test('24-core plan uses 8-31 while keeping NIC IRQ placement at 0-7', () => {
  const {plan, files} = buildPackagePlacement(fixture({gatewayCpus: '8-31',
    seastarMemoryMiB: 12288, memoryHighMiB: 14336, memoryMaxMiB: 16384}));
  assert.equal(plan.gateway_cpus, '8-31');
  assert.equal(plan.irq_cpus, '0-7');
  assert.equal(plan.irqbalance_banned_cpus, '8-31');
  assert.equal(plan.minimum_aio_capacity, 289152);
  assert.equal(plan.proposed_aio_max_nr, 524288);
  assert.match(files['bonvoyage-runtime.conf'],
    /--smp 24 --cpuset 8-31 --memory 12288M\n$/u);
});

test('15k IOCBs remain an explicit candidate with matching AIO capacity', () => {
  const {plan, files} = buildPackagePlacement(fixture({networkIOCbsPerShard: 15000}));
  assert.equal(plan.network_iocbs_per_shard, 15000);
  assert.equal(plan.minimum_aio_capacity, 136384);
  assert.equal(plan.proposed_aio_max_nr, 262144);
  assert.match(files['bonvoyage-runtime.conf'],
    /--memory 4096M --max-networking-io-control-blocks 15000\n$/u);
  assert.equal(files['aio-capacity.conf'], 'fs.aio-max-nr = 262144\n');
  const large = buildPackagePlacement(fixture({gatewayCpus: '8-31',
    networkIOCbsPerShard: 15000}));
  assert.equal(large.plan.minimum_aio_capacity, 409152);
  assert.equal(large.plan.proposed_aio_max_nr, 524288);
  const preconfigured = buildPackagePlacement(fixture({currentAioMaxNr: 2097152}));
  assert.equal(preconfigured.plan.proposed_aio_max_nr, 2097152);
});

test('response-path diagnostics are an explicit identity-bound runtime choice', () => {
  const {plan, files} = buildPackagePlacement(fixture({
    responsePathDiagnostics: true,
  }));
  assert.equal(plan.response_path_diagnostics_enabled, true);
  assert.match(files['bonvoyage-runtime.conf'],
    /--log-with-color 0 --response-path-diagnostics --smp 8/u);
  assert.equal(plan.file_sha256['bonvoyage-runtime.conf'],
    sha256(files['bonvoyage-runtime.conf']));
  assert.throws(() => buildPackagePlacement(fixture({
    responsePathDiagnostics: 'enabled',
  })), /choice must be boolean/u);
});

test('PERF-06 placement binds private runtime artifacts and rolls back cleanly', () => {
  const planId = `a1b2c3d4${'5'.repeat(56)}`;
  const runtimeRoot = `/run/bonvoyage-perf06/policy-${planId.slice(0, 16)}`;
  const {plan, files} = buildPackagePlacement(fixture({
    gatewayCpus: '8-31', seastarMemoryMiB: 12288,
    memoryHighMiB: 14336, memoryMaxMiB: 16384,
    networkIOCbsPerShard: 15000,
    runtimeSnapshotFile: `${runtimeRoot}/active.pb`,
    runtimeSecretsDirectory: `${runtimeRoot}/secrets`,
    runtimeHostsFile: `${runtimeRoot}/hosts`,
    runtimePlanId: planId,
  }));
  assert.deepEqual(plan.runtime_artifacts, {root: runtimeRoot,
    plan_id: planId,
    snapshot_file: `${runtimeRoot}/active.pb`,
    secrets_directory: `${runtimeRoot}/secrets`,
    hosts_file: `${runtimeRoot}/hosts`});
  assert.match(files['bonvoyage-runtime.conf'],
    new RegExp(`BindReadOnlyPaths=${runtimeRoot}/hosts:/etc/hosts:norbind`, 'u'));
  assert.match(files['bonvoyage-runtime.conf'],
    new RegExp(`--snapshot ${runtimeRoot}/active\\.pb`, 'u'));
  assert.match(files['bonvoyage-runtime.conf'],
    new RegExp(`--secrets-directory ${runtimeRoot}/secrets`, 'u'));
  assert.match(files['bonvoyage-runtime.conf'],
    /--smp 24 --cpuset 8-31 --memory 12288M --max-networking-io-control-blocks 15000/u);
  assert.throws(() => buildPackagePlacement(fixture({
    runtimeSnapshotFile: `${runtimeRoot}/active.pb`,
  })), /must be supplied together/u);
  assert.throws(() => buildPackagePlacement(fixture({
    runtimeSnapshotFile: '/tmp/active.pb',
    runtimeSecretsDirectory: '/tmp/secrets', runtimeHostsFile: '/tmp/hosts',
    runtimePlanId: planId,
  })), /bounded \/run root/u);
});

test('foreign package unit, CPU overlap and memory mistakes fail closed', () => {
  assert.throws(() => buildPackagePlacement(fixture({installedUnit:
    installedUnit.replace('--log-to-syslog 1', '--log-to-syslog 0')})),
  /differs from reviewed source/u);
  assert.throws(() => buildPackagePlacement(fixture({gatewayCpus: '7-14'})),
    /must be disjoint/u);
  assert.throws(() => buildPackagePlacement(fixture({gatewayCpus: '8-32'})),
    /outside online/u);
  assert.throws(() => buildPackagePlacement(fixture({gatewayCpus: '8,8,9'})),
    /duplicates/u);
  assert.throws(() => buildPackagePlacement(fixture({memoryHighMiB: 2048})),
    /memory must satisfy/u);
  assert.throws(() => buildPackagePlacement(fixture({binarySha256: 'bad'})),
    /SHA-256 invalid/u);
  assert.throws(() => buildPackagePlacement(fixture({networkIOCbsPerShard: 40001})),
    /10k-40k range/u);
  assert.throws(() => buildPackagePlacement(fixture({currentAioNr: 65537})),
    /exceeds its ceiling/u);
  assert.throws(() => buildPackagePlacement(fixture({currentAioMaxNr: -1})),
    /nonnegative integer/u);
});

test('CLI writes checksum-bound review files without authorizing measurement', (t) => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-package-placement-'));
  t.after(() => fs.rmSync(temp, {recursive: true, force: true}));
  const unit = path.join(temp, 'package.service');
  fs.writeFileSync(unit, installedUnit);
  const output = path.join(temp, 'review');
  const environment = cleanGitIdentityEnvironment(t);
  const script = path.join(root, 'benchmarks/scripts/phase5-package-placement.mjs');
  const args = [script, 'plan', '--installed-unit', unit,
    '--online-cpus', '0-31', '--gateway-cpus', '8-15', '--irq-cpus', '0-7',
    '--binary-sha256', 'a'.repeat(64), '--seastar-memory-mib', '4096',
    '--memory-high-mib', '6144', '--memory-max-mib', '8192',
    '--iocbs-per-shard', '10000', '--aio-max-nr', '65536', '--aio-nr', '11026',
    '--response-path-diagnostics', 'enabled',
    '--output', output];
  const typo = [...args];
  typo[typo.indexOf('--response-path-diagnostics')] = '--response-path-diagnostic';
  assert.throws(() => execFileSync(process.execPath, typo, {encoding: 'utf8',
    stdio: 'pipe', env: environment}), /unexpected or duplicate placement option/u);
  const duplicate = [...args, '--response-path-diagnostics', 'disabled'];
  assert.throws(() => execFileSync(process.execPath, duplicate, {encoding: 'utf8',
    stdio: 'pipe', env: environment}), /unexpected or duplicate placement option/u);
  const invalidMode = [...args];
  invalidMode[invalidMode.indexOf('enabled')] = 'on';
  assert.throws(() => execFileSync(process.execPath, invalidMode, {encoding: 'utf8',
    stdio: 'pipe', env: environment}), /must be enabled or disabled/u);
  const result = JSON.parse(execFileSync(process.execPath, args,
    {encoding: 'utf8', env: environment}));
  assert.equal(result.measurement_authorized, false);
  const plan = JSON.parse(fs.readFileSync(path.join(output, 'plan.json'), 'utf8'));
  assert.equal(typeof plan.source_dirty, 'boolean');
  assert.equal(plan.response_path_diagnostics_enabled, true);
  assert.match(fs.readFileSync(path.join(output, 'bonvoyage-runtime.conf'), 'utf8'),
    /--response-path-diagnostics/u);
  const lines = fs.readFileSync(path.join(output, 'checksums.sha256'), 'utf8')
    .trimEnd().split('\n');
  assert.equal(lines.length, 5);
  for (const line of lines) {
    const [, digest, name] = /^([a-f0-9]{64})  ([a-z.-]+)$/u.exec(line);
    assert.equal(digest, sha256(fs.readFileSync(path.join(output, name))));
  }
  assert.throws(() => execFileSync(process.execPath, args, {encoding: 'utf8',
    stdio: 'pipe', env: environment}), /EEXIST/u);
});
