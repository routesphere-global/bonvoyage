import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import {buildPackagePlacement} from './phase5-package-placement.mjs';
import {capturePlacementState, evaluatePlacementPreflight,
  verifyPlacementBundle} from './phase5-package-preflight.mjs';
import {cleanGitIdentityEnvironment} from './test-git-identity.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sourceUnit = fs.readFileSync(path.join(root, 'packaging/systemd/bonvoyage.service'), 'utf8');
const packageUnit = sourceUnit.replace('/usr/local/bin/bonvoyage-dataplane',
  '/usr/bin/bonvoyage-dataplane');
const hash = (value) => createHash('sha256').update(value).digest('hex');
const binarySha = 'b'.repeat(64);

function bundle(t, {responsePathDiagnostics = false} = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-preflight-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const {plan, files} = buildPackagePlacement({sourceUnit, installedUnit: packageUnit,
    onlineCpus: '0-31', gatewayCpus: '8-31', irqCpus: '0-7',
    binarySha256: binarySha, seastarMemoryMiB: 12288,
    memoryHighMiB: 14336, memoryMaxMiB: 16384,
    networkIOCbsPerShard: 15000, responsePathDiagnostics,
    currentAioMaxNr: 65536, currentAioNr: 11026});
  plan.source_commit = 'a'.repeat(40);
  plan.source_dirty = false;
  for (const [name, value] of Object.entries(files)) {
    fs.writeFileSync(path.join(directory, name), value);
  }
  const json = `${JSON.stringify(plan, null, 2)}\n`;
  fs.writeFileSync(path.join(directory, 'plan.json'), json);
  const manifest = [...Object.keys(files), 'plan.json'].sort().map((name) =>
    `${hash(fs.readFileSync(path.join(directory, name)))}  ${name}\n`).join('');
  fs.writeFileSync(path.join(directory, 'checksums.sha256'), manifest);
  return {directory, plan};
}

function observed() {
  const argv = sourceUnit.split('\n').find((line) => line.startsWith('ExecStart='))
    .slice('ExecStart='.length).replace('/usr/local/bin/bonvoyage-dataplane',
      '/usr/bin/bonvoyage-dataplane').split(' ');
  return {boot_id: '70c777a7-3ede-4d68-91d6-9e2fa04bf1b1', online_cpus: '0-31',
    unit_sha256: hash(packageUnit), binary_sha256: binarySha,
    gateway: {ActiveState: 'active', MainPID: '5615', NRestarts: '0',
      ControlGroup: '/system.slice/bonvoyage.service',
      FragmentPath: '/usr/lib/systemd/system/bonvoyage.service',
      DropInPaths: '', NeedDaemonReload: 'no'},
    argv, final_gateway_pid: '5615',
    irqbalance: {ActiveState: 'active', DropInPaths: ''},
    nitroIRQBalance: {ActiveState: 'inactive'},
    aio_max_nr: 65536, aio_nr: 11026, interface: 'enp39s0', combined_queues: 8,
    irq_affinity: {'70': '9', '71': '26', '72': '7', '73': '16', '74': '28',
      '75': '21', '76': '18', '77': '11', '78': '5'},
    irq_labels: {'70': 'ena-mgmnt@pci:0000:27:00.0',
      '71': 'enp39s0-Tx-Rx-0', '72': 'enp39s0-Tx-Rx-1',
      '73': 'enp39s0-Tx-Rx-2', '74': 'enp39s0-Tx-Rx-3',
      '75': 'enp39s0-Tx-Rx-4', '76': 'enp39s0-Tx-Rx-5',
      '77': 'enp39s0-Tx-Rx-6', '78': 'enp39s0-Tx-Rx-7'}};
}

test('clean plan bytes and metadata independently replay', (t) => {
  const {directory, plan} = bundle(t);
  assert.equal(verifyPlacementBundle(directory).source_commit, plan.source_commit);
  fs.appendFileSync(path.join(directory, 'bonvoyage-runtime.conf'), ' ');
  assert.throws(() => verifyPlacementBundle(directory), /checksums do not verify/u);
});

test('diagnostics-enabled plan independently replays exact runtime bytes', (t) => {
  const {directory, plan} = bundle(t, {responsePathDiagnostics: true});
  const replayed = verifyPlacementBundle(directory);
  assert.equal(replayed.response_path_diagnostics_enabled, true);
  assert.equal(replayed.source_commit, plan.source_commit);
  assert.match(fs.readFileSync(path.join(directory, 'bonvoyage-runtime.conf'), 'utf8'),
    /--response-path-diagnostics/u);
});

test('foreign members, symlinks and dirty plans fail closed', (t) => {
  const {directory} = bundle(t);
  fs.writeFileSync(path.join(directory, 'extra.conf'), 'foreign');
  assert.throws(() => verifyPlacementBundle(directory), /membership differs/u);
  fs.rmSync(path.join(directory, 'extra.conf'));
  const runtime = path.join(directory, 'bonvoyage-runtime.conf');
  fs.renameSync(runtime, `${runtime}.saved`);
  fs.symlinkSync(`${runtime}.saved`, runtime);
  fs.rmSync(`${runtime}.saved`);
  assert.throws(() => verifyPlacementBundle(directory), /membership differs|unsafe bundle member/u);
});

test('preflight identifies current IRQ overlap but never authorizes application', (t) => {
  const {directory} = bundle(t);
  const report = evaluatePlacementPreflight(verifyPlacementBundle(directory), observed(), 9);
  assert.equal(report.status, 'preflight-pass');
  assert.equal(report.expected_irq_count, 9);
  assert.deepEqual(report.irqs.map(({proposed_cpu: cpu}) => cpu),
    [0, 0, 1, 2, 3, 4, 5, 6, 7]);
  assert.equal(report.irq_mode, 'static-ena');
  assert.equal(report.desired_irqbalance_state, 'inactive');
  assert.equal(report.exact_irq_mapping_proposed, true);
  assert.equal(report.overlapping_irq_count, 7);
  assert.equal(report.activation_authorized, false);
  assert.equal(report.measurement_authorized, false);
  const alternate = evaluatePlacementPreflight(verifyPlacementBundle(directory),
    observed(), 9, 1);
  assert.equal(alternate.management_cpu, 1);
  assert.equal(alternate.irqs[0].proposed_cpu, 1);
  assert.equal(alternate.irqs[1].proposed_cpu, 0);
  assert.throws(() => evaluatePlacementPreflight(verifyPlacementBundle(directory),
    observed(), 9, 8), /cannot place the management vector/u);
});

test('irqbalance-off VM profile records NIC IRQs without proposing affinity', (t) => {
  const {directory} = bundle(t);
  const report = evaluatePlacementPreflight(verifyPlacementBundle(directory),
    observed(), 9, 0, 'irqbalance-off-unpinned');
  assert.equal(report.irq_mode, 'irqbalance-off-unpinned');
  assert.equal(report.desired_irqbalance_state, 'inactive');
  assert.equal(report.management_cpu, null);
  assert.equal(report.exact_irq_mapping_proposed, false);
  assert.equal(report.overlapping_irq_count, 7);
  assert.ok(report.irqs.every((irq) => irq.proposed_cpu === null));
  assert.equal(report.activation_authorized, false);
  assert.equal(report.measurement_authorized, false);
  assert.throws(() => evaluatePlacementPreflight(verifyPlacementBundle(directory),
    observed(), 9, 0, 'unknown'), /unknown VM IRQ mode/u);
});

test('package, process, service, CPU and AIO drift block preflight', (t) => {
  const {directory} = bundle(t);
  const plan = verifyPlacementBundle(directory);
  for (const [edit, pattern] of [
    [(state) => { state.binary_sha256 = 'c'.repeat(64); }, /package identity changed/u],
    [(state) => { state.gateway.DropInPaths = '/etc/systemd/system/bonvoyage.service.d/foreign.conf'; }, /reviewed untuned/u],
    [(state) => { state.final_gateway_pid = '5616'; }, /reviewed untuned/u],
    [(state) => { state.argv.push('--foreign'); }, /reviewed untuned/u],
    [(state) => { state.online_cpus = '0-30'; }, /online CPUs changed/u],
    [(state) => { state.aio_max_nr = 131072; }, /AIO capacity changed/u],
    [(state) => { delete state.irq_affinity['78']; }, /IRQ observation incomplete/u],
    [(state) => { delete state.irq_affinity['77']; delete state.irq_affinity['78']; },
      /IRQ observation incomplete/u],
    [(state) => { state.irq_labels['70'] = 'enp39s0-Tx-Rx-8'; },
      /unrecognized NIC IRQ label/u],
    [(state) => { state.irq_labels['78'] = 'enp39s0-Tx-Rx-6'; },
      /duplicate NIC queue IRQ/u],
  ]) {
    const state = observed();
    edit(state);
    assert.throws(() => evaluatePlacementPreflight(plan, state, 9), pattern);
  }
  assert.throws(() => evaluatePlacementPreflight(plan, observed(), 8),
    /IRQ observation incomplete/u);
});

test('SSH capture parses fixed commands and retains raw observations', () => {
  const state = observed();
  const output = new Map([
    ['sha256sum /usr/lib/systemd/system/bonvoyage.service /usr/bin/bonvoyage-dataplane',
      `${state.unit_sha256}  /usr/lib/systemd/system/bonvoyage.service\n${state.binary_sha256}  /usr/bin/bonvoyage-dataplane\n`],
    ['ip -j -4 route show default', JSON.stringify([{dst: 'default', dev: 'enp39s0'}])],
    ['ethtool -l enp39s0', 'Pre-set maximums:\nCombined: 8\nCurrent hardware settings:\nCombined: 8\n'],
    ['ls /sys/class/net/enp39s0/device/msi_irqs', `${Object.keys(state.irq_affinity).join('\n')}\n`],
    ['cat /proc/interrupts', Object.entries(state.irq_labels).map(([irq, label]) =>
      ` ${irq}: 0 0 PCI-MSIX-0000:27:00.0 0-edge ${label}\n`).join('')],
    ['cat /proc/sys/fs/aio-max-nr', '65536\n'], ['cat /proc/sys/fs/aio-nr', '11026\n'],
    ['systemctl show bonvoyage.service --all --property=ActiveState,MainPID,NRestarts,ControlGroup,FragmentPath,DropInPaths,NeedDaemonReload',
      Object.entries(state.gateway).map(([key, value]) => `${key}=${value}\n`).join('')],
    ['cat /proc/5615/cmdline', `${state.argv.join('\x00')}\x00`],
    ['systemctl show bonvoyage.service --all --property=ActiveState,MainPID',
      'ActiveState=active\nMainPID=5615\n'],
    ['cat /proc/sys/kernel/random/boot_id', `${state.boot_id}\n`],
    ['cat /sys/devices/system/cpu/online', '0-31\n'],
    ['systemctl show irqbalance.service --all --property=ActiveState,DropInPaths',
      'ActiveState=active\nDropInPaths=\n'],
    ['systemctl show aws-nitro-irqbalance.service --all --property=ActiveState',
      'ActiveState=inactive\n'],
  ]);
  for (const [irq, affinity] of Object.entries(state.irq_affinity)) {
    output.set(`cat /proc/irq/${irq}/effective_affinity_list`, `${affinity}\n`);
  }
  const transcript = {};
  const captured = capturePlacementState('gateway-target.example.test', transcript, (command) => {
    assert.ok(output.has(command), `unexpected command: ${command}`);
    return output.get(command);
  });
  assert.deepEqual(captured, state);
  assert.equal(Object.keys(transcript).length, output.size + 2);
  assert.throws(() => capturePlacementState('-oProxyCommand=bad', {}, () => ''),
    /invalid SSH target/u);
});

test('blocked CLI retains a checksum-bound report without contacting SSH', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-blocked-preflight-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const output = path.join(directory, 'attempt');
  const environment = cleanGitIdentityEnvironment(t);
  const script = path.join(root, 'benchmarks/scripts/phase5-package-preflight.mjs');
  assert.throws(() => execFileSync(process.execPath, [script, 'inspect',
    '--bundle', path.join(directory, 'missing'), '--host', 'gateway-target.example.test',
    '--expected-irqs', '9', '--management-cpu', '0', '--irq-mode', 'static-ena',
    '--output', output],
  {encoding: 'utf8', stdio: 'pipe', env: environment}));
  const contents = fs.readFileSync(path.join(output, 'report.json'));
  const report = JSON.parse(contents);
  assert.equal(report.status, 'preflight-blocked');
  assert.equal(report.measurement_authorized, false);
  assert.equal(report.activation_authorized, false);
  assert.equal(typeof report.tool_source_dirty, 'boolean');
  assert.equal(fs.readFileSync(path.join(output, 'checksums.sha256'), 'utf8'),
    `${hash(contents)}  report.json\n`);
});
