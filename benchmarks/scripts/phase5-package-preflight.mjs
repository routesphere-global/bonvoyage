#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {buildPackagePlacement} from './phase5-package-placement.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const FILES = ['aio-capacity.conf', 'bonvoyage-resources.conf',
  'bonvoyage-runtime.conf', 'irqbalance-exclusion.conf'];
const MEMBERS = [...FILES, 'plan.json'].sort();
const UNIT = '/usr/lib/systemd/system/bonvoyage.service';
const BINARY = '/usr/bin/bonvoyage-dataplane';
const SHA256 = /^[0-9a-f]{64}$/u;

function requireValue(ok, message) {
  if (!ok) throw new Error(message);
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function verifyPlacementBundle(directory) {
  requireValue(fs.lstatSync(directory).isDirectory(), 'placement bundle path is not a directory');
  const names = fs.readdirSync(directory).sort();
  requireValue(JSON.stringify(names) === JSON.stringify([...MEMBERS, 'checksums.sha256'].sort()),
    'placement bundle membership differs from the reviewed contract');
  const read = (name) => {
    const file = path.join(directory, name);
    requireValue(fs.lstatSync(file).isFile(), `unsafe bundle member: ${name}`);
    return fs.readFileSync(file);
  };
  const manifest = read('checksums.sha256').toString('utf8');
  const expectedManifest = MEMBERS.map((name) => `${digest(read(name))}  ${name}\n`).join('');
  requireValue(manifest === expectedManifest, 'placement checksums do not verify');
  const plan = JSON.parse(read('plan.json').toString('utf8'));
  requireValue(plan.schema_version === 1 && plan.evidence_class === 'shared-vm-placement-plan' &&
    plan.source_dirty === false && plan.measurement_authorized === false &&
    /^[0-9a-f]{40}$/u.test(plan.source_commit) && SHA256.test(plan.binary_sha256),
  'placement identity or evidence class invalid');
  const sourceUnit = fs.readFileSync(path.join(ROOT, 'packaging/systemd/bonvoyage.service'), 'utf8');
  const installedUnit = sourceUnit.replace('/usr/local/bin/bonvoyage-dataplane', BINARY);
  const rebuilt = buildPackagePlacement({sourceUnit, installedUnit,
    onlineCpus: plan.online_cpus, gatewayCpus: plan.gateway_cpus, irqCpus: plan.irq_cpus,
    binarySha256: plan.binary_sha256, seastarMemoryMiB: plan.seastar_memory_mib,
    memoryHighMiB: plan.memory_high_mib, memoryMaxMiB: plan.memory_max_mib,
    networkIOCbsPerShard: plan.network_iocbs_per_shard,
    responsePathDiagnostics: plan.response_path_diagnostics_enabled,
    currentAioMaxNr: plan.current_aio_max_nr, currentAioNr: plan.current_aio_nr,
    runtimeSnapshotFile: plan.runtime_artifacts?.snapshot_file ?? null,
    runtimeSecretsDirectory: plan.runtime_artifacts?.secrets_directory ?? null,
    runtimeHostsFile: plan.runtime_artifacts?.hosts_file ?? null,
    runtimePlanId: plan.runtime_artifacts?.plan_id ?? null});
  for (const [name, contents] of Object.entries(rebuilt.files)) {
    requireValue(read(name).equals(Buffer.from(contents)), `placement file differs: ${name}`);
  }
  for (const [name, value] of Object.entries(rebuilt.plan)) {
    requireValue(JSON.stringify(plan[name]) === JSON.stringify(value),
      `placement plan field differs: ${name}`);
  }
  requireValue(Object.keys(plan).length === Object.keys(rebuilt.plan).length + 2,
    'unexpected placement plan fields');
  return plan;
}

function packageArguments() {
  const source = fs.readFileSync(path.join(ROOT, 'packaging/systemd/bonvoyage.service'), 'utf8');
  const lines = source.split('\n').filter((line) => line.startsWith('ExecStart='));
  requireValue(lines.length === 1 && !/["'\\]/u.test(lines[0]),
    'package command requires explicit review');
  return lines[0].slice('ExecStart='.length)
    .replace('/usr/local/bin/bonvoyage-dataplane', BINARY).split(' ');
}

function properties(output) {
  const result = {};
  for (const line of output.trimEnd().split('\n')) {
    const at = line.indexOf('=');
    requireValue(at > 0 && !(line.slice(0, at) in result), 'invalid systemd property output');
    result[line.slice(0, at)] = line.slice(at + 1);
  }
  return result;
}

function cpuSet(text) {
  requireValue(/^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$/u.test(text), 'invalid CPU set');
  const result = new Set();
  for (const part of text.split(',')) {
    const [first, last = first] = part.split('-').map(Number);
    requireValue(first <= last && last - first < 4096, 'invalid CPU range');
    for (let cpu = first; cpu <= last; cpu += 1) result.add(cpu);
  }
  return result;
}

export function evaluatePlacementPreflight(plan, observed, expectedIrqCount,
  managementCpu = 0, irqMode = 'static-ena') {
  requireValue(irqMode === 'static-ena' || irqMode === 'irqbalance-off-unpinned',
    'unknown VM IRQ mode');
  requireValue(Number.isSafeInteger(expectedIrqCount) && expectedIrqCount >= 1 &&
    expectedIrqCount <= 512, 'expected NIC IRQ count invalid');
  requireValue(observed.online_cpus === plan.online_cpus, 'online CPUs changed');
  requireValue(observed.unit_sha256 === plan.package_unit_sha256 &&
    observed.binary_sha256 === plan.binary_sha256, 'installed package identity changed');
  requireValue(observed.gateway.ActiveState === 'active' &&
    observed.gateway.FragmentPath === plan.expected_fragment_path &&
    observed.gateway.DropInPaths === '' && observed.gateway.NeedDaemonReload === 'no' &&
    observed.gateway.ControlGroup === '/system.slice/bonvoyage.service' &&
    /^[1-9]\d*$/u.test(observed.gateway.MainPID) &&
    observed.gateway.MainPID === observed.final_gateway_pid &&
    JSON.stringify(observed.argv) === JSON.stringify(packageArguments()),
  'gateway service is not the reviewed untuned package service');
  requireValue(observed.gateway.NRestarts === '0', 'gateway restarted before preflight');
  requireValue(observed.irqbalance.ActiveState === 'active' &&
    observed.irqbalance.DropInPaths === '' &&
    observed.nitroIRQBalance.ActiveState === 'inactive',
  'IRQ services differ from the reviewed baseline');
  requireValue(observed.aio_max_nr === plan.current_aio_max_nr &&
    Number.isSafeInteger(observed.aio_nr) && observed.aio_nr >= 0 &&
    observed.aio_nr <= observed.aio_max_nr,
  'AIO capacity changed or is invalid');
  requireValue(/^[a-zA-Z0-9_.-]+$/u.test(observed.interface) &&
    Number.isSafeInteger(observed.combined_queues) && observed.combined_queues > 0 &&
    /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(observed.boot_id),
  'host NIC or boot identity invalid');
  const gateway = cpuSet(plan.gateway_cpus);
  const irqCpus = [...cpuSet(plan.irq_cpus)].sort((a, b) => a - b);
  requireValue(irqCpus.length === observed.combined_queues &&
    (irqMode !== 'static-ena' || (irqCpus.includes(managementCpu) &&
      !gateway.has(managementCpu))),
  'planned IRQ CPUs cannot place the management vector');
  requireValue(observed.irq_labels && typeof observed.irq_labels === 'object',
    'NIC IRQ labels missing');
  const queues = new Set();
  let management = 0;
  const irqDetails = Object.entries(observed.irq_affinity).map(([irq, affinity]) => {
    requireValue(/^\d+$/u.test(irq), 'invalid IRQ identifier');
    const actual = cpuSet(affinity);
    const label = observed.irq_labels[irq];
    let proposedCpu;
    if (/^ena-mgmnt@pci:[0-9a-f:.]+$/u.test(label)) {
      management += 1;
      proposedCpu = irqMode === 'static-ena' ? managementCpu : null;
    } else {
      const prefix = `${observed.interface}-Tx-Rx-`;
      const suffix = typeof label === 'string' && label.startsWith(prefix)
        ? label.slice(prefix.length) : '';
      requireValue(/^\d+$/u.test(suffix) && Number(suffix) < observed.combined_queues,
        'unrecognized NIC IRQ label');
      const queue = Number(suffix);
      requireValue(!queues.has(queue), 'duplicate NIC queue IRQ');
      queues.add(queue);
      proposedCpu = irqMode === 'static-ena' ? irqCpus[queue] : null;
    }
    return {irq: Number(irq), label, affinity, proposed_cpu: proposedCpu,
      overlaps_gateway: [...actual].some((cpu) => gateway.has(cpu))};
  }).sort((a, b) => a.irq - b.irq);
  requireValue(irqDetails.length === expectedIrqCount &&
    irqDetails.length >= observed.combined_queues, 'NIC IRQ observation incomplete');
  requireValue(management === 1 && queues.size === observed.combined_queues,
    'ENA management or queue IRQ mapping incomplete');
  return {status: 'preflight-pass', activation_authorized: false,
    measurement_authorized: false, boot_id: observed.boot_id,
    interface: observed.interface, combined_queues: observed.combined_queues,
    expected_irq_count: expectedIrqCount,
    irq_mode: irqMode, desired_irqbalance_state: 'inactive',
    management_cpu: irqMode === 'static-ena' ? managementCpu : null,
    exact_irq_mapping_proposed: irqMode === 'static-ena',
    overlapping_irq_count: irqDetails.filter((row) => row.overlaps_gateway).length,
    irqs: irqDetails, gateway_pid: Number(observed.gateway.MainPID),
    aio_max_nr: observed.aio_max_nr, aio_nr: observed.aio_nr};
}

export function capturePlacementState(host, transcript, ssh = (command) =>
  execFileSync('ssh', ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', host, command],
    {encoding: 'utf8', timeout: 12000, maxBuffer: 65536})) {
  requireValue(/^[A-Za-z0-9][A-Za-z0-9_.-]*$/u.test(host), 'invalid SSH target');
  const remote = (name, command) => {
    const result = ssh(command);
    transcript[name] = {command, output: result};
    return result.trim();
  };
  const bootId = remote('boot_id', 'cat /proc/sys/kernel/random/boot_id');
  const hashes = remote('package_hashes', `sha256sum ${UNIT} ${BINARY}`).split('\n');
  requireValue(hashes.length === 2, 'package hash output incomplete');
  const matchHash = (line, filename) => {
    const match = /^([0-9a-f]{64})  (\/\S+)$/u.exec(line);
    requireValue(match && match[2] === filename, 'invalid package hash output');
    return match[1];
  };
  const routes = JSON.parse(remote('default_route', 'ip -j -4 route show default'));
  requireValue(Array.isArray(routes) && routes.length === 1 &&
    /^[a-zA-Z0-9_.-]+$/u.test(routes[0].dev), 'ambiguous default interface');
  const device = routes[0].dev;
  const channels = remote('nic_channels', `ethtool -l ${device}`);
  const current = channels.split('Current hardware settings:')[1];
  const queueMatch = current && /(?:^|\n)Combined:\s*(\d+)/u.exec(current);
  requireValue(queueMatch, 'NIC queue count unavailable');
  const irqs = remote('nic_irqs', `ls /sys/class/net/${device}/device/msi_irqs`).split('\n');
  const affinity = {};
  const irqLabels = {};
  const interruptLines = remote('interrupt_labels', 'cat /proc/interrupts').split('\n');
  for (const line of interruptLines) {
    const match = /^\s*(\d+):/u.exec(line);
    if (match) irqLabels[match[1]] = line.trim().split(/\s+/u).at(-1);
  }
  for (const irq of irqs) {
    requireValue(/^\d+$/u.test(irq), 'invalid NIC IRQ identifier');
    requireValue(typeof irqLabels[irq] === 'string', 'NIC IRQ label missing');
    affinity[irq] = remote(`irq_${irq}`, `cat /proc/irq/${irq}/effective_affinity_list`);
  }
  const aioMax = Number(remote('aio_max_nr', 'cat /proc/sys/fs/aio-max-nr'));
  const aioNr = Number(remote('aio_nr', 'cat /proc/sys/fs/aio-nr'));
  const gateway = properties(remote('gateway_service',
    'systemctl show bonvoyage.service --all --property=ActiveState,MainPID,NRestarts,ControlGroup,FragmentPath,DropInPaths,NeedDaemonReload'));
  requireValue(/^[1-9]\d*$/u.test(gateway.MainPID), 'invalid gateway PID');
  const argv = remote('gateway_cmdline', `cat /proc/${gateway.MainPID}/cmdline`)
    .split('\x00').filter((value) => value !== '');
  const final = properties(remote('gateway_final_state',
    'systemctl show bonvoyage.service --all --property=ActiveState,MainPID'));
  requireValue(final.ActiveState === 'active', 'gateway stopped during preflight');
  const finalIrqs = remote('nic_irqs_final',
    `ls /sys/class/net/${device}/device/msi_irqs`).split('\n');
  requireValue(JSON.stringify(finalIrqs) === JSON.stringify(irqs),
    'NIC IRQ membership changed during preflight');
  requireValue(remote('boot_id_final', 'cat /proc/sys/kernel/random/boot_id') === bootId,
    'host rebooted during preflight');
  const observed = {
    boot_id: bootId,
    online_cpus: remote('online_cpus', 'cat /sys/devices/system/cpu/online'),
    unit_sha256: matchHash(hashes[0], UNIT), binary_sha256: matchHash(hashes[1], BINARY),
    gateway, argv, final_gateway_pid: final.MainPID,
    irqbalance: properties(remote('irqbalance_service', 'systemctl show irqbalance.service --all --property=ActiveState,DropInPaths')),
    nitroIRQBalance: properties(remote('nitro_irqbalance_service', 'systemctl show aws-nitro-irqbalance.service --all --property=ActiveState')),
    aio_max_nr: aioMax, aio_nr: aioNr, interface: device,
    combined_queues: Number(queueMatch[1]), irq_affinity: affinity,
    irq_labels: Object.fromEntries(irqs.map((irq) => [irq, irqLabels[irq]])),
  };
  return observed;
}

function main() {
  const args = process.argv.slice(2);
  requireValue(args.length === 13 && args[0] === 'inspect' && args[1] === '--bundle' &&
    args[3] === '--host' && args[5] === '--expected-irqs' &&
    args[7] === '--management-cpu' && args[9] === '--irq-mode' &&
    args[11] === '--output',
  'usage: phase5-package-preflight.mjs inspect --bundle DIR --host SSH_TARGET --expected-irqs N --management-cpu N --irq-mode static-ena|irqbalance-off-unpinned --output DIR');
  const output = args[12];
  fs.mkdirSync(output, {mode: 0o700});
  const toolSourceCommit = execFileSync('git', ['-C', ROOT, 'rev-parse', 'HEAD'],
    {encoding: 'utf8'}).trim();
  const toolSourceDirty = execFileSync('git', ['-C', ROOT, 'status', '--porcelain'],
    {encoding: 'utf8'}).trim() !== '';
  let report;
  const transcript = {};
  let observed;
  try {
    const plan = verifyPlacementBundle(args[2]);
    observed = capturePlacementState(args[4], transcript);
    report = {schema_version: 1, evidence_class: 'shared-vm-package-preflight',
      captured_at_utc: new Date().toISOString(),
      tool_source_commit: toolSourceCommit, tool_source_dirty: toolSourceDirty,
      plan_source_commit: plan.source_commit, plan_source_dirty: plan.source_dirty,
      package_unit_sha256: plan.package_unit_sha256, binary_sha256: plan.binary_sha256,
      ...evaluatePlacementPreflight(plan, observed, Number(args[6]),
        Number(args[8]), args[10]), observed, transcript};
  } catch (error) {
    report = {schema_version: 1, evidence_class: 'shared-vm-package-preflight',
      captured_at_utc: new Date().toISOString(),
      tool_source_commit: toolSourceCommit, tool_source_dirty: toolSourceDirty,
      status: 'preflight-blocked', activation_authorized: false,
      measurement_authorized: false, error: error.message, transcript,
      ...(observed ? {observed} : {})};
    process.exitCode = 1;
  }
  const contents = `${JSON.stringify(report, null, 2)}\n`;
  fs.writeFileSync(path.join(output, 'report.json'), contents, {mode: 0o600});
  fs.writeFileSync(path.join(output, 'checksums.sha256'),
    `${digest(contents)}  report.json\n`, {mode: 0o600});
  process.stdout.write(`${JSON.stringify({status: report.status,
    activation_authorized: false, output})}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  try { main(); } catch (error) {
    process.stderr.write(`phase5-package-preflight: ${error.message}\n`);
    process.exitCode = 1;
  }
}
