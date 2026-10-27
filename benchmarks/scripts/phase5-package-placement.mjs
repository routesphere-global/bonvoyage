#!/usr/bin/env node

import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {execFileSync} from 'node:child_process';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SOURCE_UNIT = path.join(ROOT, 'packaging/systemd/bonvoyage.service');
const SOURCE_BINARY = '/usr/local/bin/bonvoyage-dataplane';
const PACKAGE_BINARY = '/usr/bin/bonvoyage-dataplane';
const PACKAGE_FRAGMENT = '/usr/lib/systemd/system/bonvoyage.service';
const SHA256 = /^[0-9a-f]{64}$/u;
const CAMPAIGN_ROOT = /^\/run\/bonvoyage-perf06\/[a-z0-9][a-z0-9-]{0,63}$/u;

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

function cpus(spec, label) {
  requireValue(typeof spec === 'string' &&
    /^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$/u.test(spec), `${label} syntax invalid`);
  const values = [];
  for (const part of spec.split(',')) {
    const [start, end = start] = part.split('-').map(Number);
    requireValue(Number.isSafeInteger(start) && Number.isSafeInteger(end) &&
      start <= end && end - start < 4096, `${label} range invalid`);
    for (let cpu = start; cpu <= end; cpu += 1) values.push(cpu);
  }
  requireValue(values.length > 0 && new Set(values).size === values.length,
    `${label} duplicates or empty`);
  return values.sort((a, b) => a - b);
}

function ranges(values) {
  const parts = [];
  for (let index = 0; index < values.length;) {
    const first = values[index];
    let last = first;
    while (index + 1 < values.length && values[index + 1] === last + 1) {
      last = values[++index];
    }
    parts.push(first === last ? String(first) : `${first}-${last}`);
    index += 1;
  }
  return parts.join(',');
}

function mib(value, label) {
  requireValue(Number.isSafeInteger(value) && value > 0 && value <= 1048576,
    `${label} must be a positive MiB integer`);
  return value;
}

function safeNonnegative(value, label) {
  requireValue(Number.isSafeInteger(value) && value >= 0, `${label} must be a nonnegative integer`);
  return value;
}

function nextPowerOfTwo(value) {
  let result = 1;
  while (result < value) result *= 2;
  requireValue(Number.isSafeInteger(result), 'AIO target exceeds safe integer range');
  return result;
}

function runtimeArtifacts(input) {
  const values = [input.runtimeSnapshotFile, input.runtimeSecretsDirectory,
    input.runtimeHostsFile, input.runtimePlanId];
  if (values.every((value) => value === undefined || value === null)) {
    return null;
  }
  requireValue(values.every((value) => typeof value === 'string'),
    'campaign runtime artifact paths must be supplied together');
  const root = path.posix.dirname(input.runtimeSnapshotFile);
  requireValue(CAMPAIGN_ROOT.test(root) &&
    SHA256.test(input.runtimePlanId) &&
    root === `/run/bonvoyage-perf06/policy-${input.runtimePlanId.slice(0, 16)}` &&
    input.runtimeSnapshotFile === `${root}/active.pb` &&
    input.runtimeSecretsDirectory === `${root}/secrets` &&
    input.runtimeHostsFile === `${root}/hosts`,
  'campaign runtime artifacts must use one bounded /run root');
  return {root, plan_id: input.runtimePlanId,
    snapshot_file: input.runtimeSnapshotFile,
    secrets_directory: input.runtimeSecretsDirectory,
    hosts_file: input.runtimeHostsFile};
}

export function buildPackagePlacement(input) {
  const sourceUnit = input.sourceUnit;
  const installedUnit = input.installedUnit;
  requireValue(typeof sourceUnit === 'string' && typeof installedUnit === 'string',
    'both unit contents are required');
  requireValue(sourceUnit.split(SOURCE_BINARY).length === 2,
    'source unit does not contain exactly one dataplane path');
  const expectedUnit = sourceUnit.replace(SOURCE_BINARY, PACKAGE_BINARY);
  requireValue(installedUnit === expectedUnit,
    'installed package unit differs from reviewed source rendering');
  const starts = expectedUnit.split('\n').filter((line) => line.startsWith('ExecStart='));
  requireValue(starts.length === 1 && starts[0].startsWith(`ExecStart=${PACKAGE_BINARY} `) &&
    starts[0].endsWith(' --smp 1 --memory 512M'),
  'package base command changed; review before tuning');
  requireValue(SHA256.test(input.binarySha256), 'binary SHA-256 invalid');
  const host = cpus(input.onlineCpus, 'online CPUs');
  const gateway = cpus(input.gatewayCpus, 'gateway CPUs');
  const irq = cpus(input.irqCpus, 'IRQ CPUs');
  const hostSet = new Set(host);
  requireValue(gateway.every((cpu) => hostSet.has(cpu)) &&
    irq.every((cpu) => hostSet.has(cpu)), 'CPU placement lies outside online host CPUs');
  requireValue(gateway.every((cpu) => !irq.includes(cpu)),
    'gateway and IRQ CPUs must be disjoint');
  const seastar = mib(input.seastarMemoryMiB, 'Seastar memory');
  const high = mib(input.memoryHighMiB, 'MemoryHigh');
  const max = mib(input.memoryMaxMiB, 'MemoryMax');
  requireValue(seastar <= high && high <= max,
    'memory must satisfy Seastar <= MemoryHigh <= MemoryMax');
  const iocbs = safeNonnegative(input.networkIOCbsPerShard, 'network IOCBs per shard');
  requireValue(iocbs >= 10000 && iocbs <= 40000,
    'network IOCB candidate must be within the reviewed 10k-40k range');
  const responsePathDiagnostics = input.responsePathDiagnostics ?? false;
  requireValue(typeof responsePathDiagnostics === 'boolean',
    'response-path diagnostics choice must be boolean');
  const currentAioMax = safeNonnegative(input.currentAioMaxNr, 'current aio-max-nr');
  const currentAio = safeNonnegative(input.currentAioNr, 'current aio-nr');
  requireValue(currentAioMax > 0 && currentAio <= currentAioMax,
    'current AIO registration exceeds its ceiling');
  // The prior 24-shard probe observed 1,026 extra registered IOCBs per shard.
  // Reserve 2,048 per shard, then leave a further 25% host-wide margin.
  const minimumAio = (iocbs + 2048) * gateway.length;
  const targetAio = Math.max(currentAioMax, nextPowerOfTwo(Math.ceil(minimumAio * 1.25)));
  const gatewayList = ranges(gateway);
  const irqList = ranges(irq);
  const banned = ranges(host.filter((cpu) => !irq.includes(cpu)));
  requireValue(banned !== '', 'IRQ placement must leave CPUs excluded from irqbalance');
  const runtime = runtimeArtifacts(input);
  const baseArguments = starts[0].slice('ExecStart='.length)
    .replace(/ --smp 1 --memory 512M$/u, '').split(' ');
  if (runtime !== null) {
    const snapshot = baseArguments.indexOf('--snapshot');
    requireValue(snapshot >= 0 && snapshot + 1 < baseArguments.length,
      'package command does not expose one snapshot argument');
    baseArguments[snapshot + 1] = runtime.snapshot_file;
    baseArguments.push('--secrets-directory', runtime.secrets_directory);
  }
  const base = baseArguments.join(' ');
  const diagnosticsArgument = responsePathDiagnostics ? ' --response-path-diagnostics' : '';
  const iocbArgument = iocbs === 10000 ? '' : ` --max-networking-io-control-blocks ${iocbs}`;
  const hostsBinding = runtime === null ? '' :
    `BindReadOnlyPaths=${runtime.hosts_file}:/etc/hosts:norbind\n`;
  const files = {
    'bonvoyage-resources.conf': `[Service]\nCPUAffinity=${gateway.join(' ')}\nAllowedCPUs=${gatewayList}\nMemoryHigh=${high}M\nMemoryMax=${max}M\n`,
    'bonvoyage-runtime.conf': `[Service]\n${hostsBinding}ExecStart=\nExecStart=${base}${diagnosticsArgument} --smp ${gateway.length} --cpuset ${gatewayList} --memory ${seastar}M${iocbArgument}\n`,
    'irqbalance-exclusion.conf': `[Service]\nEnvironment="IRQBALANCE_BANNED_CPULIST=${banned}"\n`,
    'aio-capacity.conf': `fs.aio-max-nr = ${targetAio}\n`,
  };
  const plan = {schema_version: 1, evidence_class: 'shared-vm-placement-plan',
    measurement_authorized: false, source_unit_sha256: digest(sourceUnit),
    package_unit_sha256: digest(installedUnit), binary_sha256: input.binarySha256,
    expected_fragment_path: PACKAGE_FRAGMENT,
    install_targets: {
      'bonvoyage-resources.conf': '/etc/systemd/system/bonvoyage.service.d/20-perf01-resources.conf',
      'bonvoyage-runtime.conf': '/etc/systemd/system/bonvoyage.service.d/30-perf01-runtime.conf',
      'irqbalance-exclusion.conf': '/etc/systemd/system/irqbalance.service.d/30-perf01-exclusion.conf',
      'aio-capacity.conf': '/etc/sysctl.d/99-bonvoyage-perf01-aio.conf',
    },
    online_cpus: ranges(host), gateway_cpus: gatewayList, irq_cpus: irqList,
    irqbalance_banned_cpus: banned, seastar_memory_mib: seastar,
    memory_high_mib: high, memory_max_mib: max,
    network_iocbs_per_shard: iocbs,
    response_path_diagnostics_enabled: responsePathDiagnostics,
    ...(runtime === null ? {} : {runtime_artifacts: runtime}),
    current_aio_max_nr: currentAioMax,
    current_aio_nr: currentAio, minimum_aio_capacity: minimumAio,
    proposed_aio_max_nr: targetAio,
    file_sha256: Object.fromEntries(Object.entries(files).map(([name, contents]) =>
      [name, digest(contents)])),
    prerequisites: ['Ubuntu 24.04 package service', 'irqbalance active',
      'aws-nitro-irqbalance inactive', 'no foreign drop-ins',
      'host-wide AIO change and prior-value rollback reviewed',
      'independent effective CPU, memory, argv, AIO and NIC IRQ observation']};
  return {plan, files};
}

function option(args, name) {
  const index = args.indexOf(name);
  requireValue(index >= 0 && args[index + 1], `missing ${name}`);
  return args[index + 1];
}

function main() {
  const [, , mode, ...args] = process.argv;
  requireValue(mode === 'plan', 'usage: phase5-package-placement.mjs plan --installed-unit FILE --online-cpus SET --gateway-cpus SET --irq-cpus SET --binary-sha256 SHA --seastar-memory-mib N --memory-high-mib N --memory-max-mib N --iocbs-per-shard N --aio-max-nr N --aio-nr N [--response-path-diagnostics enabled|disabled] --output DIR');
  const names = ['--installed-unit', '--online-cpus', '--gateway-cpus',
    '--irq-cpus', '--binary-sha256', '--seastar-memory-mib',
    '--memory-high-mib', '--memory-max-mib', '--iocbs-per-shard',
    '--aio-max-nr', '--aio-nr', '--output'];
  const diagnosticsOption = '--response-path-diagnostics';
  const runtimeOptions = ['--runtime-snapshot-file',
    '--runtime-secrets-directory', '--runtime-hosts-file',
    '--runtime-plan-id'];
  const suppliedNames = args.filter((_, index) => index % 2 === 0);
  const suppliedValues = args.filter((_, index) => index % 2 === 1);
  const allowedNames = new Set([...names, diagnosticsOption,
    ...runtimeOptions]);
  requireValue(args.length % 2 === 0 &&
    names.every((name) => suppliedNames.filter((value) => value === name).length === 1) &&
    suppliedNames.every((name) => allowedNames.has(name)) &&
    [...allowedNames].every((name) =>
      suppliedNames.filter((value) => value === name).length <= 1) &&
    suppliedValues.every((value) => value !== '' && !value.startsWith('--')),
  'unexpected or duplicate placement option');
  const runtimeOptionCount = runtimeOptions.filter((name) =>
    suppliedNames.includes(name)).length;
  requireValue(runtimeOptionCount === 0 ||
    runtimeOptionCount === runtimeOptions.length,
  'campaign runtime artifact options must be supplied together');
  const diagnosticsMode = args.includes(diagnosticsOption) ?
    option(args, diagnosticsOption) : 'disabled';
  requireValue(['enabled', 'disabled'].includes(diagnosticsMode),
    'response-path diagnostics must be enabled or disabled');
  const output = option(args, '--output');
  const {plan, files} = buildPackagePlacement({
    sourceUnit: fs.readFileSync(SOURCE_UNIT, 'utf8'),
    installedUnit: fs.readFileSync(option(args, '--installed-unit'), 'utf8'),
    onlineCpus: option(args, '--online-cpus'),
    gatewayCpus: option(args, '--gateway-cpus'), irqCpus: option(args, '--irq-cpus'),
    binarySha256: option(args, '--binary-sha256'),
    seastarMemoryMiB: Number(option(args, '--seastar-memory-mib')),
    memoryHighMiB: Number(option(args, '--memory-high-mib')),
    memoryMaxMiB: Number(option(args, '--memory-max-mib')),
    networkIOCbsPerShard: Number(option(args, '--iocbs-per-shard')),
    responsePathDiagnostics: diagnosticsMode === 'enabled',
    currentAioMaxNr: Number(option(args, '--aio-max-nr')),
    currentAioNr: Number(option(args, '--aio-nr')),
    runtimeSnapshotFile: runtimeOptionCount === 0 ? null :
      option(args, '--runtime-snapshot-file'),
    runtimeSecretsDirectory: runtimeOptionCount === 0 ? null :
      option(args, '--runtime-secrets-directory'),
    runtimeHostsFile: runtimeOptionCount === 0 ? null :
      option(args, '--runtime-hosts-file'),
    runtimePlanId: runtimeOptionCount === 0 ? null :
      option(args, '--runtime-plan-id'),
  });
  const sourceCommit = execFileSync('git', ['-C', ROOT, 'rev-parse', 'HEAD'],
    {encoding: 'utf8'}).trim();
  const sourceDirty = execFileSync('git', ['-C', ROOT, 'status', '--porcelain'],
    {encoding: 'utf8'}).trim() !== '';
  plan.source_commit = sourceCommit;
  plan.source_dirty = sourceDirty;
  fs.mkdirSync(output, {mode: 0o700});
  for (const [name, contents] of Object.entries(files)) {
    fs.writeFileSync(path.join(output, name), contents, {mode: 0o600});
  }
  fs.writeFileSync(path.join(output, 'plan.json'), `${JSON.stringify(plan, null, 2)}\n`,
    {mode: 0o600});
  const manifest = [...Object.keys(files), 'plan.json'].sort().map((name) =>
    `${digest(fs.readFileSync(path.join(output, name)))}  ${name}\n`).join('');
  fs.writeFileSync(path.join(output, 'checksums.sha256'), manifest, {mode: 0o600});
  process.stdout.write(`${JSON.stringify({output, source_dirty: sourceDirty,
    package_unit_sha256: plan.package_unit_sha256,
    measurement_authorized: false})}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try { main(); } catch (error) {
    process.stderr.write(`phase5-package-placement: ${error.message}\n`);
    process.exitCode = 1;
  }
}
