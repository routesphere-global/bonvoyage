#!/usr/bin/env node

import {spawn, execFileSync} from 'node:child_process';
import {createHash, randomBytes} from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {collectionTimeout, createCollectionSupervisor} from './dedicated-collection-supervisor.mjs';

import {
  REPOSITORY_ROOT,
  digestBuffer,
  schemaErrors,
  sha256File,
  stableJson,
} from './dedicated-preflight.mjs';

const require = createRequire(path.join(REPOSITORY_ROOT, 'package.json'));
const yaml = require('js-yaml');

const TOPOLOGY_SCHEMA =
  'benchmarks/spec/dedicated-environment-topology.schema.json';
const REVIEW_SCHEMA =
  'benchmarks/spec/dedicated-environment-review.schema.json';
const REPORT_SCHEMA =
  'benchmarks/spec/dedicated-environment-report.schema.json';
const PREFLIGHT_SCHEMA = 'benchmarks/spec/dedicated-preflight.schema.json';
const ARCHIVE_ROOT = path.join(
  REPOSITORY_ROOT,
  'benchmarks/results/local-archives',
);
const TUNING_POLICY = path.join(
  REPOSITORY_ROOT,
  'deploy/tuning/policies/throughput-balanced.yaml',
);
const REQUIRED_ROLES = [
  'load-generator',
  'gateway-target',
  'controlled-upstream',
];
const REQUIRED_INVENTORY_COMMANDS = [
  'lscpu',
  'numactl-hardware',
  'lspci',
  'lspci-tree',
  'cpupower-frequency',
  'uname',
  'os-release',
  'kernel-command-line',
  'interrupts',
  'memory',
  'scheduler-stat',
  'network-device-stat',
  'ip-addresses-json',
  'ip-routes-all-json',
  'clock-state',
  'systemd-version',
  'systemd-timers',
  'systemd-running-services',
  'process-snapshot',
  'uptime',
  'clocksource',
  'kernel-warnings',
];
const CLAIM_BOUNDARY =
  'Environment suitability only; no gateway performance, capacity, ' +
  'production-readiness, competitive, security, or marketing claim is authorized.';

function slashPath(value) {
  return value.split(path.sep).join('/');
}

function readJson(absolutePath) {
  return JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
}

function readYaml(absolutePath) {
  return yaml.load(fs.readFileSync(absolutePath, 'utf8'));
}

function currentSourceState() {
  const git = (arguments_) => execFileSync('git', arguments_, {
    cwd: REPOSITORY_ROOT,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout: 10000,
    killSignal: 'SIGKILL',
  }).trim();
  return {
    commit: git(['rev-parse', 'HEAD']),
    clean: git(['status', '--porcelain=v1', '--untracked-files=all']) === '',
  };
}

function parseKeyValue(value) {
  const result = {};
  for (const line of value.split('\n')) {
    if (!line.includes('=')) {
      continue;
    }
    const index = line.indexOf('=');
    result[line.slice(0, index)] = line.slice(index + 1).replace(/^"|"$/gu, '');
  }
  return result;
}

function sameValues(left, right) {
  return stableJson([...left].sort()) === stableJson([...right].sort());
}

function isPrivateIPv4(value) {
  if (net.isIPv4(value) === 0) {
    return false;
  }
  const octets = value.split('.').map(Number);
  return octets[0] === 10 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168);
}

function uniqueValues(values) {
  return new Set(values).size === values.length;
}

export function inspectTopologyDocument(document, {allowTemplate = false} = {}) {
  const errors = schemaErrors(TOPOLOGY_SCHEMA, document);
  if (errors.length > 0) {
    return {valid: false, errors};
  }
  if (!allowTemplate && /^0+$/u.test(document.source_commit)) {
    errors.push('source_commit must identify the selected release candidate');
  }
  if (!sameValues(
    document.roles.map(({role}) => role),
    REQUIRED_ROLES,
  )) {
    errors.push('topology must contain each dedicated role exactly once');
  }
  for (const [field, values] of [
    ['instance IDs', document.roles.map(({instance_id: value}) => value)],
    ['private addresses', document.roles.map(({private_ipv4: value}) => value)],
    ['SSH targets', document.roles.map(({ssh_target: value}) => value)],
  ]) {
    if (!uniqueValues(values)) {
      errors.push(`topology repeats ${field}`);
    }
  }
  if (document.roles.some(({private_ipv4: value}) => !isPrivateIPv4(value))) {
    errors.push('every role must use an RFC 1918 private IPv4 address');
  }
  const gateway = document.roles.find(({role}) => role === 'gateway-target');
  if (document.mode === 'qualification') {
    if (gateway?.expected_tenancy !== 'host' ||
        gateway?.expected_host_id !== document.aws.dedicated_host_id ||
        document.roles.some((role) => role.role !== 'gateway-target' &&
          (role.expected_tenancy !== 'default' || role.expected_host_id))) {
      errors.push(
        'qualification requires only the gateway on the declared Dedicated Host',
      );
    }
  } else if (document.aws.dedicated_host_id ||
      document.roles.some((role) =>
        role.expected_tenancy !== 'default' || role.expected_host_id)) {
    errors.push('rehearsal requires three ordinary default-tenancy instances');
  }
  if (!sameValues(
    document.observation.required_gateway_physical_cores,
    [1, 2, 4, 8, 16],
  )) {
    errors.push('gateway plans must cover exactly 1, 2, 4, 8, and 16 physical cores');
  }
  return {valid: errors.length === 0, errors};
}

export function inspectLinuxAMD64Executable(buffer) {
  if (buffer.length < 20 || buffer[0] !== 0x7f ||
      buffer.toString('ascii', 1, 4) !== 'ELF') {
    return {valid: false, error: 'host-tune executable is not ELF'};
  }
  if (buffer[4] !== 2 || buffer[5] !== 1 || buffer.readUInt16LE(18) !== 62) {
    return {
      valid: false,
      error: 'host-tune executable is not a little-endian Linux AMD64 ELF binary',
    };
  }
  return {valid: true};
}

export function reviewAttemptNames(environmentId, reviewSha256) {
  if (!/^dq-infra-002-[a-f0-9]{16}$/u.test(environmentId) ||
      !/^[a-f0-9]{64}$/u.test(reviewSha256)) {
    throw new Error('review attempt requires a valid environment ID and digest');
  }
  return {
    review: `operator-review-${environmentId}-${reviewSha256}.json`,
    decision: `environment-decision-${environmentId}-${reviewSha256}.json`,
  };
}

export function sshArguments(target, remoteArguments, connectTimeout = 10) {
  if (!/^(?:[A-Za-z0-9][A-Za-z0-9._-]{0,31}@)?[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/u
    .test(target)) {
    throw new Error(`unsafe SSH target: ${target}`);
  }
  if (remoteArguments.some((value) => !/^[A-Za-z0-9_./:=,+-]+$/u.test(value))) {
    throw new Error('remote command contains an unsafe argument');
  }
  return [
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', 'ForwardAgent=no',
    '-o', `ConnectTimeout=${connectTimeout}`,
    '-o', 'ServerAliveInterval=15',
    '-o', 'ServerAliveCountMax=3',
    '-o', 'LogLevel=ERROR',
    '--',
    target,
    ...remoteArguments,
  ];
}

function scpArguments(target, source, destination, connectTimeout = 10) {
  if (!/^(?:[A-Za-z0-9][A-Za-z0-9._-]{0,31}@)?[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/u
    .test(target)) {
    throw new Error(`unsafe SCP target: ${target}`);
  }
  return [
    '-p',
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', 'ForwardAgent=no',
    '-o', `ConnectTimeout=${connectTimeout}`,
    source,
    destination,
  ];
}

export function awsCommands(topology) {
  const instanceIds = topology.roles
    .map(({instance_id: instanceId}) => instanceId)
    .sort();
  const common = ['--no-cli-pager', 'ec2'];
  const ending = ['--region', topology.aws.region, '--output', 'json'];
  const commands = [
    {
      id: 'describe-instances',
      argv: [...common, 'describe-instances', '--instance-ids', ...instanceIds, ...ending],
    },
    {
      id: 'describe-instance-status',
      argv: [
        ...common,
        'describe-instance-status',
        '--include-all-instances',
        '--instance-ids',
        ...instanceIds,
        ...ending,
      ],
    },
  ];
  if (topology.aws.dedicated_host_id) {
    commands.push({
      id: 'describe-hosts',
      argv: [
        ...common,
        'describe-hosts',
        '--host-ids',
        topology.aws.dedicated_host_id,
        ...ending,
      ],
    });
  }
  return commands;
}

function physicalCoreCount(inventory) {
  return new Set(
    inventory.cpus
      .filter(({online}) => online)
      .map(({socket_id: socket, core_id: core}) => `${socket}:${core}`),
  ).size;
}

function selectedInterface(inventory, requested) {
  if (requested !== 'auto') {
    return inventory.interfaces.find(({name}) => name === requested);
  }
  const candidates = inventory.interfaces.filter(({default_route: value}) => value);
  return candidates.length === 1 ? candidates[0] : undefined;
}

function flattenInstances(document) {
  return (document.Reservations ?? [])
    .flatMap(({Instances: instances = []}) => instances);
}

function statusMap(document) {
  return new Map(
    (document.InstanceStatuses ?? []).map((status) => [status.InstanceId, status]),
  );
}

function instanceMap(document) {
  return new Map(flattenInstances(document).map((instance) => [
    instance.InstanceId,
    instance,
  ]));
}

function dedicatedHost(document, expectedHostId) {
  return (document.Hosts ?? []).find(({HostId: hostId}) => hostId === expectedHostId);
}

function matchesExpectedHostId(role, hostId) {
  return role.expected_tenancy === 'host'
    ? Boolean(role.expected_host_id) && hostId === role.expected_host_id
    : role.expected_tenancy === 'default' && (hostId === undefined || hostId === '');
}

function makeCheck(id, valid, passMessage, blockMessage, missingIsWarning = false) {
  if (valid) {
    return {id, status: 'pass', message: passMessage};
  }
  return {
    id,
    status: missingIsWarning ? 'warn' : 'block',
    message: blockMessage,
  };
}

function commandCoverage(inventory, networkInterface) {
  const commands = new Map(inventory.commands.map((command) => [command.name, command]));
  const nicPrefix = `nic-${networkInterface.name.replace(/[^A-Za-z0-9-]/gu, '-')}`;
  const required = [
    ...REQUIRED_INVENTORY_COMMANDS,
    `${nicPrefix}-link`,
    `${nicPrefix}-driver`,
    `${nicPrefix}-channels`,
    `${nicPrefix}-rss`,
    `${nicPrefix}-offloads`,
    `${nicPrefix}-coalescing`,
    `${nicPrefix}-statistics`,
  ];
  const missing = required.filter((name) => !commands.has(name));
  const failed = required.filter((name) => commands.get(name)?.exit_code !== 0);
  return {complete: missing.length === 0 && failed.length === 0, missing, failed};
}

function normalizeRole(topologyRole, instance, roleEvidence) {
  const inventory = roleEvidence.inventory;
  const nic = selectedInterface(inventory, topologyRole.network_interface);
  if (!instance || !nic) {
    throw new Error(`${topologyRole.role} lacks complete cloud or NIC evidence`);
  }
  const osRelease = roleEvidence.osRelease;
  const role = {
    role: topologyRole.role,
    instance_id: instance.InstanceId,
    image_id: instance.ImageId,
    private_ipv4: instance.PrivateIpAddress,
    availability_zone: instance.Placement?.AvailabilityZone ?? 'unknown',
    tenancy: instance.Placement?.Tenancy ?? 'unknown',
    instance_type: instance.InstanceType ?? 'unknown',
    cloud_state: instance.State?.Name ?? 'unknown',
    host_fingerprint_sha256: inventory.host.fingerprint_sha256,
    boot_id: inventory.host.boot_id,
    operating_system: osRelease.PRETTY_NAME ?? 'unknown',
    architecture: inventory.host.architecture,
    kernel_release: inventory.host.kernel_release,
    logical_cpu_count: inventory.cpus.filter(({online}) => online).length,
    physical_core_count: physicalCoreCount(inventory),
    numa_node_count: inventory.numa_nodes.length,
    memory_total_bytes: inventory.host.memory_total_bytes,
    cgroup_version: inventory.host.cgroup_version,
    swap_total_bytes: inventory.host.swap_total_bytes,
    network: {
      interface: nic.name,
      driver: nic.driver,
      pci_bus_address: nic.pci_bus_address,
      numa_node: nic.numa_node,
      mtu: nic.mtu,
      link_speed_mbps: nic.link_speed_mbps,
      rx_queue_count: nic.rx_queues.length,
      tx_queue_count: nic.tx_queues.length,
      irq_count: nic.irqs.length,
      hardware_rss_inventory_passed: nic.hardware_rss_inventory_passed,
    },
    observation: roleEvidence.observation,
    inventory: roleEvidence.inventoryReference,
    tuning_plans: roleEvidence.tuningPlans.map(({document, reference}) => ({
      physical_cores: document.cpu.gateway_physical_core_count,
      gateway_cpuset: document.cpu.gateway_cpuset,
      reference,
    })),
  };
  if (instance.Placement?.HostId) {
    role.host_id = instance.Placement.HostId;
  }
  return role;
}

function reviewInspection(review, context) {
  if (!review) {
    return {present: false, valid: false, errors: []};
  }
  const errors = schemaErrors(REVIEW_SCHEMA, review.document);
  if (errors.length === 0 && review.document.campaign_id !== context.campaignId) {
    errors.push('review campaign differs from the environment');
  }
  if (errors.length === 0 && review.document.environment_id !== context.environmentId) {
    errors.push('review environment ID differs from the collected environment');
  }
  if (errors.length === 0 &&
      review.document.raw_manifest_sha256 !== context.rawManifestSha256) {
    errors.push('review raw-manifest digest differs from the collected environment');
  }
  const values = Object.values(review.document.attestations ?? {});
  if (values.length !== 6 || values.some((value) => value !== true)) {
    errors.push('all six operator attestations must pass');
  }
  return {present: true, valid: errors.length === 0, errors};
}

export function buildEnvironmentReport({
  topology,
  topologyReference,
  preflight,
  preflightReference,
  hostTuneReference,
  sourceBefore,
  sourceAfter,
  cloudBefore,
  cloudAfter,
  cloudReferences,
  roleEvidence,
  rawManifest,
  review,
  generatedAt = new Date().toISOString(),
}) {
  const checks = [];
  const topologyInspection = inspectTopologyDocument(topology);
  checks.push(makeCheck(
    'topology-contract',
    topologyInspection.valid,
    'The three-role topology contract is complete and internally consistent.',
    topologyInspection.errors.join('; '),
  ));

  const sourceStable = sourceBefore?.clean === true && sourceAfter?.clean === true &&
    sourceBefore.commit === topology.source_commit &&
    sourceAfter.commit === topology.source_commit;
  checks.push(makeCheck(
    'collection-source-state',
    sourceStable,
    'The authorized clean source commit remained unchanged throughout collection.',
    'the source tree was dirty or changed before collection completed',
  ));

  const preflightErrors = schemaErrors(PREFLIGHT_SCHEMA, preflight);
  const validPreflightMode = topology.mode === 'qualification'
    ? preflight.mode === 'strict' && preflight.status === 'ready' &&
      preflight.allocation_authorized === true
    : preflight.status === 'ready';
  const preflightValid = preflightErrors.length === 0 && validPreflightMode &&
    preflight.campaign_id === topology.campaign_id &&
    preflight.source?.commit === topology.source_commit &&
    preflight.source?.clean === true && preflight.source?.pushed === true;
  checks.push(makeCheck(
    'preflight-chain',
    preflightValid,
    'The environment is bound to the matching DQ-INFRA-001 source and preflight.',
    preflightErrors.length > 0
      ? preflightErrors.join('; ')
      : 'preflight mode, campaign, source, readiness, or allocation state differs',
  ));

  const beforeInstances = instanceMap(cloudBefore.instances);
  const afterInstances = instanceMap(cloudAfter.instances);
  const beforeStatuses = statusMap(cloudBefore.statuses);
  const afterStatuses = statusMap(cloudAfter.statuses);
  const hostBefore = dedicatedHost(
    cloudBefore.hosts,
    topology.aws.dedicated_host_id,
  );
  const hostAfter = dedicatedHost(
    cloudAfter.hosts,
    topology.aws.dedicated_host_id,
  );

  const expectedInstanceIds = topology.roles.map(({instance_id: value}) => value);
  const exactCloudSet = beforeInstances.size === 3 && afterInstances.size === 3 &&
    expectedInstanceIds.every((id) => beforeInstances.has(id) && afterInstances.has(id));
  checks.push(makeCheck(
    'three-instance-identity',
    exactCloudSet && uniqueValues(expectedInstanceIds),
    'The same three distinct EC2 instances are present before and after observation.',
    'the cloud snapshots do not contain the exact three declared instances',
  ));

  const cloudPlacementValid = topology.roles.every((role) => {
    const before = beforeInstances.get(role.instance_id);
    const after = afterInstances.get(role.instance_id);
    return before?.PrivateIpAddress === role.private_ipv4 &&
      after?.PrivateIpAddress === role.private_ipv4 &&
      before?.ImageId === topology.aws.image_id &&
      after?.ImageId === topology.aws.image_id &&
      before?.InstanceType === role.instance_type &&
      after?.InstanceType === role.instance_type &&
      before?.Placement?.AvailabilityZone === topology.aws.availability_zone &&
      after?.Placement?.AvailabilityZone === topology.aws.availability_zone &&
      before?.Placement?.Tenancy === role.expected_tenancy &&
      after?.Placement?.Tenancy === role.expected_tenancy &&
      matchesExpectedHostId(role, before?.Placement?.HostId) &&
      matchesExpectedHostId(role, after?.Placement?.HostId) &&
      before?.Architecture === 'x86_64' && after?.Architecture === 'x86_64';
  });
  checks.push(makeCheck(
    'private-placement',
    cloudPlacementValid,
    'All roles retain their declared AMI, instance type, private address, Availability Zone, tenancy, Host ID placement, and x86-64 architecture.',
    'a role has an incorrect AMI, instance type, address, Availability Zone, tenancy, Host ID placement, or architecture',
  ));

  const metadataValid = topology.roles.every(({instance_id: instanceId}) => {
    const valid = (instance) => instance?.MetadataOptions?.HttpEndpoint === 'enabled' &&
      instance?.MetadataOptions?.HttpTokens === 'required' &&
      instance?.MetadataOptions?.HttpPutResponseHopLimit === 1 &&
      instance?.MetadataOptions?.State === 'applied';
    return valid(beforeInstances.get(instanceId)) && valid(afterInstances.get(instanceId));
  });
  checks.push(makeCheck(
    'imds-v2-enforcement',
    metadataValid,
    'Every instance enforces IMDSv2 with a native-host response hop limit of one.',
    'an instance allows IMDSv1, disables metadata, changes metadata state, or uses a different hop limit',
  ));

  const gateway = topology.roles.find(({role}) => role === 'gateway-target');
  const gatewayBefore = beforeInstances.get(gateway?.instance_id);
  const gatewayAfter = afterInstances.get(gateway?.instance_id);
  const hostContainsOnlyGateway = (host) => (host?.Instances ?? []).length === 1 &&
    host.Instances[0].InstanceId === gateway?.instance_id &&
    host.Instances[0].InstanceType === gateway?.instance_type;
  const hostBound = Boolean(hostBefore && hostAfter &&
    hostBefore.HostId === hostAfter.HostId &&
    hostBefore.HostId === topology.aws.dedicated_host_id &&
    hostBefore.AvailabilityZone === topology.aws.availability_zone &&
    hostAfter.AvailabilityZone === topology.aws.availability_zone &&
    hostBefore.State === 'available' && hostAfter.State === 'available' &&
    hostBefore.AutoPlacement === 'off' && hostAfter.AutoPlacement === 'off' &&
    hostBefore.HostRecovery === 'on' && hostAfter.HostRecovery === 'on' &&
    hostBefore.HostProperties?.InstanceType === gateway?.instance_type &&
    hostAfter.HostProperties?.InstanceType === gateway?.instance_type &&
    hostContainsOnlyGateway(hostBefore) && hostContainsOnlyGateway(hostAfter) &&
    gatewayBefore?.Placement?.HostId === hostBefore.HostId &&
    gatewayAfter?.Placement?.HostId === hostBefore.HostId &&
    gatewayBefore?.Placement?.Affinity === 'host' &&
    gatewayAfter?.Placement?.Affinity === 'host');
  checks.push(topology.mode === 'qualification'
    ? makeCheck(
      'dedicated-host-binding',
      hostBound,
      'The gateway remains the sole intended resident on the same policy-compliant Dedicated Host.',
      'the gateway Dedicated Host identity, type, state, policy, residency, zone, or affinity is not stable',
    )
    : {
      id: 'dedicated-host-binding',
      status: 'warn',
      message: 'Dedicated Host binding is intentionally not exercised by ordinary-instance rehearsal.',
    });

  const healthValid = topology.roles.every(({instance_id: instanceId}) => {
    const before = beforeStatuses.get(instanceId);
    const after = afterStatuses.get(instanceId);
    const healthy = (status) => status?.InstanceState?.Name === 'running' &&
      status?.InstanceStatus?.Status === 'ok' &&
      status?.SystemStatus?.Status === 'ok' &&
      (status?.Events ?? []).length === 0;
    return beforeInstances.get(instanceId)?.State?.Name === 'running' &&
      afterInstances.get(instanceId)?.State?.Name === 'running' &&
      healthy(before) && healthy(after);
  });
  checks.push(makeCheck(
    'cloud-health-events',
    healthValid,
    'All instances remain running with healthy EC2 checks and no scheduled events.',
    'an instance state, health check, or scheduled-event record is not acceptable',
  ));

  const roleEvidenceByName = new Map(roleEvidence.map((entry) => [entry.role, entry]));
  const normalizedRoles = topology.roles.map((role) => normalizeRole(
    role,
    beforeInstances.get(role.instance_id),
    roleEvidenceByName.get(role.role),
  ));
  const guestIdentityValid = topology.roles.every((role) => {
    const evidence = roleEvidenceByName.get(role.role);
    const cloud = evidence.inventory.cloud;
    return evidence.inventory.schema_version === 2 &&
      evidence.inventory.host.operating_system === 'linux' &&
      evidence.inventory.host.architecture === 'amd64' &&
      evidence.osRelease.ID === 'ubuntu' && evidence.osRelease.VERSION_ID === '24.04' &&
      cloud?.provider === 'aws' && cloud.instance_id === role.instance_id &&
      cloud.instance_type === role.instance_type &&
      cloud.image_id === topology.aws.image_id &&
      cloud.private_ipv4 === role.private_ipv4 &&
      cloud.availability_zone === topology.aws.availability_zone &&
      cloud.region === topology.aws.region && cloud.architecture === 'x86_64' &&
      matchesExpectedHostId(role, cloud.host_id);
  }) && uniqueValues(normalizedRoles.map(({host_fingerprint_sha256: value}) => value));
  checks.push(makeCheck(
    'ubuntu-amd64-guest-identity',
    guestIdentityValid,
    'Every guest is a distinct Ubuntu 24.04 AMD64 host with a retained boot fingerprint.',
    'guest cloud identity, OS, architecture, inventory version, or host fingerprint is not acceptable',
  ));

  const cpuNUMAValid = normalizedRoles.every((role) => role.logical_cpu_count > 0 &&
    role.physical_core_count > 0 && role.numa_node_count > 0 &&
    role.memory_total_bytes > 0 && role.cgroup_version === 2 &&
    role.swap_total_bytes === 0);
  checks.push(makeCheck(
    'cpu-numa-memory',
    cpuNUMAValid,
    'CPU, physical-core, NUMA, memory, cgroup v2, and disabled-swap evidence is complete.',
    'CPU/NUMA/memory evidence is incomplete, cgroup v2 is absent, or swap is enabled',
  ));

  const networkValid = normalizedRoles.every(({network: networkState}) =>
    networkState.driver === 'ena' && networkState.pci_bus_address.length > 0 &&
    networkState.numa_node >= 0 && networkState.mtu >= 1500 &&
    Number.isInteger(networkState.link_speed_mbps) && networkState.link_speed_mbps >= 0 &&
    networkState.rx_queue_count > 0 && networkState.tx_queue_count > 0 &&
    networkState.irq_count > 0 && networkState.hardware_rss_inventory_passed);
  checks.push(makeCheck(
    'ena-queue-irq-topology',
    networkValid,
    'ENA PCI/NUMA, MTU, queue, RSS, and MSI-X IRQ topology is complete.',
    'ENA interface, PCI/NUMA, MTU, queue, RSS, or IRQ evidence is incomplete',
  ));
  const linkSpeedReported = normalizedRoles.every(({network: networkState}) =>
    networkState.link_speed_mbps > 0);
  checks.push(makeCheck(
    'link-speed-observability',
    linkSpeedReported,
    'Every guest reports a positive virtual NIC link speed.',
    'one or more ENA guests report link speed as unknown; DQ-INFRA-003 must establish measured capacity',
    true,
  ));

  const commandEvidenceValid = topology.roles.every((role) => {
    const evidence = roleEvidenceByName.get(role.role);
    const nic = selectedInterface(evidence.inventory, role.network_interface);
    return nic && commandCoverage(evidence.inventory, nic).complete &&
      evidence.inventoryChecksumsValid;
  });
  checks.push(makeCheck(
    'guest-evidence-completeness',
    commandEvidenceValid,
    'Kernel, frequency, route, clock, timer, process, and NIC evidence is checksum-valid.',
    'one or more required guest evidence commands or inventory checksums failed',
  ));

  const observationValid = topology.roles.every((role) => {
    const observation = roleEvidenceByName.get(role.role).observation;
    return observation.duration_seconds >= topology.observation.idle_seconds &&
      observation.steal_percent <= topology.observation.maximum_steal_percent &&
      observation.network_error_delta <=
        topology.observation.maximum_network_error_delta &&
      observation.clock_synchronized_before && observation.clock_synchronized_after;
  });
  checks.push(makeCheck(
    'idle-noise-observation',
    observationValid,
    'The idle window stayed within steal, network-error, and synchronized-clock bounds.',
    'the idle duration, steal time, network counters, or clock state exceeded its bound',
  ));

  const targetEvidence = roleEvidenceByName.get('gateway-target');
  const plannedCoreCounts = targetEvidence.tuningPlans.map(({document}) =>
    document.cpu.gateway_physical_core_count);
  const plansValid = sameValues(
    plannedCoreCounts,
    topology.observation.required_gateway_physical_cores,
  ) &&
    targetEvidence.tuningPlans.every(({document, checksumsValid}) =>
      document.schema_version === 1 && document.mode === 'benchmark-fixed' &&
      (document.scope === undefined || document.scope === 'full-host') &&
      document.host_fingerprint_sha256 === targetEvidence.inventory.host.fingerprint_sha256 &&
      document.inventory_sha256 === targetEvidence.inventoryReference.sha256 &&
      topology.observation.required_gateway_physical_cores.includes(
        document.cpu.gateway_physical_core_count,
      ) && document.warnings.length === 0 && checksumsValid);
  const supportPlansAbsent = roleEvidence
    .filter(({role}) => role !== 'gateway-target')
    .every(({tuningPlans}) => tuningPlans.length === 0);
  checks.push(makeCheck(
    'fixed-core-tuning-plans',
    plansValid && supportPlansAbsent,
    'Checksum-bound 1/2/4/8/16-core plans match the gateway inventory without warnings.',
    'gateway fixed-core plans are missing, stale, duplicated, scope-limited, or contain unresolved warnings',
  ));

  checks.push(makeCheck(
    'raw-evidence-integrity',
    rawManifest.valid,
    `The raw evidence manifest verifies ${rawManifest.entries} immutable files.`,
    rawManifest.error ?? 'the raw evidence manifest did not verify',
  ));

  const identityMaterial = {
    campaign_id: topology.campaign_id,
    mode: topology.mode,
    source_commit: topology.source_commit,
    topology_sha256: topologyReference.sha256,
    preflight_sha256: preflightReference.sha256,
    host_tune_sha256: hostTuneReference.sha256,
    cloud_sha256: cloudReferences.map(({sha256}) => sha256),
    role_inventory_sha256: roleEvidence.map(({inventoryReference}) =>
      inventoryReference.sha256),
    role_plan_sha256: roleEvidence.flatMap(({tuningPlans}) =>
      tuningPlans.map(({reference}) => reference.sha256)),
    raw_manifest_sha256: rawManifest.reference.sha256,
  };
  const environmentId = `dq-infra-002-${digestBuffer(stableJson(identityMaterial)).slice(0, 16)}`;
  const reviewed = reviewInspection(review, {
    campaignId: topology.campaign_id,
    environmentId,
    rawManifestSha256: rawManifest.reference.sha256,
  });
  checks.push(makeCheck(
    'operator-review',
    reviewed.valid,
    'The operator accepted process, timer, kernel, cloud, clock, and network evidence.',
    reviewed.present
      ? reviewed.errors.join('; ')
      : 'operator review is required before measurements begin',
    !reviewed.present,
  ));

  const blockers = checks.filter(({status}) => status === 'block').map(({id}) => id);
  const warnings = checks.filter(({status}) => status === 'warn').map(({id}) => id);
  const status = blockers.length > 0
    ? 'blocked'
    : reviewed.valid ? 'accepted' : 'review-required';
  const evidence = {
    topology: topologyReference,
    preflight: preflightReference,
    host_tune_binary: hostTuneReference,
    raw_manifest: rawManifest.reference,
  };
  if (review?.reference) {
    evidence.review = review.reference;
  }
  const report = {
    schema_version: 1,
    environment_id: environmentId,
    generated_at: generatedAt,
    campaign_id: topology.campaign_id,
    mode: topology.mode,
    evidence_class: topology.mode === 'qualification'
      ? 'native-qualification'
      : 'distributed-rehearsal',
    status,
    measurement_authorized: status === 'accepted',
    source_commit: topology.source_commit,
    evidence,
    cloud: {
      region: topology.aws.region,
      availability_zone: topology.aws.availability_zone,
      image_id: topology.aws.image_id,
      records: cloudReferences,
    },
    roles: normalizedRoles,
    checks,
    blockers,
    warnings,
    claim_boundary: CLAIM_BOUNDARY,
  };
  if (topology.aws.dedicated_host_id) {
    report.cloud.dedicated_host_id = topology.aws.dedicated_host_id;
    report.cloud.host_state_before = hostBefore?.State ?? 'missing';
    report.cloud.host_state_after = hostAfter?.State ?? 'missing';
  }
  if (reviewed.valid) {
    report.review = {
      reviewer_id_sha256: review.document.reviewer_id_sha256,
      reviewed_at: review.document.reviewed_at,
      attestations_passed: 6,
    };
  }
  const reportErrors = schemaErrors(REPORT_SCHEMA, report);
  if (reportErrors.length > 0) {
    throw new Error(`environment report failed its schema: ${reportErrors.join('; ')}`);
  }
  return report;
}

function procStat(value) {
  const line = value.split('\n').find((candidate) => candidate.startsWith('cpu '));
  if (!line) {
    throw new Error('scheduler snapshot has no aggregate CPU row');
  }
  const counters = line.trim().split(/\s+/u).slice(1).map(Number);
  if (counters.length < 8 || counters.some((counter) => !Number.isFinite(counter))) {
    throw new Error('scheduler snapshot has invalid CPU counters');
  }
  return {total: counters.reduce((sum, counter) => sum + counter, 0), steal: counters[7]};
}

function linkErrorCount(value) {
  const links = JSON.parse(value);
  if (!Array.isArray(links) || links.length !== 1) {
    throw new Error('link snapshot must contain exactly one interface');
  }
  const stats = links[0].stats64 ?? links[0].stats;
  const rx = stats?.rx;
  const tx = stats?.tx;
  const counters = [rx?.errors, rx?.dropped, tx?.errors, tx?.dropped];
  if (counters.some((counter) => !Number.isInteger(counter) || counter < 0)) {
    throw new Error('link snapshot lacks non-negative error and drop counters');
  }
  return counters.reduce((sum, counter) => sum + counter, 0);
}

function clockSynchronized(value) {
  return parseKeyValue(value).NTPSynchronized === 'yes';
}

export function calculateObservation({
  beforeProcStat,
  afterProcStat,
  beforeLink,
  afterLink,
  beforeClock,
  afterClock,
  startedAt,
  completedAt,
}) {
  const beforeCPU = procStat(beforeProcStat);
  const afterCPU = procStat(afterProcStat);
  const totalDelta = afterCPU.total - beforeCPU.total;
  const stealDelta = afterCPU.steal - beforeCPU.steal;
  const networkDelta = linkErrorCount(afterLink) - linkErrorCount(beforeLink);
  const durationSeconds = (Date.parse(completedAt) - Date.parse(startedAt)) / 1000;
  if (totalDelta <= 0 || stealDelta < 0 || networkDelta < 0 || durationSeconds < 0) {
    throw new Error('idle observation counters moved backwards or did not advance');
  }
  return {
    duration_seconds: durationSeconds,
    steal_percent: Number(((stealDelta / totalDelta) * 100).toFixed(6)),
    network_error_delta: networkDelta,
    clock_synchronized_before: clockSynchronized(beforeClock),
    clock_synchronized_after: clockSynchronized(afterClock),
  };
}

function archiveDirectory(value, {mustExist = false, mustBeNew = false} = {}) {
  const absolutePath = path.resolve(value);
  const relative = path.relative(ARCHIVE_ROOT, absolutePath);
  if (relative === '' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error('evidence root must be below benchmarks/results/local-archives');
  }
  if (mustExist && (!fs.existsSync(absolutePath) || !fs.statSync(absolutePath).isDirectory())) {
    throw new Error(`evidence root does not exist: ${value}`);
  }
  if (mustBeNew && fs.existsSync(absolutePath)) {
    throw new Error(`evidence root already exists: ${value}`);
  }
  return absolutePath;
}

function fileReference(absolutePath) {
  const relative = path.relative(REPOSITORY_ROOT, absolutePath);
  if (relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative) ||
      !fs.existsSync(absolutePath) || !fs.statSync(absolutePath).isFile()) {
    throw new Error(`evidence file is missing or outside the repository: ${absolutePath}`);
  }
  return {path: slashPath(relative), sha256: sha256File(absolutePath)};
}

function writeJsonExclusive(absolutePath, document) {
  fs.mkdirSync(path.dirname(absolutePath), {recursive: true, mode: 0o700});
  fs.writeFileSync(absolutePath, `${JSON.stringify(document, null, 2)}\n`, {
    flag: 'wx',
    mode: 0o600,
  });
}

function copyExclusive(source, destination, mode = 0o600) {
  fs.mkdirSync(path.dirname(destination), {recursive: true, mode: 0o700});
  fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
  fs.chmodSync(destination, mode);
}

function runFile(command, arguments_, {timeout, maxBuffer, signal}) {
  return new Promise((resolve) => {
    let termination = null;
    let drainTimer;
    let timer;
    const grouped = process.platform !== 'win32';
    const killGroup = () => {
      if (!child.pid) return;
      try {
        if (grouped) process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch (error) {
        if (error.code !== 'ESRCH') termination ??= 'termination-error';
      }
    };
    const drain = () => {
      if (drainTimer) return;
      // A detached descendant can retain a pipe after the transport exits.
      drainTimer = setTimeout(() => {
        termination ??= 'incomplete-output';
        child.stdout?.destroy();
        child.stderr?.destroy();
      }, 1000);
    };
    const terminate = (kind) => {
      termination ??= kind;
      killGroup();
      drain();
    };
    const abort = () => terminate('cancelled');
    const child = spawn(command, arguments_, {
      cwd: REPOSITORY_ROOT,
      detached: grouped,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {...process.env, AWS_PAGER: ''},
    });
    const output = {stdout: [], stderr: []};
    const sizes = {stdout: 0, stderr: 0};
    let spawnError;
    for (const name of ['stdout', 'stderr']) {
      child[name].on('data', (chunk) => {
        const retained = chunk.subarray(0, Math.max(0, maxBuffer - sizes[name]));
        if (retained.length) output[name].push(retained);
        sizes[name] += chunk.length;
        if (sizes[name] > maxBuffer) terminate('output-limit');
      });
    }
    child.once('error', (error) => { spawnError = error; });
    child.once('close', (code, exitSignal) => {
      clearTimeout(timer);
      clearTimeout(drainTimer);
      signal?.removeEventListener('abort', abort);
      const failureKind = termination ?? (spawnError ? 'spawn-error' : exitSignal ? 'signal' : null);
      resolve({
        exitCode: failureKind ? null : code,
        failureKind,
        errorCode: spawnError?.code ?? null,
        signal: exitSignal ?? null,
        stdout: Buffer.concat(output.stdout),
        stderr: Buffer.concat(output.stderr),
      });
    });
    child.once('exit', () => { killGroup(); drain(); });
    timer = setTimeout(() => terminate('timeout'), timeout);
    signal?.addEventListener('abort', abort, {once: true});
    if (signal?.aborted) abort();
  });
}

export async function runCaptured(command, arguments_, outputBase, {
  timeout = 120000,
  maxBuffer = 64 * 1024 * 1024,
  signal,
} = {}) {
  signal?.throwIfAborted();
  if (!Number.isSafeInteger(timeout) || timeout <= 0 || timeout > 300000 ||
      !Number.isSafeInteger(maxBuffer) || maxBuffer <= 0 || maxBuffer > 64 * 1024 * 1024) {
    throw new Error('transport requires positive bounded timeout and output limits');
  }
  fs.mkdirSync(path.dirname(outputBase), {recursive: true, mode: 0o700});
  for (const suffix of ['stdout', 'stderr', 'command.json']) {
    try {
      fs.lstatSync(`${outputBase}.${suffix}`);
      throw new Error(`transport evidence already exists: ${outputBase}.${suffix}`);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  // Reserve the attempt before starting any external operation, including retries.
  writeJsonExclusive(`${outputBase}.started.json`, {
    command, argv: arguments_, timeout_ms: timeout, max_output_bytes: maxBuffer,
    started_at: new Date().toISOString(),
  });
  const result = await runFile(command, arguments_, {timeout, maxBuffer, signal});
  fs.writeFileSync(`${outputBase}.stdout`, result.stdout, {flag: 'wx', mode: 0o600});
  fs.writeFileSync(`${outputBase}.stderr`, result.stderr, {flag: 'wx', mode: 0o600});
  writeJsonExclusive(`${outputBase}.command.json`, {
    command,
    argv: arguments_,
    exit_code: result.exitCode,
    failure_kind: result.failureKind,
    error_code: result.errorCode,
    signal: result.signal,
    cancellation_reason: signal?.aborted ? signal.reason?.kind ?? 'cancelled' : null,
    timeout_ms: timeout,
    completed_at: new Date().toISOString(),
  });
  if (result.failureKind) {
    throw new Error(result.failureKind === 'timeout'
      ? `${command} timed out after ${timeout} ms; evidence: ${outputBase}`
      : `${command} failed (${result.failureKind}); evidence: ${outputBase}`);
  }
  if (result.exitCode !== 0) {
    throw new Error(`${command} failed with exit code ${result.exitCode}`);
  }
  return result.stdout.toString('utf8');
}

async function collectAwsSnapshot(topology, evidenceRoot, label, signal) {
  const directory = path.join(evidenceRoot, 'aws', label);
  const documents = {};
  for (const command of awsCommands(topology)) {
    const outputPath = path.join(directory, command.id);
    const stdout = await runCaptured('aws', command.argv, outputPath, {signal});
    documents[command.id] = JSON.parse(stdout);
    fs.renameSync(`${outputPath}.stdout`, `${outputPath}.json`);
  }
  return {
    instances: documents['describe-instances'],
    statuses: documents['describe-instance-status'],
    hosts: documents['describe-hosts'],
  };
}

function sshBase(role, remoteArguments) {
  return sshArguments(role.ssh_target, remoteArguments);
}

async function runRemote(role, remoteArguments, outputBase, timeout, signal) {
  return runCaptured('ssh', sshBase(role, remoteArguments), outputBase, {timeout, signal});
}

async function transferTo(role, localPath, remotePath, outputBase, signal) {
  return runCaptured(
    'scp',
    scpArguments(role.ssh_target, localPath, `${role.ssh_target}:${remotePath}`),
    outputBase,
    {signal},
  );
}

async function transferDirectoryFrom(role, remotePath, localParent, outputBase, signal) {
  const arguments_ = scpArguments(
    role.ssh_target,
    `${role.ssh_target}:${remotePath}`,
    `${localParent}${path.sep}`,
  );
  arguments_.splice(1, 0, '-r');
  return runCaptured('scp', arguments_, outputBase, {timeout: 300000, signal});
}

export function remoteStage(topology, role, attemptId) {
  if (typeof attemptId !== 'string' || !/^[a-f0-9]{32}$/u.test(attemptId)) {
    throw new Error('collection attempt requires a 128-bit lowercase hex ID');
  }
  const suffix = createHash('sha256')
    .update(`${topology.source_commit}:${role.instance_id}`)
    .digest('hex')
    .slice(0, 10);
  return `/var/tmp/bonvoyage-${topology.campaign_id}-${role.role}-${suffix}-${attemptId}`;
}

async function prepareRemoteRole({
  topology,
  role,
  evidenceRoot,
  hostTunePath,
  tuningPolicyPath,
  attemptId,
  signal,
}) {
  const roleRoot = path.join(evidenceRoot, 'environment', role.role);
  const transportRoot = path.join(roleRoot, 'transport');
  const stage = remoteStage(topology, role, attemptId);
  const remoteBinary = `${stage}/bonvoyage-host-tune`;
  const remotePolicy = `${stage}/throughput-balanced.yaml`;
  const remoteEvidence = `${stage}/evidence`;
  const remote = (argv, outputBase, timeout) => runRemote(role, argv, outputBase, timeout, signal);
  fs.mkdirSync(roleRoot, {recursive: true, mode: 0o700});
  await remote(
    ['mkdir', '--mode=700', '--', stage],
    path.join(transportRoot, '01-create-stage'),
  );
  await remote(
    ['mkdir', '--mode=700', '--', remoteEvidence],
    path.join(transportRoot, '02-create-evidence'),
  );
  await transferTo(
    role,
    hostTunePath,
    remoteBinary,
    path.join(transportRoot, '03-upload-host-tune'),
    signal,
  );
  await transferTo(
    role,
    tuningPolicyPath,
    remotePolicy,
    path.join(transportRoot, '04-upload-policy'),
    signal,
  );
  await remote(
    ['chmod', '700', '--', remoteBinary],
    path.join(transportRoot, '05-chmod-host-tune'),
  );
  const remoteBinaryDigest = (await remote(
    ['sha256sum', '--', remoteBinary],
    path.join(transportRoot, '06-hash-host-tune'),
  )).trim().split(/\s+/u)[0];
  const remotePolicyDigest = (await remote(
    ['sha256sum', '--', remotePolicy],
    path.join(transportRoot, '07-hash-policy'),
  )).trim().split(/\s+/u)[0];
  if (remoteBinaryDigest !== sha256File(hostTunePath) ||
      remotePolicyDigest !== sha256File(tuningPolicyPath)) {
    throw new Error(`${role.role} received a different host utility or tuning policy`);
  }
  await remote(
    [remoteBinary, 'version'],
    path.join(transportRoot, '08-host-tune-version'),
  );
  await remote(
    [
      remoteBinary,
      'inspect',
      '--aws-instance-identity',
      '--interface', role.network_interface,
      '--output', `${remoteEvidence}/host-inventory`,
    ],
    path.join(transportRoot, '09-inspect'),
    300000,
  );
  await transferDirectoryFrom(
    role,
    `${remoteEvidence}/host-inventory`,
    roleRoot,
    path.join(transportRoot, '10-download-inventory'),
    signal,
  );
  const inventoryPath = path.join(roleRoot, 'host-inventory', 'inventory.json');
  const inventory = readJson(inventoryPath);
  const nic = selectedInterface(inventory, role.network_interface);
  if (!nic) {
    throw new Error(`${role.role} does not have one selected network interface`);
  }
  if (role.role === 'gateway-target') {
    let sequence = 11;
    for (const cores of topology.observation.required_gateway_physical_cores) {
      const planName = `host-plan-${cores}`;
      await remote(
        [
          remoteBinary,
          'plan',
          '--inventory', `${remoteEvidence}/host-inventory/inventory.json`,
          '--policy', remotePolicy,
          '--interface', nic.name,
          '--gateway-physical-cores', String(cores),
          '--output', `${remoteEvidence}/${planName}`,
        ],
        path.join(transportRoot, `${String(sequence).padStart(2, '0')}-plan-${cores}`),
        300000,
      );
      sequence += 1;
      await transferDirectoryFrom(
        role,
        `${remoteEvidence}/${planName}`,
        roleRoot,
        path.join(
          transportRoot,
          `${String(sequence).padStart(2, '0')}-download-plan-${cores}`,
        ),
        signal,
      );
      sequence += 1;
    }
  }
  return {role, roleRoot, nic, stage};
}

async function captureObservation(roleState, label, signal) {
  const {role, roleRoot, nic} = roleState;
  const directory = path.join(roleRoot, 'observation', label);
  const commands = [
    ['proc-stat', ['cat', '/proc/stat']],
    ['link', ['ip', '-s', '-j', 'link', 'show', 'dev', nic.name]],
    ['clock', [
      'timedatectl', 'show', '--property=NTPSynchronized', '--property=Timezone',
      '--property=LocalRTC', '--property=TimeUSec',
    ]],
    ['boot-id', ['cat', '/proc/sys/kernel/random/boot_id']],
    ['frequency', ['cpupower', 'frequency-info']],
    ['kernel-warnings', ['dmesg', '--color=never', '--level=err,warn']],
  ];
  for (const [id, argv] of commands) {
    await runRemote(role, argv, path.join(directory, id), 120000, signal);
  }
}

function verifyChecksumFile(directory) {
  const manifestPath = path.join(directory, 'checksums.sha256');
  if (!fs.existsSync(manifestPath)) {
    return {valid: false, entries: 0, error: `${manifestPath} is missing`};
  }
  let entries = 0;
  for (const line of fs.readFileSync(manifestPath, 'utf8').split('\n').filter(Boolean)) {
    const match = /^([a-f0-9]{64})  (.+)$/u.exec(line);
    if (!match) {
      return {valid: false, entries, error: `invalid checksum line: ${line}`};
    }
    const absolutePath = path.resolve(directory, match[2]);
    const relative = path.relative(directory, absolutePath);
    if (relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative) ||
        !fs.existsSync(absolutePath) || sha256File(absolutePath) !== match[1]) {
      return {valid: false, entries, error: `checksum mismatch: ${match[2]}`};
    }
    entries += 1;
  }
  return {valid: entries > 0, entries};
}

function rawFiles(root) {
  const files = [];
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, {withFileTypes: true})) {
      const absolutePath = path.join(current, entry.name);
      const relative = slashPath(path.relative(root, absolutePath));
      if (entry.isSymbolicLink()) {
        throw new Error(`raw evidence contains a symlink: ${relative}`);
      }
      if (entry.isDirectory()) {
        if (relative !== 'reports') {
          pending.push(absolutePath);
        }
      } else if (entry.isFile() &&
          !['raw-checksums.sha256', 'failure.json'].includes(relative)) {
        files.push({absolutePath, relative});
      }
    }
  }
  return files.sort((left, right) => left.relative.localeCompare(right.relative));
}

export function writeRawManifest(root) {
  const manifestPath = path.join(root, 'raw-checksums.sha256');
  const lines = rawFiles(root).map(({absolutePath, relative}) =>
    `${sha256File(absolutePath)}  ./${relative}`);
  fs.writeFileSync(manifestPath, `${lines.join('\n')}\n`, {flag: 'wx', mode: 0o600});
  return verifyRawManifest(root);
}

export function verifyRawManifest(root) {
  const manifestPath = path.join(root, 'raw-checksums.sha256');
  if (!fs.existsSync(manifestPath)) {
    return {
      valid: false,
      entries: 0,
      error: 'raw-checksums.sha256 is missing',
      reference: {path: slashPath(path.relative(REPOSITORY_ROOT, manifestPath)), sha256: '0'.repeat(64)},
    };
  }
  const expected = new Map();
  for (const line of fs.readFileSync(manifestPath, 'utf8').split('\n').filter(Boolean)) {
    const match = /^([a-f0-9]{64})  \.\/(.+)$/u.exec(line);
    if (!match || expected.has(match?.[2])) {
      return {
        valid: false,
        entries: expected.size,
        error: `invalid or duplicate raw checksum line: ${line}`,
        reference: fileReference(manifestPath),
      };
    }
    expected.set(match[2], match[1]);
  }
  const actual = rawFiles(root);
  for (const {absolutePath, relative} of actual) {
    if (expected.get(relative) !== sha256File(absolutePath)) {
      return {
        valid: false,
        entries: expected.size,
        error: `raw evidence mismatch or unbound file: ${relative}`,
        reference: fileReference(manifestPath),
      };
    }
  }
  if (actual.length !== expected.size) {
    return {
      valid: false,
      entries: expected.size,
      error: 'raw manifest references a missing file',
      reference: fileReference(manifestPath),
    };
  }
  return {
    valid: expected.size > 0,
    entries: expected.size,
    reference: fileReference(manifestPath),
  };
}

function cloudReferences(root) {
  return ['before', 'after'].flatMap((label) => [
    'describe-instances',
    'describe-instance-status',
    'describe-hosts',
  ].map((id) => path.join(root, 'aws', label, `${id}.json`))
    .filter((absolutePath) => fs.existsSync(absolutePath))
    .map(fileReference));
}

function loadCloud(root, label) {
  const read = (id) => readJson(path.join(root, 'aws', label, `${id}.json`));
  const hostsPath = path.join(root, 'aws', label, 'describe-hosts.json');
  return {
    instances: read('describe-instances'),
    statuses: read('describe-instance-status'),
    hosts: fs.existsSync(hostsPath) ? read('describe-hosts') : {Hosts: []},
  };
}

function observationOutput(roleRoot, label, id) {
  return fs.readFileSync(
    path.join(roleRoot, 'observation', label, `${id}.stdout`),
    'utf8',
  );
}

function loadRoleEvidence(root, topology, observationWindow) {
  return topology.roles.map((role) => {
    const roleRoot = path.join(root, 'environment', role.role);
    const inventoryDirectory = path.join(roleRoot, 'host-inventory');
    const inventoryPath = path.join(inventoryDirectory, 'inventory.json');
    const inventory = readJson(inventoryPath);
    const osReleasePath = path.join(inventoryDirectory, 'raw', 'os-release.stdout');
    const tuningPlans = role.role === 'gateway-target'
      ? topology.observation.required_gateway_physical_cores.map((cores) => {
        const planDirectory = path.join(roleRoot, `host-plan-${cores}`);
        const planPath = path.join(planDirectory, 'tuning-plan.json');
        return {
          document: readJson(planPath),
          reference: fileReference(planPath),
          checksumsValid: verifyChecksumFile(planDirectory).valid,
        };
      })
      : [];
    const beforeBoot = observationOutput(roleRoot, 'before', 'boot-id').trim();
    const afterBoot = observationOutput(roleRoot, 'after', 'boot-id').trim();
    if (!beforeBoot || beforeBoot !== afterBoot || beforeBoot !== inventory.host.boot_id) {
      throw new Error(`${role.role} boot identity changed during observation`);
    }
    return {
      role: role.role,
      inventory,
      inventoryReference: fileReference(inventoryPath),
      inventoryChecksumsValid: verifyChecksumFile(inventoryDirectory).valid,
      osRelease: parseKeyValue(fs.readFileSync(osReleasePath, 'utf8')),
      observation: calculateObservation({
        beforeProcStat: observationOutput(roleRoot, 'before', 'proc-stat'),
        afterProcStat: observationOutput(roleRoot, 'after', 'proc-stat'),
        beforeLink: observationOutput(roleRoot, 'before', 'link'),
        afterLink: observationOutput(roleRoot, 'after', 'link'),
        beforeClock: observationOutput(roleRoot, 'before', 'clock'),
        afterClock: observationOutput(roleRoot, 'after', 'clock'),
        startedAt: observationWindow.started_at,
        completedAt: observationWindow.completed_at,
      }),
      tuningPlans,
    };
  });
}

function collectionInputs(root) {
  const topologyPath = path.join(root, 'inputs', 'topology.yaml');
  const preflightPath = path.join(root, 'inputs', 'preflight.json');
  const hostTunePath = path.join(root, 'artifacts', 'bonvoyage-host-tune');
  const metadata = readJson(path.join(root, 'collection.json'));
  const topology = readYaml(topologyPath);
  return {
    topology,
    topologyReference: fileReference(topologyPath),
    preflight: readJson(preflightPath),
    preflightReference: fileReference(preflightPath),
    hostTuneReference: fileReference(hostTunePath),
    sourceBefore: readJson(path.join(root, 'inputs', 'source-before.json')),
    sourceAfter: readJson(path.join(root, 'inputs', 'source-after.json')),
    cloudBefore: loadCloud(root, 'before'),
    cloudAfter: loadCloud(root, 'after'),
    cloudReferences: cloudReferences(root),
    roleEvidence: loadRoleEvidence(root, topology, metadata.observation),
    rawManifest: verifyRawManifest(root),
  };
}

function parseArguments(argv) {
  const command = argv[0];
  const allowed = {
    collect: ['--topology', '--preflight', '--host-tune-binary', '--output', '--timeout-seconds'],
    assess: ['--evidence-root', '--review'],
    recover: ['--evidence-root', '--output', '--timeout-seconds'],
  }[command] ?? [];
  const values = {};
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!allowed.includes(key) || value === undefined || Object.hasOwn(values, key)) {
      throw new Error(`invalid argument sequence near ${key ?? '<end>'}`);
    }
    values[key] = value;
  }
  return {command, values};
}

function requiredArgument(values, name) {
  if (!values[name]) {
    throw new Error(`${name} is required`);
  }
  return values[name];
}

export async function runRolePhase(roles, operation) {
  // A failed phase must not return while another role can still append evidence.
  const results = await Promise.allSettled(roles.map(async (role) => operation(role)));
  const failures = results.filter(({status}) => status === 'rejected').map(({reason}) => reason);
  if (failures.length > 0) {
    throw new AggregateError(failures,
      `role phase failed: ${failures.map((error) => error?.message ?? String(error)).join('; ')}`);
  }
  return results.map(({value}) => value);
}

async function collectCommand(values) {
  const topologySource = path.resolve(requiredArgument(values, '--topology'));
  const preflightSource = path.resolve(requiredArgument(values, '--preflight'));
  const hostTuneSource = path.resolve(requiredArgument(values, '--host-tune-binary'));
  const root = archiveDirectory(requiredArgument(values, '--output'), {mustBeNew: true});
  const topology = readYaml(topologySource);
  const timeoutMs = collectionTimeout(values['--timeout-seconds'], topology.observation?.idle_seconds);
  const topologyInspection = inspectTopologyDocument(topology);
  if (!topologyInspection.valid) {
    throw new Error(`invalid topology: ${topologyInspection.errors.join('; ')}`);
  }
  const executableInspection = inspectLinuxAMD64Executable(
    fs.readFileSync(hostTuneSource).subarray(0, 64),
  );
  if (!executableInspection.valid) {
    throw new Error(executableInspection.error);
  }
  const preflight = readJson(preflightSource);
  const preflightErrors = schemaErrors(PREFLIGHT_SCHEMA, preflight);
  const preflightModeValid = topology.mode === 'qualification'
    ? preflight.mode === 'strict' && preflight.status === 'ready' &&
      preflight.allocation_authorized === true
    : preflight.status === 'ready';
  if (preflightErrors.length > 0 || !preflightModeValid ||
      preflight.campaign_id !== topology.campaign_id ||
      preflight.source?.commit !== topology.source_commit ||
      preflight.source?.clean !== true || preflight.source?.pushed !== true) {
    throw new Error(
      `preflight does not authorize this topology: ${preflightErrors.join('; ') ||
        'mode, campaign, source, readiness, or allocation state differs'}`,
    );
  }
  const sourceBefore = currentSourceState();
  if (!sourceBefore.clean || sourceBefore.commit !== topology.source_commit) {
    throw new Error('current source must be clean and match the authorized commit');
  }
  const hostTuneDigest = sha256File(hostTuneSource);
  const tuningPolicyDigest = sha256File(TUNING_POLICY);
  const attemptId = randomBytes(16).toString('hex');
  const remoteStaging = topology.roles.map((role) => ({
    role: role.role, path: remoteStage(topology, role, attemptId),
  }));
  fs.mkdirSync(root, {mode: 0o700});
  const supervisor = createCollectionSupervisor({timeoutMs});
  try {
    // Persist every possible remote path before the first SSH command can fail.
    writeJsonExclusive(path.join(root, 'collection-attempt.json'), {
      schema_version: 1, attempt_id: attemptId,
      source_commit: topology.source_commit, remote_staging: remoteStaging,
      supervision: supervisor.snapshot(),
    });
    copyExclusive(topologySource, path.join(root, 'inputs', 'topology.yaml'));
    copyExclusive(preflightSource, path.join(root, 'inputs', 'preflight.json'));
    copyExclusive(hostTuneSource, path.join(root, 'artifacts', 'bonvoyage-host-tune'), 0o700);
    copyExclusive(TUNING_POLICY, path.join(root, 'artifacts', 'throughput-balanced.yaml'));
    writeJsonExclusive(path.join(root, 'inputs', 'source-before.json'), sourceBefore);

    const retainedHostTune = path.join(root, 'artifacts', 'bonvoyage-host-tune');
    const retainedPolicy = path.join(root, 'artifacts', 'throughput-balanced.yaml');
    if (sha256File(retainedHostTune) !== hostTuneDigest ||
        sha256File(retainedPolicy) !== tuningPolicyDigest) {
      throw new Error('a retained collection artifact changed while it was copied');
    }
    const retainedExecutableInspection = inspectLinuxAMD64Executable(
      fs.readFileSync(retainedHostTune).subarray(0, 64),
    );
    if (!retainedExecutableInspection.valid) {
      throw new Error(retainedExecutableInspection.error);
    }

    const remoteStates = await runRolePhase(topology.roles, (role) =>
      prepareRemoteRole({
        topology,
        role,
        evidenceRoot: root,
        hostTunePath: retainedHostTune,
        tuningPolicyPath: retainedPolicy,
        attemptId,
        signal: supervisor.signal,
      }));
    supervisor.check();
    await collectAwsSnapshot(topology, root, 'before', supervisor.signal);
    await runRolePhase(remoteStates, (state) => captureObservation(state, 'before', supervisor.signal));
    const startedAt = new Date().toISOString();
    await supervisor.wait(topology.observation.idle_seconds * 1000);
    await runRolePhase(remoteStates, (state) => captureObservation(state, 'after', supervisor.signal));
    const completedAt = new Date().toISOString();
    await collectAwsSnapshot(topology, root, 'after', supervisor.signal);
    supervisor.check();
    const sourceAfter = currentSourceState();
    writeJsonExclusive(path.join(root, 'inputs', 'source-after.json'), sourceAfter);
    writeJsonExclusive(path.join(root, 'collection.json'), {
      schema_version: 1,
      campaign_id: topology.campaign_id,
      source_commit: topology.source_commit,
      observation: {started_at: startedAt, completed_at: completedAt},
      attempt_id: attemptId,
      remote_staging: remoteStates.map(({role, stage}) => ({role: role.role, path: stage})),
      cloud_snapshot_count: 2,
      destructive_cleanup_performed: false,
      supervision: supervisor.snapshot(),
    });
    writeRawManifest(root);
    const report = buildEnvironmentReport({
      ...collectionInputs(root),
      generatedAt: new Date().toISOString(),
    });
    supervisor.check();
    writeJsonExclusive(path.join(root, 'reports', 'environment-candidate.json'), report);
    process.stdout.write(
      `${report.status}: ${report.environment_id}\n` +
      `${path.join(root, 'reports', 'environment-candidate.json')}\n`,
    );
    return report;
  } catch (error) {
    supervisor.cancel('operation-failure', error.message);
    const failurePath = path.join(root, 'failure.json');
    if (!fs.existsSync(failurePath)) {
      writeJsonExclusive(failurePath, {
        schema_version: 1,
        failed_at: new Date().toISOString(),
        campaign_id: topology.campaign_id,
        source_commit: topology.source_commit,
        error: error.message,
        attempt_id: attemptId,
        remote_staging: remoteStaging,
        remote_cleanup_performed: false,
        supervision: supervisor.snapshot(),
      });
    }
    throw error;
  } finally {
    supervisor.dispose();
  }
}

export function recoveryObservation({expectedBoot, beforeBoot, afterBoot, processList, stage}) {
  const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u;
  const before = beforeBoot.trim();
  const after = afterBoot.trim();
  const lines = processList.trim().split('\n');
  const validProcesses = lines.length > 0 && lines.every((line) => /^\s*[1-9][0-9]*\s+\S/u.test(line));
  const matching = lines.filter((line) => line.includes(stage));
  const identityMatched = uuid.test(expectedBoot ?? '') && before === expectedBoot && after === before;
  return {
    status: !identityMatched || !validProcesses ? 'unknown'
      : matching.length ? 'activity-observed' : 'no-matching-process-observed',
    expected_boot_id: expectedBoot ?? null,
    boot_id_before: before,
    boot_id_after: after,
    boot_identity_matched: identityMatched,
    process_snapshot_valid: validProcesses,
    matching_process_count: matching.length,
    remote_quiescence_confirmed: false,
    cleanup_authorized: false,
  };
}

async function recoverCommand(values) {
  const original = archiveDirectory(requiredArgument(values, '--evidence-root'), {mustExist: true});
  const root = archiveDirectory(requiredArgument(values, '--output'), {mustBeNew: true});
  // Recovery must never append files to the original, possibly partial collection.
  const realOriginal = fs.realpathSync(original);
  const realParent = fs.realpathSync(path.dirname(root));
  const archive = fs.realpathSync(ARCHIVE_ROOT);
  for (const directory of [realOriginal, realParent]) {
    const relativeArchive = path.relative(archive, directory);
    if (relativeArchive === '..' || relativeArchive.startsWith('..' + path.sep) ||
        path.isAbsolute(relativeArchive)) {
      throw new Error('recovery paths must resolve inside the private archive root');
    }
  }
  const relative = path.relative(realOriginal, realParent);
  if (relative === '' || (relative !== '..' &&
      !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))) {
    throw new Error('recovery output must be outside the original evidence root');
  }
  const timeoutMs = collectionTimeout(values['--timeout-seconds'] ?? '300');
  const topologyPath = path.join(original, 'inputs', 'topology.yaml');
  const attemptPath = path.join(original, 'collection-attempt.json');
  const topologyDigest = sha256File(topologyPath);
  const attemptDigest = sha256File(attemptPath);
  const topology = readYaml(topologyPath);
  const attempt = readJson(attemptPath);
  const inspection = inspectTopologyDocument(topology);
  if (!inspection.valid || attempt.schema_version !== 1 ||
      attempt.source_commit !== topology.source_commit ||
      !/^[a-f0-9]{32}$/u.test(attempt.attempt_id ?? '')) {
    throw new Error('invalid retained topology or collection attempt');
  }
  const stages = topology.roles.map((role) => ({
    role: role.role, path: remoteStage(topology, role, attempt.attempt_id),
  }));
  if (stableJson(stages) !== stableJson(attempt.remote_staging)) {
    throw new Error('retained attempt staging does not match topology');
  }
  fs.mkdirSync(root, {mode: 0o700});
  copyExclusive(topologyPath, path.join(root, 'inputs/topology.yaml'));
  copyExclusive(attemptPath, path.join(root, 'inputs/collection-attempt.json'));
  if (sha256File(path.join(root, 'inputs/topology.yaml')) !== topologyDigest ||
      sha256File(path.join(root, 'inputs/collection-attempt.json')) !== attemptDigest) {
    throw new Error('recovery inputs changed while copying');
  }
  const supervisor = createCollectionSupervisor({timeoutMs});
  try {
    const observations = await runRolePhase(topology.roles, async (role) => {
      const roleRoot = path.join(root, 'observations', role.role);
      const stage = remoteStage(topology, role, attempt.attempt_id);
      let expectedBoot;
      let baselineError = null;
      // A partial download without a checksum binding is not a boot identity baseline.
      try {
        const inventoryRoot = path.join(original, 'environment', role.role, 'host-inventory');
        const inventoryPath = path.join(inventoryRoot, 'inventory.json');
        const digest = sha256File(inventoryPath);
        const manifest = fs.readFileSync(path.join(inventoryRoot, 'checksums.sha256'), 'utf8');
        if (!verifyChecksumFile(inventoryRoot).valid ||
            !manifest.split('\n').some((line) => line === `${digest}  ./inventory.json` ||
              line === `${digest}  inventory.json`)) {
          throw new Error('inventory is not checksum-bound');
        }
        const retained = path.join(root, 'inputs', role.role, 'inventory.json');
        copyExclusive(inventoryPath, retained);
        copyExclusive(path.join(inventoryRoot, 'checksums.sha256'),
          path.join(root, 'inputs', role.role, 'inventory-checksums.sha256'));
        if (sha256File(retained) !== digest) throw new Error('inventory changed while copying');
        expectedBoot = readJson(retained).host?.boot_id;
      } catch (error) {
        baselineError = error.message;
      }
      try {
        const beforeBoot = await runRemote(role, ['cat', '/proc/sys/kernel/random/boot_id'],
          path.join(roleRoot, '01-boot-before'), 30000, supervisor.signal);
        const processList = await runRemote(role, ['ps', '-ww', '-eo', 'pid=,args='],
          path.join(roleRoot, '02-processes'), 30000, supervisor.signal);
        const afterBoot = await runRemote(role, ['cat', '/proc/sys/kernel/random/boot_id'],
          path.join(roleRoot, '03-boot-after'), 30000, supervisor.signal);
        supervisor.check();
        return {role: role.role, stage, baseline_error: baselineError,
          ...recoveryObservation({expectedBoot, beforeBoot, afterBoot, processList, stage})};
      } catch (error) {
        return {role: role.role, stage, status: 'unknown', error: error.message,
          baseline_error: baselineError, remote_quiescence_confirmed: false, cleanup_authorized: false};
      }
    });
    const report = {
      schema_version: 1,
      attempt_id: attempt.attempt_id,
      source_commit: attempt.source_commit,
      generated_at: new Date().toISOString(),
      status: supervisor.signal.aborted || observations.some(({status}) => status === 'unknown')
        ? 'blocked' : 'review-required',
      observations,
      supervision: supervisor.snapshot(),
      requires_operator_review: true,
      remote_quiescence_confirmed: false,
      remote_cleanup_performed: false,
      cleanup_authorized: false,
      measurement_authorized: false,
    };
    writeJsonExclusive(path.join(root, 'recovery.json'), report);
    const manifest = writeRawManifest(root);
    if (!manifest.valid) throw new Error(manifest.error);
    process.stdout.write(`${report.status}: ${path.join(root, 'recovery.json')}\n`);
    if (report.status === 'blocked') process.exitCode = 1;
    return report;
  } finally {
    supervisor.dispose();
  }
}

async function assessCommand(values) {
  const root = archiveDirectory(requiredArgument(values, '--evidence-root'), {
    mustExist: true,
  });
  const reviewSource = path.resolve(requiredArgument(values, '--review'));
  const inputs = collectionInputs(root);
  const preliminary = buildEnvironmentReport({
    ...inputs,
    generatedAt: new Date().toISOString(),
  });
  const reviewDocument = readJson(reviewSource);
  const reviewDigest = sha256File(reviewSource);
  const names = reviewAttemptNames(preliminary.environment_id, reviewDigest);
  const destination = path.join(
    root,
    'reports',
    names.review,
  );
  copyExclusive(reviewSource, destination);
  const report = buildEnvironmentReport({
    ...inputs,
    review: {document: reviewDocument, reference: fileReference(destination)},
    generatedAt: new Date().toISOString(),
  });
  const reportPath = path.join(
    root,
    'reports',
    names.decision,
  );
  writeJsonExclusive(reportPath, report);
  process.stdout.write(`${report.status}: ${report.environment_id}\n${reportPath}\n`);
  if (!report.measurement_authorized) {
    process.exitCode = 1;
  }
  return report;
}

async function main(argv) {
  const {command, values} = parseArguments(argv);
  if (command === 'collect') {
    await collectCommand(values);
    return;
  }
  if (command === 'assess') {
    await assessCommand(values);
    return;
  }
  if (command === 'recover') {
    await recoverCommand(values);
    return;
  }
  throw new Error(
    'usage: dedicated-environment.mjs collect --topology FILE --preflight FILE ' +
    '--host-tune-binary FILE --output DIRECTORY [--timeout-seconds SECONDS]\n' +
    '       dedicated-environment.mjs assess --evidence-root DIRECTORY --review FILE\n' +
    '       dedicated-environment.mjs recover --evidence-root DIRECTORY --output NEW_DIRECTORY ' +
    '[--timeout-seconds SECONDS]',
  );
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`dedicated-environment: ${error.message}\n`);
    process.exitCode = 1;
  });
}
