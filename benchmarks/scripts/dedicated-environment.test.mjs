import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import {
  REPOSITORY_ROOT,
  evaluatePreflight,
} from './dedicated-preflight.mjs';
import {
  awsCommands,
  buildEnvironmentReport,
  calculateObservation,
  inspectLinuxAMD64Executable,
  inspectTopologyDocument,
  reviewAttemptNames,
  sshArguments,
  verifyRawManifest,
  writeRawManifest,
} from './dedicated-environment.mjs';

const REQUIRED_COMMANDS = [
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
  'nic-eth0-link',
  'nic-eth0-driver',
  'nic-eth0-channels',
  'nic-eth0-rss',
  'nic-eth0-offloads',
  'nic-eth0-coalescing',
  'nic-eth0-statistics',
];

function reference(character) {
  return {path: `evidence/${character}.json`, sha256: character.repeat(64)};
}

function topology(mode = 'rehearsal') {
  const document = {
    schema_version: 1,
    campaign_id: 'phase1-phase3-dedicated-qualification-v1',
    mode,
    source_commit: 'a'.repeat(40),
    observation: {
      idle_seconds: mode === 'qualification' ? 900 : 60,
      maximum_steal_percent: 0.1,
      maximum_network_error_delta: 0,
      required_gateway_physical_cores: [1, 2, 4, 8, 16],
    },
    aws: {
      region: 'ap-southeast-1',
      availability_zone: 'ap-southeast-1a',
      image_id: 'ami-11111111111111111',
    },
    roles: [
      {
        role: 'load-generator',
        ssh_target: 'load-generator',
        instance_id: 'i-11111111111111111',
        instance_type: 'c7a.16xlarge',
        private_ipv4: '10.42.0.11',
        network_interface: 'auto',
        expected_tenancy: 'default',
      },
      {
        role: 'gateway-target',
        ssh_target: 'gateway-target',
        instance_id: 'i-22222222222222222',
        instance_type: 'c7a.16xlarge',
        private_ipv4: '10.42.0.12',
        network_interface: 'auto',
        expected_tenancy: 'default',
      },
      {
        role: 'controlled-upstream',
        ssh_target: 'controlled-upstream',
        instance_id: 'i-33333333333333333',
        instance_type: 'c7a.16xlarge',
        private_ipv4: '10.42.0.13',
        network_interface: 'auto',
        expected_tenancy: 'default',
      },
    ],
  };
  if (mode === 'qualification') {
    document.aws.dedicated_host_id = 'h-11111111111111111';
    const gateway = document.roles.find(({role}) => role === 'gateway-target');
    gateway.expected_tenancy = 'host';
    gateway.expected_host_id = document.aws.dedicated_host_id;
  }
  return document;
}

function preflight(mode = 'strict') {
  const document = JSON.parse(fs.readFileSync(path.join(
    REPOSITORY_ROOT,
    'benchmarks/spec/fixtures/dedicated-preflight.valid.json',
  ), 'utf8'));
  document.mode = mode;
  document.source.commit = 'a'.repeat(40);
  document.source.hardening_commit = 'a'.repeat(40);
  document.allocation_authorized = mode === 'strict';
  if (mode === 'candidate') {
    document.warnings = ['candidate-mode'];
  }
  return document;
}

function instance(input, role, after = false) {
  const placement = {
    AvailabilityZone: 'ap-southeast-1a',
    Tenancy: role.expected_tenancy,
  };
  if (role.expected_tenancy === 'host') {
    placement.HostId = 'h-11111111111111111';
    placement.Affinity = 'host';
  }
  return {
    InstanceId: role.instance_id,
    ImageId: input.aws.image_id,
    InstanceType: role.instance_type,
    Architecture: 'x86_64',
    PrivateIpAddress: role.private_ipv4,
    State: {Name: 'running'},
    Placement: placement,
    MetadataOptions: {
      HttpEndpoint: 'enabled',
      HttpTokens: 'required',
      HttpPutResponseHopLimit: 1,
      State: 'applied',
    },
    LaunchTime: after ? '2026-09-05T00:00:00Z' : '2026-09-05T00:00:00Z',
  };
}

function cloudSnapshot(input, after = false) {
  return {
    instances: {
      Reservations: [{Instances: input.roles.map((role) => instance(input, role, after))}],
    },
    statuses: {
      InstanceStatuses: input.roles.map((role) => ({
        InstanceId: role.instance_id,
        AvailabilityZone: 'ap-southeast-1a',
        InstanceState: {Name: 'running'},
        InstanceStatus: {Status: 'ok'},
        SystemStatus: {Status: 'ok'},
        Events: [],
      })),
    },
    hosts: {
      Hosts: input.aws.dedicated_host_id ? [{
        HostId: 'h-11111111111111111',
        State: 'available',
        AvailabilityZone: 'ap-southeast-1a',
        AutoPlacement: 'off',
        HostRecovery: 'on',
        HostProperties: {
          Cores: 64,
          TotalVCpus: 64,
          InstanceType: 'c7a.16xlarge',
          Sockets: 2,
        },
        Instances: [{
          InstanceId: 'i-22222222222222222',
          InstanceType: 'c7a.16xlarge',
        }],
      }] : [],
    },
  };
}

function inventory(index) {
  const cpus = Array.from({length: 64}, (_, id) => ({
    id,
    core_id: id,
    socket_id: 0,
    numa_node: id < 32 ? 0 : 1,
    online: true,
    siblings: [id],
  }));
  return {
    schema_version: 2,
    captured_at: '2026-09-05T01:00:00Z',
    host: {
      hostname: `fixture-${index}`,
      operating_system: 'linux',
      architecture: 'amd64',
      kernel_release: '6.8.0-fixture',
      machine_id_sha256: String(index).repeat(64),
      boot_id: `boot-${index}`,
      fingerprint_sha256: String(index).repeat(64),
      memory_total_bytes: 137438953472,
      memory_available_bytes: 128849018880,
      swap_total_bytes: 0,
      cgroup_version: 2,
    },
    cloud: {
      provider: 'aws',
      instance_id: [
        'i-11111111111111111',
        'i-22222222222222222',
        'i-33333333333333333',
      ][index - 1],
      instance_type: 'c7a.16xlarge',
      image_id: 'ami-11111111111111111',
      private_ipv4: `10.42.0.${10 + index}`,
      availability_zone: 'ap-southeast-1a',
      region: 'ap-southeast-1',
      architecture: 'x86_64',
    },
    cpu_lists: {online: cpus.map(({id}) => id), isolated: [], nohz_full: []},
    cpus,
    numa_nodes: [
      {id: 0, cpus: cpus.slice(0, 32).map(({id}) => id), distance: [10, 20], memory_total_bytes: 68719476736},
      {id: 1, cpus: cpus.slice(32).map(({id}) => id), distance: [20, 10], memory_total_bytes: 68719476736},
    ],
    interfaces: [{
      name: 'eth0',
      default_route: true,
      operational_state: 'up',
      driver: 'ena',
      pci_bus_address: '0000:00:05.0',
      numa_node: 0,
      mtu: 9001,
      link_speed_mbps: 50000,
      rx_queues: Array.from({length: 16}, (_, queue) => `rx-${queue}`),
      tx_queues: Array.from({length: 16}, (_, queue) => `tx-${queue}`),
      irqs: Array.from({length: 16}, (_, irq) => ({
        irq: 100 + irq,
        configured_affinity_list: String(irq),
        effective_affinity_list: String(irq),
      })),
      hardware_rss_inventory_passed: true,
    }],
    commands: REQUIRED_COMMANDS.map((name) => ({
      name,
      command: name,
      exit_code: 0,
      stdout_path: `raw/${name}.stdout`,
      stderr_path: `raw/${name}.stderr`,
    })),
    warnings: [],
  };
}

function roleEvidence(input) {
  return input.roles.map((role, index) => {
    const hostInventory = inventory(index + 1);
    if (input.mode === 'qualification' && role.role === 'gateway-target') {
      hostInventory.cloud.host_id = input.aws.dedicated_host_id;
    }
    const inventoryReference = reference(String(index + 1));
    const tuningPlans = role.role === 'gateway-target'
      ? input.observation.required_gateway_physical_cores.map((cores, planIndex) => ({
        document: {
          schema_version: 1,
          generated_at: '2026-09-05T01:01:00Z',
          policy_id: 'throughput-balanced-v1',
          policy_sha256: '9'.repeat(64),
          inventory_sha256: inventoryReference.sha256,
          host_fingerprint_sha256: hostInventory.host.fingerprint_sha256,
          mode: 'benchmark-fixed',
          interface: {},
          cpu: {
            gateway_physical_core_count: cores,
            gateway_cpuset: cores === 1 ? '0' : `0-${cores - 1}`,
          },
          memory: {},
          irq: {},
          recommendations: [],
          warnings: [],
        },
        reference: reference(['d', 'e', 'f', 'a', 'b'][planIndex]),
        checksumsValid: true,
      }))
      : [];
    return {
      role: role.role,
      inventory: hostInventory,
      inventoryReference,
      inventoryChecksumsValid: true,
      osRelease: {
        ID: 'ubuntu',
        VERSION_ID: '24.04',
        PRETTY_NAME: 'Ubuntu 24.04.3 LTS',
      },
      observation: {
        duration_seconds: input.observation.idle_seconds,
        steal_percent: 0,
        network_error_delta: 0,
        clock_synchronized_before: true,
        clock_synchronized_after: true,
      },
      tuningPlans,
    };
  });
}

function reportInput(mode = 'rehearsal') {
  const input = topology(mode);
  return {
    topology: input,
    topologyReference: reference('a'),
    preflight: preflight(mode === 'qualification' ? 'strict' : 'candidate'),
    preflightReference: reference('b'),
    hostTuneReference: reference('c'),
    sourceBefore: {commit: 'a'.repeat(40), clean: true},
    sourceAfter: {commit: 'a'.repeat(40), clean: true},
    cloudBefore: cloudSnapshot(input),
    cloudAfter: cloudSnapshot(input, true),
    cloudReferences: ['d', 'e', 'f', '7', '8', '9'].map(reference),
    roleEvidence: roleEvidence(input),
    rawManifest: {
      valid: true,
      entries: 100,
      reference: reference('f'),
    },
    generatedAt: '2026-09-05T01:15:00Z',
  };
}

test('topology requires distinct private roles and the complete CPU plan set', () => {
  assert.deepEqual(inspectTopologyDocument(topology()), {valid: true, errors: []});
  const duplicate = topology();
  duplicate.roles[2].private_ipv4 = duplicate.roles[0].private_ipv4;
  const inspection = inspectTopologyDocument(duplicate);
  assert.equal(inspection.valid, false);
  assert.match(inspection.errors.join('\n'), /repeats private addresses/);

  const publicAddress = topology();
  publicAddress.roles[0].private_ipv4 = '198.51.100.10';
  assert.match(
    inspectTopologyDocument(publicAddress).errors.join('\n'),
    /RFC 1918/,
  );
});

test('topology binds qualification Host IDs only to the gateway', async (t) => {
  assert.deepEqual(inspectTopologyDocument(topology('qualification')), {
    valid: true,
    errors: [],
  });
  for (const mode of ['rehearsal', 'qualification']) {
    for (const role of topology(mode).roles) {
      for (const field of ['expected_tenancy', 'expected_host_id']) {
        await t.test(`${mode} ${role.role} rejects changed ${field}`, () => {
          const input = topology(mode);
          const changed = input.roles.find((entry) => entry.role === role.role);
          changed[field] = field === 'expected_tenancy'
            ? (role.expected_tenancy === 'host' ? 'default' : 'host')
            : 'h-22222222222222222';
          const inspection = inspectTopologyDocument(input);
          assert.equal(inspection.valid, false);
          assert.match(inspection.errors.join('\n'), mode === 'qualification'
            ? /only the gateway on the declared Dedicated Host/
            : /three ordinary default-tenancy instances/);
        });
      }
    }
  }
  const missingGatewayHost = topology('qualification');
  delete missingGatewayHost.roles.find(({role}) => role === 'gateway-target')
    .expected_host_id;
  assert.equal(inspectTopologyDocument(missingGatewayHost).valid, false);
  const missingAuthorizedHost = topology('qualification');
  delete missingAuthorizedHost.aws.dedicated_host_id;
  assert.equal(inspectTopologyDocument(missingAuthorizedHost).valid, false);
});

test('qualification accepts only a Dedicated Host gateway with ordinary support guests', () => {
  const input = reportInput('qualification');
  const expectedHostId = input.topology.aws.dedicated_host_id;
  for (const evidence of input.roleEvidence) {
    assert.equal(evidence.inventory.cloud.host_id,
      evidence.role === 'gateway-target' ? expectedHostId : undefined);
  }
  const candidate = buildEnvironmentReport(input);
  assert.equal(candidate.status, 'review-required');
  assert.equal(candidate.measurement_authorized, false);
  assert.deepEqual(candidate.blockers, []);
  assert.deepEqual(candidate.warnings, ['operator-review']);
  assert.equal(candidate.checks.every(({id, status}) =>
    id === 'operator-review' || status === 'pass'), true);
  assert.deepEqual(candidate.roles.map(({role, tenancy, host_id: hostId}) => ({
    role, tenancy, hostId,
  })), input.topology.roles.map(({role, expected_tenancy: tenancy,
    expected_host_id: hostId}) => ({role, tenancy, hostId})));

  const review = JSON.parse(fs.readFileSync(path.join(
    REPOSITORY_ROOT,
    'benchmarks/spec/fixtures/dedicated-environment-review.valid.json',
  ), 'utf8'));
  review.campaign_id = candidate.campaign_id;
  review.environment_id = candidate.environment_id;
  review.raw_manifest_sha256 = input.rawManifest.reference.sha256;
  input.review = {document: review, reference: reference('8')};
  const accepted = buildEnvironmentReport(input);
  assert.equal(accepted.status, 'accepted');
  assert.equal(accepted.measurement_authorized, true);
  assert.deepEqual(accepted.blockers, []);
  assert.deepEqual(accepted.warnings, []);

  // Review cannot waive incorrect placement, even when every guest reports the same host.
  for (const evidence of input.roleEvidence) {
    evidence.inventory.cloud.host_id = expectedHostId;
  }
  for (const snapshot of [input.cloudBefore, input.cloudAfter]) {
    for (const instance of snapshot.instances.Reservations[0].Instances) {
      instance.Placement.HostId = expectedHostId;
    }
  }
  const misplaced = buildEnvironmentReport(input);
  assert.equal(misplaced.status, 'blocked');
  assert.equal(misplaced.measurement_authorized, false);
  assert.deepEqual(misplaced.blockers, ['private-placement', 'ubuntu-amd64-guest-identity']);
});

test('guest Host ID checks follow each role in rehearsal and qualification', async (t) => {
  for (const mode of ['rehearsal', 'qualification']) {
    for (const role of topology(mode).roles) {
      for (const hostId of [undefined, '', null, false, 0,
        'h-11111111111111111', 'h-22222222222222222']) {
        await t.test(`${mode} ${role.role} Host ID ${JSON.stringify(hostId) ?? 'omitted'}`, () => {
          const input = reportInput(mode);
          const cloud = input.roleEvidence.find((entry) => entry.role === role.role)
            .inventory.cloud;
          if (hostId === undefined) {
            delete cloud.host_id;
          } else {
            cloud.host_id = hostId;
          }
          const valid = role.expected_tenancy === 'host'
            ? hostId === role.expected_host_id
            : hostId === undefined || hostId === '';
          const report = buildEnvironmentReport(input);
          assert.equal(report.status, valid ? 'review-required' : 'blocked');
          assert.equal(report.measurement_authorized, false);
          assert.deepEqual(report.blockers, valid ? [] : ['ubuntu-amd64-guest-identity']);
        });
      }
    }
  }
});

test('cloud Host ID checks reject incorrect placement in either snapshot', async (t) => {
  for (const mode of ['rehearsal', 'qualification']) {
    for (const role of topology(mode).roles) {
      for (const snapshot of ['cloudBefore', 'cloudAfter']) {
        for (const hostId of [undefined, '', null, false, 0,
          'h-11111111111111111', 'h-22222222222222222']) {
          await t.test(`${mode} ${role.role} ${snapshot} Host ID ${JSON.stringify(hostId) ?? 'omitted'}`, () => {
            const input = reportInput(mode);
            const placement = input[snapshot].instances.Reservations[0].Instances
              .find(({InstanceId}) => InstanceId === role.instance_id).Placement;
            if (hostId === undefined) {
              delete placement.HostId;
            } else {
              placement.HostId = hostId;
            }
            const valid = role.expected_tenancy === 'host'
              ? hostId === role.expected_host_id
              : hostId === undefined || hostId === '';
            const report = buildEnvironmentReport(input);
            assert.equal(report.status, valid ? 'review-required' : 'blocked');
            assert.equal(report.measurement_authorized, false);
            assert.deepEqual(report.blockers, valid ? [] : [
              'private-placement',
              ...(role.expected_tenancy === 'host' ? ['dedicated-host-binding'] : []),
            ]);
          });
        }
      }
    }
  }
});

test('matching Host IDs do not excuse wrong cloud tenancy', async (t) => {
  for (const mode of ['rehearsal', 'qualification']) {
    for (const role of topology(mode).roles) {
      for (const snapshot of ['cloudBefore', 'cloudAfter']) {
        await t.test(`${mode} ${role.role} ${snapshot}`, () => {
          const input = reportInput(mode);
          input[snapshot].instances.Reservations[0].Instances
            .find(({InstanceId}) => InstanceId === role.instance_id).Placement.Tenancy =
            role.expected_tenancy === 'host' ? 'default' : 'host';
          const report = buildEnvironmentReport(input);
          assert.equal(report.status, 'blocked');
          assert.equal(report.measurement_authorized, false);
          assert.deepEqual(report.blockers, ['private-placement']);
        });
      }
    }
  }
});

test('guest and cloud agreement cannot authorize a different gateway Host ID', () => {
  const input = reportInput('qualification');
  const wrongHostId = 'h-22222222222222222';
  const gateway = input.topology.roles.find(({role}) => role === 'gateway-target');
  input.roleEvidence.find(({role}) => role === gateway.role).inventory.cloud.host_id =
    wrongHostId;
  for (const snapshot of [input.cloudBefore, input.cloudAfter]) {
    snapshot.instances.Reservations[0].Instances
      .find(({InstanceId}) => InstanceId === gateway.instance_id).Placement.HostId = wrongHostId;
    snapshot.hosts.Hosts[0].HostId = wrongHostId;
  }
  const report = buildEnvironmentReport(input);
  assert.equal(report.status, 'blocked');
  assert.equal(report.measurement_authorized, false);
  assert.deepEqual(report.blockers, [
    'private-placement', 'dedicated-host-binding', 'ubuntu-amd64-guest-identity',
  ]);
});

test('SSH and AWS command construction is bounded and non-interactive', () => {
  const args = sshArguments('ubuntu@gateway-target', [
    '/var/tmp/bonvoyage/bonvoyage-host-tune',
    'inspect',
    '--interface',
    'ens5',
  ]);
  assert.equal(args.includes('BatchMode=yes'), true);
  assert.equal(args.includes('StrictHostKeyChecking=yes'), true);
  assert.equal(args.includes('ubuntu@gateway-target'), true);
  const targetIndex = args.indexOf('ubuntu@gateway-target');
  assert.equal(args[targetIndex - 1], '--');
  assert.equal(args[targetIndex + 1], '/var/tmp/bonvoyage/bonvoyage-host-tune');
  assert.throws(
    () => sshArguments('gateway;touch-bad', ['uname', '-a']),
    /unsafe SSH target/,
  );
  assert.throws(
    () => sshArguments('gateway-target', ['sh', '-c', 'uname; id']),
    /unsafe argument/,
  );

  const commands = awsCommands(topology());
  assert.deepEqual(commands.map(({id}) => id), [
    'describe-instances',
    'describe-instance-status',
  ]);
  const qualificationCommands = awsCommands(topology('qualification'));
  assert.equal(qualificationCommands[2].id, 'describe-hosts');
  assert.equal(
    qualificationCommands[2].argv.includes('h-11111111111111111'),
    true,
  );
});

test('host-tune transfer accepts only an AMD64 ELF executable', () => {
  const elf = Buffer.alloc(64);
  elf[0] = 0x7f;
  elf.write('ELF', 1, 'ascii');
  elf[4] = 2;
  elf[5] = 1;
  elf.writeUInt16LE(62, 18);
  assert.deepEqual(inspectLinuxAMD64Executable(elf), {valid: true});
  elf.writeUInt16LE(183, 18);
  assert.match(inspectLinuxAMD64Executable(elf).error, /AMD64/);
  assert.match(inspectLinuxAMD64Executable(Buffer.from('script')).error, /ELF/);
});

test('idle observation derives steal, drop, duration, and clock state', () => {
  const observation = calculateObservation({
    beforeProcStat: 'cpu  100 0 50 850 0 0 0 0 0 0\n',
    afterProcStat: 'cpu  200 0 100 1700 0 0 0 0 0 0\n',
    beforeLink: JSON.stringify([{stats64: {rx: {errors: 0, dropped: 0}, tx: {errors: 0, dropped: 0}}}]),
    afterLink: JSON.stringify([{stats64: {rx: {errors: 0, dropped: 0}, tx: {errors: 0, dropped: 0}}}]),
    beforeClock: 'NTPSynchronized=yes\n',
    afterClock: 'NTPSynchronized=yes\n',
    startedAt: '2026-09-05T00:00:00Z',
    completedAt: '2026-09-05T00:15:00Z',
  });
  assert.deepEqual(observation, {
    duration_seconds: 900,
    steal_percent: 0,
    network_error_delta: 0,
    clock_synchronized_before: true,
    clock_synchronized_after: true,
  });
});

test('raw evidence manifests reject mutation and unbound files', () => {
  const archiveRoot = path.join(
    REPOSITORY_ROOT,
    'benchmarks/results/local-archives',
  );
  fs.mkdirSync(archiveRoot, {recursive: true});
  const root = fs.mkdtempSync(path.join(archiveRoot, 'environment-manifest-test-'));
  try {
    fs.writeFileSync(path.join(root, 'evidence.txt'), 'original\n');
    const initial = writeRawManifest(root);
    assert.equal(initial.valid, true);
    assert.equal(initial.entries, 1);

    fs.writeFileSync(path.join(root, 'evidence.txt'), 'altered\n');
    assert.equal(verifyRawManifest(root).valid, false);
    fs.writeFileSync(path.join(root, 'evidence.txt'), 'original\n');
    fs.writeFileSync(path.join(root, 'unbound.txt'), 'new\n');
    assert.equal(verifyRawManifest(root).valid, false);
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('review attempts use immutable content-addressed names', () => {
  const environmentId = 'dq-infra-002-aaaaaaaaaaaaaaaa';
  const first = reviewAttemptNames(environmentId, '1'.repeat(64));
  const corrected = reviewAttemptNames(environmentId, '2'.repeat(64));
  assert.notDeepEqual(first, corrected);
  assert.match(first.review, /-1{64}\.json$/u);
  assert.match(first.decision, /-1{64}\.json$/u);
  assert.throws(
    () => reviewAttemptNames(environmentId, '../review'),
    /valid environment ID and digest/,
  );
});

test('complete automated evidence waits for explicit operator review', () => {
  const input = reportInput();
  const candidate = buildEnvironmentReport(input);
  assert.equal(candidate.status, 'review-required');
  assert.equal(candidate.measurement_authorized, false);
  assert.deepEqual(candidate.blockers, []);
  assert.deepEqual(candidate.warnings, [
    'dedicated-host-binding',
    'operator-review',
  ]);

  const review = {
    schema_version: 1,
    campaign_id: candidate.campaign_id,
    environment_id: candidate.environment_id,
    raw_manifest_sha256: input.rawManifest.reference.sha256,
    reviewed_at: '2026-09-05T01:20:00Z',
    reviewer_id_sha256: '8'.repeat(64),
    attestations: {
      unrelated_processes_absent: true,
      scheduled_work_quiesced: true,
      kernel_and_frequency_state_accepted: true,
      cloud_events_and_host_identity_accepted: true,
      clock_state_accepted: true,
      network_noise_accepted: true,
    },
    notes: [],
  };
  const accepted = buildEnvironmentReport({
    ...input,
    review: {document: review, reference: reference('8')},
  });
  assert.equal(accepted.environment_id, candidate.environment_id);
  assert.equal(accepted.status, 'accepted');
  assert.equal(accepted.measurement_authorized, true);
  assert.deepEqual(accepted.blockers, []);
  assert.deepEqual(accepted.warnings, ['dedicated-host-binding']);
});

test('host movement, cloud events, noise, and stale review fail closed', () => {
  const moved = reportInput('qualification');
  moved.cloudAfter.instances.Reservations[0].Instances[1].Placement.HostId =
    'h-22222222222222222';
  const movedReport = buildEnvironmentReport(moved);
  assert.equal(movedReport.status, 'blocked');
  assert.equal(movedReport.blockers.includes('dedicated-host-binding'), true);

  const noisy = reportInput();
  noisy.cloudAfter.statuses.InstanceStatuses[0].Events = [{Code: 'instance-reboot'}];
  noisy.roleEvidence[1].observation.steal_percent = 0.2;
  noisy.roleEvidence[2].observation.network_error_delta = 1;
  const noisyReport = buildEnvironmentReport(noisy);
  assert.equal(noisyReport.blockers.includes('cloud-health-events'), true);
  assert.equal(noisyReport.blockers.includes('idle-noise-observation'), true);

  const changedSource = reportInput();
  changedSource.sourceAfter.clean = false;
  const changedSourceReport = buildEnvironmentReport(changedSource);
  assert.equal(changedSourceReport.blockers.includes('collection-source-state'), true);

  const staleReviewInput = reportInput();
  const candidate = buildEnvironmentReport(staleReviewInput);
  const stale = {
    schema_version: 1,
    campaign_id: candidate.campaign_id,
    environment_id: candidate.environment_id,
    raw_manifest_sha256: '0'.repeat(64),
    reviewed_at: '2026-09-05T01:20:00Z',
    reviewer_id_sha256: '8'.repeat(64),
    attestations: {
      unrelated_processes_absent: true,
      scheduled_work_quiesced: true,
      kernel_and_frequency_state_accepted: true,
      cloud_events_and_host_identity_accepted: true,
      clock_state_accepted: true,
      network_noise_accepted: true,
    },
    notes: [],
  };
  const staleReport = buildEnvironmentReport({
    ...staleReviewInput,
    review: {document: stale, reference: reference('8')},
  });
  assert.equal(staleReport.status, 'blocked');
  assert.equal(staleReport.blockers.includes('operator-review'), true);
});

test('guest identity and tuning-plan checksum mismatches fail closed', () => {
  const wrongGuest = reportInput();
  wrongGuest.roleEvidence[0].inventory.cloud.instance_id =
    'i-99999999999999999';
  const wrongGuestReport = buildEnvironmentReport(wrongGuest);
  assert.equal(wrongGuestReport.status, 'blocked');
  assert.equal(
    wrongGuestReport.blockers.includes('ubuntu-amd64-guest-identity'),
    true,
  );

  const changedPlan = reportInput();
  changedPlan.roleEvidence
    .find(({role}) => role === 'gateway-target')
    .tuningPlans[0].checksumsValid = false;
  const changedPlanReport = buildEnvironmentReport(changedPlan);
  assert.equal(changedPlanReport.status, 'blocked');
  assert.equal(
    changedPlanReport.blockers.includes('fixed-core-tuning-plans'),
    true,
  );
});

test('dedicated environment rejects VM or invalid tuning scopes', () => {
  for (const mode of ['rehearsal', 'qualification']) {
    for (const scope of ['vm-cpu-memory', 'unknown-scope', null, '']) {
      const input = reportInput(mode);
      input.roleEvidence.find(({role}) => role === 'gateway-target')
        .tuningPlans[0].document.scope = scope;
      const report = buildEnvironmentReport(input);
      assert.equal(report.status, 'blocked');
      assert.equal(report.blockers.includes('fixed-core-tuning-plans'), true);
    }
    for (const scope of [undefined, 'full-host']) {
      const input = reportInput(mode);
      input.roleEvidence.find(({role}) => role === 'gateway-target')
        .tuningPlans[0].document.scope = scope;
      const report = buildEnvironmentReport(input);
      assert.equal(report.blockers.includes('fixed-core-tuning-plans'), false);
    }
  }
});

test('AMI, instance size, and IMDS policy substitutions fail closed', () => {
  const substitutedHost = reportInput();
  substitutedHost.cloudAfter.instances.Reservations[0].Instances[0].ImageId =
    'ami-99999999999999999';
  substitutedHost.cloudAfter.instances.Reservations[0].Instances[1].InstanceType =
    'c7a.8xlarge';
  const substitutedHostReport = buildEnvironmentReport(substitutedHost);
  assert.equal(substitutedHostReport.status, 'blocked');
  assert.equal(substitutedHostReport.blockers.includes('private-placement'), true);

  const weakMetadata = reportInput();
  weakMetadata.cloudBefore.instances.Reservations[0].Instances[2]
    .MetadataOptions.HttpTokens = 'optional';
  const weakMetadataReport = buildEnvironmentReport(weakMetadata);
  assert.equal(weakMetadataReport.status, 'blocked');
  assert.equal(
    weakMetadataReport.blockers.includes('imds-v2-enforcement'),
    true,
  );

  const unknownLinkSpeed = reportInput();
  unknownLinkSpeed.roleEvidence[0].inventory.interfaces[0].link_speed_mbps = 0;
  const unknownLinkSpeedReport = buildEnvironmentReport(unknownLinkSpeed);
  assert.equal(unknownLinkSpeedReport.status, 'review-required');
  assert.equal(unknownLinkSpeedReport.blockers.length, 0);
  assert.equal(
    unknownLinkSpeedReport.warnings.includes('link-speed-observability'),
    true,
  );
});

test('qualification mode rejects a candidate-only preflight', () => {
  const input = reportInput('qualification');
  input.preflight = preflight('candidate');
  const report = buildEnvironmentReport(input);
  assert.equal(report.status, 'blocked');
  assert.equal(report.blockers.includes('preflight-chain'), true);
});

// Compose the real decision producer and consumer, rather than editing a ready fixture.
function generatedRehearsalPreflight(input, {missingReceipt = false} = {}) {
  const previous = input.preflight;
  const accepted = (id) => ({...previous.evidence.find((entry) => entry.id === id), valid: true});
  const validationReceipt = accepted('validation-receipt');
  if (missingReceipt) {
    validationReceipt.valid = false;
    validationReceipt.status = 'missing';
  }
  return evaluatePreflight({
    mode: 'rehearsal', generatedAt: previous.generated_at,
    campaign: {id: previous.campaign_id, status: 'pre-execution', hasInfra001: true},
    source: previous.source, auditorHost: previous.auditor_host, bindings: previous.bindings,
    hardening: accepted('local-hardening'), comparator: accepted('comparator-identity'),
    artifactLock: accepted('artifact-lock'), validationReceipt,
  });
}

test('unfrozen rehearsal preflight composes with the three-role environment review gate', () => {
  const input = reportInput();
  input.preflight = generatedRehearsalPreflight(input);
  const report = buildEnvironmentReport(input);
  assert.equal(report.status, 'review-required');
  assert.deepEqual(report.blockers, []);
  assert.equal(report.measurement_authorized, false);
  assert.equal(report.warnings.includes('operator-review'), true);
  assert.equal(input.preflight.allocation_authorized, false);
});

test('rehearsal evidence cannot authorize a Dedicated Host qualification environment', () => {
  const input = reportInput('qualification');
  input.preflight = generatedRehearsalPreflight(input);
  const report = buildEnvironmentReport(input);
  assert.equal(report.status, 'blocked');
  assert.equal(report.blockers.includes('preflight-chain'), true);
  assert.equal(report.measurement_authorized, false);
});

test('rehearsal composition rejects missing receipts and mismatched source', async (t) => {
  for (const condition of ['missing-receipt', 'stale-source']) {
    await t.test(condition, () => {
      const input = reportInput();
      input.preflight = generatedRehearsalPreflight(input, {missingReceipt: condition === 'missing-receipt'});
      if (condition === 'stale-source') input.preflight.source.commit = 'b'.repeat(40);
      const report = buildEnvironmentReport(input);
      assert.equal(report.status, 'blocked');
      assert.equal(report.blockers.includes('preflight-chain'), true);
      assert.equal(report.measurement_authorized, false);
    });
  }
});
