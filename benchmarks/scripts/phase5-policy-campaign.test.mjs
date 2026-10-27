import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {createPolicyRuntimeBundle, sealPolicyCampaignBundle,
  verifyPolicyCampaignBundle, verifyPolicyRuntimeBundle} from
  './phase5-policy-campaign.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const profiles = ['P5-B02', 'P5-C00', 'P5-C01', 'P5-C02', 'P5-C03',
  'P5-C04', 'P5-C05'];

function input() {
  return {schema_version: 2,
    evidence_class: 'shared-vm-directional-campaign-input',
    source: {binary_source_commit: '1'.repeat(40),
      gateway_binary_sha256: sha256('gateway'),
      client_image: `example.test/oha@sha256:${'a'.repeat(64)}`,
      upstream_sha256: sha256('upstream')},
    topology: {roles: [
      {role: 'load_generator', host_id: 'load', private_address: '10.0.0.10'},
      {role: 'gateway', host_id: 'gateway', private_address: '10.0.0.20'},
      {role: 'controlled_upstream', host_id: 'upstream',
        private_address: '10.0.0.30'},
    ], gateway_cpu_set: Array.from({length: 24}, (_, index) => index + 8),
    housekeeping_cpu_set: Array.from({length: 8}, (_, index) => index),
    load_generator_cpu_set: Array.from({length: 16}, (_, index) => index),
    load_generator_lanes: 8, irq_policy: 'irqbalance-observed',
    controlled_upstream: {port: 8081, max_connections_per_shard: 128}},
    placement: {online_cpus: '0-31', gateway_cpus: '8-31',
      irq_cpus: '0-7', seastar_memory_mib: 12288,
      memory_high_mib: 14336, memory_max_mib: 16384,
      network_iocbs_per_shard: 15000, current_aio_max_nr: 65536,
      current_aio_nr: 11026},
    workload: {offered_rps_by_payload: {'256': 24000, '8192': 12000},
      connections: 256, warmup_seconds: 60, measurement_seconds: 60,
      request_timeout_ms: 5000, maximum_cleanup_ms: 5000,
      minimum_delivery_ratio: 0.95, p95_ceiling_ms: 50,
      p99_ceiling_ms: 500, maximum_support_capacity_percent: 80,
      maximum_retained_rss_growth_bytes: 16 * 1024 * 1024,
      maximum_retained_fd_growth: 4},
    jwt: {algorithm: 'RS256', maximum_age_seconds_at_start: 90,
      minimum_remaining_lifetime_seconds_at_end: 30}};
}

function write(filename, value) {
  fs.mkdirSync(path.dirname(filename), {recursive: true, mode: 0o700});
  fs.writeFileSync(filename, value, {mode: 0o600});
}

function fixture(t, mutateInput) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'perf06-campaign-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const value = input();
  mutateInput?.(value);
  write(path.join(directory, 'input.json'),
    `${JSON.stringify(value, null, 2)}\n`);
  for (const [source, target] of [
    ['benchmarks/workloads/policy-cost/phase5-policy-cost.json',
      'catalog.json'],
    ['benchmarks/workloads/policy-cost/header-transform-request.json',
      'requests/header-transform-request.json'],
    ['benchmarks/products/upstream/nginx.conf', 'upstream/nginx.conf'],
  ]) write(path.join(directory, target), fs.readFileSync(path.join(root, source)));
  write(path.join(directory, 'hosts'),
    '127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n' +
    '10.0.0.30 upstream-a upstream-b\n');
  for (const profile of profiles) {
    write(path.join(directory, `snapshots/${profile}.pb`),
      `compiled-${profile}\n`);
  }
  write(path.join(directory, 'secrets/ca.pem'), 'fixture-ca\n');
  write(path.join(directory, 'secrets/server-chain.pem'), 'fixture-chain\n');
  write(path.join(directory, 'secrets/server-key.pem'), 'fixture-key\n');
  const tlsNames = ['ca.pem', 'server-chain.pem', 'server-key.pem'];
  write(path.join(directory, 'secrets/tls-checksums.sha256'), tlsNames
    .map((name) => `${sha256(fs.readFileSync(path.join(directory,
      `secrets/${name}`)))}  ${name}\n`).join(''));
  write(path.join(directory, 'secrets/phase5-policy-api-keys.txt'),
    '0123456789abcdef0123456789abcdef\n');
  const signing = path.join(directory, 'signing');
  const generator = spawnSync('python3', ['-B', path.join(root,
    'scripts/generate-jwt-smoke-material.py'), signing], {encoding: 'utf8'});
  assert.equal(generator.status, 0, generator.stderr);
  fs.rmSync(path.join(signing, 'jwt-tokens.json'));
  write(path.join(directory, 'secrets/phase5-policy-jwks.json'),
    fs.readFileSync(path.join(signing, 'phase3-jwks.json')));
  const sourceUnit = fs.readFileSync(path.join(root,
    'packaging/systemd/bonvoyage.service'), 'utf8');
  const installedUnit = Buffer.from(sourceUnit.replace(
    '/usr/local/bin/bonvoyage-dataplane', '/usr/bin/bonvoyage-dataplane'));
  const result = sealPolicyCampaignBundle({root: directory, input: value,
    installedUnit, sourceCommit: '2'.repeat(40)});
  return {directory, input: value, result};
}

test('PERF-06 campaign seals seven private points without authorizing traffic', (t) => {
  const value = fixture(t);
  assert.equal(value.result.status, 'bundle-verified');
  assert.equal(value.result.point_count, 7);
  assert.equal(value.result.setup_authorized, false);
  assert.equal(value.result.measurement_authorized, false);
  const plan = JSON.parse(fs.readFileSync(path.join(value.directory,
    'plan.json')));
  const campaign = JSON.parse(fs.readFileSync(path.join(value.directory,
    'campaign.json')));
  assert.equal(plan.schema_version, 2);
  assert.deepEqual(plan.input.topology.controlled_upstream,
    {port: 8081, max_connections_per_shard: 128});
  assert.equal(plan.points[0].request_path, '/payload/256');
  assert.equal(plan.points[1].request_path, '/policy/payload/8192');
  assert.equal(campaign.private_bundle, true);
  assert.equal(plan.input.topology.irq_policy, 'irqbalance-observed');
  assert.equal(campaign.gateway_profile, 'irqbalance-active-observed');
  assert.equal(campaign.points.length, 7);
  assert.equal(campaign.points.find((point) => point.profile_id === 'P5-C03')
    .request_artifact, 'secrets/phase5-policy-api-keys.txt');
  assert.equal(JSON.stringify(campaign).includes(
    '0123456789abcdef0123456789abcdef'), false);
  const runtime = fs.readFileSync(path.join(value.directory,
    'placement/bonvoyage-runtime.conf'), 'utf8');
  assert.match(runtime, /BindReadOnlyPaths=\/run\/bonvoyage-perf06\/policy-/u);
  assert.match(runtime, /--snapshot \/run\/bonvoyage-perf06\/policy-[a-f0-9]{16}\/active\.pb/u);
  assert.match(runtime, /--secrets-directory \/run\/bonvoyage-perf06\/policy-[a-f0-9]{16}\/secrets/u);
});

test('PERF-06 campaign preserves the v3 profiled-warmup contract', (t) => {
  const value = fixture(t, (campaignInput) => {
    campaignInput.schema_version = 3;
    campaignInput.workload.profiled_warmup_repetitions = 3;
    campaignInput.jwt.maximum_age_seconds_at_start = 210;
  });
  const plan = JSON.parse(fs.readFileSync(path.join(value.directory,
    'plan.json')));
  assert.equal(plan.schema_version, 3);
  assert.equal(plan.input.workload.profiled_warmup_repetitions, 3);
  assert.equal(plan.input.jwt.maximum_age_seconds_at_start, 210);
  assert.equal(verifyPolicyCampaignBundle(value.directory,
    {requireSource: false}).status, 'bundle-verified');
});

test('PERF-06 campaign emits a verifiable v4 evidence plan', (t) => {
  const value = fixture(t, (campaignInput) => {
    campaignInput.schema_version = 4;
    campaignInput.workload.profiled_warmup_repetitions = 3;
    campaignInput.jwt.maximum_age_seconds_at_start = 210;
  });
  const plan = JSON.parse(fs.readFileSync(path.join(value.directory,
    'plan.json')));
  assert.equal(plan.schema_version, 4);
  assert.equal(plan.input.workload.profiled_warmup_repetitions, 3);
  assert.equal(verifyPolicyCampaignBundle(value.directory,
    {requireSource: false}).status, 'bundle-verified');
});

test('PERF-06 campaign keeps legacy v1 bundles verifiable', (t) => {
  const value = fixture(t, (campaignInput) => {
    campaignInput.schema_version = 1;
    delete campaignInput.topology.controlled_upstream;
  });
  const plan = JSON.parse(fs.readFileSync(path.join(value.directory,
    'plan.json')));
  assert.equal(plan.schema_version, 1);
  assert.equal(verifyPolicyCampaignBundle(value.directory,
    {requireSource: false}).status, 'bundle-verified');
});

test('PERF-06 campaign retains strict IRQ policy when the host can enforce it',
  (t) => {
    const value = fixture(t, (campaignInput) => {
      campaignInput.topology.irq_policy = 'irqbalance-with-gateway-ban';
    });
    const plan = JSON.parse(fs.readFileSync(path.join(value.directory,
      'plan.json')));
    const campaign = JSON.parse(fs.readFileSync(path.join(value.directory,
      'campaign.json')));
    assert.equal(plan.input.topology.irq_policy,
      'irqbalance-with-gateway-ban');
    assert.equal(campaign.gateway_profile, 'irqbalance-active-exclusion');
  });

test('PERF-06 campaign verifier rejects tampering and extra members', (t) => {
  const changed = fixture(t);
  fs.appendFileSync(path.join(changed.directory, 'hosts'), '10.0.0.31 foreign\n');
  assert.throws(() => verifyPolicyCampaignBundle(changed.directory,
    {requireSource: false}), /checksum manifest does not verify/u);

  const extra = fixture(t);
  write(path.join(extra.directory, 'unbound.txt'), 'unbound\n');
  assert.throws(() => verifyPolicyCampaignBundle(extra.directory,
    {requireSource: false}), /membership differs/u);
});

test('PERF-06 runtime bundle excludes signing material and binds one point', (t) => {
  const campaign = fixture(t);
  const runtime = path.join(path.dirname(campaign.directory),
    `${path.basename(campaign.directory)}-runtime`);
  t.after(() => fs.rmSync(runtime, {recursive: true, force: true}));
  const result = createPolicyRuntimeBundle({campaign: campaign.directory,
    profileId: 'P5-B02', output: runtime, requireSource: false});
  assert.equal(result.status, 'runtime-bundle-verified');
  assert.equal(result.profile_id, 'P5-B02');
  assert.equal(fs.existsSync(path.join(runtime, 'signing')), false);
  assert.equal(fs.readFileSync(path.join(runtime, 'active.pb'), 'utf8'),
    'compiled-P5-B02\n');
  assert.equal(verifyPolicyRuntimeBundle(runtime, campaign.directory,
    {requireSource: false}).manifest_sha256, result.manifest_sha256);
  fs.appendFileSync(path.join(runtime, 'hosts'), '10.0.0.31 foreign\n');
  assert.throws(() => verifyPolicyRuntimeBundle(runtime, campaign.directory,
    {requireSource: false}), /checksum manifest does not verify/u);
});
