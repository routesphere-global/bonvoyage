#!/usr/bin/env node

import {spawnSync} from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';

import {buildPackagePlacement} from './phase5-package-placement.mjs';
import {verifyPlacementBundle} from './phase5-package-preflight.mjs';
import {policyCostCollectorIdentity} from './phase5-policy-cost-executor.mjs';
import {buildPolicyCostPlan, validatePolicyCostPlan} from
  './phase5-policy-cost.mjs';
import {validateTlsBundle} from './phase5-protocol-p5-t01-executor.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const CATALOG = path.join(ROOT,
  'benchmarks/workloads/policy-cost/phase5-policy-cost.json');
const HEADER_REQUEST = path.join(ROOT,
  'benchmarks/workloads/policy-cost/header-transform-request.json');
const UPSTREAM_CONFIG = path.join(ROOT,
  'benchmarks/products/upstream/nginx.conf');
const GENERATE_JWT = path.join(ROOT, 'scripts/generate-jwt-smoke-material.py');
const SOURCE_UNIT = path.join(ROOT, 'packaging/systemd/bonvoyage.service');
const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const IMAGE = /^\S+@sha256:([0-9a-f]{64})$/u;
const IRQ_POLICY_TO_PROFILE = Object.freeze({
  'irqbalance-with-gateway-ban': 'irqbalance-active-exclusion',
  'irqbalance-observed': 'irqbalance-active-observed',
});
const PROFILE_FIXTURES = Object.freeze({
  'P5-B02': 'tests/fixtures/phase5-baseline-base.yaml',
  'P5-C00': 'tests/fixtures/phase5-policy-c00.yaml',
  'P5-C01': 'tests/fixtures/phase5-policy-c01.yaml',
  'P5-C02': 'tests/fixtures/phase5-policy-c02.yaml',
  'P5-C03': 'tests/fixtures/phase5-policy-c03.yaml',
  'P5-C04': 'tests/fixtures/phase5-policy-c04.yaml',
  'P5-C05': 'tests/fixtures/phase5-policy-c05.yaml',
});
const EXPECTED_FILES = Object.freeze([
  'campaign.json', 'catalog.json', 'hosts', 'input.json', 'plan.json',
  'placement/aio-capacity.conf',
  'placement/bonvoyage-resources.conf',
  'placement/bonvoyage-runtime.conf',
  'placement/checksums.sha256',
  'placement/irqbalance-exclusion.conf',
  'placement/plan.json',
  'requests/header-transform-request.json',
  'secrets/ca.pem', 'secrets/phase5-policy-api-keys.txt',
  'secrets/phase5-policy-jwks.json', 'secrets/server-chain.pem',
  'secrets/server-key.pem', 'secrets/tls-checksums.sha256',
  'signing/jwt-private.pem', 'signing/phase3-jwks.json',
  ...Object.keys(PROFILE_FIXTURES).map((id) => `snapshots/${id}.pb`),
  'upstream/nginx.conf',
]);
const RUNTIME_FILES = Object.freeze([
  'active.pb', 'hosts', 'runtime.json',
  'secrets/ca.pem', 'secrets/phase5-policy-api-keys.txt',
  'secrets/phase5-policy-jwks.json', 'secrets/server-chain.pem',
  'secrets/server-key.pem',
]);

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function exactKeys(value, keys, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value) &&
    isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort()),
  `${label} has missing or unexpected keys`);
}

function readRegular(filename, label, maximum = 256 * 1024 * 1024) {
  const absolute = path.resolve(filename);
  const stat = fs.lstatSync(absolute);
  requireValue(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.size > 0 && stat.size <= maximum,
  `${label} must be a bounded regular non-symlink file`);
  return fs.readFileSync(absolute);
}

function write(filename, value, mode = 0o600) {
  fs.mkdirSync(path.dirname(filename), {recursive: true, mode: 0o700});
  fs.writeFileSync(filename, value, {mode, flag: 'wx'});
}

function writeJson(filename, value) {
  write(filename, `${JSON.stringify(value, null, 2)}\n`);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {cwd: options.cwd, encoding: 'utf8',
    input: options.input, maxBuffer: 64 * 1024 * 1024});
  requireValue(result.error === undefined,
    `${options.label ?? command} failed to start: ${result.error?.message}`);
  requireValue(result.status === 0,
    `${options.label ?? command} exited ${result.status}: ${result.stderr.trim()}`);
  return result;
}

function sourceState() {
  const commit = run('git', ['-C', ROOT, 'rev-parse', 'HEAD'],
    {label: 'source commit'}).stdout.trim();
  const status = run('git', ['-C', ROOT, 'status', '--porcelain'],
    {label: 'source status'}).stdout;
  requireValue(COMMIT.test(commit) && status === '',
    'PERF-06 campaign freeze requires clean committed source');
  return commit;
}

function listFiles(root) {
  const result = [];
  const visit = (directory) => {
    for (const name of fs.readdirSync(directory).sort()) {
      const absolute = path.join(directory, name);
      const stat = fs.lstatSync(absolute);
      requireValue(!stat.isSymbolicLink(),
        'PERF-06 campaign bundle contains a symlink');
      if (stat.isDirectory()) visit(absolute);
      else {
        requireValue(stat.isFile() && stat.nlink === 1,
          'PERF-06 campaign bundle contains a non-regular member');
        result.push(path.relative(root, absolute).split(path.sep).join('/'));
      }
    }
  };
  visit(root);
  return result;
}

function exactManifest(root, names) {
  return names.map((name) =>
    `${sha256(readRegular(path.join(root, name), `campaign ${name}`))}  ${name}\n`)
    .join('');
}

function validateInput(value) {
  exactKeys(value, ['schema_version', 'evidence_class', 'source', 'topology',
    'placement', 'workload', 'jwt'], 'PERF-06 campaign input');
  requireValue([1, 2, 3, 4].includes(value.schema_version) &&
    value.evidence_class === 'shared-vm-directional-campaign-input',
  'PERF-06 campaign input header is invalid');
  exactKeys(value.source, ['binary_source_commit', 'gateway_binary_sha256',
    'client_image', 'upstream_sha256'], 'PERF-06 campaign source');
  requireValue(COMMIT.test(value.source.binary_source_commit) &&
    SHA256.test(value.source.gateway_binary_sha256) &&
    SHA256.test(value.source.upstream_sha256) &&
    IMAGE.test(value.source.client_image),
  'PERF-06 campaign source identity is invalid');
  const topologyKeys = ['roles', 'gateway_cpu_set',
    'housekeeping_cpu_set', 'load_generator_cpu_set',
    'load_generator_lanes', 'irq_policy'];
  if (value.schema_version >= 2) topologyKeys.push('controlled_upstream');
  exactKeys(value.topology, topologyKeys, 'PERF-06 campaign topology');
  requireValue(Object.hasOwn(IRQ_POLICY_TO_PROFILE, value.topology.irq_policy),
    'PERF-06 campaign IRQ policy is unsupported');
  if (value.schema_version >= 2) {
    exactKeys(value.topology.controlled_upstream,
      ['port', 'max_connections_per_shard'],
      'PERF-06 campaign controlled-upstream contract');
    requireValue(Number.isSafeInteger(value.topology.controlled_upstream.port) &&
      value.topology.controlled_upstream.port > 0 &&
      value.topology.controlled_upstream.port <= 65535 &&
      Number.isSafeInteger(
        value.topology.controlled_upstream.max_connections_per_shard) &&
      value.topology.controlled_upstream.max_connections_per_shard > 0,
    'PERF-06 campaign controlled-upstream contract is invalid');
  }
  exactKeys(value.placement, ['online_cpus', 'gateway_cpus', 'irq_cpus',
    'seastar_memory_mib', 'memory_high_mib', 'memory_max_mib',
    'network_iocbs_per_shard', 'current_aio_max_nr', 'current_aio_nr'],
  'PERF-06 campaign placement');
  return value;
}

function hostsBytes(input) {
  const upstream = input.topology.roles.find((item) =>
    item.role === 'controlled_upstream');
  requireValue(upstream && typeof upstream.private_address === 'string',
    'PERF-06 campaign input omits the controlled upstream');
  return Buffer.from('127.0.0.1 localhost\n' +
    '::1 localhost ip6-localhost ip6-loopback\n' +
    `${upstream.private_address} upstream-a upstream-b\n`, 'ascii');
}

function requestArtifact(point) {
  if (point.request.mode === 'static-json') {
    return 'requests/header-transform-request.json';
  }
  if (point.request.mode === 'secret-file') {
    return 'secrets/phase5-policy-api-keys.txt';
  }
  return null;
}

function campaignMetadata(plan, placement, root) {
  const runtimeRoot = placement.runtime_artifacts.root;
  return {schema_version: 1, checkpoint: 'PERF-06',
    evidence_class: 'private-shared-vm-campaign-bundle',
    source_commit: plan.input.source.harness_commit, source_dirty: false,
    plan_id: plan.plan_id, runtime_root: runtimeRoot,
    gateway_profile: IRQ_POLICY_TO_PROFILE[plan.input.topology.irq_policy],
    active_snapshot_file: `${runtimeRoot}/active.pb`,
    secrets_directory: `${runtimeRoot}/secrets`,
    hosts_file: `${runtimeRoot}/hosts`,
    placement_manifest_sha256: sha256(readRegular(path.join(root,
      'placement/checksums.sha256'), 'placement manifest')),
    tls_bundle_sha256: plan.input.source.tls_bundle_sha256,
    points: plan.points.map((point) => ({point_id: point.point_id,
      profile_id: point.profile_id,
      snapshot_file: `snapshots/${point.profile_id}.pb`,
      snapshot_sha256: point.snapshot_sha256,
      request_mode: point.request.mode,
      request_artifact: requestArtifact(point)})),
    jwt_signing_directory: 'signing', private_bundle: true,
    setup_authorized: false, measurement_authorized: false,
    publication_authorized: false};
}

function planInput(input, root, sourceCommit) {
  const client = IMAGE.exec(input.source.client_image);
  const snapshotSha = Object.fromEntries(Object.keys(PROFILE_FIXTURES).map(
    (id) => [id, sha256(readRegular(path.join(root, `snapshots/${id}.pb`),
      `${id} snapshot`))]));
  const value = {evidence_class: 'shared-vm-directional',
    catalog_sha256: sha256(readRegular(path.join(root, 'catalog.json'),
      'campaign catalog')),
    source: {binary_source_commit: input.source.binary_source_commit,
      harness_commit: sourceCommit, source_dirty: false,
      gateway_binary_sha256: input.source.gateway_binary_sha256,
      client_sha256: client[1], upstream_sha256: input.source.upstream_sha256,
      collector_bundle_sha256: policyCostCollectorIdentity().sha256,
      tls_bundle_sha256: sha256(readRegular(path.join(root,
        'secrets/tls-checksums.sha256'), 'TLS bundle manifest'))},
    topology: input.topology,
    artifacts: {p5_b02_snapshot_sha256: snapshotSha['P5-B02'],
      profile_snapshot_sha256: Object.fromEntries(Object.entries(snapshotSha)
        .filter(([id]) => id !== 'P5-B02')),
      header_transform_request_sha256: sha256(readRegular(path.join(root,
        'requests/header-transform-request.json'), 'header request')),
      api_key_credential_sha256: sha256(readRegular(path.join(root,
        'secrets/phase5-policy-api-keys.txt'), 'API-key credential')),
      jwt_jwks_sha256: sha256(readRegular(path.join(root,
        'secrets/phase5-policy-jwks.json'), 'JWT JWKS'))},
    workload: input.workload, jwt: input.jwt};
  if (input.schema_version >= 2) value.schema_version = input.schema_version;
  return value;
}

function placementInput(input, installedUnit, runtimeRoot, runtimePlanId) {
  return {sourceUnit: readRegular(SOURCE_UNIT, 'source package unit').toString(),
    installedUnit: installedUnit.toString(),
    onlineCpus: input.placement.online_cpus,
    gatewayCpus: input.placement.gateway_cpus,
    irqCpus: input.placement.irq_cpus,
    binarySha256: input.source.gateway_binary_sha256,
    seastarMemoryMiB: input.placement.seastar_memory_mib,
    memoryHighMiB: input.placement.memory_high_mib,
    memoryMaxMiB: input.placement.memory_max_mib,
    networkIOCbsPerShard: input.placement.network_iocbs_per_shard,
    responsePathDiagnostics: false,
    currentAioMaxNr: input.placement.current_aio_max_nr,
    currentAioNr: input.placement.current_aio_nr,
    runtimeSnapshotFile: `${runtimeRoot}/active.pb`,
    runtimeSecretsDirectory: `${runtimeRoot}/secrets`,
    runtimeHostsFile: `${runtimeRoot}/hosts`,
    runtimePlanId};
}

export function sealPolicyCampaignBundle(options) {
  const root = path.resolve(options.root);
  const input = validateInput(options.input);
  requireValue(COMMIT.test(options.sourceCommit),
    'PERF-06 campaign source commit is invalid');
  requireValue(!fs.existsSync(path.join(root, 'plan.json')) &&
    !fs.existsSync(path.join(root, 'campaign.json')) &&
    !fs.existsSync(path.join(root, 'checksums.sha256')),
  'PERF-06 campaign metadata already exists');
  const plan = buildPolicyCostPlan(planInput(input, root,
    options.sourceCommit), readRegular(path.join(root, 'catalog.json'),
    'campaign catalog'));
  writeJson(path.join(root, 'plan.json'), plan);
  const runtimeRoot = `/run/bonvoyage-perf06/policy-${plan.plan_id.slice(0, 16)}`;
  const placement = buildPackagePlacement(placementInput(input,
    options.installedUnit, runtimeRoot, plan.plan_id));
  placement.plan.source_commit = options.sourceCommit;
  placement.plan.source_dirty = false;
  const placementRoot = path.join(root, 'placement');
  for (const [name, bytes] of Object.entries(placement.files)) {
    write(path.join(placementRoot, name), bytes);
  }
  writeJson(path.join(placementRoot, 'plan.json'), placement.plan);
  const placementNames = [...Object.keys(placement.files), 'plan.json'].sort();
  write(path.join(placementRoot, 'checksums.sha256'),
    exactManifest(placementRoot, placementNames));
  writeJson(path.join(root, 'campaign.json'), campaignMetadata(plan,
    placement.plan, root));
  const names = [...EXPECTED_FILES].sort();
  requireValue(isDeepStrictEqual(listFiles(root).sort(), names),
    'PERF-06 campaign staging membership differs from the contract');
  write(path.join(root, 'checksums.sha256'), exactManifest(root, names));
  return verifyPolicyCampaignBundle(root, {requireSource: false});
}

function verifyJwtIdentity(root) {
  const signing = path.join(root, 'signing');
  const output = fs.mkdtempSync(path.join(os.tmpdir(), 'perf06-jwt-verify-'));
  try {
    run('python3', ['-B', GENERATE_JWT, output, '--lifetime-seconds', '120',
      '--reuse-key-directory', signing], {label: 'JWT signing verification'});
    requireValue(readRegular(path.join(output, 'phase3-jwks.json'),
      'derived JWT JWKS').equals(readRegular(path.join(root,
      'secrets/phase5-policy-jwks.json'), 'runtime JWT JWKS')),
    'PERF-06 signing key does not match the runtime JWKS');
  } finally {
    fs.rmSync(output, {recursive: true, force: true});
  }
}

export function verifyPolicyCampaignBundle(directory, options = {}) {
  const root = path.resolve(directory);
  requireValue(fs.lstatSync(root).isDirectory() &&
    !fs.lstatSync(root).isSymbolicLink(),
  'PERF-06 campaign bundle root is unsafe');
  const expected = [...EXPECTED_FILES, 'checksums.sha256'].sort();
  const actual = listFiles(root).sort();
  requireValue(isDeepStrictEqual(actual, expected),
    'PERF-06 campaign bundle membership differs from the contract');
  const manifest = readRegular(path.join(root, 'checksums.sha256'),
    'campaign checksum manifest').toString();
  requireValue(manifest === exactManifest(root, [...EXPECTED_FILES].sort()),
    'PERF-06 campaign checksum manifest does not verify');
  const input = validateInput(JSON.parse(readRegular(path.join(root,
    'input.json'), 'campaign input')));
  const catalog = readRegular(path.join(root, 'catalog.json'),
    'campaign catalog');
  const plan = JSON.parse(readRegular(path.join(root, 'plan.json'),
    'campaign plan'));
  validatePolicyCostPlan(plan, catalog);
  const placement = verifyPlacementBundle(path.join(root, 'placement'));
  const campaign = JSON.parse(readRegular(path.join(root, 'campaign.json'),
    'campaign metadata'));
  requireValue(isDeepStrictEqual(campaign,
    campaignMetadata(plan, placement, root)),
  'PERF-06 campaign metadata differs from its bound artifacts');
  requireValue(plan.input.source.gateway_binary_sha256 ===
    input.source.gateway_binary_sha256 && plan.input.source.upstream_sha256 ===
    input.source.upstream_sha256 && placement.binary_sha256 ===
    input.source.gateway_binary_sha256,
  'PERF-06 campaign binary or upstream identity differs from input');
  for (const point of plan.points) {
    requireValue(sha256(readRegular(path.join(root,
      `snapshots/${point.profile_id}.pb`), `${point.profile_id} snapshot`)) ===
      point.snapshot_sha256,
    `${point.profile_id} snapshot differs from the plan`);
  }
  requireValue(readRegular(path.join(root, 'hosts'), 'campaign hosts')
    .equals(hostsBytes(input)),
  'PERF-06 campaign hosts file differs from the controlled topology');
  requireValue(readRegular(path.join(root, 'signing/phase3-jwks.json'),
    'signing JWKS').equals(readRegular(path.join(root,
    'secrets/phase5-policy-jwks.json'), 'runtime JWKS')),
  'PERF-06 signing and runtime JWKS bytes differ');
  const tls = validateTlsBundle(path.join(root,
    'secrets/tls-checksums.sha256'), path.join(root, 'secrets/ca.pem'));
  requireValue(tls.sha256 === plan.input.source.tls_bundle_sha256,
    'PERF-06 TLS bundle differs from the plan');
  verifyJwtIdentity(root);
  if (options.requireSource !== false) {
    requireValue(sourceState() === plan.input.source.harness_commit,
      'PERF-06 campaign bundle belongs to another source commit');
  }
  return {schema_version: 1, status: 'bundle-verified',
    plan_id: plan.plan_id, source_commit: plan.input.source.harness_commit,
    point_count: plan.points.length, setup_authorized: false,
    measurement_authorized: false, publication_authorized: false};
}

function runtimeMetadata(campaignRoot, campaign, point) {
  return {schema_version: 1,
    evidence_class: 'private-perf06-runtime-bundle',
    source_commit: campaign.source_commit, plan_id: campaign.plan_id,
    profile_id: point.profile_id, runtime_root: campaign.runtime_root,
    snapshot_sha256: point.snapshot_sha256,
    campaign_manifest_sha256: sha256(readRegular(path.join(campaignRoot,
      'checksums.sha256'), 'campaign checksum manifest'))};
}

export function verifyPolicyRuntimeBundle(directory, campaignDirectory,
  options = {}) {
  const root = path.resolve(directory);
  const campaignRoot = path.resolve(campaignDirectory);
  requireValue(fs.lstatSync(root).isDirectory() &&
    !fs.lstatSync(root).isSymbolicLink(),
  'PERF-06 runtime bundle root is unsafe');
  const expected = [...RUNTIME_FILES, 'checksums.sha256'].sort();
  requireValue(isDeepStrictEqual(listFiles(root).sort(), expected),
    'PERF-06 runtime bundle membership differs from the contract');
  const manifest = readRegular(path.join(root, 'checksums.sha256'),
    'runtime checksum manifest').toString();
  requireValue(manifest === exactManifest(root, [...RUNTIME_FILES].sort()),
    'PERF-06 runtime checksum manifest does not verify');
  const metadata = JSON.parse(readRegular(path.join(root, 'runtime.json'),
    'runtime metadata'));
  exactKeys(metadata, ['schema_version', 'evidence_class', 'source_commit',
    'plan_id', 'profile_id', 'runtime_root', 'snapshot_sha256',
    'campaign_manifest_sha256'], 'PERF-06 runtime metadata');
  requireValue(metadata.schema_version === 1 &&
    metadata.evidence_class === 'private-perf06-runtime-bundle' &&
    COMMIT.test(metadata.source_commit) && SHA256.test(metadata.plan_id) &&
    Object.hasOwn(PROFILE_FIXTURES, metadata.profile_id) &&
    metadata.runtime_root ===
      `/run/bonvoyage-perf06/policy-${metadata.plan_id.slice(0, 16)}` &&
    SHA256.test(metadata.snapshot_sha256) &&
    SHA256.test(metadata.campaign_manifest_sha256),
  'PERF-06 runtime metadata identity is invalid');
  const campaignResult = verifyPolicyCampaignBundle(campaignRoot,
    {requireSource: options.requireSource});
  const campaign = JSON.parse(readRegular(path.join(campaignRoot,
    'campaign.json'), 'campaign metadata'));
  const point = campaign.points.find((item) =>
    item.profile_id === metadata.profile_id);
  requireValue(point && isDeepStrictEqual(metadata,
    runtimeMetadata(campaignRoot, campaign, point)) &&
    campaignResult.plan_id === metadata.plan_id,
  'PERF-06 runtime metadata differs from the campaign');
  const copies = [
    [`snapshots/${metadata.profile_id}.pb`, 'active.pb'],
    ['hosts', 'hosts'],
    ['secrets/ca.pem', 'secrets/ca.pem'],
    ['secrets/phase5-policy-api-keys.txt',
      'secrets/phase5-policy-api-keys.txt'],
    ['secrets/phase5-policy-jwks.json',
      'secrets/phase5-policy-jwks.json'],
    ['secrets/server-chain.pem', 'secrets/server-chain.pem'],
    ['secrets/server-key.pem', 'secrets/server-key.pem'],
  ];
  for (const [source, target] of copies) {
    requireValue(readRegular(path.join(root, target), `runtime ${target}`)
      .equals(readRegular(path.join(campaignRoot, source),
        `campaign ${source}`)),
    `PERF-06 runtime artifact differs from the campaign: ${target}`);
  }
  requireValue(sha256(readRegular(path.join(root, 'active.pb'),
    'runtime snapshot')) === metadata.snapshot_sha256,
  'PERF-06 runtime snapshot differs from metadata');
  return {schema_version: 1, status: 'runtime-bundle-verified',
    source_commit: metadata.source_commit, plan_id: metadata.plan_id,
    profile_id: metadata.profile_id, runtime_root: metadata.runtime_root,
    manifest_sha256: sha256(Buffer.from(manifest)),
    setup_authorized: false, measurement_authorized: false,
    publication_authorized: false};
}

export function createPolicyRuntimeBundle(options) {
  const campaignRoot = path.resolve(options.campaign);
  const output = path.resolve(options.output);
  verifyPolicyCampaignBundle(campaignRoot,
    {requireSource: options.requireSource});
  requireValue(Object.hasOwn(PROFILE_FIXTURES, options.profileId),
    'PERF-06 runtime profile is unknown');
  requireValue(output !== campaignRoot &&
    !output.startsWith(`${campaignRoot}${path.sep}`) &&
    !fs.existsSync(output),
  'PERF-06 runtime output must be new and outside the campaign');
  const campaign = JSON.parse(readRegular(path.join(campaignRoot,
    'campaign.json'), 'campaign metadata'));
  const point = campaign.points.find((item) =>
    item.profile_id === options.profileId);
  requireValue(point, 'PERF-06 runtime profile is absent from the campaign');
  const parent = path.dirname(output);
  fs.mkdirSync(parent, {recursive: true});
  const staging = fs.mkdtempSync(path.join(parent,
    `.${path.basename(output)}.staging-`));
  fs.chmodSync(staging, 0o700);
  try {
    for (const [source, target] of [
      [`snapshots/${options.profileId}.pb`, 'active.pb'],
      ['hosts', 'hosts'],
      ['secrets/ca.pem', 'secrets/ca.pem'],
      ['secrets/phase5-policy-api-keys.txt',
        'secrets/phase5-policy-api-keys.txt'],
      ['secrets/phase5-policy-jwks.json',
        'secrets/phase5-policy-jwks.json'],
      ['secrets/server-chain.pem', 'secrets/server-chain.pem'],
      ['secrets/server-key.pem', 'secrets/server-key.pem'],
    ]) {
      write(path.join(staging, target), readRegular(path.join(campaignRoot,
        source), `campaign ${source}`));
    }
    writeJson(path.join(staging, 'runtime.json'), runtimeMetadata(campaignRoot,
      campaign, point));
    write(path.join(staging, 'checksums.sha256'), exactManifest(staging,
      [...RUNTIME_FILES].sort()));
    fs.renameSync(staging, output);
  } catch (error) {
    fs.rmSync(staging, {recursive: true, force: true});
    throw error;
  }
  return verifyPolicyRuntimeBundle(output, campaignRoot,
    {requireSource: options.requireSource});
}

function generateTls(root, scratch) {
  const secrets = path.join(root, 'secrets');
  fs.mkdirSync(secrets, {recursive: true, mode: 0o700});
  const caKey = path.join(scratch, 'ca-key.pem');
  const ca = path.join(secrets, 'ca.pem');
  const serverKey = path.join(secrets, 'server-key.pem');
  const request = path.join(scratch, 'server.csr');
  const extension = path.join(scratch, 'server-ext.cnf');
  run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days',
    '1', '-sha256', '-subj', '/CN=BonVoyage PERF-06 CA', '-keyout', caKey,
    '-out', ca], {label: 'PERF-06 CA generation'});
  run('openssl', ['req', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj',
    '/CN=api.example.test', '-keyout', serverKey, '-out', request],
  {label: 'PERF-06 server key generation'});
  fs.writeFileSync(extension,
    'subjectAltName=DNS:api.example.test\nextendedKeyUsage=serverAuth\n' +
    'keyUsage=digitalSignature,keyEncipherment\n', {mode: 0o600});
  run('openssl', ['x509', '-req', '-days', '1', '-sha256', '-in', request,
    '-CA', ca, '-CAkey', caKey, '-set_serial', '1', '-extfile', extension,
    '-out', path.join(secrets, 'server-chain.pem')],
  {label: 'PERF-06 server certificate generation'});
  for (const name of ['ca.pem', 'server-chain.pem', 'server-key.pem']) {
    fs.chmodSync(path.join(secrets, name), 0o600);
  }
  const names = ['ca.pem', 'server-chain.pem', 'server-key.pem'];
  write(path.join(secrets, 'tls-checksums.sha256'),
    exactManifest(secrets, names));
}

function generateJwt(root) {
  const signing = path.join(root, 'signing');
  run('python3', ['-B', GENERATE_JWT, signing, '--lifetime-seconds', '180'],
    {label: 'PERF-06 signing identity generation'});
  fs.rmSync(path.join(signing, 'jwt-tokens.json'));
  fs.copyFileSync(path.join(signing, 'phase3-jwks.json'), path.join(root,
    'secrets/phase5-policy-jwks.json'), fs.constants.COPYFILE_EXCL);
  fs.chmodSync(path.join(root, 'secrets/phase5-policy-jwks.json'), 0o600);
}

function compileSnapshots(root) {
  const output = path.join(root, 'snapshots');
  fs.mkdirSync(output, {recursive: true, mode: 0o700});
  for (const [id, fixture] of Object.entries(PROFILE_FIXTURES)) {
    run('go', ['run', './cmd/bonvoyage-control-plane', '-input',
      path.join('..', fixture), '-output', path.join(output, `${id}.pb`)],
    {cwd: path.join(ROOT, 'control-plane'), label: `${id} snapshot compile`});
    fs.chmodSync(path.join(output, `${id}.pb`), 0o600);
  }
}

function prepareFreeze(root, input) {
  writeJson(path.join(root, 'input.json'), input);
  fs.mkdirSync(path.join(root, 'requests'), {recursive: true, mode: 0o700});
  fs.mkdirSync(path.join(root, 'upstream'), {recursive: true, mode: 0o700});
  fs.copyFileSync(CATALOG, path.join(root, 'catalog.json'),
    fs.constants.COPYFILE_EXCL);
  fs.copyFileSync(HEADER_REQUEST, path.join(root,
    'requests/header-transform-request.json'), fs.constants.COPYFILE_EXCL);
  fs.copyFileSync(UPSTREAM_CONFIG, path.join(root, 'upstream/nginx.conf'),
    fs.constants.COPYFILE_EXCL);
  for (const name of ['catalog.json', 'requests/header-transform-request.json',
    'upstream/nginx.conf']) fs.chmodSync(path.join(root, name), 0o600);
  write(path.join(root, 'hosts'), hostsBytes(input));
  write(path.join(root, 'secrets/phase5-policy-api-keys.txt'),
    `${crypto.randomBytes(32).toString('hex')}\n`);
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'perf06-freeze-'));
  try {
    generateTls(root, scratch);
    generateJwt(root);
    compileSnapshots(root);
  } finally {
    fs.rmSync(scratch, {recursive: true, force: true});
  }
}

function parseOptions(argv, expected) {
  requireValue(argv.length === expected.length * 2,
    'PERF-06 campaign options are incomplete');
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    requireValue(expected.includes(argv[index]) && argv[index + 1] &&
      !argv[index + 1].startsWith('--') && !values.has(argv[index]),
    `invalid PERF-06 campaign option: ${argv[index] ?? ''}`);
    values.set(argv[index], argv[index + 1]);
  }
  return values;
}

function freeze(argv) {
  const args = parseOptions(argv, ['--input', '--installed-unit', '--output']);
  const output = path.resolve(args.get('--output'));
  requireValue(output !== ROOT && !output.startsWith(`${ROOT}${path.sep}`) &&
    !fs.existsSync(output),
  'PERF-06 private campaign output must be new and outside the checkout');
  const input = validateInput(JSON.parse(readRegular(path.resolve(
    args.get('--input')), 'campaign input')));
  const installedUnit = readRegular(path.resolve(args.get('--installed-unit')),
    'installed package unit');
  const sourceCommit = sourceState();
  const parent = path.dirname(output);
  fs.mkdirSync(parent, {recursive: true});
  const staging = fs.mkdtempSync(path.join(parent,
    `.${path.basename(output)}.staging-`));
  fs.chmodSync(staging, 0o700);
  try {
    prepareFreeze(staging, input);
    sealPolicyCampaignBundle({root: staging, input, installedUnit,
      sourceCommit});
    fs.renameSync(staging, output);
  } catch (error) {
    fs.rmSync(staging, {recursive: true, force: true});
    throw error;
  }
  return verifyPolicyCampaignBundle(output);
}

function main() {
  const [, , command, ...argv] = process.argv;
  if (command === 'freeze') {
    process.stdout.write(`${JSON.stringify(freeze(argv), null, 2)}\n`);
    return;
  }
  if (command === 'verify') {
    const args = parseOptions(argv, ['--bundle']);
    process.stdout.write(`${JSON.stringify(verifyPolicyCampaignBundle(
      path.resolve(args.get('--bundle'))), null, 2)}\n`);
    return;
  }
  if (command === 'runtime') {
    const args = parseOptions(argv, ['--campaign', '--profile-id', '--output']);
    process.stdout.write(`${JSON.stringify(createPolicyRuntimeBundle({
      campaign: path.resolve(args.get('--campaign')),
      profileId: args.get('--profile-id'),
      output: path.resolve(args.get('--output'))}), null, 2)}\n`);
    return;
  }
  if (command === 'verify-runtime') {
    const args = parseOptions(argv, ['--bundle', '--campaign']);
    process.stdout.write(`${JSON.stringify(verifyPolicyRuntimeBundle(
      path.resolve(args.get('--bundle')),
      path.resolve(args.get('--campaign'))), null, 2)}\n`);
    return;
  }
  throw new Error('usage: phase5-policy-campaign.mjs freeze|verify|runtime|verify-runtime [options]');
}

if (process.argv[1] && import.meta.url ===
    pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-policy-campaign: ${error.message}\n`);
    process.exitCode = 1;
  }
}
