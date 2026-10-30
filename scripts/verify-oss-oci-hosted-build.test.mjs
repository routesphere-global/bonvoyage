import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {
  hostedReceipt,
  validateImageInspection,
  verifyHostedBuildContract,
} from './verify-oss-oci-hosted-build.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACT = path.join(ROOT,
  'packaging/release/oci/oss-oci-hosted-build-contract.json');
const WORKFLOW = path.join(ROOT,
  'packaging/release/oci/oss-oci-reproducibility.workflow.yml');
const VERIFICATION_RECEIPT = path.join(ROOT,
  'packaging/release/oci/oss-oci-builder-image-verification.json');
const ACTIVE_WORKFLOW = path.join(ROOT,
  '.github/workflows/oss-oci-reproducibility.yml');
const VERIFIER = path.join(ROOT, 'scripts/verify-oss-oci-hosted-build.mjs');
const IMAGE_DIGEST = 'a'.repeat(64);
const IMAGE_REFERENCE =
  `ghcr.io/routesphere-global/bonvoyage-oci-builder@sha256:${IMAGE_DIGEST}`;

function copyFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-hosted-oci-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const packageRoot = path.join(root, 'packaging/release/oci');
  fs.mkdirSync(packageRoot, {recursive: true});
  const contractPath = path.join(packageRoot, 'oss-oci-hosted-build-contract.json');
  const workflowPath = path.join(packageRoot, 'oss-oci-reproducibility.workflow.yml');
  fs.copyFileSync(CONTRACT, contractPath);
  fs.copyFileSync(WORKFLOW, workflowPath);
  fs.copyFileSync(VERIFICATION_RECEIPT,
    path.join(packageRoot, 'oss-oci-builder-image-verification.json'));
  const activeWorkflow = path.join(root, '.github/workflows/oss-oci-reproducibility.yml');
  fs.mkdirSync(path.dirname(activeWorkflow), {recursive: true});
  fs.copyFileSync(ACTIVE_WORKFLOW, activeWorkflow);
  return {root, contractPath, workflowPath};
}

function activate(contractPath, root) {
  const packageRoot = path.join(root, 'packaging/release/oci');
  const contract = JSON.parse(fs.readFileSync(contractPath, 'utf8'));
  contract.activation = {
    ...contract.activation,
    state: 'activatable',
    public_repository_created: true,
    builder_image_identity_verified: true,
    repository_settings_verified: true,
  };
  contract.builder_image.reference = IMAGE_REFERENCE;
  contract.builder_image.verification_receipt =
    'packaging/release/oci/oss-oci-builder-image-verification.json';
  const receiptPath = path.join(packageRoot, 'oss-oci-builder-image-verification.json');
  fs.writeFileSync(receiptPath, `${JSON.stringify({
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-oci-builder-image-verification',
    repository: contract.builder_image.repository,
    reference: IMAGE_REFERENCE,
    digest: IMAGE_DIGEST,
    platform: 'linux/amd64',
    registry: 'ghcr.io',
    verified_at: '2026-10-07T12:00:00.000Z',
    verification_methods: ['registry-manifest', 'anonymous-pull', 'local-image-inspect'],
    release_admitted: false,
    publishable: false,
  }, null, 2)}\n`);
  fs.writeFileSync(contractPath, `${JSON.stringify(contract, null, 2)}\n`);
  return contract;
}

test('committed hosted-build contract is activatable and powerless', () => {
  const {result} = verifyHostedBuildContract(CONTRACT, WORKFLOW,
    {requireActivatable: true});
  assert.equal(result.outcome, 'activatable');
  assert.equal(result.activation_ready, true);
  assert.equal(result.blockers.length, 0);
  assert.equal(result.builder_image_verification.path,
    'packaging/release/oci/oss-oci-builder-image-verification.json');
  assert.equal(result.provenance_created, true);
  assert.equal(result.release_admitted, false);
  assert.equal(result.publishable, false);
});

test('blocked contract rejects accidental workflow activation', (t) => {
  const fixture = copyFixture(t);
  const contract = JSON.parse(fs.readFileSync(fixture.contractPath, 'utf8'));
  contract.activation = {
    ...contract.activation,
    state: 'blocked-pending-public-builder-image',
    public_repository_created: false,
    builder_image_identity_verified: false,
    repository_settings_verified: false,
  };
  contract.builder_image.reference = null;
  contract.builder_image.verification_receipt = null;
  fs.writeFileSync(fixture.contractPath, `${JSON.stringify(contract, null, 2)}\n`);
  assert.throws(() => verifyHostedBuildContract(fixture.contractPath,
    fixture.workflowPath), /must not have an active GitHub workflow/u);
});

test('activatable fixture requires exact image verification and tagged public source', (t) => {
  const fixture = copyFixture(t);
  activate(fixture.contractPath, fixture.root);
  const {result} = verifyHostedBuildContract(fixture.contractPath, fixture.workflowPath, {
    requireActivatable: true,
    githubRepository: 'routesphere-global/bonvoyage',
    githubRefType: 'tag',
    githubRefName: 'v1.0.0-rc.1',
    githubSha: 'b'.repeat(40),
  });
  assert.equal(result.outcome, 'activatable');
  assert.equal(result.builder_image_verification.path,
    'packaging/release/oci/oss-oci-builder-image-verification.json');
  assert.throws(() => verifyHostedBuildContract(fixture.contractPath, fixture.workflowPath, {
    requireActivatable: true,
    githubRepository: 'fork/bonvoyage',
    githubRefType: 'branch',
    githubRefName: 'main',
    githubSha: 'b'.repeat(40),
  }), /tagged public commit/u);
});

test('floating image, partial activation and changed authority are rejected', (t) => {
  for (const mutation of [
    (contract) => { contract.builder_image.reference = 'ghcr.io/routesphere/builder:latest'; },
    (contract) => { contract.activation.repository_settings_verified = false; },
    (contract) => { contract.authority.publishable = true; },
    (contract) => { contract.authority.provenance_created = false; },
    (contract) => { contract.execution.permissions = {contents: 'write'}; },
    (contract) => { contract.execution.provenance_permissions['id-token'] = 'read'; },
  ]) {
    const fixture = copyFixture(t);
    const contract = activate(fixture.contractPath, fixture.root);
    mutation(contract);
    fs.writeFileSync(fixture.contractPath, `${JSON.stringify(contract, null, 2)}\n`);
    assert.throws(() => verifyHostedBuildContract(
      fixture.contractPath, fixture.workflowPath, {requireActivatable: true}));
  }
});

test('automatic trigger, unpinned action, secret and publishing command are rejected', (t) => {
  for (const replacement of [
    ['  workflow_dispatch:\n', '  push:\n    branches: [main]\n'],
    ['actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', 'actions/checkout@v7'],
    ['actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6', 'actions/attest@v4'],
    ['npm ci --ignore-scripts', 'echo "${{ secrets.RELEASE_TOKEN }}"'],
    ['mkdir -p "$RUNNER_TEMP/oss-oci-comparison"', 'gh release create v1.0.0'],
    ['      id-token: write\n', '      id-token: read\n'],
  ]) {
    const fixture = copyFixture(t);
    const source = fs.readFileSync(fixture.workflowPath, 'utf8');
    fs.writeFileSync(fixture.workflowPath, source.replace(replacement[0], replacement[1]));
    assert.throws(() => verifyHostedBuildContract(fixture.contractPath, fixture.workflowPath));
  }
});

test('comparison receipt requires complete GitHub source context', (t) => {
  const fixture = copyFixture(t);
  const source = fs.readFileSync(fixture.workflowPath, 'utf8');
  fs.writeFileSync(fixture.workflowPath,
    source.replaceAll('            --github-ref-type "$GITHUB_REF_TYPE" \\\n', ''));
  assert.throws(() => verifyHostedBuildContract(fixture.contractPath,
    fixture.workflowPath), /complete GitHub source context/u);
});

test('pulled image observation must expose the exact contracted digest', (t) => {
  const fixture = copyFixture(t);
  const contract = activate(fixture.contractPath, fixture.root);
  const observation = validateImageInspection(contract, [{
    Id: `sha256:${'c'.repeat(64)}`,
    RepoDigests: [IMAGE_REFERENCE],
    Architecture: 'amd64',
    Os: 'linux',
  }]);
  assert.equal(observation.manifest_digest, IMAGE_DIGEST);
  assert.equal(observation.externally_resolved, true);
  assert.equal(observation.publishable, false);
  assert.throws(() => validateImageInspection(contract, [{
    Id: `sha256:${'c'.repeat(64)}`,
    RepoDigests: [`ghcr.io/routesphere-global/bonvoyage-oci-builder@sha256:${'d'.repeat(64)}`],
    Architecture: 'amd64',
    Os: 'linux',
  }]), /contracted repository digest/u);
});

test('CLI accepts the array emitted by docker image inspect', (t) => {
  const fixture = copyFixture(t);
  activate(fixture.contractPath, fixture.root);
  const inspectionPath = path.join(fixture.root, 'builder-image-inspect.json');
  const observationPath = path.join(fixture.root, 'builder-image-observation.json');
  fs.writeFileSync(inspectionPath, `${JSON.stringify([{
    Id: `sha256:${'c'.repeat(64)}`,
    RepoDigests: [IMAGE_REFERENCE],
    Architecture: 'amd64',
    Os: 'linux',
  }], null, 2)}\n`);

  const result = spawnSync(process.execPath, [
    VERIFIER,
    '--contract', fixture.contractPath,
    '--workflow', fixture.workflowPath,
    '--require-activatable',
    '--image-inspection', inspectionPath,
    '--image-observation', observationPath,
  ], {encoding: 'utf8'});

  assert.equal(result.status, 0, result.stderr);
  const observation = JSON.parse(fs.readFileSync(observationPath, 'utf8'));
  assert.equal(observation.manifest_digest, IMAGE_DIGEST);
  assert.equal(observation.externally_resolved, true);
  assert.equal(observation.publishable, false);
});

test('CLI rejects an object in place of docker image inspect output', (t) => {
  const fixture = copyFixture(t);
  activate(fixture.contractPath, fixture.root);
  const inspectionPath = path.join(fixture.root, 'builder-image-inspect.json');
  const observationPath = path.join(fixture.root, 'builder-image-observation.json');
  fs.writeFileSync(inspectionPath, `${JSON.stringify({
    Id: `sha256:${'c'.repeat(64)}`,
    RepoDigests: [IMAGE_REFERENCE],
    Architecture: 'amd64',
    Os: 'linux',
  }, null, 2)}\n`);

  const result = spawnSync(process.execPath, [
    VERIFIER,
    '--contract', fixture.contractPath,
    '--workflow', fixture.workflowPath,
    '--require-activatable',
    '--image-inspection', inspectionPath,
    '--image-observation', observationPath,
  ], {encoding: 'utf8'});

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Docker image inspection must be an array/u);
  assert.equal(fs.existsSync(observationPath), false);
});

test('hosted comparison upgrades independence only and retains no release authority', (t) => {
  const fixture = copyFixture(t);
  const contract = activate(fixture.contractPath, fixture.root);
  const technical = {
    classification: 'routesphere-bonvoyage-oss-oci-reproducibility',
    outcome: 'byte-identical-technical-candidates',
    source: {repository: 'https://github.com/routesphere-global/bonvoyage',
      commit: 'b'.repeat(40), tag: 'v1.0.0', dirty: false},
    platform: {architecture: 'amd64', os: 'linux'},
    version: '1.0.0',
    builder_image: contract.builder_image.reference,
    builders: ['github-42-1-a', 'github-42-1-b'],
    archive: {path: 'bonvoyage-gateway-1.0.0-linux-amd64.oci.tar', bytes: 10,
      sha256: 'e'.repeat(64)},
    manifest: {bytes: 11, digest: `sha256:${'2'.repeat(64)}`},
    config: {bytes: 12, digest: `sha256:${'3'.repeat(64)}`},
    layer: {bytes: 13, digest: `sha256:${'4'.repeat(64)}`,
      diff_id: `sha256:${'5'.repeat(64)}`},
    technical_reproducibility_observed: true,
    hosted_builder_independence_qualified: false,
    release_admitted: false,
    publishable: false,
  };
  const receipt = hostedReceipt(contract, technical, {
    githubSha: 'b'.repeat(40), githubRefName: 'v1.0.0', githubRunId: '42',
    githubRunAttempt: '1', firstArtifactDigest: 'f'.repeat(64),
    secondArtifactDigest: '0'.repeat(64), technicalReceiptSha256: '1'.repeat(64),
  });
  assert.equal(receipt.hosted_builder_independence_qualified, true);
  assert.deepEqual(receipt.archive, technical.archive);
  assert.deepEqual(receipt.manifest, technical.manifest);
  assert.deepEqual(receipt.config, technical.config);
  assert.deepEqual(receipt.layer, technical.layer);
  assert.equal(receipt.release_admitted, false);
  assert.equal(receipt.publishable, false);
  assert.throws(() => hostedReceipt(contract, technical, {
    githubSha: 'b'.repeat(40), githubRefName: 'v1.0.0', githubRunId: '42',
    githubRunAttempt: '1', firstArtifactDigest: 'f'.repeat(64),
    secondArtifactDigest: 'f'.repeat(64), technicalReceiptSha256: '1'.repeat(64),
  }), /distinct uploaded evidence/u);
});
