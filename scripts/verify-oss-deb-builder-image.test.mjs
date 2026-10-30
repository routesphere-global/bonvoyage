import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {
  localObservation,
  verifyBuilderImageFoundation,
} from './verify-oss-deb-builder-image.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACT = path.join(ROOT,
  'packaging/release/debian/oss-deb-builder-image-contract.json');
const DOCKERFILE = path.join(ROOT, 'deploy/docker/bonvoyage/Dockerfile');
const ENTRYPOINT = path.join(ROOT, 'scripts/oss-deb-builder-entrypoint.py');
const WORKFLOW = path.join(ROOT,
  'packaging/release/debian/oss-deb-reproducibility.workflow.yml');
const RECEIPT = path.join(ROOT,
  'packaging/release/debian/oss-deb-builder-image-verification.json');
const ACTIVE_WORKFLOW = path.join(ROOT,
  '.github/workflows/oss-deb-reproducibility.yml');

function copyFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-builder-image-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const paths = {
    contract: 'packaging/release/debian/oss-deb-builder-image-contract.json',
    dockerfile: 'deploy/docker/bonvoyage/Dockerfile',
    entrypoint: 'scripts/oss-deb-builder-entrypoint.py',
    workflow: 'packaging/release/debian/oss-deb-reproducibility.workflow.yml',
    receipt: 'packaging/release/debian/oss-deb-builder-image-verification.json',
    activeWorkflow: '.github/workflows/oss-deb-reproducibility.yml',
  };
  for (const [name, relative] of Object.entries(paths)) {
    const destination = path.join(root, relative);
    fs.mkdirSync(path.dirname(destination), {recursive: true});
    fs.copyFileSync({contract: CONTRACT, dockerfile: DOCKERFILE,
      entrypoint: ENTRYPOINT, workflow: WORKFLOW, receipt: RECEIPT,
      activeWorkflow: ACTIVE_WORKFLOW}[name], destination);
    paths[name] = destination;
  }
  return {root, ...paths};
}

function verify(paths, options = {}) {
  return verifyBuilderImageFoundation(
    paths.contract, paths.dockerfile, paths.entrypoint, paths.workflow, options,
  );
}

function inspection() {
  return [{
    Id: `sha256:${'a'.repeat(64)}`,
    Os: 'linux',
    Architecture: 'amd64',
    Config: {
      Entrypoint: ['/usr/local/bin/bonvoyage-oss-deb-builder'],
      User: '65532:65532',
      WorkingDir: '/workspace',
      Labels: {
        'io.routesphere.bonvoyage.role': 'oss-deb-builder',
        'io.routesphere.bonvoyage.ubuntu-snapshot': '20261029T000000Z',
        'io.routesphere.bonvoyage.release-authority': 'false',
      },
    },
  }];
}

test('committed builder image foundation is publicly verified and powerless', () => {
  const {result} = verify({contract: CONTRACT, dockerfile: DOCKERFILE,
    entrypoint: ENTRYPOINT, workflow: WORKFLOW});
  assert.equal(result.outcome, 'public-foundation-accepted');
  assert.equal(result.registry_reference_verified, true);
  assert.equal(result.verification_receipt.path,
    'packaging/release/debian/oss-deb-builder-image-verification.json');
  assert.equal(result.hosted_execution_qualified, false);
  assert.equal(result.release_admitted, false);
  assert.equal(result.publishable, false);
});

test('public registry identity and authority must remain exact and powerless', (t) => {
  for (const mutation of [
    (value) => { value.state = 'activatable'; },
    (value) => { value.registry.reference = 'ghcr.io/routesphere-global/bonvoyage-debian-builder:latest'; },
    (value) => { value.registry.external_verification_receipt = null; },
    (value) => { value.registry.anonymous_pull_verified = false; },
    (value) => { value.authority.publishable = true; },
  ]) {
    const fixture = copyFixture(t);
    const contract = JSON.parse(fs.readFileSync(fixture.contract, 'utf8'));
    mutation(contract);
    fs.writeFileSync(fixture.contract, `${JSON.stringify(contract, null, 2)}\n`);
    assert.throws(() => verify(fixture));
  }
});

test('unpublished foundation rejects an active hosted workflow', (t) => {
  const fixture = copyFixture(t);
  const contract = JSON.parse(fs.readFileSync(fixture.contract, 'utf8'));
  contract.state = 'local-foundation-unpublished';
  contract.registry.reference = null;
  contract.registry.external_verification_receipt = null;
  contract.registry.anonymous_pull_verified = false;
  fs.writeFileSync(fixture.contract, `${JSON.stringify(contract, null, 2)}\n`);
  assert.throws(() => verify(fixture), /must not activate/u);
  fs.rmSync(fixture.activeWorkflow);
  const {result} = verify(fixture);
  assert.equal(result.outcome, 'local-foundation-accepted');
  assert.equal(result.registry_reference_verified, false);
});

test('builder stage rejects embedded product source and floating package indexes', (t) => {
  for (const replacement of [
    ['COPY scripts/oss-deb-builder-entrypoint.py', 'COPY dataplane/ /usr/src/bonvoyage/dataplane/\nCOPY scripts/oss-deb-builder-entrypoint.py'],
    ['COPY scripts/oss-deb-builder-entrypoint.py', 'RUN test ! -e /opt/bonvoyage\nCOPY scripts/oss-deb-builder-entrypoint.py'],
    ['APT::Update::Error-Mode=any', 'APT::Update::Error-Mode=none'],
    ['FROM ubuntu-snapshot AS seastar-build', 'FROM ${UBUNTU_IMAGE} AS seastar-build'],
    ['ca-certificates_20240203_all.deb', 'ca-certificates_20240203_amd64.deb'],
    ['641de77d8f142cfd62a1a6f964ba67b20754d3337c480efb529d086075a06c9a',
      'c2fdbca9d1a811c06e854ecc817cb26100e3022bb06f5642119ff67cc145a7c6'],
    ['https://archive.ubuntu.com/ubuntu/pool/main/c/ca-certificates/',
      'https://snapshot.ubuntu.com/ubuntu/20261029T000000Z/pool/main/c/ca-certificates/'],
    ['dpkg-deb --field /tmp/ca-certificates.deb Version', 'true'],
    ['io.routesphere.bonvoyage.release-authority="false"',
      'io.routesphere.bonvoyage.release-authority="true"'],
  ]) {
    const fixture = copyFixture(t);
    const source = fs.readFileSync(fixture.dockerfile, 'utf8');
    fs.writeFileSync(fixture.dockerfile, source.replace(replacement[0], replacement[1]));
    assert.throws(() => verify(fixture));
  }
});

test('entrypoint requires clean tagged source, compiled tests and powerless output', (t) => {
  for (const replacement of [
    ['f"safe.directory={root}"', '"safe.directory=*"'],
    ['status", "--porcelain=v1"', 'status", "--ignored"'],
    ['reviewed public LICENSE file required', 'license optional'],
    ['compiled_tests_passed', 'tests_skipped'],
    ['release_admitted": False', 'release_admitted": True'],
  ]) {
    const fixture = copyFixture(t);
    const source = fs.readFileSync(fixture.entrypoint, 'utf8');
    fs.writeFileSync(fixture.entrypoint, source.replaceAll(replacement[0], replacement[1]));
    assert.throws(() => verify(fixture));
  }
});

test('hosted builders require distinct writable work mounts and exact image identity', (t) => {
  for (const replacement of [
    ['source=$RUNNER_TEMP/oss-deb-work-a,target=/workspace/work',
      'source=$RUNNER_TEMP/oss-deb-build-a,target=/workspace/output'],
    ['--env BONVOYAGE_BUILDER_IMAGE=', '--env FLOATING_IMAGE='],
    ['--tmpfs /tmp:rw,nosuid,nodev,noexec', '--tmpfs /tmp:rw'],
  ]) {
    const fixture = copyFixture(t);
    const source = fs.readFileSync(fixture.workflow, 'utf8');
    fs.writeFileSync(fixture.workflow, source.replace(replacement[0], replacement[1]));
    assert.throws(() => verify(fixture));
  }
});

test('local Docker observation is exact but grants no external identity', () => {
  const contract = JSON.parse(fs.readFileSync(CONTRACT, 'utf8'));
  const result = localObservation(contract, inspection());
  assert.equal(result.outcome, 'local-image-observed');
  assert.equal(result.externally_resolved, false);
  assert.equal(result.registry_reference_verified, false);
  assert.equal(result.publishable, false);
  const wrong = inspection();
  wrong[0].Architecture = 'arm64';
  assert.throws(() => localObservation(contract, wrong), /does not satisfy/u);
});
