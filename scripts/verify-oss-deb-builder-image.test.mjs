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
const HOSTED_CONTRACT = path.join(ROOT,
  'packaging/release/debian/oss-deb-hosted-build-contract.json');
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
    hostedContract: 'packaging/release/debian/oss-deb-hosted-build-contract.json',
    dockerfile: 'deploy/docker/bonvoyage/Dockerfile',
    entrypoint: 'scripts/oss-deb-builder-entrypoint.py',
    workflow: 'packaging/release/debian/oss-deb-reproducibility.workflow.yml',
    receipt: 'packaging/release/debian/oss-deb-builder-image-verification.json',
    activeWorkflow: '.github/workflows/oss-deb-reproducibility.yml',
  };
  for (const [name, relative] of Object.entries(paths)) {
    const destination = path.join(root, relative);
    fs.mkdirSync(path.dirname(destination), {recursive: true});
    fs.copyFileSync({contract: CONTRACT, hostedContract: HOSTED_CONTRACT, dockerfile: DOCKERFILE,
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
        'io.routesphere.bonvoyage.ubuntu-snapshot': '20261006T000000Z',
        'io.routesphere.bonvoyage.zlib1g-version': '1:1.3.dfsg-3.1ubuntu2.3',
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
    (value) => { value.image.foundation_reference = value.registry.reference.replace(/.$/u, '0'); },
    (value) => { value.remediation.zlib1g_sha256 = '0'.repeat(64); },
    (value) => { value.remediation.zlib1g_dev_sha256 = '0'.repeat(64); },
    (value) => { value.remediation.zlib1g_version = '1:1.3.dfsg-3.1ubuntu2.2'; },
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

test('builder stage rejects changed foundations, package bytes and embedded source', (t) => {
  for (const replacement of [
    ['COPY scripts/oss-deb-builder-entrypoint.py', 'COPY dataplane/ /usr/src/bonvoyage/dataplane/\nCOPY scripts/oss-deb-builder-entrypoint.py'],
    ['COPY scripts/oss-deb-builder-entrypoint.py', 'RUN test ! -e /opt/bonvoyage\nCOPY scripts/oss-deb-builder-entrypoint.py'],
    ['sha256:f32465ff914634bcb5bbb2ff9271dd1ba0cbb8838be0ab26c696e64d2a17a225',
      `sha256:${'0'.repeat(64)}`],
    ['376249c8de139568221dbb242318cc8cb8f02299e3a62b7432948e1754fbddf9',
      '0'.repeat(64)],
    ['419902a649e1078f24596cdf31ced9c839519828790f59888056fcdcd58e8a28',
      '0'.repeat(64)],
    ['zlib1g_1.3.dfsg-3.1ubuntu2.3_amd64.deb',
      'zlib1g_1.3.dfsg-3.1ubuntu2.2_amd64.deb'],
    ['dpkg-deb --field /tmp/zlib1g.deb Package', 'apt-get update'],
    ['io.routesphere.bonvoyage.release-authority="false"',
      'io.routesphere.bonvoyage.release-authority="true"'],
  ]) {
    const fixture = copyFixture(t);
    const source = fs.readFileSync(fixture.dockerfile, 'utf8');
    const mutated = source.replace(replacement[0], replacement[1]);
    assert.notEqual(mutated, source, `missing mutation fixture ${replacement[0]}`);
    fs.writeFileSync(fixture.dockerfile, mutated);
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

test('hosted provenance identity remains exact and cannot enter builder jobs', (t) => {
  for (const replacement of [
    ['id-token: write', 'id-token: read'],
    ['actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6',
      `actions/attest@${'a'.repeat(40)}`],
    ['  build-a:\n    name:',
      '  build-a:\n    permissions:\n      id-token: write\n    name:'],
    ['  provenance:\n    name:', '  provenance:\n    needs: build-a\n    name:'],
    ['name: OSS Debian Reproducibility Candidate',
      'name: OSS Debian Reproducibility Candidate\n# docker push is forbidden'],
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
