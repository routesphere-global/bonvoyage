import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {localObservation, verifyOciBuilderImage} from './verify-oss-oci-builder-image.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACT = path.join(ROOT,
  'packaging/release/oci/oss-oci-builder-image-contract.json');
const DOCKERFILE = path.join(ROOT, 'deploy/docker/bonvoyage/Dockerfile');
const ENTRYPOINT = path.join(ROOT, 'scripts/oss-oci-builder-entrypoint.py');
const WORKFLOW = path.join(ROOT,
  'packaging/release/oci/oss-oci-reproducibility.workflow.yml');
const RECEIPT = path.join(ROOT,
  'packaging/release/oci/oss-oci-builder-image-verification.json');
const ACTIVE_WORKFLOW = path.join(ROOT,
  '.github/workflows/oss-oci-reproducibility.yml');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-oci-builder-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const relative = {
    contract: 'packaging/release/oci/oss-oci-builder-image-contract.json',
    dockerfile: 'deploy/docker/bonvoyage/Dockerfile',
    entrypoint: 'scripts/oss-oci-builder-entrypoint.py',
    workflow: 'packaging/release/oci/oss-oci-reproducibility.workflow.yml',
    receipt: 'packaging/release/oci/oss-oci-builder-image-verification.json',
    activeWorkflow: '.github/workflows/oss-oci-reproducibility.yml',
  };
  const sources = {contract: CONTRACT, dockerfile: DOCKERFILE, entrypoint: ENTRYPOINT,
    workflow: WORKFLOW, receipt: RECEIPT, activeWorkflow: ACTIVE_WORKFLOW};
  const values = {};
  for (const [name, source] of Object.entries(sources)) {
    const destination = path.join(root, relative[name]);
    fs.mkdirSync(path.dirname(destination), {recursive: true});
    fs.copyFileSync(source, destination);
    values[name] = destination;
  }
  return {root, ...values};
}

function verify(paths, options = {}) {
  return verifyOciBuilderImage(
    paths.contract, paths.dockerfile, paths.entrypoint, paths.workflow, options,
  );
}

function inspection() {
  return [{
    Id: `sha256:${'a'.repeat(64)}`,
    Os: 'linux',
    Architecture: 'amd64',
    Config: {
      Entrypoint: ['/usr/local/bin/bonvoyage-oss-oci-builder'],
      User: '65532:65532',
      WorkingDir: '/workspace',
      Labels: {
        'io.routesphere.bonvoyage.role': 'oss-oci-builder',
        'io.routesphere.bonvoyage.ubuntu-snapshot': '20261006T000000Z',
        'io.routesphere.bonvoyage.zlib1g-version': '1:1.3.dfsg-3.1ubuntu2.3',
        'io.routesphere.bonvoyage.release-authority': 'false',
      },
    },
  }];
}

test('committed OCI builder foundation is publicly verified and powerless', () => {
  const {result} = verify({contract: CONTRACT, dockerfile: DOCKERFILE,
    entrypoint: ENTRYPOINT, workflow: WORKFLOW});
  assert.equal(result.outcome, 'public-foundation-accepted');
  assert.equal(result.registry_reference_verified, true);
  assert.equal(result.verification_receipt.path,
    'packaging/release/oci/oss-oci-builder-image-verification.json');
  assert.equal(result.hosted_execution_qualified, false);
  assert.equal(result.release_admitted, false);
  assert.equal(result.publishable, false);
});

test('public registry identity and authority must remain exact and powerless', (t) => {
  for (const mutation of [
    (value) => { value.state = 'activatable'; },
    (value) => { value.registry.reference = 'ghcr.io/routesphere-global/bonvoyage-oci-builder:latest'; },
    (value) => { value.registry.external_verification_receipt = null; },
    (value) => { value.registry.anonymous_pull_verified = false; },
    (value) => { value.image.foundation_reference = value.registry.reference.replace(/.$/u, '0'); },
    (value) => { value.remediation.zlib1g_sha256 = '0'.repeat(64); },
    (value) => { value.remediation.zlib1g_dev_sha256 = '0'.repeat(64); },
    (value) => { value.remediation.zlib1g_version = '1:1.3.dfsg-3.1ubuntu2.2'; },
    (value) => { value.authority.publishable = true; },
  ]) {
    const paths = fixture(t);
    const contract = JSON.parse(fs.readFileSync(paths.contract, 'utf8'));
    mutation(contract);
    fs.writeFileSync(paths.contract, `${JSON.stringify(contract, null, 2)}\n`);
    assert.throws(() => verify(paths));
  }
});

test('unpublished foundation rejects an active hosted workflow', (t) => {
  const paths = fixture(t);
  const contract = JSON.parse(fs.readFileSync(paths.contract, 'utf8'));
  contract.state = 'local-foundation-unpublished';
  contract.registry.reference = null;
  contract.registry.external_verification_receipt = null;
  contract.registry.anonymous_pull_verified = false;
  fs.writeFileSync(paths.contract, `${JSON.stringify(contract, null, 2)}\n`);
  assert.throws(() => verify(paths), /must not activate/u);
  fs.rmSync(paths.activeWorkflow);
  const {result} = verify(paths);
  assert.equal(result.outcome, 'local-foundation-accepted');
  assert.equal(result.registry_reference_verified, false);
});

test('builder stage rejects changed foundations, package bytes and product source', (t) => {
  for (const replacement of [
    ['COPY scripts/build-oss-oci.py',
      'COPY dataplane/ /usr/src/bonvoyage/dataplane/\nCOPY scripts/build-oss-oci.py'],
    ['io.routesphere.bonvoyage.release-authority="false"',
      'io.routesphere.bonvoyage.release-authority="true"'],
    ['test ! -e /opt/bonvoyage/bin/bonvoyage-dataplane',
      'cp /tmp/bonvoyage-dataplane /opt/bonvoyage/bin/bonvoyage-dataplane'],
    ['sha256:51d38192e3bdd43714b77b30b87908030a0424224aacd75747125186624ada9b',
      `sha256:${'0'.repeat(64)}`],
    ['376249c8de139568221dbb242318cc8cb8f02299e3a62b7432948e1754fbddf9',
      '0'.repeat(64)],
    ['419902a649e1078f24596cdf31ced9c839519828790f59888056fcdcd58e8a28',
      '0'.repeat(64)],
    ['zlib1g_1.3.dfsg-3.1ubuntu2.3_amd64.deb',
      'zlib1g_1.3.dfsg-3.1ubuntu2.2_amd64.deb'],
    ['dpkg-deb --field /tmp/zlib1g.deb Package', 'apt-get update'],
  ]) {
    const paths = fixture(t);
    const source = fs.readFileSync(paths.dockerfile, 'utf8');
    const mutated = source.replaceAll(replacement[0], replacement[1]);
    assert.notEqual(mutated, source, `missing mutation fixture ${replacement[0]}`);
    fs.writeFileSync(paths.dockerfile, mutated);
    assert.throws(() => verify(paths), undefined,
      `mutation must be rejected: ${replacement[0]}`);
  }
});

test('entrypoint requires exact clean source, tests and powerless output', (t) => {
  for (const replacement of [
    ['f"safe.directory={root}"', '"safe.directory=*"'],
    ['status", "--porcelain=v1"', 'status", "--ignored"'],
    ['compiled_tests_passed', 'tests_skipped'],
    ['release_admitted": False', 'release_admitted": True'],
  ]) {
    const paths = fixture(t);
    const source = fs.readFileSync(paths.entrypoint, 'utf8');
    fs.writeFileSync(paths.entrypoint, source.replaceAll(replacement[0], replacement[1]));
    assert.throws(() => verify(paths));
  }
});

test('hosted OCI builders retain the hardened runtime boundary', (t) => {
  for (const replacement of [
    ['source=$RUNNER_TEMP/oss-oci-work-a,target=/workspace/work',
      'source=$RUNNER_TEMP/oss-oci-build-a,target=/workspace/output'],
    ['--env BONVOYAGE_BUILDER_IMAGE=', '--env FLOATING_IMAGE='],
    ['--tmpfs /tmp:rw,nosuid,nodev,noexec', '--tmpfs /tmp:rw'],
  ]) {
    const paths = fixture(t);
    const source = fs.readFileSync(paths.workflow, 'utf8');
    fs.writeFileSync(paths.workflow, source.replace(replacement[0], replacement[1]));
    assert.throws(() => verify(paths));
  }
});

test('local image observation is exact and grants no external identity', () => {
  const contract = JSON.parse(fs.readFileSync(CONTRACT, 'utf8'));
  const result = localObservation(contract, inspection());
  assert.equal(result.outcome, 'local-image-observed');
  assert.equal(result.registry_reference_verified, false);
  assert.equal(result.publishable, false);
  const wrong = inspection();
  wrong[0].Config.Labels['io.routesphere.bonvoyage.zlib1g-version'] =
    '1:1.3.dfsg-3.1ubuntu2.2';
  assert.throws(() => localObservation(contract, wrong), /does not satisfy/u);
});
