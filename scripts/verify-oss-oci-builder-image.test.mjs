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

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-oci-builder-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const values = {};
  for (const [name, source] of Object.entries({contract: CONTRACT,
    dockerfile: DOCKERFILE, entrypoint: ENTRYPOINT})) {
    const destination = path.join(root, path.basename(source));
    fs.copyFileSync(source, destination);
    values[name] = destination;
  }
  return values;
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
        'io.routesphere.bonvoyage.release-authority': 'false',
      },
    },
  }];
}

test('committed OCI builder foundation is inactive and powerless', () => {
  const {result} = verifyOciBuilderImage(CONTRACT, DOCKERFILE, ENTRYPOINT);
  assert.equal(result.outcome, 'local-foundation-accepted');
  assert.equal(result.registry_reference_verified, false);
  assert.equal(result.hosted_execution_qualified, false);
  assert.equal(result.release_admitted, false);
  assert.equal(result.publishable, false);
});

test('registry identity and authority cannot be asserted locally', (t) => {
  for (const mutation of [
    (value) => { value.state = 'active'; },
    (value) => { value.registry.reference = `sha256:${'b'.repeat(64)}`; },
    (value) => { value.registry.anonymous_pull_verified = true; },
    (value) => { value.authority.publishable = true; },
  ]) {
    const paths = fixture(t);
    const contract = JSON.parse(fs.readFileSync(paths.contract, 'utf8'));
    mutation(contract);
    fs.writeFileSync(paths.contract, `${JSON.stringify(contract, null, 2)}\n`);
    assert.throws(() => verifyOciBuilderImage(
      paths.contract, paths.dockerfile, paths.entrypoint));
  }
});

test('builder stage rejects product source, binaries and authority', (t) => {
  for (const replacement of [
    ['COPY scripts/build-oss-oci.py',
      'COPY dataplane/ /usr/src/bonvoyage/dataplane/\nCOPY scripts/build-oss-oci.py'],
    ['io.routesphere.bonvoyage.release-authority="false"',
      'io.routesphere.bonvoyage.release-authority="true"'],
    ['test ! -e /opt/bonvoyage/bin/bonvoyage-dataplane',
      'cp /tmp/bonvoyage-dataplane /opt/bonvoyage/bin/bonvoyage-dataplane'],
  ]) {
    const paths = fixture(t);
    const source = fs.readFileSync(paths.dockerfile, 'utf8');
    fs.writeFileSync(paths.dockerfile, source.replaceAll(replacement[0], replacement[1]));
    assert.throws(() => verifyOciBuilderImage(
      paths.contract, paths.dockerfile, paths.entrypoint));
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
    assert.throws(() => verifyOciBuilderImage(
      paths.contract, paths.dockerfile, paths.entrypoint));
  }
});

test('local image observation is exact and grants no external identity', () => {
  const contract = JSON.parse(fs.readFileSync(CONTRACT, 'utf8'));
  const result = localObservation(contract, inspection());
  assert.equal(result.outcome, 'local-image-observed');
  assert.equal(result.registry_reference_verified, false);
  assert.equal(result.publishable, false);
  const wrong = inspection();
  wrong[0].Architecture = 'arm64';
  assert.throws(() => localObservation(contract, wrong), /does not satisfy/u);
});
