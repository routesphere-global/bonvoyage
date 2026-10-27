import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import {
  REPOSITORY_ROOT,
  inspectArtifactLockDocument,
} from './dedicated-preflight.mjs';
import {
  buildArtifactLock,
  normalizeImageInspection,
} from './dedicated-artifact-lock.mjs';

function fixture(name) {
  return JSON.parse(fs.readFileSync(
    path.join(REPOSITORY_ROOT, 'benchmarks/spec/fixtures', name),
    'utf8',
  ));
}

test('image inspection accepts only the exact Linux AMD64 identity', () => {
  const digest = `sha256:${'1'.repeat(64)}`;
  const result = normalizeImageInspection({
    Id: digest,
    Os: 'linux',
    Architecture: 'amd64',
    Config: {Labels: {'org.opencontainers.image.version': '0.2.0'}},
  }, {
    id: 'bonvoyage',
    reference: 'bonvoyage-dataplane:rc-test',
  });
  assert.equal(result.id, digest);
  assert.equal(
    result.immutableReference,
    `local.routesphere.invalid/bonvoyage@${digest}`,
  );
  assert.equal(result.platformDigest, digest);

  assert.throws(
    () => normalizeImageInspection({
      Id: digest,
      Os: 'linux',
      Architecture: 'arm64',
    }, {id: 'bonvoyage', reference: 'image:test'}),
    /linux\/amd64 is required/,
  );
  assert.throws(
    () => normalizeImageInspection({
      Id: digest,
      Os: 'linux',
      Architecture: 'amd64',
    }, {
      id: 'nginx',
      reference: `nginx@${digest}`,
      expectedPlatformDigest: `sha256:${'2'.repeat(64)}`,
    }),
    /differs from locked AMD64 manifest/,
  );
});

test('Docker index identities cannot masquerade as selected platform manifests', () => {
  const digest = `sha256:${'1'.repeat(64)}`;
  for (const mediaType of ['application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json']) {
    assert.throws(() => normalizeImageInspection({
      Id: digest, Os: 'linux', Architecture: 'amd64',
      Descriptor: {mediaType, digest},
    }, {id: 'bonvoyage', reference: `bonvoyage@${digest}`,
      expectedPlatformDigest: digest}), /image index; resolve and inspect/);
  }
});

test('explicit AMD64 inspection preserves runtime identity while binding the platform manifest', () => {
  const imageId = `sha256:${'1'.repeat(64)}`;
  const platformId = `sha256:${'2'.repeat(64)}`;
  const original = {Id: imageId, Os: 'linux', Architecture: 'amd64',
    Descriptor: {mediaType: 'application/vnd.oci.image.index.v1+json', digest: imageId},
    Config: {User: '65532:65532', Labels: {profile: 'accepted'}},
    RootFS: {Type: 'layers', Layers: [`sha256:${'3'.repeat(64)}`]}};
  const selected = {...original, Id: platformId,
    Descriptor: {mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: platformId}};
  const options = {id: 'bonvoyage', reference: 'bonvoyage:accepted', platformInspection: selected};
  const normalized = normalizeImageInspection(original, options);
  assert.equal(normalized.id, imageId);
  assert.equal(normalized.platformDigest, platformId);
  assert.equal(normalized.immutableReference, `local.routesphere.invalid/bonvoyage@${imageId}`);
  for (const change of [
    {Architecture: 'arm64'},
    {Id: 'invalid'},
    {Config: {...selected.Config, User: 'root'}},
    {RootFS: {Type: 'layers', Layers: []}},
    {Descriptor: {...selected.Descriptor, digest: imageId}},
    {Descriptor: {mediaType: 'application/vnd.oci.image.index.v1+json', digest: platformId}},
  ]) {
    assert.throws(() => normalizeImageInspection(original,
      {...options, platformInspection: {...selected, ...change}}), /selected AMD64 inspection differs/);
  }
  assert.throws(() => normalizeImageInspection(original, {
    ...options, reference: `bonvoyage@${imageId}`, expectedPlatformDigest: imageId,
  }), /selected manifest differs/);
});

test('artifact-lock identity is deterministic and independent of capture time', () => {
  const source = fixture('dedicated-artifact-lock.valid.json');
  const first = buildArtifactLock({
    campaignId: source.campaign_id,
    sourceCommit: source.source_commit,
    capturedAt: '2026-09-05T00:00:00Z',
    bindings: source.input_bindings,
    artifacts: source.artifacts,
    sboms: source.sboms,
    evidence: source.evidence,
  });
  const second = buildArtifactLock({
    campaignId: source.campaign_id,
    sourceCommit: source.source_commit,
    capturedAt: '2026-09-05T02:00:00Z',
    bindings: [...source.input_bindings].reverse(),
    artifacts: [...source.artifacts].reverse(),
    sboms: [...source.sboms].reverse(),
    evidence: [...source.evidence].reverse(),
  });
  assert.equal(first.lock_id, second.lock_id);
  assert.equal(first.captured_at, '2026-09-05T00:00:00Z');
  assert.deepEqual(
    inspectArtifactLockDocument(first, {
      campaignId: source.campaign_id,
      sourceCommit: source.source_commit,
      bindings: source.input_bindings,
    }),
    {valid: true, errors: []},
  );
});

test('artifact lock fails closed when security provenance is incomplete', () => {
  const document = fixture('dedicated-artifact-lock.valid.json');
  document.evidence.find(
    ({id}) => id === 'runtime-vulnerability-summary',
  ).id = 'unrelated-evidence';
  const inspection = inspectArtifactLockDocument(document);
  assert.equal(inspection.valid, false);
  assert.match(inspection.errors.join('\n'), /runtime-vulnerability-summary/);
});
