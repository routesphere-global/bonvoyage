import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  recordHostedProvenance,
  resolveHostedProvenanceSubject,
} from './record-oss-hosted-provenance.mjs';

const COMMIT = 'a'.repeat(40);
const TAG = 'v1.0.0-rc.14';
const REPOSITORY = 'routesphere-global/bonvoyage';

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function writeCanonical(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function fixture(t, format) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `bonvoyage-${format}-provenance-`));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const input = path.join(root, 'input');
  fs.mkdirSync(input);
  const payload = Buffer.from(`exact-${format}-candidate`);
  const filename = format === 'debian'
    ? 'bonvoyage-gateway_1.0.0~rc.14-1_amd64.deb'
    : 'bonvoyage-gateway-1.0.0-rc.14-linux-amd64.oci.tar';
  fs.writeFileSync(path.join(input, filename), payload);
  const source = {
    repository: `https://github.com/${REPOSITORY}`,
    commit: COMMIT,
    tag: TAG,
    dirty: false,
  };
  const receiptName = format === 'debian' ? 'build-receipt.json' : 'oci-builder-execution.json';
  writeCanonical(path.join(input, receiptName), {
    schema_version: 1,
    classification: format === 'debian'
      ? 'routesphere-bonvoyage-oss-deb-build'
      : 'routesphere-bonvoyage-oss-oci-builder-execution',
    source,
    [format === 'debian' ? 'package' : 'archive']: {
      path: filename,
      bytes: payload.length,
      sha256: sha256(payload),
    },
    technical_candidate_built: true,
    release_admitted: false,
    publishable: false,
  });
  const workflow = format === 'debian'
    ? '.github/workflows/oss-deb-reproducibility.yml'
    : '.github/workflows/oss-oci-reproducibility.yml';
  const bundle = path.join(root, 'bundle.jsonl');
  fs.writeFileSync(bundle, '{"signedEnvelope":"fixture"}\n');
  return {
    root,
    input,
    bundle,
    output: path.join(root, 'output'),
    options: {
      format,
      input,
      repository: REPOSITORY,
      commit: COMMIT,
      tag: TAG,
      runId: '42',
      runAttempt: '1',
      workflowRef: `${REPOSITORY}/${workflow}@refs/tags/${TAG}`,
      workflowSha: COMMIT,
    },
  };
}

for (const format of ['debian', 'oci']) {
  test(`resolves and records exact ${format} hosted provenance without release authority`, (t) => {
    const value = fixture(t, format);
    const resolved = resolveHostedProvenanceSubject(value.options);
    assert.equal(resolved.subject.sha256,
      sha256(Buffer.from(`exact-${format}-candidate`)));
    const result = recordHostedProvenance({
      ...value.options,
      bundle: value.bundle,
      attestationId: 'attestation-1234',
      attestationUrl:
        'https://github.com/routesphere-global/bonvoyage/attestations/1234',
      output: value.output,
    });
    assert.equal(result.receipt.format, format);
    assert.equal(result.receipt.subject.sha256, resolved.subject.sha256);
    assert.equal(result.receipt.attestation.slsa_build_level, 2);
    assert.equal(result.receipt.authority.provenance_created, true);
    assert.equal(result.receipt.authority.signature_created, false);
    assert.equal(result.receipt.authority.release_admitted, false);
    assert.equal(result.receipt.authority.publishable, false);
    assert.deepEqual(fs.readdirSync(value.output).sort(),
      ['provenance-receipt.json', 'provenance.sigstore.jsonl']);
    assert.equal(fs.readFileSync(result.receiptPath, 'utf8'),
      `${JSON.stringify(result.receipt, null, 2)}\n`);
  });
}

test('rejects payload bytes that do not match the producer receipt', (t) => {
  const value = fixture(t, 'debian');
  fs.appendFileSync(path.join(value.input,
    'bonvoyage-gateway_1.0.0~rc.14-1_amd64.deb'), 'changed');
  assert.throws(() => resolveHostedProvenanceSubject(value.options),
    /subject bytes do not match/u);
});

test('rejects source, workflow and repository mismatches', (t) => {
  const value = fixture(t, 'oci');
  assert.throws(() => resolveHostedProvenanceSubject({
    ...value.options,
    repository: 'fork/bonvoyage',
  }), /public-repository-only/u);
  assert.throws(() => resolveHostedProvenanceSubject({
    ...value.options,
    workflowRef: `${REPOSITORY}/.github/workflows/release.yml@refs/tags/${TAG}`,
  }), /expected tagged producer workflow/u);
  assert.throws(() => resolveHostedProvenanceSubject({
    ...value.options,
    commit: 'b'.repeat(40),
    workflowSha: 'b'.repeat(40),
  }), /exact clean public source/u);
});

test('rejects non-repository attestation URLs and nonempty output directories', (t) => {
  const value = fixture(t, 'debian');
  assert.throws(() => recordHostedProvenance({
    ...value.options,
    bundle: value.bundle,
    attestationId: 'attestation-1234',
    attestationUrl: 'https://example.test/attestations/1234',
    output: value.output,
  }), /must identify this public repository/u);
  fs.mkdirSync(value.output);
  fs.writeFileSync(path.join(value.output, 'unexpected'), 'x');
  assert.throws(() => recordHostedProvenance({
    ...value.options,
    bundle: value.bundle,
    attestationId: 'attestation-1234',
    attestationUrl:
      'https://github.com/routesphere-global/bonvoyage/attestations/1234',
    output: value.output,
  }), /must be empty/u);
});
