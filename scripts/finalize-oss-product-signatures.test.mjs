import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  finalizeProductSignatures,
  validateProductSignatureReceipt,
} from './finalize-oss-product-signatures.mjs';
import {prepareProductSignatures} from './prepare-oss-product-signatures.mjs';

const COMMIT = 'a'.repeat(40);
const TAG = 'v1.0.0-rc.16';
const CURRENT_RUN = '43000000000';
const CANDIDATE_RUN = '42999999999';

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function write(root, relative, value) {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), {recursive: true});
  fs.writeFileSync(target, value);
  return target;
}

function fileRecord(root, relative) {
  const value = fs.readFileSync(path.join(root, relative));
  return {path: relative, bytes: value.length, sha256: hash(value)};
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-product-finalize-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const intake = path.join(root, 'intake');
  const evidence = path.join(root, 'evidence');
  fs.mkdirSync(intake);
  const repositoryRoot = path.resolve(import.meta.dirname, '..');
  const candidateContractSource = path.join(repositoryRoot,
    'packaging/release/oss-candidate-intake-contract.json');
  const candidateContract = fs.readFileSync(candidateContractSource);
  write(intake, 'metadata/oss-candidate-intake-contract.json', candidateContract);

  const debianPath = 'artifacts/bonvoyage-gateway_1.0.0~rc.16-1_amd64.deb';
  const ociPath = 'artifacts/bonvoyage-gateway-1.0.0-rc.16-linux-amd64.oci.tar';
  write(intake, debianPath, 'debian-candidate\n');
  write(intake, ociPath, 'oci-candidate\n');
  write(intake, 'evidence/proof.json', '{"bounded":true}\n');
  const files = [
    debianPath,
    ociPath,
    'evidence/proof.json',
    'metadata/oss-candidate-intake-contract.json',
  ].map((relative) => fileRecord(intake, relative))
    .sort((left, right) => left.path.localeCompare(right.path));
  const debian = files.find(({path: value}) => value === debianPath);
  const oci = files.find(({path: value}) => value === ociPath);
  const receipt = {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-candidate-intake-receipt',
    product: 'RouteSphere BonVoyage API Gateway',
    created_at: '2026-10-31T07:00:00.000Z',
    contract: {
      path: 'metadata/oss-candidate-intake-contract.json',
      bytes: candidateContract.length,
      sha256: hash(candidateContract),
    },
    source: {
      repository: 'https://github.com/routesphere-global/bonvoyage',
      commit: COMMIT,
      tag: TAG,
      dirty: false,
    },
    artifacts: [
      {
        id: 'gateway-deb-linux-amd64',
        kind: 'debian-package',
        platform: 'linux/amd64',
        ...debian,
      },
      {
        id: 'gateway-oci-linux-amd64',
        kind: 'oci-image',
        platform: 'linux/amd64',
        ...oci,
      },
    ],
    files,
    authority: {
      release_admitted: false,
      publishable: false,
      github_release_created: false,
      package_uploaded: false,
      container_uploaded: false,
      signature_created: false,
      provenance_created: false,
    },
  };
  write(intake, 'candidate-intake-receipt.json', `${JSON.stringify(receipt, null, 2)}\n`);
  const githubOutput = write(root, 'github-output', '');
  prepareProductSignatures({
    intakeRoot: intake,
    output: evidence,
    sourceCommit: COMMIT,
    sourceTag: TAG,
    currentRunId: CURRENT_RUN,
    candidateRunId: CANDIDATE_RUN,
    createdAt: '2026-10-31T08:00:00.000Z',
    githubOutput,
  });
  const cosign = write(root, 'cosign-fixture', `#!/usr/bin/env node
if (process.argv[2] !== 'version' || process.argv[3] !== '--json') process.exit(2);
process.stdout.write(JSON.stringify({gitVersion: 'v3.1.4', gitCommit: 'fixture'}));
`);
  fs.chmodSync(cosign, 0o700);
  for (const id of ['gateway-deb-linux-amd64', 'gateway-oci-linux-amd64']) {
    write(evidence, `signatures/${id}.sigstore.json`, `${JSON.stringify({
      mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
      verificationMaterial: {fixture: id},
    }, null, 2)}\n`);
    write(evidence, `signing-verification/${id}.online.txt`, 'Verified OK\n');
    write(evidence, `signing-verification/${id}.offline.txt`, 'Verified OK\n');
  }
  return {root, intake, evidence, receipt, cosign};
}

function finalize(value) {
  return finalizeProductSignatures({
    intakeRoot: value.intake,
    evidenceRoot: value.evidence,
    createdAt: '2026-10-31T08:05:00.000Z',
    cosign: value.cosign,
  });
}

test('finalizes exactly two checksum-bound product signatures', (t) => {
  const value = fixture(t);
  const result = finalize(value);
  assert.equal(result.status, 'PASS');
  assert.equal(result.signature_created, true);
  assert.equal(result.independently_verified, false);
  assert.equal(result.release_admitted, false);
  assert.equal(result.artifacts.length, 2);
  const validated = validateProductSignatureReceipt({
    intakeRoot: value.intake,
    evidenceRoot: value.evidence,
  });
  assert.deepEqual(validated.receipt.artifacts.map(({id}) => id), [
    'gateway-deb-linux-amd64',
    'gateway-oci-linux-amd64',
  ]);
  assert.equal(validated.receipt.authority.publishable, false);
});

test('rejects changed candidate bytes, empty bundles and extra evidence', (t) => {
  const changed = fixture(t);
  fs.appendFileSync(path.join(changed.intake, changed.receipt.artifacts[0].path), 'changed');
  assert.throws(() => finalize(changed), /changed|does not match/u);

  const emptyBundle = fixture(t);
  fs.writeFileSync(path.join(emptyBundle.evidence,
    'signatures/gateway-deb-linux-amd64.sigstore.json'), '');
  assert.throws(() => finalize(emptyBundle), /empty/u);

  const extra = fixture(t);
  write(extra.evidence, 'unexpected.txt', 'unexpected\n');
  assert.throws(() => finalize(extra), /unexpected files/u);
});

test('rejects authority escalation and receipt reuse', (t) => {
  const value = fixture(t);
  finalize(value);
  const receiptPath = path.join(value.evidence, 'product-signature-receipt.json');
  const receipt = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
  receipt.authority.publishable = true;
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  assert.throws(() => validateProductSignatureReceipt({
    intakeRoot: value.intake,
    evidenceRoot: value.evidence,
  }), /authority is invalid/u);
  assert.throws(() => finalize(value), /must be new/u);
});

test('independent evidence is excluded only for the independent verifier', (t) => {
  const value = fixture(t);
  finalize(value);
  write(value.evidence, 'independent-verification/receipt.json', '{}\n');
  assert.throws(() => validateProductSignatureReceipt({
    intakeRoot: value.intake,
    evidenceRoot: value.evidence,
  }), /inventory changed/u);
  assert.doesNotThrow(() => validateProductSignatureReceipt({
    intakeRoot: value.intake,
    evidenceRoot: value.evidence,
    allowIndependentVerification: true,
  }));
});
