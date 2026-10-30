import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {finalizeProductSignatures} from './finalize-oss-product-signatures.mjs';
import {prepareProductSignatures} from './prepare-oss-product-signatures.mjs';
import {
  validateIndependentProductVerification,
  verifyProductSignatures,
} from './verify-oss-product-signatures.mjs';

const COMMIT = 'a'.repeat(40);
const TAG = 'v1.0.0-rc.16';

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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-product-verify-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const intake = path.join(root, 'intake');
  const evidence = path.join(root, 'evidence');
  const output = path.join(evidence, 'independent-verification');
  fs.mkdirSync(intake);
  const repositoryRoot = path.resolve(import.meta.dirname, '..');
  const candidateContract = fs.readFileSync(path.join(repositoryRoot,
    'packaging/release/oss-candidate-intake-contract.json'));
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
  const record = (value) => files.find(({path: relative}) => relative === value);
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
        id: 'gateway-deb-linux-amd64', kind: 'debian-package', platform: 'linux/amd64',
        ...record(debianPath),
      },
      {
        id: 'gateway-oci-linux-amd64', kind: 'oci-image', platform: 'linux/amd64',
        ...record(ociPath),
      },
    ],
    files,
    authority: {
      release_admitted: false, publishable: false, github_release_created: false,
      package_uploaded: false, container_uploaded: false, signature_created: false,
      provenance_created: false,
    },
  };
  write(intake, 'candidate-intake-receipt.json', `${JSON.stringify(receipt, null, 2)}\n`);

  const log = path.join(root, 'cosign-log.jsonl');
  const cosign = write(root, 'cosign-fixture', `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.COSIGN_TEST_LOG, JSON.stringify({
  args,
  oidcToken: Boolean(process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN),
  githubToken: Boolean(process.env.GITHUB_TOKEN),
}) + '\\n');
if (args[0] === 'version' && args[1] === '--json') {
  process.stdout.write(JSON.stringify({
    gitVersion: process.env.COSIGN_TEST_VERSION || 'v3.1.4',
    gitCommit: 'fixture',
  }));
  process.exit(0);
}
if (args[0] !== 'verify-blob') process.exit(2);
const mode = args.includes('--offline=true') ? 'offline' : 'online';
if (process.env.COSIGN_TEST_FAIL_MODE === mode) {
  process.stderr.write('fixture verification failure\\n');
  process.exit(1);
}
process.stdout.write('Verified OK ' + mode + '\\n');
`);
  fs.chmodSync(cosign, 0o700);
  const previousLog = process.env.COSIGN_TEST_LOG;
  const previousVersion = process.env.COSIGN_TEST_VERSION;
  const previousFailure = process.env.COSIGN_TEST_FAIL_MODE;
  process.env.COSIGN_TEST_LOG = log;
  t.after(() => {
    if (previousLog === undefined) delete process.env.COSIGN_TEST_LOG;
    else process.env.COSIGN_TEST_LOG = previousLog;
    if (previousVersion === undefined) delete process.env.COSIGN_TEST_VERSION;
    else process.env.COSIGN_TEST_VERSION = previousVersion;
    if (previousFailure === undefined) delete process.env.COSIGN_TEST_FAIL_MODE;
    else process.env.COSIGN_TEST_FAIL_MODE = previousFailure;
  });

  const githubOutput = write(root, 'github-output', '');
  prepareProductSignatures({
    intakeRoot: intake,
    output: evidence,
    sourceCommit: COMMIT,
    sourceTag: TAG,
    currentRunId: '43000000000',
    candidateRunId: '42999999999',
    createdAt: '2026-10-31T08:00:00.000Z',
    githubOutput,
  });
  for (const id of ['gateway-deb-linux-amd64', 'gateway-oci-linux-amd64']) {
    write(evidence, `signatures/${id}.sigstore.json`, `${JSON.stringify({
      mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
      verificationMaterial: {fixture: id},
    }, null, 2)}\n`);
    write(evidence, `signing-verification/${id}.online.txt`, 'Verified OK\n');
    write(evidence, `signing-verification/${id}.offline.txt`, 'Verified OK\n');
  }
  finalizeProductSignatures({
    intakeRoot: intake,
    evidenceRoot: evidence,
    createdAt: '2026-10-31T08:05:00.000Z',
    cosign,
  });
  fs.writeFileSync(log, '');
  return {root, intake, evidence, output, receipt, cosign, log};
}

function verify(value, overrides = {}) {
  return verifyProductSignatures({
    intakeRoot: value.intake,
    evidenceRoot: value.evidence,
    output: value.output,
    createdAt: '2026-10-31T08:10:00.000Z',
    cosign: value.cosign,
    ...overrides,
  });
}

test('independently verifies both product artifacts online and offline', (t) => {
  const value = fixture(t);
  process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = 'must-not-reach-verifier';
  process.env.GITHUB_TOKEN = 'must-not-reach-verifier';
  t.after(() => {
    delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    delete process.env.GITHUB_TOKEN;
  });
  const result = verify(value);
  assert.equal(result.status, 'PASS');
  assert.equal(result.independently_verified, true);
  assert.equal(result.release_admitted, false);
  const validation = validateIndependentProductVerification({
    intakeRoot: value.intake,
    evidenceRoot: value.evidence,
  });
  assert.equal(validation.receipt.authority.independently_verified, true);
  assert.equal(validation.receipt.authority.publishable, false);

  const invocations = fs.readFileSync(value.log, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(invocations.length, 5);
  assert.deepEqual(invocations.map(({args}) => args[0]), [
    'version', 'verify-blob', 'verify-blob', 'verify-blob', 'verify-blob',
  ]);
  assert.equal(invocations.filter(({args}) => args.includes('--offline=true')).length, 2);
  for (const invocation of invocations) {
    assert.equal(invocation.oidcToken, false);
    assert.equal(invocation.githubToken, false);
  }
  for (const invocation of invocations.slice(1)) {
    assert.ok(invocation.args.includes('--certificate-github-workflow-repository'));
    assert.ok(invocation.args.includes('routesphere-global/bonvoyage'));
    assert.ok(invocation.args.includes('--certificate-github-workflow-sha'));
    assert.ok(invocation.args.includes(COMMIT));
    assert.ok(invocation.args.includes('--certificate-github-workflow-ref'));
    assert.ok(invocation.args.includes(`refs/tags/${TAG}`));
    assert.ok(invocation.args.includes('--certificate-github-workflow-trigger'));
    assert.ok(invocation.args.includes('workflow_dispatch'));
  }
});

test('fails closed on changed evidence and verifier version drift', (t) => {
  const changed = fixture(t);
  fs.appendFileSync(path.join(changed.evidence,
    'signatures/gateway-deb-linux-amd64.sigstore.json'), 'changed');
  assert.throws(() => verify(changed), /does not match|inventory changed/u);

  const drifted = fixture(t);
  process.env.COSIGN_TEST_VERSION = 'v3.2.0';
  assert.throws(() => verify(drifted), /version differs/u);
  delete process.env.COSIGN_TEST_VERSION;
});

test('retains a failed attempt without issuing an independent receipt', (t) => {
  const value = fixture(t);
  process.env.COSIGN_TEST_FAIL_MODE = 'offline';
  assert.throws(() => verify(value), /fixture verification failure/u);
  assert.equal(fs.existsSync(path.join(value.output,
    'independent-verification-receipt.json')), false);
  delete process.env.COSIGN_TEST_FAIL_MODE;
});

test('rejects independent authority escalation and output reuse', (t) => {
  const value = fixture(t);
  verify(value);
  const receiptPath = path.join(value.output, 'independent-verification-receipt.json');
  const receipt = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
  receipt.authority.release_admitted = true;
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  assert.throws(() => validateIndependentProductVerification({
    intakeRoot: value.intake,
    evidenceRoot: value.evidence,
  }), /authority is invalid/u);
  assert.throws(() => verify(value), /must be new/u);
});
