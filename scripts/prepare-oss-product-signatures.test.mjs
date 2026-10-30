import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {prepareProductSignatures} from './prepare-oss-product-signatures.mjs';

const COMMIT = 'a'.repeat(40);
const TAG = 'v1.0.0-rc.16';
const CURRENT_RUN = '43000000000';
const CANDIDATE_RUN = '42999999999';
const CREATED_AT = '2026-10-31T08:00:00.000Z';

function hash(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function fileRecord(root, relative) {
  const value = fs.readFileSync(path.join(root, relative));
  return {path: relative, bytes: value.length, sha256: hash(value)};
}
function write(root, relative, value) {
  const target = path.join(root, relative);
  fs.mkdirSync(path.dirname(target), {recursive: true});
  fs.writeFileSync(target, value);
  return target;
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-product-signing-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const intake = path.join(root, 'intake');
  const output = path.join(root, 'output');
  fs.mkdirSync(intake);
  const repositoryRoot = path.resolve(import.meta.dirname, '..');
  const candidateContractSource = path.join(repositoryRoot,
    'packaging/release/oss-candidate-intake-contract.json');
  const contractBytes = fs.readFileSync(candidateContractSource);
  write(intake, 'metadata/oss-candidate-intake-contract.json', contractBytes);
  const deb = Buffer.from('debian-candidate\n');
  const oci = Buffer.from('oci-candidate\n');
  write(intake, 'artifacts/bonvoyage-gateway_1.0.0~rc.16-1_amd64.deb', deb);
  write(intake, 'artifacts/bonvoyage-gateway-1.0.0-rc.16-linux-amd64.oci.tar', oci);
  write(intake, 'evidence/proof.json', '{"bounded":true}\n');
  const files = [
    'artifacts/bonvoyage-gateway_1.0.0~rc.16-1_amd64.deb',
    'artifacts/bonvoyage-gateway-1.0.0-rc.16-linux-amd64.oci.tar',
    'evidence/proof.json',
    'metadata/oss-candidate-intake-contract.json',
  ].map((relative) => fileRecord(intake, relative)).sort((a, b) => a.path.localeCompare(b.path));
  const receipt = {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-candidate-intake-receipt',
    product: 'RouteSphere BonVoyage API Gateway',
    created_at: '2026-10-31T07:00:00.000Z',
    contract: {
      path: 'metadata/oss-candidate-intake-contract.json',
      bytes: contractBytes.length,
      sha256: hash(contractBytes),
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
        path: files[0].path, bytes: files[0].bytes, sha256: files[0].sha256,
      },
      {
        id: 'gateway-oci-linux-amd64', kind: 'oci-image', platform: 'linux/amd64',
        path: files[1].path, bytes: files[1].bytes, sha256: files[1].sha256,
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
  const githubOutput = write(root, 'github-output', 'existing=value\n');
  return {root, intake, output, receipt, githubOutput};
}

function run(value, overrides = {}) {
  return prepareProductSignatures({
    intakeRoot: value.intake,
    output: value.output,
    sourceCommit: COMMIT,
    sourceTag: TAG,
    currentRunId: CURRENT_RUN,
    candidateRunId: CANDIDATE_RUN,
    createdAt: CREATED_AT,
    githubOutput: value.githubOutput,
    ...overrides,
  });
}

test('prepares exactly two checksum-bound signing targets', (t) => {
  const value = fixture(t);
  const result = run(value);
  assert.equal(result.status, 'PASS');
  assert.equal(result.signature_created, false);
  assert.equal(result.release_admitted, false);
  assert.equal(result.artifacts.length, 2);
  assert.match(result.workflow_identity,
    /oss-product-signing\.yml@refs\/tags\/v1\.0\.0-rc\.16$/u);
  const plan = JSON.parse(fs.readFileSync(result.plan_path, 'utf8'));
  assert.deepEqual(plan.artifacts.map(({id}) => id), [
    'gateway-deb-linux-amd64', 'gateway-oci-linux-amd64',
  ]);
  const outputs = fs.readFileSync(value.githubOutput, 'utf8');
  assert.match(outputs, /^existing=value\ndebian_artifact=/u);
  assert.match(outputs, /oci_bundle=.*gateway-oci-linux-amd64\.sigstore\.json/u);
});

test('rejects changed, extra, linked and mixed-source candidate input', (t) => {
  const changed = fixture(t);
  fs.appendFileSync(path.join(changed.intake, changed.receipt.artifacts[0].path), 'changed');
  assert.throws(() => run(changed), /inventory|bytes do not match/u);
  assert.equal(fs.existsSync(changed.output), false);

  const extra = fixture(t);
  write(extra.intake, 'unexpected.txt', 'unexpected\n');
  assert.throws(() => run(extra), /inventory/u);

  const linked = fixture(t);
  fs.symlinkSync('proof.json', path.join(linked.intake, 'evidence/link.json'));
  assert.throws(() => run(linked), /link/u);

  const mixed = fixture(t);
  assert.throws(() => run(mixed, {sourceCommit: 'b'.repeat(40)}), /source does not match/u);
});

test('rejects authority escalation and output reuse', (t) => {
  const escalated = fixture(t);
  const receiptPath = path.join(escalated.intake, 'candidate-intake-receipt.json');
  const receipt = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
  receipt.authority.publishable = true;
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  assert.throws(() => run(escalated), /publishable must remain false/u);

  const reused = fixture(t);
  fs.mkdirSync(reused.output);
  assert.throws(() => run(reused), /output directory must be new/u);
});
