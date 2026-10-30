import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {intakeReleaseCandidate} from './intake-oss-release-candidate.mjs';

const COMMIT = 'a'.repeat(40);
const TAG = 'v1.0.0-rc.7';
const DEB_RUN = '41000000001';
const OCI_RUN = '41000000002';
const CREATED_AT = '2026-10-30T04:00:00.000Z';
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACT = path.join(
  REPOSITORY_ROOT, 'packaging/release/oss-candidate-intake-contract.json');

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function sha256File(filePath) {
  return sha256(fs.readFileSync(filePath));
}

function write(root, relative, value) {
  const destination = path.join(root, relative);
  fs.mkdirSync(path.dirname(destination), {recursive: true});
  fs.writeFileSync(destination, value);
  return destination;
}

function writeJson(root, relative, value) {
  return write(root, relative, `${JSON.stringify(value, null, 2)}\n`);
}

function source() {
  return {
    repository: 'https://github.com/routesphere-global/bonvoyage',
    commit: COMMIT,
    tag: TAG,
    dirty: false,
  };
}

function powerless() {
  return {release_admitted: false, publishable: false};
}

function runtimeIdentity() {
  return {
    command: ['/work/output/.internal/install/bin/bonvoyage-dataplane',
      '--smp', '1', '--memory', '256M', '--version'],
    dataplane_version: '0.2.0',
    release_version: TAG.slice(1),
    upstream_http1_client: 'seastar-reference',
    stdout_sha256: '8'.repeat(64),
    stderr_sha256: '9'.repeat(64),
  };
}

function createFixture(t) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-intake-'));
  t.after(() => fs.rmSync(temporary, {recursive: true, force: true}));
  const debRoot = path.join(temporary, 'deb');
  const ociRoot = path.join(temporary, 'oci');
  const output = path.join(temporary, 'output');
  fs.mkdirSync(debRoot);
  fs.mkdirSync(ociRoot);

  const debBytes = Buffer.from('debian-candidate\n');
  const debPackage = {
    architecture: 'amd64',
    bytes: debBytes.length,
    path: 'bonvoyage-gateway_1.0.0~rc.7-1_amd64.deb',
    sha256: sha256(debBytes),
    version: '1.0.0~rc.7-1',
  };
  const debBuilderIds = ['a', 'b'].map((suffix) => `github-${DEB_RUN}-1-${suffix}`);
  const debBuildReceiptPaths = ['a', 'b'].map((suffix, index) => {
    const directory = `oss-deb-build-${suffix}`;
    write(debRoot, `${directory}/${debPackage.path}`, debBytes);
    writeJson(debRoot, `${directory}/builder-image-observation.json`, {
      fixture: true,
      builder: suffix,
    });
    writeJson(debRoot, `${directory}/builder-execution.json`, {
      builder_id: debBuilderIds[index],
      compiled_tests_passed: true,
      package: {
        bytes: debPackage.bytes,
        path: debPackage.path,
        sha256: debPackage.sha256,
      },
      runtime_identity: runtimeIdentity(),
      source: source(),
      technical_candidate_built: true,
      ...powerless(),
    });
    return writeJson(debRoot, `${directory}/build-receipt.json`, {
      builder_id: debBuilderIds[index],
      package: debPackage,
      source: source(),
      technical_candidate_built: true,
      ...powerless(),
    });
  });
  const debTechnical = {
    classification: 'routesphere-bonvoyage-oss-deb-reproducibility',
    outcome: 'byte-identical-technical-candidates',
    source: source(),
    builders: debBuilderIds,
    build_receipts: debBuildReceiptPaths.map((file, index) => ({
      builder_id: debBuilderIds[index],
      sha256: sha256File(file),
    })),
    package: debPackage,
    technical_reproducibility_observed: true,
    hosted_builder_independence_qualified: false,
    ...powerless(),
  };
  const debTechnicalPath = writeJson(debRoot,
    'oss-deb-comparison/reproducibility-receipt.json', debTechnical);
  writeJson(debRoot, 'oss-deb-comparison/hosted-reproducibility-receipt.json', {
    classification: 'routesphere-bonvoyage-oss-deb-hosted-reproducibility',
    outcome: 'byte-identical-hosted-technical-candidates',
    source: source(),
    workflow: {
      name: 'OSS Debian Reproducibility Candidate',
      run_id: DEB_RUN,
      run_attempt: '1',
      jobs: ['build-a', 'build-b', 'compare'],
    },
    evidence_artifacts: [
      {name: 'oss-deb-build-a', sha256: 'b'.repeat(64)},
      {name: 'oss-deb-build-b', sha256: 'c'.repeat(64)},
    ],
    technical_receipt_sha256: sha256File(debTechnicalPath),
    package: debPackage,
    technical_reproducibility_observed: true,
    hosted_builder_independence_qualified: true,
    ...powerless(),
  });

  const ociBytes = Buffer.from('oci-candidate\n');
  const ociArchive = {
    bytes: ociBytes.length,
    path: 'bonvoyage-gateway-1.0.0-rc.7-linux-amd64.oci.tar',
    sha256: sha256(ociBytes),
  };
  const manifest = {bytes: 10, digest: `sha256:${'d'.repeat(64)}`};
  const config = {bytes: 11, digest: `sha256:${'e'.repeat(64)}`};
  const layer = {
    bytes: 12,
    digest: `sha256:${'f'.repeat(64)}`,
    diff_id: `sha256:${'0'.repeat(64)}`,
  };
  const ociBuilderIds = ['a', 'b'].map((suffix) => `github-${OCI_RUN}-1-${suffix}`);
  const ociBuildReceiptPaths = ['a', 'b'].map((suffix, index) => {
    const directory = `oss-oci-build-${suffix}`;
    write(ociRoot, `${directory}/${ociArchive.path}`, ociBytes);
    writeJson(ociRoot, `${directory}/builder-image-observation.json`, {
      fixture: true,
      builder: suffix,
    });
    return writeJson(ociRoot, `${directory}/oci-builder-execution.json`, {
      archive: ociArchive,
      builder_id: ociBuilderIds[index],
      compiled_tests_passed: true,
      config,
      layer,
      manifest,
      runtime_identity: runtimeIdentity(),
      source: source(),
      technical_candidate_built: true,
      ...powerless(),
    });
  });
  const ociTechnical = {
    classification: 'routesphere-bonvoyage-oss-oci-reproducibility',
    outcome: 'byte-identical-technical-candidates',
    source: source(),
    builders: ociBuilderIds,
    build_receipts: ociBuildReceiptPaths.map((file, index) => ({
      builder_id: ociBuilderIds[index],
      sha256: sha256File(file),
    })),
    archive: ociArchive,
    manifest,
    config,
    layer,
    technical_reproducibility_observed: true,
    hosted_builder_independence_qualified: false,
    ...powerless(),
  };
  const ociTechnicalPath = writeJson(ociRoot,
    'oss-oci-comparison/reproducibility-receipt.json', ociTechnical);
  writeJson(ociRoot, 'oss-oci-comparison/hosted-reproducibility-receipt.json', {
    classification: 'routesphere-bonvoyage-oss-oci-hosted-reproducibility',
    outcome: 'byte-identical-hosted-technical-candidates',
    source: source(),
    workflow: {
      name: 'OSS OCI Reproducibility Candidate',
      run_id: OCI_RUN,
      run_attempt: '1',
      jobs: ['build-a', 'build-b', 'compare'],
    },
    evidence_artifacts: [
      {name: 'oss-oci-build-a', sha256: '1'.repeat(64)},
      {name: 'oss-oci-build-b', sha256: '2'.repeat(64)},
    ],
    technical_receipt_sha256: sha256File(ociTechnicalPath),
    archive: ociArchive,
    manifest,
    config,
    layer,
    technical_reproducibility_observed: true,
    hosted_builder_independence_qualified: true,
    ...powerless(),
  });
  return {temporary, debRoot, ociRoot, output, debPackage, ociArchive};
}

function run(fixture, overrides = {}) {
  return intakeReleaseCandidate({
    debRoot: fixture.debRoot,
    ociRoot: fixture.ociRoot,
    output: fixture.output,
    sourceCommit: COMMIT,
    sourceTag: TAG,
    debRunId: DEB_RUN,
    ociRunId: OCI_RUN,
    createdAt: CREATED_AT,
    ...overrides,
  });
}

test('intakes two exact hosted candidates without granting release authority', (t) => {
  const fixture = createFixture(t);
  const result = run(fixture);
  assert.equal(result.status, 'PASS');
  assert.equal(result.release_admitted, false);
  assert.equal(result.publishable, false);
  assert.match(result.receipt_sha256, /^[a-f0-9]{64}$/u);
  const receipt = JSON.parse(fs.readFileSync(result.receipt_path, 'utf8'));
  assert.deepEqual(receipt.source, {
    repository: 'https://github.com/routesphere-global/bonvoyage',
    commit: COMMIT,
    tag: TAG,
    dirty: false,
  });
  assert.equal(receipt.artifacts.length, 2);
  assert.equal(receipt.authority.release_admitted, false);
  assert.equal(receipt.authority.publishable, false);
  assert.equal(fs.existsSync(path.join(fixture.output,
    `evidence/debian/oss-deb-build-b/${fixture.debPackage.path}`)), false);
  assert.equal(fs.existsSync(path.join(fixture.output,
    `artifacts/${fixture.ociArchive.path}`)), true);
});

test('rejects changed candidate bytes and does not create output', (t) => {
  const fixture = createFixture(t);
  fs.appendFileSync(path.join(fixture.debRoot,
    `oss-deb-build-b/${fixture.debPackage.path}`), 'changed');
  assert.throws(() => run(fixture), /bytes do not match/u);
  assert.equal(fs.existsSync(fixture.output), false);
});

test('rejects mixed source and hosted run identities', (t) => {
  const wrongSource = createFixture(t);
  assert.throws(() => run(wrongSource, {sourceCommit: 'b'.repeat(40)}),
    /exact clean public source/u);
  assert.equal(fs.existsSync(wrongSource.output), false);

  const wrongRun = createFixture(t);
  assert.throws(() => run(wrongRun, {debRunId: '41000009999'}),
    /workflow identity changed/u);
  assert.equal(fs.existsSync(wrongRun.output), false);
});

test('rejects stale runtime product identity from a builder execution', (t) => {
  const fixture = createFixture(t);
  const executionPath = path.join(fixture.debRoot,
    'oss-deb-build-a/builder-execution.json');
  const execution = JSON.parse(fs.readFileSync(executionPath, 'utf8'));
  execution.runtime_identity.release_version = '0.2.0';
  fs.writeFileSync(executionPath, `${JSON.stringify(execution, null, 2)}\n`);
  assert.throws(() => run(fixture), /runtime release identity does not match/u);
  assert.equal(fs.existsSync(fixture.output), false);
});

test('rejects authority escalation and changed technical receipt', (t) => {
  const authority = createFixture(t);
  const hostedPath = path.join(authority.debRoot,
    'oss-deb-comparison/hosted-reproducibility-receipt.json');
  const hosted = JSON.parse(fs.readFileSync(hostedPath, 'utf8'));
  hosted.publishable = true;
  fs.writeFileSync(hostedPath, `${JSON.stringify(hosted, null, 2)}\n`);
  assert.throws(() => run(authority), /publishable must remain false/u);

  const changedReceipt = createFixture(t);
  const technicalPath = path.join(changedReceipt.ociRoot,
    'oss-oci-comparison/reproducibility-receipt.json');
  const technical = JSON.parse(fs.readFileSync(technicalPath, 'utf8'));
  technical.fixture_note = 'changed after hosted receipt';
  fs.writeFileSync(technicalPath, `${JSON.stringify(technical, null, 2)}\n`);
  assert.throws(() => run(changedReceipt), /does not bind the retained technical receipt/u);
});

test('rejects intake contract identity or authority-field drift', (t) => {
  const artifactDrift = createFixture(t);
  const changedArtifactContract = JSON.parse(fs.readFileSync(CONTRACT, 'utf8'));
  changedArtifactContract.artifacts[0].workflow = 'Renamed workflow';
  const changedArtifactContractPath = writeJson(
    artifactDrift.temporary, 'changed-artifact-contract.json', changedArtifactContract);
  assert.throws(() => run(artifactDrift, {contractPath: changedArtifactContractPath}),
    /artifact identities changed/u);
  assert.equal(fs.existsSync(artifactDrift.output), false);

  const authorityDrift = createFixture(t);
  const changedAuthorityContract = JSON.parse(fs.readFileSync(CONTRACT, 'utf8'));
  changedAuthorityContract.authority.future_release_switch = false;
  const changedAuthorityContractPath = writeJson(
    authorityDrift.temporary, 'changed-authority-contract.json', changedAuthorityContract);
  assert.throws(() => run(authorityDrift, {contractPath: changedAuthorityContractPath}),
    /authority fields must be exactly/u);
  assert.equal(fs.existsSync(authorityDrift.output), false);
});

test('rejects unexpected files, links and pre-existing output', (t) => {
  const unexpected = createFixture(t);
  write(unexpected.debRoot, 'unexpected.txt', 'unexpected\n');
  assert.throws(() => run(unexpected), /files must be exactly/u);

  const linked = createFixture(t);
  fs.symlinkSync(
    path.join(linked.ociRoot, `oss-oci-build-a/${linked.ociArchive.path}`),
    path.join(linked.ociRoot, 'linked'));
  assert.throws(() => run(linked), /symbolic link/u);

  const existing = createFixture(t);
  fs.mkdirSync(existing.output);
  assert.throws(() => run(existing), /must not already exist/u);
});
