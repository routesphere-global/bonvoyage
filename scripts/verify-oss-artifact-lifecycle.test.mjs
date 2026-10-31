import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {verifyArtifactLifecycle} from './verify-oss-artifact-lifecycle.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_CONTRACT = path.join(
  ROOT, 'packaging/release/oss-artifact-lifecycle-contract.json');
const REPOSITORY = 'https://github.com/routesphere-global/bonvoyage';
const LEGACY_COMMIT = '78e7cc798eab902a6cc87b7063b6bc2ef09284da';
const LEGACY_TAG = 'v1.0.0-rc.6';
const LEGACY_RUN_IDS = Object.freeze({debian: '40984886786', oci: '40984894383'});
const AUTHORITY = Object.freeze({
  release_admitted: false,
  publishable: false,
  github_release_created: false,
  package_uploaded: false,
  container_uploaded: false,
  signature_created: false,
  provenance_created: false,
});

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), {recursive: true});
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function fileIdentity(filePath) {
  const content = fs.readFileSync(filePath);
  return {bytes: content.length, sha256: sha256(content)};
}

function inventory(root, excluded = new Set()) {
  const result = [];
  function walk(directory, prefix = '') {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(absolute, relative);
      else if (!excluded.has(relative)) result.push({path: relative, ...fileIdentity(absolute)});
    }
  }
  walk(root);
  return result.sort((left, right) => left.path.localeCompare(right.path));
}

function createIntake(root, {
  commit,
  tag,
  runIds,
  artifactBodies,
  legacyRuntimeIdentityAbsence = false,
}) {
  const metadataPath = path.join(root, 'metadata/oss-candidate-intake-contract.json');
  writeJson(metadataPath, {schema_version: 1, classification: 'test-intake-contract'});
  const specifications = [
    {
      id: 'gateway-deb-linux-amd64',
      kind: 'debian-package',
      filename: `bonvoyage-gateway-${tag.slice(1)}.deb`,
      body: artifactBodies.debian,
      runId: runIds.debian,
    },
    {
      id: 'gateway-oci-linux-amd64',
      kind: 'oci-image',
      filename: `bonvoyage-gateway-${tag.slice(1)}.oci.tar`,
      body: artifactBodies.oci,
      runId: runIds.oci,
    },
  ];
  const artifacts = specifications.map((specification) => {
    const relative = `artifacts/${specification.filename}`;
    const absolute = path.join(root, relative);
    fs.mkdirSync(path.dirname(absolute), {recursive: true});
    fs.writeFileSync(absolute, specification.body);
    return {
      id: specification.id,
      kind: specification.kind,
      platform: 'linux/amd64',
      path: relative,
      ...fileIdentity(absolute),
      hosted_run_id: specification.runId,
    };
  });
  const source = {repository: REPOSITORY, commit, tag, dirty: false};
  if (legacyRuntimeIdentityAbsence) {
    writeJson(path.join(root, 'evidence/legacy-runtime-identity-absence.json'), {
      schema_version: 1,
      classification: 'routesphere-bonvoyage-legacy-runtime-identity-absence',
      scope: 'historical-lifecycle-baseline-only',
      source,
      hosted_runs: runIds,
      runtime_identity: {
        debian: ['absent', 'absent'],
        oci: ['absent', 'absent'],
      },
      authority: {...AUTHORITY},
    });
  }
  const metadata = fileIdentity(metadataPath);
  const receipt = {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-candidate-intake-receipt',
    product: 'RouteSphere BonVoyage API Gateway',
    created_at: '2026-10-30T00:00:00.000Z',
    contract: {
      path: 'metadata/oss-candidate-intake-contract.json',
      ...metadata,
    },
    source,
    artifacts,
    files: inventory(root),
    authority: {...AUTHORITY},
  };
  const receiptPath = path.join(root, 'candidate-intake-receipt.json');
  writeJson(receiptPath, receipt);
  return {
    source, artifacts, receipt, receiptPath,
    receiptSha256: fileIdentity(receiptPath).sha256,
  };
}

function summary(intake) {
  return {
    intake_receipt_sha256: intake.receiptSha256,
    source: intake.source,
    artifacts: intake.artifacts.map(({id, kind, bytes, sha256: digest}) => ({
      id, kind, bytes, sha256: digest,
    })),
  };
}

function makeFixture({
  baselineTag = 'v1.0.0-rc.1',
  candidateTag = 'v1.0.0-rc.2',
  candidateCommit = 'b'.repeat(40),
  candidateSame = false,
  legacyBaseline = false,
  legacyCandidateEvidence = false,
} = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-lifecycle-test-'));
  const baselineRoot = path.join(root, 'baseline');
  const candidateRoot = path.join(root, 'candidate');
  const evidenceRoot = path.join(root, 'evidence');
  const contractPath = path.join(root, 'contract.json');
  fs.mkdirSync(baselineRoot);
  fs.mkdirSync(candidateRoot);
  fs.mkdirSync(path.join(evidenceRoot, 'raw'), {recursive: true});
  const baselineBodies = {
    debian: Buffer.from('baseline-debian'),
    oci: Buffer.from('baseline-oci'),
  };
  const candidateBodies = candidateSame ? baselineBodies : {
    debian: Buffer.from('candidate-debian'),
    oci: Buffer.from('candidate-oci'),
  };
  const baselineRunIds = legacyBaseline ? LEGACY_RUN_IDS : {debian: '101', oci: '102'};
  const baseline = createIntake(baselineRoot, {
    commit: legacyBaseline ? LEGACY_COMMIT : 'a'.repeat(40),
    tag: legacyBaseline ? LEGACY_TAG : baselineTag,
    runIds: baselineRunIds,
    artifactBodies: baselineBodies,
    legacyRuntimeIdentityAbsence: legacyBaseline,
  });
  const candidate = createIntake(candidateRoot, {
    commit: candidateCommit,
    tag: candidateTag,
    runIds: {debian: '201', oci: '202'},
    artifactBodies: candidateBodies,
    legacyRuntimeIdentityAbsence: legacyCandidateEvidence,
  });

  const contract = JSON.parse(fs.readFileSync(DEFAULT_CONTRACT, 'utf8'));
  contract.baseline = {
    source: {commit: baseline.source.commit, tag: baseline.source.tag},
    hosted_runs: baselineRunIds,
    artifacts: baseline.artifacts.map(({id, kind, bytes, sha256: digest}) => ({
      id, kind, bytes, sha256: digest,
    })),
  };
  writeJson(contractPath, contract);
  const contractSha256 = fileIdentity(contractPath).sha256;

  const candidateById = new Map(candidate.artifacts.map((artifact) => [artifact.id, artifact]));
  const baselineById = new Map(baseline.artifacts.map((artifact) => [artifact.id, artifact]));
  const artifactObservations = contract.artifacts.map((artifact) => ({
    id: artifact.id,
    kind: artifact.kind,
    transition: artifact.transition,
    candidate_sha256: candidateById.get(artifact.id).sha256,
    baseline_sha256: baselineById.get(artifact.id).sha256,
    phases: artifact.phases.map((phase) => {
      const filename = `${artifact.id}-${phase.id}.txt`;
      const relative = `raw/${filename}`;
      const absolute = path.join(evidenceRoot, relative);
      fs.writeFileSync(absolute, `${artifact.id}:${phase.id}:PASS\n`);
      return {
        id: phase.id,
        status: 'PASS',
        checks: Object.fromEntries(phase.required_checks.map((check) => [check, true])),
        evidence: [{path: relative, ...fileIdentity(absolute)}],
      };
    }),
  }));
  const observation = {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-artifact-lifecycle-observation',
    outcome: 'passed',
    captured_at: '2026-10-30T01:00:00.000Z',
    contract: {
      path: 'packaging/release/oss-artifact-lifecycle-contract.json',
      sha256: contractSha256,
    },
    candidate: summary(candidate),
    baseline: summary(baseline),
    runner: {
      provider: 'github-actions',
      operating_system: 'ubuntu-24.04',
      architecture: 'amd64',
      run_id: '301',
      run_attempt: '1',
      jobs: contract.runner.jobs,
    },
    artifacts: artifactObservations,
    authority: {...AUTHORITY},
  };
  const observationPath = path.join(evidenceRoot, 'observation.json');
  writeJson(observationPath, observation);
  return {
    root,
    contractPath,
    contract,
    baselineRoot,
    baseline,
    candidateRoot,
    candidate,
    evidenceRoot,
    observationPath,
    observation,
  };
}

function verify(fixture) {
  return verifyArtifactLifecycle({
    contractPath: fixture.contractPath,
    candidateRoot: fixture.candidateRoot,
    baselineRoot: fixture.baselineRoot,
    evidenceRoot: fixture.evidenceRoot,
    allowUnpinnedContractForTests: true,
  });
}

test('accepts exact fresh, upgrade, rollback, reactivation and removal evidence', () => {
  const fixture = makeFixture();
  const report = verify(fixture);
  assert.equal(report.outcome, 'verified-artifact-lifecycle');
  assert.equal(report.lifecycle_qualified, true);
  assert.equal(report.release_admitted, false);
  assert.equal(report.publishable, false);
  assert.equal(report.artifacts.length, 2);
});

test('accepts the retained exception only for the exact historical baseline', () => {
  const fixture = makeFixture({
    legacyBaseline: true,
    candidateTag: 'v1.0.0',
  });
  assert.equal(verify(fixture).lifecycle_qualified, true);
});

test('requires retained legacy evidence for the exact historical baseline', () => {
  const fixture = makeFixture({
    legacyBaseline: true,
    candidateTag: 'v1.0.0',
  });
  fs.unlinkSync(path.join(
    fixture.baselineRoot, 'evidence/legacy-runtime-identity-absence.json'));
  fs.rmdirSync(path.join(fixture.baselineRoot, 'evidence'));
  fixture.baseline.receipt.files = inventory(
    fixture.baselineRoot, new Set(['candidate-intake-receipt.json']));
  writeJson(fixture.baseline.receiptPath, fixture.baseline.receipt);
  assert.throws(() => verify(fixture),
    /baseline legacy runtime identity evidence must be an object/);
});

test('rejects legacy runtime-identity evidence from a candidate intake', () => {
  const fixture = makeFixture({legacyCandidateEvidence: true});
  assert.throws(() => verify(fixture),
    /candidate intake must not use the legacy runtime identity exception/);
});

test('rejects a candidate tag that is not newer than the rollback baseline', () => {
  const fixture = makeFixture({candidateTag: 'v1.0.0-rc.1'});
  assert.throws(() => verify(fixture), /candidate tag must be newer/);
});

test('orders semantic versions without numeric precision loss', () => {
  const fixture = makeFixture({
    baselineTag: 'v9007199254740992.0.0',
    candidateTag: 'v9007199254740993.0.0',
  });
  assert.equal(verify(fixture).lifecycle_qualified, true);
});

test('rejects zero-prefixed numeric prerelease identifiers', () => {
  const fixture = makeFixture({candidateTag: 'v1.0.0-rc.02'});
  assert.throws(() => verify(fixture), /zero-prefixed numeric prerelease identifier/);
});

test('rejects a candidate artifact identical to the rollback baseline', () => {
  const fixture = makeFixture({candidateSame: true});
  assert.throws(() => verify(fixture), /must differ from the rollback baseline/);
});

test('rejects changed baseline artifact bytes', () => {
  const fixture = makeFixture();
  fs.appendFileSync(path.join(fixture.baselineRoot, fixture.baseline.artifacts[0].path), 'changed');
  assert.throws(() => verify(fixture), /baseline intake tree does not match/);
});

test('rejects a baseline identity not pinned by the lifecycle contract', () => {
  const fixture = makeFixture();
  const contract = JSON.parse(fs.readFileSync(fixture.contractPath, 'utf8'));
  contract.baseline.artifacts[0].sha256 = 'f'.repeat(64);
  writeJson(fixture.contractPath, contract);
  assert.throws(() => verify(fixture), /does not match the pinned hosted identity/);
});

test('rejects a false lifecycle check', () => {
  const fixture = makeFixture();
  fixture.observation.artifacts[0].phases[0].checks.package_identity_exact = false;
  writeJson(fixture.observationPath, fixture.observation);
  assert.throws(() => verify(fixture), /package_identity_exact must be true/);
});

test('rejects a missing lifecycle phase', () => {
  const fixture = makeFixture();
  fixture.observation.artifacts[0].phases.pop();
  writeJson(fixture.observationPath, fixture.observation);
  assert.throws(() => verify(fixture), /phase count changed/);
});

test('rejects changed raw evidence', () => {
  const fixture = makeFixture();
  const evidencePath = fixture.observation.artifacts[0].phases[0].evidence[0].path;
  fs.appendFileSync(path.join(fixture.evidenceRoot, evidencePath), 'changed');
  assert.throws(() => verify(fixture), /is missing or changed/);
});

test('rejects unbound lifecycle evidence', () => {
  const fixture = makeFixture();
  fs.writeFileSync(path.join(fixture.evidenceRoot, 'raw/unbound.txt'), 'unbound\n');
  assert.throws(() => verify(fixture), /bound lifecycle evidence paths must be exactly/);
});

test('rejects elevated release authority', () => {
  const fixture = makeFixture();
  fixture.observation.authority.publishable = true;
  writeJson(fixture.observationPath, fixture.observation);
  assert.throws(() => verify(fixture), /observation\.authority\.publishable must remain false/);
});

test('rejects a repeated hosted run attempt', () => {
  const fixture = makeFixture();
  fixture.observation.runner.run_attempt = '2';
  writeJson(fixture.observationPath, fixture.observation);
  assert.throws(() => verify(fixture), /runner identity changed/);
});

test('rejects symbolic links in candidate intake evidence', () => {
  const fixture = makeFixture();
  const metadata = path.join(
    fixture.candidateRoot, 'metadata/oss-candidate-intake-contract.json');
  fs.unlinkSync(metadata);
  fs.symlinkSync('/dev/null', metadata);
  assert.throws(() => verify(fixture), /must not be a link/);
});
