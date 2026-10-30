import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {assembleLifecycle} from './assemble-oss-artifact-lifecycle.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACT = path.join(
  ROOT, 'packaging/release/oss-artifact-lifecycle-contract.json');
const REPOSITORY = 'https://github.com/routesphere-global/bonvoyage';
const AUTHORITY = {
  release_admitted: false,
  publishable: false,
  github_release_created: false,
  package_uploaded: false,
  container_uploaded: false,
  signature_created: false,
  provenance_created: false,
};

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), {recursive: true});
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function identity(filePath) {
  const body = fs.readFileSync(filePath);
  return {bytes: body.length, sha256: digest(body)};
}

function inventory(root, excluded = new Set()) {
  const result = [];
  function walk(directory, prefix = '') {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(absolute, relative);
      else if (!excluded.has(relative)) result.push({path: relative, ...identity(absolute)});
    }
  }
  walk(root);
  return result.sort((left, right) => left.path.localeCompare(right.path));
}

function createIntake(root, commit, tag, bodies, runs) {
  const metadata = path.join(root, 'metadata/oss-candidate-intake-contract.json');
  writeJson(metadata, {schema_version: 1, classification: 'test'});
  const source = {repository: REPOSITORY, commit, tag, dirty: false};
  const artifacts = [
    ['gateway-deb-linux-amd64', 'debian-package', 'candidate.deb', bodies.deb, runs.deb],
    ['gateway-oci-linux-amd64', 'oci-image', 'candidate.oci.tar', bodies.oci, runs.oci],
  ].map(([id, kind, filename, body, hostedRunId]) => {
    const relative = `artifacts/${filename}`;
    const absolute = path.join(root, relative);
    fs.mkdirSync(path.dirname(absolute), {recursive: true});
    fs.writeFileSync(absolute, body);
    return {id, kind, platform: 'linux/amd64', path: relative,
      ...identity(absolute), hosted_run_id: hostedRunId};
  });
  const receipt = {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-candidate-intake-receipt',
    product: 'RouteSphere BonVoyage API Gateway',
    created_at: '2026-10-30T00:00:00.000Z',
    contract: {path: 'metadata/oss-candidate-intake-contract.json', ...identity(metadata)},
    source,
    artifacts,
    files: inventory(root),
    authority: {...AUTHORITY},
  };
  writeJson(path.join(root, 'candidate-intake-receipt.json'), receipt);
  return {source, artifacts};
}

function createLane(root, job, artifact, candidate, baseline, phases) {
  fs.mkdirSync(path.join(root, 'raw'), {recursive: true});
  const records = phases.map((phase) => {
    const relative = `raw/${phase.id}.txt`;
    fs.writeFileSync(path.join(root, relative), `${job}:${phase.id}:PASS\n`);
    return {
      id: phase.id,
      status: 'PASS',
      checks: Object.fromEntries(phase.required_checks.map((name) => [name, true])),
      evidence: [relative],
    };
  });
  writeJson(path.join(root, 'lane.json'), {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-artifact-lifecycle-lane',
    outcome: 'passed',
    job,
    candidate: candidate.source,
    baseline: baseline.source,
    artifact: {
      id: artifact.id,
      kind: artifact.kind,
      candidate_sha256: candidate.artifacts.find((item) => item.id === artifact.id).sha256,
      baseline_sha256: baseline.artifacts.find((item) => item.id === artifact.id).sha256,
    },
    phases: records,
    authority: {...AUTHORITY},
  });
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-assembler-'));
  const contractPath = path.join(root, 'contract.json');
  const contract = JSON.parse(fs.readFileSync(CONTRACT, 'utf8'));
  const baselineRoot = path.join(root, 'baseline');
  const candidateRoot = path.join(root, 'candidate');
  fs.mkdirSync(baselineRoot);
  fs.mkdirSync(candidateRoot);
  const baseline = createIntake(baselineRoot, 'a'.repeat(40), 'v1.0.0-rc.1',
    {deb: Buffer.from('baseline-deb'), oci: Buffer.from('baseline-oci')},
    {deb: '101', oci: '102'});
  const candidate = createIntake(candidateRoot, 'b'.repeat(40), 'v1.0.0-rc.2',
    {deb: Buffer.from('candidate-deb'), oci: Buffer.from('candidate-oci')},
    {deb: '201', oci: '202'});
  contract.baseline = {
    source: {commit: baseline.source.commit, tag: baseline.source.tag},
    hosted_runs: {debian: '101', oci: '102'},
    artifacts: baseline.artifacts.map(({id, kind, bytes, sha256}) => ({
      id, kind, bytes, sha256,
    })),
  };
  writeJson(contractPath, contract);
  const debian = contract.artifacts.find((item) => item.id === 'gateway-deb-linux-amd64');
  const oci = contract.artifacts.find((item) => item.id === 'gateway-oci-linux-amd64');
  const roots = {
    'debian-candidate-fresh': path.join(root, 'fresh'),
    'debian-transition': path.join(root, 'transition'),
    'oci-lifecycle': path.join(root, 'oci'),
  };
  createLane(roots['debian-candidate-fresh'], 'debian-candidate-fresh', debian,
    candidate, baseline, debian.phases.slice(0, 1));
  createLane(roots['debian-transition'], 'debian-transition', debian,
    candidate, baseline, debian.phases.slice(1));
  createLane(roots['oci-lifecycle'], 'oci-lifecycle', oci,
    candidate, baseline, oci.phases);
  return {root, contractPath, candidateRoot, baselineRoot, roots,
    output: path.join(root, 'output')};
}

function assemble(value) {
  return assembleLifecycle({
    contractPath: value.contractPath,
    candidateRoot: value.candidateRoot,
    baselineRoot: value.baselineRoot,
    laneRoots: value.roots,
    output: value.output,
    runId: '301',
    runAttempt: '1',
    capturedAt: '2026-10-30T01:00:00.000Z',
    allowUnpinnedContractForTests: true,
  });
}

test('assembles all exact lanes and passes the accepted lifecycle verifier', () => {
  const value = fixture();
  const report = assemble(value);
  assert.equal(report.lifecycle_qualified, true);
  assert.equal(report.release_admitted, false);
  assert.equal(report.publishable, false);
  const observation = JSON.parse(fs.readFileSync(
    path.join(value.output, 'observation.json'), 'utf8'));
  assert.equal(observation.artifacts[0].phases.length, 5);
  assert.equal(observation.artifacts[1].phases.length, 5);
});

test('accepts semantically identical lane identities with reordered fields', () => {
  const value = fixture();
  const lanePath = path.join(value.roots['debian-transition'], 'lane.json');
  const lane = JSON.parse(fs.readFileSync(lanePath, 'utf8'));
  lane.candidate = {
    commit: lane.candidate.commit,
    dirty: lane.candidate.dirty,
    repository: lane.candidate.repository,
    tag: lane.candidate.tag,
  };
  lane.baseline = {
    commit: lane.baseline.commit,
    dirty: lane.baseline.dirty,
    repository: lane.baseline.repository,
    tag: lane.baseline.tag,
  };
  writeJson(lanePath, lane);
  assert.equal(assemble(value).lifecycle_qualified, true);
});

test('rejects a changed lane identity after semantic comparison', () => {
  const value = fixture();
  const lanePath = path.join(value.roots['debian-transition'], 'lane.json');
  const lane = JSON.parse(fs.readFileSync(lanePath, 'utf8'));
  lane.candidate = {
    commit: 'c'.repeat(40),
    dirty: lane.candidate.dirty,
    repository: lane.candidate.repository,
    tag: lane.candidate.tag,
  };
  writeJson(lanePath, lane);
  assert.throws(() => assemble(value), /lane identity changed/);
});

test('rejects an unbound lane file', () => {
  const value = fixture();
  fs.writeFileSync(path.join(value.roots['oci-lifecycle'], 'raw/unbound.txt'), 'unbound\n');
  assert.throws(() => assemble(value), /unbound or missing files/);
});

test('rejects elevated lane authority', () => {
  const value = fixture();
  const lanePath = path.join(value.roots['debian-transition'], 'lane.json');
  const lane = JSON.parse(fs.readFileSync(lanePath, 'utf8'));
  lane.authority.publishable = true;
  writeJson(lanePath, lane);
  assert.throws(() => assemble(value), /must grant no release authority/);
});

test('rejects duplicate evidence binding', () => {
  const value = fixture();
  const lanePath = path.join(value.roots['debian-transition'], 'lane.json');
  const lane = JSON.parse(fs.readFileSync(lanePath, 'utf8'));
  lane.phases[1].evidence = lane.phases[0].evidence;
  writeJson(lanePath, lane);
  assert.throws(() => assemble(value), /duplicated or reserved/);
});
