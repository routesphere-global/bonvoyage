import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import test from 'node:test';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';

import {
  CLAIM_BOUNDARY,
  REPOSITORY_ROOT,
  collectBindings,
  evaluatePreflight,
  schemaErrors,
  inspectArtifactLockDocument,
  inspectValidationReceiptDocument,
  verifyChecksumManifest,
  runtimeChangesRequiringHardening,
} from './dedicated-preflight.mjs';

test('hardening manifests accept sha256sum forms and reject unsafe or altered evidence', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-rc-manifest-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const directory = path.join(root, 'evidence');
  fs.mkdirSync(directory);
  const digest = createHash('sha256').update('verified\n').digest('hex');
  fs.writeFileSync(path.join(directory, 'result.txt'), 'verified\n');
  const manifest = path.join(directory, 'checksums.sha256');
  for (const filename of ['result.txt', './result.txt']) {
    for (const mode of [' ', '*']) {
      fs.writeFileSync(manifest, `${digest} ${mode}${filename}\n`);
      assert.deepEqual(verifyChecksumManifest(directory), {valid: true, entries: 1});
    }
  }
  fs.writeFileSync(path.join(root, 'outside.txt'), 'verified\n');
  fs.symlinkSync(path.join(root, 'outside.txt'), path.join(directory, 'link.txt'));
  fs.symlinkSync(root, path.join(directory, 'outside-directory'));
  for (const filename of ['../outside.txt', path.join(root, 'outside.txt'),
    'link.txt', 'outside-directory/outside.txt', '.', '..', 'missing.txt']) {
    fs.writeFileSync(manifest, `${digest}  ${filename}\n`);
    assert.equal(verifyChecksumManifest(directory).valid, false, filename);
  }
  fs.writeFileSync(manifest, `${digest}  result.txt\n${digest}  ./result.txt\n`);
  assert.equal(verifyChecksumManifest(directory).valid, false);
  fs.writeFileSync(manifest, `${'0'.repeat(64)}  result.txt\n`);
  assert.equal(verifyChecksumManifest(directory).valid, false);
  fs.writeFileSync(manifest, '');
  assert.equal(verifyChecksumManifest(directory).valid, false);
});

test('dedicated artifacts bind the actual accounting and analysis source', () => {
  const bindings = collectBindings({
    campaignPath: 'benchmarks/plans/dedicated-qualification-v1.yaml',
    productLock: {path: 'benchmarks/products/lock.json',
      absolutePath: path.join(REPOSITORY_ROOT, 'benchmarks/products/lock.json')},
    tuningPolicyPath: 'deploy/tuning/policies/throughput-balanced.yaml',
  });
  for (const [id, file] of [
    ['environment-supervisor', 'benchmarks/scripts/dedicated-collection-supervisor.mjs'],
    ['phase1-runner', 'benchmarks/scripts/run-phase1-scaling.sh'],
    ['phase1-accounting', 'benchmarks/scripts/phase1-accounting.jq'],
    ['phase2-analyzer', 'benchmarks/scripts/summarize-phase2.mjs'],
    ['benchmark-fairness-contract', 'benchmarks/contracts/benchmark-fairness.md'],
    ['dedicated-security-plan', 'benchmarks/contracts/dedicated-security-test-plan.md'],
  ]) {
    assert.deepEqual(bindings.find((binding) => binding.id === id), {
      id, path: file,
      sha256: createHash('sha256').update(fs.readFileSync(path.join(REPOSITORY_ROOT, file))).digest('hex'),
    });
  }
});

function fixture(name) {
  return JSON.parse(fs.readFileSync(
    path.join(REPOSITORY_ROOT, 'benchmarks/spec/fixtures', name),
    'utf8',
  ));
}

function evidence(id, status, valid) {
  return {
    id,
    status,
    valid,
    required_for_strict: true,
    path: `evidence/${id}.json`,
    sha256: 'a'.repeat(64),
    message: valid ? `${id} accepted` : `${id} missing`,
  };
}

function readyInput(mode = 'strict') {
  const sourceCommit = 'a'.repeat(40);
  return {
    mode,
    generatedAt: '2026-09-05T01:00:00Z',
    campaign: {
      id: 'phase1-phase3-dedicated-qualification-v1',
      status: 'frozen',
      hasInfra001: true,
    },
    source: {
      commit: sourceCommit,
      remote_ref: 'origin/main',
      clean: true,
      pushed: true,
      hardening_commit: sourceCommit,
      runtime_changes_since_hardening: [],
    },
    auditorHost: {
      operating_system: 'Ubuntu 24.04 LTS',
      architecture: 'x86_64',
      target_compatible: true,
    },
    bindings: fixture('dedicated-artifact-lock.valid.json').input_bindings,
    hardening: evidence('local-hardening', 'reusable-nonpublication', true),
    comparator: evidence('comparator-identity', 'accepted', true),
    artifactLock: evidence('artifact-lock', 'accepted', true),
    validationReceipt: evidence('validation-receipt', 'accepted', true),
  };
}

test('a complete strict preflight is deterministic and authorizes allocation', () => {
  const first = evaluatePreflight(readyInput());
  const later = evaluatePreflight({
    ...readyInput(),
    generatedAt: '2026-09-05T02:00:00Z',
  });
  assert.equal(first.status, 'ready');
  assert.equal(first.allocation_authorized, true);
  assert.equal(first.preflight_id, later.preflight_id);
  assert.equal(first.claim_boundary, CLAIM_BOUNDARY);
  assert.deepEqual(first.blockers, []);
});

test('candidate mode can report readiness but never authorizes spending', () => {
  const report = evaluatePreflight(readyInput('candidate'));
  assert.equal(report.status, 'ready');
  assert.equal(report.allocation_authorized, false);
  assert.deepEqual(report.warnings, ['candidate-mode']);
});

test('rehearsal readiness precedes campaign freeze without authorizing allocation', () => {
  const input = readyInput('rehearsal');
  input.campaign.status = 'pre-execution';
  const report = evaluatePreflight(input);
  assert.equal(report.status, 'ready');
  assert.equal(report.allocation_authorized, false);
  assert.deepEqual(report.blockers, []);
  assert.deepEqual(report.warnings, ['campaign-frozen', 'rehearsal-mode']);
  assert.equal(report.checks.find(({id}) => id === 'campaign-frozen').status, 'warn');
  assert.equal(report.preflight_id, evaluatePreflight({
    ...input, generatedAt: '2026-09-06T01:00:00Z',
  }).preflight_id);
  for (const mode of ['candidate', 'strict']) {
    const blocked = evaluatePreflight({...input, mode});
    assert.deepEqual(blocked.blockers, ['campaign-frozen']);
    assert.equal(blocked.allocation_authorized, false);
    assert.notEqual(blocked.preflight_id, report.preflight_id);
  }
  const frozen = evaluatePreflight(readyInput('rehearsal'));
  assert.equal(frozen.status, 'ready');
  assert.equal(frozen.allocation_authorized, false);
  assert.deepEqual(frozen.warnings, ['rehearsal-mode']);
});

test('rehearsal keeps every non-freeze gate fail closed', async (t) => {
  const mutations = [
    ['campaign-contract', (input) => { input.campaign.hasInfra001 = false; }],
    ['campaign-frozen', (input) => { input.campaign.status = 'unknown'; }],
    ['source-clean', (input) => { input.source.clean = false; }],
    ['source-pushed', (input) => { input.source.pushed = false; }],
    ['runtime-equivalence', (input) => { input.source.runtime_changes_since_hardening = ['dataplane/src/gateway.cc']; }],
    ['binding-integrity', (input) => { input.bindingsValid = false; }],
    ...[['hardening-evidence', 'hardening'], ['comparator-identity', 'comparator'],
      ['artifact-lock', 'artifactLock'], ['validation-receipt', 'validationReceipt']]
      .map(([gate, key]) => [gate, (input) => { input[key] = evidence(input[key].id, 'invalid', false); }]),
  ];
  for (const [gate, mutate] of mutations) {
    await t.test(gate, () => {
      const input = readyInput('rehearsal');
      input.campaign.status = 'pre-execution';
      mutate(input);
      const report = evaluatePreflight(input);
      assert.equal(report.status, 'blocked');
      assert.equal(report.allocation_authorized, false);
      assert.deepEqual(report.blockers, [gate]);
    });
  }
});

test('schema rejects rehearsal spending and promotion without a passed freeze check', () => {
  const input = readyInput('rehearsal');
  input.campaign.status = 'pre-execution';
  const report = evaluatePreflight(input);
  const schema = 'benchmarks/spec/dedicated-preflight.schema.json';
  assert.deepEqual(schemaErrors(schema, report), []);
  assert.notDeepEqual(schemaErrors(schema, {...report, allocation_authorized: true}), []);
  assert.notDeepEqual(schemaErrors(schema, {...report, mode: 'strict', allocation_authorized: true}), []);
  const strict = evaluatePreflight(readyInput());
  strict.checks = strict.checks.filter(({id}) => id !== 'campaign-frozen');
  assert.notDeepEqual(schemaErrors(schema, strict), []);
});

test('public Make entry point invokes the non-authorizing rehearsal mode', () => {
  const command = execFileSync('make', ['--dry-run', 'dedicated-preflight-rehearsal'], {
    cwd: REPOSITORY_ROOT, encoding: 'utf8',
  });
  assert.match(command, /dedicated-preflight\.mjs --mode rehearsal/);
});

test('source, campaign, and runtime deviations independently block strict mode', () => {
  const input = readyInput();
  input.campaign.status = 'pre-execution';
  input.source.clean = false;
  input.source.pushed = false;
  input.source.runtime_changes_since_hardening = ['dataplane/src/gateway.cc'];
  const report = evaluatePreflight(input);
  assert.equal(report.status, 'blocked');
  assert.equal(report.allocation_authorized, false);
  assert.deepEqual(report.blockers, [
    'campaign-frozen',
    'source-clean',
    'source-pushed',
    'runtime-equivalence',
  ]);
});

test('missing immutable artifacts and receipts fail closed', () => {
  const input = readyInput();
  input.artifactLock = evidence('artifact-lock', 'missing', false);
  input.validationReceipt = evidence('validation-receipt', 'missing', false);
  const report = evaluatePreflight(input);
  assert.deepEqual(report.blockers, ['artifact-lock', 'validation-receipt']);
  assert.equal(report.allocation_authorized, false);
});

test('scanner-only changes require fresh security evidence, not a replacement gateway soak', () => {
  const tooling = ['scripts/qualify-runtime-dependencies.sh', 'benchmarks/scripts/dedicated-preflight.mjs'];
  assert.deepEqual(runtimeChangesRequiringHardening(tooling), []);
  const critical = ['dataplane/src/gateway.cc', 'deploy/docker/bonvoyage/Dockerfile',
    'scripts/build-dataplane-container.sh', 'scripts/phase3-multi-hour-hardening.sh',
    'tests/fixtures/phase3-composite-hardening.yaml', 'config/default.yaml',
    'control-plane/internal/snapshot/compiler.go', 'third_party/runtime-source.cc'];
  assert.deepEqual(runtimeChangesRequiringHardening([...tooling, ...critical]), critical.sort());
  const input = readyInput();
  input.source.runtime_changes_since_hardening = runtimeChangesRequiringHardening(tooling);
  input.artifactLock = evidence('artifact-lock', 'missing', false);
  input.validationReceipt = evidence('validation-receipt', 'missing', false);
  const report = evaluatePreflight(input);
  assert.equal(report.allocation_authorized, false);
  assert.deepEqual(report.blockers, ['artifact-lock', 'validation-receipt']);
});

test('a non-target audit host is explicit but does not forge target evidence', () => {
  const input = readyInput();
  input.auditorHost = {
    operating_system: 'Darwin fixture',
    architecture: 'aarch64',
    target_compatible: false,
  };
  const report = evaluatePreflight(input);
  assert.equal(report.status, 'ready');
  assert.equal(report.allocation_authorized, true);
  assert.deepEqual(report.warnings, ['auditor-host']);
});

test('artifact lock rejects missing products, stale source, and stale inputs', () => {
  const document = fixture('dedicated-artifact-lock.valid.json');
  const context = {
    campaignId: document.campaign_id,
    sourceCommit: document.source_commit,
    bindings: document.input_bindings,
  };
  assert.deepEqual(
    inspectArtifactLockDocument(document, context),
    {valid: true, errors: []},
  );

  const missingProduct = structuredClone(document);
  missingProduct.artifacts = missingProduct.artifacts
    .filter(({id}) => id !== 'nginx');
  assert.equal(
    inspectArtifactLockDocument(missingProduct, context).valid,
    false,
  );

  const stale = structuredClone(document);
  stale.source_commit = 'b'.repeat(40);
  stale.input_bindings[0].sha256 = '0'.repeat(64);
  const inspection = inspectArtifactLockDocument(stale, context);
  assert.equal(inspection.valid, false);
  assert.match(inspection.errors.join('\n'), /source commit/);
  assert.match(inspection.errors.join('\n'), /input bindings/);
});

test('validation receipt requires the exact lock and every required check', () => {
  const document = fixture('dedicated-validation-receipt.valid.json');
  const context = {
    campaignId: document.campaign_id,
    sourceCommit: document.source_commit,
    artifactLockPath: document.artifact_lock.path,
    artifactLockSha256: document.artifact_lock.sha256,
  };
  assert.deepEqual(
    inspectValidationReceiptDocument(document, context),
    {valid: true, errors: []},
  );

  const stale = structuredClone(document);
  stale.artifact_lock.sha256 = '0'.repeat(64);
  stale.checks = stale.checks.filter(({id}) => id !== 'http2-fuzz');
  stale.completed_at = '2026-09-04T23:59:59Z';
  const inspection = inspectValidationReceiptDocument(stale, context);
  assert.equal(inspection.valid, false);
  assert.match(inspection.errors.join('\n'), /different artifact-lock digest/);
  assert.match(inspection.errors.join('\n'), /missing http2-fuzz/);
  assert.match(inspection.errors.join('\n'), /completion precedes/);
});
