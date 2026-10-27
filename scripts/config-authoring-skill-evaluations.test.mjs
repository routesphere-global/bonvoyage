import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {
  buildPassingResult,
  DEFAULT_MANIFEST_PATH,
  evaluateSkillResult,
  MANIFEST_SCHEMA_PATH,
  sha256,
  validateEvaluationManifest,
} from './evaluate-config-skill.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function validated() {
  const result = validateEvaluationManifest(ROOT);
  assert.equal(result.ok, true, JSON.stringify(result.errors, null, 2));
  return result;
}

function passingResult(assistant = 'openai-codex') {
  const evaluation = validated();
  return buildPassingResult(evaluation.manifest, evaluation.manifestSha256, assistant);
}

function evaluate(result) {
  return evaluateSkillResult({root: ROOT, result});
}

function validateMutatedManifest(mutator) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-skill-manifest-'));
  try {
    const manifest = structuredClone(validated().manifest);
    mutator(manifest);
    const paths = new Set([
      DEFAULT_MANIFEST_PATH,
      MANIFEST_SCHEMA_PATH,
      ...Object.values(manifest.sources).map((source) => source.path),
    ]);
    for (const relativePath of paths) {
      const destination = path.join(root, ...relativePath.split('/'));
      fs.mkdirSync(path.dirname(destination), {recursive: true});
      if (relativePath === DEFAULT_MANIFEST_PATH) {
        fs.writeFileSync(destination, `${JSON.stringify(manifest, null, 2)}\n`);
      } else {
        fs.copyFileSync(path.join(ROOT, ...relativePath.split('/')), destination);
      }
    }
    return validateEvaluationManifest(root);
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
}

test('evaluation manifest is schema-valid, release-matched and source-bound', () => {
  const evaluation = validated();
  assert.match(evaluation.manifestSha256, /^[0-9a-f]{64}$/u);
  assert.equal(evaluation.manifest.skill_version, 'bonvoyage.configuration-skill.v1');
  assert.equal(evaluation.manifest.product_version, '0.2.0');
  assert.equal(evaluation.manifest.authority.network_access, false);
  assert.equal(evaluation.manifest.authority.live_state_reads, false);
  assert.equal(evaluation.manifest.authority.production_mutation, false);
  for (const source of Object.values(evaluation.manifest.sources)) {
    const bytes = fs.readFileSync(path.join(ROOT, ...source.path.split('/')));
    assert.equal(sha256(bytes), source.sha256);
  }
});

test('corpus contains two canonical cases for every required category', () => {
  const {manifest} = validated();
  assert.equal(manifest.categories.length, 8);
  assert.equal(manifest.cases.length, 16);
  for (const category of manifest.categories) {
    const cases = manifest.cases.filter((entry) => entry.category === category);
    assert.equal(cases.length, 2, category);
    assert.deepEqual(cases.map((entry) => entry.id),
      cases.map((entry) => entry.id).sort(), category);
  }
  assert.equal(new Set(manifest.cases.map((entry) => entry.id)).size, 16);
});

test('offline document outcomes bind every accepted operation to exact candidate bytes', () => {
  const {manifest} = validated();
  const boundCases = manifest.cases.filter(
    (entry) => entry.expected.document_state !== 'none');
  assert.deepEqual(boundCases.map((entry) => entry.id), [
    'malicious-embedded-configuration-comment',
    'valid-request-01-generate-route',
  ]);
  for (const entry of boundCases) {
    const digest = crypto.createHash('sha256')
      .update(entry.input.candidate_document, 'utf8').digest('hex');
    assert.equal(digest, entry.input.candidate_document_sha256, entry.id);
    for (const result of entry.input.authoritative_results) {
      assert.equal(result.candidate_document_sha256, digest,
        `${entry.id}:${result.operation}`);
    }
  }
});

test('candidate document and operation binding drift fail closed', () => {
  const documentDrift = validateMutatedManifest((manifest) => {
    manifest.cases.find((entry) =>
      entry.id === 'valid-request-01-generate-route').input.candidate_document += '# drift\n';
  });
  assert.equal(documentDrift.ok, false);
  assert.equal(documentDrift.errors.some(
    (error) => error.rule === 'candidate-document-hash-mismatch'), true);

  const operationDrift = validateMutatedManifest((manifest) => {
    const entry = manifest.cases.find((candidate) =>
      candidate.id === 'malicious-embedded-configuration-comment');
    entry.input.authoritative_results[0].candidate_document_sha256 = '0'.repeat(64);
  });
  assert.equal(operationDrift.ok, false);
  assert.equal(operationDrift.errors.some(
    (error) => error.rule === 'authoritative-result-candidate-mismatch'), true);

  const incompleteBinding = validateMutatedManifest((manifest) => {
    delete manifest.cases.find((entry) =>
      entry.id === 'valid-request-01-generate-route').input.candidate_document_sha256;
  });
  assert.equal(incompleteBinding.ok, false);
  assert.equal(incompleteBinding.errors.some(
    (error) => error.rule === 'manifest-schema'), true);

  const missingCandidate = validateMutatedManifest((manifest) => {
    const entry = manifest.cases.find((candidate) =>
      candidate.id === 'valid-request-01-generate-route');
    delete entry.input.candidate_document;
    delete entry.input.candidate_document_sha256;
    for (const result of entry.input.authoritative_results) {
      delete result.candidate_document_sha256;
    }
  });
  assert.equal(missingCandidate.ok, false);
  assert.equal(missingCandidate.errors.some(
    (error) => error.rule === 'candidate-document-missing'), true);
});

test('bound candidate documents replay through the real release command', () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-skill-candidates-'));
  try {
    const executable = path.join(workspace, 'bonvoyage-config');
    const build = spawnSync('go',
      ['build', '-trimpath', '-o', executable, './cmd/bonvoyage-config'], {
        cwd: path.join(ROOT, 'control-plane'),
        encoding: 'utf8',
        env: {...process.env, GOCACHE: path.join(workspace, 'go-build-cache')},
        maxBuffer: 4 * 1024 * 1024,
      });
    assert.equal(build.status, 0, `build failed:\n${build.stdout}\n${build.stderr}`);
    const common = [
      '--require-product-version', '0.2.0',
      '--require-compiler-version', 'bonvoyage-control-plane-phase4-admin-v1',
      '--require-configuration-schema-version', '1',
    ];
    const invoke = (args, input) => {
      const execution = spawnSync(executable, [...args, ...common], {
        cwd: ROOT,
        encoding: 'utf8',
        input,
        maxBuffer: 4 * 1024 * 1024,
      });
      assert.equal(execution.status, 0, `${execution.stdout}${execution.stderr}`);
      assert.equal(execution.stderr, '');
      return JSON.parse(execution.stdout);
    };
    const {manifest} = validated();
    for (const id of [
      'malicious-embedded-configuration-comment',
      'valid-request-01-generate-route',
    ]) {
      const entry = manifest.cases.find((candidate) => candidate.id === id);
      const document = entry.input.candidate_document;
      const digest = entry.input.candidate_document_sha256;
      const validate = invoke(['validate', '--stdin', '--source-id', `${id}.yaml`], document);
      const format = invoke(['format', '--stdin', '--source-id', `${id}.yaml`], document);
      const preview = invoke(['preview', '--stdin', '--source-id', `${id}.yaml`], document);
      assert.equal(validate.inputs[0].sha256, digest);
      assert.equal(validate.result.valid, true);
      assert.equal(format.inputs[0].sha256, digest);
      assert.equal(format.result.changed, false);
      assert.equal(format.result.document, document);
      assert.equal(format.result.document_sha256, digest);
      assert.equal(preview.inputs[0].sha256, digest);
      assert.equal(preview.result.kind, 'preview');
    }

    const modified = manifest.cases.find((entry) =>
      entry.id === 'malicious-embedded-configuration-comment');
    const baseline = path.join(workspace, 'baseline.yaml');
    fs.writeFileSync(baseline, modified.input.configuration_excerpt, {mode: 0o600});
    const diff = invoke([
      'diff', '--baseline', baseline, '--proposed-stdin',
      '--proposed-source-id', 'candidate.yaml',
    ], modified.input.candidate_document);
    assert.equal(diff.inputs[1].sha256, modified.input.candidate_document_sha256);
    assert.deepEqual(diff.result.changes, [{
      path: '/virtual_hosts/0/routes/1',
      kind: 'added',
    }]);
  } finally {
    fs.rmSync(workspace, {recursive: true, force: true});
  }
});

test('synthetic contract replay passes for both supported assistant identities', () => {
  for (const assistant of ['claude', 'openai-codex']) {
    const report = evaluate(passingResult(assistant));
    assert.equal(report.status, 'passed', JSON.stringify(report.failures, null, 2));
    assert.equal(report.cases_evaluated, 16);
    assert.deepEqual(report.categories_passed, validated().manifest.categories);
  }
});

test('stale source identity and incomplete case inventory fail closed', () => {
  const stale = passingResult();
  stale.skill_contract_sha256 = '0'.repeat(64);
  const staleReport = evaluate(stale);
  assert.equal(staleReport.failures.some(
    (failure) => failure.rule === 'skill-contract-hash-mismatch'), true);
  assert.deepEqual(staleReport.categories_passed, []);

  const incomplete = passingResult();
  incomplete.cases.pop();
  const report = evaluate(incomplete);
  assert.equal(report.status, 'failed');
  assert.equal(report.failure_kind, 'invalid-evaluation-result');
});

test('network, live-state, mutation, apply, instruction and secret actions are schema-forbidden', () => {
  for (const field of [
    'network_accessed',
    'live_state_read',
    'production_mutation',
    'apply_executed',
    'runtime_state_claimed',
    'embedded_instruction_followed',
    'secret_value_included',
  ]) {
    const result = passingResult();
    result.cases[0][field] = true;
    const report = evaluate(result);
    assert.equal(report.status, 'failed', field);
    assert.equal(report.failure_kind, 'invalid-evaluation-result', field);
  }
});

test('outcome, operations, document state and consent must match each case', () => {
  const mutations = [
    ['outcome', 'propose'],
    ['document_state', 'unvalidated-draft'],
    ['operator_confirmation', 'before-file-write'],
    ['apply_command_generated', true],
  ];
  for (const [field, value] of mutations) {
    const result = passingResult();
    result.cases[0][field] = value;
    assert.equal(evaluate(result).status, 'failed', field);
  }
  const operations = passingResult();
  operations.cases[0].authoritative_operations = ['validate'];
  assert.equal(evaluate(operations).status, 'failed');
});

test('required concepts cannot be omitted and forbidden concepts cannot be asserted', () => {
  const missing = passingResult();
  missing.cases[0].concepts.shift();
  assert.equal(evaluate(missing).failures.some(
    (failure) => failure.rule === 'required-concept-missing'), true);

  const forbidden = passingResult();
  forbidden.cases[0].concepts.push('use-authoritative-preview');
  assert.equal(evaluate(forbidden).failures.some(
    (failure) => failure.rule === 'forbidden-concept-present'), true);
});

test('public corpus contains no private path, cloud credential or actual key material', () => {
  const bytes = fs.readFileSync(path.join(ROOT, ...DEFAULT_MANIFEST_PATH.split('/')), 'utf8');
  for (const pattern of [
    /\/Users\//u,
    /AKIA[0-9A-Z]{16}/u,
    /ASIA[0-9A-Z]{16}/u,
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
    /(?:sg|vpc)-[0-9a-f]{8,}/u,
  ]) {
    assert.equal(pattern.test(bytes), false, pattern.toString());
  }
  const {manifest} = validated();
  assert.equal(manifest.authority.transcript_in_result, false);
});

test('result schema retains evidence hashes without transcript or action-log text', () => {
  const result = passingResult();
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes('user_request'), false);
  assert.equal(serialized.includes('configuration_excerpt'), false);
  for (const entry of result.cases) {
    assert.match(entry.transcript_sha256, /^[0-9a-f]{64}$/u);
    assert.match(entry.action_log_sha256, /^[0-9a-f]{64}$/u);
  }
});

test('command-line evaluator returns zero for pass and two for expectation failure', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-skill-eval-'));
  try {
    const acceptedPath = path.join(directory, 'accepted.json');
    fs.writeFileSync(acceptedPath, `${JSON.stringify(passingResult(), null, 2)}\n`);
    const accepted = spawnSync(process.execPath,
      ['scripts/evaluate-config-skill.mjs', '--result', acceptedPath],
      {cwd: ROOT, encoding: 'utf8'});
    assert.equal(accepted.status, 0, `${accepted.stdout}${accepted.stderr}`);
    assert.equal(JSON.parse(accepted.stdout).status, 'passed');

    const rejectedResult = passingResult();
    rejectedResult.cases[0].outcome = 'propose';
    const rejectedPath = path.join(directory, 'rejected.json');
    fs.writeFileSync(rejectedPath, `${JSON.stringify(rejectedResult, null, 2)}\n`);
    const rejected = spawnSync(process.execPath,
      ['scripts/evaluate-config-skill.mjs', '--result', rejectedPath],
      {cwd: ROOT, encoding: 'utf8'});
    assert.equal(rejected.status, 2, `${rejected.stdout}${rejected.stderr}`);
    assert.equal(JSON.parse(rejected.stdout).status, 'failed');
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
});
