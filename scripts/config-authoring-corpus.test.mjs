import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CORPUS_ROOT = path.join(ROOT, 'config/authoring/corpus/v1');
const MANIFEST_PATH = path.join(CORPUS_ROOT, 'manifest.json');
const CORPUS_SCHEMA_PATH = path.join(
  ROOT, 'config/schemas/bonvoyage-authoring-corpus-v1.schema.json');
const RESULT_SCHEMA_PATH = path.join(
  ROOT, 'config/schemas/bonvoyage-authoring-result-v1.schema.json');
const CONTRACT_PATH = path.join(
  ROOT, 'config/authoring/bonvoyage-authoring-v1.json');

const manifest = readJson(MANIFEST_PATH);
const validateCorpus = validator(CORPUS_SCHEMA_PATH);
const validateResult = validator(RESULT_SCHEMA_PATH);

let workspace;
let executable;

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function validator(schemaPath) {
  return new Ajv2020({allErrors: true, strict: true}).compile(readJson(schemaPath));
}

function assertValid(validate, value) {
  assert.equal(
    validate(value),
    true,
    validate.errors ? JSON.stringify(validate.errors, null, 2) : 'invalid document',
  );
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function listYaml(root, relative = '') {
  const output = [];
  for (const entry of fs.readdirSync(path.join(root, relative), {withFileTypes: true})) {
    const child = path.posix.join(relative, entry.name);
    if (entry.isDirectory()) output.push(...listYaml(root, child));
    if (entry.isFile() && /\.ya?ml$/u.test(entry.name)) output.push(child);
  }
  return output.sort();
}

function invoke(document) {
  const execution = spawnSync(executable, ['validate', '--input', document], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(execution.signal, null, `command terminated by ${execution.signal}`);
  assert.equal(execution.stderr, '', `unexpected stderr: ${execution.stderr}`);
  const parsed = JSON.parse(execution.stdout);
  assertValid(validateResult, parsed);
  assert.equal(parsed.exit_code, execution.status);
  return {parsed, stdout: execution.stdout};
}

function projectedDiagnostic(diagnostic, sourceId) {
  if (diagnostic.source) assert.equal(diagnostic.source.source_id, sourceId);
  return {
    code: diagnostic.code,
    severity: diagnostic.severity,
    path: diagnostic.path ?? null,
    source: diagnostic.source ? {
      start: diagnostic.source.start,
      end: diagnostic.source.end,
    } : null,
    redacted: diagnostic.redacted,
  };
}

test.before(() => {
  workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-corpus-test-'));
  executable = path.join(workspace, 'bonvoyage-config');
  const build = spawnSync('go', ['build', '-trimpath', '-o', executable, './cmd/bonvoyage-config'], {
    cwd: path.join(ROOT, 'control-plane'),
    encoding: 'utf8',
    env: {...process.env, GOCACHE: path.join(workspace, 'go-build-cache')},
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(build.status, 0, `build failed:\n${build.stdout}\n${build.stderr}`);
});

test.after(() => {
  fs.rmSync(workspace, {recursive: true, force: true});
});

test('corpus manifest is strict, ordered and bound to the authoring authority', () => {
  assertValid(validateCorpus, manifest);

  const ids = manifest.cases.map((entry) => entry.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.deepEqual(ids, [...ids].sort());

  const contract = readJson(CONTRACT_PATH);
  assert.equal(manifest.contract_version, contract.contract_version);
  assert.equal(manifest.compiler_version, contract.authority.compiler_identity);
  assert.deepEqual(
    [manifest.configuration_schema_version],
    contract.authority.supported_configuration_schema_versions,
  );
  assert.equal(manifest.authority.semantic_validation, contract.authority.compiler_entrypoint);
  assert.equal(manifest.authority.network_access, false);
  assert.equal(manifest.authority.live_mutation, false);

  const listedCorpusYaml = manifest.cases
    .map((entry) => entry.document)
    .filter((document) => document.startsWith('config/authoring/corpus/v1/'))
    .map((document) => path.posix.relative('config/authoring/corpus/v1', document))
    .sort();
  assert.deepEqual(listYaml(CORPUS_ROOT), listedCorpusYaml);

  const missingDigest = structuredClone(manifest);
  delete missingDigest.cases[0].sha256;
  assert.equal(validateCorpus(missingDigest), false);
});

for (const corpusCase of manifest.cases) {
  test(`corpus case ${corpusCase.id} matches the real compiler`, () => {
    const filePath = path.resolve(ROOT, corpusCase.document);
    assert.equal(filePath.startsWith(`${ROOT}${path.sep}`), true);
    assert.equal(fs.lstatSync(filePath).isSymbolicLink(), false);
    assert.equal(fs.statSync(filePath).isFile(), true);

    const source = fs.readFileSync(filePath);
    assert.equal(source.length, corpusCase.bytes);
    assert.equal(sha256(source), corpusCase.sha256);

    const first = invoke(corpusCase.document);
    const second = invoke(corpusCase.document);
    assert.deepEqual(first.parsed, second.parsed);

    const result = first.parsed;
    assert.equal(result.contract_version, manifest.contract_version);
    assert.equal(result.operation, 'validate');
    assert.equal(result.status, corpusCase.expected.status);
    assert.equal(result.exit_code, corpusCase.expected.exit_code);
    assert.equal(result.failure_kind, corpusCase.expected.failure_kind);
    assert.equal(result.versions.product_version, manifest.product_version);
    assert.equal(result.versions.compiler_version, manifest.compiler_version);
    assert.deepEqual(
      result.versions.supported_configuration_schema_versions,
      [manifest.configuration_schema_version],
    );
    assert.equal(
      result.versions.input_configuration_schema_version,
      corpusCase.expected.input_configuration_schema_version,
    );
    assert.deepEqual(result.inputs, [{
      source_id: corpusCase.document,
      bytes: corpusCase.bytes,
      sha256: corpusCase.sha256,
    }]);
    assert.equal(result.diagnostics_truncated, false);

    if (corpusCase.expected.status === 'accepted') {
      assert.deepEqual(result.diagnostics, []);
      assert.deepEqual(result.result, {
        kind: 'validation',
        valid: true,
        artifact: corpusCase.expected.artifact,
      });
    } else {
      assert.equal(result.diagnostics.length, 1);
      assert.deepEqual(
        projectedDiagnostic(result.diagnostics[0], corpusCase.document),
        corpusCase.expected.diagnostic,
      );
      assert.deepEqual(result.result, {
        kind: 'validation',
        valid: false,
        artifact: null,
      });
    }

    for (const forbidden of corpusCase.forbidden_output_literals ?? []) {
      assert.equal(first.stdout.includes(forbidden), false);
    }
  });
}
