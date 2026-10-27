import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';
import yaml from 'js-yaml';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACT_PATH = path.join(
  ROOT, 'config/authoring/cross-surface/v1/contract.json');
const SCHEMA_PATH = path.join(
  ROOT, 'config/schemas/bonvoyage-authoring-cross-surface-v1.schema.json');
const FOUNDER_EXPORT_ROOT = 'tools/oss-export/public-root';

function exists(relativePath) {
  return fs.existsSync(path.join(ROOT, ...relativePath.split('/')));
}

function sourceLayout() {
  const founder = exists('tools/oss-export/manifest.json') &&
    exists('console/server/gateway.go') &&
    exists('console/src/api/client.ts');
  const publicExport = !exists('tools/oss-export/manifest.json') &&
    !exists('console') &&
    exists('.github/workflows/ci.yml');

  assert.notEqual(founder, publicExport,
    'expected exactly one supported founder or public-export source layout');
  return founder ? 'founder' : 'public-export';
}

function publicPath(relativePath) {
  return sourceLayout() === 'founder'
    ? `${FOUNDER_EXPORT_ROOT}/${relativePath}`
    : relativePath;
}

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, ...relativePath.split('/')));
}

function readText(relativePath) {
  return read(relativePath).toString('utf8');
}

function readJson(relativePath) {
  return JSON.parse(readText(relativePath));
}

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function surface(contract, id) {
  const value = contract.surfaces.find((candidate) => candidate.id === id);
  assert.ok(value, `missing surface ${id}`);
  return value;
}

const contract = JSON.parse(fs.readFileSync(CONTRACT_PATH, 'utf8'));

test('cross-surface contract is strict, ordered and source-bound', () => {
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf8'));
  const validate = new Ajv2020({allErrors: true, strict: true}).compile(schema);
  assert.equal(validate(contract), true,
    validate.errors ? JSON.stringify(validate.errors, null, 2) : 'invalid contract');

  const surfaceIDs = contract.surfaces.map((entry) => entry.id);
  assert.deepEqual(surfaceIDs, [...surfaceIDs].sort());
  assert.equal(new Set(surfaceIDs).size, surfaceIDs.length);
  assert.deepEqual(surfaceIDs, [
    'claude-code-skill',
    'console',
    'go-snapshot-compiler',
    'local-command',
    'openai-codex-skill',
    'public-ci',
  ]);

  const lifecycleIDs = contract.lifecycle_requirements.map((entry) => entry.id);
  assert.deepEqual(lifecycleIDs, [...lifecycleIDs].sort());
  assert.equal(new Set(lifecycleIDs).size, lifecycleIDs.length);

  for (const binding of Object.values(contract.sources)) {
    const bytes = read(binding.path);
    assert.equal(bytes.length, binding.bytes, `${binding.path} byte count`);
    assert.equal(digest(bytes), binding.sha256, `${binding.path} SHA-256`);
  }
});

test('agreement identity and corpus inventory match the shipped authority', () => {
  const authoring = readJson('config/authoring/bonvoyage-authoring-v1.json');
  const corpus = readJson('config/authoring/corpus/v1/manifest.json');
  const skill = readJson('config/authoring/skills/v1/contract.json');

  assert.equal(contract.product_version, corpus.product_version);
  assert.equal(contract.product_version, skill.product_version);
  assert.equal(contract.contract_version, authoring.contract_version);
  assert.equal(contract.contract_version, corpus.contract_version);
  assert.equal(contract.contract_version, skill.contract_version);
  assert.equal(contract.compiler_version, authoring.authority.compiler_identity);
  assert.equal(contract.compiler_version, corpus.compiler_version);
  assert.equal(contract.compiler_version, skill.compiler_version);
  assert.deepEqual(
    contract.configuration_schema_versions,
    authoring.authority.supported_configuration_schema_versions,
  );
  assert.deepEqual(contract.configuration_schema_versions, skill.configuration_schema_versions);
  assert.equal(contract.authority.semantic_validation, corpus.authority.semantic_validation);

  const accepted = corpus.cases.filter((entry) => entry.expected.status === 'accepted');
  const rejected = corpus.cases.filter((entry) => entry.expected.status === 'rejected');
  assert.deepEqual(contract.corpus, {
    case_count: corpus.cases.length,
    accepted_count: accepted.length,
    rejected_count: rejected.length,
  });
  assert.deepEqual(contract.agreement.accepted_projection, [
    'decision',
    'artifact.sha256',
    'artifact.bytes',
    'artifact.snapshot_id',
    'artifact.schema_version',
    'artifact.minimum_dataplane_version',
  ]);
  assert.deepEqual(contract.agreement.rejected_projection, [
    'decision',
    'diagnostic.code',
    'diagnostic.path',
    'diagnostic.source.start',
    'diagnostic.source.end',
    'diagnostic.redacted',
    'forbidden-output-absence',
  ]);
});

test('compiler, command and exact skill packages share one authority', () => {
  const commandSource = readText('control-plane/cmd/bonvoyage-config/main.go');
  const validationSource = readText('control-plane/internal/configauthoring/validate.go');
  assert.match(commandSource, /configauthoring\.ValidateReader/u);
  assert.match(commandSource, /configauthoring\.ValidatePath/u);
  assert.match(validationSource, /snapshot\.Compile\(bytes\.NewReader\(input\.data\)\)/u);
  assert.match(validationSource, /snapshot\.MarshalDeterministic\(compiled\)/u);

  const corpusBinding = contract.sources.corpus_manifest;
  for (const [id, wrapperPath, assistant] of [
    ['claude-code-skill', 'config/authoring/skills/v1/wrappers/claude.json', 'claude'],
    ['openai-codex-skill', 'config/authoring/skills/v1/wrappers/openai-codex.json', 'openai-codex'],
  ]) {
    const wrapper = readJson(wrapperPath);
    const current = surface(contract, id);
    assert.equal(current.state, 'ready');
    assert.equal(current.agreement_profile, 'delegated-command');
    assert.equal(current.delegates_to, 'local-command');
    assert.equal(wrapper.assistant, assistant);
    assert.equal(wrapper.release_binding.contract_version, contract.contract_version);
    assert.equal(wrapper.release_binding.compiler_version, contract.compiler_version);
    const packagedCorpus = wrapper.package.files.find((entry) => entry.path === 'references/corpus.json');
    assert.ok(packagedCorpus, `${id} has no packaged corpus`);
    assert.equal(packagedCorpus.bytes, corpusBinding.bytes);
    assert.equal(packagedCorpus.sha256, corpusBinding.sha256);
    const packageCorpusPath = `${wrapper.package.path}/references/corpus.json`;
    assert.equal(digest(read(packageCorpusPath)), corpusBinding.sha256);
  }

  assert.equal(
    surface(contract, 'openai-codex-skill').model_qualification,
    'accepted-separate-evidence',
  );
  assert.equal(
    surface(contract, 'claude-code-skill').model_qualification,
    'deferred-separate-evidence',
  );
});

test('public CI executes the exact cross-surface contract without provider access', () => {
  const workflow = yaml.load(readText(publicPath('.github/workflows/ci.yml')));
  const runCommands = workflow.jobs.foundation.steps
    .filter((step) => typeof step.run === 'string')
    .map((step) => step.run);
  assert.ok(runCommands.includes('make test'));

  const makefile = readText(publicPath('Makefile'));
  assert.match(makefile, /test-node:[\s\S]*\$\(MAKE\) config-authoring-cross-surface-contract-test/u);
  assert.match(makefile,
    /config-authoring-cross-surface-contract-test:\n\t@node --test scripts\/config-authoring-cross-surface-contract\.test\.mjs/u);

  assert.equal(contract.authority.network_access, false);
  assert.equal(contract.authority.live_mutation, false);
  assert.equal(surface(contract, 'public-ci').state, 'ready');
  assert.equal(surface(contract, 'public-ci').agreement_profile, 'orchestration');
});

test('authenticated Console preserves bounded redacted validation diagnostics', () => {
  const openapi = yaml.load(readText('api/openapi/bonvoyage-admin-v1.yaml'));
  const validationOperation = openapi.paths['/configurations/validate'].post;
  const validationResult = openapi.components.schemas.ValidationResult;
  const validationProblem = openapi.components.schemas.ConfigurationValidationProblem;
  const diagnostic = openapi.components.schemas.ConfigurationDiagnostic;
  const sourceRange = openapi.components.schemas.ConfigurationSourceRange;
  const problem = openapi.components.schemas.Problem;
  const current = surface(contract, 'console');

  assert.equal(validationOperation.responses['200'].content['application/json'].schema.$ref,
    '#/components/schemas/ValidationResult');
  assert.equal(validationResult.properties.valid.const, true);
  assert.equal(
    validationOperation.responses['422'].content['application/problem+json'].schema.$ref,
    '#/components/schemas/ConfigurationValidationProblem',
  );
  assert.equal(validationProblem.properties.status.const, 422);
  assert.equal(validationProblem.properties.code.const, 'INVALID_CONFIGURATION');
  assert.equal(validationProblem.properties.diagnostics.minItems, 1);
  assert.equal(validationProblem.properties.diagnostics.maxItems, 256);
  assert.equal(diagnostic.properties.code.pattern, '^BV_CFG_[A-Z0-9_]+$');
  assert.equal(diagnostic.properties.path.maxLength, 4096);
  assert.equal(diagnostic.properties.redacted.type, 'boolean');
  assert.deepEqual(sourceRange.required, ['start', 'end']);
  assert.equal(Object.hasOwn(sourceRange.properties, 'source_id'), false);
  assert.equal(Object.hasOwn(problem.properties, 'diagnostics'), false);
  assert.equal(current.state, 'ready');
  assert.equal(current.gap, null);

  const sharedEvidence = [
    'api/openapi/bonvoyage-admin-v1.yaml',
    'control-plane/internal/adminservice/preview.go',
    'control-plane/internal/adminservice/validation_test.go',
    'control-plane/internal/adminapi/handler.go',
    'control-plane/internal/adminapi/validation_corpus_test.go',
  ];
  const privateEvidence = [
    'console/server/gateway.go',
    'console/server/server_test.go',
    'console/src/api/client.ts',
    'console/src/api/client.test.ts',
    'console/src/features/configuration/ConfigurationEditor.tsx',
    'console/src/features/configuration/ConfigurationValidationResult.tsx',
    'console/src/features/configuration/ConfigurationValidationResult.test.tsx',
    'console/src/features/configuration/ConfigurationEditor.test.tsx',
    'console/e2e/live-source-ip-policy-lifecycle.spec.ts',
    'console/e2e/live-authentication-lifecycle.spec.ts',
  ];
  assert.deepEqual(current.evidence, [
    ...sharedEvidence,
    ...privateEvidence,
  ]);
  for (const evidencePath of sharedEvidence) assert.equal(exists(evidencePath), true);

  const adminValidation = readText('control-plane/internal/adminservice/preview.go');
  const adminHandler = readText('control-plane/internal/adminapi/handler.go');
  assert.match(adminValidation, /configauthoring\.ValidateReader/u);
  assert.match(adminHandler, /writeConfigurationValidationProblem/u);

  if (sourceLayout() === 'founder') {
    for (const evidencePath of privateEvidence) assert.equal(exists(evidencePath), true);
    assert.match(readText('console/src/api/client.ts'),
      /isConfigurationValidationProblem/u);
    assert.match(readText('console/src/features/configuration/ConfigurationEditor.tsx'),
      /validationProblem[\s\S]*canPreview/u);
  } else {
    for (const evidencePath of privateEvidence) {
      assert.equal(exists(evidencePath), false,
        `${evidencePath} must remain outside the public export`);
    }
  }
  assert.deepEqual(contract.release_gate.blocking_surfaces, []);
  assert.equal(contract.release_gate.status, 'open');
});

test('remaining lifecycle work is enumerated rather than inferred as passed', () => {
  const states = Object.fromEntries(
    contract.lifecycle_requirements.map((entry) => [entry.id, entry.state]),
  );
  assert.deepEqual(states, {
    'downgrade-rejection': 'covered',
    'incompatible-version': 'covered',
    'malformed-output': 'covered',
    'missing-compiler': 'covered',
    'offline-install': 'covered',
    'uninstall': 'covered',
    'upgrade': 'covered',
    'windows-large-file': 'partial',
  });
  assert.deepEqual(contract.release_gate.blocking_lifecycle_requirements, [
    'windows-large-file',
  ]);
  for (const requirement of contract.lifecycle_requirements) {
    if (requirement.state === 'covered') {
      assert.ok(requirement.evidence.length > 0,
        `${requirement.id} is covered without evidence`);
    }
    for (const evidencePath of requirement.evidence) {
      assert.equal(exists(evidencePath), true,
        `${requirement.id} evidence is missing: ${evidencePath}`);
    }
  }
  assert.deepEqual(
    contract.release_gate.blocking_lifecycle_requirements,
    contract.lifecycle_requirements
      .filter((entry) => entry.state !== 'covered')
      .map((entry) => entry.id),
  );
  assert.deepEqual(contract.deferred_surfaces, [{
    id: 'notepad-plus-plus',
    release_boundary: 'oss-1.1-or-ga-beta',
    gate_behavior: 'joins-this-gate-when-shipped',
  }]);
});
