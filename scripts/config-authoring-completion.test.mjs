import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

import {
  buildCompletionMetadata,
  CONFIG_SCHEMA_PATH,
  CONTRACT_PATH,
  FIELD_HELP_PATH,
  generateCompletionMetadata,
  OUTPUT_PATH,
  renderCompletionMetadata,
} from './generate-config-completion-metadata.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const COMPLETION_SCHEMA_PATH = path.join(
  ROOT, 'config/schemas/bonvoyage-authoring-completion-v1.schema.json');

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, ...relativePath.split('/')), 'utf8'));
}

function sha256(relativePath) {
  return crypto.createHash('sha256')
    .update(fs.readFileSync(path.join(ROOT, ...relativePath.split('/'))))
    .digest('hex');
}

function sourceInputs() {
  return {
    configurationSchema: readJson(CONFIG_SCHEMA_PATH),
    fieldHelp: readJson(FIELD_HELP_PATH),
    contract: readJson(CONTRACT_PATH),
    sourceSha256: {
      authoring_contract: sha256(CONTRACT_PATH),
      configuration_schema: sha256(CONFIG_SCHEMA_PATH),
      field_explanations: sha256(FIELD_HELP_PATH),
    },
  };
}

function entry(metadata, pointer) {
  const result = metadata.entries.find((candidate) => candidate.path === pointer);
  assert.ok(result, `missing completion entry ${pointer}`);
  return result;
}

test('committed completion metadata is deterministic, current and schema-valid', () => {
  const first = generateCompletionMetadata(ROOT);
  const second = generateCompletionMetadata(ROOT);
  const committed = readJson(OUTPUT_PATH);
  assert.deepEqual(first, second);
  assert.deepEqual(committed, first);
  assert.equal(committed.$schema,
    '../../../schemas/bonvoyage-authoring-completion-v1.schema.json');
  assert.equal(
    fs.readFileSync(path.join(ROOT, ...OUTPUT_PATH.split('/')), 'utf8'),
    renderCompletionMetadata(first),
  );

  const ajv = new Ajv2020({allErrors: true, strict: true});
  const validate = ajv.compile(JSON.parse(fs.readFileSync(COMPLETION_SCHEMA_PATH, 'utf8')));
  assert.equal(validate(committed), true,
    validate.errors ? JSON.stringify(validate.errors, null, 2) : 'invalid metadata');

  const check = spawnSync(
    process.execPath,
    ['scripts/generate-config-completion-metadata.mjs', '--check'],
    {cwd: ROOT, encoding: 'utf8'},
  );
  assert.equal(check.status, 0, `${check.stdout}${check.stderr}`);
});

test('metadata covers the reviewed 160-path catalog in canonical order', () => {
  const metadata = generateCompletionMetadata(ROOT);
  const paths = metadata.entries.map((candidate) => candidate.path);
  const helpPaths = readJson(FIELD_HELP_PATH).entries.map((candidate) => candidate.path);
  assert.equal(metadata.entry_count, 160);
  assert.equal(metadata.entry_count, metadata.entries.length);
  assert.equal(new Set(paths).size, paths.length);
  assert.deepEqual(paths, [...paths].sort());
  assert.deepEqual(paths, helpPaths);
  assert.deepEqual(entry(metadata, ''), {
    path: '',
    parent_path: null,
    key: null,
    title: 'BonVoyage configuration',
    summary: 'The complete declarative desired state compiled into one immutable BonVoyage snapshot.',
    required_in_parent: true,
    secret_reference: false,
    value: {kind: 'object'},
  });
});

test('direct completion hints preserve useful literals and bounded constraints', () => {
  const metadata = generateCompletionMetadata(ROOT);
  assert.deepEqual(entry(metadata, '/listeners/*/protocol').value, {
    kind: 'string',
    enum_values: ['http1', 'http2', 'http3'],
  });
  assert.deepEqual(entry(metadata, '/snapshot/schema_version').value, {
    kind: 'integer',
    const_value: 1,
  });
  assert.deepEqual(entry(metadata, '/clusters/*/connect_timeout_ms').value, {
    kind: 'integer',
    minimum: 1,
    maximum: 60000,
  });
  assert.deepEqual(entry(metadata, '/clusters').value, {
    kind: 'array',
    min_items: 1,
    item: {kind: 'object'},
  });

  for (const candidate of metadata.entries) {
    assert.equal(Object.hasOwn(candidate.value, 'item'), candidate.value.kind === 'array');
    if (candidate.value.enum_values) {
      assert.equal(new Set(candidate.value.enum_values).size,
        candidate.value.enum_values.length);
    }
    if (Object.hasOwn(candidate.value, 'minimum') &&
        Object.hasOwn(candidate.value, 'maximum')) {
      assert.ok(candidate.value.minimum <= candidate.value.maximum);
    }
    if (Object.hasOwn(candidate.value, 'min_length') &&
        Object.hasOwn(candidate.value, 'max_length')) {
      assert.ok(candidate.value.min_length <= candidate.value.max_length);
    }
    if (Object.hasOwn(candidate.value, 'min_items') &&
        Object.hasOwn(candidate.value, 'max_items')) {
      assert.ok(candidate.value.min_items <= candidate.value.max_items);
    }
  }
});

test('secret-reference classification is exact and contains no document values', () => {
  const metadata = generateCompletionMetadata(ROOT);
  const secretPaths = metadata.entries
    .filter((candidate) => candidate.secret_reference)
    .map((candidate) => candidate.path);
  assert.deepEqual(secretPaths, [
    '/clusters/*/upstream_tls/certificate_chain_secret',
    '/clusters/*/upstream_tls/private_key_secret',
    '/clusters/*/upstream_tls/trust_bundle_secret',
    '/listeners/*/downstream_tls/certificate_chain_secret',
    '/listeners/*/downstream_tls/private_key_secret',
    '/listeners/*/downstream_tls/trust_bundle_secret',
    '/virtual_hosts/*/routes/*/api_key_auth/credentials_secret',
    '/virtual_hosts/*/routes/*/jwt_auth/jwks_secret',
  ]);
  assert.equal(metadata.security_boundary.document_values_included, false);
  assert.equal(metadata.security_boundary.secret_values_included, false);
  assert.equal(metadata.security_boundary.environment_secret_reads, false);
  assert.equal(metadata.authority.network_access, false);
  assert.equal(metadata.authority.live_mutation, false);
});

test('source identities bind the exact reviewed inputs', () => {
  const metadata = generateCompletionMetadata(ROOT);
  assert.deepEqual(metadata.sources, {
    authoring_contract: {
      path: CONTRACT_PATH,
      sha256: sha256(CONTRACT_PATH),
    },
    configuration_schema: {
      path: CONFIG_SCHEMA_PATH,
      sha256: sha256(CONFIG_SCHEMA_PATH),
    },
    field_explanations: {
      path: FIELD_HELP_PATH,
      sha256: sha256(FIELD_HELP_PATH),
    },
  });
  assert.equal(metadata.authority.semantic_validation, 'snapshot.Compile');
  assert.equal(metadata.authority.configuration_schema_role, 'structural-assistance-only');
  assert.equal(metadata.authority.completion_scope,
    'direct-structural-and-literal-hints-only');
});

test('generation fails closed when field-help coverage drifts', () => {
  const inputs = sourceInputs();
  inputs.fieldHelp.entries.pop();
  assert.throws(
    () => buildCompletionMetadata(inputs),
    /configuration schema and field-help paths differ/u,
  );
});

test('generation fails closed when the secret-reference registry drifts', () => {
  const inputs = sourceInputs();
  inputs.contract.redaction.secret_reference_fields.push('unreviewed_secret');
  assert.throws(
    () => buildCompletionMetadata(inputs),
    /complete secret-reference registry/u,
  );
});

test('generation refuses external schema references and unsupported type unions', () => {
  const external = sourceInputs();
  external.configurationSchema.properties.snapshot = {
    $ref: 'https://example.invalid/unreviewed-schema.json',
  };
  assert.throws(
    () => buildCompletionMetadata(external),
    /unsupported schema reference/u,
  );

  const union = sourceInputs();
  union.configurationSchema.properties.snapshot.type = ['object', 'null'];
  delete union.configurationSchema.properties.snapshot.$ref;
  assert.throws(
    () => buildCompletionMetadata(union),
    /union schema types are outside completion metadata v1/u,
  );
});

test('generator command refuses ambiguous or unknown modes', () => {
  for (const args of [[], ['--unknown'], ['--check', '--write']]) {
    const result = spawnSync(
      process.execPath,
      ['scripts/generate-config-completion-metadata.mjs', ...args],
      {cwd: ROOT, encoding: 'utf8'},
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /usage: generate-config-completion-metadata/u);
  }
});
