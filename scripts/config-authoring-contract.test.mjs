import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACT_PATH = path.join(
  ROOT, 'config/authoring/bonvoyage-authoring-v1.json');
const CONTRACT_SCHEMA_PATH = path.join(
  ROOT, 'config/schemas/bonvoyage-authoring-contract-v1.schema.json');
const RESULT_SCHEMA_PATH = path.join(
  ROOT, 'config/schemas/bonvoyage-authoring-result-v1.schema.json');
const CONFIG_SCHEMA_PATH = path.join(
  ROOT, 'config/schemas/bonvoyage-config.schema.json');
const EXPLANATION_CATALOG_PATH = path.join(
  ROOT,
  'control-plane/internal/configauthoring/catalog/bonvoyage-field-explanations-v1.json',
);

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function validator(schemaPath) {
  const ajv = new Ajv2020({allErrors: true, strict: true});
  return ajv.compile(readJson(schemaPath));
}

function assertValid(validate, value) {
  assert.equal(
    validate(value),
    true,
    validate.errors ? JSON.stringify(validate.errors, null, 2) : 'invalid document',
  );
}

function assertInvalid(validate, value) {
  assert.equal(validate(value), false, 'document unexpectedly passed its schema');
}

function collectPropertyNames(value, output = new Set()) {
  if (Array.isArray(value)) {
    for (const item of value) collectPropertyNames(item, output);
    return output;
  }
  if (value === null || typeof value !== 'object') return output;
  if (value.properties && typeof value.properties === 'object') {
    for (const name of Object.keys(value.properties)) output.add(name);
  }
  for (const child of Object.values(value)) collectPropertyNames(child, output);
  return output;
}

function escapePointerToken(value) {
  return value.replaceAll('~', '~0').replaceAll('/', '~1');
}

function resolveLocalReference(root, value) {
  if (!value || typeof value !== 'object' || !value.$ref) return value;
  assert.match(value.$ref, /^#\//u, 'configuration schema references must be local');
  return value.$ref.slice(2).split('/').reduce(
    (current, token) => current[token.replaceAll('~1', '/').replaceAll('~0', '~')],
    root,
  );
}

function collectConfigurationPaths(root) {
  const paths = new Set(['']);

  function visit(value, parentPath) {
    const schema = resolveLocalReference(root, value);
    if (!schema || typeof schema !== 'object') return;
    if (schema.properties && typeof schema.properties === 'object') {
      for (const [name, property] of Object.entries(schema.properties)) {
        const propertyPath = `${parentPath}/${escapePointerToken(name)}`;
        paths.add(propertyPath);
        const resolvedProperty = resolveLocalReference(root, property);
        if (resolvedProperty.type === 'array') {
          const item = resolveLocalReference(root, resolvedProperty.items);
          if (item?.properties) visit(item, `${propertyPath}/*`);
        } else if (resolvedProperty.properties) {
          visit(resolvedProperty, propertyPath);
        }
      }
    }
  }

  visit(root, '');
  return [...paths].sort();
}

function versions(inputSchemaVersion = 1) {
  return {
    product_version: '1.0.0-rc.1',
    compiler_version: 'bonvoyage-control-plane-phase4-admin-v1',
    supported_configuration_schema_versions: [1],
    input_configuration_schema_version: inputSchemaVersion,
  };
}

function input(sourceId = 'bonvoyage.yaml') {
  return {
    source_id: sourceId,
    bytes: 4096,
    sha256: 'a'.repeat(64),
  };
}

function artifact() {
  return {
    sha256: 'b'.repeat(64),
    bytes: 8192,
    snapshot_id: 'candidate-42',
    schema_version: 1,
    minimum_dataplane_version: '0.2.0',
  };
}

test('authoring contract is schema-valid and bound to current authority', () => {
  const contract = readJson(CONTRACT_PATH);
  assertValid(validator(CONTRACT_SCHEMA_PATH), contract);

  assert.equal(contract.implementation_state, 'implemented');
  assert.equal(contract.authority.compiler_entrypoint, 'snapshot.Compile');
  assert.deepEqual(contract.authority.supported_configuration_schema_versions, [1]);
  assert.equal(contract.file_detection.maximum_bytes, 1 << 20);
  assert.equal(contract.file_detection.extension_case_sensitive, false);
  assert.equal(contract.file_detection.read_only_symlink_policy,
    'resolve-to-regular-file');
  assert.equal(contract.version_binding.caller_override_allowed, false);

  const snapshotSource = fs.readFileSync(
    path.join(ROOT, 'control-plane/internal/snapshot/snapshot.go'), 'utf8');
  const adminTypes = fs.readFileSync(
    path.join(ROOT, 'control-plane/internal/adminservice/types.go'), 'utf8');
  assert.match(snapshotSource, /MaxConfigBytes\s+int64\s*=\s*1\s*<<\s*20/u);
  assert.match(snapshotSource,
    /if \*cfg\.Snapshot\.SchemaVersion != 1/u);
  assert.match(snapshotSource,
    /CompilerVersion\s*=\s*"bonvoyage-control-plane-phase4-admin-v1"/u);
  assert.match(adminTypes, /CompilerVersion\s*=\s*snapshot\.CompilerVersion/u);
});

test('all six operations remain offline, non-applying and explicit', () => {
  const contract = readJson(CONTRACT_PATH);
  assert.deepEqual(Object.keys(contract.operations),
    ['validate', 'format', 'explain', 'diff', 'migrate', 'preview']);
  for (const operation of Object.values(contract.operations)) {
    assert.equal(operation.network_access, false);
    assert.equal(operation.live_mutation, false);
    assert.ok(operation.constraints.length > 0);
  }
  assert.equal(contract.operations.validate.document_output, 'none');
  assert.equal(contract.operations.preview.document_output, 'none');
  assert.equal(contract.operations.format.in_place, 'explicit-only');
  assert.equal(contract.operations.format.requires_valid_configuration, true);
  assert.match(contract.operations.format.constraints.join(' '), /Every comment/u);
  assert.match(contract.operations.migrate.constraints.join(' '),
    /version 1 to version 1 is a no-change result/u);
  assert.match(contract.operations.preview.primary_output, /post-default artifact metadata/u);
  assert.match(contract.operations.preview.constraints.join(' '), /not enumerated/u);
  assert.equal(contract.security_boundary.live_apply, false);
  assert.equal(contract.security_boundary.telemetry, false);
});

test('diagnostic registry is unique, ordered and covers truncation', () => {
  const contract = readJson(CONTRACT_PATH);
  const resultSchema = readJson(RESULT_SCHEMA_PATH);
  const codes = contract.diagnostics.reason_codes.map((entry) => entry.code);
  assert.equal(new Set(codes).size, codes.length);
  assert.deepEqual(codes, [...codes].sort());
  assert.equal(codes.includes(contract.diagnostics.truncation_reason_code), true);
  assert.deepEqual(
    contract.diagnostics.fields.map((field) => field.name),
    ['code', 'severity', 'message', 'path', 'source', 'redacted'],
  );
  assert.deepEqual(
    contract.process_exit_codes.map((entry) => entry.code),
    [0, 2, 3, 4, 70],
  );
  assert.deepEqual(resultSchema.$defs.diagnostic.properties.code.enum, codes);
});

test('redaction registry covers every compiler secret-reference field', () => {
  const contract = readJson(CONTRACT_PATH);
  const configSchema = readJson(path.join(
    ROOT, 'config/schemas/bonvoyage-config.schema.json'));
  const schemaSecretFields = [...collectPropertyNames(configSchema)]
    .filter((name) => name.endsWith('_secret'))
    .sort();
  assert.deepEqual(
    [...contract.redaction.secret_reference_fields].sort(),
    schemaSecretFields,
  );
  assert.equal(contract.redaction.diagnostics_echo_document_values, false);
  assert.equal(contract.redaction.logs_echo_document_values, false);
  assert.equal(contract.redaction.hash_secret_values, false);
  assert.equal(contract.redaction.pem_literal_policy, 'reject-without-echo');
});

test('reviewed explanation catalog exactly covers the configuration schema', () => {
  const configurationSchema = readJson(CONFIG_SCHEMA_PATH);
  const catalog = readJson(EXPLANATION_CATALOG_PATH);
  const catalogPaths = catalog.entries.map((entry) => entry.path);

  assert.equal(catalog.schema_version, 1);
  assert.equal(catalog.classification,
    'routesphere-bonvoyage-field-explanations');
  assert.equal(catalog.contract_version,
    'bonvoyage.configuration-authoring.v1');
  assert.equal(catalog.configuration_schema_version, 1);
  assert.equal(new Set(catalogPaths).size, catalogPaths.length);
  assert.deepEqual(catalogPaths, [...catalogPaths].sort());
  assert.deepEqual(catalogPaths, collectConfigurationPaths(configurationSchema));
  for (const entry of catalog.entries) {
    assert.equal(typeof entry.title, 'string');
    assert.ok(entry.title.length > 0 && entry.title.length <= 256);
    assert.equal(typeof entry.summary, 'string');
    assert.ok(entry.summary.length > 0 && entry.summary.length <= 4096);
  }
});

test('result schema accepts deterministic success and bounded rejection', () => {
  const validate = validator(RESULT_SCHEMA_PATH);
  const accepted = {
    contract_version: 'bonvoyage.configuration-authoring.v1',
    operation: 'preview',
    status: 'accepted',
    exit_code: 0,
    failure_kind: 'none',
    versions: versions(),
    inputs: [input()],
    diagnostics: [],
    diagnostics_truncated: false,
    result: {
      kind: 'preview',
      artifact: artifact(),
      counts: {
        listeners: 1,
        virtual_hosts: 1,
        routes: 2,
        clusters: 1,
        endpoints: 1,
      },
      changes: [],
    },
  };
  assertValid(validate, accepted);

  const rejected = {
    contract_version: 'bonvoyage.configuration-authoring.v1',
    operation: 'validate',
    status: 'rejected',
    exit_code: 2,
    failure_kind: 'validation',
    versions: versions(),
    inputs: [input()],
    diagnostics: [{
      code: 'BV_CFG_SCHEMA_REQUIRED_FIELD',
      severity: 'error',
      message: 'A required field is missing.',
      path: '/snapshot/schema_version',
      source: {
        source_id: 'bonvoyage.yaml',
        start: {line: 5, column: 1, byte_offset: 72},
        end: {line: 5, column: 1, byte_offset: 72},
      },
      redacted: false,
    }],
    diagnostics_truncated: false,
    result: {kind: 'validation', valid: false, artifact: null},
  };
  assertValid(validate, rejected);
});

test('result schema rejects status, location and operation contradictions', () => {
  const validate = validator(RESULT_SCHEMA_PATH);
  const accepted = {
    contract_version: 'bonvoyage.configuration-authoring.v1',
    operation: 'validate',
    status: 'accepted',
    exit_code: 0,
    failure_kind: 'none',
    versions: versions(),
    inputs: [input()],
    diagnostics: [],
    diagnostics_truncated: false,
    result: {kind: 'validation', valid: true, artifact: artifact()},
  };

  const wrongExit = structuredClone(accepted);
  wrongExit.exit_code = 2;
  assertInvalid(validate, wrongExit);

  const wrongResult = structuredClone(accepted);
  wrongResult.result = {
    kind: 'field-explanation',
    path: '/listeners',
    title: 'Listeners',
    summary: 'Listener definitions.',
  };
  assertInvalid(validate, wrongResult);

  const acceptedInvalid = structuredClone(accepted);
  acceptedInvalid.result = {kind: 'validation', valid: false, artifact: null};
  assertInvalid(validate, acceptedInvalid);

  const badLocation = structuredClone(accepted);
  badLocation.status = 'rejected';
  badLocation.exit_code = 2;
  badLocation.failure_kind = 'validation';
  badLocation.result = null;
  badLocation.diagnostics = [{
    code: 'BV_CFG_YAML_SYNTAX',
    severity: 'error',
    message: 'The YAML document is not syntactically valid.',
    source: {
      source_id: 'bonvoyage.yaml',
      start: {line: 0, column: 1, byte_offset: 0},
      end: {line: 1, column: 2, byte_offset: 1},
    },
    redacted: true,
  }];
  assertInvalid(validate, badLocation);

  const acceptedWithError = structuredClone(accepted);
  acceptedWithError.diagnostics = [{
    code: 'BV_CFG_INTERNAL',
    severity: 'error',
    message: 'Internal failure.',
    redacted: false,
  }];
  assertInvalid(validate, acceptedWithError);

  const unknownCode = structuredClone(badLocation);
  unknownCode.diagnostics[0].source.start.line = 1;
  unknownCode.diagnostics[0].code = 'BV_CFG_NOT_REGISTERED';
  assertInvalid(validate, unknownCode);

  const rejectedValid = structuredClone(badLocation);
  rejectedValid.diagnostics[0].source.start.line = 1;
  rejectedValid.result = {kind: 'validation', valid: true, artifact: artifact()};
  assertInvalid(validate, rejectedValid);

  const missingTruncationMarker = structuredClone(badLocation);
  missingTruncationMarker.diagnostics[0].source.start.line = 1;
  missingTruncationMarker.diagnostics_truncated = true;
  assertInvalid(validate, missingTruncationMarker);

  const leakedPartialResult = structuredClone(badLocation);
  leakedPartialResult.operation = 'preview';
  leakedPartialResult.result = {
    kind: 'preview',
    artifact: artifact(),
    counts: {listeners: 1, virtual_hosts: 1, routes: 1, clusters: 1, endpoints: 1},
    changes: [],
  };
  assertInvalid(validate, leakedPartialResult);

  const invalidPointer = structuredClone(badLocation);
  invalidPointer.diagnostics[0].source.start.line = 1;
  invalidPointer.diagnostics[0].path = 'snapshot.schema_version';
  assertInvalid(validate, invalidPointer);
});
