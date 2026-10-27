import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
export const ROOT = path.resolve(path.dirname(SCRIPT_PATH), '..');
export const OUTPUT_PATH = 'config/authoring/completion/v1/metadata.json';
export const CONFIG_SCHEMA_PATH = 'config/schemas/bonvoyage-config.schema.json';
export const CONTRACT_PATH = 'config/authoring/bonvoyage-authoring-v1.json';
export const FIELD_HELP_PATH =
  'control-plane/internal/configauthoring/catalog/bonvoyage-field-explanations-v1.json';

const CLASSIFICATION = 'routesphere-bonvoyage-configuration-completion-metadata';
const COMPLETION_VERSION = 'bonvoyage.configuration-completion.v1';
const SIMPLE_KINDS = new Set(['string', 'integer', 'number', 'boolean']);

function readBoundSource(root, relativePath) {
  const absolutePath = path.resolve(root, ...relativePath.split('/'));
  assert.equal(
    absolutePath.startsWith(`${path.resolve(root)}${path.sep}`),
    true,
    `source escapes repository root: ${relativePath}`,
  );
  const information = fs.lstatSync(absolutePath);
  assert.equal(information.isSymbolicLink(), false, `source is a symlink: ${relativePath}`);
  assert.equal(information.isFile(), true, `source is not a regular file: ${relativePath}`);
  const bytes = fs.readFileSync(absolutePath);
  return {
    bytes,
    document: JSON.parse(bytes.toString('utf8')),
    sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
  };
}

function assertExactKeys(value, expected, context) {
  assert.equal(value !== null && typeof value === 'object' && !Array.isArray(value), true,
    `${context} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(),
    `${context} has an unexpected shape`);
}

function escapePointerToken(value) {
  return value.replaceAll('~', '~0').replaceAll('/', '~1');
}

function pointerTokens(reference) {
  assert.match(reference, /^#\/(?:[^~]|~[01])*$/u, `unsupported schema reference: ${reference}`);
  return reference.slice(2).split('/').map(
    (token) => token.replaceAll('~1', '/').replaceAll('~0', '~'),
  );
}

function resolveReference(root, schema, visited = new Set()) {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema) || !schema.$ref) {
    return schema;
  }
  assert.equal(typeof schema.$ref, 'string', 'schema reference must be a string');
  assert.equal(visited.has(schema.$ref), false, `cyclic schema reference: ${schema.$ref}`);
  const nextVisited = new Set(visited);
  nextVisited.add(schema.$ref);
  const target = pointerTokens(schema.$ref).reduce((current, token) => {
    assert.equal(current !== null && typeof current === 'object', true,
      `schema reference does not resolve: ${schema.$ref}`);
    assert.equal(Object.hasOwn(current, token), true,
      `schema reference does not resolve: ${schema.$ref}`);
    return current[token];
  }, root);
  const resolved = resolveReference(root, target, nextVisited);
  const siblings = Object.fromEntries(
    Object.entries(schema).filter(([name]) => name !== '$ref'),
  );
  return Object.keys(siblings).length === 0 ? resolved : {...resolved, ...siblings};
}

function scalarKind(value) {
  if (typeof value === 'string' || typeof value === 'boolean') return typeof value;
  if (typeof value === 'number') {
    assert.equal(Number.isFinite(value), true, 'completion number literals must be finite');
    return Number.isInteger(value) ? 'integer' : 'number';
  }
  throw new Error('completion literals must be strings, booleans or finite numbers');
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function schemaKind(root, schema) {
  const resolved = resolveReference(root, schema);
  assert.equal(resolved !== null && typeof resolved === 'object' && !Array.isArray(resolved), true,
    'configuration schema node must be an object');
  if (typeof resolved.type === 'string') return resolved.type;
  assert.equal(Array.isArray(resolved.type), false,
    'union schema types are outside completion metadata v1');
  if (resolved.properties) return 'object';
  if (resolved.items) return 'array';
  if (Array.isArray(resolved.enum) && resolved.enum.length > 0) {
    const kinds = new Set(resolved.enum.map(scalarKind));
    assert.equal(kinds.size, 1, 'mixed-type enums are outside completion metadata v1');
    return [...kinds][0];
  }
  if (Object.hasOwn(resolved, 'const')) return scalarKind(resolved.const);
  throw new Error('configuration schema node has no bounded completion kind');
}

function copyNumber(source, sourceKey, destination, destinationKey) {
  if (!Object.hasOwn(source, sourceKey)) return;
  assert.equal(typeof source[sourceKey], 'number', `${sourceKey} must be numeric`);
  assert.equal(Number.isFinite(source[sourceKey]), true, `${sourceKey} must be finite`);
  destination[destinationKey] = source[sourceKey];
}

function valueDescriptor(root, schema, includeItem = true) {
  const resolved = resolveReference(root, schema);
  const kind = schemaKind(root, resolved);
  assert.equal(
    kind === 'object' || kind === 'array' || SIMPLE_KINDS.has(kind),
    true,
    `unsupported completion kind: ${kind}`,
  );
  const descriptor = {kind};
  if (Array.isArray(resolved.enum)) {
    assert.ok(resolved.enum.length > 0 && resolved.enum.length <= 64,
      'completion enum must contain between 1 and 64 values');
    for (const value of resolved.enum) {
      assert.equal(scalarKind(value) === kind || kind === 'number' && scalarKind(value) === 'integer',
        true, 'completion enum value does not match its kind');
    }
    descriptor.enum_values = [...resolved.enum];
  }
  if (Object.hasOwn(resolved, 'const')) {
    scalarKind(resolved.const);
    descriptor.const_value = resolved.const;
  }
  copyNumber(resolved, 'minimum', descriptor, 'minimum');
  copyNumber(resolved, 'maximum', descriptor, 'maximum');
  copyNumber(resolved, 'minLength', descriptor, 'min_length');
  copyNumber(resolved, 'maxLength', descriptor, 'max_length');
  copyNumber(resolved, 'minItems', descriptor, 'min_items');
  copyNumber(resolved, 'maxItems', descriptor, 'max_items');
  if (Object.hasOwn(resolved, 'pattern')) {
    assert.equal(typeof resolved.pattern, 'string', 'pattern must be a string');
    descriptor.pattern = resolved.pattern;
  }
  if (Object.hasOwn(resolved, 'uniqueItems')) {
    assert.equal(typeof resolved.uniqueItems, 'boolean', 'uniqueItems must be boolean');
    descriptor.unique_items = resolved.uniqueItems;
  }
  if (kind === 'array' && includeItem) {
    assert.equal(resolved.items !== null && typeof resolved.items === 'object', true,
      'array completion metadata requires one item schema');
    descriptor.item = valueDescriptor(root, resolved.items, false);
  }
  return descriptor;
}

function collectSchemaFields(root) {
  const fields = new Map();

  function add(pathValue, schema, parentPath, key, requiredInParent) {
    assert.equal(fields.has(pathValue), false, `duplicate configuration path: ${pathValue}`);
    fields.set(pathValue, {
      path: pathValue,
      parentPath,
      key,
      requiredInParent,
      schema,
    });
  }

  function visitObjectProperties(schema, parentPath) {
    const resolved = resolveReference(root, schema);
    assert.equal(resolved.properties !== null && typeof resolved.properties === 'object', true,
      `object schema has no properties at ${parentPath}`);
    const required = new Set(resolved.required ?? []);
    for (const [key, childSchema] of Object.entries(resolved.properties)) {
      const childPath = `${parentPath}/${escapePointerToken(key)}`;
      visitNode(childSchema, childPath, parentPath, key, required.has(key));
    }
  }

  function visitNode(schema, pathValue, parentPath, key, requiredInParent) {
    add(pathValue, schema, parentPath, key, requiredInParent);
    const resolved = resolveReference(root, schema);
    const kind = schemaKind(root, resolved);
    if (kind === 'object') visitObjectProperties(resolved, pathValue);
    if (kind === 'array') {
      const item = resolveReference(root, resolved.items);
      if (schemaKind(root, item) === 'object') {
        visitObjectProperties(item, `${pathValue}/*`);
      }
    }
  }

  visitNode(root, '', null, null, true);
  return fields;
}

function validateInputs(configurationSchema, fieldHelp, contract) {
  assertExactKeys(fieldHelp,
    ['schema_version', 'classification', 'contract_version',
      'configuration_schema_version', 'entries'], 'field-help catalog');
  assert.equal(fieldHelp.schema_version, 1);
  assert.equal(fieldHelp.classification, 'routesphere-bonvoyage-field-explanations');
  assert.equal(fieldHelp.contract_version, contract.contract_version);
  assert.deepEqual(
    [fieldHelp.configuration_schema_version],
    contract.authority.supported_configuration_schema_versions,
  );
  assert.equal(contract.authority.configuration_schema, CONFIG_SCHEMA_PATH);
  assert.equal(contract.authority.compiler_entrypoint, 'snapshot.Compile');
  assert.equal(contract.authority.json_schema_role, 'structural-assistance-only');
  assert.equal(contract.security_boundary.offline, true);
  assert.equal(contract.security_boundary.network_access, false);
  assert.equal(contract.security_boundary.live_apply, false);
  assert.equal(contract.security_boundary.environment_secret_reads, false);
  assert.equal(configurationSchema.type, 'object');
  assert.equal(configurationSchema.additionalProperties, false);
  assert.equal(Array.isArray(fieldHelp.entries), true);
  assert.ok(fieldHelp.entries.length > 0);
}

export function buildCompletionMetadata({
  configurationSchema,
  fieldHelp,
  contract,
  sourceSha256,
}) {
  validateInputs(configurationSchema, fieldHelp, contract);
  assertExactKeys(sourceSha256,
    ['authoring_contract', 'configuration_schema', 'field_explanations'],
    'completion source digest set');
  for (const digest of Object.values(sourceSha256)) assert.match(digest, /^[0-9a-f]{64}$/u);

  const fields = collectSchemaFields(configurationSchema);
  const helpByPath = new Map();
  let previousPath = null;
  for (const entry of fieldHelp.entries) {
    assertExactKeys(entry, ['path', 'title', 'summary'], `field help ${entry.path}`);
    assert.equal(typeof entry.path, 'string');
    assert.equal(typeof entry.title, 'string');
    assert.equal(typeof entry.summary, 'string');
    assert.ok(entry.title.length > 0 && entry.summary.length > 0);
    if (previousPath !== null) assert.ok(entry.path > previousPath,
      'field-help paths must be unique and sorted');
    assert.equal(helpByPath.has(entry.path), false, `duplicate field-help path: ${entry.path}`);
    helpByPath.set(entry.path, entry);
    previousPath = entry.path;
  }
  assert.deepEqual([...fields.keys()].sort(), [...helpByPath.keys()].sort(),
    'configuration schema and field-help paths differ');

  const secretReferences = new Set(contract.redaction.secret_reference_fields);
  const entries = [...fields.values()]
    .sort((left, right) => compareText(left.path, right.path))
    .map((field) => {
      const help = helpByPath.get(field.path);
      return {
        path: field.path,
        parent_path: field.parentPath,
        key: field.key,
        title: help.title,
        summary: help.summary,
        required_in_parent: field.requiredInParent,
        secret_reference: field.key !== null && secretReferences.has(field.key),
        value: valueDescriptor(configurationSchema, field.schema),
      };
    });

  const observedSecretKeys = new Set(
    entries.filter((entry) => entry.secret_reference).map((entry) => entry.key),
  );
  assert.deepEqual([...observedSecretKeys].sort(), [...secretReferences].sort(),
    'completion metadata does not cover the complete secret-reference registry');

  return {
    $schema: '../../../schemas/bonvoyage-authoring-completion-v1.schema.json',
    schema_version: 1,
    classification: CLASSIFICATION,
    completion_version: COMPLETION_VERSION,
    contract_version: contract.contract_version,
    compiler_version: contract.authority.compiler_identity,
    configuration_schema_version: fieldHelp.configuration_schema_version,
    authority: {
      semantic_validation: contract.authority.compiler_entrypoint,
      configuration_schema_role: contract.authority.json_schema_role,
      completion_scope: 'direct-structural-and-literal-hints-only',
      field_help: 'reviewed-release-asset',
      network_access: false,
      live_mutation: false,
    },
    security_boundary: {
      offline: true,
      document_values_included: false,
      secret_values_included: false,
      environment_secret_reads: false,
    },
    sources: {
      authoring_contract: {path: CONTRACT_PATH, sha256: sourceSha256.authoring_contract},
      configuration_schema: {path: CONFIG_SCHEMA_PATH, sha256: sourceSha256.configuration_schema},
      field_explanations: {path: FIELD_HELP_PATH, sha256: sourceSha256.field_explanations},
    },
    entry_count: entries.length,
    entries,
  };
}

export function generateCompletionMetadata(root = ROOT) {
  const configurationSchema = readBoundSource(root, CONFIG_SCHEMA_PATH);
  const fieldHelp = readBoundSource(root, FIELD_HELP_PATH);
  const contract = readBoundSource(root, CONTRACT_PATH);
  return buildCompletionMetadata({
    configurationSchema: configurationSchema.document,
    fieldHelp: fieldHelp.document,
    contract: contract.document,
    sourceSha256: {
      authoring_contract: contract.sha256,
      configuration_schema: configurationSchema.sha256,
      field_explanations: fieldHelp.sha256,
    },
  });
}

export function renderCompletionMetadata(metadata) {
  return `${JSON.stringify(metadata, null, 2)}\n`;
}

function main(args) {
  assert.equal(args.length, 1, 'usage: generate-config-completion-metadata.mjs --check|--write');
  assert.equal(args[0] === '--check' || args[0] === '--write', true,
    'usage: generate-config-completion-metadata.mjs --check|--write');
  const rendered = renderCompletionMetadata(generateCompletionMetadata());
  const output = path.join(ROOT, ...OUTPUT_PATH.split('/'));
  if (args[0] === '--write') {
    fs.mkdirSync(path.dirname(output), {recursive: true});
    fs.writeFileSync(output, rendered, {encoding: 'utf8', mode: 0o644});
    return;
  }
  assert.equal(fs.readFileSync(output, 'utf8'), rendered,
    `${OUTPUT_PATH} is stale; run the generator with --write`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === SCRIPT_PATH) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
