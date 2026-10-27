import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

import yaml from 'js-yaml';

import {
  CONTRACT_PATH,
  generateCompletionMetadata,
  OUTPUT_PATH as COMPLETION_PATH,
} from './generate-config-completion-metadata.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
export const ROOT = path.resolve(path.dirname(SCRIPT_PATH), '..');
export const SOURCE_MANIFEST_PATH =
  'config/authoring/snippets/v1/reviewed-sources.json';
export const OUTPUT_PATH = 'config/authoring/snippets/v1/catalog.json';
export const SNIPPET_SCHEMA_PATH =
  'config/schemas/bonvoyage-authoring-snippets-v1.schema.json';

const CLASSIFICATION = 'routesphere-bonvoyage-configuration-snippet-catalog';
const SOURCE_CLASSIFICATION =
  'routesphere-bonvoyage-reviewed-configuration-snippet-sources';
const SNIPPET_VERSION = 'bonvoyage.configuration-snippets.v1';
const CATEGORIES = new Set([
  'baseline',
  'routing',
  'security',
  'traffic-policy',
  'transformation',
  'transport',
]);
const INSERTION_MODES = new Set([
  'replace-document',
  'merge-object',
  'append-array-item',
]);
const SECRET_FILENAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const PRIVATE_PATTERNS = [
  /-----BEGIN [A-Z0-9 ]+-----/u,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u,
  /\b[0-9]{12}\b/u,
];

function digest(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function assertExactKeys(value, expected, context) {
  assert.equal(value !== null && typeof value === 'object' && !Array.isArray(value), true,
    `${context} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(),
    `${context} has an unexpected shape`);
}

function assertRepositoryPath(relativePath, context) {
  assert.equal(typeof relativePath, 'string', `${context} path must be a string`);
  assert.ok(relativePath.length > 0, `${context} path must not be empty`);
  assert.equal(relativePath.includes('\\'), false, `${context} path must use POSIX separators`);
  assert.equal(path.posix.isAbsolute(relativePath), false, `${context} path must be relative`);
  assert.equal(path.posix.normalize(relativePath), relativePath,
    `${context} path must be normalized`);
  assert.equal(relativePath === '..' || relativePath.startsWith('../') ||
    relativePath.includes('/../'), false, `${context} path escapes the repository`);
}

function readBoundSource(root, relativePath, parser) {
  assertRepositoryPath(relativePath, 'source');
  const repositoryRoot = path.resolve(root);
  const absolutePath = path.resolve(root, ...relativePath.split('/'));
  assert.equal(absolutePath.startsWith(`${repositoryRoot}${path.sep}`), true,
    `source escapes repository root: ${relativePath}`);
  const information = fs.lstatSync(absolutePath);
  assert.equal(information.isSymbolicLink(), false, `source is a symlink: ${relativePath}`);
  assert.equal(information.isFile(), true, `source is not a regular file: ${relativePath}`);
  const bytes = fs.readFileSync(absolutePath);
  return {bytes, document: parser(bytes, relativePath), sha256: digest(bytes)};
}

function parseJson(bytes, relativePath) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new Error(`invalid JSON source ${relativePath}: ${error.message}`);
  }
}

function parseYaml(bytes, relativePath) {
  const documents = [];
  try {
    yaml.loadAll(bytes.toString('utf8'), (document) => documents.push(document));
  } catch (error) {
    throw new Error(`invalid YAML source ${relativePath}: ${error.message}`);
  }
  assert.equal(documents.length, 1, `snippet source must contain one YAML document: ${relativePath}`);
  assert.equal(documents[0] !== null && typeof documents[0] === 'object', true,
    `snippet source must contain a mapping or sequence: ${relativePath}`);
  return documents[0];
}

function escapePointerToken(value) {
  return value.replaceAll('~', '~0').replaceAll('/', '~1');
}

function pointerTokens(pointer, context = 'JSON Pointer') {
  assert.equal(typeof pointer, 'string', `${context} must be a string`);
  assert.match(pointer, /^(?:|\/(?:[^~]|~[01])*)$/u, `${context} is not RFC 6901 syntax`);
  if (pointer === '') return [];
  return pointer.slice(1).split('/').map(
    (token) => token.replaceAll('~1', '/').replaceAll('~0', '~'),
  );
}

function pointerFromTokens(tokens) {
  return tokens.length === 0 ? '' : `/${tokens.map(escapePointerToken).join('/')}`;
}

function resolvePointer(document, pointer, context = 'JSON Pointer') {
  return pointerTokens(pointer, context).reduce((current, token) => {
    if (Array.isArray(current)) {
      assert.match(token, /^(?:0|[1-9][0-9]*)$/u,
        `${context} has a non-index array token: ${pointer}`);
      const index = Number(token);
      assert.ok(index < current.length, `${context} does not resolve: ${pointer}`);
      return current[index];
    }
    assert.equal(current !== null && typeof current === 'object', true,
      `${context} does not resolve: ${pointer}`);
    assert.equal(Object.hasOwn(current, token), true, `${context} does not resolve: ${pointer}`);
    return current[token];
  }, document);
}

function canonicalConfigurationPath(containerPath, payloadPath) {
  const container = pointerTokens(containerPath, 'insertion container path');
  const payload = pointerTokens(payloadPath, 'payload path')
    .map((token) => /^(?:0|[1-9][0-9]*)$/u.test(token) ? '*' : token);
  return pointerFromTokens([...container, ...payload]);
}

function completionEntryForPath(completionByPath, configurationPath) {
  const direct = completionByPath.get(configurationPath);
  if (direct) return direct;
  const tokens = pointerTokens(configurationPath, 'configuration path');
  if (tokens.at(-1) !== '*') return null;
  const parent = completionByPath.get(pointerFromTokens(tokens.slice(0, -1)));
  if (!parent || parent.value.kind !== 'array') return null;
  return {
    ...parent,
    path: configurationPath,
    secret_reference: false,
    value: parent.value.item,
  };
}

function containerKind(completionByPath, containerPath) {
  const entry = completionEntryForPath(completionByPath, containerPath);
  assert.ok(entry, `insertion container is not in completion metadata: ${containerPath}`);
  return entry.value.kind;
}

function assertSafeString(value, context) {
  for (const pattern of PRIVATE_PATTERNS) {
    assert.equal(pattern.test(value), false, `${context} contains private or secret-shaped material`);
  }
  const pathTokens = value.replaceAll('\\', '/').split('/');
  const looksLikeUserHome = pathTokens[0] === '' &&
    ['Users', 'home'].includes(pathTokens[1]) && pathTokens[2]?.length > 0;
  assert.equal(looksLikeUserHome, false,
    `${context} contains private or secret-shaped material`);
}

function scanPayload(value, pointer, containerPath, completionByPath, secretPayloadPaths) {
  assert.notEqual(value, null, `snippet payload contains null at ${pointer || '<root>'}`);
  if (typeof value === 'number') {
    assert.equal(Number.isFinite(value), true,
      `snippet payload contains a non-finite number at ${pointer || '<root>'}`);
    return;
  }
  if (typeof value === 'boolean') return;
  if (typeof value === 'string') {
    assertSafeString(value, `snippet payload ${pointer || '<root>'}`);
    const configurationPath = canonicalConfigurationPath(containerPath, pointer);
    const completion = completionEntryForPath(completionByPath, configurationPath);
    if (completion?.secret_reference) {
      assert.match(value, SECRET_FILENAME,
        `secret reference must be a bounded deployment filename at ${pointer}`);
      assert.equal(value.includes('/') || value.includes('\\'), false,
        `secret reference must not contain a path separator at ${pointer}`);
      secretPayloadPaths.add(pointer);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => scanPayload(
      item,
      `${pointer}/${index}`,
      containerPath,
      completionByPath,
      secretPayloadPaths,
    ));
    return;
  }
  assert.equal(typeof value, 'object', true,
    `unsupported snippet payload value at ${pointer || '<root>'}`);
  for (const [key, child] of Object.entries(value)) {
    scanPayload(
      child,
      `${pointer}/${escapePointerToken(key)}`,
      containerPath,
      completionByPath,
      secretPayloadPaths,
    );
  }
}

function wrapSelection(selection, pointer, mode) {
  if (mode === 'replace-document') {
    assert.equal(pointer, '', 'replace-document requires the source document root');
    assert.equal(selection !== null && typeof selection === 'object' && !Array.isArray(selection),
      true, 'replace-document requires a mapping');
    return structuredClone(selection);
  }
  if (mode === 'append-array-item') {
    assert.equal(selection !== null && typeof selection === 'object' && !Array.isArray(selection),
      true, 'append-array-item requires a mapping source selection');
    return [structuredClone(selection)];
  }
  assert.equal(mode, 'merge-object');
  const tokens = pointerTokens(pointer, 'source pointer');
  assert.ok(tokens.length > 0, 'merge-object requires a non-root source selection');
  const key = tokens.at(-1);
  assert.equal(/^(?:0|[1-9][0-9]*)$/u.test(key), false,
    'merge-object source selection must end in an object key');
  return {[key]: structuredClone(selection)};
}

function validateManifest(manifest) {
  assertExactKeys(manifest,
    ['schema_version', 'classification', 'snippet_version', 'entries'],
    'reviewed snippet source manifest');
  assert.equal(manifest.schema_version, 1);
  assert.equal(manifest.classification, SOURCE_CLASSIFICATION);
  assert.equal(manifest.snippet_version, SNIPPET_VERSION);
  assert.equal(Array.isArray(manifest.entries), true);
  assert.ok(manifest.entries.length > 0 && manifest.entries.length <= 128,
    'reviewed snippet source manifest must contain between 1 and 128 entries');

  let previousId = null;
  for (const entry of manifest.entries) {
    assertExactKeys(entry,
      ['id', 'title', 'summary', 'category', 'source', 'insertion', 'edit_points'],
      `snippet source ${entry.id}`);
    assert.match(entry.id, /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u);
    if (previousId !== null) assert.ok(entry.id > previousId,
      'snippet source IDs must be unique and sorted');
    previousId = entry.id;
    assert.equal(typeof entry.title, 'string');
    assert.equal(typeof entry.summary, 'string');
    assert.ok(entry.title.length > 0 && entry.title.length <= 256);
    assert.ok(entry.summary.length > 0 && entry.summary.length <= 4096);
    assertSafeString(entry.title, `snippet ${entry.id} title`);
    assertSafeString(entry.summary, `snippet ${entry.id} summary`);
    assert.equal(CATEGORIES.has(entry.category), true,
      `unsupported snippet category: ${entry.category}`);

    assertExactKeys(entry.source, ['path', 'pointer', 'sha256'],
      `snippet source selection ${entry.id}`);
    assertRepositoryPath(entry.source.path, `snippet ${entry.id}`);
    pointerTokens(entry.source.pointer, `snippet ${entry.id} source pointer`);
    assert.match(entry.source.sha256, /^[0-9a-f]{64}$/u);

    assertExactKeys(entry.insertion, ['container_path', 'mode'],
      `snippet insertion ${entry.id}`);
    pointerTokens(entry.insertion.container_path,
      `snippet ${entry.id} insertion container path`);
    assert.equal(INSERTION_MODES.has(entry.insertion.mode), true,
      `unsupported snippet insertion mode: ${entry.insertion.mode}`);

    assert.equal(Array.isArray(entry.edit_points), true);
    assert.ok(entry.edit_points.length > 0 && entry.edit_points.length <= 64,
      `snippet ${entry.id} must contain between 1 and 64 edit points`);
    let previousEditPoint = null;
    for (const editPoint of entry.edit_points) {
      pointerTokens(editPoint, `snippet ${entry.id} edit point`);
      assert.notEqual(editPoint, '', `snippet ${entry.id} edit point must not be the payload root`);
      if (previousEditPoint !== null) assert.ok(editPoint > previousEditPoint,
        `snippet ${entry.id} edit points must be unique and sorted`);
      previousEditPoint = editPoint;
    }
  }
}

function validateAuthority(contract, completion, sourceSha256) {
  assert.equal(contract.contract_version, 'bonvoyage.configuration-authoring.v1');
  assert.equal(contract.authority.compiler_entrypoint, 'snapshot.Compile');
  assert.deepEqual(contract.authority.supported_configuration_schema_versions, [1]);
  assert.equal(contract.security_boundary.offline, true);
  assert.equal(contract.security_boundary.network_access, false);
  assert.equal(contract.security_boundary.live_apply, false);
  assert.equal(contract.security_boundary.environment_secret_reads, false);
  assert.equal(contract.redaction.pem_literal_policy, 'reject-without-echo');

  assert.equal(completion.classification,
    'routesphere-bonvoyage-configuration-completion-metadata');
  assert.equal(completion.contract_version, contract.contract_version);
  assert.equal(completion.compiler_version, contract.authority.compiler_identity);
  assert.equal(completion.configuration_schema_version, 1);
  assert.equal(completion.authority.semantic_validation, 'snapshot.Compile');
  assert.equal(completion.authority.network_access, false);
  assert.equal(completion.authority.live_mutation, false);
  assert.equal(completion.security_boundary.secret_values_included, false);
  assert.equal(completion.sources.authoring_contract.path, CONTRACT_PATH);
  assert.equal(completion.sources.authoring_contract.sha256, sourceSha256.authoring_contract);
}

export function buildSnippetCatalog({
  contract,
  completion,
  manifest,
  sourceDocuments,
  sourceSha256,
}) {
  assertExactKeys(sourceSha256,
    ['authoring_contract', 'completion_metadata', 'reviewed_source_manifest'],
    'snippet source digest set');
  for (const value of Object.values(sourceSha256)) assert.match(value, /^[0-9a-f]{64}$/u);
  validateAuthority(contract, completion, sourceSha256);
  validateManifest(manifest);

  const completionByPath = new Map(completion.entries.map((entry) => [entry.path, entry]));
  assert.equal(completionByPath.size, completion.entries.length,
    'completion metadata contains duplicate paths');

  const referencedPaths = [...new Set(manifest.entries.map((entry) => entry.source.path))].sort();
  assert.deepEqual(Object.keys(sourceDocuments).sort(), referencedPaths,
    'loaded snippet source document set differs from the reviewed manifest');
  const expectedDigestByPath = new Map();
  for (const entry of manifest.entries) {
    const previous = expectedDigestByPath.get(entry.source.path);
    if (previous) assert.equal(previous, entry.source.sha256,
      `snippet source digest disagrees for ${entry.source.path}`);
    expectedDigestByPath.set(entry.source.path, entry.source.sha256);
  }
  for (const sourcePath of referencedPaths) {
    assert.equal(sourceDocuments[sourcePath].sha256, expectedDigestByPath.get(sourcePath),
      `reviewed snippet source digest changed: ${sourcePath}`);
  }

  const entries = manifest.entries.map((entry) => {
    const source = sourceDocuments[entry.source.path];
    const selection = resolvePointer(
      source.document,
      entry.source.pointer,
      `snippet ${entry.id} source pointer`,
    );
    const payload = wrapSelection(selection, entry.source.pointer, entry.insertion.mode);
    const insertionKind = containerKind(completionByPath, entry.insertion.container_path);
    if (entry.insertion.mode === 'replace-document') {
      assert.equal(entry.insertion.container_path, '',
        'replace-document insertion container must be the document root');
      assert.equal(insertionKind, 'object');
    }
    if (entry.insertion.mode === 'merge-object') assert.equal(insertionKind, 'object',
      `merge-object requires an object insertion container for ${entry.id}`);
    if (entry.insertion.mode === 'append-array-item') assert.equal(insertionKind, 'array',
      `append-array-item requires an array insertion container for ${entry.id}`);

    const editPoints = entry.edit_points.map((payloadPath) => {
      resolvePointer(payload, payloadPath, `snippet ${entry.id} edit point`);
      const configurationPath = canonicalConfigurationPath(
        entry.insertion.container_path,
        payloadPath,
      );
      const completionEntry = completionByPath.get(configurationPath);
      assert.ok(completionEntry,
        `snippet ${entry.id} edit point has no completion entry: ${configurationPath}`);
      return {
        payload_path: payloadPath,
        configuration_path: configurationPath,
        title: completionEntry.title,
        summary: completionEntry.summary,
        secret_reference: completionEntry.secret_reference,
        value: structuredClone(completionEntry.value),
      };
    });

    const secretPayloadPaths = new Set();
    scanPayload(payload, '', entry.insertion.container_path, completionByPath, secretPayloadPaths);
    const declaredSecretPaths = new Set(editPoints
      .filter((editPoint) => editPoint.secret_reference)
      .map((editPoint) => editPoint.payload_path));
    assert.deepEqual([...declaredSecretPaths].sort(), [...secretPayloadPaths].sort(),
      `snippet ${entry.id} must expose every secret reference as an edit point`);

    const renderedYaml = yaml.dump(payload, {
      noRefs: true,
      noCompatMode: true,
      lineWidth: 100,
      sortKeys: false,
    });
    assert.deepEqual(yaml.load(renderedYaml), payload,
      `snippet ${entry.id} YAML does not round-trip to its payload`);

    return {
      id: entry.id,
      title: entry.title,
      summary: entry.summary,
      category: entry.category,
      source: structuredClone(entry.source),
      insertion: structuredClone(entry.insertion),
      payload,
      yaml: renderedYaml,
      yaml_sha256: digest(Buffer.from(renderedYaml, 'utf8')),
      edit_points: editPoints,
    };
  });

  const catalog = {
    $schema: '../../../schemas/bonvoyage-authoring-snippets-v1.schema.json',
    schema_version: 1,
    classification: CLASSIFICATION,
    snippet_version: SNIPPET_VERSION,
    contract_version: contract.contract_version,
    compiler_version: contract.authority.compiler_identity,
    configuration_schema_version: 1,
    authority: {
      semantic_validation: contract.authority.compiler_entrypoint,
      snippet_scope: 'reviewed-syntactic-starting-points-only',
      insertion_authority: 'consumer',
      validation_required_after_insertion: true,
      network_access: false,
      live_mutation: false,
    },
    security_boundary: {
      offline: true,
      secret_values_included: false,
      secret_references_may_be_included: true,
      environment_secret_reads: false,
      private_material_included: false,
    },
    sources: {
      authoring_contract: {path: CONTRACT_PATH, sha256: sourceSha256.authoring_contract},
      completion_metadata: {path: COMPLETION_PATH, sha256: sourceSha256.completion_metadata},
      reviewed_source_manifest: {
        path: SOURCE_MANIFEST_PATH,
        sha256: sourceSha256.reviewed_source_manifest,
      },
    },
    source_document_count: referencedPaths.length,
    source_documents: referencedPaths.map((sourcePath) => ({
      path: sourcePath,
      sha256: sourceDocuments[sourcePath].sha256,
    })),
    entry_count: entries.length,
    entries,
  };
  return catalog;
}

export function loadSnippetInputs(root = ROOT) {
  const contract = readBoundSource(root, CONTRACT_PATH, parseJson);
  const completion = readBoundSource(root, COMPLETION_PATH, parseJson);
  const manifest = readBoundSource(root, SOURCE_MANIFEST_PATH, parseJson);
  const currentCompletion = generateCompletionMetadata(root);
  assert.deepEqual(completion.document, currentCompletion,
    `${COMPLETION_PATH} is stale; regenerate completion metadata first`);
  const sourcePaths = [...new Set(manifest.document.entries.map((entry) => entry.source.path))]
    .sort();
  const sourceDocuments = Object.fromEntries(sourcePaths.map((sourcePath) => [
    sourcePath,
    readBoundSource(root, sourcePath, parseYaml),
  ]));
  return {
    contract: contract.document,
    completion: completion.document,
    manifest: manifest.document,
    sourceDocuments,
    sourceSha256: {
      authoring_contract: contract.sha256,
      completion_metadata: completion.sha256,
      reviewed_source_manifest: manifest.sha256,
    },
  };
}

export function generateSnippetCatalog(root = ROOT) {
  return buildSnippetCatalog(loadSnippetInputs(root));
}

export function renderSnippetCatalog(catalog) {
  return `${JSON.stringify(catalog, null, 2)}\n`;
}

function main(args) {
  assert.equal(args.length, 1, 'usage: generate-config-snippets.mjs --check|--write');
  assert.equal(args[0] === '--check' || args[0] === '--write', true,
    'usage: generate-config-snippets.mjs --check|--write');
  const rendered = renderSnippetCatalog(generateSnippetCatalog());
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
