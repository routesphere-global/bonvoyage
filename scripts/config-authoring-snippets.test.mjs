import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';
import yaml from 'js-yaml';

import {
  buildSnippetCatalog,
  generateSnippetCatalog,
  loadSnippetInputs,
  OUTPUT_PATH,
  renderSnippetCatalog,
  SNIPPET_SCHEMA_PATH,
} from './generate-config-snippets.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const COMPLETION_PATH = 'config/authoring/completion/v1/metadata.json';

let workspace;
let executable;

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, ...relativePath.split('/')), 'utf8'));
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function cloneInputs() {
  return structuredClone(loadSnippetInputs(ROOT));
}

function validateSourceDocument(relativePath) {
  const execution = spawnSync(executable, ['validate', '--input', relativePath], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(execution.signal, null, `validation terminated by ${execution.signal}`);
  assert.equal(execution.stderr, '', `unexpected validator stderr: ${execution.stderr}`);
  assert.equal(execution.status, 0, `validator rejected ${relativePath}: ${execution.stdout}`);
  const result = JSON.parse(execution.stdout);
  assert.equal(result.status, 'accepted');
  assert.equal(result.result.kind, 'validation');
  assert.equal(result.result.valid, true);
  assert.ok(result.result.artifact);
}

test.before(() => {
  workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-snippet-test-'));
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

test('committed snippet catalog is deterministic, current and schema-valid', () => {
  const first = generateSnippetCatalog(ROOT);
  const second = generateSnippetCatalog(ROOT);
  const committed = readJson(OUTPUT_PATH);
  assert.deepEqual(first, second);
  assert.deepEqual(committed, first);
  assert.equal(
    fs.readFileSync(path.join(ROOT, ...OUTPUT_PATH.split('/')), 'utf8'),
    renderSnippetCatalog(first),
  );

  const validate = new Ajv2020({allErrors: true, strict: true})
    .compile(readJson(SNIPPET_SCHEMA_PATH));
  assert.equal(validate(committed), true,
    validate.errors ? JSON.stringify(validate.errors, null, 2) : 'invalid snippet catalog');

  const check = spawnSync(process.execPath, ['scripts/generate-config-snippets.mjs', '--check'], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.equal(check.status, 0, `${check.stdout}${check.stderr}`);
});

test('catalog contains the 14 reviewed snippets in canonical order', () => {
  const catalog = generateSnippetCatalog(ROOT);
  const ids = catalog.entries.map((entry) => entry.id);
  assert.equal(catalog.entry_count, 14);
  assert.equal(catalog.entry_count, catalog.entries.length);
  assert.equal(new Set(ids).size, ids.length);
  assert.deepEqual(ids, [...ids].sort());
  assert.deepEqual(ids, [
    'cluster-upstream-mtls',
    'document-local-baseline',
    'listener-downstream-tls',
    'route-api-key-auth',
    'route-cors',
    'route-fixed-response',
    'route-header-transformations',
    'route-jwt-auth',
    'route-local-rate-limit',
    'route-request-content',
    'route-rewrite',
    'route-static-redirect',
    'route-upstream',
    'route-weighted-clusters',
  ]);
  assert.deepEqual([...new Set(catalog.entries.map((entry) => entry.category))].sort(), [
    'baseline',
    'routing',
    'security',
    'traffic-policy',
    'transformation',
    'transport',
  ]);
});

test('every reviewed source identity is exact and accepted by the real compiler', () => {
  const catalog = generateSnippetCatalog(ROOT);
  assert.equal(catalog.source_document_count, 12);
  assert.equal(catalog.source_document_count, catalog.source_documents.length);
  assert.deepEqual(
    catalog.source_documents.map((source) => source.path),
    catalog.source_documents.map((source) => source.path).sort(),
  );
  for (const source of catalog.source_documents) {
    const contents = fs.readFileSync(path.join(ROOT, ...source.path.split('/')));
    assert.equal(sha256(contents), source.sha256);
    validateSourceDocument(source.path);
  }
});

test('JSON payloads and YAML fragments round-trip with exact digests', () => {
  const catalog = generateSnippetCatalog(ROOT);
  for (const entry of catalog.entries) {
    assert.deepEqual(yaml.load(entry.yaml), entry.payload, entry.id);
    assert.equal(sha256(Buffer.from(entry.yaml, 'utf8')), entry.yaml_sha256, entry.id);
    assert.ok(entry.yaml.endsWith('\n'), entry.id);
    assert.equal(entry.yaml.includes('-----BEGIN '), false, entry.id);
  }
});

test('insertion modes and edit points remain bound to completion metadata', () => {
  const catalog = generateSnippetCatalog(ROOT);
  const completion = readJson(COMPLETION_PATH);
  const completionByPath = new Map(completion.entries.map((entry) => [entry.path, entry]));
  assert.deepEqual(catalog.entries.map((entry) => entry.insertion.mode), [
    'merge-object',
    'replace-document',
    'merge-object',
    'merge-object',
    'merge-object',
    'append-array-item',
    'merge-object',
    'merge-object',
    'merge-object',
    'merge-object',
    'merge-object',
    'merge-object',
    'append-array-item',
    'merge-object',
  ]);
  for (const entry of catalog.entries) {
    const paths = entry.edit_points.map((editPoint) => editPoint.payload_path);
    assert.deepEqual(paths, [...paths].sort(), entry.id);
    assert.equal(new Set(paths).size, paths.length, entry.id);
    for (const editPoint of entry.edit_points) {
      const completionEntry = completionByPath.get(editPoint.configuration_path);
      assert.ok(completionEntry, `${entry.id}: ${editPoint.configuration_path}`);
      assert.equal(editPoint.title, completionEntry.title);
      assert.equal(editPoint.summary, completionEntry.summary);
      assert.equal(editPoint.secret_reference, completionEntry.secret_reference);
      assert.deepEqual(editPoint.value, completionEntry.value);
    }
  }
});

test('secret references are filenames, explicit edit points and never secret contents', () => {
  const catalog = generateSnippetCatalog(ROOT);
  const secretPoints = catalog.entries.flatMap((entry) => entry.edit_points
    .filter((editPoint) => editPoint.secret_reference)
    .map((editPoint) => `${entry.id}:${editPoint.configuration_path}`));
  assert.deepEqual(secretPoints, [
    'cluster-upstream-mtls:/clusters/*/upstream_tls/certificate_chain_secret',
    'cluster-upstream-mtls:/clusters/*/upstream_tls/private_key_secret',
    'cluster-upstream-mtls:/clusters/*/upstream_tls/trust_bundle_secret',
    'listener-downstream-tls:/listeners/*/downstream_tls/certificate_chain_secret',
    'listener-downstream-tls:/listeners/*/downstream_tls/private_key_secret',
    'route-api-key-auth:/virtual_hosts/*/routes/*/api_key_auth/credentials_secret',
    'route-jwt-auth:/virtual_hosts/*/routes/*/jwt_auth/jwks_secret',
  ]);
  assert.equal(catalog.security_boundary.secret_values_included, false);
  assert.equal(catalog.security_boundary.private_material_included, false);
  assert.doesNotMatch(JSON.stringify(catalog), /-----BEGIN [A-Z0-9 ]+-----/u);
  assert.doesNotMatch(JSON.stringify(catalog), /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u);
});

test('generation fails closed when a reviewed source or selector drifts', () => {
  const changedSource = cloneInputs();
  changedSource.sourceDocuments['config/examples/local.yaml'].sha256 = '0'.repeat(64);
  assert.throws(
    () => buildSnippetCatalog(changedSource),
    /reviewed snippet source digest changed/u,
  );

  const missingSelection = cloneInputs();
  missingSelection.manifest.entries[0].source.pointer = '/clusters/0/not_present';
  assert.throws(
    () => buildSnippetCatalog(missingSelection),
    /does not resolve/u,
  );
});

test('generation rejects secret contents and private workstation material', () => {
  const unsafeSecret = cloneInputs();
  const tlsPath = 'config/examples/tls.yaml';
  unsafeSecret.sourceDocuments[tlsPath].document.listeners[0]
    .downstream_tls.certificate_chain_secret = '-----BEGIN CERTIFICATE-----';
  unsafeSecret.sourceDocuments[tlsPath].sha256 = 'a'.repeat(64);
  for (const entry of unsafeSecret.manifest.entries) {
    if (entry.source.path === tlsPath) entry.source.sha256 = 'a'.repeat(64);
  }
  assert.throws(
    () => buildSnippetCatalog(unsafeSecret),
    /secret reference must be a bounded deployment filename|private or secret-shaped material/u,
  );

  const privatePath = cloneInputs();
  const localPath = 'config/examples/local.yaml';
  privatePath.sourceDocuments[localPath].document.server.node_id =
    ['', 'Users', 'example', 'Documents', 'private'].join('/');
  privatePath.sourceDocuments[localPath].sha256 = 'b'.repeat(64);
  for (const entry of privatePath.manifest.entries) {
    if (entry.source.path === localPath) entry.source.sha256 = 'b'.repeat(64);
  }
  assert.throws(
    () => buildSnippetCatalog(privatePath),
    /private or secret-shaped material/u,
  );
});

test('generation rejects invalid insertion and edit-point contracts', () => {
  const unknownMode = cloneInputs();
  unknownMode.manifest.entries[0].insertion.mode = 'paste-anywhere';
  assert.throws(() => buildSnippetCatalog(unknownMode), /unsupported snippet insertion mode/u);

  const wrongContainer = cloneInputs();
  const fixedResponse = wrongContainer.manifest.entries
    .find((entry) => entry.id === 'route-fixed-response');
  fixedResponse.insertion.container_path = '/virtual_hosts/*/routes/*';
  assert.throws(
    () => buildSnippetCatalog(wrongContainer),
    /append-array-item requires an array insertion container/u,
  );

  const unknownEditPoint = cloneInputs();
  unknownEditPoint.manifest.entries[0].edit_points[0] = '/upstream_tls/not_present';
  assert.throws(() => buildSnippetCatalog(unknownEditPoint), /does not resolve/u);
});

test('catalog binds its exact reviewed authorities and remains offline', () => {
  const catalog = generateSnippetCatalog(ROOT);
  const inputs = loadSnippetInputs(ROOT);
  assert.deepEqual(catalog.sources, {
    authoring_contract: {
      path: 'config/authoring/bonvoyage-authoring-v1.json',
      sha256: inputs.sourceSha256.authoring_contract,
    },
    completion_metadata: {
      path: 'config/authoring/completion/v1/metadata.json',
      sha256: inputs.sourceSha256.completion_metadata,
    },
    reviewed_source_manifest: {
      path: 'config/authoring/snippets/v1/reviewed-sources.json',
      sha256: inputs.sourceSha256.reviewed_source_manifest,
    },
  });
  assert.equal(catalog.authority.semantic_validation, 'snapshot.Compile');
  assert.equal(catalog.authority.validation_required_after_insertion, true);
  assert.equal(catalog.authority.network_access, false);
  assert.equal(catalog.authority.live_mutation, false);
});

test('generator command refuses ambiguous or unknown modes', () => {
  for (const args of [[], ['--unknown'], ['--check', '--write']]) {
    const result = spawnSync(process.execPath, ['scripts/generate-config-snippets.mjs', ...args], {
      cwd: ROOT,
      encoding: 'utf8',
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /usage: generate-config-snippets/u);
  }
});
