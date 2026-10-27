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
const RESULT_SCHEMA = JSON.parse(fs.readFileSync(path.join(
  ROOT, 'config/schemas/bonvoyage-authoring-result-v1.schema.json'), 'utf8'));
const validateResult = new Ajv2020({allErrors: true, strict: true}).compile(RESULT_SCHEMA);

let workspace;
let executable;

function invoke(args, input) {
  const execution = spawnSync(executable, args, {
    cwd: ROOT,
    encoding: 'utf8',
    input,
    maxBuffer: 4 * 1024 * 1024,
  });
  assert.equal(execution.signal, null, `command terminated by ${execution.signal}`);
  assert.equal(execution.stderr, '', `unexpected stderr: ${execution.stderr}`);
  const parsed = JSON.parse(execution.stdout);
  assert.equal(
    validateResult(parsed),
    true,
    validateResult.errors ? JSON.stringify(validateResult.errors, null, 2) : 'invalid result',
  );
  assert.equal(parsed.exit_code, execution.status);
  return parsed;
}

test.before(() => {
  workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-config-test-'));
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

test('validate emits a schema-valid deterministic artifact result', () => {
  const inputPath = path.join(ROOT, 'config/examples/local.yaml');
  const first = invoke(['validate', '--input', inputPath]);
  const second = invoke(['validate', '--input', inputPath]);
  assert.equal(first.status, 'accepted');
  assert.equal(first.result.valid, true);
  assert.equal(first.result.artifact.snapshot_id, 'local-bootstrap');
  assert.equal(first.result.artifact.sha256,
    '0df685415364762d826d71e722864ba2b7ed1f53508999c8be080897c0b1774b');
  assert.deepEqual(first, second);
});

test('validate emits a redacted rejection without copying unknown values', () => {
  const source = fs.readFileSync(path.join(ROOT, 'config/examples/local.yaml'), 'utf8')
    .replace('  node_id: "bonvoyage-local"',
      '  private_customer_token: "do-not-echo"\n  node_id: "bonvoyage-local"');
  const result = invoke(['validate', '--stdin', '--source-id', 'invalid.yaml'], source);
  assert.equal(result.status, 'rejected');
  assert.equal(result.diagnostics[0].code, 'BV_CFG_SCHEMA_UNKNOWN_FIELD');
  assert.equal(result.diagnostics[0].redacted, true);
  assert.equal(JSON.stringify(result).includes('do-not-echo'), false);
});

test('validate refuses an exact installed-version mismatch', () => {
  const source = fs.readFileSync(path.join(ROOT, 'config/examples/local.yaml'), 'utf8');
  const result = invoke([
    'validate', '--stdin', '--source-id', 'version.yaml',
    '--require-product-version', '9.9.9',
  ], source);
  assert.equal(result.status, 'refused');
  assert.equal(result.failure_kind, 'compatibility');
  assert.equal(result.diagnostics[0].code, 'BV_CFG_VERSION_MISMATCH');
});

test('validate reports only the bounded observation for oversized input', () => {
  const input = 'x'.repeat((1 << 20) + 1);
  const result = invoke(['validate', '--stdin', '--source-id', 'large.yaml'], input);
  assert.equal(result.status, 'rejected');
  assert.equal(result.diagnostics[0].code, 'BV_CFG_INPUT_TOO_LARGE');
  assert.equal(result.inputs[0].bytes, 1 << 20);
  assert.equal(
    result.inputs[0].sha256,
    crypto.createHash('sha256').update(input.slice(0, 1 << 20)).digest('hex'),
  );
});

test('validate reports an unreadable file with a schema-valid I/O failure', () => {
  const result = invoke(['validate', '--input', path.join(workspace, 'missing.yaml')]);
  assert.equal(result.status, 'failed');
  assert.equal(result.failure_kind, 'io');
  assert.equal(result.diagnostics[0].code, 'BV_CFG_INPUT_UNREADABLE');
});

test('format returns a comment-preserving deterministic document without changing its source', () => {
  const inputPath = path.join(workspace, 'commented.yaml');
  const source = fs.readFileSync(path.join(ROOT, 'config/examples/local.yaml'), 'utf8')
    .replace('server:\n', '# gateway intent\nserver: # server block\n')
    .replace('  node_id: "bonvoyage-local"', '  node_id:    "bonvoyage-local" # stable identity');
  fs.writeFileSync(inputPath, source, {mode: 0o640});

  const first = invoke(['format', '--input', inputPath]);
  assert.equal(first.status, 'accepted');
  assert.equal(first.operation, 'format');
  assert.equal(first.result.kind, 'formatted-document');
  assert.equal(first.result.changed, true);
  assert.match(first.result.document, /# gateway intent/);
  assert.match(first.result.document, /# server block/);
  assert.match(first.result.document, /# stable identity/);
  assert.equal(
    first.result.document_sha256,
    crypto.createHash('sha256').update(first.result.document).digest('hex'),
  );
  assert.equal(fs.readFileSync(inputPath, 'utf8'), source);

  const second = invoke(['format', '--stdin', '--source-id', 'formatted.yaml'], first.result.document);
  assert.equal(second.result.changed, false);
  assert.equal(second.result.document, first.result.document);
  assert.equal(second.result.document_sha256, first.result.document_sha256);
});

test('format replaces a regular file only when in-place is explicit', () => {
  const inputPath = path.join(workspace, 'in-place.yaml');
  const source = fs.readFileSync(path.join(ROOT, 'config/examples/local.yaml'), 'utf8')
    .replace('  node_id: "bonvoyage-local"', '  node_id:    "bonvoyage-local"');
  fs.writeFileSync(inputPath, source, {mode: 0o640});

  const result = invoke(['format', '--input', inputPath, '--in-place']);
  assert.equal(result.status, 'accepted');
  assert.equal(result.result.changed, true);
  assert.equal(fs.readFileSync(inputPath, 'utf8'), result.result.document);
  assert.equal(fs.statSync(inputPath).mode & 0o777, 0o640);
});

test('format rejects unsafe line endings and never returns a partial document', () => {
  const source = fs.readFileSync(path.join(ROOT, 'config/examples/local.yaml'), 'utf8')
    .replace('server:\n', 'server:\r\n');
  const result = invoke(['format', '--stdin', '--source-id', 'mixed.yaml'], source);
  assert.equal(result.status, 'rejected');
  assert.equal(result.diagnostics[0].code, 'BV_CFG_FORMAT_UNSAFE');
  assert.equal(result.result, null);
});

test('format rejects in-place replacement through a symlink', (t) => {
  const target = path.join(workspace, 'format-target.yaml');
  const link = path.join(workspace, 'format-link.yaml');
  const source = fs.readFileSync(path.join(ROOT, 'config/examples/local.yaml'), 'utf8');
  fs.writeFileSync(target, source);
  try {
    fs.symlinkSync(target, link);
  } catch (error) {
    t.skip(`symlink unavailable: ${error.message}`);
    return;
  }
  const result = invoke(['format', '--input', link, '--in-place']);
  assert.equal(result.status, 'rejected');
  assert.equal(result.diagnostics[0].code, 'BV_CFG_INPUT_SYMLINK');
  assert.equal(result.result, null);
  assert.equal(fs.readFileSync(target, 'utf8'), source);
});

test('format rejects invalid in-place source without echoing or modifying it', () => {
  const inputPath = path.join(workspace, 'invalid-in-place.yaml');
  const source = fs.readFileSync(path.join(ROOT, 'config/examples/local.yaml'), 'utf8')
    .replace('  node_id: "bonvoyage-local"',
      '  private_customer_token: "format-do-not-echo"\n  node_id: "bonvoyage-local"');
  fs.writeFileSync(inputPath, source);

  const result = invoke(['format', '--input', inputPath, '--in-place']);
  assert.equal(result.status, 'rejected');
  assert.equal(result.diagnostics[0].code, 'BV_CFG_SCHEMA_UNKNOWN_FIELD');
  assert.equal(result.result, null);
  assert.equal(JSON.stringify(result).includes('format-do-not-echo'), false);
  assert.equal(fs.readFileSync(inputPath, 'utf8'), source);
});

test('explain returns release-matched static help without reading a document', () => {
  const first = invoke(['explain', '--path', '/listeners/0/port'], 'ignored-secret');
  const second = invoke(['explain', '--path', '/listeners/0/port'], 'different-input');
  assert.equal(first.status, 'accepted');
  assert.equal(first.operation, 'explain');
  assert.deepEqual(first.inputs, []);
  assert.equal(first.versions.input_configuration_schema_version, 1);
  assert.deepEqual(first.result, {
    kind: 'field-explanation',
    path: '/listeners/0/port',
    title: 'Listener port',
    summary: 'The TCP port on which this listener accepts downstream connections.',
  });
  assert.deepEqual(first, second);
  assert.equal(JSON.stringify(first).includes('ignored-secret'), false);
});

test('explain accepts root and reviewed wildcard paths', () => {
  const root = invoke(['explain', '--path', '']);
  const wildcard = invoke(['explain', '--path', '/clusters/*/endpoints/*/address']);
  assert.equal(root.status, 'accepted');
  assert.equal(root.result.path, '');
  assert.equal(root.result.title, 'BonVoyage configuration');
  assert.equal(wildcard.status, 'accepted');
  assert.equal(wildcard.result.path, '/clusters/*/endpoints/*/address');
  assert.equal(wildcard.result.title, 'Endpoint address');
});

test('explain rejects unknown paths without echoing caller-controlled text', () => {
  for (const fieldPath of [
    'not-a-pointer',
    '/listeners/01/port',
    '/private/customer-secret-do-not-echo',
    '/listeners/0/bad~2token',
  ]) {
    const result = invoke(['explain', '--path', fieldPath]);
    assert.equal(result.status, 'rejected');
    assert.equal(result.failure_kind, 'validation');
    assert.equal(result.diagnostics[0].code, 'BV_CFG_EXPLAIN_PATH_UNKNOWN');
    assert.equal(result.result, null);
    assert.deepEqual(result.inputs, []);
    assert.equal(JSON.stringify(result).includes(fieldPath), false);
  }
});

test('explain refuses exact installed-version mismatches', () => {
  const result = invoke([
    'explain', '--path', '/server/node_id',
    '--require-configuration-schema-version', '2',
  ]);
  assert.equal(result.status, 'refused');
  assert.equal(result.failure_kind, 'compatibility');
  assert.equal(result.diagnostics[0].code, 'BV_CFG_VERSION_MISMATCH');
  assert.equal(result.result, null);
  assert.deepEqual(result.inputs, []);
});

test('diff emits a deterministic schema-valid compiled semantic change set', () => {
  const baselinePath = path.join(workspace, 'diff-baseline.yaml');
  const proposedPath = path.join(workspace, 'diff-proposed.yaml');
  const baseline = fs.readFileSync(path.join(ROOT, 'config/examples/local.yaml'), 'utf8');
  const proposed = baseline.replace('    port: 8080', '    port: 8443');
  fs.writeFileSync(baselinePath, baseline);
  fs.writeFileSync(proposedPath, proposed);

  const first = invoke(['diff', '--baseline', baselinePath, '--proposed', proposedPath]);
  const second = invoke(['diff', '--baseline', baselinePath, '--proposed', proposedPath]);
  assert.equal(first.status, 'accepted');
  assert.equal(first.operation, 'diff');
  assert.equal(first.inputs.length, 2);
  assert.equal(first.result.kind, 'semantic-diff');
  assert.notEqual(first.result.baseline_artifact_sha256, first.result.proposed_artifact_sha256);
  assert.deepEqual(first.result.changes, [
    {path: '/listeners/0/port', kind: 'changed'},
  ]);
  assert.equal(JSON.stringify(first).includes('8443'), false);
  assert.deepEqual(first, second);
});

test('diff ignores source-only presentation and node-local server changes', () => {
  const proposedPath = path.join(workspace, 'diff-source-only.yaml');
  const baseline = fs.readFileSync(path.join(ROOT, 'config/examples/local.yaml'), 'utf8');
  const proposed = `# presentation-only comment\n${baseline}`
    .replace('  node_id: "bonvoyage-local"', '  node_id: "bonvoyage-other"');
  fs.writeFileSync(proposedPath, proposed);

  const result = invoke([
    'diff', '--baseline-stdin', '--baseline-source-id', 'baseline-stdin.yaml',
    '--proposed', proposedPath,
  ], baseline);
  assert.equal(result.status, 'accepted');
  assert.deepEqual(result.result.changes, []);
  assert.equal(result.result.baseline_artifact_sha256, result.result.proposed_artifact_sha256);
  assert.notEqual(result.inputs[0].sha256, result.inputs[1].sha256);
});

test('diff identifies an invalid side without echoing rejected values', () => {
  const proposedPath = path.join(workspace, 'diff-valid-proposal.yaml');
  fs.copyFileSync(path.join(ROOT, 'config/examples/local.yaml'), proposedPath);
  const invalid = 'server:\n  private_customer_token: diff-do-not-echo\n';
  const result = invoke([
    'diff', '--baseline-stdin', '--baseline-source-id', 'invalid-baseline.yaml',
    '--proposed', proposedPath,
  ], invalid);
  assert.equal(result.status, 'rejected');
  assert.equal(result.result, null);
  assert.equal(result.inputs.length, 2);
  assert.equal(result.diagnostics[0].code, 'BV_CFG_DIFF_INPUT_INVALID');
  assert.equal(result.diagnostics[0].path, '/baseline');
  assert.equal(JSON.stringify(result).includes('diff-do-not-echo'), false);
});

test('migrate emits a deterministic schema-valid no-change result', () => {
  const inputPath = path.join(ROOT, 'config/examples/local.yaml');
  const source = fs.readFileSync(inputPath, 'utf8');
  const first = invoke([
    'migrate', '--input', inputPath,
    '--from-schema-version', '1', '--to-schema-version', '1',
  ]);
  const second = invoke([
    'migrate', '--input', inputPath,
    '--from-schema-version', '1', '--to-schema-version', '1',
  ]);
  assert.equal(first.status, 'accepted');
  assert.equal(first.operation, 'migrate');
  assert.equal(first.versions.input_configuration_schema_version, 1);
  assert.deepEqual(first.result, {
    kind: 'migration',
    from_schema_version: 1,
    to_schema_version: 1,
    changed: false,
    document: source,
    document_sha256: crypto.createHash('sha256').update(source).digest('hex'),
  });
  assert.deepEqual(first, second);
});

test('migrate preserves stdin bytes without requiring current semantic validity', () => {
  const source = fs.readFileSync(path.join(ROOT, 'config/examples/local.yaml'), 'utf8')
    .replace('      - "default"', '      - "missing-virtual-host"');
  const result = invoke([
    'migrate', '--stdin', '--source-id', 'legacy.yaml',
    '--from-schema-version', '1', '--to-schema-version', '1',
  ], source);
  assert.equal(result.status, 'accepted');
  assert.equal(result.result.changed, false);
  assert.equal(result.result.document, source);
  assert.equal(result.result.document_sha256,
    crypto.createHash('sha256').update(source).digest('hex'));
});

test('migrate refuses every unshipped version pair', () => {
  const source = fs.readFileSync(path.join(ROOT, 'config/examples/local.yaml'), 'utf8');
  const result = invoke([
    'migrate', '--stdin', '--source-id', 'legacy.yaml',
    '--from-schema-version', '1', '--to-schema-version', '2',
  ], source);
  assert.equal(result.status, 'refused');
  assert.equal(result.failure_kind, 'compatibility');
  assert.equal(result.diagnostics[0].code, 'BV_CFG_MIGRATION_UNSUPPORTED');
  assert.equal(result.result, null);
});

test('migrate rejects an embedded private key without echoing it', () => {
  const secret = [
    '-----BEGIN PRIVATE KEY-----',
    'migration-private-material-must-not-echo',
    '-----END PRIVATE KEY-----',
  ].join('\n');
  const source = fs.readFileSync(path.join(ROOT, 'config/examples/local.yaml'), 'utf8')
    .replace(
      '    virtual_hosts:\n      - "default"\n',
      `    virtual_hosts:\n      - "default"\n    downstream_tls:\n` +
      `      certificate_chain_secret: server-chain.pem\n` +
      `      private_key_secret: |\n        ${secret.replaceAll('\n', '\n        ')}\n`,
    );
  const result = invoke([
    'migrate', '--stdin', '--source-id', 'secret.yaml',
    '--from-schema-version', '1', '--to-schema-version', '1',
  ], source);
  assert.equal(result.status, 'rejected');
  assert.equal(result.diagnostics[0].code, 'BV_CFG_SECRET_LITERAL_FORBIDDEN');
  assert.equal(result.diagnostics[0].redacted, true);
  assert.equal(result.result, null);
  assert.equal(JSON.stringify(result).includes('migration-private-material-must-not-echo'), false);
});

test('preview emits deterministic post-default artifact metadata and resource counts', () => {
  const inputPath = path.join(ROOT, 'config/examples/local.yaml');
  const first = invoke(['preview', '--input', inputPath]);
  const second = invoke(['preview', '--input', inputPath]);
  assert.equal(first.status, 'accepted');
  assert.equal(first.operation, 'preview');
  assert.equal(first.inputs.length, 1);
  assert.equal(first.result.kind, 'preview');
  assert.equal(first.result.artifact.sha256,
    '0df685415364762d826d71e722864ba2b7ed1f53508999c8be080897c0b1774b');
  assert.deepEqual(first.result.counts, {
    listeners: 1,
    virtual_hosts: 1,
    routes: 2,
    clusters: 1,
    endpoints: 1,
  });
  assert.deepEqual(first.result.changes, []);
  assert.equal('baseline_artifact_sha256' in first.result, false);
  assert.deepEqual(first, second);
});

test('preview compares one optional local baseline without exposing scalar values', () => {
  const baselinePath = path.join(workspace, 'preview-baseline.yaml');
  const baseline = fs.readFileSync(path.join(ROOT, 'config/examples/local.yaml'), 'utf8');
  const proposed = baseline.replace('    port: 8080', '    port: 8443');
  fs.writeFileSync(baselinePath, baseline);

  const result = invoke([
    'preview', '--stdin', '--source-id', 'proposal.yaml', '--baseline', baselinePath,
  ], proposed);
  assert.equal(result.status, 'accepted');
  assert.equal(result.inputs.length, 2);
  assert.equal(result.result.kind, 'preview');
  assert.notEqual(result.result.baseline_artifact_sha256, result.result.artifact.sha256);
  assert.deepEqual(result.result.changes, [
    {path: '/listeners/0/port', kind: 'changed'},
  ]);
  assert.equal(JSON.stringify(result).includes('8443'), false);
});

test('preview identifies a rejected baseline and returns no partial artifact', () => {
  const baselinePath = path.join(workspace, 'preview-invalid-baseline.yaml');
  fs.writeFileSync(baselinePath, 'server:\n  private_customer_token: preview-do-not-echo\n');
  const result = invoke([
    'preview', '--input', path.join(ROOT, 'config/examples/local.yaml'),
    '--baseline', baselinePath,
  ]);
  assert.equal(result.status, 'rejected');
  assert.equal(result.result, null);
  assert.equal(result.inputs.length, 2);
  assert.equal(result.diagnostics[0].code, 'BV_CFG_PREVIEW_INPUT_INVALID');
  assert.equal(result.diagnostics[0].path, '/baseline');
  assert.equal(JSON.stringify(result).includes('preview-do-not-echo'), false);
});
