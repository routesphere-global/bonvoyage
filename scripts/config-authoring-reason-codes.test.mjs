import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

import {
  buildReasonCodeCatalog,
  generateReasonCodeCatalog,
  GUIDANCE_PATH,
  loadReasonCodeInputs,
  OUTPUT_PATH,
  REASON_CODE_SCHEMA_PATH,
  renderReasonCodeCatalog,
} from './generate-config-reason-codes.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, ...relativePath.split('/')), 'utf8'));
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function cloneInputs() {
  return structuredClone(loadReasonCodeInputs(ROOT));
}

function resolvePublicFile(relativePath) {
  const segments = relativePath.split('/');
  const candidates = [
    path.join(ROOT, 'tools/oss-export/public-root', ...segments),
    path.join(ROOT, ...segments),
  ];
  const resolved = candidates.find((candidate) => fs.existsSync(candidate));
  assert.ok(resolved, `public file is missing from private and exported layouts: ${relativePath}`);
  return resolved;
}

test('committed reason-code catalog is deterministic, current and schema-valid', () => {
  const first = generateReasonCodeCatalog(ROOT);
  const second = generateReasonCodeCatalog(ROOT);
  const committed = readJson(OUTPUT_PATH);
  assert.deepEqual(first, second);
  assert.deepEqual(committed, first);
  assert.equal(
    fs.readFileSync(path.join(ROOT, ...OUTPUT_PATH.split('/')), 'utf8'),
    renderReasonCodeCatalog(first),
  );

  const validate = new Ajv2020({allErrors: true, strict: true})
    .compile(readJson(REASON_CODE_SCHEMA_PATH));
  assert.equal(validate(committed), true,
    validate.errors ? JSON.stringify(validate.errors, null, 2) : 'invalid reason-code catalog');

  const check = spawnSync(process.execPath,
    ['scripts/generate-config-reason-codes.mjs', '--check'],
    {cwd: ROOT, encoding: 'utf8'});
  assert.equal(check.status, 0, `${check.stdout}${check.stderr}`);
});

test('catalog contains the exact 31 stable reason codes in canonical order', () => {
  const catalog = generateReasonCodeCatalog(ROOT);
  const codes = catalog.entries.map((entry) => entry.code);
  assert.equal(catalog.entry_count, 31);
  assert.equal(catalog.entry_count, catalog.entries.length);
  assert.equal(new Set(codes).size, codes.length);
  assert.deepEqual(codes, [...codes].sort());
  assert.equal(codes[0], 'BV_CFG_DIAGNOSTICS_TRUNCATED');
  assert.equal(codes.at(-1), 'BV_CFG_YAML_SYNTAX');

  const publicReference = fs.readFileSync(resolvePublicFile(
    'docs-site/src/content/docs/reference/configuration-diagnostics.md',
  ), 'utf8');
  const documentedCodes = [...new Set(
    [...publicReference.matchAll(/`(BV_CFG_[A-Z0-9_]+)`/gu)].map((match) => match[1]),
  )].sort();
  assert.deepEqual(documentedCodes, codes,
    'public diagnostic reference must name every stable reason code');
});

test('classification, severity and retry behavior come only from the contract', () => {
  const inputs = loadReasonCodeInputs(ROOT);
  const catalog = buildReasonCodeCatalog(inputs);
  assert.deepEqual(
    catalog.entries.map(({code, class: reasonClass, default_severity, retryable}) => ({
      code,
      class: reasonClass,
      default_severity,
      retryable,
    })),
    inputs.contract.diagnostics.reason_codes,
  );
  assert.deepEqual(
    catalog.entries.filter((entry) => entry.retryable).map((entry) => entry.code),
    ['BV_CFG_INPUT_UNREADABLE'],
  );
});

test('reviewed guidance exactly covers the registry and has bounded shape', () => {
  const inputs = loadReasonCodeInputs(ROOT);
  const registryCodes = inputs.contract.diagnostics.reason_codes.map((entry) => entry.code);
  const guidanceCodes = inputs.guidance.entries.map((entry) => entry.code);
  assert.deepEqual(guidanceCodes, registryCodes);
  for (const entry of inputs.guidance.entries) {
    assert.deepEqual(Object.keys(entry).sort(),
      ['code', 'operator_action', 'summary', 'title']);
    assert.ok(entry.title.length >= 4 && entry.title.length <= 80);
    assert.ok(entry.summary.length >= 10 && entry.summary.length <= 240);
    assert.ok(entry.operator_action.length >= 10 && entry.operator_action.length <= 240);
  }
});

test('anchors are stable, derived and unique', () => {
  const catalog = generateReasonCodeCatalog(ROOT);
  const anchors = catalog.entries.map((entry) => entry.anchor);
  assert.equal(new Set(anchors).size, anchors.length);
  for (const entry of catalog.entries) {
    assert.equal(entry.anchor, entry.code.toLowerCase().replaceAll('_', '-'));
  }
});

test('presentation content is static and excludes dynamic placeholders', () => {
  const serialized = JSON.stringify(generateReasonCodeCatalog(ROOT));
  assert.doesNotMatch(serialized, /\$\{|\{\{|<%|%>|process\.env|\benv\s*\(/u);
  assert.doesNotMatch(serialized, /\r|\n/u);
});

test('catalog carries no document, secret or private material', () => {
  const catalog = generateReasonCodeCatalog(ROOT);
  const serialized = JSON.stringify(catalog);
  assert.equal(catalog.security_boundary.document_values_included, false);
  assert.equal(catalog.security_boundary.secret_values_included, false);
  assert.equal(catalog.security_boundary.environment_secret_reads, false);
  assert.equal(catalog.security_boundary.private_material_included, false);
  assert.doesNotMatch(serialized, /-----BEGIN [A-Z0-9 ]+-----/u);
  assert.doesNotMatch(serialized, /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u);
  assert.doesNotMatch(serialized, /(?:^|[\s'"(])\/(?:Users|home)\/[^\s'"),]+/u);
});

test('source identities bind the exact contract and reviewed guidance', () => {
  const catalog = generateReasonCodeCatalog(ROOT);
  for (const source of Object.values(catalog.sources)) {
    const bytes = fs.readFileSync(path.join(ROOT, ...source.path.split('/')));
    assert.equal(source.sha256, sha256(bytes));
  }
  assert.equal(catalog.sources.reviewed_guidance.path, GUIDANCE_PATH);
});

test('generation fails closed when the contract registry drifts', () => {
  const inputs = cloneInputs();
  inputs.contract.diagnostics.reason_codes.push({
    code: 'BV_CFG_Z_FUTURE',
    class: 'operation',
    default_severity: 'error',
    retryable: false,
  });
  assert.throws(() => buildReasonCodeCatalog(inputs),
    /must exactly cover the authoring contract reason-code registry/u);
});

test('generation rejects missing, extra, duplicate and unsafe guidance', () => {
  const missing = cloneInputs();
  missing.guidance.entries.pop();
  assert.throws(() => buildReasonCodeCatalog(missing), /must exactly cover/u);

  const extra = cloneInputs();
  extra.guidance.entries.push({
    code: 'BV_CFG_Z_UNKNOWN',
    title: 'Unknown future code',
    summary: 'This entry is not present in the stable reason-code registry.',
    operator_action: 'Remove the unregistered guidance entry before generation.',
  });
  assert.throws(() => buildReasonCodeCatalog(extra), /must exactly cover/u);

  const duplicate = cloneInputs();
  duplicate.guidance.entries.splice(1, 0, structuredClone(duplicate.guidance.entries[0]));
  assert.throws(() => buildReasonCodeCatalog(duplicate), /unique and sorted|duplicate/u);

  const unsafe = cloneInputs();
  unsafe.guidance.entries[0].operator_action =
    'Read ${SECRET_VALUE} from the environment before trying this operation again.';
  assert.throws(() => buildReasonCodeCatalog(unsafe),
    /private, secret-shaped or dynamic material/u);
});

test('ambiguous and unknown generator modes are refused', () => {
  for (const args of [[], ['--write', '--check'], ['--unknown']]) {
    const execution = spawnSync(process.execPath,
      ['scripts/generate-config-reason-codes.mjs', ...args],
      {cwd: ROOT, encoding: 'utf8'});
    assert.notEqual(execution.status, 0, args.join(' '));
    assert.match(execution.stderr, /usage: generate-config-reason-codes\.mjs --check\|--write/u);
  }
});
