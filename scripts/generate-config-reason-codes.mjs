import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
export const ROOT = path.resolve(path.dirname(SCRIPT_PATH), '..');
export const CONTRACT_PATH = 'config/authoring/bonvoyage-authoring-v1.json';
export const GUIDANCE_PATH =
  'config/authoring/reason-codes/v1/reviewed-guidance.json';
export const OUTPUT_PATH = 'config/authoring/reason-codes/v1/catalog.json';
export const REASON_CODE_SCHEMA_PATH =
  'config/schemas/bonvoyage-authoring-reason-codes-v1.schema.json';

const CLASSIFICATION =
  'routesphere-bonvoyage-configuration-reason-code-catalog';
const GUIDANCE_CLASSIFICATION =
  'routesphere-bonvoyage-reviewed-configuration-reason-code-guidance';
const GUIDANCE_VERSION = 'bonvoyage.configuration-reason-code-guidance.v1';
const REASON_CODE_VERSION = 'bonvoyage.configuration-reason-codes.v1';
const REASON_CODE = /^BV_CFG_[A-Z0-9_]+$/u;
const CLASSES = new Set([
  'compatibility',
  'input',
  'internal',
  'operation',
  'schema',
  'security',
  'semantic',
  'syntax',
]);
const SEVERITIES = new Set(['error', 'warning', 'info']);
const UNSAFE_PATTERNS = [
  /-----BEGIN [A-Z0-9 ]+-----/u,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u,
  /\b[0-9]{12}\b/u,
  /\$\{|\{\{|<%|%>|process\.env|\benv\s*\(/u,
  /(?:^|[\s'"(])\/(?:Users|home)\/[^\s'"),]+/u,
  /\b[A-Za-z]:\\Users\\[^\s'"),]+/u,
];

function digest(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
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

function readBoundJson(root, relativePath) {
  assertRepositoryPath(relativePath, 'source');
  const repositoryRoot = path.resolve(root);
  const absolutePath = path.resolve(root, ...relativePath.split('/'));
  assert.equal(absolutePath.startsWith(`${repositoryRoot}${path.sep}`), true,
    `source escapes repository root: ${relativePath}`);
  const information = fs.lstatSync(absolutePath);
  assert.equal(information.isSymbolicLink(), false, `source is a symlink: ${relativePath}`);
  assert.equal(information.isFile(), true, `source is not a regular file: ${relativePath}`);
  const bytes = fs.readFileSync(absolutePath);
  try {
    return {bytes, document: JSON.parse(bytes.toString('utf8')), sha256: digest(bytes)};
  } catch (error) {
    throw new Error(`invalid JSON source ${relativePath}: ${error.message}`);
  }
}

function assertPresentationString(value, minimum, maximum, context) {
  assert.equal(typeof value, 'string', `${context} must be a string`);
  assert.ok(value.length >= minimum && value.length <= maximum,
    `${context} must contain ${minimum} to ${maximum} characters`);
  assert.equal(/[\r\n]/u.test(value), false, `${context} must be one line`);
  for (const pattern of UNSAFE_PATTERNS) {
    assert.equal(pattern.test(value), false,
      `${context} contains private, secret-shaped or dynamic material`);
  }
}

function anchorForCode(code) {
  return code.toLowerCase().replaceAll('_', '-');
}

export function buildReasonCodeCatalog({contract, guidance, sourceSha256}) {
  assertExactKeys(guidance,
    ['schema_version', 'classification', 'guidance_version', 'entries'],
    'reviewed guidance');
  assert.equal(guidance.schema_version, 1, 'unsupported reviewed guidance schema version');
  assert.equal(guidance.classification, GUIDANCE_CLASSIFICATION,
    'unexpected reviewed guidance classification');
  assert.equal(guidance.guidance_version, GUIDANCE_VERSION,
    'unexpected reviewed guidance version');
  assert.ok(contract?.diagnostics?.reason_codes,
    'authoring contract does not contain the reason-code registry');
  assert.equal(Array.isArray(contract.diagnostics.reason_codes), true,
    'authoring contract reason-code registry must be an array');
  assert.equal(Array.isArray(guidance.entries), true,
    'reviewed guidance entries must be an array');

  const registry = contract.diagnostics.reason_codes;
  const registryCodes = registry.map((entry, index) => {
    assertExactKeys(entry, ['code', 'class', 'default_severity', 'retryable'],
      `authoring contract reason code ${index}`);
    assert.match(entry.code, REASON_CODE,
      `authoring contract reason code ${index} is invalid`);
    assert.equal(CLASSES.has(entry.class), true,
      `unsupported reason-code class: ${entry.class}`);
    assert.equal(SEVERITIES.has(entry.default_severity), true,
      `unsupported reason-code severity: ${entry.default_severity}`);
    assert.equal(typeof entry.retryable, 'boolean',
      `reason-code retryable flag must be boolean: ${entry.code}`);
    return entry.code;
  });
  assert.deepEqual(registryCodes, [...registryCodes].sort(compareText),
    'authoring contract reason codes must be sorted');
  assert.equal(new Set(registryCodes).size, registryCodes.length,
    'authoring contract reason codes must be unique');

  const guidanceByCode = new Map();
  let previousCode = null;
  for (const [index, entry] of guidance.entries.entries()) {
    assertExactKeys(entry, ['code', 'title', 'summary', 'operator_action'],
      `reviewed guidance entry ${index}`);
    assert.match(entry.code, REASON_CODE, `reviewed guidance code ${index} is invalid`);
    if (previousCode !== null) {
      assert.ok(entry.code > previousCode, 'reviewed guidance entries must be unique and sorted');
    }
    assert.equal(guidanceByCode.has(entry.code), false,
      `duplicate reviewed guidance code: ${entry.code}`);
    assertPresentationString(entry.title, 4, 80, `${entry.code} title`);
    assertPresentationString(entry.summary, 10, 240, `${entry.code} summary`);
    assertPresentationString(entry.operator_action, 10, 240,
      `${entry.code} operator action`);
    guidanceByCode.set(entry.code, entry);
    previousCode = entry.code;
  }
  assert.deepEqual([...guidanceByCode.keys()], registryCodes,
    'reviewed guidance must exactly cover the authoring contract reason-code registry');

  const entries = registry.map((registered) => {
    const reviewed = guidanceByCode.get(registered.code);
    return {
      code: registered.code,
      class: registered.class,
      default_severity: registered.default_severity,
      retryable: registered.retryable,
      anchor: anchorForCode(registered.code),
      title: reviewed.title,
      summary: reviewed.summary,
      operator_action: reviewed.operator_action,
    };
  });
  assert.equal(new Set(entries.map((entry) => entry.anchor)).size, entries.length,
    'generated reason-code anchors must be unique');

  return {
    $schema: '../../../schemas/bonvoyage-authoring-reason-codes-v1.schema.json',
    schema_version: 1,
    classification: CLASSIFICATION,
    reason_code_version: REASON_CODE_VERSION,
    contract_version: contract.contract_version,
    compiler_version: contract.authority.compiler_identity,
    authority: {
      registry: 'authoring-contract',
      runtime_diagnostics: 'bonvoyage-config',
      semantic_validation: contract.authority.compiler_entrypoint,
      presentation_scope: 'static-remediation-guidance-only',
      runtime_message_is_stable_contract: false,
      network_access: false,
      live_mutation: false,
    },
    security_boundary: {
      offline: true,
      document_values_included: false,
      secret_values_included: false,
      environment_secret_reads: false,
      private_material_included: false,
    },
    sources: {
      authoring_contract: {path: CONTRACT_PATH, sha256: sourceSha256.authoring_contract},
      reviewed_guidance: {path: GUIDANCE_PATH, sha256: sourceSha256.reviewed_guidance},
    },
    entry_count: entries.length,
    entries,
  };
}

export function loadReasonCodeInputs(root = ROOT) {
  const contract = readBoundJson(root, CONTRACT_PATH);
  const guidance = readBoundJson(root, GUIDANCE_PATH);
  return {
    contract: contract.document,
    guidance: guidance.document,
    sourceSha256: {
      authoring_contract: contract.sha256,
      reviewed_guidance: guidance.sha256,
    },
  };
}

export function generateReasonCodeCatalog(root = ROOT) {
  return buildReasonCodeCatalog(loadReasonCodeInputs(root));
}

export function renderReasonCodeCatalog(catalog) {
  return `${JSON.stringify(catalog, null, 2)}\n`;
}

function main(args) {
  assert.equal(args.length, 1, 'usage: generate-config-reason-codes.mjs --check|--write');
  assert.equal(args[0] === '--check' || args[0] === '--write', true,
    'usage: generate-config-reason-codes.mjs --check|--write');
  const rendered = renderReasonCodeCatalog(generateReasonCodeCatalog());
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
