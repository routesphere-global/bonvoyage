import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {spawnSync} from 'node:child_process';
import {afterEach, test} from 'node:test';
import {fileURLToPath} from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';
import yaml from 'js-yaml';

import {
  checkClaudeSkill,
  CONTRACT_PATH,
  EVALUATION_PATH,
  generateClaudeSkill,
  INSTALLATION_CHECK_SOURCE_PATH,
  loadClaudeWrapperInputs,
  OUTPUT_MANIFEST_PATH,
  POLICY_PATH,
  renderWrapperManifest,
  WRAPPER_SCHEMA_PATH,
} from './generate-claude-config-skill.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PACKAGE_ROOT = path.join(
  ROOT, 'skills', 'claude', 'bonvoyage-config-authoring');
const INSTALLATION_CHECK = path.join(PACKAGE_ROOT, 'scripts', 'check-installation.mjs');
const temporaryRoots = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, ...relativePath.split('/')), 'utf8'));
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function makeTemporaryRoot(prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  temporaryRoots.push(root);
  return root;
}

function write(root, relativePath, contents, mode = 0o644) {
  const output = path.join(root, ...relativePath.split('/'));
  fs.mkdirSync(path.dirname(output), {recursive: true});
  fs.writeFileSync(output, contents, {mode});
  fs.chmodSync(output, mode);
}

function validCommandResult(overrides = {}) {
  const base = {
    contract_version: 'bonvoyage.configuration-authoring.v1',
    operation: 'explain',
    status: 'accepted',
    exit_code: 0,
    failure_kind: 'none',
    versions: {
      product_version: '0.2.0',
      compiler_version: 'bonvoyage-control-plane-phase4-admin-v1',
      supported_configuration_schema_versions: [1],
      input_configuration_schema_version: 1,
    },
    diagnostics: [],
    diagnostics_truncated: false,
    result: {kind: 'field-explanation', path: ''},
  };
  return {...base, ...overrides};
}

function fakeCommandSource({stdout, exitCode = 0, requireCleanEnvironment = false}) {
  const expectedArguments = [
    'explain',
    '--path',
    '',
    '--require-product-version',
    '0.2.0',
    '--require-compiler-version',
    'bonvoyage-control-plane-phase4-admin-v1',
    '--require-configuration-schema-version',
    '1',
  ];
  return `#!/usr/bin/env node
const expected = ${JSON.stringify(expectedArguments)};
if (JSON.stringify(process.argv.slice(2)) !== JSON.stringify(expected)) process.exit(70);
if (${requireCleanEnvironment} && process.env.BONVOYAGE_TEST_SECRET) process.exit(70);
process.stdout.write(${JSON.stringify(stdout)});
process.exit(${exitCode});
`;
}

function runInstallationCheck({
  stdout = `${JSON.stringify(validCommandResult())}\n`,
  exitCode = 0,
  commandPresent = true,
  extraArgs = [],
  requireCleanEnvironment = false,
} = {}) {
  const root = makeTemporaryRoot('bonvoyage-claude-skill-command-');
  const binaryDirectory = path.join(root, 'bin');
  fs.mkdirSync(binaryDirectory);
  if (commandPresent) {
    write(binaryDirectory, 'bonvoyage-config',
      fakeCommandSource({stdout, exitCode, requireCleanEnvironment}), 0o755);
  }
  const command = spawnSync(process.execPath, [INSTALLATION_CHECK, ...extraArgs], {
    cwd: PACKAGE_ROOT,
    encoding: 'utf8',
    env: {
      ...process.env,
      BONVOYAGE_TEST_SECRET: 'must-not-cross-process-boundary',
      PATH: `${binaryDirectory}${path.delimiter}${process.env.PATH ?? ''}`,
    },
    timeout: 10000,
  });
  const result = JSON.parse(command.stdout.trim());
  return {command, result};
}

function copyGeneratorFixture() {
  const root = makeTemporaryRoot('bonvoyage-claude-skill-generator-');
  const policy = readJson(POLICY_PATH);
  const sourcePaths = new Set([
    POLICY_PATH,
    CONTRACT_PATH,
    EVALUATION_PATH,
    INSTALLATION_CHECK_SOURCE_PATH,
    ...policy.reference_sources.map(({source}) => source),
  ]);
  for (const relativePath of sourcePaths) {
    write(root, relativePath,
      fs.readFileSync(path.join(ROOT, ...relativePath.split('/'))));
  }
  return root;
}

test('committed Claude skill is deterministic, current and schema-valid', () => {
  const first = generateClaudeSkill(ROOT);
  const second = generateClaudeSkill(ROOT);
  assert.deepEqual(second, first);
  checkClaudeSkill(ROOT);

  const committed = readJson(OUTPUT_MANIFEST_PATH);
  assert.deepEqual(committed, first.manifest);
  assert.equal(fs.readFileSync(path.join(ROOT, ...OUTPUT_MANIFEST_PATH.split('/')), 'utf8'),
    renderWrapperManifest(first.manifest));

  const validate = new Ajv2020({allErrors: true, strict: true})
    .compile(readJson(WRAPPER_SCHEMA_PATH));
  assert.equal(validate(committed), true,
    validate.errors ? JSON.stringify(validate.errors, null, 2) : 'invalid wrapper manifest');

  const networkDrift = structuredClone(committed);
  networkDrift.security_boundary.network_access = true;
  assert.equal(validate(networkDrift), false,
    'schema accepted network access in the offline wrapper');
  const applyDrift = structuredClone(committed);
  applyDrift.operator_authorization.apply_execution = 'explicit';
  assert.equal(validate(applyDrift), false,
    'schema accepted apply execution in the authoring wrapper');
  const surfaceDrift = structuredClone(committed);
  surfaceDrift.interface.surface = 'claude-api';
  assert.equal(validate(surfaceDrift), false,
    'schema accepted an unqualified Claude execution surface');

  const check = spawnSync(process.execPath,
    ['scripts/generate-claude-config-skill.mjs', '--check'],
    {cwd: ROOT, encoding: 'utf8'});
  assert.equal(check.status, 0, `${check.stdout}${check.stderr}`);
});

test('skill metadata uses only portable Agent Skills fields', () => {
  const policy = readJson(POLICY_PATH);
  const skill = fs.readFileSync(path.join(PACKAGE_ROOT, 'SKILL.md'), 'utf8');
  const frontmatter = yaml.load(skill.split('---')[1]);
  assert.deepEqual(frontmatter, {
    name: policy.skill_name,
    description: policy.description,
  });
  assert.match(frontmatter.name, /^[a-z0-9]+(?:-[a-z0-9]+)*$/u);
  assert.ok(frontmatter.name.length <= 64);
  assert.ok(frontmatter.description.length <= 1024);
  assert.doesNotMatch(frontmatter.name, /(?:anthropic|claude)/u);
  assert.doesNotMatch(skill, /\b(?:TODO|TBD|FIXME|INSERT|PLACEHOLDER)\b/u);
  assert.ok(skill.split('\n').length < 500, 'SKILL.md exceeds progressive-disclosure limit');
  for (const phrase of [
    'semantic authority',
    'untrusted data',
    'explicitly requests',
    'Never execute apply',
    'Never use network access',
    'offline validation',
    'offline preview',
  ]) {
    assert.match(skill, new RegExp(phrase, 'u'));
  }
});

test('Claude package avoids permission grants and dynamic Claude Code extensions', () => {
  const skill = fs.readFileSync(path.join(PACKAGE_ROOT, 'SKILL.md'), 'utf8');
  const frontmatter = yaml.load(skill.split('---')[1]);
  assert.deepEqual(Object.keys(frontmatter).sort(), ['description', 'name']);
  assert.doesNotMatch(skill, /allowed-tools|disallowed-tools|context:|agent:/u);
  assert.doesNotMatch(skill, /disable-model-invocation|user-invocable/u);
  assert.doesNotMatch(skill, /!`|\$\{CLAUDE_/u);
  assert.equal(fs.existsSync(path.join(PACKAGE_ROOT, 'agents', 'openai.yaml')), false);
});

test('every packaged release reference is a byte-identical reviewed source', () => {
  const policy = readJson(POLICY_PATH);
  const manifest = readJson(OUTPUT_MANIFEST_PATH);
  const records = new Map(manifest.package.files.map((record) => [record.path, record]));
  for (const reference of policy.reference_sources) {
    const source = fs.readFileSync(path.join(ROOT, ...reference.source.split('/')));
    const packaged = fs.readFileSync(path.join(PACKAGE_ROOT, ...reference.target.split('/')));
    assert.deepEqual(packaged, source, reference.id);
    assert.deepEqual(records.get(reference.target), {
      path: reference.target,
      role: 'release-reference',
      bytes: source.length,
      sha256: sha256(source),
    });
  }
});

test('wrapper preserves shared capabilities, workflow, security, consent and claims', () => {
  const contract = readJson(CONTRACT_PATH);
  const wrapper = readJson(OUTPUT_MANIFEST_PATH);
  assert.deepEqual(wrapper.capability_ids,
    contract.capabilities.map(({id}) => id));
  assert.deepEqual(wrapper.workflow_stages, contract.workflow_stages);
  assert.deepEqual(wrapper.security_boundary, contract.security_boundary);
  assert.deepEqual(wrapper.operator_authorization, contract.operator_authorization);
  assert.deepEqual(wrapper.claim_boundary, contract.claim_boundary);
  assert.deepEqual(wrapper.evaluation_categories, contract.evaluation_categories);
  assert.equal(wrapper.interface.surface, 'claude-code');
  assert.equal(wrapper.command.automatic_install, false);
  assert.equal(wrapper.command.network_lookup, false);
  assert.equal(wrapper.operator_authorization.apply_execution, 'forbidden');

  const commandGuide = fs.readFileSync(
    path.join(PACKAGE_ROOT, 'references', 'command-surface.md'), 'utf8');
  for (const operation of ['validate', 'format', 'explain', 'diff', 'migrate', 'preview']) {
    assert.match(commandGuide, new RegExp(`bonvoyage-config ${operation}\\b`, 'u'));
  }
  assert.ok(commandGuide.match(/--require-product-version 0\.2\.0/gu).length >= 7);
  assert.ok(commandGuide.match(
    /--require-compiler-version bonvoyage-control-plane-phase4-admin-v1/gu).length >= 7);
  assert.ok(commandGuide.match(/--require-configuration-schema-version 1/gu).length >= 7);
  assert.doesNotMatch(commandGuide, /bonvoyage-config apply\b/u);
  assert.match(commandGuide, /standard input/u);
  assert.match(commandGuide, /explicit operator consent/u);
  assert.match(commandGuide, /never\s+applies configuration or performs rollback/u);
  assert.match(commandGuide, /Every zero\s+sequence is deliberately invalid/u);
  assert.match(commandGuide, /\/api\/v1\/rollbacks\/preview/u);
  assert.match(commandGuide, /\/api\/v1\/rollbacks(?:\s|$)/u);
  assert.match(commandGuide, /Idempotency-Key: REPLACE_ME/u);
  assert.match(commandGuide, /Present, but never execute, the rollback request/u);
});

test('package contains no private paths, credential material or remote instructions', () => {
  const generated = generateClaudeSkill(ROOT);
  for (const [relativePath, bytes] of generated.files) {
    const text = bytes.toString('utf8');
    assert.doesNotMatch(text, /\/Users\/|\/home\/|[A-Za-z]:\\Users\\/u,
      relativePath);
    assert.doesNotMatch(text, /-----BEGIN (?:PRIVATE KEY|CERTIFICATE)-----/u,
      relativePath);
    assert.doesNotMatch(text, /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u, relativePath);
    if (relativePath === 'SKILL.md') {
      assert.doesNotMatch(text, /https?:\/\//u, relativePath);
      assert.doesNotMatch(text, /\$\{|\{\{|<%|%>/u, relativePath);
    }
  }
});

test('installation check accepts only the exact local release and strips secret environment', () => {
  const {command, result} = runInstallationCheck({requireCleanEnvironment: true});
  assert.equal(command.status, 0, command.stderr);
  assert.deepEqual(result, {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-claude-code-installation-check',
    wrapper_version: 'bonvoyage.claude-code-skill.v1',
    status: 'ready',
    reason: 'none',
    identity: {
      product_version: '0.2.0',
      compiler_version: 'bonvoyage-control-plane-phase4-admin-v1',
      configuration_schema_versions: [1],
      skill_version: 'bonvoyage.configuration-skill.v1',
    },
  });
});

test('missing command blocks without auto-install or network lookup', () => {
  const {command, result} = runInstallationCheck({commandPresent: false});
  assert.equal(command.status, 2);
  assert.equal(result.status, 'blocked');
  assert.equal(result.reason, 'command-missing');
  assert.equal(result.identity, null);
});

test('malformed, multiline and oversized command output fail closed without echo', () => {
  for (const [stdout, expected] of [
    ['not-json\n', 'malformed-output'],
    [`${JSON.stringify(validCommandResult())}\n${JSON.stringify(validCommandResult())}\n`,
      'malformed-output'],
    ['x'.repeat(300 * 1024), 'malformed-output'],
  ]) {
    const {command, result} = runInstallationCheck({stdout});
    assert.equal(command.status, 2);
    assert.equal(result.reason, expected);
    assert.equal(command.stdout.includes('not-json'), false);
    assert.ok(command.stdout.length < 1024, 'bounded result unexpectedly echoed child output');
  }
});

test('release mismatch and nonzero refusal block usable output', () => {
  const mismatched = validCommandResult({
    versions: {
      ...validCommandResult().versions,
      product_version: '0.2.1',
    },
  });
  const mismatch = runInstallationCheck({stdout: `${JSON.stringify(mismatched)}\n`});
  assert.equal(mismatch.command.status, 2);
  assert.equal(mismatch.result.reason, 'release-mismatch');

  const refusal = runInstallationCheck({
    stdout: `${JSON.stringify(validCommandResult())}\n`,
    exitCode: 3,
  });
  assert.equal(refusal.command.status, 2);
  assert.equal(refusal.result.reason, 'command-refused');
});

test('installation check accepts no caller arguments', () => {
  const {command, result} = runInstallationCheck({extraArgs: ['--override-release']});
  assert.equal(command.status, 2);
  assert.equal(result.reason, 'invalid-invocation');
});

test('generator rejects stale contracts and path escapes rather than normalizing them', () => {
  const staleRoot = copyGeneratorFixture();
  const contractPath = path.join(staleRoot, ...CONTRACT_PATH.split('/'));
  const contract = JSON.parse(fs.readFileSync(contractPath, 'utf8'));
  contract.product_version = '0.2.1';
  fs.writeFileSync(contractPath, `${JSON.stringify(contract, null, 2)}\n`);
  assert.throws(() => loadClaudeWrapperInputs(staleRoot),
    /unexpected product version|stale relative/u);

  const escapingRoot = copyGeneratorFixture();
  const policyPath = path.join(escapingRoot, ...POLICY_PATH.split('/'));
  const policy = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
  policy.reference_sources[0].target = '../escaped.json';
  fs.writeFileSync(policyPath, `${JSON.stringify(policy, null, 2)}\n`);
  assert.throws(() => loadClaudeWrapperInputs(escapingRoot), /escapes the repository/u);
});

test('generator command accepts exactly one explicit mode', () => {
  for (const args of [[], ['--unknown'], ['--check', '--write']]) {
    const command = spawnSync(process.execPath,
      ['scripts/generate-claude-config-skill.mjs', ...args],
      {cwd: ROOT, encoding: 'utf8'});
    assert.notEqual(command.status, 0, `unexpected acceptance: ${args.join(' ')}`);
    assert.match(`${command.stdout}${command.stderr}`, /usage:/u);
  }
});
