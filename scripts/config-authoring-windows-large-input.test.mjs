import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {afterEach, test} from 'node:test';
import {fileURLToPath} from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

import {
  createLargeInputFixture,
  validateCommandResultForTest,
  verifyWindowsAcceptanceContract,
} from './run-config-authoring-windows-large-input.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACT_PATH = path.join(
  ROOT, 'packaging', 'release', 'windows', 'config-authoring-large-input-contract.json');
const WORKFLOW_PATH = path.join(
  ROOT, 'packaging', 'release', 'windows', 'config-authoring-large-input.workflow.yml');
const EVIDENCE_SCHEMA_PATH = path.join(
  ROOT, 'config', 'schemas', 'bonvoyage-windows-large-input-evidence-v1.schema.json');
const temporaryRoots = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function write(root, relativePath, contents) {
  const destination = path.join(root, ...relativePath.split('/'));
  fs.mkdirSync(path.dirname(destination), {recursive: true});
  fs.writeFileSync(destination, contents);
  return destination;
}

function copyFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-windows-contract-'));
  temporaryRoots.push(root);
  const contractPath = write(root,
    'packaging/release/windows/config-authoring-large-input-contract.json',
    fs.readFileSync(CONTRACT_PATH));
  const workflowPath = write(root,
    'packaging/release/windows/config-authoring-large-input.workflow.yml',
    fs.readFileSync(WORKFLOW_PATH));
  return {root, contractPath, workflowPath};
}

function expectedCommandResult(contract) {
  return {
    contract_version: contract.expected_result.contract_version,
    operation: 'validate',
    status: 'rejected',
    exit_code: 2,
    failure_kind: 'validation',
    versions: {
      product_version: '0.2.0',
      compiler_version: 'bonvoyage-control-plane-phase4-admin-v1',
      supported_configuration_schema_versions: [1],
      input_configuration_schema_version: null,
    },
    inputs: [{
      source_id: 'windows-large-input.yaml',
      bytes: contract.fixture.observed_bytes,
      sha256: contract.fixture.observed_sha256,
    }],
    diagnostics: [{
      code: 'BV_CFG_INPUT_TOO_LARGE',
      severity: 'error',
      message: 'The input exceeds the maximum supported configuration size.',
      redacted: false,
    }],
    diagnostics_truncated: false,
    result: {kind: 'validation', valid: false, artifact: null},
  };
}

function git(root, ...args) {
  return execFileSync('git', ['-C', root, ...args], {encoding: 'utf8'}).trim();
}

test('blocked Windows contract and inactive workflow are reviewable without Actions usage', () => {
  const result = verifyWindowsAcceptanceContract(CONTRACT_PATH, WORKFLOW_PATH, {
    repositoryRoot: ROOT,
  });
  assert.equal(result.contract.activation.state, 'blocked-pending-public-repository');
  assert.match(result.workflow_sha256, /^[0-9a-f]{64}$/u);
  assert.equal(fs.existsSync(path.join(
    ROOT, '.github', 'workflows', 'config-authoring-windows-large-input.yml')), false);
});

test('blocked Windows contract cannot be treated as activatable', () => {
  assert.throws(() => verifyWindowsAcceptanceContract(CONTRACT_PATH, WORKFLOW_PATH, {
    repositoryRoot: ROOT,
    requireActivatable: true,
    environment: {},
  }), /contract-not-activatable/u);
});

test('unexpected active workflow fails the blocked contract closed', () => {
  const fixture = copyFixture();
  write(fixture.root, '.github/workflows/config-authoring-windows-large-input.yml',
    fs.readFileSync(fixture.workflowPath));
  assert.throws(() => verifyWindowsAcceptanceContract(
    fixture.contractPath, fixture.workflowPath, {repositoryRoot: fixture.root}),
  /blocked-contract-activation-drift/u);
});

test('contract, template and active workflow symbolic links are refused', (context) => {
  const fixture = copyFixture();
  const originalContract = fs.readFileSync(fixture.contractPath);
  const realContract = write(fixture.root, 'real-contract.json', originalContract);
  fs.rmSync(fixture.contractPath);
  try {
    fs.symlinkSync(realContract, fixture.contractPath);
  } catch (error) {
    context.skip(`symbolic links are unavailable: ${error.message}`);
    return;
  }
  assert.throws(() => verifyWindowsAcceptanceContract(
    fixture.contractPath, fixture.workflowPath, {repositoryRoot: fixture.root}),
  /contract-unreadable/u);
  fs.rmSync(fixture.contractPath);
  fs.writeFileSync(fixture.contractPath, originalContract);

  const linkedWorkflow = path.join(fixture.root, 'linked.workflow.yml');
  fs.symlinkSync(fixture.workflowPath, linkedWorkflow);
  assert.throws(() => verifyWindowsAcceptanceContract(
    fixture.contractPath, linkedWorkflow, {repositoryRoot: fixture.root}),
  /workflow-path-invalid/u);

  const originalWorkflow = fs.readFileSync(fixture.workflowPath);
  fs.rmSync(fixture.workflowPath);
  const realWorkflow = write(fixture.root, 'real.workflow.yml', originalWorkflow);
  fs.symlinkSync(realWorkflow, fixture.workflowPath);
  assert.throws(() => verifyWindowsAcceptanceContract(
    fixture.contractPath, fixture.workflowPath, {repositoryRoot: fixture.root}),
  /workflow-unreadable/u);
});

test('ready contract requires exact active bytes, clean tagged source and hosted context', () => {
  const fixture = copyFixture();
  const contract = readJson(fixture.contractPath);
  contract.activation.state = 'ready-for-manual-execution';
  contract.activation.public_repository_created = true;
  contract.activation.repository_settings_verified = true;
  fs.writeFileSync(fixture.contractPath, `${JSON.stringify(contract, null, 2)}\n`);
  write(fixture.root, contract.activation.active_workflow_path,
    fs.readFileSync(fixture.workflowPath));
  git(fixture.root, 'init', '-b', 'main');
  git(fixture.root, 'config', 'user.name', 'Windows Contract Test');
  git(fixture.root, 'config', 'user.email', 'windows-contract@example.invalid');
  git(fixture.root, 'add', '.');
  git(fixture.root, 'commit', '-m', 'fixture');
  git(fixture.root, 'tag', 'v0.2.0');
  const commit = git(fixture.root, 'rev-parse', 'HEAD');
  const result = verifyWindowsAcceptanceContract(fixture.contractPath, fixture.workflowPath, {
    repositoryRoot: fixture.root,
    requireActivatable: true,
    environment: {
      GITHUB_ACTIONS: 'true',
      GITHUB_EVENT_NAME: 'workflow_dispatch',
      GITHUB_REPOSITORY: 'routesphere-global/bonvoyage',
      GITHUB_REF_TYPE: 'tag',
      GITHUB_REF_NAME: 'v0.2.0',
      GITHUB_SHA: commit,
      GITHUB_RUN_ID: '42',
      GITHUB_RUN_ATTEMPT: '1',
    },
  });
  assert.equal(result.contract.activation.state, 'ready-for-manual-execution');
  const activeWorkflow = path.join(fixture.root, contract.activation.active_workflow_path);
  fs.rmSync(activeWorkflow);
  fs.symlinkSync(fixture.workflowPath, activeWorkflow);
  assert.throws(() => verifyWindowsAcceptanceContract(fixture.contractPath, fixture.workflowPath, {
    repositoryRoot: fixture.root,
    requireActivatable: true,
    environment: {
      GITHUB_ACTIONS: 'true',
      GITHUB_EVENT_NAME: 'workflow_dispatch',
      GITHUB_REPOSITORY: 'routesphere-global/bonvoyage',
      GITHUB_REF_TYPE: 'tag',
      GITHUB_REF_NAME: 'v0.2.0',
      GITHUB_SHA: commit,
      GITHUB_RUN_ID: '42',
      GITHUB_RUN_ATTEMPT: '1',
    },
  }), /contract-not-activatable/u);
});

test('workflow trigger, runner, permissions and action pins are immutable', () => {
  const mutations = [
    ['  workflow_dispatch:\n', '  push:\n    branches: [main]\n'],
    ['runs-on: windows-2025', 'runs-on: windows-latest'],
    ['permissions:\n  contents: read', 'permissions:\n  contents: write'],
    [
      'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
      'actions/checkout@0000000000000000000000000000000000000000',
    ],
  ];
  for (const [before, after] of mutations) {
    const fixture = copyFixture();
    const source = fs.readFileSync(fixture.workflowPath, 'utf8');
    assert.ok(source.includes(before));
    fs.writeFileSync(fixture.workflowPath, source.replace(before, after));
    assert.throws(() => verifyWindowsAcceptanceContract(
      fixture.contractPath, fixture.workflowPath, {repositoryRoot: fixture.root}));
  }
});

test('workflow cannot gain secrets, publication commands or network download helpers', () => {
  for (const addition of [
    '\n# ${{ secrets.RELEASE_TOKEN }}\n',
    '\n# npm publish\n',
    '\n# Invoke-WebRequest https://example.invalid/tool\n',
  ]) {
    const fixture = copyFixture();
    fs.appendFileSync(fixture.workflowPath, addition);
    assert.throws(() => verifyWindowsAcceptanceContract(
      fixture.contractPath, fixture.workflowPath, {repositoryRoot: fixture.root}),
    /workflow-forbidden-authority/u);
  }
});

test('large-input fixture has exact full and observed identities', () => {
  const contract = readJson(CONTRACT_PATH);
  const fixture = createLargeInputFixture(contract);
  assert.equal(fixture.length, 1048577);
  assert.equal(sha256(fixture), contract.fixture.sha256);
  assert.equal(sha256(fixture.subarray(0, 1048576)), contract.fixture.observed_sha256);
  assert.equal(fixture.subarray(0, contract.fixture.marker.length).toString('ascii'),
    contract.fixture.marker);
  assert.equal(fixture[fixture.length - 1], 0x79);
});

test('bounded command result accepts the exact rejection projection for both modes', () => {
  const contract = readJson(CONTRACT_PATH);
  const result = expectedCommandResult(contract);
  const file = validateCommandResultForTest(contract, result, 'file');
  const stdin = validateCommandResultForTest(contract, result, 'stdin');
  assert.equal(file.projection_sha256, contract.expected_result.normalized_projection_sha256);
  assert.equal(stdin.projection_sha256, file.projection_sha256);
  assert.equal(file.observed_bytes, 1048576);
  assert.equal(file.diagnostic_code, 'BV_CFG_INPUT_TOO_LARGE');
});

test('wrong bound, diagnostic or echoed marker fails command evidence closed', () => {
  const contract = readJson(CONTRACT_PATH);
  for (const mutate of [
    (result) => { result.inputs[0].bytes -= 1; },
    (result) => { result.diagnostics[0].code = 'BV_CFG_YAML_INVALID'; },
    (result) => { result.diagnostics[0].message = contract.fixture.marker; },
  ]) {
    const result = expectedCommandResult(contract);
    mutate(result);
    assert.throws(() => validateCommandResultForTest(contract, result),
      /command-(?:output|result(?:-schema)?)-invalid/u);
  }
});

test('accepted evidence schema permits only the bounded two-mode receipt', () => {
  const schema = readJson(EVIDENCE_SCHEMA_PATH);
  const validate = new Ajv2020({allErrors: true, strict: true}).compile(schema);
  const contract = readJson(CONTRACT_PATH);
  const execution = {
    mode: 'file',
    exit_code: 2,
    status: 'rejected',
    failure_kind: 'validation',
    diagnostic_code: 'BV_CFG_INPUT_TOO_LARGE',
    observed_bytes: 1048576,
    observed_sha256: contract.fixture.observed_sha256,
    projection_sha256: contract.expected_result.normalized_projection_sha256,
    stdout_bytes: 512,
    stderr_bytes: 0,
  };
  const evidence = {
    $schema: schema.$id,
    schema_version: 1,
    classification: 'routesphere-bonvoyage-windows-config-large-input-evidence',
    gate_version: contract.gate_version,
    accepted: true,
    source: {
      repository: 'routesphere-global/bonvoyage',
      commit: 'a'.repeat(40),
      tag: 'v0.2.0',
      run_id: '42',
      run_attempt: 1,
    },
    platform: {
      os: 'windows', architecture: 'amd64', runner: 'windows-2025',
      go_version: 'go1.23.0', node_version: 'v22.12.0',
    },
    binary: {bytes: 1024, sha256: 'b'.repeat(64)},
    fixture: {
      bytes: contract.fixture.bytes,
      observed_bytes: contract.fixture.observed_bytes,
      sha256: contract.fixture.sha256,
      observed_sha256: contract.fixture.observed_sha256,
      retained: false,
    },
    executions: [execution, {...execution, mode: 'stdin'}],
    agreement_sha256: contract.expected_result.normalized_projection_sha256,
    authority: {...contract.authority},
  };
  assert.equal(validate(evidence), true,
    validate.errors ? JSON.stringify(validate.errors, null, 2) : 'invalid evidence');
  evidence.executions.push({...execution, mode: 'stdin'});
  assert.equal(validate(evidence), false);
});
