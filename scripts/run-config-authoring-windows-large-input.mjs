#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';
import yaml from 'js-yaml';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPOSITORY_ROOT = path.resolve(path.dirname(SCRIPT_PATH), '..');
const MAX_JSON_BYTES = 4 * 1024 * 1024;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const COMMIT_PATTERN = /^[0-9a-f]{40}$/u;
const RUN_ID_PATTERN = /^[1-9][0-9]*$/u;
const ACTION_PATTERN = /^[a-z0-9-]+\/[a-z0-9-]+@[0-9a-f]{40}$/u;

const EXPECTED_ACTIONS = Object.freeze({
  checkout: 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
  setup_go: 'actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e',
  setup_node: 'actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1',
  upload_artifact: 'actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9',
});

class AcceptanceError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function reject(code) {
  throw new AcceptanceError(code);
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function exactKeys(value, expected, code) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) reject(code);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) reject(code);
  return value;
}

function exactValue(actual, expected, code) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) reject(code);
}

function readBoundedJson(filePath, code) {
  try {
    const bytes = fs.readFileSync(filePath);
    if (bytes.length === 0 || bytes.length > MAX_JSON_BYTES) reject(code);
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    if (error instanceof AcceptanceError) throw error;
    reject(code);
  }
}

function requireRegularFile(filePath, code) {
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch {
    reject(code);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) reject(code);
}

function safeRelativePath(value) {
  return typeof value === 'string' && value.length > 0 && !value.includes('\\') &&
    !path.posix.isAbsolute(value) && path.posix.normalize(value) === value &&
    value !== '..' && !value.startsWith('../');
}

function resolveWithin(root, relativePath, code) {
  if (!safeRelativePath(relativePath)) reject(code);
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, ...relativePath.split('/'));
  if (resolved !== resolvedRoot && !resolved.startsWith(`${resolvedRoot}${path.sep}`)) reject(code);
  return resolved;
}

export function createLargeInputFixture(contract) {
  const fixture = contract.fixture;
  const marker = Buffer.from(`${fixture.marker}\n`, 'ascii');
  const bytes = Buffer.alloc(fixture.bytes, 0x78);
  if (marker.length >= fixture.observed_bytes || fixture.bytes !== fixture.observed_bytes + 1) {
    reject('fixture-contract-invalid');
  }
  marker.copy(bytes, 0);
  bytes[bytes.length - 1] = 0x79;
  if (sha256(bytes) !== fixture.sha256 ||
      sha256(bytes.subarray(0, fixture.observed_bytes)) !== fixture.observed_sha256) {
    reject('fixture-contract-invalid');
  }
  return bytes;
}

function expectedProjection(contract) {
  return {
    contract_version: contract.expected_result.contract_version,
    operation: contract.expected_result.operation,
    status: contract.expected_result.status,
    exit_code: contract.expected_result.exit_code,
    failure_kind: contract.expected_result.failure_kind,
    versions: {
      product_version: '0.2.0',
      compiler_version: 'bonvoyage-control-plane-phase4-admin-v1',
      supported_configuration_schema_versions: [1],
      input_configuration_schema_version: null,
    },
    input: {
      bytes: contract.fixture.observed_bytes,
      sha256: contract.fixture.observed_sha256,
    },
    diagnostic: {
      code: contract.expected_result.diagnostic_code,
      severity: contract.expected_result.diagnostic_severity,
      redacted: contract.expected_result.diagnostic_redacted,
    },
    diagnostics_truncated: false,
    result: {kind: 'validation', valid: false, artifact: null},
  };
}

function normalizedProjection(result) {
  return {
    contract_version: result.contract_version,
    operation: result.operation,
    status: result.status,
    exit_code: result.exit_code,
    failure_kind: result.failure_kind,
    versions: result.versions,
    input: {
      bytes: result.inputs[0].bytes,
      sha256: result.inputs[0].sha256,
    },
    diagnostic: {
      code: result.diagnostics[0].code,
      severity: result.diagnostics[0].severity,
      redacted: result.diagnostics[0].redacted,
    },
    diagnostics_truncated: result.diagnostics_truncated,
    result: result.result,
  };
}

function validateContractShape(contract) {
  exactKeys(contract, [
    'schema_version', 'classification', 'gate_version', 'activation', 'source',
    'execution', 'toolchain', 'fixture', 'expected_result', 'actions', 'evidence',
    'authority',
  ], 'contract-invalid');
  if (contract.schema_version !== 1 ||
      contract.classification !== 'routesphere-bonvoyage-windows-config-large-input-contract' ||
      contract.gate_version !== 'bonvoyage.configuration-windows-large-input.v1') {
    reject('contract-invalid');
  }

  exactKeys(contract.activation, [
    'state', 'template_path', 'active_workflow_path', 'public_repository_created',
    'repository_settings_verified',
  ], 'contract-activation-invalid');
  if (!['blocked-pending-public-repository', 'ready-for-manual-execution']
    .includes(contract.activation.state) ||
      contract.activation.template_path !==
        'packaging/release/windows/config-authoring-large-input.workflow.yml' ||
      contract.activation.active_workflow_path !==
        '.github/workflows/config-authoring-windows-large-input.yml') {
    reject('contract-activation-invalid');
  }

  exactKeys(contract.source, [
    'repository', 'event', 'ref_type', 'tag_pattern', 'protected_tag_required',
    'pushed_commit_required', 'clean_checkout_required',
  ], 'contract-source-invalid');
  if (contract.source.repository !== 'https://github.com/routesphere-global/bonvoyage' ||
      contract.source.event !== 'workflow_dispatch' || contract.source.ref_type !== 'tag' ||
      contract.source.protected_tag_required !== true ||
      contract.source.pushed_commit_required !== true ||
      contract.source.clean_checkout_required !== true) {
    reject('contract-source-invalid');
  }
  try {
    new RegExp(contract.source.tag_pattern, 'u');
  } catch {
    reject('contract-source-invalid');
  }

  exactKeys(contract.execution, [
    'environment', 'runner', 'platform', 'permissions', 'timeout_minutes',
    'command_timeout_seconds', 'artifact_retention_days', 'maximum_billable_job_minutes',
    'manual_only', 'scheduled_runs', 'self_hosted_runners', 'cancel_in_progress',
  ], 'contract-execution-invalid');
  exactValue(contract.execution, {
    environment: 'release',
    runner: 'windows-2025',
    platform: 'windows/amd64',
    permissions: {contents: 'read'},
    timeout_minutes: 15,
    command_timeout_seconds: 30,
    artifact_retention_days: 3,
    maximum_billable_job_minutes: 15,
    manual_only: true,
    scheduled_runs: false,
    self_hosted_runners: false,
    cancel_in_progress: false,
  }, 'contract-execution-invalid');

  exactKeys(contract.toolchain, ['go_version', 'node_version'], 'contract-toolchain-invalid');
  exactValue(contract.toolchain, {go_version: '1.23.0', node_version: '22.12.0'},
    'contract-toolchain-invalid');

  exactKeys(contract.fixture, [
    'filename', 'bytes', 'observed_bytes', 'marker', 'sha256', 'observed_sha256',
  ], 'fixture-contract-invalid');
  if (contract.fixture.filename !== 'windows-large-input.yaml' ||
      contract.fixture.bytes !== 1048577 || contract.fixture.observed_bytes !== 1048576 ||
      contract.fixture.marker !== 'BONVOYAGE_WINDOWS_LARGE_INPUT_DO_NOT_ECHO' ||
      !SHA256_PATTERN.test(contract.fixture.sha256) ||
      !SHA256_PATTERN.test(contract.fixture.observed_sha256)) {
    reject('fixture-contract-invalid');
  }
  createLargeInputFixture(contract);

  exactKeys(contract.expected_result, [
    'contract_version', 'operation', 'status', 'exit_code', 'failure_kind',
    'diagnostic_code', 'diagnostic_severity', 'diagnostic_redacted',
    'normalized_projection_sha256',
  ], 'expected-result-invalid');
  exactValue(contract.expected_result, {
    contract_version: 'bonvoyage.configuration-authoring.v1',
    operation: 'validate',
    status: 'rejected',
    exit_code: 2,
    failure_kind: 'validation',
    diagnostic_code: 'BV_CFG_INPUT_TOO_LARGE',
    diagnostic_severity: 'error',
    diagnostic_redacted: false,
    normalized_projection_sha256: 'e15b1d8e8c7b46abef0fbc802847280b42f47e4887f0128e546aea124213c4cf',
  }, 'expected-result-invalid');
  if (sha256(Buffer.from(JSON.stringify(expectedProjection(contract)), 'utf8')) !==
      contract.expected_result.normalized_projection_sha256) {
    reject('expected-result-invalid');
  }

  exactKeys(contract.actions, Object.keys(EXPECTED_ACTIONS), 'contract-actions-invalid');
  for (const [name, value] of Object.entries(contract.actions)) {
    if (!ACTION_PATTERN.test(value) || value !== EXPECTED_ACTIONS[name]) {
      reject('contract-actions-invalid');
    }
  }

  exactKeys(contract.evidence, [
    'schema_path', 'artifact_name', 'files', 'raw_configuration_retained',
    'raw_command_output_retained',
  ], 'contract-evidence-invalid');
  exactValue(contract.evidence, {
    schema_path: 'config/schemas/bonvoyage-windows-large-input-evidence-v1.schema.json',
    artifact_name: 'config-authoring-windows-large-input',
    files: ['acceptance.json', 'checksums.sha256'],
    raw_configuration_retained: false,
    raw_command_output_retained: false,
  }, 'contract-evidence-invalid');

  exactKeys(contract.authority, [
    'release_admitted', 'publishable', 'github_release_created',
    'artifact_uploaded_to_release', 'live_configuration_applied',
  ], 'contract-authority-invalid');
  if (Object.values(contract.authority).some((value) => value !== false)) {
    reject('contract-authority-invalid');
  }
}

function validateWorkflow(contract, workflowSource) {
  let workflow;
  try {
    workflow = yaml.load(workflowSource);
  } catch {
    reject('workflow-invalid');
  }
  exactKeys(workflow, ['name', 'on', 'permissions', 'concurrency', 'env', 'jobs'],
    'workflow-invalid');
  if (workflow.name !== 'Configuration Authoring Windows Large Input') {
    reject('workflow-invalid');
  }
  exactValue(workflow.on, {workflow_dispatch: null}, 'workflow-trigger-invalid');
  exactValue(workflow.permissions, {contents: 'read'}, 'workflow-permissions-invalid');
  if (workflow.concurrency?.['cancel-in-progress'] !== false ||
      workflow.concurrency?.group !== 'config-authoring-windows-large-input-${{ github.ref }}') {
    reject('workflow-concurrency-invalid');
  }
  exactValue(workflow.env, {
    CONTRACT_PATH: contract.activation.template_path.replace(/\.workflow\.yml$/u, '-contract.json'),
    WORKFLOW_TEMPLATE: contract.activation.template_path,
  }, 'workflow-environment-invalid');
  exactKeys(workflow.jobs, ['windows-large-input'], 'workflow-jobs-invalid');
  const job = workflow.jobs['windows-large-input'];
  exactKeys(job, ['name', 'runs-on', 'timeout-minutes', 'environment', 'steps'],
    'workflow-job-invalid');
  if (job.name !== 'Windows AMD64 large-input acceptance' ||
      job['runs-on'] !== contract.execution.runner ||
      job['timeout-minutes'] !== contract.execution.timeout_minutes ||
      job.environment !== contract.execution.environment || !Array.isArray(job.steps) ||
      job.steps.length !== 8) {
    reject('workflow-job-invalid');
  }

  const [checkout, setupGo, setupNode, install, preflight, build, execute, upload] = job.steps;
  if (checkout.uses !== contract.actions.checkout || checkout.with?.['fetch-depth'] !== 0 ||
      checkout.with?.['persist-credentials'] !== false ||
      checkout.with?.ref !== '${{ github.sha }}') reject('workflow-checkout-invalid');
  if (setupGo.uses !== contract.actions.setup_go ||
      setupGo.with?.['go-version'] !== contract.toolchain.go_version ||
      setupGo.with?.cache !== false) reject('workflow-toolchain-invalid');
  if (setupNode.uses !== contract.actions.setup_node ||
      setupNode.with?.['node-version'] !== contract.toolchain.node_version ||
      setupNode.with?.cache !== 'npm') reject('workflow-toolchain-invalid');
  if (install.run !== 'npm ci --ignore-scripts') reject('workflow-install-invalid');
  if (preflight.shell !== 'pwsh' || !preflight.run.includes(' verify-contract ') ||
      !preflight.run.includes('--require-activatable')) reject('workflow-preflight-invalid');
  if (build.shell !== 'pwsh' || !build.run.includes('go build -trimpath') ||
      !build.run.includes('bonvoyage-config.exe')) reject('workflow-build-invalid');
  if (execute.shell !== 'pwsh' || !execute.run.includes(' run ') ||
      !execute.run.includes('--require-activatable') ||
      !execute.run.includes('bonvoyage-config.exe')) reject('workflow-execution-invalid');
  if (upload.if !== 'always()' || upload.uses !== contract.actions.upload_artifact ||
      upload.with?.name !== contract.evidence.artifact_name ||
      upload.with?.path !== '${{ runner.temp }}/bonvoyage-config-windows-evidence' ||
      upload.with?.['if-no-files-found'] !== 'error' ||
      upload.with?.['compression-level'] !== 0 || upload.with?.overwrite !== false ||
      upload.with?.['include-hidden-files'] !== false ||
      upload.with?.['retention-days'] !== contract.execution.artifact_retention_days) {
    reject('workflow-upload-invalid');
  }

  for (const forbidden of [
    /\bpush\s*:/u, /\bpull_request\s*:/u, /\bschedule\s*:/u, /self-hosted/u,
    /\$\{\{\s*secrets\./u, /permissions:\s*write/u, /git\s+push/u,
    /npm\s+publish/u, /gh\s+release/u, /Invoke-WebRequest/u, /curl(?:\.exe)?\s/u,
  ]) {
    if (forbidden.test(workflowSource)) reject('workflow-forbidden-authority');
  }
}

function verifyHostedContext(contract, environment, repositoryRoot) {
  if (environment.GITHUB_ACTIONS !== 'true' || environment.GITHUB_EVENT_NAME !== 'workflow_dispatch' ||
      environment.GITHUB_REPOSITORY !== 'routesphere-global/bonvoyage' ||
      environment.GITHUB_REF_TYPE !== 'tag' ||
      !new RegExp(contract.source.tag_pattern, 'u').test(environment.GITHUB_REF_NAME ?? '') ||
      !COMMIT_PATTERN.test(environment.GITHUB_SHA ?? '') ||
      !RUN_ID_PATTERN.test(environment.GITHUB_RUN_ID ?? '') ||
      !RUN_ID_PATTERN.test(environment.GITHUB_RUN_ATTEMPT ?? '')) {
    reject('hosted-context-invalid');
  }
  const head = spawnSync('git', ['rev-parse', 'HEAD'], {
    cwd: repositoryRoot, encoding: 'utf8', windowsHide: true,
  });
  const status = spawnSync('git', ['status', '--porcelain', '--untracked-files=no'], {
    cwd: repositoryRoot, encoding: 'utf8', windowsHide: true,
  });
  const tag = spawnSync('git', ['rev-parse', `refs/tags/${environment.GITHUB_REF_NAME}^{commit}`], {
    cwd: repositoryRoot, encoding: 'utf8', windowsHide: true,
  });
  if (head.status !== 0 || status.status !== 0 || tag.status !== 0 ||
      head.stdout.trim() !== environment.GITHUB_SHA ||
      tag.stdout.trim() !== environment.GITHUB_SHA || status.stdout !== '') {
    reject('hosted-source-invalid');
  }
}

export function verifyWindowsAcceptanceContract(contractPath, workflowPath, options = {}) {
  const repositoryRoot = path.resolve(options.repositoryRoot ?? REPOSITORY_ROOT);
  requireRegularFile(contractPath, 'contract-unreadable');
  const contract = readBoundedJson(contractPath, 'contract-unreadable');
  validateContractShape(contract);
  const expectedTemplate = resolveWithin(repositoryRoot, contract.activation.template_path,
    'contract-activation-invalid');
  if (path.resolve(workflowPath) !== expectedTemplate) reject('workflow-path-invalid');
  requireRegularFile(workflowPath, 'workflow-unreadable');
  let workflowSource;
  try {
    workflowSource = fs.readFileSync(workflowPath, 'utf8');
  } catch {
    reject('workflow-unreadable');
  }
  validateWorkflow(contract, workflowSource);

  const activeWorkflow = resolveWithin(repositoryRoot, contract.activation.active_workflow_path,
    'contract-activation-invalid');
  const activeExists = fs.existsSync(activeWorkflow);
  if (options.requireActivatable === true) {
    if (activeExists) requireRegularFile(activeWorkflow, 'contract-not-activatable');
    if (contract.activation.state !== 'ready-for-manual-execution' ||
        contract.activation.public_repository_created !== true ||
        contract.activation.repository_settings_verified !== true || !activeExists ||
        sha256(fs.readFileSync(activeWorkflow)) !== sha256(Buffer.from(workflowSource, 'utf8'))) {
      reject('contract-not-activatable');
    }
    verifyHostedContext(contract, options.environment ?? process.env, repositoryRoot);
  } else if (contract.activation.state !== 'blocked-pending-public-repository' ||
      contract.activation.public_repository_created !== false ||
      contract.activation.repository_settings_verified !== false || activeExists) {
    reject('blocked-contract-activation-drift');
  }
  return {contract, workflow_sha256: sha256(Buffer.from(workflowSource, 'utf8'))};
}

function parseCommandResult(contract, schemaValidator, execution, mode) {
  if (execution.error || execution.signal !== null || execution.status !== 2) {
    reject('command-process-invalid');
  }
  const stdout = execution.stdout ?? Buffer.alloc(0);
  const stderr = execution.stderr ?? Buffer.alloc(0);
  if (stderr.length !== 0 || stdout.length === 0 || stdout.length > MAX_JSON_BYTES ||
      stdout.includes(Buffer.from(contract.fixture.marker, 'utf8'))) {
    reject('command-output-invalid');
  }
  let result;
  try {
    result = JSON.parse(stdout.toString('utf8'));
  } catch {
    reject('command-output-invalid');
  }
  if (!schemaValidator(result)) reject('command-result-schema-invalid');
  if (result.inputs.length !== 1 || result.diagnostics.length !== 1) {
    reject('command-result-invalid');
  }
  const projection = normalizedProjection(result);
  const projectionSHA256 = sha256(Buffer.from(JSON.stringify(projection), 'utf8'));
  if (JSON.stringify(projection) !== JSON.stringify(expectedProjection(contract)) ||
      projectionSHA256 !== contract.expected_result.normalized_projection_sha256) {
    reject('command-result-invalid');
  }
  return {
    mode,
    exit_code: result.exit_code,
    status: result.status,
    failure_kind: result.failure_kind,
    diagnostic_code: result.diagnostics[0].code,
    observed_bytes: result.inputs[0].bytes,
    observed_sha256: result.inputs[0].sha256,
    projection_sha256: projectionSHA256,
    stdout_bytes: stdout.length,
    stderr_bytes: stderr.length,
  };
}

function inspectWindowsAMD64Binary(binaryPath) {
  let bytes;
  try {
    bytes = fs.readFileSync(binaryPath);
  } catch {
    reject('binary-unreadable');
  }
  if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) {
    reject('binary-format-invalid');
  }
  const peOffset = bytes.readUInt32LE(0x3c);
  if (peOffset + 6 > bytes.length || bytes.subarray(peOffset, peOffset + 4).toString('binary') !==
      'PE\u0000\u0000' || bytes.readUInt16LE(peOffset + 4) !== 0x8664) {
    reject('binary-format-invalid');
  }
  return {bytes: bytes.length, sha256: sha256(bytes)};
}

function prepareOutputDirectory(outputPath) {
  if (fs.existsSync(outputPath)) {
    const stat = fs.lstatSync(outputPath);
    if (!stat.isDirectory() || stat.isSymbolicLink() || fs.readdirSync(outputPath).length !== 0) {
      reject('output-directory-refused');
    }
  } else {
    fs.mkdirSync(outputPath, {recursive: true, mode: 0o700});
  }
}

function writeEvidence(outputPath, fileName, value) {
  const rendered = `${JSON.stringify(value, null, 2)}\n`;
  const destination = path.join(outputPath, fileName);
  const temporary = `${destination}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, rendered, {encoding: 'utf8', mode: 0o600, flag: 'wx'});
  fs.renameSync(temporary, destination);
  return Buffer.from(rendered, 'utf8');
}

function goVersion(contract, repositoryRoot) {
  const observed = spawnSync('go', ['version'], {
    cwd: repositoryRoot, encoding: 'utf8', windowsHide: true,
  });
  const match = /^go version (go[^ ]+) windows\/amd64\r?\n$/u.exec(observed.stdout ?? '');
  if (observed.status !== 0 || observed.stderr !== '' || !match ||
      match[1] !== `go${contract.toolchain.go_version}`) reject('go-toolchain-invalid');
  return match[1];
}

export function validateCommandResultForTest(contract, result, mode = 'file') {
  const schemaPath = path.join(REPOSITORY_ROOT,
    ...'config/schemas/bonvoyage-authoring-result-v1.schema.json'.split('/'));
  const schema = readBoundedJson(schemaPath, 'result-schema-unreadable');
  const validate = new Ajv2020({allErrors: true, strict: true}).compile(schema);
  const execution = {
    error: null,
    signal: null,
    status: 2,
    stdout: Buffer.from(`${JSON.stringify(result)}\n`, 'utf8'),
    stderr: Buffer.alloc(0),
  };
  return parseCommandResult(contract, validate, execution, mode);
}

function runWindowsAcceptance(contract, binaryPath, outputPath, repositoryRoot, environment) {
  if (process.platform !== 'win32' || process.arch !== 'x64' ||
      environment.RUNNER_OS !== 'Windows' || environment.RUNNER_ARCH !== 'X64' ||
      process.version !== `v${contract.toolchain.node_version}`) {
    reject('windows-platform-invalid');
  }
  prepareOutputDirectory(outputPath);
  const binary = inspectWindowsAMD64Binary(binaryPath);
  const fixture = createLargeInputFixture(contract);
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-windows-large-input-'));
  const fixturePath = path.join(temporaryRoot, contract.fixture.filename);
  const resultSchema = readBoundedJson(resolveWithin(repositoryRoot,
    'config/schemas/bonvoyage-authoring-result-v1.schema.json', 'result-schema-unreadable'),
  'result-schema-unreadable');
  const evidenceSchema = readBoundedJson(resolveWithin(repositoryRoot,
    contract.evidence.schema_path, 'evidence-schema-unreadable'), 'evidence-schema-unreadable');
  const ajv = new Ajv2020({allErrors: true, strict: true});
  const validateResult = ajv.compile(resultSchema);
  const validateEvidence = ajv.compile(evidenceSchema);
  const timeout = contract.execution.command_timeout_seconds * 1000;
  let executions;
  try {
    fs.writeFileSync(fixturePath, fixture, {flag: 'wx'});
    executions = [
      parseCommandResult(contract, validateResult, spawnSync(binaryPath, [
        'validate', '--input', fixturePath,
      ], {encoding: null, maxBuffer: MAX_JSON_BYTES, timeout, windowsHide: true}), 'file'),
      parseCommandResult(contract, validateResult, spawnSync(binaryPath, [
        'validate', '--stdin', '--source-id', contract.fixture.filename,
      ], {input: fixture, encoding: null, maxBuffer: MAX_JSON_BYTES, timeout, windowsHide: true}),
      'stdin'),
    ];
  } finally {
    fs.rmSync(temporaryRoot, {recursive: true, force: true});
  }
  if (executions[0].projection_sha256 !== executions[1].projection_sha256) {
    reject('command-mode-disagreement');
  }

  const evidence = {
    $schema: 'https://schemas.routesphere.global/bonvoyage/windows-large-input-evidence-v1.schema.json',
    schema_version: 1,
    classification: 'routesphere-bonvoyage-windows-config-large-input-evidence',
    gate_version: contract.gate_version,
    accepted: true,
    source: {
      repository: environment.GITHUB_REPOSITORY,
      commit: environment.GITHUB_SHA,
      tag: environment.GITHUB_REF_NAME,
      run_id: environment.GITHUB_RUN_ID,
      run_attempt: Number.parseInt(environment.GITHUB_RUN_ATTEMPT, 10),
    },
    platform: {
      os: 'windows',
      architecture: 'amd64',
      runner: contract.execution.runner,
      go_version: goVersion(contract, repositoryRoot),
      node_version: process.version,
    },
    binary,
    fixture: {
      bytes: fixture.length,
      observed_bytes: contract.fixture.observed_bytes,
      sha256: sha256(fixture),
      observed_sha256: sha256(fixture.subarray(0, contract.fixture.observed_bytes)),
      retained: false,
    },
    executions,
    agreement_sha256: executions[0].projection_sha256,
    authority: {...contract.authority},
  };
  if (!validateEvidence(evidence)) reject('evidence-schema-invalid');
  const evidenceBytes = writeEvidence(outputPath, 'acceptance.json', evidence);
  fs.writeFileSync(path.join(outputPath, 'checksums.sha256'),
    `${sha256(evidenceBytes)}  acceptance.json\n`, {encoding: 'utf8', mode: 0o600, flag: 'wx'});
  return evidence;
}

function parseArguments(argv) {
  const command = argv[0];
  if (!['verify-contract', 'run'].includes(command)) reject('invalid-invocation');
  const options = {};
  for (let index = 1; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--require-activatable') {
      if (options.requireActivatable) reject('invalid-invocation');
      options.requireActivatable = true;
      continue;
    }
    if (!['--contract', '--workflow', '--repository-root', '--binary', '--output']
      .includes(argument) || index + 1 >= argv.length) reject('invalid-invocation');
    const name = argument.slice(2).replace(/-([a-z])/gu, (_, letter) => letter.toUpperCase());
    if (Object.hasOwn(options, name)) reject('invalid-invocation');
    options[name] = argv[index + 1];
    index += 1;
  }
  for (const required of ['contract', 'workflow', 'repositoryRoot']) {
    if (!options[required]) reject('invalid-invocation');
  }
  if (command === 'run' && (!options.binary || !options.output)) reject('invalid-invocation');
  if (command === 'verify-contract' && (options.binary || options.output)) reject('invalid-invocation');
  return {command, options};
}

function failureOutputPath(argv) {
  const index = argv.indexOf('--output');
  if (index < 0 || index + 1 >= argv.length) return null;
  return path.resolve(argv[index + 1]);
}

function writeFailureReceipt(outputPath, error) {
  if (!outputPath) return;
  try {
    prepareOutputDirectory(outputPath);
    const receipt = {
      schema_version: 1,
      classification: 'routesphere-bonvoyage-windows-config-large-input-failure',
      accepted: false,
      reason: error instanceof AcceptanceError ? error.code : 'internal-failure',
      authority: {
        release_admitted: false,
        publishable: false,
        live_configuration_applied: false,
      },
    };
    const bytes = writeEvidence(outputPath, 'failure.json', receipt);
    fs.writeFileSync(path.join(outputPath, 'checksums.sha256'),
      `${sha256(bytes)}  failure.json\n`, {encoding: 'utf8', mode: 0o600, flag: 'wx'});
  } catch {
    // Preserve the original bounded failure code; never overwrite an existing output tree.
  }
}

async function main() {
  let outputPath = failureOutputPath(process.argv.slice(2));
  try {
    const {command, options} = parseArguments(process.argv.slice(2));
    const repositoryRoot = path.resolve(options.repositoryRoot);
    const contractPath = path.resolve(options.contract);
    const workflowPath = path.resolve(options.workflow);
    const verified = verifyWindowsAcceptanceContract(contractPath, workflowPath, {
      repositoryRoot,
      requireActivatable: options.requireActivatable === true,
      environment: process.env,
    });
    if (command === 'verify-contract') {
      process.stdout.write(`${JSON.stringify({
        status: 'ready',
        activation: verified.contract.activation.state,
        workflow_sha256: verified.workflow_sha256,
      })}\n`);
      return;
    }
    outputPath = path.resolve(options.output);
    const evidence = runWindowsAcceptance(
      verified.contract,
      path.resolve(options.binary),
      outputPath,
      repositoryRoot,
      process.env,
    );
    process.stdout.write(`${JSON.stringify({
      status: 'accepted',
      gate_version: evidence.gate_version,
      agreement_sha256: evidence.agreement_sha256,
    })}\n`);
  } catch (error) {
    writeFailureReceipt(outputPath, error);
    const code = error instanceof AcceptanceError ? error.code : 'internal-failure';
    process.stderr.write(`Windows large-input acceptance failed: ${code}\n`);
    process.exitCode = 1;
  }
}

if (path.resolve(process.argv[1] ?? '') === SCRIPT_PATH) await main();
