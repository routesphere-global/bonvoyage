import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const PACKAGE_ROOT = path.resolve(path.dirname(SCRIPT_PATH), '..');
const CONTRACT_PATH = path.join(PACKAGE_ROOT, 'references', 'contract.json');
const MAX_OUTPUT_BYTES = 256 * 1024;
const TIMEOUT_MS = 5000;

function emit(status, reason, identity = null) {
  const result = {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-openai-codex-installation-check',
    wrapper_version: 'bonvoyage.openai-codex-skill.v1',
    status,
    reason,
    identity,
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

function block(reason) {
  emit('blocked', reason);
  return 2;
}

function readContract() {
  const bytes = fs.readFileSync(CONTRACT_PATH);
  const contract = JSON.parse(bytes.toString('utf8'));
  if (contract.skill_version !== 'bonvoyage.configuration-skill.v1' ||
      contract.product_version !== '0.2.0' ||
      contract.compiler_version !== 'bonvoyage-control-plane-phase4-admin-v1' ||
      JSON.stringify(contract.configuration_schema_versions) !== '[1]') {
    throw new Error('packaged-contract-mismatch');
  }
  return contract;
}

function safeChildEnvironment() {
  const environment = {PATH: process.env.PATH ?? ''};
  if (process.platform === 'win32' && process.env.SystemRoot) {
    environment.SystemRoot = process.env.SystemRoot;
  }
  if (process.platform === 'win32' && process.env.PATHEXT) {
    environment.PATHEXT = process.env.PATHEXT;
  }
  return environment;
}

function parseResult(stdout) {
  if (typeof stdout !== 'string' || Buffer.byteLength(stdout, 'utf8') > MAX_OUTPUT_BYTES) {
    throw new Error('malformed-output');
  }
  const trimmed = stdout.trim();
  if (trimmed.length === 0 || trimmed.includes('\n')) throw new Error('malformed-output');
  const result = JSON.parse(trimmed);
  if (result === null || typeof result !== 'object' || Array.isArray(result)) {
    throw new Error('malformed-output');
  }
  return result;
}

function main(args) {
  if (args.length !== 0) return block('invalid-invocation');

  let contract;
  try {
    contract = readContract();
  } catch {
    return block('packaged-contract-invalid');
  }

  const child = spawnSync('bonvoyage-config', [
    'explain',
    '--path', '',
    '--require-product-version', contract.product_version,
    '--require-compiler-version', contract.compiler_version,
    '--require-configuration-schema-version',
    String(contract.configuration_schema_versions[0]),
  ], {
    encoding: 'utf8',
    env: safeChildEnvironment(),
    maxBuffer: MAX_OUTPUT_BYTES,
    shell: false,
    timeout: TIMEOUT_MS,
    windowsHide: true,
  });

  if (child.error?.code === 'ENOENT') return block('command-missing');
  if (child.error?.code === 'ETIMEDOUT') return block('command-timeout');
  if (child.error?.code === 'ENOBUFS') return block('malformed-output');
  if (child.error) return block('command-failed');

  let result;
  try {
    result = parseResult(child.stdout);
  } catch {
    return block('malformed-output');
  }

  const versions = result.versions;
  const releaseMatches =
    versions !== null && typeof versions === 'object' && !Array.isArray(versions) &&
    versions.product_version === contract.product_version &&
    versions.compiler_version === contract.compiler_version &&
    Array.isArray(versions.supported_configuration_schema_versions) &&
    JSON.stringify(versions.supported_configuration_schema_versions) ===
      JSON.stringify(contract.configuration_schema_versions) &&
    versions.input_configuration_schema_version === contract.configuration_schema_versions[0];
  if (!releaseMatches) return block('release-mismatch');

  if (child.status !== 0 || result.contract_version !== contract.contract_version ||
      result.operation !== 'explain' || result.status !== 'accepted' ||
      result.exit_code !== 0 || result.failure_kind !== 'none' ||
      !Array.isArray(result.diagnostics) || result.diagnostics.length !== 0 ||
      result.diagnostics_truncated !== false ||
      result.result?.kind !== 'field-explanation' || result.result?.path !== '') {
    return block('command-refused');
  }

  emit('ready', 'none', {
    product_version: contract.product_version,
    compiler_version: contract.compiler_version,
    configuration_schema_versions: contract.configuration_schema_versions,
    skill_version: contract.skill_version,
  });
  return 0;
}

process.exitCode = main(process.argv.slice(2));
