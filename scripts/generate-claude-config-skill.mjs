import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

import {
  assertEvaluationManifest,
  assertSharedContract,
  listPackageFiles,
  renderCommandSurface,
  renderSkillBody,
} from './generate-openai-codex-config-skill.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
export const ROOT = path.resolve(path.dirname(SCRIPT_PATH), '..');
export const POLICY_PATH =
  'config/authoring/skills/v1/wrappers/claude-policy.json';
export const CONTRACT_PATH = 'config/authoring/skills/v1/contract.json';
export const EVALUATION_PATH =
  'config/authoring/skills/v1/evaluations/manifest.json';
export const INSTALLATION_CHECK_SOURCE_PATH =
  'config/authoring/skills/v1/wrappers/claude-check-installation.mjs';
export const OUTPUT_MANIFEST_PATH =
  'config/authoring/skills/v1/wrappers/claude.json';
export const WRAPPER_SCHEMA_PATH =
  'config/schemas/bonvoyage-authoring-claude-wrapper-v1.schema.json';

const EXPECTED_CAPABILITIES = Object.freeze([
  'diagnose',
  'explain',
  'generate',
  'migrate',
  'modify',
  'verify',
]);
const EXPECTED_WORKFLOW = Object.freeze([
  'requirements',
  'release-binding',
  'draft',
  'authoritative-check',
  'present',
]);
const EXPECTED_CATEGORIES = Object.freeze([
  'ambiguous-requirements',
  'invalid-yaml',
  'malicious-embedded-instructions',
  'rollback-guidance',
  'secret-handling',
  'semantic-conflict',
  'stale-version',
  'valid-request',
]);
const PACKAGE_ROLES = Object.freeze({
  'SKILL.md': 'entrypoint',
  'scripts/check-installation.mjs': 'installation-check',
  'references/command-surface.md': 'command-reference',
});
const UNSAFE_TEXT = [
  /-----BEGIN [A-Z0-9 ]+-----/u,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u,
  /\b[0-9]{12}\b/u,
  /\$\{|\{\{|<%|%>|process\.env/u,
  /(?:^|[\s'"(])\/(?:Users|home)\/[^\s'"),]+/u,
  /\b[A-Za-z]:\\Users\\[^\s'"),]+/u,
];

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function assertExactKeys(value, expected, context) {
  assert.equal(value !== null && typeof value === 'object' && !Array.isArray(value), true,
    `${context} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(),
    `${context} has an unexpected shape`);
}

function assertRepositoryPath(relativePath, context) {
  assert.equal(typeof relativePath, 'string', `${context} must be a string`);
  assert.ok(relativePath.length > 0, `${context} must not be empty`);
  assert.equal(relativePath.includes('\\'), false, `${context} must use POSIX separators`);
  assert.equal(path.posix.isAbsolute(relativePath), false, `${context} must be relative`);
  assert.equal(path.posix.normalize(relativePath), relativePath,
    `${context} must be normalized`);
  assert.equal(relativePath === '..' || relativePath.startsWith('../') ||
    relativePath.includes('/../'), false, `${context} escapes the repository`);
}

function resolveRepositoryFile(root, relativePath, context) {
  assertRepositoryPath(relativePath, context);
  const repositoryRoot = path.resolve(root);
  const absolutePath = path.resolve(root, ...relativePath.split('/'));
  assert.equal(absolutePath.startsWith(`${repositoryRoot}${path.sep}`), true,
    `${context} escapes the repository`);
  const information = fs.lstatSync(absolutePath);
  assert.equal(information.isSymbolicLink(), false, `${context} is a symlink`);
  assert.equal(information.isFile(), true, `${context} is not a regular file`);
  return absolutePath;
}

function readBoundFile(root, relativePath, context) {
  return fs.readFileSync(resolveRepositoryFile(root, relativePath, context));
}

function readBoundJson(root, relativePath, context) {
  const bytes = readBoundFile(root, relativePath, context);
  try {
    return {bytes, document: JSON.parse(bytes.toString('utf8'))};
  } catch (error) {
    throw new Error(`${context} is not valid JSON: ${error.message}`);
  }
}

function assertSafeText(value, context, minimum = 1, maximum = 512) {
  assert.equal(typeof value, 'string', `${context} must be a string`);
  assert.ok(value.length >= minimum && value.length <= maximum,
    `${context} must contain ${minimum} to ${maximum} characters`);
  assert.equal(/[\r\n]/u.test(value), false, `${context} must be one line`);
  assert.equal(/<\/?[A-Za-z][^>]*>/u.test(value), false,
    `${context} must not contain XML tags`);
  for (const pattern of UNSAFE_TEXT) {
    assert.equal(pattern.test(value), false,
      `${context} contains private, secret-shaped or dynamic material`);
  }
}

function assertPolicy(policy) {
  assertExactKeys(policy, [
    'schema_version',
    'classification',
    'wrapper_version',
    'assistant',
    'package_path',
    'skill_name',
    'description',
    'interface',
    'command',
    'reference_sources',
  ], 'Claude wrapper policy');
  assert.equal(policy.schema_version, 1, 'unsupported wrapper-policy schema');
  assert.equal(policy.classification,
    'routesphere-bonvoyage-reviewed-claude-code-wrapper-policy',
    'unexpected wrapper-policy classification');
  assert.equal(policy.wrapper_version, 'bonvoyage.claude-code-skill.v1',
    'unexpected wrapper version');
  assert.equal(policy.assistant, 'claude', 'unexpected assistant identity');
  assert.equal(policy.package_path, 'skills/claude/bonvoyage-config-authoring',
    'unexpected package path');
  assert.equal(policy.skill_name, 'bonvoyage-config-authoring',
    'unexpected skill name');
  assert.match(policy.skill_name, /^[a-z0-9]+(?:-[a-z0-9]+)*$/u,
    'skill name is not portable Agent Skills metadata');
  assert.ok(policy.skill_name.length <= 64, 'skill name exceeds Agent Skills limit');
  assertSafeText(policy.description, 'skill description', 40, 1024);

  assertExactKeys(policy.interface, [
    'surface',
    'command_name',
    'automatic_invocation',
    'user_invocable',
    'portable_frontmatter',
    'personal_install_path',
    'project_install_path',
  ], 'Claude interface policy');
  assert.deepEqual(policy.interface, {
    surface: 'claude-code',
    command_name: '/bonvoyage-config-authoring',
    automatic_invocation: true,
    user_invocable: true,
    portable_frontmatter: ['name', 'description'],
    personal_install_path: '~/.claude/skills/bonvoyage-config-authoring',
    project_install_path: '.claude/skills/bonvoyage-config-authoring',
  }, 'Claude interface must remain portable and filesystem-local');

  assert.deepEqual(policy.command, {
    executable: 'bonvoyage-config',
    automatic_install: false,
    network_lookup: false,
    unwritten_document_transport: 'stdin',
    machine_output: 'json',
    missing_command: 'block',
    malformed_output: 'block',
  }, 'command policy must remain local and fail closed');

  assert.equal(Array.isArray(policy.reference_sources), true,
    'reference sources must be an array');
  assert.equal(policy.reference_sources.length, 10,
    'reference-source inventory is incomplete');
  const ids = [];
  const targets = [];
  for (const reference of policy.reference_sources) {
    assertExactKeys(reference, ['id', 'source', 'target', 'purpose'],
      'reference source');
    assert.match(reference.id, /^[a-z0-9]+(?:-[a-z0-9]+)*$/u,
      'reference id is invalid');
    assertRepositoryPath(reference.source, `reference ${reference.id} source`);
    assertRepositoryPath(reference.target, `reference ${reference.id} target`);
    assert.equal(reference.target.startsWith('references/'), true,
      `reference ${reference.id} target must remain under references/`);
    assert.equal(reference.target.endsWith('.json'), true,
      `reference ${reference.id} target must be JSON`);
    assertSafeText(reference.purpose, `reference ${reference.id} purpose`, 20, 240);
    ids.push(reference.id);
    targets.push(reference.target);
  }
  assert.deepEqual(ids, [...ids].sort(), 'reference sources must be ordered by id');
  assert.equal(new Set(ids).size, ids.length, 'reference ids must be unique');
  assert.equal(new Set(targets).size, targets.length, 'reference targets must be unique');
}

function renderSkill(policy, contract) {
  return `---
name: ${policy.skill_name}
description: ${JSON.stringify(policy.description)}
---

${renderSkillBody(contract)}`;
}

function packageRole(relativePath) {
  return PACKAGE_ROLES[relativePath] ??
    (relativePath.startsWith('references/') && relativePath.endsWith('.json')
      ? 'release-reference'
      : null);
}

export function loadClaudeWrapperInputs(root = ROOT) {
  const policySource = readBoundJson(root, POLICY_PATH, 'reviewed Claude wrapper policy');
  const contractSource = readBoundJson(root, CONTRACT_PATH, 'shared skill contract');
  const evaluationSource = readBoundJson(root, EVALUATION_PATH,
    'shared evaluation manifest');
  const installationCheck = readBoundFile(root, INSTALLATION_CHECK_SOURCE_PATH,
    'reviewed Claude installation check');
  assertPolicy(policySource.document);
  assertSharedContract(contractSource.document);
  assert.equal(contractSource.document.supported_assistants.includes('claude'), true,
    'shared contract does not support Claude');
  assertEvaluationManifest(evaluationSource.document, contractSource.bytes);
  assert.equal(evaluationSource.document.supported_assistants.includes('claude'), true,
    'evaluation manifest does not support Claude');

  const references = new Map();
  for (const reference of policySource.document.reference_sources) {
    const bytes = readBoundFile(root, reference.source, `reference ${reference.id}`);
    JSON.parse(bytes.toString('utf8'));
    references.set(reference.target, bytes);
  }

  return {
    policy: policySource.document,
    policyBytes: policySource.bytes,
    contract: contractSource.document,
    contractBytes: contractSource.bytes,
    evaluation: evaluationSource.document,
    evaluationBytes: evaluationSource.bytes,
    installationCheck,
    references,
  };
}

export function buildClaudeSkill(inputs) {
  const files = new Map([
    ['SKILL.md', Buffer.from(renderSkill(inputs.policy, inputs.contract), 'utf8')],
    ['scripts/check-installation.mjs', inputs.installationCheck],
    ['references/command-surface.md',
      Buffer.from(renderCommandSurface(inputs.contract), 'utf8')],
    ...inputs.references,
  ]);
  const fileRecords = [...files.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([relativePath, bytes]) => {
      const role = packageRole(relativePath);
      assert.notEqual(role, null, `unclassified package file: ${relativePath}`);
      return {path: relativePath, role, bytes: bytes.length, sha256: sha256(bytes)};
    });

  const manifest = {
    $schema: '../../../../schemas/bonvoyage-authoring-claude-wrapper-v1.schema.json',
    schema_version: 1,
    classification: 'routesphere-bonvoyage-claude-code-skill-wrapper',
    wrapper_version: inputs.policy.wrapper_version,
    assistant: inputs.policy.assistant,
    skill_name: inputs.policy.skill_name,
    release_binding: {
      product_version: inputs.contract.product_version,
      skill_version: inputs.contract.skill_version,
      contract_version: inputs.contract.contract_version,
      compiler_version: inputs.contract.compiler_version,
      configuration_schema_versions:
        structuredClone(inputs.contract.configuration_schema_versions),
    },
    sources: {
      shared_contract: {
        path: CONTRACT_PATH,
        bytes: inputs.contractBytes.length,
        sha256: sha256(inputs.contractBytes),
      },
      evaluation_manifest: {
        path: EVALUATION_PATH,
        bytes: inputs.evaluationBytes.length,
        sha256: sha256(inputs.evaluationBytes),
      },
      reviewed_wrapper_policy: {
        path: POLICY_PATH,
        bytes: inputs.policyBytes.length,
        sha256: sha256(inputs.policyBytes),
      },
      installation_check: {
        path: INSTALLATION_CHECK_SOURCE_PATH,
        bytes: inputs.installationCheck.length,
        sha256: sha256(inputs.installationCheck),
      },
    },
    package: {
      path: inputs.policy.package_path,
      entrypoint: 'SKILL.md',
      installation_check: 'scripts/check-installation.mjs',
      files: fileRecords,
    },
    command: structuredClone(inputs.policy.command),
    interface: structuredClone(inputs.policy.interface),
    capability_ids: inputs.contract.capabilities.map(({id}) => id),
    workflow_stages: structuredClone(inputs.contract.workflow_stages),
    security_boundary: structuredClone(inputs.contract.security_boundary),
    operator_authorization: structuredClone(inputs.contract.operator_authorization),
    claim_boundary: structuredClone(inputs.contract.claim_boundary),
    evaluation_categories: structuredClone(inputs.contract.evaluation_categories),
  };
  assert.deepEqual(manifest.capability_ids, EXPECTED_CAPABILITIES);
  assert.deepEqual(manifest.workflow_stages, EXPECTED_WORKFLOW);
  assert.deepEqual(manifest.evaluation_categories, EXPECTED_CATEGORIES);
  return {files, manifest};
}

export function generateClaudeSkill(root = ROOT) {
  return buildClaudeSkill(loadClaudeWrapperInputs(root));
}

export function renderWrapperManifest(manifest) {
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

export function writeClaudeSkill(root = ROOT) {
  const generated = generateClaudeSkill(root);
  const packageRoot = path.join(root, ...generated.manifest.package.path.split('/'));
  const expected = [...generated.files.keys()].sort();
  const existing = listPackageFiles(packageRoot);
  const unexpected = existing.filter((entry) => !generated.files.has(entry));
  assert.deepEqual(unexpected, [],
    'Claude skill package contains unexpected files; review and remove them explicitly');
  for (const [relativePath, bytes] of generated.files) {
    const output = path.join(packageRoot, ...relativePath.split('/'));
    fs.mkdirSync(path.dirname(output), {recursive: true});
    fs.writeFileSync(output, bytes, {mode: 0o644});
  }
  assert.deepEqual(listPackageFiles(packageRoot), expected,
    'written Claude skill package inventory is incomplete');
  const manifestPath = path.join(root, ...OUTPUT_MANIFEST_PATH.split('/'));
  fs.writeFileSync(manifestPath, renderWrapperManifest(generated.manifest),
    {encoding: 'utf8', mode: 0o644});
}

export function checkClaudeSkill(root = ROOT) {
  const generated = generateClaudeSkill(root);
  const packageRoot = path.join(root, ...generated.manifest.package.path.split('/'));
  assert.deepEqual(listPackageFiles(packageRoot), [...generated.files.keys()].sort(),
    'Claude skill package inventory is stale');
  for (const [relativePath, bytes] of generated.files) {
    assert.deepEqual(fs.readFileSync(path.join(packageRoot, ...relativePath.split('/'))), bytes,
      `Claude skill package file is stale: ${relativePath}`);
  }
  const manifestPath = path.join(root, ...OUTPUT_MANIFEST_PATH.split('/'));
  assert.equal(fs.readFileSync(manifestPath, 'utf8'),
    renderWrapperManifest(generated.manifest),
    `${OUTPUT_MANIFEST_PATH} is stale`);
}

function main(args) {
  assert.equal(args.length, 1,
    'usage: generate-claude-config-skill.mjs --check|--write');
  assert.equal(args[0] === '--check' || args[0] === '--write', true,
    'usage: generate-claude-config-skill.mjs --check|--write');
  if (args[0] === '--write') writeClaudeSkill();
  else checkClaudeSkill();
}

if (process.argv[1] && path.resolve(process.argv[1]) === SCRIPT_PATH) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
