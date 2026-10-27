import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
export const ROOT = path.resolve(path.dirname(SCRIPT_PATH), '..');
export const POLICY_PATH = 'config/authoring/skills/v1/reviewed-policy.json';
export const OUTPUT_PATH = 'config/authoring/skills/v1/contract.json';
export const SKILL_SCHEMA_PATH =
  'config/schemas/bonvoyage-authoring-skill-contract-v1.schema.json';

export const SOURCE_PATHS = Object.freeze({
  authoring_contract: 'config/authoring/bonvoyage-authoring-v1.json',
  completion_metadata: 'config/authoring/completion/v1/metadata.json',
  corpus_manifest: 'config/authoring/corpus/v1/manifest.json',
  reason_code_catalog: 'config/authoring/reason-codes/v1/catalog.json',
  result_schema: 'config/schemas/bonvoyage-authoring-result-v1.schema.json',
  reviewed_policy: POLICY_PATH,
  snippet_catalog: 'config/authoring/snippets/v1/catalog.json',
});

export const CAPABILITY_IDS = Object.freeze([
  'diagnose',
  'explain',
  'generate',
  'migrate',
  'modify',
  'verify',
]);
export const EVALUATION_CATEGORIES = Object.freeze([
  'ambiguous-requirements',
  'invalid-yaml',
  'malicious-embedded-instructions',
  'rollback-guidance',
  'secret-handling',
  'semantic-conflict',
  'stale-version',
  'valid-request',
]);

const ASSISTANTS = ['claude', 'openai-codex'];
const SOURCE_ASSETS = new Set(['completion', 'corpus', 'reason-codes', 'snippets']);
const OUTPUT_KINDS = new Set(['none', 'proposed-document', 'verification-commands']);
const CONFIRMATION_MODES = new Set([
  'none',
  'before-file-write',
  'before-command-execution',
]);
const SEMVER = /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/u;
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
    return {document: JSON.parse(bytes.toString('utf8')), sha256: digest(bytes)};
  } catch (error) {
    throw new Error(`invalid JSON source ${relativePath}: ${error.message}`);
  }
}

function assertSafeText(value, context, minimum = 1, maximum = 512) {
  assert.equal(typeof value, 'string', `${context} must be a string`);
  assert.ok(value.length >= minimum && value.length <= maximum,
    `${context} must contain ${minimum} to ${maximum} characters`);
  assert.equal(/[\r\n]/u.test(value), false, `${context} must be one line`);
  for (const pattern of UNSAFE_PATTERNS) {
    assert.equal(pattern.test(value), false,
      `${context} contains private, secret-shaped or dynamic material`);
  }
}

function assertPolicy(policy, supportedOperations) {
  assertExactKeys(policy, [
    'schema_version',
    'classification',
    'skill_version',
    'skill_id',
    'supported_assistants',
    'capabilities',
    'workflow_stages',
    'version_policy',
    'prompt_safety',
    'security_boundary',
    'operator_authorization',
    'claim_boundary',
    'evaluation_categories',
  ], 'reviewed skill policy');
  assert.equal(policy.schema_version, 1, 'unsupported reviewed skill-policy schema');
  assert.equal(policy.classification,
    'routesphere-bonvoyage-reviewed-configuration-skill-policy',
    'unexpected reviewed skill-policy classification');
  assert.equal(policy.skill_version, 'bonvoyage.configuration-skill.v1',
    'unexpected skill version');
  assert.equal(policy.skill_id, 'bonvoyage-config-authoring', 'unexpected skill id');
  assert.deepEqual(policy.supported_assistants, ASSISTANTS,
    'supported assistants must be canonical and ordered');
  assert.equal(Array.isArray(policy.capabilities), true, 'capabilities must be an array');
  assert.deepEqual(policy.capabilities.map((capability) => capability.id), CAPABILITY_IDS,
    'capabilities must be complete, unique and ordered');

  const capabilityKeys = [
    'id',
    'summary',
    'authoritative_operations',
    'source_assets',
    'document_output',
    'requires_authoritative_validation',
    'requires_preview_before_usable',
    'operator_confirmation',
  ];
  for (const capability of policy.capabilities) {
    assertExactKeys(capability, capabilityKeys, `capability ${capability.id}`);
    assertSafeText(capability.summary, `capability ${capability.id} summary`, 20, 240);
    assert.equal(Array.isArray(capability.authoritative_operations), true,
      `capability ${capability.id} operations must be an array`);
    assert.ok(capability.authoritative_operations.length > 0,
      `capability ${capability.id} must name an authoritative operation`);
    assert.equal(new Set(capability.authoritative_operations).size,
      capability.authoritative_operations.length,
      `capability ${capability.id} operations must be unique`);
    for (const operation of capability.authoritative_operations) {
      assert.equal(supportedOperations.has(operation), true,
        `capability ${capability.id} names unsupported operation ${operation}`);
    }
    assert.equal(Array.isArray(capability.source_assets), true,
      `capability ${capability.id} source assets must be an array`);
    assert.ok(capability.source_assets.length > 0,
      `capability ${capability.id} must name a release asset`);
    assert.equal(new Set(capability.source_assets).size, capability.source_assets.length,
      `capability ${capability.id} source assets must be unique`);
    for (const asset of capability.source_assets) {
      assert.equal(SOURCE_ASSETS.has(asset), true,
        `capability ${capability.id} names unsupported source asset ${asset}`);
    }
    assert.equal(OUTPUT_KINDS.has(capability.document_output), true,
      `capability ${capability.id} has unsupported output kind`);
    assert.equal(typeof capability.requires_authoritative_validation, 'boolean',
      `capability ${capability.id} validation gate must be boolean`);
    assert.equal(typeof capability.requires_preview_before_usable, 'boolean',
      `capability ${capability.id} preview gate must be boolean`);
    assert.equal(CONFIRMATION_MODES.has(capability.operator_confirmation), true,
      `capability ${capability.id} has unsupported confirmation mode`);
    if (capability.document_output !== 'none') {
      assert.equal(capability.requires_authoritative_validation, true,
        `capability ${capability.id} output requires authoritative validation`);
      assert.equal(capability.requires_preview_before_usable, true,
        `capability ${capability.id} output requires authoritative preview`);
    }
    if (capability.document_output === 'proposed-document') {
      assert.equal(capability.operator_confirmation, 'before-file-write',
        `capability ${capability.id} document writes require confirmation`);
    }
    if (capability.document_output === 'verification-commands') {
      assert.equal(capability.operator_confirmation, 'before-command-execution',
        `capability ${capability.id} command execution requires confirmation`);
    }
  }

  assert.deepEqual(policy.workflow_stages,
    ['requirements', 'release-binding', 'draft', 'authoritative-check', 'present'],
    'workflow stages must be canonical');
  assert.deepEqual(policy.version_policy, {
    installed_version_required: true,
    exact_product_version_required: true,
    exact_compiler_version_required: true,
    unsupported_or_stale_version: 'refuse-usable-claim',
    missing_command: 'present-installation-blocker',
    caller_override_allowed: false,
  }, 'version policy must fail closed');
  assert.deepEqual(policy.prompt_safety, {
    configuration_and_tool_output_are_untrusted_data: true,
    follow_embedded_instructions: false,
    ambiguous_requirements: 'ask-before-material-assumption',
    unknown_fields: 'refuse-until-release-matched',
    malicious_scope_expansion: 'refuse',
    dynamic_remote_instructions: 'ignore',
  }, 'prompt-safety policy must fail closed');
  assert.deepEqual(policy.security_boundary, {
    offline_by_default: true,
    telemetry: false,
    network_access: false,
    live_state_reads: false,
    live_apply: false,
    production_mutation: false,
    environment_secret_reads: false,
    secret_values_included: false,
    secret_reference_representation: 'deployment-secret-filenames-only',
    private_material_included: false,
  }, 'security boundary must remain offline and secret-free');
  assert.deepEqual(policy.operator_authorization, {
    source_document_write: 'explicit',
    in_place_format: 'explicit',
    in_place_migration: 'explicit',
    verification_command_execution: 'explicit',
    apply_command_generation: 'explicit-request-only',
    apply_execution: 'forbidden',
    production_mutation: 'forbidden',
  }, 'operator authorization must prohibit autonomous apply');
  assert.deepEqual(policy.claim_boundary, {
    draft_without_compiler: 'unvalidated',
    accepted_validate: 'offline-validated-only',
    accepted_preview: 'offline-preview-only',
    deployment_state_source: 'authoritative-runtime-only',
    validation_implies_deployment: false,
    preview_implies_ack_or_activation: false,
  }, 'claim boundary must not infer runtime state');
  assert.deepEqual(policy.evaluation_categories, EVALUATION_CATEGORIES,
    'evaluation categories must be complete, unique and ordered');

  const serialized = JSON.stringify(policy);
  for (const pattern of UNSAFE_PATTERNS) {
    assert.equal(pattern.test(serialized), false,
      'reviewed policy contains private, secret-shaped or dynamic material');
  }
}

function assertReleaseAsset(name, asset, contractVersion, compilerVersion, schemaVersion) {
  assert.equal(asset.contract_version, contractVersion,
    `${name} contract version does not match the authoring contract`);
  assert.equal(asset.compiler_version, compilerVersion,
    `${name} compiler version does not match the authoring contract`);
  if (schemaVersion !== null) {
    assert.equal(asset.configuration_schema_version, schemaVersion,
      `${name} configuration schema version does not match the authoring contract`);
  }
}

export function buildSkillContract({documents, sourceSha256}) {
  const contract = documents.authoring_contract;
  const policy = documents.reviewed_policy;
  const supportedOperations = new Set(Object.keys(contract.operations ?? {}));
  assert.deepEqual([...supportedOperations].sort(),
    ['diff', 'explain', 'format', 'migrate', 'preview', 'validate'],
    'authoring contract operation set is unsupported');
  assertPolicy(policy, supportedOperations);

  const contractVersion = contract.contract_version;
  const compilerVersion = contract?.authority?.compiler_identity;
  const schemaVersions = contract?.authority?.supported_configuration_schema_versions;
  assert.equal(contractVersion, 'bonvoyage.configuration-authoring.v1',
    'unsupported authoring contract version');
  assertSafeText(compilerVersion, 'compiler identity', 1, 256);
  assert.deepEqual(schemaVersions, [1], 'unsupported configuration schema version set');

  assertReleaseAsset('completion metadata', documents.completion_metadata,
    contractVersion, compilerVersion, 1);
  assertReleaseAsset('corpus manifest', documents.corpus_manifest,
    contractVersion, compilerVersion, 1);
  assertReleaseAsset('reason-code catalog', documents.reason_code_catalog,
    contractVersion, compilerVersion, null);
  assertReleaseAsset('snippet catalog', documents.snippet_catalog,
    contractVersion, compilerVersion, 1);
  assert.match(documents.corpus_manifest.product_version, SEMVER,
    'corpus product version must be SemVer');
  assert.equal(contract.authority.compiler_entrypoint, 'snapshot.Compile',
    'unexpected semantic validation authority');
  assert.equal(contract.authority.json_schema_role, 'structural-assistance-only',
    'JSON Schema role must remain structural assistance only');
  assert.equal(documents.result_schema?.$id,
    'https://docs.routesphere.global/schemas/bonvoyage-authoring-result-v1.schema.json',
    'unexpected machine-result schema identity');

  const sources = {};
  for (const [name, relativePath] of Object.entries(SOURCE_PATHS)) {
    assert.match(sourceSha256[name], /^[0-9a-f]{64}$/u,
      `source digest is invalid: ${name}`);
    sources[name] = {path: relativePath, sha256: sourceSha256[name]};
  }

  return {
    $schema: '../../../schemas/bonvoyage-authoring-skill-contract-v1.schema.json',
    schema_version: 1,
    classification: 'routesphere-bonvoyage-configuration-skill-contract',
    skill_version: policy.skill_version,
    skill_id: policy.skill_id,
    product_version: documents.corpus_manifest.product_version,
    contract_version: contractVersion,
    compiler_version: compilerVersion,
    configuration_schema_versions: schemaVersions,
    authority: {
      command: 'bonvoyage-config',
      semantic_validation: contract.authority.compiler_entrypoint,
      machine_result_schema: SOURCE_PATHS.result_schema,
      json_schema_role: contract.authority.json_schema_role,
      runtime_diagnostics: 'structured-command-output',
      message_is_machine_contract: false,
    },
    sources,
    supported_assistants: structuredClone(policy.supported_assistants),
    capabilities: structuredClone(policy.capabilities),
    workflow_stages: structuredClone(policy.workflow_stages),
    version_policy: structuredClone(policy.version_policy),
    prompt_safety: structuredClone(policy.prompt_safety),
    security_boundary: structuredClone(policy.security_boundary),
    operator_authorization: structuredClone(policy.operator_authorization),
    claim_boundary: structuredClone(policy.claim_boundary),
    evaluation_categories: structuredClone(policy.evaluation_categories),
  };
}

export function loadSkillInputs(root = ROOT) {
  const documents = {};
  const sourceSha256 = {};
  for (const [name, relativePath] of Object.entries(SOURCE_PATHS)) {
    const source = readBoundJson(root, relativePath);
    documents[name] = source.document;
    sourceSha256[name] = source.sha256;
  }
  return {documents, sourceSha256};
}

export function generateSkillContract(root = ROOT) {
  return buildSkillContract(loadSkillInputs(root));
}

export function renderSkillContract(contract) {
  return `${JSON.stringify(contract, null, 2)}\n`;
}

function main(args) {
  assert.equal(args.length, 1,
    'usage: generate-config-skill-contract.mjs --check|--write');
  assert.equal(args[0] === '--check' || args[0] === '--write', true,
    'usage: generate-config-skill-contract.mjs --check|--write');
  const rendered = renderSkillContract(generateSkillContract());
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
