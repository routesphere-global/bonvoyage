import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath, pathToFileURL} from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

const SCRIPT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export const DEFAULT_MANIFEST_PATH =
  'config/authoring/skills/v1/evaluations/manifest.json';
export const MANIFEST_SCHEMA_PATH =
  'config/schemas/bonvoyage-authoring-skill-evaluations-v1.schema.json';
export const RESULT_SCHEMA_PATH =
  'config/schemas/bonvoyage-authoring-skill-evaluation-result-v1.schema.json';

function resolveRelative(root, relativePath) {
  return path.join(root, ...relativePath.split('/'));
}

function readJson(root, relativePath) {
  return JSON.parse(fs.readFileSync(resolveRelative(root, relativePath), 'utf8'));
}

export function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function schemaErrors(errors) {
  return (errors ?? []).map((error) => ({
    instance_path: error.instancePath,
    keyword: error.keyword,
    message: error.message,
  }));
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function unique(values) {
  return new Set(values).size === values.length;
}

const DOCUMENT_OPERATIONS = new Set(['diff', 'format', 'migrate', 'preview', 'validate']);

function loadManifest(root, manifestPath) {
  const bytes = fs.readFileSync(resolveRelative(root, manifestPath));
  return {bytes, document: JSON.parse(bytes.toString('utf8'))};
}

export function validateEvaluationManifest(
  root = SCRIPT_ROOT,
  manifestPath = DEFAULT_MANIFEST_PATH,
) {
  const {bytes, document: manifest} = loadManifest(root, manifestPath);
  const schema = readJson(root, MANIFEST_SCHEMA_PATH);
  const validate = new Ajv2020({allErrors: true, strict: true}).compile(schema);
  if (!validate(manifest)) {
    return {
      ok: false,
      manifest,
      manifestSha256: sha256(bytes),
      errors: [{rule: 'manifest-schema', details: schemaErrors(validate.errors)}],
    };
  }

  const errors = [];
  for (const [name, source] of Object.entries(manifest.sources)) {
    const sourcePath = resolveRelative(root, source.path);
    if (!fs.existsSync(sourcePath)) {
      errors.push({rule: 'source-missing', source: name});
      continue;
    }
    const actual = sha256(fs.readFileSync(sourcePath));
    if (actual !== source.sha256) {
      errors.push({rule: 'source-drift', source: name, expected: source.sha256, actual});
    }
  }

  const contract = readJson(root, manifest.sources.skill_contract.path);
  if (contract.skill_version !== manifest.skill_version) {
    errors.push({rule: 'skill-version-mismatch'});
  }
  if (contract.product_version !== manifest.product_version) {
    errors.push({rule: 'product-version-mismatch'});
  }
  if (contract.contract_version !== manifest.contract_version) {
    errors.push({rule: 'contract-version-mismatch'});
  }
  if (contract.compiler_version !== manifest.compiler_version) {
    errors.push({rule: 'compiler-version-mismatch'});
  }
  if (!arraysEqual(contract.supported_assistants, manifest.supported_assistants)) {
    errors.push({rule: 'assistant-inventory-mismatch'});
  }
  if (!arraysEqual(contract.evaluation_categories, manifest.categories)) {
    errors.push({rule: 'category-inventory-mismatch'});
  }

  const caseIds = manifest.cases.map((entry) => entry.id);
  if (!unique(caseIds)) errors.push({rule: 'duplicate-case-id'});

  const contractCapabilities = new Map(
    contract.capabilities.map((capability) => [capability.id, capability]),
  );
  for (const category of manifest.categories) {
    const cases = manifest.cases.filter((entry) => entry.category === category);
    if (cases.length !== 2) {
      errors.push({rule: 'category-case-count', category, expected: 2, actual: cases.length});
    }
    const ids = cases.map((entry) => entry.id);
    if (!arraysEqual(ids, [...ids].sort())) {
      errors.push({rule: 'category-case-order', category});
    }
  }

  for (const entry of manifest.cases) {
    const capability = contractCapabilities.get(entry.expected.capability);
    if (!capability) {
      errors.push({case_id: entry.id, rule: 'unknown-capability'});
      continue;
    }
    for (const operation of entry.expected.authoritative_operations) {
      if (!capability.authoritative_operations.includes(operation)) {
        errors.push({case_id: entry.id, rule: 'operation-outside-capability', operation});
      }
    }
    const observedOperations = entry.input.authoritative_results.map((result) => result.operation);
    if (!arraysEqual(observedOperations, entry.expected.authoritative_operations)) {
      errors.push({case_id: entry.id, rule: 'authoritative-result-inventory'});
    }
    const candidateDocument = entry.input.candidate_document;
    const candidateSha256 = entry.input.candidate_document_sha256;
    const requiresCandidate = entry.expected.document_state === 'offline-previewed' ||
      entry.expected.document_state === 'offline-validated';
    if (requiresCandidate && candidateDocument === undefined) {
      errors.push({case_id: entry.id, rule: 'candidate-document-missing'});
    }
    if (candidateDocument !== undefined) {
      const actualCandidateSha256 = sha256(Buffer.from(candidateDocument, 'utf8'));
      if (actualCandidateSha256 !== candidateSha256) {
        errors.push({
          case_id: entry.id,
          rule: 'candidate-document-hash-mismatch',
          expected: candidateSha256,
          actual: actualCandidateSha256,
        });
      }
    }
    for (const result of entry.input.authoritative_results) {
      if (result.status !== 'accepted' || !DOCUMENT_OPERATIONS.has(result.operation)) continue;
      if (candidateDocument === undefined) {
        if (result.candidate_document_sha256 !== undefined) {
          errors.push({
            case_id: entry.id,
            operation: result.operation,
            rule: 'authoritative-result-candidate-unexpected',
          });
        }
        continue;
      }
      if (result.candidate_document_sha256 !== candidateSha256) {
        errors.push({
          case_id: entry.id,
          operation: result.operation,
          rule: 'authoritative-result-candidate-mismatch',
        });
      }
    }
    const forbidden = new Set(entry.expected.forbidden_concepts);
    if (entry.expected.required_concepts.some((concept) => forbidden.has(concept))) {
      errors.push({case_id: entry.id, rule: 'required-concept-forbidden'});
    }
  }

  return {
    ok: errors.length === 0,
    manifest,
    manifestSha256: sha256(bytes),
    errors,
  };
}

function compareCase(expectedCase, actualCase) {
  const failures = [];
  const expected = expectedCase.expected;
  for (const field of [
    'outcome',
    'capability',
    'document_state',
    'operator_confirmation',
    'apply_command_generated',
  ]) {
    if (actualCase[field] !== expected[field]) {
      failures.push({rule: `expected-${field}`});
    }
  }
  if (!arraysEqual(actualCase.authoritative_operations, expected.authoritative_operations)) {
    failures.push({rule: 'expected-authoritative-operations'});
  }
  const concepts = new Set(actualCase.concepts);
  for (const concept of expected.required_concepts) {
    if (!concepts.has(concept)) failures.push({rule: 'required-concept-missing', concept});
  }
  for (const concept of expected.forbidden_concepts) {
    if (concepts.has(concept)) failures.push({rule: 'forbidden-concept-present', concept});
  }
  return failures.map((failure) => ({case_id: expectedCase.id, ...failure}));
}

export function evaluateSkillResult({
  root = SCRIPT_ROOT,
  manifestPath = DEFAULT_MANIFEST_PATH,
  result,
}) {
  const validatedManifest = validateEvaluationManifest(root, manifestPath);
  if (!validatedManifest.ok) {
    return {
      status: 'failed',
      failure_kind: 'invalid-evaluation-manifest',
      cases_evaluated: 0,
      categories_passed: [],
      failures: validatedManifest.errors,
    };
  }

  const resultSchema = readJson(root, RESULT_SCHEMA_PATH);
  const validateResult = new Ajv2020({allErrors: true, strict: true}).compile(resultSchema);
  if (!validateResult(result)) {
    return {
      status: 'failed',
      failure_kind: 'invalid-evaluation-result',
      cases_evaluated: 0,
      categories_passed: [],
      failures: [{rule: 'result-schema', details: schemaErrors(validateResult.errors)}],
    };
  }

  const manifest = validatedManifest.manifest;
  const failures = [];
  if (result.skill_contract_sha256 !== manifest.sources.skill_contract.sha256) {
    failures.push({rule: 'skill-contract-hash-mismatch'});
  }
  if (result.evaluation_manifest_sha256 !== validatedManifest.manifestSha256) {
    failures.push({rule: 'evaluation-manifest-hash-mismatch'});
  }
  if (!manifest.supported_assistants.includes(result.assistant)) {
    failures.push({rule: 'unsupported-assistant'});
  }

  const resultIds = result.cases.map((entry) => entry.id);
  if (!unique(resultIds)) failures.push({rule: 'duplicate-result-case-id'});
  const resultById = new Map(result.cases.map((entry) => [entry.id, entry]));
  const expectedIds = manifest.cases.map((entry) => entry.id);
  if (!arraysEqual([...resultIds].sort(), [...expectedIds].sort())) {
    failures.push({rule: 'case-inventory-mismatch'});
  }

  const failuresByCategory = new Map(manifest.categories.map((category) => [category, 0]));
  for (const expectedCase of manifest.cases) {
    const actualCase = resultById.get(expectedCase.id);
    if (!actualCase) {
      failuresByCategory.set(expectedCase.category,
        failuresByCategory.get(expectedCase.category) + 1);
      continue;
    }
    const caseFailures = compareCase(expectedCase, actualCase);
    failures.push(...caseFailures);
    if (caseFailures.length > 0) {
      failuresByCategory.set(expectedCase.category,
        failuresByCategory.get(expectedCase.category) + caseFailures.length);
    }
  }

  const hasGlobalFailure = failures.some((failure) => !failure.case_id);
  const categoriesPassed = hasGlobalFailure
    ? []
    : manifest.categories.filter((category) => failuresByCategory.get(category) === 0);
  return {
    classification: 'routesphere-bonvoyage-configuration-skill-evaluation-report',
    evaluation_version: manifest.evaluation_version,
    skill_version: manifest.skill_version,
    assistant: result.assistant,
    wrapper_version: result.wrapper_version,
    model_id: result.model_id,
    status: failures.length === 0 ? 'passed' : 'failed',
    failure_kind: failures.length === 0 ? 'none' : 'expectation-mismatch',
    cases_evaluated: manifest.cases.length,
    categories_passed: categoriesPassed,
    failures,
  };
}

export function buildPassingResult(
  manifest,
  manifestSha256,
  assistant = 'openai-codex',
) {
  return {
    $schema: 'https://docs.routesphere.global/schemas/bonvoyage-authoring-skill-evaluation-result-v1.schema.json',
    schema_version: 1,
    classification: 'routesphere-bonvoyage-configuration-skill-evaluation-result',
    skill_version: manifest.skill_version,
    assistant,
    wrapper_version: `${manifest.skill_version}.${assistant}.evaluation`,
    model_id: 'synthetic-contract-replay',
    skill_contract_sha256: manifest.sources.skill_contract.sha256,
    evaluation_manifest_sha256: manifestSha256,
    cases: manifest.cases.map((entry) => ({
      id: entry.id,
      outcome: entry.expected.outcome,
      capability: entry.expected.capability,
      authoritative_operations: entry.expected.authoritative_operations,
      document_state: entry.expected.document_state,
      operator_confirmation: entry.expected.operator_confirmation,
      apply_command_generated: entry.expected.apply_command_generated,
      apply_executed: false,
      network_accessed: false,
      live_state_read: false,
      production_mutation: false,
      runtime_state_claimed: false,
      embedded_instruction_followed: false,
      secret_value_included: false,
      concepts: entry.expected.required_concepts,
      transcript_sha256: sha256(`transcript:${entry.id}`),
      action_log_sha256: sha256(`actions:${entry.id}`),
    })),
  };
}

function parseArguments(args) {
  const parsed = {manifestPath: DEFAULT_MANIFEST_PATH, resultPath: null};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--manifest' && args[index + 1]) {
      parsed.manifestPath = args[index + 1];
      index += 1;
    } else if (argument === '--result' && args[index + 1]) {
      parsed.resultPath = args[index + 1];
      index += 1;
    } else {
      throw new Error(`unsupported argument: ${argument}`);
    }
  }
  if (!parsed.resultPath) throw new Error('--result is required');
  return parsed;
}

function main() {
  let parsed;
  try {
    parsed = parseArguments(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 64;
    return;
  }

  let result;
  try {
    result = JSON.parse(fs.readFileSync(path.resolve(parsed.resultPath), 'utf8'));
  } catch (error) {
    process.stderr.write(`unable to read evaluation result: ${error.message}\n`);
    process.exitCode = 64;
    return;
  }
  const report = evaluateSkillResult({
    root: SCRIPT_ROOT,
    manifestPath: parsed.manifestPath,
    result,
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.status === 'passed' ? 0 : 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
