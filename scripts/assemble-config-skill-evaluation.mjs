import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {TextDecoder} from 'node:util';
import {fileURLToPath, pathToFileURL} from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

import {
  DEFAULT_MANIFEST_PATH,
  evaluateSkillResult,
  sha256,
  validateEvaluationManifest,
} from './evaluate-config-skill.mjs';

const SCRIPT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MAX_DESCRIPTOR_BYTES = 1024 * 1024;
const MAX_EVIDENCE_BYTES = 1024 * 1024;
const MAX_REPOSITORY_FILE_BYTES = 16 * 1024 * 1024;
const RUN_SCHEMA_PATH =
  'config/schemas/bonvoyage-authoring-skill-evaluation-run-v1.schema.json';

const WRAPPERS = {
  claude: {
    path: 'config/authoring/skills/v1/wrappers/claude.json',
    schema: 'config/schemas/bonvoyage-authoring-claude-wrapper-v1.schema.json',
    version: 'bonvoyage.claude-code-skill.v1',
  },
  'openai-codex': {
    path: 'config/authoring/skills/v1/wrappers/openai-codex.json',
    schema: 'config/schemas/bonvoyage-authoring-openai-codex-wrapper-v1.schema.json',
    version: 'bonvoyage.openai-codex-skill.v1',
  },
};

function fail(message) {
  throw new Error(message);
}

function schemaErrors(errors) {
  return (errors ?? []).map((error) => ({
    instance_path: error.instancePath,
    keyword: error.keyword,
    message: error.message,
  }));
}

function resolveRepositoryPath(root, relativePath) {
  return path.join(root, ...relativePath.split('/'));
}

function assertSafeRelativePath(relativePath, label) {
  if (typeof relativePath !== 'string' || relativePath.length === 0 ||
      relativePath.includes('\\') || path.posix.isAbsolute(relativePath) ||
      path.posix.normalize(relativePath) !== relativePath ||
      relativePath.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    fail(`${label} must be a normalized POSIX-relative path`);
  }
}

function readBoundedRegularFile(filePath, label, maximumBytes) {
  let information;
  try {
    information = fs.lstatSync(filePath);
  } catch {
    fail(`${label} is missing`);
  }
  if (information.isSymbolicLink() || !information.isFile()) {
    fail(`${label} must be a regular non-symlink file`);
  }
  if (information.size <= 0 || information.size > maximumBytes) {
    fail(`${label} must contain 1 to ${maximumBytes} bytes`);
  }
  return {bytes: fs.readFileSync(filePath), information};
}

function decodeUtf8(bytes, label) {
  let text;
  try {
    text = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
  } catch {
    fail(`${label} must contain valid UTF-8`);
  }
  if (text.includes('\0')) fail(`${label} must not contain NUL bytes`);
  return text;
}

function loadJsonBytes(bytes, label) {
  const text = decodeUtf8(bytes, label);
  try {
    return JSON.parse(text);
  } catch {
    fail(`${label} must contain valid JSON`);
  }
}

function validateWithSchema(document, schema, label) {
  const validate = new Ajv2020({allErrors: true, strict: true}).compile(schema);
  if (!validate(document)) {
    fail(`${label} failed schema validation: ${JSON.stringify(schemaErrors(validate.errors))}`);
  }
}

function validateRepositoryFile(root, source, label) {
  assertSafeRelativePath(source.path, `${label} path`);
  const absolutePath = resolveRepositoryPath(root, source.path);
  const {bytes} = readBoundedRegularFile(
    absolutePath, label, MAX_REPOSITORY_FILE_BYTES);
  if (source.bytes !== undefined && bytes.length !== source.bytes) {
    fail(`${label} byte count does not match its wrapper manifest`);
  }
  if (sha256(bytes) !== source.sha256) {
    fail(`${label} checksum does not match its wrapper manifest`);
  }
}

export function validateWrapper(root, assistant, manifest, manifestSha256) {
  const contract = WRAPPERS[assistant];
  if (!contract) fail(`unsupported assistant: ${assistant}`);

  const wrapperPath = resolveRepositoryPath(root, contract.path);
  const {bytes: wrapperBytes} = readBoundedRegularFile(
    wrapperPath, `${assistant} wrapper manifest`, MAX_DESCRIPTOR_BYTES);
  const wrapper = loadJsonBytes(wrapperBytes, `${assistant} wrapper manifest`);
  const wrapperSchema = loadJsonBytes(readBoundedRegularFile(
    resolveRepositoryPath(root, contract.schema), `${assistant} wrapper schema`,
    MAX_DESCRIPTOR_BYTES).bytes, `${assistant} wrapper schema`);
  validateWithSchema(wrapper, wrapperSchema, `${assistant} wrapper manifest`);

  if (wrapper.wrapper_version !== contract.version || wrapper.assistant !== assistant) {
    fail(`${assistant} wrapper identity is inconsistent`);
  }
  if (wrapper.release_binding.skill_version !== manifest.skill_version ||
      wrapper.release_binding.product_version !== manifest.product_version ||
      wrapper.release_binding.contract_version !== manifest.contract_version ||
      wrapper.release_binding.compiler_version !== manifest.compiler_version) {
    fail(`${assistant} wrapper release binding does not match the evaluation manifest`);
  }
  if (wrapper.sources.shared_contract.path !== manifest.sources.skill_contract.path ||
      wrapper.sources.shared_contract.sha256 !== manifest.sources.skill_contract.sha256 ||
      wrapper.sources.evaluation_manifest.path !== DEFAULT_MANIFEST_PATH ||
      wrapper.sources.evaluation_manifest.sha256 !== manifestSha256) {
    fail(`${assistant} wrapper is not bound to the active evaluation contract`);
  }

  for (const [name, source] of Object.entries(wrapper.sources)) {
    validateRepositoryFile(root, source, `${assistant} wrapper source ${name}`);
  }
  const packagePaths = new Set();
  for (const entry of wrapper.package.files) {
    assertSafeRelativePath(entry.path, `${assistant} package entry path`);
    if (packagePaths.has(entry.path)) fail(`${assistant} wrapper repeats a package entry`);
    packagePaths.add(entry.path);
    validateRepositoryFile(root, {
      path: `${wrapper.package.path}/${entry.path}`,
      bytes: entry.bytes,
      sha256: entry.sha256,
    }, `${assistant} package entry ${entry.path}`);
  }

  return {wrapper, wrapperSha256: sha256(wrapperBytes)};
}

function loadRunDescriptor(runPath, root) {
  const absolutePath = path.resolve(runPath);
  const {bytes} = readBoundedRegularFile(
    absolutePath, 'evaluation run descriptor', MAX_DESCRIPTOR_BYTES);
  const run = loadJsonBytes(bytes, 'evaluation run descriptor');
  const schema = loadJsonBytes(readBoundedRegularFile(
    resolveRepositoryPath(root, RUN_SCHEMA_PATH), 'evaluation run schema',
    MAX_DESCRIPTOR_BYTES).bytes, 'evaluation run schema');
  validateWithSchema(run, schema, 'evaluation run descriptor');
  return {bytes, run};
}

function validateEvidenceRoot(evidenceRoot) {
  const absoluteRoot = path.resolve(evidenceRoot);
  let information;
  try {
    information = fs.lstatSync(absoluteRoot);
  } catch {
    fail('evidence root is missing');
  }
  if (information.isSymbolicLink() || !information.isDirectory()) {
    fail('evidence root must be a non-symlink directory');
  }
  return {absoluteRoot, realRoot: fs.realpathSync(absoluteRoot)};
}

function readEvidenceFile(root, relativePath, label, seenPaths, seenFiles) {
  assertSafeRelativePath(relativePath, `${label} path`);
  if (seenPaths.has(relativePath)) fail(`${label} reuses an evidence path`);

  const parts = relativePath.split('/');
  let candidate = root.absoluteRoot;
  for (let index = 0; index < parts.length; index += 1) {
    candidate = path.join(candidate, parts[index]);
    let information;
    try {
      information = fs.lstatSync(candidate);
    } catch {
      fail(`${label} is missing`);
    }
    if (information.isSymbolicLink()) fail(`${label} path must not contain symlinks`);
    if (index < parts.length - 1 && !information.isDirectory()) {
      fail(`${label} parent must be a directory`);
    }
  }

  const {bytes, information} = readBoundedRegularFile(candidate, label, MAX_EVIDENCE_BYTES);
  if (information.nlink !== 1) fail(`${label} must not be hard-linked`);
  const realCandidate = fs.realpathSync(candidate);
  const relativeRealPath = path.relative(root.realRoot, realCandidate);
  if (relativeRealPath === '' || relativeRealPath.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relativeRealPath)) {
    fail(`${label} escapes the evidence root`);
  }
  const fileIdentity = realCandidate;
  if (seenFiles.has(fileIdentity)) fail(`${label} reuses an evidence file`);
  seenPaths.add(relativePath);
  seenFiles.add(fileIdentity);
  return bytes;
}

function validateCaseInventory(run, manifest) {
  const expectedIds = manifest.cases.map((entry) => entry.id);
  const observedIds = run.cases.map((entry) => entry.id);
  if (new Set(observedIds).size !== observedIds.length) {
    fail('evaluation run descriptor repeats a case ID');
  }
  if (JSON.stringify([...observedIds].sort()) !== JSON.stringify([...expectedIds].sort())) {
    fail('evaluation run descriptor must contain the exact 16-case inventory');
  }
}

export function assembleEvaluationRun({
  root = SCRIPT_ROOT,
  runPath,
  evidenceRoot,
}) {
  if (!runPath || !evidenceRoot) fail('runPath and evidenceRoot are required');

  const validatedManifest = validateEvaluationManifest(root);
  if (!validatedManifest.ok) {
    fail(`evaluation manifest is invalid: ${JSON.stringify(validatedManifest.errors)}`);
  }
  const {bytes: runBytes, run} = loadRunDescriptor(runPath, root);
  const {wrapper, wrapperSha256} = validateWrapper(
    root, run.assistant, validatedManifest.manifest, validatedManifest.manifestSha256);
  if (run.wrapper_version !== wrapper.wrapper_version) {
    fail('evaluation run wrapper version does not match the active wrapper');
  }
  validateCaseInventory(run, validatedManifest.manifest);

  const evidence = validateEvidenceRoot(evidenceRoot);
  const seenPaths = new Set();
  const seenFiles = new Set();
  const runCases = new Map(run.cases.map((entry) => [entry.id, entry]));
  let transcriptBytes = 0;
  let actionLogBytes = 0;

  const cases = validatedManifest.manifest.cases.map((expectedCase) => {
    const entry = runCases.get(expectedCase.id);
    const transcript = readEvidenceFile(
      evidence, entry.transcript_path, `transcript for ${entry.id}`, seenPaths, seenFiles);
    decodeUtf8(transcript, `transcript for ${entry.id}`);
    const actionLog = readEvidenceFile(
      evidence, entry.action_log_path, `action log for ${entry.id}`, seenPaths, seenFiles);
    const parsedActionLog = loadJsonBytes(actionLog, `action log for ${entry.id}`);
    if (parsedActionLog === null || typeof parsedActionLog !== 'object') {
      fail(`action log for ${entry.id} must contain a JSON object or array`);
    }
    transcriptBytes += transcript.length;
    actionLogBytes += actionLog.length;

    const {
      transcript_path: ignoredTranscriptPath,
      action_log_path: ignoredActionLogPath,
      ...decisions
    } = entry;
    void ignoredTranscriptPath;
    void ignoredActionLogPath;
    return {
      ...decisions,
      concepts: [...entry.concepts].sort(),
      transcript_sha256: sha256(transcript),
      action_log_sha256: sha256(actionLog),
    };
  });

  const result = {
    $schema: 'https://docs.routesphere.global/schemas/bonvoyage-authoring-skill-evaluation-result-v1.schema.json',
    schema_version: 1,
    classification: 'routesphere-bonvoyage-configuration-skill-evaluation-result',
    skill_version: validatedManifest.manifest.skill_version,
    assistant: run.assistant,
    wrapper_version: run.wrapper_version,
    model_id: run.model_id,
    skill_contract_sha256: validatedManifest.manifest.sources.skill_contract.sha256,
    evaluation_manifest_sha256: validatedManifest.manifestSha256,
    cases,
  };
  const evaluation = evaluateSkillResult({root, result});
  const resultBytes = Buffer.from(`${JSON.stringify(result, null, 2)}\n`, 'utf8');
  const report = {
    classification: 'routesphere-bonvoyage-configuration-skill-evaluation-driver-report',
    driver_version: 'bonvoyage.configuration-skill-evaluation-driver.v1',
    assistant: run.assistant,
    wrapper_version: run.wrapper_version,
    model_id: run.model_id,
    run_descriptor_sha256: sha256(runBytes),
    wrapper_manifest_sha256: wrapperSha256,
    evaluation_result_sha256: sha256(resultBytes),
    evidence: {
      case_count: cases.length,
      unique_file_count: seenFiles.size,
      transcript_bytes: transcriptBytes,
      action_log_bytes: actionLogBytes,
      portable_contents_retained: false,
    },
    evaluation,
  };
  return {evaluation, report, result, resultBytes};
}

function parseArguments(args) {
  const parsed = {runPath: null, evidenceRoot: null, resultPath: null, reportPath: null};
  const options = new Map([
    ['--run', 'runPath'],
    ['--evidence-root', 'evidenceRoot'],
    ['--result', 'resultPath'],
    ['--report', 'reportPath'],
  ]);
  for (let index = 0; index < args.length; index += 1) {
    const property = options.get(args[index]);
    if (!property || !args[index + 1]) fail(`unsupported or incomplete argument: ${args[index]}`);
    parsed[property] = args[index + 1];
    index += 1;
  }
  for (const [option, property] of options) {
    if (!parsed[property]) fail(`${option} is required`);
  }
  return parsed;
}

function validateOutputPath(filePath, label) {
  const absolutePath = path.resolve(filePath);
  if (fs.existsSync(absolutePath)) fail(`${label} must be a new output`);
  const parent = path.dirname(absolutePath);
  fs.mkdirSync(parent, {recursive: true, mode: 0o700});
  const parentInformation = fs.lstatSync(parent);
  if (parentInformation.isSymbolicLink() || !parentInformation.isDirectory()) {
    fail(`${label} parent must be a non-symlink directory`);
  }
  return absolutePath;
}

function writeOutputs(resultPath, reportPath, result, report) {
  const absoluteResult = validateOutputPath(resultPath, 'evaluation result');
  const absoluteReport = validateOutputPath(reportPath, 'evaluation report');
  if (absoluteResult === absoluteReport) fail('result and report outputs must differ');

  const created = [];
  try {
    fs.writeFileSync(absoluteResult, `${JSON.stringify(result, null, 2)}\n`, {
      flag: 'wx',
      mode: 0o600,
    });
    created.push(absoluteResult);
    fs.writeFileSync(absoluteReport, `${JSON.stringify(report, null, 2)}\n`, {
      flag: 'wx',
      mode: 0o600,
    });
    created.push(absoluteReport);
  } catch (error) {
    for (const output of created) fs.rmSync(output, {force: true});
    throw error;
  }
}

function main() {
  try {
    const options = parseArguments(process.argv.slice(2));
    const assembled = assembleEvaluationRun(options);
    writeOutputs(options.resultPath, options.reportPath, assembled.result, assembled.report);
    process.stdout.write(`${JSON.stringify(assembled.report, null, 2)}\n`);
    process.exitCode = assembled.evaluation.status === 'passed' ? 0 : 2;
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 64;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
