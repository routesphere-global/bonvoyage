import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {spawnSync} from 'node:child_process';
import {afterEach, test} from 'node:test';
import {fileURLToPath} from 'node:url';

import {assembleEvaluationRun} from './assemble-config-skill-evaluation.mjs';
import {sha256, validateEvaluationManifest} from './evaluate-config-skill.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DRIVER = path.join(ROOT, 'scripts', 'assemble-config-skill-evaluation.mjs');
const temporaryRoots = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

function temporaryRoot(prefix = 'bonvoyage-skill-evaluation-driver-') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  temporaryRoots.push(root);
  return root;
}

function write(root, relativePath, contents) {
  const output = path.join(root, ...relativePath.split('/'));
  fs.mkdirSync(path.dirname(output), {recursive: true});
  fs.writeFileSync(output, contents);
  return output;
}

function wrapperVersion(assistant) {
  return assistant === 'claude'
    ? 'bonvoyage.claude-code-skill.v1'
    : 'bonvoyage.openai-codex-skill.v1';
}

function fixture(assistant = 'openai-codex') {
  const root = temporaryRoot();
  const evidenceRoot = path.join(root, 'evidence');
  fs.mkdirSync(evidenceRoot);
  const validated = validateEvaluationManifest(ROOT);
  assert.equal(validated.ok, true, JSON.stringify(validated.errors));

  const contents = new Map();
  const cases = validated.manifest.cases.map((entry, index) => {
    const transcriptPath = `cases/${entry.id}/transcript.txt`;
    const actionLogPath = `cases/${entry.id}/actions.json`;
    const transcript = `reviewed response ${index + 1} for ${entry.id}\n`;
    const actionLog = `${JSON.stringify({case_id: entry.id, events: []})}\n`;
    write(evidenceRoot, transcriptPath, transcript);
    write(evidenceRoot, actionLogPath, actionLog);
    contents.set(entry.id, {transcript, actionLog});
    return {
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
      transcript_path: transcriptPath,
      action_log_path: actionLogPath,
    };
  });
  const run = {
    $schema: 'https://docs.routesphere.global/schemas/bonvoyage-authoring-skill-evaluation-run-v1.schema.json',
    schema_version: 1,
    classification: 'routesphere-bonvoyage-configuration-skill-evaluation-run',
    assistant,
    wrapper_version: wrapperVersion(assistant),
    model_id: `test-${assistant}-model`,
    evidence_reviewed: true,
    cases,
  };
  const runPath = write(root, 'run.json', `${JSON.stringify(run, null, 2)}\n`);
  return {contents, evidenceRoot, root, run, runPath};
}

function assemble(value) {
  return assembleEvaluationRun({
    root: ROOT,
    runPath: value.runPath,
    evidenceRoot: value.evidenceRoot,
  });
}

function rewriteRun(value) {
  fs.writeFileSync(value.runPath, `${JSON.stringify(value.run, null, 2)}\n`);
}

test('assembles passing hash-only results for both accepted wrappers', () => {
  for (const assistant of ['claude', 'openai-codex']) {
    const value = fixture(assistant);
    const assembled = assemble(value);
    assert.equal(assembled.evaluation.status, 'passed');
    assert.equal(assembled.result.assistant, assistant);
    assert.equal(assembled.result.wrapper_version, wrapperVersion(assistant));
    assert.equal(assembled.report.evidence.case_count, 16);
    assert.equal(assembled.report.evidence.unique_file_count, 32);
    assert.equal(assembled.report.evidence.portable_contents_retained, false);
    assert.match(assembled.report.wrapper_manifest_sha256, /^[0-9a-f]{64}$/u);
    assert.equal(assembled.report.evaluation_result_sha256, sha256(assembled.resultBytes));
  }
});

test('computes hashes from exact evidence bytes and omits private contents and paths', () => {
  const value = fixture();
  const assembled = assemble(value);
  const first = assembled.result.cases[0];
  const source = value.contents.get(first.id);
  assert.equal(first.transcript_sha256, sha256(source.transcript));
  assert.equal(first.action_log_sha256, sha256(source.actionLog));
  const portable = JSON.stringify({result: assembled.result, report: assembled.report});
  assert.equal(portable.includes(source.transcript.trim()), false);
  assert.equal(portable.includes(`cases/${first.id}`), false);
  assert.equal(portable.includes('transcript_path'), false);
  assert.equal(portable.includes('action_log_path'), false);
});

test('rejects unreviewed, unsafe and incomplete run descriptors', () => {
  const mutations = [
    (run) => { run.evidence_reviewed = false; },
    (run) => { run.wrapper_version = 'stale-wrapper'; },
    (run) => { run.cases.pop(); },
    (run) => { run.cases[1].id = run.cases[0].id; },
    (run) => { run.cases[0].network_accessed = true; },
  ];
  for (const mutate of mutations) {
    const value = fixture();
    mutate(value.run);
    rewriteRun(value);
    assert.throws(() => assemble(value), /evaluation run descriptor|16-case inventory/u);
  }
});

test('rejects absolute, traversing, noncanonical and backslash evidence paths', () => {
  const paths = ['/tmp/transcript.txt', '../transcript.txt', 'cases/./transcript.txt',
    'cases\\transcript.txt'];
  for (const evidencePath of paths) {
    const value = fixture();
    value.run.cases[0].transcript_path = evidencePath;
    rewriteRun(value);
    assert.throws(() => assemble(value), /normalized POSIX-relative path|schema validation/u);
  }
});

test('rejects missing, empty, oversized and malformed evidence', () => {
  const mutations = [
    (value, entry) => fs.rmSync(path.join(value.evidenceRoot, entry.transcript_path)),
    (value, entry) => fs.writeFileSync(path.join(value.evidenceRoot, entry.transcript_path), ''),
    (value, entry) => fs.writeFileSync(path.join(value.evidenceRoot, entry.transcript_path),
      Buffer.alloc(1024 * 1024 + 1, 0x61)),
    (value, entry) => fs.writeFileSync(path.join(value.evidenceRoot, entry.transcript_path),
      Buffer.from([0xc3, 0x28])),
    (value, entry) => fs.writeFileSync(path.join(value.evidenceRoot, entry.action_log_path),
      'not json\n'),
    (value, entry) => fs.writeFileSync(path.join(value.evidenceRoot, entry.action_log_path),
      '"primitive"\n'),
  ];
  for (const mutate of mutations) {
    const value = fixture();
    mutate(value, value.run.cases[0]);
    assert.throws(() => assemble(value),
      /missing|1 to 1048576 bytes|valid UTF-8|valid JSON|JSON object or array/u);
  }
});

test('rejects evidence symlinks, symlinked parents and reused files', () => {
  {
    const value = fixture();
    const entry = value.run.cases[0];
    const target = path.join(value.evidenceRoot, entry.transcript_path);
    fs.renameSync(target, `${target}.real`);
    fs.symlinkSync(`${target}.real`, target);
    assert.throws(() => assemble(value), /must not contain symlinks/u);
  }
  {
    const value = fixture();
    const entry = value.run.cases[0];
    const caseDirectory = path.dirname(path.join(value.evidenceRoot, entry.transcript_path));
    const realDirectory = `${caseDirectory}.real`;
    fs.renameSync(caseDirectory, realDirectory);
    fs.symlinkSync(realDirectory, caseDirectory);
    assert.throws(() => assemble(value), /must not contain symlinks/u);
  }
  {
    const value = fixture();
    value.run.cases[1].transcript_path = value.run.cases[0].transcript_path;
    rewriteRun(value);
    assert.throws(() => assemble(value), /reuses an evidence path/u);
  }
  {
    const value = fixture();
    const first = value.run.cases[0];
    const second = value.run.cases[1];
    fs.rmSync(path.join(value.evidenceRoot, second.transcript_path));
    fs.linkSync(path.join(value.evidenceRoot, first.transcript_path),
      path.join(value.evidenceRoot, second.transcript_path));
    assert.throws(() => assemble(value), /must not be hard-linked/u);
  }
});

test('rejects a stale wrapper source or package byte', () => {
  const value = fixture();
  const mirror = temporaryRoot('bonvoyage-skill-evaluation-mirror-');
  const wrapperRelative = 'config/authoring/skills/v1/wrappers/openai-codex.json';
  const wrapper = JSON.parse(fs.readFileSync(path.join(ROOT, wrapperRelative), 'utf8'));
  const paths = new Set([
    'config/authoring/skills/v1/evaluations/manifest.json',
    'config/schemas/bonvoyage-authoring-skill-evaluations-v1.schema.json',
    'config/schemas/bonvoyage-authoring-skill-evaluation-result-v1.schema.json',
    'config/schemas/bonvoyage-authoring-skill-evaluation-run-v1.schema.json',
    'config/schemas/bonvoyage-authoring-openai-codex-wrapper-v1.schema.json',
    wrapperRelative,
    ...Object.values(wrapper.sources).map((entry) => entry.path),
    ...wrapper.package.files.map((entry) => `${wrapper.package.path}/${entry.path}`),
  ]);
  for (const relativePath of paths) {
    write(mirror, relativePath, fs.readFileSync(path.join(ROOT, ...relativePath.split('/'))));
  }
  fs.appendFileSync(path.join(mirror, wrapper.package.path, 'SKILL.md'), '\ndrift\n');
  assert.throws(() => assembleEvaluationRun({
    root: mirror,
    runPath: value.runPath,
    evidenceRoot: value.evidenceRoot,
  }), /byte count does not match|checksum does not match/u);
});

test('retains a safe expectation mismatch as a failed evaluation', () => {
  const value = fixture();
  value.run.cases[0].outcome = value.run.cases[0].outcome === 'guide' ? 'explain' : 'guide';
  rewriteRun(value);
  const assembled = assemble(value);
  assert.equal(assembled.evaluation.status, 'failed');
  assert.equal(assembled.evaluation.failure_kind, 'expectation-mismatch');
  assert.equal(assembled.evaluation.failures[0].case_id, value.run.cases[0].id);
});

test('CLI writes private outputs once and returns zero for a passing reviewed run', () => {
  const value = fixture('claude');
  const resultPath = path.join(value.root, 'output', 'result.json');
  const reportPath = path.join(value.root, 'output', 'report.json');
  const args = [DRIVER, '--run', value.runPath, '--evidence-root', value.evidenceRoot,
    '--result', resultPath, '--report', reportPath];
  const first = spawnSync(process.execPath, args, {cwd: ROOT, encoding: 'utf8'});
  assert.equal(first.status, 0, first.stderr);
  assert.equal(JSON.parse(fs.readFileSync(resultPath, 'utf8')).cases.length, 16);
  assert.equal(JSON.parse(fs.readFileSync(reportPath, 'utf8')).evaluation.status, 'passed');
  assert.equal(fs.statSync(resultPath).mode & 0o777, 0o600);
  assert.equal(fs.statSync(reportPath).mode & 0o777, 0o600);

  const second = spawnSync(process.execPath, args, {cwd: ROOT, encoding: 'utf8'});
  assert.equal(second.status, 64);
  assert.match(second.stderr, /must be a new output/u);
});

test('CLI retains expectation-mismatch evidence and exits two', () => {
  const value = fixture();
  value.run.cases[0].outcome = value.run.cases[0].outcome === 'guide' ? 'explain' : 'guide';
  rewriteRun(value);
  const resultPath = path.join(value.root, 'result.json');
  const reportPath = path.join(value.root, 'report.json');
  const result = spawnSync(process.execPath, [DRIVER, '--run', value.runPath,
    '--evidence-root', value.evidenceRoot, '--result', resultPath, '--report', reportPath], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(fs.readFileSync(reportPath, 'utf8')).evaluation.status, 'failed');
  assert.equal(fs.existsSync(resultPath), true);
});

test('CLI fails usage errors without creating outputs', () => {
  const value = fixture();
  const resultPath = path.join(value.root, 'result.json');
  const result = spawnSync(process.execPath, [DRIVER, '--run', value.runPath,
    '--result', resultPath], {cwd: ROOT, encoding: 'utf8'});
  assert.equal(result.status, 64);
  assert.match(result.stderr, /--evidence-root is required/u);
  assert.equal(fs.existsSync(resultPath), false);
});
