import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {spawnSync} from 'node:child_process';
import {afterEach, test} from 'node:test';
import {fileURLToPath} from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

import {captureOpenAICodexEvaluation} from
  './capture-openai-codex-config-skill-evaluation.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DRIVER = path.join(ROOT, 'scripts',
  'capture-openai-codex-config-skill-evaluation.mjs');
const PROMPT_REFERENCE_PATHS = Object.freeze([
  'skills/bonvoyage-config-authoring/references/command-surface.md',
  'skills/bonvoyage-config-authoring/references/completion.json',
  'skills/bonvoyage-config-authoring/references/configuration-schema.json',
  'skills/bonvoyage-config-authoring/references/snippets.json',
]);
const temporaryRoots = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

function temporaryRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-codex-capture-'));
  temporaryRoots.push(root);
  return root;
}

function executable(root, name, source) {
  const filePath = path.join(root, name);
  fs.writeFileSync(filePath, source, {mode: 0o700});
  fs.chmodSync(filePath, 0o700);
  return filePath;
}

function commandFixture(root) {
  return executable(root, 'bonvoyage-config', `#!/usr/bin/env node
const result = {
  contract_version: 'bonvoyage.configuration-authoring.v1',
  operation: 'explain',
  status: 'accepted',
  exit_code: 0,
  failure_kind: 'none',
  versions: {
    product_version: '0.2.0',
    compiler_version: 'bonvoyage-control-plane-phase4-admin-v1',
    supported_configuration_schema_versions: [1],
    input_configuration_schema_version: 1
  },
  diagnostics: [],
  diagnostics_truncated: false,
  result: {kind: 'field-explanation', path: ''}
};
process.stdout.write(JSON.stringify(result) + '\\n');
`);
}

function codexFixture(root, malformed = false, enabledFeature = null, failed = false,
  eventScenario = 'normal') {
  return executable(root, 'codex', `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
if (args[0] === '--version') {
  process.stdout.write('codex-cli 0.160.1\\n');
  process.exit(0);
}
const overrides = args.flatMap((value, index) => value === '-c' ? [args[index + 1]] : []);
const requiredOverrides = [
  'mcp_servers={}',
  'web_search="disabled"',
  'features.apps=false',
  'features.browser_use=false',
  'features.computer_use=false',
  'features.multi_agent=false',
  'features.remote_plugin=false',
  'features.shell_tool=false'
];
const featureProbe = args.includes('features') && args.at(-1) === 'list';
if ((!featureProbe && !args.includes('--strict-config')) ||
    requiredOverrides.some((value) => !overrides.includes(value))) {
  process.stderr.write('model tools were not disabled under strict config\\n');
  process.exit(72);
}
if (featureProbe) {
  const enabledFeature = ${JSON.stringify(enabledFeature)};
  const features = [
    'apps', 'browser_use', 'code_mode', 'code_mode_host', 'computer_use', 'goals',
    'hooks', 'image_generation', 'in_app_browser', 'multi_agent', 'plugins',
    'remote_plugin', 'shell_tool', 'skill_search', 'sleep_tool', 'tool_suggest',
    'view_image', 'workspace_dependencies', 'worktrees'
  ];
  for (const feature of features) {
    process.stdout.write(feature + ' stable ' +
      (feature === enabledFeature ? 'true' : 'false') + '\\n');
  }
  process.exit(0);
}
if (${failed}) {
  process.stdout.write(JSON.stringify({type: 'error', message: 'synthetic failure'}) + '\\n');
  process.stderr.write('synthetic provider failure\\n');
  process.exit(9);
}
const outputIndex = args.indexOf('--output-last-message');
const prompt = args.at(-1);
const match = prompt.match(/Case ID: ([a-z0-9-]+)/);
const id = match ? match[1] : 'unknown';
fs.writeFileSync(args[outputIndex + 1], 'reviewed response for ' + id + '\\n');
${malformed ? "process.stdout.write('not-json\\n');" : `
const scenario = ${JSON.stringify(eventScenario)};
const warningMessage = 'Code Mode is unavailable because code-mode host is disabled. ' +
  'Code mode will fail closed; enable \`features.code_mode_host\` and install ' +
  '\`codex-code-mode-host\`.';
const warning = (message = warningMessage, extra = {}) => ({
  type: 'item.completed',
  item: {id: 'item-warning', type: 'error', message, ...extra}
});
const events = [{type: 'thread.started', thread_id: 'thread-' + id}];
if (scenario === 'warning-valid') events.push(warning());
if (scenario === 'warning-changed') events.push(warning(warningMessage + ' changed'));
if (scenario === 'warning-duplicate') events.push(warning(), warning());
if (scenario === 'warning-generic') events.push(warning('synthetic provider item error'));
if (scenario === 'warning-extra-field') events.push(warning(warningMessage, {detail: 'extra'}));
events.push({type: 'turn.started'});
if (scenario === 'warning-late') events.push(warning());
events.push(
  {type: 'item.completed', item: {id: 'item-0', type: 'agent_message', text: 'reviewed response for ' + id}},
  {type: 'turn.completed', usage: {input_tokens: 100, cached_input_tokens: 50, output_tokens: 10, reasoning_output_tokens: 2}}
);
for (const event of events) process.stdout.write(JSON.stringify(event) + '\\n');`}
`);
}

function toolAttemptCodexFixture(root) {
  return executable(root, 'codex', `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
if (args[0] === '--version') {
  process.stdout.write('codex-cli 0.160.1\\n');
  process.exit(0);
}
if (args.includes('features') && args.at(-1) === 'list') {
  const features = [
    'apps', 'browser_use', 'code_mode', 'code_mode_host', 'computer_use', 'goals',
    'hooks', 'image_generation', 'in_app_browser', 'multi_agent', 'plugins',
    'remote_plugin', 'shell_tool', 'skill_search', 'sleep_tool', 'tool_suggest',
    'view_image', 'workspace_dependencies', 'worktrees'
  ];
  for (const feature of features) {
    process.stdout.write(feature + ' stable false\\n');
  }
  process.exit(0);
}
const outputIndex = args.indexOf('--output-last-message');
const prompt = args.at(-1);
const match = prompt.match(/Case ID: ([a-z0-9-]+)/);
const id = match ? match[1] : 'unknown';
fs.writeFileSync(args[outputIndex + 1], 'unsafe response\\n');
const events = [
  {type: 'thread.started', thread_id: 'thread-' + id},
  {type: 'turn.started'},
  {type: 'item.completed', item: {id: 'item-tool', type: 'command_execution', command: 'env'}},
  {type: 'item.completed', item: {id: 'item-0', type: 'agent_message', text: 'unsafe response'}},
  {type: 'turn.completed', usage: {input_tokens: 100, cached_input_tokens: 50, output_tokens: 10, reasoning_output_tokens: 2}}
];
for (const event of events) process.stdout.write(JSON.stringify(event) + '\\n');
`);
}

function sanitizedRoot() {
  const root = temporaryRoot();
  const wrapperPath = 'config/authoring/skills/v1/wrappers/openai-codex.json';
  const wrapper = JSON.parse(fs.readFileSync(path.join(ROOT, wrapperPath), 'utf8'));
  const paths = new Set([
    wrapperPath,
    'config/authoring/skills/v1/evaluations/manifest.json',
    'config/schemas/bonvoyage-authoring-skill-evaluations-v1.schema.json',
    'config/schemas/bonvoyage-authoring-skill-evaluation-result-v1.schema.json',
    'config/schemas/bonvoyage-authoring-openai-codex-wrapper-v1.schema.json',
    'config/schemas/bonvoyage-authoring-openai-codex-capture-v1.schema.json',
    'scripts/assemble-config-skill-evaluation.mjs',
    'scripts/capture-openai-codex-config-skill-evaluation.mjs',
    'scripts/evaluate-config-skill.mjs',
    ...Object.values(wrapper.sources).map((entry) => entry.path),
    ...wrapper.package.files.map((entry) => `${wrapper.package.path}/${entry.path}`),
  ]);
  for (const relativePath of paths) {
    const source = path.join(ROOT, ...relativePath.split('/'));
    const destination = path.join(root, ...relativePath.split('/'));
    fs.mkdirSync(path.dirname(destination), {recursive: true});
    fs.copyFileSync(source, destination);
  }
  const sourceModules = path.join(ROOT, 'node_modules');
  if (fs.existsSync(sourceModules)) {
    fs.symlinkSync(sourceModules, path.join(root, 'node_modules'), 'dir');
  }
  return root;
}

function fixture(options = {}) {
  const tools = temporaryRoot();
  const root = sanitizedRoot();
  return {
    root,
    evidenceRoot: path.join(temporaryRoot(), 'evidence'),
    codexPath: codexFixture(tools, options.malformed, options.enabledFeature, options.failed,
      options.eventScenario),
    commandPath: commandFixture(tools),
    modelId: 'gpt-test-codex',
    timeoutSeconds: 30,
    now: (() => {
      const values = [new Date('2026-10-09T00:00:00.000Z'),
        new Date('2026-10-09T00:01:00.000Z')];
      return () => values.shift() ?? values.at(-1);
    })(),
  };
}

test('captures all 16 cases without exposing expected answers', () => {
  const value = fixture();
  const result = captureOpenAICodexEvaluation(value);
  assert.equal(result.capture.cases.length, 16);
  assert.equal(result.capture.execution.expected_answers_exposed, false);
  assert.equal(result.capture.execution.automatic_retry, false);
  assert.equal(result.capture.execution.shell_tool_enabled, false);
  assert.equal(result.capture.execution.web_search, 'disabled');
  assert.equal(result.capture.execution.mcp_server_count, 0);
  assert.equal(result.capture.execution.tool_event_policy, 'reject');
  assert.ok(result.capture.execution.disabled_features.includes('shell_tool'));
  assert.deepEqual(result.capture.execution.embedded_reference_paths,
    PROMPT_REFERENCE_PATHS);
  assert.equal(result.capture.codex_cli_version, 'codex-cli 0.160.1');
  assert.match(result.captureSha256, /^[0-9a-f]{64}$/u);
  assert.equal(fs.statSync(value.evidenceRoot).mode & 0o777, 0o700);
  assert.equal(fs.statSync(path.join(value.evidenceRoot, 'capture.json')).mode & 0o777, 0o600);

  const manifest = JSON.parse(fs.readFileSync(
    path.join(value.root, 'config/authoring/skills/v1/evaluations/manifest.json'), 'utf8'));
  for (const captured of result.capture.cases) {
    const source = manifest.cases.find((entry) => entry.id === captured.id);
    const prompt = fs.readFileSync(path.join(value.evidenceRoot, captured.prompt_path), 'utf8');
    assert.match(prompt, new RegExp(`Case ID: ${captured.id}`, 'u'));
    assert.match(prompt, /disables local shell, web search/u);
    assert.match(prompt, /candidate_document is the exact complete in-memory YAML/u);
    assert.match(prompt, /BEGIN EXACT skills\/bonvoyage-config-authoring\/SKILL\.md/u);
    for (const referencePath of PROMPT_REFERENCE_PATHS) {
      const referenceText = fs.readFileSync(
        path.join(value.root, ...referencePath.split('/')), 'utf8');
      const exactBlock = [
        `---BEGIN EXACT ${referencePath}---`,
        referenceText,
        `---END EXACT ${referencePath}---`,
      ].join('\n');
      assert.equal(prompt.includes(exactBlock), true,
        `prompt omitted exact reviewed reference ${referencePath}`);
    }
    assert.equal(prompt.includes(
      'BEGIN EXACT config/authoring/skills/v1/evaluations/manifest.json'), false);
    assert.equal(prompt.includes(JSON.stringify(source.expected)), false);
    assert.equal(prompt.includes(source.purpose), false);
    if (source.input.candidate_document !== undefined) {
      assert.equal(prompt.includes(source.input.candidate_document_sha256), true);
      assert.equal(prompt.includes(JSON.stringify(source.input.candidate_document)), true);
    }
    assert.equal(fs.statSync(path.join(value.evidenceRoot, captured.prompt_path)).mode & 0o777,
      0o600);
    assert.equal(JSON.parse(fs.readFileSync(
      path.join(value.evidenceRoot, captured.action_log_path), 'utf8')).length, 4);
    assert.deepEqual(captured.startup_warnings, []);
    const providerEvents = fs.readFileSync(
      path.join(value.evidenceRoot, captured.provider_event_log_path), 'utf8');
    assert.equal(providerEvents.trimEnd().split('\n').length, 4);
    assert.equal(fs.statSync(
      path.join(value.evidenceRoot, captured.provider_event_log_path)).mode & 0o777, 0o600);
  }
});

test('accepts and records only the exact pre-turn disabled code-mode warning', () => {
  const value = fixture({eventScenario: 'warning-valid'});
  const result = captureOpenAICodexEvaluation(value);
  for (const captured of result.capture.cases) {
    assert.deepEqual(captured.startup_warnings, [{
      code: 'code_mode_host_disabled',
      message: 'Code Mode is unavailable because code-mode host is disabled. ' +
        'Code mode will fail closed; enable `features.code_mode_host` and install ' +
        '`codex-code-mode-host`.',
      event_index: 1,
    }]);
    assert.equal(captured.event_count, 5);
    const actions = JSON.parse(fs.readFileSync(
      path.join(value.evidenceRoot, captured.action_log_path), 'utf8'));
    assert.equal(actions[1].item.type, 'error');
    assert.equal(actions[1].item.message, captured.startup_warnings[0].message);
  }
});

test('keeps accepted version-one capture manifests schema-compatible', () => {
  const value = fixture();
  const result = captureOpenAICodexEvaluation(value);
  const historical = structuredClone(result.capture);
  delete historical.execution.embedded_reference_paths;
  for (const captured of historical.cases) delete captured.startup_warnings;
  const schema = JSON.parse(fs.readFileSync(path.join(value.root,
    'config/schemas/bonvoyage-authoring-openai-codex-capture-v1.schema.json'), 'utf8'));
  const validate = new Ajv2020({allErrors: true, strict: true}).compile(schema);
  assert.equal(validate(historical), true, JSON.stringify(validate.errors));
});

test('rejects altered, duplicate, late, generic and extended startup warning events', () => {
  for (const eventScenario of ['warning-changed', 'warning-duplicate', 'warning-late',
    'warning-generic', 'warning-extra-field']) {
    const value = fixture({eventScenario});
    assert.throws(() => captureOpenAICodexEvaluation(value),
      /reported an unsupported item error/u, eventScenario);
    const failure = JSON.parse(fs.readFileSync(
      path.join(value.evidenceRoot, 'capture-failure.json'), 'utf8'));
    assert.match(failure.message, /reported an unsupported item error/u);
    assert.match(fs.readFileSync(path.join(value.evidenceRoot,
      'cases/ambiguous-requirements-backend/provider-events.jsonl'), 'utf8'),
    /"type":"error"/u);
    assert.equal(fs.existsSync(path.join(value.evidenceRoot, 'capture.json')), false);
  }
});

test('rejects unsafe roots, command identities and model IDs before capture', () => {
  {
    const value = fixture();
    fs.mkdirSync(value.evidenceRoot);
    assert.throws(() => captureOpenAICodexEvaluation(value), /must not already exist/u);
  }
  {
    const value = fixture();
    value.modelId = 'bad\nmodel';
    assert.throws(() => captureOpenAICodexEvaluation(value), /model ID/u);
  }
  {
    const value = fixture();
    const renamed = path.join(path.dirname(value.commandPath), 'wrong-name');
    fs.renameSync(value.commandPath, renamed);
    value.commandPath = renamed;
    assert.throws(() => captureOpenAICodexEvaluation(value), /must be named bonvoyage-config/u);
  }
  {
    const value = fixture();
    fs.mkdirSync(path.join(value.root, '.git'));
    assert.throws(() => captureOpenAICodexEvaluation(value), /sanitized no-Git/u);
  }
  {
    const value = fixture();
    fs.mkdirSync(path.join(value.root, 'nested', '.git'), {recursive: true});
    assert.throws(() => captureOpenAICodexEvaluation(value), /sanitized no-Git/u);
  }
  {
    const value = fixture();
    value.evidenceRoot = path.join(value.root, 'private-evidence');
    assert.throws(() => captureOpenAICodexEvaluation(value), /must not overlap/u);
  }
});

test('retains a private failure marker for malformed provider events', () => {
  const value = fixture({malformed: true});
  assert.throws(() => captureOpenAICodexEvaluation(value), /malformed JSON events/u);
  const failure = JSON.parse(fs.readFileSync(
    path.join(value.evidenceRoot, 'capture-failure.json'), 'utf8'));
  assert.match(failure.message, /malformed JSON events/u);
  assert.equal(fs.statSync(path.join(value.evidenceRoot, 'capture-failure.json')).mode & 0o777,
    0o600);
  assert.equal(fs.readFileSync(path.join(value.evidenceRoot,
    'cases/ambiguous-requirements-backend/provider-events.jsonl'), 'utf8'), 'not-json\n');
  assert.equal(fs.existsSync(path.join(value.evidenceRoot, 'capture.json')), false);
});

test('rejects capture if a required Codex feature remains enabled', () => {
  const value = fixture({enabledFeature: 'shell_tool'});
  assert.throws(() => captureOpenAICodexEvaluation(value),
    /did not disable required features: shell_tool/u);
  assert.equal(fs.existsSync(value.evidenceRoot), false);
});

test('retains raw provider output before rejecting a nonzero exit', () => {
  const value = fixture({failed: true});
  assert.throws(() => captureOpenAICodexEvaluation(value), /failed .* status 9/u);
  assert.match(fs.readFileSync(path.join(value.evidenceRoot,
    'cases/ambiguous-requirements-backend/provider-events.jsonl'), 'utf8'),
    /"message":"synthetic failure"/u);
  assert.equal(fs.readFileSync(path.join(value.evidenceRoot,
    'cases/ambiguous-requirements-backend/provider-stderr.txt'), 'utf8'),
  'synthetic provider failure\n');
  const failure = JSON.parse(fs.readFileSync(
    path.join(value.evidenceRoot, 'capture-failure.json'), 'utf8'));
  assert.match(failure.message, /failed .* status 9/u);
});

test('fails closed if provider events report any tool attempt', () => {
  const value = fixture();
  value.codexPath = toolAttemptCodexFixture(temporaryRoot());
  assert.throws(() => captureOpenAICodexEvaluation(value), /attempted a disabled tool/u);
  const failure = JSON.parse(fs.readFileSync(
    path.join(value.evidenceRoot, 'capture-failure.json'), 'utf8'));
  assert.match(failure.message, /attempted a disabled tool/u);
  assert.match(fs.readFileSync(path.join(value.evidenceRoot,
    'cases/ambiguous-requirements-backend/provider-events.jsonl'), 'utf8'),
    /"type":"command_execution"/u);
  assert.equal(fs.existsSync(path.join(value.evidenceRoot, 'capture.json')), false);
});

test('CLI emits only an unreviewed capture summary and refuses overwrite', () => {
  const value = fixture();
  const args = [DRIVER,
    '--root', value.root,
    '--evidence-root', value.evidenceRoot,
    '--codex', value.codexPath,
    '--command', value.commandPath,
    '--model', value.modelId,
    '--timeout-seconds', '30'];
  const first = spawnSync(process.execPath, args, {
    cwd: value.root,
    encoding: 'utf8',
  });
  assert.equal(first.status, 0, first.stderr);
  const summary = JSON.parse(first.stdout);
  assert.equal(summary.status, 'captured-unreviewed');
  assert.equal(summary.case_count, 16);
  assert.equal(summary.evidence_root, undefined);

  const second = spawnSync(process.execPath, args, {
    cwd: value.root,
    encoding: 'utf8',
  });
  assert.equal(second.status, 64);
  assert.match(second.stderr, /must not already exist/u);
});
