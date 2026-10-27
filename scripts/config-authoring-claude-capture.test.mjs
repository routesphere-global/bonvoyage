import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {spawnSync} from 'node:child_process';
import {afterEach, test} from 'node:test';
import {fileURLToPath} from 'node:url';

import {captureClaudeEvaluation} from
  './capture-claude-config-skill-evaluation.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DRIVER = path.join(ROOT, 'scripts',
  'capture-claude-config-skill-evaluation.mjs');
const PROMPT_REFERENCE_PATHS = Object.freeze([
  'skills/claude/bonvoyage-config-authoring/references/command-surface.md',
  'skills/claude/bonvoyage-config-authoring/references/completion.json',
  'skills/claude/bonvoyage-config-authoring/references/configuration-schema.json',
  'skills/claude/bonvoyage-config-authoring/references/snippets.json',
]);
const temporaryRoots = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

function temporaryRoot() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-claude-capture-test-'));
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

function claudeFixture(root, scenario = 'normal', version = '2.1.259 (Claude Code)') {
  return executable(root, 'claude', `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
if (args[0] === '--version') {
  if (process.env.ANTHROPIC_API_KEY !== undefined) {
    process.stderr.write('provider credential reached version preflight\\n');
    process.exit(74);
  }
  process.stdout.write(${JSON.stringify(version)} + '\\n');
  process.exit(0);
}
const requiredFlags = [
  '--bare', '--restricted', '--print', '--verbose', '--strict-mcp-config',
  '--disable-slash-commands', '--no-session-persistence', '--no-chrome'
];
const requiredPairs = new Map([
  ['--output-format', 'stream-json'],
  ['--model', 'claude-test-model'],
  ['--max-turns', '1'],
  ['--permission-mode', 'dontAsk'],
  ['--permission-prompts', 'none'],
  ['--setting-sources', ''],
  ['--mcp-config', '{"mcpServers":{}}'],
  ['--tools', ''],
  ['--disallowedTools', '*,mcp__*']
]);
const pairMissing = [...requiredPairs].some(([name, value]) => {
  const index = args.indexOf(name);
  return index < 0 || args[index + 1] !== value;
});
if (requiredFlags.some((flag) => !args.includes(flag)) || pairMissing ||
    args.some((value) => value.includes('Case ID:'))) {
  process.stderr.write('capture flags or stdin transport are unsafe\\n');
  process.exit(72);
}
if (process.env.ANTHROPIC_API_KEY !== 'test-provider-key' ||
    process.env.BONVOYAGE_CAPTURE_SENTINEL !== undefined ||
    process.env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC !== '1' ||
    process.env.CLAUDE_CODE_SKIP_PROMPT_HISTORY !== '1' ||
    process.env.DISABLE_AUTOUPDATER !== '1' ||
    !process.env.HOME.includes('bonvoyage-claude-home-') ||
    !process.env.TMPDIR.startsWith(process.env.HOME)) {
  process.stderr.write('capture environment is unsafe\\n');
  process.exit(73);
}
const prompt = fs.readFileSync(0, 'utf8');
const match = prompt.match(/Case ID: ([a-z0-9-]+)/);
const id = match ? match[1] : 'unknown';
const scenario = ${JSON.stringify(scenario)};
if (scenario === 'failed') {
  process.stdout.write(JSON.stringify({type: 'system', subtype: 'error',
    error: 'synthetic failure', session_id: 'session-' + id}) + '\\n');
  process.stderr.write('synthetic provider failure\\n');
  process.exit(9);
}
if (scenario === 'malformed') {
  process.stdout.write('not-json\\n');
  process.exit(0);
}
const sessionId = scenario === 'reused-session' ? 'session-reused' : 'session-' + id;
const tools = scenario === 'tool-inventory' ? ['Read'] : [];
const mcpServers = scenario === 'mcp-inventory' ? [{name: 'unsafe'}] : [];
const init = {type: 'system', subtype: 'init', session_id: sessionId,
  tools, mcp_servers: mcpServers, model: 'claude-test-model', permissionMode: 'dontAsk'};
const response = 'reviewed response for ' + id;
const content = scenario === 'tool-attempt'
  ? [{type: 'tool_use', id: 'tool-1', name: 'Read', input: {file_path: '/etc/passwd'}}]
  : [{type: 'text', text: response}];
const assistant = {type: 'assistant', session_id: sessionId, parent_tool_use_id: null,
  message: {role: 'assistant', content}};
const events = [init, assistant];
const denials = scenario === 'permission-denial' ? [{tool_name: 'Read'}] : [];
if (scenario === 'permission-denial') {
  events.push({type: 'system', subtype: 'permission_denied', session_id: sessionId});
}
events.push({
  type: 'result', subtype: 'success', is_error: false, num_turns: 1,
  result: scenario === 'mismatch' ? response + ' changed' : response,
  session_id: sessionId, total_cost_usd: 0.01, permission_denials: denials,
  usage: {input_tokens: 100, cache_creation_input_tokens: 20,
    cache_read_input_tokens: 30, output_tokens: 10}
});
for (const event of events) process.stdout.write(JSON.stringify(event) + '\\n');
`);
}

function sanitizedRoot() {
  const root = temporaryRoot();
  const wrapperPath = 'config/authoring/skills/v1/wrappers/claude.json';
  const wrapper = JSON.parse(fs.readFileSync(path.join(ROOT, wrapperPath), 'utf8'));
  const paths = new Set([
    wrapperPath,
    'config/authoring/skills/v1/evaluations/manifest.json',
    'config/schemas/bonvoyage-authoring-skill-evaluations-v1.schema.json',
    'config/schemas/bonvoyage-authoring-skill-evaluation-result-v1.schema.json',
    'config/schemas/bonvoyage-authoring-claude-wrapper-v1.schema.json',
    'config/schemas/bonvoyage-authoring-claude-capture-v1.schema.json',
    'scripts/assemble-config-skill-evaluation.mjs',
    'scripts/capture-claude-config-skill-evaluation.mjs',
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
    claudePath: claudeFixture(tools, options.scenario, options.version),
    commandPath: commandFixture(tools),
    modelId: 'claude-test-model',
    providerApiKey: 'test-provider-key',
    timeoutSeconds: 30,
    now: (() => {
      const values = [new Date('2026-10-10T00:00:00.000Z'),
        new Date('2026-10-10T00:01:00.000Z')];
      return () => values.shift() ?? values.at(-1);
    })(),
  };
}

test('captures all 16 Claude cases with isolated tools, state and evidence', () => {
  process.env.BONVOYAGE_CAPTURE_SENTINEL = 'must-not-cross';
  try {
    const value = fixture();
    const result = captureClaudeEvaluation(value);
    assert.equal(result.capture.cases.length, 16);
    assert.equal(result.capture.claude_cli_version, '2.1.259 (Claude Code)');
    assert.match(result.capture.claude_cli_sha256, /^[0-9a-f]{64}$/u);
    assert.deepEqual(result.capture.execution.built_in_tools, []);
    assert.deepEqual(result.capture.execution.settings_sources, []);
    assert.equal(result.capture.execution.mcp_server_count, 0);
    assert.equal(result.capture.execution.expected_answers_exposed, false);
    assert.equal(result.capture.execution.automatic_retry, false);
    assert.equal(result.capture.execution.host_network_isolation,
      'not-established-by-adapter');
    assert.deepEqual(result.capture.execution.embedded_reference_paths,
      PROMPT_REFERENCE_PATHS);
    assert.equal(fs.statSync(value.evidenceRoot).mode & 0o777, 0o700);
    assert.equal(fs.statSync(path.join(value.evidenceRoot, 'capture.json')).mode & 0o777,
      0o600);

    const manifest = JSON.parse(fs.readFileSync(
      path.join(value.root, 'config/authoring/skills/v1/evaluations/manifest.json'), 'utf8'));
    const sessionIds = new Set();
    for (const captured of result.capture.cases) {
      sessionIds.add(captured.session_id);
      const source = manifest.cases.find((entry) => entry.id === captured.id);
      const prompt = fs.readFileSync(path.join(value.evidenceRoot, captured.prompt_path),
        'utf8');
      assert.match(prompt, new RegExp(`Case ID: ${captured.id}`, 'u'));
      assert.match(prompt, /disables shell, file, web, MCP/u);
      assert.match(prompt, /candidate_document is the exact complete in-memory YAML/u);
      assert.match(prompt,
        /BEGIN EXACT skills\/claude\/bonvoyage-config-authoring\/SKILL\.md/u);
      for (const referencePath of PROMPT_REFERENCE_PATHS) {
        const referenceText = fs.readFileSync(
          path.join(value.root, ...referencePath.split('/')), 'utf8');
        assert.equal(prompt.includes([
          `---BEGIN EXACT ${referencePath}---`,
          referenceText,
          `---END EXACT ${referencePath}---`,
        ].join('\n')), true);
      }
      assert.equal(prompt.includes(
        'BEGIN EXACT config/authoring/skills/v1/evaluations/manifest.json'), false);
      assert.equal(prompt.includes(JSON.stringify(source.expected)), false);
      assert.equal(prompt.includes(source.purpose), false);
      const actions = JSON.parse(fs.readFileSync(
        path.join(value.evidenceRoot, captured.action_log_path), 'utf8'));
      assert.deepEqual(actions.map((entry) => entry.type), ['system', 'assistant', 'result']);
      assert.equal(actions.some((entry) => Object.hasOwn(entry, 'thinking')), false);
      assert.equal(fs.readFileSync(
        path.join(value.evidenceRoot, captured.transcript_path), 'utf8'),
      `reviewed response for ${captured.id}`);
      assert.equal(captured.total_cost_usd, 0.01);
    }
    assert.equal(sessionIds.size, 16);
    assert.match(result.captureSha256, /^[0-9a-f]{64}$/u);
  } finally {
    delete process.env.BONVOYAGE_CAPTURE_SENTINEL;
  }
});

test('rejects absent credentials and unsupported Claude versions before capture', () => {
  {
    const value = fixture();
    value.providerApiKey = '';
    assert.throws(() => captureClaudeEvaluation(value), /ANTHROPIC_API_KEY/u);
    assert.equal(fs.existsSync(value.evidenceRoot), false);
  }
  {
    const value = fixture({version: '2.1.258 (Claude Code)'});
    assert.throws(() => captureClaudeEvaluation(value), /2\.1\.259 or newer/u);
    assert.equal(fs.existsSync(value.evidenceRoot), false);
  }
  {
    const value = fixture({version: 'unexpected'});
    assert.throws(() => captureClaudeEvaluation(value), /unsupported format/u);
    assert.equal(fs.existsSync(value.evidenceRoot), false);
  }
});

test('rejects unsafe roots, command identities and model IDs before capture', () => {
  {
    const value = fixture();
    fs.mkdirSync(value.evidenceRoot);
    assert.throws(() => captureClaudeEvaluation(value), /must not already exist/u);
  }
  {
    const value = fixture();
    value.modelId = 'sonnet';
    assert.throws(() => captureClaudeEvaluation(value), /explicit Claude model/u);
  }
  {
    const value = fixture();
    const renamed = path.join(path.dirname(value.commandPath), 'wrong-name');
    fs.renameSync(value.commandPath, renamed);
    value.commandPath = renamed;
    assert.throws(() => captureClaudeEvaluation(value), /must be named bonvoyage-config/u);
  }
  {
    const value = fixture();
    fs.mkdirSync(path.join(value.root, '.git'));
    assert.throws(() => captureClaudeEvaluation(value), /sanitized no-Git/u);
  }
  {
    const value = fixture();
    value.evidenceRoot = path.join(value.root, 'private-evidence');
    assert.throws(() => captureClaudeEvaluation(value), /must not overlap/u);
  }
});

test('retains raw provider output before rejecting malformed or failed runs', () => {
  {
    const value = fixture({scenario: 'malformed'});
    assert.throws(() => captureClaudeEvaluation(value), /malformed JSON events/u);
    assert.equal(fs.readFileSync(path.join(value.evidenceRoot,
      'cases/ambiguous-requirements-backend/provider-events.jsonl'), 'utf8'), 'not-json\n');
    assert.match(JSON.parse(fs.readFileSync(
      path.join(value.evidenceRoot, 'capture-failure.json'), 'utf8')).message,
    /malformed JSON events/u);
  }
  {
    const value = fixture({scenario: 'failed'});
    assert.throws(() => captureClaudeEvaluation(value), /failed .* status 9/u);
    assert.match(fs.readFileSync(path.join(value.evidenceRoot,
      'cases/ambiguous-requirements-backend/provider-events.jsonl'), 'utf8'),
    /synthetic failure/u);
    assert.equal(fs.readFileSync(path.join(value.evidenceRoot,
      'cases/ambiguous-requirements-backend/provider-stderr.txt'), 'utf8'),
    'synthetic provider failure\n');
  }
});

test('fails closed for tools, MCP servers and permission denials', () => {
  for (const [scenario, message] of [
    ['tool-attempt', /attempted a disabled tool/u],
    ['tool-inventory', /exposed a disabled tool or MCP/u],
    ['mcp-inventory', /exposed a disabled tool or MCP/u],
    ['permission-denial', /unsupported event|denied capability/u],
  ]) {
    const value = fixture({scenario});
    assert.throws(() => captureClaudeEvaluation(value), message, scenario);
    assert.equal(fs.existsSync(path.join(value.evidenceRoot, 'capture.json')), false);
    assert.equal(fs.existsSync(path.join(value.evidenceRoot,
      'cases/ambiguous-requirements-backend/provider-events.jsonl')), true);
  }
});

test('rejects transcript disagreement and cross-case session reuse', () => {
  {
    const value = fixture({scenario: 'mismatch'});
    assert.throws(() => captureClaudeEvaluation(value), /transcript and final event disagree/u);
  }
  {
    const value = fixture({scenario: 'reused-session'});
    assert.throws(() => captureClaudeEvaluation(value), /reused a session/u);
    assert.equal(fs.existsSync(path.join(value.evidenceRoot, 'capture.json')), false);
  }
});

test('CLI emits only an unreviewed summary and refuses overwrite', () => {
  const value = fixture();
  const args = [DRIVER,
    '--root', value.root,
    '--evidence-root', value.evidenceRoot,
    '--claude', value.claudePath,
    '--command', value.commandPath,
    '--model', value.modelId,
    '--timeout-seconds', '30'];
  const environment = {...process.env, ANTHROPIC_API_KEY: value.providerApiKey};
  const first = spawnSync(process.execPath, args, {
    cwd: value.root,
    encoding: 'utf8',
    env: environment,
  });
  assert.equal(first.status, 0, first.stderr);
  const summary = JSON.parse(first.stdout);
  assert.equal(summary.status, 'captured-unreviewed');
  assert.equal(summary.assistant, 'claude');
  assert.equal(summary.case_count, 16);
  assert.equal(summary.evidence_root, undefined);

  const second = spawnSync(process.execPath, args, {
    cwd: value.root,
    encoding: 'utf8',
    env: environment,
  });
  assert.equal(second.status, 64);
  assert.match(second.stderr, /must not already exist/u);
});
