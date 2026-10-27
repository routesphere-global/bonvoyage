import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {createRequire} from 'node:module';

import {
  REPOSITORY_ROOT,
  digestBuffer,
  inspectValidationCheckDocument,
  inspectValidationPlanDocument,
  inspectValidationReceiptDocument,
  sha256File,
  VALIDATION_RUNTIME_ENVIRONMENT_NAMES,
} from './dedicated-preflight.mjs';
import {
  buildValidationCheckRecord,
  prepareCheckEnvironment,
  validateTestClientPolicy,
} from './dedicated-validation-check.mjs';
import {buildValidationReceipt} from './dedicated-validation-receipt.mjs';

const require = createRequire(path.join(REPOSITORY_ROOT, 'package.json'));
const yaml = require('js-yaml');

function fixture(name) {
  return JSON.parse(fs.readFileSync(
    path.join(REPOSITORY_ROOT, 'benchmarks/spec/fixtures', name),
    'utf8',
  ));
}

function validationPlan() {
  return yaml.load(fs.readFileSync(
    path.join(REPOSITORY_ROOT, 'benchmarks/plans/dedicated-rc-validation-v1.yaml'),
    'utf8',
  ));
}

for (const [profile, variable] of [
  ['upstream-http1', 'BONVOYAGE_UPSTREAM_HTTP1_FUZZ_EVIDENCE_DIR'],
  ['http2', 'BONVOYAGE_HTTP2_FUZZ_EVIDENCE_DIR'],
]) {
  for (const mode of ['relative', 'absolute', 'default']) {
    test(profile + ' fuzz evidence supports ' + mode + ' paths without overwriting', () => {
      const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-fuzz-path-'));
      const repository = path.join(directory, 'repository with spaces');
      const bin = path.join(directory, 'bin');
      const script = 'scripts/phase3-' + profile + '-fuzz.sh';
      fs.mkdirSync(bin, {recursive: true});
      const files = [
        'deploy/docker/bonvoyage/Dockerfile',
        'deploy/docker/bonvoyage/patches/nghttp2-rfc9113-stream-errors.patch',
        'security/dependencies/nghttp2-1.70.0.json',
        'security/dependencies/llhttp-9.4.3.json',
        'dataplane/include/fixture.hh',
        'dataplane/fuzz/fixture.cc',
        'dataplane/src/http2_session.cc',
        'dataplane/src/http2_client_session.cc',
        'dataplane/src/upstream_response_head_parser.cc',
        script,
      ];
      for (const file of files) {
        const destination = path.join(repository, file);
        fs.mkdirSync(path.dirname(destination), {recursive: true});
        fs.writeFileSync(destination, file === script
          ? fs.readFileSync(path.join(REPOSITORY_ROOT, script))
          : 'fixture\n');
      }
      fs.writeFileSync(path.join(bin, 'git'), '#!/bin/sh\ncase "$*" in\n"rev-parse HEAD") printf "fixture-commit\\n" ;;\n"status --porcelain=v1 --untracked-files=all") : ;;\n*) exit 2 ;;\nesac\n');
      fs.chmodSync(path.join(bin, 'git'), 0o755);
      fs.writeFileSync(path.join(bin, 'docker'), [
        '#!/usr/bin/env node',
        "const fs = require('node:fs');",
        "const path = require('node:path');",
        'const args = process.argv.slice(2);',
        "fs.appendFileSync(process.env.FAKE_DOCKER_CALLS, JSON.stringify(args) + '\\n');",
        "if (args[0] === 'info') {",
        "  console.log('amd64');",
        "} else if (args[0] === 'image' && args[1] === 'inspect') {",
        "  console.log('[]');",
        "} else if (args[0] === 'buildx') {",
        "  console.log('fixture build');",
        "} else if (args[0] === 'run') {",
        "  const mount = args[args.indexOf('--volume') + 1];",
        "  const directory = mount.slice(0, -':/evidence'.length);",
        "  if (!mount.endsWith(':/evidence') || !path.isAbsolute(directory)) {",
        "    console.error('Docker bind source must be absolute');",
        '    process.exit(125);',
        '  }',
        "  fs.writeFileSync(path.join(directory, 'fixture-result.txt'), 'fixture passed\\n');",
        '} else {',
        '  process.exit(2);',
        '}',
      ].join('\n'));
      fs.chmodSync(path.join(bin, 'docker'), 0o755);
      const calls = path.join(directory, 'docker-calls.jsonl');
      const environment = {...process.env, PATH: bin + ':' + process.env.PATH,
        FAKE_DOCKER_CALLS: calls};
      delete environment.BONVOYAGE_HTTP2_FUZZ_EVIDENCE_DIR;
      delete environment.BONVOYAGE_UPSTREAM_HTTP1_FUZZ_EVIDENCE_DIR;
      if (mode !== 'default') {
        environment[variable] = mode === 'relative'
          ? 'build/fuzz evidence'
          : path.join(directory, 'absolute evidence');
      }
      const invoke = () => spawnSync('/bin/sh', [path.join(repository, script)],
        {cwd: directory, env: environment, encoding: 'utf8'});
      try {
        const result = invoke();
        assert.equal(result.status, 0, result.stdout + result.stderr);
        const commands = fs.readFileSync(calls, 'utf8').trim().split('\n').map(line => JSON.parse(line));
        const run = commands.find(args => args[0] === 'run');
        assert.ok(run);
        const evidence = run[run.indexOf('--volume') + 1].slice(0, -':/evidence'.length);
        const expected = mode === 'relative' ? path.join(repository, 'build/fuzz evidence')
          : mode === 'absolute' ? environment[variable] : evidence;
        assert.equal(evidence, fs.realpathSync(expected));
        if (mode === 'default') {
          assert.ok(evidence.startsWith(fs.realpathSync(repository) + '/build/evidence/phase3-' + profile + '-fuzz/'));
        }
        const before = fs.readFileSync(path.join(evidence, 'SHA256SUMS'), 'utf8');
        const callsBefore = fs.readFileSync(calls, 'utf8');
        environment[variable] = evidence;
        const repeated = invoke();
        assert.notEqual(repeated.status, 0);
        assert.match(repeated.stderr, /evidence directory already exists/);
        assert.equal(fs.readFileSync(path.join(evidence, 'SHA256SUMS'), 'utf8'), before);
        assert.equal(fs.readFileSync(calls, 'utf8'), callsBefore);
      } finally {
        fs.rmSync(directory, {recursive: true, force: true});
      }
    });
  }
}

test('validation plan contains every required check and no shell command', () => {
  const plan = validationPlan();
  assert.deepEqual(
    inspectValidationPlanDocument(plan, {campaignId: plan.campaign_id}),
    {valid: true, errors: []},
  );

  const missing = structuredClone(plan);
  missing.checks = missing.checks.filter(({id}) => id !== 'http2-fuzz');
  assert.match(
    inspectValidationPlanDocument(missing).errors.join('\n'),
    /missing http2-fuzz/,
  );

  const shell = structuredClone(plan);
  shell.checks[0].command.argv = ['sh', '-c', 'make config-validate'];
  assert.match(
    inspectValidationPlanDocument(shell).errors.join('\n'),
    /shell interpreter/,
  );
});

test('derived and fixed check environments are explicit and deterministic', () => {
  const check = validationPlan().checks.find(({id}) => id === 'asan-ubsan');
  const directory = 'benchmarks/results/local-archives/fixture/asan-ubsan';
  const environment = prepareCheckEnvironment(check, directory, {});
  assert.equal(
    environment.BONVOYAGE_SANITIZER_EVIDENCE_ROOT,
    'benchmarks/results/local-archives/fixture/asan-ubsan/evidence/sanitizer-evidence-root',
  );
  assert.equal(
    environment.BONVOYAGE_SANITIZER_EVIDENCE_ID,
    'sanitizers-dedicated-rc',
  );
});

test('integration client policy is fixed, non-root and immune to ambient overrides', () => {
  const plan = validationPlan();
  const check = plan.checks.find(({id}) => id === 'phase3-integration');
  const productLock = JSON.parse(fs.readFileSync(path.join(REPOSITORY_ROOT, 'benchmarks/products/lock.json')));
  const client = productLock.load_generator;
  const reference = `${client.repository}@${client.manifests.linux_amd64}`;
  const env = prepareCheckEnvironment(check, 'test', {
    BONVOYAGE_OHA_IMAGE: 'custom-client:latest', BONVOYAGE_RC_TEST_CLIENT_USER: '0:0',
  });
  assert.equal(env.BONVOYAGE_OHA_IMAGE, reference);
  assert.equal(env.BONVOYAGE_RC_TEST_CLIENT_USER, '65532:65532');
  for (const change of [{BONVOYAGE_OHA_IMAGE: 'custom:latest'},
    {BONVOYAGE_RC_TEST_CLIENT_USER: '0:0'}, {BONVOYAGE_RC_TEST_CLIENT_USER: undefined}]) {
    const altered = structuredClone(plan);
    Object.assign(altered.checks.find(({id}) => id === check.id).fixed_environment, change);
    assert.equal(inspectValidationPlanDocument(altered).valid, false);
  }
});

test('client identity must match the stock product lock, artifact lock and actual executor', () => {
  const check = validationPlan().checks.find(({id}) => id === 'phase3-integration');
  const productLock = JSON.parse(fs.readFileSync(path.join(REPOSITORY_ROOT, 'benchmarks/products/lock.json')));
  const reference = check.fixed_environment.BONVOYAGE_OHA_IMAGE;
  const digest = productLock.load_generator.manifests.linux_amd64;
  const inspection = {Id: digest, Os: 'linux', Architecture: 'amd64',
    Config: {User: '65535'}, Descriptor: {mediaType: 'application/vnd.oci.image.manifest.v1+json', digest}};
  const lock = {artifacts: [{id: 'load-generator', image_reference: reference,
    image_digest: digest, platform_digest: digest}]};
  const validate = (l = lock, i = inspection, user = '65532:65532', c = check) =>
    validateTestClientPolicy(c, l, productLock, i, user);
  assert.equal(validate().image_default_user, '65535');
  assert.equal(validate().executor_user, '65532:65532');
  for (const user of ['0:0', '65535:65535', '65532:0', '1000:1000']) {
    assert.throws(() => validate(lock, inspection, user), /executor UID\/GID/);
  }
  for (const change of [{image_reference: 'custom:latest'},
    {image_digest: `sha256:${'1'.repeat(64)}`}, {platform_digest: `sha256:${'1'.repeat(64)}`}]) {
    assert.throws(() => validate({artifacts: [{...lock.artifacts[0], ...change}]}), /locked stock/);
  }
  assert.throws(() => validate({artifacts: []}), /locked stock/);
  assert.throws(() => validate(lock, {...inspection, Architecture: 'arm64'}), /linux\/amd64/);
  assert.throws(() => validate(lock, {...inspection, Id: `sha256:${'2'.repeat(64)}`}), /locked stock/);
  assert.throws(() => validate(lock, inspection, '65532:65532', {...check,
    fixed_environment: {...check.fixed_environment, BONVOYAGE_OHA_IMAGE: 'custom:latest'}}), /stock pinned/);
});

test('combined deadline and Cookie targets preserve separate exclusive evidence paths', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-cookie-evidence-'));
  const evidence = path.join(directory, 'private evidence');
  try {
    fs.mkdirSync(path.join(directory, 'scripts'));
    fs.writeFileSync(path.join(directory, 'scripts/phase3-http2-deadline.sh'),
      '#!/bin/sh\nset -eu\numask 077\n' +
      'output="${BONVOYAGE_HTTP2_DEADLINE_EVIDENCE_DIR:-$(mktemp -d)}"\n' +
      'mkdir -p "$output"\n(set -C; printf "%s\\n" "$1" >"$output/mode")\n', {mode: 0o755});
    const run = () => spawnSync('make', ['--no-print-directory', '-f',
      path.join(REPOSITORY_ROOT, 'Makefile'), '-o', 'dataplane-build',
      'dataplane-http2-deadline', 'dataplane-http2-cookie'], {
      cwd: directory, encoding: 'utf8',
      env: {...process.env, BONVOYAGE_HTTP2_DEADLINE_EVIDENCE_DIR: evidence},
    });
    const first = run();
    assert.equal(first.status, 0, first.stderr);
    assert.equal(fs.readFileSync(path.join(evidence, 'mode'), 'utf8'), 'all\n');
    assert.equal(fs.readFileSync(path.join(`${evidence}-cookie`, 'mode'), 'utf8'), 'cookie\n');
    assert.notEqual(run().status, 0, 'reused evidence must still fail closed');
    assert.equal(fs.readFileSync(path.join(evidence, 'mode'), 'utf8'), 'all\n');
    assert.equal(fs.readFileSync(path.join(`${evidence}-cookie`, 'mode'), 'utf8'), 'cookie\n');
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
});

test('HTTP/2 deadline evidence writers explicitly use the caller UID/GID', () => {
  const script = path.join(REPOSITORY_ROOT, 'scripts/phase3-http2-deadline.sh');
  const lines = fs.readFileSync(script, 'utf8').split('\n');
  let writers = 0;
  for (let i = 0; i < lines.length; i += 1) {
    if (!/^\s*docker run /u.test(lines[i])) continue;
    let command = lines[i];
    while (lines[i].endsWith('\\')) command += `\n${lines[++i]}`;
    if (!command.includes('"$client_id"') || !command.includes(':/evidence"')) continue;
    writers += 1;
    assert.equal(command.split('--user').length, 2, 'one explicit writer user required');
    assert.ok(command.includes('--user "$(id -u):$(id -g)"'), 'evidence must remain caller-owned');
    assert.ok(command.indexOf('--user') < command.indexOf('"$client_id"'), 'user must be a Docker option');
  }
  assert.equal(writers, 2, 'exercise both per-case and final-metrics writers');
  assert.equal(spawnSync('sh', ['-n', script]).status, 0);
});

test('all Phase 3 private-volume oha launches explicitly use the caller UID/GID', () => {
  let count = 0;
  const scripts = path.join(REPOSITORY_ROOT, 'scripts');
  for (const name of fs.readdirSync(scripts).filter(n => /^phase3-.*\.sh$/u.test(n))) {
    const lines = fs.readFileSync(path.join(scripts, name), 'utf8').split('\n');
    for (let i = 0; i < lines.length; i += 1) {
      if (!/^\s*docker run /u.test(lines[i])) continue;
      let command = lines[i];
      while (lines[i].endsWith('\\')) command += `\n${lines[++i]}`;
      if (!/"\$oha_image(?:_id)?"/u.test(command) || !command.includes('--volume')) continue;
      count += 1;
      assert.equal(command.split('--user').length, 2, `${name}: one explicit user required`);
      assert.ok(command.includes('--user "$(id -u):$(id -g)"'), `${name}: must use caller UID/GID`);
      assert.match(command, /--volume "[^"\n]+:ro"/u, `${name}: private volume must be read-only`);
    }
    assert.equal(spawnSync('sh', ['-n', path.join(scripts, name)]).status, 0, `${name}: syntax`);
  }
  assert.ok(count >= 24, `expected private-fixture launchers, found ${count}`);
});

test('integration receipt binds the selected client and executor policy', () => {
  const document = fixture('dedicated-validation-check.valid.json');
  const planCheck = validationPlan().checks.find(({id}) => id === 'phase3-integration');
  const lock = fixture('dedicated-artifact-lock.valid.json');
  lock.artifacts.find(({id}) => id === 'load-generator').image_reference = planCheck.fixed_environment.BONVOYAGE_OHA_IMAGE;
  document.check_id = planCheck.id;
  document.command = planCheck.command;
  document.environment = document.environment.filter(({name}) => VALIDATION_RUNTIME_ENVIRONMENT_NAMES.includes(name));
  for (const [name, value] of Object.entries(prepareCheckEnvironment(planCheck, 'check', {}))) {
    document.environment.push({name, value_sha256: digestBuffer(value)});
  }
  const context = {planCheck, artifactLock: {...document.artifact_lock, document: lock}};
  assert.deepEqual(inspectValidationCheckDocument(document, context), {valid: true, errors: []});
  for (const name of ['BONVOYAGE_OHA_IMAGE', 'BONVOYAGE_RC_TEST_CLIENT_USER']) {
    const altered = structuredClone(document);
    altered.environment.find(e => e.name === name).value_sha256 = digestBuffer('override');
    assert.equal(inspectValidationCheckDocument(altered, context).valid, false);
  }
  lock.artifacts.find(({id}) => id === 'load-generator').image_reference = 'custom:latest';
  assert.match(inspectValidationCheckDocument(document, context).errors.join('\n'), /test client differs/);
});

test('check record binds exact command, environment, source, and runtime image', () => {
  const document = fixture('dedicated-validation-check.valid.json');
  const planCheck = validationPlan().checks.find(
    ({id}) => id === document.check_id,
  );
  const lockDocument = fixture('dedicated-artifact-lock.valid.json');
  const context = {
    campaignId: document.campaign_id,
    sourceCommit: document.source_commit,
    artifactLock: {...document.artifact_lock, document: lockDocument},
    validationPlan: document.validation_plan,
    planCheck,
  };
  assert.deepEqual(
    inspectValidationCheckDocument(document, context),
    {valid: true, errors: []},
  );

  const wrongCommand = structuredClone(document);
  wrongCommand.command.argv = ['make', 'test'];
  const commandInspection = inspectValidationCheckDocument(wrongCommand, context);
  assert.match(commandInspection.errors.join('\n'), /command differs/);

  const wrongImage = structuredClone(document);
  wrongImage.runtime_image.image_digest_after = `sha256:${'0'.repeat(64)}`;
  const imageInspection = inspectValidationCheckDocument(wrongImage, context);
  assert.match(imageInspection.errors.join('\n'), /locked runtime image/);
});

test('receipt verification requires intact before/after test-client observations', () => {
  const archive = path.join(REPOSITORY_ROOT, 'benchmarks/results/local-archives');
  fs.mkdirSync(archive, {recursive: true});
  const directory = fs.mkdtempSync(path.join(archive, 'client-policy-test-'));
  fs.mkdirSync(path.join(directory, 'evidence'));
  try {
    const relative = path.relative(REPOSITORY_ROOT, directory).split(path.sep).join('/');
    const document = fixture('dedicated-validation-check.valid.json');
    const check = validationPlan().checks.find(({id}) => id === 'phase3-integration');
    const lock = fixture('dedicated-artifact-lock.valid.json');
    const client = lock.artifacts.find(({id}) => id === 'load-generator');
    client.image_reference = check.fixed_environment.BONVOYAGE_OHA_IMAGE;
    document.check_id = check.id;
    document.command = check.command;
    document.environment = document.environment.filter(({name}) => VALIDATION_RUNTIME_ENVIRONMENT_NAMES.includes(name));
    for (const [name, value] of Object.entries(prepareCheckEnvironment(check, relative, {}))) {
      document.environment.push({name, value_sha256: digestBuffer(value)});
    }
    const observation = {policy: 'stock-image-explicit-caller-uid-v1', executor_user: '65532:65532',
      reference: client.image_reference, image_digest: client.image_digest,
      platform_digest: client.platform_digest, image_default_user: '65535'};
    const writeObservation = (stage, data) => {
      const name = `evidence/test-client-${stage}.json`;
      fs.writeFileSync(path.join(directory, name), JSON.stringify(data));
      return {path: `${relative}/${name}`, sha256: sha256File(path.join(directory, name))};
    };
    document.evidence = ['before', 'after'].map(stage => writeObservation(stage, observation));
    const context = {planCheck: check, artifactLock: {...document.artifact_lock, document: lock},
      recordPath: `${relative}/check.json`, verifyEvidence: true};
    assert.deepEqual(inspectValidationCheckDocument(document, context), {valid: true, errors: []});
    const missing = structuredClone(document);
    missing.evidence.pop();
    assert.match(inspectValidationCheckDocument(missing, context).errors.join('\n'), /missing test-client after/);
    for (const change of [{executor_user: '0:0'}, {image_digest: `sha256:${'f'.repeat(64)}`},
      {reference: 'custom:latest'}, {policy: 'unverified'}]) {
      document.evidence[1] = writeObservation('after', {...observation, ...change});
      assert.match(inspectValidationCheckDocument(document, context).errors.join('\n'), /test-client after evidence differs/);
    }
    document.evidence[1] = writeObservation('after', {...observation, image_default_user: '0'});
    assert.match(inspectValidationCheckDocument(document, context).errors.join('\n'), /identity changed/);
    document.evidence[1] = writeObservation('after', observation);
    fs.appendFileSync(path.join(directory, 'evidence/test-client-after.json'), '\n');
    assert.match(inspectValidationCheckDocument(document, context).errors.join('\n'), /SHA-256/);
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
});

test('check evidence digest mismatch fails closed', () => {
  const archiveRoot = path.join(
    REPOSITORY_ROOT,
    'benchmarks/results/local-archives',
  );
  fs.mkdirSync(archiveRoot, {recursive: true});
  const directory = fs.mkdtempSync(path.join(archiveRoot, 'validation-test-'));
  try {
    const evidencePath = path.join(directory, 'command.log');
    fs.writeFileSync(evidencePath, 'original\n');
    const document = fixture('dedicated-validation-check.valid.json');
    document.evidence = [{
      path: path.relative(REPOSITORY_ROOT, evidencePath).split(path.sep).join('/'),
      sha256: sha256File(evidencePath),
    }];
    fs.writeFileSync(evidencePath, 'altered\n');
    const inspection = inspectValidationCheckDocument(document, {
      verifyEvidence: true,
    });
    assert.equal(inspection.valid, false);
    assert.match(inspection.errors.join('\n'), /retained SHA-256 digest/);
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
});

test('locked-image guard accepts an exact image and rejects substitution', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-docker-'));
  const fakeDocker = path.join(directory, 'docker');
  const digest = `sha256:${'1'.repeat(64)}`;
  fs.writeFileSync(fakeDocker, `#!/bin/sh
case "$*" in
  *"{{.Id}}"*) printf '%s\\n' "$FAKE_DOCKER_ID" ;;
  *"{{.Os}}/{{.Architecture}}"*) printf '%s\\n' "linux/amd64" ;;
  *) exit 2 ;;
esac
`);
  fs.chmodSync(fakeDocker, 0o755);
  const invoke = (expected) => spawnSync(
    path.join(REPOSITORY_ROOT, 'scripts/require-locked-dataplane-image.sh'),
    [],
    {
      cwd: REPOSITORY_ROOT,
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${directory}:${process.env.PATH}`,
        FAKE_DOCKER_ID: digest,
        BONVOYAGE_DATAPLANE_IMAGE: 'bonvoyage:test',
        BONVOYAGE_LOCKED_DATAPLANE_IMAGE_ID: expected,
      },
    },
  );
  try {
    assert.equal(invoke(digest).status, 0);
    const rejected = invoke(`sha256:${'2'.repeat(64)}`);
    assert.equal(rejected.status, 1);
    assert.match(rejected.stderr, /locked dataplane image mismatch/);
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
});

test('check record builder hashes environment values without retaining values', () => {
  const planCheck = validationPlan().checks.find(({id}) => id === 'http2-fuzz');
  const digest = `sha256:${'1'.repeat(64)}`;
  const record = buildValidationCheckRecord({
    check: planCheck,
    campaignId: 'phase1-phase3-dedicated-qualification-v1',
    sourceCommit: 'a'.repeat(40),
    artifactLock: {path: 'evidence/lock.json', sha256: 'b'.repeat(64)},
    validationPlan: {path: 'evidence/plan.yaml', sha256: 'c'.repeat(64)},
    startedAt: '2026-09-05T00:00:00Z',
    completedAt: '2026-09-05T00:01:00Z',
    environment: {
      BONVOYAGE_HTTP2_FUZZ_EVIDENCE_DIR: '/private/evidence/path',
      BONVOYAGE_HTTP2_FUZZ_SECONDS: '30',
    },
    runtimeReference: 'bonvoyage:rc',
    runtimeDigestBefore: digest,
    runtimeDigestAfter: digest,
    remoteRef: 'origin/main',
    evidence: [{path: 'evidence/command.log', sha256: 'd'.repeat(64)}],
  });
  assert.equal(record.environment.length, 2);
  assert.equal(
    record.environment.find(({name}) => name === 'BONVOYAGE_HTTP2_FUZZ_SECONDS')
      .value_sha256,
    digestBuffer('30'),
  );
  assert.equal(JSON.stringify(record).includes('/private/evidence/path'), false);
});

test('receipt identity is deterministic and missing checks fail closed', () => {
  const fixtureReceipt = fixture('dedicated-validation-receipt.valid.json');
  const baseCheck = fixture('dedicated-validation-check.valid.json');
  const records = fixtureReceipt.checks.map((check, index) => ({
    reference: check.record,
    document: {
      ...structuredClone(baseCheck),
      check_id: check.id,
      started_at: `2026-09-05T00:${String(index).padStart(2, '0')}:00Z`,
      completed_at: `2026-09-05T00:${String(index + 1).padStart(2, '0')}:00Z`,
      evidence: check.evidence,
    },
  }));
  const first = buildValidationReceipt({
    campaignId: fixtureReceipt.campaign_id,
    sourceCommit: fixtureReceipt.source_commit,
    artifactLock: fixtureReceipt.artifact_lock,
    validationPlan: fixtureReceipt.validation_plan,
    records,
  });
  const second = buildValidationReceipt({
    campaignId: fixtureReceipt.campaign_id,
    sourceCommit: fixtureReceipt.source_commit,
    artifactLock: fixtureReceipt.artifact_lock,
    validationPlan: fixtureReceipt.validation_plan,
    records,
  });
  assert.equal(first.receipt_id, second.receipt_id);
  assert.equal(first.checks.length, 13);

  first.checks = first.checks.filter(({id}) => id !== 'http2-fuzz');
  const inspection = inspectValidationReceiptDocument(first);
  assert.equal(inspection.valid, false);
  assert.match(inspection.errors.join('\n'), /missing http2-fuzz/);
});
