import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import {createRequire} from 'node:module';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../../', import.meta.url));
const require = createRequire(path.join(root, 'package.json'));
const yaml = require('js-yaml');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const logicalLines = source => source.replace(/\\\n/g, ' ').split('\n').map(line => line.trim());
const scripts = fs.readdirSync(path.join(root, 'scripts')).filter(name => /^phase3-.*\.sh$/.test(name)).sort();
const callers = scripts.filter(name => /^bv_stage_fixture_secrets /m.test(read(`scripts/${name}`)));
const mutations = new Set(['phase3-tls-smoke.sh', 'phase3-upstream-tls-smoke.sh',
  'phase3-api-key-smoke.sh', 'phase3-jwt-smoke.sh']);
const noSourceEvidence = new Set(['phase3-tls-smoke.sh', 'phase3-upstream-tls-smoke.sh']);

function references(value, result = new Set()) {
  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      if (key.endsWith('_secret')) {
        assert.equal(typeof child, 'string');
        result.add(child);
      } else references(child, result);
    }
  }
  return [...result].sort();
}

// This is a literal source contract, not a general shell interpreter.
function stages(source) {
  return logicalLines(source).filter(line => line.startsWith('bv_stage_fixture_secrets ')).map(line => {
    const match = line.match(/^bv_stage_fixture_secrets (?:--refresh\s+)?"\$secret_volume" "([^"]+)" "([^"]+)" "\$platform"\s+(.+?)(?:\s+\|\|.*)?$/);
    assert.ok(match, `unsupported staging command: ${line}`);
    const files = match[3].trim().split(/\s+/);
    assert.ok(files.every(file => /^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(file)), line);
    assert.equal(new Set(files).size, files.length, 'duplicate staging basename');
    return {line, directory: match[1], image: match[2], files: files.sort(), refresh: line.includes(' --refresh ')};
  });
}

function fixtureReferences(name, source) {
  const compiler = logicalLines(source).filter(line => /^(?:docker run|docker_run_support) /.test(line) &&
    line.includes(' -input ') && line.includes(' -output '));
  assert.equal(compiler.length, 1, `${name}: one actual compiler input`);
  if (name === 'phase3-http2-deadline.sh') {
    assert.ok(compiler[0].includes('--volume "$evidence/fixture.yaml:/fixture.yaml:ro"'));
    assert.match(source, /"\$client_id" -mode generate >"\$evidence\/fixture.yaml"/);
    // Deadline has no checked-in YAML. Inspect the literal TLS object used by
    // its real Go YAML generator; do not substitute the unrelated HTTP/2 YAML.
    const go = read('tests/fixtures/http2-deadline/main.go');
    const generate = go.match(/func generate\(\) error \{([\s\S]*?)\n\}/)?.[1];
    assert.ok(generate, 'deadline generator is present');
    const objects = [...generate.matchAll(/"downstream_tls":\s*object\{([^{}]+)\}/g)];
    assert.equal(objects.length, 1, 'review new generated TLS objects explicitly');
    const tls = JSON.parse(`{${objects[0][1]}}`);
    return references(tls);
  }
  let fixture = compiler[0].match(/--volume "\$(?:PWD|repo_root)\/(tests\/fixtures\/[^":]+\.yaml):/)?.[1];
  if (!fixture) {
    assert.ok(compiler[0].includes('--volume "$fixture:'), `${name}: unsupported compiler fixture`);
    fixture = source.match(/^fixture="\$repo_root\/(tests\/fixtures\/[^"\n]+\.yaml)"$/m)?.[1];
  }
  assert.ok(fixture, `${name}: actual YAML fixture must be identifiable`);
  return references(yaml.load(read(fixture)));
}

test('all 31 secret consumers are staged, including non-Phase-3-plan hardening', () => {
  assert.equal(callers.length, 31, 'review added or removed callers explicitly');
  const consumers = scripts.filter(name => read(`scripts/${name}`).includes(':/etc/bonvoyage/secrets:ro'));
  assert.deepEqual(consumers, callers);
  assert.match(read('deploy/docker/bonvoyage/Dockerfile'), /^USER 65532:65532$/m);
});

for (const name of callers) {
  const source = read(`scripts/${name}`);
  test(`${name}: allowlists match the actual compiler fixture`, () => {
    const expected = fixtureReferences(name, source);
    assert.ok(expected.length > 0, 'fixture must require secrets');
    const calls = stages(source);
    assert.equal(calls.length, mutations.has(name) ? 2 : 1);
    for (const call of calls) assert.deepEqual(call.files, expected, call.line);
    assert.equal(calls[0].refresh, false, 'initial staging must create a new volume');
    for (const call of calls.slice(1)) {
      assert.equal(call.refresh, true, 'intentional mutations require explicit refresh');
      assert.equal(call.directory, calls[0].directory);
      assert.equal(call.image, calls[0].image);
    }
  });

  test(`${name}: caller context, guarded cleanup and nonroot gateway are preserved`, () => {
    const calls = stages(source), lines = logicalLines(source);
    const sourceIndex = source.search(/^\. "\$(?:PWD\/scripts|script_dir)\/test-fixture-secrets\.sh"$/m);
    assert.ok(sourceIndex >= 0 && sourceIndex < source.indexOf(calls[0].line.split(' ')[0]), 'source helper before use');
    const cdIndex = source.indexOf('\ncd "$repo_root"');
    if (cdIndex >= 0) assert.ok(sourceIndex > cdIndex, 'source helper after repository cd');
    assert.match(source, /^secret_volume="\$\{(?:volume|snapshot_volume)\}-secrets"$/m);
    const cleanups = lines.filter(line => line.startsWith('bv_remove_fixture_secrets '));
    assert.equal(cleanups.length, 1);
    assert.ok(cleanups[0].startsWith(`bv_remove_fixture_secrets "$secret_volume" "${calls[0].directory}" `));
    assert.ok(cleanups[0].endsWith('|| {'), 'cleanup failure must not be silently ignored');
    assert.match(source, /private fixture volume cleanup failed:[^\n]*\n\s*\[ "\$status" -ne 0 \] \|\| status=1/);
    assert.ok(!lines.some(line => line.startsWith('docker volume rm ') && line.includes('"$secret_volume"')),
      'never delete a colliding volume unconditionally');
    const gateways = lines.filter(line => /^(?:docker run|docker_run_gateway) /.test(line) &&
      /--name "\$(?:gateway|invalid_gateway)"/.test(line));
    assert.ok(gateways.length > 0);
    for (const command of gateways) {
      assert.doesNotMatch(command, /(?:^|\s)(?:--user(?:=|\s)|-u(?:=|\s))/);
      assert.ok(command.includes('--volume "$secret_volume:/etc/bonvoyage/secrets:ro"'), command);
    }
    const syntax = spawnSync('sh', ['-n'], {input: source, encoding: 'utf8'});
    assert.equal(syntax.status, 0, syntax.stderr);
  });

  test(`${name}: exit trap propagates secret cleanup failure`, () => {
    const cleanup = source.match(/^cleanup\(\) \{([\s\S]*?)^\}/m)?.[1];
    assert.ok(cleanup, 'cleanup function must be identifiable');
    const removal = cleanup.match(/^  bv_remove_fixture_secrets[^\n]*\|\| \{\n[\s\S]*?^  \}/m)?.[0];
    const terminal = cleanup.trim().split('\n').at(-1).trim();
    assert.ok(removal, 'exercise the actual removal failure block');
    assert.match(terminal, /^(?:exit|return) "\$status"$/);
    // Run the actual error block and terminal statement under a real EXIT
    // trap. A function return alone does not replace the shell's exit status.
    for (const [original, removed, expected] of [[0, 0, 0], [0, 1, 1], [7, 0, 7], [7, 1, 7]]) {
      const fixture = `bv_remove_fixture_secrets() { return ${removed}; }\ncleanup() {\nstatus=$?\n${removal}\n${terminal}\n}\ntrap cleanup EXIT\nexit ${original}\n`;
      const result = spawnSync('sh', ['-c', fixture], {encoding: 'utf8', timeout: 2000});
      assert.equal(result.status, expected, `${name}: original=${original}, removal=${removed}: ${result.stderr}`);
    }
  });

  test(`${name}: retained source evidence binds the helper`, () => {
    if (noSourceEvidence.has(name)) {
      assert.doesNotMatch(source, /source-checksums|input-checksums/);
      return;
    }
    const manifests = [...source.matchAll(/cat >"\$(?:stage_dir|evidence_dir)\/source-files\.txt" <<'EOF'\n([\s\S]*?)\nEOF/g)];
    const listBound = manifests.some(match => match[1].split('\n').includes('scripts/test-fixture-secrets.sh'));
    const lines = logicalLines(source);
    const loopBound = lines.some(line => /^for (?:source|input) in /.test(line) &&
      /(?:^|\s)scripts\/test-fixture-secrets\.sh(?:\s|;)/.test(line));
    const directBound = lines.includes('hash_file "$script_dir/test-fixture-secrets.sh"');
    const copyBound = lines.includes('cp "$script_dir/test-fixture-secrets.sh" "$evidence_dir/test-fixture-secrets.sh"') &&
      lines.some(line => line.includes('fixture_helper_sha256=') && line.includes('$(checksum_value "$script_dir/test-fixture-secrets.sh")'));
    assert.ok(listBound || loopBound || directBound || copyBound, 'include helper in actual source manifest/hash, not just sourcing');
  });
}
