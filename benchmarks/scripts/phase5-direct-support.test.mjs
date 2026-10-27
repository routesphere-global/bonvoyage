import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const digest = (value) => createHash('sha256').update(value).digest('hex');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-direct-support-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const repo = path.join(root, 'repo');
  const scripts = path.join(repo, 'benchmarks', 'scripts');
  const bin = path.join(root, 'bin');
  fs.mkdirSync(scripts, {recursive: true});
  fs.mkdirSync(bin);
  for (const name of ['phase5-direct-support.sh', 'phase5-oha-lanes.mjs']) {
    fs.copyFileSync(new URL(name, import.meta.url), path.join(scripts, name));
  }
  fs.chmodSync(path.join(scripts, 'phase5-direct-support.sh'), 0o755);
  const git = (args) => spawnSync('git', args, {cwd: repo, encoding: 'utf8'});
  assert.equal(git(['init', '-q']).status, 0);
  assert.equal(git(['config', 'user.email', 'test@example.invalid']).status, 0);
  assert.equal(git(['config', 'user.name', 'Test']).status, 0);
  assert.equal(git(['add', '.']).status, 0);
  assert.equal(git(['commit', '-qm', 'fixture']).status, 0);
  const commit = git(['rev-parse', 'HEAD']).stdout.trim();
  const runner = fs.readFileSync(path.join(scripts, 'phase5-oha-lanes.mjs'));
  const runnerDigest = digest(runner);
  const ssh = `#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in -o) shift 2 ;; -*) shift ;; *) host="$1"; shift; break ;; esac
done
case "$1" in
  hostname) echo "$host" ;;
  cat) printf 'cpu 100 0 20 200 0 0 10 0\\n' ;;
  git)
    case "$*" in *'rev-parse HEAD'*) echo "$EXPECTED_COMMIT" ;; *'status --porcelain'*) : ;; *) exit 2 ;; esac ;;
  sha256sum) printf '%s  %s\\n' "$EXPECTED_RUNNER" "$2" ;;
  *) exit 2 ;;
esac
`;
  fs.writeFileSync(path.join(bin, 'ssh'), ssh, {mode: 0o755});
  const client = path.join(bin, 'client');
  fs.writeFileSync(client, '#!/bin/sh\nprintf \'{"kind":"diagnostic"}\\n\'\n',
    {mode: 0o755});
  return {root, repo, script: path.join(scripts, 'phase5-direct-support.sh'),
    bin, client, commit, runnerDigest};
}

function run(item, output, client = item.client) {
  return spawnSync(item.script, ['--output', output, '--load-host', 'loadgen',
    '--upstream-host-a', 'upstream-a', '--upstream-host-b', 'upstream-b',
    '--load-repository', '/remote/repo', '--', client], {
    cwd: item.repo, encoding: 'utf8', env: {...process.env,
      PATH: `${item.bin}:${process.env.PATH}`, EXPECTED_COMMIT: item.commit,
      EXPECTED_RUNNER: item.runnerDigest}});
}

test('direct support capture binds source, roles, CPU interval, client, and checksums', (t) => {
  const item = fixture(t);
  const output = path.join(item.root, 'evidence');
  const result = run(item, output);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /DIRECT_SUPPORT_DIR=/u);
  assert.equal(fs.readFileSync(path.join(output, 'source-commit.txt'), 'utf8').trim(),
    item.commit);
  assert.equal(fs.readFileSync(path.join(output,
    'loadgen-runner-sha256-after.txt'), 'utf8').trim(), item.runnerDigest);
  assert.equal(fs.readFileSync(path.join(output, 'client-exit-code.txt'), 'utf8').trim(),
    '0');
  const verified = spawnSync('sha256sum', ['-c', 'checksums.sha256'],
    {cwd: output, encoding: 'utf8'});
  assert.equal(verified.status, 0, verified.stderr);
});

test('failed direct support client retains checksum-bound partial evidence', (t) => {
  const item = fixture(t);
  const failedClient = path.join(item.bin, 'failed-client');
  fs.writeFileSync(failedClient,
    '#!/bin/sh\nprintf \'{"kind":"failed"}\\n\'\nexit 7\n', {mode: 0o755});
  const output = path.join(item.root, 'failed-evidence');
  const result = run(item, output, failedClient);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /checksum-bound partial evidence retained/u);
  assert.equal(fs.readFileSync(path.join(output, 'client-exit-code.txt'), 'utf8').trim(),
    '7');
  assert.ok(fs.existsSync(path.join(output, 'checksums.sha256')));
  const verified = spawnSync('sha256sum', ['-c', 'checksums.sha256'],
    {cwd: output, encoding: 'utf8'});
  assert.equal(verified.status, 0, verified.stderr);
});
