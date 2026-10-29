import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {afterEach, test} from 'node:test';

import {verifyRange} from './verify-dco-signoffs.mjs';

const roots = [];

afterEach(() => {
  while (roots.length > 0) {
    fs.rmSync(roots.pop(), {recursive: true, force: true});
  }
});

function git(root, args, {name = 'Alice Example', email = 'alice@example.test'} = {}) {
  const result = spawnSync('git', [
    '-c', `user.name=${name}`,
    '-c', `user.email=${email}`,
    ...args,
  ], {cwd: root, encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function repository() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-dco-'));
  roots.push(root);
  git(root, ['init', '--initial-branch=main']);
  fs.writeFileSync(path.join(root, 'value.txt'), 'base\n');
  git(root, ['add', 'value.txt']);
  git(root, ['commit', '-m', 'base\n\nSigned-off-by: Alice Example <alice@example.test>']);
  return root;
}

function commit(root, text, message, identity) {
  fs.appendFileSync(path.join(root, 'value.txt'), `${text}\n`);
  git(root, ['add', 'value.txt'], identity);
  git(root, ['commit', '-m', message], identity);
  return git(root, ['rev-parse', 'HEAD']);
}

test('accepts every non-merge commit signed by its author', () => {
  const root = repository();
  const base = git(root, ['rev-parse', 'HEAD']);
  commit(root, 'one', 'one\n\nSigned-off-by: Alice Example <alice@example.test>');
  const head = commit(
    root,
    'two',
    'two\n\nSigned-off-by: Bob Example <bob@example.test>',
    {name: 'Bob Example', email: 'bob@example.test'},
  );
  assert.equal(verifyRange({base, head, repository: root}).commits.length, 2);
});

test('rejects a missing sign-off', () => {
  const root = repository();
  const base = git(root, ['rev-parse', 'HEAD']);
  const head = commit(root, 'unsigned', 'unsigned');
  assert.throws(
    () => verifyRange({base, head, repository: root}),
    new RegExp(head),
  );
});

test('rejects a sign-off belonging to another identity', () => {
  const root = repository();
  const base = git(root, ['rev-parse', 'HEAD']);
  const head = commit(
    root,
    'wrong',
    'wrong\n\nSigned-off-by: Mallory Example <mallory@example.test>',
  );
  assert.throws(
    () => verifyRange({base, head, repository: root}),
    /does not match the commit author/u,
  );
});

test('uses the merge base when the target branch advances', () => {
  const root = repository();
  const branchPoint = git(root, ['rev-parse', 'HEAD']);
  git(root, ['switch', '-c', 'feature']);
  const head = commit(root, 'feature', 'feature\n\nSigned-off-by: Alice Example <alice@example.test>');
  git(root, ['switch', 'main']);
  commit(root, 'main', 'main\n\nSigned-off-by: Alice Example <alice@example.test>');
  const advancedBase = git(root, ['rev-parse', 'HEAD']);
  assert.equal(verifyRange({base: advancedBase, head, repository: root}).mergeBase, branchPoint);
});
