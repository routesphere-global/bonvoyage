#!/usr/bin/env node

import {spawnSync} from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

const COMMIT = /^[0-9a-f]{40}$/u;

function fail(message) {
  throw new Error(message);
}

function git(args, {cwd = process.cwd(), input} = {}) {
  const result = spawnSync('git', args, {
    cwd,
    input,
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error) {
    fail(`git ${args[0]} failed: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || '').trim();
    fail(`git ${args[0]} failed${detail ? `: ${detail}` : ''}`);
  }
  return result.stdout;
}

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!['--base', '--head', '--repository'].includes(name) || value === undefined) {
      fail('usage: verify-dco-signoffs.mjs --base COMMIT --head COMMIT [--repository PATH]');
    }
    if (values.has(name)) {
      fail(`duplicate argument ${name}`);
    }
    values.set(name, value);
  }
  const base = values.get('--base');
  const head = values.get('--head');
  if (!COMMIT.test(base ?? '') || !COMMIT.test(head ?? '')) {
    fail('--base and --head must be full lowercase Git commit identifiers');
  }
  return {base, head, repository: values.get('--repository') ?? process.cwd()};
}

function commitIdentity(repository, commit) {
  const raw = git(['show', '-s', '--format=%an%x00%ae%x00%B', commit], {
    cwd: repository,
  });
  const first = raw.indexOf('\0');
  const second = raw.indexOf('\0', first + 1);
  if (first <= 0 || second <= first + 1) {
    fail(`commit ${commit} has an invalid author identity`);
  }
  return {
    name: raw.slice(0, first),
    email: raw.slice(first + 1, second),
    message: raw.slice(second + 1),
  };
}

function parsedSignoffs(repository, message) {
  const trailers = git(['interpret-trailers', '--parse'], {
    cwd: repository,
    input: message,
  });
  const result = [];
  for (const line of trailers.split('\n')) {
    const match = /^Signed-off-by:\s*(.+?)\s*<([^<>\s]+)>\s*$/iu.exec(line);
    if (match) {
      result.push({name: match[1], email: match[2]});
    }
  }
  return result;
}

export function verifyRange({base, head, repository = process.cwd()}) {
  if (!COMMIT.test(base) || !COMMIT.test(head)) {
    fail('base and head must be full lowercase Git commit identifiers');
  }
  const mergeBase = git(['merge-base', base, head], {cwd: repository}).trim();
  if (!COMMIT.test(mergeBase)) {
    fail('Git did not return a valid merge base');
  }
  const commits = git(
    ['rev-list', '--reverse', '--no-merges', `${mergeBase}..${head}`],
    {cwd: repository},
  ).trim().split('\n').filter(Boolean);
  if (commits.length === 0) {
    fail('pull request contains no non-merge commits to verify');
  }

  const rejected = [];
  for (const commit of commits) {
    if (!COMMIT.test(commit)) {
      fail('Git returned an invalid commit identifier');
    }
    const author = commitIdentity(repository, commit);
    const signoffs = parsedSignoffs(repository, author.message);
    const accepted = signoffs.some((signoff) =>
      signoff.name === author.name &&
      signoff.email.toLowerCase() === author.email.toLowerCase());
    if (!accepted) {
      rejected.push({commit, author: `${author.name} <${author.email}>`});
    }
  }

  if (rejected.length > 0) {
    const details = rejected.map(({commit, author}) =>
      `  ${commit} author ${author}`).join('\n');
    fail(
      'Developer Certificate of Origin sign-off missing or does not match the commit author:\n' +
      `${details}\nAmend each commit with: git commit --amend --signoff`,
    );
  }
  return {mergeBase, commits};
}

function main() {
  try {
    const options = parseArguments(process.argv.slice(2));
    const result = verifyRange(options);
    process.stdout.write(`Verified DCO sign-offs for ${result.commits.length} commit(s).\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main();
}
