#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const CLASSIFICATION = 'routesphere-bonvoyage-oss-release-identity-probe';
const REPOSITORY = 'routesphere-global/bonvoyage';
const REPOSITORY_URL = `https://github.com/${REPOSITORY}`;
const SUBJECT_PREFIX = `${REPOSITORY_URL}/.github/workflows/release.yml@refs/tags/`;
const TAG = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const POSITIVE_INTEGER = /^[1-9][0-9]*$/u;

function fail(message) {
  throw new Error(message);
}

function requireCondition(condition, message) {
  if (!condition) fail(message);
}

function parseArguments(argv) {
  const mapping = new Map([
    ['--output', 'output'],
    ['--repository', 'repository'],
    ['--ref-type', 'refType'],
    ['--tag', 'tag'],
    ['--commit', 'commit'],
    ['--run-id', 'runId'],
    ['--run-attempt', 'runAttempt'],
  ]);
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const key = mapping.get(argv[index]);
    requireCondition(key !== undefined && index + 1 < argv.length,
      `unsupported or incomplete argument ${argv[index]}`);
    options[key] = argv[index + 1];
    index += 1;
  }
  for (const value of mapping.values()) {
    requireCondition(options[value] !== undefined, `--${value} is required`);
  }
  return options;
}

export function createIdentityProbe(options) {
  requireCondition(options.repository === REPOSITORY,
    'identity probe requires the public RouteSphere repository');
  requireCondition(options.refType === 'tag', 'identity probe requires a tag ref');
  requireCondition(typeof options.tag === 'string' && TAG.test(options.tag),
    'identity probe requires a strict v-prefixed SemVer tag');
  requireCondition(typeof options.commit === 'string' && COMMIT.test(options.commit),
    'identity probe requires a lowercase 40-character source commit');
  requireCondition(typeof options.runId === 'string' && POSITIVE_INTEGER.test(options.runId),
    'identity probe requires a positive GitHub run ID');
  requireCondition(typeof options.runAttempt === 'string' &&
    POSITIVE_INTEGER.test(options.runAttempt),
  'identity probe requires a positive GitHub run attempt');

  return {
    schema_version: 1,
    classification: CLASSIFICATION,
    repository: REPOSITORY_URL,
    workflow_identity: `${SUBJECT_PREFIX}${options.tag}`,
    source: {
      commit: options.commit,
      tag: options.tag,
      ref_type: options.refType,
    },
    github_run: {
      id: options.runId,
      attempt: options.runAttempt,
    },
    authority: {
      identity_probe_only: true,
      product_artifact_signed: false,
      product_provenance_created: false,
      release_admitted: false,
      publishable: false,
    },
  };
}

function writeNewJson(output, value) {
  const target = path.resolve(output);
  requireCondition(!fs.existsSync(target), 'identity probe output must be new');
  fs.mkdirSync(path.dirname(target), {recursive: true});
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, {
    flag: 'wx',
    mode: 0o600,
  });
}

if (import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  try {
    const options = parseArguments(process.argv.slice(2));
    const probe = createIdentityProbe(options);
    writeNewJson(options.output, probe);
    process.stdout.write(`${JSON.stringify(probe, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`OSS release identity probe rejected: ${error.message}\n`);
    process.exitCode = 1;
  }
}
