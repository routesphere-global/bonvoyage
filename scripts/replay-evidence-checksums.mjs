import {createHash} from 'node:crypto';
import {existsSync, lstatSync, readFileSync, readdirSync, realpathSync} from 'node:fs';
import path from 'node:path';

function fail(message) {
  throw new Error(`Evidence checksum replay: ${message}`);
}

function filesNamed(root, name) {
  const matches = [];
  for (const entry of readdirSync(root, {withFileTypes: true})) {
    const candidate = path.join(root, entry.name);
    if (entry.isDirectory()) matches.push(...filesNamed(candidate, name));
    else if (entry.isFile() && entry.name === name) matches.push(candidate);
  }
  return matches;
}

const evidenceInput = process.argv[2];
if (!evidenceInput) fail('expected one evidence directory');
const evidenceRoot = realpathSync(evidenceInput);
const manifestPath = path.join(evidenceRoot, 'SHA256SUMS');
const lines = readFileSync(manifestPath, 'utf8').trim().split('\n').filter(Boolean);
if (lines.length === 0) fail('checksum manifest is empty');

let verified = 0;
for (const line of lines) {
  const match = /^([0-9a-f]{64}) [ *](.+)$/.exec(line);
  if (match === null) fail(`invalid checksum line: ${line}`);
  const [, expected, recorded] = match;
  let candidate = path.isAbsolute(recorded)
    ? recorded
    : path.resolve(evidenceRoot, recorded);
  if (!existsSync(candidate)) {
    const matches = filesNamed(evidenceRoot, path.basename(recorded));
    if (matches.length !== 1) {
      fail(`cannot relocate ${recorded}; found ${matches.length} retained basename matches`);
    }
    candidate = matches[0];
  }
  const info = lstatSync(candidate);
  if (!info.isFile() || info.isSymbolicLink()) fail(`unsafe checksum target: ${candidate}`);
  const actual = createHash('sha256').update(readFileSync(candidate)).digest('hex');
  if (actual !== expected) fail(`digest mismatch for ${recorded}`);
  process.stdout.write(`${path.relative(evidenceRoot, candidate)}: OK\n`);
  verified++;
}
process.stdout.write(`verified_files=${verified}\n`);
