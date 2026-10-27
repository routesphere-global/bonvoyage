import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import {
  COMPLETION_PATH,
  OUTPUT_ROOT,
  OUTPUT_PATH,
  SNIPPETS_PATH,
  SOURCE_ROOT,
  generatePublicConfigReference,
} from './generate-public-config-reference.mjs';

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(SOURCE_ROOT, ...relativePath.split('/')), 'utf8'));
}

test('public YAML parameter reference is current and complete', () => {
  const completion = readJson(COMPLETION_PATH);
  const snippets = readJson(SNIPPETS_PATH);
  const rendered = generatePublicConfigReference(SOURCE_ROOT);
  const committed = fs.readFileSync(path.join(OUTPUT_ROOT, ...OUTPUT_PATH.split('/')), 'utf8');

  assert.equal(committed, rendered);
  for (const entry of completion.entries.filter((candidate) => candidate.path !== '')) {
    assert.equal(rendered.includes(`\`${entry.path}\``), true,
      `public reference omits ${entry.path}`);
    assert.equal(rendered.includes(entry.summary), true,
      `public reference omits reviewed help for ${entry.path}`);
  }
  for (const entry of snippets.entries) {
    assert.equal(rendered.includes(entry.title), true,
      `public reference omits snippet title ${entry.id}`);
    assert.equal(rendered.includes(entry.yaml.trimEnd()), true,
      `public reference omits snippet YAML ${entry.id}`);
  }
  assert.doesNotMatch(rendered, /\/Users\/|tools\/oss-export|johnynixon/iu);
  assert.match(rendered, /http3.*rejected by semantic validation/su);
  assert.match(rendered, /deployment-secret filename only; never secret contents/u);
  assert.match(rendered, /\[configuration diagnostics\]\(\.\.\/configuration-diagnostics\/\)/u);
  assert.match(rendered, /\[supported capabilities\]\(\.\.\/supported-capabilities\/\)/u);
});
