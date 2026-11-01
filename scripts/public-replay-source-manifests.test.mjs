import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MANIFEST_SCRIPTS = [
  'scripts/phase3-http2-smoke.sh',
  'scripts/phase3-cors-smoke.sh',
  'scripts/phase3-request-content-smoke.sh',
  'scripts/phase3-header-transformations-smoke.sh',
  'scripts/phase3-route-rewrites-smoke.sh',
  'scripts/phase3-redirect-smoke.sh',
];
const SOURCE_MANIFEST = /cat >"\$(?:evidence_dir|stage_dir)\/source-files\.txt" <<'EOF'\n([\s\S]*?)\nEOF/gu;

function sourcePaths(scriptPath) {
  const source = fs.readFileSync(path.join(ROOT, scriptPath), 'utf8');
  const matches = [...source.matchAll(SOURCE_MANIFEST)];
  assert.equal(matches.length, 1,
    `${scriptPath} must define exactly one evidence source manifest`);
  return matches[0][1].split('\n').filter((entry) => entry.length > 0);
}

test('public replay source manifests reference only exported regular files', () => {
  for (const scriptPath of MANIFEST_SCRIPTS) {
    const entries = sourcePaths(scriptPath);
    assert.ok(entries.length > 0, `${scriptPath} has an empty source manifest`);
    assert.equal(new Set(entries).size, entries.length,
      `${scriptPath} contains duplicate source-manifest entries`);

    for (const entry of entries) {
      assert.equal(path.isAbsolute(entry), false,
        `${scriptPath} contains absolute path ${entry}`);
      assert.equal(path.normalize(entry), entry,
        `${scriptPath} contains non-canonical path ${entry}`);
      assert.equal(entry.startsWith('../'), false,
        `${scriptPath} escapes the repository through ${entry}`);

      const exportedPath = path.join(ROOT, entry);
      assert.equal(fs.existsSync(exportedPath), true,
        `${scriptPath} references non-exported path ${entry}`);
      assert.equal(fs.statSync(exportedPath).isFile(), true,
        `${scriptPath} references non-file path ${entry}`);
    }
  }
});
