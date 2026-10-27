import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const script = fileURLToPath(new URL('../../scripts/qualify-runtime-dependencies.sh', import.meta.url));

function invoke(t, value) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-scan-cache-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const marker = path.join(directory, 'docker-called');
  fs.writeFileSync(path.join(directory, 'docker'), '#!/bin/sh\nprintf invoked > "$CACHE_TEST_MARKER"\nexit 97\n', {mode: 0o700});
  const env = {...process.env, PATH: `${directory}:${process.env.PATH}`, CACHE_TEST_MARKER: marker};
  delete env.BONVOYAGE_GRYPE_CACHE_MIB;
  if (value !== undefined) env.BONVOYAGE_GRYPE_CACHE_MIB = value;
  const result = spawnSync('/bin/sh', ['-x', script], {env, encoding: 'utf8', timeout: 5000});
  assert.equal(result.error, undefined);
  return {...result, calledDocker: fs.existsSync(marker)};
}

for (const value of ['0', '-1', '1023', '16385', '01', '8g', '8192m', '1;true', '4096', '8192', '99999999999999999999999999999999']) {
  test(`rejects obsolete tmpfs cache size ${value} before Docker access`, (t) => {
    const result = invoke(t, value);
    assert.equal(result.status, 2);
    assert.equal(result.calledDocker, false);
    assert.match(result.stderr, /is obsolete; unset it/);
  });
}

for (const value of [undefined, '']) {
  test(`accepts retained-disk default with legacy value ${JSON.stringify(value)}`, (t) => {
    const result = invoke(t, value);
    assert.equal(result.calledDocker, true);
    assert.equal(result.status, 1); // The stub deliberately reports a missing image.
  });
}

test('same-database runner replaces the transient Grype cache', () => {
  const source = fs.readFileSync(script, 'utf8');
  assert.ok(source.includes('database_storage=dual-format/database'));
  assert.ok(source.includes('python3 -B scripts/scan-runtime-sbom-pair.py'));
  assert.ok(source.includes('--read-only'));
  assert.ok(source.includes('--security-opt no-new-privileges'));
});
