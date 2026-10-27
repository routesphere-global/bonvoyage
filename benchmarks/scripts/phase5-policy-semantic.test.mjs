import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {validateSemanticProbe} from './phase5-policy-semantic.mjs';

const root = path.resolve(import.meta.dirname, '../..');
const catalog = JSON.parse(fs.readFileSync(path.join(root,
  'benchmarks/workloads/policy-cost/phase5-policy-cost.json'), 'utf8'));

function probe(profileId, product, probeCase, status, headers, body) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'phase5-policy-semantic-'));
  const statusPath = path.join(work, 'status');
  const headersPath = path.join(work, 'headers');
  const bodyPath = path.join(work, 'body');
  fs.writeFileSync(statusPath, `${status}\n`);
  fs.writeFileSync(headersPath, `HTTP/1.1 ${status} Result\r\n${headers}\r\n`);
  fs.writeFileSync(bodyPath, body);
  try {
    return validateSemanticProbe(catalog, {
      profile_id: profileId,
      product,
      case: probeCase,
      status_path: statusPath,
      headers_path: headersPath,
      body_path: bodyPath,
    });
  } finally {
    fs.rmSync(work, {recursive: true, force: true});
  }
}

test('plain BonVoyage and NGINX controls require the exact payload', () => {
  for (const product of ['bonvoyage', 'nginx']) {
    const result = probe('P5-C00', product, 'allow', 200,
      'Content-Type: application/octet-stream\r\n', Buffer.alloc(8192, 'x'));
    assert.equal(result.semantic_result, 'pass');
    assert.equal(result.body_bytes, 8192);
  }
  assert.throws(() => probe('P5-C00', 'bonvoyage', 'allow', 200, '',
    Buffer.alloc(8192, 'y')), /controlled payload/u);
});

test('header transformation probe binds request and response semantics', () => {
  const headers = [
    'x-upstream-policy-set: gateway-set',
    'x-upstream-policy-append: upstream-append, gateway-append',
    'x-policy-response-added: gateway-added',
    'x-observed-request-set: gateway-set',
    'x-observed-request-append: client-append, gateway-append',
    'x-observed-request-added: gateway-added',
  ].join('\r\n');
  for (const product of ['bonvoyage', 'nginx']) {
    assert.equal(probe('P5-C01', product, 'allow', 200, headers,
      Buffer.alloc(256, 'x')).semantic_result, 'pass');
  }
  assert.throws(() => probe('P5-C01', 'bonvoyage', 'allow', 200,
    `${headers}\r\nx-upstream-policy-remove: retained`, Buffer.alloc(256, 'x')),
  /must be absent/u);
});

test('authentication probes distinguish allow, rejection, and scope denial', () => {
  assert.equal(probe('P5-C03', 'bonvoyage', 'allow', 200, '',
    Buffer.alloc(8192, 'x')).http_status, 200);
  assert.equal(probe('P5-C03', 'bonvoyage', 'invalid-credential', 401, '',
    Buffer.from('unauthorized')).http_status, 401);
  assert.equal(probe('P5-C04', 'bonvoyage', 'insufficient-scope', 403, '',
    Buffer.from('forbidden')).http_status, 403);
  assert.throws(() => probe('P5-C04', 'nginx', 'allow', 200, '',
    Buffer.alloc(256, 'x')), /cannot be claimed/u);
});

test('rejection probes fail if traffic reached the controlled upstream', () => {
  assert.throws(() => probe('P5-C05', 'bonvoyage', 'invalid-credential', 401,
    'x-upstream-policy-set: upstream-set\r\n', Buffer.from('unauthorized')),
  /must be absent/u);
});

test('AWS preflight keeps secrets private and restores every changed role', () => {
  const source = fs.readFileSync(path.join(root,
    'benchmarks/scripts/phase5-policy-semantic-preflight.sh'), 'utf8');
  assert.doesNotMatch(source, /set -x/u);
  assert.match(source, /load-generator[.]example[.]test/u);
  assert.match(source, /gateway-target[.]example[.]test/u);
  assert.match(source, /upstream-a[.]example[.]test/u);
  assert.match(source, /upstream-b[.]example[.]test/u);
  const privateCampaignPrefix = ['bonvoyage', 'amd64', ''].join('-');
  assert.equal(source.includes(privateCampaignPrefix), false);
  assert.match(source, /source tree must be clean/u);
  assert.match(source, /source commit must match origin\/main/u);
  assert.match(source, /ls-files --others --exclude-standard/u);
  assert.match(source, /source_dirty:false/u);
  assert.match(source, /bonvoyage_probe_count:12,nginx_probe_count:3/u);
  assert.match(source, /phase5-policy-semantic\.mjs/u);
  assert.match(source, /nginx@sha256:9e4b33ead4c69/u);
  assert.match(source, /restore_remote \|\| fail 'remote restoration failed'/u);
  assert.match(source, /restore_status=0/u);
  assert.doesNotMatch(source, /restore_remote\(\) \{\s+status=0/u);
  assert.match(source, /sudo rm -rf '\$remote_dir'/u);
  assert.match(source, /sudo chmod 711 '\$remote_dir'/u);
  assert.match(source,
    /sudo install -o bonvoyage -g bonvoyage -m 600[^\n]+ && rm -f/u);
  assert.match(source, /sudo chmod 711[^\n]+ && sudo chown -R bonvoyage/u);
  assert.match(source, /run_probe\(\) \(/u);
  assert.match(source, /retain_probe\(\) \(/u);
  assert.match(source, /test ! -e '\$remote_dir'/u);
  assert.match(source, /upstream-a-after\.txt/u);
  assert.match(source, /upstream-b-after\.txt/u);
  assert.match(source,
    /for attempt in 1 2 3 4 5 6 7 8 9 10[^\n]+State\.Health\.Status/u);
  assert.doesNotMatch(source, /chmod 600 '\$remote_dir\/secrets\/'\*/u);
  assert.match(source, /rm -rf "\$private"/u);
  assert.doesNotMatch(source,
    /scp[^\n]*(?:jwt-private\.pem|jwt-tokens\.json|ca-key\.pem)[^\n]*\$evidence/u);
});

test('AWS preflight validates its default IPv4 inputs on the host awk', () => {
  const script = path.join(root,
    'benchmarks/scripts/phase5-policy-semantic-preflight.sh');
  const result = spawnSync('sh', [script], {
    cwd: root,
    encoding: 'utf8',
    env: {...process.env, BONVOYAGE_POLICY_EVIDENCE_DIR: ''},
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /BONVOYAGE_POLICY_EVIDENCE_DIR is required/u);
  assert.doesNotMatch(result.stderr, /awk:|invalid IPv4/u);
  assert.match(result.stderr, /before evidence-directory creation/u);
});
