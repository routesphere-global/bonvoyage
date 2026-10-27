import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {REPOSITORY_ROOT, inspectRuntimeSecurityIdentity} from './dedicated-preflight.mjs';

const digest = `sha256:${'1'.repeat(64)}`;
const commit = 'a'.repeat(40);
const scriptPath = 'scripts/qualify-runtime-dependencies.sh';
const script = fs.readFileSync(path.join(REPOSITORY_ROOT, scriptPath), 'utf8');

function sandbox(t, scenario = '', locked = true) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-scan-binding-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const files = script.match(/source-files\.txt" <<'EOF'\n([\s\S]*?)\nEOF/u)[1].split('\n');
  for (const file of files) {
    fs.mkdirSync(path.dirname(path.join(root, file)), {recursive: true});
    fs.copyFileSync(path.join(REPOSITORY_ROOT, file), path.join(root, file));
  }
  fs.mkdirSync(path.join(root, 'deploy/docker/bonvoyage/patches'), {recursive: true});
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  // Fake external tools exercise orchestration only; they do not assert scanner correctness.
  const stub = `#!${process.execPath}
const fs = require('node:fs'), path = require('node:path');
const args = process.argv.slice(2), tool = path.basename(process.argv[1]);
const root = process.env.BINDING_TEST_ROOT, scenario = process.env.BINDING_TEST_SCENARIO;
const marker = path.join(root, 'scan-started');
fs.appendFileSync(path.join(root, 'calls.jsonl'), JSON.stringify({tool, args}) + '\\n');
if (tool === 'stat') {
  console.log('1234');
} else if (tool === 'uname') {
  console.log(scenario === 'darwin' ? 'Darwin' : 'Linux');
} else if (tool === 'git') {
  if (args[0] === 'rev-parse') console.log((fs.existsSync(marker) && scenario === 'commit-drift' ? 'b' : 'a').repeat(40));
  else if (args[0] === 'status') {
    if (scenario === 'untracked' || (fs.existsSync(marker) && scenario === 'source-drift')) console.log('?? surprise.txt');
  } else process.exit(92);
} else if (tool === 'node') {
  if (args[0] === 'scripts/summarize-vulnerability-scan.mjs') {
    if (scenario === 'summary-failure') process.exit(2);
    fs.writeFileSync(args[2], JSON.stringify({gate:{passed:true}, blocking:[]}));
    if (scenario === 'high-findings') process.exit(1);
  }
} else if (tool === 'python3') {
  const output = args[args.indexOf('--output') + 1];
  if (args.includes('scripts/scan-runtime-sbom-pair.py')) {
    if (scenario === 'scanner-failure') process.exit(23);
    fs.mkdirSync(output);
    for (const name of ['result.json', 'evidence-checksums.json', 'scan-cdx.stdout']) fs.writeFileSync(path.join(output, name), '{}');
    if (scenario === 'dependency-drift') fs.appendFileSync(path.join(root, 'security/dependencies/nghttp2-1.70.0.json'), ' ');
    if (scenario === 'high-findings') process.exit(1);
  } else fs.writeFileSync(output, '{}');
} else if (tool === 'docker') {
  if (args[0] === 'image' && args[1] === 'inspect') {
    const format = args[args.indexOf('--format') + 1];
    if (!args.includes('--format')) console.log('[]');
    else if (format === '{{.Id}}') console.log('sha256:' + (fs.existsSync(marker) && scenario === 'image-drift' ? '2' : '1').repeat(64));
    else if (format === '{{.Os}}/{{.Architecture}}') console.log(scenario === 'arm64' ? 'linux/arm64' : 'linux/amd64');
    else if (format.includes('org.opencontainers.image.revision')) console.log('a'.repeat(40));
    else if (format.includes('io.routesphere.bonvoyage.source-dirty')) console.log('false');
    else console.log('seastar-reference');
  } else if (args[0] === 'image' && args[1] === 'save') {
    fs.writeFileSync(args[args.indexOf('--output') + 1], 'synthetic OCI placeholder');
  } else if (args[0] === 'container' && args[1] === 'inspect') {
    console.log('[]');
  } else if (args[0] === 'export') {
    fs.writeFileSync(args[args.indexOf('--output') + 1], 'synthetic rootfs placeholder');
  } else if (args[0] === 'create') {
    console.log('binding-record-container');
  } else if (args[0] === 'rm') {
    process.exit(0);
  } else if (args[0] === 'cp') {
    const destination = args[args.length - 1];
    if (args[1].endsWith('/bonvoyage-dataplane')) {
      fs.writeFileSync(destination, 'synthetic gateway');
      process.exit(0);
    } else if (args[1].endsWith('/runtime-package-ownership.json')) {
      fs.writeFileSync(destination, '{}');
      process.exit(0);
    }
    fs.cpSync(path.join(root, 'security/dependencies'), destination, {recursive:true});
    if (scenario === 'embedded-record-drift') fs.appendFileSync(path.join(destination, 'c-ares-1.34.8.json'), ' ');
  } else if (args[0] === 'run') {
    const mount = args.find(value => value.endsWith(':/out'));
    const out = mount.slice(0, -5);
    if (args.some(value => value.startsWith('anchore/syft:'))) {
      fs.writeFileSync(marker, 'started');
      for (const arg of args.filter(value => value.includes('=/out/'))) {
        fs.writeFileSync(path.join(out, arg.split('=/out/')[1]), '{}');
      }
      fs.writeFileSync(path.join(out, 'runtime.cdx.json'), '{}');
      fs.writeFileSync(path.join(out, 'runtime.syft.spdx.json'), '{}');
    } else {
      if (scenario === 'scanner-failure') process.exit(23);
      fs.writeFileSync(path.join(out, 'vulnerabilities.grype.json'), '{}');
      if (scenario === 'dependency-drift') fs.appendFileSync(path.join(root, 'security/dependencies/nghttp2-1.70.0.json'), ' ');
    }
  } else process.exit(93);
}
`;
  for (const tool of ['docker', 'git', 'node', 'stat', 'uname', 'python3']) fs.writeFileSync(path.join(bin, tool), stub, {mode: 0o700});
  const out = path.join(root, 'evidence');
  const env = {...process.env, PATH: `${bin}:${process.env.PATH}`, BINDING_TEST_ROOT: root,
    BINDING_TEST_SCENARIO: scenario, BONVOYAGE_SECURITY_EVIDENCE_DIR: out,
    BONVOYAGE_DATAPLANE_IMAGE: 'bonvoyage:movable'};
  delete env.BONVOYAGE_GRYPE_CACHE_MIB;
  delete env.BONVOYAGE_LOCKED_DATAPLANE_IMAGE_ID;
  if (locked) env.BONVOYAGE_LOCKED_DATAPLANE_IMAGE_ID = digest;
  const invoke = () => spawnSync('/bin/sh', [path.join(root, scriptPath)], {env, encoding: 'utf8', timeout: 20000});
  return {root, out, env, invoke, calls: () => fs.readFileSync(path.join(root, 'calls.jsonl'), 'utf8').trim().split('\n').map(JSON.parse)};
}

test('scan pins the immutable Docker source and platform, never the original tag', t => {
  assert.ok(script.includes('benchmarks/results/local-archives/runtime-security-$timestamp'));
  const fixture = sandbox(t);
  const result = fixture.invoke();
  assert.equal(result.status, 0, result.stderr);
  const syft = fixture.calls().find(c => c.tool === 'docker' && c.args.includes('docker:' + digest));
  assert.ok(syft);
  assert.equal(syft.args.includes('bonvoyage:movable'), false);
  assert.equal(syft.args[syft.args.indexOf('--platform') + 1], 'linux/amd64');
  const summary = fixture.calls().find(c => c.tool === 'node' && c.args[0] === 'scripts/summarize-vulnerability-scan.mjs');
  assert.equal(summary.args.length, 4);
  assert.equal(summary.args[3], 'docker:' + digest);
  assert.equal(syft.args[syft.args.indexOf('--group-add') + 1], '1234');
  const pair = fixture.calls().find(c => c.tool === 'python3' && c.args.includes('scripts/scan-runtime-sbom-pair.py'));
  assert.equal(pair.args[pair.args.indexOf('--expected-image-id') + 1], digest);
  assert.equal(pair.args[pair.args.indexOf('--platform') + 1], 'linux/amd64');
  assert.equal(fixture.calls().filter(c => c.tool === 'docker' && c.args.some(a => a.startsWith('anchore/grype:'))).length, 0);
  const environment = fs.readFileSync(path.join(fixture.out, 'environment.txt'), 'utf8');
  assert.match(environment, /source_dirty=false/u);
  assert.ok(environment.includes(`runtime_scan_target=docker:${digest}`));
  assert.ok(fs.existsSync(path.join(fixture.out, 'evidence-checksums.sha256')));
});

test('Docker Desktop grants the scanner the container-visible socket group', t => {
  const fixture = sandbox(t, 'darwin');
  const result = fixture.invoke();
  assert.equal(result.status, 0, result.stderr);
  const syft = fixture.calls().find(c => c.tool === 'docker' && c.args.includes('docker:' + digest));
  assert.equal(syft.args[syft.args.indexOf('--group-add') + 1], '0');
  assert.equal(fixture.calls().some(c => c.tool === 'stat'), false);
});

for (const scenario of ['untracked', 'arm64', 'wrong-image']) {
  test(`locked scan rejects ${scenario} before scanner execution`, t => {
    const fixture = sandbox(t, scenario);
    if (scenario === 'wrong-image') fixture.env.BONVOYAGE_LOCKED_DATAPLANE_IMAGE_ID = `sha256:${'2'.repeat(64)}`;
    const result = fixture.invoke();
    assert.equal(result.status, 2, result.stderr);
    assert.match(result.stderr, /expected AMD64 image and clean source/u);
    assert.equal(fixture.calls().some(c => c.tool === 'docker' && c.args[0] === 'run'), false);
    assert.equal(fs.existsSync(fixture.out), false);
  });
}

for (const scenario of ['source-drift', 'commit-drift', 'image-drift', 'dependency-drift', 'embedded-record-drift', 'scanner-failure', 'summary-failure']) {
  test(`${scenario} cannot leave an accepted scan manifest`, t => {
    const fixture = sandbox(t, scenario);
    const result = fixture.invoke();
    assert.notEqual(result.status, 0);
    assert.equal(fs.existsSync(path.join(fixture.out, 'evidence-checksums.sha256')), false);
    assert.ok(fs.existsSync(path.join(fixture.out, 'runtime.cdx.json')));
  });
}

test('an existing evidence directory is never overwritten', t => {
  const fixture = sandbox(t);
  fs.mkdirSync(fixture.out);
  fs.writeFileSync(path.join(fixture.out, 'environment.txt'), 'sealed original');
  const result = fixture.invoke();
  assert.equal(result.status, 2);
  assert.match(result.stderr, /must be new/u);
  assert.equal(fs.readFileSync(path.join(fixture.out, 'environment.txt'), 'utf8'), 'sealed original');
});

test('High findings preserve the checksummed evidence but fail qualification', t => {
  const fixture = sandbox(t, 'high-findings');
  const result = fixture.invoke();
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /vulnerability gate blocked/);
  assert.ok(fs.existsSync(path.join(fixture.out, 'evidence-checksums.sha256')));
  assert.ok(fs.existsSync(path.join(fixture.out, 'dual-format/result.json')));
});

test('non-RC exploratory scans report untracked source as dirty', t => {
  const fixture = sandbox(t, 'untracked', false);
  const result = fixture.invoke();
  assert.equal(result.status, 0, result.stderr);
  assert.match(fs.readFileSync(path.join(fixture.out, 'environment.txt'), 'utf8'), /source_dirty=true/u);
});

test('artifact capture and verification require the same fresh scan identity', () => {
  const artifact = {image_digest: digest, metadata: {upstream_http1_client: 'seastar-reference'}};
  const values = {source_commit: commit, source_dirty: 'false', runtime_platform: 'linux/amd64',
    runtime_image_id: digest, runtime_scan_target: `docker:${digest}`, upstream_http1_client: 'seastar-reference'};
  const context = {sourceCommit: commit, artifact};
  assert.deepEqual(inspectRuntimeSecurityIdentity(values, context), []);
  for (const name of Object.keys(values)) {
    assert.ok(inspectRuntimeSecurityIdentity({...values, [name]: 'mismatch'}, context).length > 0, name);
    const missing = {...values};
    delete missing[name];
    assert.ok(inspectRuntimeSecurityIdentity(missing, context).length > 0, name);
  }
  assert.ok(inspectRuntimeSecurityIdentity(values, {sourceCommit: commit}).length > 0);
});
