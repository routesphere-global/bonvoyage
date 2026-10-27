import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import {createRequire} from 'node:module';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../../', import.meta.url));
const require = createRequire(path.join(root, 'package.json'));
const yaml = require('js-yaml');
const scripts = path.join(root, 'scripts');

test('phase3 upstream source remains readable after private source staging', () => {
  const dockerfile = fs.readFileSync(
    path.join(root, 'deploy/docker/upstream/Dockerfile'),
    'utf8',
  );
  assert.match(dockerfile, /^COPY --chmod=0644 server\.py \.$/m);
});

test('accept recovery sends asserted runtime events to Docker stderr', () => {
  const source = fs.readFileSync(
    path.join(scripts, 'phase3-accept-recovery.sh'),
    'utf8',
  );
  const launches = source.replace(/\\\n/g, ' ').split('\n')
    .map(line => line.trim())
    .filter(line => line.startsWith('docker run ') && line.includes('--name "$gateway"'));
  assert.equal(launches.length, 1);
  assert.match(launches[0], /--runtime-log-transport stderr-pipe/);
  assert.match(source, /grep -q 'listener accept resource exhaustion' "\$output\/gateway\.log"/);
  assert.match(source, /grep -q 'listener accept recovered' "\$output\/gateway\.log"/);
});

test('observability fixture sends asserted lifecycle events to Docker stderr', () => {
  const source = fs.readFileSync(
    path.join(scripts, 'phase3-observability-decision-telemetry.sh'),
    'utf8',
  );
  const launches = source.replace(/\\\n/g, ' ').split('\n')
    .map(line => line.trim())
    .filter(line => line.startsWith('docker run ') && line.includes('--name "$gateway"'));
  assert.equal(launches.length, 1);
  assert.match(launches[0], /--runtime-log-transport stderr-pipe/);
  assert.match(source, /grep -F 'event=dataplane_ready' "\$stage_dir\/gateway\.log"/);
  assert.match(source, /grep -F 'event=dataplane_stopped' "\$stage_dir\/gateway\.log"/);
});

test('trace fixture backlog covers cold bursts without relaxing gateway timeouts', () => {
  const fixture = yaml.load(fs.readFileSync(path.join(root, 'tests/fixtures/phase3-otlp-tracing.yaml'), 'utf8'));
  const client = fs.readFileSync(path.join(scripts, 'phase3-otlp-tracing-client.py'), 'utf8');
  const workers = [...client.matchAll(/max_workers=(\d+)/g)].map(match => Number(match[1]));
  assert.ok(workers.length > 0);
  const result = spawnSync('python3', ['-c', 'import runpy; print(runpy.run_path("scripts/phase3-trace-upstream.py")["Server"].request_queue_size)'], {cwd:root, encoding:'utf8'});
  assert.equal(result.status, 0, result.stderr);
  const backlog = Number(result.stdout.trim());
  assert.ok(Number.isInteger(backlog));
  assert.ok(backlog >= Math.max(fixture.clusters[0].max_connections_per_shard, ...workers));
  assert.equal(fixture.clusters[0].connect_timeout_ms, 1000);
});

const privateMountCases = [
  ['phase3-http2-conformance.sh', 4, ['--volume "$client_dir:/tls:ro"']],
  ['phase3-http2-reliability.sh', 3, ['--volume "$evidence_dir:/evidence:ro"', '--volume "$work_dir/client:/tls:ro"']],
  ['phase3-http2-cost.sh', 4, ['--volume "$evidence_dir:/evidence:ro"', '--volume "$work_dir/client:/tls:ro"']],
  ['phase3-composite-hardening.sh', 6, ['--name "$loadgen"', '--name "$container"', '--name "$websocket"', '--name "$grpc_upstream"', '--volume "$work_dir/secrets:/tls:ro"', '--volume "$work_dir/secrets:/secrets:ro"']],
  ['phase3-otlp-tracing-smoke.sh', 3, ['--name "$collector"', '--name "$upstream"', '--volume "$work_dir:/tls:ro"']],
  ['phase3-saas-canary-telemetry-failure.sh', 2, ['--name "$loadgen"', '--name "$container"']],
  ['phase3-multi-hour-hardening.sh', 8, ['--name "$loadgen"', '--name "$container"', '--name "$websocket"', '--name "$grpc_upstream"', '--name "$collector"', '--name "$h2_load"', '--volume "$work_dir/secrets:/secrets:ro"', '--volume "$stage_dir:/evidence"']],
];

for (const [name, count, mounts] of privateMountCases) {
  test(`${name}: private fixture mounts use the caller UID without elevating the gateway`, () => {
    const source = fs.readFileSync(path.join(scripts, name), 'utf8');
    const commands = source.replace(/\\\n/g, ' ').split('\n').map(line => line.trim()).filter(line => line.startsWith('docker run '));
    const clients = commands.filter(line => mounts.some(mount => line.includes(mount)));
    assert.equal(clients.length, count, 'all reviewed private-mount launches must be covered');
    for (const client of clients) assert.ok(client.includes('--user "$(id -u):$(id -g)"'), client);
    assert.match(source, /^umask 077$/m);
    for (const gateway of commands.filter(line => line.includes('--name "$gateway"'))) {
      assert.ok(!gateway.includes('--user '), 'gateway keeps its image-defined non-root UID');
      assert.ok(gateway.includes('--cap-drop ALL'));
    }
    const syntax = spawnSync('sh', ['-n', path.join(scripts, name)], {encoding:'utf8'});
    assert.equal(syntax.status, 0, syntax.stderr);
  });
}

test('telemetry fixtures assert the published contract version', () => {
  const contract = yaml.load(fs.readFileSync(path.join(root, 'observability/telemetry-contract.yaml'), 'utf8'));
  const version = contract.contract_version;
  assert.ok(Number.isInteger(version) && version > 0);
  for (const name of ['phase3-observability-decision-telemetry.sh', 'phase3-saas-canary-telemetry-failure.sh']) {
    const source = fs.readFileSync(path.join(scripts, name), 'utf8');
    const assertions = [...source.matchAll(/"telemetry_contract_version": (\d+)/g)];
    assert.ok(assertions.length > 0, name);
    for (const match of assertions) assert.equal(Number(match[1]), version, name);
    for (const match of source.matchAll(/^telemetry_contract_version=(\d+)$/gm)) {
      assert.equal(Number(match[1]), version, name);
    }
  }
});

test('conformance queue admits the advertised stream limit without changing protocol limits', () => {
  const fixture = yaml.load(fs.readFileSync(path.join(root, 'tests/fixtures/phase3-http2-conformance.yaml'), 'utf8'));
  const baseline = yaml.load(fs.readFileSync(path.join(root, 'tests/fixtures/phase3-http2.yaml'), 'utf8'));
  const pending = fixture.clusters[0].max_pending_requests_per_shard;
  const connections = fixture.clusters[0].max_connections_per_shard;
  assert.ok(pending + connections >= 101);
  baseline.snapshot.snapshot_id = fixture.snapshot.snapshot_id;
  baseline.clusters[0].max_pending_requests_per_shard = pending;
  assert.deepEqual(fixture, baseline);
  assert.ok(fs.readFileSync(path.join(scripts, 'phase3-http2-conformance.sh'), 'utf8').includes('phase3-http2-conformance.yaml'));
});

for (const name of fs.readdirSync(scripts).filter(name => name.startsWith('phase3-') && name.endsWith('.sh'))) {
  const source = fs.readFileSync(path.join(scripts, name), 'utf8');
  if (!source.includes('docker network create --internal')) continue;
  test(`${name}: isolated gateway does not inherit host DNS search domains`, () => {
    const commands = source.replace(/\\\n/g, ' ').split('\n');
    const launches = commands.filter(line => line.startsWith('docker run ') && line.includes('--name "$gateway"'));
    assert.ok(launches.length > 0);
    for (const launch of launches) assert.match(launch, /--dns-search \. /);
  });
}

test('access-log evidence is copied by Docker as the host caller', () => {
  const source = fs.readFileSync(path.join(scripts, 'phase3-http2-smoke.sh'), 'utf8');
  assert.ok(source.includes('docker cp "$gateway:/var/log/bonvoyage/." "$work_dir/"'));
  assert.ok(source.includes('\' >"$work_dir/access-log-validation.json"'));
  assert.ok(!source.includes('shutil.copy2('));
});

for (const mode of ['locked', 'mismatch', 'developer']) {
  test(`scale harness ${mode}: gateway image ownership is respected`, t => {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-scale-lock-test-'));
    t.after(() => fs.rmSync(temp, {recursive:true, force:true}));
    const log = path.join(temp, 'docker.jsonl');
    const id = `sha256:${'a'.repeat(64)}`;
    fs.writeFileSync(path.join(temp, 'docker'), `#!${process.execPath}\n` + `
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.FIXTURE_DOCKER_LOG, JSON.stringify(args)+'\\n');
if (args[0] === 'image' && args[1] === 'inspect') {
  process.stdout.write(args.includes('{{.Id}}') ? process.env.FIXTURE_IMAGE_ID+'\\n' : 'linux/amd64\\n');
} else if (args[0] === 'buildx') {
  process.exit(73);
} else if (args[0] === 'inspect') {
  process.exit(1);
}
`, {mode:0o755});
    const env = {...process.env, PATH:`${temp}:${process.env.PATH}`, TMPDIR:temp,
      BONVOYAGE_DATAPLANE_IMAGE:'fixture-gateway:locked', BONVOYAGE_BUILD_PLATFORM:'linux/amd64',
      FIXTURE_DOCKER_LOG:log, FIXTURE_IMAGE_ID:mode === 'mismatch' ? `sha256:${'b'.repeat(64)}` : id};
    delete env.BONVOYAGE_LOCKED_DATAPLANE_IMAGE_ID;
    if (mode !== 'developer') env.BONVOYAGE_LOCKED_DATAPLANE_IMAGE_ID = id;
    const result = spawnSync('sh', ['scripts/phase3-route-scale-connection-density.sh'], {cwd:root, env, encoding:'utf8', timeout:10000});
    assert.equal(result.status, mode === 'mismatch' ? 1 : 73, result.stdout+result.stderr);
    const commands = fs.readFileSync(log, 'utf8').trim().split('\n').map(line => JSON.parse(line));
    const builds = commands.filter(args => args[0] === 'buildx');
    if (mode === 'mismatch') assert.equal(builds.length, 0);
    else {
      assert.equal(builds.length, 1);
      assert.equal(builds[0].includes('fixture-gateway:locked'), mode === 'developer');
    }
  });
}
