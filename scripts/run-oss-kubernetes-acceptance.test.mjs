import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {KubernetesAcceptance, Rejected} from './run-oss-kubernetes-acceptance.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const contractPath = path.join(root, 'packaging', 'release', 'kubernetes',
  'oss-kubernetes-fresh-install-contract.json');
const commit = 'a'.repeat(40);
const context = 'kind-bonvoyage-oss-acceptance';
const cluster = 'bonvoyage-oss-acceptance';

function result(status = 0, stdout = '', stderr = '') {
  return {status, stdout, stderr, signal: null, timedOut: false};
}

const imageByRole = {
  dataplane: 'bonvoyage-local-bonvoyage:oss-kubernetes',
  snapshot_compiler: 'bonvoyage-local-snapshot-compiler:oss-kubernetes',
  upstream: 'bonvoyage-local-upstream:oss-kubernetes',
};

function fakeArchive(role, options = {}) {
  const configuration = `${JSON.stringify({config: {Labels: {
    'org.opencontainers.image.revision': commit,
    'io.routesphere.bonvoyage.source-dirty': options.archiveDirty ? 'true' : 'false',
  }}})}\n`;
  const configDigest = `sha256:${crypto.createHash('sha256')
    .update(configuration).digest('hex')}`;
  const manifest = `${JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: {
      mediaType: 'application/vnd.oci.image.config.v1+json',
      digest: configDigest,
      size: Buffer.byteLength(configuration),
    },
    layers: [],
  })}\n`;
  const actualManifestDigest = `sha256:${crypto.createHash('sha256')
    .update(manifest).digest('hex')}`;
  const manifestDigest = options.archiveDigestMismatch ?
    `sha256:${'0'.repeat(64)}` : actualManifestDigest;
  const image = imageByRole[role];
  const index = `${JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.index.v1+json',
    manifests: [{
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      digest: manifestDigest,
      size: Buffer.byteLength(manifest),
      annotations: {
        'io.containerd.image.name': `docker.io/library/${image}`,
      },
      platform: {
        architecture: options.archivePlatformMismatch ? 'amd64' : 'arm64',
        os: 'linux',
      },
    }],
  })}\n`;
  const indexDigest = `sha256:${crypto.createHash('sha256')
    .update(index).digest('hex')}`;
  return {
    configuration,
    configDigest,
    manifest,
    manifestDigest,
    index,
    indexDigest,
  };
}

function gatewayPod(name, configMap, isReady, failed = false) {
  return {
    metadata: {name, uid: `${name}-uid`},
    spec: {volumes: [{name: 'config', configMap: {name: configMap}}]},
    status: {
      conditions: [{type: 'Ready', status: isReady ? 'True' : 'False'}],
      initContainerStatuses: [{
        name: 'snapshot-compiler',
        restartCount: failed ? 1 : 0,
        state: failed ? {waiting: {reason: 'CrashLoopBackOff'}} :
          {terminated: {exitCode: 0}},
      }],
    },
  };
}

class FakeExecutor {
  constructor(options = {}) {
    this.options = options;
    this.calls = [];
    this.clusterExists = options.clusterExists || false;
    this.namespaceExists = false;
    this.configMap = 'bonvoyage-config-v1';
    this.interruptedBy = null;
    this.statusQueries = 0;
    this.gatewayPodQueries = 0;
  }

  interrupt(signal) {
    this.interruptedBy = signal;
  }

  async run(program, args, options = {}) {
    this.calls.push({program, args: [...args], env: options.env});
    const name = path.basename(program);

    if (name === 'git' && args[0] === 'rev-parse') return result(0, `${commit}\n`);
    if (name === 'git' && args[0] === 'status') {
      this.statusQueries += 1;
      const dirty = this.options.dirtySource ||
        (this.options.dirtyAfterBuild && this.statusQueries >= 2);
      return result(0, dirty ? ' M changed\n' : '');
    }
    if (name === 'kind' && args[0] === 'version') {
      return result(0, this.options.wrongKindVersion ?
        'kind v0.32.0 compatibility-v0.33.0\n' :
        'kind v0.33.0 go1.25.0 darwin/arm64\n');
    }
    if (name === 'kubectl' && args[0] === 'version') {
      return result(0, '{"clientVersion":{"gitVersion":"v1.37.0"}}\n');
    }
    if (name === 'docker' && args[0] === 'version') {
      return result(0, 'linux/arm64\n');
    }
    if (name === 'kind' && args[0] === 'get' && args[1] === 'clusters') {
      return result(0, this.clusterExists ? `${cluster}\n` : '');
    }
    if (name === 'kubectl' && args[0] === 'config' && args[1] === 'get-contexts') {
      const exists = this.clusterExists || this.options.contextExists;
      return result(0, exists ? `${context}\n` : '');
    }
    if (name === 'build-dataplane-container.sh') return result();
    if (name === 'docker' && args[0] === 'build') return result();
    if (name === 'docker' && args[0] === 'image' && args[1] === 'inspect') {
      const image = args[2];
      const id = crypto.createHash('sha256').update(image).digest('hex');
      return result(0, `${JSON.stringify([{
        Id: `sha256:${id}`,
        Descriptor: {
          digest: `sha256:${id}`,
          mediaType: 'application/vnd.oci.image.index.v1+json',
        },
        RepoTags: [image],
        Config: {Labels: {
          'org.opencontainers.image.revision': commit,
          'io.routesphere.bonvoyage.source-dirty': 'false',
        }},
      }])}\n`);
    }
    if (name === 'docker' && args[0] === 'image' && args[1] === 'save') {
      const archive = args[args.indexOf('--output') + 1];
      fs.writeFileSync(archive, `fake archive for ${path.basename(archive)}\n`);
      return result();
    }
    if (name === 'tar' && args[0] === '-xOf') {
      const archive = args[1];
      const member = args[2];
      const role = path.basename(archive, '.tar');
      const document = fakeArchive(role, this.options);
      if (member === 'index.json') return result(0, document.index);
      if (member === `blobs/sha256/${document.manifestDigest.slice(7)}`) {
        return result(0, document.manifest);
      }
      if (member === `blobs/sha256/${document.configDigest.slice(7)}`) {
        return result(0, document.configuration);
      }
      return result(1, '', `archive member not found: ${member}\n`);
    }
    if (name === 'kind' && args[0] === 'create') {
      this.clusterExists = true;
      return this.options.createFailsAfterCreation ?
        result(1, '', 'cluster bootstrap failed\n') : result(0, 'created\n');
    }
    if (name === 'kubectl' && args[0] === 'config' &&
        args[1] === 'current-context') {
      if (this.clusterExists) return result(0, `${context}\n`);
      if (this.options.previousContext) {
        return result(0, `${this.options.previousContext}\n`);
      }
      return result(1, '', 'current-context is not set\n');
    }
    if (name === 'kubectl' && args[0] === 'config' &&
        args[1] === 'use-context') return result(0, `Switched to context ${args[2]}.\n`);
    if (name === 'kind' && args[0] === 'load') return result();
    if (name === 'kind' && args[0] === 'export') return result();
    if (name === 'kind' && args[0] === 'delete') {
      this.clusterExists = false;
      this.namespaceExists = false;
      return result(0, 'deleted\n');
    }

    if (name === 'node' && args[0]?.endsWith('verify-kubernetes-deployment.mjs')) {
      assert.equal(options.env
        .BONVOYAGE_KUBERNETES_EXPECTED_DATAPLANE_ROOT_DIGEST,
      fakeArchive('dataplane', this.options).indexDigest);
      assert.equal(options.env
        .BONVOYAGE_KUBERNETES_EXPECTED_COMPILER_ROOT_DIGEST,
      fakeArchive('snapshot_compiler', this.options).indexDigest);
      assert.equal(options.env
        .BONVOYAGE_KUBERNETES_EXPECTED_UPSTREAM_ROOT_DIGEST,
      fakeArchive('upstream', this.options).indexDigest);
      return result(0, `status=pass\nconfig_map=${options.env
        .BONVOYAGE_KUBERNETES_EXPECTED_CONFIG_MAP}\n`);
    }

    if (name === 'kubectl' && args[0] === '--context') {
      assert.equal(args[1], context);
      return this.kubectl(args.slice(2));
    }
    throw new Error(`unhandled fake command: ${program} ${args.join(' ')}`);
  }

  kubectl(args) {
    if (args[0] === 'get' && args[1] === 'namespace') {
      return this.namespaceExists ? result(0, 'bonvoyage\n') :
        result(1, '', 'Error from server (NotFound): namespaces "bonvoyage" not found\n');
    }
    if (args[0] === 'apply' && args[1] === '-k') {
      this.namespaceExists = true;
      this.configMap = 'bonvoyage-config-v1';
      return result(0, 'applied\n');
    }
    if (args.includes('patch') && args.includes('deployment')) {
      const patch = JSON.parse(args[args.indexOf('-p') + 1]);
      this.configMap = patch.spec.template.spec.volumes[0].configMap.name;
      return result(0, 'patched\n');
    }
    if (args.includes('rollout') && args.includes('status')) {
      if (this.configMap === 'bonvoyage-config-invalid' &&
          !this.options.invalidRolloutSucceeds) {
        return result(1, '', 'error: timed out waiting for the condition\n');
      }
      return result(0, 'deployment successfully rolled out\n');
    }
    if (args[0] === '-n' && args[2] === 'get' && args[3] === 'replicasets') {
      return result(0, `${JSON.stringify({items: [{
        metadata: {name: 'bonvoyage-v1'},
        spec: {
          replicas: 0,
          template: {spec: {volumes: [{name: 'config', configMap: {
            name: 'bonvoyage-config-v1',
          }}]}},
        },
      }]})}\n`);
    }
    if (args[0] === '-n' && args[2] === 'get' && args[3] === 'pods') {
      const selector = args[args.indexOf('-l') + 1];
      if (selector === upstreamSelector) {
        return result(0, `${JSON.stringify({items: [{
          metadata: {name: 'upstream-0'},
          status: {conditions: [{type: 'Ready', status: 'True'}]},
        }]})}\n`);
      }
      if (this.configMap === 'bonvoyage-config-invalid') {
        const healthyCount = this.options.healthyCount ?? 2;
        const items = Array.from({length: healthyCount}, (_, index) =>
          gatewayPod(`gateway-v2-${index}`, 'bonvoyage-config-v2', true));
        items.push(gatewayPod('gateway-invalid',
          'bonvoyage-config-invalid', false, true));
        return result(0, `${JSON.stringify({items})}\n`);
      }
      const items = [
        gatewayPod('gateway-a', this.configMap, true),
        gatewayPod('gateway-b', this.configMap, true),
      ];
      this.gatewayPodQueries += 1;
      if (this.options.transientTerminatingPod &&
          this.configMap === 'bonvoyage-config-v2' &&
          !this.transientTerminatingPodObserved) {
        const terminating = gatewayPod('gateway-v1-terminating',
          'bonvoyage-config-v1', true);
        terminating.metadata.deletionTimestamp = '2026-10-20T00:00:00Z';
        items.push(terminating);
        this.transientTerminatingPodObserved = true;
      }
      return result(0, `${JSON.stringify({items})}\n`);
    }
    if (args[0] === '-n' && args[2] === 'get' && args[3] === 'deployment') {
      return result(0, `${JSON.stringify({
        status: {readyReplicas: 2, availableReplicas: 2},
      })}\n`);
    }
    if (args.includes('exec') && args.includes('wget')) {
      const url = args.at(-1);
      return result(0, url.endsWith('/bonvoyage/ready') ? 'ready-v2\n' : 'ok\n');
    }
    if (args.includes('logs')) return result(0, 'invalid YAML\n');
    if (args[0] === '-n' && args[2] === 'get' &&
        args[3] === 'all,poddisruptionbudgets,configmaps,replicasets,pods') {
      return result(0, 'apiVersion: v1\nkind: List\n');
    }
    if (args[0] === 'delete' || (args[0] === '-n' && args[2] === 'delete')) {
      this.namespaceExists = false;
      return result(0, 'namespace deleted\n');
    }
    if (args[0] === 'wait' || (args[0] === '-n' && args[2] === 'wait')) {
      return result(0, 'namespace condition met\n');
    }
    throw new Error(`unhandled fake kubectl command: ${args.join(' ')}`);
  }
}

function upstreamSelectorValue() {
  return 'app.kubernetes.io/name=bonvoyage-acceptance-upstream';
}
const upstreamSelector = upstreamSelectorValue();

function setup(t, fakeOptions = {}, runnerOptions = {}) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-k8s-run-'));
  t.after(() => fs.rmSync(temporary, {recursive: true, force: true}));
  const evidencePath = path.join(temporary, 'evidence');
  const executor = new FakeExecutor(fakeOptions);
  const acceptance = new KubernetesAcceptance({
    contractPath,
    evidencePath,
    confirmation: 'delete-kind-bonvoyage-oss-acceptance',
    ...runnerOptions,
  }, {executor, sleep: async () => {}});
  return {acceptance, evidencePath, executor};
}

function verifyChecksums(evidencePath) {
  const lines = fs.readFileSync(path.join(evidencePath, 'checksums.sha256'), 'utf8')
    .trim().split('\n');
  assert.ok(lines.length >= 2);
  for (const line of lines) {
    const match = line.match(/^([0-9a-f]{64})  (.+)$/u);
    assert.ok(match, line);
    const contents = fs.readFileSync(path.join(evidencePath, match[2]));
    assert.equal(crypto.createHash('sha256').update(contents).digest('hex'), match[1]);
  }
}

test('the runner contract pins its disposable cluster, tools, images, and claims', () => {
  const contract = JSON.parse(fs.readFileSync(contractPath, 'utf8'));
  assert.equal(contract.runner.cluster_name, cluster);
  assert.equal(contract.target.context, context);
  assert.equal(contract.runner.confirmation, `delete-kind-${cluster}`);
  assert.equal(contract.runner.kind_version, 'v0.33.0');
  assert.match(contract.runner.kind_node_image,
    /^kindest\/node:v1\.37\.0@sha256:[0-9a-f]{64}$/u);
  assert.deepEqual(Object.keys(contract.runner.images).sort(),
    ['dataplane', 'snapshot_compiler', 'upstream']);
  assert.equal(contract.schema_version, 2);
  assert.equal(contract.qualification_authority, 'live-run-summary-only');
  assert.equal(contract.qualifications.fresh_install_qualified, false);
  assert.equal(contract.qualifications.runner_foundation_qualified, true);
  assert.equal(contract.qualifications.upgrade_qualified, false);
  assert.equal(contract.qualifications.rollback_qualified, false);
  assert.equal(contract.qualifications.kubernetes_qualified, false);
  assert.equal(contract.qualifications.release_admitted, false);
  assert.equal(contract.qualifications.publishable, false);
});

test('the full lifecycle accepts baseline, upgrade, rejection, rollback, and teardown',
  async t => {
    const {acceptance, evidencePath, executor} = setup(t);
    const summary = await acceptance.run();
    assert.equal(summary.outcome, 'accepted');
    assert.deepEqual(summary.phases.map(phase => phase.id), [
      'preflight', 'baseline', 'upgrade', 'rejected-candidate', 'rollback',
      'teardown',
    ]);
    assert.equal(summary.qualifications.lifecycle_qualified, true);
    assert.equal(summary.qualifications.fresh_install_qualified, true);
    assert.equal(summary.qualifications.upgrade_qualified, true);
    assert.equal(summary.qualifications.rollback_qualified, true);
    assert.equal(summary.qualifications.kubernetes_qualified, true);
    assert.equal(summary.qualification_authority, 'live-run-summary');
    assert.equal(summary.image_identity_domain,
      'oci-archive-root-and-platform-graph');
    assert.equal(summary.images.dataplane.runtime_root_digest,
      fakeArchive('dataplane').indexDigest);
    assert.equal(summary.images.dataplane.platform_manifest_digest,
      fakeArchive('dataplane').manifestDigest);
    assert.equal(summary.qualifications.release_admitted, false);
    assert.equal(summary.qualifications.publishable, false);
    assert.equal(executor.clusterExists, false);
    assert.ok(executor.calls.some(call => call.args[0] === 'create'));
    const loads = executor.calls.filter(call => call.args[0] === 'load');
    assert.equal(loads.length, 3);
    assert.ok(loads.every(call => call.args[1] === 'image-archive'));
    assert.ok(executor.calls.some(call =>
      call.args.join(' ').includes('bonvoyage-config-invalid')));
    assert.ok(executor.calls.some(call => call.args[0] === 'delete' &&
      call.args[1] === 'cluster'));
    verifyChecksums(evidencePath);
  });

test('dirty source is rejected before any image build or cluster mutation', async t => {
  const {acceptance, evidencePath, executor} = setup(t, {dirtySource: true});
  await assert.rejects(acceptance.run(), Rejected);
  assert.equal(executor.calls.some(call =>
    path.basename(call.program) === 'build-dataplane-container.sh'), false);
  assert.equal(executor.calls.some(call => call.args[0] === 'create'), false);
  const summary = JSON.parse(fs.readFileSync(path.join(evidencePath, 'summary.json')));
  assert.equal(summary.outcome, 'rejected');
  assert.match(summary.error.message, /clean source/);
  verifyChecksums(evidencePath);
});

test('source drift caused during image construction blocks cluster creation', async t => {
  const {acceptance, executor} = setup(t, {dirtyAfterBuild: true});
  await assert.rejects(acceptance.run(), /source became dirty during post-build/);
  assert.ok(executor.calls.some(call =>
    path.basename(call.program) === 'build-dataplane-container.sh'));
  assert.equal(executor.calls.some(call => call.args[0] === 'create'), false);
});

test('an archive whose manifest bytes differ from its digest is rejected', async t => {
  const {acceptance, executor} = setup(t, {archiveDigestMismatch: true});
  await assert.rejects(acceptance.run(), /platform manifest content digest differs/);
  assert.equal(executor.calls.some(call => call.args[0] === 'create'), false);
});

test('an archive for a different platform is rejected before cluster creation',
  async t => {
    const {acceptance, executor} = setup(t, {archivePlatformMismatch: true});
    await assert.rejects(acceptance.run(), /archive platform differs/);
    assert.equal(executor.calls.some(call => call.args[0] === 'create'), false);
  });

test('archive configuration must independently retain clean-source labels',
  async t => {
    const {acceptance, executor} = setup(t, {archiveDirty: true});
    await assert.rejects(acceptance.run(), /archive is not clean-source bound/);
    assert.equal(executor.calls.some(call => call.args[0] === 'create'), false);
  });

test('an existing acceptance cluster is rejected and never deleted', async t => {
  const {acceptance, executor} = setup(t, {clusterExists: true});
  await assert.rejects(acceptance.run(), /already exists/);
  assert.equal(executor.calls.some(call => call.args[0] === 'delete' &&
    call.args[1] === 'cluster'), false);
  assert.equal(executor.clusterExists, true);
});

test('an existing dedicated context is rejected before cluster creation', async t => {
  const {acceptance, executor} = setup(t, {contextExists: true});
  await assert.rejects(acceptance.run(), /context already exists/);
  assert.equal(executor.calls.some(call => call.args[0] === 'create'), false);
});

test('a cluster left by failed creation is discovered and deleted safely', async t => {
  const {acceptance, executor} = setup(t, {createFailsAfterCreation: true});
  await assert.rejects(acceptance.run(), /cluster creation exited/);
  assert.equal(executor.clusterExists, false);
  assert.ok(executor.calls.some(call => call.args[0] === 'delete' &&
    call.args[1] === 'cluster'));
});

test('the Kubernetes context active before the run is restored after teardown',
  async t => {
    const {acceptance, executor} = setup(t, {previousContext: 'operator-context'});
    const summary = await acceptance.run();
    assert.equal(summary.teardown.previous_context, 'operator-context');
    assert.equal(summary.teardown.previous_context_restored, true);
    assert.ok(executor.calls.some(call =>
      call.args.join(' ') === 'config use-context operator-context'));
  });

test('rollout verification waits for terminating old replicas to disappear', async t => {
  const {acceptance, executor} = setup(t, {transientTerminatingPod: true});
  const summary = await acceptance.run();
  assert.equal(summary.outcome, 'accepted');
  assert.equal(executor.transientTerminatingPodObserved, true);
  assert.ok(executor.gatewayPodQueries >= 4);
});

test('the exact pinned kind version is mandatory', async t => {
  const {acceptance, executor} = setup(t, {wrongKindVersion: true});
  await assert.rejects(acceptance.run(), /v0\.33\.0/);
  assert.equal(executor.calls.some(call => call.args[0] === 'create'), false);
});

test('an invalid candidate that completes rollout is a hard failure with teardown',
  async t => {
    const {acceptance, executor, evidencePath} = setup(t,
      {invalidRolloutSucceeds: true});
    await assert.rejects(acceptance.run(), /unexpectedly completed/);
    assert.equal(executor.clusterExists, false);
    const summary = JSON.parse(fs.readFileSync(path.join(evidencePath, 'summary.json')));
    assert.equal(summary.outcome, 'rejected');
    assert.equal(summary.phases.some(phase => phase.id === 'rollback'), false);
    assert.equal(summary.teardown.passed, true);
  });

test('a failed candidate that reduces healthy capacity is rejected and torn down',
  async t => {
    const {acceptance, executor} = setup(t, {healthyCount: 1});
    await assert.rejects(acceptance.run(), /healthy upgraded replicas/);
    assert.equal(executor.clusterExists, false);
  });

test('the deletion confirmation is exact and bound to the dedicated cluster', async t => {
  const {acceptance, executor} = setup(t, {}, {confirmation: 'yes'});
  await assert.rejects(acceptance.run(), /BONVOYAGE_KUBERNETES_ACCEPTANCE_CONFIRM/);
  assert.equal(executor.calls.some(call => call.args[0] === 'create'), false);
});

test('an operator interrupt prevents mutation and still completes safe cleanup', async t => {
  const {acceptance, executor} = setup(t);
  acceptance.interrupt('SIGINT');
  await assert.rejects(acceptance.run(), /interrupted by SIGINT/);
  assert.equal(executor.calls.some(call => call.args[0] === 'create'), false);
  assert.equal(executor.clusterExists, false);
});
