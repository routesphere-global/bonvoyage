import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import yaml from 'js-yaml';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const verifier = path.join(root, 'scripts', 'verify-kubernetes-deployment.mjs');
const fixture = path.join(root, 'tests', 'fixtures',
  'oss-kubernetes-fresh-install');
const fakeKubectl = path.join(fixture, 'fake-kubectl.mjs');
const contractPath = path.join(root, 'packaging', 'release', 'kubernetes',
  'oss-kubernetes-fresh-install-contract.json');

function initialState() {
  return {
    podQueries: 0,
    nextPod: 0,
    counters: {
      'bonvoyage-a': {fixed: 0, proxied: 0},
      'bonvoyage-b': {fixed: 0, proxied: 0},
    },
  };
}

function runVerifier(t, mode = '', overrides = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-k8s-verify-'));
  const statePath = path.join(directory, 'state.json');
  fs.writeFileSync(statePath, `${JSON.stringify(initialState())}\n`);
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));

  const result = spawnSync(process.execPath, [verifier], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      BONVOYAGE_KUBECTL: fakeKubectl,
      BONVOYAGE_FAKE_KUBECTL_STATE: statePath,
      BONVOYAGE_FAKE_KUBECTL_MODE: mode,
      BONVOYAGE_KUBERNETES_REQUESTS_PER_ROUTE: '3',
      BONVOYAGE_KUBERNETES_EXPECTED_DATAPLANE_ROOT_DIGEST:
        `sha256:${'d'.repeat(64)}`,
      BONVOYAGE_KUBERNETES_EXPECTED_COMPILER_ROOT_DIGEST:
        `sha256:${'c'.repeat(64)}`,
      BONVOYAGE_KUBERNETES_EXPECTED_UPSTREAM_ROOT_DIGEST:
        `sha256:${'b'.repeat(64)}`,
      ...overrides,
    },
  });
  return {result, state: JSON.parse(fs.readFileSync(statePath, 'utf8'))};
}

test('the static contract delegates lifecycle qualification to live evidence', () => {
  const contract = JSON.parse(fs.readFileSync(contractPath, 'utf8'));
  assert.equal(contract.schema_version, 2);
  assert.equal(contract.qualification_authority, 'live-run-summary-only');
  assert.equal(contract.target.context, 'kind-bonvoyage-oss-acceptance');
  assert.equal(contract.target.replicas, 2);
  assert.equal(contract.target.metrics_service, 'bonvoyage-metrics');
  assert.deepEqual(contract.phases.map(phase => phase.id), [
    'preflight',
    'baseline',
    'upgrade',
    'rejected-candidate',
    'rollback',
    'teardown',
  ]);
  assert.equal(contract.qualifications.verifier_foundation_qualified, true);
  assert.equal(contract.qualifications.runner_foundation_qualified, true);
  for (const key of [
    'fresh_install_qualified',
    'upgrade_qualified',
    'rollback_qualified',
    'kubernetes_qualified',
  ]) assert.equal(contract.qualifications[key], false, key);
  for (const key of [
    'benchmark_reproduction_qualified',
    'release_admitted',
    'publishable',
  ]) assert.equal(contract.qualifications[key], false, key);
});

test('the fixture uses revisioned configuration and a containment rollout', () => {
  const kustomization = yaml.load(fs.readFileSync(
    path.join(fixture, 'kustomization.yaml'), 'utf8'));
  assert.deepEqual(kustomization.resources, [
    '../../../deploy/kubernetes/base',
    'configmap-v1.yaml',
    'configmap-v2.yaml',
    'configmap-invalid.yaml',
    'upstream.yaml',
  ]);
  const patch = yaml.load(fs.readFileSync(
    path.join(fixture, 'deployment-patch.yaml'), 'utf8'));
  assert.deepEqual(patch.spec.strategy, {
    type: 'RollingUpdate',
    rollingUpdate: {maxUnavailable: 0, maxSurge: 1},
  });
  assert.equal(patch.spec.template.spec.volumes[0].configMap.name,
    'bonvoyage-config-v1');

  const documents = [];
  yaml.loadAll(fs.readFileSync(path.join(fixture, 'upstream.yaml'), 'utf8'),
    value => documents.push(value));
  const upstream = documents.find(value => value.kind === 'Deployment');
  assert.equal(upstream.spec.template.spec.automountServiceAccountToken, false);
  assert.equal(upstream.spec.template.spec.securityContext.runAsNonRoot, true);
  assert.equal(upstream.spec.template.metadata.labels[
    'routesphere.global/metrics-access'], 'true');
  const container = upstream.spec.template.spec.containers[0];
  assert.equal(container.securityContext.readOnlyRootFilesystem, true);
  assert.deepEqual(container.securityContext.capabilities.drop, ['ALL']);

  const invalid = yaml.load(fs.readFileSync(
    path.join(fixture, 'configmap-invalid.yaml'), 'utf8'));
  assert.throws(() => yaml.load(invalid.data['local.yaml']), /unexpected end|missed comma/i);
});

test('the base defaults gateway ingress to deny and scopes diagnostics', () => {
  const base = path.join(root, 'deploy', 'kubernetes', 'base');
  const kustomization = yaml.load(fs.readFileSync(
    path.join(base, 'kustomization.yaml'), 'utf8'));
  for (const resource of [
    'metrics-service.yaml',
    'network-policy-default-deny.yaml',
    'network-policy-data.yaml',
    'network-policy-metrics.yaml',
    'network-policy-admin.yaml',
  ]) assert.ok(kustomization.resources.includes(resource), resource);

  const service = yaml.load(fs.readFileSync(path.join(base, 'service.yaml'), 'utf8'));
  assert.equal(service.spec.type, 'ClusterIP');
  assert.deepEqual(service.spec.selector, {
    'app.kubernetes.io/name': 'bonvoyage',
    'app.kubernetes.io/component': 'gateway',
  });
  assert.deepEqual(service.spec.ports, [{name: 'http', port: 80, targetPort: 'http'}]);
  const metricsService = yaml.load(fs.readFileSync(
    path.join(base, 'metrics-service.yaml'), 'utf8'));
  assert.equal(metricsService.spec.type, 'ClusterIP');
  assert.deepEqual(metricsService.spec.selector, {
    'app.kubernetes.io/name': 'bonvoyage',
    'app.kubernetes.io/component': 'gateway',
  });
  assert.deepEqual(metricsService.spec.ports,
    [{name: 'metrics', port: 9090, targetPort: 'metrics'}]);

  const selector = {
    'app.kubernetes.io/name': 'bonvoyage',
    'app.kubernetes.io/component': 'gateway',
  };
  const loadPolicy = name => yaml.load(fs.readFileSync(path.join(base, name), 'utf8'));
  const defaultDeny = loadPolicy('network-policy-default-deny.yaml');
  assert.deepEqual(defaultDeny.spec.podSelector.matchLabels, selector);
  assert.deepEqual(defaultDeny.spec.policyTypes, ['Ingress']);
  assert.deepEqual(defaultDeny.spec.ingress, []);

  const data = loadPolicy('network-policy-data.yaml');
  assert.equal(Object.hasOwn(data.spec.ingress[0], 'from'), false);
  assert.deepEqual(data.spec.ingress[0].ports, [
    {protocol: 'TCP', port: 8080},
    {protocol: 'TCP', port: 8443},
  ]);

  for (const [file, accessLabel, port] of [
    ['network-policy-metrics.yaml', 'routesphere.global/metrics-access', 9090],
    ['network-policy-admin.yaml', 'routesphere.global/diagnostics-access', 9901],
  ]) {
    const policy = loadPolicy(file);
    assert.deepEqual(policy.spec.podSelector.matchLabels, selector);
    assert.deepEqual(policy.spec.policyTypes, ['Ingress']);
    assert.equal(policy.spec.ingress.length, 1);
    assert.deepEqual(policy.spec.ingress[0].from, [{
      podSelector: {matchLabels: {[accessLabel]: 'true'}},
    }]);
    assert.deepEqual(policy.spec.ingress[0].ports, [{protocol: 'TCP', port}]);
  }
});

test('the base fails closed until an overlay supplies immutable image digests', () => {
  const deployment = yaml.load(fs.readFileSync(
    path.join(root, 'deploy', 'kubernetes', 'base', 'deployment.yaml'), 'utf8'));
  const pod = deployment.spec.template.spec;
  const compiler = pod.initContainers.find(value => value.name === 'snapshot-compiler');
  const dataplane = pod.containers.find(value => value.name === 'dataplane');
  for (const image of [compiler.image, dataplane.image]) {
    assert.match(image, /@sha256:[0-9a-f]{64}$/);
    assert.match(image, /@sha256:0{64}$/);
  }
});

test('the verifier accepts exact readiness, traffic, accounting, and identity', t => {
  const {result, state} = runVerifier(t);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^status=pass$/m);
  assert.match(result.stdout, /^replicas=2$/m);
  assert.match(result.stdout, /^request_delta=6$/m);
  assert.match(result.stdout, /^upstream_selection_delta=3$/m);
  assert.match(result.stdout, /^admin_service_exposed=false$/m);
  assert.match(result.stdout, /^gateway_service_set_exact=true$/m);
  assert.match(result.stdout, /^network_policy_set_exact=true$/m);
  assert.match(result.stdout, /^host_network_disabled=true$/m);
  assert.match(result.stdout, /^host_ports_absent=true$/m);
  assert.match(result.stdout, /^metrics_service_routable=true$/m);
  assert.match(result.stdout, /^diagnostic_ingress_default_deny=true$/m);
  assert.match(result.stdout, /^metrics_ingress_scoped=true$/m);
  assert.match(result.stdout, /^admin_ingress_scoped=true$/m);
  assert.equal(state.podQueries, 2);
  assert.equal(Object.values(state.counters)
    .reduce((sum, value) => sum + value.fixed, 0), 3);
  assert.equal(Object.values(state.counters)
    .reduce((sum, value) => sum + value.proxied, 0), 3);
});

test('the verifier compares Kubernetes label maps independent of key order', t => {
  const {result} = runVerifier(t, 'reordered-label-map');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^status=pass$/m);
});

test('the verifier rejects an unrelated active context before observation', t => {
  const {result, state} = runVerifier(t, 'wrong-context');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /active Kubernetes context/);
  assert.equal(state.podQueries, 0);
});

test('the verifier rejects an invalid request bound', t => {
  const {result} = runVerifier(t, '', {
    BONVOYAGE_KUBERNETES_REQUESTS_PER_ROUTE: 'many',
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /must be a positive integer/);
});

test('the verifier rejects incomplete deployment readiness', t => {
  const {result} = runVerifier(t, 'bad-ready');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /ready gateway replicas/);
});

test('the verifier rejects an exposed admin service', t => {
  const {result} = runVerifier(t, 'admin-exposed');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /gateway service port count|admin listener/);
});

test('the verifier rejects a missing default-deny policy', t => {
  const {result} = runVerifier(t, 'missing-network-policy');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /default-deny policy/);
});

test('the verifier rejects an unexpected additional network policy', t => {
  const {result} = runVerifier(t, 'extra-network-policy');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /namespace network-policy names/);
});

test('the verifier rejects NetworkPolicy selector expressions', t => {
  const {result} = runVerifier(t, 'policy-selector-expression');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /gateway metrics policy pod selector/);
});

test('the verifier rejects a cross-namespace metrics policy', t => {
  const {result} = runVerifier(t, 'broad-metrics-policy');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /metrics policy source/);
});

test('the verifier rejects a cross-namespace admin policy', t => {
  const {result} = runVerifier(t, 'broad-admin-policy');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /admin policy source/);
});

test('the verifier rejects host networking', t => {
  const {result} = runVerifier(t, 'host-network');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /host-network state/);
});

test('the verifier rejects host ports', t => {
  const {result} = runVerifier(t, 'host-port');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /host-port state/);
});

test('the verifier rejects an externally exposed metrics service', t => {
  const {result} = runVerifier(t, 'loadbalancer-metrics-service');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /gateway metrics service type/);
});

test('the verifier rejects a metrics node port', t => {
  const {result} = runVerifier(t, 'node-port-metrics-service');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /gateway metrics service exposes a node port/);
});

test('the verifier rejects an additional admin service', t => {
  const {result} = runVerifier(t, 'extra-admin-service');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /namespace service names/);
});

test('the verifier rejects an additional selectorless service', t => {
  const {result} = runVerifier(t, 'extra-selectorless-service');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /namespace service names/);
});

test('the verifier rejects a widened gateway service selector', t => {
  const {result} = runVerifier(t, 'wrong-service-selector');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /gateway metrics service selector/);
});

test('the verifier rejects weakened pod security', t => {
  const {result} = runVerifier(t, 'bad-security');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /read-only root filesystem/);
});

test('the verifier rejects a dataplane restart', t => {
  const {result} = runVerifier(t, 'restart');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /dataplane restart count/);
});

test('the verifier rejects a consistent but unapproved dataplane OCI root', t => {
  const {result} = runVerifier(t, '', {
    BONVOYAGE_KUBERNETES_EXPECTED_DATAPLANE_ROOT_DIGEST:
      `sha256:${'e'.repeat(64)}`,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /approved dataplane OCI root digest/);
});

test('the verifier rejects a consistent but unapproved compiler OCI root', t => {
  const {result} = runVerifier(t, '', {
    BONVOYAGE_KUBERNETES_EXPECTED_COMPILER_ROOT_DIGEST:
      `sha256:${'e'.repeat(64)}`,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /approved compiler OCI root digest/);
});

test('the verifier rejects an unapproved dataplane image reference', t => {
  const {result} = runVerifier(t, 'wrong-dataplane-reference');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /approved dataplane image reference/);
});

test('the verifier rejects an unapproved controlled-upstream OCI root', t => {
  const {result} = runVerifier(t, 'wrong-upstream-digest');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /controlled upstream approved OCI root digest/);
});

test('the verifier rejects response drift', t => {
  const {result} = runVerifier(t, 'bad-body');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /fixed-route body/);
});

test('the verifier rejects accounting drift', t => {
  const {result} = runVerifier(t, 'bad-accounting');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /upstream-selection counter delta/);
});

test('the verifier rejects a missing required metric', t => {
  const {result} = runVerifier(t, 'missing-metric');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /required metric is absent/);
});

test('the verifier rejects a nonzero runtime failure counter', t => {
  const {result} = runVerifier(t, 'runtime-error');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /bonvoyage_memory_malloc_failed/);
});

test('the verifier rejects pod replacement during the bounded sample', t => {
  const {result} = runVerifier(t, 'identity-change');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /gateway pod identities/);
});
