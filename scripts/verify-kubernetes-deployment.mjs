#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {spawnSync} from 'node:child_process';
import {isDeepStrictEqual} from 'node:util';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const contractPath = path.resolve(
  process.env.BONVOYAGE_KUBERNETES_CONTRACT ||
    path.join(root, 'packaging', 'release', 'kubernetes',
      'oss-kubernetes-fresh-install-contract.json'),
);
const kubectl = process.env.BONVOYAGE_KUBECTL || 'kubectl';
const requestCount = positiveInteger(
  process.env.BONVOYAGE_KUBERNETES_REQUESTS_PER_ROUTE || '25',
  'BONVOYAGE_KUBERNETES_REQUESTS_PER_ROUTE',
);
const requestTimeout = positiveInteger(
  process.env.BONVOYAGE_KUBERNETES_REQUEST_TIMEOUT_SECONDS || '10',
  'BONVOYAGE_KUBERNETES_REQUEST_TIMEOUT_SECONDS',
);

function fail(message, exitCode = 1) {
  console.error(`Kubernetes deployment verification failed: ${message}`);
  process.exit(exitCode);
}

function positiveInteger(value, label) {
  if (!/^[1-9][0-9]*$/.test(value)) {
    fail(`${label} must be a positive integer`, 2);
  }
  return Number.parseInt(value, 10);
}

function requireValue(condition, message) {
  if (!condition) fail(message);
}

function exact(actual, expected, label) {
  if (actual !== expected) {
    fail(`${label}: expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
  }
}

function deepExact(actual, expected, label) {
  if (!isDeepStrictEqual(actual, expected)) {
    fail(`${label}: expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
  }
}

function imageDigest(value, label) {
  const match = String(value || '').match(/(sha256:[0-9a-f]{64})$/);
  requireValue(match, `${label} is not an immutable sha256 identity`);
  return match[1];
}

function readJSON(file, label) {
  let value;
  try {
    value = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`, 2);
  }
  return value;
}

function runKubectl(args, label) {
  const result = spawnSync(kubectl, args, {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error) {
    fail(`${label}: unable to execute ${kubectl}: ${result.error.message}`, 2);
  }
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || '').trim();
    fail(`${label}: kubectl exited ${result.status}${detail ? `: ${detail}` : ''}`);
  }
  return result.stdout;
}

function kubectlJSON(args, label) {
  const output = runKubectl([...args, '-o', 'json'], label);
  try {
    return JSON.parse(output);
  } catch (error) {
    fail(`${label}: kubectl returned invalid JSON: ${error.message}`);
  }
}

function named(items, name, label) {
  const value = items?.find(item => item.name === name);
  requireValue(value, `${label} ${JSON.stringify(name)} is absent`);
  return value;
}

function readyCondition(pod) {
  return pod.status?.conditions?.some(
    condition => condition.type === 'Ready' && condition.status === 'True',
  );
}

function intOrString(value) {
  return typeof value === 'number' ? value : Number.parseInt(value, 10);
}

function validateSecurity(pod, contract) {
  const podName = pod.metadata?.name || '<unnamed>';
  const security = contract.security;
  const podSecurity = pod.spec?.securityContext || {};
  exact(Boolean(pod.spec?.hostNetwork), security.host_network,
    `${podName} host-network state`);
  const containers = [
    ...(pod.spec?.initContainers || []),
    ...(pod.spec?.containers || []),
  ];
  const hasHostPorts = containers.some(container =>
    (container.ports || []).some(port =>
      port.hostPort !== undefined && intOrString(port.hostPort) !== 0));
  exact(hasHostPorts, security.host_ports, `${podName} host-port state`);
  exact(pod.spec?.automountServiceAccountToken,
    security.automount_service_account_token,
    `${podName} service-account token automount`);
  exact(podSecurity.runAsNonRoot, security.run_as_non_root,
    `${podName} runAsNonRoot`);
  exact(podSecurity.runAsUser, security.run_as_user, `${podName} runAsUser`);
  exact(podSecurity.runAsGroup, security.run_as_group, `${podName} runAsGroup`);
  exact(podSecurity.seccompProfile?.type, security.seccomp_profile,
    `${podName} seccomp profile`);

  const dataplane = named(pod.spec?.containers, 'dataplane', `${podName} container`);
  const containerSecurity = dataplane.securityContext || {};
  exact(containerSecurity.allowPrivilegeEscalation,
    security.allow_privilege_escalation,
    `${podName} privilege escalation`);
  exact(containerSecurity.readOnlyRootFilesystem,
    security.read_only_root_filesystem,
    `${podName} read-only root filesystem`);
  deepExact(containerSecurity.capabilities?.drop, security.drop_capabilities,
    `${podName} dropped capabilities`);
  exact(dataplane.resources?.requests?.cpu, '1', `${podName} requested CPU`);
  exact(dataplane.resources?.limits?.cpu, '1', `${podName} CPU limit`);
  exact(dataplane.resources?.requests?.memory, '512Mi',
    `${podName} requested memory`);
  exact(dataplane.resources?.limits?.memory, '512Mi', `${podName} memory limit`);
  const snapshotMount = named(dataplane.volumeMounts, 'snapshot',
    `${podName} volume mount`);
  exact(snapshotMount.readOnly, true, `${podName} snapshot mount read-only state`);
}

function validatePod(pod, contract, expectedConfigMap, expectedImages) {
  const podName = pod.metadata?.name || '<unnamed>';
  requireValue(!pod.metadata?.deletionTimestamp, `${podName} is terminating`);
  requireValue(readyCondition(pod), `${podName} is not Ready`);
  requireValue(pod.status?.podIP, `${podName} has no pod IP`);
  requireValue(pod.metadata?.uid, `${podName} has no UID`);
  validateSecurity(pod, contract);
  deepExact(pod.metadata?.labels, {
    'app.kubernetes.io/name': 'bonvoyage',
    'app.kubernetes.io/component': 'gateway',
  }, `${podName} labels`);

  const configVolume = named(pod.spec?.volumes, 'config', `${podName} volume`);
  exact(configVolume.configMap?.name, expectedConfigMap,
    `${podName} selected configuration`);

  const initStatus = named(pod.status?.initContainerStatuses,
    'snapshot-compiler', `${podName} init status`);
  const initContainer = named(pod.spec?.initContainers,
    'snapshot-compiler', `${podName} init container`);
  exact(initContainer.image, expectedImages.compiler.name,
    `${podName} approved compiler image reference`);
  exact(initStatus.restartCount, 0, `${podName} compiler restart count`);
  exact(initStatus.state?.terminated?.exitCode, 0,
    `${podName} compiler exit code`);
  requireValue(initStatus.imageID, `${podName} compiler image identity is absent`);
  const compilerImageID = imageDigest(initStatus.imageID,
    `${podName} compiler image identity`);
  exact(compilerImageID, expectedImages.compiler.digest,
    `${podName} approved compiler OCI root digest`);

  const dataplane = named(pod.spec?.containers, 'dataplane',
    `${podName} container`);
  exact(dataplane.image, expectedImages.dataplane.name,
    `${podName} approved dataplane image reference`);
  const dataplaneStatus = named(pod.status?.containerStatuses,
    'dataplane', `${podName} container status`);
  exact(dataplaneStatus.ready, true, `${podName} dataplane readiness`);
  exact(dataplaneStatus.restartCount, 0, `${podName} dataplane restart count`);
  requireValue(dataplaneStatus.state?.running?.startedAt,
    `${podName} dataplane is not running`);
  requireValue(dataplaneStatus.imageID,
    `${podName} dataplane image identity is absent`);
  const dataplaneImageID = imageDigest(dataplaneStatus.imageID,
    `${podName} dataplane image identity`);
  exact(dataplaneImageID, expectedImages.dataplane.digest,
    `${podName} approved dataplane OCI root digest`);

  return {
    name: podName,
    uid: pod.metadata.uid,
    ip: pod.status.podIP,
    dataplaneImageID,
    compilerImageID,
  };
}

function metricValue(document, metric) {
  let found = false;
  let sum = 0;
  for (const line of document.split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{[^}]*\})?\s+([^\s]+)(?:\s+\d+)?$/);
    if (!match || match[1] !== metric) continue;
    const value = Number(match[2]);
    requireValue(Number.isFinite(value), `${metric} contains a non-numeric sample`);
    found = true;
    sum += value;
  }
  requireValue(found, `required metric is absent: ${metric}`);
  return sum;
}

const contract = readJSON(contractPath, 'Kubernetes acceptance contract');
exact(contract.schema_version, 2, 'contract schema version');
exact(contract.classification,
  'routesphere-bonvoyage-oss-kubernetes-fresh-install-contract',
  'contract classification');
exact(contract.qualification_authority, 'live-run-summary-only',
  'contract qualification authority');
exact(contract.qualifications?.verifier_foundation_qualified, true,
  'verifier foundation qualification');
for (const key of ['fresh_install_qualified', 'upgrade_qualified',
  'rollback_qualified', 'kubernetes_qualified',
  'benchmark_reproduction_qualified', 'release_admitted', 'publishable']) {
  exact(contract.qualifications?.[key], false,
    `static contract ${key}`);
}

const namespace = contract.target?.namespace;
const deploymentName = contract.target?.deployment;
const serviceName = contract.target?.service;
const metricsServiceName = contract.target?.metrics_service;
const replicas = contract.target?.replicas;
const expectedContext = process.env.BONVOYAGE_KUBERNETES_CONTEXT ||
  contract.target?.context;
const expectedConfigMap = process.env.BONVOYAGE_KUBERNETES_EXPECTED_CONFIG_MAP ||
  contract.fixture?.baseline_config_map;
const expectedImages = {
  dataplane: {
    name: contract.runner?.images?.dataplane,
    digest: imageDigest(
      process.env.BONVOYAGE_KUBERNETES_EXPECTED_DATAPLANE_ROOT_DIGEST,
      'BONVOYAGE_KUBERNETES_EXPECTED_DATAPLANE_ROOT_DIGEST',
    ),
  },
  compiler: {
    name: contract.runner?.images?.snapshot_compiler,
    digest: imageDigest(
      process.env.BONVOYAGE_KUBERNETES_EXPECTED_COMPILER_ROOT_DIGEST,
      'BONVOYAGE_KUBERNETES_EXPECTED_COMPILER_ROOT_DIGEST',
    ),
  },
  upstream: {
    name: contract.runner?.images?.upstream,
    digest: imageDigest(
      process.env.BONVOYAGE_KUBERNETES_EXPECTED_UPSTREAM_ROOT_DIGEST,
      'BONVOYAGE_KUBERNETES_EXPECTED_UPSTREAM_ROOT_DIGEST',
    ),
  },
};
const fixedBody = process.env.BONVOYAGE_KUBERNETES_EXPECTED_FIXED_BODY ||
  (expectedConfigMap === contract.fixture?.upgrade_config_map ? 'ready-v2\n' : 'ready-v1\n');
const proxiedBody = process.env.BONVOYAGE_KUBERNETES_EXPECTED_PROXIED_BODY || 'ok\n';

requireValue(namespace && deploymentName && serviceName && metricsServiceName &&
  expectedContext,
  'contract target is incomplete');
exact(runKubectl(['config', 'current-context'], 'current context').trim(),
  expectedContext, 'active Kubernetes context');

const namespaced = ['-n', namespace];
const deployment = kubectlJSON([...namespaced, 'get', 'deployment', deploymentName],
  'gateway deployment');
const gatewayLabels = {
  'app.kubernetes.io/name': 'bonvoyage',
  'app.kubernetes.io/component': 'gateway',
};
exact(deployment.spec?.replicas, replicas, 'gateway replica target');
deepExact(deployment.spec?.selector?.matchLabels, gatewayLabels,
  'gateway deployment selector');
deepExact(deployment.spec?.template?.metadata?.labels, gatewayLabels,
  'gateway pod-template labels');
exact(deployment.spec?.strategy?.type, contract.rollout?.strategy,
  'gateway rollout strategy');
exact(intOrString(deployment.spec?.strategy?.rollingUpdate?.maxUnavailable),
  contract.rollout?.maximum_unavailable, 'maximum unavailable replicas');
exact(intOrString(deployment.spec?.strategy?.rollingUpdate?.maxSurge),
  contract.rollout?.maximum_surge, 'maximum surge replicas');
requireValue(deployment.status?.observedGeneration >= deployment.metadata?.generation,
  'gateway deployment generation is not observed');
exact(deployment.status?.updatedReplicas, replicas, 'updated gateway replicas');
exact(deployment.status?.readyReplicas, replicas, 'ready gateway replicas');
exact(deployment.status?.availableReplicas, replicas, 'available gateway replicas');
exact(deployment.status?.unavailableReplicas || 0, 0, 'unavailable gateway replicas');

const service = kubectlJSON([...namespaced, 'get', 'service', serviceName],
  'gateway service');
function validateGatewayService(value, label) {
  deepExact(value.spec?.selector, gatewayLabels, `${label} selector`);
  exact(value.spec?.type, 'ClusterIP', `${label} type`);
  deepExact(value.spec?.externalIPs || [], [], `${label} external IPs`);
  requireValue(!(value.spec?.ports || []).some(port =>
    port.nodePort !== undefined && intOrString(port.nodePort) !== 0),
  `${label} exposes a node port`);
}
validateGatewayService(service, 'gateway service');
const servicePorts = service.spec?.ports || [];
exact(servicePorts.length, 1, 'gateway service port count');
const httpPort = named(servicePorts, 'http', 'gateway service port');
exact(httpPort.port, 80, 'gateway service HTTP port');
exact(httpPort.targetPort, 'http', 'gateway service HTTP target');
const metricsService = kubectlJSON([...namespaced, 'get', 'service',
  metricsServiceName], 'gateway metrics service');
validateGatewayService(metricsService, 'gateway metrics service');
const metricsServicePorts = metricsService.spec?.ports || [];
exact(metricsServicePorts.length, 1, 'gateway metrics service port count');
const metricsPort = named(metricsServicePorts, 'metrics',
  'gateway metrics service port');
exact(metricsPort.port, 9090, 'gateway service metrics port');
exact(metricsPort.targetPort, 'metrics', 'gateway service metrics target');
const exposedPorts = [...servicePorts, ...metricsServicePorts];
requireValue(!exposedPorts.some(port => port.name === 'admin' || port.port === 9901 ||
  port.targetPort === 'admin' || port.targetPort === 9901),
'gateway service exposes the admin listener');

const namespaceServices = kubectlJSON([...namespaced, 'get', 'services'],
  'namespace services');
const expectedServiceNames = [
  serviceName,
  metricsServiceName,
  contract.fixture?.controlled_upstream_service,
].sort();
const actualServiceNames = (namespaceServices.items || [])
  .map(value => value.metadata?.name)
  .sort();
deepExact(actualServiceNames, expectedServiceNames,
  'namespace service names');

const networkPolicyContract = contract.security?.network_policy;
requireValue(networkPolicyContract?.default_deny && networkPolicyContract?.data &&
  networkPolicyContract?.metrics && networkPolicyContract?.admin &&
  networkPolicyContract?.metrics_access_label &&
  networkPolicyContract?.admin_access_label,
'network-policy contract is incomplete');
const namespacePolicies = kubectlJSON([...namespaced, 'get', 'networkpolicies'],
  'namespace network policies');
const expectedPolicyNames = [
  networkPolicyContract.default_deny,
  networkPolicyContract.data,
  networkPolicyContract.metrics,
  networkPolicyContract.admin,
].sort();
const actualPolicyNames = (namespacePolicies.items || [])
  .map(value => value.metadata?.name)
  .sort();
deepExact(actualPolicyNames, expectedPolicyNames,
  'namespace network-policy names');
function policy(name, label) {
  const value = kubectlJSON([...namespaced, 'get', 'networkpolicy', name], label);
  deepExact(value.spec?.podSelector, {matchLabels: gatewayLabels},
    `${label} pod selector`);
  deepExact(value.spec?.policyTypes, ['Ingress'], `${label} policy types`);
  return value;
}
function scopedDiagnosticPolicy(value, accessLabel, port, label) {
  const ingress = value.spec?.ingress || [];
  exact(ingress.length, 1, `${label} ingress rule count`);
  exact(ingress[0].from?.length, 1, `${label} source count`);
  const source = ingress[0].from[0];
  deepExact(source, {
    podSelector: {matchLabels: {[accessLabel]: 'true'}},
  }, `${label} source`);
  deepExact(ingress[0].ports, [{protocol: 'TCP', port}], `${label} ports`);
}

const defaultDenyPolicy = policy(networkPolicyContract.default_deny,
  'gateway default-deny policy');
deepExact(defaultDenyPolicy.spec?.ingress, [],
  'gateway default-deny ingress rules');
const dataPolicy = policy(networkPolicyContract.data, 'gateway data policy');
const dataIngress = dataPolicy.spec?.ingress || [];
exact(dataIngress.length, 1, 'gateway data ingress rule count');
requireValue(!Object.hasOwn(dataIngress[0], 'from'),
  'gateway data ingress unexpectedly restricts downstream sources');
deepExact(dataIngress[0].ports, [
  {protocol: 'TCP', port: 8080},
  {protocol: 'TCP', port: 8443},
], 'gateway data ingress ports');
const metricsPolicy = policy(networkPolicyContract.metrics,
  'gateway metrics policy');
scopedDiagnosticPolicy(metricsPolicy,
  networkPolicyContract.metrics_access_label, 9090, 'gateway metrics policy');
const adminPolicy = policy(networkPolicyContract.admin, 'gateway admin policy');
scopedDiagnosticPolicy(adminPolicy,
  networkPolicyContract.admin_access_label, 9901, 'gateway admin policy');

const disruptionBudget = kubectlJSON([...namespaced, 'get',
  'poddisruptionbudget', deploymentName], 'gateway disruption budget');
exact(intOrString(disruptionBudget.spec?.maxUnavailable), 1,
  'disruption-budget maximum unavailable replicas');
exact(disruptionBudget.status?.currentHealthy, replicas,
  'disruption-budget healthy replicas');
exact(disruptionBudget.status?.expectedPods, replicas,
  'disruption-budget expected replicas');

const gatewaySelector =
  'app.kubernetes.io/name=bonvoyage,app.kubernetes.io/component=gateway';
const gatewayPodsBefore = kubectlJSON([...namespaced, 'get', 'pods',
  '-l', gatewaySelector], 'gateway pods');
exact(gatewayPodsBefore.items?.length, replicas, 'gateway pod count');
const identitiesBefore = gatewayPodsBefore.items
  .map(pod => validatePod(pod, contract, expectedConfigMap, expectedImages))
  .sort((left, right) => left.name.localeCompare(right.name));
exact(new Set(identitiesBefore.map(value => value.dataplaneImageID)).size, 1,
  'dataplane image identity count');
exact(new Set(identitiesBefore.map(value => value.compilerImageID)).size, 1,
  'compiler image identity count');

const upstreamSelector =
  `app.kubernetes.io/name=${contract.fixture?.controlled_upstream_deployment}`;
const upstreamPods = kubectlJSON([...namespaced, 'get', 'pods',
  '-l', upstreamSelector], 'controlled upstream pods');
exact(upstreamPods.items?.length, 1, 'controlled upstream pod count');
const upstreamPod = upstreamPods.items[0];
requireValue(readyCondition(upstreamPod), 'controlled upstream is not Ready');
exact(upstreamPod.metadata?.labels?.[networkPolicyContract.metrics_access_label],
  'true', 'controlled upstream metrics-access label');
const upstreamContainer = named(upstreamPod.spec?.containers,
  'upstream', 'controlled upstream container');
exact(upstreamContainer.image, expectedImages.upstream.name,
  'controlled upstream approved image reference');
const upstreamStatus = named(upstreamPod.status?.containerStatuses,
  'upstream', 'controlled upstream status');
exact(upstreamStatus.ready, true, 'controlled upstream readiness');
exact(upstreamStatus.restartCount, 0, 'controlled upstream restart count');
const upstreamImageID = imageDigest(upstreamStatus.imageID,
  'controlled upstream image identity');
exact(upstreamImageID, expectedImages.upstream.digest,
  'controlled upstream approved OCI root digest');
const upstreamPodName = upstreamPod.metadata?.name;
requireValue(upstreamPodName, 'controlled upstream pod name is absent');

function probe(url, label) {
  return runKubectl([...namespaced, 'exec', upstreamPodName, '--',
    'wget', '-q', '-O', '-', '-T', String(requestTimeout), url], label);
}

function captureMetrics(identities) {
  return new Map(identities.map(identity => [identity.name,
    probe(`http://${identity.ip}:9090/metrics`, `${identity.name} metrics`),
  ]));
}

function metricTotal(documents, metric) {
  let sum = 0;
  for (const document of documents.values()) sum += metricValue(document, metric);
  return sum;
}

const serviceURL = `http://${serviceName}.${namespace}.svc.cluster.local`;
const metricsServiceURL =
  `http://${metricsServiceName}.${namespace}.svc.cluster.local:9090/metrics`;
const metricsServiceDocument = probe(metricsServiceURL,
  'gateway metrics service');
exact(metricValue(metricsServiceDocument,
  'bonvoyage_bonvoyage_gateway_ready'), 1,
'gateway metrics service readiness');
const metricsBefore = captureMetrics(identitiesBefore);
const requestsBefore = metricTotal(metricsBefore,
  'bonvoyage_bonvoyage_gateway_requests_total');
const responsesBefore = metricTotal(metricsBefore,
  'bonvoyage_bonvoyage_gateway_responses_2xx_total');
const upstreamBefore = metricTotal(metricsBefore,
  'bonvoyage_bonvoyage_gateway_upstream_endpoint_selections_total');

for (const [podName, document] of metricsBefore) {
  exact(metricValue(document, 'bonvoyage_bonvoyage_gateway_ready'), 1,
    `${podName} readiness metric`);
  exact(metricValue(document, 'bonvoyage_bonvoyage_gateway_configured_routes'),
    contract.traffic?.expected_configured_routes_per_pod,
    `${podName} configured routes`);
  exact(metricValue(document, 'bonvoyage_bonvoyage_gateway_configured_listeners'),
    contract.traffic?.expected_configured_listeners_per_pod,
    `${podName} configured listeners`);
  exact(metricValue(document, 'bonvoyage_bonvoyage_gateway_configured_clusters'),
    contract.traffic?.expected_configured_clusters_per_pod,
    `${podName} configured clusters`);
  exact(metricValue(document, 'bonvoyage_bonvoyage_gateway_configured_endpoints'),
    contract.traffic?.expected_configured_endpoints_per_pod,
    `${podName} configured endpoints`);
}

for (let index = 0; index < requestCount; index += 1) {
  exact(probe(`${serviceURL}/bonvoyage/ready`, 'fixed route'), fixedBody,
    'fixed-route body');
  exact(probe(`${serviceURL}/healthz`, 'proxied route'), proxiedBody,
    'proxied-route body');
}

const metricsAfter = captureMetrics(identitiesBefore);
const requestsAfter = metricTotal(metricsAfter,
  'bonvoyage_bonvoyage_gateway_requests_total');
const responsesAfter = metricTotal(metricsAfter,
  'bonvoyage_bonvoyage_gateway_responses_2xx_total');
const upstreamAfter = metricTotal(metricsAfter,
  'bonvoyage_bonvoyage_gateway_upstream_endpoint_selections_total');
const expectedRequests = requestCount * 2;
exact(requestsAfter - requestsBefore, expectedRequests, 'request counter delta');
exact(responsesAfter - responsesBefore, expectedRequests,
  '2xx response counter delta');
exact(upstreamAfter - upstreamBefore, requestCount,
  'upstream-selection counter delta');

for (const metric of contract.traffic?.zero_counters || []) {
  exact(metricTotal(metricsAfter, metric), 0, metric);
}

const gatewayPodsAfter = kubectlJSON([...namespaced, 'get', 'pods',
  '-l', gatewaySelector], 'final gateway pods');
exact(gatewayPodsAfter.items?.length, replicas, 'final gateway pod count');
const identitiesAfter = gatewayPodsAfter.items
  .map(pod => validatePod(pod, contract, expectedConfigMap, expectedImages))
  .sort((left, right) => left.name.localeCompare(right.name));
deepExact(identitiesAfter, identitiesBefore, 'gateway pod identities');

console.log([
  'status=pass',
  `context=${expectedContext}`,
  `namespace=${namespace}`,
  `replicas=${replicas}`,
  `config_map=${expectedConfigMap}`,
  `dataplane_manifest_digest=${expectedImages.dataplane.digest}`,
  `compiler_manifest_digest=${expectedImages.compiler.digest}`,
  `upstream_manifest_digest=${expectedImages.upstream.digest}`,
  `fixed_requests=${requestCount}`,
  `proxied_requests=${requestCount}`,
  `request_delta=${expectedRequests}`,
  `response_2xx_delta=${expectedRequests}`,
  `upstream_selection_delta=${requestCount}`,
  'pod_restarts=0',
  'runtime_error_counters=0',
  'admin_service_exposed=false',
  'gateway_service_set_exact=true',
  'network_policy_set_exact=true',
  'host_network_disabled=true',
  'host_ports_absent=true',
  'metrics_service_routable=true',
  'diagnostic_ingress_default_deny=true',
  'metrics_ingress_scoped=true',
  'admin_ingress_scoped=true',
].join('\n'));
