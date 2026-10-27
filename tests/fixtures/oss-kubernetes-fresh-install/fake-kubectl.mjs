#!/usr/bin/env node

import fs from 'node:fs';
import process from 'node:process';

const args = process.argv.slice(2);
const statePath = process.env.BONVOYAGE_FAKE_KUBECTL_STATE;
const mode = process.env.BONVOYAGE_FAKE_KUBECTL_MODE || '';
const configMap = process.env.BONVOYAGE_FAKE_KUBECTL_CONFIG_MAP ||
  'bonvoyage-config-v1';
const compilerImage = 'bonvoyage-local-snapshot-compiler:oss-kubernetes';
const dataplaneImage = 'bonvoyage-local-bonvoyage:oss-kubernetes';
const upstreamImage = 'bonvoyage-local-upstream:oss-kubernetes';

if (!statePath) {
  console.error('BONVOYAGE_FAKE_KUBECTL_STATE is required');
  process.exit(2);
}

const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));

function persist() {
  fs.writeFileSync(statePath, `${JSON.stringify(state)}\n`);
}

function output(value) {
  process.stdout.write(typeof value === 'string' ? value : `${JSON.stringify(value)}\n`);
  process.exit(0);
}

function gatewayLabels() {
  if (mode === 'reordered-label-map') {
    return {
      'app.kubernetes.io/component': 'gateway',
      'app.kubernetes.io/name': 'bonvoyage',
    };
  }
  return {
    'app.kubernetes.io/name': 'bonvoyage',
    'app.kubernetes.io/component': 'gateway',
  };
}

function gatewayPod(name, uid, ip) {
  const restartCount = mode === 'restart' && name === 'bonvoyage-a' ? 1 : 0;
  const readOnlyRootFilesystem = mode !== 'bad-security';
  const dataplanePorts = [
    {name: 'http', containerPort: 8080},
    {name: 'metrics', containerPort: 9090},
    {name: 'admin', containerPort: 9901},
  ];
  if (mode === 'host-port') dataplanePorts[2].hostPort = 9901;
  return {
    metadata: {name, uid, labels: gatewayLabels()},
    spec: {
      hostNetwork: mode === 'host-network',
      automountServiceAccountToken: false,
      securityContext: {
        runAsNonRoot: true,
        runAsUser: 65532,
        runAsGroup: 65532,
        seccompProfile: {type: 'RuntimeDefault'},
      },
      initContainers: [{
        name: 'snapshot-compiler',
        image: compilerImage,
      }],
      containers: [{
        name: 'dataplane',
        image: mode === 'wrong-dataplane-reference' ?
          'unapproved/dataplane:latest' : dataplaneImage,
        ports: dataplanePorts,
        resources: {
          requests: {cpu: '1', memory: '512Mi'},
          limits: {cpu: '1', memory: '512Mi'},
        },
        securityContext: {
          allowPrivilegeEscalation: false,
          capabilities: {drop: ['ALL']},
          readOnlyRootFilesystem,
        },
        volumeMounts: [{name: 'snapshot', readOnly: true}],
      }],
      volumes: [
        {name: 'config', configMap: {name: configMap}},
        {name: 'snapshot', emptyDir: {}},
      ],
    },
    status: {
      podIP: ip,
      conditions: [{type: 'Ready', status: 'True'}],
      initContainerStatuses: [{
        name: 'snapshot-compiler',
        imageID: `sha256:${'c'.repeat(64)}`,
        restartCount: 0,
        state: {terminated: {exitCode: 0}},
      }],
      containerStatuses: [{
        name: 'dataplane',
        imageID: `sha256:${'d'.repeat(64)}`,
        ready: true,
        restartCount,
        state: {running: {startedAt: '2026-10-20T00:00:00Z'}},
      }],
    },
  };
}

function upstreamPod() {
  return {
    metadata: {
      name: 'upstream-0',
      uid: 'upstream-uid',
      labels: {'routesphere.global/metrics-access': 'true'},
    },
    spec: {
      containers: [{name: 'upstream', image: upstreamImage}],
    },
    status: {
      conditions: [{type: 'Ready', status: 'True'}],
      containerStatuses: [{
        name: 'upstream',
        imageID: `sha256:${(mode === 'wrong-upstream-digest' ? 'f' : 'b').repeat(64)}`,
        ready: true,
        restartCount: 0,
        state: {running: {startedAt: '2026-10-20T00:00:00Z'}},
      }],
    },
  };
}

function metricDocument(pod) {
  const counters = state.counters[pod];
  const requests = counters.fixed + counters.proxied;
  let upstreamSelections = counters.proxied;
  if (mode === 'bad-accounting' && upstreamSelections > 0) upstreamSelections -= 1;
  const runtimeErrors = mode === 'runtime-error' ? 1 : 0;
  const lines = [
    'bonvoyage_bonvoyage_gateway_ready{shard="0"} 1',
    'bonvoyage_bonvoyage_gateway_configured_clusters{shard="0"} 1',
    'bonvoyage_bonvoyage_gateway_configured_endpoints{shard="0"} 1',
    'bonvoyage_bonvoyage_gateway_configured_listeners{shard="0"} 1',
    'bonvoyage_bonvoyage_gateway_configured_routes{shard="0"} 2',
    `bonvoyage_bonvoyage_gateway_requests_total{shard="0"} ${requests}`,
    `bonvoyage_bonvoyage_gateway_responses_2xx_total{shard="0"} ${requests}`,
    `bonvoyage_bonvoyage_gateway_upstream_endpoint_selections_total{shard="0"} ${upstreamSelections}`,
    'bonvoyage_bonvoyage_gateway_responses_4xx_total{shard="0"} 0',
    'bonvoyage_bonvoyage_gateway_responses_5xx_total{shard="0"} 0',
    'bonvoyage_bonvoyage_gateway_route_misses_total{shard="0"} 0',
    'bonvoyage_bonvoyage_gateway_request_timeouts_total{shard="0"} 0',
    'bonvoyage_bonvoyage_gateway_overload_rejections_total{shard="0"} 0',
    'bonvoyage_bonvoyage_gateway_upstream_failures_total{shard="0"} 0',
    `bonvoyage_memory_malloc_failed{shard="0"} ${runtimeErrors}`,
    'bonvoyage_reactor_abandoned_failed_futures{shard="0"} 0',
    'bonvoyage_stall_detector_reported{shard="0"} 0',
  ];
  if (mode === 'missing-metric') lines.splice(4, 1);
  return `${lines.join('\n')}\n`;
}

if (args[0] === 'config' && args[1] === 'current-context') {
  output(mode === 'wrong-context' ? 'kind-unrelated\n' :
    'kind-bonvoyage-oss-acceptance\n');
}

const command = args[2];
const resource = args[3];
const name = args[4];

if (args[0] === '-n' && command === 'get' && resource === 'deployment') {
  const labels = gatewayLabels();
  output({
    metadata: {name, namespace: 'bonvoyage', generation: 3},
    spec: {
      replicas: 2,
      selector: {matchLabels: labels},
      template: {metadata: {labels}},
      strategy: {
        type: 'RollingUpdate',
        rollingUpdate: {maxUnavailable: 0, maxSurge: 1},
      },
    },
    status: {
      observedGeneration: 3,
      replicas: 2,
      updatedReplicas: 2,
      readyReplicas: mode === 'bad-ready' ? 1 : 2,
      availableReplicas: mode === 'bad-ready' ? 1 : 2,
      unavailableReplicas: mode === 'bad-ready' ? 1 : 0,
    },
  });
}

function gatewayService(serviceName) {
  const metrics = serviceName === 'bonvoyage-metrics';
  const ports = metrics ?
    [{name: 'metrics', port: 9090, targetPort: 'metrics'}] :
    [{name: 'http', port: 80, targetPort: 'http'}];
  if (mode === 'admin-exposed' && !metrics) {
    ports.push({name: 'admin', port: 9901, targetPort: 'admin'});
  }
  if (mode === 'node-port-metrics-service' && metrics) {
    ports[0].nodePort = 30909;
  }
  const selector = mode === 'wrong-service-selector' && metrics ?
    {'app.kubernetes.io/name': 'bonvoyage'} : gatewayLabels();
  return {
    metadata: {name: serviceName},
    spec: {
      type: mode === 'loadbalancer-metrics-service' && metrics ?
        'LoadBalancer' : 'ClusterIP',
      selector,
      externalIPs: mode === 'loadbalancer-metrics-service' && metrics ?
        ['203.0.113.10'] : [],
      ports,
    },
  };
}

if (args[0] === '-n' && command === 'get' && resource === 'service') {
  output(gatewayService(name));
}

if (args[0] === '-n' && command === 'get' && resource === 'services') {
  const items = [
    gatewayService('bonvoyage'),
    gatewayService('bonvoyage-metrics'),
    {
      metadata: {name: 'upstream'},
      spec: {
        type: 'ClusterIP',
        selector: {'app.kubernetes.io/name': 'bonvoyage-acceptance-upstream'},
        ports: [{name: 'http', port: 8081, targetPort: 'http'}],
      },
    },
  ];
  if (mode === 'extra-admin-service') {
    items.push({
      metadata: {name: 'bonvoyage-admin'},
      spec: {
        type: 'ClusterIP',
        selector: {'app.kubernetes.io/name': 'bonvoyage'},
        ports: [{name: 'admin', port: 9901, targetPort: 'admin'}],
      },
    });
  }
  if (mode === 'extra-selectorless-service') {
    items.push({
      metadata: {name: 'bonvoyage-selectorless-admin'},
      spec: {
        type: 'ClusterIP',
        ports: [{name: 'admin', port: 9901, targetPort: 9901}],
      },
    });
  }
  output({items});
}

const networkPolicyNames = [
  'bonvoyage-default-deny-ingress',
  'bonvoyage-data-ingress',
  'bonvoyage-metrics-ingress',
  'bonvoyage-admin-ingress',
];

if (args[0] === '-n' && command === 'get' && resource === 'networkpolicies') {
  const items = networkPolicyNames.map(policyName => ({
    metadata: {name: policyName},
  }));
  if (mode === 'extra-network-policy') {
    items.push({metadata: {name: 'bonvoyage-unexpected-allow-all'}});
  }
  output({items});
}

if (args[0] === '-n' && command === 'get' && resource === 'networkpolicy') {
  if (mode === 'missing-network-policy' &&
      name === 'bonvoyage-default-deny-ingress') {
    console.error('networkpolicy not found');
    process.exit(1);
  }
  const gatewaySelector = gatewayLabels();
  const base = {
    metadata: {name},
    spec: {podSelector: {matchLabels: gatewaySelector}, policyTypes: ['Ingress']},
  };
  if (mode === 'policy-selector-expression' &&
      name === 'bonvoyage-metrics-ingress') {
    base.spec.podSelector.matchExpressions = [{
      key: 'routesphere.global/impossible', operator: 'Exists',
    }];
  }
  if (name === 'bonvoyage-default-deny-ingress') {
    base.spec.ingress = [];
  } else if (name === 'bonvoyage-data-ingress') {
    base.spec.ingress = [{ports: [
      {protocol: 'TCP', port: 8080},
      {protocol: 'TCP', port: 8443},
    ]}];
  } else if (name === 'bonvoyage-metrics-ingress') {
    const source = {
      podSelector: {matchLabels: {'routesphere.global/metrics-access': 'true'}},
    };
    if (mode === 'broad-metrics-policy') source.namespaceSelector = {};
    base.spec.ingress = [{
      from: [source],
      ports: [{protocol: 'TCP', port: 9090}],
    }];
  } else if (name === 'bonvoyage-admin-ingress') {
    const source = {
      podSelector: {matchLabels: {
        'routesphere.global/diagnostics-access': 'true',
      }},
    };
    if (mode === 'broad-admin-policy') source.namespaceSelector = {};
    base.spec.ingress = [{
      from: [source],
      ports: [{protocol: 'TCP', port: 9901}],
    }];
  } else {
    console.error(`unsupported network policy: ${name}`);
    process.exit(1);
  }
  output(base);
}

if (args[0] === '-n' && command === 'get' &&
    resource === 'poddisruptionbudget') {
  output({
    metadata: {name},
    spec: {maxUnavailable: 1},
    status: {currentHealthy: 2, desiredHealthy: 1, expectedPods: 2},
  });
}

if (args[0] === '-n' && command === 'get' && resource === 'pods') {
  const selector = args[args.indexOf('-l') + 1];
  if (selector.includes('component=gateway')) {
    state.podQueries += 1;
    persist();
    const secondUID = mode === 'identity-change' && state.podQueries > 1 ?
      'gateway-b-replaced' : 'gateway-b-uid';
    output({items: [
      gatewayPod('bonvoyage-a', 'gateway-a-uid', '10.0.0.11'),
      gatewayPod('bonvoyage-b', secondUID, '10.0.0.12'),
    ]});
  }
  output({items: [upstreamPod()]});
}

if (args[0] === '-n' && command === 'exec') {
  const url = args.at(-1);
  if (url === 'http://10.0.0.11:9090/metrics') output(metricDocument('bonvoyage-a'));
  if (url === 'http://10.0.0.12:9090/metrics') output(metricDocument('bonvoyage-b'));
  if (url === 'http://bonvoyage-metrics.bonvoyage.svc.cluster.local:9090/metrics') {
    output(metricDocument('bonvoyage-a'));
  }

  const target = state.nextPod === 0 ? 'bonvoyage-a' : 'bonvoyage-b';
  state.nextPod = state.nextPod === 0 ? 1 : 0;
  if (url.endsWith('/bonvoyage/ready')) {
    state.counters[target].fixed += 1;
    persist();
    output(mode === 'bad-body' ? 'unexpected\n' : 'ready-v1\n');
  }
  if (url.endsWith('/healthz')) {
    state.counters[target].proxied += 1;
    persist();
    output('ok\n');
  }
}

console.error(`unsupported fake kubectl command: ${args.join(' ')}`);
process.exit(2);
