import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {renderPolicyNginxConfig} from './phase5-policy-nginx.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const catalog = JSON.parse(fs.readFileSync(path.join(root,
  'benchmarks/workloads/policy-cost/phase5-policy-cost.json'), 'utf8'));

function runtime(workers = 8) {
  return {workers, listener_port: 8443, readiness_port: 9901,
    upstream_addresses: ['10.0.0.43', '10.0.0.44'], upstream_port: 8081,
    certificate_path: '/tls/server-chain.pem',
    private_key_path: '/tls/server-key.pem'};
}

test('plain policy control renders TLS, two upstreams, and no cache', () => {
  const config = renderPolicyNginxConfig(catalog, 'P5-C00', runtime(24));
  assert.match(config, /^worker_processes 24;/u);
  assert.match(config, /listen 8443 ssl reuseport;/u);
  assert.match(config, /ssl_protocols TLSv1\.3;/u);
  assert.match(config, /server 10\.0\.0\.43:8081;/u);
  assert.match(config, /server 10\.0\.0\.44:8081;/u);
  assert.match(config, /location = \/policy\/payload\/8192/u);
  assert.match(config, /proxy_cache off;/u);
  assert.doesNotMatch(config, /proxy_set_header x-policy-set/u);
});

test('header profiles render matched request and response transformations', () => {
  for (const [id, bytes] of [['P5-C01', 256], ['P5-C02', 8192]]) {
    const config = renderPolicyNginxConfig(catalog, id, runtime());
    assert.match(config, new RegExp(`location = /policy/payload/${bytes}`));
    assert.match(config, /proxy_set_header x-policy-set gateway-set;/u);
    assert.match(config, /proxy_set_header x-policy-append \$policy_request_append;/u);
    assert.match(config, /proxy_set_header x-policy-remove "";/u);
    assert.match(config, /proxy_set_header x-policy-added gateway-added;/u);
    assert.match(config, /proxy_hide_header x-upstream-policy-remove;/u);
    assert.match(config, /add_header x-upstream-policy-set gateway-set always;/u);
    assert.match(config, /\$upstream_http_x_upstream_policy_append, gateway-append/u);
    assert.match(config, /add_header x-policy-response-added gateway-added always;/u);
  }
});

test('renderer refuses non-equivalent API-key and JWT profiles', () => {
  for (const id of ['P5-C03', 'P5-C04', 'P5-C05']) {
    assert.throws(() => renderPolicyNginxConfig(catalog, id, runtime()),
      /cannot be rendered as a vanilla-equivalent/u);
  }
});

test('renderer rejects placement, topology, port, and TLS path drift', () => {
  assert.throws(() => renderPolicyNginxConfig(catalog, 'P5-C00', runtime(16)),
    /workers must be 8 or 24/u);
  const duplicate = runtime();
  duplicate.upstream_addresses[1] = duplicate.upstream_addresses[0];
  assert.throws(() => renderPolicyNginxConfig(catalog, 'P5-C00', duplicate),
    /two distinct upstreams/u);
  const port = runtime();
  port.listener_port = 8080;
  assert.throws(() => renderPolicyNginxConfig(catalog, 'P5-C00', port),
    /ports changed/u);
  const key = runtime();
  key.private_key_path = '/tmp/key.pem';
  assert.throws(() => renderPolicyNginxConfig(catalog, 'P5-C00', key),
    /TLS paths changed/u);
});
