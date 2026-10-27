import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createRequire} from 'node:module';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {validatePolicyCatalog} from './phase5-policy-workloads.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const require = createRequire(path.join(root, 'package.json'));
const yaml = require('js-yaml');
const catalog = validatePolicyCatalog(JSON.parse(fs.readFileSync(path.join(root,
  'benchmarks/workloads/policy-cost/phase5-policy-cost.json'), 'utf8')));

function fixture(id) {
  return yaml.load(fs.readFileSync(path.join(root, 'tests/fixtures',
    `phase5-policy-${id.toLowerCase().replace('p5-', '')}.yaml`), 'utf8'));
}

test('policy fixtures preserve one-route isolation and common runtime shape', () => {
  const loaded = catalog.profiles.map((profile) => [profile, fixture(profile.id)]);
  const [, first] = loaded[0];
  for (const [profile, config] of loaded) {
    assert.equal(config.server.node_id, `phase5-policy-${profile.id.toLowerCase()
      .replace('p5-', '')}`);
    assert.equal(config.snapshot.snapshot_id, config.server.node_id);
    assert.equal(config.virtual_hosts.length, 1);
    assert.equal(config.virtual_hosts[0].routes.length, 1);
    assert.equal(config.listeners.length, 1);
    assert.deepEqual(config.listeners[0], first.listeners[0]);
    assert.deepEqual(config.clusters, first.clusters);
    assert.deepEqual(config.runtime_limits, first.runtime_limits);
    const route = config.virtual_hosts[0].routes[0];
    assert.equal(route.match.path_exact,
      `/policy/payload/${profile.response_payload_bytes}`);
    assert.deepEqual(route.match.methods, ['GET']);
    assert.equal(route.cluster, 'upstream');
  }
});

test('header fixtures compile the exact bounded mutation sequence', () => {
  for (const id of ['P5-C01', 'P5-C02']) {
    const route = fixture(id).virtual_hosts[0].routes[0];
    assert.deepEqual(route.header_transformations.request, [
      {operation: 'set', name: 'x-policy-set', value: 'gateway-set'},
      {operation: 'append', name: 'x-policy-append', value: 'gateway-append'},
      {operation: 'remove', name: 'x-policy-remove'},
      {operation: 'set', name: 'x-policy-added', value: 'gateway-added'},
    ]);
    assert.deepEqual(route.header_transformations.response, [
      {operation: 'set', name: 'x-upstream-policy-set', value: 'gateway-set'},
      {operation: 'append', name: 'x-upstream-policy-append',
        value: 'gateway-append'},
      {operation: 'remove', name: 'x-upstream-policy-remove'},
      {operation: 'set', name: 'x-policy-response-added', value: 'gateway-added'},
    ]);
    assert.equal(route.api_key_auth, undefined);
    assert.equal(route.jwt_auth, undefined);
  }
});

test('header transformation input matches the catalog contract', () => {
  const requestHeaders = JSON.parse(fs.readFileSync(path.join(root,
    'benchmarks/workloads/policy-cost/header-transform-request.json'), 'utf8'));
  const expectedNames = catalog.profiles.find((profile) =>
    profile.id === 'P5-C01').request_header_names;
  assert.deepEqual(Object.keys(requestHeaders).sort(), expectedNames);
  assert.deepEqual(requestHeaders, {
    'x-policy-append': 'client-append',
    'x-policy-remove': 'client-remove',
    'x-policy-set': 'client-set',
  });
});

test('API-key and JWT fixtures freeze distinct authentication semantics', () => {
  const apiKey = fixture('P5-C03').virtual_hosts[0].routes[0];
  assert.deepEqual(apiKey.api_key_auth, {header_name: 'x-api-key',
    credentials_secret: 'phase5-policy-api-keys.txt'});
  assert.equal(apiKey.jwt_auth, undefined);

  for (const id of ['P5-C04', 'P5-C05']) {
    const jwt = fixture(id).virtual_hosts[0].routes[0].jwt_auth;
    assert.deepEqual(jwt.algorithms, ['RS256']);
    assert.equal(jwt.jwks_secret, 'phase5-policy-jwks.json');
    assert.equal(jwt.issuer, 'https://issuer.example.test');
    assert.equal(jwt.audience, 'payments-api');
    assert.equal(jwt.required_type, 'at+jwt');
    assert.deepEqual(jwt.required_scopes, ['payments:read']);
    assert.deepEqual(jwt.required_claims, [{name: 'tenant', exact: 'tenant-a'}]);
    assert.deepEqual(jwt.verification_rate_limit,
      {capacity: 1000000, refill_tokens_per_second: 1000000});
  }
});

test('controlled upstream exposes both policy payloads and observation headers', () => {
  const source = fs.readFileSync(path.join(root,
    'benchmarks/products/upstream/nginx.conf'), 'utf8');
  for (const bytes of [256, 8192]) {
    assert.match(source, new RegExp(`location = /policy/payload/${bytes} \\{`));
    assert.match(source, new RegExp(`alias /srv/payload/${bytes};`));
  }
  for (const name of ['x-upstream-policy-set', 'x-upstream-policy-append',
    'x-upstream-policy-remove', 'x-observed-request-set',
    'x-observed-request-append', 'x-observed-request-remove',
    'x-observed-request-added']) {
    assert.equal(source.match(new RegExp(`add_header ${name} `, 'g'))?.length, 2,
      `${name} must be present once per policy payload`);
  }
});
