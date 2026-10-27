#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {validatePolicyCatalog} from './phase5-policy-workloads.mjs';

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/u;

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function validIpv4(value, label) {
  requireValue(typeof value === 'string' && IPV4.test(value) &&
    value.split('.').every((part) => Number(part) <= 255), `${label} invalid`);
}

function validateRuntime(runtime) {
  requireValue(runtime && typeof runtime === 'object' && !Array.isArray(runtime) &&
    JSON.stringify(Object.keys(runtime).sort()) === JSON.stringify([
      'certificate_path', 'listener_port', 'private_key_path', 'readiness_port',
      'upstream_addresses', 'upstream_port', 'workers',
    ].sort()), 'policy NGINX runtime has missing or unexpected keys');
  requireValue([8, 24].includes(runtime.workers),
    'policy NGINX workers must be 8 or 24');
  requireValue(runtime.listener_port === 8443 && runtime.readiness_port === 9901 &&
    runtime.upstream_port === 8081, 'policy NGINX ports changed');
  requireValue(runtime.certificate_path === '/tls/server-chain.pem' &&
    runtime.private_key_path === '/tls/server-key.pem',
  'policy NGINX TLS paths changed');
  requireValue(Array.isArray(runtime.upstream_addresses) &&
    runtime.upstream_addresses.length === 2 &&
    new Set(runtime.upstream_addresses).size === 2,
  'policy NGINX requires two distinct upstreams');
  runtime.upstream_addresses.forEach((address, index) =>
    validIpv4(address, `policy NGINX upstream ${index}`));
}

function proxyDirectives(transformed) {
  const common = `      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_set_header Host $http_host;
      proxy_request_buffering off;
      proxy_buffering off;
      proxy_cache off;
      proxy_connect_timeout 1s;
      proxy_send_timeout 15s;
      proxy_read_timeout 15s;`;
  if (!transformed) return common;
  return `${common}
      proxy_set_header x-policy-set gateway-set;
      proxy_set_header x-policy-append $policy_request_append;
      proxy_set_header x-policy-remove "";
      proxy_set_header x-policy-added gateway-added;
      proxy_hide_header x-upstream-policy-set;
      proxy_hide_header x-upstream-policy-append;
      proxy_hide_header x-upstream-policy-remove;
      add_header x-upstream-policy-set gateway-set always;
      add_header x-upstream-policy-append "$upstream_http_x_upstream_policy_append, gateway-append" always;
      add_header x-policy-response-added gateway-added always;`;
}

export function renderPolicyNginxConfig(catalogInput, profileId, runtime) {
  const catalog = validatePolicyCatalog(catalogInput);
  validateRuntime(runtime);
  const profile = catalog.profiles.find((entry) => entry.id === profileId);
  requireValue(profile, 'policy NGINX profile unavailable');
  requireValue(profile.nginx_comparator === 'vanilla-equivalent',
    `${profileId} cannot be rendered as a vanilla-equivalent NGINX comparator`);
  const transformed = profile.feature === 'bounded-header-transformations';
  requireValue(profile.feature === 'plain-proxy-control' || transformed,
    `${profileId} feature is unsupported by the vanilla NGINX renderer`);
  const pathName = `/policy/payload/${profile.response_payload_bytes}`;
  const appendMap = transformed ? `
  map $http_x_policy_append $policy_request_append {
    ""      "gateway-append";
    default "$http_x_policy_append, gateway-append";
  }
` : '';
  return `worker_processes ${runtime.workers};
worker_rlimit_nofile 1048576;
error_log /dev/stderr crit;
pid /tmp/nginx.pid;

events {
  worker_connections 32768;
  multi_accept on;
}

http {
  access_log off;
  client_body_temp_path /tmp/client-body;
  proxy_temp_path /tmp/proxy;
  fastcgi_temp_path /tmp/fastcgi;
  uwsgi_temp_path /tmp/uwsgi;
  scgi_temp_path /tmp/scgi;
  client_max_body_size 10m;
  client_header_buffer_size 8k;
  large_client_header_buffers 4 8k;
  keepalive_timeout 60s;
  keepalive_requests 1000000;
  tcp_nodelay on;
${appendMap}
  upstream controlled_upstream {
    server ${runtime.upstream_addresses[0]}:${runtime.upstream_port};
    server ${runtime.upstream_addresses[1]}:${runtime.upstream_port};
    keepalive 128;
    keepalive_requests 1000000;
  }

  server {
    listen ${runtime.listener_port} ssl reuseport;
    ssl_certificate ${runtime.certificate_path};
    ssl_certificate_key ${runtime.private_key_path};
    ssl_protocols TLSv1.3;
    ssl_session_tickets off;
    server_name api.example.test;

    location = ${pathName} {
${proxyDirectives(transformed)}
      proxy_pass http://controlled_upstream;
    }

    location / { return 404; }
  }

  server {
    listen 127.0.0.1:${runtime.readiness_port};
    server_name _;
    location = /health/ready { default_type text/plain; return 200 "ready\\n"; }
    location = /status { stub_status; }
    location / { return 404; }
  }
}
`;
}

function option(args, name) {
  const index = args.indexOf(name);
  requireValue(index >= 0 && args[index + 1], `missing ${name}`);
  return args[index + 1];
}

function main() {
  const args = process.argv.slice(2);
  const catalog = JSON.parse(fs.readFileSync(option(args, '--catalog'), 'utf8'));
  process.stdout.write(renderPolicyNginxConfig(catalog, option(args, '--profile'), {
    workers: Number(option(args, '--workers')),
    listener_port: 8443,
    readiness_port: 9901,
    upstream_addresses: [option(args, '--upstream-a'), option(args, '--upstream-b')],
    upstream_port: 8081,
    certificate_path: '/tls/server-chain.pem',
    private_key_path: '/tls/server-key.pem',
  }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-policy-nginx: ${error.message}\n`);
    process.exitCode = 1;
  }
}
