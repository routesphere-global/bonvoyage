#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {validatePolicyCatalog} from './phase5-policy-workloads.mjs';

const PRODUCTS = new Set(['bonvoyage', 'nginx']);
const CASES = new Set([
  'allow', 'invalid-credential', 'missing-credential', 'insufficient-scope',
]);

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function regularFile(filename, label) {
  const stat = fs.lstatSync(filename);
  requireValue(stat.isFile() && !stat.isSymbolicLink(),
    `${label} must be a regular file`);
}

function parseStatus(filename) {
  regularFile(filename, 'status');
  const value = fs.readFileSync(filename, 'ascii').trim();
  requireValue(/^\d{3}$/u.test(value), 'status must contain one HTTP code');
  return Number(value);
}

function parseHeaders(filename) {
  regularFile(filename, 'headers');
  const blocks = fs.readFileSync(filename, 'latin1').replaceAll('\r\n', '\n')
    .trim().split(/\n\n+/u).filter(Boolean);
  requireValue(blocks.length > 0, 'response headers are empty');
  const lines = blocks.at(-1).split('\n');
  requireValue(/^HTTP\/1\.[01] \d{3}(?: |$)/u.test(lines.shift() ?? ''),
    'response status line invalid');
  const headers = new Map();
  for (const line of lines) {
    if (line === '') continue;
    const separator = line.indexOf(':');
    requireValue(separator > 0, 'malformed response header');
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    requireValue(/^[!#$%&'*+.^_`|~0-9a-z-]+$/u.test(name),
      'response header name invalid');
    const values = headers.get(name) ?? [];
    values.push(value);
    headers.set(name, values);
  }
  return headers;
}

function singleHeader(headers, name) {
  const values = headers.get(name) ?? [];
  requireValue(values.length === 1, `${name} must occur exactly once`);
  return values[0];
}

function requireAbsent(headers, name) {
  requireValue(!headers.has(name), `${name} must be absent`);
}

function expectedBody(payloadBytes) {
  return Buffer.alloc(payloadBytes, 'x');
}

function validateAllow(profile, headers, body) {
  const expected = expectedBody(profile.response_payload_bytes);
  requireValue(body.equals(expected),
    `${profile.id} body differs from the controlled payload`);
  if (profile.feature !== 'bounded-header-transformations') return;
  const expectedHeaders = {
    'x-upstream-policy-set': 'gateway-set',
    'x-upstream-policy-append': 'upstream-append, gateway-append',
    'x-policy-response-added': 'gateway-added',
    'x-observed-request-set': 'gateway-set',
    'x-observed-request-append': 'client-append, gateway-append',
    'x-observed-request-added': 'gateway-added',
  };
  for (const [name, value] of Object.entries(expectedHeaders)) {
    requireValue(singleHeader(headers, name) === value,
      `${profile.id} ${name} semantics changed`);
  }
  requireAbsent(headers, 'x-upstream-policy-remove');
  requireAbsent(headers, 'x-observed-request-remove');
}

function expectedRejection(profile, probeCase) {
  if (profile.feature === 'static-api-key-hmac-admission' &&
      ['invalid-credential', 'missing-credential'].includes(probeCase)) {
    return 401;
  }
  if (profile.feature === 'rs256-jwt-admission' &&
      ['invalid-credential', 'missing-credential'].includes(probeCase)) {
    return 401;
  }
  if (profile.feature === 'rs256-jwt-admission' &&
      probeCase === 'insufficient-scope') return 403;
  throw new Error(`${profile.id} does not support ${probeCase}`);
}

export function validateSemanticProbe(catalogInput, input) {
  const catalog = validatePolicyCatalog(catalogInput);
  requireValue(input && typeof input === 'object' && !Array.isArray(input),
    'semantic probe input must be an object');
  const keys = Object.keys(input).sort();
  requireValue(JSON.stringify(keys) === JSON.stringify([
    'body_path', 'case', 'headers_path', 'product', 'profile_id', 'status_path',
  ].sort()), 'semantic probe input has missing or unexpected keys');
  requireValue(PRODUCTS.has(input.product), 'semantic probe product invalid');
  requireValue(CASES.has(input.case), 'semantic probe case invalid');
  const profile = catalog.profiles.find((entry) => entry.id === input.profile_id);
  requireValue(profile, 'semantic probe profile unavailable');
  if (input.product === 'nginx') {
    requireValue(profile.nginx_comparator === 'vanilla-equivalent',
      `${profile.id} cannot be claimed as a vanilla NGINX semantic match`);
  }
  const statusPath = path.resolve(input.status_path);
  const headersPath = path.resolve(input.headers_path);
  const bodyPath = path.resolve(input.body_path);
  regularFile(bodyPath, 'body');
  const status = parseStatus(statusPath);
  const headers = parseHeaders(headersPath);
  const body = fs.readFileSync(bodyPath);
  if (input.case === 'allow') {
    requireValue(status === 200, `${profile.id} allow probe returned ${status}`);
    validateAllow(profile, headers, body);
  } else {
    requireValue(input.product === 'bonvoyage',
      'NGINX authentication rejection is not an equivalent policy probe');
    const expected = expectedRejection(profile, input.case);
    requireValue(status === expected,
      `${profile.id} ${input.case} returned ${status}, expected ${expected}`);
    requireValue(body.length > 0, 'gateway rejection body must not be empty');
    for (const name of ['x-upstream-policy-set', 'x-observed-request-set']) {
      requireAbsent(headers, name);
    }
  }
  return {
    schema_version: 1,
    evidence_class: 'shared-vm-semantic-preflight',
    product: input.product,
    profile_id: profile.id,
    case: input.case,
    http_status: status,
    body_bytes: body.length,
    body_sha256: crypto.createHash('sha256').update(body).digest('hex'),
    response_header_names: [...headers.keys()].sort(),
    semantic_result: 'pass',
  };
}

function option(args, name) {
  const index = args.indexOf(name);
  requireValue(index >= 0 && args[index + 1], `missing ${name}`);
  return args[index + 1];
}

function main() {
  const args = process.argv.slice(2);
  const catalog = JSON.parse(fs.readFileSync(option(args, '--catalog'), 'utf8'));
  const result = validateSemanticProbe(catalog, {
    profile_id: option(args, '--profile'),
    product: option(args, '--product'),
    case: option(args, '--case'),
    status_path: option(args, '--status'),
    headers_path: option(args, '--headers'),
    body_path: option(args, '--body'),
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-policy-semantic: ${error.message}\n`);
    process.exitCode = 1;
  }
}
