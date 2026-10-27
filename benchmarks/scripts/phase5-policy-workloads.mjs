#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

const PROFILE_IDS = ['P5-C00', 'P5-C01', 'P5-C02', 'P5-C03', 'P5-C04', 'P5-C05'];
const FEATURES = new Set([
  'plain-proxy-control', 'bounded-header-transformations',
  'static-api-key-hmac-admission', 'rs256-jwt-admission',
]);
const HEADER_MODES = new Set(['none', 'digest-bound-json', 'api-key-file']);
const COMPARATORS = new Set([
  'vanilla-equivalent', 'semantic-only-no-hmac-equivalence',
  'blocked-until-extension-pinned',
]);

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(object, expected, label) {
  requireValue(object && typeof object === 'object' && !Array.isArray(object),
    `${label} must be an object`);
  requireValue(JSON.stringify(Object.keys(object).sort()) ===
    JSON.stringify([...expected].sort()), `${label} has missing or unexpected keys`);
}

export function validatePolicyCatalog(input) {
  exactKeys(input, ['schema_version', 'evidence_class', 'protocol', 'tls',
    'method', 'core_counts', 'profiles', 'excluded_claims'], 'policy catalog');
  requireValue(input.schema_version === 1, 'policy catalog schema version invalid');
  requireValue(input.evidence_class === 'shared-vm-engineering',
    'policy catalog cannot authorize dedicated or publication claims');
  requireValue(input.protocol === 'http1' && input.method === 'GET',
    'initial policy catalog must remain an HTTP/1.1 GET matrix');
  exactKeys(input.tls, ['version', 'cipher_family'], 'policy catalog TLS');
  requireValue(input.tls.version === '1.3' && input.tls.cipher_family === 'AES',
    'policy catalog TLS contract changed');
  requireValue(JSON.stringify(input.core_counts) === JSON.stringify([8, 24]),
    'policy catalog requires 8-core and 24-core points');
  requireValue(Array.isArray(input.profiles) && input.profiles.length ===
    PROFILE_IDS.length, 'policy catalog profile count invalid');
  requireValue(JSON.stringify(input.profiles.map((profile) => profile.id)) ===
    JSON.stringify(PROFILE_IDS), 'policy catalog IDs or ordering changed');
  for (const profile of input.profiles) {
    exactKeys(profile, ['id', 'feature', 'response_payload_bytes',
      'request_headers_mode', 'request_header_names', 'bonvoyage_policy',
      'nginx_comparator'],
    `policy profile ${profile.id}`);
    requireValue(FEATURES.has(profile.feature), `${profile.id} feature invalid`);
    requireValue([256, 8192].includes(profile.response_payload_bytes),
      `${profile.id} response payload invalid`);
    requireValue(HEADER_MODES.has(profile.request_headers_mode),
      `${profile.id} request header mode invalid`);
    requireValue(Array.isArray(profile.request_header_names) &&
      profile.request_header_names.length <= 16 &&
      new Set(profile.request_header_names).size ===
        profile.request_header_names.length &&
      JSON.stringify(profile.request_header_names) ===
        JSON.stringify([...profile.request_header_names].sort()) &&
      profile.request_header_names.every((name) =>
        /^[!#$%&'*+.^_`|~0-9a-z-]+$/u.test(name)),
    `${profile.id} request header names invalid`);
    requireValue(typeof profile.bonvoyage_policy === 'string' &&
      profile.bonvoyage_policy.length > 0, `${profile.id} policy invalid`);
    requireValue(COMPARATORS.has(profile.nginx_comparator),
      `${profile.id} comparator invalid`);
  }
  const byId = Object.fromEntries(input.profiles.map((profile) =>
    [profile.id, profile]));
  requireValue(byId['P5-C00'].feature === 'plain-proxy-control' &&
    byId['P5-C00'].response_payload_bytes === 8192 &&
    byId['P5-C00'].request_headers_mode === 'none' &&
    byId['P5-C00'].request_header_names.length === 0 &&
    byId['P5-C00'].nginx_comparator === 'vanilla-equivalent',
  'P5-C00 control semantics changed');
  for (const id of ['P5-C01', 'P5-C02']) {
    requireValue(byId[id].feature === 'bounded-header-transformations' &&
      byId[id].request_headers_mode === 'digest-bound-json' &&
      JSON.stringify(byId[id].request_header_names) === JSON.stringify([
        'x-policy-append', 'x-policy-remove', 'x-policy-set']) &&
      byId[id].nginx_comparator === 'vanilla-equivalent',
    `${id} header-transformation semantics changed`);
  }
  requireValue(byId['P5-C01'].response_payload_bytes === 256 &&
    byId['P5-C02'].response_payload_bytes === 8192,
  'header-transformation payload boundary changed');
  requireValue(byId['P5-C03'].feature === 'static-api-key-hmac-admission' &&
    byId['P5-C03'].request_headers_mode === 'api-key-file' &&
    JSON.stringify(byId['P5-C03'].request_header_names) ===
      JSON.stringify(['x-api-key']) &&
    byId['P5-C03'].response_payload_bytes === 8192 &&
    byId['P5-C03'].nginx_comparator === 'semantic-only-no-hmac-equivalence',
  'P5-C03 API-key semantics changed');
  for (const id of ['P5-C04', 'P5-C05']) {
    requireValue(byId[id].feature === 'rs256-jwt-admission' &&
      byId[id].request_headers_mode === 'digest-bound-json' &&
      JSON.stringify(byId[id].request_header_names) ===
        JSON.stringify(['authorization']) &&
      byId[id].nginx_comparator === 'blocked-until-extension-pinned',
    `${id} JWT semantics changed`);
  }
  requireValue(byId['P5-C04'].response_payload_bytes === 256 &&
    byId['P5-C05'].response_payload_bytes === 8192,
  'JWT payload boundary changed');
  requireValue(Array.isArray(input.excluded_claims) &&
    input.excluded_claims.length === 4 &&
    input.excluded_claims.every((claim) => typeof claim === 'string' &&
      claim.length > 0), 'policy catalog exclusions invalid');
  return input;
}

function main() {
  const [, , filename] = process.argv;
  requireValue(filename && process.argv.length === 3,
    'usage: phase5-policy-workloads.mjs CATALOG.json');
  const absolute = path.resolve(filename);
  const stat = fs.lstatSync(absolute);
  requireValue(stat.isFile() && !stat.isSymbolicLink(),
    'policy catalog must be a regular file');
  const catalog = validatePolicyCatalog(JSON.parse(fs.readFileSync(absolute, 'utf8')));
  process.stdout.write(`${JSON.stringify(catalog)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`phase5-policy-workloads: ${error.message}\n`);
    process.exitCode = 1;
  }
}
