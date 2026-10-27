import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {validatePolicyCatalog} from './phase5-policy-workloads.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const catalogPath = path.join(root,
  'benchmarks/workloads/policy-cost/phase5-policy-cost.json');

function catalog() {
  return JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
}

test('committed Phase 5 policy catalog is valid', () => {
  const value = validatePolicyCatalog(catalog());
  assert.deepEqual(value.core_counts, [8, 24]);
  assert.deepEqual(value.profiles.map((profile) => profile.id),
    ['P5-C00', 'P5-C01', 'P5-C02', 'P5-C03', 'P5-C04', 'P5-C05']);
});

test('catalog rejects workload and claim drift', () => {
  const payload = catalog();
  payload.profiles[1].response_payload_bytes = 4096;
  assert.throws(() => validatePolicyCatalog(payload), /response payload/u);

  const jwtComparator = catalog();
  jwtComparator.profiles[4].nginx_comparator = 'vanilla-equivalent';
  assert.throws(() => validatePolicyCatalog(jwtComparator), /JWT semantics/u);

  const hmacClaim = catalog();
  hmacClaim.profiles[3].nginx_comparator = 'vanilla-equivalent';
  assert.throws(() => validatePolicyCatalog(hmacClaim), /API-key semantics/u);

  const evidenceClass = catalog();
  evidenceClass.evidence_class = 'publication-grade';
  assert.throws(() => validatePolicyCatalog(evidenceClass), /cannot authorize/u);
});

test('catalog rejects unexpected fields and reordered IDs', () => {
  const unexpected = catalog();
  unexpected.profiles[0].marketing_claim = 'fastest';
  assert.throws(() => validatePolicyCatalog(unexpected), /unexpected keys/u);

  const reordered = catalog();
  [reordered.profiles[0], reordered.profiles[1]] =
    [reordered.profiles[1], reordered.profiles[0]];
  assert.throws(() => validatePolicyCatalog(reordered), /ordering changed/u);
});
