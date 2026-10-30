import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {verifyBuilderPublicationWorkflow} from './verify-oss-builder-publication-workflow.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CONTRACT = path.join(ROOT,
  'packaging/release/oss-builder-publication-workflow-contract.json');
const WORKFLOW = path.join(ROOT, '.github/workflows/oss-builder-publication.yml');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-builder-publication-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const contract = path.join(root, 'contract.json');
  const workflow = path.join(root, 'workflow.yml');
  fs.copyFileSync(CONTRACT, contract);
  fs.copyFileSync(WORKFLOW, workflow);
  return {contract, workflow};
}

test('accepts only the manual powerless builder publication boundary', () => {
  const result = verifyBuilderPublicationWorkflow({
    contractPath: CONTRACT, workflowPath: WORKFLOW,
  });
  assert.equal(result.status, 'POWERLESS_BUILDER_PUBLICATION_VERIFIED');
  assert.equal(result.authority.builder_container_upload_allowed, true);
  assert.equal(result.authority.product_container_uploaded, false);
  assert.equal(result.authority.release_admitted, false);
});

test('rejects automatic triggers and product publication authority', (t) => {
  for (const [before, after] of [
    ['  workflow_dispatch:\n', '  push:\n'],
    ["    if: github.ref == 'refs/heads/main'\n", ''],
    ['      packages: write\n', '      packages: read\n'],
    ['--target oss-deb-builder', '--target runtime'],
    ['docker push "$DEB_IMAGE"', 'docker push ghcr.io/routesphere-global/bonvoyage:latest'],
    ['ref: ${{ inputs.source_commit }}', 'ref: main'],
    ['1:1.3.dfsg-3.1ubuntu2.3', '1:1.3.dfsg-3.1ubuntu2.2'],
  ]) {
    const paths = fixture(t);
    const source = fs.readFileSync(paths.workflow, 'utf8');
    assert.notEqual(source.indexOf(before), -1, `fixture is missing ${before}`);
    fs.writeFileSync(paths.workflow, source.replace(before, after));
    assert.throws(() => verifyBuilderPublicationWorkflow({
      contractPath: paths.contract, workflowPath: paths.workflow,
    }));
  }
});

test('rejects contract authority and registry drift', (t) => {
  for (const mutate of [
    (contract) => { contract.authority.product_container_uploaded = true; },
    (contract) => { contract.execution.targets[0].repository = 'ghcr.io/example/builder'; },
    (contract) => { contract.execution.timeout_minutes = 0; },
    (contract) => { contract.source.workflow_branch = 'feature'; },
  ]) {
    const paths = fixture(t);
    const contract = JSON.parse(fs.readFileSync(paths.contract, 'utf8'));
    mutate(contract);
    fs.writeFileSync(paths.contract, `${JSON.stringify(contract, null, 2)}\n`);
    assert.throws(() => verifyBuilderPublicationWorkflow({
      contractPath: paths.contract, workflowPath: paths.workflow,
    }));
  }
});
