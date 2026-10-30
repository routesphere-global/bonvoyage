import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  bindCycloneDx,
  bindSpdx,
  copyBoundFile,
  decodedPackages,
  fileIdentity,
  loadCandidate,
  normalizeFinding,
  normalizeGrypeScan,
  prepareValidator,
  produceSbom,
  produceVulnerability,
  syftSourceDescriptor,
  validatorInstallScript,
} from './produce-oss-supply-chain-evidence.mjs';

const COMMIT = 'a'.repeat(40);
const TAG = 'v1.0.0-rc.9';
const SCHEMA = Buffer.from('{"fixture":"spdx schema"}\n');
const SPDX_SCHEMA_SHA =
  '239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b';
const SPDX_LOCK_SHA =
  'e2e52a0b047055d4d860b379b1c0e35931659d94069398c6bf0b68cb21d6e194';
const PYTHON =
  'python:3.12-slim@sha256:1148dbb014615300fa7e713b2f94f550c0d1c69780c0805f84f093ceee34dd0b';

function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), {recursive: true});
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}
function source() {
  return {
    repository: 'https://github.com/routesphere-global/bonvoyage',
    commit: COMMIT, tag: TAG, dirty: false,
  };
}
function createCandidate(root) {
  const specifications = [
    ['gateway-deb-linux-amd64', 'debian-package', 'candidate.deb', 'deb'],
    ['gateway-oci-linux-amd64', 'oci-image', 'candidate.oci.tar', 'oci'],
  ];
  const artifacts = specifications.map(([id, kind, file, content]) => {
    const destination = path.join(root, 'artifacts', file);
    fs.mkdirSync(path.dirname(destination), {recursive: true});
    fs.writeFileSync(destination, content);
    return {
      id, kind, platform: 'linux/amd64', path: `artifacts/${file}`,
      bytes: Buffer.byteLength(content), sha256: sha256(content),
    };
  });
  writeJson(path.join(root, 'candidate-intake-receipt.json'), {
    classification: 'routesphere-bonvoyage-oss-candidate-intake-receipt',
    source: source(), artifacts,
  });
  return artifacts;
}
function rawCdx() {
  return {
    bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
    metadata: {component: {type: 'file', name: 'raw'}},
    components: [{
      type: 'library', 'bom-ref': 'pkg:deb/ubuntu/libc6@2.39', name: 'libc6',
      version: '2.39', purl: 'pkg:deb/ubuntu/libc6@2.39',
    }],
  };
}
function rawSpdx() {
  return {
    spdxVersion: 'SPDX-2.3', dataLicense: 'CC0-1.0', SPDXID: 'SPDXRef-DOCUMENT',
    name: 'raw', documentNamespace: 'https://example.test/raw',
    creationInfo: {created: '2026-10-30T00:00:00Z', creators: ['Tool: syft-1.44.0']},
    packages: [{
      SPDXID: 'SPDXRef-Package-libc6', name: 'libc6', versionInfo: '2.39',
      downloadLocation: 'NOASSERTION', filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION', licenseDeclared: 'NOASSERTION',
      copyrightText: 'NOASSERTION', externalRefs: [{
        referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl',
        referenceLocator: 'pkg:deb/ubuntu/libc6@2.39',
      }],
    }],
    relationships: [{
      spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES',
      relatedSpdxElement: 'SPDXRef-Package-libc6',
    }],
  };
}
function syftDecoded() {
  return {
    artifacts: [{name: 'libc6', version: '2.39', type: 'deb',
      purl: 'pkg:deb/ubuntu/libc6@2.39'}],
  };
}
function scan(target) {
  return {
    source: {type: 'file', target},
    distro: {name: 'ubuntu', version: '24.04'},
    matches: [],
    descriptor: {
      name: 'grype', version: '0.116.1', timestamp: '2026-10-30T08:30:00Z',
      db: {status: {
        schemaVersion: 'v6.1.9', valid: true, built: '2026-10-30T08:00:00Z',
        path: '/database/6/vulnerability.db',
        from: 'https://grype.anchore.io/databases/v6/database.tar.zst?' +
          `checksum=sha256%3A${'7'.repeat(64)}`,
      }},
      configuration: {
        'only-fixed': false, 'only-notfixed': false, 'ignore-wontfix': '',
        exclude: [], 'vex-documents': [], 'vex-add': [], ignore: [],
        db: {'validate-by-hash-on-start': true, 'validate-age': true,
          'max-allowed-built-age': 172800000000000},
      },
    },
  };
}
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-producer-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const candidate = path.join(root, 'candidate');
  const validator = path.join(root, 'validator');
  fs.mkdirSync(candidate);
  fs.mkdirSync(validator);
  createCandidate(candidate);
  writeJson(path.join(validator, 'validator-receipt.json'), {
    python_image: PYTHON,
    schema: {sha256: SPDX_SCHEMA_SHA}, lock: {sha256: SPDX_LOCK_SHA},
  });
  return {root, candidate, validator};
}

test('binds both SBOM roots to the exact candidate bytes', () => {
  const artifact = {
    id: 'gateway-deb-linux-amd64', kind: 'debian-package', platform: 'linux/amd64',
    bytes: 3, sha256: 'f'.repeat(64),
  };
  const cdx = bindCycloneDx(rawCdx(), artifact, source());
  assert.equal(cdx.metadata.component['bom-ref'], `artifact:${artifact.id}`);
  assert.equal(cdx.metadata.component.hashes[0].content, artifact.sha256);
  const spdx = bindSpdx(rawSpdx(), artifact, source());
  assert.equal(spdx.packages[0].SPDXID, 'SPDXRef-ArtifactRoot');
  assert.equal(spdx.packages.length, 1);
  assert.deepEqual(spdx.relationships.filter(({relationshipType}) =>
    relationshipType === 'DESCRIBES').map(({relatedSpdxElement}) => relatedSpdxElement),
  ['SPDXRef-ArtifactRoot']);
});

test('normalizes unique decoded packages and logical database path', () => {
  const decoded = syftDecoded();
  decoded.artifacts.push({...decoded.artifacts[0]});
  assert.equal(decodedPackages(decoded).length, 1);
  const target = '/input/gateway-deb-linux-amd64/cyclonedx.json';
  const normalized = normalizeGrypeScan(scan('gateway-deb-linux-amd64'), target);
  assert.equal(normalized.source.target, target);
  assert.equal(normalized.descriptor.db.status.path,
    '/evidence/database/vulnerability.db');
  assert.throws(() => normalizeGrypeScan(scan('wrong-artifact'), target),
    /expected SBOM artifact root/u);
});

test('rejects incomplete decoded package identities instead of dropping them', () => {
  const decoded = syftDecoded();
  decoded.artifacts.push({name: 'incomplete', version: '1', type: 'deb'});
  assert.throws(() => decodedPackages(decoded), /package URL/u);
});

test('normalizes format-local package IDs to one package URL', () => {
  const base = {
    vulnerability: {
      id: 'CVE-2026-1000', namespace: 'ubuntu:distro:ubuntu:24.04',
      severity: 'Medium', fix: {state: 'not-fixed', versions: []},
    },
  };
  const artifact = {
    name: 'libexample1', version: '1.2.3', type: 'deb',
    purl: 'pkg:deb/ubuntu/libexample1@1.2.3?arch=amd64',
  };
  assert.deepEqual(
    normalizeFinding({...base, artifact: {...artifact, id: artifact.purl}}),
    normalizeFinding({...base, artifact: {...artifact, id: 'Package-deb-libexample1-abcd'}}));
  assert.throws(() => normalizeFinding({...base, artifact: {...artifact, purl: undefined}}),
    /finding package URL/u);
});

test('rejects candidate substitution before invoking a producer', (t) => {
  const value = fixture(t);
  const candidate = loadCandidate(value.candidate, COMMIT, TAG);
  assert.equal(candidate.artifacts.length, 2);
  fs.appendFileSync(candidate.artifacts[0].path, 'changed');
  assert.throws(() => loadCandidate(value.candidate, COMMIT, TAG), /bytes changed/u);
});

test('hashes large files incrementally and rejects linked evidence', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-identity-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const file = path.join(root, 'database.bin');
  const content = Buffer.alloc((3 * 1024 * 1024) + 17, 0x5a);
  fs.writeFileSync(file, content);
  assert.deepEqual(fileIdentity(file), {bytes: content.length, sha256: sha256(content)});

  const linked = path.join(root, 'database-linked.bin');
  fs.linkSync(file, linked);
  assert.throws(() => fileIdentity(file), /non-hard-linked/u);
});

test('copies only checksum-bound regular evidence bytes', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-copy-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const sourcePath = path.join(root, 'source.bin');
  const destinationPath = path.join(root, 'nested', 'copy.bin');
  fs.writeFileSync(sourcePath, 'bounded evidence');
  const identity = fileIdentity(sourcePath);
  assert.deepEqual(copyBoundFile(sourcePath, destinationPath, identity), identity);
  assert.deepEqual(fileIdentity(destinationPath), identity);
  assert.throws(() => copyBoundFile(sourcePath, path.join(root, 'wrong.bin'),
    {...identity, sha256: '0'.repeat(64)}), /expected identity changed/u);
});

test('prepares only checksum-bound validator material', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-validator-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const output = path.join(root, 'validator');
  const expected = Buffer.alloc(0);
  await assert.rejects(() => prepareValidator({
    output,
    fetchImpl: async () => ({ok: true, status: 200,
      arrayBuffer: async () => expected}),
    runner: () => { throw new Error('must not run'); },
  }), /schema byte pin/u);
  assert.equal(fs.existsSync(path.join(output, 'validator-receipt.json')), false);
});

test('constructs one hash-locked validator install command', () => {
  assert.equal(validatorInstallScript(), [
    'python -m venv /validator/venv',
    '/validator/venv/bin/python -m pip install --disable-pip-version-check ' +
      '--no-cache-dir --require-hashes ' +
      '-r /repository/security/tools/native-sbom-python.lock',
  ].join(' && '));
});

test('preserves archive identity in Syft source paths', () => {
  assert.deepEqual(syftSourceDescriptor({kind: 'debian-package'}), {
    mountPath: '/input/candidate.deb', source: 'file:/input/candidate.deb',
  });
  assert.deepEqual(syftSourceDescriptor({kind: 'oci-image'}), {
    mountPath: '/input/candidate.oci.tar',
    source: 'oci-archive:/input/candidate.oci.tar',
  });
});

test('produces dual SBOM evidence but no vulnerability review', (t) => {
  const value = fixture(t);
  const output = path.join(value.root, 'sbom');
  const runner = (argv) => {
    if (argv.includes('scan')) {
      const format = argv.at(-1);
      return {exitCode: 0, stdout: Buffer.from(JSON.stringify(
        format.startsWith('cyclonedx') ? rawCdx() : rawSpdx())), stderr: Buffer.alloc(0)};
    }
    if (argv.includes('convert')) {
      return {exitCode: 0, stdout: Buffer.from(JSON.stringify(syftDecoded())),
        stderr: Buffer.alloc(0)};
    }
    const volumeIndex = argv.indexOf('--volume');
    const volumes = argv.filter((item, index) => argv[index - 1] === '--volume');
    const invalid = volumes.some((item) => item.includes('invalid-'));
    assert.ok(volumeIndex > 0);
    return {exitCode: invalid ? 1 : 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0)};
  };
  produceSbom({
    candidateRoot: value.candidate, validatorRoot: value.validator, output,
    sourceCommit: COMMIT, sourceTag: TAG, runner,
  });
  for (const id of ['gateway-deb-linux-amd64', 'gateway-oci-linux-amd64']) {
    const directory = path.join(output, 'evidence', id);
    assert.ok(fs.existsSync(path.join(directory, 'validation.json')));
    assert.equal(fs.existsSync(path.join(directory, 'review.json')), false);
  }
  assert.equal(JSON.parse(fs.readFileSync(path.join(output, 'producer-receipt.json')))
    .review_generated, false);
});

test('uses one database for four scans and emits review input, not review authority', (t) => {
  const value = fixture(t);
  const sbomOutput = path.join(value.root, 'sbom');
  const sbomRunner = (argv) => {
    if (argv.includes('scan')) {
      return {exitCode: 0, stdout: Buffer.from(JSON.stringify(
        argv.at(-1).startsWith('cyclonedx') ? rawCdx() : rawSpdx())), stderr: Buffer.alloc(0)};
    }
    if (argv.includes('convert')) return {exitCode: 0,
      stdout: Buffer.from(JSON.stringify(syftDecoded())), stderr: Buffer.alloc(0)};
    const invalid = argv.filter((item, index) => argv[index - 1] === '--volume')
      .some((item) => item.includes('invalid-'));
    return {exitCode: invalid ? 1 : 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0)};
  };
  produceSbom({candidateRoot: value.candidate, validatorRoot: value.validator,
    output: sbomOutput, sourceCommit: COMMIT, sourceTag: TAG, runner: sbomRunner});
  const output = path.join(value.root, 'vulnerability');
  let scanCount = 0;
  const vulnerabilityRunner = (argv) => {
    if (argv.includes('update')) {
      const databaseMount = argv.filter((item, index) => argv[index - 1] === '--volume')
        .find((item) => item.includes(':/database:rw'));
      const databaseRoot = databaseMount.split(':/database:rw')[0];
      fs.mkdirSync(path.join(databaseRoot, '6'), {recursive: true});
      fs.writeFileSync(path.join(databaseRoot, '6/vulnerability.db'), 'database');
      return {exitCode: 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0)};
    }
    const target = argv.find((item) => item.startsWith('sbom:')).slice(5);
    scanCount += 1;
    return {exitCode: 0, stdout: Buffer.from(JSON.stringify(
      scan(path.posix.basename(path.posix.dirname(target))))),
      stderr: Buffer.alloc(0)};
  };
  produceVulnerability({candidateRoot: value.candidate, sbomRoot: sbomOutput,
    output, sourceCommit: COMMIT, sourceTag: TAG, runner: vulnerabilityRunner});
  assert.equal(scanCount, 4);
  assert.ok(fs.existsSync(path.join(output, 'evidence/database/vulnerability.db')));
  for (const id of ['gateway-deb-linux-amd64', 'gateway-oci-linux-amd64']) {
    assert.ok(fs.existsSync(path.join(output, 'review-input', `${id}.json`)));
    assert.equal(fs.existsSync(path.join(output, 'evidence', id, 'review.json')), false);
  }
  const receipt = JSON.parse(fs.readFileSync(path.join(output, 'producer-receipt.json')));
  assert.equal(receipt.release_blocked_pending_review, true);
  assert.ok(Object.values(receipt.authority).every((value) => value === false));
});

test('rejects substituted or unexpected SBOM evidence before scanning', (t) => {
  const sbomRunner = (argv) => {
    if (argv.includes('scan')) return {exitCode: 0, stdout: Buffer.from(JSON.stringify(
      argv.at(-1).startsWith('cyclonedx') ? rawCdx() : rawSpdx())), stderr: Buffer.alloc(0)};
    if (argv.includes('convert')) return {exitCode: 0,
      stdout: Buffer.from(JSON.stringify(syftDecoded())), stderr: Buffer.alloc(0)};
    const invalid = argv.filter((item, index) => argv[index - 1] === '--volume')
      .some((item) => item.includes('invalid-'));
    return {exitCode: invalid ? 1 : 0, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0)};
  };
  const neverScan = () => { throw new Error('scanner must not run'); };

  const substituted = fixture(t);
  const substitutedSbom = path.join(substituted.root, 'sbom');
  produceSbom({candidateRoot: substituted.candidate, validatorRoot: substituted.validator,
    output: substitutedSbom, sourceCommit: COMMIT, sourceTag: TAG, runner: sbomRunner});
  fs.appendFileSync(path.join(substitutedSbom, 'evidence', 'gateway-deb-linux-amd64',
    'cyclonedx.json'), 'changed');
  assert.throws(() => produceVulnerability({candidateRoot: substituted.candidate,
    sbomRoot: substitutedSbom, output: path.join(substituted.root, 'vulnerability'),
    sourceCommit: COMMIT, sourceTag: TAG, runner: neverScan}),
  /cyclonedx-1\.6-json bytes changed/u);

  const expanded = fixture(t);
  const expandedSbom = path.join(expanded.root, 'sbom');
  produceSbom({candidateRoot: expanded.candidate, validatorRoot: expanded.validator,
    output: expandedSbom, sourceCommit: COMMIT, sourceTag: TAG, runner: sbomRunner});
  fs.writeFileSync(path.join(expandedSbom, 'evidence', 'unexpected.json'), '{}\n');
  assert.throws(() => produceVulnerability({candidateRoot: expanded.candidate,
    sbomRoot: expandedSbom, output: path.join(expanded.root, 'vulnerability'),
    sourceCommit: COMMIT, sourceTag: TAG, runner: neverScan}), /file inventory changed/u);
});
