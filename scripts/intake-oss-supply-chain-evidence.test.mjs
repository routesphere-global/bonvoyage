import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {intakeSupplyChainEvidence} from './intake-oss-supply-chain-evidence.mjs';

const COMMIT = 'a'.repeat(40);
const TAG = 'v1.0.0-rc.8';
const NOW = Date.parse('2026-10-30T04:00:00.000Z');
const SCANNED_AT = '2026-10-30T02:00:00.000Z';
const REVIEWED_AT = '2026-10-30T03:00:00.000Z';
const BUILT_AT = '2026-10-30T01:00:00.000Z';
const ARCHIVE_DIGEST = '7'.repeat(64);
const SYFT_IMAGE =
  'anchore/syft:v1.44.0@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6';
const CDX_VALIDATOR =
  'cyclonedx/cyclonedx-cli:0.33.1@sha256:9a37575fb51fcaed3a4c62dddba091c46ffc867712e46bdb6cdf219a7e90a061';
const SPDX_SCHEMA =
  '239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b';
const SPDX_LOCK =
  'e2e52a0b047055d4d860b379b1c0e35931659d94069398c6bf0b68cb21d6e194';
const SPDX_VALIDATOR =
  `spdx-json-schema@sha256:${SPDX_SCHEMA}+` +
  `validator-lock@sha256:${SPDX_LOCK}`;
const GRYPE_IMAGE =
  'anchore/grype:v0.116.1@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db';
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const INTAKE_CONTRACT = path.join(
  REPOSITORY_ROOT, 'packaging/release/oss-candidate-intake-contract.json');
const SUPPLY_CHAIN_CONTRACT = path.join(
  REPOSITORY_ROOT, 'packaging/release/oss-supply-chain-evidence-contract.json');

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function identity(filePath) {
  const content = fs.readFileSync(filePath);
  return {bytes: content.length, sha256: sha256(content)};
}

function write(root, relative, value) {
  const destination = path.join(root, relative);
  fs.mkdirSync(path.dirname(destination), {recursive: true});
  fs.writeFileSync(destination, value);
  return destination;
}

function writeJson(root, relative, value) {
  return write(root, relative, `${JSON.stringify(value, null, 2)}\n`);
}

function replaceJson(filePath, mutate) {
  const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  mutate(value);
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function inventory(root, excluded = new Set()) {
  const files = [];
  function walk(directory, prefix = '') {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(absolute, relative);
      else if (!excluded.has(relative)) files.push({path: relative, ...identity(absolute)});
    }
  }
  walk(root);
  return files.sort((left, right) => left.path.localeCompare(right.path));
}

function source() {
  return {
    repository: 'https://github.com/routesphere-global/bonvoyage',
    commit: COMMIT,
    tag: TAG,
    dirty: false,
  };
}

function powerless() {
  return {
    product_artifact_signature_allowed: false,
    product_provenance_allowed: false,
    release_admitted: false,
    publishable: false,
    github_release_created: false,
    package_uploaded: false,
    container_uploaded: false,
  };
}

function candidateAuthority() {
  return {
    release_admitted: false,
    publishable: false,
    github_release_created: false,
    package_uploaded: false,
    container_uploaded: false,
    signature_created: false,
    provenance_created: false,
  };
}

function artifactBinding(artifact) {
  return {
    id: artifact.id,
    kind: artifact.kind,
    platform: artifact.platform,
    bytes: artifact.bytes,
    sha256: artifact.sha256,
  };
}

function grypeFinding(severity = 'Medium', packageId = 'package-1') {
  return {
    vulnerability: {
      id: 'CVE-fixture',
      namespace: 'ubuntu:distro:ubuntu:24.04',
      severity,
      fix: {state: 'not-fixed', versions: []},
    },
    artifact: {
      id: packageId,
      name: 'libc6',
      version: '2.39',
      type: 'deb',
      purl: 'pkg:deb/ubuntu/libc6@2.39?arch=amd64&distro=ubuntu-24.04',
    },
    matchDetails: [{
      type: 'exact-direct-match',
      matcher: 'dpkg-matcher',
      searchedBy: {},
      found: {},
    }],
  };
}

function grypeScan(target, {
  severity = 'Medium', digest = ARCHIVE_DIGEST, sourceType = 'sbom-file', distro,
  packageId = 'package-1',
} = {}) {
  return {
    source: {type: sourceType, target},
    distro,
    matches: [grypeFinding(severity, packageId)],
    descriptor: {
      name: 'grype',
      version: '0.116.1',
      timestamp: SCANNED_AT,
      db: {
        status: {
          valid: true,
          schemaVersion: 'v6.1.9',
          built: BUILT_AT,
          path: '/evidence/database/vulnerability.db',
          from: 'https://grype.anchore.io/databases/v6/database.tar.zst' +
            `?checksum=sha256%3A${digest}`,
        },
      },
      configuration: {
        'only-fixed': false,
        'only-notfixed': false,
        'ignore-wontfix': '',
        exclude: [],
        'vex-documents': [],
        'vex-add': [],
        ignore: [],
        db: {
          'validate-by-hash-on-start': true,
          'validate-age': true,
          'max-allowed-built-age': 172800000000000,
        },
      },
    },
  };
}

function reviewedFinding(severity = 'Medium') {
  return {
    id: 'CVE-fixture',
    namespace: 'ubuntu:distro:ubuntu:24.04',
    package_id: 'pkg:deb/ubuntu/libc6@2.39?arch=amd64&distro=ubuntu-24.04',
    package: 'libc6',
    version: '2.39',
    type: 'deb',
    severity,
    fix_state: 'not-fixed',
    fix_versions: [],
    disposition: 'observed-nonblocking',
    rationale: 'Medium fixture is retained as nonblocking technical evidence.',
  };
}

function createCandidate(candidateRoot) {
  const contractContent = fs.readFileSync(INTAKE_CONTRACT);
  const contractPath = write(candidateRoot,
    'metadata/oss-candidate-intake-contract.json', contractContent);
  const specifications = [
    ['gateway-deb-linux-amd64', 'debian-package',
      'artifacts/bonvoyage-gateway_1.0.0~rc.8-1_amd64.deb', 'debian candidate\n',
      '1001', 'oss-deb'],
    ['gateway-oci-linux-amd64', 'oci-image',
      'artifacts/bonvoyage-gateway-1.0.0-rc.8-linux-amd64.oci.tar', 'oci candidate\n',
      '1002', 'oss-oci'],
  ];
  const artifacts = specifications.map(([
    id, kind, artifactPath, content, runId, evidencePrefix,
  ]) => {
    const payloadPath = write(candidateRoot, artifactPath, content);
    const artifact = {
      id,
      kind,
      platform: 'linux/amd64',
      path: artifactPath,
      ...identity(payloadPath),
      hosted_run_id: runId,
      builders: ['a', 'b'].map((suffix) => `github-${runId}-1-${suffix}`),
      hosted_evidence_artifacts: ['a', 'b'].map((suffix) => ({
        name: `${evidencePrefix}-build-${suffix}`,
        sha256: sha256(`${id}:${suffix}`),
      })),
    };
    if (kind === 'oci-image') {
      artifact.manifest = {bytes: 10, digest: `sha256:${'d'.repeat(64)}`};
      artifact.config = {bytes: 11, digest: `sha256:${'e'.repeat(64)}`};
      artifact.layer = {
        bytes: 12,
        diff_id: `sha256:${'0'.repeat(64)}`,
        digest: `sha256:${'f'.repeat(64)}`,
      };
    }
    return artifact;
  });
  writeJson(candidateRoot, 'candidate-intake-receipt.json', {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-candidate-intake-receipt',
    product: 'RouteSphere BonVoyage API Gateway',
    created_at: '2026-10-30T00:00:00.000Z',
    contract: {
      path: 'metadata/oss-candidate-intake-contract.json',
      ...identity(contractPath),
    },
    source: source(),
    artifacts,
    files: inventory(candidateRoot, new Set(['candidate-intake-receipt.json'])),
    authority: candidateAuthority(),
  });
  return new Map(artifacts.map((artifact) => [artifact.id, artifact]));
}

function createDatabase(reviewRoot) {
  const payloadPath = write(
    reviewRoot, 'database/vulnerability.db', 'synthetic grype database fixture\n');
  const payload = identity(payloadPath);
  const database = {
    path: 'vulnerability.db',
    ...payload,
    built_at: BUILT_AT,
    schema_version: 'v6.1.9',
    origin: 'https://grype.anchore.io/databases/v6/database.tar.zst',
    archive_sha256: ARCHIVE_DIGEST,
  };
  writeJson(reviewRoot, 'database/receipt.json', {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-vulnerability-database-evidence',
    source: source(),
    scanner_image: GRYPE_IMAGE,
    database,
    authority: powerless(),
  });
  return database;
}

function cyclonedx(artifact) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:00000000-0000-4000-8000-${artifact.sha256.slice(0, 12)}`,
    version: 1,
    metadata: {
      timestamp: '2026-10-30T01:30:00.000Z',
      component: {
        type: 'file',
        'bom-ref': `artifact:${artifact.id}`,
        name: artifact.id,
        version: TAG,
        hashes: [{alg: 'SHA-256', content: artifact.sha256}],
        properties: [
          {name: 'routesphere:artifact-kind', value: artifact.kind},
          {name: 'routesphere:platform', value: artifact.platform},
          {name: 'routesphere:source-commit', value: COMMIT},
        ],
      },
    },
    components: [{
      type: 'library',
      'bom-ref': 'pkg:deb/ubuntu/libc6@2.39',
      name: 'libc6',
      version: '2.39',
      purl: 'pkg:deb/ubuntu/libc6@2.39?arch=amd64&distro=ubuntu-24.04',
    }],
  };
}

function spdx(artifact) {
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${artifact.id}-sbom`,
    documentNamespace: `https://routesphere.global/spdx/${artifact.sha256}`,
    creationInfo: {
      created: '2026-10-30T01:30:00Z',
      creators: ['Tool: syft-1.44.0'],
    },
    packages: [
      {
        SPDXID: 'SPDXRef-ArtifactRoot',
        name: artifact.id,
        versionInfo: TAG,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        primaryPackagePurpose: 'FILE',
        checksums: [{algorithm: 'SHA256', checksumValue: artifact.sha256}],
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: 'NOASSERTION',
        copyrightText: 'NOASSERTION',
      },
      {
        SPDXID: 'SPDXRef-Package-libc6',
        name: 'libc6',
        versionInfo: '2.39',
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: 'NOASSERTION',
        copyrightText: 'NOASSERTION',
        externalRefs: [{
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator:
            'pkg:deb/ubuntu/libc6@2.39?arch=amd64&distro=ubuntu-24.04',
        }],
      },
    ],
    relationships: [{
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: 'SPDXRef-ArtifactRoot',
    }],
  };
}

function decoded(artifact, format) {
  return {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-sbom-decoded-inventory',
    source: source(),
    artifact: artifactBinding(artifact),
    format,
    descriptor: {name: 'syft', version: '1.44.0'},
    packages: [{
      name: 'libc6',
      version: '2.39',
      type: 'deb',
      purl: 'pkg:deb/ubuntu/libc6@2.39?arch=amd64&distro=ubuntu-24.04',
    }],
  };
}

function commandReceipts(artifact, documents) {
  const receipts = [];
  for (const document of documents) {
    const validator = document.format === 'cyclonedx-1.6-json' ?
      CDX_VALIDATOR : SPDX_VALIDATOR;
    const invalid = sha256(`invalid-control:${document.format}`);
    receipts.push(
      {
        operation: 'generate',
        format: document.format,
        tool: SYFT_IMAGE,
        argv: ['syft', artifact.id, '-o', document.format],
        exit_code: 0,
        input_sha256: artifact.sha256,
        output_sha256: document.sha256,
      },
      {
        operation: 'schema-validate',
        format: document.format,
        tool: validator,
        argv: ['validate', document.path],
        exit_code: 0,
        input_sha256: document.sha256,
        output_sha256: document.sha256,
      },
      {
        operation: 'invalid-control',
        format: document.format,
        tool: validator,
        argv: ['validate', `invalid-${document.path}`],
        exit_code: 1,
        input_sha256: invalid,
        output_sha256: invalid,
      },
      {
        operation: 'decode',
        format: document.format,
        tool: SYFT_IMAGE,
        argv: ['syft', 'convert', document.path, '-o', 'syft-json'],
        exit_code: 0,
        input_sha256: document.sha256,
        output_sha256: document.decoded_sha256,
      },
    );
  }
  return receipts;
}

function createReview(reviewRoot, artifact, database) {
  const directory = artifact.id;
  const cdxPath = writeJson(reviewRoot, `${directory}/cyclonedx.json`,
    cyclonedx(artifact));
  const spdxPath = writeJson(reviewRoot, `${directory}/spdx.json`,
    spdx(artifact));
  const decodedCdxPath = writeJson(
    reviewRoot, `${directory}/decoded-cyclonedx.json`,
    decoded(artifact, 'cyclonedx-1.6-json'));
  const decodedSpdxPath = writeJson(
    reviewRoot, `${directory}/decoded-spdx.json`,
    decoded(artifact, 'spdx-2.3-json'));
  const documents = [
    {
      format: 'cyclonedx-1.6-json',
      path: 'cyclonedx.json',
      ...identity(cdxPath),
      decoded_path: 'decoded-cyclonedx.json',
      decoded_bytes: identity(decodedCdxPath).bytes,
      decoded_sha256: identity(decodedCdxPath).sha256,
    },
    {
      format: 'spdx-2.3-json',
      path: 'spdx.json',
      ...identity(spdxPath),
      decoded_path: 'decoded-spdx.json',
      decoded_bytes: identity(decodedSpdxPath).bytes,
      decoded_sha256: identity(decodedSpdxPath).sha256,
    },
  ];
  writeJson(reviewRoot, `${directory}/validation.json`, {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-sbom-validation-evidence',
    source: source(),
    artifact: artifactBinding(artifact),
    tools: {
      syft_image: SYFT_IMAGE,
      cyclonedx_validator_image: CDX_VALIDATOR,
      spdx_schema_sha256: SPDX_SCHEMA,
      spdx_validator_lock_sha256: SPDX_LOCK,
    },
    documents,
    command_receipts: commandReceipts(artifact, documents),
    decoder_parity: true,
    authority: powerless(),
  });

  const scanSpecifications = [
    ['cyclonedx-1.6-json', 'scan-cyclonedx.json',
      `/input/${artifact.id}/cyclonedx.json`, identity(cdxPath).sha256, 'file'],
    ['spdx-2.3-json', 'scan-spdx.json',
      `/input/${artifact.id}/spdx.json`, identity(spdxPath).sha256, 'directory'],
  ];
  const scans = scanSpecifications.map(([
    format, file, target, inputSha, sourceType,
  ]) => {
    const distro = artifact.kind === 'debian-package' ?
      {name: '', version: '', idLike: null} :
      {name: 'ubuntu', version: '24.04',
        idLike: [format === 'cyclonedx-1.6-json' ? 'debian' : 'ubuntu']};
    const filePath = writeJson(
      reviewRoot, `${directory}/${file}`, grypeScan(target, {
        sourceType,
        distro,
        packageId: format === 'cyclonedx-1.6-json' ?
          'pkg:deb/ubuntu/libc6@2.39?package-id=fixture' :
          'Package-deb-libc6-fixture',
      }));
    return {
      format,
      path: file,
      ...identity(filePath),
      target,
      input_sha256: inputSha,
    };
  });
  writeJson(reviewRoot, `${directory}/review.json`, {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-vulnerability-review-evidence',
    source: source(),
    artifact: artifactBinding(artifact),
    scanner_image: GRYPE_IMAGE,
    database,
    scans: scans.map(({input_sha256, ...scan}) => scan),
    scan_commands: scans.map((scan) => ({
      format: scan.format,
      tool: GRYPE_IMAGE,
      argv: ['grype', `sbom:${scan.target}`, '-o', 'json'],
      exit_code: 0,
      input_sha256: scan.input_sha256,
      database_sha256: database.sha256,
      output_sha256: scan.sha256,
    })),
    reviewer: {
      identity: 'johnynixon@routesphere.global',
      role: 'release-security-reviewer',
    },
    findings: [reviewedFinding()],
    format_parity: true,
    unreviewed_findings: 0,
    unresolved_blocking_findings: 0,
    reviewed_at: REVIEWED_AT,
    authority: powerless(),
  });
}

function createFixture(t) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-supply-chain-'));
  t.after(() => fs.rmSync(temporary, {recursive: true, force: true}));
  const candidateRoot = path.join(temporary, 'candidate');
  const reviewRoot = path.join(temporary, 'review');
  const output = path.join(temporary, 'output');
  fs.mkdirSync(candidateRoot);
  fs.mkdirSync(reviewRoot);
  const artifacts = createCandidate(candidateRoot);
  const database = createDatabase(reviewRoot);
  for (const artifact of artifacts.values()) createReview(reviewRoot, artifact, database);
  return {temporary, candidateRoot, reviewRoot, output, artifacts, database};
}

function run(fixture, overrides = {}) {
  return intakeSupplyChainEvidence({
    candidateRoot: fixture.candidateRoot,
    reviewRoot: fixture.reviewRoot,
    output: fixture.output,
    sourceCommit: COMMIT,
    sourceTag: TAG,
    verifiedAt: NOW,
    ...overrides,
  });
}

function rejectWithoutOutput(fixture, expression, overrides = {}) {
  assert.throws(() => run(fixture, overrides), expression);
  assert.equal(fs.existsSync(fixture.output), false);
}

function evidencePath(fixture, artifactId, file) {
  return path.join(fixture.reviewRoot, artifactId, file);
}

test('retains one neutral supply-chain handoff without minting gate receipts', (t) => {
  const fixture = createFixture(t);
  const result = run(fixture);
  assert.equal(result.status, 'EVIDENCE_RETAINED');
  assert.equal(result.release_admitted, false);
  assert.equal(result.publishable, false);
  assert.equal(result.artifacts.length, 2);
  assert.match(result.handoff_sha256, /^[a-f0-9]{64}$/u);
  const handoff = JSON.parse(fs.readFileSync(result.handoff_path, 'utf8'));
  assert.equal(handoff.classification,
    'routesphere-bonvoyage-oss-supply-chain-evidence-handoff');
  assert.equal(handoff.status, 'EVIDENCE_RETAINED');
  assert.equal(handoff.authority.evidence_handoff_allowed, true);
  assert.equal(fs.existsSync(path.join(fixture.output, 'receipts')), false);
  assert.equal(fs.readFileSync(result.handoff_path, 'utf8').includes('PASS'), false);
  for (const field of Object.keys(powerless())) {
    assert.equal(handoff.authority[field], false);
  }
});

test('rejects candidate substitution and unaccounted intake files', (t) => {
  const substituted = createFixture(t);
  const artifact = substituted.artifacts.get('gateway-deb-linux-amd64');
  fs.appendFileSync(path.join(substituted.candidateRoot, artifact.path), 'changed');
  rejectWithoutOutput(substituted, /receipt\.files|payload/u);

  const extra = createFixture(t);
  write(extra.candidateRoot, 'unexpected.txt', 'unexpected\n');
  rejectWithoutOutput(extra, /receipt\.files/u);
});

test('rejects hosted candidate metadata drift', (t) => {
  const builder = createFixture(t);
  replaceJson(path.join(builder.candidateRoot, 'candidate-intake-receipt.json'), (value) => {
    value.artifacts[0].builders[1] = 'github-1001-1-c';
  });
  rejectWithoutOutput(builder, /builders do not bind the hosted run/u);

  const layer = createFixture(t);
  replaceJson(path.join(layer.candidateRoot, 'candidate-intake-receipt.json'), (value) => {
    value.artifacts[1].layer.diff_id = '0'.repeat(64);
  });
  rejectWithoutOutput(layer, /layer\.diff_id must be a lowercase sha256: digest/u);
});

test('rejects SBOM substitution and a candidate-root digest mismatch', (t) => {
  const substituted = createFixture(t);
  fs.appendFileSync(evidencePath(
    substituted, 'gateway-deb-linux-amd64', 'cyclonedx.json'), ' ');
  rejectWithoutOutput(substituted, /validation is unbound/u);

  const rootMismatch = createFixture(t);
  replaceJson(evidencePath(
    rootMismatch, 'gateway-oci-linux-amd64', 'spdx.json'), (value) => {
    value.packages[0].checksums[0].checksumValue = 'b'.repeat(64);
  });
  rejectWithoutOutput(rootMismatch, /SPDX root is not bound/u);
});

test('rejects incomplete command evidence and duplicate JSON keys', (t) => {
  const incomplete = createFixture(t);
  replaceJson(evidencePath(
    incomplete, 'gateway-deb-linux-amd64', 'validation.json'), (value) => {
    value.command_receipts.pop();
  });
  rejectWithoutOutput(incomplete, /command_receipts is incomplete/u);

  const duplicate = createFixture(t);
  const file = evidencePath(duplicate, 'gateway-deb-linux-amd64', 'cyclonedx.json');
  const text = fs.readFileSync(file, 'utf8').replace(
    '"bomFormat": "CycloneDX",',
    '"bomFormat": "CycloneDX",\n  "bom\\u0046ormat": "CycloneDX",');
  fs.writeFileSync(file, text);
  rejectWithoutOutput(duplicate, /duplicate JSON key/u);
});

test('rejects decoded inventory divergence', (t) => {
  const fixture = createFixture(t);
  replaceJson(evidencePath(
    fixture, 'gateway-oci-linux-amd64', 'decoded-spdx.json'), (value) => {
    value.packages[0].version = '2.40';
  });
  rejectWithoutOutput(fixture, /decoded package inventories differ/u);
});

test('rejects changed pinned tool identities in the contract', (t) => {
  const fixture = createFixture(t);
  const contract = JSON.parse(fs.readFileSync(SUPPLY_CHAIN_CONTRACT, 'utf8'));
  contract.sbom.syft_image = contract.sbom.syft_image.replace('v1.44.0', 'v1.45.0');
  const contractPath = writeJson(fixture.temporary, 'changed-contract.json', contract);
  rejectWithoutOutput(fixture, /pinned tool identity changed/u, {contractPath});
});

test('rejects mixed source and artifact bindings', (t) => {
  const sourceMismatch = createFixture(t);
  replaceJson(evidencePath(
    sourceMismatch, 'gateway-deb-linux-amd64', 'review.json'), (value) => {
    value.source.commit = 'b'.repeat(40);
  });
  rejectWithoutOutput(sourceMismatch, /exact clean public source/u);

  const artifactMismatch = createFixture(t);
  replaceJson(evidencePath(
    artifactMismatch, 'gateway-oci-linux-amd64', 'validation.json'), (value) => {
    value.artifact.sha256 = 'b'.repeat(64);
  });
  rejectWithoutOutput(artifactMismatch, /does not match the candidate artifact/u);
});

test('rejects cross-artifact database drift', (t) => {
  const fixture = createFixture(t);
  for (const file of ['scan-cyclonedx.json', 'scan-spdx.json']) {
    replaceJson(evidencePath(
      fixture, 'gateway-oci-linux-amd64', file), (value) => {
      value.descriptor.db.status.from = value.descriptor.db.status.from
        .replace(ARCHIVE_DIGEST, '8'.repeat(64));
    });
  }
  rejectWithoutOutput(fixture, /retained database receipt/u);
});

test('rejects an unrecognized retained scanner source type', (t) => {
  const fixture = createFixture(t);
  replaceJson(evidencePath(
    fixture, 'gateway-deb-linux-amd64', 'scan-cyclonedx.json'), (value) => {
    value.source.type = 'image';
  });
  rejectWithoutOutput(fixture, /source is not bound to the retained SBOM target/u);
});

test('rejects retained scanner distro drift', (t) => {
  const fixture = createFixture(t);
  replaceJson(evidencePath(
    fixture, 'gateway-oci-linux-amd64', 'scan-spdx.json'), (value) => {
    value.distro.version = '22.04';
  });
  rejectWithoutOutput(fixture, /must retain the Ubuntu 24\.04 image identity/u);
});

test('rejects physical database substitution', (t) => {
  const fixture = createFixture(t);
  fs.appendFileSync(
    path.join(fixture.reviewRoot, 'database/vulnerability.db'), 'changed');
  rejectWithoutOutput(fixture, /does not bind the retained database/u);
});

test('rejects findings that differ between SBOM formats', (t) => {
  const fixture = createFixture(t);
  replaceJson(evidencePath(
    fixture, 'gateway-oci-linux-amd64', 'scan-spdx.json'), (value) => {
    value.matches[0].vulnerability.severity = 'Low';
  });
  rejectWithoutOutput(fixture, /findings differ/u);
});

test('rejects suppressed findings and blocking severities', (t) => {
  const suppressed = createFixture(t);
  replaceJson(evidencePath(
    suppressed, 'gateway-deb-linux-amd64', 'scan-cyclonedx.json'), (value) => {
    value.ignoredMatches = [grypeFinding('Low')];
  });
  rejectWithoutOutput(suppressed, /suppressed matches rejected/u);

  const blocking = createFixture(t);
  for (const file of ['scan-cyclonedx.json', 'scan-spdx.json']) {
    replaceJson(evidencePath(
      blocking, 'gateway-oci-linux-amd64', file), (value) => {
      value.matches[0].vulnerability.severity = 'High';
    });
  }
  rejectWithoutOutput(blocking, /unresolved High or Critical/u);
});

test('rejects missing reviewer, incomplete findings and stale review', (t) => {
  const reviewer = createFixture(t);
  replaceJson(evidencePath(
    reviewer, 'gateway-deb-linux-amd64', 'review.json'), (value) => {
    value.reviewer.identity = 'security@routesphere.global';
  });
  rejectWithoutOutput(reviewer, /accountable contracted reviewer/u);

  const incomplete = createFixture(t);
  replaceJson(evidencePath(
    incomplete, 'gateway-deb-linux-amd64', 'review.json'), (value) => {
    value.findings = [];
  });
  rejectWithoutOutput(incomplete, /does not cover every exact finding/u);

  const stale = createFixture(t);
  replaceJson(evidencePath(
    stale, 'gateway-oci-linux-amd64', 'review.json'), (value) => {
    value.reviewed_at = '2026-10-27T03:00:00.000Z';
  });
  rejectWithoutOutput(stale, /stale or future-dated/u);
});

test('rejects authority escalation and unexpected evidence files', (t) => {
  const authority = createFixture(t);
  replaceJson(evidencePath(
    authority, 'gateway-deb-linux-amd64', 'review.json'), (value) => {
    value.authority.publishable = true;
  });
  rejectWithoutOutput(authority, /publishable must remain false/u);

  const extra = createFixture(t);
  write(extra.reviewRoot, 'gateway-oci-linux-amd64/extra.json', '{}\n');
  rejectWithoutOutput(extra, /exactly the fixed evidence files/u);
});

test('rejects linked evidence and refuses to overwrite output', (t) => {
  const linked = createFixture(t);
  const directory = path.join(linked.reviewRoot, 'gateway-deb-linux-amd64');
  fs.unlinkSync(path.join(directory, 'spdx.json'));
  fs.symlinkSync(path.join(directory, 'cyclonedx.json'), path.join(directory, 'spdx.json'));
  rejectWithoutOutput(linked, /fixed evidence files/u);

  const existing = createFixture(t);
  fs.mkdirSync(existing.output);
  assert.throws(() => run(existing), /must not already exist/u);
});
