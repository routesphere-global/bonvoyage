import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

import {
  verifyReleaseBundle,
  verifyReleaseBundleForTests,
} from './verify-oss-release-bundle.mjs';

const CONTRACT_PATH = fileURLToPath(new URL(
  '../packaging/release/oss-1.0-contract.json', import.meta.url));
const VERIFIER_PATH = fileURLToPath(new URL(
  './verify-oss-release-bundle.mjs', import.meta.url));
const COMMIT = 'a'.repeat(40);
const VERSION = '1.0.0-rc.1';
const CREATED_AT = '2026-10-07T12:00:00.000Z';
const APPROVED_AT = '2026-10-07T12:30:00.000Z';
const AUTHORIZATION_CREATED_AT = '2026-10-07T13:00:00.000Z';
const AUTHORIZATION_EXPIRES_AT = '2026-10-08T13:00:00.000Z';
const AUTHORIZATION_VERIFICATION_TIME = Date.parse('2026-10-07T13:30:00.000Z');

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function sha256File(filePath) {
  return sha256(fs.readFileSync(filePath));
}

function write(root, relativePath, value) {
  const destination = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(destination), {recursive: true});
  fs.writeFileSync(destination, value);
  return {
    path: relativePath,
    sha256: sha256File(destination),
  };
}

function writeJson(root, relativePath, value) {
  return write(root, relativePath, `${JSON.stringify(value, null, 2)}\n`);
}

function inventory(root) {
  const records = [];
  function walk(directory, prefix = '') {
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
      const relativePath = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      const absolutePath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        walk(absolutePath, relativePath);
      } else if (relativePath !== 'release-manifest.json') {
        const stat = fs.statSync(absolutePath);
        records.push({
          path: relativePath,
          bytes: stat.size,
          sha256: sha256File(absolutePath),
        });
      }
    }
  }
  walk(root);
  return records.sort((left, right) => left.path.localeCompare(right.path));
}

function gateReceipt(root, {gate, artifactId = null, artifactSha256 = null}) {
  const scope = artifactId ?? 'global';
  const evidence = write(root, `evidence/${scope}/${gate}.txt`, `${scope}:${gate}:PASS\n`);
  return writeJson(root, `receipts/${scope}-${gate}.json`, {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-release-gate-receipt',
    gate,
    status: 'PASS',
    source_commit: COMMIT,
    artifact_id: artifactId,
    artifact_sha256: artifactSha256,
    evidence: [evidence],
  });
}

function createActiveTestContract(
    temporaryRoot,
    {
      privateKeyInTrustRoot = false,
      unsafeReviewerIdentity = false,
    } = {}) {
  const contract = JSON.parse(fs.readFileSync(CONTRACT_PATH, 'utf8'));
  contract.publication_authorization.status = 'active';
  const privateKeys = new Map();
  for (const role of contract.publication_review_roles) {
    const {privateKey, publicKey} = crypto.generateKeyPairSync('ed25519');
    const keyId = `fixture-${role}-key`;
    const reviewerIdentity =
      `fixture-reviewer:${role}${unsafeReviewerIdentity ? '\u200b' : ''}`;
    contract.publication_authorization.role_signers[role] = [{
      key_id: keyId,
      algorithm: 'ed25519',
      reviewer_identity: reviewerIdentity,
      public_key_pem: privateKeyInTrustRoot
        ? privateKey.export({type: 'pkcs8', format: 'pem'})
        : publicKey.export({type: 'spki', format: 'pem'}),
      status: 'active',
    }];
    privateKeys.set(role, {keyId, reviewerIdentity, privateKey});
  }
  const contractPath = path.join(temporaryRoot, 'active-test-contract.json');
  fs.writeFileSync(contractPath, `${JSON.stringify(contract, null, 2)}\n`);
  return {contract, contractPath, privateKeys};
}

function authorizationInventory(root) {
  return inventory(root).filter(
    (record) => record.path !== 'publication-authorization.json');
}

function createBundle(
    t,
    {
      authorized = false,
      privateKeyInTrustRoot = false,
      unsafeReviewerIdentity = false,
    } = {}) {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-release-'));
  t.after(() => fs.rmSync(temporaryRoot, {recursive: true, force: true}));
  const root = path.join(temporaryRoot, 'bundle');
  fs.mkdirSync(root);

  const activeContract = authorized
    ? createActiveTestContract(
      temporaryRoot, {
        privateKeyInTrustRoot,
        unsafeReviewerIdentity,
      })
    : null;
  const contractPath = activeContract?.contractPath ?? CONTRACT_PATH;
  const contract = JSON.parse(fs.readFileSync(contractPath, 'utf8'));
  const contractRef = write(
    root,
    'metadata/oss-1.0-contract.json',
    fs.readFileSync(contractPath));
  const globalReceipts = contract.global_gates.map((gate) => ({
    gate,
    ...gateReceipt(root, {gate}),
  }));

  const workflowIdentity =
    `${contract.requirements.signature_subject_prefix}v${VERSION}`;
  const artifacts = contract.artifacts.map((contractArtifact) => {
    const extension = contractArtifact.kind === 'debian-package' ? 'deb' : 'tar';
    const payload = write(
      root,
      `artifacts/${contractArtifact.id}.${extension}`,
      `payload:${contractArtifact.id}\n`);
    const sboms = contract.requirements.sbom_formats.map((format) => ({
      format,
      ...writeJson(root, `sbom/${contractArtifact.id}.${format}.json`, {
        fixture: true,
        artifact_sha256: payload.sha256,
        format,
      }),
    }));
    const provenance = {
      ...writeJson(root, `provenance/${contractArtifact.id}.intoto.jsonl`, {
        fixture: true,
        subject_sha256: payload.sha256,
      }),
      slsa_build_level: 2,
      subject_sha256: payload.sha256,
    };
    const signature = {
      ...writeJson(root, `signatures/${contractArtifact.id}.sigstore.json`, {
        fixture: true,
        artifact_sha256: payload.sha256,
      }),
      mode: contract.requirements.signature_mode,
      issuer: contract.requirements.signature_issuer,
      subject: workflowIdentity,
    };
    const receipts = contract.artifact_gates.map((gate) => ({
      gate,
      ...gateReceipt(root, {
        gate,
        artifactId: contractArtifact.id,
        artifactSha256: payload.sha256,
      }),
    }));
    return {
      ...contractArtifact,
      ...payload,
      bytes: fs.statSync(path.join(root, payload.path)).size,
      reproducibility: {
        byte_identical: true,
        builds: [
          {builder: 'hosted-build-a', artifact_sha256: payload.sha256},
          {builder: 'hosted-build-b', artifact_sha256: payload.sha256},
        ],
      },
      sboms,
      vulnerability_review: {
        database_built_at: '2026-10-07T00:00:00.000Z',
        database_digest: 'b'.repeat(64),
        format_parity: true,
        unreviewed_findings: 0,
        unresolved_blocking_findings: 0,
      },
      provenance,
      signature,
      receipts,
    };
  });

  const hostedBuild = {
    hosted: true,
    provider: 'github-actions',
    workflow_identity: workflowIdentity,
    run_id: '123456789',
    slsa_build_level: 2,
  };
  const manifest = {
    schema_version: 2,
    classification: 'routesphere-bonvoyage-oss-release-manifest',
    product: contract.product,
    version: VERSION,
    created_at: CREATED_AT,
    contract: contractRef,
    source: {
      repository: contract.source_repository,
      commit: COMMIT,
      tag: `v${VERSION}`,
      clean: true,
      pushed: true,
    },
    hosted_build: hostedBuild,
    global_receipts: globalReceipts,
    artifacts,
    files: inventory(root),
  };
  const manifestPath = path.join(root, 'release-manifest.json');
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  const fixture = {
    root,
    manifest,
    manifestPath,
    manifestSha256: sha256File(manifestPath),
    contractPath,
    contractSha256: contractRef.sha256,
    allowUnpinnedContractForTests: authorized,
    privateKeys: activeContract?.privateKeys ?? null,
    authorizationRoot: null,
    authorization: null,
    authorizationPath: null,
    authorizationSha256: null,
  };
  if (authorized) {
    createAuthorization(fixture, contract);
  }
  return fixture;
}

function createAuthorization(fixture, contract) {
  const authorizationRoot = path.join(path.dirname(fixture.root), 'authorization');
  fs.mkdirSync(authorizationRoot);
  const rightsGates = contract.publication_authorization.rights_gate_ids.map((id) => {
    const evidence = writeJson(
      authorizationRoot,
      `evidence/rights/${id}.json`,
      {gate_id: id, fixture_review_record: true},
    );
    return {
      id,
      status: 'APPROVED',
      evidence: [evidence],
    };
  });
  const rightsRecord = writeJson(
    authorizationRoot,
    'rights/rights-approval.json',
    {
      schema_version: 1,
      classification: 'routesphere-bonvoyage-oss-rights-approval-record',
      technical_manifest_sha256: fixture.manifestSha256,
      contract_sha256: fixture.contractSha256,
      approved_at: APPROVED_AT,
      gates: rightsGates,
    },
  );
  const reviews = contract.publication_review_roles.map((role) => {
    const signer = fixture.privateKeys.get(role);
    const statement = {
      schema_version: 1,
      classification: 'routesphere-bonvoyage-oss-publication-review-statement',
      role,
      status: 'APPROVED',
      signer_key_id: signer.keyId,
      reviewer_identity: signer.reviewerIdentity,
      approved_at: APPROVED_AT,
      authorization_created_at: AUTHORIZATION_CREATED_AT,
      authorization_expires_at: AUTHORIZATION_EXPIRES_AT,
      technical_manifest_sha256: fixture.manifestSha256,
      contract_sha256: fixture.contractSha256,
      rights_record_sha256: role === 'release-owner' ? rightsRecord.sha256 : null,
      evidence: [fixture.manifest.contract],
    };
    const statementRef = writeJson(
      authorizationRoot, `reviews/${role}.json`, statement);
    const statementBytes = fs.readFileSync(
      path.join(authorizationRoot, statementRef.path));
    const signature = crypto.sign(null, statementBytes, signer.privateKey);
    const signatureRef = write(
      authorizationRoot,
      `signatures/${role}.sig`,
      `${signature.toString('base64')}\n`,
    );
    return {
      role,
      ...statementRef,
      signature_path: signatureRef.path,
      signature_sha256: signatureRef.sha256,
      signer_key_id: signer.keyId,
    };
  });
  const authorization = {
    schema_version: 1,
    classification: 'routesphere-bonvoyage-oss-publication-authorization',
    product: contract.product,
    version: VERSION,
    created_at: AUTHORIZATION_CREATED_AT,
    expires_at: AUTHORIZATION_EXPIRES_AT,
    technical_manifest_sha256: fixture.manifestSha256,
    contract_sha256: fixture.contractSha256,
    rights_record: rightsRecord,
    reviews,
    files: authorizationInventory(authorizationRoot),
  };
  const authorizationPath = path.join(
    authorizationRoot, 'publication-authorization.json');
  fs.writeFileSync(
    authorizationPath, `${JSON.stringify(authorization, null, 2)}\n`);
  fixture.authorizationRoot = authorizationRoot;
  fixture.authorization = authorization;
  fixture.authorizationPath = authorizationPath;
  fixture.authorizationSha256 = sha256File(authorizationPath);
}

function rewriteManifest(fixture, mutate) {
  mutate(fixture.manifest);
  fs.writeFileSync(
    fixture.manifestPath,
    `${JSON.stringify(fixture.manifest, null, 2)}\n`);
  fixture.manifestSha256 = sha256File(fixture.manifestPath);
}

function refreshInventoryRecord(fixture, relativePath) {
  const absolutePath = path.join(fixture.root, relativePath);
  const stat = fs.statSync(absolutePath);
  const record = fixture.manifest.files.find((value) => value.path === relativePath);
  assert.ok(record, `missing fixture inventory record for ${relativePath}`);
  record.bytes = stat.size;
  record.sha256 = sha256File(absolutePath);
  return record;
}

function rewriteAuthorization(fixture, mutate) {
  mutate(fixture.authorization);
  fs.writeFileSync(
    fixture.authorizationPath,
    `${JSON.stringify(fixture.authorization, null, 2)}\n`);
  fixture.authorizationSha256 = sha256File(fixture.authorizationPath);
}

function refreshAuthorizationInventoryRecord(fixture, relativePath) {
  const absolutePath = path.join(fixture.authorizationRoot, relativePath);
  const stat = fs.statSync(absolutePath);
  const record = fixture.authorization.files.find(
    (value) => value.path === relativePath);
  assert.ok(record, `missing authorization inventory record for ${relativePath}`);
  record.bytes = stat.size;
  record.sha256 = sha256File(absolutePath);
  return record;
}

function mutatePublicationReview(fixture, index, mutate, {resign = true} = {}) {
  const reference = fixture.authorization.reviews[index];
  const statementPath = path.join(fixture.authorizationRoot, reference.path);
  const statement = JSON.parse(fs.readFileSync(statementPath, 'utf8'));
  mutate(statement, reference);
  fs.writeFileSync(statementPath, `${JSON.stringify(statement, null, 2)}\n`);
  const statementRecord = refreshAuthorizationInventoryRecord(
    fixture, reference.path);
  reference.sha256 = statementRecord.sha256;
  if (resign) {
    const signer = fixture.privateKeys.get(reference.role);
    const signature = crypto.sign(
      null, fs.readFileSync(statementPath), signer.privateKey);
    const signaturePath = path.join(
      fixture.authorizationRoot, reference.signature_path);
    fs.writeFileSync(signaturePath, `${signature.toString('base64')}\n`);
    const signatureRecord = refreshAuthorizationInventoryRecord(
      fixture, reference.signature_path);
    reference.signature_sha256 = signatureRecord.sha256;
  }
  rewriteAuthorization(fixture, () => {});
}

function mutateRightsRecord(fixture, mutate) {
  const reference = fixture.authorization.rights_record;
  const rightsPath = path.join(fixture.authorizationRoot, reference.path);
  const rights = JSON.parse(fs.readFileSync(rightsPath, 'utf8'));
  mutate(rights, reference);
  fs.writeFileSync(rightsPath, `${JSON.stringify(rights, null, 2)}\n`);
  const record = refreshAuthorizationInventoryRecord(fixture, reference.path);
  reference.sha256 = record.sha256;
  rewriteAuthorization(fixture, () => {});
}

function verify(fixture, overrides = {}) {
  const common = {
    bundlePath: fixture.root,
    manifestSha256: fixture.manifestSha256,
    authorizationPath: fixture.authorizationRoot,
    authorizationSha256: fixture.authorizationSha256,
    ...overrides,
  };
  if (!fixture.allowUnpinnedContractForTests) {
    return verifyReleaseBundle(common);
  }
  if (!Object.hasOwn(common, 'verificationTime')) {
    common.verificationTime = AUTHORIZATION_VERIFICATION_TIME;
  }
  return verifyReleaseBundleForTests({
    ...common,
    contractPath: fixture.contractPath,
    trustedContractSha256: fixture.contractSha256,
  });
}

test('accepts a complete technical candidate without authorizing publication', (t) => {
  const fixture = createBundle(t);
  const result = verify(fixture);
  assert.equal(result.status, 'PASS');
  assert.equal(result.publishable, false);
  assert.equal(result.artifacts, 2);
  assert.throws(
    () => verify(fixture, {requirePublishable: true}),
    /publication is not authorized/);
});

test('technical manifest rejects embedded publication authority', (t) => {
  const fixture = createBundle(t);
  rewriteManifest(fixture, (manifest) => {
    manifest.publication = {authorized: true};
  });
  assert.throws(
    () => verify(fixture),
    /release-manifest.json fields must be exactly/u);
});

test('validates signed authorization mechanics without reporting publishable', (t) => {
  const fixture = createBundle(t, {authorized: true});
  const result = verify(fixture, {requirePublishable: true});
  assert.equal(result.status, 'TEST_ONLY_PASS');
  assert.equal(result.publishable, false);
  assert.equal(result.authorization_test_valid, true);
  assert.equal(result.test_only, true);
  assert.equal(
    result.publication_authorization_sha256,
    fixture.authorizationSha256);
  assert.equal(result.publication_reviewers, 1);
});

test('requires every publication review role exactly once', (t) => {
  const missing = createBundle(t, {authorized: true});
  rewriteAuthorization(missing, (authorization) => {
    authorization.reviews.pop();
  });
  assert.throws(() => verify(missing), /authorization review roles must be exactly/u);

  const duplicate = createBundle(t, {authorized: true});
  rewriteAuthorization(duplicate, (authorization) => {
    authorization.reviews.push({...authorization.reviews[0]});
  });
  assert.throws(() => verify(duplicate), /authorization review roles must be exactly/u);
});

test('publication reviews bind the exact technical candidate and trusted identity', (t) => {
  const wrongSubject = createBundle(t, {authorized: true});
  mutatePublicationReview(wrongSubject, 0, (statement) => {
    statement.technical_manifest_sha256 = 'c'.repeat(64);
  });
  assert.throws(() => verify(wrongSubject), /exact technical candidate/u);

  const unsafeReviewer = createBundle(t, {authorized: true});
  mutatePublicationReview(unsafeReviewer, 0, (statement) => {
    statement.reviewer_identity = 'reviewer\nsubstitution';
  });
  assert.throws(
    () => verify(unsafeReviewer),
    /bounded normalized printable ASCII identity/u);

  const lateApproval = createBundle(t, {authorized: true});
  mutatePublicationReview(lateApproval, 0, (statement) => {
    statement.approved_at = '2026-10-07T13:00:01.000Z';
  });
  assert.throws(() => verify(lateApproval), /stale or outside the review window/u);

  const changedAuthorizationTime = createBundle(t, {authorized: true});
  rewriteAuthorization(changedAuthorizationTime, (authorization) => {
    authorization.created_at = '2026-10-07T13:01:00.000Z';
  });
  assert.throws(
    () => verify(changedAuthorizationTime),
    /does not bind the authorization creation time/u);

  const changedAuthorizationExpiry = createBundle(t, {authorized: true});
  rewriteAuthorization(changedAuthorizationExpiry, (authorization) => {
    authorization.expires_at = '2026-10-08T12:59:00.000Z';
  });
  assert.throws(
    () => verify(changedAuthorizationExpiry),
    /does not bind the authorization expiry time/u);

  const staleApproval = createBundle(t, {authorized: true});
  const staleAuthorizationTime = '2026-10-15T12:31:00.000Z';
  const staleAuthorizationExpiry = '2026-10-16T12:31:00.000Z';
  rewriteAuthorization(staleApproval, (authorization) => {
    authorization.created_at = staleAuthorizationTime;
    authorization.expires_at = staleAuthorizationExpiry;
  });
  for (let index = 0; index < staleApproval.authorization.reviews.length; index += 1) {
    mutatePublicationReview(staleApproval, index, (statement) => {
      statement.authorization_created_at = staleAuthorizationTime;
      statement.authorization_expires_at = staleAuthorizationExpiry;
    });
  }
  assert.throws(
    () => verify(staleApproval, {
      verificationTime: Date.parse('2026-10-15T13:00:00.000Z'),
    }),
    /stale or outside the review window/u);

  const expiredAuthorization = createBundle(t, {authorized: true});
  assert.throws(
    () => verify(expiredAuthorization, {
      verificationTime: Date.parse('2026-10-08T13:00:00.001Z'),
    }),
    /publication authorization is not currently valid/u);
});

test('generic, unsigned, recursive, or extended publication reviews fail closed', (t) => {
  const generic = createBundle(t, {authorized: true});
  mutatePublicationReview(generic, 0, (statement) => {
    statement.classification = 'routesphere-bonvoyage-oss-release-gate-receipt';
  });
  assert.throws(() => verify(generic), /required signed approval/u);

  const unsigned = createBundle(t, {authorized: true});
  mutatePublicationReview(unsigned, 0, (statement) => {
    const artifact = unsigned.manifest.artifacts[0];
    statement.evidence = [{path: artifact.path, sha256: artifact.sha256}];
  }, {resign: false});
  assert.throws(() => verify(unsigned), /signature verification failed/u);

  const recursive = createBundle(t, {authorized: true});
  mutatePublicationReview(recursive, 0, (statement) => {
    const rights = recursive.authorization.rights_record;
    statement.evidence = [{path: rights.path, sha256: rights.sha256}];
  });
  assert.throws(() => verify(recursive), /technical evidence .*missing or changed/u);

  const extended = createBundle(t, {authorized: true});
  mutatePublicationReview(extended, 0, (statement) => {
    statement.unreviewed_claim = true;
  });
  assert.throws(() => verify(extended), /fields must be exactly/u);
});

test('company release owner binds all twelve approved rights gates', (t) => {
  const unresolved = createBundle(t, {authorized: true});
  mutateRightsRecord(unresolved, (rights) => {
    rights.gates[0].status = 'OPEN';
  });
  assert.throws(() => verify(unresolved), /must record APPROVED/u);

  const missingEvidence = createBundle(t, {authorized: true});
  mutateRightsRecord(missingEvidence, (rights) => {
    rights.gates[0].evidence[0].path = 'evidence/rights/not-retained.json';
  });
  assert.throws(
    () => verify(missingEvidence),
    /evidence .* is missing or changed/u);

  const changedRecord = createBundle(t, {authorized: true});
  mutateRightsRecord(changedRecord, (rights) => {
    rights.approved_at = '2026-10-07T12:31:00.000Z';
  });
  assert.throws(
    () => verify(changedRecord),
    /release-owner is not bound to the approved rights record/u);

  const missingBinding = createBundle(t, {authorized: true});
  const ownerIndex = missingBinding.authorization.reviews.findIndex(
    (review) => review.role === 'release-owner');
  mutatePublicationReview(missingBinding, ownerIndex, (statement) => {
    statement.rights_record_sha256 = null;
  });
  assert.throws(
    () => verify(missingBinding),
    /release-owner is not bound to the approved rights record/u);
});

test('canonical active trust policy rejects malformed publication authorization', (t) => {
  const fixture = createBundle(t);
  const authorizationRoot = path.join(path.dirname(fixture.root), 'untrusted-authorization');
  fs.mkdirSync(authorizationRoot);
  const authorizationPath = path.join(
    authorizationRoot, 'publication-authorization.json');
  fs.writeFileSync(authorizationPath, '{}\n');
  assert.throws(
    () => verify(fixture, {
      authorizationPath: authorizationRoot,
      authorizationSha256: sha256File(authorizationPath),
      requirePublishable: true,
    }),
    /publication-authorization\.json fields must be exactly/u);
});

test('authorization cannot be reused against a changed technical manifest', (t) => {
  const fixture = createBundle(t, {authorized: true});
  rewriteManifest(fixture, (manifest) => {
    manifest.hosted_build.run_id = '987654321';
  });
  assert.throws(
    () => verify(fixture),
    /publication authorization is not bound to the exact technical candidate/u);
});

test('publication authorization enforces owner signer hygiene', (t) => {
  const privatePem = createBundle(t, {
    authorized: true,
    privateKeyInTrustRoot: true,
  });
  assert.throws(
    () => verify(privatePem),
    /must contain only canonical SPKI public-key PEM/u);

  const ambiguousIdentity = createBundle(t, {
    authorized: true,
    unsafeReviewerIdentity: true,
  });
  assert.throws(
    () => verify(ambiguousIdentity),
    /bounded normalized printable ASCII identity/u);
});

test('CLI reports admission and enforces strict publication authorization', (t) => {
  const fixture = createBundle(t);
  const argumentsBase = [
    VERIFIER_PATH,
    '--bundle', fixture.root,
    '--manifest-sha256', fixture.manifestSha256,
  ];
  const admitted = spawnSync(process.execPath, argumentsBase, {encoding: 'utf8'});
  assert.equal(admitted.status, 0, admitted.stderr);
  assert.equal(JSON.parse(admitted.stdout).publishable, false);

  const strict = spawnSync(
    process.execPath,
    [...argumentsBase, '--require-publishable'],
    {encoding: 'utf8'},
  );
  assert.equal(strict.status, 1);
  assert.match(strict.stderr, /publication is not authorized/);

  const callerSelectedContract = spawnSync(
    process.execPath,
    [...argumentsBase, '--contract', fixture.contractPath],
    {encoding: 'utf8'},
  );
  assert.equal(callerSelectedContract.status, 1);
  assert.match(callerSelectedContract.stderr, /unknown argument --contract/u);

  assert.throws(
    () => verifyReleaseBundle({
      bundlePath: fixture.root,
      manifestSha256: fixture.manifestSha256,
      contractPath: fixture.contractPath,
    }),
    /production release verification contains unsupported options: contractPath/u);

  const inheritedTrustRoot = Object.create({
    contractPath: fixture.contractPath,
    trustedContractSha256: fixture.contractSha256,
    allowUnpinnedContractForTests: true,
  });
  inheritedTrustRoot.bundlePath = fixture.root;
  inheritedTrustRoot.manifestSha256 = fixture.manifestSha256;
  assert.throws(
    () => verifyReleaseBundle(inheritedTrustRoot),
    /must be a plain options object/u);
});

test('rejects an artifact changed after manifest creation', (t) => {
  const fixture = createBundle(t);
  fs.appendFileSync(
    path.join(fixture.root, fixture.manifest.artifacts[0].path),
    'changed\n');
  assert.throws(() => verify(fixture), /inventory byte count mismatch/);
});

test('stream-hashes large artifacts without whole-file reads', (t) => {
  const fixture = createBundle(t);
  const largePath = path.join(fixture.root, 'unexpected-large-artifact.bin');
  fs.writeFileSync(largePath, Buffer.alloc((8 * 1024 * 1024) + 1, 0x5a));

  const originalReadFileSync = fs.readFileSync;
  fs.readFileSync = (file, ...args) => {
    if (typeof file === 'number' ||
        path.resolve(String(file)) === path.resolve(largePath)) {
      throw new Error('whole-file reads are forbidden during verification');
    }
    return originalReadFileSync(file, ...args);
  };
  try {
    assert.throws(
      () => verify(fixture),
      /manifest\.files paths must be exactly/u);
  } finally {
    fs.readFileSync = originalReadFileSync;
  }
});

test('rejects unexpected files and symbolic links', async (t) => {
  const unexpected = createBundle(t);
  write(unexpected.root, 'unexpected.txt', 'not bound\n');
  assert.throws(() => verify(unexpected), /manifest.files paths/);

  const linked = createBundle(t);
  fs.symlinkSync(
    path.join(linked.root, linked.manifest.artifacts[0].path),
    path.join(linked.root, 'linked-artifact'));
  assert.throws(() => verify(linked), /must not be a symbolic link/);

  const hardLinked = createBundle(t);
  fs.linkSync(
    path.join(hardLinked.root, hardLinked.manifest.artifacts[0].path),
    path.join(hardLinked.root, 'hard-linked-artifact'));
  assert.throws(() => verify(hardLinked), /must not be a hard link/);
});

test('rejects missing and duplicate gate coverage', (t) => {
  const missing = createBundle(t);
  rewriteManifest(missing, (manifest) => manifest.artifacts[0].receipts.pop());
  assert.throws(() => verify(missing), /receipt.*gates must be exactly/);

  const duplicated = createBundle(t);
  rewriteManifest(duplicated, (manifest) => {
    manifest.global_receipts[1].gate = manifest.global_receipts[0].gate;
  });
  assert.throws(() => verify(duplicated), /global_receipts gates must be exactly/);
});

test('rejects dirty, unpushed, or incorrectly signed source', (t) => {
  const dirty = createBundle(t);
  rewriteManifest(dirty, (manifest) => { manifest.source.clean = false; });
  assert.throws(() => verify(dirty), /source must be clean and pushed/);

  const unpushed = createBundle(t);
  rewriteManifest(unpushed, (manifest) => { manifest.source.pushed = false; });
  assert.throws(() => verify(unpushed), /source must be clean and pushed/);

  const wrongIdentity = createBundle(t);
  rewriteManifest(wrongIdentity, (manifest) => {
    manifest.artifacts[0].signature.subject =
      'https://github.com/personal/fork/.github/workflows/release.yml@refs/tags/v1.0.0';
  });
  assert.throws(() => verify(wrongIdentity), /signature identity/);
});

test('rejects re-checksummed receipts with the wrong source or artifact binding', (t) => {
  const wrongSource = createBundle(t);
  const globalRef = wrongSource.manifest.global_receipts[0];
  const globalReceiptPath = path.join(wrongSource.root, globalRef.path);
  const globalReceipt = JSON.parse(fs.readFileSync(globalReceiptPath, 'utf8'));
  globalReceipt.source_commit = 'c'.repeat(40);
  fs.writeFileSync(globalReceiptPath, `${JSON.stringify(globalReceipt, null, 2)}\n`);
  const globalRecord = refreshInventoryRecord(wrongSource, globalRef.path);
  globalRef.sha256 = globalRecord.sha256;
  rewriteManifest(wrongSource, () => {});
  assert.throws(() => verify(wrongSource), /is not bound to source/);

  const wrongArtifact = createBundle(t);
  const artifact = wrongArtifact.manifest.artifacts[0];
  const artifactRef = artifact.receipts[0];
  const artifactReceiptPath = path.join(wrongArtifact.root, artifactRef.path);
  const artifactReceipt = JSON.parse(fs.readFileSync(artifactReceiptPath, 'utf8'));
  artifactReceipt.artifact_sha256 = 'd'.repeat(64);
  fs.writeFileSync(artifactReceiptPath, `${JSON.stringify(artifactReceipt, null, 2)}\n`);
  const artifactRecord = refreshInventoryRecord(wrongArtifact, artifactRef.path);
  artifactRef.sha256 = artifactRecord.sha256;
  rewriteManifest(wrongArtifact, () => {});
  assert.throws(() => verify(wrongArtifact), /has the wrong artifact binding/);
});

test('rejects stale, inconsistent, or unresolved vulnerability review', (t) => {
  const stale = createBundle(t);
  rewriteManifest(stale, (manifest) => {
    manifest.artifacts[0].vulnerability_review.database_built_at =
      '2026-10-01T00:00:00.000Z';
  });
  assert.throws(() => verify(stale), /database is too old/);

  const parity = createBundle(t);
  rewriteManifest(parity, (manifest) => {
    manifest.artifacts[0].vulnerability_review.format_parity = false;
  });
  assert.throws(() => verify(parity), /does not establish SBOM format parity/);

  const unreviewed = createBundle(t);
  rewriteManifest(unreviewed, (manifest) => {
    manifest.artifacts[0].vulnerability_review.unreviewed_findings = 1;
  });
  assert.throws(() => verify(unreviewed), /unreviewed vulnerability findings/);

  const blocking = createBundle(t);
  rewriteManifest(blocking, (manifest) => {
    manifest.artifacts[0].vulnerability_review.unresolved_blocking_findings = 1;
  });
  assert.throws(() => verify(blocking), /unresolved release-blocking/);
});

test('rejects insufficient reproducibility and provenance', (t) => {
  const oneBuild = createBundle(t);
  rewriteManifest(oneBuild, (manifest) => {
    manifest.artifacts[0].reproducibility.builds.pop();
  });
  assert.throws(() => verify(oneBuild), /fewer than 2 independent builds/);

  const repeatedBuilder = createBundle(t);
  rewriteManifest(repeatedBuilder, (manifest) => {
    manifest.artifacts[0].reproducibility.builds[1].builder = 'hosted-build-a';
  });
  assert.throws(() => verify(repeatedBuilder), /builders must be independent/);

  const weakProvenance = createBundle(t);
  rewriteManifest(weakProvenance, (manifest) => {
    manifest.artifacts[0].provenance.slsa_build_level = 1;
  });
  assert.throws(() => verify(weakProvenance), /provenance does not meet/);
});

test('rejects changed receipt evidence and re-checksummed contract substitution', (t) => {
  const evidence = createBundle(t);
  const receiptPath = evidence.manifest.global_receipts[0].path;
  const receipt = JSON.parse(
    fs.readFileSync(path.join(evidence.root, receiptPath), 'utf8'));
  fs.appendFileSync(path.join(evidence.root, receipt.evidence[0].path), 'changed\n');
  assert.throws(() => verify(evidence), /inventory byte count mismatch/);

  const contract = createBundle(t);
  const embeddedContractPath = path.join(
    contract.root, contract.manifest.contract.path);
  const substitutedContract = JSON.parse(
    fs.readFileSync(embeddedContractPath, 'utf8'));
  substitutedContract.product = 'Substituted Product';
  fs.writeFileSync(
    embeddedContractPath,
    `${JSON.stringify(substitutedContract, null, 2)}\n`);
  const contractRecord = refreshInventoryRecord(
    contract, contract.manifest.contract.path);
  contract.manifest.contract.sha256 = contractRecord.sha256;
  rewriteManifest(contract, () => {});
  assert.throws(() => verify(contract), /does not match the verifier contract/);
});

test('rejects a changed release manifest unless its external digest is updated', (t) => {
  const fixture = createBundle(t);
  const acceptedSha = fixture.manifestSha256;
  rewriteManifest(fixture, (manifest) => { manifest.hosted_build.run_id = '987654321'; });
  assert.throws(
    () => verify(fixture, {manifestSha256: acceptedSha}),
    /does not match --manifest-sha256/);
});

test('rejects a bundle file changed during verification', (t) => {
  const fixture = createBundle(t);
  const target = path.join(fixture.root, fixture.manifest.artifacts[0].path);
  const originalOpenSync = fs.openSync;
  let targetOpens = 0;
  fs.openSync = (filePath, ...args) => {
    if (path.resolve(String(filePath)) === path.resolve(target)) {
      targetOpens += 1;
      if (targetOpens === 2) {
        const descriptor = originalOpenSync(
          target, fs.constants.O_WRONLY | fs.constants.O_APPEND);
        try {
          fs.writeSync(descriptor, 'changed-during-verification\n');
        } finally {
          fs.closeSync(descriptor);
        }
      }
    }
    return originalOpenSync(filePath, ...args);
  };
  try {
    assert.throws(
      () => verify(fixture),
      /changed during verification/u);
  } finally {
    fs.openSync = originalOpenSync;
  }
});

test('rejects ambiguous JSON and noncanonical timestamps', (t) => {
  const duplicateMember = createBundle(t);
  const manifestText = fs.readFileSync(duplicateMember.manifestPath, 'utf8');
  fs.writeFileSync(
    duplicateMember.manifestPath,
    manifestText.replace(
      '  "schema_version": 2,',
      '  "schema_version": 2,\n  "schema_version": 2,'),
  );
  duplicateMember.manifestSha256 = sha256File(duplicateMember.manifestPath);
  assert.throws(
    () => verify(duplicateMember),
    /must use the canonical JSON encoding/u);

  const noncanonicalTime = createBundle(t);
  rewriteManifest(noncanonicalTime, (manifest) => {
    manifest.created_at = '2026-10-07T12:00:00Z';
  });
  assert.throws(
    () => verify(noncanonicalTime),
    /must be a canonical UTC timestamp/u);
});
