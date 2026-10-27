#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {TextDecoder} from 'node:util';
import {fileURLToPath, pathToFileURL} from 'node:url';

const RELEASE_MANIFEST = 'release-manifest.json';
const PUBLICATION_AUTHORIZATION = 'publication-authorization.json';
const RECEIPT_CLASSIFICATION =
  'routesphere-bonvoyage-oss-release-gate-receipt';
const PUBLICATION_REVIEW_CLASSIFICATION =
  'routesphere-bonvoyage-oss-publication-review-statement';
const PUBLICATION_AUTHORIZATION_CLASSIFICATION =
  'routesphere-bonvoyage-oss-publication-authorization';
const RIGHTS_APPROVAL_CLASSIFICATION =
  'routesphere-bonvoyage-oss-rights-approval-record';
const MANIFEST_CLASSIFICATION =
  'routesphere-bonvoyage-oss-release-manifest';
const PUBLICATION_REVIEW_ROLES = Object.freeze([
  'architecture',
  'security',
  'documentation',
  'release',
  'legal',
]);
const MAX_CONTROL_FILE_BYTES = 8 * 1024 * 1024;
const UTF8_DECODER = new TextDecoder('utf-8', {fatal: true});
const SCRIPT_ROOT = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_CONTRACT = path.resolve(
  SCRIPT_ROOT, '..', 'packaging', 'release', 'oss-1.0-contract.json');
// Updated deliberately whenever the canonical release contract changes. The
// production CLI has no caller-selectable contract root.
const DEFAULT_CONTRACT_SHA256 =
  'feb4da3316c98bf81018804be6baffbdb8edd16281d93a610fcbfe6293f5be52';

function fail(message) {
  throw new Error(message);
}

function requireObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value;
}

function requireArray(value, label) {
  if (!Array.isArray(value)) {
    fail(`${label} must be an array`);
  }
  return value;
}

function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    fail(`${label} must be a nonempty string`);
  }
  return value;
}

function requireInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${label} must be a nonnegative safe integer`);
  }
  return value;
}

function requireSha256(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    fail(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireDate(value, label) {
  requireString(value, label);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    fail(`${label} must be a canonical UTC timestamp`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    fail(`${label} must be a valid canonical UTC timestamp`);
  }
  return parsed;
}

function requireReviewerIdentity(value, label) {
  requireString(value, label);
  if (value.length > 256 || /[\u0000-\u001f\u007f]/u.test(value) ||
      value !== value.trim() || value !== value.normalize('NFKC') ||
      !/^[A-Za-z0-9][A-Za-z0-9._:@/+~-]*$/u.test(value)) {
    fail(`${label} must be a bounded normalized printable ASCII identity`);
  }
  return value;
}

function requireNullableSha256(value, label) {
  if (value === null) {
    return null;
  }
  return requireSha256(value, label);
}

function requireSignature(value, label) {
  requireString(value, label);
  if (!/^[A-Za-z0-9+/]{86}==$/u.test(value)) {
    fail(`${label} must be one base64-encoded Ed25519 signature`);
  }
  const signature = Buffer.from(value, 'base64');
  if (signature.length !== 64 || signature.toString('base64') !== value) {
    fail(`${label} must be one canonical base64-encoded Ed25519 signature`);
  }
  return signature;
}

function assertExactObjectKeys(value, expectedKeys, label) {
  assertExactSet(Object.keys(value), expectedKeys, `${label} fields`);
}

function parseCanonicalJson(content, label) {
  let value;
  let text;
  try {
    text = UTF8_DECODER.decode(content);
    value = JSON.parse(text);
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
  requireObject(value, label);
  const canonical = `${JSON.stringify(value, null, 2)}\n`;
  if (text !== canonical) {
    fail(`${label} must use the canonical JSON encoding`);
  }
  return value;
}

function sha256Bytes(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function snapshotRegularFile(filePath, label) {
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
    const before = fs.fstatSync(descriptor);
    if (!before.isFile()) {
      fail(`${label} must be a regular file`);
    }
    if (before.nlink !== 1) {
      fail(`${label} must not be a hard link`);
    }
    const hash = crypto.createHash('sha256');
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    let retainedChunks = before.size <= MAX_CONTROL_FILE_BYTES ? [] : null;
    let bytes = 0;
    while (true) {
      const bytesRead = fs.readSync(
        descriptor, chunk, 0, chunk.length, null);
      if (bytesRead === 0) {
        break;
      }
      const slice = chunk.subarray(0, bytesRead);
      hash.update(slice);
      bytes += bytesRead;
      if (retainedChunks !== null) {
        if (bytes > MAX_CONTROL_FILE_BYTES) {
          retainedChunks = null;
        } else {
          retainedChunks.push(Buffer.from(slice));
        }
      }
    }
    const after = fs.fstatSync(descriptor);
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs ||
        before.ctimeMs !== after.ctimeMs || bytes !== after.size) {
      fail(`${label} changed while it was being read`);
    }
    const content = retainedChunks === null
      ? null
      : Buffer.concat(retainedChunks, bytes);
    return {
      absolutePath: filePath,
      bytes,
      sha256: hash.digest('hex'),
      content,
    };
  } catch (error) {
    if (error.message.startsWith(label)) {
      throw error;
    }
    fail(`${label} could not be read safely: ${error.message}`);
  } finally {
    if (descriptor !== undefined) {
      fs.closeSync(descriptor);
    }
  }
}

function parseJsonRecord(record, label) {
  if (!record.content) {
    fail(`${label} exceeds the ${MAX_CONTROL_FILE_BYTES}-byte control-file limit`);
  }
  return parseCanonicalJson(record.content, label);
}

function validateRelativePath(value, label) {
  requireString(value, label);
  if (value.includes('\\') || value.includes('\0') || path.posix.isAbsolute(value)) {
    fail(`${label} must be a safe POSIX-relative path`);
  }
  if (value === '.' || value.startsWith('./') || path.posix.normalize(value) !== value) {
    fail(`${label} must be normalized without dot segments`);
  }
  if (value.split('/').some((part) => part.length === 0 || part === '..')) {
    fail(`${label} must not contain empty or parent segments`);
  }
  return value;
}

function walkBundle(root) {
  const files = new Map();
  const emptyDirectories = [];

  function walk(absoluteDirectory, relativeDirectory) {
    const entries = fs.readdirSync(absoluteDirectory, {withFileTypes: true});
    if (entries.length === 0 && relativeDirectory !== '') {
      emptyDirectories.push(relativeDirectory);
    }

    for (const entry of entries) {
      const relativePath = relativeDirectory === ''
        ? entry.name
        : `${relativeDirectory}/${entry.name}`;
      validateRelativePath(relativePath, `bundle path ${JSON.stringify(relativePath)}`);
      const absolutePath = path.join(absoluteDirectory, entry.name);
      const stat = fs.lstatSync(absolutePath);
      if (stat.isSymbolicLink()) {
        fail(`bundle path ${relativePath} must not be a symbolic link`);
      }
      if (stat.isDirectory()) {
        walk(absolutePath, relativePath);
        continue;
      }
      if (!stat.isFile()) {
        fail(`bundle path ${relativePath} must be a regular file or directory`);
      }
      files.set(
        relativePath,
        snapshotRegularFile(absolutePath, `bundle path ${relativePath}`));
    }
  }

  walk(root, '');
  if (emptyDirectories.length > 0) {
    fail(`bundle contains unbound empty directories: ${emptyDirectories.sort().join(', ')}`);
  }
  return files;
}

function assertTreeStable(root, expectedFiles, label) {
  const observed = walkBundle(root);
  assertExactSet(observed.keys(), expectedFiles.keys(), `${label} stable paths`);
  for (const [relativePath, expected] of expectedFiles) {
    const actual = observed.get(relativePath);
    if (actual.bytes !== expected.bytes || actual.sha256 !== expected.sha256) {
      fail(`${label} path ${relativePath} changed during verification`);
    }
  }
}

function uniqueStrings(values, label) {
  const result = requireArray(values, label).map((value, index) =>
    requireString(value, `${label}[${index}]`));
  if (new Set(result).size !== result.length) {
    fail(`${label} must not contain duplicates`);
  }
  return result;
}

function assertExactSet(actualValues, expectedValues, label) {
  const actual = [...actualValues].sort();
  const expected = [...expectedValues].sort();
  if (actual.length !== expected.length ||
      actual.some((value, index) => value !== expected[index])) {
    fail(`${label} must be exactly [${expected.join(', ')}], got [${actual.join(', ')}]`);
  }
}

function validateContract(contract) {
  assertExactObjectKeys(contract, [
    'schema_version',
    'classification',
    'product',
    'source_repository',
    'platforms',
    'artifacts',
    'global_gates',
    'artifact_gates',
    'publication_review_roles',
    'publication_authorization',
    'requirements',
  ], 'release contract');
  if (contract.schema_version !== 2 ||
      contract.classification !== 'routesphere-bonvoyage-oss-release-contract') {
    fail('release contract schema or classification is unsupported');
  }
  requireString(contract.product, 'contract.product');
  requireString(contract.source_repository, 'contract.source_repository');
  const platforms = uniqueStrings(contract.platforms, 'contract.platforms');
  if (platforms.length === 0) {
    fail('contract.platforms must not be empty');
  }

  const artifacts = requireArray(contract.artifacts, 'contract.artifacts');
  if (artifacts.length === 0) {
    fail('contract.artifacts must not be empty');
  }
  const artifactIds = new Set();
  for (const [index, value] of artifacts.entries()) {
    const artifact = requireObject(value, `contract.artifacts[${index}]`);
    const id = requireString(artifact.id, `contract.artifacts[${index}].id`);
    requireString(artifact.kind, `contract.artifacts[${index}].kind`);
    const platform = requireString(
      artifact.platform, `contract.artifacts[${index}].platform`);
    if (artifactIds.has(id)) {
      fail(`contract artifact id ${id} is duplicated`);
    }
    if (!platforms.includes(platform)) {
      fail(`contract artifact ${id} uses undeclared platform ${platform}`);
    }
    artifactIds.add(id);
  }

  const globalGates = uniqueStrings(contract.global_gates, 'contract.global_gates');
  const artifactGates = uniqueStrings(
    contract.artifact_gates, 'contract.artifact_gates');
  if (globalGates.length === 0 || artifactGates.length === 0) {
    fail('contract gate sets must not be empty');
  }
  const publicationReviewRoles = uniqueStrings(
    contract.publication_review_roles, 'contract.publication_review_roles');
  assertExactSet(
    publicationReviewRoles,
    PUBLICATION_REVIEW_ROLES,
    'contract.publication_review_roles');

  const publicationAuthorization = requireObject(
    contract.publication_authorization,
    'contract.publication_authorization');
  assertExactObjectKeys(publicationAuthorization, [
    'status',
    'authorization_classification',
    'review_statement_classification',
    'rights_record_classification',
    'maximum_review_age_hours',
    'maximum_authorization_lifetime_hours',
    'minimum_distinct_reviewers',
    'legal_role',
    'legal_gate_ids',
    'role_signers',
  ], 'contract.publication_authorization');
  if (!['pending-identity-activation', 'active'].includes(
      publicationAuthorization.status)) {
    fail('contract publication authorization status is unsupported');
  }
  if (publicationAuthorization.authorization_classification !==
      PUBLICATION_AUTHORIZATION_CLASSIFICATION ||
      publicationAuthorization.review_statement_classification !==
      PUBLICATION_REVIEW_CLASSIFICATION ||
      publicationAuthorization.rights_record_classification !==
      RIGHTS_APPROVAL_CLASSIFICATION) {
    fail('contract publication authorization classifications are unsupported');
  }
  const maximumReviewAgeHours = requireInteger(
    publicationAuthorization.maximum_review_age_hours,
    'contract.publication_authorization.maximum_review_age_hours');
  if (maximumReviewAgeHours === 0) {
    fail('contract publication review age must be greater than zero');
  }
  const maximumAuthorizationLifetimeHours = requireInteger(
    publicationAuthorization.maximum_authorization_lifetime_hours,
    'contract.publication_authorization.maximum_authorization_lifetime_hours');
  if (maximumAuthorizationLifetimeHours === 0) {
    fail('contract publication authorization lifetime must be greater than zero');
  }
  const minimumDistinctReviewers = requireInteger(
    publicationAuthorization.minimum_distinct_reviewers,
    'contract.publication_authorization.minimum_distinct_reviewers');
  if (minimumDistinctReviewers < 2 ||
      minimumDistinctReviewers > publicationReviewRoles.length) {
    fail('contract publication authorization requires an invalid reviewer count');
  }
  const legalRole = requireString(
    publicationAuthorization.legal_role,
    'contract.publication_authorization.legal_role');
  if (legalRole !== 'legal' || !publicationReviewRoles.includes(legalRole)) {
    fail('contract publication authorization legal role must be legal');
  }
  const legalGateIds = uniqueStrings(
    publicationAuthorization.legal_gate_ids,
    'contract.publication_authorization.legal_gate_ids');
  if (legalGateIds.length === 0) {
    fail('contract publication authorization legal gates must not be empty');
  }
  const roleSigners = requireObject(
    publicationAuthorization.role_signers,
    'contract.publication_authorization.role_signers');
  assertExactSet(
    Object.keys(roleSigners),
    publicationReviewRoles,
    'contract.publication_authorization.role_signers roles');
  const signersByRole = new Map();
  const signerKeys = new Set();
  const signerPublicKeys = new Set();
  for (const role of publicationReviewRoles) {
    const signers = requireArray(
      roleSigners[role],
      `contract.publication_authorization.role_signers.${role}`)
      .map((value, index) => {
        const label =
          `contract.publication_authorization.role_signers.${role}[${index}]`;
        const signer = requireObject(value, label);
        assertExactObjectKeys(signer, [
          'key_id',
          'algorithm',
          'reviewer_identity',
          'public_key_pem',
          'status',
        ], label);
        const keyId = requireString(signer.key_id, `${label}.key_id`);
        if (!/^[a-z0-9][a-z0-9._:-]{2,127}$/u.test(keyId)) {
          fail(`${label}.key_id must be a bounded lowercase identifier`);
        }
        if (signerKeys.has(keyId)) {
          fail(`contract publication signer key ${keyId} is duplicated`);
        }
        signerKeys.add(keyId);
        if (signer.algorithm !== 'ed25519' || signer.status !== 'active') {
          fail(`${label} must be an active Ed25519 signer`);
        }
        const reviewerIdentity = requireReviewerIdentity(
          signer.reviewer_identity, `${label}.reviewer_identity`);
        const publicKeyPem = requireString(
          signer.public_key_pem, `${label}.public_key_pem`);
        let publicKey;
        try {
          publicKey = crypto.createPublicKey(publicKeyPem);
        } catch (error) {
          fail(`${label}.public_key_pem is invalid: ${error.message}`);
        }
        if (publicKey.asymmetricKeyType !== 'ed25519') {
          fail(`${label}.public_key_pem must contain an Ed25519 key`);
        }
        const canonicalPublicKeyPem = publicKey.export({
          type: 'spki',
          format: 'pem',
        });
        if (publicKeyPem !== canonicalPublicKeyPem) {
          fail(`${label}.public_key_pem must contain only canonical SPKI public-key PEM`);
        }
        const publicKeyFingerprint = sha256Bytes(
          publicKey.export({type: 'spki', format: 'der'}));
        if (signerPublicKeys.has(publicKeyFingerprint)) {
          fail('contract publication signer public-key material is duplicated');
        }
        signerPublicKeys.add(publicKeyFingerprint);
        return {keyId, reviewerIdentity, publicKey};
      });
    if (publicationAuthorization.status === 'active' && signers.length === 0) {
      fail(`active publication policy has no signer for ${role}`);
    }
    if (publicationAuthorization.status !== 'active' && signers.length !== 0) {
      fail('pending publication policy must not contain active signers');
    }
    signersByRole.set(role, signers);
  }

  const requirements = requireObject(contract.requirements, 'contract.requirements');
  assertExactObjectKeys(requirements, [
    'independent_builds',
    'slsa_build_level',
    'sbom_formats',
    'signature_mode',
    'signature_issuer',
    'signature_subject_prefix',
    'maximum_vulnerability_database_age_hours',
    'maximum_unreviewed_findings',
    'maximum_unresolved_blocking_findings',
    'publication_default',
  ], 'contract.requirements');
  if (requireInteger(requirements.independent_builds,
      'contract.requirements.independent_builds') < 2) {
    fail('contract requires at least two independent builds');
  }
  if (requireInteger(requirements.slsa_build_level,
      'contract.requirements.slsa_build_level') < 2) {
    fail('contract requires SLSA Build Level 2 or stronger');
  }
  const sbomFormats = uniqueStrings(
    requirements.sbom_formats, 'contract.requirements.sbom_formats');
  if (sbomFormats.length !== 2) {
    fail('contract must require exactly two SBOM formats');
  }
  requireString(requirements.signature_mode, 'contract.requirements.signature_mode');
  requireString(requirements.signature_issuer, 'contract.requirements.signature_issuer');
  requireString(
    requirements.signature_subject_prefix,
    'contract.requirements.signature_subject_prefix');
  requireInteger(
    requirements.maximum_vulnerability_database_age_hours,
    'contract.requirements.maximum_vulnerability_database_age_hours');
  requireInteger(
    requirements.maximum_unreviewed_findings,
    'contract.requirements.maximum_unreviewed_findings');
  requireInteger(
    requirements.maximum_unresolved_blocking_findings,
    'contract.requirements.maximum_unresolved_blocking_findings');
  if (requirements.publication_default !== false) {
    fail('contract publication_default must remain false');
  }

  return {
    artifacts,
    globalGates,
    artifactGates,
    publicationReviewRoles,
    publicationAuthorization: {
      status: publicationAuthorization.status,
      maximumReviewAgeHours,
      maximumAuthorizationLifetimeHours,
      minimumDistinctReviewers,
      legalRole,
      legalGateIds,
      signersByRole,
    },
    requirements,
    sbomFormats,
  };
}

function buildInventory(manifest, actualFiles) {
  const records = new Map();
  for (const [index, value] of requireArray(manifest.files, 'manifest.files').entries()) {
    const record = requireObject(value, `manifest.files[${index}]`);
    const relativePath = validateRelativePath(
      record.path, `manifest.files[${index}].path`);
    if (relativePath === RELEASE_MANIFEST) {
      fail(`${RELEASE_MANIFEST} must not include itself in manifest.files`);
    }
    if (records.has(relativePath)) {
      fail(`manifest.files contains duplicate path ${relativePath}`);
    }
    requireInteger(record.bytes, `manifest.files[${index}].bytes`);
    requireSha256(record.sha256, `manifest.files[${index}].sha256`);
    records.set(relativePath, record);
  }

  const actualPaths = [...actualFiles.keys()]
    .filter((value) => value !== RELEASE_MANIFEST)
    .sort();
  assertExactSet(records.keys(), actualPaths, 'manifest.files paths');
  for (const [relativePath, record] of records) {
    const actual = actualFiles.get(relativePath);
    if (record.bytes !== actual.bytes) {
      fail(`inventory byte count mismatch for ${relativePath}`);
    }
    if (record.sha256 !== actual.sha256) {
      fail(`inventory SHA-256 mismatch for ${relativePath}`);
    }
    records.set(relativePath, {
      ...record,
      absolutePath: actual.absolutePath,
      content: actual.content,
    });
  }
  return records;
}

function verifyReceiptSet({
  refs,
  expectedGates,
  label,
  inventory,
  boundPaths,
  sourceCommit,
  artifactId = null,
  artifactSha256 = null,
}) {
  const references = requireArray(refs, label).map((value, index) => {
    const ref = requireObject(value, `${label}[${index}]`);
    const gate = requireString(ref.gate, `${label}[${index}].gate`);
    const receiptPath = validateRelativePath(ref.path, `${label}[${index}].path`);
    const receiptSha256 = requireSha256(
      ref.sha256, `${label}[${index}].sha256`);
    return {gate, path: receiptPath, sha256: receiptSha256};
  });
  assertExactSet(references.map((value) => value.gate), expectedGates, `${label} gates`);
  if (new Set(references.map((value) => value.path)).size !== references.length) {
    fail(`${label} receipt paths must be unique`);
  }

  for (const reference of references) {
    const inventoryRecord = inventory.get(reference.path);
    if (!inventoryRecord) {
      fail(`${label} receipt ${reference.path} is absent from manifest.files`);
    }
    if (inventoryRecord.sha256 !== reference.sha256) {
      fail(`${label} receipt ${reference.path} has a conflicting SHA-256`);
    }
    boundPaths.add(reference.path);
    const receipt = parseJsonRecord(
      inventoryRecord, `${label} receipt ${reference.path}`);
    if (receipt.schema_version !== 1 ||
        receipt.classification !== RECEIPT_CLASSIFICATION) {
      fail(`${label} receipt ${reference.path} has an unsupported schema or classification`);
    }
    if (receipt.gate !== reference.gate || receipt.status !== 'PASS') {
      fail(`${label} receipt ${reference.path} does not record PASS for ${reference.gate}`);
    }
    if (receipt.source_commit !== sourceCommit) {
      fail(`${label} receipt ${reference.path} is not bound to source ${sourceCommit}`);
    }
    if (receipt.artifact_id !== artifactId ||
        receipt.artifact_sha256 !== artifactSha256) {
      fail(`${label} receipt ${reference.path} has the wrong artifact binding`);
    }

    const evidence = requireArray(
      receipt.evidence, `${label} receipt ${reference.path}.evidence`);
    if (evidence.length === 0) {
      fail(`${label} receipt ${reference.path} must bind at least one evidence file`);
    }
    for (const [index, value] of evidence.entries()) {
      const item = requireObject(
        value, `${label} receipt ${reference.path}.evidence[${index}]`);
      const evidencePath = validateRelativePath(
        item.path, `${label} receipt ${reference.path}.evidence[${index}].path`);
      const evidenceSha = requireSha256(
        item.sha256, `${label} receipt ${reference.path}.evidence[${index}].sha256`);
      if (evidencePath === reference.path || evidencePath === RELEASE_MANIFEST) {
        fail(`${label} receipt ${reference.path} has a recursive evidence reference`);
      }
      const evidenceRecord = inventory.get(evidencePath);
      if (!evidenceRecord || evidenceRecord.sha256 !== evidenceSha) {
        fail(`${label} receipt ${reference.path} evidence ${evidencePath} is missing or changed`);
      }
      boundPaths.add(evidencePath);
    }
  }
}

function buildAuthorizationInventory(authorization, actualFiles) {
  const records = new Map();
  for (const [index, value] of requireArray(
      authorization.files, 'authorization.files').entries()) {
    const label = `authorization.files[${index}]`;
    const record = requireObject(value, label);
    assertExactObjectKeys(record, ['path', 'bytes', 'sha256'], label);
    const relativePath = validateRelativePath(record.path, `${label}.path`);
    if (relativePath === PUBLICATION_AUTHORIZATION) {
      fail(`${PUBLICATION_AUTHORIZATION} must not include itself in authorization.files`);
    }
    if (records.has(relativePath)) {
      fail(`authorization.files contains duplicate path ${relativePath}`);
    }
    requireInteger(record.bytes, `${label}.bytes`);
    requireSha256(record.sha256, `${label}.sha256`);
    records.set(relativePath, record);
  }

  const actualPaths = [...actualFiles.keys()]
    .filter((value) => value !== PUBLICATION_AUTHORIZATION)
    .sort();
  assertExactSet(records.keys(), actualPaths, 'authorization.files paths');
  for (const [relativePath, record] of records) {
    const actual = actualFiles.get(relativePath);
    if (record.bytes !== actual.bytes || record.sha256 !== actual.sha256) {
      fail(`authorization inventory mismatch for ${relativePath}`);
    }
    records.set(relativePath, {
      ...record,
      absolutePath: actual.absolutePath,
      content: actual.content,
    });
  }
  return records;
}

function verifyRightsApprovalRecord({
  reference,
  inventory,
  boundPaths,
  manifestSha256,
  contractSha256,
  policy,
  manifestCreatedAt,
  authorizationCreatedAt,
}) {
  const bound = bindFileReference(
    reference, 'authorization.rights_record', inventory, boundPaths);
  const rights = parseJsonRecord(
    bound.record, 'authorization rights approval record');
  assertExactObjectKeys(rights, [
    'schema_version',
    'classification',
    'technical_manifest_sha256',
    'contract_sha256',
    'approved_at',
    'gates',
  ], 'authorization rights approval record');
  if (rights.schema_version !== 1 ||
      rights.classification !== RIGHTS_APPROVAL_CLASSIFICATION) {
    fail('authorization rights approval record schema or classification is unsupported');
  }
  if (rights.technical_manifest_sha256 !== manifestSha256 ||
      rights.contract_sha256 !== contractSha256) {
    fail('authorization rights approval record is not bound to the technical candidate');
  }
  const approvedAt = requireDate(
    rights.approved_at, 'authorization rights approval record.approved_at');
  if (approvedAt < manifestCreatedAt || approvedAt > authorizationCreatedAt) {
    fail('authorization rights approval record timestamp is outside the review window');
  }
  const gates = requireArray(
    rights.gates, 'authorization rights approval record.gates');
  const gateIds = [];
  for (const [index, value] of gates.entries()) {
    const label = `authorization rights approval record.gates[${index}]`;
    const gate = requireObject(value, label);
    assertExactObjectKeys(gate, ['id', 'status', 'evidence'], label);
    const gateId = requireString(gate.id, `${label}.id`);
    gateIds.push(gateId);
    if (gate.status !== 'APPROVED') {
      fail(`${label} must record APPROVED`);
    }
    const evidence = requireArray(gate.evidence, `${label}.evidence`);
    if (evidence.length === 0) {
      fail(`${label} must bind at least one retained evidence record`);
    }
    const evidencePaths = new Set();
    for (const [evidenceIndex, evidenceValue] of evidence.entries()) {
      const evidenceLabel = `${label}.evidence[${evidenceIndex}]`;
      const item = requireObject(evidenceValue, evidenceLabel);
      assertExactObjectKeys(item, ['path', 'sha256'], evidenceLabel);
      const evidencePath = validateRelativePath(
        item.path, `${evidenceLabel}.path`);
      const evidenceSha = requireSha256(item.sha256, `${evidenceLabel}.sha256`);
      if (evidencePaths.has(evidencePath)) {
        fail(`${label} contains duplicate evidence path ${evidencePath}`);
      }
      evidencePaths.add(evidencePath);
      if (evidencePath === bound.relativePath ||
          evidencePath === PUBLICATION_AUTHORIZATION) {
        fail(`${label} contains recursive rights evidence`);
      }
      const evidenceRecord = inventory.get(evidencePath);
      if (!evidenceRecord || evidenceRecord.sha256 !== evidenceSha) {
        fail(`${label} evidence ${evidencePath} is missing or changed`);
      }
      boundPaths.add(evidencePath);
    }
  }
  assertExactSet(gateIds, policy.legalGateIds, 'rights approval gate ids');
  return bound.sha256;
}

function verifyPublicationAuthorization({
  authorizationPath,
  authorizationSha256,
  technicalManifestSha256,
  contractSha256,
  product,
  version,
  technicalInventory,
  manifestCreatedAt,
  verificationTime,
  policy,
}) {
  if (policy.status !== 'active') {
    fail('publication trust policy is not active');
  }
  const expectedAuthorizationSha = requireSha256(
    authorizationSha256, 'authorizationSha256');
  const authorizationRoot = path.resolve(authorizationPath);
  const rootStat = fs.lstatSync(authorizationRoot);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    fail('authorizationPath must be a real directory, not a symbolic link');
  }
  const actualFiles = walkBundle(authorizationRoot);
  const envelopeFile = actualFiles.get(PUBLICATION_AUTHORIZATION);
  if (!envelopeFile) {
    fail(`${PUBLICATION_AUTHORIZATION} is missing`);
  }
  if (envelopeFile.sha256 !== expectedAuthorizationSha) {
    fail(`${PUBLICATION_AUTHORIZATION} does not match --authorization-sha256`);
  }
  const authorization = parseJsonRecord(
    envelopeFile, PUBLICATION_AUTHORIZATION);
  assertExactObjectKeys(authorization, [
    'schema_version',
    'classification',
    'product',
    'version',
    'created_at',
    'expires_at',
    'technical_manifest_sha256',
    'contract_sha256',
    'rights_record',
    'reviews',
    'files',
  ], PUBLICATION_AUTHORIZATION);
  if (authorization.schema_version !== 1 ||
      authorization.classification !== PUBLICATION_AUTHORIZATION_CLASSIFICATION) {
    fail('publication authorization schema or classification is unsupported');
  }
  if (authorization.product !== product || authorization.version !== version ||
      authorization.technical_manifest_sha256 !== technicalManifestSha256 ||
      authorization.contract_sha256 !== contractSha256) {
    fail('publication authorization is not bound to the exact technical candidate');
  }
  const authorizationCreatedAt = requireDate(
    authorization.created_at, 'authorization.created_at');
  const authorizationExpiresAt = requireDate(
    authorization.expires_at, 'authorization.expires_at');
  if (authorizationCreatedAt < manifestCreatedAt) {
    fail('publication authorization predates the technical manifest');
  }
  const authorizationLifetimeHours =
    (authorizationExpiresAt - authorizationCreatedAt) / (60 * 60 * 1000);
  if (authorizationLifetimeHours <= 0 ||
      authorizationLifetimeHours > policy.maximumAuthorizationLifetimeHours) {
    fail('publication authorization has an invalid lifetime');
  }
  if (verificationTime < authorizationCreatedAt ||
      verificationTime > authorizationExpiresAt) {
    fail('publication authorization is not currently valid');
  }
  const inventory = buildAuthorizationInventory(authorization, actualFiles);
  const boundPaths = new Set();
  const rightsRecordSha256 = verifyRightsApprovalRecord({
    reference: authorization.rights_record,
    inventory,
    boundPaths,
    manifestSha256: technicalManifestSha256,
    contractSha256,
    policy,
    manifestCreatedAt,
    authorizationCreatedAt,
  });

  const label = 'authorization.reviews';
  const reviews = requireArray(authorization.reviews, label).map((value, index) => {
    const reviewLabel = `${label}[${index}]`;
    const review = requireObject(value, reviewLabel);
    assertExactObjectKeys(review, [
      'role',
      'path',
      'sha256',
      'signature_path',
      'signature_sha256',
      'signer_key_id',
    ], reviewLabel);
    return {
      role: requireString(review.role, `${reviewLabel}.role`),
      path: validateRelativePath(review.path, `${reviewLabel}.path`),
      sha256: requireSha256(review.sha256, `${reviewLabel}.sha256`),
      signaturePath: validateRelativePath(
        review.signature_path, `${reviewLabel}.signature_path`),
      signatureSha256: requireSha256(
        review.signature_sha256, `${reviewLabel}.signature_sha256`),
      signerKeyId: requireString(
        review.signer_key_id, `${reviewLabel}.signer_key_id`),
    };
  });
  assertExactSet(
    reviews.map((value) => value.role),
    PUBLICATION_REVIEW_ROLES,
    'authorization review roles');
  const referencedPaths = reviews.flatMap((value) => [value.path, value.signaturePath]);
  if (new Set(referencedPaths).size !== referencedPaths.length) {
    fail('authorization review and signature paths must be unique');
  }

  const reviewerIdentities = new Set();
  for (const review of reviews) {
    const reviewLabel = `authorization review ${review.role}`;
    const reviewRef = bindFileReference({
      path: review.path,
      sha256: review.sha256,
    }, reviewLabel, inventory, boundPaths);
    const signatureRef = bindFileReference({
      path: review.signaturePath,
      sha256: review.signatureSha256,
    }, `${reviewLabel} signature`, inventory, boundPaths);
    const statement = parseJsonRecord(reviewRef.record, reviewLabel);
    assertExactObjectKeys(statement, [
      'schema_version',
      'classification',
      'role',
      'status',
      'signer_key_id',
      'reviewer_identity',
      'approved_at',
      'authorization_created_at',
      'authorization_expires_at',
      'technical_manifest_sha256',
      'contract_sha256',
      'rights_record_sha256',
      'evidence',
    ], reviewLabel);
    if (statement.schema_version !== 1 ||
        statement.classification !== PUBLICATION_REVIEW_CLASSIFICATION ||
        statement.role !== review.role || statement.status !== 'APPROVED' ||
        statement.signer_key_id !== review.signerKeyId) {
      fail(`${reviewLabel} does not contain the required signed approval`);
    }
    const signers = policy.signersByRole.get(review.role) ?? [];
    const signer = signers.find((value) => value.keyId === review.signerKeyId);
    if (!signer) {
      fail(`${reviewLabel} uses an unauthorized signing key`);
    }
    const reviewerIdentity = requireReviewerIdentity(
      statement.reviewer_identity, `${reviewLabel}.reviewer_identity`);
    if (reviewerIdentity !== signer.reviewerIdentity) {
      fail(`${reviewLabel} reviewer identity does not match the trusted signer`);
    }
    reviewerIdentities.add(reviewerIdentity);
    const approvedAt = requireDate(statement.approved_at, `${reviewLabel}.approved_at`);
    const signedAuthorizationCreatedAt = requireDate(
      statement.authorization_created_at,
      `${reviewLabel}.authorization_created_at`);
    if (signedAuthorizationCreatedAt !== authorizationCreatedAt) {
      fail(`${reviewLabel} does not bind the authorization creation time`);
    }
    const signedAuthorizationExpiresAt = requireDate(
      statement.authorization_expires_at,
      `${reviewLabel}.authorization_expires_at`);
    if (signedAuthorizationExpiresAt !== authorizationExpiresAt) {
      fail(`${reviewLabel} does not bind the authorization expiry time`);
    }
    const approvalAgeHours =
      (authorizationCreatedAt - approvedAt) / (60 * 60 * 1000);
    if (approvedAt < manifestCreatedAt || approvedAt > authorizationCreatedAt ||
        approvalAgeHours > policy.maximumReviewAgeHours) {
      fail(`${reviewLabel} timestamp is stale or outside the review window`);
    }
    if (statement.technical_manifest_sha256 !== technicalManifestSha256 ||
        statement.contract_sha256 !== contractSha256) {
      fail(`${reviewLabel} is not bound to the exact technical candidate`);
    }
    const statementRightsSha = requireNullableSha256(
      statement.rights_record_sha256, `${reviewLabel}.rights_record_sha256`);
    if (review.role === policy.legalRole) {
      if (statementRightsSha !== rightsRecordSha256) {
        fail(`${reviewLabel} is not bound to the approved rights record`);
      }
    } else if (statementRightsSha !== null) {
      fail(`${reviewLabel} must not assert the legal rights record`);
    }

    const evidence = requireArray(statement.evidence, `${reviewLabel}.evidence`);
    if (evidence.length === 0) {
      fail(`${reviewLabel} must bind at least one technical evidence file`);
    }
    const evidencePaths = new Set();
    for (const [index, value] of evidence.entries()) {
      const evidenceLabel = `${reviewLabel}.evidence[${index}]`;
      const item = requireObject(value, evidenceLabel);
      assertExactObjectKeys(item, ['path', 'sha256'], evidenceLabel);
      const evidencePath = validateRelativePath(item.path, `${evidenceLabel}.path`);
      const evidenceSha = requireSha256(item.sha256, `${evidenceLabel}.sha256`);
      if (evidencePaths.has(evidencePath)) {
        fail(`${reviewLabel} contains duplicate evidence path ${evidencePath}`);
      }
      evidencePaths.add(evidencePath);
      const evidenceRecord = technicalInventory.get(evidencePath);
      if (!evidenceRecord || evidenceRecord.sha256 !== evidenceSha) {
        fail(`${reviewLabel} technical evidence ${evidencePath} is missing or changed`);
      }
    }

    if (!signatureRef.record.content) {
      fail(`${reviewLabel} signature exceeds the control-file limit`);
    }
    let signatureFile;
    try {
      signatureFile = UTF8_DECODER.decode(signatureRef.record.content);
    } catch (error) {
      fail(`${reviewLabel} signature is not UTF-8: ${error.message}`);
    }
    if (!signatureFile.endsWith('\n') || signatureFile.includes('\r') ||
        signatureFile.slice(0, -1).includes('\n')) {
      fail(`${reviewLabel} signature file must contain one canonical line`);
    }
    const signature = requireSignature(
      signatureFile.slice(0, -1), `${reviewLabel} signature`);
    const statementBytes = reviewRef.record.content;
    if (!crypto.verify(null, statementBytes, signer.publicKey, signature)) {
      fail(`${reviewLabel} signature verification failed`);
    }
  }

  if (reviewerIdentities.size < policy.minimumDistinctReviewers) {
    fail(`publication authorization requires at least ${policy.minimumDistinctReviewers} distinct reviewers`);
  }
  const unbound = [...inventory.keys()]
    .filter((relativePath) => !boundPaths.has(relativePath))
    .sort();
  if (unbound.length > 0) {
    fail(`authorization.files contains unbound files: ${unbound.join(', ')}`);
  }
  assertTreeStable(authorizationRoot, actualFiles, 'authorization package');
  return {
    authorizationSha256: expectedAuthorizationSha,
    reviewers: reviewerIdentities.size,
  };
}

function bindFileReference(reference, label, inventory, boundPaths, {bytes = false} = {}) {
  const value = requireObject(reference, label);
  const relativePath = validateRelativePath(value.path, `${label}.path`);
  const sha256 = requireSha256(value.sha256, `${label}.sha256`);
  const record = inventory.get(relativePath);
  if (!record) {
    fail(`${label} path ${relativePath} is absent from manifest.files`);
  }
  if (record.sha256 !== sha256) {
    fail(`${label} path ${relativePath} has a conflicting SHA-256`);
  }
  if (bytes) {
    requireInteger(value.bytes, `${label}.bytes`);
    if (record.bytes !== value.bytes) {
      fail(`${label} path ${relativePath} has a conflicting byte count`);
    }
  }
  boundPaths.add(relativePath);
  return {value, relativePath, sha256, record};
}

function verifyReleaseBundleWithTrustRoot({
  bundlePath,
  manifestSha256,
  contractPath = DEFAULT_CONTRACT,
  trustedContractSha256 = DEFAULT_CONTRACT_SHA256,
  allowUnpinnedContractForTests = false,
  authorizationPath = null,
  authorizationSha256 = null,
  verificationTime = Date.now(),
  requirePublishable = false,
}) {
  requireString(bundlePath, 'bundlePath');
  const expectedManifestSha = requireSha256(
    manifestSha256, 'manifestSha256');
  const checkedVerificationTime = requireInteger(
    verificationTime, 'verificationTime');
  const bundleRoot = path.resolve(bundlePath);
  const rootStat = fs.lstatSync(bundleRoot);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    fail('bundlePath must be a real directory, not a symbolic link');
  }

  const actualFiles = walkBundle(bundleRoot);
  const manifestFile = actualFiles.get(RELEASE_MANIFEST);
  if (!manifestFile) {
    fail(`${RELEASE_MANIFEST} is missing`);
  }
  if (manifestFile.sha256 !== expectedManifestSha) {
    fail(`${RELEASE_MANIFEST} does not match --manifest-sha256`);
  }

  const resolvedContractPath = path.resolve(contractPath);
  if (!allowUnpinnedContractForTests && resolvedContractPath !== DEFAULT_CONTRACT) {
    fail('production verification uses the pinned canonical release contract');
  }
  const contractFile = snapshotRegularFile(
    resolvedContractPath, 'release contract');
  const contract = parseJsonRecord(contractFile, 'release contract');
  const contractInfo = validateContract(contract);
  const contractSha = contractFile.sha256;
  if (contractSha !== requireSha256(
      trustedContractSha256, 'trustedContractSha256')) {
    fail('release contract does not match the pinned trust root');
  }
  const manifest = parseJsonRecord(manifestFile, RELEASE_MANIFEST);
  assertExactObjectKeys(manifest, [
    'schema_version',
    'classification',
    'product',
    'version',
    'created_at',
    'contract',
    'source',
    'hosted_build',
    'global_receipts',
    'artifacts',
    'files',
  ], RELEASE_MANIFEST);
  if (manifest.schema_version !== 2 ||
      manifest.classification !== MANIFEST_CLASSIFICATION) {
    fail('release manifest schema or classification is unsupported');
  }
  if (manifest.product !== contract.product) {
    fail('release manifest product does not match the release contract');
  }
  const version = requireString(manifest.version, 'manifest.version');
  if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)) {
    fail('manifest.version must be a semantic version without a leading v');
  }
  const createdAt = requireDate(manifest.created_at, 'manifest.created_at');
  const inventory = buildInventory(manifest, actualFiles);
  const boundPaths = new Set();

  const embeddedContract = bindFileReference(
    manifest.contract, 'manifest.contract', inventory, boundPaths);
  if (embeddedContract.sha256 !== contractSha) {
    fail('embedded release contract does not match the verifier contract');
  }

  const source = requireObject(manifest.source, 'manifest.source');
  if (source.repository !== contract.source_repository) {
    fail('manifest.source.repository does not match the release contract');
  }
  const sourceCommit = requireString(source.commit, 'manifest.source.commit');
  if (!/^[0-9a-f]{40}$/.test(sourceCommit)) {
    fail('manifest.source.commit must be a lowercase 40-character Git commit');
  }
  if (source.tag !== `v${version}`) {
    fail(`manifest.source.tag must be v${version}`);
  }
  if (source.clean !== true || source.pushed !== true) {
    fail('release source must be clean and pushed');
  }

  const hostedBuild = requireObject(manifest.hosted_build, 'manifest.hosted_build');
  if (hostedBuild.hosted !== true || hostedBuild.provider !== 'github-actions') {
    fail('release build must be hosted by GitHub Actions');
  }
  requireString(hostedBuild.run_id, 'manifest.hosted_build.run_id');
  const expectedWorkflow =
    `${contractInfo.requirements.signature_subject_prefix}${source.tag}`;
  if (hostedBuild.workflow_identity !== expectedWorkflow) {
    fail('hosted build workflow identity does not match the tagged release workflow');
  }
  if (requireInteger(hostedBuild.slsa_build_level,
      'manifest.hosted_build.slsa_build_level') <
      contractInfo.requirements.slsa_build_level) {
    fail('hosted build does not meet the required SLSA build level');
  }

  verifyReceiptSet({
    refs: manifest.global_receipts,
    expectedGates: contractInfo.globalGates,
    label: 'manifest.global_receipts',
    inventory,
    boundPaths,
    sourceCommit,
  });

  const artifactRecords = requireArray(manifest.artifacts, 'manifest.artifacts');
  const artifactsById = new Map();
  for (const [index, value] of artifactRecords.entries()) {
    const artifact = requireObject(value, `manifest.artifacts[${index}]`);
    const id = requireString(artifact.id, `manifest.artifacts[${index}].id`);
    if (artifactsById.has(id)) {
      fail(`manifest artifact id ${id} is duplicated`);
    }
    artifactsById.set(id, artifact);
  }
  assertExactSet(
    artifactsById.keys(),
    contractInfo.artifacts.map((artifact) => artifact.id),
    'manifest artifact ids');

  for (const contractArtifact of contractInfo.artifacts) {
    const artifact = artifactsById.get(contractArtifact.id);
    const label = `artifact ${contractArtifact.id}`;
    if (artifact.kind !== contractArtifact.kind ||
        artifact.platform !== contractArtifact.platform) {
      fail(`${label} kind or platform does not match the release contract`);
    }
    const payload = bindFileReference(artifact, label, inventory, boundPaths, {bytes: true});
    const reproducibility = requireObject(
      artifact.reproducibility, `${label}.reproducibility`);
    if (reproducibility.byte_identical !== true) {
      fail(`${label} independent builds are not byte-identical`);
    }
    const builds = requireArray(reproducibility.builds, `${label}.reproducibility.builds`);
    if (builds.length < contractInfo.requirements.independent_builds) {
      fail(`${label} has fewer than ${contractInfo.requirements.independent_builds} independent builds`);
    }
    const builders = new Set();
    for (const [index, value] of builds.entries()) {
      const build = requireObject(value, `${label}.reproducibility.builds[${index}]`);
      const builder = requireString(
        build.builder, `${label}.reproducibility.builds[${index}].builder`);
      if (builders.has(builder)) {
        fail(`${label} reproducibility builders must be independent`);
      }
      builders.add(builder);
      if (build.artifact_sha256 !== payload.sha256) {
        fail(`${label} reproducibility build ${builder} has a different artifact digest`);
      }
    }

    const sboms = requireArray(artifact.sboms, `${label}.sboms`);
    assertExactSet(
      sboms.map((value, index) =>
        requireString(requireObject(value, `${label}.sboms[${index}]`).format,
          `${label}.sboms[${index}].format`)),
      contractInfo.sbomFormats,
      `${label} SBOM formats`);
    for (const [index, sbom] of sboms.entries()) {
      bindFileReference(sbom, `${label}.sboms[${index}]`, inventory, boundPaths);
    }

    const vulnerability = requireObject(
      artifact.vulnerability_review, `${label}.vulnerability_review`);
    const databaseBuiltAt = requireDate(
      vulnerability.database_built_at, `${label}.vulnerability_review.database_built_at`);
    requireSha256(
      vulnerability.database_digest, `${label}.vulnerability_review.database_digest`);
    if (databaseBuiltAt > createdAt) {
      fail(`${label} vulnerability database timestamp is after manifest creation`);
    }
    const databaseAgeHours = (createdAt - databaseBuiltAt) / (60 * 60 * 1000);
    if (databaseAgeHours >
        contractInfo.requirements.maximum_vulnerability_database_age_hours) {
      fail(`${label} vulnerability database is too old`);
    }
    if (vulnerability.format_parity !== true) {
      fail(`${label} vulnerability review does not establish SBOM format parity`);
    }
    if (requireInteger(vulnerability.unreviewed_findings,
        `${label}.vulnerability_review.unreviewed_findings`) >
        contractInfo.requirements.maximum_unreviewed_findings) {
      fail(`${label} has unreviewed vulnerability findings`);
    }
    if (requireInteger(vulnerability.unresolved_blocking_findings,
        `${label}.vulnerability_review.unresolved_blocking_findings`) >
        contractInfo.requirements.maximum_unresolved_blocking_findings) {
      fail(`${label} has unresolved release-blocking vulnerability findings`);
    }

    const provenance = bindFileReference(
      artifact.provenance, `${label}.provenance`, inventory, boundPaths);
    if (requireInteger(provenance.value.slsa_build_level,
        `${label}.provenance.slsa_build_level`) <
        contractInfo.requirements.slsa_build_level ||
        provenance.value.subject_sha256 !== payload.sha256) {
      fail(`${label} provenance does not meet the required level or artifact subject`);
    }

    const signature = bindFileReference(
      artifact.signature, `${label}.signature`, inventory, boundPaths);
    if (signature.value.mode !== contractInfo.requirements.signature_mode ||
        signature.value.issuer !== contractInfo.requirements.signature_issuer ||
        signature.value.subject !== expectedWorkflow) {
      fail(`${label} signature identity does not match the protected release workflow`);
    }

    verifyReceiptSet({
      refs: artifact.receipts,
      expectedGates: contractInfo.artifactGates,
      label: `${label}.receipts`,
      inventory,
      boundPaths,
      sourceCommit,
      artifactId: contractArtifact.id,
      artifactSha256: payload.sha256,
    });
  }

  let publishable = false;
  const unbound = [...inventory.keys()]
    .filter((relativePath) => !boundPaths.has(relativePath))
    .sort();
  if (unbound.length > 0) {
    fail(`manifest.files contains unbound files: ${unbound.join(', ')}`);
  }
  const hasAuthorizationPath = authorizationPath !== null;
  const hasAuthorizationSha = authorizationSha256 !== null;
  if (hasAuthorizationPath !== hasAuthorizationSha) {
    fail('authorizationPath and authorizationSha256 must be supplied together');
  }
  let publicationAuthorizationSha256 = null;
  let publicationReviewers = 0;
  if (hasAuthorizationPath) {
    const authorization = verifyPublicationAuthorization({
      authorizationPath,
      authorizationSha256,
      technicalManifestSha256: expectedManifestSha,
      contractSha256: contractSha,
      product: manifest.product,
      version,
      technicalInventory: inventory,
      manifestCreatedAt: createdAt,
      verificationTime: checkedVerificationTime,
      policy: contractInfo.publicationAuthorization,
    });
    publicationAuthorizationSha256 = authorization.authorizationSha256;
    publicationReviewers = authorization.reviewers;
    publishable = true;
  }
  if (requirePublishable && !publishable) {
    fail('bundle passes technical admission but publication is not authorized');
  }

  assertTreeStable(bundleRoot, actualFiles, 'release bundle');
  const finalContractFile = snapshotRegularFile(
    resolvedContractPath, 'release contract');
  if (finalContractFile.bytes !== contractFile.bytes ||
      finalContractFile.sha256 !== contractFile.sha256) {
    fail('release contract changed during verification');
  }

  return {
    status: 'PASS',
    publishable,
    product: manifest.product,
    version,
    source_commit: sourceCommit,
    manifest_sha256: expectedManifestSha,
    publication_authorization_sha256: publicationAuthorizationSha256,
    publication_reviewers: publicationReviewers,
    artifacts: artifactRecords.length,
    files: inventory.size,
  };
}

function copyOwnOptions(options, allowed, label) {
  requireObject(options, label);
  const prototype = Object.getPrototypeOf(options);
  if (prototype !== Object.prototype && prototype !== null) {
    fail(`${label} must be a plain options object`);
  }
  const ownKeys = Reflect.ownKeys(options);
  const unknown = ownKeys.filter(
    (key) => typeof key !== 'string' || !allowed.includes(key));
  if (unknown.length > 0) {
    fail(`${label} contains unsupported options: ${unknown.map(String).sort().join(', ')}`);
  }
  const result = Object.create(null);
  for (const key of allowed) {
    if (Object.hasOwn(options, key)) {
      result[key] = options[key];
    }
  }
  return result;
}

export function verifyReleaseBundle(options) {
  const checked = copyOwnOptions(options, [
    'bundlePath',
    'manifestSha256',
    'authorizationPath',
    'authorizationSha256',
    'requirePublishable',
  ], 'production release verification');
  return verifyReleaseBundleWithTrustRoot(checked);
}

// This entry point exists only to exercise signature and authorization
// failures with ephemeral fixture keys. The production CLI and API above never
// call it and never accept a caller-selected trust root.
export function verifyReleaseBundleForTests(options) {
  const checked = copyOwnOptions(options, [
    'bundlePath',
    'manifestSha256',
    'contractPath',
    'trustedContractSha256',
    'authorizationPath',
    'authorizationSha256',
    'verificationTime',
    'requirePublishable',
  ], 'test release verification');
  const result = verifyReleaseBundleWithTrustRoot({
    ...checked,
    allowUnpinnedContractForTests: true,
  });
  return {
    ...result,
    status: 'TEST_ONLY_PASS',
    publishable: false,
    authorization_test_valid: result.publishable,
    test_only: true,
  };
}

function parseArguments(argv) {
  const values = {requirePublishable: false};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--require-publishable') {
      values.requirePublishable = true;
      continue;
    }
    if (![
      '--bundle',
      '--manifest-sha256',
      '--authorization',
      '--authorization-sha256',
    ].includes(argument)) {
      fail(`unknown argument ${argument}`);
    }
    if (index + 1 >= argv.length) {
      fail(`${argument} requires a value`);
    }
    const key = argument === '--bundle'
      ? 'bundlePath'
      : argument === '--manifest-sha256'
        ? 'manifestSha256'
        : argument === '--authorization'
          ? 'authorizationPath'
          : 'authorizationSha256';
    values[key] = argv[index + 1];
    index += 1;
  }
  if (!values.bundlePath || !values.manifestSha256) {
    fail('usage: verify-oss-release-bundle.mjs --bundle DIR --manifest-sha256 SHA256 [--authorization DIR --authorization-sha256 SHA256] [--require-publishable]');
  }
  return values;
}

const invokedPath = process.argv[1]
  ? pathToFileURL(path.resolve(process.argv[1])).href
  : '';
if (import.meta.url === invokedPath) {
  try {
    const result = verifyReleaseBundle(parseArguments(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`OSS release bundle verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
