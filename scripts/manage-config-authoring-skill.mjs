#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const DEFAULT_REPOSITORY_ROOT = path.resolve(path.dirname(SCRIPT_PATH), '..');
const SKILL_ID = 'bonvoyage-config-authoring';
const INSTALLATION_RECORD = '.bonvoyage-installation.json';
const MANAGER_VERSION = 'bonvoyage.configuration-skill-lifecycle.v1';
const INSTALLATION_CLASSIFICATION =
  'routesphere-bonvoyage-configuration-skill-installation';
const LOCK_CLASSIFICATION =
  'routesphere-bonvoyage-configuration-skill-lifecycle-lock';
const RESULT_CLASSIFICATION =
  'routesphere-bonvoyage-configuration-skill-lifecycle-result';
const MAX_JSON_BYTES = 1024 * 1024;

const SURFACES = Object.freeze({
  'claude-code': Object.freeze({
    wrapper: 'config/authoring/skills/v1/wrappers/claude.json',
    packagePath: 'skills/claude/bonvoyage-config-authoring',
    assistant: 'claude',
    wrapperClassification: 'routesphere-bonvoyage-claude-code-skill-wrapper',
    scopes: Object.freeze(['project', 'user']),
  }),
  'openai-codex': Object.freeze({
    wrapper: 'config/authoring/skills/v1/wrappers/openai-codex.json',
    packagePath: 'skills/bonvoyage-config-authoring',
    assistant: 'openai-codex',
    wrapperClassification: 'routesphere-bonvoyage-openai-codex-skill-wrapper',
    scopes: Object.freeze(['user']),
  }),
});

class LifecycleError extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

function reject(reason) {
  throw new LifecycleError(reason);
}

function readJson(filePath, reason) {
  try {
    const bytes = fs.readFileSync(filePath);
    if (bytes.length > MAX_JSON_BYTES) reject(reason);
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    reject(reason);
  }
}

function pathEntryExists(filePath) {
  try {
    fs.lstatSync(filePath);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    reject('filesystem-state-unreadable');
  }
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function sortedUniqueStrings(values) {
  return Array.isArray(values) &&
    values.every((value) => typeof value === 'string') &&
    new Set(values).size === values.length &&
    values.every((value, index) =>
      index === 0 || values[index - 1].localeCompare(value, 'en') < 0);
}

function safePackagePath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\\')) {
    return false;
  }
  if (path.posix.isAbsolute(value)) return false;
  const normalized = path.posix.normalize(value);
  return normalized === value && normalized !== '..' && !normalized.startsWith('../');
}

function listPackageFiles(root, {excludeInstallationRecord = false} = {}) {
  const files = [];

  function visit(directory, relativeDirectory = '') {
    const entries = fs.readdirSync(directory, {withFileTypes: true})
      .sort((left, right) => left.name.localeCompare(right.name, 'en'));
    for (const entry of entries) {
      const relativePath = relativeDirectory
        ? `${relativeDirectory}/${entry.name}`
        : entry.name;
      if (excludeInstallationRecord && relativePath === INSTALLATION_RECORD) continue;
      const absolutePath = path.join(directory, entry.name);
      const stat = fs.lstatSync(absolutePath);
      if (stat.isSymbolicLink()) reject('symbolic-link-refused');
      if (stat.isDirectory()) {
        visit(absolutePath, relativePath);
      } else if (stat.isFile()) {
        const bytes = fs.readFileSync(absolutePath);
        files.push({path: relativePath, bytes: bytes.length, sha256: sha256(bytes)});
      } else {
        reject('unsupported-package-entry');
      }
    }
  }

  visit(root);
  return files;
}

function packageDigest(files) {
  const input = files
    .map((entry) => `${entry.path}\0${entry.bytes}\0${entry.sha256}\n`)
    .join('');
  return sha256(Buffer.from(input, 'utf8'));
}

function releaseIdentity(contract) {
  if (contract === null || typeof contract !== 'object' || Array.isArray(contract) ||
      contract.classification !== 'routesphere-bonvoyage-configuration-skill-contract' ||
      contract.skill_id !== SKILL_ID ||
      typeof contract.product_version !== 'string' ||
      typeof contract.skill_version !== 'string' ||
      typeof contract.contract_version !== 'string' ||
      typeof contract.compiler_version !== 'string' ||
      !Array.isArray(contract.configuration_schema_versions) ||
      contract.configuration_schema_versions.length === 0 ||
      !contract.configuration_schema_versions.every(
        (version) => Number.isSafeInteger(version) && version > 0)) {
    reject('package-contract-invalid');
  }
  return {
    product_version: contract.product_version,
    skill_version: contract.skill_version,
    contract_version: contract.contract_version,
    compiler_version: contract.compiler_version,
    configuration_schema_versions: [...contract.configuration_schema_versions],
  };
}

function sameIdentity(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function parseProductVersion(value) {
  const match = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u.exec(value);
  if (!match) reject('package-version-invalid');
  return match.slice(1).map(BigInt);
}

function parseSkillVersion(value) {
  const match = /^bonvoyage\.configuration-skill\.v(0|[1-9][0-9]*)$/u.exec(value);
  if (!match) reject('package-version-invalid');
  return BigInt(match[1]);
}

function compareRelease(left, right) {
  const leftProduct = parseProductVersion(left.product_version);
  const rightProduct = parseProductVersion(right.product_version);
  for (let index = 0; index < leftProduct.length; index += 1) {
    if (leftProduct[index] < rightProduct[index]) return -1;
    if (leftProduct[index] > rightProduct[index]) return 1;
  }
  const leftSkill = parseSkillVersion(left.skill_version);
  const rightSkill = parseSkillVersion(right.skill_version);
  if (leftSkill < rightSkill) return -1;
  if (leftSkill > rightSkill) return 1;
  return 0;
}

function verifySourcePackage(repositoryRoot, surface) {
  const definition = SURFACES[surface];
  const wrapper = readJson(path.join(repositoryRoot, ...definition.wrapper.split('/')),
    'source-wrapper-invalid');
  if (wrapper.classification !== definition.wrapperClassification ||
      wrapper.assistant !== definition.assistant ||
      wrapper.skill_name !== SKILL_ID ||
      wrapper.package?.path !== definition.packagePath ||
      !Array.isArray(wrapper.package?.files)) {
    reject('source-wrapper-invalid');
  }

  const declaredPaths = wrapper.package.files.map((entry) => entry.path);
  if (!declaredPaths.every(safePackagePath) || !sortedUniqueStrings(declaredPaths)) {
    reject('source-wrapper-invalid');
  }
  const sourceRoot = path.join(repositoryRoot, ...definition.packagePath.split('/'));
  const sourceStat = fs.lstatSync(sourceRoot);
  if (!sourceStat.isDirectory() || sourceStat.isSymbolicLink()) {
    reject('source-package-invalid');
  }
  const actualFiles = listPackageFiles(sourceRoot);
  if (JSON.stringify(actualFiles.map((entry) => entry.path)) !== JSON.stringify(declaredPaths)) {
    reject('source-package-drift');
  }
  for (let index = 0; index < actualFiles.length; index += 1) {
    const declared = wrapper.package.files[index];
    const actual = actualFiles[index];
    if (declared.bytes !== actual.bytes || declared.sha256 !== actual.sha256) {
      reject('source-package-drift');
    }
  }

  const contract = readJson(path.join(sourceRoot, 'references', 'contract.json'),
    'source-package-invalid');
  const identity = releaseIdentity(contract);
  if (!sameIdentity(identity, wrapper.release_binding)) reject('source-wrapper-invalid');
  return {
    sourceRoot,
    identity,
    files: actualFiles,
    package_sha256: packageDigest(actualFiles),
  };
}

function installationRecord(source, surface, scope) {
  return {
    schema_version: 1,
    classification: INSTALLATION_CLASSIFICATION,
    manager_version: MANAGER_VERSION,
    skill_id: SKILL_ID,
    surface,
    scope,
    release_binding: source.identity,
    package_sha256: source.package_sha256,
    package_files: source.files,
  };
}

function renderInstallationRecord(record) {
  return `${JSON.stringify(record, null, 2)}\n`;
}

function verifyInstallation(target, surface, scope) {
  let targetStat;
  try {
    targetStat = fs.lstatSync(target);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    reject('installed-package-unreadable');
  }
  if (!targetStat.isDirectory() || targetStat.isSymbolicLink()) {
    reject('installed-target-refused');
  }

  const record = readJson(path.join(target, INSTALLATION_RECORD),
    'unmanaged-installed-package');
  const keys = Object.keys(record).sort();
  const expectedKeys = [
    'classification',
    'manager_version',
    'package_files',
    'package_sha256',
    'release_binding',
    'schema_version',
    'scope',
    'skill_id',
    'surface',
  ].sort();
  if (JSON.stringify(keys) !== JSON.stringify(expectedKeys) ||
      record.schema_version !== 1 ||
      record.classification !== INSTALLATION_CLASSIFICATION ||
      record.manager_version !== MANAGER_VERSION ||
      record.skill_id !== SKILL_ID ||
      record.surface !== surface ||
      record.scope !== scope ||
      !Array.isArray(record.package_files)) {
    reject('unmanaged-installed-package');
  }
  const recordedPaths = record.package_files.map((entry) => entry.path);
  if (!recordedPaths.every(safePackagePath) || !sortedUniqueStrings(recordedPaths)) {
    reject('unmanaged-installed-package');
  }
  const files = listPackageFiles(target, {excludeInstallationRecord: true});
  if (JSON.stringify(files) !== JSON.stringify(record.package_files) ||
      packageDigest(files) !== record.package_sha256) {
    reject('installed-package-drift');
  }
  const identity = releaseIdentity(readJson(
    path.join(target, 'references', 'contract.json'), 'installed-package-drift'));
  if (!sameIdentity(identity, record.release_binding)) reject('installed-package-drift');
  return {identity, files, package_sha256: record.package_sha256};
}

function homeDirectory(environment) {
  const value = environment.HOME || environment.USERPROFILE || os.homedir();
  if (typeof value !== 'string' || value.trim().length === 0) reject('home-directory-missing');
  return path.resolve(value);
}

function resolveTarget(surface, scope, {environment = process.env, cwd = process.cwd()} = {}) {
  const definition = SURFACES[surface];
  if (!definition || !definition.scopes.includes(scope)) reject('unsupported-surface-scope');
  if (surface === 'openai-codex') {
    const codexHome = environment.CODEX_HOME
      ? path.resolve(environment.CODEX_HOME)
      : path.join(homeDirectory(environment), '.codex');
    return path.join(codexHome, 'skills', SKILL_ID);
  }
  if (scope === 'project') {
    return path.join(path.resolve(cwd), '.claude', 'skills', SKILL_ID);
  }
  return path.join(homeDirectory(environment), '.claude', 'skills', SKILL_ID);
}

function assertDirectDirectory(directory) {
  const stat = fs.lstatSync(directory);
  if (stat.isSymbolicLink()) reject('symbolic-link-refused');
  if (!stat.isDirectory()) reject('destination-parent-invalid');
}

function prepareParent(target, {create}) {
  const parent = path.dirname(target);
  const root = path.parse(parent).root;
  assertDirectDirectory(root);
  let cursor = root;
  const components = path.relative(root, parent).split(path.sep).filter(Boolean);
  for (const component of components) {
    cursor = path.join(cursor, component);
    if (!pathEntryExists(cursor)) {
      if (!create) return null;
      fs.mkdirSync(cursor, {mode: 0o700});
    }
    assertDirectDirectory(cursor);
  }
  return parent;
}

function temporarySibling(parent, label) {
  return path.join(parent, `.${SKILL_ID}.${label}-${process.pid}-${crypto.randomBytes(8).toString('hex')}`);
}

function stageSource(source, staging, surface, scope) {
  try {
    fs.cpSync(source.sourceRoot, staging, {
      recursive: true,
      dereference: false,
      errorOnExist: true,
      force: false,
      preserveTimestamps: false,
    });
    fs.writeFileSync(path.join(staging, INSTALLATION_RECORD),
      renderInstallationRecord(installationRecord(source, surface, scope)),
      {encoding: 'utf8', mode: 0o600, flag: 'wx'});
    verifyInstallation(staging, surface, scope);
    return staging;
  } catch (error) {
    if (error instanceof LifecycleError) throw error;
    reject('staging-failed');
  }
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === 'ESRCH') return false;
    return true;
  }
}

function transactionPathIsSafe(candidate, parent, label) {
  return typeof candidate === 'string' &&
    path.dirname(candidate) === parent &&
    path.basename(candidate).startsWith(`.${SKILL_ID}.${label}-`);
}

function readLifecycleLock(lockPath, parent, target, surface, scope) {
  const stat = fs.lstatSync(lockPath);
  if (!stat.isFile() || stat.isSymbolicLink()) reject('lifecycle-operation-locked');
  const record = readJson(lockPath, 'lifecycle-operation-locked');
  if (record === null || typeof record !== 'object' || Array.isArray(record)) {
    reject('lifecycle-operation-locked');
  }
  const keys = Object.keys(record).sort();
  const expectedKeys = [
    'classification',
    'manager_version',
    'operation',
    'pid',
    'recovery',
    'schema_version',
    'scope',
    'staging',
    'surface',
    'target',
  ].sort();
  const validTransactionPaths =
    (record.operation === 'install' &&
      transactionPathIsSafe(record.staging, parent, 'stage') && record.recovery === null) ||
    (record.operation === 'status' && record.staging === null && record.recovery === null) ||
    (record.operation === 'upgrade' &&
      transactionPathIsSafe(record.staging, parent, 'stage') &&
      transactionPathIsSafe(record.recovery, parent, 'backup')) ||
    (record.operation === 'uninstall' && record.staging === null &&
      transactionPathIsSafe(record.recovery, parent, 'remove'));
  if (JSON.stringify(keys) !== JSON.stringify(expectedKeys) ||
      record.schema_version !== 1 ||
      record.classification !== LOCK_CLASSIFICATION ||
      record.manager_version !== MANAGER_VERSION ||
      !Number.isSafeInteger(record.pid) || record.pid <= 0 ||
      !['install', 'status', 'uninstall', 'upgrade'].includes(record.operation) ||
      record.target !== target || record.surface !== surface || record.scope !== scope ||
      !validTransactionPaths) {
    reject('lifecycle-operation-locked');
  }
  return record;
}

function recoverInterruptedLifecycle(record, target, surface, scope) {
  if (processIsAlive(record.pid)) reject('lifecycle-operation-locked');
  if (pathEntryExists(target)) {
    verifyInstallation(target, surface, scope);
    return;
  }
  if (record.recovery !== null && pathEntryExists(record.recovery)) {
    verifyInstallation(record.recovery, surface, scope);
    fs.renameSync(record.recovery, target);
    verifyInstallation(target, surface, scope);
    return;
  }
  if (record.operation === 'install' && record.staging !== null &&
      pathEntryExists(record.staging)) {
    verifyInstallation(record.staging, surface, scope);
    fs.renameSync(record.staging, target);
    verifyInstallation(target, surface, scope);
    return;
  }
  if (record.operation === 'upgrade' || record.operation === 'uninstall') {
    reject('interrupted-recovery-missing');
  }
}

function lifecycleLockRecord({operation, target, staging, recovery, surface, scope}) {
  return {
    schema_version: 1,
    classification: LOCK_CLASSIFICATION,
    manager_version: MANAGER_VERSION,
    pid: process.pid,
    operation,
    surface,
    scope,
    target,
    staging,
    recovery,
  };
}

function withLifecycleLock(parent, transaction, action) {
  const lockPath = path.join(parent, `.${SKILL_ID}.lifecycle.lock`);
  let descriptor;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      descriptor = fs.openSync(lockPath, 'wx', 0o600);
      break;
    } catch (error) {
      if (error?.code !== 'EEXIST' || attempt > 0) reject('lifecycle-operation-locked');
      const stale = readLifecycleLock(
        lockPath, parent, transaction.target, transaction.surface, transaction.scope);
      recoverInterruptedLifecycle(
        stale, transaction.target, transaction.surface, transaction.scope);
      fs.rmSync(lockPath, {force: false});
    }
  }
  if (descriptor === undefined) reject('lifecycle-operation-locked');
  try {
    fs.writeFileSync(descriptor,
      `${JSON.stringify(lifecycleLockRecord(transaction), null, 2)}\n`, 'utf8');
    fs.fsyncSync(descriptor);
    return action();
  } finally {
    try {
      fs.closeSync(descriptor);
    } finally {
      fs.rmSync(lockPath, {force: true});
    }
  }
}

function install(source, target, surface, scope) {
  const parent = prepareParent(target, {create: true});
  const staging = temporarySibling(parent, 'stage');
  const transaction = {
    operation: 'install', target, staging, recovery: null, surface, scope,
  };
  return withLifecycleLock(parent, transaction, () => {
    try {
      if (pathEntryExists(target)) reject('installed-target-exists');
      stageSource(source, staging, surface, scope);
      if (pathEntryExists(target)) reject('installed-target-exists');
      fs.renameSync(staging, target);
      verifyInstallation(target, surface, scope);
    } catch (error) {
      if (error instanceof LifecycleError) throw error;
      reject('install-failed');
    }
    return {reason: 'installed', changed: true, identity: source.identity, recovery: null};
  });
}

function upgrade(source, target, surface, scope) {
  const parent = prepareParent(target, {create: false});
  if (parent === null) reject('installed-package-missing');
  const staging = temporarySibling(parent, 'stage');
  const backup = temporarySibling(parent, 'backup');
  const transaction = {
    operation: 'upgrade', target, staging, recovery: backup, surface, scope,
  };
  return withLifecycleLock(parent, transaction, () => {
    let movedOld = false;
    try {
      const installed = verifyInstallation(target, surface, scope);
      if (!installed) reject('installed-package-missing');
      const comparison = compareRelease(source.identity, installed.identity);
      if (comparison < 0) reject('downgrade-refused');
      if (comparison === 0) {
        if (!sameIdentity(source.identity, installed.identity)) {
          reject('release-identity-conflict');
        }
        if (source.package_sha256 !== installed.package_sha256) {
          reject('release-content-conflict');
        }
        return {
          reason: 'already-current', changed: false, identity: installed.identity, recovery: null,
        };
      }

      stageSource(source, staging, surface, scope);
      verifyInstallation(target, surface, scope);
      fs.renameSync(target, backup);
      movedOld = true;
      verifyInstallation(backup, surface, scope);
      fs.renameSync(staging, target);
      verifyInstallation(target, surface, scope);
      return {
        reason: 'upgraded',
        changed: true,
        identity: source.identity,
        recovery: path.basename(backup),
      };
    } catch (error) {
      if (movedOld && pathEntryExists(backup) && !pathEntryExists(target)) {
        try {
          verifyInstallation(backup, surface, scope);
          fs.renameSync(backup, target);
          verifyInstallation(target, surface, scope);
        } catch {
          reject('upgrade-recovery-failed');
        }
      }
      if (error instanceof LifecycleError) throw error;
      reject('upgrade-failed');
    }
  });
}

function uninstall(target, surface, scope) {
  const parent = prepareParent(target, {create: false});
  if (parent === null) {
    return {reason: 'already-absent', changed: false, identity: null, recovery: null};
  }
  const tombstone = temporarySibling(parent, 'remove');
  const transaction = {
    operation: 'uninstall', target, staging: null, recovery: tombstone, surface, scope,
  };
  return withLifecycleLock(parent, transaction, () => {
    let moved = false;
    try {
      const installed = verifyInstallation(target, surface, scope);
      if (!installed) {
        return {reason: 'already-absent', changed: false, identity: null, recovery: null};
      }
      verifyInstallation(target, surface, scope);
      fs.renameSync(target, tombstone);
      moved = true;
      verifyInstallation(tombstone, surface, scope);
      return {
        reason: 'uninstalled',
        changed: true,
        identity: installed.identity,
        recovery: path.basename(tombstone),
      };
    } catch (error) {
      if (moved && pathEntryExists(tombstone) && !pathEntryExists(target)) {
        try {
          fs.renameSync(tombstone, target);
        } catch {
          reject('uninstall-recovery-failed');
        }
      }
      if (error instanceof LifecycleError) throw error;
      reject('uninstall-failed');
    }
  });
}

function status(source, target, surface, scope) {
  const parent = prepareParent(target, {create: false});
  if (parent === null) {
    return {reason: 'not-installed', changed: false, identity: null, recovery: null};
  }
  const transaction = {
    operation: 'status', target, staging: null, recovery: null, surface, scope,
  };
  return withLifecycleLock(parent, transaction, () => {
    const installed = verifyInstallation(target, surface, scope);
    if (!installed) {
      return {reason: 'not-installed', changed: false, identity: null, recovery: null};
    }
    const comparison = compareRelease(source.identity, installed.identity);
    if (comparison > 0) {
      return {
        reason: 'upgrade-available', changed: false, identity: installed.identity, recovery: null,
      };
    }
    if (comparison < 0) {
      return {
        reason: 'installed-newer', changed: false, identity: installed.identity, recovery: null,
      };
    }
    if (!sameIdentity(source.identity, installed.identity)) reject('release-identity-conflict');
    if (source.package_sha256 !== installed.package_sha256) {
      reject('release-content-conflict');
    }
    return {
      reason: 'installed-current', changed: false, identity: installed.identity, recovery: null,
    };
  });
}

export function manageSkillLifecycle({
  operation,
  surface,
  scope,
  repositoryRoot = DEFAULT_REPOSITORY_ROOT,
  environment = process.env,
  cwd = process.cwd(),
}) {
  if (!['install', 'status', 'uninstall', 'upgrade'].includes(operation)) {
    reject('unsupported-operation');
  }
  if (!Object.hasOwn(SURFACES, surface)) reject('unsupported-surface-scope');
  const target = resolveTarget(surface, scope, {environment, cwd});
  if (operation === 'status') {
    const source = verifySourcePackage(path.resolve(repositoryRoot), surface);
    return status(source, target, surface, scope);
  }
  if (operation === 'uninstall') return uninstall(target, surface, scope);
  const source = verifySourcePackage(path.resolve(repositoryRoot), surface);
  if (operation === 'install') return install(source, target, surface, scope);
  return upgrade(source, target, surface, scope);
}

function parseArguments(args) {
  if (args.length !== 5) reject('invalid-invocation');
  const [operation, firstFlag, firstValue, secondFlag, secondValue] = args;
  const fields = new Map([
    [firstFlag, firstValue],
    [secondFlag, secondValue],
  ]);
  if (fields.size !== 2 || !fields.has('--surface') || !fields.has('--scope')) {
    reject('invalid-invocation');
  }
  return {operation, surface: fields.get('--surface'), scope: fields.get('--scope')};
}

function emit(operation, surface, scope, status, reason, changed, identity, recovery) {
  process.stdout.write(`${JSON.stringify({
    schema_version: 1,
    classification: RESULT_CLASSIFICATION,
    manager_version: MANAGER_VERSION,
    operation: operation ?? null,
    surface: surface ?? null,
    scope: scope ?? null,
    status,
    reason,
    changed,
    identity,
    recovery,
  })}\n`);
}

function main(args) {
  let parsed = {operation: null, surface: null, scope: null};
  try {
    parsed = parseArguments(args);
    const result = manageSkillLifecycle(parsed);
    emit(parsed.operation, parsed.surface, parsed.scope, 'accepted', result.reason,
      result.changed, result.identity, result.recovery);
    return 0;
  } catch (error) {
    const reason = error instanceof LifecycleError ? error.reason : 'operation-failed';
    emit(parsed.operation, parsed.surface, parsed.scope, 'blocked', reason, false, null, null);
    return 2;
  }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath === SCRIPT_PATH) process.exitCode = main(process.argv.slice(2));

export {
  INSTALLATION_CLASSIFICATION,
  INSTALLATION_RECORD,
  LOCK_CLASSIFICATION,
  MANAGER_VERSION,
  RESULT_CLASSIFICATION,
};
