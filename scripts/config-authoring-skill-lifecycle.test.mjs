import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {spawnSync} from 'node:child_process';
import {afterEach, test} from 'node:test';
import {fileURLToPath} from 'node:url';

import {
  INSTALLATION_CLASSIFICATION,
  INSTALLATION_RECORD,
  LOCK_CLASSIFICATION,
  MANAGER_VERSION,
  manageSkillLifecycle,
} from './manage-config-authoring-skill.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MANAGER = path.join(ROOT, 'scripts', 'manage-config-authoring-skill.mjs');
const SKILL_ID = 'bonvoyage-config-authoring';
const temporaryRoots = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

function temporaryRoot(prefix) {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), prefix));
  temporaryRoots.push(root);
  return root;
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function packageFiles(root, {excludeInstallationRecord = true} = {}) {
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
      if (entry.isDirectory()) {
        visit(absolutePath, relativePath);
      } else {
        const bytes = fs.readFileSync(absolutePath);
        files.push({path: relativePath, bytes: bytes.length, sha256: sha256(bytes)});
      }
    }
  }
  visit(root);
  return files;
}

function packageDigest(files) {
  return sha256(Buffer.from(files
    .map((entry) => `${entry.path}\0${entry.bytes}\0${entry.sha256}\n`)
    .join(''), 'utf8'));
}

function treeDigest(root) {
  if (!fs.existsSync(root)) return null;
  return packageDigest(packageFiles(root, {excludeInstallationRecord: false}));
}

function isolatedEnvironment(root, {codexHome = true} = {}) {
  const home = path.join(root, 'home');
  fs.mkdirSync(home, {recursive: true});
  return {
    HOME: home,
    PATH: process.env.PATH ?? '',
    ...(process.platform === 'win32' && process.env.SystemRoot
      ? {SystemRoot: process.env.SystemRoot}
      : {}),
    ...(process.platform === 'win32' && process.env.PATHEXT
      ? {PATHEXT: process.env.PATHEXT}
      : {}),
    ...(codexHome ? {CODEX_HOME: path.join(root, 'codex-home')} : {}),
    BONVOYAGE_TEST_SECRET: 'must-not-appear',
  };
}

function runLifecycle({operation, surface, scope, environment, cwd}) {
  const command = spawnSync(process.execPath, [
    MANAGER,
    operation,
    '--surface', surface,
    '--scope', scope,
  ], {
    cwd,
    env: environment,
    encoding: 'utf8',
    timeout: 10000,
  });
  assert.equal(command.stderr, '');
  assert.equal(command.stdout.trim().includes('\n'), false, command.stdout);
  assert.doesNotMatch(command.stdout, /must-not-appear/u);
  return {command, result: JSON.parse(command.stdout.trim())};
}

function assertAccepted(run, reason, changed) {
  assert.equal(run.command.status, 0, run.command.stdout);
  assert.equal(run.result.status, 'accepted');
  assert.equal(run.result.reason, reason);
  assert.equal(run.result.changed, changed);
  assert.equal(run.result.manager_version, MANAGER_VERSION);
  assert.equal(Object.hasOwn(run.result, 'recovery'), true);
}

function assertBlocked(run, reason) {
  assert.equal(run.command.status, 2, run.command.stdout);
  assert.equal(run.result.status, 'blocked');
  assert.equal(run.result.reason, reason);
  assert.equal(run.result.changed, false);
  assert.equal(run.result.identity, null);
  assert.equal(run.result.recovery, null);
}

function openAiTarget(environment) {
  return path.join(environment.CODEX_HOME, 'skills', SKILL_ID);
}

function claudeUserTarget(environment) {
  return path.join(environment.HOME, '.claude', 'skills', SKILL_ID);
}

function claudeProjectTarget(cwd) {
  return path.join(cwd, '.claude', 'skills', SKILL_ID);
}

function rewriteManagedRelease(target, productVersion, {addMarker = false} = {}) {
  const contractPath = path.join(target, 'references', 'contract.json');
  const contract = JSON.parse(fs.readFileSync(contractPath, 'utf8'));
  contract.product_version = productVersion;
  fs.writeFileSync(contractPath, `${JSON.stringify(contract, null, 2)}\n`);
  if (addMarker) fs.writeFileSync(path.join(target, 'legacy-release.txt'), `${productVersion}\n`);

  const recordPath = path.join(target, INSTALLATION_RECORD);
  const record = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
  record.release_binding.product_version = productVersion;
  record.package_files = packageFiles(target);
  record.package_sha256 = packageDigest(record.package_files);
  fs.writeFileSync(recordPath, `${JSON.stringify(record, null, 2)}\n`);
}

function recoveryPath(target, run) {
  assert.equal(typeof run.result.recovery, 'string');
  assert.match(run.result.recovery, /^\.bonvoyage-config-authoring\.(?:backup|remove)-/u);
  return path.join(path.dirname(target), run.result.recovery);
}

function writeInterruptedLock({target, operation, staging = null, recovery = null, surface, scope}) {
  const lock = path.join(path.dirname(target), `.${SKILL_ID}.lifecycle.lock`);
  fs.writeFileSync(lock, `${JSON.stringify({
    schema_version: 1,
    classification: LOCK_CLASSIFICATION,
    manager_version: MANAGER_VERSION,
    pid: 2147483647,
    operation,
    surface,
    scope,
    target,
    staging,
    recovery,
  }, null, 2)}\n`, {mode: 0o600});
  return lock;
}

test('manager exposes a bounded offline command surface', () => {
  const source = fs.readFileSync(MANAGER, 'utf8');
  assert.doesNotMatch(source, /from ['"]node:(?:http|https|net|tls|dns)['"]/u);
  assert.doesNotMatch(source, /from ['"]node:child_process['"]/u);
  assert.doesNotMatch(source, /\bfetch\s*\(/u);

  const root = temporaryRoot('bonvoyage-skill-invalid-');
  const command = spawnSync(process.execPath, [MANAGER, 'install'], {
    cwd: root,
    env: isolatedEnvironment(root),
    encoding: 'utf8',
  });
  assert.equal(command.status, 2);
  const result = JSON.parse(command.stdout.trim());
  assert.deepEqual({status: result.status, reason: result.reason}, {
    status: 'blocked',
    reason: 'invalid-invocation',
  });
});

test('OpenAI Codex user install, status and uninstall preserve sibling skills', () => {
  const root = temporaryRoot('bonvoyage-skill-openai-');
  const environment = isolatedEnvironment(root);
  const target = openAiTarget(environment);
  const sibling = path.join(path.dirname(target), 'operator-owned-skill', 'keep.txt');
  fs.mkdirSync(path.dirname(sibling), {recursive: true});
  fs.writeFileSync(sibling, 'keep\n');

  const install = runLifecycle({
    operation: 'install', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  });
  assertAccepted(install, 'installed', true);
  assert.equal(fs.existsSync(path.join(target, 'SKILL.md')), true);
  const record = JSON.parse(fs.readFileSync(path.join(target, INSTALLATION_RECORD), 'utf8'));
  assert.equal(record.classification, INSTALLATION_CLASSIFICATION);
  assert.equal(record.surface, 'openai-codex');
  assert.equal(record.scope, 'user');
  assert.equal(record.package_sha256, packageDigest(record.package_files));

  const status = runLifecycle({
    operation: 'status', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  });
  assertAccepted(status, 'installed-current', false);
  const duplicate = runLifecycle({
    operation: 'install', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  });
  assertBlocked(duplicate, 'installed-target-exists');

  const uninstall = runLifecycle({
    operation: 'uninstall', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  });
  assertAccepted(uninstall, 'uninstalled', true);
  assert.equal(fs.existsSync(target), false);
  const removedPackage = recoveryPath(target, uninstall);
  assert.equal(fs.existsSync(path.join(removedPackage, 'SKILL.md')), true);
  assert.equal(fs.readFileSync(sibling, 'utf8'), 'keep\n');
  const repeated = runLifecycle({
    operation: 'uninstall', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  });
  assertAccepted(repeated, 'already-absent', false);
});

test('Claude Code project and user scopes resolve only their documented destinations', () => {
  const root = temporaryRoot('bonvoyage-skill-claude-');
  const project = path.join(root, 'project');
  fs.mkdirSync(project);
  const environment = isolatedEnvironment(root, {codexHome: false});

  const projectInstall = runLifecycle({
    operation: 'install', surface: 'claude-code', scope: 'project', environment, cwd: project,
  });
  assertAccepted(projectInstall, 'installed', true);
  assert.equal(fs.existsSync(claudeProjectTarget(project)), true);
  assert.equal(fs.existsSync(claudeUserTarget(environment)), false);

  const userInstall = runLifecycle({
    operation: 'install', surface: 'claude-code', scope: 'user', environment, cwd: project,
  });
  assertAccepted(userInstall, 'installed', true);
  assert.equal(fs.existsSync(claudeUserTarget(environment)), true);

  assertAccepted(runLifecycle({
    operation: 'uninstall', surface: 'claude-code', scope: 'project', environment, cwd: project,
  }), 'uninstalled', true);
  assertAccepted(runLifecycle({
    operation: 'uninstall', surface: 'claude-code', scope: 'user', environment, cwd: project,
  }), 'uninstalled', true);
});

test('upgrade atomically replaces a valid older managed release', () => {
  const root = temporaryRoot('bonvoyage-skill-upgrade-');
  const environment = isolatedEnvironment(root);
  const target = openAiTarget(environment);
  assertAccepted(runLifecycle({
    operation: 'install', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'installed', true);
  rewriteManagedRelease(target, '0.1.0', {addMarker: true});
  assertAccepted(runLifecycle({
    operation: 'status', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'upgrade-available', false);

  const upgrade = runLifecycle({
    operation: 'upgrade', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  });
  assertAccepted(upgrade, 'upgraded', true);
  assert.equal(upgrade.result.identity.product_version, '0.2.0');
  assert.equal(fs.existsSync(path.join(target, 'legacy-release.txt')), false);
  const installedContract = JSON.parse(fs.readFileSync(
    path.join(target, 'references', 'contract.json'), 'utf8'));
  assert.equal(installedContract.product_version, '0.2.0');
  const previousRelease = recoveryPath(target, upgrade);
  assert.equal(fs.readFileSync(path.join(previousRelease, 'legacy-release.txt'), 'utf8'), '0.1.0\n');
  assertAccepted(runLifecycle({
    operation: 'upgrade', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'already-current', false);
  assert.deepEqual(fs.readdirSync(path.dirname(target))
    .filter((name) => name.startsWith(`.${SKILL_ID}.`)), [upgrade.result.recovery]);
});

test('upgrade refuses a valid newer managed release without changing it', () => {
  const root = temporaryRoot('bonvoyage-skill-downgrade-');
  const environment = isolatedEnvironment(root);
  const target = openAiTarget(environment);
  assertAccepted(runLifecycle({
    operation: 'install', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'installed', true);
  rewriteManagedRelease(target, '0.3.0', {addMarker: true});
  const before = treeDigest(target);
  assertAccepted(runLifecycle({
    operation: 'status', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'installed-newer', false);

  const upgrade = runLifecycle({
    operation: 'upgrade', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  });
  assertBlocked(upgrade, 'downgrade-refused');
  assert.equal(treeDigest(target), before);
  assert.equal(fs.readFileSync(path.join(target, 'legacy-release.txt'), 'utf8'), '0.3.0\n');
});

test('drifted and unmanaged targets are never overwritten or removed', () => {
  const root = temporaryRoot('bonvoyage-skill-drift-');
  const environment = isolatedEnvironment(root);
  const target = openAiTarget(environment);
  assertAccepted(runLifecycle({
    operation: 'install', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'installed', true);
  fs.appendFileSync(path.join(target, 'SKILL.md'), '\nlocal operator change\n');
  const before = fs.readFileSync(path.join(target, 'SKILL.md'), 'utf8');
  assertBlocked(runLifecycle({
    operation: 'upgrade', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'installed-package-drift');
  assertBlocked(runLifecycle({
    operation: 'uninstall', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'installed-package-drift');
  assert.equal(fs.readFileSync(path.join(target, 'SKILL.md'), 'utf8'), before);

  fs.rmSync(target, {recursive: true});
  fs.mkdirSync(target, {recursive: true});
  fs.writeFileSync(path.join(target, 'operator.txt'), 'unmanaged\n');
  assertBlocked(runLifecycle({
    operation: 'uninstall', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'unmanaged-installed-package');
  assert.equal(fs.readFileSync(path.join(target, 'operator.txt'), 'utf8'), 'unmanaged\n');
});

test('same-version divergent content and concurrent lifecycle operations fail closed', () => {
  const root = temporaryRoot('bonvoyage-skill-conflict-');
  const environment = isolatedEnvironment(root);
  const target = openAiTarget(environment);
  assertAccepted(runLifecycle({
    operation: 'install', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'installed', true);
  rewriteManagedRelease(target, '0.2.0', {addMarker: true});
  const before = treeDigest(target);
  assertBlocked(runLifecycle({
    operation: 'status', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'release-content-conflict');
  assertBlocked(runLifecycle({
    operation: 'upgrade', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'release-content-conflict');
  assert.equal(treeDigest(target), before);

  const lock = path.join(path.dirname(target), `.${SKILL_ID}.lifecycle.lock`);
  fs.writeFileSync(lock, 'held\n');
  assertBlocked(runLifecycle({
    operation: 'uninstall', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'lifecycle-operation-locked');
  assert.equal(treeDigest(target), before);
  fs.rmSync(lock);
});

test('dead lifecycle locks recover interrupted install, upgrade and uninstall transactions', () => {
  const root = temporaryRoot('bonvoyage-skill-recovery-');
  const environment = isolatedEnvironment(root);
  const target = openAiTarget(environment);
  assertAccepted(runLifecycle({
    operation: 'install', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'installed', true);

  const installStage = path.join(
    path.dirname(target), `.${SKILL_ID}.stage-2147483647-install`);
  fs.renameSync(target, installStage);
  writeInterruptedLock({
    target,
    operation: 'install',
    staging: installStage,
    surface: 'openai-codex',
    scope: 'user',
  });
  assertAccepted(runLifecycle({
    operation: 'status', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'installed-current', false);
  assert.equal(fs.existsSync(target), true);
  assert.equal(fs.existsSync(installStage), false);

  rewriteManagedRelease(target, '0.1.0', {addMarker: true});
  const upgradeBackup = path.join(
    path.dirname(target), `.${SKILL_ID}.backup-2147483647-upgrade`);
  fs.renameSync(target, upgradeBackup);
  writeInterruptedLock({
    target,
    operation: 'upgrade',
    staging: path.join(path.dirname(target), `.${SKILL_ID}.stage-2147483647-upgrade`),
    recovery: upgradeBackup,
    surface: 'openai-codex',
    scope: 'user',
  });
  assertAccepted(runLifecycle({
    operation: 'status', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'upgrade-available', false);
  assert.equal(fs.readFileSync(path.join(target, 'legacy-release.txt'), 'utf8'), '0.1.0\n');
  assert.equal(fs.existsSync(upgradeBackup), false);

  const uninstallRecovery = path.join(
    path.dirname(target), `.${SKILL_ID}.remove-2147483647-uninstall`);
  fs.renameSync(target, uninstallRecovery);
  writeInterruptedLock({
    target,
    operation: 'uninstall',
    recovery: uninstallRecovery,
    surface: 'openai-codex',
    scope: 'user',
  });
  assertAccepted(runLifecycle({
    operation: 'status', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'upgrade-available', false);
  assert.equal(fs.existsSync(target), true);
  assert.equal(fs.existsSync(uninstallRecovery), false);
});

test('source hash drift is rejected before destination mutation', () => {
  const root = temporaryRoot('bonvoyage-skill-source-');
  const repository = path.join(root, 'repository');
  const environment = isolatedEnvironment(root);
  for (const relativePath of [
    'config/authoring/skills/v1/wrappers/openai-codex.json',
    'skills/bonvoyage-config-authoring',
  ]) {
    const source = path.join(ROOT, ...relativePath.split('/'));
    const destination = path.join(repository, ...relativePath.split('/'));
    fs.mkdirSync(path.dirname(destination), {recursive: true});
    fs.cpSync(source, destination, {recursive: true});
  }
  fs.appendFileSync(path.join(repository, 'skills', SKILL_ID, 'SKILL.md'), '\ndrift\n');

  assert.throws(() => manageSkillLifecycle({
    operation: 'install',
    surface: 'openai-codex',
    scope: 'user',
    repositoryRoot: repository,
    environment,
    cwd: root,
  }), /source-package-drift/u);
  assert.equal(fs.existsSync(openAiTarget(environment)), false);
});

test('symbolic-link targets are refused when the platform permits the fixture', (context) => {
  const root = temporaryRoot('bonvoyage-skill-symlink-');
  const environment = isolatedEnvironment(root);
  const target = openAiTarget(environment);
  const outside = path.join(root, 'outside');
  fs.mkdirSync(path.dirname(target), {recursive: true});
  fs.mkdirSync(outside);
  try {
    fs.symlinkSync(outside, target, process.platform === 'win32' ? 'junction' : 'dir');
  } catch {
    context.skip('symbolic links are unavailable in this environment');
    return;
  }
  const status = runLifecycle({
    operation: 'status', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  });
  assertBlocked(status, 'installed-target-refused');
  assert.equal(fs.existsSync(outside), true);

  fs.rmSync(target);
  const missing = path.join(root, 'missing-target');
  try {
    fs.symlinkSync(missing, target, process.platform === 'win32' ? 'junction' : 'dir');
  } catch {
    context.skip('dangling symbolic links are unavailable in this environment');
    return;
  }
  const install = runLifecycle({
    operation: 'install', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  });
  assertBlocked(install, 'installed-target-exists');
  assert.equal(fs.lstatSync(target).isSymbolicLink(), true);
});

test('symbolic-link destination parents are refused before child directories are created', (context) => {
  const root = temporaryRoot('bonvoyage-skill-parent-symlink-');
  const environment = isolatedEnvironment(root);
  const outside = path.join(root, 'outside');
  const linkedCodexHome = path.join(root, 'linked-codex-home');
  fs.mkdirSync(outside);
  try {
    fs.symlinkSync(outside, linkedCodexHome, process.platform === 'win32' ? 'junction' : 'dir');
  } catch {
    context.skip('symbolic links are unavailable in this environment');
    return;
  }
  environment.CODEX_HOME = linkedCodexHome;

  assertBlocked(runLifecycle({
    operation: 'install', surface: 'openai-codex', scope: 'user', environment, cwd: root,
  }), 'symbolic-link-refused');
  assert.equal(fs.existsSync(path.join(outside, 'skills')), false);
});
