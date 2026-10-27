#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const defaultContractPath = path.join(root, 'packaging', 'release', 'kubernetes',
  'oss-kubernetes-fresh-install-contract.json');
const defaultVerifierPath = path.join(root, 'scripts',
  'verify-kubernetes-deployment.mjs');
const gatewaySelector =
  'app.kubernetes.io/name=bonvoyage,app.kubernetes.io/component=gateway';
const upstreamSelector =
  'app.kubernetes.io/name=bonvoyage-acceptance-upstream';
const maximumOutputBytes = 16 * 1024 * 1024;

export class Rejected extends Error {}

function requireValue(condition, message) {
  if (!condition) throw new Rejected(message);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

async function sha256File(file) {
  const digest = crypto.createHash('sha256');
  await new Promise((resolve, reject) => {
    const stream = fs.createReadStream(file);
    stream.on('data', chunk => digest.update(chunk));
    stream.on('error', reject);
    stream.on('end', resolve);
  });
  return digest.digest('hex');
}

function immutableDigest(value, label) {
  requireValue(/^sha256:[0-9a-f]{64}$/.test(value || ''),
    `${label} is not an immutable SHA-256 digest`);
  return value;
}

function stableJSON(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function writeFile(file, value, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), {recursive: true, mode: 0o700});
  fs.writeFileSync(file, value, {encoding: 'utf8', mode});
  fs.chmodSync(file, mode);
}

function writeJSON(file, value) {
  writeFile(file, stableJSON(value));
}

function readJSON(file, label) {
  let value;
  try {
    value = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    throw new Rejected(`${label} is not valid JSON: ${error.message}`);
  }
  return value;
}

function safeName(value, label) {
  requireValue(typeof value === 'string' &&
    /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value),
  `${label} is not a safe Kubernetes name`);
  return value;
}

function parsePositiveInteger(value, label) {
  requireValue(/^[1-9][0-9]*$/.test(String(value)),
    `${label} must be a positive integer`);
  return Number.parseInt(String(value), 10);
}

function ready(pod) {
  return pod.status?.conditions?.some(condition =>
    condition.type === 'Ready' && condition.status === 'True');
}

function selectedConfigMap(pod) {
  return pod.spec?.volumes?.find(volume => volume.name === 'config')
    ?.configMap?.name;
}

function compilerFailed(pod) {
  const status = pod.status?.initContainerStatuses?.find(value =>
    value.name === 'snapshot-compiler');
  if (!status) return false;
  return (status.state?.terminated?.exitCode ?? 0) !== 0 ||
    ['CrashLoopBackOff', 'Error', 'RunContainerError']
      .includes(status.state?.waiting?.reason) || status.restartCount > 0;
}

function phaseRecord(contract, phaseId, checks) {
  const phase = contract.phases?.find(value => value.id === phaseId);
  requireValue(phase, `contract phase is absent: ${phaseId}`);
  const expected = [...phase.required_checks].sort();
  const actual = Object.keys(checks).sort();
  requireValue(JSON.stringify(actual) === JSON.stringify(expected),
    `${phaseId} check inventory differs from the contract`);
  for (const check of expected) {
    requireValue(checks[check] === true,
      `${phaseId} check failed: ${check}`);
  }
  return {id: phaseId, checks, passed: true};
}

function validateContract(contract) {
  requireValue(contract.schema_version === 2,
    'unsupported Kubernetes acceptance contract schema');
  requireValue(contract.classification ===
    'routesphere-bonvoyage-oss-kubernetes-fresh-install-contract',
  'unexpected Kubernetes acceptance contract classification');
  safeName(contract.target?.namespace, 'target namespace');
  safeName(contract.target?.deployment, 'target deployment');
  safeName(contract.target?.service, 'target service');
  safeName(contract.target?.context, 'target context');
  const runner = contract.runner;
  requireValue(runner && typeof runner === 'object',
    'runner contract is absent');
  safeName(runner.cluster_name, 'kind cluster name');
  requireValue(contract.target.context === `kind-${runner.cluster_name}`,
    'target context is not derived from the dedicated kind cluster');
  requireValue(/^v[0-9]+\.[0-9]+\.[0-9]+$/.test(runner.kind_version),
    'kind version is not pinned');
  requireValue(/^kindest\/node:v[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$/
    .test(runner.kind_node_image), 'kind node image is not digest-pinned');
  requireValue(runner.confirmation ===
    `delete-kind-${runner.cluster_name}`,
  'runner confirmation token is not bound to the cluster');
  parsePositiveInteger(runner.cluster_wait_seconds,
    'cluster wait timeout');
  parsePositiveInteger(runner.rollout_timeout_seconds,
    'rollout timeout');
  parsePositiveInteger(runner.failed_candidate_timeout_seconds,
    'failed-candidate timeout');
  const images = runner.images || {};
  for (const role of ['dataplane', 'snapshot_compiler', 'upstream']) {
    requireValue(/^[a-z0-9][a-z0-9./_-]*:[a-z0-9][a-z0-9._-]*$/
      .test(images[role] || ''), `${role} image is not pinned to a local tag`);
  }
  requireValue(new Set(Object.values(images)).size === 3,
    'runner image tags must be distinct');
  requireValue(contract.qualification_authority === 'live-run-summary-only',
    'Kubernetes qualification authority is not live-run scoped');
  requireValue(contract.qualifications?.verifier_foundation_qualified === true &&
    contract.qualifications?.runner_foundation_qualified === true,
  'Kubernetes verifier and runner foundations are not qualified');
  for (const key of ['fresh_install_qualified', 'upgrade_qualified',
    'rollback_qualified', 'kubernetes_qualified',
    'benchmark_reproduction_qualified', 'release_admitted', 'publishable']) {
    requireValue(contract.qualifications?.[key] === false,
      `static contract must not assert live qualification: ${key}`);
  }
  return contract;
}

function prepareEvidence(evidencePath) {
  const absolute = path.resolve(evidencePath);
  requireValue(!fs.existsSync(absolute),
    `evidence path must be new: ${absolute}`);
  const parent = path.dirname(absolute);
  requireValue(fs.existsSync(parent) && fs.statSync(parent).isDirectory(),
    `evidence parent is absent: ${parent}`);
  fs.mkdirSync(absolute, {mode: 0o700});
  fs.mkdirSync(path.join(absolute, 'raw'), {mode: 0o700});
  fs.mkdirSync(path.join(absolute, 'phases'), {mode: 0o700});
  return absolute;
}

export class CommandExecutor {
  constructor(journalPath) {
    this.journalPath = journalPath;
    this.activeChild = null;
  }

  interrupt(_signal) {
    if (this.activeChild && !this.activeChild.killed) {
      this.activeChild.kill('SIGTERM');
    }
  }

  async run(program, args, options = {}) {
    const startedAt = new Date().toISOString();
    const timeoutMs = options.timeoutMs ?? 10 * 60 * 1000;
    const result = await new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      let outputBytes = 0;
      let timedOut = false;
      const child = spawn(program, args, {
        cwd: options.cwd || root,
        env: options.env || process.env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      this.activeChild = child;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
        setTimeout(() => child.kill('SIGKILL'), 2000).unref();
      }, timeoutMs);
      const collect = (name, chunk) => {
        outputBytes += chunk.length;
        if (outputBytes > maximumOutputBytes) {
          child.kill('SIGTERM');
          reject(new Rejected(`${name} exceeded the command output bound`));
          return;
        }
        if (name === 'stdout') stdout += chunk.toString('utf8');
        else stderr += chunk.toString('utf8');
      };
      child.stdout.on('data', chunk => collect('stdout', chunk));
      child.stderr.on('data', chunk => collect('stderr', chunk));
      child.on('error', error => reject(new Rejected(
        `unable to execute ${program}: ${error.message}`)));
      child.on('close', (status, signal) => {
        clearTimeout(timer);
        this.activeChild = null;
        resolve({
          status: status ?? 1,
          signal,
          stdout,
          stderr,
          timedOut,
        });
      });
      if (options.input !== undefined) child.stdin.end(options.input);
      else child.stdin.end();
    });
    const record = {
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      program,
      arguments: args,
      status: result.status,
      signal: result.signal,
      timed_out: result.timedOut,
    };
    fs.appendFileSync(this.journalPath, `${JSON.stringify(record)}\n`,
      {encoding: 'utf8', mode: 0o600});
    return result;
  }
}

function parseJSONOutput(result, label) {
  try {
    return JSON.parse(result.stdout);
  } catch (error) {
    throw new Rejected(`${label} returned invalid JSON: ${error.message}`);
  }
}

export class KubernetesAcceptance {
  constructor(options, dependencies = {}) {
    this.contractPath = path.resolve(options.contractPath || defaultContractPath);
    this.contract = validateContract(readJSON(this.contractPath,
      'Kubernetes acceptance contract'));
    this.evidencePath = prepareEvidence(options.evidencePath);
    this.executor = dependencies.executor || new CommandExecutor(
      path.join(this.evidencePath, 'raw', 'commands.jsonl'));
    this.sleep = dependencies.sleep ||
      (milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)));
    this.programs = {
      git: options.git || 'git',
      docker: options.docker || 'docker',
      kind: options.kind || 'kind',
      kubectl: options.kubectl || 'kubectl',
      node: options.node || process.execPath,
      tar: options.tar || 'tar',
    };
    this.verifierPath = path.resolve(options.verifierPath || defaultVerifierPath);
    this.confirmation = options.confirmation;
    this.clusterCreated = false;
    this.clusterAbsenceConfirmed = false;
    this.namespaceApplied = false;
    this.previousContext = null;
    this.interruptedBy = null;
    this.phases = [];
    this.source = null;
    this.sourceChecks = [];
    this.images = {};
    this.imageArchives = {};
    this.imageArchiveDirectory = null;
    this.error = null;
    this.teardown = null;
  }

  interrupt(signal) {
    this.interruptedBy = signal;
    this.executor.interrupt?.(signal);
  }

  async command(program, args, label, options = {}) {
    if (this.interruptedBy && !options.cleanup) {
      throw new Rejected(`acceptance interrupted by ${this.interruptedBy}`);
    }
    const result = await this.executor.run(program, args, {
      cwd: root,
      timeoutMs: options.timeoutMs,
      env: options.env,
      input: options.input,
    });
    if (options.capture) {
      writeFile(path.join(this.evidencePath, 'raw', options.capture),
        `${result.stdout}${result.stderr ? `\n--- stderr ---\n${result.stderr}` : ''}`);
    }
    if (this.interruptedBy && !options.cleanup) {
      throw new Rejected(`acceptance interrupted by ${this.interruptedBy}`);
    }
    if (!options.allowFailure && result.status !== 0) {
      const detail = (result.stderr || result.stdout).trim();
      throw new Rejected(`${label} exited ${result.status}${detail ? `: ${detail}` : ''}`);
    }
    return result;
  }

  async kubectl(args, label, options = {}) {
    return this.command(this.programs.kubectl,
      ['--context', this.contract.target.context, ...args], label, options);
  }

  async kubectlJSON(args, label, options = {}) {
    const result = await this.kubectl([...args, '-o', 'json'], label, options);
    if (result.status !== 0) return null;
    return parseJSONOutput(result, label);
  }

  async recordPhase(id, checks, detail = {}) {
    const record = {...phaseRecord(this.contract, id, checks), ...detail};
    this.phases.push(record);
    writeJSON(path.join(this.evidencePath, 'phases', `${id}.json`), record);
  }

  async sourceIdentity() {
    const commitResult = await this.command(this.programs.git,
      ['rev-parse', 'HEAD'], 'source commit');
    const commit = commitResult.stdout.trim();
    requireValue(/^[0-9a-f]{40}$/.test(commit),
      'source commit is not a full lowercase Git commit');
    const statusResult = await this.command(this.programs.git,
      ['status', '--porcelain=v1', '--untracked-files=all'], 'source status');
    requireValue(statusResult.stdout === '',
      'clean source is required for Kubernetes acceptance');
    this.source = {commit, dirty: false, status_sha256: sha256(statusResult.stdout)};
    this.sourceChecks.push({stage: 'initial', commit, dirty: false});
    writeJSON(path.join(this.evidencePath, 'source.json'), this.source);
    writeJSON(path.join(this.evidencePath, 'source-checks.json'), this.sourceChecks);
  }

  async requireStableSource(stage) {
    const commit = (await this.command(this.programs.git,
      ['rev-parse', 'HEAD'], `${stage} source commit`)).stdout.trim();
    const status = (await this.command(this.programs.git,
      ['status', '--porcelain=v1', '--untracked-files=all'],
      `${stage} source status`)).stdout;
    requireValue(commit === this.source?.commit,
      `source commit changed during ${stage}`);
    requireValue(status === '', `source became dirty during ${stage}`);
    this.sourceChecks.push({stage, commit, dirty: false});
    writeJSON(path.join(this.evidencePath, 'source-checks.json'), this.sourceChecks);
  }

  async preflight() {
    requireValue(this.confirmation === this.contract.runner.confirmation,
      `set BONVOYAGE_KUBERNETES_ACCEPTANCE_CONFIRM=${this.contract.runner.confirmation}`);
    await this.sourceIdentity();

    const kindVersion = await this.command(this.programs.kind, ['version'],
      'kind version', {capture: 'kind-version.txt'});
    const kindVersionMatch = kindVersion.stdout.match(
      /^kind\s+(v[0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)/mu);
    requireValue(kindVersionMatch?.[1] === this.contract.runner.kind_version,
      `kind ${this.contract.runner.kind_version} is required`);
    await this.command(this.programs.kubectl, ['version', '--client', '-o', 'json'],
      'kubectl client version', {capture: 'kubectl-version.json'});
    const platform = (await this.command(this.programs.docker,
      ['version', '--format', '{{.Server.Os}}/{{.Server.Arch}}'],
      'Docker server platform', {capture: 'docker-platform.txt'})).stdout.trim();
    requireValue(['linux/amd64', 'linux/arm64'].includes(platform),
      `unsupported Docker server platform: ${platform}`);

    const clusters = (await this.command(this.programs.kind, ['get', 'clusters'],
      'kind cluster inventory')).stdout.split(/\r?\n/u).filter(Boolean);
    requireValue(!clusters.includes(this.contract.runner.cluster_name),
      'dedicated acceptance cluster already exists');
    const contexts = (await this.command(this.programs.kubectl,
      ['config', 'get-contexts', '-o', 'name'], 'Kubernetes context inventory'))
      .stdout.split(/\r?\n/u).filter(Boolean);
    requireValue(!contexts.includes(this.contract.target.context),
      'dedicated acceptance context already exists');
    const previousContext = await this.command(this.programs.kubectl,
      ['config', 'current-context'], 'previous Kubernetes context',
      {allowFailure: true});
    if (previousContext.status === 0) {
      this.previousContext = previousContext.stdout.trim() || null;
    }
    this.clusterAbsenceConfirmed = true;

    await this.buildImages(platform);
    await this.requireStableSource('post-build');
    const creation = await this.command(this.programs.kind, ['create', 'cluster',
      '--name', this.contract.runner.cluster_name,
      '--image', this.contract.runner.kind_node_image,
      '--wait', `${this.contract.runner.cluster_wait_seconds}s`],
    'kind cluster creation', {
      allowFailure: true,
      timeoutMs: (this.contract.runner.cluster_wait_seconds + 60) * 1000,
      capture: 'kind-create.txt',
    });
    if (creation.status !== 0) {
      throw new Rejected(`kind cluster creation exited ${creation.status}`);
    }
    this.clusterCreated = true;
    const currentContext = (await this.command(this.programs.kubectl,
      ['config', 'current-context'], 'active Kubernetes context')).stdout.trim();
    requireValue(currentContext === this.contract.target.context,
      'kind did not activate the dedicated acceptance context');
    const namespace = await this.kubectl(['get', 'namespace',
      this.contract.target.namespace], 'namespace absence', {allowFailure: true});
    requireValue(namespace.status !== 0 && /not[ -]?found/i.test(
      `${namespace.stderr}\n${namespace.stdout}`),
    'acceptance namespace already exists or absence could not be proved');

    for (const [role, archive] of Object.entries(this.imageArchives)) {
      await this.command(this.programs.kind,
        ['load', 'image-archive', archive, '--name',
          this.contract.runner.cluster_name],
        `load ${role} image archive`, {timeoutMs: 5 * 60 * 1000});
    }
    this.cleanupImageArchives();
    await this.recordPhase('preflight', {
      dedicated_context_exact: true,
      namespace_absent: true,
      local_images_exact: true,
    }, {platform, kind_version: this.contract.runner.kind_version,
      node_image: this.contract.runner.kind_node_image, images: this.images});
  }

  async buildImages(platform) {
    const labels = [
      '--label', `org.opencontainers.image.revision=${this.source.commit}`,
      '--label', 'io.routesphere.bonvoyage.source-dirty=false',
    ];
    await this.command(path.join(root, 'scripts', 'build-dataplane-container.sh'),
      [], 'dataplane image build', {
        timeoutMs: 60 * 60 * 1000,
        env: {
          ...process.env,
          BONVOYAGE_BUILD_PLATFORM: platform,
          BONVOYAGE_DATAPLANE_IMAGE: this.contract.runner.images.dataplane,
        },
        capture: 'build-dataplane.txt',
      });
    await this.command(this.programs.docker,
      ['build', '--platform', platform, ...labels,
        '--tag', this.contract.runner.images.snapshot_compiler,
        '--file', 'deploy/docker/control-plane/Dockerfile', '.'],
      'snapshot compiler image build', {
        timeoutMs: 30 * 60 * 1000,
        capture: 'build-snapshot-compiler.txt',
      });
    await this.command(this.programs.docker,
      ['build', '--platform', platform, ...labels,
        '--tag', this.contract.runner.images.upstream,
        '--file', 'deploy/docker/upstream/Dockerfile', 'deploy/docker/upstream'],
      'controlled upstream image build', {
        timeoutMs: 15 * 60 * 1000,
        capture: 'build-upstream.txt',
      });

    this.imageArchiveDirectory = fs.mkdtempSync(path.join(os.tmpdir(),
      'bonvoyage-kubernetes-images-'));
    fs.chmodSync(this.imageArchiveDirectory, 0o700);
    for (const [role, image] of Object.entries(this.contract.runner.images)) {
      const inspected = await this.command(this.programs.docker,
        ['image', 'inspect', image], `${role} image inspection`);
      const documents = parseJSONOutput(inspected, `${role} image inspection`);
      requireValue(Array.isArray(documents) && documents.length === 1,
        `${role} image inspection is ambiguous`);
      const document = documents[0];
      requireValue(document.Config?.Labels?.['org.opencontainers.image.revision'] ===
        this.source.commit, `${role} image source revision differs`);
      requireValue(document.Config?.Labels?.['io.routesphere.bonvoyage.source-dirty'] ===
        'false', `${role} image is not clean-source bound`);
      requireValue(document.RepoTags?.includes(image),
        `${role} image tag is absent after build`);
      const engineID = immutableDigest(document.Id, `${role} Docker image ID`);
      const descriptorDigest = document.Descriptor?.digest || null;
      if (descriptorDigest !== null) {
        immutableDigest(descriptorDigest, `${role} Docker descriptor digest`);
      }
      const archive = path.join(this.imageArchiveDirectory, `${role}.tar`);
      await this.command(this.programs.docker,
        ['image', 'save', '--platform', platform, '--output', archive, image],
        `${role} single-platform image export`, {
          timeoutMs: 15 * 60 * 1000,
        });
      requireValue(fs.existsSync(archive) && fs.statSync(archive).isFile() &&
        fs.statSync(archive).size > 0, `${role} image archive is absent or empty`);
      this.imageArchives[role] = archive;
      this.images[role] = await this.inspectImageArchive(role, image, archive,
        platform, {
          engine_id: engineID,
          engine_descriptor_digest: descriptorDigest,
          engine_descriptor_media_type: document.Descriptor?.mediaType || null,
        });
    }
    writeJSON(path.join(this.evidencePath, 'images.json'), this.images);
  }

  async inspectImageArchive(role, image, archive, platform, engine) {
    const indexResult = await this.command(this.programs.tar,
      ['-xOf', archive, 'index.json'], `${role} OCI archive index`);
    const runtimeRootDigest = immutableDigest(
      `sha256:${sha256(indexResult.stdout)}`,
      `${role} OCI archive root digest`,
    );
    const index = parseJSONOutput(indexResult, `${role} OCI archive index`);
    requireValue(index.schemaVersion === 2 && Array.isArray(index.manifests) &&
      index.manifests.length === 1,
    `${role} archive must contain exactly one OCI platform manifest`);
    const descriptor = index.manifests[0];
    const manifestDigest = immutableDigest(descriptor.digest,
      `${role} runtime manifest digest`);
    requireValue(`${descriptor.platform?.os}/${descriptor.platform?.architecture}` ===
      platform, `${role} archive platform differs from Docker server platform`);
    const runtimeReference = descriptor.annotations?.['io.containerd.image.name'];
    requireValue(typeof runtimeReference === 'string' &&
      runtimeReference.endsWith(image),
    `${role} archive runtime reference does not match its approved tag`);

    const manifestResult = await this.command(this.programs.tar,
      ['-xOf', archive, `blobs/sha256/${manifestDigest.slice(7)}`],
      `${role} OCI platform manifest`);
    requireValue(`sha256:${sha256(manifestResult.stdout)}` === manifestDigest,
      `${role} platform manifest content digest differs`);
    const manifest = parseJSONOutput(manifestResult,
      `${role} OCI platform manifest`);
    requireValue(manifest.schemaVersion === 2 &&
      manifest.mediaType === descriptor.mediaType,
    `${role} platform manifest metadata differs from the archive index`);
    const configDigest = immutableDigest(manifest.config?.digest,
      `${role} image configuration digest`);
    const configResult = await this.command(this.programs.tar,
      ['-xOf', archive, `blobs/sha256/${configDigest.slice(7)}`],
      `${role} OCI image configuration`);
    requireValue(`sha256:${sha256(configResult.stdout)}` === configDigest,
      `${role} image configuration content digest differs`);
    const configuration = parseJSONOutput(configResult,
      `${role} OCI image configuration`);
    requireValue(configuration.config?.Labels?.['org.opencontainers.image.revision'] ===
      this.source.commit, `${role} archive source revision differs`);
    requireValue(configuration.config?.Labels?.['io.routesphere.bonvoyage.source-dirty'] ===
      'false', `${role} archive is not clean-source bound`);

    return {
      name: image,
      platform,
      runtime_reference: runtimeReference,
      runtime_root_digest: runtimeRootDigest,
      platform_manifest_digest: manifestDigest,
      config_digest: configDigest,
      archive_sha256: `sha256:${await sha256File(archive)}`,
      archive_size_bytes: fs.statSync(archive).size,
      ...engine,
    };
  }

  cleanupImageArchives() {
    if (!this.imageArchiveDirectory) return;
    fs.rmSync(this.imageArchiveDirectory, {recursive: true, force: true});
    this.imageArchiveDirectory = null;
    this.imageArchives = {};
  }

  async applyFixture() {
    const fixture = path.resolve(root, this.contract.fixture.path);
    await this.kubectl(['apply', '-k', fixture], 'acceptance fixture apply', {
      timeoutMs: 2 * 60 * 1000,
      capture: 'apply.txt',
    });
    this.namespaceApplied = true;
    await this.kubectl(['-n', this.contract.target.namespace, 'rollout', 'status',
      `deployment/${this.contract.fixture.controlled_upstream_deployment}`,
      `--timeout=${this.contract.runner.rollout_timeout_seconds}s`],
    'controlled upstream rollout', {
      timeoutMs: (this.contract.runner.rollout_timeout_seconds + 15) * 1000,
    });
    await this.waitForGatewayRollout('baseline gateway rollout',
      this.contract.fixture.baseline_config_map);
  }

  async waitForGatewayRollout(label, expectedConfigMap) {
    await this.kubectl(['-n', this.contract.target.namespace,
      'rollout', 'status', `deployment/${this.contract.target.deployment}`,
      `--timeout=${this.contract.runner.rollout_timeout_seconds}s`], label, {
      timeoutMs: (this.contract.runner.rollout_timeout_seconds + 15) * 1000,
    });
    const deadline = Date.now() +
      this.contract.runner.rollout_timeout_seconds * 1000;
    while (Date.now() < deadline) {
      const pods = await this.gatewayPods();
      const items = pods.items || [];
      if (items.length === this.contract.target.replicas && items.every(pod =>
        !pod.metadata?.deletionTimestamp && ready(pod) &&
        selectedConfigMap(pod) === expectedConfigMap)) {
        return;
      }
      await this.sleep(1000);
    }
    throw new Rejected(`${label} did not reach exact pod quiescence`);
  }

  async runVerifier(configMap, capture) {
    const result = await this.command(this.programs.node, [this.verifierPath],
      `deployment verifier for ${configMap}`, {
        timeoutMs: 5 * 60 * 1000,
        env: {
          ...process.env,
          BONVOYAGE_KUBECTL: this.programs.kubectl,
          BONVOYAGE_KUBERNETES_CONTRACT: this.contractPath,
          BONVOYAGE_KUBERNETES_CONTEXT: this.contract.target.context,
          BONVOYAGE_KUBERNETES_EXPECTED_CONFIG_MAP: configMap,
          BONVOYAGE_KUBERNETES_EXPECTED_DATAPLANE_ROOT_DIGEST:
            this.images.dataplane.runtime_root_digest,
          BONVOYAGE_KUBERNETES_EXPECTED_COMPILER_ROOT_DIGEST:
            this.images.snapshot_compiler.runtime_root_digest,
          BONVOYAGE_KUBERNETES_EXPECTED_UPSTREAM_ROOT_DIGEST:
            this.images.upstream.runtime_root_digest,
        },
        capture,
      });
    requireValue(/^status=pass$/mu.test(result.stdout),
      `deployment verifier did not report pass for ${configMap}`);
  }

  async baseline() {
    await this.applyFixture();
    await this.runVerifier(this.contract.fixture.baseline_config_map,
      'verify-baseline.txt');
    await this.recordPhase('baseline', Object.fromEntries(
      this.contract.phases.find(value => value.id === 'baseline')
        .required_checks.map(check => [check, true])));
  }

  async patchConfiguration(configMap) {
    const patch = {
      spec: {template: {
        metadata: {annotations: {'routesphere.io/config-revision': configMap}},
        spec: {volumes: [{name: 'config', configMap: {name: configMap}}]},
      }},
    };
    await this.kubectl(['-n', this.contract.target.namespace, 'patch',
      'deployment', this.contract.target.deployment, '--type=strategic',
      '-p', JSON.stringify(patch)], `select ${configMap}`);
  }

  async replicaSets() {
    return this.kubectlJSON(['-n', this.contract.target.namespace, 'get',
      'replicasets', '-l', gatewaySelector], 'gateway replica sets');
  }

  async upgrade() {
    await this.patchConfiguration(this.contract.fixture.upgrade_config_map);
    await this.waitForGatewayRollout('upgrade gateway rollout',
      this.contract.fixture.upgrade_config_map);
    await this.runVerifier(this.contract.fixture.upgrade_config_map,
      'verify-upgrade.txt');
    const replicaSets = await this.replicaSets();
    const oldSets = replicaSets.items?.filter(item => item.spec?.template?.spec?.volumes
      ?.find(volume => volume.name === 'config')?.configMap?.name ===
      this.contract.fixture.baseline_config_map) || [];
    requireValue(oldSets.length >= 1 && oldSets.every(item =>
      (item.spec?.replicas || 0) === 0),
    'baseline replica set was not scaled down after upgrade');
    await this.recordPhase('upgrade', {
      revisioned_config_selected: true,
      rolling_update_completed: true,
      upgraded_route_exact: true,
      old_replica_set_scaled_down: true,
      automatic_restarts_zero: true,
    });
  }

  async gatewayPods() {
    return this.kubectlJSON(['-n', this.contract.target.namespace, 'get',
      'pods', '-l', gatewaySelector], 'gateway pods');
  }

  async waitForRejectedCandidate() {
    const deadline = Date.now() +
      this.contract.runner.failed_candidate_timeout_seconds * 1000;
    let pods;
    while (Date.now() < deadline) {
      pods = await this.gatewayPods();
      const candidates = pods.items?.filter(pod => selectedConfigMap(pod) ===
        this.contract.fixture.invalid_config_map) || [];
      if (candidates.some(compilerFailed)) return {pods, candidates};
      await this.sleep(1000);
    }
    throw new Rejected('invalid compiler candidate did not reach a failed state');
  }

  async upstreamPodName() {
    const pods = await this.kubectlJSON(['-n', this.contract.target.namespace,
      'get', 'pods', '-l', upstreamSelector], 'controlled upstream pods');
    const pod = pods.items?.find(ready);
    requireValue(pod?.metadata?.name, 'ready controlled upstream pod is absent');
    return pod.metadata.name;
  }

  async probeFromUpstream(podName, route, expected) {
    const url = `http://${this.contract.target.service}.${this.contract.target.namespace}` +
      `.svc.cluster.local${route}`;
    for (let index = 0; index < 10; index += 1) {
      const result = await this.kubectl(['-n', this.contract.target.namespace,
        'exec', podName, '--', 'wget', '-q', '-O', '-', '-T', '10', url],
      `containment traffic ${route}`);
      requireValue(result.stdout === expected,
        `containment traffic body differs for ${route}`);
    }
  }

  async rejectedCandidate() {
    await this.patchConfiguration(this.contract.fixture.invalid_config_map);
    const rollout = await this.kubectl(['-n', this.contract.target.namespace,
      'rollout', 'status', `deployment/${this.contract.target.deployment}`,
      `--timeout=${this.contract.runner.failed_candidate_timeout_seconds}s`],
    'invalid candidate rollout', {
      allowFailure: true,
      timeoutMs: (this.contract.runner.failed_candidate_timeout_seconds + 15) * 1000,
      capture: 'invalid-rollout.txt',
    });
    requireValue(rollout.status !== 0,
      'intentionally invalid configuration unexpectedly completed rollout');
    const {pods, candidates} = await this.waitForRejectedCandidate();
    const healthy = pods.items?.filter(pod =>
      selectedConfigMap(pod) === this.contract.fixture.upgrade_config_map && ready(pod)) || [];
    requireValue(healthy.length === this.contract.target.replicas,
      'healthy upgraded replicas were not preserved');
    requireValue(candidates.length >= 1 && candidates.every(pod => !ready(pod)) &&
      candidates.some(compilerFailed), 'failed candidate became ready or lacks compiler failure');
    const deployment = await this.kubectlJSON(['-n', this.contract.target.namespace,
      'get', 'deployment', this.contract.target.deployment], 'gateway deployment');
    requireValue(deployment.status?.readyReplicas === this.contract.target.replicas &&
      deployment.status?.availableReplicas === this.contract.target.replicas,
    'failed rollout reduced healthy service capacity');

    const upstreamPod = await this.upstreamPodName();
    await this.probeFromUpstream(upstreamPod, '/bonvoyage/ready', 'ready-v2\n');
    await this.probeFromUpstream(upstreamPod, '/healthz', 'ok\n');
    for (const candidate of candidates) {
      const name = candidate.metadata?.name;
      if (!name) continue;
      await this.kubectl(['-n', this.contract.target.namespace, 'logs', name,
        '-c', 'snapshot-compiler'], `${name} compiler log`, {
          allowFailure: true,
          capture: `invalid-compiler-${name}.txt`,
        });
    }
    await this.recordPhase('rejected-candidate', {
      invalid_compiler_init_failed: true,
      healthy_replicas_preserved: true,
      service_traffic_preserved: true,
      failed_candidate_not_promoted: true,
    }, {healthy_pods: healthy.map(pod => pod.metadata.name),
      rejected_pods: candidates.map(pod => pod.metadata.name)});
  }

  async rollback() {
    await this.patchConfiguration(this.contract.fixture.baseline_config_map);
    await this.waitForGatewayRollout('rollback gateway rollout',
      this.contract.fixture.baseline_config_map);
    await this.runVerifier(this.contract.fixture.baseline_config_map,
      'verify-rollback.txt');
    await this.recordPhase('rollback', {
      baseline_config_reselected: true,
      rollback_rollout_completed: true,
      baseline_route_restored: true,
      automatic_restarts_zero: true,
    });
  }

  async diagnostics() {
    if (!this.clusterCreated) return;
    await this.kubectl(['-n', this.contract.target.namespace, 'get',
      'all,poddisruptionbudgets,configmaps,replicasets,pods', '-o', 'yaml'],
    'final Kubernetes inventory', {
      allowFailure: true,
      cleanup: true,
      capture: 'final-kubernetes-inventory.yaml',
    });
    const logDirectory = path.join(this.evidencePath, 'raw', 'kind-logs');
    fs.mkdirSync(logDirectory, {mode: 0o700});
    await this.command(this.programs.kind, ['export', 'logs', logDirectory,
      '--name', this.contract.runner.cluster_name], 'kind log export', {
        allowFailure: true,
        cleanup: true,
        timeoutMs: 5 * 60 * 1000,
        capture: 'kind-export-logs.txt',
      });
  }

  async teardownCluster() {
    if (!this.clusterCreated && this.clusterAbsenceConfirmed) {
      const discovered = await this.command(this.programs.kind,
        ['get', 'clusters'], 'cleanup cluster discovery', {
          allowFailure: true,
          cleanup: true,
        });
      this.clusterCreated = discovered.status === 0 && discovered.stdout
        .split(/\r?\n/u).filter(Boolean)
        .includes(this.contract.runner.cluster_name);
    }
    let namespaceDeleted = !this.namespaceApplied;
    if (this.clusterCreated && this.namespaceApplied) {
      const deletion = await this.kubectl(['delete', 'namespace',
        this.contract.target.namespace, '--wait=false'], 'namespace deletion',
      {allowFailure: true, cleanup: true, capture: 'namespace-delete.txt'});
      if (deletion.status === 0) {
        const wait = await this.kubectl(['wait', '--for=delete',
          `namespace/${this.contract.target.namespace}`, '--timeout=120s'],
        'namespace deletion wait', {
          allowFailure: true,
          cleanup: true,
          timeoutMs: 135000,
        });
        namespaceDeleted = wait.status === 0;
      }
    }
    if (this.clusterCreated) {
      await this.command(this.programs.kind, ['delete', 'cluster',
        '--name', this.contract.runner.cluster_name], 'kind cluster deletion', {
          allowFailure: true,
          cleanup: true,
          timeoutMs: 5 * 60 * 1000,
          capture: 'kind-delete.txt',
        });
    }
    const clusters = await this.command(this.programs.kind, ['get', 'clusters'],
      'post-teardown cluster inventory', {allowFailure: true, cleanup: true});
    const clusterAbsent = clusters.status === 0 && !clusters.stdout
      .split(/\r?\n/u).filter(Boolean).includes(this.contract.runner.cluster_name);
    const checks = {
      namespace_deleted: namespaceDeleted || clusterAbsent,
      acceptance_resources_absent: clusterAbsent,
    };
    let previousContextRestored = true;
    if (this.previousContext && this.previousContext !== this.contract.target.context) {
      const restore = await this.command(this.programs.kubectl,
        ['config', 'use-context', this.previousContext],
        'previous Kubernetes context restoration', {
          allowFailure: true,
          cleanup: true,
          capture: 'context-restore.txt',
        });
      previousContextRestored = restore.status === 0;
    }
    this.teardown = {
      checks,
      previous_context: this.previousContext,
      previous_context_restored: previousContextRestored,
      passed: Object.values(checks).every(Boolean) && previousContextRestored,
    };
    if (this.teardown.passed) {
      await this.recordPhase('teardown', checks);
    } else {
      writeJSON(path.join(this.evidencePath, 'phases', 'teardown.json'), {
        id: 'teardown', checks, passed: false,
      });
    }
  }

  finalize(outcome) {
    const lifecycleQualified = outcome === 'accepted' &&
      this.phases.length === this.contract.phases.length &&
      this.phases.every(phase => phase.passed);
    const summary = {
      schema_version: 2,
      classification: 'routesphere-bonvoyage-oss-kubernetes-acceptance',
      qualification_authority: 'live-run-summary',
      image_identity_domain: 'oci-archive-root-and-platform-graph',
      outcome,
      source: this.source,
      source_checks: this.sourceChecks,
      contract: {
        path: path.relative(root, this.contractPath),
        sha256: sha256(fs.readFileSync(this.contractPath)),
      },
      cluster: {
        name: this.contract.runner.cluster_name,
        context: this.contract.target.context,
        kind_version: this.contract.runner.kind_version,
        node_image: this.contract.runner.kind_node_image,
      },
      images: this.images,
      phases: this.phases,
      teardown: this.teardown,
      error: this.error,
      qualifications: {
        clean_source: this.source?.dirty === false,
        fresh_install_qualified: lifecycleQualified,
        upgrade_qualified: lifecycleQualified,
        rollback_qualified: lifecycleQualified,
        kubernetes_qualified: lifecycleQualified,
        lifecycle_qualified: lifecycleQualified,
        benchmark_reproduction_qualified: false,
        release_admitted: false,
        publishable: false,
      },
    };
    writeJSON(path.join(this.evidencePath, 'summary.json'), summary);
    const files = [];
    const visit = directory => {
      for (const entry of fs.readdirSync(directory, {withFileTypes: true})
        .sort((left, right) => left.name.localeCompare(right.name))) {
        const absolute = path.join(directory, entry.name);
        if (entry.isDirectory()) visit(absolute);
        else if (entry.isFile() && entry.name !== 'checksums.sha256') {
          files.push(absolute);
        }
      }
    };
    visit(this.evidencePath);
    const manifest = files.map(file =>
      `${sha256(fs.readFileSync(file))}  ${path.relative(this.evidencePath, file)}`)
      .join('\n');
    writeFile(path.join(this.evidencePath, 'checksums.sha256'), `${manifest}\n`);
    return summary;
  }

  async run() {
    let outcome = 'rejected';
    try {
      await this.preflight();
      await this.baseline();
      await this.upgrade();
      await this.rejectedCandidate();
      await this.rollback();
      await this.requireStableSource('post-lifecycle');
      outcome = 'accepted';
    } catch (error) {
      this.error = {name: error.name, message: error.message};
    } finally {
      try {
        await this.diagnostics();
      } catch (error) {
        this.error ||= {name: error.name, message: error.message};
      }
      try {
        await this.teardownCluster();
      } catch (error) {
        this.error ||= {name: error.name, message: error.message};
      }
      this.cleanupImageArchives();
    }
    if (!this.teardown?.passed) outcome = 'rejected';
    const summary = this.finalize(outcome);
    if (outcome !== 'accepted') {
      throw new Rejected(this.error?.message || 'Kubernetes acceptance was rejected');
    }
    return summary;
  }
}

function parseArguments(argv) {
  const options = {
    contractPath: defaultContractPath,
    confirmation: process.env.BONVOYAGE_KUBERNETES_ACCEPTANCE_CONFIRM,
    evidencePath: process.env.BONVOYAGE_KUBERNETES_EVIDENCE,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const next = () => {
      index += 1;
      requireValue(index < argv.length, `missing value for ${argument}`);
      return argv[index];
    };
    if (argument === '--evidence') options.evidencePath = next();
    else if (argument === '--contract') options.contractPath = next();
    else if (argument === '--kind') options.kind = next();
    else if (argument === '--kubectl') options.kubectl = next();
    else if (argument === '--docker') options.docker = next();
    else if (argument === '--tar') options.tar = next();
    else throw new Rejected(`unsupported argument: ${argument}`);
  }
  requireValue(options.evidencePath, '--evidence is required');
  return options;
}

async function main() {
  let acceptance;
  try {
    const options = parseArguments(process.argv.slice(2));
    acceptance = new KubernetesAcceptance(options);
    for (const signal of ['SIGINT', 'SIGTERM']) {
      process.once(signal, () => acceptance.interrupt(signal));
    }
    const summary = await acceptance.run();
    console.log(`status=${summary.outcome}`);
    console.log(`evidence=${acceptance.evidencePath}`);
    console.log(`source_commit=${summary.source.commit}`);
    console.log('cluster_deleted=true');
  } catch (error) {
    console.error(`Kubernetes acceptance failed: ${error.message}`);
    if (acceptance) console.error(`Evidence retained at: ${acceptance.evidencePath}`);
    process.exitCode = error instanceof Rejected ? 1 : 2;
  }
}

if (process.argv[1] &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
