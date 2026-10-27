#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';

import {verifyEvidence} from './verify-oss-bounded-benchmark.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const defaultContractPath = path.join(root, 'packaging', 'release', 'benchmark',
  'oss-bounded-benchmark-contract.json');
const maximumOutputBytes = 16 * 1024 * 1024;
const benchmarkLabel = 'io.routesphere.bonvoyage.benchmark-run';

export class Rejected extends Error {}

function requireValue(condition, message) {
  if (!condition) throw new Rejected(message);
}

function stableJSON(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function writeFile(file, value, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), {recursive: true, mode: 0o700});
  fs.writeFileSync(file, value, {mode});
  fs.chmodSync(file, mode);
}

function writeJSON(file, value) {
  writeFile(file, stableJSON(value));
}

function readJSON(file, label) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    throw new Rejected(`${label} is not valid JSON: ${error.message}`);
  }
}

function parseJSON(text, label) {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Rejected(`${label} returned invalid JSON: ${error.message}`);
  }
}

function prepareEvidence(evidencePath) {
  const absolute = path.resolve(evidencePath);
  const parent = path.dirname(absolute);
  requireValue(fs.existsSync(parent) && fs.statSync(parent).isDirectory(),
    `evidence parent is absent: ${parent}`);
  const resolvedRoot = fs.realpathSync(root);
  const resolvedEvidence = path.join(fs.realpathSync(parent), path.basename(absolute));
  const relative = path.relative(resolvedRoot, resolvedEvidence);
  requireValue(relative.startsWith(`..${path.sep}`) || relative === '..' ||
    path.isAbsolute(relative),
  'evidence must be created outside the source worktree');
  requireValue(!fs.existsSync(absolute), `evidence path must be new: ${absolute}`);
  fs.mkdirSync(path.join(absolute, 'raw'), {recursive: true, mode: 0o700});
  return absolute;
}

function validateContract(contract) {
  requireValue(contract.schema_version === 1 && contract.classification ===
    'routesphere-bonvoyage-oss-bounded-benchmark-contract',
  'unsupported bounded benchmark contract');
  requireValue(contract.workload?.protocol === 'http1' &&
    contract.workload?.method === 'GET' &&
    /^\/[A-Za-z0-9/_-]+$/.test(contract.workload?.path || ''),
  'unsupported bounded benchmark workload');
  for (const field of ['warmup_seconds', 'measurement_seconds', 'repetitions',
    'concurrency']) {
    requireValue(Number.isSafeInteger(contract.workload[field]) &&
      contract.workload[field] > 0, `contract workload ${field} is invalid`);
  }
  requireValue(/^ghcr\.io\/hatoo\/oha@sha256:[0-9a-f]{64}$/.test(
    contract.load_generator?.image || ''), 'load-generator image is not pinned');
  requireValue(contract.load_generator.wait_ongoing_requests_after_deadline === true,
    'load generator must wait for in-flight requests');
  requireValue(contract.runner?.compose_file === 'deploy/compose/local.yml' &&
    contract.runner?.compose_project === 'bonvoyage-local',
  'unsupported local Compose identity');
  requireValue(/^[a-z0-9][a-z0-9-]*$/.test(contract.runner.container_prefix || ''),
    'runner container prefix is invalid');
  return contract;
}

function normalizeDockerArchitecture(value) {
  const normalized = {
    amd64: 'amd64',
    x86_64: 'amd64',
    arm64: 'arm64',
    aarch64: 'arm64',
  }[value];
  requireValue(normalized,
    `unsupported Docker server architecture: ${value}`);
  return normalized;
}

export class CommandExecutor {
  constructor(journalPath) {
    this.journalPath = journalPath;
    this.activeChild = null;
  }

  interrupt() {
    if (this.activeChild && !this.activeChild.killed) {
      this.activeChild.kill('SIGTERM');
    }
  }

  async run(program, args, options = {}) {
    const startedAt = new Date().toISOString();
    const timeoutMs = options.timeoutMs ?? 120000;
    const result = await new Promise((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      let outputBytes = 0;
      let timedOut = false;
      let settled = false;
      const child = spawn(program, args, {
        cwd: options.cwd || root,
        env: options.env || process.env,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      this.activeChild = child;
      const fail = error => {
        if (settled) return;
        settled = true;
        reject(error);
      };
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
        setTimeout(() => child.kill('SIGKILL'), 2000).unref();
      }, timeoutMs);
      const collect = (stream, chunk) => {
        outputBytes += chunk.length;
        if (outputBytes > maximumOutputBytes) {
          child.kill('SIGTERM');
          fail(new Rejected(`${program} exceeded the command output bound`));
          return;
        }
        if (stream === 'stdout') stdout += chunk.toString('utf8');
        else stderr += chunk.toString('utf8');
      };
      child.stdout.on('data', chunk => collect('stdout', chunk));
      child.stderr.on('data', chunk => collect('stderr', chunk));
      child.on('error', error => fail(new Rejected(
        `unable to execute ${program}: ${error.message}`)));
      child.on('close', (status, signal) => {
        clearTimeout(timer);
        this.activeChild = null;
        if (settled) return;
        settled = true;
        resolve({status: status ?? 1, signal, stdout, stderr, timedOut});
      });
    });
    fs.appendFileSync(this.journalPath, `${JSON.stringify({
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      program,
      arguments: args,
      status: result.status,
      signal: result.signal,
      timed_out: result.timedOut,
    })}\n`, {encoding: 'utf8', mode: 0o600});
    return result;
  }
}

async function rawHTTPProbe({host, port, requestPath, timeoutMs}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    let settled = false;
    const socket = net.createConnection({host, port});
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) reject(error);
      else resolve(value);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => socket.write(
      `GET ${requestPath} HTTP/1.1\r\nHost: bonvoyage.local\r\nConnection: close\r\n\r\n`));
    socket.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > 1024 * 1024) {
        finish(new Rejected('response probe exceeded one MiB'));
      } else chunks.push(chunk);
    });
    socket.once('timeout', () => finish(new Rejected('response probe timed out')));
    socket.once('error', error => finish(new Rejected(
      `response probe failed: ${error.message}`)));
    socket.once('end', () => finish(null, Buffer.concat(chunks)));
  });
}

async function fetchText(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {signal: controller.signal});
    requireValue(response.ok, `metrics endpoint returned HTTP ${response.status}`);
    const value = await response.text();
    requireValue(Buffer.byteLength(value) <= maximumOutputBytes,
      'metrics response exceeded the output bound');
    return value;
  } catch (error) {
    if (error instanceof Rejected) throw error;
    throw new Rejected(`metrics capture failed: ${error.message}`);
  } finally {
    clearTimeout(timer);
  }
}

function parseMemoryBytes(value) {
  const match = String(value).trim().match(
    /^([0-9]+(?:\.[0-9]+)?)\s*(B|kB|KB|KiB|MB|MiB|GB|GiB|TB|TiB)$/);
  requireValue(match, `unsupported Docker memory value: ${value}`);
  const scale = {
    B: 1,
    kB: 1000,
    KB: 1000,
    KiB: 1024,
    MB: 1000 ** 2,
    MiB: 1024 ** 2,
    GB: 1000 ** 3,
    GiB: 1024 ** 3,
    TB: 1000 ** 4,
    TiB: 1024 ** 4,
  }[match[2]];
  const result = Math.round(Number(match[1]) * scale);
  requireValue(Number.isSafeInteger(result), 'Docker memory value exceeds integer range');
  return result;
}

function metricValue(document, metric) {
  let found = false;
  let sum = 0;
  for (const line of document.split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const match = line.match(
      /^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{[^}]*\})?\s+([^\s]+)(?:\s+\d+)?$/);
    if (!match || match[1] !== metric) continue;
    const value = Number(match[2]);
    requireValue(Number.isFinite(value) && value >= 0,
      `${metric} contains an invalid sample`);
    found = true;
    sum += value;
  }
  requireValue(found, `required metric is absent: ${metric}`);
  return sum;
}

function countDistribution(value, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`);
  const result = new Map();
  for (const [name, count] of Object.entries(value)) {
    requireValue(Number.isSafeInteger(count) && count >= 0,
      `${label}.${name} is invalid`);
    result.set(name, count);
  }
  return result;
}

function deriveOha(raw, contract, minimumDuration, label) {
  const duration = raw?.summary?.total;
  requireValue(typeof duration === 'number' && Number.isFinite(duration) &&
    duration >= minimumDuration, `${label} duration is invalid`);
  const statuses = countDistribution(raw.statusCodeDistribution,
    `${label} status distribution`);
  const errors = countDistribution(raw.errorDistribution,
    `${label} error distribution`);
  const accepted = statuses.get(String(contract.workload.accepted_status)) || 0;
  const completed = [...statuses.values()].reduce((sum, value) => sum + value, 0);
  const deadline = errors.get('aborted due to deadline') || 0;
  requireValue(deadline <= contract.workload.concurrency,
    `${label} deadline cancellations exceed concurrency`);
  let transport = 0;
  for (const [name, count] of errors) {
    if (name !== 'aborted due to deadline') transport += count;
  }
  const measured = completed + transport;
  requireValue(measured > 0 && accepted > 0, `${label} has no accepted requests`);
  const latency = {
    p50: Number(raw.latencyPercentiles?.p50) * 1000,
    p95: Number(raw.latencyPercentiles?.p95) * 1000,
    p99: Number(raw.latencyPercentiles?.p99) * 1000,
    p999: Number(raw.latencyPercentiles?.['p99.9']) * 1000,
    max: Number(raw.summary?.slowest) * 1000,
  };
  requireValue(Object.values(latency).every(value => Number.isFinite(value) &&
    value >= 0), `${label} latency is invalid`);
  return {
    accepted_http_responses: accepted,
    completed_http_responses: completed,
    http_failures: completed - accepted,
    transport_failures: transport,
    deadline_end_cancellations: deadline,
    measured_requests: measured,
    duration_seconds: duration,
    successful_rps: accepted / duration,
    error_rate: (measured - accepted) / measured,
    latency_ms: latency,
  };
}

function summarizeResources(samples, requiredRoles) {
  const sampleCounts = {};
  const averageCPU = {};
  const peakMemory = {};
  for (const role of requiredRoles) {
    const selected = samples.filter(sample => sample.role === role);
    sampleCounts[role] = selected.length;
    averageCPU[role] = selected.reduce((sum, sample) =>
      sum + sample.cpu_percent, 0) / selected.length;
    peakMemory[role] = Math.max(...selected.map(sample => sample.memory_bytes));
  }
  return {
    sample_counts: sampleCounts,
    average_cpu_percent: averageCPU,
    peak_memory_bytes: peakMemory,
  };
}

function median(values) {
  const ordered = [...values].sort((left, right) => left - right);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2 ? ordered[middle] :
    (ordered[middle - 1] + ordered[middle]) / 2;
}

function aggregate(repetitions) {
  const rates = repetitions.map(value => value.successful_rps);
  const latency = field => median(repetitions.map(value => value.latency_ms[field]));
  return {
    valid_repetitions: repetitions.length,
    minimum_successful_rps: Math.min(...rates),
    median_successful_rps: median(rates),
    maximum_successful_rps: Math.max(...rates),
    median_latency_ms: {
      p50: latency('p50'),
      p95: latency('p95'),
      p99: latency('p99'),
      p999: latency('p999'),
      max: latency('max'),
    },
  };
}

function validateProbe(raw, workload) {
  const separator = raw.indexOf(Buffer.from('\r\n\r\n'));
  requireValue(separator > 0, 'response probe lacks an HTTP header boundary');
  const header = raw.subarray(0, separator).toString('latin1');
  requireValue(/^HTTP\/1\.1 200(?:\s|$)/.test(header.split('\r\n')[0]),
    'response probe did not return HTTP 200');
  const body = raw.subarray(separator + 4);
  requireValue(body.length === workload.response_bytes,
    'response probe body length differs');
  requireValue(sha256(body) === workload.response_sha256,
    'response probe body digest differs');
}

export class BoundedBenchmarkRunner {
  constructor(options, dependencies = {}) {
    this.contractPath = path.resolve(options.contractPath || defaultContractPath);
    this.contract = validateContract(readJSON(this.contractPath,
      'bounded benchmark contract'));
    this.evidencePath = prepareEvidence(options.evidencePath);
    this.executor = dependencies.executor || new CommandExecutor(path.join(
      this.evidencePath, this.contract.evidence.command_journal));
    this.sleep = dependencies.sleep ||
      (milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)));
    this.probe = dependencies.probe || rawHTTPProbe;
    this.fetchText = dependencies.fetchText || fetchText;
    this.programs = {git: options.git || 'git', docker: options.docker || 'docker'};
    this.runId = dependencies.runId || crypto.randomBytes(6).toString('hex');
    this.ownedContainers = new Set();
    this.interruptedBy = null;
    this.source = null;
    this.roles = null;
    this.roleDocuments = null;
    this.network = null;
    this.loadGeneratorImage = null;
    this.environment = null;
  }

  interrupt(signal) {
    this.interruptedBy = signal;
    this.executor.interrupt?.(signal);
  }

  async command(program, args, label, options = {}) {
    if (this.interruptedBy && !options.cleanup) {
      throw new Rejected(`benchmark interrupted by ${this.interruptedBy}`);
    }
    const result = await this.executor.run(program, args, {
      cwd: root,
      timeoutMs: options.timeoutMs ||
        this.contract.runner.maximum_command_seconds * 1000,
    });
    if (this.interruptedBy && !options.cleanup) {
      throw new Rejected(`benchmark interrupted by ${this.interruptedBy}`);
    }
    if (!options.allowFailure && result.status !== 0) {
      const detail = (result.stderr || result.stdout).trim();
      throw new Rejected(`${label} exited ${result.status}${detail ? `: ${detail}` : ''}`);
    }
    return result;
  }

  async docker(args, label, options = {}) {
    return this.command(this.programs.docker, args, label, options);
  }

  async sourceIdentity() {
    const commit = (await this.command(this.programs.git,
      ['rev-parse', 'HEAD'], 'source commit')).stdout.trim();
    requireValue(/^[0-9a-f]{40}$/.test(commit),
      'source commit is not a full lowercase Git commit');
    const status = (await this.command(this.programs.git,
      ['status', '--porcelain=v1', '--untracked-files=all'], 'source status')).stdout;
    requireValue(status === '', 'clean source is required for bounded benchmark');
    this.source = {commit, dirty: false};
  }

  async requireStableSource(stage) {
    const commit = (await this.command(this.programs.git,
      ['rev-parse', 'HEAD'], `${stage} source commit`)).stdout.trim();
    const status = (await this.command(this.programs.git,
      ['status', '--porcelain=v1', '--untracked-files=all'],
      `${stage} source status`)).stdout;
    requireValue(commit === this.source.commit, `source commit changed during ${stage}`);
    requireValue(status === '', `source became dirty during ${stage}`);
  }

  composeArguments(service) {
    return ['compose', '--project-name', this.contract.runner.compose_project,
      '--file', this.contract.runner.compose_file, 'ps', '--all', '--quiet', service];
  }

  async serviceID(service) {
    const result = await this.docker(this.composeArguments(service),
      `${service} Compose discovery`);
    const identities = result.stdout.split(/\r?\n/).filter(Boolean);
    requireValue(identities.length === 1 && /^[0-9a-f]{12,64}$/.test(identities[0]),
      `${service} Compose role is absent or ambiguous`);
    return identities[0];
  }

  async inspect(reference, label, options = {}) {
    const result = await this.docker(['inspect', reference], label, options);
    if (result.status !== 0) return null;
    const documents = parseJSON(result.stdout, label);
    requireValue(Array.isArray(documents) && documents.length === 1,
      `${label} is ambiguous`);
    return documents[0];
  }

  validateRole(document, service) {
    requireValue(/^[0-9a-f]{64}$/.test(document?.Id || '') &&
      /^sha256:[0-9a-f]{64}$/.test(document?.Image || ''),
    `${service} immutable identity is invalid`);
    const labels = document.Config?.Labels || {};
    requireValue(labels['com.docker.compose.project'] ===
      this.contract.runner.compose_project &&
      labels['com.docker.compose.service'] === service,
    `${service} does not belong to the contracted Compose role`);
    requireValue(document.State?.Status === 'running' &&
      document.State?.Running === true && document.RestartCount === 0,
    `${service} is not running without restarts`);
    if (service === this.contract.runner.upstream_service) {
      requireValue(document.State?.Health?.Status === 'healthy',
        'upstream Compose role is not healthy');
    }
    return document;
  }

  async discoverRoles() {
    const gatewayID = await this.serviceID(this.contract.runner.gateway_service);
    const upstreamID = await this.serviceID(this.contract.runner.upstream_service);
    const gateway = this.validateRole(await this.inspect(gatewayID,
      'gateway inspection'), this.contract.runner.gateway_service);
    const upstream = this.validateRole(await this.inspect(upstreamID,
      'upstream inspection'), this.contract.runner.upstream_service);
    const gatewayNetworks = Object.keys(gateway.NetworkSettings?.Networks || {});
    const upstreamNetworks = new Set(Object.keys(upstream.NetworkSettings?.Networks || {}));
    const shared = gatewayNetworks.filter(value => upstreamNetworks.has(value));
    requireValue(shared.length === 1, 'gateway and upstream need exactly one shared network');
    this.network = shared[0];
    this.roleDocuments = {gateway, upstream};
  }

  async discoverLoadGenerator() {
    let inspection = await this.docker(['image', 'inspect',
      this.contract.load_generator.image], 'load-generator image inspection',
    {allowFailure: true});
    if (inspection.status !== 0) {
      await this.docker(['pull', this.contract.load_generator.image],
        'load-generator image pull', {timeoutMs: 10 * 60 * 1000});
      inspection = await this.docker(['image', 'inspect',
        this.contract.load_generator.image], 'load-generator image inspection');
    }
    const documents = parseJSON(inspection.stdout, 'load-generator image inspection');
    requireValue(Array.isArray(documents) && documents.length === 1 &&
      /^sha256:[0-9a-f]{64}$/.test(documents[0]?.Id || ''),
    'load-generator image identity is invalid');
    this.loadGeneratorImage = documents[0].Id;
  }

  async preflight() {
    await this.sourceIdentity();
    const infoResult = await this.docker(['info', '--format', '{{json .}}'],
      'Docker server information');
    const info = parseJSON(infoResult.stdout, 'Docker server information');
    requireValue(info.OSType === 'linux', 'a Linux Docker server is required');
    const serverArchitecture = normalizeDockerArchitecture(info.Architecture);
    await this.discoverRoles();
    await this.discoverLoadGenerator();
    this.roles = {
      schema_version: 1,
      gateway: {service: this.contract.runner.gateway_service,
        container_id: this.roleDocuments.gateway.Id,
        image_id: this.roleDocuments.gateway.Image},
      upstream: {service: this.contract.runner.upstream_service,
        container_id: this.roleDocuments.upstream.Id,
        image_id: this.roleDocuments.upstream.Image},
      'load-generator': {image_reference: this.contract.load_generator.image,
        image_id: this.loadGeneratorImage},
    };
    this.environment = {
      schema_version: 1,
      evidence_class: this.contract.evidence_class,
      source: this.source,
      host: {os: os.platform(), release: os.release(), architecture: os.arch()},
      docker: {
        server_version: info.ServerVersion,
        server_architecture: serverArchitecture,
        logical_cpus: info.NCPU,
        total_memory_bytes: info.MemTotal,
        operating_system: info.OperatingSystem,
        kernel_version: info.KernelVersion,
      },
      topology: {single_host: true, shared_kernel: true,
        roles: ['gateway', 'load-generator', 'upstream'], network: this.network},
    };
    writeJSON(path.join(this.evidencePath, this.contract.evidence.environment),
      this.environment);
    writeJSON(path.join(this.evidencePath, this.contract.evidence.roles), this.roles);
    const response = await this.probe({
      host: this.contract.runner.gateway_probe_host,
      port: this.contract.runner.gateway_probe_port,
      requestPath: this.contract.workload.path,
      timeoutMs: 10000,
    });
    validateProbe(response, this.contract.workload);
    writeFile(path.join(this.evidencePath, this.contract.evidence.response_probe),
      response);
    await this.requireStableSource('post-preflight');
  }

  containerName(repetition, phase) {
    return `${this.contract.runner.container_prefix}-${this.runId}-r${repetition}-${phase}`;
  }

  async ensureContainerAbsent(name) {
    const existing = await this.inspect(name, `${name} collision check`,
      {allowFailure: true});
    requireValue(existing === null, `runner container already exists: ${name}`);
  }

  async startLoad(name, seconds) {
    await this.ensureContainerAbsent(name);
    this.ownedContainers.add(name);
    const url = `http://${this.contract.runner.gateway_service}:8080` +
      this.contract.workload.path;
    const result = await this.docker(['run', '--detach', '--name', name,
      '--label', `${benchmarkLabel}=${this.runId}`,
      '--network', this.network, this.contract.load_generator.image,
      '-z', `${seconds}s`, '-c', String(this.contract.workload.concurrency),
      '--wait-ongoing-requests-after-deadline', '--no-tui', '--no-color',
      '--disable-compression', '--http-version', '1.1', '--output-format', 'json',
      url], `${name} launch`);
    const identity = result.stdout.trim();
    requireValue(/^[0-9a-f]{64}$/.test(identity),
      `${name} did not return a full container identity`);
    const document = await this.inspect(name, `${name} startup inspection`);
    requireValue(document.Id === identity && document.Image === this.loadGeneratorImage &&
      document.Config?.Labels?.[benchmarkLabel] === this.runId,
    `${name} immutable identity differs from the launch`);
    return document;
  }

  async waitForLoad(name) {
    const deadline = Date.now() +
      this.contract.runner.maximum_command_seconds * 1000;
    while (Date.now() < deadline) {
      const document = await this.inspect(name, `${name} state inspection`);
      requireValue(document, `${name} disappeared before evidence capture`);
      if (!document.State?.Running) return document;
      await this.sleep(250);
    }
    throw new Rejected(`${name} exceeded the runtime bound`);
  }

  async collectOutput(name, file) {
    const document = await this.waitForLoad(name);
    requireValue(document.State?.Status === 'exited' &&
      document.State?.ExitCode === 0, `${name} did not exit successfully`);
    const logs = await this.docker(['logs', name], `${name} output capture`);
    requireValue(logs.stderr === '', `${name} emitted unexpected standard error`);
    writeFile(file, logs.stdout);
    return document;
  }

  async removeOwned(name, cleanup = false) {
    if (!this.ownedContainers.has(name)) return;
    const document = await this.inspect(name, `${name} cleanup inspection`,
      {allowFailure: true, cleanup});
    if (!document) {
      this.ownedContainers.delete(name);
      return;
    }
    requireValue(document.Config?.Labels?.[benchmarkLabel] === this.runId,
      `refusing to remove container not owned by this run: ${name}`);
    await this.docker(['rm', '--force', name], `${name} cleanup`,
      {allowFailure: cleanup, cleanup});
    const remaining = await this.inspect(name, `${name} cleanup verification`,
      {allowFailure: true, cleanup});
    requireValue(remaining === null, `owned container remains after cleanup: ${name}`);
    this.ownedContainers.delete(name);
  }

  async captureMetrics(relative) {
    const value = await this.fetchText(this.contract.runner.metrics_url, 10000);
    writeFile(path.join(this.evidencePath, relative), value);
    return value;
  }

  async runtimeRoles() {
    const gatewayID = await this.serviceID(this.contract.runner.gateway_service);
    const upstreamID = await this.serviceID(this.contract.runner.upstream_service);
    requireValue(gatewayID === this.roles.gateway.container_id &&
      upstreamID === this.roles.upstream.container_id,
    'a Compose role changed identity during the benchmark');
    const gateway = this.validateRole(await this.inspect(gatewayID,
      'gateway runtime inspection'), this.contract.runner.gateway_service);
    const upstream = this.validateRole(await this.inspect(upstreamID,
      'upstream runtime inspection'), this.contract.runner.upstream_service);
    return {gateway, upstream};
  }

  async statsSample(name, identity) {
    const roleNames = {
      gateway: this.roleDocuments.gateway.Name.replace(/^\//, ''),
      upstream: this.roleDocuments.upstream.Name.replace(/^\//, ''),
      'load-generator': name,
    };
    const result = await this.docker(['stats', '--no-stream', '--format',
      '{{json .}}', this.roles.gateway.container_id, this.roles.upstream.container_id,
      identity], `${name} resource sample`, {allowFailure: true});
    if (result.status !== 0) return [];
    const byName = new Map();
    for (const line of result.stdout.split(/\r?\n/).filter(Boolean)) {
      const value = parseJSON(line, `${name} Docker stats`);
      byName.set(value.Name, value);
    }
    const capturedAt = new Date().toISOString();
    const identities = {
      gateway: this.roles.gateway.container_id,
      upstream: this.roles.upstream.container_id,
      'load-generator': identity,
    };
    if (!Object.values(roleNames).every(value => byName.has(value))) return [];
    return Object.entries(roleNames).map(([role, containerName]) => {
      const value = byName.get(containerName);
      const cpu = Number(String(value.CPUPerc).replace(/%$/, ''));
      requireValue(Number.isFinite(cpu) && cpu >= 0,
        `${role} Docker CPU sample is invalid`);
      return {captured_at: capturedAt, role, container_id: identities[role],
        cpu_percent: cpu,
        memory_bytes: parseMemoryBytes(String(value.MemUsage).split(' / ')[0])};
    });
  }

  async sampleMeasurement(name, identity) {
    const samples = [];
    const deadline = Date.now() +
      this.contract.runner.maximum_command_seconds * 1000;
    while (Date.now() < deadline) {
      const document = await this.inspect(name, `${name} state inspection`);
      requireValue(document, `${name} disappeared during measurement`);
      if (!document.State?.Running) return {document, samples};
      samples.push(...await this.statsSample(name, identity));
      await this.sleep(this.contract.runner.resource_sample_interval_ms);
    }
    throw new Rejected(`${name} exceeded the measurement runtime bound`);
  }

  deriveCounters(before, after, measured) {
    const result = {
      requests: metricValue(after,
        'bonvoyage_bonvoyage_gateway_requests_total') - metricValue(before,
        'bonvoyage_bonvoyage_gateway_requests_total'),
      responses_2xx: metricValue(after,
        'bonvoyage_bonvoyage_gateway_responses_2xx_total') - metricValue(before,
        'bonvoyage_bonvoyage_gateway_responses_2xx_total'),
      upstream_selections: metricValue(after,
        'bonvoyage_bonvoyage_gateway_upstream_endpoint_selections_total') -
        metricValue(before,
          'bonvoyage_bonvoyage_gateway_upstream_endpoint_selections_total'),
    };
    requireValue(result.requests === measured.completed_http_responses &&
      result.responses_2xx === measured.accepted_http_responses &&
      result.upstream_selections === measured.accepted_http_responses,
    'gateway counters differ from completed client responses');
    for (const metric of this.contract.acceptance.zero_counters) {
      requireValue(metricValue(before, metric) === 0 &&
        metricValue(after, metric) === 0, `${metric} is non-zero`);
    }
    return result;
  }

  async warmup(repetition) {
    const name = this.containerName(repetition, 'warmup');
    await this.startLoad(name, this.contract.workload.warmup_seconds);
    const template = this.contract.evidence.repetition_files.warmup;
    const relative = template.replace('%02d', String(repetition).padStart(2, '0'));
    await this.collectOutput(name, path.join(this.evidencePath, relative));
    await this.removeOwned(name);
    const derived = deriveOha(readJSON(path.join(this.evidencePath, relative),
      `repetition ${repetition} warmup`), this.contract,
    this.contract.workload.warmup_seconds, `repetition ${repetition} warmup`);
    requireValue(derived.error_rate === 0, `repetition ${repetition} warmup failed`);
  }

  async measurement(repetition) {
    const files = Object.fromEntries(Object.entries(
      this.contract.evidence.repetition_files).map(([name, template]) => [name,
      template.replace('%02d', String(repetition).padStart(2, '0'))]));
    const beforeRoles = await this.runtimeRoles();
    const metricsBefore = await this.captureMetrics(files.metrics_before);
    const name = this.containerName(repetition, 'measurement');
    const started = await this.startLoad(name,
      this.contract.workload.measurement_seconds);
    const sampled = await this.sampleMeasurement(name, started.Id);
    requireValue(sampled.document.State?.Status === 'exited' &&
      sampled.document.State?.ExitCode === 0,
    `repetition ${repetition} load generator did not exit successfully`);
    const logs = await this.docker(['logs', name], `${name} output capture`);
    requireValue(logs.stderr === '', `${name} emitted unexpected standard error`);
    writeFile(path.join(this.evidencePath, files.oha), logs.stdout);
    const metricsAfter = await this.captureMetrics(files.metrics_after);
    const afterRoles = await this.runtimeRoles();
    const runtime = {
      schema_version: 1,
      gateway: {container_id: beforeRoles.gateway.Id,
        image_id: beforeRoles.gateway.Image,
        status_before: beforeRoles.gateway.State.Status,
        status_after: afterRoles.gateway.State.Status,
        restart_count_before: beforeRoles.gateway.RestartCount,
        restart_count_after: afterRoles.gateway.RestartCount},
      upstream: {container_id: beforeRoles.upstream.Id,
        image_id: beforeRoles.upstream.Image,
        status_before: beforeRoles.upstream.State.Status,
        status_after: afterRoles.upstream.State.Status,
        restart_count_before: beforeRoles.upstream.RestartCount,
        restart_count_after: afterRoles.upstream.RestartCount},
      'load-generator': {container_id: started.Id,
        image_id: started.Image, exit_code: sampled.document.State.ExitCode},
    };
    writeJSON(path.join(this.evidencePath, files.runtime), runtime);
    writeFile(path.join(this.evidencePath, files.resources),
      `${sampled.samples.map(value => JSON.stringify(value)).join('\n')}\n`);
    await this.removeOwned(name);

    const derived = deriveOha(readJSON(path.join(this.evidencePath, files.oha),
      `repetition ${repetition} measurement`), this.contract,
    this.contract.workload.measurement_seconds,
    `repetition ${repetition} measurement`);
    requireValue(derived.error_rate === 0,
      `repetition ${repetition} exceeded the error budget`);
    const resources = summarizeResources(sampled.samples,
      this.contract.acceptance.required_resource_roles);
    for (const [role, count] of Object.entries(resources.sample_counts)) {
      requireValue(count >= this.contract.acceptance.minimum_resource_samples_per_role,
        `repetition ${repetition} ${role} has too few resource samples`);
    }
    return {repetition, ...derived,
      counters: this.deriveCounters(metricsBefore, metricsAfter, derived), resources};
  }

  seal() {
    const relativeManifest = this.contract.evidence.checksum_manifest;
    const files = [];
    const visit = (directory, relative = '') => {
      for (const entry of fs.readdirSync(directory, {withFileTypes: true})
        .sort((left, right) => left.name.localeCompare(right.name))) {
        const childRelative = relative ? `${relative}/${entry.name}` : entry.name;
        const absolute = path.join(directory, entry.name);
        if (entry.isDirectory()) visit(absolute, childRelative);
        else if (entry.isFile() && childRelative !== relativeManifest) {
          files.push(childRelative);
        }
      }
    };
    visit(this.evidencePath);
    writeFile(path.join(this.evidencePath, relativeManifest),
      `${files.sort().map(file => `${sha256(fs.readFileSync(
        path.join(this.evidencePath, file)))}  ${file}`).join('\n')}\n`);
  }

  async cleanup() {
    const failures = [];
    for (const name of [...this.ownedContainers]) {
      try {
        await this.removeOwned(name, true);
      } catch (error) {
        failures.push(error.message);
      }
    }
    requireValue(failures.length === 0,
      `owned container cleanup failed: ${failures.join('; ')}`);
  }

  async run() {
    try {
      await this.preflight();
      const repetitions = [];
      for (let repetition = 1; repetition <= this.contract.workload.repetitions;
        repetition += 1) {
        await this.warmup(repetition);
        repetitions.push(await this.measurement(repetition));
      }
      await this.requireStableSource('post-benchmark');
      requireValue(this.ownedContainers.size === 0,
        'runner-owned containers remain before evidence sealing');
      const environmentPath = path.join(this.evidencePath,
        this.contract.evidence.environment);
      const rolesPath = path.join(this.evidencePath, this.contract.evidence.roles);
      const summary = {
        schema_version: 1,
        classification: 'routesphere-bonvoyage-oss-bounded-benchmark-result',
        status: 'candidate',
        contract_sha256: sha256(fs.readFileSync(this.contractPath)),
        evidence_class: this.contract.evidence_class,
        source: this.source,
        environment_sha256: sha256(fs.readFileSync(environmentPath)),
        roles_sha256: sha256(fs.readFileSync(rolesPath)),
        workload: this.contract.workload,
        repetitions,
        aggregate: aggregate(repetitions),
        claim_boundary: this.contract.claim_boundary,
        qualifications: this.contract.qualifications,
      };
      writeJSON(path.join(this.evidencePath, this.contract.evidence.summary), summary);
      this.seal();
      const verification = verifyEvidence(this.contractPath, this.evidencePath);
      return {summary, verification};
    } catch (error) {
      let failure = error;
      try {
        await this.cleanup();
      } catch (cleanupError) {
        failure = new Rejected(`${error.message}; ${cleanupError.message}`);
      }
      const manifest = path.join(this.evidencePath,
        this.contract.evidence.checksum_manifest);
      if (fs.existsSync(manifest)) fs.rmSync(manifest);
      writeJSON(path.join(this.evidencePath, 'failure.json'), {
        schema_version: 1,
        status: 'rejected',
        failed_at: new Date().toISOString(),
        error: {name: failure.name, message: failure.message},
      });
      throw failure;
    }
  }
}

function parseArguments(argv) {
  const options = {
    contractPath: defaultContractPath,
    evidencePath: process.env.BONVOYAGE_BOUNDED_BENCHMARK_EVIDENCE,
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
    else if (argument === '--docker') options.docker = next();
    else if (argument === '--git') options.git = next();
    else throw new Rejected(`unsupported argument: ${argument}`);
  }
  requireValue(options.evidencePath, '--evidence is required');
  return options;
}

async function main() {
  let runner;
  try {
    runner = new BoundedBenchmarkRunner(parseArguments(process.argv.slice(2)));
    for (const signal of ['SIGINT', 'SIGTERM']) {
      process.once(signal, () => runner.interrupt(signal));
    }
    const result = await runner.run();
    console.log('status=accepted');
    console.log(`evidence=${runner.evidencePath}`);
    console.log(`source_commit=${result.verification.source_commit}`);
    console.log(`median_successful_rps=${result.verification.median_successful_rps}`);
    console.log(`p95_ms=${result.verification.median_latency_ms.p95}`);
    console.log(`p99_ms=${result.verification.median_latency_ms.p99}`);
  } catch (error) {
    console.error(`bounded benchmark failed: ${error.message}`);
    if (runner) console.error(`Evidence retained at: ${runner.evidencePath}`);
    process.exitCode = error instanceof Rejected ? 1 : 2;
  }
}

if (process.argv[1] &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
