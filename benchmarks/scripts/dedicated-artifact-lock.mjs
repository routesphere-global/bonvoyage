#!/usr/bin/env node

import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';

import {
  REPOSITORY_ROOT,
  collectBindings,
  digestBuffer,
  inspectArtifactLockDocument,
  inspectRuntimeSecurityIdentity,
  repositoryFileReference,
  schemaErrors,
  sha256File,
  stableJson,
} from './dedicated-preflight.mjs';

const require = createRequire(path.join(REPOSITORY_ROOT, 'package.json'));
const yaml = require('js-yaml');

const TARGET_PLATFORM = {
  operating_system: 'Ubuntu 24.04 LTS',
  architecture: 'x86_64',
  container_platform: 'linux/amd64',
};

const PROMETHEUS_IMAGE =
  'prom/prometheus@sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0';
const SYFT_IMAGE =
  'anchore/syft:v1.44.0@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6';
const GRYPE_IMAGE =
  'anchore/grype:v0.116.1@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db';

function run(command, arguments_, {allowFailure = false} = {}) {
  try {
    return execFileSync(command, arguments_, {
      cwd: REPOSITORY_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', allowFailure ? 'ignore' : 'pipe'],
      maxBuffer: 64 * 1024 * 1024,
    }).trim();
  } catch (error) {
    if (allowFailure) {
      return null;
    }
    const detail = error.stderr?.toString().trim();
    throw new Error(detail || `${command} ${arguments_.join(' ')} failed`);
  }
}

function runGit(arguments_, options) {
  return run('git', arguments_, options);
}

function readJson(absolutePath) {
  return JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
}

function sourceFacts(remoteRef) {
  const commit = runGit(['rev-parse', 'HEAD']);
  const clean = runGit(['status', '--porcelain=v1', '--untracked-files=all']) === '';
  const pushed = runGit(
    ['merge-base', '--is-ancestor', commit, remoteRef],
    {allowFailure: true},
  ) !== null;
  if (!clean) {
    throw new Error('artifact capture requires a clean tree, including untracked files');
  }
  if (!pushed) {
    throw new Error(`artifact capture requires HEAD to be present on ${remoteRef}`);
  }
  return {commit, remoteRef};
}

function archivePath(value, label, {mustExist = false} = {}) {
  if (!value) {
    throw new Error(`${label} is required`);
  }
  const absolutePath = path.isAbsolute(value)
    ? path.resolve(value)
    : path.resolve(REPOSITORY_ROOT, value);
  const archiveRoot = path.join(REPOSITORY_ROOT, 'benchmarks/results/local-archives');
  const relative = path.relative(archiveRoot, absolutePath);
  if (relative === '' || relative.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relative)) {
    throw new Error(`${label} must be below benchmarks/results/local-archives`);
  }
  if (mustExist && !fs.existsSync(absolutePath)) {
    throw new Error(`${label} does not exist: ${value}`);
  }
  return absolutePath;
}

function imageDigestFromReference(reference) {
  const match = /@(sha256:[a-f0-9]{64})$/u.exec(reference);
  return match?.[1];
}

function localImmutableReference(id, imageId) {
  return `local.routesphere.invalid/${id}@${imageId}`;
}

export function normalizeImageInspection(document, {
  id,
  reference,
  expectedPlatformDigest,
  platformInspection,
} = {}) {
  if (document.Os !== 'linux' || document.Architecture !== 'amd64') {
    throw new Error(
      `${id} is ${document.Os}/${document.Architecture}; linux/amd64 is required`,
    );
  }
  if (!/^sha256:[a-f0-9]{64}$/u.test(document.Id ?? '')) {
    throw new Error(`${id} has no valid Docker image ID`);
  }
  const isIndex = ['application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json']
    .includes(document.Descriptor?.mediaType);
  if (isIndex && !platformInspection) {
    throw new Error(
      `${id} inspection identifies an image index; resolve and inspect the selected ` +
      'Linux AMD64 manifest before generating a formal artifact lock',
    );
  }
  const selected = platformInspection ?? document;
  if (platformInspection) {
    if (selected.Os !== 'linux' || selected.Architecture !== 'amd64' ||
        !/^sha256:[a-f0-9]{64}$/u.test(selected.Id ?? '') ||
        !['application/vnd.oci.image.manifest.v1+json',
          'application/vnd.docker.distribution.manifest.v2+json']
          .includes(selected.Descriptor?.mediaType) ||
        selected.Descriptor.digest !== selected.Id ||
        stableJson(selected.RootFS) !== stableJson(document.RootFS) ||
        stableJson(selected.Config) !== stableJson(document.Config)) {
      throw new Error(`${id} selected AMD64 inspection differs from the original image`);
    }
  }
  const pinnedReferenceDigest = imageDigestFromReference(reference);
  if (expectedPlatformDigest && pinnedReferenceDigest !== expectedPlatformDigest) {
    throw new Error(
      `${id} reference digest ${pinnedReferenceDigest ?? 'missing'} differs from ` +
      `locked AMD64 manifest ${expectedPlatformDigest}`,
    );
  }
  const platformDigest = selected.Descriptor?.digest ?? expectedPlatformDigest ?? selected.Id;
  if (expectedPlatformDigest && platformDigest !== expectedPlatformDigest) {
    throw new Error(`${id} selected manifest differs from the locked AMD64 manifest`);
  }
  return {
    id: document.Id,
    immutableReference: imageDigestFromReference(reference)
      ? reference
      : localImmutableReference(id, document.Id),
    platformDigest,
    labels: document.Config?.Labels ?? {},
  };
}

function inspectImage(id, reference, expectedPlatformDigest) {
  const output = run('docker', [
    'image',
    'inspect',
    reference,
    '--format',
    '{{json .}}',
  ]);
  const document = JSON.parse(output);
  // Resolve from the immutable ID so a moved tag cannot select another image.
  const indexed = ['application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json']
    .includes(document.Descriptor?.mediaType);
  const platformInspection = indexed ? JSON.parse(run('docker', [
    'image', 'inspect', '--platform', 'linux/amd64', document.Id,
    '--format', '{{json .}}',
  ])) : undefined;
  return normalizeImageInspection(document, {
    id,
    reference,
    expectedPlatformDigest,
    platformInspection,
  });
}

function extractedFileHash(imageReference, sourcePath) {
  const suffix = `${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const container = `bonvoyage-artifact-lock-${suffix}`;
  const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), 'bonvoyage-artifact-lock-'),
  );
  const destination = path.join(temporaryDirectory, 'artifact');
  try {
    run('docker', ['create', '--name', container, imageReference]);
    run('docker', ['cp', `${container}:${sourcePath}`, destination]);
    if (!fs.statSync(destination).isFile()) {
      throw new Error(`${sourcePath} in ${imageReference} is not a regular file`);
    }
    return sha256File(destination);
  } finally {
    run('docker', ['rm', '-f', container], {allowFailure: true});
    fs.rmSync(temporaryDirectory, {recursive: true, force: true});
  }
}

function repositoryIdentity(purpose, filePath) {
  const reference = repositoryFileReference(filePath, `${purpose} identity`);
  return {purpose, path: reference.path, sha256: reference.sha256};
}

function imageIdentity(imageReference, purpose, filePath) {
  return {
    purpose,
    path: filePath,
    sha256: extractedFileHash(imageReference, filePath),
  };
}

function captureArtifact({
  id,
  kind,
  version,
  imageReference,
  expectedPlatformDigest,
  imageFiles = [],
  repositoryFiles = [],
  metadataLabels = {},
}) {
  const inspection = inspectImage(id, imageReference, expectedPlatformDigest);
  const files = [
    ...imageFiles.map(({purpose, path: filePath}) =>
      imageIdentity(inspection.id, purpose, filePath)),
    ...repositoryFiles.map(({purpose, path: filePath}) =>
      repositoryIdentity(purpose, filePath)),
  ];
  if (files.length === 0) {
    throw new Error(`${id} has no file identities`);
  }
  const metadata = Object.fromEntries(
    Object.entries(metadataLabels).map(([name, label]) => {
      const value = inspection.labels[label];
      if (!value) {
        throw new Error(`${id} image lacks required label ${label}`);
      }
      return [name, value];
    }),
  );
  return {
    id,
    kind,
    version: version ?? inspection.labels['org.opencontainers.image.version'] ?? 'unknown',
    image_reference: inspection.immutableReference,
    image_digest: inspection.id,
    platform_digest: inspection.platformDigest,
    ...(Object.keys(metadata).length > 0 ? {metadata} : {}),
    files,
  };
}

function findLatestComparatorQualification() {
  const root = path.join(REPOSITORY_ROOT, 'benchmarks/results/qualification');
  const candidates = [];
  for (const directory of fs.readdirSync(root, {withFileTypes: true})) {
    if (!directory.isDirectory()) {
      continue;
    }
    const absoluteDirectory = path.join(root, directory.name);
    for (const name of fs.readdirSync(absoluteDirectory)) {
      if (name.endsWith('.qualification.json')) {
        candidates.push(path.join(absoluteDirectory, name));
      }
    }
  }
  candidates.sort().reverse();
  for (const candidate of candidates) {
    try {
      const document = readJson(candidate);
      if (document.architecture === 'x86_64' && document.passed === true) {
        return path.relative(REPOSITORY_ROOT, candidate);
      }
    } catch {
      // Project validation owns malformed retained candidates.
    }
  }
  throw new Error('no passing retained AMD64 comparator qualification was found');
}

function validateComparatorQualification(qualification, qualificationFile, productLock) {
  const errors = schemaErrors(
    'benchmarks/spec/product-qualification.schema.json',
    qualification,
  );
  if (qualification.architecture !== 'x86_64' || qualification.passed !== true) {
    errors.push('qualification is not a passing AMD64 record');
  }
  if (qualification.product_lock_sha256 !== productLock.sha256) {
    errors.push('qualification does not match the current product lock');
  }
  const names = qualification.products?.map(({name}) => name).sort() ?? [];
  if (names.join(',') !== 'envoy,haproxy,nginx') {
    errors.push('qualification does not contain Envoy, HAProxy, and NGINX exactly once');
  }
  const archivedLock = path.join(
    path.dirname(qualificationFile.absolutePath),
    'product-lock.json',
  );
  if (!fs.existsSync(archivedLock) || sha256File(archivedLock) !== productLock.sha256) {
    errors.push('qualification archived product lock is missing or stale');
  }
  if (errors.length > 0) {
    throw new Error(`comparator qualification is invalid: ${errors.join('; ')}`);
  }
}

function environmentValues(absolutePath) {
  return Object.fromEntries(
    fs.readFileSync(absolutePath, 'utf8')
      .split('\n')
      .filter((line) => line.includes('='))
      .map((line) => {
        const index = line.indexOf('=');
        return [line.slice(0, index), line.slice(index + 1)];
      }),
  );
}

function securityReferences(securityDirectory) {
  const required = [
    'environment.txt',
    'evidence-checksums.sha256',
    'runtime.cdx.json',
    'runtime.syft.spdx.json',
    'vulnerability-summary.json',
  ];
  return Object.fromEntries(required.map((name) => {
    const absolutePath = path.join(securityDirectory, name);
    if (!fs.existsSync(absolutePath) || !fs.statSync(absolutePath).isFile()) {
      throw new Error(`runtime security evidence is missing ${name}`);
    }
    return [name, repositoryFileReference(absolutePath, `runtime security ${name}`)];
  }));
}

export function buildArtifactLock({
  campaignId,
  sourceCommit,
  capturedAt,
  bindings,
  artifacts,
  sboms,
  evidence,
}) {
  const normalizedBindings = [...bindings]
    .sort((left, right) => left.id.localeCompare(right.id));
  const normalizedArtifacts = [...artifacts]
    .sort((left, right) => left.id.localeCompare(right.id));
  const normalizedSboms = [...sboms]
    .sort((left, right) =>
      `${left.artifact_id}:${left.format}`.localeCompare(
        `${right.artifact_id}:${right.format}`,
      ));
  const normalizedEvidence = [...evidence]
    .sort((left, right) => left.id.localeCompare(right.id));
  const identity = {
    campaignId,
    sourceCommit,
    bindings: normalizedBindings,
    artifacts: normalizedArtifacts,
    sboms: normalizedSboms,
    evidence: normalizedEvidence,
  };
  return {
    schema_version: 1,
    lock_id: `dq-artifacts-${digestBuffer(stableJson(identity)).slice(0, 16)}`,
    campaign_id: campaignId,
    captured_at: capturedAt,
    source_commit: sourceCommit,
    platform: TARGET_PLATFORM,
    scope_complete: true,
    input_bindings: normalizedBindings,
    artifacts: normalizedArtifacts,
    sboms: normalizedSboms,
    evidence: normalizedEvidence,
    passed: true,
  };
}

function parseArguments(argv) {
  const options = {
    mode: 'generate',
    scope: 'all',
    campaign: 'benchmarks/plans/dedicated-qualification-v1.yaml',
    productLock: 'benchmarks/products/lock.json',
    tuningPolicy: 'deploy/tuning/policies/throughput-balanced.yaml',
    comparatorQualification: undefined,
    securityEvidence: process.env.BONVOYAGE_SECURITY_EVIDENCE_DIR,
    artifactLock: process.env.BONVOYAGE_DEDICATED_ARTIFACT_LOCK,
    output: process.env.BONVOYAGE_DEDICATED_ARTIFACT_LOCK_OUTPUT,
    remoteRef: process.env.BONVOYAGE_DEDICATED_REMOTE_REF ?? 'origin/main',
    bonvoyageImage: process.env.BONVOYAGE_DEDICATED_BONVOYAGE_IMAGE,
    compilerImage: process.env.BONVOYAGE_DEDICATED_COMPILER_IMAGE,
    upstreamImage: process.env.BONVOYAGE_DEDICATED_UPSTREAM_IMAGE,
    phase3UpstreamImage: process.env.BONVOYAGE_DEDICATED_PHASE3_UPSTREAM_IMAGE,
    prometheusImage: process.env.BONVOYAGE_DEDICATED_PROMETHEUS_IMAGE ?? PROMETHEUS_IMAGE,
    syftImage: process.env.BONVOYAGE_DEDICATED_SYFT_IMAGE ?? SYFT_IMAGE,
    grypeImage: process.env.BONVOYAGE_DEDICATED_GRYPE_IMAGE ?? GRYPE_IMAGE,
  };
  const valueOptions = new Map([
    ['--scope', 'scope'],
    ['--campaign', 'campaign'],
    ['--product-lock', 'productLock'],
    ['--tuning-policy', 'tuningPolicy'],
    ['--comparator-qualification', 'comparatorQualification'],
    ['--security-evidence', 'securityEvidence'],
    ['--artifact-lock', 'artifactLock'],
    ['--output', 'output'],
    ['--remote-ref', 'remoteRef'],
    ['--bonvoyage-image', 'bonvoyageImage'],
    ['--compiler-image', 'compilerImage'],
    ['--upstream-image', 'upstreamImage'],
    ['--phase3-upstream-image', 'phase3UpstreamImage'],
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--verify') {
      options.mode = 'verify';
      continue;
    }
    if (argv[index] === '--help') {
      options.mode = 'help';
      continue;
    }
    const key = valueOptions.get(argv[index]);
    const value = argv[index + 1];
    if (!key || !value) {
      throw new Error(`unknown or incomplete argument: ${argv[index]}`);
    }
    options[key] = value;
    index += 1;
  }
  if (!['all', 'comparators', 'runtime-security'].includes(options.scope)) {
    throw new Error('scope must be all, comparators, or runtime-security');
  }
  return options;
}

function commonContext(options) {
  const source = sourceFacts(options.remoteRef);
  const campaignFile = repositoryFileReference(options.campaign, 'campaign plan');
  const campaign = yaml.load(fs.readFileSync(campaignFile.absolutePath, 'utf8'));
  const campaignErrors = schemaErrors(
    'benchmarks/spec/dedicated-campaign.schema.json',
    campaign,
  );
  if (campaignErrors.length > 0) {
    throw new Error(`campaign plan is invalid: ${campaignErrors.join('; ')}`);
  }
  const productLock = repositoryFileReference(options.productLock, 'product lock');
  const productLockDocument = readJson(productLock.absolutePath);
  const productErrors = schemaErrors(
    'benchmarks/spec/product-lock.schema.json',
    productLockDocument,
  );
  if (productErrors.length > 0) {
    throw new Error(`product lock is invalid: ${productErrors.join('; ')}`);
  }
  const tuningPolicy = repositoryFileReference(options.tuningPolicy, 'tuning policy');
  const tuningDocument = yaml.load(fs.readFileSync(tuningPolicy.absolutePath, 'utf8'));
  const tuningErrors = schemaErrors(
    'deploy/tuning/host-tuning-policy.schema.json',
    tuningDocument,
  );
  if (tuningErrors.length > 0) {
    throw new Error(`tuning policy is invalid: ${tuningErrors.join('; ')}`);
  }
  const bindings = collectBindings({
    campaignPath: campaignFile.path,
    productLock,
    tuningPolicyPath: tuningPolicy.path,
  });
  return {source, campaign, productLock, productLockDocument, bindings};
}

function generate(options) {
  const context = commonContext(options);
  const shortCommit = context.source.commit.slice(0, 12);
  const bonvoyageImage = options.bonvoyageImage ??
    `bonvoyage-dataplane:rc-${shortCommit}`;
  const compilerImage = options.compilerImage ??
    `bonvoyage-snapshot-compiler:rc-${shortCommit}`;
  const upstreamImage = options.upstreamImage ??
    `bonvoyage-controlled-upstream:rc-${shortCommit}`;
  const phase3UpstreamImage = options.phase3UpstreamImage ??
    `bonvoyage-phase3-upstream:rc-${shortCommit}`;
  const securityDirectory = archivePath(
    options.securityEvidence,
    'runtime security evidence directory',
    {mustExist: true},
  );
  const security = securityReferences(securityDirectory);
  const runtimeEnvironment = environmentValues(security['environment.txt'].absolutePath);

  const qualificationFile = repositoryFileReference(
    options.comparatorQualification ?? findLatestComparatorQualification(),
    'comparator qualification',
  );
  const qualification = readJson(qualificationFile.absolutePath);
  validateComparatorQualification(
    qualification,
    qualificationFile,
    context.productLock,
  );
  const qualified = new Map(
    qualification.products.map((product) => [product.name, product]),
  );

  const artifacts = [];
  artifacts.push(captureArtifact({
    id: 'bonvoyage',
    kind: 'gateway',
    version: '0.2.0',
    imageReference: bonvoyageImage,
    imageFiles: [
      {purpose: 'executable', path: '/usr/local/bin/bonvoyage-dataplane'},
    ],
    metadataLabels: {
      upstream_http1_client:
        'io.routesphere.bonvoyage.upstream-http1-client',
    },
  }));
  artifacts.push(captureArtifact({
    id: 'snapshot-compiler',
    kind: 'control-plane',
    version: '0.2.0',
    imageReference: compilerImage,
    imageFiles: [
      {purpose: 'executable', path: '/usr/local/bin/bonvoyage-control-plane'},
    ],
  }));
  artifacts.push(captureArtifact({
    id: 'controlled-upstream',
    kind: 'upstream',
    version: shortCommit,
    imageReference: upstreamImage,
    imageFiles: [
      {purpose: 'executable', path: '/usr/sbin/nginx'},
      {purpose: 'configuration', path: '/etc/nginx/nginx.conf'},
      {purpose: 'payload', path: '/srv/payload/256'},
    ],
  }));
  artifacts.push(captureArtifact({
    id: 'telemetry-collector',
    kind: 'telemetry',
    version: shortCommit,
    imageReference: phase3UpstreamImage,
    imageFiles: [
      {purpose: 'entrypoint', path: '/app/server.py'},
    ],
    repositoryFiles: [
      {purpose: 'entrypoint', path: 'scripts/phase3-otlp-collector.py'},
    ],
  }));

  for (const product of context.productLockDocument.products) {
    const accepted = qualified.get(product.name);
    if (!accepted) {
      throw new Error(`${product.name} is absent from comparator qualification`);
    }
    const reference = `${product.repository}@${product.manifests.linux_amd64}`;
    const artifact = captureArtifact({
      id: product.name,
      kind: 'gateway',
      version: product.version,
      imageReference: reference,
      expectedPlatformDigest: product.manifests.linux_amd64,
      imageFiles: [{purpose: 'executable', path: product.executable}],
      repositoryFiles: [{purpose: 'configuration', path: product.config}],
    });
    const executable = artifact.files.find(({purpose}) => purpose === 'executable');
    const configuration = artifact.files.find(({purpose}) => purpose === 'configuration');
    if (executable.sha256 !== accepted.executable_sha256 ||
        configuration.sha256 !== accepted.config_sha256 || accepted.passed !== true) {
      throw new Error(`${product.name} differs from accepted comparator evidence`);
    }
    artifacts.push(artifact);
  }

  const loadGenerator = context.productLockDocument.load_generator;
  artifacts.push(captureArtifact({
    id: 'load-generator',
    kind: 'load-generator',
    version: loadGenerator.version,
    imageReference: `${loadGenerator.repository}@${loadGenerator.manifests.linux_amd64}`,
    expectedPlatformDigest: loadGenerator.manifests.linux_amd64,
    imageFiles: [{purpose: 'executable', path: '/bin/oha'}],
  }));
  artifacts.push(captureArtifact({
    id: 'metrics-store',
    kind: 'telemetry',
    version: '3.14.0',
    imageReference: options.prometheusImage,
    imageFiles: [{purpose: 'executable', path: '/bin/prometheus'}],
    repositoryFiles: [
      {purpose: 'configuration', path: 'observability/prometheus/prometheus.yml'},
    ],
  }));
  artifacts.push(captureArtifact({
    id: 'sbom-generator',
    kind: 'security-tool',
    version: '1.44.0',
    imageReference: options.syftImage,
    imageFiles: [{purpose: 'executable', path: '/syft'}],
  }));
  artifacts.push(captureArtifact({
    id: 'vulnerability-scanner',
    kind: 'security-tool',
    version: '0.116.1',
    imageReference: options.grypeImage,
    imageFiles: [{purpose: 'executable', path: '/grype'}],
  }));

  const bonvoyage = artifacts.find(({id}) => id === 'bonvoyage');
  const securityErrors = inspectRuntimeSecurityIdentity(runtimeEnvironment, {
    sourceCommit: context.source.commit, artifact: bonvoyage,
  });
  if (securityErrors.length > 0) {
    throw new Error(`runtime security evidence does not identify this clean AMD64 RC image: ${securityErrors.join('; ')}`);
  }

  const document = buildArtifactLock({
    campaignId: context.campaign.id,
    sourceCommit: context.source.commit,
    capturedAt: new Date().toISOString(),
    bindings: context.bindings,
    artifacts,
    sboms: [
      {
        artifact_id: 'bonvoyage',
        format: 'CycloneDX JSON',
        path: security['runtime.cdx.json'].path,
        sha256: security['runtime.cdx.json'].sha256,
      },
      {
        artifact_id: 'bonvoyage',
        format: 'SPDX JSON',
        path: security['runtime.syft.spdx.json'].path,
        sha256: security['runtime.syft.spdx.json'].sha256,
      },
    ],
    evidence: [
      {
        id: 'comparator-qualification',
        path: qualificationFile.path,
        sha256: qualificationFile.sha256,
      },
      {
        id: 'runtime-dependency-environment',
        path: security['environment.txt'].path,
        sha256: security['environment.txt'].sha256,
      },
      {
        id: 'runtime-evidence-checksums',
        path: security['evidence-checksums.sha256'].path,
        sha256: security['evidence-checksums.sha256'].sha256,
      },
      {
        id: 'runtime-vulnerability-summary',
        path: security['vulnerability-summary.json'].path,
        sha256: security['vulnerability-summary.json'].sha256,
      },
    ],
  });
  const inspection = inspectArtifactLockDocument(document, {
    campaignId: context.campaign.id,
    sourceCommit: context.source.commit,
    bindings: context.bindings,
    verifySboms: true,
  });
  if (!inspection.valid) {
    throw new Error(`generated artifact lock is invalid: ${inspection.errors.join('; ')}`);
  }
  const sourceAfter = sourceFacts(options.remoteRef);
  if (sourceAfter.commit !== context.source.commit) {
    throw new Error('source commit changed during artifact capture');
  }
  const output = archivePath(options.output, 'artifact lock output');
  fs.mkdirSync(path.dirname(output), {recursive: true});
  fs.writeFileSync(output, `${JSON.stringify(document, null, 2)}\n`, {flag: 'wx'});
  process.stdout.write(
    `${document.lock_id}: captured ${document.artifacts.length} exact AMD64 artifacts; ` +
    `output=${path.relative(REPOSITORY_ROOT, output)}\n`,
  );
}

function verify(options) {
  if (!options.artifactLock) {
    throw new Error('BONVOYAGE_DEDICATED_ARTIFACT_LOCK or --artifact-lock is required');
  }
  const context = commonContext(options);
  const lockFile = repositoryFileReference(
    options.artifactLock,
    'artifact lock',
  );
  const document = readJson(lockFile.absolutePath);
  const inspection = inspectArtifactLockDocument(document, {
    campaignId: context.campaign.id,
    sourceCommit: context.source.commit,
    bindings: context.bindings,
    verifySboms: true,
  });
  if (!inspection.valid) {
    throw new Error(inspection.errors.join('; '));
  }
  process.stdout.write(
    `${document.lock_id}: ${options.scope} evidence verified for ` +
    `${document.artifacts.length} locked AMD64 artifacts\n`,
  );
}

function printHelp() {
  process.stdout.write(
    'usage: dedicated-artifact-lock.mjs [--verify] [--scope all|comparators|runtime-security]\n' +
    '       --security-evidence <local-archives/dir> --output <local-archives/lock.json>\n',
  );
}

function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.mode === 'help') {
    printHelp();
  } else if (options.mode === 'verify') {
    verify(options);
  } else {
    generate(options);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`dedicated-artifact-lock: ${error.message}\n`);
    process.exitCode = 1;
  }
}
