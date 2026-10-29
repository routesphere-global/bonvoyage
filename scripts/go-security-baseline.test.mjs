import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {test} from 'node:test';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const GO_VERSION = '1.26.10';
const GRPC_VERSION = '1.83.2';
const X_NET_VERSION = '0.62.0';
const GO_IMAGE =
  'golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb';

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, ...relativePath.split('/')), 'utf8');
}

function requireModuleVersion(source, moduleName, version, relativePath) {
  const escaped = moduleName.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  assert.match(
    source,
    new RegExp(`(?:^|\\n)\\s*${escaped}\\s+v${version.replaceAll('.', '[.]')}(?:\\s|$)`, 'u'),
    `${relativePath} must require ${moduleName} v${version}`,
  );
}

test('supported Go toolchain is pinned across active release contracts', () => {
  assert.match(read('.tool-versions'), new RegExp(`^go ${GO_VERSION.replaceAll('.', '[.]')}$`, 'mu'));

  for (const relativePath of [
    'api/gen/go.mod',
    'control-plane/go.mod',
    'tests/fixtures/grpc-unary/go.mod',
    'tests/fixtures/phase3-scale/go.mod',
    'tools/host-tune/go.mod',
  ]) {
    assert.match(
      read(relativePath),
      new RegExp(`^go ${GO_VERSION.replaceAll('.', '[.]')}$`, 'mu'),
      `${relativePath} must use Go ${GO_VERSION}`,
    );
  }

  assert.match(
    read('.github/workflows/ci.yml'),
    new RegExp(`go-version: ${GO_VERSION.replaceAll('.', '[.]')}`, 'u'),
  );

  const windowsContract = JSON.parse(
    read('packaging/release/windows/config-authoring-large-input-contract.json'),
  );
  assert.equal(windowsContract.toolchain.go_version, GO_VERSION);
  assert.match(
    read('config/schemas/bonvoyage-windows-large-input-evidence-v1.schema.json'),
    new RegExp(`"go_version": \\{"const": "go${GO_VERSION.replaceAll('.', '[.]')}"\\}`, 'u'),
  );
});

test('reachable gRPC dependency graph stays on the reviewed fixed line', () => {
  for (const relativePath of [
    'api/gen/go.mod',
    'control-plane/go.mod',
    'tests/fixtures/grpc-unary/go.mod',
    'tests/fixtures/phase3-scale/go.mod',
  ]) {
    const source = read(relativePath);
    requireModuleVersion(source, 'google.golang.org/grpc', GRPC_VERSION, relativePath);
    requireModuleVersion(source, 'golang.org/x/net', X_NET_VERSION, relativePath);
  }
});

test('all active Go builders use the reviewed multi-architecture image', () => {
  for (const relativePath of [
    'deploy/docker/control-plane/Dockerfile',
    'tests/fixtures/grpc-unary/Dockerfile',
    'tests/fixtures/phase3-scale/Dockerfile',
    'tests/fixtures/http2-deadline/Dockerfile',
    'tests/fixtures/perf05-sse/Dockerfile',
    'tests/fixtures/upstream-http2/Dockerfile',
  ]) {
    assert.equal(
      read(relativePath).split('\n', 1)[0],
      `ARG GO_IMAGE=${GO_IMAGE}`,
      `${relativePath} must use the reviewed Go builder`,
    );
  }
});
