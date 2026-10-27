import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {fileURLToPath} from 'node:url';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
export const ROOT = path.resolve(path.dirname(SCRIPT_PATH), '..');
export const SOURCE_ROOT = path.resolve(
  process.env.BONVOYAGE_CONFIG_REFERENCE_SOURCE_ROOT ?? ROOT,
);
export const OUTPUT_ROOT = path.resolve(
  process.env.BONVOYAGE_CONFIG_REFERENCE_OUTPUT_ROOT ?? ROOT,
);
export const COMPLETION_PATH = 'config/authoring/completion/v1/metadata.json';
export const SNIPPETS_PATH = 'config/authoring/snippets/v1/catalog.json';
export const OUTPUT_PATH =
  'docs-site/src/content/docs/reference/configuration-parameters.md';

const GROUPS = [
  {
    heading: 'Server identity and local management',
    prefix: '/server',
    introduction:
      'These fields identify one gateway process and bind its local administration and metrics endpoints.',
  },
  {
    heading: 'Snapshot identity',
    prefix: '/snapshot',
    introduction:
      'These fields version the desired state compiled into one immutable runtime snapshot.',
  },
  {
    heading: 'Listeners',
    prefix: '/listeners',
    introduction:
      'Listeners accept downstream connections, select protocol and virtual hosts, and optionally enforce TLS or trusted-proxy boundaries.',
  },
  {
    heading: 'Virtual hosts, routes, and policies',
    prefix: '/virtual_hosts',
    introduction:
      'Virtual hosts select domains. Their ordered routes match requests, choose one action, and optionally apply bounded admission or transformation policies.',
  },
  {
    heading: 'Clusters, health, retries, and endpoints',
    prefix: '/clusters',
    introduction:
      'Clusters describe upstream pools, connection limits, transport security, health behavior, retry budgets, and concrete endpoints.',
  },
  {
    heading: 'Runtime limits',
    prefix: '/runtime_limits',
    introduction:
      'Runtime limits bound request sizes, timeouts, response metadata, idle connections, and downstream connection density.',
  },
];

function readJson(root, relativePath) {
  const absolutePath = path.resolve(root, ...relativePath.split('/'));
  assert.equal(
    absolutePath.startsWith(`${path.resolve(root)}${path.sep}`),
    true,
    `input escapes repository root: ${relativePath}`,
  );
  const information = fs.lstatSync(absolutePath);
  assert.equal(information.isSymbolicLink(), false, `input is a symlink: ${relativePath}`);
  assert.equal(information.isFile(), true, `input is not a regular file: ${relativePath}`);
  return JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
}

function inlineCode(value) {
  return `\`${String(value).replaceAll('`', '\\`')}\``;
}

function formatType(value) {
  if (value.kind !== 'array') return inlineCode(value.kind);
  return inlineCode(`array<${value.item?.kind ?? 'value'}>`);
}

function formatConstraints(entry) {
  const value = entry.value;
  const constraints = [];
  if (Object.hasOwn(value, 'const_value')) {
    constraints.push(`must be ${inlineCode(value.const_value)}`);
  }
  if (Array.isArray(value.enum_values)) {
    constraints.push(`one of ${value.enum_values.map(inlineCode).join(', ')}`);
  }
  if (Object.hasOwn(value, 'minimum') && Object.hasOwn(value, 'maximum')) {
    constraints.push(`${value.minimum} to ${value.maximum}`);
  } else if (Object.hasOwn(value, 'minimum')) {
    constraints.push(`minimum ${value.minimum}`);
  } else if (Object.hasOwn(value, 'maximum')) {
    constraints.push(`maximum ${value.maximum}`);
  }
  if (Object.hasOwn(value, 'min_length') && Object.hasOwn(value, 'max_length')) {
    constraints.push(`${value.min_length} to ${value.max_length} characters`);
  } else if (Object.hasOwn(value, 'min_length')) {
    constraints.push(`at least ${value.min_length} character${value.min_length === 1 ? '' : 's'}`);
  } else if (Object.hasOwn(value, 'max_length')) {
    constraints.push(`at most ${value.max_length} characters`);
  }
  if (Object.hasOwn(value, 'min_items') && Object.hasOwn(value, 'max_items')) {
    constraints.push(`${value.min_items} to ${value.max_items} items`);
  } else if (Object.hasOwn(value, 'min_items')) {
    constraints.push(`at least ${value.min_items} item${value.min_items === 1 ? '' : 's'}`);
  } else if (Object.hasOwn(value, 'max_items')) {
    constraints.push(`at most ${value.max_items} items`);
  }
  if (value.unique_items) constraints.push('items must be unique');
  if (Object.hasOwn(value, 'pattern')) constraints.push('validated syntax');
  if (entry.secret_reference) {
    constraints.push('deployment-secret filename only; never secret contents');
  }
  return constraints.length === 0 ? 'None at this structural level' : constraints.join('; ');
}

function escapeTableCell(value) {
  return String(value).replaceAll('|', '\\|').replaceAll('\n', ' ');
}

function renderFieldTable(entries) {
  const rows = entries.map((entry) => [
    inlineCode(entry.path),
    entry.title,
    formatType(entry.value),
    entry.required_in_parent ? 'Required' : 'Optional',
    formatConstraints(entry),
    entry.summary,
  ].map(escapeTableCell).join(' | '));
  return [
    '| YAML path | Parameter | Type | Direct presence | Constraints | Meaning |',
    '| --- | --- | --- | --- | --- | --- |',
    ...rows.map((row) => `| ${row} |`),
  ].join('\n');
}

function renderSnippet(entry) {
  const destination = entry.insertion.container_path === ''
    ? 'the document root'
    : inlineCode(entry.insertion.container_path);
  return [
    `<details id="example-${entry.id}">`,
    `<summary>${entry.title}</summary>`,
    '',
    entry.summary,
    '',
    `Place this fragment at ${destination} using ${inlineCode(entry.insertion.mode)} semantics:`,
    '',
    '```yaml',
    entry.yaml.trimEnd(),
    '```',
    '',
    '</details>',
  ].join('\n');
}

function validateInputs(completion, snippets) {
  assert.equal(
    completion.classification,
    'routesphere-bonvoyage-configuration-completion-metadata',
  );
  assert.equal(completion.schema_version, 1);
  assert.equal(completion.entry_count, completion.entries.length);
  assert.equal(completion.entry_count > 0, true);
  assert.equal(snippets.classification, 'routesphere-bonvoyage-configuration-snippet-catalog');
  assert.equal(snippets.schema_version, 1);
  assert.equal(snippets.entry_count, snippets.entries.length);
  assert.equal(
    completion.configuration_schema_version,
    snippets.configuration_schema_version,
  );
  assert.equal(completion.compiler_version, snippets.compiler_version);

  const paths = new Set();
  for (const entry of completion.entries) {
    assert.equal(paths.has(entry.path), false, `duplicate completion path: ${entry.path}`);
    paths.add(entry.path);
  }
  assert.equal(paths.has(''), true, 'completion metadata must contain the document root');
  for (const entry of completion.entries.filter((candidate) => candidate.path !== '')) {
    const matches = GROUPS.filter((group) =>
      entry.path === group.prefix || entry.path.startsWith(`${group.prefix}/`));
    assert.equal(matches.length, 1, `configuration path has no unique documentation group: ${entry.path}`);
  }

  const snippetIds = new Set();
  for (const entry of snippets.entries) {
    assert.match(entry.id, /^[a-z0-9]+(?:-[a-z0-9]+)*$/u);
    assert.equal(snippetIds.has(entry.id), false, `duplicate snippet id: ${entry.id}`);
    snippetIds.add(entry.id);
    assert.equal(typeof entry.yaml, 'string');
    assert.ok(entry.yaml.length > 0);
  }
  assert.equal(snippetIds.has('document-local-baseline'), true,
    'snippet catalog must contain the complete local baseline');
}

export function renderPublicConfigReference(completion, snippets) {
  validateInputs(completion, snippets);
  const baseline = snippets.entries.find((entry) => entry.id === 'document-local-baseline');
  const featureExamples = snippets.entries.filter((entry) => entry.id !== baseline.id);
  const yamlFence = '```yaml';
  const bashFence = '```bash';
  const closingFence = '```';
  const sections = GROUPS.map((group) => {
    const entries = completion.entries.filter((entry) =>
      entry.path === group.prefix || entry.path.startsWith(`${group.prefix}/`));
    return [
      `## ${group.heading}`,
      '',
      group.introduction,
      '',
      renderFieldTable(entries),
    ].join('\n');
  });

  return `---
title: YAML configuration parameter reference
description: Every supported BonVoyage YAML field, its purpose, structural constraints, and compiler-backed examples.
---

<!-- Generated by scripts/generate-public-config-reference.mjs. Do not edit directly. -->

This reference covers all **${completion.entry_count - 1} YAML parameters and containers** in
BonVoyage configuration schema version **${completion.configuration_schema_version}**. The
tables are generated from the release-matched completion metadata and reviewed
field-help catalog. The examples come from the compiler-backed snippet catalog.

:::tip[Start with a complete document]
Use the [Docker quickstart](../../getting-started/quickstart/) and the baseline
below before adding optional transport, policy, or routing fragments.
:::

## How to read the paths

Paths use RFC 6901-style notation. A ${inlineCode('*')} represents one array item, so
${inlineCode('/listeners/*/port')} means the ${inlineCode('port')} field on every object in the
top-level ${inlineCode('listeners')} array.

${inlineCode('Required')} means the field is directly required by its containing object.
${inlineCode('Optional')} fields can still become conditionally required by another selection.
Those relationships are listed under [cross-field rules](#cross-field-rules).
Exact regular expressions and structural rules remain available in
${inlineCode('config/schemas/bonvoyage-config.schema.json')}. The authoritative
Go snapshot compiler performs semantic validation, defaults, reference checks,
and supported-feature checks that a field table cannot replace.

## Complete baseline example

**${baseline.title}.** ${baseline.summary}

${inlineCode('config/examples/local.yaml')}:

${yamlFence}
${baseline.yaml.trimEnd()}
${closingFence}

Validate the complete file before applying it:

${bashFence}
go run ./control-plane/cmd/bonvoyage-config validate \\
  --input config/examples/local.yaml
${closingFence}

## Feature examples

Each fragment below names its insertion path. Merge it into a complete document,
then validate the whole document. Secret-reference fields accept deployment
filenames such as ${inlineCode('server-key.pem')}; never paste a private key,
API key, JWKS document, or certificate body into YAML.

${featureExamples.map(renderSnippet).join('\n\n')}

## Cross-field rules

- A route match selects exactly one of ${inlineCode('path_exact')},
  ${inlineCode('path_prefix')}, or ${inlineCode('safe_regex')}.
- Every route selects exactly one action: ${inlineCode('cluster')},
  ${inlineCode('weighted_clusters')}, ${inlineCode('fixed_response')}, or
  ${inlineCode('redirect')}.
- ${inlineCode('api_key_auth')} and ${inlineCode('jwt_auth')} are mutually
  exclusive on one route.
- Header transformations and rewrites require an upstream cluster action.
  WebSocket forwarding also requires a cluster action and
  ${inlineCode('max_concurrent_requests_per_shard')}.
- Downstream mTLS requires ${inlineCode('require_client_certificate: true')}
  and ${inlineCode('trust_bundle_secret')}. Without client-certificate
  enforcement, a downstream trust bundle is rejected.
- An upstream certificate chain and private key must be configured together.
  HTTP/2 upstream clusters require ${inlineCode('upstream_tls')};
  ${inlineCode('max_http2_streams_per_connection')} is valid only for HTTP/2.
- A header or query matcher chooses exactly one of ${inlineCode('exact')} or
  ${inlineCode('present')}.
- CORS chooses either ${inlineCode('allow_any_origin: true')} or an
  ${inlineCode('allowed_origins')} list. Source-IP policy requires at least one
  allow or deny CIDR list. Request-content policy requires at least one bound.
- A ${inlineCode('remove')} header mutation carries no value; ${inlineCode('set')}
  and ${inlineCode('append')} require one.
- Redirect ${inlineCode('scheme')} and ${inlineCode('host')} are paired;
  ${inlineCode('port')} requires both. A rewrite cannot set both
  ${inlineCode('path')} and ${inlineCode('path_prefix')}.
- Schema-recognized syntax is not automatically a supported runtime feature.
  For example, the first OSS candidate supports downstream HTTP/1.1 and HTTP/2;
  selecting ${inlineCode('http3')} is rejected by semantic validation.

Run [offline validation](../../how-to/validate-configuration/) after every edit.
Use [configuration diagnostics](../configuration-diagnostics/) to interpret a
rejection and [supported capabilities](../supported-capabilities/) before relying
on a protocol or operating mode.

## Parameter catalog

${sections.join('\n\n')}

## Authority and defaults

This page describes source syntax. Optional fields may receive safe compiler
defaults, but the formatter deliberately does not materialize those defaults
into YAML. Do not infer a default merely because a field is optional. Validate
with the exact installed release and inspect preview output before rollout.

The catalog does not prove that a gateway received, ACKed, or activated a
snapshot. Runtime confirmation remains a separate management and traffic test.
`;
}

export function generatePublicConfigReference(root = SOURCE_ROOT) {
  return renderPublicConfigReference(
    readJson(root, COMPLETION_PATH),
    readJson(root, SNIPPETS_PATH),
  );
}

function main(args) {
  assert.equal(args.length, 1,
    'usage: generate-public-config-reference.mjs --check|--write');
  assert.equal(args[0] === '--check' || args[0] === '--write', true,
    'usage: generate-public-config-reference.mjs --check|--write');
  const rendered = generatePublicConfigReference();
  const output = path.join(OUTPUT_ROOT, ...OUTPUT_PATH.split('/'));
  if (args[0] === '--write') {
    fs.mkdirSync(path.dirname(output), {recursive: true});
    fs.writeFileSync(output, rendered, {encoding: 'utf8', mode: 0o644});
    return;
  }
  assert.equal(fs.readFileSync(output, 'utf8'), rendered,
    `${OUTPUT_PATH} is stale; run the generator with --write`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === SCRIPT_PATH) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
