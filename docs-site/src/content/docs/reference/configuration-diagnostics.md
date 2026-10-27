---
title: Configuration diagnostics
description: Stable reason codes and release-matched remediation guidance for BonVoyage configuration authoring.
---

BonVoyage configuration commands return stable `BV_CFG_*` reason codes. The
generated presentation catalog at
`config/authoring/reason-codes/v1/catalog.json` gives an editor, assistant or CI
surface one reviewed title, summary and operator action for every code shipped
by the matching authoring contract.

The catalog contains 31 entries in eight classes: compatibility, input,
internal, operation, schema, security, semantic and syntax. Each entry carries:

- the stable reason code;
- its contract-owned class, default severity and retryable flag;
- a stable documentation anchor; and
- reviewed, bounded, release-matched presentation guidance.

## Reason-code index

| Code | Class | Presentation title |
| --- | --- | --- |
| `BV_CFG_DIAGNOSTICS_TRUNCATED` | operation | Additional diagnostics omitted |
| `BV_CFG_DIFF_INPUT_INVALID` | operation | Diff input was rejected |
| `BV_CFG_EXPLAIN_PATH_UNKNOWN` | operation | Field path is unknown |
| `BV_CFG_FILE_TYPE_UNSUPPORTED` | input | Unsupported configuration file type |
| `BV_CFG_FORMAT_UNSAFE` | operation | Formatting cannot preserve invariants |
| `BV_CFG_INPUT_ENCODING` | input | Input is not valid UTF-8 |
| `BV_CFG_INPUT_NOT_REGULAR` | input | Input is not a regular file |
| `BV_CFG_INPUT_SYMLINK` | input | In-place symlink replacement refused |
| `BV_CFG_INPUT_TOO_LARGE` | input | Configuration exceeds the size limit |
| `BV_CFG_INPUT_UNREADABLE` | input | Input could not be read |
| `BV_CFG_INTERNAL` | internal | Internal authoring failure |
| `BV_CFG_MIGRATION_UNSUPPORTED` | operation | Migration path is unavailable |
| `BV_CFG_OPERATION_UNSUPPORTED` | operation | Operation is unavailable |
| `BV_CFG_OUTPUT_LIMIT_EXCEEDED` | operation | Operation output exceeds its limit |
| `BV_CFG_PREVIEW_INPUT_INVALID` | operation | Preview input was rejected |
| `BV_CFG_REFERENCE_DUPLICATE` | semantic | Configuration reference is duplicated |
| `BV_CFG_REFERENCE_MISSING` | semantic | Configuration reference is unresolved |
| `BV_CFG_SCHEMA_CONSTRAINT` | schema | Field violates a configuration constraint |
| `BV_CFG_SCHEMA_REQUIRED_FIELD` | schema | Required configuration is missing |
| `BV_CFG_SCHEMA_TYPE` | schema | Field has the wrong value type |
| `BV_CFG_SCHEMA_UNKNOWN_FIELD` | schema | Field is not supported |
| `BV_CFG_SCHEMA_VERSION_REQUIRED` | compatibility | Configuration schema version is required |
| `BV_CFG_SCHEMA_VERSION_UNSUPPORTED` | compatibility | Configuration schema version is unsupported |
| `BV_CFG_SECRET_LITERAL_FORBIDDEN` | security | Secret content is forbidden in configuration |
| `BV_CFG_SEMANTIC_INVALID` | semantic | Configuration is not semantically valid |
| `BV_CFG_VERSION_MISMATCH` | compatibility | Installed release identity does not match |
| `BV_CFG_YAML_ALIAS_UNSUPPORTED` | syntax | YAML aliases are unsupported |
| `BV_CFG_YAML_EMPTY` | syntax | YAML document is empty |
| `BV_CFG_YAML_LIMIT_EXCEEDED` | syntax | YAML structural limit exceeded |
| `BV_CFG_YAML_MULTIPLE_DOCUMENTS` | syntax | Multiple YAML documents are unsupported |
| `BV_CFG_YAML_SYNTAX` | syntax | YAML syntax is invalid |

## Use the catalog

1. Select the catalog whose `contract_version` and `compiler_version` match the
   installed BonVoyage release.
2. Match a result by the exact `code`. Never infer behavior from an array
   position or parse the human runtime message.
3. Present the catalog title and summary alongside the actual diagnostic path,
   source range and redaction marker returned by the command.
4. Present `operator_action` as remediation guidance, not as proof that an
   automatic retry, apply or rollout is safe.
5. Preserve unknown future codes as unknown. Update to a matching catalog
   instead of guessing their meaning.

For example:

```bash
jq '.entries[] | select(.code == "BV_CFG_REFERENCE_MISSING")' \
  config/authoring/reason-codes/v1/catalog.json
```

After changing the reason-code registry or reviewed guidance, run:

```bash
make config-authoring-reason-codes-test
```

## Stability boundary

The stable compatibility surface is the reason `code` plus its class, default
severity and retryable flag in the versioned authoring contract. The generated
title, summary and operator action are reviewed release assets for consistent
presentation.

The runtime `message` is bounded, redacted diagnostic context. Its exact prose
is **not** a stable machine API and may become more precise without changing the
reason code. Automation must branch on `code`, not message text.

Only `BV_CFG_INPUT_UNREADABLE` is retryable by default in contract v1. Even
then, a caller should first correct a path, permission or transient file
availability problem. The flag is not permission for an unbounded retry loop.

## Security and authority boundary

The generated catalog includes no source document values, secret values,
environment reads, private infrastructure or customer material. Its generator
is deterministic, offline and non-mutating; exact SHA-256 identities bind the
authoring contract and separately reviewed guidance source.

Reason-code presentation does not validate YAML, compile a snapshot, authorize
an apply, contact a gateway or prove distribution, ACK, activation, rollback or
served traffic. The installed `bonvoyage-config` command and its
`snapshot.Compile` path remain the configuration authority.

See the [configuration authoring contract](../configuration-authoring-contract/)
for the result model, the
[configuration completion metadata](../configuration-completion-metadata/) for
field assistance, and the
[configuration test corpus](../configuration-test-corpus/) for release-matched
accepted and rejected examples.
