---
title: Validate a configuration offline
description: Compile one BonVoyage YAML document locally and consume its deterministic machine result.
---

The v1.0.4 source release includes the bounded offline-validation operation of
the BonVoyage configuration-authoring command. It invokes the
same Go snapshot compiler that creates the immutable data-plane artifact. It
does not contact a gateway, inspect runtime state, or authorize an apply.

:::note[Source command]
`validate`, `format`, `explain`, `diff`, `migrate`, and `preview` are released
and tested as source commands. The examples on this site invoke them with
`go run` from the release source tree; do not assume a separate binary package.
:::

## Validate a file

From the repository's `control-plane/` directory:

```bash
go run ./cmd/bonvoyage-config validate \
  --input ../config/examples/local.yaml
```

The command writes exactly one JSON result to standard output for a valid
invocation. An accepted result includes the input identity, installed product
and compiler identities, configuration-schema version, and deterministic
snapshot artifact identity.

## Validate standard input

Standard input must be selected explicitly and should have a useful source
identifier:

```bash
cat ../config/examples/local.yaml | \
  go run ./cmd/bonvoyage-config validate \
    --stdin \
    --source-id local.yaml
```

The source identifier appears in diagnostics only as location metadata. It is
not interpreted as a path.

## Require exact versions

Automation can refuse stale or mismatched tooling instead of silently using a
different compiler:

```bash
go run ./cmd/bonvoyage-config validate \
  --input ../config/examples/local.yaml \
  --require-product-version 0.2.0 \
  --require-compiler-version bonvoyage-control-plane-phase4-admin-v1 \
  --require-configuration-schema-version 1
```

These flags constrain the installed identities. They cannot override them.

## Interpret the result

| Exit | Status | Meaning |
| ---: | --- | --- |
| `0` | `accepted` | The installed compiler accepted the document and produced the reported immutable artifact. |
| `2` | `rejected` | Syntax, schema, semantic, size, encoding, or supported-file validation failed. |
| `3` | `refused` | An exact caller version requirement did not match. |
| `4` | `failed` | The selected input could not be read as a regular file or stream. |
| `70` | `failed` | The operation encountered an internal software failure. |

Diagnostics use stable `BV_CFG_*` codes, optional RFC 6901 paths, optional
source locations, and static bounded messages. They do not echo source scalar
values. A successful local validation does **not** prove delivery, ACK,
activation, or live traffic behavior.

## Bounded input identity

The input record identifies exactly the bytes the command was allowed to
observe. For a normal file, that is the complete file. For an oversized input,
the command records and hashes only the first 1 MiB before rejecting it. For an
input that cannot be opened, it records zero observed bytes and the SHA-256 of
the empty observation. Neither case is presented as a full-file digest.

The digest covers the complete bounded document rather than any extracted
field. Treat the JSON result as configuration metadata and do not publish it
without the same review applied to the source configuration.

Read the [configuration authoring contract](../../reference/configuration-authoring-contract/)
for the complete operation, redaction, and versioning boundary.
