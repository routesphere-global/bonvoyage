---
title: Migrate a configuration explicitly
description: Run a release-shipped BonVoyage schema migration without guessing a source or target version.
---

The pre-release `bonvoyage-config migrate` operation applies one explicitly
selected, release-shipped configuration-schema migration. It runs offline,
does not contact a gateway, and never chooses a target version automatically.

:::caution[Current migration boundary]
Schema version `1` to version `1` is the only shipped pair. It is a byte-for-byte
no-change result. Every other pair is refused with
`BV_CFG_MIGRATION_UNSUPPORTED`; BonVoyage does not pretend that an unimplemented
upgrade succeeded. Packaging this source command into an approved public
release remains pending. Offline `preview` is implemented separately and does
not replace target validation.
:::

## Check a version 1 document

From the repository's `control-plane/` directory:

```bash
go run ./cmd/bonvoyage-config migrate \
  --input ../config/examples/local.yaml \
  --from-schema-version 1 \
  --to-schema-version 1
```

An accepted result identifies the exact input bytes and returns them unchanged:

```json
{
  "operation": "migrate",
  "status": "accepted",
  "result": {
    "kind": "migration",
    "from_schema_version": 1,
    "to_schema_version": 1,
    "changed": false,
    "document": "...",
    "document_sha256": "..."
  }
}
```

`document_sha256` identifies the exact returned bytes. For the current
no-change pair it equals the input SHA-256 identity.

## Read explicit standard input

Standard input must be selected deliberately and given a bounded source name:

```bash
cat legacy.yaml | go run ./cmd/bonvoyage-config migrate \
  --stdin \
  --source-id legacy.yaml \
  --from-schema-version 1 \
  --to-schema-version 1
```

The source document must declare `snapshot.schema_version: 1`; the declaration
must match `--from-schema-version`. A mismatch is refused with
`BV_CFG_VERSION_MISMATCH`.

## Validate the returned document

Migration proves only that the selected version pair exists and that the input
is safely parseable. It deliberately does not require the old document to pass
the current semantic compiler, because a future old schema may contain fields
that the current schema no longer accepts.

Always write the returned `result.document` to a separate reviewed file and
validate it with the same installed release before considering deployment:

```bash
go run ./cmd/bonvoyage-config validate \
  --input migrated.yaml \
  --require-configuration-schema-version 1
```

An accepted migration is **not** an accepted configuration, deployment, ACK,
activation, or traffic result.

## Use in-place mode carefully

`--in-place` requires `--input` and rejects symlinks. For the current no-change
pair, BonVoyage verifies the regular-file boundary but does not replace or
modify the file:

```bash
go run ./cmd/bonvoyage-config migrate \
  --input legacy.yaml \
  --from-schema-version 1 \
  --to-schema-version 1 \
  --in-place
```

Prefer separate output and review even after a future transforming migration is
shipped. Read-only migration may follow a symlink that resolves to a regular
YAML file; mutation may not.

## Safety and compatibility

- Input is UTF-8, at most 1 MiB, and exactly one YAML document.
- YAML aliases and merge keys are rejected.
- The source and target versions are mandatory, nonzero 32-bit values.
- Known secret-reference fields must contain filenames, not pasted PEM or
  private-key material; literal key material is rejected without echoing it.
- Product, compiler, and configuration-schema requirements may be pinned with
  the same `--require-*` flags as validation.
- Unsupported pairs never modify the selected input.

| Exit | Status | Meaning |
| ---: | --- | --- |
| `0` | `accepted` | The explicit pair exists and the complete migrated document was returned. |
| `2` | `rejected` | The input violated parsing, size, encoding, file, or secret-safety rules. |
| `3` | `refused` | The declared source, requested pair, or exact installed-version requirement did not match. |
| `4` | `failed` | The selected input could not be read or the result could not be written. |
| `70` | `failed` | An internal invariant failed. |
