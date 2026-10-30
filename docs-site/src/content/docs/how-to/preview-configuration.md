---
title: Preview an immutable configuration artifact
description: Compile BonVoyage YAML offline and inspect its deterministic artifact identity, resource counts, and optional redacted changes.
---

The release-matched `bonvoyage-config preview` source operation compiles one complete
configuration with the installed BonVoyage compiler and summarizes the exact
immutable artifact that compilation produced. It runs offline, returns no
source document or scalar values, and cannot contact or change a gateway.

:::note[Source command]
`preview` and the other configuration-authoring operations are released and
tested as source commands invoked with `go run`; do not assume a separate
binary package. An accepted local preview proves
compiler acceptance only. It does not prove delivery, ACK, activation, or
served traffic.
:::

## Preview one file

From the repository's `control-plane/` directory:

```bash
go run ./cmd/bonvoyage-config preview \
  --input ../config/examples/local.yaml
```

The result includes post-default artifact metadata and bounded resource counts:

```json
{
  "operation": "preview",
  "status": "accepted",
  "result": {
    "kind": "preview",
    "artifact": {
      "sha256": "...",
      "bytes": 267,
      "snapshot_id": "local-bootstrap",
      "schema_version": 1,
      "minimum_dataplane_version": "0.2.0"
    },
    "counts": {
      "listeners": 1,
      "virtual_hosts": 1,
      "routes": 2,
      "clusters": 1,
      "endpoints": 1
    },
    "changes": []
  }
}
```

`artifact.sha256` covers the deterministic serialized snapshot consumed by the
data plane. Compiler defaults are already materialized in that snapshot and
therefore affect its identity. Preview deliberately does not enumerate
source-specific defaulted paths or print their scalar values; doing so would
duplicate compiler semantics in a second detector.

## Compare with a local baseline

Use the shipped plain HTTP example as a reviewed baseline for the downstream
TLS example. This adds the same redacted semantic change set used by
`bonvoyage-config diff`:

```bash
go run ./cmd/bonvoyage-config preview \
  --input ../config/examples/tls.yaml \
  --baseline ../config/examples/local.yaml
```

The result then includes `baseline_artifact_sha256`. `changes` contains only
sorted RFC 6901 paths and `added`, `removed`, or `changed` kinds. It never
contains before or after values.

The proposed document is always the first input identity and the optional
baseline is second. The baseline is read only from the selected path. It is
never discovered from a running node or control-plane database.

## Preview standard input

The proposal may come from explicitly selected standard input while the
optional baseline remains a local path:

```bash
cat ../config/examples/tls.yaml | go run ./cmd/bonvoyage-config preview \
  --stdin \
  --source-id tls.yaml \
  --baseline ../config/examples/local.yaml
```

Omit `--baseline` for an artifact-only preview. `--source-id` is reporting
metadata and is never interpreted as a path.

## Interpret failures

Both proposal and baseline must independently pass the same installed
compiler. A rejected proposal is identified at `/document`; a rejected
baseline is identified at `/baseline`. Both use
`BV_CFG_PREVIEW_INPUT_INVALID` before the underlying redacted compiler
diagnostic. No partial artifact or count result is returned after rejection.

The change list fails closed rather than truncating above 10,000 entries.
Inputs remain bounded to 1 MiB, valid UTF-8, one YAML document, and no aliases
or merge keys.

## Require an exact release match

Automation may bind preview to the exact installed authority:

```bash
go run ./cmd/bonvoyage-config preview \
  --input ../config/examples/tls.yaml \
  --require-product-version 0.2.0 \
  --require-compiler-version bonvoyage-control-plane-phase4-admin-v1 \
  --require-configuration-schema-version 1
```

| Exit | Status | Meaning |
| ---: | --- | --- |
| `0` | `accepted` | Compilation and the complete bounded summary succeeded. |
| `2` | `rejected` | A selected input was invalid or the change limit was exceeded. |
| `3` | `refused` | An exact caller version requirement did not match. |
| `4` | `failed` | A selected input could not be read or the result could not be written. |
| `70` | `failed` | An internal invariant failed. |

Use Console Free to prove rollout and node state. Offline preview intentionally
has no credentials, target selector, apply command, or runtime authority. A
supported programmatic management contract is not part of the public OSS
documentation.
