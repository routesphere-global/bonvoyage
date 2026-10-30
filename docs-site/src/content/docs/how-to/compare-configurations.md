---
title: Compare configurations offline
description: Review deterministic, redacted changes between two accepted BonVoyage configurations by compiled meaning.
---

The release-matched `bonvoyage-config diff` source operation compiles a baseline and a
proposed configuration with the installed BonVoyage compiler, then reports
which configuration paths changed. It does not print old or new scalar values,
contact a gateway, or authorize an apply.

:::note[Source command]
`diff` and the other configuration-authoring operations are released and
tested as source commands. These examples invoke them with `go run` from the
release source tree; do not assume a separate binary package.
:::

## Compare the shipped examples

From the repository's `control-plane/` directory, compare the release-matched
plain HTTP and downstream-TLS examples:

```bash
go run ./cmd/bonvoyage-config diff \
  --baseline ../config/examples/local.yaml \
  --proposed ../config/examples/tls.yaml
```

This is a read-only comparison. It does not require the referenced TLS secret
files because it compiles the declarative secret references rather than
starting a listener.

An accepted result identifies both bounded inputs, both deterministic compiled
artifacts, and a sorted change list:

```json
{
  "operation": "diff",
  "status": "accepted",
  "result": {
    "kind": "semantic-diff",
    "baseline_artifact_sha256": "...",
    "proposed_artifact_sha256": "...",
    "changes": [
      {"path": "/listeners/0/port", "kind": "changed"}
    ]
  }
}
```

The complete machine result also carries the contract, product, compiler, and
configuration-schema identities. Each artifact digest is a full 64-character
SHA-256 value.

## Read one side from standard input

Exactly one side may come from explicit standard input:

```bash
cat ../config/examples/local.yaml | go run ./cmd/bonvoyage-config diff \
  --baseline-stdin \
  --baseline-source-id local.yaml \
  --proposed ../config/examples/tls.yaml
```

For your own files, replace these paths with two complete configurations that
you created or reviewed. Reverse the standard-input direction with
`--baseline PATH`, `--proposed-stdin`, and `--proposed-source-id NAME`. Both
sides cannot use the same standard input stream.

## Interpret paths and changes

Paths use RFC 6901 notation and the public desired-state field names. Repeated
resources use their canonical compiled index. The change kinds are:

| Kind | Meaning |
| --- | --- |
| `added` | A presence-aware field or indexed item exists only in the proposal. |
| `removed` | A presence-aware field or indexed item exists only in the baseline. |
| `changed` | A compiled scalar, map, or corresponding indexed item differs. |

The operation compares the immutable snapshot consumed by the data plane.
Comments, YAML key ordering, quoting style, and equivalent presentation do not
produce changes. Compiler-applied defaults are already present in the compared
snapshot. Node-local `server` settings are deliberately absent from that
snapshot, so changing only `server.node_id`, `server.admin_addr`, or
`server.metrics_addr` produces different input identities but no data-plane
semantic change.

Repeated collections are compared by compiled position because route,
listener, endpoint, mutation, and policy order can affect behavior. Inserting
an item near the beginning may therefore report changes at later indexes.

## Redaction and limits

The result contains paths and change kinds only. It never contains before or
after scalar values, extracted-value hashes, PEM contents, or deployment-secret
filenames. Whole-input and whole-artifact SHA-256 identities remain present as
configuration metadata.

Both inputs must independently pass the same installed compiler. A failure
identifies `/baseline` or `/proposed` with `BV_CFG_DIFF_INPUT_INVALID` and
retains the underlying redacted compiler diagnostic. The result fails closed
rather than truncating if more than 10,000 changes would be returned.

## Require an exact release match

Automation may bind the comparison to exact installed identities:

```bash
go run ./cmd/bonvoyage-config diff \
  --baseline ../config/examples/local.yaml \
  --proposed ../config/examples/tls.yaml \
  --require-product-version 0.2.0 \
  --require-compiler-version bonvoyage-control-plane-phase4-admin-v1 \
  --require-configuration-schema-version 1
```

| Exit | Status | Meaning |
| ---: | --- | --- |
| `0` | `accepted` | Both documents compiled and the complete bounded diff was returned. |
| `2` | `rejected` | An input was invalid or the bounded output limit was exceeded. |
| `3` | `refused` | An exact caller version requirement did not match. |
| `4` | `failed` | A selected input could not be read or the result could not be written. |
| `70` | `failed` | An internal invariant failed. |

An accepted local diff does not prove that any node received, ACKed, activated,
or serves the proposed snapshot. Those remain runtime management facts.
