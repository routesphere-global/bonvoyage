---
title: Configuration authoring contract
description: Version, operation, diagnostic, and safety boundaries shared by BonVoyage configuration tools.
---

BonVoyage has a versioned contract for configuration-authoring tools. It keeps
the future command line, editor add-on, public assistant skills, CI, and Console
from developing different interpretations of the same YAML.

The machine-readable policy is
`config/authoring/bonvoyage-authoring-v1.json`. Its contract and result schemas
are under `config/schemas/`.

The release-matched [configuration test corpus](../configuration-test-corpus/)
binds representative accepted artifact identities and rejected diagnostics to
this contract and the real compiler.

The generated [configuration completion metadata](../configuration-completion-metadata/)
turns reviewed schema and field-help inputs into deterministic editor hints.
It remains structural assistance and does not duplicate compiler semantics.

The generated [configuration snippets](../configuration-snippets/) provide
reviewed starting fragments from exact compiler-accepted source documents.
They still require complete-document validation after insertion.

The generated [configuration diagnostics](../configuration-diagnostics/)
map every stable reason code to release-matched presentation and remediation
guidance without making runtime message text part of the compatibility API.

:::caution[Incremental implementation]
All six offline operations are implemented and tested in the pre-release source
tree, so the machine contract is marked `implemented`. They are not yet
approved packaged-release commands; clean-source export acceptance and release
packaging remain separate gates.
:::

## One authority

The installed Go snapshot compiler is the semantic authority. The JSON Schema
is useful for completion and immediate structural feedback, but schema
acceptance alone does not mean that a configuration can be deployed.

Every result identifies:

- the authoring-contract version;
- the installed BonVoyage product version;
- the compiled-in compiler identity;
- the configuration schema versions that installation supports; and
- the schema version declared by the input document.

A caller may require exact versions. It cannot override the versions actually
installed. A mismatch is refused with `BV_CFG_VERSION_MISMATCH`.

## Operations

| Operation | Contract |
| --- | --- |
| `validate` | Compile one complete desired-state document and report acceptance, artifact identity, or structured errors. |
| `format` | Produce a separate, comment-preserving document by default; in-place replacement must be explicit and atomic. |
| `explain` | Return reviewed, release-matched help for an RFC 6901 field path. |
| `diff` | Compare two accepted documents by compiled meaning without exposing scalar before/after values. |
| `migrate` | Run only an explicit, release-shipped schema migration; v1 to v1 is currently the only no-change pair. |
| `preview` | Compile a local immutable artifact and report post-default metadata, counts, and optional redacted local-baseline changes. |

All six operations are offline. They do not use telemetry, access the network,
read environment secrets, execute a shell, contact a gateway, or authorize a
live apply.

The implemented `explain` slice reads no configuration document. It selects
one reviewed catalog entry by RFC 6901 path and reports the catalog's
configuration-schema version as the selected static authority. Concrete array
indexes and documented `*` wildcard paths are accepted. Unknown or malformed
paths fail closed without echoing the caller-controlled path.

The implemented `diff` slice compiles two complete documents and compares only
their immutable data-plane snapshots. It returns sorted RFC 6901 configuration
paths and `added`, `removed`, or `changed` kinds without returning scalar
before/after values. Presentation-only and node-local `server` changes are not
data-plane semantic changes. Repeated resources are compared by compiled
position, and output fails closed above 10,000 changes.

The implemented `migrate` slice requires explicit source and target schema
versions. Contract v1 ships only the byte-preserving version `1` to version `1`
pair; every other pair is refused. Migration applies safe parsing and secret
boundaries but does not require current semantic validity, because a future
old-schema input may not compile under the target schema. Its returned document
must therefore pass a separate `validate` operation before use.

The implemented `preview` slice compiles one complete proposal and optionally
one explicitly selected local baseline. It reports the proposal artifact
identity, resource counts, and the same path/kind-only semantic changes as
`diff`. Compiler defaults are reflected in deterministic artifact identity;
preview does not duplicate compiler semantics by enumerating inferred default
paths or values. It has no node selector, credentials, network access, or apply
authority.

## Input and locations

Automatic editor recognition requires a case-insensitive `.yaml` or `.yml` file plus the
BonVoyage top-level structure and `snapshot.schema_version`. Standard input is
accepted only when explicitly selected. Input is UTF-8, bounded to 1 MiB, and
limited to one document without aliases or merge keys.

Locations use one-based lines, one-based Unicode-scalar columns, and a
zero-based byte offset into the original UTF-8 input. End positions are
exclusive. Read-only operations may resolve a symlink path to a regular file;
in-place formatting or migration rejects symlinks.

An input identity covers exactly the bounded bytes observed by an operation.
Normal readable inputs therefore receive a complete-file identity. Oversized
inputs record and hash only the first 1 MiB, and unreadable inputs record an
empty observation; neither is represented as a full-file digest.

## Diagnostics and secrets

Diagnostics have stable `BV_CFG_*` reason codes, `error`, `warning`, or `info`
severity, an optional RFC 6901 path, an optional exact source range, and an
explicit redaction flag. At most 256 diagnostics are returned in deterministic
order.

Document values are untrusted. Diagnostics and logs never echo input scalar
values, and the tools do not emit hashes of extracted scalar or secret values.
The machine result does carry the bounded whole-input identity described above,
so it should be handled as configuration metadata. Certificate, key, trust,
API-key, and JWKS configuration fields contain bounded deployment-secret
filenames, not PEM files or credential contents. Pasted PEM material is
rejected without echoing it.

`format` and `migrate` may return a complete document only as their explicit
primary result. That necessary output is never also copied into diagnostics or
logs.

## What a local result does not prove

Validation or preview proves only what the exact installed compiler accepted.
It does not prove that a gateway received the artifact, ACKed it, activated it,
or serves traffic from it. Those are runtime facts and must come from the
authoritative management and data-plane surfaces.

Continue with [Validate a configuration](../../how-to/validate-configuration/),
[Format a configuration](../../how-to/format-configuration/),
[Explain a configuration field](../../how-to/explain-configuration-field/),
[Compare configurations](../../how-to/compare-configurations/), or
[Migrate a configuration](../../how-to/migrate-configuration/), or
[Preview a configuration](../../how-to/preview-configuration/) for the exact
pre-release command syntax and machine exit codes.
