---
title: Configuration completion metadata
description: Release-matched field, literal, constraint, help, and secret-reference hints for BonVoyage configuration tools.
---

BonVoyage publishes deterministic configuration-completion metadata at
`config/authoring/completion/v1/metadata.json`. Editors, assistant skills and
other offline authoring tools can consume this file instead of inventing their
own field catalog.

The asset is generated from three reviewed release inputs:

- the BonVoyage configuration JSON Schema;
- the versioned configuration-authoring contract; and
- the release-matched field-explanation catalog.

Each source path and SHA-256 is recorded in the generated file. Run the
following check after changing any of those inputs:

```bash
make config-authoring-completion-test
```

## Entry model

The v1 asset contains one sorted entry for each canonical RFC 6901-style field
path in the supported configuration schema. `*` denotes an array item, such as
`/listeners/*/protocol`.

Each entry reports:

- its canonical path, parent path and field key;
- reviewed title and help text;
- whether the field is directly required by its containing schema object;
- whether the field is a deployment-secret reference; and
- direct value hints such as kind, allowed literals, constants, numeric or
  string bounds, patterns, array bounds and array-item kind.

For example, `/listeners/*/protocol` offers the release-supported `http1`,
`http2` and `http3` literals. A secret field is marked as a reference field,
but the metadata never contains a certificate, private key, API key, JWKS
document, customer value or value-derived hash.

## Consumer rules

1. Select the metadata whose `contract_version`, `compiler_version` and
   `configuration_schema_version` match the installed BonVoyage release.
2. Verify or package the checked-in file; do not regenerate it from an
   unreviewed remote schema at runtime.
3. Match canonical paths and present only the hints carried by the selected
   entry.
4. Treat `required_in_parent` as direct object-level requiredness only.
   Conditional requirements, references, defaults and cross-field rules are
   intentionally absent.
5. Treat `secret_reference` as a presentation and handling warning. The field
   accepts a bounded deployment-secret filename according to the authoring
   contract, never secret contents.
6. Send the complete document to the installed `bonvoyage-config validate` or
   `preview` operation before describing it as accepted.

## Authority boundary

The completion asset is **editor assistance, not a validator**. It does not
reproduce compiler defaults, cross-resource references, conditional rules,
secret-literal rejection, immutable artifact generation, or rollout state.
`snapshot.Compile`, reached through the release-matched local command, remains
the semantic authority.

Completion metadata is offline and non-mutating. Loading it does not contact a
gateway, read environment secrets, submit telemetry, authorize an apply, or
prove that a node received, ACKed or activated a configuration.

Use the [configuration authoring contract](../configuration-authoring-contract/)
for operation and diagnostic rules, and replay the
[configuration test corpus](../configuration-test-corpus/) when integrating a
new editor or assistant surface.

Use the [configuration snippets](../configuration-snippets/) for reviewed,
compiler-backed starting fragments whose edit points reuse this metadata.

Use the [configuration diagnostics](../configuration-diagnostics/) to present
stable reason codes and reviewed remediation after validation or another
authoring operation rejects input.
