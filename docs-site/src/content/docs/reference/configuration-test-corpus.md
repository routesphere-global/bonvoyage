---
title: Configuration test corpus
description: Release-matched accepted and rejected configurations shared by BonVoyage authoring surfaces.
---

BonVoyage publishes a versioned configuration corpus so the command line,
Console, editor integrations, public assistant skills, and CI can be checked
against the same decisions. The Go snapshot compiler remains the semantic
authority; the corpus records its reviewed outcomes instead of reimplementing
its rules.

The machine-readable manifest is
`config/authoring/corpus/v1/manifest.json`. Its strict schema is
`config/schemas/bonvoyage-authoring-corpus-v1.schema.json`.

## Replay the corpus

From the repository root, install the locked JavaScript dependencies and run:

```bash
make dependencies
make config-authoring-corpus-test
```

The replay builds the real `bonvoyage-config` command and executes every case
twice. It verifies deterministic output, exact input bytes and SHA-256, the
authoring result schema, installed version identity, and the expected compiler
decision.

## Version 1 profile

The bounded version 1 profile contains 11 cases:

| Outcome | Coverage |
| --- | --- |
| Accepted | Local fixed response and upstream routing, TLS secret references, and API-key policy across HTTP/1.1 and HTTP/2 listeners |
| Rejected | Malformed YAML, multiple documents, aliases, wrong types, unknown fields, unsupported schema versions, missing references, and pasted private-key material |

Accepted cases bind the exact immutable artifact SHA-256, byte count, snapshot
identity, configuration-schema version, and minimum data-plane version.
Rejected cases bind the stable reason code, redaction state, optional RFC 6901
path, and exact source coordinates where the compiler provides them. Synthetic
private values in security cases must not appear in command output.

The corpus is intentionally reviewed and bounded. Passing it does not imply
that every possible valid or invalid configuration has been enumerated.

## Cross-surface use

An integration may use JSON Schema for completion and immediate structural
feedback, but it must use the release-matched `bonvoyage-config validate`
result for authoritative acceptance. A surface passes this contract only when
its observed status, stable reason code, source location, redaction behavior,
and accepted artifact identity agree with the corpus manifest.

Changing a fixture, expected result, compiler identity, or artifact digest is
a reviewed release change. Consumers must not silently rewrite the corpus or
substitute an editor-specific validator.

## Cross-surface release contract

The machine-readable ADOPT-06 agreement boundary is
`config/authoring/cross-surface/v1/contract.json`; its strict schema is
`config/schemas/bonvoyage-authoring-cross-surface-v1.schema.json`. It binds the
compiler, local command, public skill packages, public CI and Console to the
same normalized accepted and rejected projections.

Run its deterministic contract check with:

```bash
make config-authoring-cross-surface-contract-test
```

The current gate remains open. The Console validation path still needs to
preserve the stable redacted diagnostic projection for rejected documents, and
the remaining upgrade, downgrade, uninstall and Windows large-input lifecycle
checks must pass. The contract records these gaps rather than treating package
generation or provider-model evidence as cross-surface agreement.

## Security and runtime boundary

The corpus is offline and contains no real credential, customer value, private
infrastructure identifier, network action, or live mutation authority. Its
secret cases use conspicuous synthetic markers solely to prove no-echo
behavior.

Corpus success does not prove that a gateway received, ACKed, activated, or
served traffic from a configuration. Those facts require authenticated
control-plane evidence and a live data-plane test. See the
[configuration authoring contract](../configuration-authoring-contract/) for the
full command and authority boundary.
