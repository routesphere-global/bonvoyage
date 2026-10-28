---
title: Format a configuration safely
description: Normalize BonVoyage YAML offline while preserving comments, line endings, and compiled meaning.
---

The pre-release `bonvoyage-config format` operation formats one complete,
compiler-accepted BonVoyage configuration. It is offline and deterministic.
It does not contact a gateway, authorize an apply, or report runtime state.

:::caution[Pre-release command slice]
`format` is implemented and tested in source, but packaging it into an approved
public release remains pending. `explain`, `diff`, `migrate`, and immutable
artifact `preview` are also implemented in source.
:::

## Preview a formatted document

Formatting is non-mutating by default:

```bash
go run ./cmd/bonvoyage-config format \
  --input ../config/examples/local.yaml
```

The command emits one JSON result. The complete formatted YAML is the
`result.document` value, and `result.document_sha256` identifies those exact
bytes. `result.changed` says whether they differ from the input. The selected
file is not changed.

Standard input must be selected explicitly:

```bash
cat ../config/examples/local.yaml | \
  go run ./cmd/bonvoyage-config format \
    --stdin \
    --source-id local.yaml
```

## Replace a file explicitly

Use `--in-place` only with a selected file. For a first evaluation, copy the
shipped example to a disposable working file so the repository remains clean:

```bash
cp ../config/examples/local.yaml /tmp/bonvoyage-formatted.yaml

go run ./cmd/bonvoyage-config format \
  --input /tmp/bonvoyage-formatted.yaml \
  --in-place

go run ./cmd/bonvoyage-config validate \
  --input /tmp/bonvoyage-formatted.yaml
```

The final validation must be accepted. Use `--in-place` on a source-controlled
configuration only when you intentionally want to review and commit its
formatting change.

The command first completes every validation and preservation check. If the
result changed, it writes a temporary regular file in the same directory,
preserves the source ownership and permission bits on supported Unix systems,
flushes the file, rechecks the selected source identity, and atomically renames
the temporary file over it. An
unchanged result does not replace the file.

In-place formatting rejects symbolic links with `BV_CFG_INPUT_SYMLINK`.
Read-only formatting may resolve a symbolic link when its target and opened
descriptor are regular files.

## Preservation guarantees

An accepted result proves all of the following for the exact input and
installed release:

- the original document passed the authoritative Go snapshot compiler;
- every YAML head, line, and foot comment remained attached to the same syntax
  node with the same text;
- an optional UTF-8 BOM was preserved;
- consistent LF or CRLF style and terminal-newline presence were preserved;
- the formatted document compiled to the same deterministic snapshot bytes;
- a second format pass produced identical bytes; and
- the formatted document remained within the 1 MiB configuration limit.

The formatter preserves source field order and scalar style through the YAML
syntax tree. It does not materialize compiler defaults into the source.

## Fail-closed cases

The operation returns no partial document when preservation cannot be proved.
Mixed LF/CRLF input, a lone carriage return, a comment-association change,
non-idempotent output, changed compiled meaning, or another uncertain
presentation case returns `BV_CFG_FORMAT_UNSAFE`. Oversized output returns
`BV_CFG_OUTPUT_LIMIT_EXCEEDED`.

Syntax, schema, semantic, secret-reference, size, encoding, and exact-version
failures use the same structured result and exit codes as
[offline validation](../validate-configuration/). A formatting success proves
neither data-plane delivery nor ACK, activation, or live traffic behavior.
