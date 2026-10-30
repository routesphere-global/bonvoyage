---
title: Explain a configuration field offline
description: Read reviewed, release-matched help for one BonVoyage configuration path without loading a document.
---

The release-matched `bonvoyage-config explain` source operation returns concise field help
from a reviewed catalog embedded in the installed command. It is deterministic
and offline. It does not read a YAML document, standard input, environment
secrets, runtime state, or telemetry, and it cannot apply a configuration.

:::note[Source command]
`explain` and the other configuration-authoring operations are released and
tested as source commands. These examples invoke them with `go run` from the
release source tree; do not assume a separate binary package.
:::

## Explain one field

From the repository's `control-plane/` directory, provide an RFC 6901 path:

```bash
go run ./cmd/bonvoyage-config explain \
  --path /listeners/0/port
```

An accepted result contains `kind`, `path`, `title`, and `summary`. Its
`inputs` array is empty because no configuration document was inspected. The
reported input configuration-schema version identifies the selected embedded
catalog, not a caller document.

## Use wildcard paths

The catalog documents object-array positions with `*`. Both the reviewed
wildcard and a canonical decimal index select the same explanation:

```bash
go run ./cmd/bonvoyage-config explain \
  --path '/clusters/*/endpoints/*/address'
```

The root document is the empty RFC 6901 path and must still be passed
explicitly:

```bash
go run ./cmd/bonvoyage-config explain --path ''
```

Array indexes are canonical decimal values: `0`, `1`, and `42` are valid;
`01`, negative values, and arbitrary tokens do not match an array wildcard.
RFC 6901 escaping uses `~0` for `~` and `~1` for `/`.

## Require an exact release match

Automation can refuse help from a different installed release or schema:

```bash
go run ./cmd/bonvoyage-config explain \
  --path /virtual_hosts/0/routes/0/jwt_auth/jwks_secret \
  --require-product-version 0.2.0 \
  --require-compiler-version bonvoyage-control-plane-phase4-admin-v1 \
  --require-configuration-schema-version 1
```

These requirements constrain the installed identities. They cannot override
the embedded versions.

## Interpret the result

| Exit | Status | Meaning |
| ---: | --- | --- |
| `0` | `accepted` | The path matched a reviewed entry in the embedded release catalog. |
| `2` | `rejected` | The path was malformed or is not documented by this release. |
| `3` | `refused` | An exact caller version requirement did not match. |
| `70` | `failed` | The operation or embedded catalog failed an internal invariant. |

Unknown paths return `BV_CFG_EXPLAIN_PATH_UNKNOWN`. The diagnostic is static
and does not echo the caller-controlled path. Help text is authored for the
release and never derives from customer configuration values.

An explanation describes configuration syntax only. It does not prove that a
document is valid, that a gateway received or ACKed a snapshot, or that the
field is active in live traffic. Use [offline validation](../validate-configuration/)
for compiler acceptance and runtime management surfaces for delivery facts.
