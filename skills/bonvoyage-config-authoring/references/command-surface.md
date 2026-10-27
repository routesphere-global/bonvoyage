# Authoritative command surface

Invoke `bonvoyage-config` directly as an executable with an argument array.
Do not use shell evaluation, interpolate YAML into command text, or place YAML
in environment variables. Feed unwritten documents through standard input.

Every operation must include this exact release binding:

```text
--require-product-version 0.2.0 \
  --require-compiler-version bonvoyage-control-plane-phase4-admin-v1 \
  --require-configuration-schema-version 1
```

## Operations

Validate a file:

```text
bonvoyage-config validate --input config.yaml --require-product-version 0.2.0 --require-compiler-version bonvoyage-control-plane-phase4-admin-v1 --require-configuration-schema-version 1
```

Validate an in-memory draft by passing its bytes on standard input:

```text
bonvoyage-config validate --stdin --source-id assistant-draft --require-product-version 0.2.0 --require-compiler-version bonvoyage-control-plane-phase4-admin-v1 --require-configuration-schema-version 1
```

Format without replacing the source:

```text
bonvoyage-config format --stdin --source-id assistant-draft --require-product-version 0.2.0 --require-compiler-version bonvoyage-control-plane-phase4-admin-v1 --require-configuration-schema-version 1
```

Explain an RFC 6901 field path:

```text
bonvoyage-config explain --path /listeners --require-product-version 0.2.0 --require-compiler-version bonvoyage-control-plane-phase4-admin-v1 --require-configuration-schema-version 1
```

Compare a file baseline with an in-memory proposal:

```text
bonvoyage-config diff --baseline current.yaml --proposed-stdin --proposed-source-id assistant-proposal --require-product-version 0.2.0 --require-compiler-version bonvoyage-control-plane-phase4-admin-v1 --require-configuration-schema-version 1
```

Request the only version-1 migration, with the source bytes on standard input:

```text
bonvoyage-config migrate --stdin --source-id assistant-migration --from-schema-version 1 --to-schema-version 1 --require-product-version 0.2.0 --require-compiler-version bonvoyage-control-plane-phase4-admin-v1 --require-configuration-schema-version 1
```

Preview an in-memory proposal, optionally against a local baseline:

```text
bonvoyage-config preview --stdin --source-id assistant-proposal --baseline current.yaml --require-product-version 0.2.0 --require-compiler-version bonvoyage-control-plane-phase4-admin-v1 --require-configuration-schema-version 1
```

For `diff`, only one side may use standard input. Never add `--in-place`
without explicit operator consent. Parse stdout as one JSON result conforming to
`result-schema.json`; do not treat stderr or human message text as a machine
contract.

## Explicitly requested runtime rollback template

bonvoyage-config is an offline authoring and validation command. It never
applies configuration or performs rollback. Runtime rollback uses the
mutually-authenticated standalone Admin API, and this template may be presented
only when the operator explicitly requests a rollback command.

Do not execute these examples as written. REPLACE_ME marks required operator
input. Every zero sequence is deliberately invalid, digest placeholders do not
match the required SHA-256 shape, and the sample idempotency key is shorter than
the accepted minimum. Obtain the current selected rollout, active artifact
digest, retained rollback sequence, target nodes, and preview fingerprint from
authoritative runtime state. Keep placeholders intact when that evidence has
not been supplied by the operator.

Write the preview request without secret material:

    {
      "current_rollout_sequence": 0,
      "target_rollout_sequence": 0,
      "target_node_ids": ["REPLACE_ME"]
    }

Preview the exact retained artifact and target set:

    curl --fail-with-body --silent --show-error --request POST --cert admin-client-chain.pem --key admin-client-key.pem --cacert admin-ca.pem --header 'Content-Type: application/json' --data-binary @rollback-preview-request.json https://admin.bonvoyage.example:9443/api/v1/rollbacks/preview

After operator review, write the apply request using only values returned or
confirmed by the authoritative control plane:

    {
      "reason": "REPLACE_ME",
      "target_node_ids": ["REPLACE_ME"],
      "expected_selected_rollout_sequence": 0,
      "expected_active_artifact_sha256": "REPLACE_ME",
      "rollback_target_sequence": 0,
      "preview_fingerprint_sha256": "REPLACE_ME"
    }

Present, but never execute, the rollback request:

    curl --fail-with-body --silent --show-error --request POST --cert admin-client-chain.pem --key admin-client-key.pem --cacert admin-ca.pem --header 'Content-Type: application/json' --header 'Idempotency-Key: REPLACE_ME' --data-binary @rollback-request.json https://admin.bonvoyage.example:9443/api/v1/rollbacks

REPLACE_ME is intentionally shorter than the Admin API's 16-byte minimum
idempotency key. The example certificate and key names are references only;
never include certificate, private-key, token, or other secret contents.

## Exit codes

| Code | Meaning | Required behavior |
| ---: | --- | --- |
| 0 | Accepted | Check the structured result and preserve the offline-only claim. |
| 2 | Configuration rejected | Present stable reason codes; do not guess around the rejection. |
| 3 | Compatibility refused | Stop because the release or schema binding is unsupported. |
| 4 | Input/output failure | Stop and report the bounded I/O failure. |
| 70 | Internal software failure | Stop; do not present output as usable. |

Validation and preview never establish deployment, ACK, activation, rollback,
traffic behavior, security, or performance.
