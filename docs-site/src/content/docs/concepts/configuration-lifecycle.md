---
title: Configuration lifecycle
description: How BonVoyage validates, compiles, activates, rejects, and rolls back configuration.
---

BonVoyage treats configuration as a versioned artifact, not as mutable request-
path state.

## Offline bootstrap

The local and static-deployment path is:

```text
YAML -> schema and semantic validation -> snapshot compiler -> binary snapshot
     -> data-plane startup -> active snapshot
```

The data plane needs only the compiled snapshot at runtime. This keeps the
control plane outside the request path and supports a controller-independent
serving mode.

## Managed rollout

The standalone control plane adds a guarded sequence:

1. Submit a complete desired-state document.
2. Validate syntax, references, action exclusivity, TLS boundaries, and runtime
   limits.
3. Preview the change against the expected active sequence and target nodes.
4. Create an idempotent rollout using the preview fingerprint.
5. Distribute the immutable candidate and collect ACK or structured NACK state.
6. Activate only the accepted generation, or roll back to a retained artifact.

Listener additions and certain TLS listener changes require controlled process
replacement rather than an in-place snapshot activation. The runtime preserves
the existing listener and reports that restart requirement.

## Secret references

Configuration contains secret filenames or references, not pasted private-key
material. Operators place certificate chains, private keys, and trust bundles
through the deployment secret boundary and mount them read-only. Do not commit
live secrets to YAML or Git.

The initial OSS listener model uses one certificate and key pair per TLS
listener. Multi-tenant SNI certificate selection and managed certificate
lifecycle are not implied by the current configuration contract.
