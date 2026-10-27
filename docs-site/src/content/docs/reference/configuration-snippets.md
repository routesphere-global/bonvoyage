---
title: Configuration snippets
description: Compiler-backed, release-matched starting points for common BonVoyage configuration tasks.
---

BonVoyage publishes an editor-neutral snippet catalog at
`config/authoring/snippets/v1/catalog.json`. Each entry is extracted from an
exact reviewed YAML document that the release-matched `bonvoyage-config`
compiler accepts.

The catalog is useful to editors, assistant skills and people assembling YAML
by hand. It does not define another configuration language and it does not
make a fragment valid in every surrounding document.

## Included snippets

| ID | Purpose | Insertion |
| --- | --- | --- |
| `cluster-upstream-mtls` | Verify an upstream server and optionally present a client certificate | Merge into one cluster |
| `document-local-baseline` | Start from a complete local listener, routes, cluster and runtime limits | Replace an empty document |
| `listener-downstream-tls` | Add listener certificate and private-key references | Merge into one listener |
| `route-api-key-auth` | Require an API key from a named header | Merge into one route |
| `route-cors` | Add bounded browser-origin policy | Merge into one route |
| `route-fixed-response` | Return a local response without an upstream | Append to a route array |
| `route-header-transformations` | Set, append or remove request and response headers | Merge into one route |
| `route-jwt-auth` | Add JWT signature, claim, scope and verification-admission policy | Merge into one route |
| `route-local-rate-limit` | Add a shard-local token bucket | Merge into one route |
| `route-request-content` | Bound request size and media types | Merge into one route |
| `route-rewrite` | Rewrite upstream authority and path | Merge into one route |
| `route-static-redirect` | Return a redirect without an upstream | Merge into one route |
| `route-upstream` | Forward a path prefix to a named cluster | Append to a route array |
| `route-weighted-clusters` | Split one route across weighted clusters | Merge into one route |

Every entry carries:

- a stable ID, purpose and category;
- the exact source path, source selection and source SHA-256;
- a JSON payload and byte-bound YAML representation;
- an explicit insertion mode and canonical target container;
- reviewed edit points with release-matched field help and value constraints;
  and
- secret-reference markers where a deployment filename, never secret content,
  is expected.

## Use a snippet safely

1. Select the catalog whose contract, compiler and configuration-schema
   versions match the installed BonVoyage release.
2. Find the snippet by stable `id`; do not select a fragment by array position.
3. Apply its declared insertion mode to the declared container:
   `replace-document`, `merge-object` or `append-array-item`.
4. Review the listed edit points. Replace example names, routes, domains,
   cluster references and limits for the intended deployment.
5. For a secret-reference edit point, provide only a bounded filename made
   available through the deployment secret boundary. Never paste PEM, API-key,
   JWKS private-key or other secret contents into configuration YAML.
6. Validate the **complete resulting document** with the installed compiler,
   then preview its immutable artifact before any separate deployment action.

For inspection, this command prints the YAML representation of one catalog
entry when `jq` is available:

```bash
jq -r '.entries[] | select(.id == "route-jwt-auth") | .yaml' \
  config/authoring/snippets/v1/catalog.json
```

After integrating or changing the catalog, run:

```bash
make config-authoring-snippets-test
```

## Provenance and security boundary

The reviewed source manifest binds every source document to an exact SHA-256.
The generated catalog also binds the authoring contract, completion metadata
and manifest. Generation refuses source drift, unresolved selections,
unsupported insertion modes, unknown edit points, embedded secret material,
private workstation paths and stale checked-in output.

Secret-reference examples are filenames such as `server-key.pem`; they are not
secret values. The catalog reads no environment secret, contacts no network,
submits no telemetry and has no live gateway or rollout authority.

## Authority boundary

A snippet is a reviewed **starting point**. Insertion may still create duplicate
names, missing cluster references, incompatible route actions or another
semantic conflict in the surrounding document. Only `snapshot.Compile`,
reached through `bonvoyage-config validate` or `preview`, can accept the complete
configuration.

Validation still does not prove distribution, ACK, activation, rollback or
traffic behavior. Those facts belong to the runtime and its operational
evidence.

See the [configuration completion metadata](../configuration-completion-metadata/)
for the full field catalog and the
[configuration diagnostics](../configuration-diagnostics/) for stable
reason-code presentation. Replay the
[configuration test corpus](../configuration-test-corpus/) for shared accepted
and rejected documents.
