# Configuration

Schemas, policy examples, and sample runtime configuration. `local.yaml` is a
cleartext bootstrap, `tls.yaml` configures downstream TLS/mTLS, and
`upstream-tls.yaml` configures verified upstream mTLS. Production defaults
should be explicit and reviewable.

## Authoring contract

`authoring/bonvoyage-authoring-v1.json` freezes the shared offline contract for
future CLI, editor, assistant, CI, and Console authoring surfaces. Its contract
schema and machine-result schema are under `schemas/`. The contract defines
version binding, file recognition, `validate`, `format`, `explain`, `diff`,
`migrate`, and `preview`, stable diagnostics, source coordinates, exit codes,
and redaction rules.

All six offline operations are implemented in the pre-release source command,
and the contract is marked `implemented`; no approved packaged public command
is claimed yet. Migration currently ships only the byte-preserving schema
version 1 to version 1 pair and must be followed by validation. Preview reports
post-default artifact metadata, resource counts, and optional redacted local
changes without live authority. The existing Go snapshot compiler remains the
semantic authority.
JSON Schema supplies structural assistance and fast editor feedback, but
cannot establish deployability, data-plane ACK, or active state.

Route matching accepts exactly one of `path_exact`, `path_prefix`, or
`safe_regex`. A route can additionally constrain uppercase HTTP methods,
headers, and query parameters with exact or presence predicates. The bounded
compiler/runtime contract and ordering are documented in
`docs/architecture/decisions/0011-bounded-route-predicate-engine.md`; a complete
cross-protocol test input is in `tests/fixtures/phase3-routing.yaml`.

Proxy routes may apply bounded static request and response field mutations with
`header_transformations`. Each direction accepts at most 16 unique lowercase
field names and 16 KiB of configured names and values. `set` replaces every
case-insensitive instance, `append` uses comma-list semantics, and `remove`
deletes every instance. Framing, forwarding identity, CORS-owned, and
credential-injection mutations reject during compilation and again during
runtime snapshot preparation. The complete ownership and ordering contract is
in `docs/architecture/decisions/0024-bounded-route-header-transformations.md`;
the live HTTP/1.1 and HTTP/2 fixture is
`tests/fixtures/phase3-header-transformations.yaml`.

Proxy routes may also apply one immutable `rewrite` policy. A canonical DNS,
IPv4, or bracketed IPv6 `host` plus optional port changes only the upstream
HTTP authority; cluster TLS SNI and certificate identity remain unchanged.
`path` replaces the full path, while `path_prefix` is limited to prefix routes
and preserves the unmatched suffix. Both forms preserve the original raw
query. Replacement paths are bounded by 4,096 bytes and the configured
request-head limit, and an expanded target that crosses the runtime bound is
rejected with `414` before upstream selection. The ownership and ordering
contract is in
`docs/architecture/decisions/0025-bounded-route-host-path-rewrites.md`; the
cross-protocol controlled-upstream fixture is
`tests/fixtures/phase3-route-rewrites.yaml`.

Proxy routes may select one direct `cluster` or an ordered
`weighted_clusters` list containing 2 through 16 unique clusters. Every weight
is 1 through 4,096 and the total is at most 4,096. Each Seastar shard prepares
one smooth exact-cycle schedule per weighted route; request selection is O(1),
allocation-free, and independent of other shards. Policy failures, preflight,
and pre-selection rewrite/header-limit failures consume no schedule slot, and
retries stay in the initially selected cluster. The contract and exclusions
are in
`docs/architecture/decisions/0026-shard-local-static-weighted-route-splitting.md`;
the cross-protocol fixture is
`tests/fixtures/phase3-weighted-traffic-splitting.yaml`.

Clusters accept `round_robin`, `random`, or `least_request` through
`load_balancing_policy`; endpoint weights apply to all three. A cluster accepts
at most 4,096 endpoints, and the sum of endpoint weights is also bounded to
4,096 so prepared per-shard selection state remains finite. Optional
`passive_health` uses `consecutive_failures` (default 5, range 1-100),
`ejection_time_ms` (default 30000, range 100-300000), and
`max_ejection_percent` (default 50, range 1-100). It classifies only failures
before a valid upstream response head; HTTP status codes are not passive
transport failures. The contract and rationale are in
`docs/architecture/decisions/0012-shard-local-load-balancing-passive-health.md`,
and the controlled integration input is
`tests/fixtures/phase3-load-balancing.yaml`.

Optional `active_health` defines a bounded HTTP `GET` path, interval, timeout,
healthy/unhealthy thresholds, inclusive accepted status range, and optional
Host override. Optional `dns_refresh` defines a fixed refresh interval and
resolver timeout and requires at least one hostname endpoint. Shard zero owns
both maintenance loops and publishes state to all request shards; DNS failure
retains the last-known-good address. The accepted decision and complete bounds
are in
`docs/architecture/decisions/0013-centralized-active-health-dns-refresh.md`.
The two-shard failover fixture is
`tests/fixtures/phase3-active-health-dns.yaml`.
