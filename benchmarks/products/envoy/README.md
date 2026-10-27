# Envoy Benchmark Target

The Phase 2 baseline uses the supported Envoy 1.39 line, locked by platform
manifest in `../lock.json`. HTTP/1 is forced downstream, the upstream is static
HTTP/1, request and idle timeouts match BonVoyage, access logging is disabled,
and no health checking, retries, TLS, HTTP/2, or filters beyond the router are
enabled. The runner passes `--concurrency` and disables hot restart.
