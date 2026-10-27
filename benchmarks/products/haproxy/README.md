# HAProxy Benchmark Target

The Phase 2 baseline uses HAProxy 3.4 LTS, locked by platform manifest in
`../lock.json`. The runner sets `-nbthread` to the assigned gateway core count.
The configuration uses static HTTP/1 proxying, HAProxy's stable `safe`
upstream connection-reuse policy, matched timeouts, no health checks, no
retries, and no request logging. More aggressive reuse is not enabled unless
separate qualification proves it is both faster and error-free.
