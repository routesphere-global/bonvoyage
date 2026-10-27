# NGINX Benchmark Target

The Phase 2 baseline uses the stable NGINX 1.30 line, locked by platform
manifest in `../lock.json`. The runner sets `worker_processes` to the assigned
gateway core count. Downstream and upstream keep-alive, streaming proxying,
timeouts, request size, header limits, access logging, and the static upstream
are aligned with the baseline traffic contract.
