# Upstream Benchmark Service

The benchmark stack uses a pinned NGINX stable image to serve exact 256-byte,
8 KiB, 16 KiB, 64 KiB, and 1 MiB payloads. The 256-byte fixture remains the
Phase 1 and Phase 2 baseline; the larger fixtures support copy-cost and
payload-size experiments without changing upstream software.
This image is deliberately separate from the Python protocol fixture under
`deploy/docker/upstream`, which retains slow, chunked, and echo behaviors for
correctness and reliability tests.
