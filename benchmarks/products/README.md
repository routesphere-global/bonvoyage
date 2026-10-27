# Benchmark Products

`lock.json` is the immutable comparator and load-generator inventory for the
Phase 2 HTTP/1.1 baseline. It records both the multi-platform index and the
architecture-specific manifests used by Linux AMD64 and local ARM64 runs.

Comparator configurations intentionally share listener port 8080 and connect
to the controlled upstream at `127.0.0.1:8081`. The harness runs one gateway at
a time with host networking and supplies the one- or two-worker setting on the
product command line.

Changing a version, digest, timeout, protocol behavior, logging level, resource
limit, or response-affecting option requires a new qualification record. A
floating tag is never benchmark evidence.
