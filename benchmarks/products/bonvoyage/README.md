# BonVoyage Benchmark Target

`host-network.yaml` is the static Phase 1 baseline for an isolated native
Linux benchmark host. The upstream is loopback so gateway, load-generator, and
upstream containers can use host networking without Docker bridge contention.
The roles still require disjoint physical CPU sets.

`make benchmark-phase1-scaling` compiles this file to the immutable Protobuf
snapshot consumed by each one-core and two-core process. The benchmark does not
run the Go compiler beside the dataplane during a measurement.
