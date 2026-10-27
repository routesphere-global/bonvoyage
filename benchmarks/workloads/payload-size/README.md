# Payload Size

Payload workloads exercise exact response sizes without changing the gateway
route, upstream software, or connection policy. The controlled upstream ships
256-byte, 8 KiB, 16 KiB, 64 KiB, and 1 MiB fixtures.

The size-gated response ownership-transfer checkpoint uses:

- 256 bytes as the small-response guardrail.
- 8 KiB as the below-threshold boundary probe.
- 16 KiB as the activation-boundary probe.
- 64 KiB and 1 MiB for sustained multi-buffer forwarding.

These local probes guide engineering only. Competitive payload-size claims
require the dedicated, separated-host Phase 2 topology.

`make benchmark-copy-transfer-ab` executes the balanced five-repetition A/B
runner. It expects prebuilt baseline and candidate image tags and defaults to
`linux/amd64`; local ARM64 use must set
`BONVOYAGE_BUILD_PLATFORM=linux/arm64`. Image tags, CPU sets, request path,
connection count, warm-up, measurement duration, and result directory are
overridable through the `BONVOYAGE_AB_*` variables exposed by the script.
