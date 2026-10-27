# Runtime log service fixture

Run one mode at a time from the repository root. The gateway and snapshot are
mounted read-only; the fixture uses its own temporary socket/pipe and emits one
JSON result on success. Failure exits nonzero with a JSON error on stderr.
It also starts a controlled loopback HTTP/1.1 upstream on port 8081 and sends
16 exact-response proxy requests during the transport condition, then 16
after recovery. The baseline snapshot routes port 8080 to that upstream.

```sh
for mode in healthy-unix unix-arrival unix-replacement full-pipe; do
  docker run --rm --network none --cap-add SYS_RESOURCE \
    -v "$PWD/tests/fixtures/runtime-log-service:/fixture:ro" \
    -v "$PWD/benchmarks/results/raw/phase1-scaling-20260826T053720Z/snapshot.pb:/tmp/snapshot.pb:ro" \
    --entrypoint python3 bonvoyage-runtime-log-fixture:20260916-build \
    /fixture/check.py --mode "$mode"
done
```

`--gateway` and `--snapshot` can override the image defaults. The fixture
requires loopback admin/metrics endpoints and Linux pipe sizing for full-pipe.
The selected snapshot is SHA-256
`16e9e97b4e5c4cb6bfdd6f5bd9c749802625304e55014719a175b287f5e7dae7`;
the fixture program is SHA-256
`67a1d565b1596a6ca5946d76f2e7da955d2c9d00b19794479f51dfe21e0e9f4e`.
The Python-bearing builder image ID for this local replay is
`sha256:f4b75a1563a617c0697717f99313194f6412e9a91986b23eeab75e2a177d1532`.
Do not run this fixture inside the stripped runtime image: it intentionally
does not contain Python. Its separately checked ID is
`sha256:560e9124c747e5f46dd3a8dc695197fc37e517b2764eebb8c76968df7340e6a9`.
These values identify development images, not clean-source release artifacts.
The JSON `proxy.max_ms` values are single-run functional probe times and must
not be used as p99, p99.9, RPS, CPU cost or comparator evidence.
The replacement mode enables the existing gateway debug logger only inside
this controlled fixture so proxy requests create records after the first
healthy Unix receiver is removed. It requires the new receiver at the same
path to receive those queued records, then drains its datagrams before the
clean-shutdown assertion. This does not enable per-request debug logging in
the production default.

## TLS/HTTP/2 Receiver Pressure

From the repository root, with the locally cached ARM64 gateway, compiler,
upstream and pinned oha images:

```sh
BONVOYAGE_RETAIN_RUNTIME_LOG_HTTP2_EVIDENCE=1 \
  sh scripts/phase3-runtime-log-http2-pressure.sh
```

This separate short fixture uses the existing `phase3-http2.yaml` snapshot,
ephemeral private TLS certificates and a controlled 1 KiB upstream payload.
`unix_receiver.py` acknowledges pause/resume over a private control socket.
The launcher verifies ALPN `h2`, exact `200`/body-byte counts in 32 healthy,
64 paused and 32 recovered requests, bounded queue and would-block metrics,
no restart, clean exit and exact final log accounting. It retains JSON-only
receipts when requested; the temporary certificate keys and Docker resources
are always removed. The local results are functional fault evidence, not a
gateway CPU, latency, comparator or clean-source release gate.

Set `BONVOYAGE_RUNTIME_LOG_SHUTDOWN_MODE=stalled` to leave the receiver
paused while the gateway stops. That mode requires a bounded clean exit,
resumes the receiver only after process exit, and rejects any claim that the
clean-stop event or final accounting report was delivered. The companion
`bonvoyage-runtime-log-service-reactor` CTest directly verifies that pending
records become `shutdown_drops`, the queue reaches zero, and
`final_report_sent()` remains false when the destination is unavailable.
