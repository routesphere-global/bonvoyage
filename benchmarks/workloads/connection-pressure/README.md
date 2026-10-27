# Connection Pressure

This workload opens and validates bounded HTTP/1.1 keep-alive connections, holds
them idle, and drives active route lookups through a separate client. It tests
connection accounting, admission, active progress, RSS observation, release,
recovery, and process continuity.

The default local levels are 1K, 4K, and 8K connections against a one-shard
gateway configured for 20K downstream connections. Every held socket first
completes a route-specific request and verifies its body. At each level, the gate
requires:

- the holder and gateway active gauge to agree exactly;
- zero downstream admission-rejection increase;
- three 100,000-request active lookup samples with 100% success;
- complete release back to zero active connections;
- recorded RSS before, during, and after the level;
- unchanged process identity and successful recovery after the sequence; and
- final retained RSS within the explicit bounded local allowance.

The reported RSS-per-connection value is marginal for that level relative to
its pre-open baseline. It is not a universal object-size or production capacity
claim. A short bounded sweep also cannot prove a stable multi-hour memory slope.

Run the combined gate with:

```bash
BONVOYAGE_BUILD_PLATFORM=linux/arm64 \
  make dataplane-route-scale-density
```

The dedicated campaign must later separate the load generator, gateway, and
supporting role; raise the matrix toward 10K/50K/100K where host limits permit;
and add long churn, slow clients, HTTP/2 stream density, multi-shard fairness,
CPU headroom, and memory-slope analysis.
