# Benchmark Fairness Contract

This contract defines the minimum conditions for comparing RouteSphere
BonVoyage with another gateway. A run that does not satisfy this contract is
diagnostic evidence only and cannot support a competitive claim.

## Equivalent behavior

Every product must receive the same request method, protocol, payload,
connection policy, route behavior, upstream response, TLS mode, logging level,
health-check behavior, and policy semantics. Product-required work may not be
disabled solely to improve a score. Any unavoidable difference must be stated
beside the result.

Only the workload's accepted application status counts as successful traffic.
Transport failures, rejected responses, and every other status contribute to
the error rate. Client-reported transport success is not a substitute for
application success.

## Isolation and resources

For publication qualification, the load generator, gateway target, and
controlled upstream run on separate Linux hosts or instances connected by
private addresses. Record the CPU model, active cores, SMT state, memory,
kernel, power policy, NUMA placement, NIC, MTU, IRQ policy, process placement,
and relevant network settings for every role.

Gateway CPU and interrupt CPU placement must be explicit. Support roles must
retain at least 20 percent independently measured capacity headroom. Shared
VM and single-host results may guide engineering, but must be labeled as such
and cannot be represented as dedicated-host or bare-metal evidence.

## Measurement procedure

1. Verify response status, length, and digest before load generation.
2. Warm each product for the workload-defined interval.
3. Discover the capacity region with controlled offered-load steps.
4. Measure operating points at 50, 70, 80, 90, and 95 percent of sustainable
   capacity; run intentional overload separately.
5. Randomize product order and retain every attempt, including invalid runs.
6. Run at least five valid repetitions for each product, core count, and
   operating point used for a publication claim.
7. Preserve equivalent thermal and host state between repetitions.

Sustainable capacity is the highest full-duration point before intentional
overload that remains within the declared latency ceiling and error budget.
A point is invalid when the error rate exceeds 0.1 percent, a support role
exceeds 80 percent of measured capacity, resource throttling occurs, or added
offered load no longer produces proportional successful throughput.

## Required evidence

Each accepted run retains the exact source and artifact identity, product and
workload configuration, environment record, raw client output, latency
distribution, successful RPS, application and whole-host CPU, IRQ CPU, RSS,
descriptors, network rate, support-role utilization, process identity, and
invalidation reason where applicable. Summaries are derived from immutable raw
records and verified independently; raw data is never rewritten to agree with
a report.

## Claim boundary

Peak RPS alone does not establish superiority. The primary comparison is the
maximum sustainable successful RPS at the same correctness, error, and latency
SLO, normalized by CPU and memory cost. Report p50, p95, and p99 as primary
latency percentiles; retain p99.9 and maximum latency as diagnostic context.

The original architecture target remains at least 20 percent higher
sustainable successful RPS per core than the strongest qualified comparator at
the same tail-latency ceiling. Missing that target is recorded honestly; it is
not converted into a pass by changing the contract after measurement.
