# Dedicated Security Test Contract

This contract bounds defensive security testing of a frozen BonVoyage release
candidate. It is an authorization and evidence boundary, not a claim that the
software is free of unknown vulnerabilities.

## Authorized scope

Before active testing, record the campaign identifier, time window, private
target addresses, approved ports, exact source and artifact digests, synthetic
identities, rate and bandwidth ceilings, operator, reviewer, and emergency stop
procedure. Tests may target only the named gateway listeners and controlled
upstreams.

The campaign excludes public targets, neighboring tenants, cloud metadata,
unrelated RouteSphere products, third-party services, social engineering,
persistence, real customer data, and unapproved volumetric denial-of-service
traffic.

## Required lanes

- **White-box:** trace untrusted input through parser, policy, ownership,
  cryptographic, dependency, and deployment boundaries.
- **Gray-box:** test authentication, authorization, tenant, quota, ordering,
  and policy composition using a deliberately low-privilege synthetic identity.
- **Black-box:** test only reachable protocol behavior for malformed input,
  exposure, fingerprinting, defaults, and error disclosure.

Every finding requires reproducible evidence, affected artifact identity,
impact, severity, and a retest result. Scanner labels are inputs, not final
severity decisions.

## Coverage

The campaign covers:

1. source, sanitizer, fuzzer, static-analysis, dependency, SBOM, vulnerability,
   and secret-scanning gates;
2. listeners, privileges, capabilities, mounts, file permissions, secret
   references, and management-plane exposure;
3. TLS and mTLS validation, API-key and JWT behavior, forwarded identity,
   source policy, CORS, and request-content limits;
4. HTTP/1.1 and HTTP/2 framing ambiguity, parser desynchronization, malformed
   upstream behavior, retry boundaries, and post-failure recovery; and
5. bounded pressure from handshakes, slow headers and bodies, slow readers,
   stream churn, connection churn, admission exhaustion, oversized input,
   upstream collapse, and telemetry loss.

A low-rate healthy control flow runs throughout resource-pressure tests. Record
successful RPS, p50/p95/p99 latency, diagnostic p99.9, CPU, RSS, descriptors,
sockets, queue depth, rejection reasons, network rate, and recovery time.

## Stop and release rules

Stop immediately on traffic outside scope, unbounded resource growth,
host-wide instability, credential exposure, reliable policy bypass, or a
critical finding. Critical and high findings block the release candidate until
fixed and independently retested. Medium findings require a fix or explicit
owner, mitigation, deadline, and risk acceptance. Lower-severity observations
remain tracked separately.

A passing campaign means no unresolved release-blocking finding was discovered
within the recorded scope, tools, corpus, time, and environment. It does not
authorize a general DDoS-protection, penetration-resistance, or security-proof
claim.
