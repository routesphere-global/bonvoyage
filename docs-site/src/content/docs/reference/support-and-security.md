---
title: Support and security
description: Community reporting, vulnerability disclosure, and commercial release-assurance boundaries.
---

## Community channel

After publication, use the public repository issue tracker for reproducible
defects, documentation corrections, and bounded feature requests. Search for an
existing report first and include the BonVoyage version, deployment mode,
sanitized configuration, expected behavior, observed behavior, and a minimal
reproduction.

Community issue submission does not include a human-response, resolution,
availability, or incident-response SLA. Do not place secrets, customer data,
private logs, or suspected vulnerability details in a public issue.

## Vulnerability reporting

Use the private vulnerability-reporting channel named by the published
`SECURITY.md`. Until that channel is active, do not publish exploit details or
sensitive diagnostics. The release process must enable and verify private
reporting before public availability.

Security reports should identify the affected version and component, explain
the trust boundary and impact, and provide the smallest safe reproduction. A
dependency appearing in an SBOM is not by itself proof that a vulnerability is
reachable; affectedness conclusions require version, configuration, call-path,
and artifact evidence.

## Verified Release Assurance

Organizations whose needs are met by the OSS features may purchase Verified
Release Assurance without buying enterprise fleet management. The service is
intended for maintained release lines, artifact identities, security and
supply-chain records, and standard lifecycle notices. It is not managed
operations or an incident-response SLA.

Contact `sales@routesphere.global` for current availability and final terms.
