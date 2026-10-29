# Project Governance

RouteSphere BonVoyage API Gateway is maintained by the RouteSphere project
maintainers.
Maintainers make final decisions on architecture, roadmap, security response,
release contents, compatibility, and changes accepted into the repository.

## Decision principles

Decisions are guided by, in order:

1. Correctness and security.
2. Bounded stability, recovery, and operability.
3. Measured performance and resource efficiency.
4. Compatibility and adoption cost.
5. Implementation and maintenance complexity.

Material decisions are recorded in documentation or an architectural decision
record. Benchmark results do not become product claims until their source,
binary, configuration, environment, workload, errors, resource use, and latency
distribution are reviewable.

## Participation

Anyone may submit a well-formed issue after the public repository opens.
Community participation is issue-based: reproducible defects, interoperability
findings, documentation feedback, deployment experience, and focused test
evidence are welcome. External source-code fixes and pull requests are not
accepted at this stage; maintainers own implementation through the project's
AI-native workflow. Repository activity does not create a support entitlement
or transfer release authority.

## AI-native engineering

The project uses AI-assisted engineering under human governance. AI can propose,
implement, review, and help reproduce work; it cannot waive a gate, authorize a
release, attest legal rights, or act as the sole reviewer of sensitive changes.
Automated checks and retained evidence verify claims independently of authorship.

## Releases and security

Only maintainers may publish releases, signatures, provenance, security
advisories, or official performance statements. Security reports follow
[SECURITY.md](SECURITY.md). Support boundaries are defined in
[SUPPORT.md](SUPPORT.md).
