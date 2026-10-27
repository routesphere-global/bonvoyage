# Security Policy

## Supported versions

BonVoyage is currently pre-release. No public version has an active security
support window yet. Supported versions and update commitments will be published
with the first approved release candidate.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, discussion,
benchmark report, or support request.

After the public repository opens, use GitHub's **Report a vulnerability**
workflow in the repository Security tab. If private vulnerability reporting is
not available, do not publish the report. Private vulnerability reporting is a
release gate and must be enabled before a supported public release is declared.

Include only the information needed to reproduce and assess the report:

- affected version or commit, component, and deployment mode;
- minimal reproduction steps or proof of concept;
- impact, prerequisites, and whether exploitation is suspected;
- sanitized logs, traces, or packet details; and
- a safe contact method for coordinated follow-up.

Never include live credentials, private keys, customer data, or unredacted
production traffic.

## Response and disclosure

Security reports are triaged privately and validated against an exact source and
artifact identity. Remediation includes regression testing, release-impact
assessment, dependency and SBOM review where relevant, and coordinated
disclosure. Response targets and supported-version commitments are not implied
until they are explicitly published or contracted.

GitHub issues are appropriate for ordinary defects that have no confidential
security impact. See [SUPPORT.md](SUPPORT.md) for the community and commercial
support boundary.
