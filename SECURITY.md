# Security Policy

## Supported versions

BonVoyage `v1.0.4` is the current public release. Security reports are accepted for the current public release and the `main` development branch.

| Version | Status |
| --- | --- |
| `v1.0.4` | Current public release; security reports accepted |
| `main` | Development branch; reports accepted, but not a released version |
| Earlier versions | Not supported; reproduce against the current release where possible |

Community security handling is provided on a best-effort basis. This policy does not create an acknowledgement, remediation, disclosure, or support SLA. Any contracted security or response commitments must be stated in a separate written agreement.

Fixes may be delivered in a later release rather than backported to superseded versions.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, discussion, benchmark report, pull request, or support request.

Use GitHub's **Report a vulnerability** workflow from the repository's **Security** page. This creates a private report visible only to the reporter and authorized repository maintainers.

If private vulnerability reporting is temporarily unavailable, do not publish vulnerability details. Open a minimal public issue requesting a private security contact without including technical details, reproduction steps, logs, or evidence.

Include only the information needed to reproduce and assess the report:

- affected version or commit, component, and deployment mode;
- minimal reproduction steps or proof of concept;
- expected and observed behavior;
- impact, prerequisites, and whether exploitation is suspected;
- sanitized logs, traces, packet details, or artifact identities;
- whether the issue also affects the current public release; and
- a safe contact method for coordinated follow-up.

Test only against systems and data that you own or are explicitly authorized to assess.

Never include live credentials, private keys, customer data, private traffic, or unredacted production diagnostic material.

## Response and disclosure

Security reports are triaged privately and validated against an exact source, release, package, image, or artifact identity where applicable.

Assessment may include:

- reproduction and impact validation;
- regression and negative testing;
- release-impact analysis;
- dependency, provenance, and SBOM review where relevant; and
- preparation of a coordinated remediation and disclosure plan.

Submitting a report does not guarantee acceptance, a particular severity, a remediation deadline, a bounty, public credit, or inclusion in a specific release. Disclosure timing will be coordinated where practical, but no response or disclosure SLA is implied unless separately contracted.

GitHub issues are appropriate for ordinary defects that have no confidential security impact. See [SUPPORT.md](SUPPORT.md) for the community and commercial support boundary.
