# Contributing to BonVoyage API Gateway

BonVoyage welcomes reproducible defect reports, interoperability findings,
documentation feedback, deployment experience, and focused test evidence.
Community participation is issue-based. BonVoyage is an AI-native,
maintainer-directed project, and maintainers retain responsibility for design,
implementation, verification, security, and releases.

## Submit an issue

Use a GitHub issue to report:

- a reproducible bug or protocol interoperability problem;
- unexpected behavior in a documented deployment;
- inaccurate, incomplete, or confusing documentation;
- a bounded performance or resource observation; or
- a focused feature or compatibility requirement.

Include the BonVoyage version or commit, deployment environment, expected and
actual behavior, the smallest reproduction you can provide, and sanitized logs
or test evidence. For dependency findings, identify the component and version
and consult [DEPENDENCY_POLICY.md](DEPENDENCY_POLICY.md).

Never include credentials, private keys, customer data, private traffic, or
unredacted diagnostic bundles. Report suspected vulnerabilities privately as
described in [SECURITY.md](SECURITY.md), not in a public issue.

## What makes a report actionable

The most useful reports:

1. Describe one bounded problem or request.
2. Identify the exact version, configuration, and environment.
3. Provide steps that another engineer can repeat.
4. Include both the observed result and the expected result.
5. Remove secrets, personal data, and private infrastructure details.
6. Separate measured evidence from assumptions or proposed explanations.

An issue does not create a response, resolution, or release SLA. Maintainers
may ask for a smaller reproduction, additional evidence, or confirmation on a
current release before accepting a report.

## Code contribution boundary

External source-code fixes and pull requests are not accepted at this stage.
Please do not spend time implementing a change unless a maintainer explicitly
requests that work. Unsolicited pull requests may be closed without code
review.

Maintainers reproduce accepted reports, decide the architecture, implement or
generate the correction through the project's AI-native workflow, run the
required tests, obtain independent review where the risk requires it, and
retain final responsibility for every merged change.

This maintenance policy does not reduce the rights granted by the Apache
License 2.0. You may still use, modify, and redistribute the licensed source
under its terms; it only defines how changes enter the official BonVoyage
repository.

## Submission terms

Public issues and comments are visible to everyone. Submit only material you
are authorized to share, and understand that maintainers may quote or adapt a
reproduction into project tests and documentation. The project's Developer
Certificate of Origin applies to maintainer code commits; ordinary issue
reports do not require a DCO sign-off.
