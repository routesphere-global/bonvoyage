# Contributing to BonVoyage API Gateway

BonVoyage welcomes reproducible defect reports, interoperability findings,
documentation feedback, deployment experience, and focused test evidence.
Maintainers retain final responsibility for architecture, security, releases,
and the code merged into the project.

## Start with an issue

Use an issue to describe the problem, expected behavior, version or commit,
deployment environment, minimal reproduction, and sanitized evidence. Do not
begin a broad implementation or architectural change without maintainer
agreement. An issue or pull request does not create a response or merge SLA.

Never include credentials, private keys, customer data, private traffic, or
unredacted diagnostic bundles. Report suspected vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).

## Change requirements

Accepted changes must:

1. Preserve shard-local request ownership and keep control-plane work outside
   the data-plane request path.
2. Define input, memory, queue, timeout, cancellation, recovery, and shutdown
   bounds for affected behavior.
3. Include focused positive and negative tests.
4. Keep generated files reproducible and third-party origins attributable.
5. Update public documentation when behavior or an operator contract changes.
6. Avoid performance claims without controlled, replayable evidence.

Changes that add, replace, patch, or materially update a dependency must also
satisfy [DEPENDENCY_POLICY.md](DEPENDENCY_POLICY.md). Dependency pull requests
are reviewed; passing automation does not authorize an automatic merge.

Run the portable checks with:

```bash
make dependencies
make test
```

Run the component, sanitizer, fuzz, conformance, and deployment checks required
by the risk of the change. Record checks that could not run and why.

## AI-assisted work

AI-assisted changes are welcome when their use is disclosed in the pull request.
Generated output is not evidence. A human submitter remains responsible for
understanding the change, verifying provenance and licensing, running the stated
checks, and responding to review. Security-, concurrency-, lifetime-, release-,
and performance-sensitive changes require independent review and objective
evidence.

## Contribution terms

Do not submit code until the repository publishes its final license and
contribution terms. The intended policy is contribution under the project
license with Developer Certificate of Origin sign-off, subject to final rights
review before public contribution intake opens.
