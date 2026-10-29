> This template is for maintainer-directed repository changes. Community
> participation is issue-based; external source-code pull requests are not
> accepted at this stage.

## Purpose

Describe the user or operator outcome and the smallest change that provides it.

## Scope

- [ ] Dataplane
- [ ] Control plane or API
- [ ] Configuration or deployment
- [ ] Security or dependency boundary
- [ ] Documentation or adoption tooling
- [ ] Test or benchmark harness only

## Verification

List the exact tests run and their results. Include controlled before/after evidence for performance changes and a failure/recovery check for lifecycle changes.

## Risk and compatibility

Describe protocol, configuration, upgrade, rollback, security, resource, and request-path effects. Write `None` only after considering each category.

## Maintainer checklist

- [ ] The change is maintainer-directed, focused, and follows repository policy.
- [ ] Every commit includes a Developer Certificate of Origin sign-off (`git commit -s`).
- [ ] Tests cover the behavior changed, including rejection paths where relevant.
- [ ] Documentation and examples match the implemented behavior.
- [ ] No credentials, private infrastructure, customer data, or proprietary RouteSphere material are included.
- [ ] New or changed dependencies satisfy `DEPENDENCY_POLICY.md` and are not auto-merged.
- [ ] Performance or security claims are bounded by retained, reproducible evidence.
- [ ] I disclosed material AI assistance and independently reviewed and tested the resulting change.
