# Public CI policy

The required `Public CI / Foundation` check is intentionally small, portable,
and predictable. It runs for pull requests to `main` and for intentional manual
dispatches. It does not run again on every push to `main`, on a schedule, or as
a release publisher.

The workflow:

- receives read-only repository contents permission;
- uses only GitHub-owned actions pinned to full commit identifiers;
- disables retained checkout credentials;
- never reads repository or environment secrets;
- never uses `pull_request_target` or a self-hosted runner;
- cancels superseded runs for the same pull request or ref;
- installs locked JavaScript dependencies without lifecycle scripts;
- runs the portable Go, Node.js, Python, formatting, and documentation gates;
  and
- has a bounded 25-minute timeout and no artifact upload or publishing step.

Fork pull requests therefore validate untrusted source without gaining write
authority, private credentials, package tokens, or access to RouteSphere
infrastructure. Repository settings must keep workflow tokens read-only and
must not send secrets to fork workflows.

Container, sanitizer, fuzz, protocol, package, SBOM, provenance, signing, and
release checks remain explicit local or protected-release gates. They are not
silently weakened to fit this cost-bounded workflow. Release automation may be
added only with the verified-release checkpoint, a protected environment, and
separate least-privilege review.

## Inactive Debian reproducibility candidate

`packaging/release/debian/oss-deb-reproducibility.workflow.yml` is a reviewed
workflow template, not an active GitHub workflow. It deliberately lives outside
`.github/workflows/`, so GitHub cannot dispatch it or consume Actions minutes.

The template defines two independent Ubuntu 24.04 builders, an exact-byte
comparison job, read-only permissions, a protected `release` environment,
three-day evidence retention and a maximum 200 billable job-minute envelope.
It has no publication, package-upload, signature or provenance authority. The
contract verifier rejects activation until the public repository exists, the
protected environment settings are evidenced, and a public Linux AMD64 builder
image is pinned and externally verified by digest. Only then may the exact
reviewed template be promoted to
`.github/workflows/oss-deb-reproducibility.yml` in a separate checkpoint.
