# Public repository settings contract

Apply this contract after `routesphere-global/bonvoyage` is created and before public
contributions or release assets are accepted. Record screenshots or exported
ruleset JSON during the release audit. Repository settings are security state;
this document does not claim they are active before that evidence exists.

## Actions

- Allow GitHub-owned actions only unless a separately reviewed action is pinned
  to a full commit identifier.
- Set the default `GITHUB_TOKEN` permission to read repository contents.
- Do not allow GitHub Actions to create or approve pull requests.
- Require approval before a first-time external contributor's workflow runs.
- Never send secrets to workflows triggered from forks.
- Keep self-hosted runners disabled for untrusted pull requests.

## Main branch ruleset

- Target the default `main` branch and require changes through pull requests.
- Require the stable status check `Public CI / Foundation`.
- Require all review conversations to be resolved.
- Require linear history and block force pushes and branch deletion.
- During the single-maintainer bootstrap, require zero approving reviews because
  an author cannot approve their own pull request. CODEOWNERS still routes every
  change to the bootstrap owner.
- As soon as a second maintainer is appointed, require one code-owner approval,
  dismiss stale approvals, and require approval of the latest reviewable push.
- Limit bypass to the repository owner for bootstrap or emergency recovery.
  Every bypass requires a linked issue, written reason, and a successful manual
  `Public CI / Foundation` replay.

## Tags and releases

- Protect tags matching `v*`; only maintainers may create, update, or delete
  them.
- Do not configure package, container, signing, or provenance credentials during
  OSS-05.
- Create a protected `release` environment before activating any OSS-06 hosted
  artifact workflow. Require maintainer review, restrict deployment to protected
  `v*` tags, and record exported settings or screenshots as evidence.
- Keep the reviewed Debian reproducibility template outside `.github/workflows/`
  until its contract records the live public repository, externally verified
  digest-pinned builder image, and protected environment evidence. Promotion of
  that exact template is a separate reviewed change.
- The reproducibility workflow remains manual, read-only and non-publishing. It
  may retain evidence for three days but may not create a GitHub Release, upload
  a package or container, sign bytes, generate provenance, or use a secret.

## Security and maintenance

- Enable the dependency graph, Dependabot alerts, Dependabot security updates,
  private vulnerability reporting, secret scanning, and push protection.
- Disable automatic dependency merge. Every dependency change receives owner
  review and the required status check.
- Permit squash and rebase merges, delete merged branches, and keep merge commits
  disabled to preserve linear history.
- Keep blank issues disabled and direct suspected vulnerabilities to private
  security advisories.

## Ownership migration

The bootstrap CODEOWNERS file names `@johnynixons` because no public RouteSphere
maintainer team exists yet. The repository will be created directly in the
`routesphere-global` organization. After a least-privilege maintainer team is
available, replace the bootstrap account with that team and re-run the
governance audit before removing the individual owner.
