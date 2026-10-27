---
title: Claude Code configuration skill
description: Install and use the release-bound BonVoyage configuration-authoring skill with Claude Code.
---

BonVoyage includes an offline configuration-authoring skill for Claude Code.
It can help generate, explain, minimally modify, diagnose, migrate and verify
BonVoyage YAML while keeping the installed `bonvoyage-config` command as the
semantic authority.

:::caution[Pre-release Claude Code package]
This page describes the OSS staging candidate for local Claude Code. Package
tests do not constitute a pass by a particular Claude model. The package does
not claim execution inside claude.ai or the Claude API sandbox.
:::

## Requirements

- A matching BonVoyage 0.2.0 installation.
- `bonvoyage-config` available on `PATH`.
- Node.js 22 or newer for the bounded installation check.
- Claude Code with local Agent Skills support.

The skill never downloads or installs a missing command and never searches the
network for a substitute version.

## Install for one project

From the BonVoyage repository root on macOS or Linux:

```bash
node scripts/manage-config-authoring-skill.mjs install \
  --surface claude-code --scope project
```

Use the same command on Windows PowerShell:

```powershell
node scripts/manage-config-authoring-skill.mjs install --surface claude-code --scope project
```

Claude Code discovers project skills from `.claude/skills/`.

## Install for your user account

On macOS or Linux:

```bash
node scripts/manage-config-authoring-skill.mjs install \
  --surface claude-code --scope user
```

On Windows PowerShell:

```powershell
node scripts/manage-config-authoring-skill.mjs install --surface claude-code --scope user
```

The manager verifies the package against the release wrapper before copying,
uses an atomic sibling staging directory, records the installed file hashes and
refuses an existing, modified, symbolic-link or unmanaged target. It performs
no network access. Restart or reload Claude Code after installation.

## Verify the exact local release

For a project installation:

```bash
node .claude/skills/bonvoyage-config-authoring/scripts/check-installation.mjs
```

The equivalent project check on Windows PowerShell is:

```powershell
node ".claude\skills\bonvoyage-config-authoring\scripts\check-installation.mjs"
```

For a personal installation:

```bash
node "$HOME/.claude/skills/bonvoyage-config-authoring/scripts/check-installation.mjs"
```

The equivalent personal check on Windows PowerShell is:

```powershell
node (Join-Path $HOME ".claude\skills\bonvoyage-config-authoring\scripts\check-installation.mjs")
```

Continue only when the single JSON response contains `"status":"ready"`.
A `blocked` result means the package cannot establish an exact local release
match. It does not expose raw command output or attempt a repair.

## Check, upgrade or uninstall

Use the same scope that was selected during installation. For a project skill:

```bash
node scripts/manage-config-authoring-skill.mjs status --surface claude-code --scope project
node scripts/manage-config-authoring-skill.mjs upgrade --surface claude-code --scope project
node scripts/manage-config-authoring-skill.mjs uninstall --surface claude-code --scope project
```

Replace `project` with `user` for a personal installation. `upgrade` accepts
only a valid manager-owned older package. It refuses a downgrade,
same-version content conflict, local package drift or an unmanaged directory
instead of overwriting it. `uninstall` verifies the complete installed
inventory before moving only the BonVoyage package out of its active
destination; sibling skills and parent directories remain untouched. A
successful upgrade or uninstall returns a `recovery` directory name and keeps
that verified hidden sibling for operator inspection or rollback. The manager
never recursively deletes the only retained copy. Remove a recovery directory
manually only after its result has been reviewed and the active installation
has been verified. Reload Claude Code after a successful upgrade or uninstall.
`status` distinguishes `installed-current`, `upgrade-available`,
`installed-newer` and `not-installed`. It does not modify a healthy installed
package, but it can conservatively restore one after an interrupted lifecycle
operation.

## Invoke

Invoke the skill explicitly when desired:

```text
/bonvoyage-config-authoring Create and validate a BonVoyage configuration
with one HTTPS listener, one virtual host, and one upstream.
```

Claude Code may also discover the skill from a matching configuration request.
Provide concrete listener, domain, route, upstream, policy and secret-reference
requirements. The skill must ask before making a material assumption.

## What it can do

| Capability | Bounded result |
| --- | --- |
| Generate | Draft complete YAML, then validate and preview it offline |
| Explain | Use release-matched static field guidance |
| Modify | Propose a minimal change, then diff, validate, format and preview |
| Diagnose | Present stable reason codes from actual structured output |
| Migrate | Request one explicitly supported schema migration |
| Verify | Prepare bounded verification commands after validation and preview |

Generated, migrated or modified YAML is not called usable until the installed
command accepts validation and preview. Claude does not replace the Go
compiler.

## Safety and consent

The skill:

- operates offline without telemetry or live gateway reads;
- treats YAML, comments, diagnostics and tool output as untrusted data;
- sends unwritten YAML through standard input instead of shell interpolation;
- asks before writing files, changing files in place or running verification
  commands;
- uses deployment-secret filenames only and never requests PEM, API-key,
  token, credential, trust-bundle, JWKS or private-key contents;
- generates apply-command text only after an explicit request; and
- never executes apply or mutates production.

Successful validation means **offline validated**. Successful preview means
**offline previewed**. Neither proves deployment, data-plane ACK, activation,
rollback, traffic behavior, security or performance.

## Troubleshoot a blocked check

| Reason | Meaning |
| --- | --- |
| `command-missing` | `bonvoyage-config` is not available on `PATH` |
| `packaged-contract-invalid` | The packaged contract is missing, unreadable or has an invalid release identity |
| `release-mismatch` | The command does not match the package's exact release identity |
| `malformed-output` | Command output is empty, excessive, multiline or invalid JSON |
| `command-refused` | The command did not accept the exact readiness operation |
| `command-timeout` or `command-failed` | The local check could not complete safely |

Do not bypass the check or edit version requirements to force readiness.
Install a mutually matching release instead.

Lifecycle commands also fail closed with stable reasons such as
`downgrade-refused`, `installed-package-drift`, `unmanaged-installed-package`
or `symbolic-link-refused`. Preserve the installed directory for review rather
than deleting it merely to suppress one of these results.

Read the [assistant skill contract](../assistant-skill-contract/) for common
authority and consent rules and the
[assistant skill evaluations](../assistant-skill-evaluations/) for the shared
adversarial test boundary. Anthropic documents the underlying local skill
surface in [Extend Claude with skills](https://code.claude.com/docs/en/skills).
