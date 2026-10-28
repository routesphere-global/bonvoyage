---
title: Create the first administrator
description: Create the first named Console Free administrator without shipping or exposing a default credential.
---

Console Free ships the `auditor`, `operator`, and `administrator` roles, but it
ships **no default account or password**. The installation owner creates the
first named administrator locally on the Console host before starting the
service.

This bootstrap operation is intentionally unavailable through the browser. An
empty installation has no browser identity that could safely authorize it.

## Prerequisites

- Install the Console Free Debian package and leave its service stopped.
- Complete the Console TLS and management-plane identity configuration supplied
  with that package.
- Choose a lowercase account ID of at most 64 characters. It may contain
  letters, digits, `.`, `_`, or `-`, but it must begin with a letter or digit.
- Store a unique password in a regular owner-only file. The password must be
  14 to 256 UTF-8 bytes and must not contain a NUL byte. One trailing newline is
  accepted.

Do not put the password in a command argument, environment variable, YAML file,
Git repository, screenshot, or issue report.

## 1. Stage the password safely

Replace `/path/to/owner-only-password` with the absolute path to the password
file you prepared. The package service account reads only an owner-only regular
file and rejects symlinks, permissive modes, empty files, and oversized files.

```bash
sudo install -d -o bonvoyage-console -g bonvoyage-console -m 0700 \
  /run/bonvoyage-console

sudo install -o bonvoyage-console -g bonvoyage-console -m 0600 \
  /path/to/owner-only-password \
  /run/bonvoyage-console/bootstrap-password
```

## 2. Create the administrator

Choose an account ID and display name that identify a person or installation
owner. The example account ID below is not a shipped account.

```bash
sudo -u bonvoyage-console /usr/bin/bonvoyage-console upsert-account \
  -accounts /var/lib/bonvoyage-console/accounts.json \
  -id admin.local \
  -display-name "Installation Administrator" \
  -role administrator \
  -password-file /run/bonvoyage-console/bootstrap-password
```

A successful command reports that the named account was stored with the
`administrator` role. It writes an Argon2id verifier, not the original
password, to the owner-only account document.

## 3. Remove the staged password

Remove the temporary copy whether the account command succeeds or fails. Keep
the authoritative password only in the installation owner's approved password
manager or secret store.

```bash
sudo rm -f /run/bonvoyage-console/bootstrap-password
```

Confirm that the account document exists without printing its contents:

```bash
sudo test -s /var/lib/bonvoyage-console/accounts.json
sudo stat -c '%U:%G %a %n' /var/lib/bonvoyage-console/accounts.json
```

The account document must remain owned by the Console service account and must
not be readable by group or other users.

## 4. Start the Console

Start the service only after its exact HTTPS origin, TLS files, management API
mTLS identity, and management authorization are configured:

```bash
sudo systemctl enable --now bonvoyage-console.service
sudo systemctl status --no-pager bonvoyage-console.service
```

If the service does not start, inspect its status and correct the missing
configuration. Do not weaken file permissions or substitute a development
fixture account.

## Add or recover an account

After the first administrator exists, run the same `upsert-account` command
locally to add named `operator` or `auditor` accounts. Running it again for an
existing account changes its password, display name, or role, enables the
account, and invalidates its existing Console sessions.

There is no hidden recovery password. If an administrator loses access, the
installation owner uses this local operating-system procedure to replace that
named account's credential.

Next: [Sign in and inspect the installation](../sign-in-and-inspect/).
