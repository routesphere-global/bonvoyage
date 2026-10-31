---
title: Get Console Free
description: Download the release-matched Console Free package without registration or a RouteSphere account.
---

Console Free is an optional, no-cost visual operating surface for BonVoyage.
You can download and use it without product registration, a RouteSphere
account, a subscription, or a connection to a hosted RouteSphere service.

Console Free is proprietary binary software. Its source is not part of the
Apache-2.0 BonVoyage repository.

## Download the matching package

Console Free packages are published with admitted BonVoyage versions on the
[BonVoyage GitHub Releases page](https://github.com/routesphere-global/bonvoyage/releases).
The current package is attached to
[BonVoyage v1.0.4](https://github.com/routesphere-global/bonvoyage/releases/tag/v1.0.4).

For the initial supported platform, select the Ubuntu 24.04 AMD64 Debian
package whose version matches the gateway release you intend to operate. The
release assets and notes identify the exact filename, checksum, retained build
and vulnerability evidence, supported platform, and installation procedure.

:::caution[No package means no supported Console release]
If a BonVoyage release does not include an admitted Console Free `.deb` asset,
there is no supported public Console package for that version. Do not obtain an
internal build, rename an artifact from another release, or assume that a
gateway source snapshot implies a matching Console package.
:::

## Verify before installation

1. Confirm that the gateway and Console package identify the same admitted
   BonVoyage version.
2. Verify the package checksum using the value identified in that release.
3. Review the supplied candidate identity, SBOM, vulnerability and lifecycle
   evidence, supported-platform statement, and Console Free binary-use terms.
4. Install only after every required verification succeeds.

The package is intended for local or private-network operation. Installation
does not create an account, transmit a registration record, or enable a hosted
control plane.

## Continue the setup

After installing the verified package, keep the service stopped until you have
created the first named administrator:

1. [Create the first administrator](../create-first-administrator/).
2. [Sign in and inspect the installation](../sign-in-and-inspect/).
3. [Apply a configuration safely](../apply-configuration/).

Console Free ships no default username, password, or hidden recovery
credential. The first administrator is created locally during installation.
