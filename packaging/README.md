# Packaging

Release packaging assets for containers, Linux packages, Homebrew, checksums, and installation metadata.

The existing `systemd/bonvoyage.service` is the native service contract.
`systemd/bonvoyage-host-tune.conf` is a tmpfiles asset for the separate root
helper's volatile lock directory, not a service override or tuning command.
Native package installation and upgrade qualification remain pending; these
assets do not imply that a release `.deb` or `.rpm` is available.

`debian/` supplies the private Ubuntu 24.04 AMD64 gateway-only builder templates.
Run `make native-package-test` locally. Native assembly uses
`scripts/build-native-deb.py` with an explicitly checksum-reviewed input manifest,
executable and copyright/license text; no OSS license is selected automatically.
The package uses `/usr/bin`, delegates dependency/lifecycle generation to
debhelper and never enables/starts the service automatically. The accepted
`/usr/local` source-install unit remains unchanged; the tuning helper does not
yet accept the package unit. A successful private build is not installation,
SBOM, vulnerability, tuning or release acceptance. See
[ADR 0039](../docs/architecture/decisions/0039-native-gateway-debian-package-contract.md)
and the [acceptance runbook](../docs/deployment/native-package-acceptance.md).
