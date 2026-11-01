---
title: Install the v1.0.4 release
description: Download, verify, install, and smoke-test the published Gateway and optional Console artifacts on Ubuntu 24.04 AMD64.
---

This guide installs the exact artifacts published with
[BonVoyage v1.0.4](https://github.com/routesphere-global/bonvoyage/releases/tag/v1.0.4).
It does not build from a moving source checkout and it does not require a
RouteSphere account or product registration.

Choose one Gateway path. The native package and OCI container use the same
default traffic, metrics, and health ports, so do not run both smoke tests at
the same time.

| Goal | Path |
| --- | --- |
| Install a native `systemd` service | [Gateway Debian package](#gateway-debian-package) |
| Import a release image into Docker | [Gateway OCI archive](#gateway-oci-archive) |
| Add the optional visual operating surface | [Console Free package](#console-free-package) |
| Build the complete local example from source | [Docker quickstart](../quickstart/) |

## Requirements

The published packages currently target **Ubuntu 24.04 AMD64**. Run the
following before downloading an artifact:

```bash
test "$(uname -m)" = x86_64
. /etc/os-release
test "$ID" = ubuntu
test "$VERSION_ID" = 24.04
```

You also need `curl` and `sha256sum`. The OCI path additionally requires a
working Docker Engine.

Create a private working directory and download the release checksum file:

```bash
install -d -m 0700 "$HOME/bonvoyage-1.0.4"
cd "$HOME/bonvoyage-1.0.4"

release_base=https://github.com/routesphere-global/bonvoyage/releases/download/v1.0.4
curl --fail --location --remote-name "$release_base/SHA256SUMS"
```

Every path below verifies its selected artifact against that release-level
checksum file before installation. The release also includes Gateway Sigstore
bundles, CycloneDX and SPDX SBOMs, provenance, and retained technical evidence.
Follow the release's
[`VERIFY.md`](https://github.com/routesphere-global/bonvoyage/releases/download/v1.0.4/VERIFY.md)
when you need the complete evidence verification procedure.

## Gateway Debian package

### 1. Download and verify

```bash
asset=bonvoyage-gateway_1.0.4-1_amd64.deb
curl --fail --location --remote-name "$release_base/$asset"
grep -F "  $asset" SHA256SUMS | sha256sum --check -
```

Expected checksum result:

```text
bonvoyage-gateway_1.0.4-1_amd64.deb: OK
```

### 2. Install without activating traffic

```bash
sudo apt-get update
sudo apt-get install -y "./$asset"
dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' bonvoyage-gateway
/usr/bin/bonvoyage-dataplane --version
```

Expected package identity:

```text
bonvoyage-gateway 1.0.4-1 amd64
```

The package deliberately leaves `bonvoyage.service` disabled and inactive. It
must not serve traffic until a reviewed immutable snapshot is installed.

```bash
systemctl is-enabled bonvoyage.service || true
systemctl is-active bonvoyage.service || true
```

Expected states are `disabled` and `inactive`.

### 3. Run the bounded evaluation smoke test

The following snapshot is a release-bound **evaluation fixture**, not a
production configuration. It contains the fixed `/bonvoyage/ready` response
used by the release replay.

```bash
snapshot=oss-native-fresh-install.pb
snapshot_url=https://raw.githubusercontent.com/routesphere-global/bonvoyage/9c252fcc583641341b44ba5ca8b7434a6ff0a165/tests/fixtures/$snapshot

curl --fail --location --output "$snapshot" "$snapshot_url"
printf '%s  %s\n' \
  994c972fec3feeae03d0b93e81a95db5a86cf2d6193f7785edd36bfc1085bb09 \
  "$snapshot" | sha256sum --check -

sudo install -o root -g bonvoyage -m 0640 \
  "$snapshot" /etc/bonvoyage/snapshot.pb
sudo systemctl enable --now bonvoyage.service
```

Verify process readiness, the fixed route, and Prometheus output:

```bash
curl --fail --show-error http://127.0.0.1:9901/health/ready
curl --fail --show-error http://127.0.0.1:8080/bonvoyage/ready
curl --fail --show-error --silent http://127.0.0.1:9090/metrics \
  | grep -E 'gateway_(configured_routes|requests_total)'
```

The fixed route must return:

```text
ready
```

Stop the evaluation service before installing a production snapshot or trying
the OCI path:

```bash
sudo systemctl disable --now bonvoyage.service
```

Do not expose the fixture to external traffic. Replace it with an immutable
snapshot compiled from reviewed YAML and inspect the effective listener,
upstream, TLS, and policy settings before enabling the service again.

## Gateway OCI archive

### 1. Download and verify

```bash
asset=bonvoyage-gateway-1.0.4-linux-amd64.oci.tar
curl --fail --location --remote-name "$release_base/$asset"
grep -F "  $asset" SHA256SUMS | sha256sum --check -
```

Expected checksum result:

```text
bonvoyage-gateway-1.0.4-linux-amd64.oci.tar: OK
```

### 2. Import and inspect the image

```bash
docker load --input "$asset"
docker image inspect ghcr.io/routesphere-global/bonvoyage:1.0.4 \
  --format 'user={{.Config.User}} entrypoint={{json .Config.Entrypoint}}'
```

The release image runs as `65532:65532` and starts
`/usr/local/bin/bonvoyage-dataplane`.

### 3. Run the bounded evaluation smoke test

Download the same release-bound evaluation snapshot if it is not already in
the working directory:

```bash
snapshot=oss-native-fresh-install.pb
snapshot_url=https://raw.githubusercontent.com/routesphere-global/bonvoyage/9c252fcc583641341b44ba5ca8b7434a6ff0a165/tests/fixtures/$snapshot

test -f "$snapshot" || \
  curl --fail --location --output "$snapshot" "$snapshot_url"
printf '%s  %s\n' \
  994c972fec3feeae03d0b93e81a95db5a86cf2d6193f7785edd36bfc1085bb09 \
  "$snapshot" | sha256sum --check -
chmod 0444 "$snapshot"
```

Run the image read-only with a bounded temporary directory and the snapshot
mounted read-only:

```bash
docker run --detach --name bonvoyage-v1.0.4-smoke \
  --network host \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount "type=bind,src=$(pwd)/$snapshot,dst=/etc/bonvoyage/snapshot.pb,readonly" \
  ghcr.io/routesphere-global/bonvoyage:1.0.4
```

Verify readiness and the fixed route:

```bash
curl --fail --show-error http://127.0.0.1:9901/health/ready
curl --fail --show-error http://127.0.0.1:8080/bonvoyage/ready
```

The fixed route must return `ready`. Remove the evaluation container when the
check is complete:

```bash
docker rm --force bonvoyage-v1.0.4-smoke
```

The host-network command above is for the supported Linux evaluation target.
Use explicit container port mappings and deployment-specific network policy in
other environments.

## Console Free package

Console Free is optional proprietary binary software. It is no-cost, requires
no registration, and must match the Gateway release.

### 1. Download, verify, and install

```bash
asset=bonvoyage-console_1.0.4-1_amd64.deb
curl --fail --location --remote-name "$release_base/$asset"
grep -F "  $asset" SHA256SUMS | sha256sum --check -

sudo apt-get install -y "./$asset"
dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' bonvoyage-console
/usr/bin/bonvoyage-console version
```

Expected package identity:

```text
bonvoyage-console 1.0.4-1 amd64
```

The package ships no default username or password and does not start the
Console automatically. Continue with:

1. [Create the first administrator](/console/create-first-administrator/).
2. [Sign in and inspect](/console/sign-in-and-inspect/).
3. [Apply a configuration](/console/apply-configuration/).

The Console's management service is an internal product interface, not a
supported public OSS API or third-party UI integration contract.

## Before exposing traffic

1. Replace the evaluation fixture with a snapshot compiled from reviewed YAML.
2. Confirm the exact listeners, TLS identities, upstream endpoints, policy
   bounds, and resource limits.
3. Apply the [network-port and firewall guidance](/reference/network-ports/).
4. Keep metrics and health/admin listeners on loopback or restricted networks.
5. Verify traffic, readiness, metrics, restart behavior, and failure handling
   in the intended deployment environment.

The release smoke test proves artifact integrity, installation, startup, and a
fixed response on the supported platform. It is not a production-capacity or
security guarantee for a different topology.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Checksum reports `FAILED` | Remove the file and download it again from the exact v1.0.4 release. Do not install it. |
| Package architecture is rejected | Confirm the host reports `x86_64`; the v1.0.4 package is AMD64 only. |
| Service remains inactive after package installation | Expected. Install a reviewed snapshot, then explicitly enable and start it. |
| Port is already in use | Stop the other Gateway path or service using `8080`, `9090`, or `9901`. |
| OCI container cannot read the snapshot | Confirm the evaluation file is regular, checksum-matched, and host-readable by UID/GID `65532`. |
| Console has no login | Expected on a fresh install. Create the first named administrator locally; there is no default credential. |

