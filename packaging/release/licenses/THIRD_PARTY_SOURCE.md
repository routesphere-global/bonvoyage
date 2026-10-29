# Third-party source availability

This notice accompanies BonVoyage source and executable distributions. It
identifies the Source Code Form for third-party components whose licenses require
source availability when executable form is distributed.

## LibJWT 3.6.1

BonVoyage statically links LibJWT 3.6.1 under the Mozilla Public License 2.0 and
applies one RouteSphere-maintained source modification.

- Upstream release: <https://github.com/benmcollins/libjwt/releases/tag/v3.6.1>
- Upstream source archive: <https://github.com/benmcollins/libjwt/archive/refs/tags/v3.6.1.tar.gz>
- Upstream commit: `f4edfe5b2c44ac57edf00342550e81017f5329eb`
- Archive SHA-256: `b483a5f77e548964553f54a0ec5f0c810cc6c0629c5ac5a03610bcced150e7be`
- RouteSphere modification: `deploy/docker/bonvoyage/patches/libjwt-jwks-reject-duplicates.patch`
- Patch SHA-256: `7a554ca5ad4cd330a875d9c0fb2c91c77f7d34eab2c3bddf3c008b5c24d37190`
- License: `MPL-2.0`; the release artifact includes the complete license text.

The exact BonVoyage release tag contains the modification, its checksum-bound
dependency record and the build instructions that apply it without fuzz. To
reconstruct the covered Source Code Form, verify the upstream archive checksum,
extract it, and apply the patch with path strip level 1. The Dockerfile performs
those same operations and is the authoritative release build recipe.

The MPL-licensed files and RouteSphere modification remain available under
MPL-2.0. BonVoyage files that do not contain MPL-covered code remain under their
identified licenses. Questions about source availability may be sent to
`legal@routesphere.global`.
