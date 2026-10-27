# BonVoyage Host Tune

`bonvoyage-host-tune` turns Linux CPU, memory, NUMA, PCI, NIC queue, and IRQ
topology into a reviewable BonVoyage resource plan.

Current status: `inspect` and `plan` are unprivileged and do not modify the host.
The latest [bounded tuned reboot report](../../docs/deployment/ubuntu-native-service-rehearsal.md#tuned-reboot-persistence-on-d034732)
passes one orderly shared-VM reboot, persisted four-core tuning, independent
reactor/resource/HTTP checks, stale-approval rejection and fresh postboot
apply/rollback. Baseline restoration was separately reviewed lab maintenance;
automatic cross-boot recovery remains unsupported. Native package/SBOM and
strict NIC/dedicated qualification remain open; production commands stay gated.
The [clean-source scoped Ubuntu report](../../docs/deployment/ubuntu-native-service-rehearsal.md#clean-source-scoped-recovery-on-039430a)
passes four-core CPU/memory activation, independent reactor/resource/HTTP
checks, orderly restoration and actual interrupted-apply recovery on `039430a`.
The new native helper is installed with its predecessor preserved. Strict NIC,
co-location memory, native package/SBOM and dedicated performance
qualification remain pending. The earlier reports below retain their historical
artifact identities and outcomes.
The [Ubuntu native execution report](../../docs/deployment/ubuntu-native-service-rehearsal.md)
records artifact installation, bounded CPU/memory checks and automatic recovery.
Post-restart verification now waits for managed exec without weakening foreign
argv rejection. Strict NIC IRQ convergence failed and was deferred to dedicated
testing; full qualification remains pending. The clean `f90328c` follow-up rebuilt
and installed the helper using native Go 1.26.8, observed four reactor affinities
and tuned CPU/memory/HTTP settings, and verified automatic restoration. The
earlier dirty diagnostic and incomplete/rejected attempts remain distinct.
The original installed helper is preserved privately; no IRQ bypass was added.

The experimental `rehearsal` namespace connects verified inputs, native lab
activation, review, restoration and evidence. Production `apply`, `verify` and
`rollback` commands remain unavailable pending the Ubuntu 24.04 rehearsal and
reboot-persistence tests described by
[ADR 0036](../../docs/architecture/decisions/0036-topology-aware-host-tuning.md).

The September 14 follow-ups add an internal transaction engine, synchronized
rollback journal, and concrete native systemd/filesystem adapter. Public
apply/verify/rollback commands remain disabled. Adapter tests use real private
temporary files with injected systemd/proc/cgroup observations, never live host
settings. The production constructor requires root on Ubuntu 24.04; Darwin is
supported only for offline adapter fixtures.

The engine regenerates plans, binds approval to the exact plan, host/boot/topology
and target values, records bounded before-images before writes, and restores
owned changes in reverse order on failure. Changed identity or conflicting
operator edits require recovery instead of blind restoration. Effective restored
state must verify independently of restored file contents. Journal integrity
verification is diagnostic, not crash-recovery replay or measurement approval.
See the [checkpoint and remaining integration work](../../docs/deployment/host-tuning.md#offline-transaction-safety-checkpoint).

## Native service contract

Contract v1 reuses the unchanged `packaging/systemd/bonvoyage.service`, installed
at `/etc/systemd/system/bonvoyage.service` with the native binary at
`/usr/local/bin/bonvoyage-dataplane`. It refuses foreign service fragments,
custom argv, loaded overrides, unmanaged entries in the two managed drop-in
directories, pending daemon reloads, and missing service observations.
Both BonVoyage and irqbalance must already be running in their standard
`system.slice` cgroups on a cgroup-v2 host.

Only three adapter-owned drop-ins may change: BonVoyage resource limits,
BonVoyage runtime arguments, and irqbalance's gateway CPU exclusion.
Root-owned directory ancestry, no-follow descriptor-relative access,
single-link regular files, bounded contents, exclusive host locking, atomic
replacement and synchronized before-images protect those operations.
The helper uses `golang.org/x/sys` v0.28.0, matching the existing Go modules.

Activation and rollback reload systemd and restart **both** services. This
requires a maintenance window, not a live zero-downtime tuning promise.
The journal retains before/after process IDs, argv, effective cgroup CPU and
memory limits, irqbalance exclusion and observed IRQ affinities.
Apply checks IRQs against the plan's NIC-local reserve; rollback restores
the previous irqbalance policy, not an exact historical dynamic IRQ mask.

The root helper is separate from the unprivileged gateway. The lock directory
must exist at `/run/bonvoyage-host-tune`; the packaging tmpfiles asset describes
its boot-time recreation. Retained-artifact loading and interrupted-run recovery
are now implemented and tested with fixtures. The experimental rehearsal
commands are described below; production CLI and live Ubuntu qualification
remain gated.
See the [native adapter checkpoint](../../docs/deployment/host-tuning.md#native-service-adapter-checkpoint).

## Verified retained inputs and recovery

The local staging API creates a new private flat bundle containing the exact
policy/inventory bytes, all six regenerated plan artifacts, `execution.json`
and `checksums.sha256`. Its manifest digest must be recorded separately during
operator review/transfer. The loader checks that independent digest, exact file
membership, mode/owner/link/size bounds, strict JSON/YAML and regenerated bytes.
Execution binding includes the running executable's SHA-256, utility version,
service-contract version and unchanged unit digest. Neither staging nor loading
authorizes tuning. Existing inspect/plan output remains unchanged.

Recovery separately requires the reviewed digest of the original journal
snapshot and an execution-bound transaction matching the verified input bundle.
Its state machine checks contiguous write intents and rollback ordering.
Completed attempts, invalid records, changed utility/boot/topology, foreign
controls and unattempted changes reject. Malformed/truncated journal records
require operator reconciliation; they are never trimmed or replayed.

A read-only review under the host lock captures current controls and service
state. Its approval digest binds those observations; execution checks the
journal again under the lock and refuses subsequent drift. Only attempted
controls still equal to this transaction's proposed bytes/mode/owner can be
restored. Already restored controls are accepted. New recovery journals retain
each intent and result while the original journal is preserved. A partially
restored run can be reviewed again against that original immutable attempt.

Native recovery requires both services running, no queued jobs and a supported
recorded runtime before-image. It allows a pending daemon reload for owned
interrupted changes and verifies restored service policy after approved restarts.
Stopped services, mixed/foreign live policy, active jobs and reboot/IRQ changes
remain manual reconciliation cases pending Ubuntu qualification. The executable
digest provides exact-image binding; it does not establish publisher trust or
make checksum evidence a signature.

See the [retained-input and recovery checkpoint](../../docs/deployment/host-tuning.md#verified-inputs-and-interrupted-run-recovery).

## Rehearsal commands

`bonvoyage-host-tune rehearsal --help` lists six commands:

| Command | Purpose |
| --- | --- |
| `stage` | Verify the original plan bundle and stage execution-bound retained inputs |
| `check` | Verify retained inputs and report exact apply intent without host activation |
| `snapshot` | Report a diagnostic digest of a journal snapshot without replay |
| `apply` | Activate and verify an approved native lab plan |
| `review` | Review current state for interrupted recovery or orderly rollback |
| `restore` | Restore owned prior state using a fresh review approval |

Host commands require `--lab`. Apply/restore also require `--maintenance` and an
exact `--approve` digest. The default deadline is two minutes, capped at ten
minutes; apply failures retain the engine's separate bounded rollback behavior.
The installed CLI always uses the Ubuntu/root backend. Tests inject fixtures
internally; there is no public test-root, arbitrary-command or unsafe-path flag.

Host-operation outputs must be new named attempts directly beneath
`/var/lib/bonvoyage-host-tune/rehearsals`. That mode-0700 root-owned directory and
its ancestry are checked with no-follow access. Attempt reuse is rejected.
Each operation retains a private receipt and checksum manifest; mutations
also retain a synchronized journal. A failed receipt write leaves the journal
and failed attempt in place and returns an error.

Use `--purpose interrupted` only for valid interrupted original journals.
`--purpose rollback` requires a completed applied original journal. The
purpose is part of review approval, so those approvals cannot be interchanged.
Receipts always declare `measurement_authorized=false` and
`native_readiness_qualified=false`. HTTP readiness and native crash/reboot
behavior must still be checked during the VM rehearsal.

See the [Ubuntu native rehearsal runbook](../../docs/deployment/native-tuning-rehearsal.md).

## Build and test

```bash
make host-tune-test
make host-tune-build
make host-tune-linux-amd64
```

The executable is written to `build/tools/bonvoyage-host-tune`.
The static distributed-campaign transfer artifact is written to
`build/tools/bonvoyage-host-tune-linux-amd64` and is checked as Linux AMD64
before any remote collection begins.

The AWS adapter invokes inspection with `--aws-instance-identity`. This opt-in
flag requires IMDSv2 and binds instance ID, instance type, private address,
zone, Region, AMI, architecture, and optional Dedicated Host ID into the
inventory fingerprint. Normal bare-metal inspection does not contact the
metadata endpoint.

## Inspect an Ubuntu host

Install the read-only discovery tools before inspection:

```bash
sudo apt-get install -y pciutils ethtool iproute2 numactl linux-tools-common
```

Capture the route-facing interface automatically:

```bash
sudo -u "$USER" build/tools/bonvoyage-host-tune inspect \
  --interface auto \
  --output /var/tmp/bonvoyage-host-inventory
```

Use `--interface ens5` when the host has multiple default routes or the traffic
interface is not the default route. The output directory must not already
exist.

Inventory schema version 2 includes normalized JSON plus bounded raw evidence
from `lscpu`, `numactl`, `lspci`, `ip`, `ethtool`, `cpupower`, systemd, and
warning/error kernel messages from `dmesg`. It adds normalized NIC MTU and link
speed plus full routes, addresses, scheduler/network state, clock state,
timers, running services, and bounded process identity. Linux sysfs remains
authoritative for CPU sibling, PCI, NUMA, queue, and MSI-X IRQ identity. A
missing tool or restricted command is retained as a non-zero evidence record
and a warning.

Schema version 1 inventories must be recollected rather than rewritten. That
keeps all normalized fields, raw command output, and checksums in one genuine
capture.

The inventory contains host identifiers and is created with owner-only
permissions. Keep the original internal. Sanitize only a derived publication
copy.

## Generate the production default plan

```bash
build/tools/bonvoyage-host-tune plan \
  --inventory /var/tmp/bonvoyage-host-inventory/inventory.json \
  --policy deploy/tuning/policies/throughput-balanced.yaml \
  --output /var/tmp/bonvoyage-host-plan
```

The default assigns up to 80% of complete physical cores to BonVoyage after
reserving at least 20% and two physical cores for the host. SMT siblings remain
together. NIC IRQ cores come from the NIC-local NUMA node and never overlap the
gateway set.

The Seastar allocator proposal starts at 512 MiB per selected logical shard,
with a 1 GiB floor, a 70% host cap, and a 4 GiB host reserve. The systemd plan
sets independent `MemoryHigh` and `MemoryMax` guardrails at 80% and 85% of
physical RAM. Workload-specific sizing can replace the proposal after capacity
evidence; CPU and memory percentages are not interchangeable.

## Generate a fixed benchmark plan

Dedicated comparisons use a declared physical-core count instead of automatic
80% allocation:

```bash
build/tools/bonvoyage-host-tune plan \
  --inventory /var/tmp/bonvoyage-host-inventory/inventory.json \
  --policy deploy/tuning/policies/throughput-balanced.yaml \
  --gateway-physical-cores 8 \
  --output /var/tmp/bonvoyage-benchmark-8-core-plan
```

Repeat with `1`, `2`, `4`, `8`, and `16`. The planner rejects a fixed profile
that would consume the required host reserve.

## Explicit VM rehearsal scope

The current local checkpoint adds `--scope vm-cpu-memory` to `plan` and to
rehearsal stage/check/apply/review/restore. A fixed physical-core count is
mandatory. Default `full-host` preserves strict behavior and omitted plan
scope bytes. VM selection must match the verified plan before output or host
construction; diagnostic snapshot cannot select/attest scope.

VM scope verifies managed argv, effective CPU/memory cgroups, irqbalance
gateway exclusion and fresh host/boot/PCI/NUMA/queue/IRQ identity. Only per-NIC
affinity evidence/convergence is deferred. No NIC masks are written. Scope is
bound into plan/manifest/intent, retained original journals, runtime before-images
and fresh recovery approvals. VM receipts declare `nic_irq_verification=deferred`;
full-host declares `required`. Measurement/readiness qualification stays false.
Both campaign rehearsal and dedicated assessment reject VM plan eligibility.

Use the [scope-aware native runbook](../../docs/deployment/native-tuning-rehearsal.md#prepare-and-review-inputs).
All 79 local top-level tests and 170 subtests pass with race detection;
those local service observations are injected fixtures. Clean-source
Ubuntu scoped apply/orderly/interrupted recovery subsequently passed at clean
`039430a` with native Go 1.26.8. Its exact fault window and independent observations
are recorded in the execution report. Bounded orderly reboot acceptance is now
linked above; broader failure/identity and dedicated NIC qualification remain
pending. The new accepted helper is installed; historical
helper images and receipts remain preserved rather than rewritten.

## Plan artifacts
Each new output directory contains:

- `tuning-plan.json`: policy, inventory, host, NIC, CPU, memory, and warning
  decisions;
- `bonvoyage-resources.conf`: proposed systemd CPU and memory controls;
- `bonvoyage-runtime-arguments.txt`: matching Seastar `--smp`, `--cpuset`, and
  `--memory` arguments;
- `irqbalance.env`: proposed gateway CPU exclusion;
- `irq-affinity.plan.tsv`: proposed MSI-X IRQ-to-reserved-CPU mapping;
- `checksums.sha256`: artifact integrity binding.

These files are **not an apply script**. Do not copy them into `/etc`, write
`/proc/irq`, or restart a production gateway by hand. The future apply stage
must verify the host fingerprint, retain the prior state, perform the changes,
verify effective affinity and cgroup state, and roll back on failure.
