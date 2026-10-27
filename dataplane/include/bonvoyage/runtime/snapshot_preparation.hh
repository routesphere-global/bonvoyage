#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "bonvoyage/v1/discovery.pb.h"

namespace bonvoyage::runtime {

class RuntimeSnapshot;
class SnapshotGeneration;
class SnapshotPreparationShard;

/** SHA-256 identity of one exact immutable snapshot artifact. */
using SnapshotDigest = std::array<std::uint8_t, 32U>;

/** Maximum exact snapshot artifact accepted by the dataplane. */
inline constexpr std::size_t kMaximumSnapshotArtifactBytes = 64U << 20U;

/** Operator-facing snapshot name paired with its authoritative byte digest. */
struct SnapshotReference final {
  /** Operator-facing immutable snapshot name. */
  std::string snapshot_id;
  /** Authoritative digest of the exact artifact bytes. */
  SnapshotDigest sha256{};

  /** Returns true when no operator-facing snapshot identity is present. */
  [[nodiscard]] bool empty() const noexcept;
  /** Compares operator-facing identity and authoritative digest. */
  bool operator==(const SnapshotReference&) const = default;
};

/**
 * Move-only shard-local lease pinning one immutable active generation.
 *
 * A lease must be destroyed on its owning shard before the lifecycle owner is
 * destroyed. It uses a plain shard-local counter and performs no atomic or
 * cross-shard operation on the request path.
 */
class SnapshotReadLease final {
 public:
  /** Creates an empty lease. */
  SnapshotReadLease() noexcept = default;
  /** Releases the pinned generation when present. */
  ~SnapshotReadLease();

  /** Transfers one shard-local lease. */
  SnapshotReadLease(SnapshotReadLease&& other) noexcept;
  /** Releases the current lease and transfers another. */
  SnapshotReadLease& operator=(SnapshotReadLease&& other) noexcept;

  /** Snapshot leases cannot be copied. */
  SnapshotReadLease(const SnapshotReadLease&) = delete;
  /** Snapshot leases cannot be copy-assigned. */
  SnapshotReadLease& operator=(const SnapshotReadLease&) = delete;

  /** Returns true when this object pins an active generation. */
  [[nodiscard]] explicit operator bool() const noexcept;
  /** Returns the exact identity pinned by this lease. */
  [[nodiscard]] const SnapshotReference& snapshot() const noexcept;
  /** Returns the compiled runtime when the generation is lifecycle-owned. */
  [[nodiscard]] const RuntimeSnapshot* runtime_snapshot() const noexcept;

 private:
  friend class SnapshotPreparationShard;
  explicit SnapshotReadLease(SnapshotGeneration* generation) noexcept;
  void release() noexcept;

  SnapshotGeneration* generation_{};
};

/** One mandatory versioned behavior declared by a snapshot artifact. */
struct SnapshotCapability final {
  /** Capability behavior identifier. */
  bonvoyage::v1::NodeCapabilityType capability{
      bonvoyage::v1::NODE_CAPABILITY_TYPE_UNSPECIFIED};
  /** Required capability contract version. */
  std::uint32_t version{};

  /** Compares the capability behavior and required contract version. */
  bool operator==(const SnapshotCapability&) const = default;
};

/** Complete node-local PREPARE input copied from one rollout command. */
struct SnapshotPrepareCommand final {
  /** Monotonic rollout sequence assigned by the control plane. */
  std::uint64_t rollout_sequence{};
  /** Declared identity of the candidate artifact. */
  SnapshotReference snapshot;
  /** Exact deterministic Protobuf artifact bytes. */
  std::string snapshot_bytes;
  /** Declared configuration schema version. */
  std::uint32_t schema_version{};
  /** Oldest dataplane semantic version allowed to accept the artifact. */
  std::string minimum_dataplane_version;
  /** Versioned node behaviors required by the artifact. */
  std::vector<SnapshotCapability> required_capabilities;
  /** Exact active identity that must still be serving on every shard. */
  SnapshotReference expected_active_snapshot;
};

/** Complete node-local ACTIVATE input copied from one rollout command. */
struct SnapshotActivateCommand final {
  /** Monotonic rollout sequence previously accepted by PREPARE. */
  std::uint64_t rollout_sequence{};
  /** Exact private artifact identity authorized for publication. */
  SnapshotReference prepared_snapshot;
  /** Exact active identity that must still precede publication. */
  SnapshotReference expected_active_snapshot;
};

/** Complete node-local CANCEL input copied from one rollout command. */
struct SnapshotCancelCommand final {
  /** Monotonic rollout sequence previously accepted by PREPARE. */
  std::uint64_t rollout_sequence{};
  /** Exact private artifact identity authorized for removal. */
  SnapshotReference snapshot;
  /** Bounded operator-facing cancellation reason. */
  std::string reason;
};

/** Stable structured validation fact suitable for a later wire NACK. */
struct SnapshotPreparationIssue final {
  /** Stable machine-readable failure code. */
  std::string code;
  /** Bounded configuration or envelope location associated with the failure. */
  std::string field_path;
  /** Bounded operator-facing explanation. */
  std::string message;
};

/** Result of preparing one artifact on one shard. */
struct ShardSnapshotPreparationResult final {
  /** True only when private state exists for the requested artifact. */
  bool prepared{false};
  /** True when an exact retained preparation satisfied the request. */
  bool replayed{false};
  /** Active identity observed without mutation during PREPARE. */
  SnapshotReference active_snapshot;
  /** Structured failure when preparation did not complete. */
  std::optional<SnapshotPreparationIssue> issue;
};

/** Result of arming one shard for a node-local activation barrier. */
struct ShardSnapshotActivationResult final {
  /** True only when the shard is armed or already reflects an exact replay. */
  bool accepted{false};
  /** True when the exact activation had already completed. */
  bool replayed{false};
  /** Active identity observed before any publication step. */
  SnapshotReference active_snapshot;
  /** Structured failure when activation could not be armed. */
  std::optional<SnapshotPreparationIssue> issue;
};

/** Result of validating one identity-scoped cancellation on one shard. */
struct ShardSnapshotCancellationResult final {
  /** True only when cancellation may commit or is an exact replay. */
  bool accepted{false};
  /** True when the exact cancellation had already completed. */
  bool replayed{false};
  /** Active identity observed without mutation during cancellation. */
  SnapshotReference active_snapshot;
  /** Structured failure when cancellation could not proceed. */
  std::optional<SnapshotPreparationIssue> issue;
};

/** Result of safely reaping one retired generation on one shard. */
struct ShardSnapshotRetirementResult final {
  /** True when no matching retired generation remains. */
  bool complete{false};
  /** Number of active request leases still pinning the generation. */
  std::uint64_t pinned_leases{};
  /** Structured failure when a different retired identity was observed. */
  std::optional<SnapshotPreparationIssue> issue;
};

/** Public identity of one privately prepared shard-local snapshot. */
struct PreparedSnapshotState final {
  /** Rollout sequence that owns the private state. */
  std::uint64_t rollout_sequence{};
  /** Exact private artifact identity. */
  SnapshotReference snapshot;
};

/** Observable identity and pin count for one old active generation. */
struct RetiredSnapshotState final {
  /** Rollout sequence that originally activated the old generation. */
  std::uint64_t rollout_sequence{};
  /** Exact old artifact identity retained for in-flight requests. */
  SnapshotReference snapshot;
  /** Current shard-local request leases pinning the old generation. */
  std::uint64_t pinned_leases{};
};

/** Observable state retained by one shard-local preparation slot. */
struct SnapshotPreparationState final {
  /** Identity currently serving traffic on this shard. */
  SnapshotReference active_snapshot;
  /** Rollout sequence that activated the current identity, or zero at boot. */
  std::uint64_t active_rollout_sequence{};
  /** Private candidate identity, when one has been prepared. */
  std::optional<PreparedSnapshotState> prepared_snapshot;
  /** Previous active generation retained for existing request leases. */
  std::optional<RetiredSnapshotState> retired_snapshot;
  /** Greatest rollout sequence successfully prepared by this shard. */
  std::uint64_t last_rollout_sequence{};
  /** Whether new requests may acquire the current active generation. */
  bool admission_open{false};
  /** Whether an activation barrier currently fences new acquisitions. */
  bool activation_in_progress{false};
};

/** Returns the exact SHA-256 digest of the supplied bytes. */
[[nodiscard]] SnapshotDigest snapshot_sha256(std::string_view bytes);

/** Returns the capabilities implemented by the Phase 4 v1 dataplane. */
[[nodiscard]] std::vector<SnapshotCapability>
default_snapshot_capabilities();

/**
 * Owns one shard's immutable snapshot lifecycle without cross-shard access.
 *
 * PREPARE compiles private state. ACTIVATE gates new leases before a no-fail
 * pointer publication. Existing leases pin the old generation until safe
 * retirement. Listener, pool, and discovery-client wiring remain external.
 */
class SnapshotPreparationShard final {
 public:
  /** Creates an uninitialized shard-local preparation slot. */
  SnapshotPreparationShard();
  /** Releases any privately prepared snapshot owned by this shard. */
  ~SnapshotPreparationShard();

  /** Shard-local preparation state cannot be copied. */
  SnapshotPreparationShard(const SnapshotPreparationShard&) = delete;
  /** Shard-local preparation state cannot be copy-assigned. */
  SnapshotPreparationShard& operator=(const SnapshotPreparationShard&) =
      delete;

  /** Binds the slot to the immutable snapshot currently serving traffic. */
  void initialize(SnapshotReference active_snapshot);

  /** Configures locally implemented capabilities before preparation. */
  void configure_supported_capabilities(
      std::vector<SnapshotCapability> capabilities);

  /** Validates and privately compiles one complete artifact. */
  [[nodiscard]] ShardSnapshotPreparationResult prepare(
      const SnapshotPrepareCommand& command);

  /** Validates ACTIVATE and closes new-lease admission on this shard. */
  [[nodiscard]] ShardSnapshotActivationResult arm_activation(
      const SnapshotActivateCommand& command);

  /** Reopens admission and retains private state after a failed barrier. */
  void abort_armed_activation() noexcept;

  /** Publishes the armed generation using allocation-free pointer moves. */
  [[nodiscard]] bool commit_armed_activation() noexcept;

  /** Reopens request acquisition after every shard has published. */
  void reopen_admission() noexcept;

  /** Validates and arms an identity-scoped cancellation without clearing state. */
  [[nodiscard]] ShardSnapshotCancellationResult arm_cancel(
      const SnapshotCancelCommand& command);

  /** Clears a cancellation intent after a failed all-shard barrier. */
  void abort_armed_cancel() noexcept;

  /** Commits a cancellation that already passed all-shard validation. */
  [[nodiscard]] bool commit_armed_cancel() noexcept;

  /** Acquires the active generation, or no value while admission is fenced. */
  [[nodiscard]] std::optional<SnapshotReadLease> acquire_active_snapshot()
      noexcept;

  /** Reaps a matching old generation only after its final lease is released. */
  [[nodiscard]] ShardSnapshotRetirementResult reap_retired_snapshot(
      const SnapshotReference& snapshot);

  /** Clears only a matching private preparation; active state is untouched. */
  [[nodiscard]] bool discard_prepared(
      std::uint64_t rollout_sequence,
      const SnapshotReference& snapshot) noexcept;

  /** Returns active, prepared, retired, and activation state for reconciliation. */
  [[nodiscard]] SnapshotPreparationState state() const;

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace bonvoyage::runtime
