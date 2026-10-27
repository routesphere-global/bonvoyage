#pragma once

#include <cstdint>
#include <optional>

#include <seastar/core/future.hh>
#include <seastar/core/sharded.hh>

#include "bonvoyage/runtime/snapshot_preparation.hh"

namespace bonvoyage::runtime {

/** Node-level result emitted after the all-shard PREPARE barrier. */
struct NodeSnapshotPreparationReport final {
  /** True only after every local shard retained the private artifact. */
  bool acknowledged{false};
  /** Rollout sequence evaluated by the barrier. */
  std::uint64_t rollout_sequence{};
  /** Candidate artifact identity. */
  SnapshotReference snapshot;
  /** Active identity expected before preparation began. */
  SnapshotReference previous_active_snapshot;
  /** Active identity observed after the barrier; PREPARE never changes it. */
  SnapshotReference current_active_snapshot;
  /** Total Seastar shards required by the barrier. */
  std::uint32_t shard_count{};
  /** Number of shards that completed before success or failure. */
  std::uint32_t completed_shards{};
  /** First shard that rejected preparation, when applicable. */
  std::optional<std::uint32_t> failed_shard;
  /** Bounded structured reason for a node-level NACK. */
  std::optional<SnapshotPreparationIssue> issue;
};

/** Node-level result emitted after the all-shard ACTIVATE barrier. */
struct NodeSnapshotActivationReport final {
  /** True only after every local shard publishes or confirms exact replay. */
  bool acknowledged{false};
  /** True when every shard already reflected the exact activation. */
  bool replayed{false};
  /** Rollout sequence evaluated by the barrier. */
  std::uint64_t rollout_sequence{};
  /** Candidate artifact identity. */
  SnapshotReference snapshot;
  /** Active identity required before first publication. */
  SnapshotReference previous_active_snapshot;
  /** Active identity observed after the barrier. */
  SnapshotReference current_active_snapshot;
  /** Total Seastar shards required by the barrier. */
  std::uint32_t shard_count{};
  /** Number of shards that committed or confirmed exact replay. */
  std::uint32_t completed_shards{};
  /** First shard that rejected activation, when applicable. */
  std::optional<std::uint32_t> failed_shard;
  /** Shards still retaining the previous generation for request leases. */
  std::uint32_t retirement_pending_shards{};
  /** Total request leases currently pinning the previous generation. */
  std::uint64_t pinned_retired_leases{};
  /** Bounded structured reason for a node-level NACK. */
  std::optional<SnapshotPreparationIssue> issue;
};

/** Node-level result emitted after an identity-scoped CANCEL barrier. */
struct NodeSnapshotCancellationReport final {
  /** True only after every shard clears or confirms the exact cancellation. */
  bool acknowledged{false};
  /** True when every shard already reflected the exact cancellation. */
  bool replayed{false};
  /** Rollout sequence evaluated by the barrier. */
  std::uint64_t rollout_sequence{};
  /** Private artifact identity authorized for removal. */
  SnapshotReference snapshot;
  /** Active identity retained throughout cancellation. */
  SnapshotReference current_active_snapshot;
  /** Total Seastar shards required by the barrier. */
  std::uint32_t shard_count{};
  /** Number of shards that cleared or confirmed the private state. */
  std::uint32_t completed_shards{};
  /** First shard that rejected cancellation, when applicable. */
  std::optional<std::uint32_t> failed_shard;
  /** Bounded structured reason for a node-level NACK. */
  std::optional<SnapshotPreparationIssue> issue;
};

/** Node-level observation of safe old-generation retirement. */
struct NodeSnapshotRetirementReport final {
  /** True only when no matching old generation remains on any shard. */
  bool complete{false};
  /** Exact old artifact identity requested for retirement. */
  SnapshotReference snapshot;
  /** Total Seastar shards inspected by the retirement pass. */
  std::uint32_t shard_count{};
  /** Number of shards inspected before success or failure. */
  std::uint32_t completed_shards{};
  /** Shards still retaining the generation for active request leases. */
  std::uint32_t pending_shards{};
  /** Total request leases currently pinning the old generation. */
  std::uint64_t pinned_leases{};
  /** First shard that reported a conflicting retired identity. */
  std::optional<std::uint32_t> failed_shard;
  /** Bounded structured reason for a failed retirement pass. */
  std::optional<SnapshotPreparationIssue> issue;
};

/**
 * Prepares an artifact on every shard or clears all matching private state.
 *
 * This function must run on shard zero. It never changes active snapshots.
 */
seastar::future<NodeSnapshotPreparationReport> prepare_snapshot_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& shards,
    SnapshotPrepareCommand command);

/** Fences admission and publishes one exact prepared artifact on every shard. */
seastar::future<NodeSnapshotActivationReport> activate_snapshot_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& shards,
    SnapshotActivateCommand command);

/** Clears one exact private preparation only after every shard accepts it. */
seastar::future<NodeSnapshotCancellationReport> cancel_snapshot_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& shards,
    SnapshotCancelCommand command);

/** Reaps one old generation wherever no request lease still pins it. */
seastar::future<NodeSnapshotRetirementReport>
reap_retired_snapshot_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& shards,
    SnapshotReference snapshot);

/** Clears a matching prepared artifact from every shard. */
seastar::future<> discard_prepared_snapshot_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& shards,
    std::uint64_t rollout_sequence,
    SnapshotReference snapshot);

}  // namespace bonvoyage::runtime
