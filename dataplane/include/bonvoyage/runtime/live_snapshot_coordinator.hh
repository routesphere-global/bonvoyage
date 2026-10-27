#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>

#include <seastar/core/future.hh>
#include <seastar/core/sharded.hh>

#include "bonvoyage/runtime/gateway.hh"
#include "bonvoyage/runtime/snapshot_preparation_coordinator.hh"

namespace bonvoyage::runtime {
namespace detail {

/**
 * Shard-local live-resource operations used by the node coordinator.
 *
 * Every callable except prepared-maintenance startup executes on the shard
 * currently being coordinated. The seam keeps the barrier independently
 * testable without changing the production GatewayShard contract.
 */
struct LiveSnapshotCoordinatorOperations final {
  /** Compiles and retains one private live runtime for the PREPARE command. */
  std::function<seastar::future<ShardSnapshotPreparationResult>(
      SnapshotPrepareCommand)>
      prepare_live_snapshot;
  /** Starts health and DNS maintenance for the matching prepared runtime. */
  std::function<seastar::future<>(const SnapshotReference&)>
      start_prepared_maintenance;
  /** Stops maintenance owned by the currently active runtime. */
  std::function<seastar::future<>()> stop_active_maintenance;
  /** Validates and arms the no-fail live-runtime activation boundary. */
  std::function<ShardSnapshotActivationResult(
      const SnapshotActivateCommand&)>
      arm_live_activation;
  /** Releases a live-runtime activation arm before publication. */
  std::function<void()> abort_live_activation;
  /** Publishes the armed runtime using no-fail ownership moves. */
  std::function<bool()> commit_live_activation;
  /** Validates and arms cancellation of the matching prepared runtime. */
  std::function<ShardSnapshotCancellationResult(
      const SnapshotCancelCommand&)>
      arm_live_cancel;
  /** Releases a live-runtime cancellation arm without changing ownership. */
  std::function<void()> abort_live_cancel;
  /** Commits the armed cancellation and releases its private resources. */
  std::function<seastar::future<bool>()> commit_live_cancel;
  /** Discards private live resources for the exact rollout and snapshot. */
  std::function<seastar::future<>(std::uint64_t, SnapshotReference)>
      discard_live_prepared;
  /** Reaps a retired generation after both lifecycle and live leases drain. */
  std::function<seastar::future<ShardSnapshotRetirementResult>(
      SnapshotReference, bool)>
      reap_live_retired;
};

/** Test seam for the all-shard PREPARE transaction. */
seastar::future<NodeSnapshotPreparationReport>
prepare_live_snapshot_on_all_shards_with_operations(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    LiveSnapshotCoordinatorOperations operations,
    SnapshotPrepareCommand command);

/** Test seam for the all-shard ACTIVATE transaction. */
seastar::future<NodeSnapshotActivationReport>
activate_live_snapshot_on_all_shards_with_operations(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    LiveSnapshotCoordinatorOperations operations,
    SnapshotActivateCommand command);

/** Test seam for the all-shard CANCEL transaction. */
seastar::future<NodeSnapshotCancellationReport>
cancel_live_snapshot_on_all_shards_with_operations(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    LiveSnapshotCoordinatorOperations operations,
    SnapshotCancelCommand command);

/** Test seam for lease-aware live-resource retirement. */
seastar::future<NodeSnapshotRetirementReport>
reap_live_retired_snapshot_on_all_shards_with_operations(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    LiveSnapshotCoordinatorOperations operations,
    SnapshotReference snapshot);

/** Binds the coordinator operation seam to the production gateway shards. */
inline LiveSnapshotCoordinatorOperations gateway_operations(
    seastar::sharded<GatewayShard>& gateways) {
  LiveSnapshotCoordinatorOperations operations;
  operations.prepare_live_snapshot = [&gateways](SnapshotPrepareCommand command) {
    return gateways.local().prepare_live_snapshot(std::move(command));
  };
  operations.start_prepared_maintenance =
      [&gateways](const SnapshotReference& snapshot) {
        auto active_health_publisher =
            [&gateways, snapshot](std::size_t cluster_index,
                                  std::size_t endpoint_index,
                                  bool active_healthy) {
              return gateways.invoke_on_all(
                  [snapshot, cluster_index, endpoint_index, active_healthy](
                      GatewayShard& gateway) {
                    gateway.apply_generation_active_health(
                        snapshot, cluster_index, endpoint_index,
                        active_healthy);
                  });
            };
        auto dns_address_publisher =
            [&gateways, snapshot](std::size_t cluster_index,
                                  std::size_t endpoint_index,
                                  std::string resolved_address) {
              return gateways.invoke_on_all(
                  [snapshot, cluster_index, endpoint_index,
                   resolved_address = std::move(resolved_address)](
                      GatewayShard& gateway) {
                    gateway.apply_generation_resolved_address(
                        snapshot, cluster_index, endpoint_index,
                        resolved_address);
                  });
            };
        return gateways.local().start_prepared_maintenance(
            snapshot, std::move(active_health_publisher),
            std::move(dns_address_publisher));
      };
  operations.stop_active_maintenance = [&gateways] {
    return gateways.local().stop_maintenance();
  };
  operations.arm_live_activation = [&gateways](
                                              const SnapshotActivateCommand&
                                                  command) {
    return gateways.local().arm_live_activation(command);
  };
  operations.abort_live_activation = [&gateways] {
    gateways.local().abort_live_activation();
  };
  operations.commit_live_activation = [&gateways] {
    return gateways.local().commit_live_activation();
  };
  operations.arm_live_cancel = [&gateways](
                                          const SnapshotCancelCommand& command) {
    return gateways.local().arm_live_cancel(command);
  };
  operations.abort_live_cancel = [&gateways] {
    gateways.local().abort_live_cancel();
  };
  operations.commit_live_cancel = [&gateways] {
    return gateways.local().commit_live_cancel();
  };
  operations.discard_live_prepared =
      [&gateways](std::uint64_t rollout_sequence, SnapshotReference snapshot) {
        return gateways.local().discard_live_prepared(
            rollout_sequence, std::move(snapshot));
      };
  operations.reap_live_retired =
      [&gateways](SnapshotReference snapshot, bool lifecycle_unpinned) {
        return gateways.local().reap_live_retired(
            std::move(snapshot), lifecycle_unpinned);
      };
  return operations;
}

}  // namespace detail

/**
 * Validates and prepares lifecycle plus live gateway resources on every shard.
 *
 * This operation must run on shard zero. Active traffic is never changed.
 */
inline seastar::future<NodeSnapshotPreparationReport>
prepare_live_snapshot_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    seastar::sharded<GatewayShard>& gateways,
    SnapshotPrepareCommand command) {
  return detail::prepare_live_snapshot_on_all_shards_with_operations(
      lifecycle, detail::gateway_operations(gateways), std::move(command));
}

/**
 * Atomically publishes matching lifecycle and live generations on every shard.
 *
 * This operation must run on shard zero. A post-publication invariant failure
 * is propagated as a fatal operation error and is never converted to a NACK.
 */
inline seastar::future<NodeSnapshotActivationReport>
activate_live_snapshot_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    seastar::sharded<GatewayShard>& gateways,
    SnapshotActivateCommand command) {
  return detail::activate_live_snapshot_on_all_shards_with_operations(
      lifecycle, detail::gateway_operations(gateways), std::move(command));
}

/** Clears one exact private lifecycle and live generation on every shard. */
inline seastar::future<NodeSnapshotCancellationReport>
cancel_live_snapshot_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    seastar::sharded<GatewayShard>& gateways, SnapshotCancelCommand command) {
  return detail::cancel_live_snapshot_on_all_shards_with_operations(
      lifecycle, detail::gateway_operations(gateways), std::move(command));
}

/** Closes live retired resources only after lifecycle leases are unpinned. */
inline seastar::future<NodeSnapshotRetirementReport>
reap_live_retired_snapshot_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    seastar::sharded<GatewayShard>& gateways, SnapshotReference snapshot) {
  return detail::reap_live_retired_snapshot_on_all_shards_with_operations(
      lifecycle, detail::gateway_operations(gateways), std::move(snapshot));
}

}  // namespace bonvoyage::runtime
