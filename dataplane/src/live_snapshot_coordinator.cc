#include "bonvoyage/runtime/live_snapshot_coordinator.hh"

#include <algorithm>
#include <exception>
#include <limits>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include <seastar/core/coroutine.hh>
#include <seastar/core/reactor.hh>

namespace bonvoyage::runtime {
namespace detail {
namespace {

constexpr std::size_t kMaximumIssueCodeBytes = 128U;
constexpr std::size_t kMaximumIssueFieldPathBytes = 1024U;
constexpr std::size_t kMaximumIssueMessageBytes = 4096U;

struct CombinedActivationArm final {
  ShardSnapshotActivationResult lifecycle;
  ShardSnapshotActivationResult live;
};

struct CombinedCancellationArm final {
  ShardSnapshotCancellationResult lifecycle;
  ShardSnapshotCancellationResult live;
};

struct CombinedRetirementResult final {
  ShardSnapshotRetirementResult lifecycle;
  ShardSnapshotRetirementResult live;
};

[[nodiscard]] SnapshotPreparationIssue issue(std::string code,
                                             std::string field_path,
                                             std::string message) {
  return SnapshotPreparationIssue{std::move(code), std::move(field_path),
                                  std::move(message)};
}

[[nodiscard]] SnapshotPreparationIssue bounded_issue(
    std::optional<SnapshotPreparationIssue> candidate,
    SnapshotPreparationIssue fallback) {
  auto result = candidate.has_value() ? std::move(*candidate)
                                      : std::move(fallback);
  if (result.code.empty()) {
    result.code = "snapshot.operation.internal";
  }
  if (result.message.empty()) {
    result.message = "live snapshot operation failed internally";
  }
  result.code.resize(
      std::min(result.code.size(), kMaximumIssueCodeBytes));
  result.field_path.resize(
      std::min(result.field_path.size(), kMaximumIssueFieldPathBytes));
  result.message.resize(
      std::min(result.message.size(), kMaximumIssueMessageBytes));
  return result;
}

[[nodiscard]] SnapshotPreparationIssue preparation_internal_issue() {
  return issue("snapshot.prepare.live_internal", "snapshot",
               "live gateway preparation failed internally");
}

[[nodiscard]] SnapshotPreparationIssue preparation_resource_issue() {
  return issue("snapshot.prepare.resource_exhausted", "snapshot",
               "live gateway preparation exhausted memory");
}

[[nodiscard]] SnapshotPreparationIssue preparation_divergence_issue() {
  return issue(
      "snapshot.prepare.layer_divergence", "rollout_sequence",
      "lifecycle and live gateway preparations did not converge uniformly");
}

[[nodiscard]] SnapshotPreparationIssue maintenance_start_issue() {
  return issue("snapshot.prepare.maintenance_failed", "snapshot",
               "prepared gateway maintenance could not start");
}

[[nodiscard]] SnapshotPreparationIssue activation_internal_issue() {
  return issue("snapshot.activate.live_internal", "snapshot",
               "live gateway activation failed before publication");
}

[[nodiscard]] SnapshotPreparationIssue activation_divergence_issue() {
  return issue(
      "snapshot.activate.layer_divergence", "rollout_sequence",
      "lifecycle and live gateway activation state diverged before publication");
}

[[nodiscard]] SnapshotPreparationIssue maintenance_stop_issue() {
  return issue("snapshot.activate.maintenance_stop_failed", "snapshot",
               "active gateway maintenance could not stop before publication");
}

[[nodiscard]] SnapshotPreparationIssue cancellation_internal_issue() {
  return issue("snapshot.cancel.live_internal", "snapshot",
               "live gateway cancellation failed before commit");
}

[[nodiscard]] SnapshotPreparationIssue cancellation_divergence_issue() {
  return issue(
      "snapshot.cancel.layer_divergence", "rollout_sequence",
      "lifecycle and live gateway cancellation state did not converge uniformly");
}

[[nodiscard]] SnapshotPreparationIssue retirement_internal_issue() {
  return issue("snapshot.retirement.live_internal", "retired_snapshot",
               "live gateway retirement failed internally");
}

[[nodiscard]] SnapshotPreparationIssue retirement_resource_issue() {
  return issue("snapshot.retirement.resource_exhausted", "retired_snapshot",
               "live gateway retirement exhausted memory");
}

[[nodiscard]] std::uint32_t checked_shard_count() {
  if (seastar::smp::count == 0U ||
      seastar::smp::count >
          static_cast<unsigned>(std::numeric_limits<std::uint32_t>::max())) {
    throw std::logic_error("Seastar shard count is outside the report range");
  }
  return static_cast<std::uint32_t>(seastar::smp::count);
}

void require_shard_zero(const char* operation) {
  if (seastar::this_shard_id() != 0U) {
    throw std::logic_error(std::string(operation) +
                           " must run on shard zero");
  }
}

void require_complete_operations(
    const LiveSnapshotCoordinatorOperations& operations) {
  if (!operations.prepare_live_snapshot ||
      !operations.start_prepared_maintenance ||
      !operations.stop_active_maintenance ||
      !operations.arm_live_activation ||
      !operations.abort_live_activation ||
      !operations.commit_live_activation || !operations.arm_live_cancel ||
      !operations.abort_live_cancel || !operations.commit_live_cancel ||
      !operations.discard_live_prepared ||
      !operations.reap_live_retired) {
    throw std::logic_error(
        "live snapshot coordinator operations are incomplete");
  }
}

seastar::future<> discard_private_layers_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    const LiveSnapshotCoordinatorOperations& operations,
    std::uint64_t rollout_sequence, const SnapshotReference& snapshot) {
  std::exception_ptr cleanup_failure;
  for (seastar::shard_id shard_id = 0U; shard_id < seastar::smp::count;
       ++shard_id) {
    try {
      auto discard_live = operations.discard_live_prepared;
      co_await lifecycle.invoke_on(
          shard_id,
          [discard_live = std::move(discard_live), rollout_sequence,
           snapshot](SnapshotPreparationShard&) mutable {
            return discard_live(rollout_sequence, snapshot);
          });
    } catch (...) {
      if (cleanup_failure == nullptr) {
        cleanup_failure = std::current_exception();
      }
    }
  }

  co_await discard_prepared_snapshot_on_all_shards(
      lifecycle, rollout_sequence, snapshot);
  if (cleanup_failure != nullptr) {
    std::rethrow_exception(cleanup_failure);
  }
}

seastar::future<> abort_activation_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    const LiveSnapshotCoordinatorOperations& operations) {
  auto abort_live = operations.abort_live_activation;
  co_await lifecycle.invoke_on_all(
      [abort_live = std::move(abort_live)](
          SnapshotPreparationShard& shard) mutable {
        abort_live();
        shard.abort_armed_activation();
      });
}

seastar::future<> abort_cancel_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    const LiveSnapshotCoordinatorOperations& operations) {
  auto abort_live = operations.abort_live_cancel;
  co_await lifecycle.invoke_on_all(
      [abort_live = std::move(abort_live)](
          SnapshotPreparationShard& shard) mutable {
        abort_live();
        shard.abort_armed_cancel();
      });
}

[[noreturn]] void publication_invariant_failed() noexcept {
  std::terminate();
}

}  // namespace

seastar::future<NodeSnapshotPreparationReport>
prepare_live_snapshot_on_all_shards_with_operations(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    LiveSnapshotCoordinatorOperations operations,
    SnapshotPrepareCommand command) {
  require_shard_zero("all-shard live snapshot prepare");
  require_complete_operations(operations);

  auto report = co_await prepare_snapshot_on_all_shards(lifecycle, command);
  if (!report.acknowledged) {
    co_await discard_private_layers_on_all_shards(
        lifecycle, operations, command.rollout_sequence, command.snapshot);
    co_return report;
  }

  report.acknowledged = false;
  report.completed_shards = 0U;
  std::optional<bool> replay_mode;
  for (seastar::shard_id shard_id = 0U; shard_id < seastar::smp::count;
       ++shard_id) {
    ShardSnapshotPreparationResult result;
    try {
      auto prepare_live = operations.prepare_live_snapshot;
      auto shard_command = command;
      result = co_await lifecycle.invoke_on(
          shard_id,
          [prepare_live = std::move(prepare_live),
           command = std::move(shard_command)](
              SnapshotPreparationShard&) mutable {
            return prepare_live(std::move(command));
          });
    } catch (const std::bad_alloc&) {
      result.issue = preparation_resource_issue();
    } catch (const std::exception&) {
      result.issue = preparation_internal_issue();
    } catch (...) {
      result.issue = preparation_internal_issue();
    }

    if (!result.prepared) {
      report.failed_shard = static_cast<std::uint32_t>(shard_id);
      report.issue = bounded_issue(std::move(result.issue),
                                   preparation_internal_issue());
      co_await discard_private_layers_on_all_shards(
          lifecycle, operations, command.rollout_sequence, command.snapshot);
      co_return report;
    }
    if (result.active_snapshot != command.expected_active_snapshot ||
        (replay_mode.has_value() && *replay_mode != result.replayed)) {
      report.failed_shard = static_cast<std::uint32_t>(shard_id);
      report.issue = preparation_divergence_issue();
      co_await discard_private_layers_on_all_shards(
          lifecycle, operations, command.rollout_sequence, command.snapshot);
      co_return report;
    }
    replay_mode = result.replayed;
    ++report.completed_shards;
  }

  if (!replay_mode.value_or(false)) {
    bool maintenance_started = false;
    try {
      co_await operations.start_prepared_maintenance(command.snapshot);
      maintenance_started = true;
    } catch (const std::exception&) {
      report.failed_shard = 0U;
      report.issue = maintenance_start_issue();
    } catch (...) {
      report.failed_shard = 0U;
      report.issue = maintenance_start_issue();
    }
    if (!maintenance_started) {
      co_await discard_private_layers_on_all_shards(
          lifecycle, operations, command.rollout_sequence, command.snapshot);
      co_return report;
    }
  }

  report.acknowledged = true;
  report.issue.reset();
  report.failed_shard.reset();
  co_return report;
}

seastar::future<NodeSnapshotRetirementReport>
reap_live_retired_snapshot_on_all_shards_with_operations(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    LiveSnapshotCoordinatorOperations operations,
    SnapshotReference snapshot) {
  require_shard_zero("all-shard live snapshot retirement");
  require_complete_operations(operations);

  NodeSnapshotRetirementReport report;
  report.snapshot = snapshot;
  report.shard_count = checked_shard_count();
  for (seastar::shard_id shard_id = 0U; shard_id < seastar::smp::count;
       ++shard_id) {
    CombinedRetirementResult result;
    try {
      auto reap_live = operations.reap_live_retired;
      result = co_await lifecycle.invoke_on(
          shard_id,
          [reap_live = std::move(reap_live), snapshot](
              SnapshotPreparationShard& shard) mutable
              -> seastar::future<CombinedRetirementResult> {
            CombinedRetirementResult local;
            local.lifecycle = shard.reap_retired_snapshot(snapshot);
            if (!local.lifecycle.issue.has_value()) {
              local.live = co_await reap_live(
                  snapshot, local.lifecycle.complete);
            }
            co_return local;
          });
    } catch (const std::bad_alloc&) {
      result.live.issue = retirement_resource_issue();
    } catch (const std::exception&) {
      result.live.issue = retirement_internal_issue();
    } catch (...) {
      result.live.issue = retirement_internal_issue();
    }

    if (result.lifecycle.issue.has_value() || result.live.issue.has_value()) {
      report.failed_shard = static_cast<std::uint32_t>(shard_id);
      report.issue = bounded_issue(
          result.lifecycle.issue.has_value()
              ? std::move(result.lifecycle.issue)
              : std::move(result.live.issue),
          retirement_internal_issue());
      co_return report;
    }
    if (!result.lifecycle.complete && result.live.complete) {
      report.failed_shard = static_cast<std::uint32_t>(shard_id);
      report.issue = issue(
          "snapshot.retirement.layer_divergence", "retired_snapshot",
          "live resources retired while lifecycle leases remained pinned");
      co_return report;
    }
    ++report.completed_shards;
    if (!result.lifecycle.complete || !result.live.complete) {
      ++report.pending_shards;
      report.pinned_leases += result.lifecycle.pinned_leases;
    }
  }
  report.complete = report.pending_shards == 0U;
  co_return report;
}

seastar::future<NodeSnapshotActivationReport>
activate_live_snapshot_on_all_shards_with_operations(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    LiveSnapshotCoordinatorOperations operations,
    SnapshotActivateCommand command) {
  require_shard_zero("all-shard live snapshot activate");
  require_complete_operations(operations);

  NodeSnapshotActivationReport report;
  report.rollout_sequence = command.rollout_sequence;
  report.snapshot = command.prepared_snapshot;
  report.previous_active_snapshot = command.expected_active_snapshot;
  report.current_active_snapshot = command.expected_active_snapshot;
  report.shard_count = checked_shard_count();

  std::optional<bool> replay_mode;
  for (seastar::shard_id shard_id = 0U; shard_id < seastar::smp::count;
       ++shard_id) {
    CombinedActivationArm result;
    try {
      auto arm_live = operations.arm_live_activation;
      result = co_await lifecycle.invoke_on(
          shard_id,
          [arm_live = std::move(arm_live), command](
              SnapshotPreparationShard& shard) mutable {
            CombinedActivationArm local;
            local.lifecycle = shard.arm_activation(command);
            if (local.lifecycle.accepted) {
              local.live = arm_live(command);
            }
            return local;
          });
    } catch (const std::exception&) {
      result.live.issue = activation_internal_issue();
    } catch (...) {
      result.live.issue = activation_internal_issue();
    }

    std::optional<SnapshotPreparationIssue> rejection;
    if (!result.lifecycle.accepted) {
      rejection = bounded_issue(std::move(result.lifecycle.issue),
                                activation_internal_issue());
    } else if (!result.live.accepted) {
      rejection = bounded_issue(std::move(result.live.issue),
                                activation_internal_issue());
    } else if (result.lifecycle.replayed != result.live.replayed ||
               result.lifecycle.active_snapshot !=
                   result.live.active_snapshot) {
      rejection = activation_divergence_issue();
    } else {
      const auto& required_active =
          result.lifecycle.replayed ? command.prepared_snapshot
                                    : command.expected_active_snapshot;
      if (result.lifecycle.active_snapshot != required_active ||
          (replay_mode.has_value() &&
           *replay_mode != result.lifecycle.replayed)) {
        rejection = activation_divergence_issue();
      }
    }

    if (rejection.has_value()) {
      report.failed_shard = static_cast<std::uint32_t>(shard_id);
      report.issue = std::move(rejection);
      co_await abort_activation_on_all_shards(lifecycle, operations);
      co_return report;
    }
    replay_mode = result.lifecycle.replayed;
  }

  if (replay_mode.value_or(false)) {
    auto retirement =
        co_await reap_live_retired_snapshot_on_all_shards_with_operations(
            lifecycle, operations, command.expected_active_snapshot);
    if (retirement.issue.has_value()) {
      throw std::logic_error(
          "live snapshot retirement failed after an activation replay");
    }
    report.acknowledged = true;
    report.replayed = true;
    report.completed_shards = report.shard_count;
    report.current_active_snapshot = command.prepared_snapshot;
    report.retirement_pending_shards = retirement.pending_shards;
    report.pinned_retired_leases = retirement.pinned_leases;
    co_return report;
  }

  bool maintenance_stopped = false;
  try {
    co_await operations.stop_active_maintenance();
    maintenance_stopped = true;
  } catch (const std::exception&) {
    report.failed_shard = 0U;
    report.issue = maintenance_stop_issue();
  } catch (...) {
    report.failed_shard = 0U;
    report.issue = maintenance_stop_issue();
  }
  if (!maintenance_stopped) {
    co_await abort_activation_on_all_shards(lifecycle, operations);
    co_return report;
  }

  for (seastar::shard_id shard_id = 0U; shard_id < seastar::smp::count;
       ++shard_id) {
    auto commit_live = operations.commit_live_activation;
    co_await lifecycle.invoke_on(
        shard_id,
        [commit_live = std::move(commit_live)](
            SnapshotPreparationShard& shard) mutable {
          if (!shard.commit_armed_activation() || !commit_live()) {
            publication_invariant_failed();
          }
        });
    ++report.completed_shards;
  }

  co_await lifecycle.invoke_on_all([](SnapshotPreparationShard& shard) {
    shard.reopen_admission();
  });
  report.current_active_snapshot = command.prepared_snapshot;

  auto retirement =
      co_await reap_live_retired_snapshot_on_all_shards_with_operations(
          lifecycle, operations, command.expected_active_snapshot);
  if (retirement.issue.has_value()) {
    throw std::logic_error(
        "live snapshot retirement failed after atomic publication");
  }
  report.retirement_pending_shards = retirement.pending_shards;
  report.pinned_retired_leases = retirement.pinned_leases;
  report.acknowledged = true;
  co_return report;
}

seastar::future<NodeSnapshotCancellationReport>
cancel_live_snapshot_on_all_shards_with_operations(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    LiveSnapshotCoordinatorOperations operations,
    SnapshotCancelCommand command) {
  require_shard_zero("all-shard live snapshot cancel");
  require_complete_operations(operations);

  NodeSnapshotCancellationReport report;
  report.rollout_sequence = command.rollout_sequence;
  report.snapshot = command.snapshot;
  report.current_active_snapshot = lifecycle.local().state().active_snapshot;
  report.shard_count = checked_shard_count();

  std::optional<bool> replay_mode;
  for (seastar::shard_id shard_id = 0U; shard_id < seastar::smp::count;
       ++shard_id) {
    CombinedCancellationArm result;
    try {
      auto arm_live = operations.arm_live_cancel;
      result = co_await lifecycle.invoke_on(
          shard_id,
          [arm_live = std::move(arm_live), command](
              SnapshotPreparationShard& shard) mutable {
            CombinedCancellationArm local;
            local.lifecycle = shard.arm_cancel(command);
            if (local.lifecycle.accepted) {
              local.live = arm_live(command);
            }
            return local;
          });
    } catch (const std::exception&) {
      result.live.issue = cancellation_internal_issue();
    } catch (...) {
      result.live.issue = cancellation_internal_issue();
    }

    std::optional<SnapshotPreparationIssue> rejection;
    if (!result.lifecycle.accepted) {
      rejection = bounded_issue(std::move(result.lifecycle.issue),
                                cancellation_internal_issue());
    } else if (!result.live.accepted) {
      rejection = bounded_issue(std::move(result.live.issue),
                                cancellation_internal_issue());
    } else if (result.lifecycle.replayed != result.live.replayed ||
               result.lifecycle.active_snapshot !=
                   result.live.active_snapshot ||
               result.lifecycle.active_snapshot !=
                   report.current_active_snapshot ||
               (replay_mode.has_value() &&
                *replay_mode != result.lifecycle.replayed)) {
      rejection = cancellation_divergence_issue();
    }

    if (rejection.has_value()) {
      report.failed_shard = static_cast<std::uint32_t>(shard_id);
      report.issue = std::move(rejection);
      co_await abort_cancel_on_all_shards(lifecycle, operations);
      co_return report;
    }
    replay_mode = result.lifecycle.replayed;
  }

  if (replay_mode.value_or(false)) {
    report.acknowledged = true;
    report.replayed = true;
    report.completed_shards = report.shard_count;
    co_return report;
  }

  for (seastar::shard_id shard_id = 0U; shard_id < seastar::smp::count;
       ++shard_id) {
    auto commit_live = operations.commit_live_cancel;
    co_await lifecycle.invoke_on(
        shard_id,
        [commit_live = std::move(commit_live)](
            SnapshotPreparationShard& shard) mutable -> seastar::future<> {
          if (!(co_await commit_live()) || !shard.commit_armed_cancel()) {
            publication_invariant_failed();
          }
        });
    ++report.completed_shards;
  }
  report.acknowledged = true;
  co_return report;
}

}  // namespace detail
}  // namespace bonvoyage::runtime
