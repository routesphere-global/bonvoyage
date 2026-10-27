#include "bonvoyage/runtime/snapshot_preparation_coordinator.hh"

#include <exception>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

#include <seastar/core/coroutine.hh>
#include <seastar/core/reactor.hh>

namespace bonvoyage::runtime {
namespace {

SnapshotPreparationIssue internal_issue() {
  return SnapshotPreparationIssue{
      "snapshot.prepare.internal", "snapshot",
      "all-shard snapshot preparation failed internally"};
}

SnapshotPreparationIssue resource_exhausted_issue() {
  return SnapshotPreparationIssue{
      "snapshot.prepare.resource_exhausted", "snapshot",
      "all-shard snapshot preparation exhausted memory"};
}

SnapshotPreparationIssue activation_internal_issue() {
  return SnapshotPreparationIssue{
      "snapshot.activate.internal", "snapshot",
      "all-shard snapshot activation failed before publication"};
}

SnapshotPreparationIssue retirement_resource_exhausted_issue() {
  return SnapshotPreparationIssue{
      "snapshot.retirement.resource_exhausted", "retired_snapshot",
      "all-shard snapshot retirement exhausted memory"};
}

SnapshotPreparationIssue cancellation_internal_issue() {
  return SnapshotPreparationIssue{
      "snapshot.cancel.internal", "snapshot",
      "all-shard snapshot cancellation failed before commit"};
}

SnapshotPreparationIssue mixed_barrier_issue(const std::string& operation) {
  return SnapshotPreparationIssue{
      "snapshot." + operation + ".shard_divergence", "rollout_sequence",
      "shards disagreed whether the operation was new or an exact replay"};
}

std::uint32_t checked_shard_count() {
  if (seastar::smp::count == 0U ||
      seastar::smp::count >
          static_cast<unsigned>(std::numeric_limits<std::uint32_t>::max())) {
    throw std::logic_error("Seastar shard count is outside the report range");
  }
  return static_cast<std::uint32_t>(seastar::smp::count);
}

seastar::future<> abort_activation_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& shards) {
  co_await shards.invoke_on_all([](SnapshotPreparationShard& shard) {
    shard.abort_armed_activation();
  });
}

seastar::future<> abort_cancel_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& shards) {
  co_await shards.invoke_on_all([](SnapshotPreparationShard& shard) {
    shard.abort_armed_cancel();
  });
}

}  // namespace

seastar::future<> discard_prepared_snapshot_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& shards,
    std::uint64_t rollout_sequence,
    SnapshotReference snapshot) {
  if (seastar::this_shard_id() != 0U) {
    throw std::logic_error(
        "all-shard prepared-snapshot discard must run on shard zero");
  }
  co_await shards.invoke_on_all(
      [rollout_sequence, snapshot](SnapshotPreparationShard& shard) {
        (void)shard.discard_prepared(rollout_sequence, snapshot);
      });
}

seastar::future<NodeSnapshotPreparationReport> prepare_snapshot_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& shards,
    SnapshotPrepareCommand command) {
  if (seastar::this_shard_id() != 0U) {
    throw std::logic_error("all-shard snapshot prepare must run on shard zero");
  }

  NodeSnapshotPreparationReport report;
  report.rollout_sequence = command.rollout_sequence;
  report.snapshot = command.snapshot;
  report.previous_active_snapshot = command.expected_active_snapshot;
  report.current_active_snapshot = command.expected_active_snapshot;
  report.shard_count = checked_shard_count();

  for (seastar::shard_id shard_id = 0U; shard_id < seastar::smp::count;
       ++shard_id) {
    ShardSnapshotPreparationResult result;
    try {
      auto shard_command = command;
      result = co_await shards.invoke_on(
          shard_id,
          [command = std::move(shard_command)](
              SnapshotPreparationShard& shard) {
            return shard.prepare(command);
          });
    } catch (const std::bad_alloc&) {
      result.issue = resource_exhausted_issue();
    } catch (const std::exception&) {
      result.issue = internal_issue();
    }
    if (!result.prepared) {
      report.failed_shard = static_cast<std::uint32_t>(shard_id);
      report.issue = result.issue.value_or(internal_issue());
      co_await discard_prepared_snapshot_on_all_shards(
          shards, command.rollout_sequence, command.snapshot);
      co_return report;
    }
    ++report.completed_shards;
  }

  report.acknowledged = true;
  co_return report;
}

seastar::future<NodeSnapshotRetirementReport>
reap_retired_snapshot_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& shards,
    SnapshotReference snapshot) {
  if (seastar::this_shard_id() != 0U) {
    throw std::logic_error(
        "all-shard snapshot retirement must run on shard zero");
  }

  NodeSnapshotRetirementReport report;
  report.snapshot = snapshot;
  report.shard_count = checked_shard_count();
  for (seastar::shard_id shard_id = 0U; shard_id < seastar::smp::count;
       ++shard_id) {
    ShardSnapshotRetirementResult result;
    try {
      result = co_await shards.invoke_on(
          shard_id, [snapshot](SnapshotPreparationShard& shard) {
            return shard.reap_retired_snapshot(snapshot);
          });
    } catch (const std::bad_alloc&) {
      result.issue = retirement_resource_exhausted_issue();
    } catch (const std::exception&) {
      result.issue = SnapshotPreparationIssue{
          "snapshot.retirement.internal", "retired_snapshot",
          "all-shard snapshot retirement failed internally"};
    }
    if (result.issue.has_value()) {
      report.failed_shard = static_cast<std::uint32_t>(shard_id);
      report.issue = std::move(result.issue);
      co_return report;
    }
    ++report.completed_shards;
    if (!result.complete) {
      ++report.pending_shards;
      report.pinned_leases += result.pinned_leases;
    }
  }
  report.complete = report.pending_shards == 0U;
  co_return report;
}

seastar::future<NodeSnapshotActivationReport> activate_snapshot_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& shards,
    SnapshotActivateCommand command) {
  if (seastar::this_shard_id() != 0U) {
    throw std::logic_error("all-shard snapshot activate must run on shard zero");
  }

  NodeSnapshotActivationReport report;
  report.rollout_sequence = command.rollout_sequence;
  report.snapshot = command.prepared_snapshot;
  report.previous_active_snapshot = command.expected_active_snapshot;
  report.current_active_snapshot = command.expected_active_snapshot;
  report.shard_count = checked_shard_count();

  std::optional<bool> replay_mode;
  for (seastar::shard_id shard_id = 0U; shard_id < seastar::smp::count;
       ++shard_id) {
    ShardSnapshotActivationResult result;
    try {
      result = co_await shards.invoke_on(
          shard_id, [command](SnapshotPreparationShard& shard) {
            return shard.arm_activation(command);
          });
    } catch (const std::exception&) {
      result.issue = activation_internal_issue();
    }
    if (!result.accepted) {
      report.failed_shard = static_cast<std::uint32_t>(shard_id);
      report.issue = result.issue.value_or(activation_internal_issue());
      co_await abort_activation_on_all_shards(shards);
      co_return report;
    }
    if (!replay_mode.has_value()) {
      replay_mode = result.replayed;
    } else if (*replay_mode != result.replayed) {
      report.failed_shard = static_cast<std::uint32_t>(shard_id);
      report.issue = mixed_barrier_issue("activate");
      co_await abort_activation_on_all_shards(shards);
      co_return report;
    }
  }

  if (replay_mode.value_or(false)) {
    report.acknowledged = true;
    report.replayed = true;
    report.completed_shards = report.shard_count;
    report.current_active_snapshot = command.prepared_snapshot;
    co_return report;
  }

  for (seastar::shard_id shard_id = 0U; shard_id < seastar::smp::count;
       ++shard_id) {
    const auto committed = co_await shards.invoke_on(
        shard_id, [](SnapshotPreparationShard& shard) {
          return shard.commit_armed_activation();
        });
    if (!committed) {
      throw std::logic_error(
          "armed snapshot activation violated its no-fail commit invariant");
    }
    ++report.completed_shards;
  }
  co_await shards.invoke_on_all([](SnapshotPreparationShard& shard) {
    shard.reopen_admission();
  });
  report.current_active_snapshot = command.prepared_snapshot;

  auto retirement = co_await reap_retired_snapshot_on_all_shards(
      shards, command.expected_active_snapshot);
  if (retirement.issue.has_value()) {
    throw std::logic_error(
        "activated snapshot retained a conflicting old generation");
  }
  report.retirement_pending_shards = retirement.pending_shards;
  report.pinned_retired_leases = retirement.pinned_leases;
  report.acknowledged = true;
  co_return report;
}

seastar::future<NodeSnapshotCancellationReport> cancel_snapshot_on_all_shards(
    seastar::sharded<SnapshotPreparationShard>& shards,
    SnapshotCancelCommand command) {
  if (seastar::this_shard_id() != 0U) {
    throw std::logic_error("all-shard snapshot cancel must run on shard zero");
  }

  NodeSnapshotCancellationReport report;
  report.rollout_sequence = command.rollout_sequence;
  report.snapshot = command.snapshot;
  report.shard_count = checked_shard_count();

  std::optional<bool> replay_mode;
  std::optional<SnapshotReference> observed_active;
  for (seastar::shard_id shard_id = 0U; shard_id < seastar::smp::count;
       ++shard_id) {
    ShardSnapshotCancellationResult result;
    try {
      result = co_await shards.invoke_on(
          shard_id, [command](SnapshotPreparationShard& shard) {
            return shard.arm_cancel(command);
          });
    } catch (const std::exception&) {
      result.issue = cancellation_internal_issue();
    }
    if (!result.accepted) {
      report.failed_shard = static_cast<std::uint32_t>(shard_id);
      report.issue = result.issue.value_or(cancellation_internal_issue());
      co_await abort_cancel_on_all_shards(shards);
      co_return report;
    }
    if (!observed_active.has_value()) {
      observed_active = result.active_snapshot;
      report.current_active_snapshot = result.active_snapshot;
    } else if (*observed_active != result.active_snapshot) {
      report.failed_shard = static_cast<std::uint32_t>(shard_id);
      report.issue = SnapshotPreparationIssue{
          "snapshot.cancel.active_divergence", "active_snapshot",
          "shards disagreed about the active snapshot during cancellation"};
      co_await abort_cancel_on_all_shards(shards);
      co_return report;
    }
    if (!replay_mode.has_value()) {
      replay_mode = result.replayed;
    } else if (*replay_mode != result.replayed) {
      report.failed_shard = static_cast<std::uint32_t>(shard_id);
      report.issue = mixed_barrier_issue("cancel");
      co_await abort_cancel_on_all_shards(shards);
      co_return report;
    }
  }

  if (replay_mode.value_or(false)) {
    report.acknowledged = true;
    report.replayed = true;
    report.completed_shards = report.shard_count;
    co_return report;
  }

  for (seastar::shard_id shard_id = 0U; shard_id < seastar::smp::count;
       ++shard_id) {
    const auto committed = co_await shards.invoke_on(
        shard_id, [](SnapshotPreparationShard& shard) {
          return shard.commit_armed_cancel();
        });
    if (!committed) {
      throw std::logic_error(
          "armed snapshot cancellation violated its no-fail commit invariant");
    }
    ++report.completed_shards;
  }
  report.acknowledged = true;
  co_return report;
}

}  // namespace bonvoyage::runtime
