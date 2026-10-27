#include "bonvoyage/runtime/live_snapshot_coordinator.hh"

#include <cstdint>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/reactor.hh>

#include "bonvoyage/v1/config.pb.h"

namespace {

using bonvoyage::runtime::ShardSnapshotActivationResult;
using bonvoyage::runtime::ShardSnapshotCancellationResult;
using bonvoyage::runtime::ShardSnapshotPreparationResult;
using bonvoyage::runtime::ShardSnapshotRetirementResult;
using bonvoyage::runtime::SnapshotActivateCommand;
using bonvoyage::runtime::SnapshotCancelCommand;
using bonvoyage::runtime::SnapshotPrepareCommand;
using bonvoyage::runtime::SnapshotPreparationIssue;
using bonvoyage::runtime::SnapshotPreparationShard;
using bonvoyage::runtime::SnapshotReadLease;
using bonvoyage::runtime::SnapshotReference;
using bonvoyage::runtime::detail::LiveSnapshotCoordinatorOperations;

void require(bool condition, std::string_view message) {
  if (!condition) {
    throw std::runtime_error(std::string(message));
  }
}

bonvoyage::v1::Snapshot snapshot(std::string id, std::uint64_t generation) {
  bonvoyage::v1::Snapshot value;
  value.set_snapshot_id(std::move(id));
  value.set_generation(generation);
  value.set_minimum_dataplane_version("0.2.0");
  value.set_schema_version(1U);

  auto* host = value.add_virtual_hosts();
  host->set_name("default");
  host->add_domains("*");
  auto* route = host->add_routes();
  route->set_name("ready");
  route->mutable_match()->set_path_prefix("/");
  route->mutable_fixed_response()->set_status_code(200U);

  // The lifecycle validates the real schema; the fake live layer binds no
  // socket, so this fixture exercises coordination without network resources.
  auto* listener = value.add_listeners();
  listener->set_name("http");
  listener->set_address("127.0.0.1");
  listener->set_port(8080U);
  listener->set_protocol(bonvoyage::v1::PROTOCOL_HTTP1);
  listener->add_virtual_host_names("default");
  return value;
}

std::string deterministic_bytes(const bonvoyage::v1::Snapshot& snapshot) {
  std::string result;
  google::protobuf::io::StringOutputStream stream(&result);
  google::protobuf::io::CodedOutputStream output(&stream);
  output.SetSerializationDeterministic(true);
  require(snapshot.SerializeToCodedStream(&output),
          "fixture snapshot serialization failed");
  output.Trim();
  return result;
}

SnapshotReference reference(std::string id, std::string_view bytes) {
  return SnapshotReference{
      std::move(id), bonvoyage::runtime::snapshot_sha256(bytes)};
}

SnapshotPrepareCommand prepare_command(
    std::uint64_t sequence, const bonvoyage::v1::Snapshot& target,
    const SnapshotReference& active) {
  auto bytes = deterministic_bytes(target);
  return SnapshotPrepareCommand{
      sequence,
      reference(target.snapshot_id(), bytes),
      std::move(bytes),
      target.schema_version(),
      target.minimum_dataplane_version(),
      bonvoyage::runtime::default_snapshot_capabilities(),
      active,
  };
}

class FakeLiveShard final {
 public:
  void initialize(SnapshotReference active) {
    active_ = std::move(active);
    active_maintenance_ = seastar::this_shard_id() == 0U;
  }

  void reject_preparation(bool reject) noexcept { reject_preparation_ = reject; }

  seastar::future<ShardSnapshotPreparationResult> prepare(
      SnapshotPrepareCommand command) {
    ShardSnapshotPreparationResult result;
    result.active_snapshot = active_;
    if (reject_preparation_) {
      result.issue = SnapshotPreparationIssue{
          "snapshot.prepare.fake_rejection", "snapshot",
          "test live resource preparation was rejected"};
      co_return result;
    }
    if (command.expected_active_snapshot != active_) {
      result.issue = SnapshotPreparationIssue{
          "snapshot.active_mismatch", "expected_active_snapshot",
          "test live active identity did not match"};
      co_return result;
    }
    if (prepared_.has_value()) {
      if (prepared_->sequence == command.rollout_sequence &&
          prepared_->snapshot == command.snapshot) {
        result.prepared = true;
        result.replayed = true;
      } else {
        result.issue = SnapshotPreparationIssue{
            "snapshot.prepare.conflict", "rollout_sequence",
            "another test live generation remains prepared"};
      }
      co_return result;
    }
    prepared_ = Prepared{command.rollout_sequence, command.snapshot};
    result.prepared = true;
    co_return result;
  }

  seastar::future<> start_prepared_maintenance(SnapshotReference snapshot) {
    require(seastar::this_shard_id() == 0U,
            "prepared maintenance did not run on shard zero");
    require(prepared_.has_value() && prepared_->snapshot == snapshot,
            "prepared maintenance targeted the wrong snapshot");
    prepared_maintenance_ = true;
    co_return;
  }

  seastar::future<> stop_active_maintenance() {
    require(seastar::this_shard_id() == 0U,
            "active maintenance did not stop on shard zero");
    active_maintenance_ = false;
    co_return;
  }

  ShardSnapshotActivationResult arm_activation(
      const SnapshotActivateCommand& command) {
    ShardSnapshotActivationResult result;
    result.active_snapshot = active_;
    if (last_activation_.has_value() &&
        last_activation_->sequence == command.rollout_sequence) {
      if (last_activation_->snapshot == command.prepared_snapshot &&
          last_activation_->expected_active ==
              command.expected_active_snapshot &&
          active_ == command.prepared_snapshot) {
        result.accepted = true;
        result.replayed = true;
      } else {
        result.issue = conflict_issue();
      }
      return result;
    }
    if (retired_.has_value()) {
      result.issue = SnapshotPreparationIssue{
          "snapshot.retirement.pending", "retired_snapshot",
          "test live retired resources remain"};
      return result;
    }
    if (!prepared_.has_value() ||
        prepared_->sequence != command.rollout_sequence ||
        prepared_->snapshot != command.prepared_snapshot ||
        active_ != command.expected_active_snapshot) {
      result.issue = SnapshotPreparationIssue{
          "snapshot.activate.not_prepared", "prepared_snapshot",
          "exact test live generation is not prepared"};
      return result;
    }
    activation_intent_ = Activation{
        command.rollout_sequence, command.prepared_snapshot,
        command.expected_active_snapshot};
    result.accepted = true;
    return result;
  }

  void abort_activation() noexcept { activation_intent_.reset(); }

  bool commit_activation() noexcept {
    if (!activation_intent_.has_value() || !prepared_.has_value() ||
        retired_.has_value() ||
        activation_intent_->sequence != prepared_->sequence ||
        activation_intent_->snapshot != prepared_->snapshot ||
        activation_intent_->expected_active != active_ ||
        (seastar::this_shard_id() == 0U && active_maintenance_)) {
      return false;
    }
    retired_ = active_;
    active_ = prepared_->snapshot;
    last_activation_ = activation_intent_;
    activation_intent_.reset();
    prepared_.reset();
    active_maintenance_ = prepared_maintenance_;
    prepared_maintenance_ = false;
    return true;
  }

  ShardSnapshotCancellationResult arm_cancel(
      const SnapshotCancelCommand& command) {
    ShardSnapshotCancellationResult result;
    result.active_snapshot = active_;
    if (last_cancel_.has_value() &&
        last_cancel_->sequence == command.rollout_sequence) {
      if (last_cancel_->snapshot == command.snapshot &&
          last_cancel_->reason == command.reason) {
        result.accepted = true;
        result.replayed = true;
      } else {
        result.issue = conflict_issue();
      }
      return result;
    }
    if (!prepared_.has_value() ||
        prepared_->sequence != command.rollout_sequence ||
        prepared_->snapshot != command.snapshot) {
      result.issue = SnapshotPreparationIssue{
          "snapshot.cancel.not_prepared", "snapshot",
          "exact test live generation is not prepared"};
      return result;
    }
    cancel_intent_ =
        Cancellation{command.rollout_sequence, command.snapshot,
                     command.reason};
    result.accepted = true;
    return result;
  }

  void abort_cancel() noexcept { cancel_intent_.reset(); }

  seastar::future<bool> commit_cancel() {
    if (!cancel_intent_.has_value() || !prepared_.has_value() ||
        cancel_intent_->sequence != prepared_->sequence ||
        cancel_intent_->snapshot != prepared_->snapshot) {
      co_return false;
    }
    prepared_.reset();
    prepared_maintenance_ = false;
    last_cancel_ = cancel_intent_;
    cancel_intent_.reset();
    co_return true;
  }

  seastar::future<> discard(std::uint64_t sequence,
                            SnapshotReference snapshot) {
    if (prepared_.has_value() && prepared_->sequence == sequence &&
        prepared_->snapshot == snapshot && !activation_intent_.has_value() &&
        !cancel_intent_.has_value()) {
      prepared_.reset();
      prepared_maintenance_ = false;
    }
    co_return;
  }

  seastar::future<ShardSnapshotRetirementResult> reap(
      SnapshotReference snapshot, bool lifecycle_unpinned) {
    ShardSnapshotRetirementResult result;
    if (!retired_.has_value()) {
      result.complete = true;
      co_return result;
    }
    if (*retired_ != snapshot) {
      result.issue = SnapshotPreparationIssue{
          "snapshot.retirement.identity_mismatch", "retired_snapshot",
          "test live layer retained a different generation"};
      co_return result;
    }
    if (!lifecycle_unpinned) {
      result.pinned_leases = 1U;
      co_return result;
    }
    retired_.reset();
    result.complete = true;
    co_return result;
  }

  [[nodiscard]] const SnapshotReference& active() const noexcept {
    return active_;
  }
  [[nodiscard]] bool prepared() const noexcept {
    return prepared_.has_value();
  }
  [[nodiscard]] bool retired() const noexcept {
    return retired_.has_value();
  }
  [[nodiscard]] bool active_maintenance() const noexcept {
    return active_maintenance_;
  }

 private:
  struct Prepared final {
    std::uint64_t sequence{};
    SnapshotReference snapshot;
  };
  struct Activation final {
    std::uint64_t sequence{};
    SnapshotReference snapshot;
    SnapshotReference expected_active;
  };
  struct Cancellation final {
    std::uint64_t sequence{};
    SnapshotReference snapshot;
    std::string reason;
  };

  static SnapshotPreparationIssue conflict_issue() {
    return SnapshotPreparationIssue{
        "rollout.sequence.conflict", "rollout_sequence",
        "test rollout sequence was reused with different metadata"};
  }

  SnapshotReference active_;
  std::optional<Prepared> prepared_;
  std::optional<SnapshotReference> retired_;
  std::optional<Activation> activation_intent_;
  std::optional<Activation> last_activation_;
  std::optional<Cancellation> cancel_intent_;
  std::optional<Cancellation> last_cancel_;
  bool reject_preparation_{false};
  bool active_maintenance_{false};
  bool prepared_maintenance_{false};
};

LiveSnapshotCoordinatorOperations operations(
    seastar::sharded<FakeLiveShard>& live) {
  LiveSnapshotCoordinatorOperations value;
  value.prepare_live_snapshot = [&live](SnapshotPrepareCommand command) {
    return live.local().prepare(std::move(command));
  };
  value.start_prepared_maintenance = [&live](SnapshotReference snapshot) {
    return live.local().start_prepared_maintenance(std::move(snapshot));
  };
  value.stop_active_maintenance = [&live] {
    return live.local().stop_active_maintenance();
  };
  value.arm_live_activation = [&live](
                                     const SnapshotActivateCommand& command) {
    return live.local().arm_activation(command);
  };
  value.abort_live_activation = [&live] {
    live.local().abort_activation();
  };
  value.commit_live_activation = [&live] {
    return live.local().commit_activation();
  };
  value.arm_live_cancel = [&live](const SnapshotCancelCommand& command) {
    return live.local().arm_cancel(command);
  };
  value.abort_live_cancel = [&live] { live.local().abort_cancel(); };
  value.commit_live_cancel = [&live] {
    return live.local().commit_cancel();
  };
  value.discard_live_prepared =
      [&live](std::uint64_t sequence, SnapshotReference snapshot) {
        return live.local().discard(sequence, std::move(snapshot));
      };
  value.reap_live_retired =
      [&live](SnapshotReference snapshot, bool lifecycle_unpinned) {
        return live.local().reap(std::move(snapshot), lifecycle_unpinned);
      };
  return value;
}

seastar::future<> require_converged(
    seastar::sharded<SnapshotPreparationShard>& lifecycle,
    seastar::sharded<FakeLiveShard>& live,
    const SnapshotReference& expected_active, bool expect_prepared,
    std::optional<seastar::shard_id> retired_shard) {
  co_await lifecycle.invoke_on_all(
      [&live, expected_active, expect_prepared,
       retired_shard](SnapshotPreparationShard& shard) {
        const auto state = shard.state();
        const auto& local_live = live.local();
        const bool expect_retired =
            retired_shard.has_value() &&
            *retired_shard == seastar::this_shard_id();
        require(state.active_snapshot == expected_active,
                "lifecycle shards have mixed active identities");
        require(local_live.active() == expected_active,
                "live and lifecycle active identities diverged");
        require(state.prepared_snapshot.has_value() == expect_prepared &&
                    local_live.prepared() == expect_prepared,
                "private lifecycle and live preparation layers diverged");
        require(state.retired_snapshot.has_value() == expect_retired &&
                    local_live.retired() == expect_retired,
                "retired lifecycle and live resource layers diverged");
      });
}

seastar::future<> run() {
  require(seastar::smp::count == 2U,
          "live snapshot coordinator test requires exactly two shards");
  const auto active_bytes = deterministic_bytes(snapshot("active", 1U));
  const auto active = reference("active", active_bytes);
  const auto target = snapshot("target", 2U);

  seastar::sharded<SnapshotPreparationShard> lifecycle;
  seastar::sharded<FakeLiveShard> live;
  co_await lifecycle.start();
  co_await live.start();
  std::exception_ptr failure;
  try {
    co_await lifecycle.invoke_on_all(
        [&live, active](SnapshotPreparationShard& shard) {
          shard.initialize(active);
          live.local().initialize(active);
        });

    co_await live.invoke_on(1U, [](FakeLiveShard& shard) {
      shard.reject_preparation(true);
    });
    auto rejected_prepare = prepare_command(1U, target, active);
    const auto rejected = co_await bonvoyage::runtime::detail::
        prepare_live_snapshot_on_all_shards_with_operations(
            lifecycle, operations(live), rejected_prepare);
    require(!rejected.acknowledged && rejected.failed_shard == 1U &&
                rejected.completed_shards == 1U &&
                rejected.issue.has_value() &&
                rejected.issue->code == "snapshot.prepare.fake_rejection",
            "live preparation failure did not produce a bounded node NACK");
    co_await require_converged(lifecycle, live, active, false, std::nullopt);

    co_await live.invoke_on(1U, [](FakeLiveShard& shard) {
      shard.reject_preparation(false);
    });
    auto prepared_command = prepare_command(2U, target, active);
    const auto prepared = co_await bonvoyage::runtime::detail::
        prepare_live_snapshot_on_all_shards_with_operations(
            lifecycle, operations(live), prepared_command);
    require(prepared.acknowledged && prepared.completed_shards == 2U,
            "live preparation did not cross both private layers");
    co_await require_converged(lifecycle, live, active, true, std::nullopt);

    std::optional<SnapshotReadLease> pinned_old;
    co_await lifecycle.invoke_on(
        0U, [&pinned_old](SnapshotPreparationShard& shard) {
          pinned_old = shard.acquire_active_snapshot();
          require(pinned_old.has_value(),
                  "old active generation could not be pinned");
        });

    const SnapshotActivateCommand activate{
        2U, prepared_command.snapshot, active};
    const auto activated = co_await bonvoyage::runtime::detail::
        activate_live_snapshot_on_all_shards_with_operations(
            lifecycle, operations(live), activate);
    require(activated.acknowledged && !activated.replayed &&
                activated.completed_shards == 2U &&
                activated.retirement_pending_shards == 1U &&
                activated.pinned_retired_leases == 1U,
            "atomic live activation did not report its pinned retirement");
    co_await require_converged(lifecycle, live, prepared_command.snapshot,
                               false, seastar::shard_id{0U});
    require(live.local().active_maintenance(),
            "prepared maintenance did not become active on shard zero");

    const auto replay = co_await bonvoyage::runtime::detail::
        activate_live_snapshot_on_all_shards_with_operations(
            lifecycle, operations(live), activate);
    require(replay.acknowledged && replay.replayed &&
                replay.completed_shards == 2U &&
                replay.retirement_pending_shards == 1U &&
                replay.pinned_retired_leases == 1U,
            "exact live activation replay was not idempotent");
    co_await require_converged(lifecycle, live, prepared_command.snapshot,
                               false, seastar::shard_id{0U});

    co_await lifecycle.invoke_on(0U, [&pinned_old](SnapshotPreparationShard&) {
      pinned_old.reset();
    });
    const auto retired = co_await bonvoyage::runtime::detail::
        reap_live_retired_snapshot_on_all_shards_with_operations(
            lifecycle, operations(live), active);
    require(retired.complete && retired.completed_shards == 2U &&
                retired.pending_shards == 0U && retired.pinned_leases == 0U,
            "released lifecycle lease did not release live resources");
    co_await require_converged(lifecycle, live, prepared_command.snapshot,
                               false, std::nullopt);

    const auto cancel_target = snapshot("cancel-target", 3U);
    auto cancel_prepare =
        prepare_command(3U, cancel_target, prepared_command.snapshot);
    require((co_await bonvoyage::runtime::detail::
                 prepare_live_snapshot_on_all_shards_with_operations(
                     lifecycle, operations(live), cancel_prepare))
                .acknowledged,
            "cancellation fixture did not prepare both private layers");
    const SnapshotCancelCommand cancel{
        3U, cancel_prepare.snapshot, "operator request"};
    const auto cancelled = co_await bonvoyage::runtime::detail::
        cancel_live_snapshot_on_all_shards_with_operations(
            lifecycle, operations(live), cancel);
    require(cancelled.acknowledged && !cancelled.replayed &&
                cancelled.completed_shards == 2U &&
                cancelled.current_active_snapshot == prepared_command.snapshot,
            "live cancellation changed active traffic or missed a shard");
    const auto cancel_replay = co_await bonvoyage::runtime::detail::
        cancel_live_snapshot_on_all_shards_with_operations(
            lifecycle, operations(live), cancel);
    require(cancel_replay.acknowledged && cancel_replay.replayed,
            "exact live cancellation replay was not idempotent");
    co_await require_converged(lifecycle, live, prepared_command.snapshot,
                               false, std::nullopt);
  } catch (...) {
    failure = std::current_exception();
  }
  co_await live.stop();
  co_await lifecycle.stop();
  if (failure != nullptr) {
    std::rethrow_exception(failure);
  }
}

}  // namespace

int main(int argc, char** argv) {
  try {
    seastar::app_template app;
    return app.run(argc, argv, &run);
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
