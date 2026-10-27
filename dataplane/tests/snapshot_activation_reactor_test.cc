#include "bonvoyage/runtime/snapshot_preparation_coordinator.hh"

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

using bonvoyage::runtime::SnapshotActivateCommand;
using bonvoyage::runtime::SnapshotCancelCommand;
using bonvoyage::runtime::SnapshotPrepareCommand;
using bonvoyage::runtime::SnapshotPreparationShard;
using bonvoyage::runtime::SnapshotReadLease;
using bonvoyage::runtime::SnapshotReference;

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
  {
    google::protobuf::io::StringOutputStream stream(&result);
    google::protobuf::io::CodedOutputStream output(&stream);
    output.SetSerializationDeterministic(true);
    require(snapshot.SerializeToCodedStream(&output),
            "fixture snapshot serialization failed");
    output.Trim();
  }
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

seastar::future<> require_active_on_all(
    seastar::sharded<SnapshotPreparationShard>& shards,
    const SnapshotReference& active, bool expect_prepared) {
  co_await shards.invoke_on_all(
      [active, expect_prepared](SnapshotPreparationShard& shard) {
        const auto state = shard.state();
        require(state.active_snapshot == active,
                "shards disagree about active snapshot identity");
        require(state.admission_open && !state.activation_in_progress,
                "activation barrier did not reopen request admission");
        require(state.prepared_snapshot.has_value() == expect_prepared,
                "shards disagree about private prepared state");
      });
}

seastar::future<> run() {
  require(seastar::smp::count == 2U,
          "all-shard activation test requires exactly two shards");
  const auto active_bytes = deterministic_bytes(snapshot("active", 1U));
  const auto active = reference("active", active_bytes);
  const auto target = snapshot("target", 2U);

  seastar::sharded<SnapshotPreparationShard> shards;
  co_await shards.start();
  std::exception_ptr failure;
  try {
    co_await shards.invoke_on_all(
        [active](SnapshotPreparationShard& shard) { shard.initialize(active); });

    auto first_prepare = prepare_command(1U, target, active);
    const auto prepared =
        co_await bonvoyage::runtime::prepare_snapshot_on_all_shards(
            shards, first_prepare);
    require(prepared.acknowledged && prepared.completed_shards == 2U,
            "activation fixture did not prepare on every shard");
    const SnapshotActivateCommand first_activate{
        1U, first_prepare.snapshot, active};
    const auto activated =
        co_await bonvoyage::runtime::activate_snapshot_on_all_shards(
            shards, first_activate);
    require(activated.acknowledged && !activated.replayed &&
                activated.completed_shards == 2U &&
                activated.current_active_snapshot == first_prepare.snapshot &&
                activated.retirement_pending_shards == 0U,
            "two-shard activation did not converge and retire cleanly");
    co_await require_active_on_all(shards, first_prepare.snapshot, false);

    const auto replay =
        co_await bonvoyage::runtime::activate_snapshot_on_all_shards(
            shards, first_activate);
    require(replay.acknowledged && replay.replayed &&
                replay.completed_shards == 2U,
            "all-shard activation replay was not idempotent");
    const auto late_cancel =
        co_await bonvoyage::runtime::cancel_snapshot_on_all_shards(
            shards,
            SnapshotCancelCommand{1U, first_prepare.snapshot, "too late"});
    require(!late_cancel.acknowledged && late_cancel.issue.has_value() &&
                late_cancel.issue->code ==
                    "snapshot.cancel.activation_started",
            "cancellation was accepted after activation completed");

    const auto second_target = snapshot("second", 3U);
    auto second_prepare =
        prepare_command(2U, second_target, first_prepare.snapshot);
    require((co_await bonvoyage::runtime::prepare_snapshot_on_all_shards(
                 shards, second_prepare))
                .acknowledged,
            "partial-activation fixture did not prepare");
    co_await shards.invoke_on(
        1U, [sequence = second_prepare.rollout_sequence,
             snapshot = second_prepare.snapshot](
                SnapshotPreparationShard& shard) {
          require(shard.discard_prepared(sequence, snapshot),
                  "failed to create one-shard preparation loss");
        });
    const auto rejected =
        co_await bonvoyage::runtime::activate_snapshot_on_all_shards(
            shards,
            SnapshotActivateCommand{2U, second_prepare.snapshot,
                                    first_prepare.snapshot});
    require(!rejected.acknowledged && rejected.failed_shard == 1U &&
                rejected.issue.has_value() &&
                rejected.issue->code == "snapshot.activate.not_prepared",
            "partial preparation did not produce an activation NACK");
    co_await shards.invoke_on_all(
        [active = first_prepare.snapshot](SnapshotPreparationShard& shard) {
          const auto state = shard.state();
          require(state.active_snapshot == active && state.admission_open &&
                      !state.activation_in_progress,
                  "failed activation changed traffic or left admission fenced");
        });
    co_await shards.invoke_on(
        0U, [sequence = second_prepare.rollout_sequence,
             snapshot = second_prepare.snapshot](
                SnapshotPreparationShard& shard) {
          require(shard.discard_prepared(sequence, snapshot),
                  "failed to clear partial activation fixture");
        });

    const auto cancel_target = snapshot("cancel-target", 4U);
    auto cancel_prepare =
        prepare_command(3U, cancel_target, first_prepare.snapshot);
    require((co_await bonvoyage::runtime::prepare_snapshot_on_all_shards(
                 shards, cancel_prepare))
                .acknowledged,
            "cancellation fixture did not prepare");
    const SnapshotCancelCommand cancel{
        3U, cancel_prepare.snapshot, "operator request"};
    const auto cancelled =
        co_await bonvoyage::runtime::cancel_snapshot_on_all_shards(
            shards, cancel);
    require(cancelled.acknowledged && !cancelled.replayed &&
                cancelled.completed_shards == 2U &&
                cancelled.current_active_snapshot == first_prepare.snapshot,
            "two-shard cancellation did not retain active state");
    const auto cancel_replay =
        co_await bonvoyage::runtime::cancel_snapshot_on_all_shards(
            shards, cancel);
    require(cancel_replay.acknowledged && cancel_replay.replayed,
            "all-shard cancellation replay was not idempotent");
    co_await require_active_on_all(shards, first_prepare.snapshot, false);

    std::optional<SnapshotReadLease> pinned_old;
    co_await shards.invoke_on(
        0U, [&pinned_old](SnapshotPreparationShard& shard) {
          pinned_old = shard.acquire_active_snapshot();
          require(pinned_old.has_value(),
                  "failed to pin old generation on shard zero");
        });
    const auto leased_target = snapshot("leased-target", 5U);
    auto leased_prepare =
        prepare_command(4U, leased_target, first_prepare.snapshot);
    require((co_await bonvoyage::runtime::prepare_snapshot_on_all_shards(
                 shards, leased_prepare))
                .acknowledged,
            "leased-retirement fixture did not prepare");
    const auto leased_activation =
        co_await bonvoyage::runtime::activate_snapshot_on_all_shards(
            shards,
            SnapshotActivateCommand{4U, leased_prepare.snapshot,
                                    first_prepare.snapshot});
    require(leased_activation.acknowledged &&
                leased_activation.retirement_pending_shards == 1U &&
                leased_activation.pinned_retired_leases == 1U,
            "activation did not report the pinned retired shard");
    co_await require_active_on_all(shards, leased_prepare.snapshot, false);

    const auto blocked_target = snapshot("blocked-target", 6U);
    auto blocked_prepare =
        prepare_command(5U, blocked_target, leased_prepare.snapshot);
    require((co_await bonvoyage::runtime::prepare_snapshot_on_all_shards(
                 shards, blocked_prepare))
                .acknowledged,
            "blocked-retirement fixture did not prepare");
    const auto blocked_activation =
        co_await bonvoyage::runtime::activate_snapshot_on_all_shards(
            shards,
            SnapshotActivateCommand{5U, blocked_prepare.snapshot,
                                    leased_prepare.snapshot});
    require(!blocked_activation.acknowledged &&
                blocked_activation.failed_shard == 0U &&
                blocked_activation.issue.has_value() &&
                blocked_activation.issue->code ==
                    "snapshot.retirement.pending",
            "second activation accumulated another retired generation");
    co_await require_active_on_all(shards, leased_prepare.snapshot, true);

    pinned_old.reset();
    const auto retirement =
        co_await bonvoyage::runtime::reap_retired_snapshot_on_all_shards(
            shards, first_prepare.snapshot);
    require(retirement.complete && retirement.completed_shards == 2U &&
                retirement.pending_shards == 0U,
            "released generation did not retire across all shards");
    const auto recovered =
        co_await bonvoyage::runtime::activate_snapshot_on_all_shards(
            shards,
            SnapshotActivateCommand{5U, blocked_prepare.snapshot,
                                    leased_prepare.snapshot});
    require(recovered.acknowledged && recovered.completed_shards == 2U,
            "activation did not recover after safe retirement");
    co_await require_active_on_all(shards, blocked_prepare.snapshot, false);
  } catch (...) {
    failure = std::current_exception();
  }
  co_await shards.stop();
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
