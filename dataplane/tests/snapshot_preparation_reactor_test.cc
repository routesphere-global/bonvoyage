#include "bonvoyage/runtime/snapshot_preparation_coordinator.hh"

#include <exception>
#include <iostream>
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

using bonvoyage::runtime::SnapshotPrepareCommand;
using bonvoyage::runtime::SnapshotPreparationShard;
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

SnapshotPrepareCommand command(std::uint64_t sequence,
                               const bonvoyage::v1::Snapshot& target,
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

seastar::future<> require_state_on_all(
    seastar::sharded<SnapshotPreparationShard>& shards,
    const SnapshotReference& active,
    const std::optional<SnapshotReference>& prepared) {
  co_await shards.invoke_on_all(
      [active, prepared](SnapshotPreparationShard& shard) {
        const auto state = shard.state();
        require(state.active_snapshot == active,
                "PREPARE changed an active shard identity");
        require(state.prepared_snapshot.has_value() == prepared.has_value(),
                "shards disagree about private prepared state");
        if (prepared.has_value()) {
          require(state.prepared_snapshot->snapshot == *prepared,
                  "shard retained the wrong private snapshot identity");
        }
      });
}

seastar::future<> run() {
  require(seastar::smp::count == 2U,
          "all-shard preparation test requires exactly two shards");
  const auto active_bytes = deterministic_bytes(snapshot("active", 1U));
  const auto active = reference("active", active_bytes);
  const auto target = snapshot("target", 2U);

  seastar::sharded<SnapshotPreparationShard> shards;
  co_await shards.start();
  std::exception_ptr failure;
  try {
    co_await shards.invoke_on_all(
        [active](SnapshotPreparationShard& shard) { shard.initialize(active); });

    auto first_command = command(1U, target, active);
    const auto first = co_await bonvoyage::runtime::prepare_snapshot_on_all_shards(
        shards, first_command);
    require(first.acknowledged && first.shard_count == 2U &&
                first.completed_shards == 2U && !first.failed_shard.has_value(),
            "all-shard success did not cross the complete PREPARE barrier");
    co_await require_state_on_all(shards, active, first_command.snapshot);

    co_await bonvoyage::runtime::discard_prepared_snapshot_on_all_shards(
        shards, 1U, first_command.snapshot);
    co_await require_state_on_all(shards, active, std::nullopt);

    auto limited = bonvoyage::runtime::default_snapshot_capabilities();
    limited.pop_back();
    co_await shards.invoke_on(
        1U, [capabilities = std::move(limited)](
                SnapshotPreparationShard& shard) mutable {
          shard.configure_supported_capabilities(std::move(capabilities));
        });

    auto rejected_command = command(2U, target, active);
    const auto rejected =
        co_await bonvoyage::runtime::prepare_snapshot_on_all_shards(
            shards, rejected_command);
    require(!rejected.acknowledged && rejected.shard_count == 2U &&
                rejected.completed_shards == 1U &&
                rejected.failed_shard == 1U && rejected.issue.has_value() &&
                rejected.issue->code == "snapshot.capability.unsupported",
            "partial-shard failure did not produce the expected node NACK");
    co_await require_state_on_all(shards, active, std::nullopt);

    co_await shards.invoke_on(
        1U, [](SnapshotPreparationShard& shard) {
          shard.configure_supported_capabilities(
              bonvoyage::runtime::default_snapshot_capabilities());
        });
    auto recovered_command = command(3U, target, active);
    const auto recovered =
        co_await bonvoyage::runtime::prepare_snapshot_on_all_shards(
            shards, recovered_command);
    require(recovered.acknowledged && recovered.completed_shards == 2U,
            "all-shard PREPARE did not recover under a newer sequence");
    co_await require_state_on_all(shards, active, recovered_command.snapshot);
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
