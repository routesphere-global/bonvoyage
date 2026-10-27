#include "bonvoyage/runtime/snapshot_preparation.hh"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/unknown_field_set.h>

#include "bonvoyage/v1/config.pb.h"

namespace {

using bonvoyage::runtime::SnapshotPrepareCommand;
using bonvoyage::runtime::SnapshotPreparationShard;
using bonvoyage::runtime::SnapshotReference;
using bonvoyage::runtime::kMaximumSnapshotArtifactBytes;

unsigned assertions{};

void require(bool condition, std::string_view message) {
  ++assertions;
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

  auto* cluster = value.add_clusters();
  cluster->set_name("api");
  cluster->set_load_balancing_policy(
      bonvoyage::v1::LOAD_BALANCING_POLICY_ROUND_ROBIN);
  auto* endpoint = cluster->add_endpoints();
  endpoint->set_name("api-1");
  endpoint->set_address("127.0.0.1");
  endpoint->set_port(8081U);
  endpoint->set_weight(1U);

  auto* host = value.add_virtual_hosts();
  host->set_name("default");
  host->add_domains("*");
  auto* route = host->add_routes();
  route->set_name("default");
  route->mutable_match()->set_path_prefix("/");
  route->set_cluster_name("api");

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

void require_issue(const SnapshotPrepareCommand& input,
                   SnapshotPreparationShard& shard,
                   std::string_view expected_code) {
  const auto result = shard.prepare(input);
  require(!result.prepared, "invalid preparation unexpectedly succeeded");
  require(result.issue.has_value(), "invalid preparation omitted its issue");
  require(result.issue->code == expected_code,
          "invalid preparation returned the wrong issue code");
}

void test_prepare_replay_discard_and_stale_sequence() {
  const auto active_bytes = deterministic_bytes(snapshot("active", 1U));
  const auto active = reference("active", active_bytes);
  const auto target = snapshot("target", 2U);
  auto prepare = command(2U, target, active);

  SnapshotPreparationShard shard;
  shard.initialize(active);
  const auto first = shard.prepare(prepare);
  require(first.prepared && !first.replayed,
          "first valid preparation did not complete");
  require(first.active_snapshot == active,
          "preparation changed the active snapshot identity");
  auto state = shard.state();
  require(state.active_snapshot == active && state.prepared_snapshot.has_value(),
          "prepared state was not retained privately");
  require(state.prepared_snapshot->rollout_sequence == 2U &&
              state.prepared_snapshot->snapshot == prepare.snapshot,
          "prepared state retained the wrong command identity");

  const auto replay = shard.prepare(prepare);
  require(replay.prepared && replay.replayed,
          "exact PREPARE replay was not idempotent");

  const auto other_target = snapshot("other-target", 3U);
  const auto conflict = command(2U, other_target, active);
  require_issue(conflict, shard, "rollout.sequence.conflict");

  const auto newer = command(3U, other_target, active);
  require_issue(newer, shard, "snapshot.prepare.conflict");

  require(shard.discard_prepared(2U, prepare.snapshot),
          "matching private state was not discarded");
  state = shard.state();
  require(!state.prepared_snapshot.has_value() &&
              state.active_snapshot == active &&
              state.last_rollout_sequence == 2U,
          "discard changed active state or lost replay history");
  require_issue(prepare, shard, "rollout.sequence.stale");
  const auto older = command(1U, target, active);
  require_issue(older, shard, "rollout.sequence.stale");
}

void test_envelope_and_runtime_rejections() {
  const auto active_bytes = deterministic_bytes(snapshot("active", 1U));
  const auto active = reference("active", active_bytes);
  const auto target = snapshot("target", 2U);

  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid = command(1U, target, active);
    invalid.snapshot_bytes.clear();
    require_issue(invalid, shard, "snapshot.size.invalid");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid = command(1U, target, active);
    invalid.snapshot_bytes.assign(kMaximumSnapshotArtifactBytes + 1U, 'x');
    require_issue(invalid, shard, "snapshot.size.invalid");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid = command(1U, target, active);
    invalid.snapshot_bytes.push_back('\0');
    require_issue(invalid, shard, "snapshot.digest.mismatch");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid = command(1U, target, active);
    invalid.snapshot_bytes.append("\xa0\x06\x01", 3U);
    invalid.snapshot.sha256 =
        bonvoyage::runtime::snapshot_sha256(invalid.snapshot_bytes);
    require_issue(invalid, shard, "snapshot.protobuf.unknown_field");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto nested_unknown = target;
    nested_unknown.mutable_virtual_hosts(0)
        ->mutable_routes(0)
        ->GetReflection()
        ->MutableUnknownFields(
            nested_unknown.mutable_virtual_hosts(0)->mutable_routes(0))
        ->AddVarint(100, 1U);
    auto invalid = command(1U, nested_unknown, active);
    require_issue(invalid, shard, "snapshot.protobuf.unknown_field");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid = command(1U, target, active);
    invalid.snapshot_bytes.append("\x40\x01", 2U);
    invalid.snapshot.sha256 =
        bonvoyage::runtime::snapshot_sha256(invalid.snapshot_bytes);
    require_issue(invalid, shard, "snapshot.protobuf.non_deterministic");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid = command(1U, target, active);
    invalid.snapshot.snapshot_id = "other-target";
    require_issue(invalid, shard, "snapshot.metadata.mismatch");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid = command(1U, target, active);
    invalid.schema_version = 2U;
    require_issue(invalid, shard, "snapshot.schema.unsupported");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid = command(1U, target, active);
    invalid.minimum_dataplane_version.clear();
    require_issue(invalid, shard, "snapshot.version.invalid");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid = command(1U, target, active);
    invalid.required_capabilities.clear();
    require_issue(invalid, shard, "snapshot.capability.invalid");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid = command(1U, target, active);
    invalid.required_capabilities.erase(
        invalid.required_capabilities.begin());
    require_issue(invalid, shard, "snapshot.capability.missing");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid = command(1U, target, active);
    invalid.required_capabilities.push_back(
        invalid.required_capabilities.front());
    require_issue(invalid, shard, "snapshot.capability.duplicate");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid = command(1U, target, active);
    invalid.required_capabilities.front().version = 2U;
    require_issue(invalid, shard, "snapshot.capability.unsupported");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid = command(1U, target, active);
    invalid.snapshot.sha256.fill(0U);
    require_issue(invalid, shard, "snapshot.reference.invalid");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid = command(1U, target, active);
    invalid.expected_active_snapshot.snapshot_id = "other-active";
    require_issue(invalid, shard, "snapshot.active_mismatch");
  }
  {
    SnapshotPreparationShard shard;
    shard.initialize(active);
    auto invalid_snapshot = target;
    invalid_snapshot.set_generation(0U);
    auto invalid = command(1U, invalid_snapshot, active);
    require_issue(invalid, shard, "snapshot.validation_failed");
    require(!shard.state().prepared_snapshot.has_value(),
            "runtime validation failure retained private state");
  }
}

}  // namespace

int main() {
  try {
    test_prepare_replay_discard_and_stale_sequence();
    test_envelope_and_runtime_rejections();
    std::cout << "{\"status\":\"passed\",\"assertions\":" << assertions
              << "}\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
