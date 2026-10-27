#include "bonvoyage/runtime/discovery_protocol.hh"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>

#include <google/protobuf/unknown_field_set.h>
#include <google/protobuf/stubs/common.h>

#include "bonvoyage/runtime/snapshot_preparation_coordinator.hh"

namespace {

using bonvoyage::runtime::DiscoveryNodeIdentity;
using bonvoyage::runtime::DiscoveryProtocolError;
using bonvoyage::runtime::GrpcMessageDeframer;
using bonvoyage::runtime::NodeSnapshotActivationReport;
using bonvoyage::runtime::NodeSnapshotCancellationReport;
using bonvoyage::runtime::NodeSnapshotPreparationReport;
using bonvoyage::runtime::PreparedSnapshotState;
using bonvoyage::runtime::SnapshotActivateCommand;
using bonvoyage::runtime::SnapshotCancelCommand;
using bonvoyage::runtime::SnapshotCapability;
using bonvoyage::runtime::SnapshotLifecycleCommand;
using bonvoyage::runtime::SnapshotPrepareCommand;
using bonvoyage::runtime::SnapshotPreparationIssue;
using bonvoyage::runtime::SnapshotPreparationState;
using bonvoyage::runtime::SnapshotReference;

unsigned assertions{};

void require(bool condition, std::string_view message) {
  ++assertions;
  if (!condition) {
    throw std::runtime_error(std::string(message));
  }
}

template <typename Callback>
void require_error(Callback callback, std::string_view expected_code) {
  ++assertions;
  try {
    callback();
  } catch (const DiscoveryProtocolError& error) {
    if (error.code() != expected_code) {
      throw std::runtime_error("wrong discovery protocol error: " +
                               error.code());
    }
    return;
  }
  throw std::runtime_error("expected discovery protocol error was not thrown");
}

[[nodiscard]] std::span<const std::uint8_t> bytes(std::string_view value) {
  return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}

[[nodiscard]] SnapshotReference reference(std::string id,
                                          std::string_view content) {
  return SnapshotReference{
      std::move(id), bonvoyage::runtime::snapshot_sha256(content)};
}

void set_reference(bonvoyage::v1::SnapshotReference* destination,
                   const SnapshotReference& source) {
  destination->set_snapshot_id(source.snapshot_id);
  destination->set_snapshot_sha256(
      reinterpret_cast<const char*>(source.sha256.data()),
      source.sha256.size());
}

void add_default_capabilities(bonvoyage::v1::SnapshotArtifact* artifact) {
  for (const auto& capability :
       bonvoyage::runtime::default_snapshot_capabilities()) {
    auto* wire = artifact->add_required_capabilities();
    wire->set_capability(capability.capability);
    wire->set_version(capability.version);
  }
}

[[nodiscard]] bonvoyage::v1::RolloutCommand prepare_command() {
  constexpr std::string_view snapshot_bytes{"snapshot-v2"};
  const auto target = reference("target", snapshot_bytes);
  const auto active = reference("active", "snapshot-v1");
  bonvoyage::v1::RolloutCommand command;
  command.set_rollout_sequence(7U);
  auto* prepare = command.mutable_prepare();
  auto* artifact = prepare->mutable_artifact();
  set_reference(artifact->mutable_snapshot(), target);
  artifact->set_snapshot_bytes(snapshot_bytes.data(), snapshot_bytes.size());
  artifact->set_schema_version(1U);
  artifact->set_minimum_dataplane_version("0.2.0");
  add_default_capabilities(artifact);
  set_reference(prepare->mutable_expected_active_snapshot(), active);
  return command;
}

[[nodiscard]] bonvoyage::v1::RolloutCommand activate_command() {
  bonvoyage::v1::RolloutCommand command;
  command.set_rollout_sequence(7U);
  set_reference(command.mutable_activate()->mutable_prepared_snapshot(),
                reference("target", "snapshot-v2"));
  set_reference(command.mutable_activate()->mutable_expected_active_snapshot(),
                reference("active", "snapshot-v1"));
  return command;
}

[[nodiscard]] bonvoyage::v1::RolloutCommand cancel_command() {
  bonvoyage::v1::RolloutCommand command;
  command.set_rollout_sequence(7U);
  set_reference(command.mutable_cancel()->mutable_snapshot(),
                reference("target", "snapshot-v2"));
  command.mutable_cancel()->set_reason("operator cancelled rollout");
  return command;
}

void test_grpc_framing_and_fragmentation() {
  const auto framed = bonvoyage::runtime::frame_grpc_message("payload");
  require(framed.size() == 12U, "gRPC frame size changed");
  require(static_cast<std::uint8_t>(framed[0]) == 0U &&
              static_cast<std::uint8_t>(framed[4]) == 7U,
          "gRPC frame prefix changed");

  GrpcMessageDeframer fragmented;
  std::optional<std::string> decoded;
  for (std::size_t offset = 0U; offset < framed.size(); ++offset) {
    const auto result = fragmented.consume(bytes(framed).subspan(offset, 1U));
    require(result.consumed == 1U,
            "single-byte fragment was not consumed exactly");
    if (result.message.has_value()) {
      require(!decoded.has_value(), "fragmented frame emitted twice");
      decoded = result.message;
    }
  }
  fragmented.finish();
  require(decoded == std::optional<std::string>{"payload"},
          "fragmented gRPC message changed");

  const auto joined = bonvoyage::runtime::frame_grpc_message("one") +
                      bonvoyage::runtime::frame_grpc_message("two");
  GrpcMessageDeframer multiple;
  std::size_t offset = 0U;
  std::string observed;
  while (offset < joined.size()) {
    const auto result = multiple.consume(bytes(joined).subspan(offset));
    require(result.consumed != 0U, "multi-frame decoder made no progress");
    offset += result.consumed;
    if (result.message.has_value()) {
      observed += *result.message;
    }
  }
  multiple.finish();
  require(observed == "onetwo", "coalesced gRPC frames changed");

  const auto empty = bonvoyage::runtime::frame_grpc_message("");
  GrpcMessageDeframer empty_decoder;
  const auto empty_result = empty_decoder.consume(bytes(empty));
  require(empty_result.message.has_value() && empty_result.message->empty(),
          "zero-length gRPC message was not preserved");
  empty_decoder.finish();

  GrpcMessageDeframer exact(4U);
  const auto exact_frame = bonvoyage::runtime::frame_grpc_message("1234", 4U);
  require(exact.consume(bytes(exact_frame)).message ==
              std::optional<std::string>{"1234"},
          "maximum-sized permitted frame was rejected");
}

void test_grpc_framing_rejections() {
  require_error([] { GrpcMessageDeframer invalid(0U); },
                "grpc.frame.limit_invalid");
  require_error(
      [] { (void)bonvoyage::runtime::frame_grpc_message("12345", 4U); },
      "grpc.frame.size_invalid");

  std::string oversized(5U, '\0');
  oversized[4] = 5;
  GrpcMessageDeframer bounded(4U);
  require_error([&] { (void)bounded.consume(bytes(oversized)); },
                "grpc.frame.size_invalid");

  std::string compressed(5U, '\0');
  compressed[0] = 1;
  GrpcMessageDeframer compressed_decoder;
  require_error(
      [&] { (void)compressed_decoder.consume(bytes(compressed)); },
      "grpc.frame.compression_unsupported");
  compressed[0] = 2;
  GrpcMessageDeframer invalid_flag;
  require_error([&] { (void)invalid_flag.consume(bytes(compressed)); },
                "grpc.frame.compression_unsupported");

  GrpcMessageDeframer partial_prefix;
  const std::string prefix{"\0\0", 2U};
  (void)partial_prefix.consume(bytes(prefix));
  require_error([&] { partial_prefix.finish(); }, "grpc.frame.truncated");

  GrpcMessageDeframer partial_payload;
  const auto frame = bonvoyage::runtime::frame_grpc_message("payload");
  (void)partial_payload.consume(bytes(frame).first(frame.size() - 1U));
  require_error([&] { partial_payload.finish(); }, "grpc.frame.truncated");
  partial_payload.reset();
  partial_payload.finish();
}

void test_rollout_command_mapping() {
  const auto prepare = bonvoyage::runtime::map_rollout_command(prepare_command());
  require(std::holds_alternative<SnapshotPrepareCommand>(prepare),
          "PREPARE mapped to the wrong lifecycle command");
  const auto& prepared = std::get<SnapshotPrepareCommand>(prepare);
  require(prepared.rollout_sequence == 7U &&
              prepared.snapshot.snapshot_id == "target" &&
              prepared.snapshot_bytes == "snapshot-v2" &&
              prepared.schema_version == 1U &&
              prepared.minimum_dataplane_version == "0.2.0" &&
              prepared.required_capabilities.size() == 3U &&
              prepared.expected_active_snapshot.snapshot_id == "active",
          "PREPARE lifecycle fields changed");

  const auto activate =
      bonvoyage::runtime::map_rollout_command(activate_command());
  require(std::holds_alternative<SnapshotActivateCommand>(activate),
          "ACTIVATE mapped to the wrong lifecycle command");
  require(std::get<SnapshotActivateCommand>(activate)
                  .prepared_snapshot.snapshot_id == "target",
          "ACTIVATE target identity changed");

  const auto cancel = bonvoyage::runtime::map_rollout_command(cancel_command());
  require(std::holds_alternative<SnapshotCancelCommand>(cancel),
          "CANCEL mapped to the wrong lifecycle command");
  require(std::get<SnapshotCancelCommand>(cancel).reason ==
              "operator cancelled rollout",
          "CANCEL reason changed");

  bonvoyage::v1::StreamSnapshotsResponse response;
  *response.mutable_command() = prepare_command();
  const auto encoded = response.SerializeAsString();
  require(std::holds_alternative<SnapshotPrepareCommand>(
              bonvoyage::runtime::decode_discovery_response(encoded)),
          "serialized discovery response did not map to PREPARE");

  const auto command_bytes = activate_command().SerializeAsString();
  require(std::holds_alternative<SnapshotActivateCommand>(
              bonvoyage::runtime::decode_rollout_command(command_bytes)),
          "serialized rollout command did not map to ACTIVATE");
}

void test_malformed_and_unknown_commands() {
  const std::string malformed{"\x80", 1U};
  require_error(
      [&] { (void)bonvoyage::runtime::decode_rollout_command(malformed); },
      "discovery.protobuf.invalid");

  const std::string unknown_operation{"\x08\x01\x2a\x00", 4U};
  require_error(
      [&] {
        (void)bonvoyage::runtime::decode_rollout_command(unknown_operation);
      },
      "discovery.protobuf.unknown_field");

  bonvoyage::v1::RolloutCommand missing;
  missing.set_rollout_sequence(1U);
  require_error(
      [&] { (void)bonvoyage::runtime::map_rollout_command(missing); },
      "rollout.command.missing");

  auto zero_sequence = prepare_command();
  zero_sequence.set_rollout_sequence(0U);
  require_error(
      [&] { (void)bonvoyage::runtime::map_rollout_command(zero_sequence); },
      "rollout.sequence.invalid");

  auto unknown_nested = prepare_command();
  auto* artifact = unknown_nested.mutable_prepare()->mutable_artifact();
  artifact->GetReflection()->MutableUnknownFields(artifact)->AddVarint(99, 1U);
  require_error(
      [&] { (void)bonvoyage::runtime::map_rollout_command(unknown_nested); },
      "discovery.protobuf.unknown_field");

  bonvoyage::v1::StreamSnapshotsResponse legacy;
  legacy.mutable_delivery()->set_rollout_sequence(1U);
  require_error(
      [&] {
        (void)bonvoyage::runtime::decode_discovery_response(
            legacy.SerializeAsString());
      },
      "discovery.response.legacy_delivery_unsupported");
}

void test_digest_and_capability_rejections() {
  for (const auto length : {31U, 33U}) {
    auto command = prepare_command();
    command.mutable_prepare()
        ->mutable_artifact()
        ->mutable_snapshot()
        ->set_snapshot_sha256(std::string(length, 'x'));
    require_error(
        [&] { (void)bonvoyage::runtime::map_rollout_command(command); },
        "snapshot.digest.length_invalid");
  }

  auto zero_digest = prepare_command();
  zero_digest.mutable_prepare()
      ->mutable_artifact()
      ->mutable_snapshot()
      ->set_snapshot_sha256(std::string(32U, '\0'));
  require_error(
      [&] { (void)bonvoyage::runtime::map_rollout_command(zero_digest); },
      "snapshot.reference.invalid");

  auto mismatch = prepare_command();
  mismatch.mutable_prepare()
      ->mutable_artifact()
      ->mutable_snapshot()
      ->set_snapshot_sha256(std::string(32U, 'x'));
  require_error(
      [&] { (void)bonvoyage::runtime::map_rollout_command(mismatch); },
      "snapshot.digest.mismatch");

  auto unsupported = prepare_command();
  unsupported.mutable_prepare()
      ->mutable_artifact()
      ->mutable_required_capabilities(0)
      ->set_capability(
          static_cast<bonvoyage::v1::NodeCapabilityType>(99));
  require_error(
      [&] { (void)bonvoyage::runtime::map_rollout_command(unsupported); },
      "snapshot.capability.unsupported");

  auto wrong_version = prepare_command();
  wrong_version.mutable_prepare()
      ->mutable_artifact()
      ->mutable_required_capabilities(0)
      ->set_version(2U);
  require_error(
      [&] { (void)bonvoyage::runtime::map_rollout_command(wrong_version); },
      "snapshot.capability.unsupported");

  auto duplicate = prepare_command();
  *duplicate.mutable_prepare()
       ->mutable_artifact()
       ->add_required_capabilities() =
      duplicate.prepare().artifact().required_capabilities(0);
  require_error(
      [&] { (void)bonvoyage::runtime::map_rollout_command(duplicate); },
      "snapshot.capability.duplicate");

  auto missing_two_phase = prepare_command();
  auto* required = missing_two_phase.mutable_prepare()
                       ->mutable_artifact()
                       ->mutable_required_capabilities();
  required->DeleteSubrange(0, 1);
  require_error(
      [&] {
        (void)bonvoyage::runtime::map_rollout_command(missing_two_phase);
      },
      "snapshot.capability.missing");

  auto missing_identity = activate_command();
  missing_identity.mutable_activate()->clear_prepared_snapshot();
  require_error(
      [&] { (void)bonvoyage::runtime::map_rollout_command(missing_identity); },
      "rollout.command.invalid");
}

[[nodiscard]] DiscoveryNodeIdentity identity() {
  return DiscoveryNodeIdentity{"node-1", "process-1", "0.2.0"};
}

[[nodiscard]] SnapshotPreparationState runtime_state() {
  SnapshotPreparationState state;
  state.active_snapshot = reference("active", "snapshot-v1");
  state.active_rollout_sequence = 6U;
  state.prepared_snapshot =
      PreparedSnapshotState{7U, reference("target", "snapshot-v2")};
  state.last_rollout_sequence = 7U;
  state.admission_open = true;
  return state;
}

void test_hello_and_heartbeat_builders() {
  const auto state = runtime_state();
  const auto hello =
      bonvoyage::runtime::build_node_hello(identity(), state, 8U);
  require(hello.node_id() == "node-1" &&
              hello.process_instance_id() == "process-1" &&
              hello.dataplane_version() == "0.2.0" &&
              hello.supported_schema_versions_size() == 1 &&
              hello.supported_schema_versions(0) == 1U &&
              hello.capabilities_size() == 3,
          "node hello identity or capabilities changed");
  require(hello.active_snapshot_id() == "active" &&
              hello.runtime_state().active_snapshot().snapshot_id() ==
                  "active" &&
              hello.runtime_state().active_shard_count() == 8U &&
              hello.runtime_state().prepared_snapshot().rollout_sequence() ==
                  7U &&
              hello.runtime_state().prepared_snapshot().shard_count() == 8U,
          "node hello runtime state changed");

  const auto observed_at = std::chrono::system_clock::time_point{
                               std::chrono::seconds{123}} +
                           std::chrono::nanoseconds{456};
  const auto heartbeat = bonvoyage::runtime::build_node_heartbeat(
      identity(), state, 8U, observed_at);
  require(heartbeat.node_id() == "node-1" &&
              heartbeat.observed_at().seconds() == 123 &&
              heartbeat.observed_at().nanos() == 456 &&
              heartbeat.runtime_state().last_rollout_sequence() == 7U,
          "node heartbeat changed");

  auto incomplete = identity();
  incomplete.capabilities.pop_back();
  require_error(
      [&] {
        (void)bonvoyage::runtime::build_node_hello(incomplete, state, 8U);
      },
      "snapshot.capability.incomplete");

  auto invalid_state = state;
  invalid_state.prepared_snapshot->rollout_sequence = 8U;
  require_error(
      [&] {
        (void)bonvoyage::runtime::build_node_heartbeat(
            identity(), invalid_state, 8U, observed_at);
      },
      "snapshot.state.invalid");
}

void test_structured_rollout_reports() {
  const auto active = reference("active", "snapshot-v1");
  const auto target = reference("target", "snapshot-v2");
  const auto completed_at = std::chrono::system_clock::time_point{
                                std::chrono::seconds{456}} +
                            std::chrono::nanoseconds{789};

  NodeSnapshotPreparationReport prepare_ack;
  prepare_ack.acknowledged = true;
  prepare_ack.rollout_sequence = 7U;
  prepare_ack.snapshot = target;
  prepare_ack.previous_active_snapshot = active;
  prepare_ack.current_active_snapshot = active;
  prepare_ack.shard_count = 8U;
  prepare_ack.completed_shards = 8U;
  const auto prepare_wire = bonvoyage::runtime::build_node_rollout_report(
      identity(), prepare_ack, completed_at);
  require(prepare_wire.operation() ==
                  bonvoyage::v1::ROLLOUT_OPERATION_PREPARE &&
              prepare_wire.result() ==
                  bonvoyage::v1::ACKNOWLEDGEMENT_RESULT_ACK &&
              prepare_wire.errors().empty() &&
              prepare_wire.completed_at().seconds() == 456 &&
              prepare_wire.completed_at().nanos() == 789,
          "PREPARE ACK mapping changed");

  NodeSnapshotPreparationReport prepare_nack = prepare_ack;
  prepare_nack.acknowledged = false;
  prepare_nack.completed_shards = 3U;
  prepare_nack.failed_shard = 3U;
  prepare_nack.issue = SnapshotPreparationIssue{
      "snapshot.digest.mismatch", "artifact.snapshot.sha256",
      "snapshot bytes do not match the declared digest"};
  const auto nack_wire = bonvoyage::runtime::build_node_rollout_report(
      identity(), prepare_nack, completed_at);
  require(nack_wire.result() ==
                  bonvoyage::v1::ACKNOWLEDGEMENT_RESULT_NACK &&
              nack_wire.errors_size() == 1 &&
              nack_wire.errors(0).code() == "snapshot.digest.mismatch" &&
              nack_wire.errors(0).field_path() ==
                  "artifact.snapshot.sha256" &&
              nack_wire.errors(0).message() ==
                  "snapshot bytes do not match the declared digest",
          "structured PREPARE NACK mapping changed");

  NodeSnapshotActivationReport activation;
  activation.acknowledged = true;
  activation.rollout_sequence = 7U;
  activation.snapshot = target;
  activation.previous_active_snapshot = active;
  activation.current_active_snapshot = target;
  activation.shard_count = 8U;
  activation.completed_shards = 8U;
  const auto activation_wire = bonvoyage::runtime::build_node_rollout_report(
      identity(), activation, completed_at);
  require(activation_wire.operation() ==
                  bonvoyage::v1::ROLLOUT_OPERATION_ACTIVATE &&
              activation_wire.current_active_snapshot().snapshot_id() ==
                  "target",
          "ACTIVATE ACK mapping changed");

  NodeSnapshotCancellationReport cancellation;
  cancellation.acknowledged = true;
  cancellation.rollout_sequence = 8U;
  cancellation.snapshot = target;
  cancellation.current_active_snapshot = active;
  cancellation.shard_count = 8U;
  cancellation.completed_shards = 8U;
  const auto cancel_wire = bonvoyage::runtime::build_node_rollout_report(
      identity(), cancellation, completed_at);
  require(cancel_wire.operation() ==
                  bonvoyage::v1::ROLLOUT_OPERATION_CANCEL &&
              cancel_wire.previous_active_snapshot().snapshot_id() ==
                  "active" &&
              cancel_wire.current_active_snapshot().snapshot_id() == "active",
          "CANCEL ACK mapping changed");

  auto inconsistent = prepare_nack;
  inconsistent.issue.reset();
  require_error(
      [&] {
        (void)bonvoyage::runtime::build_node_rollout_report(
            identity(), inconsistent, completed_at);
      },
      "rollout.result.invalid");

  auto partial_ack = activation;
  partial_ack.completed_shards = 7U;
  require_error(
      [&] {
        (void)bonvoyage::runtime::build_node_rollout_report(
            identity(), partial_ack, completed_at);
      },
      "rollout.shards.invalid");
}

}  // namespace

int main() {
  try {
    test_grpc_framing_and_fragmentation();
    test_grpc_framing_rejections();
    test_rollout_command_mapping();
    test_malformed_and_unknown_commands();
    test_digest_and_capability_rejections();
    test_hello_and_heartbeat_builders();
    test_structured_rollout_reports();
    std::cout << "{\"status\":\"passed\",\"assertions\":" << assertions
              << "}\n"
              << std::flush;
    google::protobuf::ShutdownProtobufLibrary();
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    google::protobuf::ShutdownProtobufLibrary();
    return 1;
  }
}
