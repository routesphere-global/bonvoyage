#include "bonvoyage/runtime/discovery_protocol.hh"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>

#include "bonvoyage/runtime/snapshot_preparation_coordinator.hh"

namespace bonvoyage::runtime {
namespace {

constexpr std::size_t kMaximumCapabilities = 16U;
constexpr std::size_t kMaximumSchemaVersions = 32U;
constexpr std::size_t kMaximumIdentifierBytes = 128U;
constexpr std::size_t kMaximumCancelReasonBytes = 1024U;
constexpr std::size_t kMaximumFieldPathBytes = 1024U;
constexpr std::size_t kMaximumIssueBytes = 4096U;
constexpr std::uint32_t kSupportedSchemaVersion = 1U;
constexpr std::uint32_t kSupportedCapabilityVersion = 1U;
constexpr std::int64_t kMinimumProtobufTimestampSeconds = -62'135'596'800LL;
constexpr std::int64_t kMaximumProtobufTimestampSeconds = 253'402'300'799LL;

[[noreturn]] void fail(std::string code, std::string field_path,
                       const std::string& message) {
  throw DiscoveryProtocolError(std::move(code), std::move(field_path),
                               message);
}

[[nodiscard]] bool zero_digest(const SnapshotDigest& digest) noexcept {
  return std::all_of(digest.begin(), digest.end(),
                     [](std::uint8_t byte) { return byte == 0U; });
}

[[nodiscard]] bool valid_utf8(std::string_view value) noexcept {
  std::size_t offset = 0U;
  while (offset < value.size()) {
    const auto first = static_cast<std::uint8_t>(value[offset]);
    if (first <= 0x7fU) {
      ++offset;
      continue;
    }

    std::size_t continuation_count = 0U;
    std::uint8_t second_minimum = 0x80U;
    std::uint8_t second_maximum = 0xbfU;
    if (first >= 0xc2U && first <= 0xdfU) {
      continuation_count = 1U;
    } else if (first >= 0xe0U && first <= 0xefU) {
      continuation_count = 2U;
      if (first == 0xe0U) {
        second_minimum = 0xa0U;
      } else if (first == 0xedU) {
        second_maximum = 0x9fU;
      }
    } else if (first >= 0xf0U && first <= 0xf4U) {
      continuation_count = 3U;
      if (first == 0xf0U) {
        second_minimum = 0x90U;
      } else if (first == 0xf4U) {
        second_maximum = 0x8fU;
      }
    } else {
      return false;
    }

    if (offset + continuation_count >= value.size()) {
      return false;
    }
    const auto second = static_cast<std::uint8_t>(value[offset + 1U]);
    if (second < second_minimum || second > second_maximum) {
      return false;
    }
    for (std::size_t index = 2U; index <= continuation_count; ++index) {
      const auto byte = static_cast<std::uint8_t>(value[offset + index]);
      if (byte < 0x80U || byte > 0xbfU) {
        return false;
      }
    }
    offset += continuation_count + 1U;
  }
  return true;
}

[[nodiscard]] bool contains_visible_text(std::string_view value) noexcept {
  return std::any_of(value.begin(), value.end(), [](char character) {
    return static_cast<unsigned char>(character) > 0x20U;
  });
}

void validate_text(std::string_view value, std::size_t maximum,
                   bool required, std::string_view field_path) {
  if (value.size() > maximum || !valid_utf8(value) ||
      (required && !contains_visible_text(value))) {
    fail("discovery.text.invalid", std::string(field_path),
         "text is missing, malformed, or exceeds its byte limit");
  }
  if (std::any_of(value.begin(), value.end(), [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return byte < 0x20U || byte == 0x7fU;
      })) {
    fail("discovery.text.invalid", std::string(field_path),
         "text contains an ASCII control character");
  }
}

[[nodiscard]] bool identifier_character(char character,
                                        bool allow_colon) noexcept {
  return (character >= 'a' && character <= 'z') ||
         (character >= 'A' && character <= 'Z') ||
         (character >= '0' && character <= '9') || character == '.' ||
         character == '_' || character == '-' ||
         (allow_colon && character == ':');
}

void validate_identifier(std::string_view value, std::string_view field_path,
                         bool allow_colon, bool require_alphanumeric_first) {
  if (value.empty() || value.size() > kMaximumIdentifierBytes ||
      !std::all_of(value.begin(), value.end(), [allow_colon](char character) {
        return identifier_character(character, allow_colon);
      })) {
    fail("discovery.identifier.invalid", std::string(field_path),
         "identifier must contain 1-128 supported ASCII bytes");
  }
  const auto first = value.front();
  const auto first_alphanumeric =
      (first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') ||
      (first >= '0' && first <= '9');
  if ((require_alphanumeric_first && !first_alphanumeric) ||
      (!require_alphanumeric_first &&
       (first == '.' || first == ':' || first == '-'))) {
    fail("discovery.identifier.invalid", std::string(field_path),
         "identifier has an unsupported leading character");
  }
}

void validate_snapshot_reference(const SnapshotReference& reference,
                                 std::string_view field_path) {
  validate_identifier(reference.snapshot_id,
                      std::string(field_path) + ".snapshot_id", false, true);
  if (zero_digest(reference.sha256)) {
    fail("snapshot.reference.invalid", std::string(field_path) + ".sha256",
         "snapshot digest must be a non-zero SHA-256 value");
  }
}

[[nodiscard]] SnapshotReference reference_from_proto(
    const bonvoyage::v1::SnapshotReference& reference,
    std::string_view field_path) {
  validate_identifier(reference.snapshot_id(),
                      std::string(field_path) + ".snapshot_id", false, true);
  if (reference.snapshot_sha256().size() != SnapshotDigest{}.size()) {
    fail("snapshot.digest.length_invalid",
         std::string(field_path) + ".snapshot_sha256",
         "snapshot digest must contain exactly 32 bytes");
  }
  SnapshotReference converted;
  converted.snapshot_id = reference.snapshot_id();
  std::transform(reference.snapshot_sha256().begin(),
                 reference.snapshot_sha256().end(), converted.sha256.begin(),
                 [](char byte) { return static_cast<std::uint8_t>(byte); });
  if (zero_digest(converted.sha256)) {
    fail("snapshot.reference.invalid",
         std::string(field_path) + ".snapshot_sha256",
         "snapshot digest must be non-zero");
  }
  return converted;
}

void set_reference(bonvoyage::v1::SnapshotReference* destination,
                   const SnapshotReference& reference) {
  destination->set_snapshot_id(reference.snapshot_id);
  destination->set_snapshot_sha256(
      reinterpret_cast<const char*>(reference.sha256.data()),
      reference.sha256.size());
}

[[nodiscard]] bool known_capability(
    bonvoyage::v1::NodeCapabilityType capability) noexcept {
  switch (capability) {
    case bonvoyage::v1::NODE_CAPABILITY_TYPE_TWO_PHASE_ROLLOUT:
    case bonvoyage::v1::NODE_CAPABILITY_TYPE_EXACT_ARTIFACT_ROLLBACK:
    case bonvoyage::v1::NODE_CAPABILITY_TYPE_HEARTBEAT_STATE_REPORT:
      return true;
    case bonvoyage::v1::NODE_CAPABILITY_TYPE_UNSPECIFIED:
    default:
      return false;
  }
}

[[nodiscard]] std::vector<SnapshotCapability> validate_capabilities(
    std::vector<SnapshotCapability> capabilities, bool require_exact_defaults,
    std::string_view field_path) {
  if (capabilities.empty() || capabilities.size() > kMaximumCapabilities) {
    fail("snapshot.capability.invalid", std::string(field_path),
         "capability count must be between 1 and 16");
  }
  std::sort(capabilities.begin(), capabilities.end(),
            [](const SnapshotCapability& left,
               const SnapshotCapability& right) {
              return left.capability < right.capability;
            });
  bool has_two_phase = false;
  for (std::size_t index = 0U; index < capabilities.size(); ++index) {
    const auto& capability = capabilities[index];
    if (!known_capability(capability.capability) ||
        capability.version != kSupportedCapabilityVersion) {
      fail("snapshot.capability.unsupported",
           std::string(field_path) + "[" + std::to_string(index) + "]",
           "capability type or version is unsupported");
    }
    if (index != 0U &&
        capabilities[index - 1U].capability == capability.capability) {
      fail("snapshot.capability.duplicate",
           std::string(field_path) + "[" + std::to_string(index) + "]",
           "capability type is duplicated");
    }
    has_two_phase =
        has_two_phase ||
        capability.capability ==
            bonvoyage::v1::NODE_CAPABILITY_TYPE_TWO_PHASE_ROLLOUT;
  }
  if (!has_two_phase) {
    fail("snapshot.capability.missing", std::string(field_path),
         "two-phase rollout capability version 1 is required");
  }

  if (require_exact_defaults) {
    auto expected = default_snapshot_capabilities();
    std::sort(expected.begin(), expected.end(),
              [](const SnapshotCapability& left,
                 const SnapshotCapability& right) {
                return left.capability < right.capability;
              });
    if (capabilities != expected) {
      fail("snapshot.capability.incomplete", std::string(field_path),
           "node discovery requires the complete Phase 4 capability set");
    }
  }
  return capabilities;
}

[[nodiscard]] std::vector<SnapshotCapability> capabilities_from_proto(
    const bonvoyage::v1::SnapshotArtifact& artifact) {
  std::vector<SnapshotCapability> capabilities;
  capabilities.reserve(
      static_cast<std::size_t>(artifact.required_capabilities_size()));
  for (const auto& capability : artifact.required_capabilities()) {
    capabilities.push_back(
        SnapshotCapability{capability.capability(), capability.version()});
  }
  return validate_capabilities(std::move(capabilities), false,
                               "command.prepare.artifact.required_capabilities");
}

[[nodiscard]] bool find_unknown_fields(const google::protobuf::Message& message,
                                       std::string path,
                                       std::string& unknown_path) {
  const auto* reflection = message.GetReflection();
  if (reflection->GetUnknownFields(message).field_count() != 0) {
    unknown_path = std::move(path);
    return true;
  }
  const auto* descriptor = message.GetDescriptor();
  for (int field_index = 0; field_index < descriptor->field_count();
       ++field_index) {
    const auto* field = descriptor->field(field_index);
    if (field->cpp_type() !=
        google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE) {
      continue;
    }
    const auto child_path = path + "." + field->name();
    if (field->is_repeated()) {
      const auto count = reflection->FieldSize(message, field);
      for (int item = 0; item < count; ++item) {
        if (find_unknown_fields(
                reflection->GetRepeatedMessage(message, field, item),
                child_path + "[" + std::to_string(item) + "]",
                unknown_path)) {
          return true;
        }
      }
    } else if (reflection->HasField(message, field) &&
               find_unknown_fields(reflection->GetMessage(message, field),
                                   child_path, unknown_path)) {
      return true;
    }
  }
  return false;
}

void reject_unknown_fields(const google::protobuf::Message& message,
                           std::string path) {
  std::string unknown_path;
  if (find_unknown_fields(message, std::move(path), unknown_path)) {
    fail("discovery.protobuf.unknown_field", std::move(unknown_path),
         "discovery protobuf contains an unknown field");
  }
}

template <typename Message>
[[nodiscard]] Message parse_message(std::string_view bytes,
                                    std::string_view field_path) {
  if (bytes.size() > kMaximumDiscoveryMessageBytes ||
      bytes.size() >
          static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    fail("discovery.protobuf.size_invalid", std::string(field_path),
         "discovery protobuf exceeds its configured byte limit");
  }
  Message message;
  if (!message.ParseFromArray(bytes.data(), static_cast<int>(bytes.size()))) {
    fail("discovery.protobuf.invalid", std::string(field_path),
         "discovery protobuf is malformed or truncated");
  }
  reject_unknown_fields(message, std::string(field_path));
  return message;
}

void validate_identity(const DiscoveryNodeIdentity& identity) {
  validate_identifier(identity.node_id, "node_id", true, false);
  validate_identifier(identity.process_instance_id, "process_instance_id",
                      true, false);
  validate_text(identity.dataplane_version, kMaximumIdentifierBytes, true,
                "dataplane_version");

  if (identity.supported_schema_versions.empty() ||
      identity.supported_schema_versions.size() > kMaximumSchemaVersions) {
    fail("snapshot.schema.invalid", "supported_schema_versions",
         "supported schema version count must be between 1 and 32");
  }
  auto schemas = identity.supported_schema_versions;
  std::sort(schemas.begin(), schemas.end());
  if (schemas.front() == 0U ||
      std::adjacent_find(schemas.begin(), schemas.end()) != schemas.end() ||
      !std::binary_search(schemas.begin(), schemas.end(),
                          kSupportedSchemaVersion)) {
    fail("snapshot.schema.invalid", "supported_schema_versions",
         "schema versions must be non-zero, unique, and include version 1");
  }
  (void)validate_capabilities(identity.capabilities, true, "capabilities");
}

void set_runtime_state(bonvoyage::v1::NodeRuntimeState* destination,
                       const SnapshotPreparationState& state,
                       std::uint32_t shard_count) {
  if (shard_count == 0U) {
    fail("snapshot.state.invalid", "active_shard_count",
         "active snapshot state requires at least one shard");
  }
  validate_snapshot_reference(state.active_snapshot, "active_snapshot");
  set_reference(destination->mutable_active_snapshot(), state.active_snapshot);
  destination->set_last_rollout_sequence(state.last_rollout_sequence);
  destination->set_active_shard_count(shard_count);

  if (!state.prepared_snapshot.has_value()) {
    return;
  }
  const auto& prepared = *state.prepared_snapshot;
  if (prepared.rollout_sequence == 0U ||
      prepared.rollout_sequence > state.last_rollout_sequence) {
    fail("snapshot.state.invalid", "prepared_snapshot.rollout_sequence",
         "prepared sequence must be non-zero and already accepted");
  }
  validate_snapshot_reference(prepared.snapshot, "prepared_snapshot.snapshot");
  auto* wire = destination->mutable_prepared_snapshot();
  wire->set_rollout_sequence(prepared.rollout_sequence);
  set_reference(wire->mutable_snapshot(), prepared.snapshot);
  wire->set_shard_count(shard_count);
}

void set_timestamp(google::protobuf::Timestamp* destination,
                   std::chrono::system_clock::time_point value,
                   std::string_view field_path) {
  const auto elapsed = value.time_since_epoch();
  const auto seconds = std::chrono::floor<std::chrono::seconds>(elapsed);
  const auto nanoseconds =
      std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed - seconds);
  if (seconds.count() < kMinimumProtobufTimestampSeconds ||
      seconds.count() > kMaximumProtobufTimestampSeconds ||
      nanoseconds.count() < 0 || nanoseconds.count() >= 1'000'000'000LL) {
    fail("discovery.timestamp.invalid", std::string(field_path),
         "timestamp is outside the protobuf Timestamp range");
  }
  destination->set_seconds(seconds.count());
  destination->set_nanos(static_cast<std::int32_t>(nanoseconds.count()));
}

void validate_issue(const SnapshotPreparationIssue& issue) {
  validate_identifier(issue.code, "errors.code", true, false);
  validate_text(issue.field_path, kMaximumFieldPathBytes, false,
                "errors.field_path");
  validate_text(issue.message, kMaximumIssueBytes, true, "errors.message");
}

[[nodiscard]] bonvoyage::v1::NodeRolloutReport make_report(
    const DiscoveryNodeIdentity& identity, std::uint64_t rollout_sequence,
    const SnapshotReference& snapshot,
    bonvoyage::v1::RolloutOperation operation, bool acknowledged,
    const SnapshotReference& previous_active_snapshot,
    const SnapshotReference& current_active_snapshot,
    std::uint32_t shard_count, std::uint32_t completed_shards,
    const std::optional<std::uint32_t>& failed_shard,
    const std::optional<SnapshotPreparationIssue>& issue,
    std::chrono::system_clock::time_point completed_at) {
  validate_identity(identity);
  if (rollout_sequence == 0U) {
    fail("rollout.sequence.invalid", "rollout_sequence",
         "rollout sequence must be non-zero");
  }
  validate_snapshot_reference(snapshot, "snapshot");
  validate_snapshot_reference(previous_active_snapshot,
                              "previous_active_snapshot");
  validate_snapshot_reference(current_active_snapshot,
                              "current_active_snapshot");
  if (shard_count == 0U || completed_shards > shard_count ||
      (acknowledged && completed_shards != shard_count)) {
    fail("rollout.shards.invalid", "completed_shards",
         "shard completion does not match the rollout result");
  }
  if (failed_shard.has_value() && *failed_shard >= shard_count) {
    fail("rollout.shards.invalid", "failed_shard",
         "failed shard is outside the node shard range");
  }
  if (acknowledged == issue.has_value()) {
    fail("rollout.result.invalid", "errors",
         "ACK must have no issue and NACK must have one structured issue");
  }
  if (issue.has_value()) {
    validate_issue(*issue);
  }

  bonvoyage::v1::NodeRolloutReport wire;
  wire.set_node_id(identity.node_id);
  wire.set_process_instance_id(identity.process_instance_id);
  wire.set_rollout_sequence(rollout_sequence);
  set_reference(wire.mutable_snapshot(), snapshot);
  wire.set_operation(operation);
  wire.set_result(
      acknowledged
          ? bonvoyage::v1::ACKNOWLEDGEMENT_RESULT_ACK
          : bonvoyage::v1::ACKNOWLEDGEMENT_RESULT_NACK);
  set_reference(wire.mutable_previous_active_snapshot(),
                previous_active_snapshot);
  set_reference(wire.mutable_current_active_snapshot(),
                current_active_snapshot);
  if (issue.has_value()) {
    auto* error = wire.add_errors();
    error->set_code(issue->code);
    error->set_field_path(issue->field_path);
    error->set_message(issue->message);
  }
  wire.set_shard_count(shard_count);
  wire.set_completed_shards(completed_shards);
  set_timestamp(wire.mutable_completed_at(), completed_at, "completed_at");
  return wire;
}

}  // namespace

DiscoveryProtocolError::DiscoveryProtocolError(std::string code,
                                               std::string field_path,
                                               const std::string& message)
    : std::runtime_error(message),
      code_(std::move(code)),
      field_path_(std::move(field_path)) {}

const std::string& DiscoveryProtocolError::code() const noexcept {
  return code_;
}

const std::string& DiscoveryProtocolError::field_path() const noexcept {
  return field_path_;
}

GrpcMessageDeframer::GrpcMessageDeframer(std::size_t maximum_message_bytes)
    : maximum_message_bytes_(maximum_message_bytes) {
  if (maximum_message_bytes_ == 0U ||
      maximum_message_bytes_ >
          static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
    fail("grpc.frame.limit_invalid", "maximum_message_bytes",
         "gRPC message limit must fit a non-zero 32-bit length prefix");
  }
}

GrpcDeframeResult GrpcMessageDeframer::consume(
    std::span<const std::uint8_t> fragment) {
  GrpcDeframeResult result;
  while (result.consumed < fragment.size()) {
    if (!prefix_complete_) {
      const auto available = fragment.size() - result.consumed;
      const auto needed = kGrpcMessagePrefixBytes - prefix_bytes_;
      const auto copied = std::min(available, needed);
      std::copy_n(fragment.begin() +
                      static_cast<std::ptrdiff_t>(result.consumed),
                  static_cast<std::ptrdiff_t>(copied),
                  prefix_ + static_cast<std::ptrdiff_t>(prefix_bytes_));
      prefix_bytes_ += copied;
      result.consumed += copied;
      if (prefix_bytes_ != kGrpcMessagePrefixBytes) {
        return result;
      }
      if (prefix_[0] != 0U) {
        fail("grpc.frame.compression_unsupported", "compressed_flag",
             "discovery messages must use the uncompressed gRPC flag");
      }
      declared_length_ =
          (static_cast<std::uint32_t>(prefix_[1]) << 24U) |
          (static_cast<std::uint32_t>(prefix_[2]) << 16U) |
          (static_cast<std::uint32_t>(prefix_[3]) << 8U) |
          static_cast<std::uint32_t>(prefix_[4]);
      if (declared_length_ > maximum_message_bytes_) {
        fail("grpc.frame.size_invalid", "message_length",
             "gRPC message exceeds the configured discovery limit");
      }
      prefix_complete_ = true;
      payload_.clear();
      payload_.reserve(declared_length_);
      if (declared_length_ == 0U) {
        result.message.emplace();
        reset();
        return result;
      }
    }

    const auto remaining =
        static_cast<std::size_t>(declared_length_) - payload_.size();
    const auto copied =
        std::min(remaining, fragment.size() - result.consumed);
    payload_.append(
        reinterpret_cast<const char*>(fragment.data() + result.consumed),
        copied);
    result.consumed += copied;
    if (payload_.size() == declared_length_) {
      result.message.emplace(std::move(payload_));
      reset();
      return result;
    }
  }
  return result;
}

void GrpcMessageDeframer::finish() const {
  if (prefix_bytes_ != 0U || prefix_complete_ || !payload_.empty()) {
    fail("grpc.frame.truncated", "grpc_message",
         "discovery stream ended in a partial gRPC message");
  }
}

void GrpcMessageDeframer::reset() noexcept {
  std::fill(std::begin(prefix_), std::end(prefix_), 0U);
  prefix_bytes_ = 0U;
  declared_length_ = 0U;
  prefix_complete_ = false;
  payload_.clear();
}

std::string frame_grpc_message(std::string_view protobuf_bytes,
                               std::size_t maximum_message_bytes) {
  if (maximum_message_bytes == 0U ||
      protobuf_bytes.size() > maximum_message_bytes ||
      protobuf_bytes.size() >
          static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
    fail("grpc.frame.size_invalid", "protobuf_bytes",
         "protobuf payload exceeds the configured gRPC message limit");
  }
  const auto size = static_cast<std::uint32_t>(protobuf_bytes.size());
  std::string framed;
  framed.reserve(kGrpcMessagePrefixBytes + protobuf_bytes.size());
  framed.push_back('\0');
  framed.push_back(static_cast<char>((size >> 24U) & 0xffU));
  framed.push_back(static_cast<char>((size >> 16U) & 0xffU));
  framed.push_back(static_cast<char>((size >> 8U) & 0xffU));
  framed.push_back(static_cast<char>(size & 0xffU));
  framed.append(protobuf_bytes);
  return framed;
}

SnapshotLifecycleCommand map_rollout_command(
    const bonvoyage::v1::RolloutCommand& command) {
  reject_unknown_fields(command, "rollout_command");
  if (command.rollout_sequence() == 0U) {
    fail("rollout.sequence.invalid", "rollout_command.rollout_sequence",
         "rollout sequence must be non-zero");
  }

  switch (command.command_case()) {
    case bonvoyage::v1::RolloutCommand::kPrepare: {
      const auto& prepare = command.prepare();
      if (!prepare.has_artifact() || !prepare.artifact().has_snapshot() ||
          !prepare.has_expected_active_snapshot()) {
        fail("rollout.command.invalid", "rollout_command.prepare",
             "PREPARE requires artifact, target, and expected active identities");
      }
      const auto& artifact = prepare.artifact();
      auto snapshot = reference_from_proto(
          artifact.snapshot(), "rollout_command.prepare.artifact.snapshot");
      auto expected_active = reference_from_proto(
          prepare.expected_active_snapshot(),
          "rollout_command.prepare.expected_active_snapshot");
      if (artifact.snapshot_bytes().empty() ||
          artifact.snapshot_bytes().size() > kMaximumSnapshotArtifactBytes) {
        fail("snapshot.size.invalid",
             "rollout_command.prepare.artifact.snapshot_bytes",
             "snapshot artifact must contain between 1 byte and 64 MiB");
      }
      if (snapshot_sha256(artifact.snapshot_bytes()) != snapshot.sha256) {
        fail("snapshot.digest.mismatch",
             "rollout_command.prepare.artifact.snapshot.snapshot_sha256",
             "snapshot bytes do not match the declared digest");
      }
      if (artifact.schema_version() != kSupportedSchemaVersion) {
        fail("snapshot.schema.unsupported",
             "rollout_command.prepare.artifact.schema_version",
             "only snapshot schema version 1 is supported");
      }
      validate_text(artifact.minimum_dataplane_version(),
                    kMaximumIdentifierBytes, true,
                    "rollout_command.prepare.artifact.minimum_dataplane_version");
      return SnapshotPrepareCommand{
          command.rollout_sequence(),
          std::move(snapshot),
          artifact.snapshot_bytes(),
          artifact.schema_version(),
          artifact.minimum_dataplane_version(),
          capabilities_from_proto(artifact),
          std::move(expected_active),
      };
    }
    case bonvoyage::v1::RolloutCommand::kActivate: {
      const auto& activate = command.activate();
      if (!activate.has_prepared_snapshot() ||
          !activate.has_expected_active_snapshot()) {
        fail("rollout.command.invalid", "rollout_command.activate",
             "ACTIVATE requires prepared and expected active identities");
      }
      return SnapshotActivateCommand{
          command.rollout_sequence(),
          reference_from_proto(
              activate.prepared_snapshot(),
              "rollout_command.activate.prepared_snapshot"),
          reference_from_proto(
              activate.expected_active_snapshot(),
              "rollout_command.activate.expected_active_snapshot"),
      };
    }
    case bonvoyage::v1::RolloutCommand::kCancel: {
      const auto& cancel = command.cancel();
      if (!cancel.has_snapshot()) {
        fail("rollout.command.invalid", "rollout_command.cancel.snapshot",
             "CANCEL requires an exact prepared snapshot identity");
      }
      validate_text(cancel.reason(), kMaximumCancelReasonBytes, true,
                    "rollout_command.cancel.reason");
      return SnapshotCancelCommand{
          command.rollout_sequence(),
          reference_from_proto(cancel.snapshot(),
                               "rollout_command.cancel.snapshot"),
          cancel.reason(),
      };
    }
    case bonvoyage::v1::RolloutCommand::COMMAND_NOT_SET:
    default:
      fail("rollout.command.missing", "rollout_command.command",
           "rollout command has no supported operation");
  }
}

SnapshotLifecycleCommand decode_rollout_command(
    std::string_view protobuf_bytes) {
  return map_rollout_command(parse_message<bonvoyage::v1::RolloutCommand>(
      protobuf_bytes, "rollout_command"));
}

SnapshotLifecycleCommand decode_discovery_response(
    std::string_view protobuf_bytes) {
  auto response = parse_message<bonvoyage::v1::StreamSnapshotsResponse>(
      protobuf_bytes, "stream_snapshots_response");
  if (response.has_delivery()) {
    fail("discovery.response.legacy_delivery_unsupported", "delivery",
         "two-phase dataplanes reject the Phase 1 delivery path");
  }
  if (!response.has_command()) {
    fail("discovery.response.command_missing", "command",
         "discovery response does not contain a rollout command");
  }
  return map_rollout_command(response.command());
}

bonvoyage::v1::NodeHello build_node_hello(
    const DiscoveryNodeIdentity& identity,
    const SnapshotPreparationState& state, std::uint32_t shard_count) {
  validate_identity(identity);
  bonvoyage::v1::NodeHello hello;
  hello.set_node_id(identity.node_id);
  hello.set_dataplane_version(identity.dataplane_version);
  auto schemas = identity.supported_schema_versions;
  std::sort(schemas.begin(), schemas.end());
  for (const auto schema : schemas) {
    hello.add_supported_schema_versions(schema);
  }
  validate_snapshot_reference(state.active_snapshot, "active_snapshot");
  hello.set_active_snapshot_id(state.active_snapshot.snapshot_id);
  hello.set_active_snapshot_sha256(
      reinterpret_cast<const char*>(state.active_snapshot.sha256.data()),
      state.active_snapshot.sha256.size());
  hello.set_last_rollout_sequence(state.last_rollout_sequence);
  hello.set_process_instance_id(identity.process_instance_id);
  auto capabilities =
      validate_capabilities(identity.capabilities, true, "capabilities");
  for (const auto& capability : capabilities) {
    auto* wire = hello.add_capabilities();
    wire->set_capability(capability.capability);
    wire->set_version(capability.version);
  }
  set_runtime_state(hello.mutable_runtime_state(), state, shard_count);
  return hello;
}

bonvoyage::v1::NodeHeartbeat build_node_heartbeat(
    const DiscoveryNodeIdentity& identity,
    const SnapshotPreparationState& state, std::uint32_t shard_count,
    std::chrono::system_clock::time_point observed_at) {
  validate_identity(identity);
  bonvoyage::v1::NodeHeartbeat heartbeat;
  heartbeat.set_node_id(identity.node_id);
  heartbeat.set_process_instance_id(identity.process_instance_id);
  set_runtime_state(heartbeat.mutable_runtime_state(), state, shard_count);
  set_timestamp(heartbeat.mutable_observed_at(), observed_at, "observed_at");
  return heartbeat;
}

bonvoyage::v1::NodeRolloutReport build_node_rollout_report(
    const DiscoveryNodeIdentity& identity,
    const NodeSnapshotPreparationReport& report,
    std::chrono::system_clock::time_point completed_at) {
  if (report.previous_active_snapshot != report.current_active_snapshot) {
    fail("rollout.result.invalid", "current_active_snapshot",
         "PREPARE must not change the active snapshot");
  }
  return make_report(
      identity, report.rollout_sequence, report.snapshot,
      bonvoyage::v1::ROLLOUT_OPERATION_PREPARE, report.acknowledged,
      report.previous_active_snapshot, report.current_active_snapshot,
      report.shard_count, report.completed_shards, report.failed_shard,
      report.issue, completed_at);
}

bonvoyage::v1::NodeRolloutReport build_node_rollout_report(
    const DiscoveryNodeIdentity& identity,
    const NodeSnapshotActivationReport& report,
    std::chrono::system_clock::time_point completed_at) {
  if ((report.acknowledged &&
       report.current_active_snapshot != report.snapshot) ||
      (!report.acknowledged &&
       report.current_active_snapshot != report.previous_active_snapshot)) {
    fail("rollout.result.invalid", "current_active_snapshot",
         "ACTIVATE result disagrees with its atomic publication outcome");
  }
  return make_report(
      identity, report.rollout_sequence, report.snapshot,
      bonvoyage::v1::ROLLOUT_OPERATION_ACTIVATE, report.acknowledged,
      report.previous_active_snapshot, report.current_active_snapshot,
      report.shard_count, report.completed_shards, report.failed_shard,
      report.issue, completed_at);
}

bonvoyage::v1::NodeRolloutReport build_node_rollout_report(
    const DiscoveryNodeIdentity& identity,
    const NodeSnapshotCancellationReport& report,
    std::chrono::system_clock::time_point completed_at) {
  return make_report(
      identity, report.rollout_sequence, report.snapshot,
      bonvoyage::v1::ROLLOUT_OPERATION_CANCEL, report.acknowledged,
      report.current_active_snapshot, report.current_active_snapshot,
      report.shard_count, report.completed_shards, report.failed_shard,
      report.issue, completed_at);
}

}  // namespace bonvoyage::runtime
