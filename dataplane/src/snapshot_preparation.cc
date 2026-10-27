#include "bonvoyage/runtime/snapshot_preparation.hh"

#include <gnutls/crypto.h>

#include <algorithm>
#include <cctype>
#include <exception>
#include <limits>
#include <new>
#include <stdexcept>
#include <unordered_map>
#include <utility>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/message.h>
#include <google/protobuf/unknown_field_set.h>

#include "bonvoyage/runtime/runtime_snapshot.hh"

namespace bonvoyage::runtime {

class SnapshotGeneration final {
 public:
  SnapshotGeneration(SnapshotReference reference, std::uint64_t sequence)
      : reference_(std::move(reference)), rollout_sequence_(sequence) {}

  SnapshotGeneration(SnapshotReference reference, std::uint64_t sequence,
                     RuntimeSnapshot runtime_snapshot)
      : reference_(std::move(reference)),
        rollout_sequence_(sequence),
        runtime_snapshot_(std::move(runtime_snapshot)) {}

  SnapshotReference reference_;
  std::uint64_t rollout_sequence_{};
  std::optional<RuntimeSnapshot> runtime_snapshot_;
  std::uint64_t leases_{};
};

namespace {

constexpr std::size_t kMaximumCapabilities = 16U;
constexpr std::size_t kMaximumFieldPathBytes = 1024U;
constexpr std::size_t kMaximumIssueBytes = 4096U;
constexpr std::size_t kMaximumCancelReasonBytes = 1024U;
constexpr std::uint32_t kSupportedSchemaVersion = 1U;
constexpr std::uint32_t kSupportedCapabilityVersion = 1U;

class PreparationFailure final : public std::runtime_error {
 public:
  explicit PreparationFailure(SnapshotPreparationIssue issue)
      : std::runtime_error(issue.message), issue_(std::move(issue)) {}

  [[nodiscard]] const SnapshotPreparationIssue& issue() const noexcept {
    return issue_;
  }

 private:
  SnapshotPreparationIssue issue_;
};

std::string bounded(std::string value, std::size_t maximum) {
  if (value.size() > maximum) {
    value.resize(maximum);
  }
  return value;
}

[[noreturn]] void fail(std::string code, std::string field_path,
                       std::string message) {
  throw PreparationFailure(SnapshotPreparationIssue{
      bounded(std::move(code), 128U),
      bounded(std::move(field_path), kMaximumFieldPathBytes),
      bounded(std::move(message), kMaximumIssueBytes)});
}

bool zero_digest(const SnapshotDigest& digest) noexcept {
  return std::all_of(digest.begin(), digest.end(),
                     [](std::uint8_t byte) { return byte == 0U; });
}

bool valid_reference_id(std::string_view value) noexcept {
  if (value.empty() || value.size() > 128U) {
    return false;
  }
  const auto alphanumeric = [](char character) {
    return (character >= 'a' && character <= 'z') ||
           (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9');
  };
  if (!alphanumeric(value.front())) {
    return false;
  }
  return std::all_of(value.begin() + 1, value.end(),
                     [alphanumeric](char character) {
                       return alphanumeric(character) || character == '.' ||
                              character == '_' || character == '-';
                     });
}

void validate_reference(const SnapshotReference& reference,
                        std::string_view field_path) {
  if (!valid_reference_id(reference.snapshot_id)) {
    fail("snapshot.reference.invalid", std::string(field_path) + ".snapshot_id",
         "snapshot identity must be a valid 1-128 byte BonVoyage name");
  }
  if (zero_digest(reference.sha256)) {
    fail("snapshot.reference.invalid", std::string(field_path) + ".sha256",
         "snapshot digest must be a non-zero SHA-256 value");
  }
}

bool valid_cancel_reason(std::string_view reason) noexcept {
  if (reason.empty() || reason.size() > kMaximumCancelReasonBytes) {
    return false;
  }
  return std::none_of(reason.begin(), reason.end(), [](char character) {
    const auto byte = static_cast<unsigned char>(character);
    return byte < 0x20U || byte == 0x7fU;
  });
}

bool same_activation(const SnapshotActivateCommand& left,
                     const SnapshotActivateCommand& right) noexcept {
  return left.rollout_sequence == right.rollout_sequence &&
         left.prepared_snapshot == right.prepared_snapshot &&
         left.expected_active_snapshot == right.expected_active_snapshot;
}

bool same_cancellation(const SnapshotCancelCommand& left,
                       const SnapshotCancelCommand& right) noexcept {
  return left.rollout_sequence == right.rollout_sequence &&
         left.snapshot == right.snapshot && left.reason == right.reason;
}

bool known_capability(bonvoyage::v1::NodeCapabilityType capability) noexcept {
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

std::vector<SnapshotCapability> normalize_capabilities(
    std::vector<SnapshotCapability> capabilities, bool require_two_phase,
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
  bool found_two_phase = false;
  for (std::size_t index = 0U; index < capabilities.size(); ++index) {
    const auto& capability = capabilities[index];
    if (!known_capability(capability.capability) ||
        capability.version != kSupportedCapabilityVersion) {
      fail("snapshot.capability.unsupported",
           std::string(field_path) + "[" + std::to_string(index) + "]",
           "required capability type or version is unsupported");
    }
    if (index != 0U &&
        capabilities[index - 1U].capability == capability.capability) {
      fail("snapshot.capability.duplicate",
           std::string(field_path) + "[" + std::to_string(index) + "]",
           "required capability is duplicated");
    }
    found_two_phase =
        found_two_phase ||
        capability.capability ==
            bonvoyage::v1::NODE_CAPABILITY_TYPE_TWO_PHASE_ROLLOUT;
  }
  if (require_two_phase && !found_two_phase) {
    fail("snapshot.capability.missing", std::string(field_path),
         "two-phase rollout capability version 1 is required");
  }
  return capabilities;
}

bool find_unknown_fields(const google::protobuf::Message& message,
                         std::string path, std::string& unknown_path) {
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

std::string deterministic_bytes(const bonvoyage::v1::Snapshot& snapshot) {
  std::string encoded;
  {
    google::protobuf::io::StringOutputStream stream(&encoded);
    google::protobuf::io::CodedOutputStream output(&stream);
    output.SetSerializationDeterministic(true);
    if (!snapshot.SerializeToCodedStream(&output) || output.HadError()) {
      fail("snapshot.protobuf.encode_failed", "artifact.snapshot_bytes",
           "snapshot could not be deterministically encoded");
    }
    output.Trim();
  }
  return encoded;
}

struct ValidatedArtifact final {
  bonvoyage::v1::Snapshot snapshot;
  std::vector<SnapshotCapability> required_capabilities;
};

ValidatedArtifact validate_artifact_envelope(
    const SnapshotPrepareCommand& command,
    const std::vector<SnapshotCapability>& supported_capabilities) {
  validate_reference(command.snapshot, "artifact.snapshot");
  validate_reference(command.expected_active_snapshot,
                     "expected_active_snapshot");
  if (command.snapshot_bytes.empty() ||
      command.snapshot_bytes.size() > kMaximumSnapshotArtifactBytes) {
    fail("snapshot.size.invalid", "artifact.snapshot_bytes",
         "snapshot artifact must contain between 1 byte and 64 MiB");
  }
  if (snapshot_sha256(command.snapshot_bytes) != command.snapshot.sha256) {
    fail("snapshot.digest.mismatch", "artifact.snapshot.sha256",
         "snapshot bytes do not match the declared SHA-256 digest");
  }
  if (command.schema_version != kSupportedSchemaVersion) {
    fail("snapshot.schema.unsupported", "artifact.schema_version",
         "only snapshot schema version 1 is supported");
  }
  if (command.minimum_dataplane_version.empty() ||
      command.minimum_dataplane_version.size() > 128U) {
    fail("snapshot.version.invalid", "artifact.minimum_dataplane_version",
         "minimum dataplane version must contain 1-128 bytes");
  }

  auto required = normalize_capabilities(command.required_capabilities, true,
                                         "artifact.required_capabilities");
  const auto supported = normalize_capabilities(
      supported_capabilities, false, "node.supported_capabilities");
  for (const auto& capability : required) {
    if (std::find(supported.begin(), supported.end(), capability) ==
        supported.end()) {
      fail("snapshot.capability.unsupported",
           "artifact.required_capabilities",
           "snapshot requires a capability not implemented by this shard");
    }
  }

  if (command.snapshot_bytes.size() >
      static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    fail("snapshot.size.invalid", "artifact.snapshot_bytes",
         "snapshot artifact exceeds the protobuf parser limit");
  }
  bonvoyage::v1::Snapshot snapshot;
  if (!snapshot.ParseFromArray(
          command.snapshot_bytes.data(),
          static_cast<int>(command.snapshot_bytes.size()))) {
    fail("snapshot.protobuf.invalid", "artifact.snapshot_bytes",
         "snapshot artifact is not a valid BonVoyage protobuf payload");
  }
  std::string unknown_path;
  if (find_unknown_fields(snapshot, "snapshot", unknown_path)) {
    fail("snapshot.protobuf.unknown_field", std::move(unknown_path),
         "snapshot artifact contains an unknown protobuf field");
  }
  if (deterministic_bytes(snapshot) != command.snapshot_bytes) {
    fail("snapshot.protobuf.non_deterministic", "artifact.snapshot_bytes",
         "snapshot artifact is not encoded in deterministic canonical form");
  }
  if (snapshot.snapshot_id() != command.snapshot.snapshot_id) {
    fail("snapshot.metadata.mismatch", "artifact.snapshot.snapshot_id",
         "artifact identity disagrees with the embedded snapshot identity");
  }
  if (snapshot.schema_version() != command.schema_version) {
    fail("snapshot.metadata.mismatch", "artifact.schema_version",
         "artifact schema disagrees with the embedded snapshot schema");
  }
  if (snapshot.minimum_dataplane_version() !=
      command.minimum_dataplane_version) {
    fail("snapshot.metadata.mismatch",
         "artifact.minimum_dataplane_version",
         "artifact minimum version disagrees with the embedded snapshot");
  }
  return ValidatedArtifact{std::move(snapshot), std::move(required)};
}

SnapshotPreparationIssue runtime_validation_issue(
    const std::invalid_argument& error) {
  std::string detail = error.what();
  std::string field_path = "snapshot";
  const auto separator = detail.find(": ");
  if (separator != std::string::npos && separator != 0U) {
    field_path = detail.substr(0U, separator);
    detail.erase(0U, separator + 2U);
  }
  return SnapshotPreparationIssue{
      "snapshot.validation_failed",
      bounded(std::move(field_path), kMaximumFieldPathBytes),
      bounded(std::move(detail), kMaximumIssueBytes)};
}

}  // namespace

SnapshotReadLease::SnapshotReadLease(SnapshotGeneration* generation) noexcept
    : generation_(generation) {
  if (generation_ != nullptr) {
    ++generation_->leases_;
  }
}

SnapshotReadLease::~SnapshotReadLease() { release(); }

SnapshotReadLease::SnapshotReadLease(SnapshotReadLease&& other) noexcept
    : generation_(std::exchange(other.generation_, nullptr)) {}

SnapshotReadLease& SnapshotReadLease::operator=(
    SnapshotReadLease&& other) noexcept {
  if (this != &other) {
    release();
    generation_ = std::exchange(other.generation_, nullptr);
  }
  return *this;
}

SnapshotReadLease::operator bool() const noexcept {
  return generation_ != nullptr;
}

const SnapshotReference& SnapshotReadLease::snapshot() const noexcept {
  static const SnapshotReference empty;
  return generation_ == nullptr ? empty : generation_->reference_;
}

const RuntimeSnapshot* SnapshotReadLease::runtime_snapshot() const noexcept {
  if (generation_ == nullptr ||
      !generation_->runtime_snapshot_.has_value()) {
    return nullptr;
  }
  return &*generation_->runtime_snapshot_;
}

void SnapshotReadLease::release() noexcept {
  if (generation_ != nullptr) {
    if (generation_->leases_ != 0U) {
      --generation_->leases_;
    }
    generation_ = nullptr;
  }
}

bool SnapshotReference::empty() const noexcept {
  return snapshot_id.empty() && zero_digest(sha256);
}

SnapshotDigest snapshot_sha256(std::string_view bytes) {
  SnapshotDigest digest{};
  const auto status = gnutls_hash_fast(GNUTLS_DIG_SHA256, bytes.data(),
                                       bytes.size(), digest.data());
  if (status != GNUTLS_E_SUCCESS) {
    throw std::runtime_error("GnuTLS could not compute snapshot SHA-256");
  }
  return digest;
}

std::vector<SnapshotCapability> default_snapshot_capabilities() {
  return {
      {bonvoyage::v1::NODE_CAPABILITY_TYPE_TWO_PHASE_ROLLOUT, 1U},
      {bonvoyage::v1::NODE_CAPABILITY_TYPE_EXACT_ARTIFACT_ROLLBACK, 1U},
      {bonvoyage::v1::NODE_CAPABILITY_TYPE_HEARTBEAT_STATE_REPORT, 1U},
  };
}

class SnapshotPreparationShard::Impl final {
 public:
  struct Prepared final {
    std::uint64_t rollout_sequence{};
    SnapshotReference expected_active_snapshot;
    std::uint32_t schema_version{};
    std::string minimum_dataplane_version;
    std::vector<SnapshotCapability> required_capabilities;
    std::unique_ptr<SnapshotGeneration> generation;
  };

  ~Impl() {
    if ((active_ != nullptr && active_->leases_ != 0U) ||
        (retired_ != nullptr && retired_->leases_ != 0U)) {
      std::terminate();
    }
  }

  void initialize(SnapshotReference active_snapshot) {
    if (initialized_) {
      throw std::logic_error("snapshot preparation shard is already initialized");
    }
    validate_reference(active_snapshot, "active_snapshot");
    active_ = std::make_unique<SnapshotGeneration>(
        std::move(active_snapshot), 0U);
    initialized_ = true;
    admission_open_ = true;
  }

  void configure_supported_capabilities(
      std::vector<SnapshotCapability> capabilities) {
    if (prepared_.has_value() || activation_in_progress() ||
        cancel_intent_.has_value()) {
      throw std::logic_error(
          "cannot change capabilities during a snapshot operation");
    }
    supported_capabilities_ = normalize_capabilities(
        std::move(capabilities), true, "node.supported_capabilities");
  }

  ShardSnapshotPreparationResult prepare(
      const SnapshotPrepareCommand& command) {
    ShardSnapshotPreparationResult result;
    result.active_snapshot = active_reference();
    try {
      if (!initialized_) {
        fail("snapshot.prepare.not_initialized", "node.active_snapshot",
             "snapshot preparation shard has no active snapshot identity");
      }
      if (activation_in_progress() || cancel_intent_.has_value()) {
        fail("snapshot.operation.in_progress", "rollout_sequence",
             "another snapshot lifecycle operation is in progress");
      }
      if (command.rollout_sequence == 0U) {
        fail("rollout.sequence.invalid", "rollout_sequence",
             "rollout sequence must be greater than zero");
      }
      if (command.expected_active_snapshot != active_->reference_) {
        fail("snapshot.active_mismatch", "expected_active_snapshot",
             "expected active snapshot does not match this shard");
      }
      if (prepared_.has_value()) {
        if (command.rollout_sequence < prepared_->rollout_sequence) {
          fail("rollout.sequence.stale", "rollout_sequence",
               "rollout sequence is older than the prepared sequence");
        }
        if (command.rollout_sequence > prepared_->rollout_sequence) {
          fail("snapshot.prepare.conflict", "rollout_sequence",
               "a different snapshot remains privately prepared");
        }
      } else if (command.rollout_sequence <= last_rollout_sequence_) {
        fail("rollout.sequence.stale", "rollout_sequence",
             "rollout sequence is not newer than the last prepared sequence");
      }

      auto validated = validate_artifact_envelope(
          command, supported_capabilities_);
      if (prepared_.has_value()) {
        if (command.rollout_sequence == prepared_->rollout_sequence) {
          const bool exact_replay =
              command.snapshot == prepared_->generation->reference_ &&
              command.expected_active_snapshot ==
                  prepared_->expected_active_snapshot &&
              command.schema_version == prepared_->schema_version &&
              command.minimum_dataplane_version ==
                  prepared_->minimum_dataplane_version &&
              validated.required_capabilities ==
                  prepared_->required_capabilities;
          if (!exact_replay) {
            fail("rollout.sequence.conflict", "rollout_sequence",
                 "rollout sequence was reused with different preparation metadata");
          }
          result.prepared = true;
          result.replayed = true;
          return result;
        }
      }

      auto runtime_snapshot = RuntimeSnapshot::compile(validated.snapshot);
      runtime_snapshot.validate_live_gateway_capabilities();
      auto generation = std::make_unique<SnapshotGeneration>(
          command.snapshot, command.rollout_sequence,
          std::move(runtime_snapshot));
      prepared_.emplace(Prepared{
          command.rollout_sequence,
          command.expected_active_snapshot,
          command.schema_version,
          command.minimum_dataplane_version,
          std::move(validated.required_capabilities),
          std::move(generation),
      });
      last_rollout_sequence_ = command.rollout_sequence;
      result.prepared = true;
      return result;
    } catch (const PreparationFailure& error) {
      result.issue = error.issue();
    } catch (const std::invalid_argument& error) {
      result.issue = runtime_validation_issue(error);
    } catch (const std::bad_alloc&) {
      result.issue = SnapshotPreparationIssue{
          "snapshot.prepare.resource_exhausted", "snapshot",
          "shard-local snapshot preparation exhausted memory"};
    } catch (const std::exception&) {
      result.issue = SnapshotPreparationIssue{
          "snapshot.prepare.internal", "snapshot",
          "shard-local snapshot preparation failed internally"};
    }
    return result;
  }

  ShardSnapshotActivationResult arm_activation(
      const SnapshotActivateCommand& command) {
    ShardSnapshotActivationResult result;
    result.active_snapshot = active_reference();
    try {
      if (!initialized_) {
        fail("snapshot.activate.not_initialized", "node.active_snapshot",
             "snapshot lifecycle shard has no active snapshot identity");
      }
      if (command.rollout_sequence == 0U) {
        fail("rollout.sequence.invalid", "rollout_sequence",
             "rollout sequence must be greater than zero");
      }
      validate_reference(command.prepared_snapshot, "prepared_snapshot");
      validate_reference(command.expected_active_snapshot,
                         "expected_active_snapshot");
      if (activation_in_progress() || cancel_intent_.has_value()) {
        fail("snapshot.activate.in_progress", "rollout_sequence",
             "a snapshot lifecycle operation is already in progress");
      }
      if (last_activation_.has_value() &&
          command.rollout_sequence == last_activation_->rollout_sequence) {
        if (!same_activation(command, *last_activation_) ||
            active_->reference_ != command.prepared_snapshot) {
          fail("rollout.sequence.conflict", "rollout_sequence",
               "activation sequence was reused with a different identity");
        }
        result.accepted = true;
        result.replayed = true;
        return result;
      }
      if (command.rollout_sequence < last_rollout_sequence_) {
        fail("rollout.sequence.stale", "rollout_sequence",
             "activation sequence is older than the accepted sequence");
      }
      if (command.expected_active_snapshot != active_->reference_) {
        fail("snapshot.active_mismatch", "expected_active_snapshot",
             "expected active snapshot does not match this shard");
      }
      reap_unpinned_retired();
      if (retired_ != nullptr) {
        fail("snapshot.retirement.pending", "retired_snapshot",
             "the previous active generation is still pinned by requests");
      }
      if (!prepared_.has_value()) {
        fail("snapshot.activate.not_prepared", "prepared_snapshot",
             "activation requires a matching privately prepared snapshot");
      }
      if (command.rollout_sequence != prepared_->rollout_sequence) {
        fail(command.rollout_sequence < prepared_->rollout_sequence
                 ? "rollout.sequence.stale"
                 : "snapshot.activate.not_prepared",
             "rollout_sequence",
             "activation sequence does not identify the prepared snapshot");
      }
      if (command.prepared_snapshot != prepared_->generation->reference_) {
        fail("snapshot.activate.identity_mismatch", "prepared_snapshot",
             "activation identity does not match the prepared artifact");
      }
      if (command.expected_active_snapshot !=
          prepared_->expected_active_snapshot) {
        fail("snapshot.activate.identity_mismatch",
             "expected_active_snapshot",
             "activation prior identity does not match PREPARE");
      }

      activation_intent_ = command;
      admission_open_ = false;
      result.accepted = true;
      return result;
    } catch (const PreparationFailure& error) {
      result.issue = error.issue();
    } catch (const std::bad_alloc&) {
      result.issue = SnapshotPreparationIssue{
          "snapshot.activate.resource_exhausted", "snapshot",
          "shard-local activation preflight exhausted memory"};
    } catch (const std::exception&) {
      result.issue = SnapshotPreparationIssue{
          "snapshot.activate.internal", "snapshot",
          "shard-local activation preflight failed internally"};
    }
    return result;
  }

  void abort_armed_activation() noexcept {
    activation_intent_.reset();
    if (!activation_committed_pending_reopen_) {
      admission_open_ = initialized_;
    }
  }

  bool commit_armed_activation() noexcept {
    if (!activation_intent_.has_value() || !prepared_.has_value() ||
        retired_ != nullptr ||
        activation_intent_->rollout_sequence != prepared_->rollout_sequence ||
        activation_intent_->prepared_snapshot !=
            prepared_->generation->reference_) {
      return false;
    }
    retired_ = std::move(active_);
    active_ = std::move(prepared_->generation);
    prepared_.reset();
    last_activation_ = std::move(activation_intent_);
    activation_intent_.reset();
    activation_committed_pending_reopen_ = true;
    return true;
  }

  void reopen_admission() noexcept {
    activation_intent_.reset();
    activation_committed_pending_reopen_ = false;
    admission_open_ = initialized_;
  }

  ShardSnapshotCancellationResult arm_cancel(
      const SnapshotCancelCommand& command) {
    ShardSnapshotCancellationResult result;
    result.active_snapshot = active_reference();
    try {
      if (!initialized_) {
        fail("snapshot.cancel.not_initialized", "node.active_snapshot",
             "snapshot lifecycle shard has no active snapshot identity");
      }
      if (command.rollout_sequence == 0U) {
        fail("rollout.sequence.invalid", "rollout_sequence",
             "rollout sequence must be greater than zero");
      }
      validate_reference(command.snapshot, "snapshot");
      if (!valid_cancel_reason(command.reason)) {
        fail("snapshot.cancel.reason_invalid", "reason",
             "cancellation reason must contain 1-1024 printable bytes");
      }
      if (activation_in_progress()) {
        fail("snapshot.cancel.activation_started", "rollout_sequence",
             "cancellation is forbidden after activation begins");
      }
      if (cancel_intent_.has_value()) {
        fail("snapshot.cancel.in_progress", "rollout_sequence",
             "another cancellation is already in progress");
      }
      if (last_cancellation_.has_value() &&
          command.rollout_sequence ==
              last_cancellation_->rollout_sequence) {
        if (!same_cancellation(command, *last_cancellation_)) {
          fail("rollout.sequence.conflict", "rollout_sequence",
               "cancellation sequence was reused with different metadata");
        }
        result.accepted = true;
        result.replayed = true;
        return result;
      }
      if (last_activation_.has_value() &&
          command.rollout_sequence == last_activation_->rollout_sequence) {
        fail("snapshot.cancel.activation_started", "rollout_sequence",
             "the requested sequence has already activated");
      }
      if (command.rollout_sequence < last_rollout_sequence_) {
        fail("rollout.sequence.stale", "rollout_sequence",
             "cancellation sequence is older than the accepted sequence");
      }
      if (!prepared_.has_value()) {
        fail("snapshot.cancel.not_prepared", "snapshot",
             "cancellation requires a matching privately prepared snapshot");
      }
      if (command.rollout_sequence != prepared_->rollout_sequence) {
        fail(command.rollout_sequence < prepared_->rollout_sequence
                 ? "rollout.sequence.stale"
                 : "snapshot.cancel.not_prepared",
             "rollout_sequence",
             "cancellation sequence does not identify the prepared snapshot");
      }
      if (command.snapshot != prepared_->generation->reference_) {
        fail("snapshot.cancel.identity_mismatch", "snapshot",
             "cancellation identity does not match the prepared artifact");
      }

      cancel_intent_ = command;
      result.accepted = true;
      return result;
    } catch (const PreparationFailure& error) {
      result.issue = error.issue();
    } catch (const std::bad_alloc&) {
      result.issue = SnapshotPreparationIssue{
          "snapshot.cancel.resource_exhausted", "snapshot",
          "shard-local cancellation preflight exhausted memory"};
    } catch (const std::exception&) {
      result.issue = SnapshotPreparationIssue{
          "snapshot.cancel.internal", "snapshot",
          "shard-local cancellation preflight failed internally"};
    }
    return result;
  }

  void abort_armed_cancel() noexcept { cancel_intent_.reset(); }

  bool commit_armed_cancel() noexcept {
    if (!cancel_intent_.has_value() || !prepared_.has_value() ||
        cancel_intent_->rollout_sequence != prepared_->rollout_sequence ||
        cancel_intent_->snapshot != prepared_->generation->reference_) {
      return false;
    }
    prepared_.reset();
    last_cancellation_ = std::move(cancel_intent_);
    cancel_intent_.reset();
    return true;
  }

  SnapshotGeneration* acquire_active_generation() noexcept {
    if (!initialized_ || !admission_open_ || active_ == nullptr) {
      return nullptr;
    }
    return active_.get();
  }

  ShardSnapshotRetirementResult reap_retired_snapshot(
      const SnapshotReference& snapshot) {
    ShardSnapshotRetirementResult result;
    if (retired_ == nullptr) {
      result.complete = true;
      return result;
    }
    if (retired_->reference_ != snapshot) {
      result.issue = SnapshotPreparationIssue{
          "snapshot.retirement.identity_mismatch", "retired_snapshot",
          "retirement identity does not match the retained generation"};
      return result;
    }
    result.pinned_leases = retired_->leases_;
    if (retired_->leases_ != 0U) {
      return result;
    }
    retired_.reset();
    result.complete = true;
    return result;
  }

  bool discard_prepared(std::uint64_t rollout_sequence,
                        const SnapshotReference& snapshot) noexcept {
    if (activation_in_progress() || cancel_intent_.has_value() ||
        !prepared_.has_value() ||
        prepared_->rollout_sequence != rollout_sequence ||
        prepared_->generation->reference_ != snapshot) {
      return false;
    }
    prepared_.reset();
    return true;
  }

  SnapshotPreparationState state() const {
    SnapshotPreparationState result;
    result.active_snapshot = active_reference();
    result.active_rollout_sequence =
        active_ == nullptr ? 0U : active_->rollout_sequence_;
    result.last_rollout_sequence = last_rollout_sequence_;
    result.admission_open = admission_open_;
    result.activation_in_progress = activation_in_progress();
    if (prepared_.has_value()) {
      result.prepared_snapshot = PreparedSnapshotState{
          prepared_->rollout_sequence, prepared_->generation->reference_};
    }
    if (retired_ != nullptr) {
      result.retired_snapshot = RetiredSnapshotState{
          retired_->rollout_sequence_, retired_->reference_,
          retired_->leases_};
    }
    return result;
  }

 private:
  [[nodiscard]] const SnapshotReference& active_reference() const noexcept {
    static const SnapshotReference empty;
    return active_ == nullptr ? empty : active_->reference_;
  }

  [[nodiscard]] bool activation_in_progress() const noexcept {
    return activation_intent_.has_value() ||
           activation_committed_pending_reopen_;
  }

  void reap_unpinned_retired() noexcept {
    if (retired_ != nullptr && retired_->leases_ == 0U) {
      retired_.reset();
    }
  }

  std::vector<SnapshotCapability> supported_capabilities_{
      default_snapshot_capabilities()};
  std::unique_ptr<SnapshotGeneration> active_;
  std::optional<Prepared> prepared_;
  std::unique_ptr<SnapshotGeneration> retired_;
  std::optional<SnapshotActivateCommand> activation_intent_;
  std::optional<SnapshotActivateCommand> last_activation_;
  std::optional<SnapshotCancelCommand> cancel_intent_;
  std::optional<SnapshotCancelCommand> last_cancellation_;
  std::uint64_t last_rollout_sequence_{};
  bool initialized_{false};
  bool admission_open_{false};
  bool activation_committed_pending_reopen_{false};
};

SnapshotPreparationShard::SnapshotPreparationShard()
    : impl_(std::make_unique<Impl>()) {}

SnapshotPreparationShard::~SnapshotPreparationShard() = default;

void SnapshotPreparationShard::initialize(SnapshotReference active_snapshot) {
  impl_->initialize(std::move(active_snapshot));
}

void SnapshotPreparationShard::configure_supported_capabilities(
    std::vector<SnapshotCapability> capabilities) {
  impl_->configure_supported_capabilities(std::move(capabilities));
}

ShardSnapshotPreparationResult SnapshotPreparationShard::prepare(
    const SnapshotPrepareCommand& command) {
  return impl_->prepare(command);
}

ShardSnapshotActivationResult SnapshotPreparationShard::arm_activation(
    const SnapshotActivateCommand& command) {
  return impl_->arm_activation(command);
}

void SnapshotPreparationShard::abort_armed_activation() noexcept {
  impl_->abort_armed_activation();
}

bool SnapshotPreparationShard::commit_armed_activation() noexcept {
  return impl_->commit_armed_activation();
}

void SnapshotPreparationShard::reopen_admission() noexcept {
  impl_->reopen_admission();
}

ShardSnapshotCancellationResult SnapshotPreparationShard::arm_cancel(
    const SnapshotCancelCommand& command) {
  return impl_->arm_cancel(command);
}

void SnapshotPreparationShard::abort_armed_cancel() noexcept {
  impl_->abort_armed_cancel();
}

bool SnapshotPreparationShard::commit_armed_cancel() noexcept {
  return impl_->commit_armed_cancel();
}

std::optional<SnapshotReadLease>
SnapshotPreparationShard::acquire_active_snapshot() noexcept {
  auto* generation = impl_->acquire_active_generation();
  if (generation == nullptr) {
    return std::nullopt;
  }
  return SnapshotReadLease(generation);
}

ShardSnapshotRetirementResult
SnapshotPreparationShard::reap_retired_snapshot(
    const SnapshotReference& snapshot) {
  return impl_->reap_retired_snapshot(snapshot);
}

bool SnapshotPreparationShard::discard_prepared(
    std::uint64_t rollout_sequence,
    const SnapshotReference& snapshot) noexcept {
  return impl_->discard_prepared(rollout_sequence, snapshot);
}

SnapshotPreparationState SnapshotPreparationShard::state() const {
  return impl_->state();
}

}  // namespace bonvoyage::runtime
