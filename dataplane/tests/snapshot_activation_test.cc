#include "bonvoyage/runtime/snapshot_preparation.hh"

#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

#include "bonvoyage/runtime/runtime_snapshot.hh"
#include "bonvoyage/v1/config.pb.h"

namespace {

using bonvoyage::runtime::SnapshotActivateCommand;
using bonvoyage::runtime::SnapshotCancelCommand;
using bonvoyage::runtime::SnapshotPrepareCommand;
using bonvoyage::runtime::SnapshotPreparationShard;
using bonvoyage::runtime::SnapshotReadLease;
using bonvoyage::runtime::SnapshotReference;

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

void require_activation_issue(SnapshotPreparationShard& shard,
                              const SnapshotActivateCommand& command,
                              std::string_view expected_code) {
  const auto result = shard.arm_activation(command);
  require(!result.accepted, "invalid activation unexpectedly succeeded");
  require(result.issue.has_value(), "invalid activation omitted its issue");
  require(result.issue->code == expected_code,
          "invalid activation returned the wrong issue code");
}

void require_cancel_issue(SnapshotPreparationShard& shard,
                          const SnapshotCancelCommand& command,
                          std::string_view expected_code) {
  const auto result = shard.arm_cancel(command);
  require(!result.accepted, "invalid cancellation unexpectedly succeeded");
  require(result.issue.has_value(), "invalid cancellation omitted its issue");
  require(result.issue->code == expected_code,
          "invalid cancellation returned the wrong issue code");
}

void release(SnapshotReadLease& lease) { lease = SnapshotReadLease{}; }

void test_activation_pins_and_retires_generations() {
  const auto active_bytes = deterministic_bytes(snapshot("active", 1U));
  const auto active = reference("active", active_bytes);
  const auto target = snapshot("target", 2U);
  auto prepare = prepare_command(1U, target, active);

  SnapshotPreparationShard shard;
  shard.initialize(active);
  auto old_lease = shard.acquire_active_snapshot();
  require(old_lease.has_value() && old_lease->snapshot() == active,
          "initial active generation was not leasable");
  require(old_lease->runtime_snapshot() == nullptr,
          "bootstrap identity unexpectedly owned a compiled runtime");
  require(shard.prepare(prepare).prepared,
          "valid target did not prepare before activation");

  const SnapshotActivateCommand activate{1U, prepare.snapshot, active};
  const auto armed = shard.arm_activation(activate);
  require(armed.accepted && !armed.replayed,
          "valid activation did not arm");
  auto state = shard.state();
  require(!state.admission_open && state.activation_in_progress,
          "activation did not fence new request leases");
  require(!shard.acquire_active_snapshot().has_value(),
          "request lease crossed the activation fence");
  require_cancel_issue(
      shard, SnapshotCancelCommand{1U, prepare.snapshot, "too late"},
      "snapshot.cancel.activation_started");

  require(shard.commit_armed_activation(),
          "armed activation violated its no-fail commit contract");
  state = shard.state();
  require(state.active_snapshot == prepare.snapshot &&
              state.active_rollout_sequence == 1U &&
              state.retired_snapshot.has_value() &&
              state.retired_snapshot->snapshot == active &&
              state.retired_snapshot->pinned_leases == 1U &&
              !state.prepared_snapshot.has_value() &&
              !state.admission_open,
          "activation did not publish and retain the expected generations");
  require(old_lease->snapshot() == active,
          "activation changed an already acquired request generation");

  shard.reopen_admission();
  auto target_lease = shard.acquire_active_snapshot();
  require(target_lease.has_value() &&
              target_lease->snapshot() == prepare.snapshot &&
              target_lease->runtime_snapshot() != nullptr &&
              target_lease->runtime_snapshot()->snapshot_id() == "target",
          "new requests did not acquire the published runtime");
  auto retirement = shard.reap_retired_snapshot(active);
  require(!retirement.complete && retirement.pinned_leases == 1U,
          "retirement ignored an outstanding old-generation lease");

  const auto next_target = snapshot("next", 3U);
  auto next_prepare = prepare_command(2U, next_target, prepare.snapshot);
  require(shard.prepare(next_prepare).prepared,
          "next generation did not prepare while one old generation drained");
  require_activation_issue(
      shard,
      SnapshotActivateCommand{2U, next_prepare.snapshot, prepare.snapshot},
      "snapshot.retirement.pending");
  require(shard.state().admission_open,
          "failed retirement preflight left admission closed");

  release(*old_lease);
  retirement = shard.reap_retired_snapshot(active);
  require(retirement.complete && retirement.pinned_leases == 0U,
          "released old generation did not retire");

  const SnapshotActivateCommand activate_next{
      2U, next_prepare.snapshot, prepare.snapshot};
  require(shard.arm_activation(activate_next).accepted,
          "next activation did not arm after retirement");
  require(shard.commit_armed_activation(),
          "next activation did not commit");
  shard.reopen_admission();
  state = shard.state();
  require(state.active_snapshot == next_prepare.snapshot &&
              state.retired_snapshot.has_value() &&
              state.retired_snapshot->snapshot == prepare.snapshot &&
              state.retired_snapshot->pinned_leases == 1U,
          "second activation did not preserve its leased predecessor");
  require(target_lease->snapshot() == prepare.snapshot,
          "second activation mutated the first target lease");

  release(*target_lease);
  retirement = shard.reap_retired_snapshot(prepare.snapshot);
  require(retirement.complete,
          "first target did not retire after its final lease released");
  const auto replay = shard.arm_activation(activate_next);
  require(replay.accepted && replay.replayed,
          "exact activation replay was not idempotent");
  require_cancel_issue(
      shard,
      SnapshotCancelCommand{2U, next_prepare.snapshot, "rollback requested"},
      "snapshot.cancel.activation_started");
}

void test_activation_rejection_and_abort() {
  const auto active_bytes = deterministic_bytes(snapshot("active", 1U));
  const auto active = reference("active", active_bytes);
  const auto target = snapshot("target", 2U);
  auto prepare = prepare_command(4U, target, active);

  SnapshotPreparationShard shard;
  shard.initialize(active);
  require_activation_issue(
      shard, SnapshotActivateCommand{4U, prepare.snapshot, active},
      "snapshot.activate.not_prepared");
  require(shard.prepare(prepare).prepared,
          "activation rejection fixture did not prepare");

  auto wrong_active = active;
  wrong_active.snapshot_id = "other-active";
  require_activation_issue(
      shard, SnapshotActivateCommand{4U, prepare.snapshot, wrong_active},
      "snapshot.active_mismatch");
  auto wrong_target = prepare.snapshot;
  wrong_target.snapshot_id = "other-target";
  require_activation_issue(
      shard, SnapshotActivateCommand{4U, wrong_target, active},
      "snapshot.activate.identity_mismatch");
  require_activation_issue(
      shard, SnapshotActivateCommand{5U, prepare.snapshot, active},
      "snapshot.activate.not_prepared");

  require(shard.arm_activation(
                    SnapshotActivateCommand{4U, prepare.snapshot, active})
              .accepted,
          "valid activation did not arm for abort coverage");
  shard.abort_armed_activation();
  const auto state = shard.state();
  require(state.admission_open && !state.activation_in_progress &&
              state.active_snapshot == active &&
              state.prepared_snapshot.has_value(),
          "activation abort changed state or failed to reopen admission");
  require(shard.acquire_active_snapshot().has_value(),
          "activation abort did not restore request acquisition");
}

void test_identity_scoped_cancellation() {
  const auto active_bytes = deterministic_bytes(snapshot("active", 1U));
  const auto active = reference("active", active_bytes);
  const auto target = snapshot("target", 2U);
  auto prepare = prepare_command(7U, target, active);

  SnapshotPreparationShard shard;
  shard.initialize(active);
  require(shard.prepare(prepare).prepared,
          "cancellation fixture did not prepare");

  auto wrong_target = prepare.snapshot;
  wrong_target.snapshot_id = "other-target";
  require_cancel_issue(
      shard, SnapshotCancelCommand{7U, wrong_target, "operator request"},
      "snapshot.cancel.identity_mismatch");
  require_cancel_issue(
      shard, SnapshotCancelCommand{7U, prepare.snapshot, "bad\nreason"},
      "snapshot.cancel.reason_invalid");

  const SnapshotCancelCommand cancel{
      7U, prepare.snapshot, "operator request"};
  const auto armed = shard.arm_cancel(cancel);
  require(armed.accepted && !armed.replayed,
          "valid cancellation did not arm");
  const auto blocked_prepare =
      prepare_command(8U, snapshot("next", 3U), active);
  const auto blocked = shard.prepare(blocked_prepare);
  require(!blocked.prepared && blocked.issue.has_value() &&
              blocked.issue->code == "snapshot.operation.in_progress",
          "armed cancellation did not serialize lifecycle mutation");
  shard.abort_armed_cancel();
  require(shard.state().prepared_snapshot.has_value(),
          "cancellation abort removed private state");

  require(shard.arm_cancel(cancel).accepted,
          "valid cancellation did not re-arm after abort");
  require(shard.commit_armed_cancel(),
          "armed cancellation violated its no-fail commit contract");
  auto state = shard.state();
  require(state.active_snapshot == active && state.admission_open &&
              !state.prepared_snapshot.has_value() &&
              state.last_rollout_sequence == 7U,
          "cancellation changed active state or replay watermark");
  const auto replay = shard.arm_cancel(cancel);
  require(replay.accepted && replay.replayed,
          "exact cancellation replay was not idempotent");
  require_cancel_issue(
      shard,
      SnapshotCancelCommand{7U, prepare.snapshot, "different reason"},
      "rollout.sequence.conflict");
}

}  // namespace

int main() {
  try {
    test_activation_pins_and_retires_generations();
    test_activation_rejection_and_abort();
    test_identity_scoped_cancellation();
    std::cout << "{\"status\":\"passed\",\"assertions\":" << assertions
              << "}\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
